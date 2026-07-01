#include "installer.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/evp.h>
#include <zlib.h>

/* ---- gzip decompression (zlib) ---- */

#define FOTA_GUNZIP_CHUNK 65536u

fota_install_result_t fota_gunzip(const uint8_t *gz_data, size_t gz_len,
                                   size_t max_output_size, uint8_t **out_data,
                                   size_t *out_len) {
    if (gz_data == NULL || out_data == NULL || out_len == NULL ||
        gz_len == 0 || max_output_size == 0) {
        return FOTA_INSTALL_ERR_INVALID_ARG;
    }

    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    /* 16 + MAX_WBITS: gzip-format-only (not raw deflate or zlib). */
    if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
        return FOTA_INSTALL_ERR_DECOMPRESS_FAILED;
    }

    strm.next_in = (unsigned char *)(uintptr_t)gz_data;
    strm.avail_in = (unsigned int)gz_len;

    size_t capacity = FOTA_GUNZIP_CHUNK < max_output_size
                          ? FOTA_GUNZIP_CHUNK
                          : max_output_size;
    uint8_t *buf = malloc(capacity);
    if (buf == NULL) {
        inflateEnd(&strm);
        return FOTA_INSTALL_ERR_DECOMPRESS_FAILED;
    }
    size_t total = 0;

    int zret = Z_OK;
    while (zret != Z_STREAM_END) {
        if (total == capacity) {
            if (capacity >= max_output_size) {
                /* Already at the cap and inflate() still wants more
                 * output space - the decompressed size would exceed
                 * max_output_size. Abort before growing further,
                 * regardless of how much compressed input remains
                 * unread (docs/THREAT_MODEL.md's decompression-bomb
                 * entry). */
                free(buf);
                inflateEnd(&strm);
                return FOTA_INSTALL_ERR_DECOMPRESSED_TOO_LARGE;
            }
            size_t new_capacity = capacity * 2u;
            if (new_capacity > max_output_size) {
                new_capacity = max_output_size;
            }
            uint8_t *bigger = realloc(buf, new_capacity);
            if (bigger == NULL) {
                free(buf);
                inflateEnd(&strm);
                return FOTA_INSTALL_ERR_DECOMPRESS_FAILED;
            }
            buf = bigger;
            capacity = new_capacity;
        }

        strm.next_out = buf + total;
        strm.avail_out = (unsigned int)(capacity - total);

        size_t before = strm.avail_out;
        zret = inflate(&strm, Z_NO_FLUSH);
        total += before - strm.avail_out;

        if (zret != Z_OK && zret != Z_STREAM_END) {
            free(buf);
            inflateEnd(&strm);
            return FOTA_INSTALL_ERR_DECOMPRESS_FAILED;
        }
        if (zret == Z_OK && strm.avail_in == 0 && strm.avail_out > 0) {
            /* No more input and inflate() made no forward progress -
             * truncated stream. */
            free(buf);
            inflateEnd(&strm);
            return FOTA_INSTALL_ERR_DECOMPRESS_FAILED;
        }
    }

    inflateEnd(&strm);
    *out_data = buf;
    *out_len = total;
    return FOTA_INSTALL_OK;
}

/* ---- tar path safety (lexical only, no filesystem access) ---- */

int fota_tar_path_is_safe(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    if (path[0] == '/') {
        return 0; /* absolute path */
    }

    size_t component_start = 0;
    size_t i;
    for (i = 0;; i++) {
        if (path[i] == '/' || path[i] == '\0') {
            size_t component_len = i - component_start;
            if (component_len == 2 && path[component_start] == '.' &&
                path[component_start + 1] == '.') {
                return 0; /* ".." component - path traversal attempt */
            }
            if (path[i] == '\0') {
                break;
            }
            component_start = i + 1;
        }
    }

    return 1;
}

/* ---- tar header parsing (ustar) ---- */

#define FOTA_TAR_BLOCK_SIZE 512u
#define FOTA_TAR_TYPEFLAG_OFFSET 156u
#define FOTA_TAR_LINKNAME_OFFSET 157u
#define FOTA_TAR_LINKNAME_SIZE 100u
#define FOTA_TAR_MAGIC_OFFSET 257u
#define FOTA_TAR_PREFIX_OFFSET 345u
#define FOTA_TAR_PREFIX_SIZE 155u
#define FOTA_TAR_SIZE_OFFSET 124u
#define FOTA_TAR_SIZE_FIELD_SIZE 12u
#define FOTA_TAR_CHKSUM_OFFSET 148u
#define FOTA_TAR_CHKSUM_FIELD_SIZE 8u

/* strnlen is POSIX, not ISO C11 - avoid depending on a feature-test
 * macro for one bounded scan. */
static size_t bounded_strlen(const char *s, size_t max_len) {
    size_t i = 0;
    while (i < max_len && s[i] != '\0') {
        i++;
    }
    return i;
}

static int is_all_zero(const uint8_t *block, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (block[i] != 0) {
            return 0;
        }
    }
    return 1;
}

/* Parses a fixed-length octal ASCII field (NUL/space padded, either
 * leading or trailing) into a size_t. Returns 0 on success. */
static int parse_octal_field(const uint8_t *field, size_t field_len,
                              size_t *out_value) {
    size_t value = 0;
    size_t i;
    int seen_digit = 0;
    for (i = 0; i < field_len; i++) {
        uint8_t c = field[i];
        if (c == '\0' || c == ' ') {
            if (seen_digit) {
                break; /* trailing NUL/space terminator after digits */
            }
            continue; /* leading space padding before digits */
        }
        if (c < '0' || c > '7') {
            return -1;
        }
        seen_digit = 1;
        value = (value << 3) + (size_t)(c - '0');
    }
    if (!seen_digit) {
        return -1;
    }
    *out_value = value;
    return 0;
}

static unsigned long compute_header_checksum(const uint8_t *header) {
    unsigned long sum = 0;
    size_t i;
    for (i = 0; i < FOTA_TAR_BLOCK_SIZE; i++) {
        if (i >= FOTA_TAR_CHKSUM_OFFSET &&
            i < FOTA_TAR_CHKSUM_OFFSET + FOTA_TAR_CHKSUM_FIELD_SIZE) {
            sum += (unsigned char)' '; /* chksum field treated as spaces */
        } else {
            sum += header[i];
        }
    }
    return sum;
}

fota_install_result_t fota_tar_parse(const uint8_t *tar_data, size_t tar_len,
                                      fota_tar_entries_t *out) {
    if (tar_data == NULL || out == NULL) {
        return FOTA_INSTALL_ERR_INVALID_ARG;
    }

    out->entries = NULL;
    out->count = 0;

    size_t capacity = 0;
    size_t offset = 0;
    int end_of_archive = 0;

    while (offset < tar_len) {
        if (tar_len - offset < FOTA_TAR_BLOCK_SIZE) {
            fota_tar_entries_free(out);
            return FOTA_INSTALL_ERR_MALFORMED_TAR; /* truncated header */
        }

        const uint8_t *header = tar_data + offset;
        if (is_all_zero(header, FOTA_TAR_BLOCK_SIZE)) {
            end_of_archive = 1;
            break; /* standard end-of-archive marker */
        }

        size_t stored_chksum;
        if (parse_octal_field(header + FOTA_TAR_CHKSUM_OFFSET,
                               FOTA_TAR_CHKSUM_FIELD_SIZE,
                               &stored_chksum) != 0 ||
            stored_chksum != compute_header_checksum(header)) {
            fota_tar_entries_free(out);
            return FOTA_INSTALL_ERR_MALFORMED_TAR;
        }

        char name[FOTA_TAR_NAME_MAX + 1];
        memcpy(name, header, FOTA_TAR_NAME_MAX);
        name[FOTA_TAR_NAME_MAX] = '\0';
        /* name may legitimately fill all 100 bytes with no NUL - trim
         * defensively to the declared field length either way. */
        size_t name_len = bounded_strlen(name, FOTA_TAR_NAME_MAX);
        name[name_len] = '\0';

        if (!is_all_zero(header + FOTA_TAR_PREFIX_OFFSET,
                          FOTA_TAR_PREFIX_SIZE)) {
            /* This project's own tarballs never need the ustar "prefix"
             * long-name extension (all paths are short) - reject rather
             * than silently mishandle a name we're not prepared for. */
            fota_tar_entries_free(out);
            return FOTA_INSTALL_ERR_UNSUPPORTED_ENTRY;
        }

        if (!fota_tar_path_is_safe(name)) {
            fota_tar_entries_free(out);
            return FOTA_INSTALL_ERR_UNSAFE_PATH;
        }

        uint8_t typeflag = header[FOTA_TAR_TYPEFLAG_OFFSET];
        fota_tar_entry_type_t entry_type;
        if (typeflag == '0' || typeflag == '\0') {
            entry_type = FOTA_TAR_ENTRY_FILE;
        } else if (typeflag == '5') {
            entry_type = FOTA_TAR_ENTRY_DIRECTORY;
        } else {
            /* Symlinks ('2'), hardlinks ('1'), device/fifo entries, GNU
             * long-name ('L')/pax ('x','g') extensions, and anything
             * else are all rejected outright - see installer.h. */
            fota_tar_entries_free(out);
            return FOTA_INSTALL_ERR_UNSUPPORTED_ENTRY;
        }

        size_t entry_size = 0;
        if (parse_octal_field(header + FOTA_TAR_SIZE_OFFSET,
                               FOTA_TAR_SIZE_FIELD_SIZE, &entry_size) != 0) {
            fota_tar_entries_free(out);
            return FOTA_INSTALL_ERR_MALFORMED_TAR;
        }
        if (entry_type == FOTA_TAR_ENTRY_DIRECTORY) {
            entry_size = 0; /* directory entries carry no data blocks */
        }

        size_t data_blocks = (entry_size + FOTA_TAR_BLOCK_SIZE - 1u) /
                              FOTA_TAR_BLOCK_SIZE;
        size_t data_offset = offset + FOTA_TAR_BLOCK_SIZE;
        size_t next_offset = data_offset + data_blocks * FOTA_TAR_BLOCK_SIZE;
        if (next_offset < offset || next_offset > tar_len) {
            /* overflow or the declared size runs past the buffer */
            fota_tar_entries_free(out);
            return FOTA_INSTALL_ERR_MALFORMED_TAR;
        }

        if (out->count == capacity) {
            size_t new_capacity = capacity == 0 ? 16 : capacity * 2u;
            fota_tar_entry_t *bigger =
                realloc(out->entries, new_capacity * sizeof(*out->entries));
            if (bigger == NULL) {
                fota_tar_entries_free(out);
                return FOTA_INSTALL_ERR_IO;
            }
            out->entries = bigger;
            capacity = new_capacity;
        }

        fota_tar_entry_t *entry = &out->entries[out->count++];
        memcpy(entry->path, name, name_len + 1);
        entry->type = entry_type;
        entry->data = tar_data + data_offset;
        entry->size = entry_size;

        offset = next_offset;
    }

    if (!end_of_archive) {
        /* Ran off the end without ever seeing the end-of-archive
         * marker - truncated archive. */
        fota_tar_entries_free(out);
        return FOTA_INSTALL_ERR_MALFORMED_TAR;
    }

    return FOTA_INSTALL_OK;
}

void fota_tar_entries_free(fota_tar_entries_t *entries) {
    if (entries == NULL) {
        return;
    }
    free(entries->entries);
    entries->entries = NULL;
    entries->count = 0;
}

/* ---- minimal manifest.json parsing ---- */
/* Deliberately narrow: only extracts the "files" array's "path"/"sha256"
 * string pairs from JSON produced by this project's own manifest.py -
 * not a general JSON parser (CLAUDE.md ground rule 5). Anything that
 * doesn't match the expected shape is rejected. */

#define FOTA_MANIFEST_MAX_PATH_LEN 255u
#define FOTA_MANIFEST_SHA256_HEX_LEN 64u

typedef struct {
    char path[FOTA_MANIFEST_MAX_PATH_LEN + 1];
    char sha256_hex[FOTA_MANIFEST_SHA256_HEX_LEN + 1];
} fota_manifest_file_t;

typedef struct {
    fota_manifest_file_t *files;
    size_t count;
} fota_manifest_files_t;

static void manifest_files_free(fota_manifest_files_t *files) {
    free(files->files);
    files->files = NULL;
    files->count = 0;
}

/* Extracts a JSON string value (content between the next unescaped
 * quote pair) starting at *pos, unescaping only the small set of
 * escapes we expect (\", \\, \/). Rejects anything else, including
 * \uXXXX, as out of scope for our own generator's output. Writes into
 * out (capacity out_cap, including room for the NUL) and NUL-terminates.
 * Returns 0 on success, -1 on any parse/overflow error. */
static int extract_json_string(const char *buf, size_t buf_len, size_t *pos,
                                char *out, size_t out_cap) {
    size_t i = *pos;
    if (i >= buf_len || buf[i] != '"') {
        return -1;
    }
    i++;

    size_t out_len = 0;
    while (i < buf_len && buf[i] != '"') {
        char c = buf[i];
        if (c == '\\') {
            if (i + 1 >= buf_len) {
                return -1;
            }
            char next = buf[i + 1];
            if (next != '"' && next != '\\' && next != '/') {
                return -1; /* unsupported escape */
            }
            c = next;
            i += 2;
        } else {
            i++;
        }
        if (out_len + 1 >= out_cap) {
            return -1; /* value too long */
        }
        out[out_len++] = c;
    }
    if (i >= buf_len) {
        return -1; /* unterminated string */
    }
    i++; /* closing quote */

    out[out_len] = '\0';
    *pos = i;
    return 0;
}

static void skip_json_whitespace(const char *buf, size_t buf_len,
                                  size_t *pos) {
    while (*pos < buf_len && (buf[*pos] == ' ' || buf[*pos] == '\t' ||
                               buf[*pos] == '\n' || buf[*pos] == '\r')) {
        (*pos)++;
    }
}

static fota_install_result_t parse_manifest_files(
    const char *buf, size_t buf_len, fota_manifest_files_t *out) {
    out->files = NULL;
    out->count = 0;

    const char *key = "\"files\"";
    size_t key_len = strlen(key);
    size_t i;
    size_t files_key_pos = (size_t)-1;
    for (i = 0; i + key_len <= buf_len; i++) {
        if (memcmp(buf + i, key, key_len) == 0) {
            files_key_pos = i;
            break;
        }
    }
    if (files_key_pos == (size_t)-1) {
        return FOTA_INSTALL_ERR_MANIFEST_PARSE; /* no "files" key at all */
    }

    size_t pos = files_key_pos + key_len;
    skip_json_whitespace(buf, buf_len, &pos);
    if (pos >= buf_len || buf[pos] != ':') {
        return FOTA_INSTALL_ERR_MANIFEST_PARSE;
    }
    pos++;
    skip_json_whitespace(buf, buf_len, &pos);
    if (pos >= buf_len || buf[pos] != '[') {
        return FOTA_INSTALL_ERR_MANIFEST_PARSE;
    }
    pos++;

    size_t capacity = 0;
    for (;;) {
        skip_json_whitespace(buf, buf_len, &pos);
        if (pos >= buf_len) {
            manifest_files_free(out);
            return FOTA_INSTALL_ERR_MANIFEST_PARSE;
        }
        if (buf[pos] == ']') {
            pos++;
            break; /* end of files array */
        }
        if (buf[pos] == ',') {
            pos++;
            continue;
        }
        if (buf[pos] != '{') {
            manifest_files_free(out);
            return FOTA_INSTALL_ERR_MANIFEST_PARSE;
        }
        pos++;

        char path[FOTA_MANIFEST_MAX_PATH_LEN + 1];
        char sha256_hex[FOTA_MANIFEST_SHA256_HEX_LEN + 1];
        int have_path = 0;
        int have_sha256 = 0;

        for (;;) {
            skip_json_whitespace(buf, buf_len, &pos);
            if (pos >= buf_len) {
                manifest_files_free(out);
                return FOTA_INSTALL_ERR_MANIFEST_PARSE;
            }
            if (buf[pos] == '}') {
                pos++;
                break;
            }
            if (buf[pos] == ',') {
                pos++;
                continue;
            }

            char field_key[16];
            if (extract_json_string(buf, buf_len, &pos, field_key,
                                     sizeof(field_key)) != 0) {
                manifest_files_free(out);
                return FOTA_INSTALL_ERR_MANIFEST_PARSE;
            }
            skip_json_whitespace(buf, buf_len, &pos);
            if (pos >= buf_len || buf[pos] != ':') {
                manifest_files_free(out);
                return FOTA_INSTALL_ERR_MANIFEST_PARSE;
            }
            pos++;
            skip_json_whitespace(buf, buf_len, &pos);

            if (strcmp(field_key, "path") == 0) {
                if (extract_json_string(buf, buf_len, &pos, path,
                                         sizeof(path)) != 0) {
                    manifest_files_free(out);
                    return FOTA_INSTALL_ERR_MANIFEST_PARSE;
                }
                have_path = 1;
            } else if (strcmp(field_key, "sha256") == 0) {
                if (extract_json_string(buf, buf_len, &pos, sha256_hex,
                                         sizeof(sha256_hex)) != 0 ||
                    strlen(sha256_hex) != FOTA_MANIFEST_SHA256_HEX_LEN) {
                    manifest_files_free(out);
                    return FOTA_INSTALL_ERR_MANIFEST_PARSE;
                }
                have_sha256 = 1;
            } else {
                manifest_files_free(out);
                return FOTA_INSTALL_ERR_MANIFEST_PARSE; /* unexpected key */
            }
        }

        if (!have_path || !have_sha256) {
            manifest_files_free(out);
            return FOTA_INSTALL_ERR_MANIFEST_PARSE;
        }

        if (out->count == capacity) {
            size_t new_capacity = capacity == 0 ? 8 : capacity * 2u;
            fota_manifest_file_t *bigger =
                realloc(out->files, new_capacity * sizeof(*out->files));
            if (bigger == NULL) {
                manifest_files_free(out);
                return FOTA_INSTALL_ERR_IO;
            }
            out->files = bigger;
            capacity = new_capacity;
        }
        fota_manifest_file_t *entry = &out->files[out->count++];
        memcpy(entry->path, path, sizeof(path));
        memcpy(entry->sha256_hex, sha256_hex, sizeof(sha256_hex));
    }

    return FOTA_INSTALL_OK;
}

static void bytes_to_hex_lower(const uint8_t *bytes, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 0x0Fu];
    }
    out[len * 2] = '\0';
}

static const fota_tar_entry_t *find_entry(const fota_tar_entries_t *entries,
                                           const char *path) {
    size_t i;
    for (i = 0; i < entries->count; i++) {
        if (entries->entries[i].type == FOTA_TAR_ENTRY_FILE &&
            strcmp(entries->entries[i].path, path) == 0) {
            return &entries->entries[i];
        }
    }
    return NULL;
}

fota_install_result_t fota_verify_manifest(
    const fota_tar_entries_t *entries) {
    if (entries == NULL) {
        return FOTA_INSTALL_ERR_INVALID_ARG;
    }

    const fota_tar_entry_t *manifest_entry = find_entry(entries, "manifest.json");
    if (manifest_entry == NULL) {
        return FOTA_INSTALL_ERR_MANIFEST_MISSING;
    }

    fota_manifest_files_t manifest_files;
    fota_install_result_t result = parse_manifest_files(
        (const char *)manifest_entry->data, manifest_entry->size,
        &manifest_files);
    if (result != FOTA_INSTALL_OK) {
        return result;
    }

    /* Track which non-manifest file entries get matched, so we can
     * detect "extra file present in tarball but not listed in
     * manifest" afterwards - not just "listed file missing from
     * tarball". */
    size_t file_entry_count = 0;
    size_t i;
    for (i = 0; i < entries->count; i++) {
        if (entries->entries[i].type == FOTA_TAR_ENTRY_FILE &&
            strcmp(entries->entries[i].path, "manifest.json") != 0) {
            file_entry_count++;
        }
    }

    uint8_t *matched = calloc(entries->count > 0 ? entries->count : 1, 1);
    if (matched == NULL) {
        manifest_files_free(&manifest_files);
        return FOTA_INSTALL_ERR_IO;
    }

    size_t matched_count = 0;
    for (i = 0; i < manifest_files.count; i++) {
        const fota_manifest_file_t *mf = &manifest_files.files[i];

        size_t entry_index = (size_t)-1;
        size_t j;
        for (j = 0; j < entries->count; j++) {
            if (entries->entries[j].type == FOTA_TAR_ENTRY_FILE &&
                strcmp(entries->entries[j].path, mf->path) == 0) {
                entry_index = j;
                break;
            }
        }
        if (entry_index == (size_t)-1) {
            free(matched);
            manifest_files_free(&manifest_files);
            return FOTA_INSTALL_ERR_MANIFEST_MISMATCH; /* listed but absent */
        }

        const fota_tar_entry_t *fe = &entries->entries[entry_index];
        uint8_t digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;
        if (EVP_Digest(fe->data, fe->size, digest, &digest_len, EVP_sha256(),
                        NULL) != 1) {
            free(matched);
            manifest_files_free(&manifest_files);
            return FOTA_INSTALL_ERR_IO;
        }

        char digest_hex[FOTA_MANIFEST_SHA256_HEX_LEN + 1];
        bytes_to_hex_lower(digest, digest_len, digest_hex);

        if (strcmp(digest_hex, mf->sha256_hex) != 0) {
            free(matched);
            manifest_files_free(&manifest_files);
            return FOTA_INSTALL_ERR_MANIFEST_MISMATCH; /* content hash mismatch */
        }

        matched[entry_index] = 1;
        matched_count++;
    }

    manifest_files_free(&manifest_files);

    if (matched_count != file_entry_count) {
        /* At least one file entry in the tarball was never matched to
         * a manifest listing - an extra, unaccounted-for file. */
        free(matched);
        return FOTA_INSTALL_ERR_MANIFEST_MISMATCH;
    }

    free(matched);
    return FOTA_INSTALL_OK;
}

/* ---- full pipeline: decompress + parse + verify + write to disk ---- */

static int ensure_parent_dirs(const char *install_dir, const char *rel_path) {
    char full_path[4096];
    int written =
        snprintf(full_path, sizeof(full_path), "%s/%s", install_dir, rel_path);
    if (written < 0 || (size_t)written >= sizeof(full_path)) {
        return -1;
    }

    char *slash = full_path + strlen(install_dir) + 1;
    for (;;) {
        slash = strchr(slash, '/');
        if (slash == NULL) {
            break;
        }
        *slash = '\0';
        if (mkdir(full_path, 0755) != 0 && errno != EEXIST) {
            return -1;
        }
        *slash = '/';
        slash++;
    }
    return 0;
}

static int write_entry_file(const char *install_dir,
                             const fota_tar_entry_t *entry) {
    if (ensure_parent_dirs(install_dir, entry->path) != 0) {
        return -1;
    }

    char full_path[4096];
    int written = snprintf(full_path, sizeof(full_path), "%s/%s", install_dir,
                            entry->path);
    if (written < 0 || (size_t)written >= sizeof(full_path)) {
        return -1;
    }

    FILE *fp = fopen(full_path, "wb");
    if (fp == NULL) {
        return -1;
    }
    size_t written_bytes = entry->size > 0
                                ? fwrite(entry->data, 1, entry->size, fp)
                                : 0;
    int close_ok = (fclose(fp) == 0);
    if (written_bytes != entry->size || !close_ok) {
        return -1;
    }
    return 0;
}

fota_install_result_t fota_installer_extract(const uint8_t *tar_gz_data,
                                              size_t tar_gz_len,
                                              const char *install_dir) {
    if (tar_gz_data == NULL || install_dir == NULL) {
        return FOTA_INSTALL_ERR_INVALID_ARG;
    }

    uint8_t *tar_data = NULL;
    size_t tar_len = 0;
    fota_install_result_t result =
        fota_gunzip(tar_gz_data, tar_gz_len, FOTA_INSTALLER_MAX_DECOMPRESSED_SIZE,
                    &tar_data, &tar_len);
    if (result != FOTA_INSTALL_OK) {
        return result;
    }

    fota_tar_entries_t entries;
    result = fota_tar_parse(tar_data, tar_len, &entries);
    if (result != FOTA_INSTALL_OK) {
        free(tar_data);
        return result;
    }

    result = fota_verify_manifest(&entries);
    if (result != FOTA_INSTALL_OK) {
        fota_tar_entries_free(&entries);
        free(tar_data);
        return result;
    }

    /* Everything validated - now, and only now, write to disk. */
    size_t i;
    for (i = 0; i < entries.count; i++) {
        const fota_tar_entry_t *entry = &entries.entries[i];
        if (entry->type != FOTA_TAR_ENTRY_FILE) {
            continue;
        }
        /* manifest.json is packaging-internal metadata, already consumed
         * by fota_verify_manifest above - it's not a firmware file and
         * doesn't get installed. */
        if (strcmp(entry->path, "manifest.json") == 0) {
            continue;
        }
        if (write_entry_file(install_dir, entry) != 0) {
            fota_tar_entries_free(&entries);
            free(tar_data);
            return FOTA_INSTALL_ERR_IO;
        }
    }

    fota_tar_entries_free(&entries);
    free(tar_data);
    return FOTA_INSTALL_OK;
}
