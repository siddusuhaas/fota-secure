#ifndef FOTA_SECURE_INSTALLER_H
#define FOTA_SECURE_INSTALLER_H

/* Decompresses and extracts the firmware tarball (the decrypted payload,
 * see docs/FORMAT_SPEC.md's Payload Section), verifies every file
 * against manifest.json's per-file SHA-256 list, and writes the result
 * to an install directory. Nothing is written to disk unless the whole
 * package validates - see fota_installer_extract's doc comment.
 *
 * Deliberately narrow-scope tar/JSON handling: this only needs to
 * understand tarballs and manifest.json produced by this project's own
 * packager (docs/ARCHITECTURE.md's tarball.py/manifest.py), not tar or
 * JSON in general - see CLAUDE.md ground rule 5 (single platform, no
 * speculative generality). Anything that doesn't match the expected
 * shape is rejected rather than guessed at. */

#include <stddef.h>
#include <stdint.h>

typedef enum {
    FOTA_INSTALL_OK = 0,
    FOTA_INSTALL_ERR_INVALID_ARG,
    FOTA_INSTALL_ERR_DECOMPRESS_FAILED,
    FOTA_INSTALL_ERR_DECOMPRESSED_TOO_LARGE,
    FOTA_INSTALL_ERR_MALFORMED_TAR,
    FOTA_INSTALL_ERR_UNSAFE_PATH,
    FOTA_INSTALL_ERR_UNSUPPORTED_ENTRY,
    FOTA_INSTALL_ERR_MANIFEST_MISSING,
    FOTA_INSTALL_ERR_MANIFEST_PARSE,
    FOTA_INSTALL_ERR_MANIFEST_MISMATCH,
    FOTA_INSTALL_ERR_IO
} fota_install_result_t;

/* Default cap fota_installer_extract uses for fota_gunzip's
 * max_output_size: a defensive bound against decompression-bomb style
 * resource exhaustion (a small compressed input inflating into
 * something far larger than any real firmware image needs to be) - see
 * docs/THREAT_MODEL.md. 512 MiB is a generous v1 default for a single
 * firmware bundle; tune to your actual maximum expected package size. */
#define FOTA_INSTALLER_MAX_DECOMPRESSED_SIZE ((size_t)512u * 1024u * 1024u)

/* ---- gzip decompression (zlib) ---- */

/* Decompresses gz_data (gzip format) fully into a heap buffer, aborting
 * with FOTA_INSTALL_ERR_DECOMPRESSED_TOO_LARGE before allocating past
 * max_output_size if the (possibly attacker-controlled) compressed
 * input would inflate beyond it. Caller must free(*out_data) on
 * FOTA_INSTALL_OK. */
fota_install_result_t fota_gunzip(const uint8_t *gz_data, size_t gz_len,
                                   size_t max_output_size, uint8_t **out_data,
                                   size_t *out_len);

/* ---- in-memory tar parsing - no filesystem access ---- */

#define FOTA_TAR_NAME_MAX 100u /* ustar name field size */

typedef enum {
    FOTA_TAR_ENTRY_FILE,
    FOTA_TAR_ENTRY_DIRECTORY
    /* Symlinks and every other typeflag are rejected during parsing
     * (FOTA_INSTALL_ERR_UNSUPPORTED_ENTRY), not represented here - this
     * project's own tarballs never contain symlinks, and honoring an
     * untrusted symlink entry during extraction is a classic
     * vulnerability class (see docs/THREAT_MODEL.md). */
} fota_tar_entry_type_t;

typedef struct {
    char path[FOTA_TAR_NAME_MAX + 1]; /* NUL-terminated; already
                                          validated as a safe relative
                                          path (no "..", not absolute) */
    fota_tar_entry_type_t type;
    const uint8_t *data; /* points into the caller-owned tar buffer */
    size_t size;
} fota_tar_entry_t;

typedef struct {
    fota_tar_entry_t *entries;
    size_t count;
} fota_tar_entries_t;

/* Returns 1 if path is safe to extract under an install directory
 * (non-empty, not absolute, no ".." path component anywhere), 0
 * otherwise. Purely lexical - never touches the filesystem. */
int fota_tar_path_is_safe(const char *path);

/* Parses tar_data (raw, already-decompressed tar bytes) into *out.
 * Every entry's header checksum is validated; any entry with an
 * unsafe path, any symlink or other non-file/non-directory typeflag,
 * or any malformed/truncated header causes the whole parse to fail -
 * no partial results. Caller must fota_tar_entries_free(out) on
 * FOTA_INSTALL_OK. */
fota_install_result_t fota_tar_parse(const uint8_t *tar_data, size_t tar_len,
                                      fota_tar_entries_t *out);

void fota_tar_entries_free(fota_tar_entries_t *entries);

/* ---- manifest verification - no filesystem access ---- */

/* Finds manifest.json among entries, parses its "files" list, and
 * confirms exact set equality against the OTHER file entries present:
 * every manifest-listed path must exist among entries with a matching
 * SHA-256, and no file entry may exist that isn't listed in the
 * manifest (docs/FORMAT_SPEC.md's Manifest section). */
fota_install_result_t fota_verify_manifest(const fota_tar_entries_t *entries);

/* ---- full pipeline: decompress + parse + verify + write to disk ---- */

/* Runs the full extract pipeline. install_dir must already exist.
 * Nothing is written to install_dir unless decompression, tar parsing,
 * AND manifest verification all succeed first - a bad package fails
 * closed with no partial install. */
fota_install_result_t fota_installer_extract(const uint8_t *tar_gz_data,
                                              size_t tar_gz_len,
                                              const char *install_dir);

#endif /* FOTA_SECURE_INSTALLER_H */
