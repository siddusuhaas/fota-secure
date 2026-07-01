/* valid.tar.gz is produced by the real Python packager (tarball.py/
 * manifest.py) via generate_installer_fixtures.py - genuine interop.
 * The malicious/malformed fixtures are hand-crafted with Python's
 * tarfile module to exercise attacks our own packager never produces. */

#include "../src/installer.h"

#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int tests_run = 0;
static int tests_failed = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        tests_run++;                                                         \
        if (!(cond)) {                                                       \
            tests_failed++;                                                  \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        }                                                                     \
    } while (0)

static char *join_path(const char *dir, const char *name) {
    size_t len = strlen(dir) + strlen(name) + 2;
    char *out = malloc(len);
    assert(out != NULL);
    snprintf(out, len, "%s/%s", dir, name);
    return out;
}

static uint8_t *read_file(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "cannot open fixture %s\n", path);
        exit(2);
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)size > 0 ? (size_t)size : 1);
    assert(buf != NULL);
    size_t n = fread(buf, 1, (size_t)size, fp);
    fclose(fp);
    assert(n == (size_t)size);
    *out_len = (size_t)size;
    return buf;
}

/* Counts regular files under dir, recursively - used to confirm a
 * failed extraction left the install directory untouched. */
static int count_files_recursive(const char *dir) {
    DIR *d = opendir(dir);
    if (d == NULL) {
        return -1;
    }
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        char *child = join_path(dir, ent->d_name);
        struct stat st;
        if (stat(child, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                int sub = count_files_recursive(child);
                if (sub >= 0) {
                    count += sub;
                }
            } else {
                count++;
            }
        }
        free(child);
    }
    closedir(d);
    return count;
}

/* ---- fota_tar_path_is_safe ---- */

static void test_path_is_safe(void) {
    CHECK(fota_tar_path_is_safe("kernel.bin") == 1);
    CHECK(fota_tar_path_is_safe("config/settings.ini") == 1);
    CHECK(fota_tar_path_is_safe("a/b/c/d.txt") == 1);

    CHECK(fota_tar_path_is_safe("") == 0);
    CHECK(fota_tar_path_is_safe("/etc/passwd") == 0);        /* absolute */
    CHECK(fota_tar_path_is_safe("../etc/passwd") == 0);      /* traversal */
    CHECK(fota_tar_path_is_safe("a/../../etc/passwd") == 0); /* traversal */
    CHECK(fota_tar_path_is_safe("a/..") == 0);               /* traversal */
    CHECK(fota_tar_path_is_safe("..") == 0);                 /* traversal */
    CHECK(fota_tar_path_is_safe(NULL) == 0);

    /* "..foo" and "foo.." are NOT traversal - only an exact ".."
     * component is rejected. */
    CHECK(fota_tar_path_is_safe("..foo/bar") == 1);
    CHECK(fota_tar_path_is_safe("foo../bar") == 1);
}

/* ---- gunzip ---- */

static void test_gunzip_rejects_non_gzip_data(void) {
    uint8_t garbage[16];
    memset(garbage, 0x42, sizeof(garbage));

    uint8_t *out_data = NULL;
    size_t out_len = 0;
    fota_install_result_t result =
        fota_gunzip(garbage, sizeof(garbage), FOTA_INSTALLER_MAX_DECOMPRESSED_SIZE,
                    &out_data, &out_len);

    CHECK(result == FOTA_INSTALL_ERR_DECOMPRESS_FAILED);
    CHECK(out_data == NULL);
}

/* Real valid.tar.gz decompresses to well over 10 bytes - passing a tiny
 * max_output_size proves the cap actually aborts before over-allocating,
 * without needing a genuine multi-hundred-MB decompression bomb fixture. */
static void test_gunzip_rejects_output_over_cap(const char *fixtures_dir) {
    char *fixture_path = join_path(fixtures_dir, "valid.tar.gz");
    size_t gz_len;
    uint8_t *gz_data = read_file(fixture_path, &gz_len);
    free(fixture_path);

    uint8_t *out_data = NULL;
    size_t out_len = 0;
    fota_install_result_t result =
        fota_gunzip(gz_data, gz_len, 10, &out_data, &out_len);

    CHECK(result == FOTA_INSTALL_ERR_DECOMPRESSED_TOO_LARGE);
    CHECK(out_data == NULL);

    free(gz_data);
}

/* ---- full pipeline against real + malicious fixtures ---- */

static void extract_into_fresh_dir(const char *fixtures_dir,
                                    const char *scratch_dir,
                                    const char *fixture_name,
                                    const char *install_subdir,
                                    fota_install_result_t expected) {
    char *fixture_path = join_path(fixtures_dir, fixture_name);
    size_t tar_gz_len;
    uint8_t *tar_gz_data = read_file(fixture_path, &tar_gz_len);
    free(fixture_path);

    char *install_dir = join_path(scratch_dir, install_subdir);
    mkdir(install_dir, 0755);

    fota_install_result_t result =
        fota_installer_extract(tar_gz_data, tar_gz_len, install_dir);
    CHECK(result == expected);

    int file_count = count_files_recursive(install_dir);
    if (expected == FOTA_INSTALL_OK) {
        CHECK(file_count == 3); /* kernel.bin, rootfs.img, config/settings.ini */
    } else {
        /* Fail-closed: nothing should ever be written for a package
         * that doesn't fully validate. */
        CHECK(file_count == 0);
    }

    free(install_dir);
    free(tar_gz_data);
}

static void test_valid_package_extracts_successfully(const char *fixtures_dir,
                                                       const char *scratch_dir) {
    extract_into_fresh_dir(fixtures_dir, scratch_dir, "valid.tar.gz",
                            "install_valid", FOTA_INSTALL_OK);
}

static void test_path_traversal_rejected(const char *fixtures_dir,
                                          const char *scratch_dir) {
    extract_into_fresh_dir(fixtures_dir, scratch_dir, "traversal.tar.gz",
                            "install_traversal", FOTA_INSTALL_ERR_UNSAFE_PATH);
}

static void test_symlink_entry_rejected(const char *fixtures_dir,
                                         const char *scratch_dir) {
    extract_into_fresh_dir(fixtures_dir, scratch_dir, "symlink.tar.gz",
                            "install_symlink",
                            FOTA_INSTALL_ERR_UNSUPPORTED_ENTRY);
}

static void test_manifest_lists_missing_file_rejected(
    const char *fixtures_dir, const char *scratch_dir) {
    extract_into_fresh_dir(fixtures_dir, scratch_dir,
                            "manifest_missing_file.tar.gz",
                            "install_manifest_missing",
                            FOTA_INSTALL_ERR_MANIFEST_MISMATCH);
}

static void test_extra_unlisted_file_rejected(const char *fixtures_dir,
                                               const char *scratch_dir) {
    extract_into_fresh_dir(fixtures_dir, scratch_dir,
                            "extra_unlisted_file.tar.gz",
                            "install_extra_unlisted",
                            FOTA_INSTALL_ERR_MANIFEST_MISMATCH);
}

static void test_hash_mismatch_rejected(const char *fixtures_dir,
                                        const char *scratch_dir) {
    extract_into_fresh_dir(fixtures_dir, scratch_dir, "hash_mismatch.tar.gz",
                            "install_hash_mismatch",
                            FOTA_INSTALL_ERR_MANIFEST_MISMATCH);
}

static void test_truncated_tar_rejected(const char *fixtures_dir,
                                        const char *scratch_dir) {
    char *fixture_path = join_path(fixtures_dir, "valid.tar.gz");
    size_t tar_gz_len;
    uint8_t *tar_gz_data = read_file(fixture_path, &tar_gz_len);
    free(fixture_path);

    /* Decompress for real, then chop the plaintext tar short, then
     * confirm fota_tar_parse (not fota_gunzip) catches the truncation. */
    uint8_t *tar_data = NULL;
    size_t tar_len = 0;
    fota_install_result_t gz_result =
        fota_gunzip(tar_gz_data, tar_gz_len, FOTA_INSTALLER_MAX_DECOMPRESSED_SIZE,
                    &tar_data, &tar_len);
    CHECK(gz_result == FOTA_INSTALL_OK);

    /* Real tar output is padded out to a whole "record" (a multiple of
     * 512 bytes, historically a large blocking factor) with trailing
     * all-zero blocks - truncating anywhere in that padding still looks
     * like a complete, validly-terminated archive to a correct parser,
     * since it stops at the first all-zero block regardless of what
     * (zero) bytes follow. Cut to a small fixed length instead, landing
     * inside the first entry's header/data, to actually corrupt the
     * archive rather than just shortening its trailing padding. */
    size_t truncated_len = 600;
    CHECK(tar_len > truncated_len);
    fota_tar_entries_t entries;
    fota_install_result_t result =
        fota_tar_parse(tar_data, truncated_len, &entries);
    CHECK(result == FOTA_INSTALL_ERR_MALFORMED_TAR);

    free(tar_data);
    free(tar_gz_data);
    (void)scratch_dir;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <fixtures-dir> <scratch-dir>\n", argv[0]);
        return 2;
    }
    const char *fixtures_dir = argv[1];
    const char *scratch_dir = argv[2];

    test_path_is_safe();
    test_gunzip_rejects_non_gzip_data();
    test_gunzip_rejects_output_over_cap(fixtures_dir);

    test_valid_package_extracts_successfully(fixtures_dir, scratch_dir);
    test_path_traversal_rejected(fixtures_dir, scratch_dir);
    test_symlink_entry_rejected(fixtures_dir, scratch_dir);
    test_manifest_lists_missing_file_rejected(fixtures_dir, scratch_dir);
    test_extra_unlisted_file_rejected(fixtures_dir, scratch_dir);
    test_hash_mismatch_rejected(fixtures_dir, scratch_dir);
    test_truncated_tar_rejected(fixtures_dir, scratch_dir);

    printf("%d/%d tests passed\n", tests_run - tests_failed, tests_run);
    return tests_failed == 0 ? 0 : 1;
}
