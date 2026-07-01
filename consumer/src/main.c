/* Orchestrates the full consumer flow per docs/ARCHITECTURE.md's
 * consumer flow section: parse header -> version/downgrade check ->
 * disk space check -> verify signature -> unwrap key -> decrypt ->
 * extract+install. Exit codes per docs/FORMAT_SPEC.md's Exit Codes
 * table. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/statvfs.h>

#include "config.h"
#include "fcrypto.h"
#include "header.h"
#include "installer.h"
#include "version.h"

#define FOTA_EXIT_SUCCESS 0
#define FOTA_EXIT_GENERIC_FAILURE 1
#define FOTA_EXIT_UP_TO_DATE 2
#define FOTA_EXIT_MALFORMED_HEADER 3
#define FOTA_EXIT_PLATFORM_MISMATCH 4
#define FOTA_EXIT_SIGNATURE_FAILED 5
#define FOTA_EXIT_DOWNGRADE_BLOCKED 6
#define FOTA_EXIT_INSUFFICIENT_DISK_SPACE 7
#define FOTA_EXIT_DECRYPTION_FAILED 8
#define FOTA_EXIT_INSTALLER_REJECTED 9

static uint8_t *read_all(FILE *fp, size_t *out_len) {
    size_t capacity = 65536;
    size_t total = 0;
    uint8_t *buf = malloc(capacity);
    if (buf == NULL) {
        return NULL;
    }

    for (;;) {
        if (total == capacity) {
            size_t new_capacity = capacity * 2u;
            uint8_t *bigger = realloc(buf, new_capacity);
            if (bigger == NULL) {
                free(buf);
                return NULL;
            }
            buf = bigger;
            capacity = new_capacity;
        }
        size_t n = fread(buf + total, 1, capacity - total, fp);
        total += n;
        if (n == 0) {
            break;
        }
    }
    if (ferror(fp)) {
        free(buf);
        return NULL;
    }

    *out_len = total;
    return buf;
}

/* platform_tag is a fixed-length byte buffer with no guaranteed NUL
 * terminator (docs/FORMAT_SPEC.md's note) - compare byte-for-byte
 * against the configured tag, NUL-padded to the same width, rather than
 * using strcmp on either side. */
static int platform_tag_matches(const uint8_t *header_tag) {
    uint8_t expected[FOTA_PLATFORM_TAG_SIZE] = {0};
    size_t configured_len = strlen(FOTA_CONFIG_PLATFORM_TAG);
    if (configured_len > FOTA_PLATFORM_TAG_SIZE) {
        return 0; /* misconfigured - can never match, fail closed */
    }
    memcpy(expected, FOTA_CONFIG_PLATFORM_TAG, configured_len);
    return memcmp(header_tag, expected, FOTA_PLATFORM_TAG_SIZE) == 0;
}

/* Extension point for v1: the one supported platform's post-install
 * action, if any. See docs/FORMAT_SPEC.md's "Explicit Extension Point"
 * section - multi-platform support replaces this with a small table
 * keyed by platform_tag. GENERIC has no post-install action. */
static void platform_post_install_hook(void) {
    /* no-op for GENERIC */
}

/* Maps an installer-level failure to an exit code per
 * docs/FORMAT_SPEC.md's Exit Codes table. Only the four rejection
 * reasons that table's exit code 9 explicitly names (path traversal,
 * disallowed symlink, decompression size exceeded, manifest/content
 * mismatch - the last also covering a missing/unparseable manifest.json,
 * which is the same underlying "manifest didn't check out" concern) map
 * to 9; other installer failures (malformed tar structure, a gzip
 * stream that doesn't decode at all, I/O errors) are not content the
 * package was deliberately shaped to smuggle past validation, and stay
 * under exit code 1 (generic failure). */
static int install_result_to_exit_code(fota_install_result_t result) {
    switch (result) {
    case FOTA_INSTALL_ERR_UNSAFE_PATH:
    case FOTA_INSTALL_ERR_UNSUPPORTED_ENTRY:
    case FOTA_INSTALL_ERR_DECOMPRESSED_TOO_LARGE:
    case FOTA_INSTALL_ERR_MANIFEST_MISSING:
    case FOTA_INSTALL_ERR_MANIFEST_PARSE:
    case FOTA_INSTALL_ERR_MANIFEST_MISMATCH:
        return FOTA_EXIT_INSTALLER_REJECTED;
    default:
        return FOTA_EXIT_GENERIC_FAILURE;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <package-path|-> [--downgrade-secret <secret>]\n",
                argv[0]);
        return FOTA_EXIT_GENERIC_FAILURE;
    }

    const char *input_path = argv[1];
    const char *downgrade_secret = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--downgrade-secret") == 0 && i + 1 < argc) {
            downgrade_secret = argv[i + 1];
            i++;
        }
    }

    FILE *input_fp;
    int input_is_stdin = (strcmp(input_path, "-") == 0);
    if (input_is_stdin) {
        input_fp = stdin;
    } else {
        input_fp = fopen(input_path, "rb");
        if (input_fp == NULL) {
            fprintf(stderr, "cannot open %s\n", input_path);
            return FOTA_EXIT_GENERIC_FAILURE;
        }
    }

    size_t data_len = 0;
    uint8_t *data = read_all(input_fp, &data_len);
    if (!input_is_stdin) {
        fclose(input_fp);
    }
    if (data == NULL) {
        fprintf(stderr, "failed to read input\n");
        return FOTA_EXIT_GENERIC_FAILURE;
    }

    /* ---- header parse ---- */
    fota_header_t header;
    if (fota_header_parse(data, data_len, &header) != FOTA_HEADER_OK) {
        free(data);
        return FOTA_EXIT_MALFORMED_HEADER;
    }

    if (!platform_tag_matches(header.platform_tag)) {
        free(data);
        return FOTA_EXIT_PLATFORM_MISMATCH;
    }

    /* ---- version / downgrade check ---- */
    fota_version_t new_version;
    if (fota_version_parse(header.fw_version, FOTA_FW_VERSION_SIZE,
                            &new_version) != FOTA_VERSION_PARSE_OK) {
        free(data);
        return FOTA_EXIT_MALFORMED_HEADER;
    }

    fota_version_t installed_version;
    if (fota_version_read_installed(FOTA_CONFIG_VERSION_FILE,
                                     &installed_version) !=
        FOTA_VERSION_READ_OK) {
        free(data);
        return FOTA_EXIT_GENERIC_FAILURE;
    }

    uint8_t stored_secret_hash[FOTA_DOWNGRADE_SECRET_HASH_SIZE];
    const uint8_t *stored_secret_hash_ptr = NULL;
    if (fota_version_read_downgrade_secret_hash(
            FOTA_CONFIG_DOWNGRADE_SECRET_HASH_FILE, stored_secret_hash) ==
        FOTA_SECRET_HASH_READ_OK) {
        stored_secret_hash_ptr = stored_secret_hash;
    }

    const uint8_t *secret_bytes =
        downgrade_secret != NULL ? (const uint8_t *)downgrade_secret : NULL;
    size_t secret_len = downgrade_secret != NULL ? strlen(downgrade_secret) : 0;

    fota_downgrade_check_result_t downgrade_result = fota_downgrade_check(
        &new_version, &installed_version, secret_bytes, secret_len,
        stored_secret_hash_ptr);
    if (downgrade_result == FOTA_DOWNGRADE_CHECK_UP_TO_DATE) {
        free(data);
        return FOTA_EXIT_UP_TO_DATE;
    }
    if (downgrade_result == FOTA_DOWNGRADE_CHECK_BLOCKED) {
        free(data);
        return FOTA_EXIT_DOWNGRADE_BLOCKED;
    }

    /* ---- split sections per docs/FORMAT_SPEC.md's layout:
     * header || wrapped_key || signature || payload ---- */
    size_t wrapped_key_end = FOTA_HEADER_SIZE + header.wrapped_key_len;
    size_t signature_end = wrapped_key_end + 256u;
    if (data_len < signature_end) {
        free(data);
        return FOTA_EXIT_MALFORMED_HEADER; /* truncated package */
    }
    const uint8_t *wrapped_key = data + FOTA_HEADER_SIZE;
    const uint8_t *signature = data + wrapped_key_end;
    const uint8_t *ciphertext = data + signature_end;
    size_t ciphertext_len = data_len - signature_end;

    /* ---- disk space pre-check ---- */
    struct statvfs vfs;
    if (statvfs(FOTA_CONFIG_INSTALL_DIR, &vfs) != 0) {
        free(data);
        return FOTA_EXIT_GENERIC_FAILURE;
    }
    unsigned long long available_bytes =
        (unsigned long long)vfs.f_bavail * (unsigned long long)vfs.f_frsize;
    if (available_bytes < (unsigned long long)ciphertext_len) {
        free(data);
        return FOTA_EXIT_INSUFFICIENT_DISK_SPACE;
    }

    /* ---- signature verify - BEFORE any decryption, per
     * docs/THREAT_MODEL.md item 5 ---- */
    EVP_PKEY *signing_public_key =
        fota_load_public_key(FOTA_CONFIG_SIGNING_PUBLIC_KEY_FILE);
    if (signing_public_key == NULL) {
        free(data);
        return FOTA_EXIT_GENERIC_FAILURE;
    }

    size_t signed_data_len = FOTA_HEADER_SIZE + header.wrapped_key_len + ciphertext_len;
    uint8_t *signed_data = malloc(signed_data_len);
    if (signed_data == NULL) {
        EVP_PKEY_free(signing_public_key);
        free(data);
        return FOTA_EXIT_GENERIC_FAILURE;
    }
    memcpy(signed_data, data, FOTA_HEADER_SIZE);
    memcpy(signed_data + FOTA_HEADER_SIZE, wrapped_key, header.wrapped_key_len);
    memcpy(signed_data + FOTA_HEADER_SIZE + header.wrapped_key_len, ciphertext,
           ciphertext_len);

    fota_crypto_result_t verify_result = fota_verify_signature(
        signing_public_key, signed_data, signed_data_len, signature, 256u);
    free(signed_data);
    EVP_PKEY_free(signing_public_key);
    if (verify_result != FOTA_CRYPTO_OK) {
        free(data);
        return FOTA_EXIT_SIGNATURE_FAILED;
    }

    /* ---- unwrap key + decrypt payload ---- */
    EVP_PKEY *device_private_key =
        fota_load_private_key(FOTA_CONFIG_DEVICE_PRIVATE_KEY_FILE);
    if (device_private_key == NULL) {
        free(data);
        return FOTA_EXIT_GENERIC_FAILURE;
    }

    uint8_t aes_key[FOTA_AES_KEY_SIZE];
    size_t aes_key_len = sizeof(aes_key);
    fota_crypto_result_t unwrap_result =
        fota_unwrap_key(device_private_key, wrapped_key, header.wrapped_key_len,
                         aes_key, &aes_key_len);
    EVP_PKEY_free(device_private_key);
    if (unwrap_result != FOTA_CRYPTO_OK || aes_key_len != FOTA_AES_KEY_SIZE) {
        free(data);
        return FOTA_EXIT_DECRYPTION_FAILED;
    }

    uint8_t *plaintext = malloc(ciphertext_len + FOTA_AES_IV_SIZE);
    if (plaintext == NULL) {
        free(data);
        return FOTA_EXIT_GENERIC_FAILURE;
    }
    size_t plaintext_len = 0;
    fota_crypto_result_t decrypt_result = fota_decrypt_payload(
        aes_key, sizeof(aes_key), header.iv, FOTA_IV_SIZE, ciphertext,
        ciphertext_len, plaintext, &plaintext_len);
    if (decrypt_result != FOTA_CRYPTO_OK) {
        free(plaintext);
        free(data);
        return FOTA_EXIT_DECRYPTION_FAILED;
    }

    /* ---- extract + install ---- */
    fota_install_result_t install_result =
        fota_installer_extract(plaintext, plaintext_len, FOTA_CONFIG_INSTALL_DIR);
    free(plaintext);
    free(data);
    if (install_result != FOTA_INSTALL_OK) {
        return install_result_to_exit_code(install_result);
    }

    /* Persist the new version - without this, the next invocation's
     * version check would compare against the same stale version
     * forever, and downgrade protection would never see a real bump. */
    if (fota_version_write_installed(FOTA_CONFIG_VERSION_FILE, &new_version) !=
        0) {
        return FOTA_EXIT_GENERIC_FAILURE;
    }

    platform_post_install_hook();
    return FOTA_EXIT_SUCCESS;
}
