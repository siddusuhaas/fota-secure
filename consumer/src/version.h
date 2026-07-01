#ifndef FOTA_SECURE_VERSION_H
#define FOTA_SECURE_VERSION_H

/* Firmware version parsing/comparison and downgrade protection, per
 * docs/FORMAT_SPEC.md's "Version Comparison" section and
 * docs/THREAT_MODEL.md item 7 (downgrade is a deliberate-override
 * design, not a hard block). Requires libcrypto for SHA-256 hashing and
 * a constant-time comparison of the downgrade override secret. */

#include <stddef.h>
#include <stdint.h>

#define FOTA_VERSION_PARTS 4u
#define FOTA_DOWNGRADE_SECRET_HASH_SIZE 32u /* SHA-256 digest size */

typedef struct {
    uint32_t parts[FOTA_VERSION_PARTS];
} fota_version_t;

typedef enum {
    FOTA_VERSION_PARSE_OK = 0,
    FOTA_VERSION_PARSE_ERR_MALFORMED
} fota_version_parse_result_t;

/* Parses a 4-part dotted-decimal version from a fixed-length byte
 * buffer - NOT a NUL-terminated C string. data may be NUL-padded (a NUL
 * byte within data_len ends the content early) or may fill the entire
 * data_len with no NUL at all (e.g. a 12-byte fw_version header field
 * with no room left for a terminator, exactly like the platform_tag
 * case documented in docs/FORMAT_SPEC.md) - both are handled without
 * ever reading past data_len. */
fota_version_parse_result_t fota_version_parse(const uint8_t *data,
                                                size_t data_len,
                                                fota_version_t *out);

typedef enum {
    FOTA_VERSION_READ_OK = 0,
    FOTA_VERSION_READ_ERR_MALFORMED_CONTENTS
} fota_version_read_result_t;

/* Reads the installed version from a text file at path. A missing or
 * unreadable file, or one that's empty after trimming whitespace, is
 * NOT an error - *out is set to 0.0.0.0 and FOTA_VERSION_READ_OK is
 * returned, per docs/FORMAT_SPEC.md's Version Comparison section. An
 * error is returned only when the file exists, is readable, and
 * contains content that doesn't parse as a valid 4-part version. */
fota_version_read_result_t fota_version_read_installed(const char *path,
                                                         fota_version_t *out);

/* -1 if a < b, 0 if a == b, 1 if a > b. Lexicographic
 * component-by-component numeric comparison (not a string comparison -
 * "10.0.0.0" must compare greater than "2.0.0.0"). */
int fota_version_compare(const fota_version_t *a, const fota_version_t *b);

typedef enum {
    FOTA_SECRET_HASH_READ_OK = 0,
    FOTA_SECRET_HASH_READ_ERR_UNAVAILABLE
} fota_secret_hash_read_result_t;

/* Reads the device's stored downgrade-override secret hash: exactly
 * FOTA_DOWNGRADE_SECRET_HASH_SIZE raw bytes (a SHA-256 digest, not
 * hex-encoded) at path. A missing/unreadable/wrong-sized file returns
 * ERR_UNAVAILABLE - callers must treat that as "no override possible"
 * (a fail-safe default), never as "any secret works". */
fota_secret_hash_read_result_t fota_version_read_downgrade_secret_hash(
    const char *path, uint8_t out_hash[FOTA_DOWNGRADE_SECRET_HASH_SIZE]);

typedef enum {
    FOTA_DOWNGRADE_CHECK_ALLOW = 0,  /* new > installed, or valid override */
    FOTA_DOWNGRADE_CHECK_UP_TO_DATE, /* new == installed */
    FOTA_DOWNGRADE_CHECK_BLOCKED     /* new < installed, no valid override */
} fota_downgrade_check_result_t;

/* Decides whether an update should proceed:
 *   new_version >  installed_version -> ALLOW
 *   new_version == installed_version -> UP_TO_DATE
 *   new_version <  installed_version -> BLOCKED, unless override_secret
 *     is supplied and its SHA-256 hash matches stored_secret_hash
 *     exactly, in which case -> ALLOW.
 *
 * stored_secret_hash may be NULL (no override configured on this
 * device) - a downgrade is then always BLOCKED regardless of what
 * override_secret is supplied. The hash comparison uses CRYPTO_memcmp
 * (constant-time), never a manual memcmp, for the same reason signature
 * verification avoids one - a secret-gated check must not leak timing
 * information (docs/THREAT_MODEL.md item 7). */
fota_downgrade_check_result_t fota_downgrade_check(
    const fota_version_t *new_version, const fota_version_t *installed_version,
    const uint8_t *override_secret, size_t override_secret_len,
    const uint8_t *stored_secret_hash);

#endif /* FOTA_SECURE_VERSION_H */
