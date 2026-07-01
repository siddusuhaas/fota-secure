#include "version.h"

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#define FOTA_VERSION_READ_BUF_SIZE 64u

fota_version_parse_result_t fota_version_parse(const uint8_t *data,
                                                size_t data_len,
                                                fota_version_t *out) {
    if (data == NULL || out == NULL || data_len == 0) {
        return FOTA_VERSION_PARSE_ERR_MALFORMED;
    }

    /* Content ends at the first NUL within data_len, if any, else at
     * data_len itself - never read past data_len. */
    size_t content_len = 0;
    while (content_len < data_len && data[content_len] != '\0') {
        content_len++;
    }
    if (content_len == 0) {
        return FOTA_VERSION_PARSE_ERR_MALFORMED;
    }

    uint32_t parts[FOTA_VERSION_PARTS];
    size_t parts_found = 0;
    size_t component_start = 0;
    size_t i;

    for (i = 0; i <= content_len; i++) {
        int at_boundary = (i == content_len) || (data[i] == '.');
        if (!at_boundary) {
            if (data[i] < '0' || data[i] > '9') {
                return FOTA_VERSION_PARSE_ERR_MALFORMED;
            }
            continue;
        }

        size_t component_len = i - component_start;
        if (component_len == 0 || parts_found >= FOTA_VERSION_PARTS) {
            return FOTA_VERSION_PARSE_ERR_MALFORMED;
        }

        uint64_t value = 0;
        size_t j;
        for (j = component_start; j < i; j++) {
            value = value * 10u + (uint64_t)(data[j] - '0');
            if (value > 0xFFFFFFFFu) {
                return FOTA_VERSION_PARSE_ERR_MALFORMED; /* overflow */
            }
        }
        parts[parts_found++] = (uint32_t)value;
        component_start = i + 1;
    }

    if (parts_found != FOTA_VERSION_PARTS) {
        return FOTA_VERSION_PARSE_ERR_MALFORMED;
    }

    memcpy(out->parts, parts, sizeof(parts));
    return FOTA_VERSION_PARSE_OK;
}

int fota_version_compare(const fota_version_t *a, const fota_version_t *b) {
    size_t i;
    for (i = 0; i < FOTA_VERSION_PARTS; i++) {
        if (a->parts[i] < b->parts[i]) {
            return -1;
        }
        if (a->parts[i] > b->parts[i]) {
            return 1;
        }
    }
    return 0;
}

fota_version_read_result_t fota_version_read_installed(const char *path,
                                                         fota_version_t *out) {
    memset(out, 0, sizeof(*out)); /* default: missing/empty -> 0.0.0.0 */

    if (path == NULL) {
        return FOTA_VERSION_READ_OK;
    }

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return FOTA_VERSION_READ_OK; /* missing/unreadable is not an error */
    }

    uint8_t buf[FOTA_VERSION_READ_BUF_SIZE];
    size_t n = fread(buf, 1, sizeof(buf), fp);

    /* A legitimate version string is far shorter than this buffer -
     * confirm we actually reached EOF rather than silently truncating a
     * longer (corrupt) file. */
    if (n == sizeof(buf)) {
        uint8_t extra;
        int has_more = (fread(&extra, 1, 1, fp) == 1);
        fclose(fp);
        if (has_more) {
            return FOTA_VERSION_READ_ERR_MALFORMED_CONTENTS;
        }
    } else {
        fclose(fp);
    }

    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                     buf[n - 1] == ' ' || buf[n - 1] == '\t')) {
        n--;
    }

    if (n == 0) {
        return FOTA_VERSION_READ_OK; /* empty content -> treated as missing */
    }

    fota_version_t parsed;
    if (fota_version_parse(buf, n, &parsed) != FOTA_VERSION_PARSE_OK) {
        return FOTA_VERSION_READ_ERR_MALFORMED_CONTENTS;
    }

    *out = parsed;
    return FOTA_VERSION_READ_OK;
}

fota_secret_hash_read_result_t fota_version_read_downgrade_secret_hash(
    const char *path, uint8_t out_hash[FOTA_DOWNGRADE_SECRET_HASH_SIZE]) {
    if (path == NULL || out_hash == NULL) {
        return FOTA_SECRET_HASH_READ_ERR_UNAVAILABLE;
    }

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return FOTA_SECRET_HASH_READ_ERR_UNAVAILABLE;
    }

    size_t n = fread(out_hash, 1, FOTA_DOWNGRADE_SECRET_HASH_SIZE, fp);
    uint8_t extra;
    size_t extra_n = fread(&extra, 1, 1, fp);
    fclose(fp);

    if (n != FOTA_DOWNGRADE_SECRET_HASH_SIZE || extra_n != 0) {
        return FOTA_SECRET_HASH_READ_ERR_UNAVAILABLE;
    }
    return FOTA_SECRET_HASH_READ_OK;
}

fota_downgrade_check_result_t fota_downgrade_check(
    const fota_version_t *new_version, const fota_version_t *installed_version,
    const uint8_t *override_secret, size_t override_secret_len,
    const uint8_t *stored_secret_hash) {
    int cmp = fota_version_compare(new_version, installed_version);
    if (cmp > 0) {
        return FOTA_DOWNGRADE_CHECK_ALLOW;
    }
    if (cmp == 0) {
        return FOTA_DOWNGRADE_CHECK_UP_TO_DATE;
    }

    if (stored_secret_hash == NULL || override_secret == NULL ||
        override_secret_len == 0) {
        return FOTA_DOWNGRADE_CHECK_BLOCKED;
    }

    uint8_t computed_hash[FOTA_DOWNGRADE_SECRET_HASH_SIZE];
    unsigned int computed_len = 0;
    if (EVP_Digest(override_secret, override_secret_len, computed_hash,
                    &computed_len, EVP_sha256(), NULL) != 1 ||
        computed_len != FOTA_DOWNGRADE_SECRET_HASH_SIZE) {
        return FOTA_DOWNGRADE_CHECK_BLOCKED;
    }

    if (CRYPTO_memcmp(computed_hash, stored_secret_hash,
                       FOTA_DOWNGRADE_SECRET_HASH_SIZE) == 0) {
        return FOTA_DOWNGRADE_CHECK_ALLOW;
    }

    return FOTA_DOWNGRADE_CHECK_BLOCKED;
}
