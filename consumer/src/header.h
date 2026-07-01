#ifndef FOTA_SECURE_HEADER_H
#define FOTA_SECURE_HEADER_H

/* Parses and validates the fixed header described in docs/FORMAT_SPEC.md.
 * Both packager and consumer must agree on this layout byte-for-byte. */

#include <stddef.h>
#include <stdint.h>

#define FOTA_MAGIC "FOTS"
#define FOTA_MAGIC_SIZE 4u
#define FOTA_FORMAT_VERSION 0x01u

#define FOTA_PLATFORM_TAG_SIZE 16u
#define FOTA_FW_VERSION_SIZE 12u
#define FOTA_IV_SIZE 16u

/* 4 + 1 + 16 + 12 + 2 + 16 = 51 bytes, see docs/FORMAT_SPEC.md. */
#define FOTA_HEADER_SIZE 51u

typedef enum {
    FOTA_HEADER_OK = 0,
    FOTA_HEADER_ERR_TRUNCATED,
    FOTA_HEADER_ERR_BAD_MAGIC,
    FOTA_HEADER_ERR_BAD_VERSION
} fota_header_result_t;

typedef struct {
    /* platform_tag and fw_version are fixed-length byte buffers, NOT
     * NUL-terminated C strings. platform_tag in particular has no
     * guaranteed NUL terminator at its full 16-byte length (see
     * docs/FORMAT_SPEC.md's note on platform_tag) - always compare with
     * memcmp/strncmp using the explicit *_SIZE constants above, never
     * strcmp/strlen on these fields. */
    uint8_t platform_tag[FOTA_PLATFORM_TAG_SIZE];
    uint8_t fw_version[FOTA_FW_VERSION_SIZE];
    uint16_t wrapped_key_len;
    uint8_t iv[FOTA_IV_SIZE];
} fota_header_t;

/* Parses data[0..data_len) into *out. Returns FOTA_HEADER_OK on success;
 * on any error, *out is left unmodified and a specific error code is
 * returned rather than reading past data_len or guessing. */
fota_header_result_t fota_header_parse(const uint8_t *data, size_t data_len,
                                        fota_header_t *out);

#endif /* FOTA_SECURE_HEADER_H */
