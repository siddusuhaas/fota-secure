#include "header.h"

#include <string.h>

fota_header_result_t fota_header_parse(const uint8_t *data, size_t data_len,
                                        fota_header_t *out) {
    if (data == NULL || out == NULL || data_len < FOTA_HEADER_SIZE) {
        return FOTA_HEADER_ERR_TRUNCATED;
    }

    if (memcmp(data, FOTA_MAGIC, FOTA_MAGIC_SIZE) != 0) {
        return FOTA_HEADER_ERR_BAD_MAGIC;
    }

    if (data[4] != FOTA_FORMAT_VERSION) {
        return FOTA_HEADER_ERR_BAD_VERSION;
    }

    /* Build into a local first, only write *out once every check has
     * passed, so a caller never observes a partially-populated header. */
    fota_header_t parsed;
    memcpy(parsed.platform_tag, data + 5, FOTA_PLATFORM_TAG_SIZE);
    memcpy(parsed.fw_version, data + 21, FOTA_FW_VERSION_SIZE);
    parsed.wrapped_key_len = (uint16_t)((data[33] << 8) | data[34]);
    memcpy(parsed.iv, data + 35, FOTA_IV_SIZE);

    *out = parsed;
    return FOTA_HEADER_OK;
}
