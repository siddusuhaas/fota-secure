#include "../src/header.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* Test-only helper: packs a header buffer field-by-field so tests don't
 * need to hand-write byte offsets. Not part of the production API - the
 * consumer only ever parses headers, it never constructs them. */
static void pack_header(uint8_t *out, const char *magic,
                         uint8_t format_version, const uint8_t *platform_tag,
                         const uint8_t *fw_version, uint16_t wrapped_key_len,
                         const uint8_t *iv) {
    memcpy(out, magic, FOTA_MAGIC_SIZE);
    out[4] = format_version;
    memcpy(out + 5, platform_tag, FOTA_PLATFORM_TAG_SIZE);
    memcpy(out + 21, fw_version, FOTA_FW_VERSION_SIZE);
    out[33] = (uint8_t)(wrapped_key_len >> 8);
    out[34] = (uint8_t)(wrapped_key_len & 0xFFu);
    memcpy(out + 35, iv, FOTA_IV_SIZE);
}

static void test_valid_round_trip(void) {
    uint8_t platform_tag[FOTA_PLATFORM_TAG_SIZE] = "GENERIC";
    uint8_t fw_version[FOTA_FW_VERSION_SIZE] = "1.0.0.0";
    uint8_t iv[FOTA_IV_SIZE];
    for (size_t i = 0; i < FOTA_IV_SIZE; i++) {
        iv[i] = (uint8_t)(i * 7 + 3);
    }

    uint8_t buf[FOTA_HEADER_SIZE];
    pack_header(buf, FOTA_MAGIC, FOTA_FORMAT_VERSION, platform_tag, fw_version,
                256, iv);

    fota_header_t header;
    fota_header_result_t result = fota_header_parse(buf, sizeof(buf), &header);

    CHECK(result == FOTA_HEADER_OK);
    CHECK(memcmp(header.platform_tag, platform_tag, FOTA_PLATFORM_TAG_SIZE) == 0);
    CHECK(memcmp(header.fw_version, fw_version, FOTA_FW_VERSION_SIZE) == 0);
    CHECK(header.wrapped_key_len == 256);
    CHECK(memcmp(header.iv, iv, FOTA_IV_SIZE) == 0);
}

/* platform_tag at its full 16-byte length has no room for a NUL
 * terminator (docs/FORMAT_SPEC.md's note). Buffer is allocated on the
 * heap at exactly FOTA_HEADER_SIZE bytes, no slack, so a memory checker's
 * redzone sits immediately after it - any 1-byte overread while
 * copying/comparing platform_tag (e.g. from a naive strlen/strcpy-based
 * implementation hunting for a terminator that isn't there) is caught
 * immediately rather than passing silently. */
static void test_platform_tag_max_length_no_null(void) {
    uint8_t platform_tag[FOTA_PLATFORM_TAG_SIZE] = "GENERIC_DEVICE01";
    uint8_t fw_version[FOTA_FW_VERSION_SIZE] = "1.0.0.0";
    uint8_t iv[FOTA_IV_SIZE];
    for (size_t i = 0; i < FOTA_IV_SIZE; i++) {
        iv[i] = (uint8_t)(i + 1);
    }

    uint8_t *buf = malloc(FOTA_HEADER_SIZE);
    assert(buf != NULL);
    pack_header(buf, FOTA_MAGIC, FOTA_FORMAT_VERSION, platform_tag, fw_version,
                256, iv);

    fota_header_t header;
    fota_header_result_t result =
        fota_header_parse(buf, FOTA_HEADER_SIZE, &header);

    CHECK(result == FOTA_HEADER_OK);
    CHECK(memcmp(header.platform_tag, platform_tag, FOTA_PLATFORM_TAG_SIZE) == 0);

    free(buf);
}

/* Same concern, same treatment, for fw_version at its full 12-byte
 * length. */
static void test_fw_version_max_length_no_null(void) {
    uint8_t platform_tag[FOTA_PLATFORM_TAG_SIZE] = "GENERIC";
    uint8_t fw_version[FOTA_FW_VERSION_SIZE] = "123.45.6.789";
    uint8_t iv[FOTA_IV_SIZE] = {0};

    uint8_t *buf = malloc(FOTA_HEADER_SIZE);
    assert(buf != NULL);
    pack_header(buf, FOTA_MAGIC, FOTA_FORMAT_VERSION, platform_tag, fw_version,
                256, iv);

    fota_header_t header;
    fota_header_result_t result =
        fota_header_parse(buf, FOTA_HEADER_SIZE, &header);

    CHECK(result == FOTA_HEADER_OK);
    CHECK(memcmp(header.fw_version, fw_version, FOTA_FW_VERSION_SIZE) == 0);

    free(buf);
}

static void test_bad_magic(void) {
    uint8_t platform_tag[FOTA_PLATFORM_TAG_SIZE] = "GENERIC";
    uint8_t fw_version[FOTA_FW_VERSION_SIZE] = "1.0.0.0";
    uint8_t iv[FOTA_IV_SIZE] = {0};
    uint8_t buf[FOTA_HEADER_SIZE];
    pack_header(buf, "XXXX", FOTA_FORMAT_VERSION, platform_tag, fw_version,
                256, iv);

    fota_header_t header;
    fota_header_result_t result = fota_header_parse(buf, sizeof(buf), &header);
    CHECK(result == FOTA_HEADER_ERR_BAD_MAGIC);
}

static void test_bad_format_version(void) {
    uint8_t platform_tag[FOTA_PLATFORM_TAG_SIZE] = "GENERIC";
    uint8_t fw_version[FOTA_FW_VERSION_SIZE] = "1.0.0.0";
    uint8_t iv[FOTA_IV_SIZE] = {0};
    uint8_t buf[FOTA_HEADER_SIZE];
    pack_header(buf, FOTA_MAGIC, 0xFFu, platform_tag, fw_version, 256, iv);

    fota_header_t header;
    fota_header_result_t result = fota_header_parse(buf, sizeof(buf), &header);
    CHECK(result == FOTA_HEADER_ERR_BAD_VERSION);
}

/* Mirrors the truncation cases blob.py's test suite already covers on the
 * Python side (packager/tests/test_blob.py::TestHeaderMalformedInput). */
static void test_truncated_inputs(void) {
    uint8_t platform_tag[FOTA_PLATFORM_TAG_SIZE] = "GENERIC";
    uint8_t fw_version[FOTA_FW_VERSION_SIZE] = "1.0.0.0";
    uint8_t iv[FOTA_IV_SIZE] = {0};
    uint8_t buf[FOTA_HEADER_SIZE];
    pack_header(buf, FOTA_MAGIC, FOTA_FORMAT_VERSION, platform_tag, fw_version,
                256, iv);

    size_t cuts[] = {0, 1, 10, FOTA_HEADER_SIZE - 1};
    for (size_t i = 0; i < sizeof(cuts) / sizeof(cuts[0]); i++) {
        fota_header_t header;
        fota_header_result_t result = fota_header_parse(buf, cuts[i], &header);
        CHECK(result == FOTA_HEADER_ERR_TRUNCATED);
    }
}

static void test_null_data_pointer(void) {
    fota_header_t header;
    fota_header_result_t result = fota_header_parse(NULL, 0, &header);
    CHECK(result == FOTA_HEADER_ERR_TRUNCATED);
}

int main(void) {
    test_valid_round_trip();
    test_platform_tag_max_length_no_null();
    test_fw_version_max_length_no_null();
    test_bad_magic();
    test_bad_format_version();
    test_truncated_inputs();
    test_null_data_pointer();

    printf("%d/%d tests passed\n", tests_run - tests_failed, tests_run);
    return tests_failed == 0 ? 0 : 1;
}
