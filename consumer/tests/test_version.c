#include "../src/version.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

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

static void write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    assert(fp != NULL);
    if (len > 0) {
        size_t written = fwrite(data, 1, len, fp);
        assert(written == len);
    }
    fclose(fp);
}

static fota_version_t make_version(uint32_t a, uint32_t b, uint32_t c,
                                    uint32_t d) {
    fota_version_t v;
    v.parts[0] = a;
    v.parts[1] = b;
    v.parts[2] = c;
    v.parts[3] = d;
    return v;
}

/* ---- fota_version_parse ---- */

static void test_parse_valid(void) {
    fota_version_t v;
    CHECK(fota_version_parse((const uint8_t *)"1.0.0.0", 7, &v) ==
          FOTA_VERSION_PARSE_OK);
    CHECK(v.parts[0] == 1 && v.parts[1] == 0 && v.parts[2] == 0 &&
          v.parts[3] == 0);

    CHECK(fota_version_parse((const uint8_t *)"255.255.255.255", 15, &v) ==
          FOTA_VERSION_PARSE_OK);
    CHECK(v.parts[0] == 255 && v.parts[3] == 255);
}

/* Exactly 12 bytes, no NUL - the fw_version header field at its full
 * length has no room for a terminator, same class of case as
 * platform_tag in docs/FORMAT_SPEC.md. Heap-allocated with no slack so
 * a memory checker's redzone sits immediately after it. */
static void test_parse_fixed_length_no_null(void) {
    const char *version_str = "123.45.6.789"; /* exactly 12 chars */
    assert(strlen(version_str) == 12);

    uint8_t *buf = malloc(12);
    assert(buf != NULL);
    memcpy(buf, version_str, 12);

    fota_version_t v;
    fota_version_parse_result_t result = fota_version_parse(buf, 12, &v);
    CHECK(result == FOTA_VERSION_PARSE_OK);
    CHECK(v.parts[0] == 123 && v.parts[1] == 45 && v.parts[2] == 6 &&
          v.parts[3] == 789);

    free(buf);
}

static void test_parse_null_padded(void) {
    uint8_t buf[12] = {0};
    memcpy(buf, "1.0.0.0", 7);
    /* remaining 5 bytes already zero */

    fota_version_t v;
    CHECK(fota_version_parse(buf, sizeof(buf), &v) == FOTA_VERSION_PARSE_OK);
    CHECK(v.parts[0] == 1 && v.parts[3] == 0);
}

static void test_parse_malformed(void) {
    fota_version_t v;
    const char *bad_strings[] = {
        "1.2.3",         /* too few parts */
        "1.2.3.4.5",     /* too many parts */
        "1.2.a.4",       /* non-digit */
        "1..2.3",        /* empty component */
        ".1.2.3",        /* leading empty component */
        "1.2.3.",        /* trailing empty component */
        "4294967296.0.0.0", /* overflows uint32 (2^32) */
        "",              /* empty */
    };
    size_t i;
    for (i = 0; i < sizeof(bad_strings) / sizeof(bad_strings[0]); i++) {
        fota_version_parse_result_t result = fota_version_parse(
            (const uint8_t *)bad_strings[i], strlen(bad_strings[i]), &v);
        CHECK(result == FOTA_VERSION_PARSE_ERR_MALFORMED);
    }
}

/* ---- fota_version_compare ---- */

static void test_compare(void) {
    fota_version_t a = make_version(1, 0, 0, 0);
    fota_version_t b = make_version(1, 0, 0, 0);
    CHECK(fota_version_compare(&a, &b) == 0);

    fota_version_t c = make_version(1, 0, 0, 1);
    CHECK(fota_version_compare(&a, &c) < 0);
    CHECK(fota_version_compare(&c, &a) > 0);

    /* Numeric, not string, comparison: "10" must be greater than "2". */
    fota_version_t ten = make_version(10, 0, 0, 0);
    fota_version_t two = make_version(2, 0, 0, 0);
    CHECK(fota_version_compare(&ten, &two) > 0);
    CHECK(fota_version_compare(&two, &ten) < 0);
}

/* ---- fota_version_read_installed ---- */

static void test_read_installed_missing_file(const char *scratch_dir) {
    char *path = join_path(scratch_dir, "does_not_exist.version");
    fota_version_t v;
    memset(&v, 0xAA, sizeof(v)); /* poison, to prove it gets overwritten */

    fota_version_read_result_t result = fota_version_read_installed(path, &v);
    CHECK(result == FOTA_VERSION_READ_OK);
    CHECK(v.parts[0] == 0 && v.parts[1] == 0 && v.parts[2] == 0 &&
          v.parts[3] == 0);

    free(path);
}

static void test_read_installed_empty_file(const char *scratch_dir) {
    char *path = join_path(scratch_dir, "empty.version");
    write_file(path, NULL, 0);

    fota_version_t v;
    fota_version_read_result_t result = fota_version_read_installed(path, &v);
    CHECK(result == FOTA_VERSION_READ_OK);
    CHECK(v.parts[0] == 0 && v.parts[3] == 0);

    free(path);
}

static void test_read_installed_valid_file(const char *scratch_dir) {
    char *path = join_path(scratch_dir, "valid.version");
    write_file(path, (const uint8_t *)"2.1.0.5\n", 8); /* trailing newline */

    fota_version_t v;
    fota_version_read_result_t result = fota_version_read_installed(path, &v);
    CHECK(result == FOTA_VERSION_READ_OK);
    CHECK(v.parts[0] == 2 && v.parts[1] == 1 && v.parts[2] == 0 &&
          v.parts[3] == 5);

    free(path);
}

static void test_read_installed_malformed_file(const char *scratch_dir) {
    char *path = join_path(scratch_dir, "malformed.version");
    write_file(path, (const uint8_t *)"not-a-version", 13);

    fota_version_t v;
    fota_version_read_result_t result = fota_version_read_installed(path, &v);
    CHECK(result == FOTA_VERSION_READ_ERR_MALFORMED_CONTENTS);

    free(path);
}

static void test_read_installed_oversized_file(const char *scratch_dir) {
    char *path = join_path(scratch_dir, "oversized.version");
    uint8_t big[128];
    memset(big, '1', sizeof(big));
    write_file(path, big, sizeof(big));

    fota_version_t v;
    fota_version_read_result_t result = fota_version_read_installed(path, &v);
    CHECK(result == FOTA_VERSION_READ_ERR_MALFORMED_CONTENTS);

    free(path);
}

/* ---- fota_version_read_downgrade_secret_hash ---- */

static void test_read_secret_hash_missing(const char *scratch_dir) {
    char *path = join_path(scratch_dir, "does_not_exist.hash");
    uint8_t hash[FOTA_DOWNGRADE_SECRET_HASH_SIZE];

    fota_secret_hash_read_result_t result =
        fota_version_read_downgrade_secret_hash(path, hash);
    CHECK(result == FOTA_SECRET_HASH_READ_ERR_UNAVAILABLE);

    free(path);
}

static void test_read_secret_hash_wrong_size(const char *scratch_dir) {
    char *path = join_path(scratch_dir, "short.hash");
    uint8_t short_hash[10] = {0};
    write_file(path, short_hash, sizeof(short_hash));

    uint8_t hash[FOTA_DOWNGRADE_SECRET_HASH_SIZE];
    fota_secret_hash_read_result_t result =
        fota_version_read_downgrade_secret_hash(path, hash);
    CHECK(result == FOTA_SECRET_HASH_READ_ERR_UNAVAILABLE);

    free(path);
}

static void test_read_secret_hash_valid(const char *scratch_dir,
                                         const uint8_t *expected_hash) {
    char *path = join_path(scratch_dir, "valid.hash");
    write_file(path, expected_hash, FOTA_DOWNGRADE_SECRET_HASH_SIZE);

    uint8_t hash[FOTA_DOWNGRADE_SECRET_HASH_SIZE];
    fota_secret_hash_read_result_t result =
        fota_version_read_downgrade_secret_hash(path, hash);
    CHECK(result == FOTA_SECRET_HASH_READ_OK);
    CHECK(memcmp(hash, expected_hash, FOTA_DOWNGRADE_SECRET_HASH_SIZE) == 0);

    free(path);
}

/* ---- fota_downgrade_check ---- */

static void test_downgrade_check_allow_when_new_greater(void) {
    fota_version_t new_v = make_version(2, 0, 0, 0);
    fota_version_t installed = make_version(1, 0, 0, 0);

    fota_downgrade_check_result_t result =
        fota_downgrade_check(&new_v, &installed, NULL, 0, NULL);
    CHECK(result == FOTA_DOWNGRADE_CHECK_ALLOW);
}

static void test_downgrade_check_up_to_date_when_equal(void) {
    fota_version_t v = make_version(1, 2, 3, 4);

    fota_downgrade_check_result_t result =
        fota_downgrade_check(&v, &v, NULL, 0, NULL);
    CHECK(result == FOTA_DOWNGRADE_CHECK_UP_TO_DATE);
}

static void test_downgrade_check_blocked_no_override_configured(void) {
    fota_version_t new_v = make_version(1, 0, 0, 0);
    fota_version_t installed = make_version(2, 0, 0, 0);

    /* stored_secret_hash is NULL - no override possible on this device,
     * regardless of what secret is supplied. */
    const uint8_t *some_secret = (const uint8_t *)"correct-horse-battery-staple";
    fota_downgrade_check_result_t result = fota_downgrade_check(
        &new_v, &installed, some_secret, strlen((const char *)some_secret),
        NULL);
    CHECK(result == FOTA_DOWNGRADE_CHECK_BLOCKED);
}

static void test_downgrade_check_blocked_with_wrong_secret(
    const uint8_t *stored_hash) {
    fota_version_t new_v = make_version(1, 0, 0, 0);
    fota_version_t installed = make_version(2, 0, 0, 0);

    const uint8_t *wrong_secret = (const uint8_t *)"definitely-the-wrong-secret";
    fota_downgrade_check_result_t result = fota_downgrade_check(
        &new_v, &installed, wrong_secret, strlen((const char *)wrong_secret),
        stored_hash);
    CHECK(result == FOTA_DOWNGRADE_CHECK_BLOCKED);
}

static void test_downgrade_check_blocked_with_no_secret_supplied(
    const uint8_t *stored_hash) {
    fota_version_t new_v = make_version(1, 0, 0, 0);
    fota_version_t installed = make_version(2, 0, 0, 0);

    fota_downgrade_check_result_t result =
        fota_downgrade_check(&new_v, &installed, NULL, 0, stored_hash);
    CHECK(result == FOTA_DOWNGRADE_CHECK_BLOCKED);
}

static void test_downgrade_check_allow_with_correct_secret(
    const uint8_t *stored_hash, const uint8_t *correct_secret,
    size_t correct_secret_len) {
    fota_version_t new_v = make_version(1, 0, 0, 0);
    fota_version_t installed = make_version(2, 0, 0, 0);

    fota_downgrade_check_result_t result = fota_downgrade_check(
        &new_v, &installed, correct_secret, correct_secret_len, stored_hash);
    CHECK(result == FOTA_DOWNGRADE_CHECK_ALLOW);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <scratch-dir>\n", argv[0]);
        return 2;
    }
    const char *scratch_dir = argv[1];

    test_parse_valid();
    test_parse_fixed_length_no_null();
    test_parse_null_padded();
    test_parse_malformed();
    test_compare();

    test_read_installed_missing_file(scratch_dir);
    test_read_installed_empty_file(scratch_dir);
    test_read_installed_valid_file(scratch_dir);
    test_read_installed_malformed_file(scratch_dir);
    test_read_installed_oversized_file(scratch_dir);

    test_read_secret_hash_missing(scratch_dir);
    test_read_secret_hash_wrong_size(scratch_dir);

    const uint8_t *correct_secret = (const uint8_t *)"the-real-downgrade-secret";
    size_t correct_secret_len = strlen((const char *)correct_secret);
    uint8_t stored_hash[FOTA_DOWNGRADE_SECRET_HASH_SIZE];
    unsigned int stored_hash_len = 0;
    int digest_ok = (EVP_Digest(correct_secret, correct_secret_len,
                                 stored_hash, &stored_hash_len, EVP_sha256(),
                                 NULL) == 1);
    assert(digest_ok);
    assert(stored_hash_len == FOTA_DOWNGRADE_SECRET_HASH_SIZE);

    test_read_secret_hash_valid(scratch_dir, stored_hash);

    test_downgrade_check_allow_when_new_greater();
    test_downgrade_check_up_to_date_when_equal();
    test_downgrade_check_blocked_no_override_configured();
    test_downgrade_check_blocked_with_wrong_secret(stored_hash);
    test_downgrade_check_blocked_with_no_secret_supplied(stored_hash);
    test_downgrade_check_allow_with_correct_secret(stored_hash, correct_secret,
                                                    correct_secret_len);

    printf("%d/%d tests passed\n", tests_run - tests_failed, tests_run);
    return tests_failed == 0 ? 0 : 1;
}
