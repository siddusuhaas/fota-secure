/* Interop tests: fixtures under the directory passed as argv[1] are
 * produced by the real Python packager (generate_fcrypto_fixtures.py),
 * using real keygen output. A pass here means Python-packaged crypto
 * output is genuinely readable by this C code - not just that this
 * code is internally self-consistent. */

#include "../src/fcrypto.h"

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

static uint8_t *read_file(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "cannot open fixture %s\n", path);
        exit(2);
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "cannot seek fixture %s\n", path);
        exit(2);
    }
    long size = ftell(fp);
    if (size < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "cannot determine size of fixture %s\n", path);
        exit(2);
    }

    uint8_t *buf = malloc((size_t)size > 0 ? (size_t)size : 1);
    assert(buf != NULL);
    size_t read_n = fread(buf, 1, (size_t)size, fp);
    fclose(fp);
    assert(read_n == (size_t)size);

    *out_len = (size_t)size;
    return buf;
}

static char *join_path(const char *dir, const char *name) {
    size_t len = strlen(dir) + strlen(name) + 2;
    char *out = malloc(len);
    assert(out != NULL);
    snprintf(out, len, "%s/%s", dir, name);
    return out;
}

typedef struct {
    EVP_PKEY *device_private;
    EVP_PKEY *signing_public;
    EVP_PKEY *signing_private; /* used only as a "wrong key" in negative tests */

    uint8_t *header;
    size_t header_len;
    uint8_t *wrapped_key;
    size_t wrapped_key_len;
    uint8_t *signature;
    size_t signature_len;
    uint8_t *ciphertext;
    size_t ciphertext_len;
    uint8_t *aes_key;
    size_t aes_key_len;
    uint8_t *iv;
    size_t iv_len;
    uint8_t *plaintext;
    size_t plaintext_len;
    uint8_t *tampered_ciphertext;
    size_t tampered_ciphertext_len;
    uint8_t *tampered_signature;
    size_t tampered_signature_len;
} fixtures_t;

static fixtures_t load_fixtures(const char *dir) {
    fixtures_t f;
    memset(&f, 0, sizeof(f));

    char *keys_dir = join_path(dir, "keys");
    char *p;

    p = join_path(keys_dir, "device_private.pem");
    f.device_private = fota_load_private_key(p);
    free(p);
    p = join_path(keys_dir, "signing_public.pem");
    f.signing_public = fota_load_public_key(p);
    free(p);
    p = join_path(keys_dir, "signing_private.pem");
    f.signing_private = fota_load_private_key(p);
    free(p);
    free(keys_dir);

    p = join_path(dir, "header.bin");
    f.header = read_file(p, &f.header_len);
    free(p);
    p = join_path(dir, "wrapped_key.bin");
    f.wrapped_key = read_file(p, &f.wrapped_key_len);
    free(p);
    p = join_path(dir, "signature.bin");
    f.signature = read_file(p, &f.signature_len);
    free(p);
    p = join_path(dir, "ciphertext.bin");
    f.ciphertext = read_file(p, &f.ciphertext_len);
    free(p);
    p = join_path(dir, "aes_key.bin");
    f.aes_key = read_file(p, &f.aes_key_len);
    free(p);
    p = join_path(dir, "iv.bin");
    f.iv = read_file(p, &f.iv_len);
    free(p);
    p = join_path(dir, "plaintext.bin");
    f.plaintext = read_file(p, &f.plaintext_len);
    free(p);
    p = join_path(dir, "tampered_ciphertext.bin");
    f.tampered_ciphertext = read_file(p, &f.tampered_ciphertext_len);
    free(p);
    p = join_path(dir, "tampered_signature.bin");
    f.tampered_signature = read_file(p, &f.tampered_signature_len);
    free(p);

    return f;
}

static void free_fixtures(fixtures_t *f) {
    EVP_PKEY_free(f->device_private);
    EVP_PKEY_free(f->signing_public);
    EVP_PKEY_free(f->signing_private);
    free(f->header);
    free(f->wrapped_key);
    free(f->signature);
    free(f->ciphertext);
    free(f->aes_key);
    free(f->iv);
    free(f->plaintext);
    free(f->tampered_ciphertext);
    free(f->tampered_signature);
}

static uint8_t *build_signed_data(const fixtures_t *f, const uint8_t *wrapped_key,
                                   size_t wrapped_key_len,
                                   const uint8_t *ciphertext,
                                   size_t ciphertext_len, size_t *out_len) {
    size_t total = f->header_len + wrapped_key_len + ciphertext_len;
    uint8_t *buf = malloc(total);
    assert(buf != NULL);
    memcpy(buf, f->header, f->header_len);
    memcpy(buf + f->header_len, wrapped_key, wrapped_key_len);
    memcpy(buf + f->header_len + wrapped_key_len, ciphertext, ciphertext_len);
    *out_len = total;
    return buf;
}

static void test_unwrap_round_trip(fixtures_t *f) {
    uint8_t out_key[FOTA_AES_KEY_SIZE];
    size_t out_key_len = sizeof(out_key);

    fota_crypto_result_t result =
        fota_unwrap_key(f->device_private, f->wrapped_key, f->wrapped_key_len,
                         out_key, &out_key_len);

    CHECK(result == FOTA_CRYPTO_OK);
    CHECK(out_key_len == f->aes_key_len);
    CHECK(memcmp(out_key, f->aes_key, f->aes_key_len) == 0);
}

static void test_unwrap_fails_with_wrong_private_key(fixtures_t *f) {
    uint8_t out_key[FOTA_AES_KEY_SIZE];
    size_t out_key_len = sizeof(out_key);

    /* signing_private is a real but *different* keypair - a realistic
     * wrong key, not an ad hoc stand-in. */
    fota_crypto_result_t result =
        fota_unwrap_key(f->signing_private, f->wrapped_key,
                         f->wrapped_key_len, out_key, &out_key_len);

    CHECK(result != FOTA_CRYPTO_OK);
}

static void test_verify_signature_round_trip(fixtures_t *f) {
    size_t signed_data_len;
    uint8_t *signed_data =
        build_signed_data(f, f->wrapped_key, f->wrapped_key_len,
                           f->ciphertext, f->ciphertext_len, &signed_data_len);

    fota_crypto_result_t result =
        fota_verify_signature(f->signing_public, signed_data, signed_data_len,
                               f->signature, f->signature_len);

    CHECK(result == FOTA_CRYPTO_OK);
    free(signed_data);
}

static void test_verify_fails_on_tampered_ciphertext(fixtures_t *f) {
    size_t signed_data_len;
    uint8_t *signed_data = build_signed_data(
        f, f->wrapped_key, f->wrapped_key_len, f->tampered_ciphertext,
        f->tampered_ciphertext_len, &signed_data_len);

    fota_crypto_result_t result =
        fota_verify_signature(f->signing_public, signed_data, signed_data_len,
                               f->signature, f->signature_len);

    /* This is the verify-then-decrypt boundary from
     * docs/THREAT_MODEL.md item 5: a tampered ciphertext byte must be
     * caught here, at signature verification, before decryption is ever
     * attempted - see test_decrypt_does_not_detect_tampered_ciphertext
     * below for why AES-CBC decrypt alone would NOT have caught it. */
    CHECK(result != FOTA_CRYPTO_OK);
    free(signed_data);
}

static void test_verify_fails_on_tampered_signature(fixtures_t *f) {
    size_t signed_data_len;
    uint8_t *signed_data =
        build_signed_data(f, f->wrapped_key, f->wrapped_key_len,
                           f->ciphertext, f->ciphertext_len, &signed_data_len);

    fota_crypto_result_t result = fota_verify_signature(
        f->signing_public, signed_data, signed_data_len,
        f->tampered_signature, f->tampered_signature_len);

    CHECK(result != FOTA_CRYPTO_OK);
    free(signed_data);
}

static void test_decrypt_round_trip(fixtures_t *f) {
    uint8_t *plaintext_out = malloc(f->ciphertext_len + FOTA_AES_IV_SIZE);
    assert(plaintext_out != NULL);
    size_t plaintext_out_len = 0;

    fota_crypto_result_t result = fota_decrypt_payload(
        f->aes_key, f->aes_key_len, f->iv, f->iv_len, f->ciphertext,
        f->ciphertext_len, plaintext_out, &plaintext_out_len);

    CHECK(result == FOTA_CRYPTO_OK);
    CHECK(plaintext_out_len == f->plaintext_len);
    CHECK(memcmp(plaintext_out, f->plaintext, f->plaintext_len) == 0);

    free(plaintext_out);
}

/* AES-CBC has no built-in integrity check. Flipping one ciphertext byte
 * in an interior block corrupts only that block's decrypted plaintext
 * (and the corresponding bits of the next block, via CBC chaining) - it
 * does NOT touch the final block's PKCS#7 padding, so
 * EVP_DecryptFinal_ex still reports success. Decrypt alone cannot detect
 * this tamper; only signature verification can (proven above in
 * test_verify_fails_on_tampered_ciphertext) - which is exactly why
 * docs/THREAT_MODEL.md item 5 requires verify-then-decrypt ordering. */
static void test_decrypt_does_not_detect_tampered_ciphertext(fixtures_t *f) {
    uint8_t *plaintext_out =
        malloc(f->tampered_ciphertext_len + FOTA_AES_IV_SIZE);
    assert(plaintext_out != NULL);
    size_t plaintext_out_len = 0;

    fota_crypto_result_t result = fota_decrypt_payload(
        f->aes_key, f->aes_key_len, f->iv, f->iv_len, f->tampered_ciphertext,
        f->tampered_ciphertext_len, plaintext_out, &plaintext_out_len);

    CHECK(result == FOTA_CRYPTO_OK);
    CHECK(memcmp(plaintext_out, f->plaintext, plaintext_out_len) != 0);

    free(plaintext_out);
}

static void test_decrypt_fails_on_truncated_ciphertext(fixtures_t *f) {
    uint8_t *plaintext_out = malloc(f->ciphertext_len + FOTA_AES_IV_SIZE);
    assert(plaintext_out != NULL);
    size_t plaintext_out_len = 0;

    /* Not a multiple of the AES block size - must fail cleanly, not
     * crash or read/write out of bounds. */
    size_t truncated_len = f->ciphertext_len - 1;
    fota_crypto_result_t result = fota_decrypt_payload(
        f->aes_key, f->aes_key_len, f->iv, f->iv_len, f->ciphertext,
        truncated_len, plaintext_out, &plaintext_out_len);

    CHECK(result != FOTA_CRYPTO_OK);
    free(plaintext_out);
}

static void test_decrypt_fails_with_wrong_key(fixtures_t *f) {
    uint8_t wrong_key[FOTA_AES_KEY_SIZE];
    memset(wrong_key, 0x42, sizeof(wrong_key)); /* definitely not the real key */

    uint8_t *plaintext_out = malloc(f->ciphertext_len + FOTA_AES_IV_SIZE);
    assert(plaintext_out != NULL);
    size_t plaintext_out_len = 0;

    fota_crypto_result_t result = fota_decrypt_payload(
        wrong_key, sizeof(wrong_key), f->iv, f->iv_len, f->ciphertext,
        f->ciphertext_len, plaintext_out, &plaintext_out_len);

    /* Wrong key -> garbage last block -> PKCS#7 unpad rejects it. */
    CHECK(result != FOTA_CRYPTO_OK);
    free(plaintext_out);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <fixtures-dir>\n", argv[0]);
        return 2;
    }

    fixtures_t f = load_fixtures(argv[1]);
    assert(f.device_private != NULL);
    assert(f.signing_public != NULL);
    assert(f.signing_private != NULL);

    test_unwrap_round_trip(&f);
    test_unwrap_fails_with_wrong_private_key(&f);
    test_verify_signature_round_trip(&f);
    test_verify_fails_on_tampered_ciphertext(&f);
    test_verify_fails_on_tampered_signature(&f);
    test_decrypt_round_trip(&f);
    test_decrypt_does_not_detect_tampered_ciphertext(&f);
    test_decrypt_fails_on_truncated_ciphertext(&f);
    test_decrypt_fails_with_wrong_key(&f);

    free_fixtures(&f);

    printf("%d/%d tests passed\n", tests_run - tests_failed, tests_run);
    return tests_failed == 0 ? 0 : 1;
}
