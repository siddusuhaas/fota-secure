#ifndef FOTA_SECURE_FCRYPTO_H
#define FOTA_SECURE_FCRYPTO_H

/* libcrypto (OpenSSL) wrappers for the three crypto operations the
 * consumer performs: RSA-OAEP unwrap of the wrapped AES key, RSA
 * PKCS#1v1.5/SHA-256 signature verification, and AES-256-CBC decrypt.
 * See docs/FORMAT_SPEC.md for the algorithms/padding this must match,
 * and docs/THREAT_MODEL.md item 5 for why verification must happen
 * before decryption is ever attempted. Link -lcrypto directly - no
 * shelling out to an openssl binary (CLAUDE.md ground rule 4). */

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>

#define FOTA_AES_KEY_SIZE 32u
#define FOTA_AES_IV_SIZE 16u

typedef enum {
    FOTA_CRYPTO_OK = 0,
    FOTA_CRYPTO_ERR_INVALID_ARG,
    FOTA_CRYPTO_ERR_UNWRAP_FAILED,
    FOTA_CRYPTO_ERR_VERIFY_FAILED,
    FOTA_CRYPTO_ERR_DECRYPT_FAILED
} fota_crypto_result_t;

/* Load a PEM private/public key from a file path. Returns NULL on any
 * failure (missing file, malformed PEM, wrong key type). Caller owns the
 * result and must EVP_PKEY_free() it. */
EVP_PKEY *fota_load_private_key(const char *path);
EVP_PKEY *fota_load_public_key(const char *path);

/* RSA-OAEP (SHA-256, MGF1-SHA256) unwrap of a wrapped AES key using the
 * device's private key. out_key must have room for at least
 * FOTA_AES_KEY_SIZE bytes; *out_key_len is an in/out parameter: on entry
 * the capacity of out_key, on success (FOTA_CRYPTO_OK) the actual
 * unwrapped key length. */
fota_crypto_result_t fota_unwrap_key(EVP_PKEY *device_private_key,
                                      const uint8_t *wrapped_key,
                                      size_t wrapped_key_len, uint8_t *out_key,
                                      size_t *out_key_len);

/* RSA PKCS#1v1.5/SHA-256 signature verification over data. Returns
 * FOTA_CRYPTO_OK only when the signature is valid. The validity check is
 * entirely EVP_DigestVerify's own return value - never a manual digest
 * byte-comparison - to avoid both a reimplementation bug and a
 * non-constant-time comparison. */
fota_crypto_result_t fota_verify_signature(EVP_PKEY *signing_public_key,
                                            const uint8_t *data,
                                            size_t data_len,
                                            const uint8_t *signature,
                                            size_t signature_len);

/* AES-256-CBC decrypt + PKCS#7 unpad. key_len must be FOTA_AES_KEY_SIZE
 * and iv_len must be FOTA_AES_IV_SIZE. plaintext_out must have room for
 * at least ciphertext_len + FOTA_AES_IV_SIZE bytes (OpenSSL's own
 * documented sizing requirement for EVP_DecryptUpdate's output buffer,
 * even though the actual plaintext is never longer than the
 * ciphertext). *plaintext_out_len receives the actual unpadded length on
 * success.
 *
 * This function provides no integrity check of its own (CBC has none) -
 * callers must always call fota_verify_signature successfully before
 * ever calling this, per docs/THREAT_MODEL.md item 5. A corrupted
 * ciphertext byte can still decrypt "successfully" here (garbage
 * plaintext, no error) if it doesn't happen to break the final block's
 * padding - that corruption must already have been caught upstream by
 * signature verification. */
fota_crypto_result_t fota_decrypt_payload(const uint8_t *key, size_t key_len,
                                           const uint8_t *iv, size_t iv_len,
                                           const uint8_t *ciphertext,
                                           size_t ciphertext_len,
                                           uint8_t *plaintext_out,
                                           size_t *plaintext_out_len);

#endif /* FOTA_SECURE_FCRYPTO_H */
