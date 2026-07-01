#include "fcrypto.h"

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

EVP_PKEY *fota_load_private_key(const char *path) {
    if (path == NULL) {
        return NULL;
    }
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return NULL;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

EVP_PKEY *fota_load_public_key(const char *path) {
    if (path == NULL) {
        return NULL;
    }
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return NULL;
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

fota_crypto_result_t fota_unwrap_key(EVP_PKEY *device_private_key,
                                      const uint8_t *wrapped_key,
                                      size_t wrapped_key_len, uint8_t *out_key,
                                      size_t *out_key_len) {
    if (device_private_key == NULL || wrapped_key == NULL ||
        out_key == NULL || out_key_len == NULL) {
        return FOTA_CRYPTO_ERR_INVALID_ARG;
    }

    fota_crypto_result_t result = FOTA_CRYPTO_ERR_UNWRAP_FAILED;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(device_private_key, NULL);
    if (ctx == NULL) {
        return FOTA_CRYPTO_ERR_UNWRAP_FAILED;
    }

    if (EVP_PKEY_decrypt_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == 1 &&
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) == 1 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) == 1) {
        /* EVP_PKEY_decrypt requires querying the required buffer size
         * first (out=NULL) - passing a buffer sized only for the known
         * final plaintext length (FOTA_AES_KEY_SIZE) fails with
         * "bad length", since the provider sizes its internal check
         * against the RSA modulus, not the eventual unpadded length. */
        size_t required_len = 0;
        if (EVP_PKEY_decrypt(ctx, NULL, &required_len, wrapped_key,
                              wrapped_key_len) == 1) {
            uint8_t *tmp = OPENSSL_malloc(required_len);
            if (tmp != NULL) {
                size_t actual_len = required_len;
                if (EVP_PKEY_decrypt(ctx, tmp, &actual_len, wrapped_key,
                                      wrapped_key_len) == 1 &&
                    actual_len <= *out_key_len) {
                    memcpy(out_key, tmp, actual_len);
                    *out_key_len = actual_len;
                    result = FOTA_CRYPTO_OK;
                }
                /* tmp held unwrapped AES key material - wipe before free. */
                OPENSSL_clear_free(tmp, required_len);
            }
        }
    }

    EVP_PKEY_CTX_free(ctx);
    return result;
}

fota_crypto_result_t fota_verify_signature(EVP_PKEY *signing_public_key,
                                            const uint8_t *data,
                                            size_t data_len,
                                            const uint8_t *signature,
                                            size_t signature_len) {
    if (signing_public_key == NULL || data == NULL || signature == NULL) {
        return FOTA_CRYPTO_ERR_INVALID_ARG;
    }

    fota_crypto_result_t result = FOTA_CRYPTO_ERR_VERIFY_FAILED;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return FOTA_CRYPTO_ERR_VERIFY_FAILED;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL,
                              signing_public_key) == 1) {
        /* EVP_DigestVerify returns 1 only for a valid signature; 0 or
         * negative means invalid/error. This is the entire validity
         * check - no manual digest memcmp anywhere in this function. */
        int rc = EVP_DigestVerify(mdctx, signature, signature_len, data,
                                   data_len);
        if (rc == 1) {
            result = FOTA_CRYPTO_OK;
        }
    }

    EVP_MD_CTX_free(mdctx);
    return result;
}

fota_crypto_result_t fota_decrypt_payload(const uint8_t *key, size_t key_len,
                                           const uint8_t *iv, size_t iv_len,
                                           const uint8_t *ciphertext,
                                           size_t ciphertext_len,
                                           uint8_t *plaintext_out,
                                           size_t *plaintext_out_len) {
    if (key == NULL || iv == NULL || ciphertext == NULL ||
        plaintext_out == NULL || plaintext_out_len == NULL ||
        key_len != FOTA_AES_KEY_SIZE || iv_len != FOTA_AES_IV_SIZE ||
        ciphertext_len == 0 || ciphertext_len > (size_t)INT32_MAX) {
        return FOTA_CRYPTO_ERR_INVALID_ARG;
    }

    fota_crypto_result_t result = FOTA_CRYPTO_ERR_DECRYPT_FAILED;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return FOTA_CRYPTO_ERR_DECRYPT_FAILED;
    }

    int update_len = 0;
    int final_len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) == 1 &&
        EVP_DecryptUpdate(ctx, plaintext_out, &update_len, ciphertext,
                           (int)ciphertext_len) == 1 &&
        EVP_DecryptFinal_ex(ctx, plaintext_out + update_len, &final_len) ==
            1) {
        *plaintext_out_len = (size_t)update_len + (size_t)final_len;
        result = FOTA_CRYPTO_OK;
    }

    EVP_CIPHER_CTX_free(ctx);
    return result;
}
