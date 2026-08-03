// --------------------------------- ABOUT -------------------------------------
// Original Author: Dx4 (DX4GREY)
// Repository: [https://github.com/DX4GREY](https://github.com/DX4GREY)
// License: MIT (see end of file)
//
// ViChaos v2 — Lightweight file/data encryption helpers for C
// Built on OpenSSL EVP API: PBKDF2-HMAC-SHA256 + AES-256-GCM (AEAD).
//
// v2 replaces the v1 hand-rolled additive/XOR/permutation layer with the
// authenticated cipher AES-256-GCM. This gives:
//   - Industry-standard confidentiality and integrity (auth tag).
//   - Hardware acceleration via AES-NI where available.
//   - Single output allocation (no intermediate plaintext/cipher buffers).
//
// Payload layout (as documented in include/vichaos.h):
//   [MAGIC "ViChaos2" (8)] [VERSION (1) = 2] [SALT (16)] [IV (12)]
//   [CIPHERTEXT (n)] [AUTH TAG (16)]
//
// The magic+version bytes are treated as additional authenticated data (AAD)
// so any tampering with the framing is rejected by the auth tag.
// -----------------------------------------------------------------------------

#include "vichaos.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------------- */
/* Internal helpers                                                           */
/* ------------------------------------------------------------------------- */

static int validate_options(const vichaos_options_t *options,
                            vichaos_result_t *err) {
    if (options == NULL) {
        if (err) *err = VICHAOS_INVALID_ARGUMENT;
        return 0;
    }
    if (options->kdf_iter < VICHAOS_MIN_KDF_ITER ||
        options->kdf_iter > VICHAOS_MAX_KDF_ITER) {
        if (err) *err = VICHAOS_INVALID_ARGUMENT;
        return 0;
    }
    return 1;
}

static vichaos_result_t derive_key(const char *password,
                                   const uint8_t *salt,
                                   uint32_t kdf_iter,
                                   uint8_t key[VICHAOS_KEY_SIZE]) {
    if (password == NULL || salt == NULL || key == NULL) {
        return VICHAOS_INVALID_ARGUMENT;
    }

    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                          salt, VICHAOS_SALT_SIZE,
                          (int)kdf_iter,
                          EVP_sha256(),
                          VICHAOS_KEY_SIZE, key) != 1) {
        return VICHAOS_CRYPTO_ERROR;
    }
    return VICHAOS_OK;
}

/* ------------------------------------------------------------------------- */
/* Public: options init                                                       */
/* ------------------------------------------------------------------------- */

void vichaos_options_init(vichaos_options_t *options) {
    if (options) {
        options->kdf_iter = VICHAOS_DEFAULT_KDF_ITER;
    }
}

/* ------------------------------------------------------------------------- */
/* Public: encryption                                                         */
/* ------------------------------------------------------------------------- */

vichaos_result_t vichaos_encrypt_with_options(
        const uint8_t *data,
        size_t data_len,
        const char *password,
        const vichaos_options_t *options,
        uint8_t **output,
        size_t *output_len) {

    vichaos_result_t result = VICHAOS_OK;
    vichaos_options_t defaults;

    if (output == NULL || output_len == NULL || password == NULL ||
        (data == NULL && data_len > 0)) {
        return VICHAOS_INVALID_ARGUMENT;
    }

    *output = NULL;
    *output_len = 0;

    /* Options may be NULL -> use defaults. */
    if (options == NULL) {
        vichaos_options_init(&defaults);
        options = &defaults;
    }
    if (!validate_options(options, &result)) {
        return result;
    }

    /* Guard against size_t overflow in output length computation. */
    if (data_len > (size_t)-1 - VICHAOS_OVERHEAD) {
        return VICHAOS_INVALID_ARGUMENT;
    }
    const size_t out_len = data_len + VICHAOS_OVERHEAD;

    uint8_t *out = malloc(out_len);
    if (out == NULL) {
        return VICHAOS_MEMORY_ERROR;
    }

    /* ---- Assemble header: magic + version ---- */
    uint8_t *ptr = out;
    memcpy(ptr, VICHAOS_FORMAT_MAGIC, VICHAOS_FORMAT_MAGIC_LEN);
    ptr += VICHAOS_FORMAT_MAGIC_LEN;
    *ptr++ = VICHAOS_VERSION;
    const uint8_t *salt = ptr;
    void *salt_dst = ptr;
    ptr += VICHAOS_SALT_SIZE;
    const uint8_t *iv = ptr;
    void *iv_dst = ptr;
    ptr += VICHAOS_IV_SIZE;
    uint8_t *ciphertext = ptr;
    uint8_t *tag = out + out_len - VICHAOS_TAG_SIZE;

    /* ---- Random salt + IV ---- */
    if (RAND_bytes(salt_dst, VICHAOS_SALT_SIZE) != 1 ||
        RAND_bytes(iv_dst, VICHAOS_IV_SIZE) != 1) {
        result = VICHAOS_CRYPTO_ERROR;
        goto fail;
    }

    /* ---- Derive key ---- */
    uint8_t key[VICHAOS_KEY_SIZE];
    result = derive_key(password, salt, options->kdf_iter, key);
    if (result != VICHAOS_OK) {
        goto fail;
    }

    /* ---- AES-256-GCM encrypt ---- */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        OPENSSL_cleanse(key, sizeof(key));
        result = VICHAOS_CRYPTO_ERROR;
        goto fail;
    }

    int len = 0;
    int final_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, VICHAOS_IV_SIZE,
                            NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        result = VICHAOS_CRYPTO_ERROR;
        goto cleanup_ctx;
    }

    /* Authenticate magic + version (AAD). */
    if (EVP_EncryptUpdate(ctx, NULL, &len,
                          (const unsigned char *)out,
                          VICHAOS_HEADER_OVERHEAD) != 1) {
        result = VICHAOS_CRYPTO_ERROR;
        goto cleanup_ctx;
    }

    /* Encrypt data (GCM updates do not expand size). */
    if (data_len > 0 &&
        EVP_EncryptUpdate(ctx, ciphertext, &len, data, (int)data_len) != 1) {
        result = VICHAOS_CRYPTO_ERROR;
        goto cleanup_ctx;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len) != 1) {
        result = VICHAOS_CRYPTO_ERROR;
        goto cleanup_ctx;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, VICHAOS_TAG_SIZE,
                            tag) != 1) {
        result = VICHAOS_CRYPTO_ERROR;
        goto cleanup_ctx;
    }

cleanup_ctx:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    if (result == VICHAOS_OK) {
        *output = out;
        *output_len = out_len;
        return VICHAOS_OK;
    }

fail:
    OPENSSL_cleanse(out, out_len);
    free(out);
    return result;
}

/* ------------------------------------------------------------------------- */
/* Public: decryption                                                         */
/* ------------------------------------------------------------------------- */

vichaos_result_t vichaos_decrypt_with_options(
        const uint8_t *data,
        size_t data_len,
        const char *password,
        const vichaos_options_t *options,
        uint8_t **output,
        size_t *output_len) {

    vichaos_result_t result = VICHAOS_OK;
    vichaos_options_t defaults;

    if (output == NULL || output_len == NULL || password == NULL ||
        (data == NULL && data_len > 0) || data == NULL) {
        return VICHAOS_INVALID_ARGUMENT;
    }

    *output = NULL;
    *output_len = 0;

    /* Options may be NULL -> use defaults. */
    if (options == NULL) {
        vichaos_options_init(&defaults);
        options = &defaults;
    }
    if (!validate_options(options, &result)) {
        return result;
    }

    /* Minimal framing check. */
    if (data_len < VICHAOS_OVERHEAD) {
        return VICHAOS_INVALID_HEADER;
    }

    /* ---- Verify magic + version ---- */
    if (memcmp(data, VICHAOS_FORMAT_MAGIC, VICHAOS_FORMAT_MAGIC_LEN) != 0) {
        return VICHAOS_INVALID_HEADER;
    }
    if (data[VICHAOS_FORMAT_MAGIC_LEN] != VICHAOS_VERSION) {
        return VICHAOS_UNSUPPORTED_VERSION;
    }

    const uint8_t *salt = data + VICHAOS_FORMAT_MAGIC_LEN + 1;
    const uint8_t *iv = salt + VICHAOS_SALT_SIZE;
    const uint8_t *ciphertext = iv + VICHAOS_IV_SIZE;
    const size_t plaintext_len = data_len - VICHAOS_OVERHEAD;
    const uint8_t *tag = data + data_len - VICHAOS_TAG_SIZE;

    /* ---- Derive key ---- */
    uint8_t key[VICHAOS_KEY_SIZE];
    result = derive_key(password, salt, options->kdf_iter, key);
    if (result != VICHAOS_OK) {
        return result;
    }

    /* ---- AES-256-GCM decrypt ---- */
    uint8_t *plaintext = NULL;
    if (plaintext_len > 0) {
        plaintext = malloc(plaintext_len);
        if (plaintext == NULL) {
            OPENSSL_cleanse(key, sizeof(key));
            return VICHAOS_MEMORY_ERROR;
        }
    }
    /* EVP_DecryptFinal_ex requires a non-NULL output buffer even for
     * empty plaintext; use a scratch buffer in that case. */
    uint8_t scratch[32];
    int len = 0;
    int final_len = 0;
    uint8_t *final_out = (plaintext_len > 0) ? (plaintext + len) : scratch;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        OPENSSL_cleanse(key, sizeof(key));
        free(plaintext);
        return VICHAOS_CRYPTO_ERROR;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, VICHAOS_IV_SIZE,
                            NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        result = VICHAOS_CRYPTO_ERROR;
        goto cleanup;
    }

    /* Authenticate magic + version (AAD). */
    if (EVP_DecryptUpdate(ctx, NULL, &len, data,
                          VICHAOS_HEADER_OVERHEAD) != 1) {
        result = VICHAOS_CRYPTO_ERROR;
        goto cleanup;
    }

    if (plaintext_len > 0 &&
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
                          (int)plaintext_len) != 1) {
        result = VICHAOS_CRYPTO_ERROR;
        goto cleanup;
    }

    /* Set expected tag before final. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, VICHAOS_TAG_SIZE,
                            (void *)tag) != 1) {
        result = VICHAOS_CRYPTO_ERROR;
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, final_out, &final_len) <= 0) {
        result = VICHAOS_HMAC_MISMATCH;
        goto cleanup;
    }

    *output = plaintext;
    *output_len = plaintext_len;
    plaintext = NULL; /* ownership transferred */

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(scratch, sizeof(scratch));
    if (plaintext != NULL) {
        OPENSSL_cleanse(plaintext, plaintext_len);
        free(plaintext);
    }
    return result;
}

/* ------------------------------------------------------------------------- */
/* Streaming API (constant memory, chunked AEAD)                              */
/* ------------------------------------------------------------------------- */

struct vichaos_stream_t {
    EVP_CIPHER_CTX *ctx;
    uint8_t key[VICHAOS_KEY_SIZE];
    int is_encrypt;
    int finalized;
    vichaos_result_t error;
};

static vichaos_stream_t *stream_alloc(EVP_CIPHER_CTX *ctx,
                                      const uint8_t key[VICHAOS_KEY_SIZE],
                                      int is_encrypt) {
    vichaos_stream_t *s = malloc(sizeof(*s));
    if (s == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    s->ctx = ctx;
    memcpy(s->key, key, VICHAOS_KEY_SIZE);
    s->is_encrypt = is_encrypt;
    s->finalized = 0;
    s->error = VICHAOS_OK;
    return s;
}

static void stream_free(vichaos_stream_t *s) {
    if (s == NULL) return;
    if (s->ctx) EVP_CIPHER_CTX_free(s->ctx);
    OPENSSL_cleanse(s->key, sizeof(s->key));
    free(s);
}

vichaos_stream_t *vichaos_stream_encrypt_init(
        const char *password,
        const vichaos_options_t *options,
        uint8_t *header_out,
        size_t *header_out_len) {

    vichaos_options_t defaults;
    if (header_out == NULL || header_out_len == NULL || password == NULL) {
        return NULL;
    }

    if (options == NULL) {
        vichaos_options_init(&defaults);
        options = &defaults;
    }
    vichaos_result_t verr;
    if (!validate_options(options, &verr)) {
        return NULL;
    }

    /* Assemble header: magic + version + salt + iv */
    memcpy(header_out, VICHAOS_FORMAT_MAGIC, VICHAOS_FORMAT_MAGIC_LEN);
    header_out[VICHAOS_FORMAT_MAGIC_LEN] = VICHAOS_VERSION;
    uint8_t *salt = header_out + VICHAOS_FORMAT_MAGIC_LEN + 1;
    uint8_t *iv = salt + VICHAOS_SALT_SIZE;

    if (RAND_bytes(salt, VICHAOS_SALT_SIZE) != 1 ||
        RAND_bytes(iv, VICHAOS_IV_SIZE) != 1) {
        return NULL;
    }
    *header_out_len = VICHAOS_HEADER_OVERHEAD;

    uint8_t key[VICHAOS_KEY_SIZE];
    if (derive_key(password, salt, options->kdf_iter, key) != VICHAOS_OK) {
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        OPENSSL_cleanse(key, sizeof(key));
        return NULL;
    }

    int len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, VICHAOS_IV_SIZE,
                            NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        /* authenticate the header as AAD */
        EVP_EncryptUpdate(ctx, NULL, &len, header_out,
                          VICHAOS_HEADER_OVERHEAD) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        return NULL;
    }

    return stream_alloc(ctx, key, 1);
}

vichaos_result_t vichaos_stream_encrypt_update(
        vichaos_stream_t *stream,
        const uint8_t *in,
        size_t in_len,
        uint8_t *out,
        size_t *out_len) {

    if (stream == NULL || out_len == NULL ||
        (in == NULL && in_len > 0) || (out == NULL && in_len > 0) ||
        stream->is_encrypt == 0 || stream->finalized) {
        return VICHAOS_INVALID_ARGUMENT;
    }

    if (stream->error != VICHAOS_OK) {
        return stream->error;
    }

    int len = 0;
    if (in_len > 0 &&
        EVP_EncryptUpdate(stream->ctx, out, &len, in, (int)in_len) != 1) {
        stream->error = VICHAOS_CRYPTO_ERROR;
        return stream->error;
    }
    *out_len = (size_t)len;
    return VICHAOS_OK;
}

vichaos_result_t vichaos_stream_encrypt_final(
        vichaos_stream_t *stream,
        uint8_t *tag_out,
        size_t *tag_out_len) {

    if (stream == NULL || tag_out == NULL || tag_out_len == NULL ||
        stream->is_encrypt == 0 || stream->finalized) {
        return VICHAOS_INVALID_ARGUMENT;
    }

    vichaos_result_t result = stream->error;
    if (result == VICHAOS_OK) {
        int len = 0;
        /* GCM final produces no trailing ciphertext */
        if (EVP_EncryptFinal_ex(stream->ctx, tag_out, &len) != 1 ||
            EVP_CIPHER_CTX_ctrl(stream->ctx, EVP_CTRL_GCM_GET_TAG,
                                VICHAOS_TAG_SIZE, tag_out) != 1) {
            result = VICHAOS_CRYPTO_ERROR;
        } else {
            *tag_out_len = VICHAOS_TAG_SIZE;
        }
    }

    stream->finalized = 1;
    stream_free(stream);
    return result;
}

vichaos_stream_t *vichaos_stream_decrypt_init(
        const char *password,
        const uint8_t *header,
        size_t header_len,
        const vichaos_options_t *options) {

    vichaos_options_t defaults;
    if (password == NULL || header == NULL ||
        header_len < VICHAOS_HEADER_OVERHEAD) {
        return NULL;
    }

    if (memcmp(header, VICHAOS_FORMAT_MAGIC, VICHAOS_FORMAT_MAGIC_LEN) != 0) {
        return NULL;
    }
    if (header[VICHAOS_FORMAT_MAGIC_LEN] != VICHAOS_VERSION) {
        return NULL;
    }

    if (options == NULL) {
        vichaos_options_init(&defaults);
        options = &defaults;
    }
    vichaos_result_t verr;
    if (!validate_options(options, &verr)) {
        return NULL;
    }

    const uint8_t *salt = header + VICHAOS_FORMAT_MAGIC_LEN + 1;
    const uint8_t *iv = salt + VICHAOS_SALT_SIZE;

    uint8_t key[VICHAOS_KEY_SIZE];
    if (derive_key(password, salt, options->kdf_iter, key) != VICHAOS_OK) {
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        OPENSSL_cleanse(key, sizeof(key));
        return NULL;
    }

    int len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, VICHAOS_IV_SIZE,
                            NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &len, header,
                          VICHAOS_HEADER_OVERHEAD) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        return NULL;
    }

    return stream_alloc(ctx, key, 0);
}

vichaos_result_t vichaos_stream_decrypt_update(
        vichaos_stream_t *stream,
        const uint8_t *in,
        size_t in_len,
        uint8_t *out,
        size_t *out_len) {

    if (stream == NULL || out_len == NULL ||
        (in == NULL && in_len > 0) || (out == NULL && in_len > 0) ||
        stream->is_encrypt != 0 || stream->finalized) {
        return VICHAOS_INVALID_ARGUMENT;
    }

    if (stream->error != VICHAOS_OK) {
        return stream->error;
    }

    int len = 0;
    if (in_len > 0 &&
        EVP_DecryptUpdate(stream->ctx, out, &len, in, (int)in_len) != 1) {
        stream->error = VICHAOS_CRYPTO_ERROR;
        return stream->error;
    }
    *out_len = (size_t)len;
    return VICHAOS_OK;
}

vichaos_result_t vichaos_stream_decrypt_final(
        vichaos_stream_t *stream,
        const uint8_t *tag,
        size_t tag_len) {

    if (stream == NULL || tag == NULL || tag_len != VICHAOS_TAG_SIZE ||
        stream->is_encrypt != 0 || stream->finalized) {
        return VICHAOS_INVALID_ARGUMENT;
    }

    vichaos_result_t result = stream->error;
    if (result == VICHAOS_OK) {
        if (EVP_CIPHER_CTX_ctrl(stream->ctx, EVP_CTRL_GCM_SET_TAG,
                                VICHAOS_TAG_SIZE, (void *)tag) != 1) {
            result = VICHAOS_CRYPTO_ERROR;
        } else {
            uint8_t scratch[32];
            int len = 0;
            if (EVP_DecryptFinal_ex(stream->ctx, scratch, &len) <= 0) {
                result = VICHAOS_HMAC_MISMATCH;
            }
            OPENSSL_cleanse(scratch, sizeof(scratch));
        }
    }

    stream->finalized = 1;
    stream_free(stream);
    return result;
}

/* ------------------------------------------------------------------------- */
/* Public: defaults & helpers                                                 */
/* ------------------------------------------------------------------------- */

vichaos_result_t vichaos_encrypt(const uint8_t *data, size_t data_len,
                                 const char *password,
                                 uint8_t **output, size_t *output_len) {
    return vichaos_encrypt_with_options(data, data_len, password, NULL,
                                        output, output_len);
}

vichaos_result_t vichaos_decrypt(const uint8_t *data, size_t data_len,
                                 const char *password,
                                 uint8_t **output, size_t *output_len) {
    return vichaos_decrypt_with_options(data, data_len, password, NULL,
                                        output, output_len);
}

const char *vichaos_error_string(vichaos_result_t result) {
    switch (result) {
        case VICHAOS_OK:                return "Success";
        case VICHAOS_INVALID_ARGUMENT:  return "Invalid argument";
        case VICHAOS_INVALID_HEADER:    return "Invalid header";
        case VICHAOS_UNSUPPORTED_VERSION: return "Unsupported payload version";
        case VICHAOS_HMAC_MISMATCH:     return "Authentication tag verification failed";
        case VICHAOS_MEMORY_ERROR:      return "Memory allocation error";
        case VICHAOS_CRYPTO_ERROR:      return "Cryptographic operation failed";
        default:                        return "Unknown error";
    }
}

void vichaos_free(void *ptr) {
    free(ptr);
}

// -----------------------------------------------------------------------------
// MIT License
//
// Copyright (c) 2026 DX4GREY
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// -----------------------------------------------------------------------------