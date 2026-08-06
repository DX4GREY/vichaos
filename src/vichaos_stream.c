// --------------------------------- ABOUT -------------------------------------
// Original Author: Dx4 (DX4GREY)
// Repository: [https://github.com/DX4GREY](https://github.com/DX4GREY)
// License: MIT (see end of file)
//
// ViChaos v2 — Streaming API (constant memory, chunked AEAD)
// -----------------------------------------------------------------------------

#include "vichaos.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>

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
    /* VICHAOS_IV_SIZE (12) is the GCM default IV length, so the
     * EVP_CTRL_GCM_SET_IVLEN call is omitted to save a ctrl round-trip. */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
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
    /* VICHAOS_IV_SIZE (12) is the GCM default IV length, so the
     * EVP_CTRL_GCM_SET_IVLEN call is omitted to save a ctrl round-trip. */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
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