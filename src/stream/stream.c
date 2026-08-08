// ViChaos v3 — Streaming encrypt/decrypt state machine
#include "../../include/vichaos.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>

struct vichaos_stream_t {
    EVP_CIPHER_CTX *ctx;
    uint8_t key[VICHAOS_KEY_SIZE];
    int is_encrypt;
    int finalized;
    vichaos_result_t error;
    vichaos_options_t options;
};

static vichaos_stream_t *stream_alloc(EVP_CIPHER_CTX *ctx,
                                      const uint8_t key[VICHAOS_KEY_SIZE],
                                      int is_encrypt,
                                      const vichaos_options_t *opts) {
    vichaos_stream_t *s = (vichaos_stream_t *)malloc(sizeof(*s));
    if (!s) { EVP_CIPHER_CTX_free(ctx); return NULL; }
    s->ctx = ctx;
    memcpy(s->key, key, VICHAOS_KEY_SIZE);
    s->is_encrypt = is_encrypt;
    s->finalized = 0;
    s->error = VICHAOS_SUCCESS;
    if (opts) memcpy(&s->options, opts, sizeof(s->options));
    else vichaos_options_init(&s->options);
    return s;
}

static void stream_free(vichaos_stream_t *s) {
    if (!s) return;
    if (s->ctx) EVP_CIPHER_CTX_free(s->ctx);
    vichaos_secure_zeroize(s->key, sizeof(s->key));
    free(s);
}

vichaos_stream_t *vichaos_stream_encrypt_init(const char *password,
                                              size_t password_len,
                                              const vichaos_options_t *options,
                                              uint8_t *header_out,
                                              size_t *header_out_len) {
    vichaos_options_t defaults;
    uint8_t key[VICHAOS_KEY_SIZE];
    uint8_t salt[VICHAOS_SALT_SIZE];
    uint8_t iv[VICHAOS_IV_SIZE];
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;

    if (!header_out || !header_out_len || !password) return NULL;

    if (options) memcpy(&defaults, options, sizeof(defaults));
    else vichaos_options_init(&defaults);

    if (defaults.chunk_size == 0) defaults.chunk_size = VICHAOS_STREAM_CHUNK;

    if (RAND_bytes(salt, VICHAOS_SALT_SIZE) != 1 ||
        RAND_bytes(iv, VICHAOS_IV_SIZE) != 1) {
        return NULL;
    }

    vichaos_result_t r = vichaos_kdf_derive(password, password_len, salt,
                                            defaults.kdf_iter, key);
    if (r != VICHAOS_SUCCESS) return NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { vichaos_secure_zeroize(key, sizeof(key)); return NULL; }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        vichaos_secure_zeroize(key, sizeof(key));
        return NULL;
    }

    memcpy(header_out, VICHAOS_FORMAT_MAGIC, VICHAOS_FORMAT_MAGIC_LEN);
    header_out[VICHAOS_FORMAT_MAGIC_LEN] = VICHAOS_PAYLOAD_VERSION;
    memcpy(header_out + VICHAOS_FORMAT_MAGIC_LEN + 1, salt, VICHAOS_SALT_SIZE);
    memcpy(header_out + VICHAOS_FORMAT_MAGIC_LEN + 1 + VICHAOS_SALT_SIZE, iv, VICHAOS_IV_SIZE);
    *header_out_len = VICHAOS_HEADER_OVERHEAD;

    if (EVP_EncryptUpdate(ctx, NULL, &len, header_out, VICHAOS_HEADER_OVERHEAD) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        vichaos_secure_zeroize(key, sizeof(key));
        return NULL;
    }

    return stream_alloc(ctx, key, 1, &defaults);
}

vichaos_result_t vichaos_stream_encrypt_update(vichaos_stream_t *stream,
                                               const uint8_t *in,
                                               size_t in_len,
                                               uint8_t *out,
                                               size_t *out_len) {
    int len = 0;
    if (!stream || !out_len || (in == NULL && in_len > 0) || (out == NULL && in_len > 0)) {
        return VICHAOS_ERR_NULL_PTR;
    }
    if (stream->is_encrypt != 1 || stream->finalized) return VICHAOS_ERR_INVALID_PARAM;
    if (stream->error != VICHAOS_SUCCESS) return stream->error;

    if (in_len > 0) {
        if (EVP_EncryptUpdate(stream->ctx, out, &len, in, (int)in_len) != 1) {
            stream->error = VICHAOS_ERR_ENCRYPT_FAIL;
            return stream->error;
        }
    } else {
        len = 0;
    }
    *out_len = (size_t)len;
    return VICHAOS_SUCCESS;
}

vichaos_result_t vichaos_stream_encrypt_final(vichaos_stream_t *stream,
                                              uint8_t *tag_out,
                                              size_t *tag_out_len) {
    int len = 0;
    if (!stream || !tag_out || !tag_out_len) return VICHAOS_ERR_NULL_PTR;
    if (stream->is_encrypt != 1 || stream->finalized) return VICHAOS_ERR_INVALID_PARAM;

    if (EVP_EncryptFinal_ex(stream->ctx, NULL, &len) != 1) {
        stream->finalized = 1;
        stream_free(stream);
        return VICHAOS_ERR_ENCRYPT_FAIL;
    }

    if (EVP_CIPHER_CTX_ctrl(stream->ctx, EVP_CTRL_GCM_GET_TAG,
                            VICHAOS_TAG_SIZE, tag_out) != 1) {
        stream->finalized = 1;
        stream_free(stream);
        return VICHAOS_ERR_ENCRYPT_FAIL;
    }

    *tag_out_len = VICHAOS_TAG_SIZE;
    stream->finalized = 1;
    stream_free(stream);
    return VICHAOS_SUCCESS;
}

vichaos_stream_t *vichaos_stream_decrypt_init(const char *password,
                                              size_t password_len,
                                              const uint8_t *header,
                                              size_t header_len,
                                              const vichaos_options_t *options) {
    vichaos_options_t defaults;
    uint8_t key[VICHAOS_KEY_SIZE];
    const uint8_t *salt, *iv;
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;

    if (!password || !header || header_len != VICHAOS_HEADER_OVERHEAD) return NULL;

    if (options) memcpy(&defaults, options, sizeof(defaults));
    else vichaos_options_init(&defaults);

    if (defaults.chunk_size == 0) defaults.chunk_size = VICHAOS_STREAM_CHUNK;

    if (memcmp(header, VICHAOS_FORMAT_MAGIC, VICHAOS_FORMAT_MAGIC_LEN) != 0 ||
        header[VICHAOS_FORMAT_MAGIC_LEN] != VICHAOS_PAYLOAD_VERSION) {
        return NULL;
    }

    salt = header + VICHAOS_FORMAT_MAGIC_LEN + 1;
    iv   = salt + VICHAOS_SALT_SIZE;

    vichaos_result_t r = vichaos_kdf_derive(password, password_len, salt,
                                            defaults.kdf_iter, key);
    if (r != VICHAOS_SUCCESS) return NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { vichaos_secure_zeroize(key, sizeof(key)); return NULL; }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        vichaos_secure_zeroize(key, sizeof(key));
        return NULL;
    }

    if (EVP_DecryptUpdate(ctx, NULL, &len, header, (int)header_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        vichaos_secure_zeroize(key, sizeof(key));
        return NULL;
    }

    return stream_alloc(ctx, key, 0, &defaults);
}

vichaos_result_t vichaos_stream_decrypt_update(vichaos_stream_t *stream,
                                               const uint8_t *in,
                                               size_t in_len,
                                               uint8_t *out,
                                               size_t *out_len) {
    int len = 0;
    if (!stream || !out_len || (in == NULL && in_len > 0) || (out == NULL && in_len > 0)) {
        return VICHAOS_ERR_NULL_PTR;
    }
    if (stream->is_encrypt != 0 || stream->finalized) return VICHAOS_ERR_INVALID_PARAM;
    if (stream->error != VICHAOS_SUCCESS) return stream->error;

    if (in_len > 0) {
        if (EVP_DecryptUpdate(stream->ctx, out, &len, in, (int)in_len) != 1) {
            stream->error = VICHAOS_ERR_DECRYPT_FAIL;
            return stream->error;
        }
    } else {
        len = 0;
    }
    *out_len = (size_t)len;
    return VICHAOS_SUCCESS;
}

vichaos_result_t vichaos_stream_decrypt_final(vichaos_stream_t *stream,
                                              const uint8_t *tag,
                                              size_t tag_len) {
    if (!stream || !tag || tag_len != VICHAOS_TAG_SIZE ||
        stream->is_encrypt != 0 || stream->finalized) {
        return VICHAOS_ERR_INVALID_PARAM;
    }

    vichaos_result_t result = stream->error;
    if (result == VICHAOS_SUCCESS) {
        uint8_t scratch[32] = {0};
        int len = 0;
        if (EVP_CIPHER_CTX_ctrl(stream->ctx, EVP_CTRL_GCM_SET_TAG,
                                VICHAOS_TAG_SIZE, (void *)tag) != 1) {
            result = VICHAOS_ERR_DECRYPT_FAIL;
        } else if (EVP_DecryptFinal_ex(stream->ctx, scratch, &len) <= 0) {
            result = VICHAOS_ERR_AUTH_FAIL;
        }
        vichaos_secure_zeroize(scratch, sizeof(scratch));
    }

    stream->finalized = 1;
    stream_free(stream);
    return result;
}
