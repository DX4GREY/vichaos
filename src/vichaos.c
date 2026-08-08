// ViChaos v3 — Library glue and backward-compatible convenience wrappers
#include "../include/vichaos.h"
#include <string.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>

struct vichaos_cipher_ctx_t {
    EVP_CIPHER_CTX *encrypt_ctx;
    EVP_CIPHER_CTX *decrypt_ctx;
    uint8_t key[VICHAOS_KEY_SIZE];
    int initialized;
};

static vichaos_options_t g_default_options;
static int g_initialized = 0;

vichaos_result_t vichaos_global_init(void) {
    if (g_initialized) return VICHAOS_SUCCESS;
    vichaos_options_init(&g_default_options);
    vichaos_openssl_init();
    g_initialized = 1;
    return VICHAOS_SUCCESS;
}

void vichaos_global_cleanup(void) {
    if (!g_initialized) return;
    vichaos_openssl_cleanup();
    vichaos_secure_zeroize(&g_default_options, sizeof(g_default_options));
    g_initialized = 0;
}

vichaos_result_t vichaos_openssl_check(int openssl_ret) {
    return openssl_ret == 1 ? VICHAOS_SUCCESS : VICHAOS_ERR_OPENSSL;
}

void vichaos_openssl_init(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /* OpenSSL 1.0.x thread-safety callbacks would go here */
#endif
}

void vichaos_options_init(vichaos_options_t *options) {
    if (options) {
        options->kdf_iter = VICHAOS_DEFAULT_KDF_ITER;
        options->chunk_size = 0;
        options->disable_aesni = 0;
    }
}


void vichaos_openssl_cleanup(void) {
    /* No-op on modern OpenSSL */
}

int vichaos_hardware_aes_supported(void) {
#if defined(__AVX512F__) || defined(__AVX2__) || defined(__AES__)
    return 1;
#else
    return 0;
#endif
}

int vichaos_disable_core_dump(void) {
#if defined(__linux__)
    struct rlimit rl = { 0, 0 };
    return setrlimit(RLIMIT_CORE, &rl);
#else
    return -1;
#endif
}

int vichaos_mlock(const void *addr, size_t len) {
#if defined(__linux__) || defined(__APPLE__)
    return mlock(addr, len);
#else
    return -1;
#endif
}

int vichaos_munlock(const void *addr, size_t len) {
#if defined(__linux__) || defined(__APPLE__)
    return munlock(addr, len);
#else
    return -1;
#endif
}

vichaos_result_t vichaos_payload_parse(const uint8_t *data,
                                       size_t data_len,
                                       vichaos_payload_header_t *header,
                                       const uint8_t **ciphertext,
                                       size_t *ciphertext_len,
                                       const uint8_t **tag,
                                       size_t *tag_len) {
    if (!data || !header || !ciphertext || !ciphertext_len || !tag || !tag_len) {
        return VICHAOS_ERR_NULL_PTR;
    }
    if (data_len < VICHAOS_OVERHEAD) return VICHAOS_ERR_BUFFER_TOO_SMALL;

    memcpy(header, data, sizeof(*header));
    *ciphertext = data + VICHAOS_HEADER_OVERHEAD;
    *ciphertext_len = data_len - VICHAOS_OVERHEAD;
    *tag = data + data_len - VICHAOS_TAG_SIZE;
    *tag_len = VICHAOS_TAG_SIZE;
    return VICHAOS_SUCCESS;
}

vichaos_result_t vichaos_payload_validate(const vichaos_payload_header_t *header) {
    if (!header) return VICHAOS_ERR_NULL_PTR;
    if (memcmp(header->magic, VICHAOS_FORMAT_MAGIC, VICHAOS_FORMAT_MAGIC_LEN) != 0) {
        return VICHAOS_ERR_INVALID_PARAM;
    }
    if (header->version != VICHAOS_PAYLOAD_VERSION) {
        return VICHAOS_ERR_VERSION_MISMATCH;
    }
    return VICHAOS_SUCCESS;
}

vichaos_result_t vichaos_encrypt(const uint8_t *plaintext,
                                 size_t plaintext_len,
                                 const char *password,
                                 size_t password_len,
                                 const vichaos_options_t *options,
                                 uint8_t **output,
                                 size_t *output_len) {
    vichaos_options_t opts;
    uint8_t *out = NULL;
    uint8_t key[VICHAOS_KEY_SIZE];
    uint8_t salt[VICHAOS_SALT_SIZE];
    uint8_t iv[VICHAOS_IV_SIZE];
    uint8_t tag[VICHAOS_TAG_SIZE];
    size_t total_len = 0;
    vichaos_result_t r = VICHAOS_SUCCESS;

    if (!password || !output || !output_len) return VICHAOS_ERR_NULL_PTR;
    if (!plaintext && plaintext_len > 0) return VICHAOS_ERR_NULL_PTR;

    *output = NULL;
    *output_len = 0;

    if (options) memcpy(&opts, options, sizeof(opts));
    else vichaos_options_init(&opts);

    if (opts.chunk_size == 0) opts.chunk_size = VICHAOS_STREAM_CHUNK;

    if (RAND_bytes(salt, VICHAOS_SALT_SIZE) != 1 ||
        RAND_bytes(iv, VICHAOS_IV_SIZE) != 1) {
        return VICHAOS_ERR_OPENSSL;
    }

    if (plaintext_len > SIZE_MAX - VICHAOS_OVERHEAD) return VICHAOS_ERR_BUFFER_TOO_SMALL;
    total_len = plaintext_len + VICHAOS_OVERHEAD;

    if (password_len == 0) password_len = strlen(password);

    r = vichaos_kdf_derive(password, password_len, salt, opts.kdf_iter, key);
    if (r != VICHAOS_SUCCESS) return r;

    out = (uint8_t *)malloc(total_len);
    if (!out) { vichaos_secure_zeroize(key, sizeof(key)); return VICHAOS_ERR_MEMORY_ALLOC; }

    memcpy(out, VICHAOS_FORMAT_MAGIC, VICHAOS_FORMAT_MAGIC_LEN);
    out[VICHAOS_FORMAT_MAGIC_LEN] = VICHAOS_PAYLOAD_VERSION;
    memcpy(out + VICHAOS_FORMAT_MAGIC_LEN + 1, salt, VICHAOS_SALT_SIZE);
    memcpy(out + VICHAOS_FORMAT_MAGIC_LEN + 1 + VICHAOS_SALT_SIZE, iv, VICHAOS_IV_SIZE);

    {
        uint8_t *ciphertext = out + VICHAOS_HEADER_OVERHEAD;
        r = vichaos_cipher_encrypt(key, iv, plaintext, plaintext_len,
                                   out, VICHAOS_HEADER_OVERHEAD, ciphertext, tag);
    }

    if (r == VICHAOS_SUCCESS) {
        memcpy(out + total_len - VICHAOS_TAG_SIZE, tag, VICHAOS_TAG_SIZE);
        *output = out;
        *output_len = total_len;
    } else {
        free(out);
    }

    vichaos_secure_zeroize(key, sizeof(key));
    return r;
}

vichaos_result_t vichaos_decrypt(const uint8_t *data,
                                 size_t data_len,
                                 const char *password,
                                 size_t password_len,
                                 const vichaos_options_t *options,
                                 uint8_t **output,
                                 size_t *output_len) {
    vichaos_options_t opts;
    vichaos_payload_header_t header;
    const uint8_t *ciphertext = NULL, *tag = NULL;
    size_t ciphertext_len = 0, tag_len = 0;
    uint8_t *plaintext = NULL;
    uint8_t key[VICHAOS_KEY_SIZE];
    vichaos_result_t r = VICHAOS_SUCCESS;

    if (!data || !password || !output || !output_len) return VICHAOS_ERR_NULL_PTR;

    *output = NULL;
    *output_len = 0;

    r = vichaos_payload_parse(data, data_len, &header, &ciphertext, &ciphertext_len, &tag, &tag_len);
    if (r != VICHAOS_SUCCESS) return r;

    r = vichaos_payload_validate(&header);
    if (r != VICHAOS_SUCCESS) return r;

    if (options) memcpy(&opts, options, sizeof(opts));
    else vichaos_options_init(&opts);

    if (password_len == 0) password_len = strlen(password);

    r = vichaos_kdf_derive(password, password_len, header.salt, opts.kdf_iter, key);
    if (r != VICHAOS_SUCCESS) return r;

    if (ciphertext_len > 0) {
        plaintext = (uint8_t *)malloc(ciphertext_len);
        if (!plaintext) { vichaos_secure_zeroize(key, sizeof(key)); return VICHAOS_ERR_MEMORY_ALLOC; }
    } else {
        plaintext = NULL;
    }

    r = vichaos_cipher_decrypt(key, header.iv, ciphertext, ciphertext_len,
                               data, VICHAOS_HEADER_OVERHEAD, tag, plaintext);

    if (r == VICHAOS_SUCCESS) {
        *output = plaintext;
        *output_len = ciphertext_len;
    } else if (plaintext) {
        vichaos_secure_zeroize(plaintext, ciphertext_len);
        free(plaintext);
    }

    vichaos_secure_zeroize(key, sizeof(key));
    return r;
}

vichaos_result_t vichaos_encrypt_string_password(const uint8_t *plaintext,
                                                 size_t plaintext_len,
                                                 const char *password,
                                                 const vichaos_options_t *options,
                                                 uint8_t **output,
                                                 size_t *output_len) {
    return vichaos_encrypt(plaintext, plaintext_len, password,
                           password ? strlen(password) : 0, options, output, output_len);
}

vichaos_result_t vichaos_decrypt_string_password(const uint8_t *data,
                                                 size_t data_len,
                                                 const char *password,
                                                 const vichaos_options_t *options,
                                                 uint8_t **output,
                                                 size_t *output_len) {
    return vichaos_decrypt(data, data_len, password,
                           password ? strlen(password) : 0, options, output, output_len);
}

vichaos_result_t vichaos_ctx_init(vichaos_cipher_ctx_t *ctx,
                                  const uint8_t key[VICHAOS_KEY_SIZE]) {
    if (!ctx || !key) return VICHAOS_ERR_NULL_PTR;
    ctx->encrypt_ctx = EVP_CIPHER_CTX_new();
    ctx->decrypt_ctx = EVP_CIPHER_CTX_new();
    if (!ctx->encrypt_ctx || !ctx->decrypt_ctx) {
        if (ctx->encrypt_ctx) EVP_CIPHER_CTX_free(ctx->encrypt_ctx);
        if (ctx->decrypt_ctx) EVP_CIPHER_CTX_free(ctx->decrypt_ctx);
        return VICHAOS_ERR_CIPHER_INIT;
    }
    memcpy(ctx->key, key, VICHAOS_KEY_SIZE);
    ctx->initialized = 1;
    return VICHAOS_SUCCESS;
}

vichaos_result_t vichaos_ctx_encrypt(vichaos_cipher_ctx_t *ctx,
                                     const uint8_t *plaintext,
                                     size_t plaintext_len,
                                     uint8_t *ciphertext,
                                     uint8_t tag[VICHAOS_TAG_SIZE]) {
    uint8_t iv[VICHAOS_IV_SIZE];
    if (!ctx || !ctx->initialized || !plaintext || !ciphertext || !tag) {
        return VICHAOS_ERR_NULL_PTR;
    }
    if (RAND_bytes(iv, VICHAOS_IV_SIZE) != 1) return VICHAOS_ERR_OPENSSL;

    if (EVP_EncryptInit_ex(ctx->encrypt_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx->encrypt_ctx, NULL, NULL, ctx->key, iv) != 1) {
        return VICHAOS_ERR_CIPHER_INIT;
    }

    {
        int len = 0, final_len = 0;
        if (EVP_EncryptUpdate(ctx->encrypt_ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
            return VICHAOS_ERR_ENCRYPT_FAIL;
        }
        if (EVP_EncryptFinal_ex(ctx->encrypt_ctx, ciphertext + len, &final_len) != 1) {
            return VICHAOS_ERR_ENCRYPT_FAIL;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx->encrypt_ctx, EVP_CTRL_GCM_GET_TAG, VICHAOS_TAG_SIZE, tag) != 1) {
            return VICHAOS_ERR_ENCRYPT_FAIL;
        }
    }
    return VICHAOS_SUCCESS;
}

vichaos_result_t vichaos_ctx_decrypt(vichaos_cipher_ctx_t *ctx,
                                     const uint8_t *ciphertext,
                                     size_t ciphertext_len,
                                     const uint8_t tag[VICHAOS_TAG_SIZE],
                                     uint8_t *plaintext) {
    uint8_t iv[VICHAOS_IV_SIZE] = {0};
    if (!ctx || !ctx->initialized || (!ciphertext && ciphertext_len > 0) || !tag || !plaintext) {
        return VICHAOS_ERR_NULL_PTR;
    }
    if (EVP_DecryptInit_ex(ctx->decrypt_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx->decrypt_ctx, NULL, NULL, ctx->key, iv) != 1) {
        return VICHAOS_ERR_CIPHER_INIT;
    }

    {
        int len = 0, final_len = 0;
        if (ciphertext_len > 0 && EVP_DecryptUpdate(ctx->decrypt_ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) {
            return VICHAOS_ERR_DECRYPT_FAIL;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx->decrypt_ctx, EVP_CTRL_GCM_SET_TAG, VICHAOS_TAG_SIZE, (void *)tag) != 1) {
            return VICHAOS_ERR_DECRYPT_FAIL;
        }
        if (EVP_DecryptFinal_ex(ctx->decrypt_ctx, plaintext + len, &final_len) <= 0) {
            return VICHAOS_ERR_AUTH_FAIL;
        }
    }
    return VICHAOS_SUCCESS;
}

void vichaos_ctx_cleanup(vichaos_cipher_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->encrypt_ctx) EVP_CIPHER_CTX_free(ctx->encrypt_ctx);
    if (ctx->decrypt_ctx) EVP_CIPHER_CTX_free(ctx->decrypt_ctx);
    vichaos_secure_zeroize(ctx->key, sizeof(ctx->key));
    ctx->initialized = 0;
}
