// -----------------------------------------------------------------------------
// ViChaos v3 — Lightweight file/data encryption library for C
// Built on OpenSSL EVP API: PBKDF2-HMAC-SHA256 + AES-256-GCM (AEAD).
//
// Copyright (c) 2026 DX4GREY
// License: MIT
// -----------------------------------------------------------------------------
//
// #include <vichaos.h>
//
// ## Data Layout
//
//   [MAGIC "ViChaos" (7)] [VERSION (1) = 0x03] [SALT (16)] [IV (12)]
//   [CIPHERTEXT (n)] [AUTH TAG (16)]
//
// ## Thread Safety
//
// All public functions are reentrant. No global mutable state.
// Call vichaos_global_init() once at program startup before any other
// ViChaos calls, and vichaos_global_cleanup() at exit.
// -----------------------------------------------------------------------------

#ifndef VICHAOS_H
#define VICHAOS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Version & constants
// ---------------------------------------------------------------------------

#define VICHAOS_VERSION_MAJOR 3
#define VICHAOS_VERSION_MINOR 0
#define VICHAOS_VERSION_PATCH 0
#define VICHAOS_VERSION_STRING "3.0.0"

#define VICHAOS_FORMAT_MAGIC     "ViChaos"
#define VICHAOS_FORMAT_MAGIC_LEN 7
#define VICHAOS_PAYLOAD_VERSION  0x03

#define VICHAOS_KEY_SIZE  32   /**< AES-256 key size in bytes */
#define VICHAOS_SALT_SIZE 16   /**< PBKDF2 salt size in bytes */
#define VICHAOS_IV_SIZE   12   /**< GCM recommended IV size in bytes */
#define VICHAOS_TAG_SIZE  16   /**< GCM authentication tag size in bytes */

#define VICHAOS_HEADER_OVERHEAD (VICHAOS_FORMAT_MAGIC_LEN + 1 + VICHAOS_SALT_SIZE + VICHAOS_IV_SIZE)
#define VICHAOS_OVERHEAD        (VICHAOS_HEADER_OVERHEAD + VICHAOS_TAG_SIZE)

#define VICHAOS_MIN_KDF_ITER 100000U
#define VICHAOS_MAX_KDF_ITER 10000000U
#define VICHAOS_DEFAULT_KDF_ITER 600000U

#define VICHAOS_STREAM_CHUNK (1024 * 1024)  /**< 1 MiB default streaming chunk */

// ---------------------------------------------------------------------------
// Result / error codes
// ---------------------------------------------------------------------------

/**
 * @brief Detailed error codes returned by all ViChaos public functions.
 */
typedef enum {
    VICHAOS_SUCCESS = 0,
    VICHAOS_ERR_NULL_PTR,           /**< NULL pointer passed to non-nullable param */
    VICHAOS_ERR_INVALID_KEY,        /**< Key is NULL or wrong length */
    VICHAOS_ERR_INVALID_IV,         /**< IV is NULL or wrong length */
    VICHAOS_ERR_INVALID_TAG,        /**< Auth tag is NULL or wrong length */
    VICHAOS_ERR_CIPHER_INIT,        /**< EVP_CIPHER_CTX initialization failed */
    VICHAOS_ERR_ENCRYPT_FAIL,       /**< Encryption operation failed */
    VICHAOS_ERR_DECRYPT_FAIL,       /**< Decryption operation failed */
    VICHAOS_ERR_AUTH_FAIL,          /**< Authentication tag verification failed */
    VICHAOS_ERR_MEMORY_ALLOC,       /**< Memory allocation failed */
    VICHAOS_ERR_IO_READ,            /**< File/stream read error */
    VICHAOS_ERR_IO_WRITE,           /**< File/stream write error */
    VICHAOS_ERR_KDF_FAIL,           /**< PBKDF2 key derivation failed */
    VICHAOS_ERR_VERSION_MISMATCH,   /**< Payload version unsupported */
    VICHAOS_ERR_BUFFER_TOO_SMALL,   /**< Output buffer capacity insufficient */
    VICHAOS_ERR_INVALID_PARAM,      /**< Invalid parameter value */
    VICHAOS_ERR_OPENSSL,            /**< OpenSSL reported an error */
    VICHAOS_ERR_UNKNOWN             /**< Unknown / fallback error */
} vichaos_result_t;

// ---------------------------------------------------------------------------
// Type aliases for clarity & const-correctness
// ---------------------------------------------------------------------------

/** @brief 32-byte AES-256 key */
typedef uint8_t vichaos_key_t[VICHAOS_KEY_SIZE];
/** @brief 16-byte salt */
typedef uint8_t vichaos_salt_t[VICHAOS_SALT_SIZE];
/** @brief 12-byte IV/nonce */
typedef uint8_t vichaos_iv_t[VICHAOS_IV_SIZE];
/** @brief 16-byte GCM authentication tag */
typedef uint8_t vichaos_tag_t[VICHAOS_TAG_SIZE];

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/**
 * @brief Configuration options for encryption/decryption operations.
 */
typedef struct {
    uint32_t kdf_iter;      /**< PBKDF2 iteration count */
    uint32_t chunk_size;    /**< Streaming chunk size in bytes (0 = default) */
    int      disable_aesni; /**< Non-zero to force software AES (disable AES-NI) */
} vichaos_options_t;

/**
 * @brief Initialize options structure with safe defaults.
 * @param options Pointer to options to initialize.
 */
void vichaos_options_init(vichaos_options_t *options);

// ---------------------------------------------------------------------------
// Secure buffer
// ---------------------------------------------------------------------------

/**
 * @brief Bounds-checked secure buffer with canary overflow detection.
 */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   capacity;
    uint32_t canary;  /**< Simple overflow guard: set to 0xDEADBEEF */
} vichaos_buffer_t;

// ---------------------------------------------------------------------------
// Cipher context (reusable for multiple operations)
// ---------------------------------------------------------------------------

/**
 * @brief Opaque reusable cipher context for high-throughput scenarios.
 */
typedef struct vichaos_cipher_ctx_t vichaos_cipher_ctx_t;

// ---------------------------------------------------------------------------
// Stream state (opaque)
// ---------------------------------------------------------------------------

typedef struct vichaos_stream_t vichaos_stream_t;

// ---------------------------------------------------------------------------
// Log levels
// ---------------------------------------------------------------------------

/**
 * @brief Logging severity levels.
 */
typedef enum {
    VICHAOS_LOG_ERROR = 0,
    VICHAOS_LOG_WARN  = 1,
    VICHAOS_LOG_INFO  = 2,
    VICHAOS_LOG_DEBUG = 3
} vichaos_log_level_t;

// ---------------------------------------------------------------------------
// Global initialization / cleanup (thread-safe, call once)
// ---------------------------------------------------------------------------

/**
 * @brief Initialize the ViChaos library. Call once at program startup.
 * @return VICHAOS_SUCCESS on success, error code on failure.
 */
vichaos_result_t vichaos_global_init(void);

/**
 * @brief Cleanup the ViChaos library. Call once at program exit.
 */
void vichaos_global_cleanup(void);

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

/**
 * @brief Convert a result code to a human-readable string.
 * @param result The vichaos_result_t to describe.
 * @return Constant string describing the error. Never returns NULL.
 */
const char *vichaos_strerror(vichaos_result_t result);

/**
 * @brief Set the minimum log level. Messages below this level are suppressed.
 * @param level Minimum severity to log.
 */
void vichaos_log_set_level(vichaos_log_level_t level);

void vichaos_log_internal(vichaos_log_level_t level,
                          const char *file,
                          int line,
                          const char *fmt,
                          ...);

/**
 * @brief Logging macro with file/line info.
 */
#define VICHAOS_LOG(level, fmt, ...) \
    vichaos_log_internal((level), __FILE__, __LINE__, fmt, ##__VA_ARGS__)

// ---------------------------------------------------------------------------
// Memory management
// ---------------------------------------------------------------------------

/**
 * @brief Secure memory allocation (page-locked where possible).
 * @param size Number of bytes to allocate.
 * @return Pointer to allocated memory, or NULL on failure.
 */
void *vichaos_secure_alloc(size_t size);

/**
 * @brief Secure memory free with automatic zeroization.
 * @param ptr Pointer to memory to free.
 * @param size Size of the memory region in bytes (for zeroization).
 */
void vichaos_secure_free(void *ptr, size_t size);

/**
 * @brief Constant-time memory zeroization with compiler barrier.
 * @param ptr Pointer to memory to clear.
 * @param len Number of bytes to zero.
 */
void vichaos_secure_zeroize(void *ptr, size_t len);

/**
 * @brief Constant-time memory comparison (prevents timing attacks).
 * @param a First buffer.
 * @param b Second buffer.
 * @param len Number of bytes to compare.
 * @return 0 if equal, non-zero otherwise.
 */
int vichaos_secure_memcmp(const void *a, const void *b, size_t len);

/**
 * @brief Standard free wrapper (for backward compatibility).
 */
void vichaos_free(void *ptr);

// ---------------------------------------------------------------------------
// Secure buffer helpers
// ---------------------------------------------------------------------------

/**
 * @brief Initialize a secure buffer.
 * @param buf Pointer to vichaos_buffer_t to initialize.
 * @param capacity Initial capacity in bytes.
 * @return VICHAOS_SUCCESS or VICHAOS_ERR_MEMORY_ALLOC.
 */
vichaos_result_t vichaos_buffer_init(vichaos_buffer_t *buf, size_t capacity);

/**
 * @brief Append data to a secure buffer.
 * @param buf Buffer to append into.
 * @param data Data to append.
 * @param len Length of data in bytes.
 * @return VICHAOS_SUCCESS or VICHAOS_ERR_BUFFER_TOO_SMALL / VICHAOS_ERR_MEMORY_ALLOC.
 */
vichaos_result_t vichaos_buffer_append(vichaos_buffer_t *buf,
                                       const uint8_t *data,
                                       size_t len);

/**
 * @brief Zeroize and free a secure buffer.
 */
void vichaos_buffer_cleanup(vichaos_buffer_t *buf);

// ---------------------------------------------------------------------------
// Hardware detection
// ---------------------------------------------------------------------------

/**
 * @brief Check if AES-NI hardware acceleration is available at runtime.
 * @return Non-zero if AES-NI is supported, 0 otherwise.
 */
int vichaos_hardware_aes_supported(void);

// ---------------------------------------------------------------------------
// Payload format helpers
// ---------------------------------------------------------------------------

/**
 * @brief Packed payload header: [MAGIC(7)] [VERSION(1)] [SALT(16)] [IV(12)]
 */
typedef struct __attribute__((packed)) {
    uint8_t  magic[VICHAOS_FORMAT_MAGIC_LEN];
    uint8_t  version;
    uint8_t  salt[VICHAOS_SALT_SIZE];
    uint8_t  iv[VICHAOS_IV_SIZE];
} vichaos_payload_header_t;

/**
 * @brief Parse a ViChaos payload into its constituent parts.
 */
vichaos_result_t vichaos_payload_parse(const uint8_t *data,
                                       size_t data_len,
                                       vichaos_payload_header_t *header,
                                       const uint8_t **ciphertext,
                                       size_t *ciphertext_len,
                                       const uint8_t **tag,
                                       size_t *tag_len);

/**
 * @brief Validate a payload header (magic + version).
 */
vichaos_result_t vichaos_payload_validate(const vichaos_payload_header_t *header);

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/**
 * @brief Derive a 256-bit key from a password using PBKDF2-HMAC-SHA256.
 */
vichaos_result_t vichaos_kdf_derive(const char *password,
                                    size_t password_len,
                                    const uint8_t salt[VICHAOS_SALT_SIZE],
                                    uint32_t kdf_iter,
                                    uint8_t key[VICHAOS_KEY_SIZE]);

// ---------------------------------------------------------------------------
// Cipher operations (low-level)
// ---------------------------------------------------------------------------

/**
 * @brief Encrypt plaintext with AES-256-GCM.
 */
vichaos_result_t vichaos_cipher_encrypt(const uint8_t key[VICHAOS_KEY_SIZE],
                                        const uint8_t iv[VICHAOS_IV_SIZE],
                                        const uint8_t *plaintext,
                                        size_t plaintext_len,
                                        const uint8_t *aad,
                                        size_t aad_len,
                                        uint8_t *ciphertext,
                                        uint8_t tag[VICHAOS_TAG_SIZE]);

/**
 * @brief Decrypt ciphertext with AES-256-GCM and verify auth tag.
 */
vichaos_result_t vichaos_cipher_decrypt(const uint8_t key[VICHAOS_KEY_SIZE],
                                        const uint8_t iv[VICHAOS_IV_SIZE],
                                        const uint8_t *ciphertext,
                                        size_t ciphertext_len,
                                        const uint8_t *aad,
                                        size_t aad_len,
                                        const uint8_t tag[VICHAOS_TAG_SIZE],
                                        uint8_t *plaintext);

// ---------------------------------------------------------------------------
// Reusable cipher context
// ---------------------------------------------------------------------------

/**
 * @brief Initialize a reusable cipher context for encryption.
 */
vichaos_result_t vichaos_ctx_init(vichaos_cipher_ctx_t *ctx,
                                  const uint8_t key[VICHAOS_KEY_SIZE]);

/**
 * @brief Encrypt data using a reusable context.
 */
vichaos_result_t vichaos_ctx_encrypt(vichaos_cipher_ctx_t *ctx,
                                     const uint8_t *plaintext,
                                     size_t plaintext_len,
                                     uint8_t *ciphertext,
                                     uint8_t tag[VICHAOS_TAG_SIZE]);

/**
 * @brief Decrypt data using a reusable context.
 */
vichaos_result_t vichaos_ctx_decrypt(vichaos_cipher_ctx_t *ctx,
                                     const uint8_t *ciphertext,
                                     size_t ciphertext_len,
                                     const uint8_t tag[VICHAOS_TAG_SIZE],
                                     uint8_t *plaintext);

/**
 * @brief Cleanup and free a cipher context.
 */
void vichaos_ctx_cleanup(vichaos_cipher_ctx_t *ctx);

// ---------------------------------------------------------------------------
// Single-shot encrypt / decrypt
// ---------------------------------------------------------------------------

/**
 * @brief Encrypt data with password, returning a complete payload.
 *
 * Output format: [MAGIC(7)] [VERSION(1)] [SALT(16)] [IV(12)]
 *                 [CIPHERTEXT(n)] [TAG(16)]
 *
 * @param plaintext     Input data to encrypt.
 * @param plaintext_len Length of plaintext in bytes.
 * @param password      Password (UTF-8 / bytes).
 * @param password_len  Length of password in bytes (0 = NUL-terminated).
 * @param options       Configuration options (NULL for defaults).
 * @param output        Output buffer allocated by the library; caller frees with
 *                      vichaos_free() or vichaos_secure_free().
 * @param output_len    Output: total payload length in bytes.
 * @return VICHAOS_SUCCESS or appropriate error code.
 *
 * @note output must be freed with vichaos_free().
 */
vichaos_result_t vichaos_encrypt(const uint8_t *plaintext,
                                 size_t plaintext_len,
                                 const char *password,
                                 size_t password_len,
                                 const vichaos_options_t *options,
                                 uint8_t **output,
                                 size_t *output_len);

/**
 * @brief Decrypt a ViChaos payload using a password.
 */
vichaos_result_t vichaos_decrypt(const uint8_t *data,
                                 size_t data_len,
                                 const char *password,
                                 size_t password_len,
                                 const vichaos_options_t *options,
                                 uint8_t **output,
                                 size_t *output_len);

// ---------------------------------------------------------------------------
// Streaming encrypt / decrypt (constant memory)
// ---------------------------------------------------------------------------

/**
 * @brief Initialize streaming encryption.
 *
 * Caller must write the returned header to the output stream before any
 * update calls.
 */
vichaos_stream_t *vichaos_stream_encrypt_init(const char *password,
                                              size_t password_len,
                                              const vichaos_options_t *options,
                                              uint8_t *header_out,
                                              size_t *header_out_len);

/**
 * @brief Encrypt a chunk of data.
 */
vichaos_result_t vichaos_stream_encrypt_update(vichaos_stream_t *stream,
                                               const uint8_t *in,
                                               size_t in_len,
                                               uint8_t *out,
                                               size_t *out_len);

/**
 * @brief Finalize streaming encryption and output the auth tag.
 *
 * This also frees the stream handle.
 */
vichaos_result_t vichaos_stream_encrypt_final(vichaos_stream_t *stream,
                                              uint8_t *tag_out,
                                              size_t *tag_out_len);

/**
 * @brief Initialize streaming decryption.
 */
vichaos_stream_t *vichaos_stream_decrypt_init(const char *password,
                                              size_t password_len,
                                              const uint8_t *header,
                                              size_t header_len,
                                              const vichaos_options_t *options);

/**
 * @brief Decrypt a chunk of ciphertext.
 */
vichaos_result_t vichaos_stream_decrypt_update(vichaos_stream_t *stream,
                                               const uint8_t *in,
                                               size_t in_len,
                                               uint8_t *out,
                                               size_t *out_len);

/**
 * @brief Finalize streaming decryption and verify the auth tag.
 *
 * IMPORTANT: Callers MUST discard/rollback any plaintext already produced
 * if this returns anything other than VICHAOS_SUCCESS.
 */
vichaos_result_t vichaos_stream_decrypt_final(vichaos_stream_t *stream,
                                              const uint8_t *tag,
                                              size_t tag_len);

// ---------------------------------------------------------------------------
// Backward-compatible convenience wrappers (NUL-terminated password)
// ---------------------------------------------------------------------------

vichaos_result_t vichaos_encrypt_string_password(const uint8_t *plaintext,
                                                 size_t plaintext_len,
                                                 const char *password,
                                                 const vichaos_options_t *options,
                                                 uint8_t **output,
                                                 size_t *output_len);

vichaos_result_t vichaos_decrypt_string_password(const uint8_t *data,
                                                 size_t data_len,
                                                 const char *password,
                                                 const vichaos_options_t *options,
                                                 uint8_t **output,
                                                 size_t *output_len);

// ---------------------------------------------------------------------------
// OpenSSL integration helpers
// ---------------------------------------------------------------------------

/**
 * @brief Map an OpenSSL return code to vichaos_result_t.
 * @param openssl_ret OpenSSL function return value (1 = success, <=0 = failure).
 * @return VICHAOS_SUCCESS if openssl_ret == 1, VICHAOS_ERR_OPENSSL otherwise.
 */
vichaos_result_t vichaos_openssl_check(int openssl_ret);

void vichaos_openssl_init(void);
void vichaos_openssl_cleanup(void);

// ---------------------------------------------------------------------------
// Security helpers
// ---------------------------------------------------------------------------

int vichaos_disable_core_dump(void);
int vichaos_mlock(const void *addr, size_t len);
int vichaos_munlock(const void *addr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VICHAOS_H */
