// --------------------------------- ABOUT -------------------------------------
// Original Author: Dx4 (DX4GREY)
// Repository: [https://github.com/DX4GREY](https://github.com/DX4GREY)
// License: MIT (see end of file)
//
// ViChaos v2 — Lightweight file/data encryption helpers for C
// A simple, self-contained encrypt/decrypt helper built on top of OpenSSL
// primitives (PBKDF2-HMAC-SHA256, AES-256-GCM, RAND_bytes).
//
// Major changes in v2 (from v1):
//   - Replaced the hand-rolled additive/XOR/permutation layer with the
//     authenticated cipher AES-256-GCM (AEAD) via the OpenSSL EVP API.
//     This provides industry-standard confidentiality + integrity and is
//     hardware-accelerated (AES-NI) — dramatically faster than v1.
//   - Format version byte embedded in the payload for future migration.
//   - Configurable KDF iteration count via vichaos_options_t
//     (default 600,000 — OWASP recommendation for PBKDF2-SHA256).
//   - All secrets (derived key, IV, etc.) are securely wiped with
//     OPENSSL_cleanse() before buffers are freed.
//   - Proper vichaos_result_t error codes everywhere (no bare -1).
//   - Reduced allocations: single output allocation per call.
//   - NEW: streaming API (vichaos_stream_*) for encrypting/decrypting
//     arbitrarily large files with constant memory (chunked I/O).
//
// Data layout produced by vichaos_encrypt:
//   [MAGIC "ViChaos2" (8)] [VERSION (1) = 2] [SALT (16)] [IV (12)]
//   [CIPHERTEXT (plaintext_len)] [AUTH TAG (16)]
//
// API usage — single-shot:
//   uint8_t *enc = NULL; size_t enc_len = 0;
//   vichaos_result_t r = vichaos_encrypt(plaintext, plaintext_len,
//                                        password, &enc, &enc_len);
//   if (r == VICHAOS_OK) { ... vichaos_free(enc); }
//
// API usage — streaming (constant memory, for large files):
//   uint8_t header[VICHAOS_HEADER_OVERHEAD]; size_t header_len = 0;
//   vichaos_stream_t *s = vichaos_stream_encrypt_init(password, NULL,
//                              header, &header_len);            // write header first
//   while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
//       vichaos_stream_encrypt_update(s, buf, n, out, &out_len);  // write out
//   }
//   vichaos_stream_encrypt_final(s, tag, &tag_len);               // write trailing tag
//
// Return values:
//   - VICHAOS_OK
//   - VICHAOS_INVALID_ARGUMENT
//   - VICHAOS_INVALID_HEADER
//   - VICHAOS_UNSUPPORTED_VERSION
//   - VICHAOS_HMAC_MISMATCH      (auth tag verification failed)
//   - VICHAOS_MEMORY_ERROR
//   - VICHAOS_CRYPTO_ERROR
//
// Security notes / caveats:
//   - Requires OpenSSL 1.1.1+ (AES-256-GCM support). Build against a
//     maintained OpenSSL version and keep it patched.
//   - PBKDF2 provides password stretching. Increase kdf_iter on fast
//     hardware; decrease on constrained devices, but NEVER below 100,000.
//   - Streaming DECRYPT releases plaintext chunks BEFORE the final auth tag
//     is verified. Callers MUST discard/rollback any output if
//     vichaos_stream_decrypt_final() returns anything other than VICHAOS_OK.
//   - Always securely erase plaintext/secrets in your own code too.
//   - This library does not implement side-channel hardened primitives
//     beyond what OpenSSL provides; treat as best-effort. For HSMs/smartcards
//     use dedicated tooling.
// -----------------------------------------------------------------------------

#ifndef VICHAOS_H
#define VICHAOS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define VICHAOS_FORMAT_MAGIC     "ViChaos2"
#define VICHAOS_FORMAT_MAGIC_LEN 8

#define VICHAOS_VERSION          2

#define VICHAOS_SALT_SIZE        16
#define VICHAOS_IV_SIZE          12   /* GCM standard nonce size */
#define VICHAOS_TAG_SIZE         16   /* GCM auth tag size */
#define VICHAOS_KEY_SIZE         32   /* AES-256 */

/* OWASP-recommended minimum for PBKDF2-HMAC-SHA256 (2023+). */
#define VICHAOS_DEFAULT_KDF_ITER 600000u
#define VICHAOS_MIN_KDF_ITER     100000u
#define VICHAOS_MAX_KDF_ITER     10000000u

/* Total fixed header overhead: magic(8) + version(1) + salt(16) + iv(12). */
#define VICHAOS_HEADER_OVERHEAD  (VICHAOS_FORMAT_MAGIC_LEN + 1 + \
                                  VICHAOS_SALT_SIZE + VICHAOS_IV_SIZE)

/* Output length = input length + HEADER_OVERHEAD + TAG_SIZE. */
#define VICHAOS_OVERHEAD         (VICHAOS_HEADER_OVERHEAD + VICHAOS_TAG_SIZE)

/* Recommended streaming chunk size (1 MiB). */
#define VICHAOS_STREAM_CHUNK      (1024u * 1024u)

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

typedef enum {
    VICHAOS_OK = 0,
    VICHAOS_INVALID_ARGUMENT,      /* NULL pointer, invalid size, bad options */
    VICHAOS_INVALID_HEADER,        /* magic/prefix mismatch */
    VICHAOS_UNSUPPORTED_VERSION,   /* payload version not supported */
    VICHAOS_HMAC_MISMATCH,         /* GCM auth tag verification failed */
    VICHAOS_MEMORY_ERROR,          /* allocation failure */
    VICHAOS_CRYPTO_ERROR           /* OpenSSL operation failed */
} vichaos_result_t;

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

typedef struct {
    uint32_t kdf_iter;   /* PBKDF2-HMAC-SHA256 iteration count */
} vichaos_options_t;

/* Initialize options with secure defaults (kdf_iter = 600000). */
void vichaos_options_init(vichaos_options_t *options);

// ---------------------------------------------------------------------------
// Single-shot core functions
// ---------------------------------------------------------------------------

/* NOTE: for decrypt, `options` is used only for KDF iteration; the iteration
 * count used at encryption time is NOT embedded in the payload. Callers that
 * used non-default kdf_iter MUST pass the same value here. */

vichaos_result_t vichaos_encrypt_with_options(
    const uint8_t *data,
    size_t data_len,
    const char *password,
    const vichaos_options_t *options,
    uint8_t **output,
    size_t *output_len);

vichaos_result_t vichaos_decrypt_with_options(
    const uint8_t *data,
    size_t data_len,
    const char *password,
    const vichaos_options_t *options,
    uint8_t **output,
    size_t *output_len);

/* Convenience wrappers using default options. */
vichaos_result_t vichaos_encrypt(
    const uint8_t *data,
    size_t data_len,
    const char *password,
    uint8_t **output,
    size_t *output_len);

vichaos_result_t vichaos_decrypt(
    const uint8_t *data,
    size_t data_len,
    const char *password,
    uint8_t **output,
    size_t *output_len);

// ---------------------------------------------------------------------------
// Streaming API (constant memory, for large files)
// ---------------------------------------------------------------------------

typedef struct vichaos_stream_t vichaos_stream_t;

/* Begin encryption. Outputs the fixed 37-byte header (magic+version+salt+iv)
 * which the caller must persist BEFORE any update output.
 * Returns NULL on failure. */
vichaos_stream_t *vichaos_stream_encrypt_init(
    const char *password,
    const vichaos_options_t *options,
    uint8_t *header_out,
    size_t *header_out_len);

/* Encrypt a chunk. out must have capacity >= in_len + 16 (EVP block margin).
 * Sets *out_len to the number of bytes written (usually == in_len for GCM). */
vichaos_result_t vichaos_stream_encrypt_update(
    vichaos_stream_t *stream,
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    size_t *out_len);

/* Finalize encryption, outputting the 16-byte auth tag. Caller must persist
 * the tag immediately AFTER all update output. Also frees the stream. */
vichaos_result_t vichaos_stream_encrypt_final(
    vichaos_stream_t *stream,
    uint8_t *tag_out,
    size_t *tag_out_len);

/* Begin decryption. header must be exactly the leading VICHAOS_HEADER_OVERHEAD
 * bytes of the payload. Returns NULL on invalid header/version/options. */
vichaos_stream_t *vichaos_stream_decrypt_init(
    const char *password,
    const uint8_t *header,
    size_t header_len,
    const vichaos_options_t *options);

/* Decrypt a chunk. out must have capacity >= in_len + 16 (EVP block margin).
 * Sets *out_len to the number of plaintext bytes written. */
vichaos_result_t vichaos_stream_decrypt_update(
    vichaos_stream_t *stream,
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    size_t *out_len);

/* Finalize decryption. `tag` is the trailing 16-byte auth tag read from the
 * end of the payload. Verifies authenticity; frees the stream.
 * IMPORTANT: callers must discard/rollback any plaintext already written if
 * this returns anything other than VICHAOS_OK. */
vichaos_result_t vichaos_stream_decrypt_final(
    vichaos_stream_t *stream,
    const uint8_t *tag,
    size_t tag_len);

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

const char *vichaos_error_string(vichaos_result_t result);
void vichaos_free(void *ptr);

/* ---------------------------------------------------------------------------
 * Internal helpers (shared across modules)
 * --------------------------------------------------------------------------- */

int validate_options(const vichaos_options_t *options,
                     vichaos_result_t *err);

vichaos_result_t derive_key(const char *password,
                            const uint8_t *salt,
                            uint32_t kdf_iter,
                            uint8_t key[VICHAOS_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* VICHAOS_H */
