// --------------------------------- ABOUT -------------------------------------
// Original Author: Dx4 (DX4GREY)
// Repository: [https://github.com/DX4GREY](https://github.com/DX4GREY)
// License: See end of file
//
// ViChaos — Lightweight file/data encryption helpers for C++
// A simple, self-contained encrypt/decrypt helper built on top of OpenSSL
// primitives (PBKDF2-HMAC-SHA256, HMAC-SHA256, RAND\_bytes) with an added
// compile-time/simple runtime permutation layer.
//
// Features:
//   - Password-based key derivation (PBKDF2 with SHA-256, KDF\_ITER rounds).
//   - Random salt (SALT\_SIZE bytes) per encryption call.
//   - Authenticated payload using HMAC-SHA256.
//   - Simple per-byte key expansion + permutation layer for obfuscation.
//   - Embedded magic header to validate payloads and support simple framing.
//   - Simple C API, returns vichaos\_result\_t error codes.
//   - Portable C (depends on OpenSSL for crypto primitives).
//
// Design notes:
//   - The data layout produced by vichaos\_encrypt:
//       \[MAGIC\_HEADER]\[SALT (SALT\_SIZE)]\[HMAC (HMAC\_SIZE)]\[CIPHER\_BYTES]
//   - The cipher bytes are produced by:
//       1) expanding the derived 32-byte key into a k\* stream sized to full\_data\_len
//       2) combining full\_data (MAGIC\_HEADER + plaintext) with k\* by additive
//          mixing, XOR and a small permutation dependent on index and k\*\[i].
//   - Decryption verifies the outer MAGIC\_HEADER, recomputes HMAC and only then
//     performs the inverse operations to recover plaintext.
//   - HMAC mismatch, invalid header, memory or crypto errors are surfaced via
//     vichaos\_result\_t.
//
// API usage:
//   // Encrypt
//   const uint8\_t \*plaintext = ...;
//   size\_t plaintext\_len = ...;
//   const char \*password = "mypassword";
//   uint8\_t \*enc = NULL;
//   size\_t enc\_len = 0;
//   if (vichaos\_encrypt(plaintext, plaintext\_len, password, \&enc, \&enc\_len) == 0) {
//       // use enc (length = enc\_len)
//       vichaos\_free(enc); // free when done
//   }
//
//   // Decrypt
//   const uint8\_t \*input = ...; // buffer returned by vichaos\_encrypt (or read from file)
//   size\_t input\_len = ...;
//   uint8\_t \*dec = NULL;
//   size\_t dec\_len = 0;
//   if (vichaos\_decrypt(input, input\_len, password, \&dec, \&dec\_len) == 0) {
//       // dec now points to plaintext (length = dec\_len)
//       vichaos\_free(dec);
//   }
//
// Important constants (from this file):
//   - MAGIC\_HEADER        : "ViChaos-Dx4"
//   - MAGIC\_HEADER\_LEN    : 11
//   - SALT\_SIZE           : 16
//   - HMAC\_SIZE           : 32
//   - KDF\_ITER            : 100000
//
// Return values:
//   - VICHAOS\_OK
//   - VICHAOS\_INVALID\_HEADER
//   - VICHAOS\_HMAC\_MISMATCH
//   - VICHAOS\_MEMORY\_ERROR
//   - VICHAOS\_CRYPTO\_ERROR
//
// Security notes / caveats:
//   - This library relies on OpenSSL for KDF, HMAC and RNG — ensure you link
//     against a recent OpenSSL and initialize it as needed for your platform.
//   - The permutation/expansion scheme is a lightweight obfuscation layer — for
//     high-security use-cases prefer authenticated AEAD ciphers (e.g. AES-GCM
//     or ChaCha20-Poly1305). This implementation uses HMAC for authentication.
//   - Adjust KDF\_ITER according to your threat model and target platform.
//   - Always securely erase secrets from memory where applicable.
//
// Example file-based workflow (pseudo):
//   - Encrypt: read plaintext -> vichaos\_encrypt -> write output to file.
//   - Decrypt: read file -> vichaos\_decrypt -> verify and use plaintext.
// -----------------------------------------------------------------------------

#ifndef VICHAOS_H
#define VICHAOS_H

#include <stdint.h>
#include <stddef.h>

#define VICHAOS_MAGIC "ViChaos-Dx4"
#define VICHAOS_MAGIC_LEN 11
#define VICHAOS_SALT_SIZE 16
#define VICHAOS_HMAC_SIZE 32
#define VICHAOS_KDF_ITER 100000

typedef enum {
    VICHAOS_OK = 0,
    VICHAOS_INVALID_HEADER,
    VICHAOS_HMAC_MISMATCH,
    VICHAOS_MEMORY_ERROR,
    VICHAOS_CRYPTO_ERROR
} vichaos_result_t;

// Core functions
vichaos_result_t vichaos_encrypt(
    const uint8_t* data,
    size_t data_len,
    const char* password,
    uint8_t** output,
    size_t* output_len
);

vichaos_result_t vichaos_decrypt(
    const uint8_t* data,
    size_t data_len,
    const char* password,
    uint8_t** output,
    size_t* output_len
);

// Helper functions
const char* vichaos_error_string(vichaos_result_t result);
void vichaos_free(void* ptr);

#endif // VICHAOS_H
