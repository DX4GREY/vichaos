# ViChaos v2 — Secure Encryption Library

*A lightweight, self-contained file/data encryption library for C, built on OpenSSL.*

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Building from Source](#building-from-source)
- [Testing](#testing)
- [Examples](#examples)
- [Security Notes](#security-notes)
- [License](#license)

## Features

- **Authenticated encryption (AEAD)** using **AES-256-GCM** via the OpenSSL EVP API
  - Industry-standard confidentiality **and** integrity (16-byte auth tag)
  - Hardware acceleration (AES-NI) where available
- **Password-based key derivation** — PBKDF2-HMAC-SHA256
  - Configurable iteration count (default 600,000, OWASP-recommended)
- **Format versioning** — version byte embedded in payload for future migration
- **Secure memory handling** — all secrets wiped with `OPENSSL_cleanse()`
- **Proper error codes** — typed `vichaos_result_t` everywhere
- **Two APIs**:
  - **Single-shot** — encrypt/decrypt a buffer in one call
  - **Streaming** — chunked encrypt/decrypt of arbitrarily large files with **constant memory**
- **Cross-platform** C implementation (OpenSSL 1.1.1+)
- **Simple CLI tools** for file operations
- **Unit test suite** + CLI integration tests

## Installation

### Linux/Unix

```bash
git clone https://github.com/DX4GREY/vichaos.git
cd vichaos

# Build shared + static libraries
make

# Run the unit test suite (91 checks)
make test

# Install to /usr/local (or set PREFIX=/your/path)
sudo make install
```

### Build Dependencies
- OpenSSL development libraries (1.1.1 or newer)
- GCC or Clang

Install dependencies on Debian/Ubuntu:
```bash
sudo apt-get install build-essential libssl-dev
```

## Usage

### Command Line Tools (streaming, constant memory)

**Encrypt a file:**
```bash
encrypt_file input.txt output.enc "yourpassword"
```

**Decrypt a file:**
```bash
decrypt_file output.enc decrypted.txt "yourpassword"
```

The CLI tools process files in 1 MiB chunks, so memory usage stays constant
regardless of file size. Decryption writes to a temporary file and only
renames it into place **after** the auth tag verifies — unauthenticated data
is never exposed.

### Library Usage — Single-shot

```c
#include <vichaos.h>

/* Encrypt */
uint8_t *enc = NULL; size_t enc_len = 0;
vichaos_result_t res = vichaos_encrypt(data, data_len, "password", &enc, &enc_len);
if (res == VICHAOS_OK) { /* use enc */ vichaos_free(enc); }

/* Decrypt */
uint8_t *dec = NULL; size_t dec_len = 0;
res = vichaos_decrypt(enc, enc_len, "password", &dec, &dec_len);
if (res == VICHAOS_OK) { /* use dec */ vichaos_free(dec); }
```

### Library Usage — Custom KDF iterations

```c
vichaos_options_t opts;
vichaos_options_init(&opts);
opts.kdf_iter = 1000000;  /* must be within [100000, 10000000] */

vichaos_encrypt_with_options(data, data_len, "password", &opts, &enc, &enc_len);
vichaos_decrypt_with_options(enc, enc_len, "password", &opts, &dec, &dec_len);
```

> **Note:** the KDF iteration count is **not** embedded in the payload. If you
> encrypt with a non-default `kdf_iter`, you must pass the same value when
> decrypting.

### Library Usage — Streaming (large files)

```c
uint8_t header[VICHAOS_HEADER_OVERHEAD]; size_t header_len = 0;
vichaos_stream_t *s = vichaos_stream_encrypt_init("password", NULL,
                                                  header, &header_len);
fwrite(header, 1, header_len, out);          /* persist header first */

uint8_t in_buf[VICHAOS_STREAM_CHUNK], out_buf[VICHAOS_STREAM_CHUNK + 16];
size_t n;
while ((n = fread(in_buf, 1, sizeof(in_buf), in)) > 0) {
    size_t out_len = 0;
    vichaos_stream_encrypt_update(s, in_buf, n, out_buf, &out_len);
    fwrite(out_buf, 1, out_len, out);
}
uint8_t tag[VICHAOS_TAG_SIZE]; size_t tag_len = 0;
vichaos_stream_encrypt_final(s, tag, &tag_len);
fwrite(tag, 1, tag_len, out);                /* persist trailing tag */
```

For decryption, feed the header to `vichaos_stream_decrypt_init`, stream the
ciphertext with `vichaos_stream_decrypt_update`, then verify the trailing tag
with `vichaos_stream_decrypt_final`. **Discard any plaintext already written
if final returns anything other than `VICHAOS_OK`.**

## Building from Source

```bash
# Build shared + static libraries
make

# Local performance build (uses native CPU features + LTO)
make OPTFLAGS="-O3 -march=native -flto"

# Install
sudo make install
```

## Testing

```bash
# Unit tests (single-shot, streaming, cross-compat, negative cases)
make test

# CLI integration tests (round-trip, wrong password, tamper detection)
make -C example test
```

## Examples

See the `example/` directory for:
- `encrypt_file.c` — streaming file encryption utility
- `decrypt_file.c` — streaming file decryption utility (authenticated)

## Security Notes

- **Always use strong passwords** (minimum 12 characters).
- **Never store passwords** with encrypted files.
- The KDF iteration count defaults to 600,000 (OWASP 2023 recommendation).
  Increase on fast hardware; never go below 100,000.
- This library relies on OpenSSL for all cryptographic primitives. Keep
  OpenSSL patched and up to date.
- The library does **not** implement side-channel hardened primitives beyond
  what OpenSSL provides. For HSMs/smartcards, use dedicated tooling.
- Always securely erase plaintext and secrets in your own application code.

## License

MIT License — See [LICENSE](LICENSE) file for details.

---

*ViChaos v2 — Authenticated encryption, built on OpenSSL.*