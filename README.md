# ViChaos v3 — Secure Encryption Library

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
- **Password-based key derivation** — PBKDF2-HMAC-SHA256 (OWASP 2023 default: 600k iterations)
- **Modular code structure** — core, stream, CLI, and utils separated
- **Thread-safe & reentrant** — no global mutable state
- **Secure memory management** — `vichaos_secure_alloc`, `vichaos_secure_zeroize`, constant-time `memcmp`
- **Structured error handling** — typed `vichaos_result_t` with human-readable strings
- **Two APIs**: single-shot and streaming (constant memory for large files)
- **CMake build system** — shared/static libs, tests, sanitizers, coverage, pkg-config
- **Doxygen documentation** throughout
- **Comprehensive test suite** — unit, integration, and fuzz targets
- **Security hardening** — stack protection, FORTIFY_SOURCE, PIE, AES-NI detection

## Installation

### Linux/Unix

```bash
# Configure
cmake -B build -DVICHAOS_BUILD_TESTS=ON

# Build
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure

# Install
sudo cmake --install build
```

### Build Dependencies
- OpenSSL development libraries (1.1.1 or newer)
- CMake 3.15+
- GCC or Clang

Install dependencies on Debian/Ubuntu:
```bash
sudo apt-get install build-essential libssl-dev cmake
```

## Usage

### Command Line Tools

```bash
# Encrypt file securely (interactive password prompt)
vichaos enc -i input.txt -o output.enc --progress

# Encrypt using keyfile or environment variable
vichaos enc -i input.txt -o output.enc -k keyfile.txt
VICHAOS_PASSPHRASE="mysecret" vichaos enc -i input.txt -o output.enc

# Inspect file header & metadata (without decrypting)
vichaos info output.enc

# Decrypt file securely
vichaos dec -i output.enc -o decrypted.txt --progress

# Legacy positional syntax (backward compatible)
vichaos_encrypt input.txt output.enc "yourpassword"
vichaos_decrypt output.enc decrypted.txt "yourpassword"
```

### Library Usage — Single-shot

```c
#include <vichaos.h>

uint8_t *enc = NULL; size_t enc_len = 0;
vichaos_result_t r = vichaos_encrypt(data, data_len,
                                     "password", 8, NULL,
                                     &enc, &enc_len);
if (r == VICHAOS_OK) { /* use enc */ vichaos_free(enc); }

uint8_t *dec = NULL; size_t dec_len = 0;
r = vichaos_decrypt(enc, enc_len, "password", 8, NULL, &dec, &dec_len);
if (r == VICHAOS_OK) { /* use dec */ vichaos_free(dec); }
```

### Library Usage — Streaming (large files)

```c
uint8_t header[VICHAOS_HEADER_OVERHEAD]; size_t header_len = 0;
vichaos_stream_t *s = vichaos_stream_encrypt_init("password", 8, NULL,
                                                  header, &header_len);
fwrite(header, 1, header_len, out);

uint8_t in_buf[VICHAOS_STREAM_CHUNK], out_buf[VICHAOS_STREAM_CHUNK + 16];
size_t n;
while ((n = fread(in_buf, 1, sizeof(in_buf), in)) > 0) {
    size_t out_len = 0;
    vichaos_stream_encrypt_update(s, in_buf, n, out_buf, &out_len);
    fwrite(out_buf, 1, out_len, out);
}
uint8_t tag[VICHAOS_TAG_SIZE]; size_t tag_len = 0;
vichaos_stream_encrypt_final(s, tag, &tag_len);
fwrite(tag, 1, tag_len, out);
```

## Building from Source

```bash
# Default build (shared + static + tests + CLI)
cmake -B build
cmake --build build

# Release with sanitizers
cmake -B build -DVICHAOS_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

# Coverage build
cmake -B build -DVICHAOS_ENABLE_COVERAGE=ON
cmake --build build
```

## Testing

```bash
# Run all tests
ctest --test-dir build --output-on-failure

# Run specific test
./build/test_cipher
```

## Security Notes

- Always use strong passwords (minimum 12 characters).
- Never store passwords with encrypted files.
- Default KDF iterations: 600,000 (OWASP 2023). Increase on fast hardware.
- All secrets are wiped with `vichaos_secure_zeroize()`.
- Constant-time memory comparison prevents timing attacks.
- Streaming decryption releases plaintext before final auth verification — discard on failure.

## License

MIT License — See [LICENSE](LICENSE) file for details.

---

*ViChaos v3 — Authenticated encryption, built on OpenSSL.*
