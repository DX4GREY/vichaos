# ViChaos v2 — Documentation

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture & Design](#architecture--design)
3. [Dependencies](#dependencies)
4. [Build & Installation](#build--installation)
5. [Usage](#usage)
   - 5.1 [Command-Line Tools](#command-line-tools)
   - 5.2 [Library Integration (Single-Shot API)](#library-integration-single-shot-api)
   - 5.3 [Library Integration (Streaming API)](#library-integration-streaming-api)
   - 5.4 [Custom Options (KDF Iterations)](#custom-options-kdf-iterations)
6. [API Reference](#api-reference)
7. [Data Format Specification](#data-format-specification)
8. [Security Considerations](#security-considerations)
9. [Testing & Benchmarking](#testing--benchmarking)
10. [Maintenance & Contributing](#maintenance--contributing)
11. [Troubleshooting](#troubleshooting)
12. [License](#license)

---

## Project Overview

**ViChaos v2** is a lightweight, self-contained encryption library for C that provides authenticated encryption for files and in-memory data. It is built on top of OpenSSL and exposes both a high-level single-shot API and a low-level streaming API.

### Key Characteristics

| Feature | Description |
|---------|-------------|
| **Cipher** | AES-256-GCM (AEAD) via OpenSSL EVP API |
| **Key Derivation** | PBKDF2-HMAC-SHA256 |
| **Default KDF Iterations** | 600,000 (OWASP 2023 recommendation) |
| **Output Format** | Versioned binary payload with embedded salt, IV, and auth tag |
| **Memory Profile** | Constant memory for streaming API (1 MiB chunks) |
| **Portability** | Linux/Unix; Windows install is manual (copy headers/libs) |
| **License** | MIT |

### What Changed in v2

- Replaced the custom permutation layer from v1 with **AES-256-GCM**, providing industry-standard confidentiality and integrity.
- Added a **format version byte** for future migration.
- Introduced **configurable KDF iterations** via `vichaos_options_t`.
- All secrets are securely wiped with `OPENSSL_cleanse()`.
- Added a **streaming API** for arbitrarily large files.

---

## Architecture & Design

### Source Layout

```
vichaos/
├── include/
│   └── vichaos.h          # Public API header
├── src/
│   ├── vichaos.c          # Internal helpers (legacy compatibility)
│   ├── vichaos_core.c     # Validation, KDF, options, error strings
│   ├── vichaos_encrypt.c  # Single-shot encryption
│   ├── vichaos_decrypt.c  # Single-shot decryption
│   └── vichaos_stream.c   # Streaming encrypt/decrypt state machine
├── example/
│   ├── encrypt_file.c     # CLI: stream-encrypt a file
│   ├── decrypt_file.c     # CLI: stream-decrypt a file
│   └── Makefile
├── test/
│   └── test_vichaos       # Pre-built unit test binary
├── bench/
│   ├── bench_speed.c      # Throughput benchmark
│   └── Makefile
├── Makefile               # Top-level build
├── libvichaos.so          # Shared library (built)
├── libvichaos.a           # Static library (built)
└── README.md
```

### Module Responsibilities

| Module | Responsibility |
|--------|----------------|
| `vichaos_core.c` | Input validation, PBKDF2 key derivation, options initialization, error-to-string mapping. |
| `vichaos_encrypt.c` | Single-shot encryption: generates salt/IV, derives key, wraps EVP cipher, writes payload. |
| `vichaos_decrypt.c` | Single-shot decryption: parses payload, derives key, verifies auth tag, returns plaintext. |
| `vichaos_stream.c` | Streaming state machine (`vichaos_stream_t`) for chunked encrypt/decrypt with constant memory. |

### Design Decisions

- **AEAD over encrypt-then-MAC**: AES-256-GCM provides confidentiality and integrity in a single, audited primitive.
- **Single allocation per call**: The library allocates exactly one output buffer per encrypt/decrypt operation to reduce heap fragmentation.
- **Streaming decryption caveat**: Chunks are released before the final auth tag is verified. Callers must discard output on failure.
- **No embedded KDF iteration count**: The iteration count is not stored in the payload to avoid versioning complexity. If you use a non-default count, you must remember it for decryption.

---

## Dependencies

### Required

- **OpenSSL 1.1.1 or newer** (development headers and libraries)
- **GCC** or **Clang**
- **Make**

### Installing Dependencies

**Debian / Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install build-essential libssl-dev
```

**Fedora / RHEL:**
```bash
sudo dnf install gcc make openssl-devel
```

**macOS (Homebrew):**
```bash
brew install openssl
# You may need to point Makefile to the brew OpenSSL:
#   make LDFLAGS="-L$(brew --prefix openssl)/lib -lcrypto" \
#        CFLAGS="-I$(brew --prefix openssl)/include"
```

**Arch Linux:**
```bash
sudo pacman -S base-devel openssl
```

---

## Build & Installation

### Quick Build

```bash
cd /path/to/vichaos
make
```

This produces:
- `libvichaos.so.2` — shared library (SONAME `libvichaos.so.2`)
- `libvichaos.so` — symlink to shared library
- `libvichaos.a` — static library

### Performance Build

```bash
make OPTFLAGS="-O3 -march=native -flto"
```

The default `OPTFLAGS` already include `-O3 -march=native -flto -fomit-frame-pointer -funroll-loops`.

### Install System-Wide

```bash
sudo make install
```

By default, this installs to `/usr/local`:
- Header: `/usr/local/include/vichaos.h`
- Shared lib: `/usr/local/lib/libvichaos.so.2`
- Static lib: `/usr/local/lib/libvichaos.a`
- Symlink: `/usr/local/lib/libvichaos.so -> libvichaos.so.2`

You can override the prefix:
```bash
sudo make install PREFIX=/opt/vichaos
```

### Uninstall

```bash
sudo make uninstall
```

### Windows

`make install` is not supported on Windows. Copy files manually:
- `include/vichaos.h` -> your include path
- `libvichaos.so` / `libvichaos.a` -> your library path

---

## Usage

### 5.1 Command-Line Tools

The `example/` directory ships with two streaming CLI utilities.

#### Encrypt a File

```bash
./example/encrypt_file <input_file> <output_file> <password>
```

**Behavior:**
- Reads the input in 1 MiB chunks.
- Writes a 37-byte header, ciphertext chunks, and a trailing 16-byte auth tag.
- Uses constant memory regardless of input size.

#### Decrypt a File

```bash
./example/decrypt_file <encrypted_file> <output_file> <password>
```

**Behavior:**
- Reads the header, streams ciphertext, reads the trailing auth tag.
- Writes plaintext to a temporary file (`<output_file>.tmp`).
- Only renames the temp file to the final output **after** the auth tag verifies.
- Deletes the temp file on failure (wrong password, tampered data).

---

## Data Format Specification

### Payload Layout (Single-Shot / Streaming)

```
Offset  Size    Field
------  ----    -----
0       8       Magic: "ViChaos2"
8       1       Version: 0x02
9       16      Salt (random, PBKDF2-HMAC-SHA256)
25      12      IV (random, 96-bit GCM nonce)
37      N       Ciphertext (same length as plaintext)
37+N   16       Auth Tag (GCM 128-bit)
```

- **Total overhead:** 53 bytes (`VICHAOS_OVERHEAD`).
- **Header overhead:** 37 bytes (`VICHAOS_HEADER_OVERHEAD`).

### Streaming File Layout

```
[Header (37 bytes)] [Ciphertext Chunks ...] [Auth Tag (16 bytes)]
```

The header and tag are fixed-size; the ciphertext length is `file_size - 37 - 16`.

---

## Security Considerations

1. **Password Strength**
   - Use passwords of at least 12 characters.
   - Avoid dictionary words, common substitutions, or reused passwords.
   - The security of the encryption is only as strong as the password.

2. **KDF Iterations**
   - Default is 600,000 (OWASP 2023 recommendation for PBKDF2-SHA256).
   - Increase on fast hardware (e.g., 1,000,000+).
   - Never go below 100,000.
   - If you customize `kdf_iter`, record it alongside the encrypted data.

3. **OpenSSL Hygiene**
   - Always link against a maintained OpenSSL version.
   - Apply security patches promptly.
   - This library relies entirely on OpenSSL for cryptographic primitive security.

4. **Memory Safety**
   - The library wipes secrets with `OPENSSL_cleanse()`.
   - Your application should also zero plaintext buffers when no longer needed.
   - Avoid swapping sensitive data to disk (use `mlock()` where appropriate).

5. **Streaming Decryption Warning**
   - Plaintext chunks are released **before** the final auth tag is verified.
   - Always write to a temporary file and rename only after `vichaos_stream_decrypt_final()` returns `VICHAOS_SUCCESS`.

6. **Side-Channel Resistance**
   - The library does not implement additional side-channel hardening beyond what OpenSSL provides.
   - For HSM, smartcard, or extreme side-channel threat models, use dedicated hardware tooling.

7. **Authenticity**
   - AES-256-GCM provides authenticity. Reject any payload that fails tag verification.
   - Do not attempt to "partial decrypt" tampered data.

## Testing & Benchmarking

### Unit Tests

```bash
make test
```

Builds `test/test_vichaos` and runs it. The suite covers:
- Single-shot round-trip (encrypt then decrypt)
- Streaming round-trip
- Cross-compatibility between single-shot and streaming
- Negative cases (wrong password, tampered data, short payloads)

### CLI Integration Tests

```bash
make -C example test
```

Runs round-trip tests for small and large (3 MiB) files, plus wrong-password and tamper-detection tests.

### Benchmark

From the `bench/` directory:

```bash
make -C bench run
# or
cd bench && make run
```

Runs throughput tests across buffer sizes from 1 KiB to 256 MiB for both single-shot and streaming APIs.

**Benchmark options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--iter N` | `3` | Repetitions per size |
| `--kdf-iter N` | `600000` | PBKDF2 iterations |
| `--min-size N` | `1K` | Smallest buffer (supports K/M/G suffix) |
| `--max-size N` | `256M` | Largest buffer (supports K/M/G suffix) |

---

## Maintenance & Contributing

### Building the Project

```bash
make clean
make
make test
```

### Adding a New Source File

1. Add the `.c` file to `SRCS` in the top-level `Makefile`.
2. Rebuild: `make clean && make`.
3. Ensure `make test` passes.

### Modifying the API

- Update `include/vichaos.h` first.
- Implement changes in the corresponding `src/` module.
- Add tests to `test/test_vichaos.c` (if the source is present in your working tree).
- Update this documentation and `README.md`.

### Coding Conventions

- **C standard:** C99 (`<stdint.h>`, `<stddef.h>`).
- **Error handling:** Every public function returns `vichaos_result_t`. Never return bare `-1`.
- **Memory:** Return exactly one allocation per call. Free with `vichaos_free()`.
- **Secrets:** Wipe with `OPENSSL_cleanse()` before freeing.
- **Headers:** Include guards with `VICHAOS_H`.
- **Strings:** Use `vichaos_strerror()` for user-facing errors.

### Releasing

1. Bump `VICHAOS_PAYLOAD_VERSION` in `include/vichaos.h` if the payload format changes.
2. Update `SONAME` in `Makefile` if the ABI changes.
3. Tag the release: `git tag v2.x.x && git push --tags`.
4. Publish the built artifacts (`libvichaos.so`, `libvichaos.a`, headers).

### Known Limitations

- Windows build/install is manual (no CMake or autotools).
- The test source (`test/test_vichaos.c`) is not present in the current tree; only the compiled binary is committed.
- Streaming decryption releases plaintext before final auth verification (by design, but requires caller discipline).

---

## Troubleshooting

| Issue | Likely Cause | Fix |
|-------|--------------|-----|
| `fatal error: openssl/evp.h: No such file or directory` | OpenSSL dev package missing | `sudo apt-get install libssl-dev` (Debian/Ubuntu) |
| `undefined reference to EVP_*` | Linker missing `-lcrypto` | Ensure `LDFLAGS ?= -lcrypto` in Makefile |
| `make: *** No rule to make target 'test/test_vichaos.c'` | Test source is absent from working tree | Rebuild tests from source if available, or ignore if using committed binary |
| `Authentication tag verification failed` | Wrong password, truncated file, or tampered data | Verify password, re-transfer file, check disk integrity |
| `Unsupported payload version` | Trying to decrypt data from a future version | Update ViChaos to a version that supports the payload version |
| `Invalid header` | File is not a ViChaos payload or is corrupted | Ensure the file was produced by ViChaos and not modified |

---

## License

MIT License - Copyright (c) 2025 Direct Xploit 4 Alphabet.

See the [LICENSE](LICENSE) file for details.

---

*ViChaos v2 - Authenticated encryption, built on OpenSSL.*

