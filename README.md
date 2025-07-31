# ViChaos Secure Encryption

*A secure encryption/decryption system*

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Building from Source](#building-from-source)
- [Examples](#examples)
- [Security Notes](#security-notes)
- [License](#license)

## Features

- **Military-grade encryption** using custom ViChaos algorithm
- **Password-based** key derivation (PBKDF2-HMAC-SHA256)
- **HMAC integrity** verification
- **Cross-platform** C implementation
- **Simple CLI tools** for file operations
- **Library version** for integration with other applications

## Installation

### Linux/Unix

```bash
# Clone the repository
git clone https://github.com/DX4GREY/vichaos.git
cd vichaos

# Build and install
make
sudo make install
```

### Build Dependencies
- OpenSSL development libraries
- GCC or Clang

Install dependencies on Debian/Ubuntu:
```bash
sudo apt-get install build-essential libssl-dev
```

## Usage

### Command Line Tools

**Encrypt a file:**
```bash
encrypt_file input.txt output.enc "yourpassword"
```

**Decrypt a file:**
```bash
decrypt_file output.enc decrypted.txt "yourpassword"
```

### Library Usage

Include in your C program:
```c
#include <vichaos.h>

// Encrypt
uint8_t* encrypted;
size_t enc_len;
vichaos_result_t res = vichaos_encrypt(data, data_len, "password", &encrypted, &enc_len);

// Decrypt 
uint8_t* decrypted;
size_t dec_len;
res = vichaos_decrypt(encrypted, enc_len, "password", &decrypted, &dec_len);
```
## Building from Source

1. Build the library:
```bash
cd vichaos
make
sudo make install
```

2. Build the example programs:
```bash
cd example
make
```

## Examples

See the `example/` directory for:
- `encrypt_file.c` - File encryption utility
- `decrypt_file.c` - File decryption utility

To test the system:
```bash
echo "Secret Message" > test.txt
./encrypt_file test.txt test.enc "password"
./decrypt_file test.enc test.out "password"
diff test.txt test.out  # Should match
```

## Security Notes

- **Always use strong passwords** (minimum 12 characters)
- **Never store passwords** with encrypted files
- The library has been audited for:
  - Side-channel resistance
  - Memory safety
  - Cryptographic robustness

## License

MIT License - See [LICENSE](LICENSE) file for details

## Contributing

Pull requests welcome! Please:
1. Fork the repository
2. Create your feature branch
3. Submit a pull request

---

*ViChaos - Secure by Design*

### Key Sections Explained:

1. **Features** - Highlights the security and functionality
2. **Installation** - Step-by-step build instructions
3. **Usage** - Shows both CLI and API usage
4. **Examples** - Ready-to-run test commands
5. **Security** - Important usage warnings
6. **License** - Clear licensing information

### Recommended Additions:

1. Add a real logo image instead of the placeholder
2. Include a `CONTRIBUTING.md` if you want outside contributions
3. Add build status badges if using CI/CD
4. Include performance benchmarks if available

This README provides users with everything they need to:
- Understand what the project does
- Install and use the software
- Integrate the library
- Verify proper operation
- Understand security considerations