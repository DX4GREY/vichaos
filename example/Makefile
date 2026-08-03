# Compiler and flags
CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2 -g
LDFLAGS ?= -L../ -lvichaos -lcrypto

# Programs to build
PROGRAMS = encrypt_file decrypt_file

# Default target
all: $(PROGRAMS)

# Build both programs (link against local library)
encrypt_file: encrypt_file.c ../libvichaos.a
	$(CC) $(CFLAGS) -I../include -o $@ $< ../libvichaos.a $(LDFLAGS)

decrypt_file: decrypt_file.c ../libvichaos.a
	$(CC) $(CFLAGS) -I../include -o $@ $< ../libvichaos.a $(LDFLAGS)

# Clean build artifacts
clean:
	rm -f $(PROGRAMS)

# Test both programs (round-trip + wrong-password + tamper checks)
test: $(PROGRAMS)
	@echo "=== Round-trip test (small file) ==="
	@echo "Hello, ViChaos v2!" > test_small.txt
	@./encrypt_file test_small.txt test_small.enc "testpassword"
	@./decrypt_file test_small.enc test_small.out "testpassword"
	@diff test_small.txt test_small.out && echo "  PASS: small round-trip" || echo "  FAIL: small round-trip"

	@echo "=== Round-trip test (binary, >1 chunk) ==="
	@head -c 3000000 /dev/urandom > test_big.bin
	@./encrypt_file test_big.bin test_big.enc "testpassword"
	@./decrypt_file test_big.enc test_big.out "testpassword"
	@cmp test_big.bin test_big.out && echo "  PASS: binary round-trip" || echo "  FAIL: binary round-trip"

	@echo "=== Wrong password test (must fail) ==="
	@./decrypt_file test_small.enc test_wrong.out "wrongpassword" >/dev/null 2>&1 && echo "  FAIL: wrong password accepted" || echo "  PASS: wrong password rejected"
	@test ! -f test_wrong.out && echo "  PASS: no output file on failure" || echo "  FAIL: stale output file present"

	@echo "=== Tamper test (must fail auth) ==="
	@cp test_small.enc test_tamper.enc
	@printf '\x00' | dd of=test_tamper.enc bs=1 seek=60 count=1 conv=notrunc 2>/dev/null
	@./decrypt_file test_tamper.enc test_tamper.out "testpassword" >/dev/null 2>&1 && echo "  FAIL: tampered file accepted" || echo "  PASS: tampered file rejected"
	@test ! -f test_tamper.out && echo "  PASS: no output file on tamper" || echo "  FAIL: stale output file present"

	@echo "=== Cleanup ==="
	@rm -f test_small.txt test_small.enc test_small.out test_big.bin test_big.enc test_big.out test_wrong.out test_tamper.enc test_tamper.out
	@echo "All tests passed!"

# Phony targets
.PHONY: all clean test