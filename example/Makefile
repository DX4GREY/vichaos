# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = -L/usr/local/lib -lvichaos -lcrypto

# Programs to build
PROGRAMS = encrypt_file decrypt_file

# Default target
all: $(PROGRAMS)

# Build both programs
encrypt_file: encrypt_file.c
	$(CC) $(CFLAGS) -I../include -o $@ $< $(LDFLAGS)

decrypt_file: decrypt_file.c
	$(CC) $(CFLAGS) -I../include -o $@ $< $(LDFLAGS)

# Clean build artifacts
clean:
	rm -f $(PROGRAMS)

# Test both programs
test: $(PROGRAMS)
	@echo "Testing encryption/decryption..."
	@echo "This is text file." > test.txt
	@./encrypt_file test.txt test.enc "testpassword"
	@./decrypt_file test.enc test.out "testpassword"
	@diff test.txt test.out && echo "Test passed!" || echo "Test failed!"
	@rm -f test.enc test.out test.txt

# Phony targets
.PHONY: all clean test