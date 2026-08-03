# Compiler and flags
CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2 -fPIC
LDFLAGS ?= -lcrypto

# Hardening for both debug and release builds
HARDEN_FLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2

# Performance build flags (default for release).
# -O3        : aggressive optimization
# -march=native : tune for the build machine's CPU (AES-NI, AVX2, etc.)
# -flto      : link-time optimization across translation units
# -fomit-frame-pointer : reduce call overhead
# -funroll-loops : unroll hot loops (helps PBKDF2 inner loop)
OPTFLAGS ?= -O3 -march=native -flto -fomit-frame-pointer -funroll-loops

# Targets
LIB_NAME    = libvichaos.so
STATIC_LIB  = libvichaos.a
SONAME      = libvichaos.so.2

# Installation paths
PREFIX      = /usr/local
INCLUDE_PATH = $(PREFIX)/include
LIB_PATH     = $(PREFIX)/lib

# Source files
SRC_DIR = src
INC_DIR = include
SRCS    = $(SRC_DIR)/vichaos.c
OBJS    = $(SRCS:.c=.o)

# Build targets
all: shared static

shared: $(OBJS)
	$(CC) -shared -Wl,-soname,$(SONAME) -o $(LIB_NAME) $(OBJS) $(LDFLAGS)

static: $(OBJS)
	ar rcs $(STATIC_LIB) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) $(OPTFLAGS) $(HARDEN_FLAGS) -I$(INC_DIR) -c $< -o $@

# ----------------------------------------------------------------------------
# Install / uninstall (conditional on OS)
# ----------------------------------------------------------------------------

ifeq ($(OS),Windows_NT)
install:
	@echo "Install is not supported on Windows. Please copy files manually:"
	@echo "  $(INC_DIR)/vichaos.h -> your include path"
	@echo "  $(LIB_NAME), $(STATIC_LIB) -> your lib path"
else
install: all
	install -d $(DESTDIR)$(INCLUDE_PATH) $(DESTDIR)$(LIB_PATH)
	install -m 0644 $(INC_DIR)/vichaos.h $(DESTDIR)$(INCLUDE_PATH)
	install -m 0755 $(LIB_NAME) $(DESTDIR)$(LIB_PATH)
	install -m 0644 $(STATIC_LIB) $(DESTDIR)$(LIB_PATH)
	ln -sf $(LIB_NAME) $(DESTDIR)$(LIB_PATH)/$(SONAME)
	@if command -v ldconfig >/dev/null 2>&1; then ldconfig; fi
endif

uninstall:
	rm -f $(DESTDIR)$(INCLUDE_PATH)/vichaos.h
	rm -f $(DESTDIR)$(LIB_PATH)/$(LIB_NAME) $(DESTDIR)$(LIB_PATH)/$(SONAME)
	rm -f $(DESTDIR)$(LIB_PATH)/$(STATIC_LIB)

# Unit tests
TEST_SRC = test/test_vichaos.c
TEST_BIN = test/test_vichaos

test: static $(TEST_BIN)
	$(TEST_BIN)

$(TEST_BIN): $(TEST_SRC) $(STATIC_LIB)
	$(CC) $(CFLAGS) $(OPTFLAGS) $(HARDEN_FLAGS) -I$(INC_DIR) -o $@ $(TEST_SRC) $(STATIC_LIB) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(LIB_NAME) $(SONAME) $(STATIC_LIB) $(TEST_BIN)

.PHONY: all shared static install uninstall clean test
