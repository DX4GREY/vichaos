# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC
LDFLAGS = -lcrypto

# Targets
LIB_NAME = libvichaos.so
STATIC_LIB = libvichaos.a

# Installation paths
PREFIX = /usr/local
INCLUDE_PATH = $(PREFIX)/include
LIB_PATH = $(PREFIX)/lib

# Source files
SRC_DIR = src
INC_DIR = include
SRCS = $(SRC_DIR)/vichaos.c
OBJS = $(SRCS:.c=.o)

# Build targets
all: shared static

shared: $(OBJS)
	$(CC) -shared -o $(LIB_NAME) $(OBJS) $(LDFLAGS)

static: $(OBJS)
	ar rcs $(STATIC_LIB) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

install: all
	install -d $(INCLUDE_PATH) $(LIB_PATH)
	install $(INC_DIR)/vichaos.h $(INCLUDE_PATH)
	install $(LIB_NAME) $(STATIC_LIB) $(LIB_PATH)
	ldconfig

uninstall:
	rm -f $(INCLUDE_PATH)/vichaos.h
	rm -f $(LIB_PATH)/$(LIB_NAME) $(LIB_PATH)/$(STATIC_LIB)

clean:
	rm -f $(OBJS) $(LIB_NAME) $(STATIC_LIB)

.PHONY: all shared static install uninstall clean