# Benchmark build for ViChaos v2 speed test.

CC       ?= gcc
CFLAGS   ?= -Wall -Wextra -O2
OPTFLAGS ?= -O3 -march=native
LDFLAGS  ?= -lcrypto

INC_DIR = ../include
SRC_DIR = ../src
BENCH_SRC = bench_speed.c
BENCH_BIN = bench_speed

# Build the static library from the main source, then link the benchmark.
$(BENCH_BIN): $(BENCH_SRC) $(SRC_DIR)/vichaos.c
	$(CC) $(CFLAGS) $(OPTFLAGS) -I$(INC_DIR) -o $@ $(BENCH_SRC) $(SRC_DIR)/vichaos.c $(LDFLAGS)

run: $(BENCH_BIN)
	./$(BENCH_BIN)

clean:
	rm -f $(BENCH_BIN)

.PHONY: run clean