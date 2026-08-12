/*
 * bench_speed.c — ViChaos v2 encryption/decryption speed benchmark.
 *
 * Measures throughput (MiB/s) and wall-clock time for:
 *   - Single-shot API  (vichaos_encrypt / vichaos_decrypt)
 *   - Streaming API    (vichaos_stream_*)
 *
 * Tests run over a range of buffer sizes (1 KiB → 256 MiB) and report
 * per-size results plus an aggregate summary.
 *
 * Usage:
 *   bench_speed [--iter N] [--kdf-iter N] [--min-size N] [--max-size N]
 *
 *   --iter N       number of benchmark repetitions per size (default 3)
 *   --kdf-iter N   PBKDF2 iteration count (default 600000)
 *   --min-size N   smallest buffer size in bytes (default 1024)
 *   --max-size N   largest buffer size in bytes (default 268435456 = 256 MiB)
 *
 * Sizes are doubled between min and max. Suffixes K/M/G are accepted
 * (e.g. 1M, 256M).
 */

#define _POSIX_C_SOURCE 199309L   /* for clock_gettime(CLOCK_MONOTONIC) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <vichaos.h>

/* ------------------------------------------------------------------ */
/* Timing helpers                                                      */
/* ------------------------------------------------------------------ */

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ------------------------------------------------------------------ */
/* CLI helpers                                                         */
/* ------------------------------------------------------------------ */

static size_t parse_size(const char *s) {
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (end && *end) {
        switch (*end) {
            case 'K': case 'k': v *= 1024ULL; break;
            case 'M': case 'm': v *= 1024ULL * 1024ULL; break;
            case 'G': case 'g': v *= 1024ULL * 1024ULL * 1024ULL; break;
            default:
                fprintf(stderr, "Invalid size suffix '%c' in '%s'\n", *end, s);
                exit(1);
        }
    }
    return (size_t)v;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [--iter N] [--kdf-iter N] [--min-size N] [--max-size N]\n"
        "\n"
        "  --iter N       repetitions per size (default 3)\n"
        "  --kdf-iter N   PBKDF2 iterations (default 600000)\n"
        "  --min-size N   smallest buffer (default 1K)\n"
        "  --max-size N   largest buffer (default 256M)\n"
        "\n"
        "Sizes accept K/M/G suffixes, e.g. 1K, 4M, 256M.\n",
        prog);
    exit(1);
}

/* ------------------------------------------------------------------ */
/* Benchmark helpers                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    double enc_total;
    double dec_total;
    size_t bytes;
    int    ok;
} bench_result_t;

/* Run one single-shot encrypt+decrypt round-trip, timing each phase. */
static bench_result_t bench_single_shot(const uint8_t *data, size_t len,
                                        const char *password,
                                        const vichaos_options_t *opts) {
    bench_result_t r = {0, 0, len, 0};
    uint8_t *enc = NULL, *dec = NULL;
    size_t enc_len = 0, dec_len = 0;

    double t0 = now_seconds();
    vichaos_result_t er = vichaos_encrypt(data, len, password,
                                                       strlen(password), opts, &enc, &enc_len);
    double t1 = now_seconds();
    if (er != VICHAOS_SUCCESS) {
        fprintf(stderr, "  encrypt failed: %s\n", vichaos_strerror(er));
        goto out;
    }

    vichaos_result_t dr = vichaos_decrypt(enc, enc_len, password,
                                                       strlen(password), opts, &dec, &dec_len);
    double t2 = now_seconds();
    if (dr != VICHAOS_SUCCESS) {
        fprintf(stderr, "  decrypt failed: %s\n", vichaos_strerror(dr));
        goto out;
    }

    if (dec_len != len || memcmp(dec, data, len) != 0) {
        fprintf(stderr, "  round-trip mismatch!\n");
        goto out;
    }

    r.enc_total = t1 - t0;
    r.dec_total = t2 - t1;
    r.ok = 1;

out:
    vichaos_free(enc);
    vichaos_free(dec);
    return r;
}

/* Run one streaming encrypt+decrypt round-trip, timing each phase. */
static bench_result_t bench_stream(const uint8_t *data, size_t len,
                                   const char *password,
                                   const vichaos_options_t *opts) {
    bench_result_t r = {0, 0, len, 0};
    uint8_t *enc = NULL, *dec = NULL;
    size_t enc_len = 0, dec_len = 0;

    /* ---- Encrypt ---- */
    uint8_t header[VICHAOS_HEADER_OVERHEAD];
    size_t header_len = 0;
    double t0 = now_seconds();

    vichaos_stream_t *es = vichaos_stream_encrypt_init(password,
                                                       strlen(password), opts,
                                                       header, &header_len);
    if (!es) {
        fprintf(stderr, "  stream encrypt init failed\n");
        return r;
    }

    /* Worst-case output: header + len + tag. */
    enc = malloc(header_len + len + VICHAOS_TAG_SIZE + 16);
    if (!enc) {
        fprintf(stderr, "  out of memory\n");
        vichaos_stream_encrypt_final(es, NULL, NULL);
        return r;
    }
    memcpy(enc, header, header_len);
    enc_len = header_len;

    size_t off = 0;
    vichaos_result_t res = VICHAOS_SUCCESS;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > VICHAOS_STREAM_CHUNK)
            chunk = VICHAOS_STREAM_CHUNK;
        size_t out_len = 0;
        res = vichaos_stream_encrypt_update(es, data + off, chunk,
                                            enc + enc_len, &out_len);
        if (res != VICHAOS_SUCCESS) {
            fprintf(stderr, "  stream encrypt update failed: %s\n",
                    vichaos_strerror(res));
            vichaos_stream_encrypt_final(es, NULL, NULL);
            free(enc);
            return r;
        }
        enc_len += out_len;
        off += chunk;
    }

    uint8_t tag[VICHAOS_TAG_SIZE];
    size_t tag_len = 0;
    res = vichaos_stream_encrypt_final(es, tag, &tag_len);
    if (res != VICHAOS_SUCCESS) {
        fprintf(stderr, "  stream encrypt final failed: %s\n",
                vichaos_strerror(res));
        free(enc);
        return r;
    }
    memcpy(enc + enc_len, tag, tag_len);
    enc_len += tag_len;
    double t1 = now_seconds();

    /* ---- Decrypt ---- */
    dec = malloc(len + 16);
    if (!dec) {
        fprintf(stderr, "  out of memory\n");
        free(enc);
        return r;
    }

    vichaos_stream_t *ds = vichaos_stream_decrypt_init(password,
                                                       strlen(password), enc,
                                                       header_len, opts);
    if (!ds) {
        fprintf(stderr, "  stream decrypt init failed\n");
        free(enc);
        free(dec);
        return r;
    }

    size_t body_len = enc_len - header_len - tag_len;
    off = 0;
    dec_len = 0;
    while (off < body_len) {
        size_t chunk = body_len - off;
        if (chunk > VICHAOS_STREAM_CHUNK)
            chunk = VICHAOS_STREAM_CHUNK;
        size_t out_len = 0;
        res = vichaos_stream_decrypt_update(ds, enc + header_len + off, chunk,
                                            dec + dec_len, &out_len);
        if (res != VICHAOS_SUCCESS) {
            fprintf(stderr, "  stream decrypt update failed: %s\n",
                    vichaos_strerror(res));
            vichaos_stream_decrypt_final(ds, NULL, 0);
            free(enc);
            free(dec);
            return r;
        }
        dec_len += out_len;
        off += chunk;
    }

    res = vichaos_stream_decrypt_final(ds, enc + enc_len - tag_len, tag_len);
    if (res != VICHAOS_SUCCESS) {
        fprintf(stderr, "  stream decrypt final failed: %s\n",
                vichaos_strerror(res));
        free(enc);
        free(dec);
        return r;
    }
    double t2 = now_seconds();

    if (dec_len != len || memcmp(dec, data, len) != 0) {
        fprintf(stderr, "  stream round-trip mismatch!\n");
        free(enc);
        free(dec);
        return r;
    }

    r.enc_total = t1 - t0;
    r.dec_total = t2 - t1;
    r.ok = 1;

    free(enc);
    free(dec);
    return r;
}

/* ------------------------------------------------------------------ */
/* Reporting                                                           */
/* ------------------------------------------------------------------ */

static const char *size_str(size_t size);

static void print_row(const char *label, size_t size, double enc_s,
                      double dec_s) {
    double enc_mib = (double)size / (1024.0 * 1024.0);
    double enc_rate = enc_s > 0 ? enc_mib / enc_s : 0.0;
    double dec_rate = dec_s > 0 ? enc_mib / dec_s : 0.0;
    printf("%-12s %10s  %10.3f s  %10.2f MiB/s  %10.3f s  %10.2f MiB/s\n",
           label, size_str(size), enc_s, enc_rate, dec_s, dec_rate);
}

static const char *size_str(size_t size) {
    static char buf[32];
    if (size >= 1024ULL * 1024ULL * 1024ULL)
        snprintf(buf, sizeof(buf), "%.2f GiB", (double)size / (1024.0*1024.0*1024.0));
    else if (size >= 1024ULL * 1024ULL)
        snprintf(buf, sizeof(buf), "%.2f MiB", (double)size / (1024.0*1024.0));
    else if (size >= 1024ULL)
        snprintf(buf, sizeof(buf), "%.2f KiB", (double)size / 1024.0);
    else
        snprintf(buf, sizeof(buf), "%zu B", size);
    return buf;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    int iters = 3;
    size_t min_size = 1024;
    size_t max_size = 256ULL * 1024ULL * 1024ULL;
    vichaos_options_t opts;
    vichaos_options_init(&opts);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--iter") == 0 && i + 1 < argc) {
            iters = atoi(argv[++i]);
            if (iters < 1) iters = 1;
        } else if (strcmp(argv[i], "--kdf-iter") == 0 && i + 1 < argc) {
            opts.kdf_iter = (uint32_t)strtoul(argv[++i], NULL, 10);
            if (opts.kdf_iter < VICHAOS_MIN_KDF_ITER) {
                fprintf(stderr, "kdf-iter below minimum %u; clamping\n",
                        VICHAOS_MIN_KDF_ITER);
                opts.kdf_iter = VICHAOS_MIN_KDF_ITER;
            }
            if (opts.kdf_iter > VICHAOS_MAX_KDF_ITER) {
                fprintf(stderr, "kdf-iter above maximum %u; clamping\n",
                        VICHAOS_MAX_KDF_ITER);
                opts.kdf_iter = VICHAOS_MAX_KDF_ITER;
            }
        } else if (strcmp(argv[i], "--min-size") == 0 && i + 1 < argc) {
            min_size = parse_size(argv[++i]);
        } else if (strcmp(argv[i], "--max-size") == 0 && i + 1 < argc) {
            max_size = parse_size(argv[++i]);
        } else {
            usage(argv[0]);
        }
    }

    if (min_size > max_size) {
        fprintf(stderr, "min-size (%zu) > max-size (%zu)\n", min_size, max_size);
        return 1;
    }

    const char *password = "benchmark-password-1234";

    printf("ViChaos v2 — Encryption/Decryption Speed Benchmark\n");
    printf("==================================================\n");
    printf("KDF iterations : %u\n", opts.kdf_iter);
    printf("Repetitions    : %d\n", iters);
    printf("Size range     : %s → %s\n", size_str(min_size), size_str(max_size));
    printf("\n");
    printf("%-12s %10s  %10s  %12s  %10s  %12s\n",
           "API", "Size", "Enc time", "Enc rate", "Dec time", "Dec rate");
    printf("%-12s %10s  %10s  %12s  %10s  %12s\n",
           "----", "----", "--------", "--------", "--------", "--------");

    double agg_enc_single = 0, agg_dec_single = 0;
    double agg_enc_stream = 0, agg_dec_stream = 0;
    size_t agg_bytes = 0;
    int agg_ok = 0;

    for (size_t size = min_size; size <= max_size; ) {
        uint8_t *data = malloc(size);
        if (!data) {
            fprintf(stderr, "out of memory for size %zu\n", size);
            return 1;
        }
        /* Deterministic pseudo-random data (not crypto RNG — just for bench). */
        uint32_t seed = 0x12345678u;
        for (size_t i = 0; i < size; i++) {
            seed = seed * 1103515245u + 12345u;
            data[i] = (uint8_t)(seed >> 24);
        }

        /* ---- Single-shot ---- */
        double enc_s = 0, dec_s = 0;
        int ok = 1;
        for (int it = 0; it < iters; it++) {
            bench_result_t r = bench_single_shot(data, size, password, &opts);
            if (!r.ok) { ok = 0; break; }
            enc_s += r.enc_total;
            dec_s += r.dec_total;
        }
        if (ok) {
            enc_s /= iters;
            dec_s /= iters;
            print_row("single-shot", size, enc_s, dec_s);
            agg_enc_single += enc_s;
            agg_dec_single += dec_s;
            agg_bytes += size;
            agg_ok++;
        }

        /* ---- Streaming ---- */
        enc_s = 0; dec_s = 0; ok = 1;
        for (int it = 0; it < iters; it++) {
            bench_result_t r = bench_stream(data, size, password, &opts);
            if (!r.ok) { ok = 0; break; }
            enc_s += r.enc_total;
            dec_s += r.dec_total;
        }
        if (ok) {
            enc_s /= iters;
            dec_s /= iters;
            print_row("streaming", size, enc_s, dec_s);
            agg_enc_stream += enc_s;
            agg_dec_stream += dec_s;
        }

        free(data);

        if (size >= max_size) break;
        size_t next = size * 2;
        if (next < size) next = max_size;   /* overflow guard */
        if (next > max_size) next = max_size;
        size = next;
    }

    printf("\n");
    printf("Aggregate (sum over all sizes, %d run(s) each):\n", iters);
    printf("  Single-shot : enc %.3f s, dec %.3f s\n",
           agg_enc_single, agg_dec_single);
    printf("  Streaming   : enc %.3f s, dec %.3f s\n",
           agg_enc_stream, agg_dec_stream);
    printf("  Total data  : %s\n", size_str(agg_bytes));

    return 0;
}