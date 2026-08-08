// ViChaos v3 — Structured error handling with logging levels
#include "../include/vichaos.h"
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static vichaos_log_level_t g_log_level = VICHAOS_LOG_WARN;

static const char *g_error_strings[] = {
    [VICHAOS_SUCCESS]           = "Success",
    [VICHAOS_ERR_NULL_PTR]      = "Null pointer argument",
    [VICHAOS_ERR_INVALID_KEY]   = "Invalid key",
    [VICHAOS_ERR_INVALID_IV]    = "Invalid IV",
    [VICHAOS_ERR_INVALID_TAG]   = "Invalid authentication tag",
    [VICHAOS_ERR_CIPHER_INIT]   = "Cipher initialization failed",
    [VICHAOS_ERR_ENCRYPT_FAIL]  = "Encryption failed",
    [VICHAOS_ERR_DECRYPT_FAIL]  = "Decryption failed",
    [VICHAOS_ERR_AUTH_FAIL]     = "Authentication failed (tag mismatch)",
    [VICHAOS_ERR_MEMORY_ALLOC]  = "Memory allocation failed",
    [VICHAOS_ERR_IO_READ]       = "I/O read error",
    [VICHAOS_ERR_IO_WRITE]      = "I/O write error",
    [VICHAOS_ERR_KDF_FAIL]      = "Key derivation failed",
    [VICHAOS_ERR_VERSION_MISMATCH] = "Unsupported payload version",
    [VICHAOS_ERR_BUFFER_TOO_SMALL] = "Buffer too small",
    [VICHAOS_ERR_INVALID_PARAM] = "Invalid parameter",
    [VICHAOS_ERR_OPENSSL]       = "OpenSSL error",
    [VICHAOS_ERR_UNKNOWN]       = "Unknown error"
};

const char *vichaos_strerror(vichaos_result_t result) {
    if (result < 0 || result >= (int)(sizeof(g_error_strings) / sizeof(g_error_strings[0]))) {
        return "Unknown error code";
    }
    return g_error_strings[result];
}

void vichaos_log_set_level(vichaos_log_level_t level) {
    g_log_level = level;
}

static void log_write(const char *prefix, const char *file, int line, const char *fmt, va_list ap) {
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), "[%s] %s:%d: ", prefix, file, line);
    if (n < 0 || (size_t)n >= sizeof(buf)) return;
    vsnprintf(buf + n, sizeof(buf) - (size_t)n, fmt, ap);
    size_t len = strlen(buf);
    buf[len++] = '\n';
    write(STDERR_FILENO, buf, len);
}

void vichaos_log_internal(vichaos_log_level_t level,
                          const char *file,
                          int line,
                          const char *fmt,
                          ...) {
    if (level > g_log_level) {
        return;
    }
    const char *prefix = "UNKNOWN";
    switch (level) {
        case VICHAOS_LOG_ERROR: prefix = "ERROR"; break;
        case VICHAOS_LOG_WARN:  prefix = "WARN";  break;
        case VICHAOS_LOG_INFO:  prefix = "INFO";  break;
        case VICHAOS_LOG_DEBUG: prefix = "DEBUG"; break;
    }
    va_list ap;
    va_start(ap, fmt);
    log_write(prefix, file, line, fmt, ap);
    va_end(ap);
}
