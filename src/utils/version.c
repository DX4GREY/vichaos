// ViChaos v3 — Version and metadata
#include "../include/vichaos.h"
#include <string.h>

const char *vichaos_version_string(void) {
    return VICHAOS_VERSION_STRING;
}

int vichaos_version_major(void) {
    return VICHAOS_VERSION_MAJOR;
}

int vichaos_version_minor(void) {
    return VICHAOS_VERSION_MINOR;
}

int vichaos_version_patch(void) {
    return VICHAOS_VERSION_PATCH;
}
