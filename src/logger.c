/**
 * Logger Implementation
 */

#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>

static FILE *g_log_file = NULL;
static log_level_t g_log_level = LOG_LEVEL_INFO;

static const char* level_to_string(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO: return "INFO";
        case LOG_LEVEL_WARNING: return "WARN";
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_CRITICAL: return "CRIT";
        default: return "UNKNOWN";
    }
}

static log_level_t string_to_level(const char *str) {
    if (strcasecmp(str, "debug") == 0) return LOG_LEVEL_DEBUG;