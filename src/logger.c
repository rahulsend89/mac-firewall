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
    if (strcasecmp(str, "info") == 0) return LOG_LEVEL_INFO;
    if (strcasecmp(str, "warning") == 0 || strcasecmp(str, "warn") == 0) return LOG_LEVEL_WARNING;
    if (strcasecmp(str, "error") == 0) return LOG_LEVEL_ERROR;
    if (strcasecmp(str, "critical") == 0 || strcasecmp(str, "crit") == 0) return LOG_LEVEL_CRITICAL;
    return LOG_LEVEL_INFO;
}

static void log_message(log_level_t level, const char *format, ...) {
    if (level < g_log_level) return;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Log to file
    if (g_log_file != NULL) {
        fprintf(g_log_file, "[%s] [%s] ", timestamp, level_to_string(level));
        
        va_list args;
        va_start(args, format);
        vfprintf(g_log_file, format, args);
        va_end(args);
        
        fprintf(g_log_file, "\n");
        fflush(g_log_file);
    }
    
    // Also log to stderr for WARNING and above
    if (level >= LOG_LEVEL_WARNING) {
        fprintf(stderr, "[%s] [%s] ", timestamp, level_to_string(level));
        
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        
        fprintf(stderr, "\n");
    }
}

bool logger_init(const char *log_file, const char *level_str) {
    g_log_level = string_to_level(level_str);
    
    if (log_file != NULL) {
        g_log_file = fopen(log_file, "a");
        if (g_log_file == NULL) {
            fprintf(stderr, "Warning: Failed to open log file: %s\n", log_file);
            return false;
        }
    }
    
    log_message(LOG_LEVEL_INFO, "=== macOS Firewall Started ===");
    log_message(LOG_LEVEL_INFO, "Log level: %s", level_str);
    log_message(LOG_LEVEL_INFO, "PID: %d", getpid());
    
    return true;
}

void log_access_attempt(const char *process, pid_t pid, const char *target, const char *operation) {
    log_message(LOG_LEVEL_DEBUG, "ACCESS: %s (PID %d) -> %s [%s]", 
               process, pid, target, operation);