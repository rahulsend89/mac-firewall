/**
 * Logging and Alerting System
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <stdbool.h>
#include <sys/types.h>

typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL
} log_level_t;

/**
 * Initialize logger
 */
bool logger_init(const char *log_file, const char *level_str);

/**
 * Log access attempt (allowed or denied)
 */
void log_access_attempt(const char *process, pid_t pid, const char *target, const char *operation);

/**
 * Log policy violation
 */
void log_violation(const char *type, const char *process, pid_t pid, 
                  const char *target, const char *reason);

/**
 * Log critical violation (always logged, may trigger alert)