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