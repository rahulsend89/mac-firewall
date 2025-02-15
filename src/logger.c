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