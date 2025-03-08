/**
 * Process Tracker Implementation
 */

#include "process_tracker.h"
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <bsm/libbsm.h>

#define MAX_PROCESSES 4096

struct process_tracker {
    process_info_t **processes;
    size_t capacity;
    size_t count;
};

process_tracker_t* process_tracker_create(void) {
    process_tracker_t *tracker = malloc(sizeof(process_tracker_t));
    if (tracker == NULL) return NULL;