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
    
    tracker->capacity = MAX_PROCESSES;
    tracker->processes = calloc(tracker->capacity, sizeof(process_info_t*));
    tracker->count = 0;
    
    if (tracker->processes == NULL) {
        free(tracker);
        return NULL;
    }
    
    return tracker;
}

static process_info_t* create_process_info(pid_t pid, const es_process_t *process) {
    process_info_t *info = calloc(1, sizeof(process_info_t));
    if (info == NULL) return NULL;
    
    info->pid = pid;
    info->ppid = process->ppid;
    info->uid = audit_token_to_euid(process->audit_token);
    info->start_time = process->start_time.tv_sec;
    
    // Copy executable path
    size_t path_len = process->executable->path.length;
    if (path_len >= sizeof(info->executable_path)) {
        path_len = sizeof(info->executable_path) - 1;
    }
    memcpy(info->executable_path, process->executable->path.data, path_len);
    info->executable_path[path_len] = '\0';
    
    // Set flags based on executable name
    info->is_npm = strstr(info->executable_path, "/npm") != NULL;
    info->is_node = strstr(info->executable_path, "/node") != NULL;
    info->is_script = strstr(info->executable_path, "python") != NULL ||
                     strstr(info->executable_path, "ruby") != NULL ||
                     strstr(info->executable_path, "bash") != NULL ||
                     strstr(info->executable_path, "sh") != NULL;
    
    // Check if native binary (not a script interpreter)
    info->is_native_binary = !info->is_node && !info->is_script;
    
    info->children = NULL;
    info->children_count = 0;
    info->parent = NULL;
    