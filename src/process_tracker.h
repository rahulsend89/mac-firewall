/**
 * Process Tree Tracker
 * Maintains parent-child relationships to detect npm install chains
 */

#ifndef PROCESS_TRACKER_H
#define PROCESS_TRACKER_H

#include <sys/types.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdbool.h>

typedef struct process_info process_info_t;

struct process_info {
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    char executable_path[1024];
    char *arguments;
    uint64_t start_time;
    
    // Process tree
    process_info_t *parent;
    process_info_t **children;
    size_t children_count;
    
    // Flags
    bool is_npm;
    bool is_node;
    bool is_script;
    bool is_native_binary;
};

typedef struct process_tracker process_tracker_t;

/**
 * Create process tracker
 */
process_tracker_t* process_tracker_create(void);

/**
 * Add process to tracker
 */
void process_tracker_add(process_tracker_t *tracker, pid_t pid, const es_process_t *process);

/**
 * Get process info
 */
process_info_t* process_tracker_get(process_tracker_t *tracker, pid_t pid);