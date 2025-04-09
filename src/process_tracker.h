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
    