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