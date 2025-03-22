/**
 * macOS EndpointSecurity Firewall Daemon
 * 
 * Hybrid approach for coexisting with other ES clients (like Little Snitch):
 * - AUTH_EXEC: Block malicious process execution (low volume, works)
 * - NOTIFY_OPEN/CREATE: Monitor file access, kill suspicious processes
 * 
 * This architecture is proven to work alongside Little Snitch.
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <mach/mach.h>

#include "cJSON.h"
#include "config_parser.h"

// Code signing flags
#ifndef CS_VALID
#define CS_VALID 0x00000001
#endif
#ifndef CS_PLATFORM_BINARY
#define CS_PLATFORM_BINARY 0x04000000
#endif

// Global state
static es_client_t *g_client = NULL;
static firewall_config_t *g_config = NULL;
static volatile int g_running = 1;

// Statistics
static volatile uint64_t g_total_events = 0;
static volatile uint64_t g_exec_blocked = 0;
static volatile uint64_t g_suspicious_detected = 0;
static volatile uint64_t g_processes_killed = 0;

/**
 * Check if process is a core system process (very strict)
 */
static int is_system_process(const es_process_t *proc) {
    if (!proc) return 1;
    
    pid_t pid = audit_token_to_pid(proc->audit_token);
    if (pid < 100) return 1;  // Kernel and core system only
    
    // Only Apple platform binaries
    if (proc->codesigning_flags & CS_PLATFORM_BINARY) return 1;
    
    const char *path = proc->executable->path.data;
    // Very strict: only macOS system paths
    if (strncmp(path, "/System/", 8) == 0 ||
        strncmp(path, "/usr/libexec/", 13) == 0 ||
        strncmp(path, "/Library/Apple/", 15) == 0) {
        return 1;
    }
    
    return 0;
}

/**
 * Check if process is in npm install context (the threat we're targeting)
 */
static int is_npm_context(const es_process_t *proc) {