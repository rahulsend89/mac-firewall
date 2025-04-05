/**
 * Exec-Only Firewall
 * 
 * Strategy: Only monitor AUTH_EXEC (process execution)
 * - Much lower event volume than AUTH_OPEN
 * - Still catches malicious binaries from npm packages
 * - Should work alongside Little Snitch
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <mach/mach.h>
#include <bsm/libbsm.h>

static es_client_t *g_client = NULL;
static volatile int g_running = 1;
static volatile uint64_t g_total = 0;
static volatile uint64_t g_blocked = 0;

// Check if path looks suspicious (npm supply chain attack vectors)
static int is_suspicious_exec(const char *path) {
    // Block executables from temp directories
    if (strstr(path, "/tmp/") != NULL) return 1;
    if (strstr(path, "/var/tmp/") != NULL) return 1;
    
    // Block executables from npm cache (postinstall attacks)
    if (strstr(path, "node_modules/.bin/") != NULL) return 0;  // Allow normal bin