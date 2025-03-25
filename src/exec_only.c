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