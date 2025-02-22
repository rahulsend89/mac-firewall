/**
 * Coexistence V2 - with deadline checking and diagnostics
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <bsm/libbsm.h>

static es_client_t *g_client = NULL;

static volatile int g_running = 1;
static volatile uint64_t g_count = 0;
static volatile uint64_t g_late = 0;

static void handler(es_client_t *c, const es_message_t *m) {
    // Check if we're past the deadline BEFORE responding
    // This helps diagnose if events are arriving late