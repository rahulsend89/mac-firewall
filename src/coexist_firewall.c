/**
 * Coexistence-Optimized EndpointSecurity Client
 * 
 * Designed to work alongside Little Snitch and other ES clients.
 * Strategy:
 * 1. Respond INSTANTLY (before any logic)
 * 2. Mute high-traffic system paths
 * 3. Use aggressive caching
 * 4. Only monitor user-specific directories for npm attacks
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <mach/mach.h>
#include <bsm/libbsm.h>

static es_client_t *g_client = NULL;
static volatile int g_running = 1;
static volatile uint64_t g_count = 0;

// CRITICAL: Respond FIRST, log LATER (if at all)
static void handler(es_client_t *c, const es_message_t *m) {
    // Respond IMMEDIATELY - no conditionals, no logic
    // This ensures we never miss the deadline
    es_respond_auth_result(c, m, ES_AUTH_RESULT_ALLOW, true);
    
    // Only then count (non-blocking)
    __atomic_fetch_add(&g_count, 1, __ATOMIC_RELAXED);
}

static void sig_handler(int s) {
    (void)s;
    g_running = 0;
}

int main(void) {
    if (getuid() != 0) {
        fprintf(stderr, "Run as root\n");
        return 1;
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("Creating ES client (coexistence mode)...\n");
    
    es_new_client_result_t r = es_new_client(&g_client, ^(es_client_t *c, const es_message_t *m) {
        handler(c, m);
    });
    
    if (r != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create client: %d\n", r);
        return 1;
    }
    
    printf("✓ Client created\n");
    