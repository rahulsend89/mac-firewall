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
    uint64_t now = mach_absolute_time();
    uint64_t deadline = m->deadline;
    
    if (now >= deadline) {
        // We're already past deadline - kernel will kill us
        // But respond anyway just in case
        __atomic_fetch_add(&g_late, 1, __ATOMIC_RELAXED);
    }
    
    // CRITICAL: Respond immediately regardless
    // Only respond to AUTH events
    if (m->action_type == ES_ACTION_TYPE_AUTH) {
        es_return_t ret = es_respond_auth_result(c, m, ES_AUTH_RESULT_ALLOW, true);
        if (ret != ES_RETURN_SUCCESS) {
            // Response failed - this is very bad
            // Could indicate message already expired
        }
    }
    
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
    
    printf("Creating ES client (coexistence v2)...\n");