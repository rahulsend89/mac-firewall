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
    
    // Mute our own process
    audit_token_t self;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&self, &count) == KERN_SUCCESS) {
        es_mute_process(g_client, &self);
        printf("✓ Muted self\n");
    }
    
    // Mute high-traffic system paths to reduce contention with Little Snitch
    // This dramatically reduces the number of events we need to handle
    const char *mute_paths[] = {
        "/System",
        "/Library",
        "/usr",
        "/bin",
        "/sbin",
        "/private/var/db",
        "/private/var/folders",
        "/dev",
        "/Applications",  // We don't care about app reads
    };
    
    for (size_t i = 0; i < sizeof(mute_paths)/sizeof(mute_paths[0]); i++) {
        es_return_t mr = es_mute_path(g_client, mute_paths[i], ES_MUTE_PATH_TYPE_TARGET_PREFIX);
        if (mr == ES_RETURN_SUCCESS) {
            printf("✓ Muted: %s\n", mute_paths[i]);
        }
    }
    
    // Subscribe to minimal events
    // Only AUTH_OPEN on non-muted paths (mainly user directories)
    es_event_type_t ev[] = { ES_EVENT_TYPE_AUTH_OPEN };
    if (es_subscribe(g_client, ev, 1) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "Subscribe failed\n");
        es_delete_client(g_client);