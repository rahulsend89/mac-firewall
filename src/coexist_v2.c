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
    
    es_new_client_result_t r = es_new_client(&g_client, ^(es_client_t *c, const es_message_t *m) {
        handler(c, m);
    });
    
    if (r != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "Failed: %d\n", r);
        return 1;
    }
    
    printf("✓ Client created\n");
    
    // Mute self
    audit_token_t self;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&self, &count) == KERN_SUCCESS) {
        es_mute_process(g_client, &self);
        printf("✓ Muted self\n");
    }
    
    // Mute high-traffic paths - be more aggressive
    const char *mute_paths[] = {
        "/System",
        "/Library", 
        "/usr",
        "/bin",
        "/sbin",
        "/private",  // Covers /private/var/db, /private/var/folders, etc.
        "/dev",
        "/Applications",
        "/opt",
        "/cores",
        "/var",  // Symlink to /private/var
    };
    
    for (size_t i = 0; i < sizeof(mute_paths)/sizeof(mute_paths[0]); i++) {
        es_return_t mr = es_mute_path(g_client, mute_paths[i], ES_MUTE_PATH_TYPE_TARGET_PREFIX);
        if (mr == ES_RETURN_SUCCESS) {