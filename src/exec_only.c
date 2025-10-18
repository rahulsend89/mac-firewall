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
    if (strstr(path, "node_modules/") != NULL && 
        (strstr(path, ".sh") || strstr(path, ".py") || strstr(path, ".rb"))) {
        return 1;  // Block scripts in node_modules
    }
    
    return 0;
}

static void handler(es_client_t *c, const es_message_t *m) {
    __atomic_fetch_add(&g_total, 1, __ATOMIC_RELAXED);
    
    // Respond immediately for all AUTH events
    if (m->action_type == ES_ACTION_TYPE_AUTH) {
        es_auth_result_t result = ES_AUTH_RESULT_ALLOW;
        
        // Only check exec events
        if (m->event_type == ES_EVENT_TYPE_AUTH_EXEC) {

            const char *path = m->event.exec.target->executable->path.data;
            if (path && is_suspicious_exec(path)) {
                result = ES_AUTH_RESULT_DENY;
                __atomic_fetch_add(&g_blocked, 1, __ATOMIC_RELAXED);
            }
        }
        
        es_respond_auth_result(c, m, result, true);
    }
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
    
    printf("Creating ES client (EXEC-only mode)...\n");
    
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
    
    // Subscribe ONLY to AUTH_EXEC - much lower volume!
    es_event_type_t ev[] = { ES_EVENT_TYPE_AUTH_EXEC };
    if (es_subscribe(g_client, ev, 1) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "Subscribe failed\n");
        es_delete_client(g_client);
        return 1;
    }
    
    printf("✓ Subscribed to AUTH_EXEC only\n");
    printf("\n🛡️  Exec-Only Firewall Running\n");
    printf("Blocking: Scripts in node_modules, executables in /tmp\n");
    printf("Press Ctrl+C to stop\n\n");
    
    while (g_running) {
        printf("  Execs: %llu | Blocked: %llu\n", g_total, g_blocked);
        sleep(1);
    }
    
    printf("\nDone. Total: %llu, Blocked: %llu\n", g_total, g_blocked);
    es_unsubscribe_all(g_client);
    es_delete_client(g_client);
    
    return 0;