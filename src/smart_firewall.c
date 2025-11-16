/**
 * Smart Firewall - Coexistence through Process Muting
 * 
 * Strategy: Instead of muting PATHS, mute PROCESSES
 * - Immediately mute any Apple-signed process (they're trusted)
 * - Only apply policy to unsigned/third-party processes
 * - This dramatically reduces event volume while maintaining security
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>  // For O_CREAT, O_TRUNC
#include <sys/fcntl.h>  // For FWRITE
#include <mach/mach.h>
#include <bsm/libbsm.h>

// Code signing flags
#define CS_VALID            0x00000001
#define CS_PLATFORM_BINARY  0x04000000

static es_client_t *g_client = NULL;
static volatile int g_running = 1;
static volatile uint64_t g_total = 0;
static volatile uint64_t g_muted_procs = 0;
static volatile uint64_t g_blocked = 0;

// Check if process is Apple-signed (trusted)
static int is_apple_process(const es_process_t *proc) {
    if (!proc) return 0;
    
    // Low PIDs are system processes
    pid_t pid = audit_token_to_pid(proc->audit_token);
    if (pid < 100) return 1;
    
    // Check code signature
    if (proc->codesigning_flags & CS_VALID) {
        if (proc->codesigning_flags & CS_PLATFORM_BINARY) {
            return 1;  // Apple platform binary
        }
    }
    
    // Check if path is in system locations
    const char *path = proc->executable->path.data;
    if (strncmp(path, "/System/", 8) == 0 ||
        strncmp(path, "/usr/", 5) == 0 ||
        strncmp(path, "/bin/", 5) == 0 ||
        strncmp(path, "/sbin/", 6) == 0 ||
        strncmp(path, "/Library/Apple/", 15) == 0) {
        return 1;
    }
    
    return 0;
}

// Check if this is a suspicious operation
static int is_suspicious(const es_message_t *m) {
    if (m->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
        const char *path = m->event.open.file->path.data;
        
        // Block reads to sensitive files
        if (strstr(path, "/.ssh/") ||
            strstr(path, "/.aws/") ||
            strstr(path, "/.gnupg/") ||
            strstr(path, "/.env") ||
            strstr(path, "/.npmrc")) {
            return 1;
        }
        
        // Block writes to sensitive locations
        uint32_t flags = m->event.open.fflag;
        if (flags & (FWRITE | O_CREAT | O_TRUNC)) {
            if (strstr(path, "/.github/workflows/") ||
                strstr(path, "/.git/hooks/") ||
                strstr(path, "/LaunchAgents/") ||
                strstr(path, "/LaunchDaemons/")) {
                return 1;
            }
        }
    }
    
    if (m->event_type == ES_EVENT_TYPE_AUTH_EXEC) {
        const char *path = m->event.exec.target->executable->path.data;
        
        // Block executables from temp
        if (strstr(path, "/tmp/") || strstr(path, "/var/tmp/")) {
            return 1;
        }
    }
    
    return 0;
}

static void handler(es_client_t *c, const es_message_t *m) {
    __atomic_fetch_add(&g_total, 1, __ATOMIC_RELAXED);
    
    es_auth_result_t result = ES_AUTH_RESULT_ALLOW;
    
    if (m->action_type == ES_ACTION_TYPE_AUTH) {
        // Check if process is Apple-signed
        if (is_apple_process(m->process)) {
            // Respond ALLOW immediately
            es_respond_auth_result(c, m, ES_AUTH_RESULT_ALLOW, true);
            
            // Mute this process for ALL future events - massive performance gain!
            es_mute_process(c, &m->process->audit_token);
            __atomic_fetch_add(&g_muted_procs, 1, __ATOMIC_RELAXED);
            return;
        }
        
        // For non-Apple processes, check policy
        if (is_suspicious(m)) {
            result = ES_AUTH_RESULT_DENY;
            __atomic_fetch_add(&g_blocked, 1, __ATOMIC_RELAXED);
            
            // Log blocked action (async would be better, but keeping simple)
            pid_t pid = audit_token_to_pid(m->process->audit_token);
            const char *proc_path = m->process->executable->path.data;
            fprintf(stderr, "🛡️  BLOCKED: PID %d (%s)\n", pid, proc_path);
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
    
    printf("Creating Smart Firewall (process-muting strategy)...\n");
    
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
    
    // Subscribe to AUTH events we care about
    es_event_type_t ev[] = { 
        ES_EVENT_TYPE_AUTH_OPEN,   // File access
        ES_EVENT_TYPE_AUTH_EXEC,   // Process execution
        ES_EVENT_TYPE_AUTH_CREATE, // File creation
    };
    
    if (es_subscribe(g_client, ev, sizeof(ev)/sizeof(ev[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "Subscribe failed\n");
        es_delete_client(g_client);
        return 1;
    }
    
    printf("✓ Subscribed to AUTH_OPEN, AUTH_EXEC, AUTH_CREATE\n");
    printf("\n🛡️  Smart Firewall Running\n");
    printf("Strategy: Mute Apple processes, monitor others\n");
    printf("Press Ctrl+C to stop\n\n");
    
    while (g_running) {
        printf("  Events: %llu | Muted Procs: %llu | Blocked: %llu\n", 
               g_total, g_muted_procs, g_blocked);
        sleep(1);
    }
    
    printf("\nShutting down...\n");
    printf("Final: Events=%llu, Muted=%llu, Blocked=%llu\n", g_total, g_muted_procs, g_blocked);
    es_unsubscribe_all(g_client);
    es_delete_client(g_client);
    