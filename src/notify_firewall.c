/**
 * NOTIFY-Based Firewall
 * 
 * Since AUTH events time out due to Little Snitch congestion,
 * we use NOTIFY events (no deadline) and kill malicious processes.
 * 
 * This is how some commercial security tools work - they observe
 * and react rather than block inline.
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <bsm/libbsm.h>

#define CS_VALID            0x00000001
#define CS_PLATFORM_BINARY  0x04000000

static es_client_t *g_client = NULL;
static volatile int g_running = 1;
static volatile uint64_t g_total = 0;
static volatile uint64_t g_suspicious = 0;
static volatile uint64_t g_killed = 0;

// Check if process is trusted (Apple-signed)
static int is_trusted(const es_process_t *proc) {
    if (!proc) return 1;
    pid_t pid = audit_token_to_pid(proc->audit_token);
    if (pid < 100) return 1;
    if (proc->codesigning_flags & CS_PLATFORM_BINARY) return 1;
    
    const char *path = proc->executable->path.data;
    if (strncmp(path, "/System/", 8) == 0 ||
        strncmp(path, "/usr/", 5) == 0 ||
        strncmp(path, "/bin/", 5) == 0 ||
        strncmp(path, "/sbin/", 6) == 0 ||
        strncmp(path, "/Applications/", 14) == 0) {
        return 1;
    }
    return 0;
}

// Kill a malicious process
static void kill_process(pid_t pid, const char *reason) {
    fprintf(stderr, "🛡️  KILLING PID %d: %s\n", pid, reason);
    kill(pid, SIGKILL);
    __atomic_fetch_add(&g_killed, 1, __ATOMIC_RELAXED);
}

static void handler(es_client_t *c, const es_message_t *m) {
    (void)c;
    __atomic_fetch_add(&g_total, 1, __ATOMIC_RELAXED);
    
    // Skip trusted processes
    if (is_trusted(m->process)) return;
    
    pid_t pid = audit_token_to_pid(m->process->audit_token);
    const char *proc_path = m->process->executable->path.data;
    
    // Check for suspicious file access
    if (m->event_type == ES_EVENT_TYPE_NOTIFY_OPEN) {
        const char *path = m->event.open.file->path.data;
        
        // Credential theft detection
        if (strstr(path, "/.ssh/id_") ||
            strstr(path, "/.aws/credentials") ||
            strstr(path, "/.gnupg/") ||
            strstr(path, "/.npmrc") ||
            strstr(path, "/.env")) {
            __atomic_fetch_add(&g_suspicious, 1, __ATOMIC_RELAXED);
            fprintf(stderr, "⚠️  SUSPICIOUS: PID %d (%s) accessed %s\n", pid, proc_path, path);
            // Optionally kill: kill_process(pid, "Credential access attempt");
        }
    }
    
    // Check for suspicious file creation
    if (m->event_type == ES_EVENT_TYPE_NOTIFY_CREATE) {
        const char *path = m->event.create.destination.new_path.dir->path.data;
        
        // Persistence mechanism detection
        if (strstr(path, "/.github/workflows") ||
            strstr(path, "/LaunchAgents/") ||
            strstr(path, "/LaunchDaemons/") ||
            strstr(path, "/.git/hooks/")) {
            __atomic_fetch_add(&g_suspicious, 1, __ATOMIC_RELAXED);
            fprintf(stderr, "⚠️  SUSPICIOUS: PID %d (%s) creating in %s\n", pid, proc_path, path);
        }
    }
    
    // Check for suspicious process execution
    if (m->event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
        const char *exec_path = m->event.exec.target->executable->path.data;
        
        // Temp directory execution - KILL IT!
        if (strstr(exec_path, "/tmp/") || strstr(exec_path, "/var/tmp/")) {
            kill_process(pid, "Execution from temp directory");
        }
        
        // Suspicious script execution from node_modules
        if (strstr(exec_path, "node_modules/") && 
            (strstr(exec_path, ".sh") || strstr(exec_path, ".py") || strstr(exec_path, ".rb"))) {
            kill_process(pid, "Script execution from node_modules");
        }
    }
}

static void sig_handler(int s) { (void)s; g_running = 0; }

int main(void) {
    if (getuid() != 0) { fprintf(stderr, "Run as root\n"); return 1; }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("Creating NOTIFY-Based Firewall...\n");
    printf("Strategy: Observe with NOTIFY events, kill malicious processes\n\n");
    
    es_new_client_result_t r = es_new_client(&g_client, ^(es_client_t *c, const es_message_t *m) {
        handler(c, m);
    });
    
    if (r != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "Failed: %d\n", r);
        return 1;
    }
    
    // Mute self
    audit_token_t self;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&self, &count) == KERN_SUCCESS) {
        es_mute_process(g_client, &self);
    }
    
    // Subscribe to NOTIFY events only (no deadline, no response needed!)
    es_event_type_t ev[] = { 
        ES_EVENT_TYPE_NOTIFY_OPEN,   // File access
        ES_EVENT_TYPE_NOTIFY_CREATE, // File creation
        ES_EVENT_TYPE_NOTIFY_EXEC,   // Process execution
        ES_EVENT_TYPE_NOTIFY_WRITE,  // File write
    };
    
    if (es_subscribe(g_client, ev, 4) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "Subscribe failed\n");