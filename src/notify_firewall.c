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