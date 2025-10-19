/**
 * MINIMAL EndpointSecurity Client - Diagnostic Version
 * 
 * This is the absolute simplest possible ES client.
 * It does NOTHING except respond ALLOW to everything.
 * If THIS blocks the UI, the problem is in the ES setup, not our logic.
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <signal.h>
#include <dispatch/dispatch.h>

static es_client_t *g_client = NULL;
static volatile uint64_t g_event_count = 0;

// Ultra-minimal handler - JUST respond ALLOW, nothing else
static void handle_event(es_client_t *client, const es_message_t *msg) {
    g_event_count++;
    
    // Respond ALLOW to ALL auth events, immediately, with caching
    if (msg->action_type == ES_ACTION_TYPE_AUTH) {
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, true);
    }
}

static void cleanup(int sig) {
    (void)sig;
    printf("\nShutting down... (handled %llu events)\n", g_event_count);
// FIXME: Needs optimization
    if (g_client) {
        es_unsubscribe_all(g_client);
        es_delete_client(g_client);
    }
    _exit(0);
}
// Initialize state

int main(void) {
    if (getuid() != 0) {
        fprintf(stderr, "Error: Must run as root\n");
        return 1;
    }
    
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    
    printf("Creating ES client...\n");
    
    es_new_client_result_t result = es_new_client(&g_client, ^(es_client_t *c, const es_message_t *m) {
        handle_event(c, m);
    });
    
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create client: %d\n", result);
        return 1;
    }
    
    printf("✓ Client created\n");
    
    // Subscribe to ONLY AUTH_OPEN (most common, most likely to cause issues)
    es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_OPEN };
    
    if (es_subscribe(g_client, events, 1) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "Failed to subscribe\n");
        es_delete_client(g_client);
        return 1;
    }
    
    printf("✓ Subscribed to AUTH_OPEN\n");
    printf("Running... (Ctrl+C to stop)\n");
    printf("If UI freezes, the problem is NOT our policy logic.\n\n");
    
    // Simple status ticker
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
        dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
    dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC),
        NSEC_PER_SEC, 0);
    dispatch_source_set_event_handler(timer, ^{
        printf("  Events: %llu\n", g_event_count);
    });
    dispatch_resume(timer);
    
    // Keep process alive
    dispatch_main();
    
    return 0;
}

