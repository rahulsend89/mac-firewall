/**
 * ULTRA MINIMAL EndpointSecurity Client
 * 
 * Stripped down to absolute bare minimum.
 * NO dispatch_main(), NO timers, NO GCD.
 * Just respond and sleep.
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>

#include <signal.h>
#include <unistd.h>

static es_client_t *g_client = NULL;
static volatile int g_running = 1;
static volatile uint64_t g_count = 0;
