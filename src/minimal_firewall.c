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