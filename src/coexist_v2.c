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
