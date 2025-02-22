/**
 * Smart Firewall - Coexistence through Process Muting
 * 
 * Strategy: Instead of muting PATHS, mute PROCESSES
 * - Immediately mute any Apple-signed process (they're trusted)
 * - Only apply policy to unsigned/third-party processes
 * - This dramatically reduces event volume while maintaining security
 */

#include <EndpointSecurity/EndpointSecurity.h>