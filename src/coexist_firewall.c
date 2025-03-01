/**
 * Coexistence-Optimized EndpointSecurity Client
 * 
 * Designed to work alongside Little Snitch and other ES clients.
 * Strategy:
 * 1. Respond INSTANTLY (before any logic)
 * 2. Mute high-traffic system paths
 * 3. Use aggressive caching
 * 4. Only monitor user-specific directories for npm attacks
 */

#include <EndpointSecurity/EndpointSecurity.h>