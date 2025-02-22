/**
 * Interactive Alert UI for macOS Firewall
 * Shows user notifications when suspicious activity is detected
 */

import Cocoa
import UserNotifications

class FirewallAlert {
    
    static let shared = FirewallAlert()