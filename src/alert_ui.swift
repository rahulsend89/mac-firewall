/**
 * Interactive Alert UI for macOS Firewall
 * Shows user notifications when suspicious activity is detected
 */

import Cocoa
import UserNotifications

class FirewallAlert {
    
    static let shared = FirewallAlert()
    private let center = UNUserNotificationCenter.current()
    
    private init() {
        // Request notification permission
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if granted {
                print("Notification permission granted")
            } else if let error = error {
                print("Notification error: \(error)")
            }
        }
    }
    