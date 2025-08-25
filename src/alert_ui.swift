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
    
    /// Show critical alert for credential theft attempt
    func showCredentialTheftAlert(process: String, pid: Int, target: String) {
        let content = UNMutableNotificationContent()
        content.title = "🚨 Security Alert: Credential Theft Blocked"
        content.body = "\(process) (PID \(pid)) tried to access \(target)"
        content.sound = .defaultCritical
        content.categoryIdentifier = "CREDENTIAL_THEFT"
        
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        
        center.add(request) { error in
            if let error = error {
                print("Error showing notification: \(error)")
            }
        }
    }
    
    /// Show alert for suspicious process execution
    func showSuspiciousExecAlert(process: String, pid: Int, executable: String) {
        let content = UNMutableNotificationContent()
        content.title = "⚠️ Suspicious Process Blocked"
        content.body = "\(process) tried to execute \(executable)"
        content.sound = .default
        content.categoryIdentifier = "SUSPICIOUS_EXEC"
        
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        
        center.add(request)
    }
    
    /// Show interactive dialog for user decision
    func showInteractiveDialog(
        process: String,
        pid: Int,
        operation: String,
        target: String,
        completion: @escaping (Bool) -> Void
    ) {
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = "Firewall: Allow or Deny?"
            alert.informativeText = """
            Process: \(process) (PID \(pid))
            Operation: \(operation)
            Target: \(target)
            
            Do you want to allow this operation?
            """
            alert.alertStyle = .warning
            alert.addButton(withTitle: "Deny")
            alert.addButton(withTitle: "Allow Once")
            alert.addButton(withTitle: "Allow Always")
            
            let response = alert.runModal()
            
            switch response {
            case .alertFirstButtonReturn: // Deny
                completion(false)
            case .alertSecondButtonReturn: // Allow Once
                completion(true)
            case .alertThirdButtonReturn: // Allow Always
                // TODO: Add to whitelist in config
                completion(true)
            default:
                completion(false)
            }
        }
    }
}

// C-compatible interface
@_cdecl("show_credential_theft_alert")
func showCredentialTheftAlert(
    process: UnsafePointer<CChar>,
    pid: Int32,
    target: UnsafePointer<CChar>
) {
    let processStr = String(cString: process)
    let targetStr = String(cString: target)
    
    FirewallAlert.shared.showCredentialTheftAlert(
        process: processStr,
        pid: Int(pid),
        target: targetStr