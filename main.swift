import Foundation
import LocalAuthentication
import Security

// MARK: - Touch ID Authentication

func authenticateWithTouchID(reason: String) -> Bool {
    let context = LAContext()
    var error: NSError?

    // Check if Touch ID is available
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
        if let error = error {
            fputs("Touch ID not available: \(error.localizedDescription)\n", stderr)
        }
        return false
    }

    let semaphore = DispatchSemaphore(value: 0)
    var success = false

    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { result, authError in
        success = result
        if let authError = authError {
            fputs("Authentication failed: \(authError.localizedDescription)\n", stderr)
        }
        semaphore.signal()
    }

    semaphore.wait()
    return success
}

// MARK: - Keychain Operations

func getKeychainPassword(service: String, account: String) -> String? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    if status == errSecSuccess, let data = result as? Data {
        return String(data: data, encoding: .utf8)
    } else if status == errSecItemNotFound {
        fputs("Error: Password not found\n", stderr)
    } else if status == errSecAuthFailed {
        fputs("Error: Authentication failed\n", stderr)
    } else {
        fputs("Error: Keychain error (status: \(status))\n", stderr)
    }

    return nil
}

func setKeychainPassword(service: String, account: String, password: String) -> Bool {
    // First, try to delete existing item
    let deleteQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account
    ]
    SecItemDelete(deleteQuery as CFDictionary)

    // Add new item (without Access Control - requires paid Developer Program)
    // Security is provided at app level via Touch ID authentication
    guard let passwordData = password.data(using: .utf8) else {
        fputs("Error: Failed to encode password\n", stderr)
        return false
    }

    let addQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecValueData as String: passwordData,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]

    let status = SecItemAdd(addQuery as CFDictionary, nil)

    if status != errSecSuccess {
        fputs("Error: Failed to save password (status: \(status))\n", stderr)
        return false
    }

    return true
}

func deleteKeychainPassword(service: String, account: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account
    ]

    let status = SecItemDelete(query as CFDictionary)

    if status == errSecSuccess || status == errSecItemNotFound {
        return true
    }

    fputs("Error: Failed to delete password (status: \(status))\n", stderr)
    return false
}

func listKeychainItems(service: String? = nil) -> [(service: String, account: String)] {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll
    ]

    if let service = service {
        query[kSecAttrService as String] = service
    }

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    var items: [(service: String, account: String)] = []

    if status == errSecSuccess, let itemList = result as? [[String: Any]] {
        for item in itemList {
            if let service = item[kSecAttrService as String] as? String,
               let account = item[kSecAttrAccount as String] as? String {
                items.append((service: service, account: account))
            }
        }
    }

    return items
}

// MARK: - Secure Input

func readSecurePassword() -> String? {
    // Disable echo for secure input
    var oldTermios = termios()
    tcgetattr(FileHandle.standardInput.fileDescriptor, &oldTermios)

    var newTermios = oldTermios
    newTermios.c_lflag &= ~UInt(ECHO)
    tcsetattr(FileHandle.standardInput.fileDescriptor, TCSANOW, &newTermios)

    defer {
        // Restore echo
        tcsetattr(FileHandle.standardInput.fileDescriptor, TCSANOW, &oldTermios)
        print("") // New line after hidden input
    }

    return readLine()
}

// MARK: - Main

func printUsage() {
    fputs("""
    Usage: keychain-fingerprint <command> [options]

    Commands:
      get <service> <account>     Get password (requires Touch ID)
      set <service> <account>     Set password (requires Touch ID)
      delete <service> <account>  Delete password (requires Touch ID)
      list [service]              List items (requires Touch ID)

    Security:
      - All commands require Touch ID authentication
      - Passwords stored in macOS Keychain (encrypted)
      - Password input is hidden (no echo)
      - Other apps require Mac password to access

    Examples:
      keychain-fingerprint get myapp user@example.com
      keychain-fingerprint set myapp user@example.com
      keychain-fingerprint list
      keychain-fingerprint delete myapp user@example.com

    Shell variable usage:
      PASSWORD=$(keychain-fingerprint get myapp user@example.com)
      # use $PASSWORD
      unset PASSWORD
    """, stderr)
}

func main() {
    let args = CommandLine.arguments

    guard args.count >= 2 else {
        printUsage()
        exit(1)
    }

    let command = args[1]

    switch command {
    case "get":
        guard args.count >= 4 else {
            fputs("Error: 'get' requires <service> and <account>\n", stderr)
            exit(1)
        }

        let service = args[2]
        let account = args[3]

        // Touch ID authentication
        guard authenticateWithTouchID(reason: "Authentication required to retrieve Keychain password") else {
            exit(1)
        }

        if let password = getKeychainPassword(service: service, account: account) {
            print(password)
        } else {
            exit(1)
        }

    case "set":
        guard args.count >= 4 else {
            fputs("Error: 'set' requires <service> and <account>\n", stderr)
            exit(1)
        }

        let service = args[2]
        let account = args[3]

        // Touch ID authentication first
        guard authenticateWithTouchID(reason: "Authentication required to save Keychain password") else {
            exit(1)
        }

        fputs("Enter password: ", stderr)
        guard let password = readSecurePassword(), !password.isEmpty else {
            fputs("Error: No password provided\n", stderr)
            exit(1)
        }

        if setKeychainPassword(service: service, account: account, password: password) {
            fputs("Password saved successfully\n", stderr)
        } else {
            exit(1)
        }

    case "delete":
        guard args.count >= 4 else {
            fputs("Error: 'delete' requires <service> and <account>\n", stderr)
            exit(1)
        }

        let service = args[2]
        let account = args[3]

        // Touch ID authentication
        guard authenticateWithTouchID(reason: "Authentication required to delete Keychain password") else {
            exit(1)
        }

        if deleteKeychainPassword(service: service, account: account) {
            fputs("Password deleted successfully\n", stderr)
        } else {
            exit(1)
        }

    case "list":
        // Touch ID authentication
        guard authenticateWithTouchID(reason: "Authentication required to list Keychain items") else {
            exit(1)
        }

        let service = args.count >= 3 ? args[2] : nil
        let items = listKeychainItems(service: service)

        if items.isEmpty {
            fputs("No items found\n", stderr)
        } else {
            fputs("Service\t\t\tAccount\n", stderr)
            fputs("-------\t\t\t-------\n", stderr)
            for item in items {
                fputs("\(item.service)\t\t\(item.account)\n", stderr)
            }
        }

    case "help", "-h", "--help":
        printUsage()

    default:
        fputs("Unknown command: \(command)\n", stderr)
        printUsage()
        exit(1)
    }
}

main()
