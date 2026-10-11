import AppKit
import Darwin
import Combine
import Foundation
import ServiceManagement

struct StateRow: Identifiable {
    let id: String
    let value: JSONValue
    func text(_ field: String) -> String {
        if field == "label", value["label"].string == "" { return value["id"].string ?? "Unnamed" }
        if field == "resource.target", value.at(field).string == "" { return value["resource"]["kind"].display }
        if field == "resource.unit", value.at(field).string == "custom" { return value["resource"]["unit_name"].display }
        if field == "window", value["window"] == .null,
           let start = value["window_start"].number, let end = value["window_end"].number {
            let formatter = ISO8601DateFormatter()
            return formatter.string(from: Date(timeIntervalSince1970: start)) + " — "
                + formatter.string(from: Date(timeIntervalSince1970: end))
        }
        if field == "freshness", value["freshness"] == .null {
            if let complete = value["complete"].boolean {
                return complete ? "Current" : "Partial: \(value["unknown_buckets"].display) unknown or stale buckets"
            }
            guard value["status"].string != "unknown", let expiry = value["expires_at"].number else { return "Unknown" }
            return expiry <= Date().timeIntervalSince1970 ? "Stale" : "Current"
        }
        if field == "remaining", value["status"].string == "unknown" { return "Unknown" }
        if field == "remaining", value["complete"].boolean == false,
           value["buckets"].number == 0 { return "Unknown" }
        if field.hasSuffix("_at"), let timestamp = value.at(field).number {
            return ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: timestamp))
        }
        if case .array(let elements) = value.at(field) {
            return elements.isEmpty ? "Unknown" : elements.map(\.display).joined(separator: ", ")
        }
        return value.at(field).display
    }
}

@MainActor
final class DaemonStore: ObservableObject {
    @Published private(set) var snapshot: JSONValue = .object([:])
    @Published private(set) var integrations: [StateRow] = []
    @Published private(set) var connected = false
    @Published private(set) var custodyAvailable = false
    @Published private(set) var connectionMessage = "Connecting…"
    @Published private(set) var message = ""
    @Published private(set) var serviceStatus = "Not enabled"
    @Published private(set) var serviceRegistered = false
    @Published private(set) var serviceExternallyManaged = false
    @Published private(set) var serviceGuidance = ""
    @Published private(set) var readiness: [StateRow] = []
    @Published private(set) var readinessMessage = "Setup readiness is unverified."
    @Published private(set) var verificationOperationID: String?
    @Published private(set) var integrationMessage = ""
    @Published private(set) var nativeThreads: [StateRow] = []
    @Published private(set) var nativeDiscoveryMessage = "Discover the native application to inspect loaded threads and hook support."
    @Published private(set) var refreshing = false
    private let connection = DaemonConnection()
    private var refreshTask: Task<Void, Never>?
    private let service = SMAppService.agent(plistName: "ai.xoxd.omux.daemon.plist")

    init() {
        updateServiceStatus()
        refreshTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }

    deinit { refreshTask?.cancel() }

    func rows(_ domain: String) -> [StateRow] {
        snapshot[domain].array.enumerated().map { index, value in
            StateRow(id: value["id"].string ?? "\(domain)-\(index)", value: value)
        }
    }

    var capacities: [StateRow] {
        let totals = rows("capacity").map { row -> StateRow in
            guard case .object(var fields) = row.value else { return row }
            fields["provider"] = .string(row.text("provider") + " (compatible total)")
            return StateRow(id: row.id, value: .object(fields))
        }
        let observations = rows("observations").map { row -> StateRow in
            guard case .object(var fields) = row.value else { return row }
            fields["provider"] = .string(accountLabel(row.text("account_id")) + " (observation)")
            return StateRow(id: row.id, value: .object(fields))
        }
        return totals + observations
    }

    func accountLabel(_ accountID: String) -> String {
        guard let row = rows("accounts").first(where: { $0.id == accountID }) else { return accountID }
        let provider = row.value["identity"]["provider"].string ?? ""
        return row.text("label") + (provider.isEmpty ? "" : " (\(provider))")
    }

    var warmAlternatives: Bool { snapshot["policy"]["warm_alternatives"].boolean ?? true }
    var canMutate: Bool { connected && custodyAvailable && uncertainOperations.isEmpty }
    var canVerifySetup: Bool { connected && uncertainOperations.isEmpty && verificationOperationID == nil }

    func verifySetup() { action("setup.refresh") }

    func refresh() async {
        guard !refreshing else { return }
        refreshing = true
        defer { refreshing = false }
        do {
            let value = try await connection.request("state.snapshot")
            snapshot = value
            await reconcileOperations()
            connected = true
            custodyAvailable = value["custody_available"].boolean ?? false
            connectionMessage = custodyAvailable ? "Connected" : "Connected; credential custody unavailable"
            do {
                let result = try await connection.request("setup.readiness")
                let findings = result["findings"].array
                let expected: Set<String> = ["artifact", "service", "vault", "source", "identity", "grant", "native"]
                guard result["schema_version"].number == 1, findings.count == 7,
                      Set(findings.compactMap { $0["phase"].string }) == expected,
                      findings.allSatisfy({ $0["reason"].string != nil && $0["action"].string != nil }) else {
                    throw ControlError.invalidFrame
                }
                readiness = findings.map { StateRow(id: $0["phase"].display, value: $0) }
                readinessMessage = result["ready"].boolean == true
                    ? "Operational readiness reported; seamless handoff still requires separate evidence."
                    : "Setup has pending or unverified phases."
            } catch {
                readiness = []
                readinessMessage = "Shared setup readiness is unavailable; inspect each phase separately."
            }
            do {
                let result = try await connection.request("integrations.status")
                let installed = result["installed"].array
                let rawRows = result["integrations"] == .null ? result["adapters"].array.map { adapter -> JSONValue in
                    let id = adapter["id"].string ?? "unknown"
                    let capabilities = adapter["capabilities"].array
                    return .object([
                        "id": .string(id), "adapter": .string(id), "installed": .bool(installed.contains(.string(id))),
                        "capability": .string(capabilities.map { "\($0["name"].display) (\($0["proof"].display))" }.joined(separator: "; ")),
                        "limitation": .string(capabilities.map { "\($0["name"].display): \($0["limitation"].display)" }.joined(separator: "\n"))
                    ])
                } : result["integrations"].array
                integrations = rawRows.enumerated().map { index, item in
                    StateRow(id: item["id"].string ?? "integration-\(index)", value: item)
                }
                integrationMessage = ""
            } catch {
                integrationMessage = "Integration status is unavailable. Displayed capabilities may be stale."
            }
        } catch {
            connected = false
            readiness = []
            readinessMessage = "Setup readiness is unverified while disconnected."
            connectionMessage = error.localizedDescription
        }
        updateServiceStatus()
    }

    private var uncertainOperations: [String: String] = [:]
    private var reconcilingOperations: Set<String> = []

    private func reconcileOperations() async {
        for id in Array(uncertainOperations.keys) {
            guard !reconcilingOperations.contains(id), let originalError = uncertainOperations[id] else { continue }
            reconcilingOperations.insert(id)
            defer { reconcilingOperations.remove(id) }
            do {
                let result = try await connection.request("operation.status", params: ["operation_id": .string(id)])
                if result["status"].string == "completed", result["operation_id"].string == id, case .object = result["result"] {
                    if verificationOperationID == id {
                        let terminal = result["result"]
                        guard validVerificationTerminal(terminal, operationID: id) else { throw ControlError.invalidFrame }
                        verificationOperationID = nil
                        uncertainOperations.removeValue(forKey: id)
                        message = terminal["outcome"].string == "verification_completed"
                            ? "Local setup verification ended. Review each readiness phase; this does not install, activate, enroll or prove native handoff."
                            : "Setup verification safely refused: " + terminal["refusal"].display
                        continue
                    }
                    uncertainOperations.removeValue(forKey: id)
                    message = originalError + "\nThe previous action outcome was recovered; account state will refresh."
                } else {
                    message = originalError + "\nThe action outcome remains unresolved. Operation: " + id
                }
            } catch {
                if let failure = error as? ControlError, case .declined(let reason) = failure, reason == "UnknownOperation" {
                    if verificationOperationID == id {
                        // Absence after reconnect may name another daemon generation;
                        // it cannot prove this verification was never admitted.
                        message = originalError + "\nVerification outcome is unknown. Retaining operation: " + id
                        continue
                    }
                    // The same installation never retires durable operation IDs.
                    // An authoritative absence confirms preflight refusal or rollback.
                    uncertainOperations.removeValue(forKey: id)
                    message = originalError + "\nNo committed operation was found; another action may be requested."
                } else {
                    message = originalError + "\nThe action outcome could not be resolved. Operation: " + id
                }
            }
        }
    }

    func action(_ method: String, params: [String: JSONValue] = [:]) {
        guard connected else { message = "The service is disconnected. Reconnect before requesting an action."; return }
        let verification = method == "setup.refresh"
        guard custodyAvailable || verification else { message = "Credential custody is unavailable. Restore custody before changing accounts or routes."; return }
        guard uncertainOperations.isEmpty else { message = "A previous action has an unknown outcome. Refresh to reconcile it."; return }
        let nativeOperation = method == "integrations.attach" || method == "integrations.detach"
            || (method == "integrations.remove" && (params["adapter"]?.string ?? "codex") == "codex")
        let operationID = nativeOperation
            ? (UUID().uuidString + UUID().uuidString).replacingOccurrences(of: "-", with: "").lowercased()
            : UUID().uuidString
        var mutationParams = params
        mutationParams["operation_id"] = .string(operationID)
        mutationParams["expected_revision"] = snapshot["revision"]
        if verification {
            verificationOperationID = operationID
            uncertainOperations[operationID] = "Setup verification is pending. Operation: " + operationID
            message = uncertainOperations[operationID] ?? "Setup verification is pending."
        }
        Task {
            do {
                let result = try await connection.request(method, params: mutationParams)
                if verification {
                    // Acknowledgement is not completion. Resolve this exact ID;
                    // periodic refresh only reads status and never starts work.
                    await reconcileOperations()
                    await refresh()
                    return
                }
                message = result["message"].string ?? "Action accepted; account state will refresh."
                if let link = result["authorization_url"].string,
                   let url = URL(string: link), url.scheme == "https", url.host != nil {
                    NSWorkspace.shared.open(url)
                }
                await refresh()
            } catch {
                message = error.localizedDescription
                if let failure = error as? ControlError {
                    switch failure {
                    case .unknownOutcome, .mutationDeclined:
                        // Retain the identity before awaiting the outcome query.
                        // A daemon error after external I/O can be indeterminate.
                        uncertainOperations[operationID] = error.localizedDescription
                        await reconcileOperations()
                    case .unavailable, .peerMismatch, .invalidFrame, .incompatibleVersion, .timedOut, .declined:
                        if verification {
                            // Even preflight-looking failures are not an admission
                            // receipt. Preserve identity until an exact terminal result.
                            uncertainOperations[operationID] = error.localizedDescription
                            await reconcileOperations()
                        }
                        break
                    }
                }
            }
        }
    }

    private func validVerificationTerminal(_ result: JSONValue, operationID: String) -> Bool {
        guard case .object(let fields) = result,
              Set(fields.keys) == Set(["schema_version", "operation_id", "generation", "observed_at", "outcome", "refusal", "phases", "elapsed_ns", "timing_scope"]),
              verificationInteger(result["schema_version"]) == 1, result["operation_id"].string == operationID,
              let generation = verificationInteger(result["generation"]),
              let observed = verificationInteger(result["observed_at"]), observed <= UInt64(Int64.max),
              result["timing_scope"].string == "admission_to_terminal_before_commit_process_local",
              result["phases"].array.count == 7 else { return false }
        let unknownReasons: Set<String> = ["observation_unknown", "observation_stale", "evidence_unobserved", "synthetic_only", "native_evidence_missing", "channel_unknown"]
        let actionReasons: Set<String> = ["channel_mismatch", "missing", "pending", "incompatible", "vault_locked", "vault_key_lost", "vault_key_unavailable", "vault_access_denied", "vault_unavailable", "authority_expired", "browser_required", "native_unsupported"]
        switch result["outcome"].string {
        case "verification_completed":
            guard generation > 0, result["refusal"] == .null else { return false }
            if result["elapsed_ns"] != .null {
                guard verificationInteger(result["elapsed_ns"]) != nil else { return false }
            }
            return result["phases"].array.allSatisfy { phase in
                guard validVerificationPhase(phase), let reason = phase["reason"].string else { return false }
                let expected = reason == "ready" ? "verified_ready"
                    : unknownReasons.contains(reason) ? "unknown"
                    : actionReasons.contains(reason) ? "action_required" : ""
                return !expected.isEmpty && phase["outcome"].string == expected
            }
        case "safe_refusal":
            return ["busy", "installation_selection_required", "collection_timed_out"].contains(result["refusal"].string ?? "")
                && result["elapsed_ns"] == .null
                && result["phases"].array.allSatisfy {
                    validVerificationPhase($0) && $0["outcome"].string == "unknown" && $0["reason"].string == "observation_unknown"
                }
        default: return false
        }
    }

    private func verificationInteger(_ value: JSONValue) -> UInt64? {
        switch value {
        case .integer(let exact): return exact
        case .number(let number):
            // Doubles beyond the safe integer range cannot establish exact
            // authority. Wide wire integers retain their UInt64 representation.
            guard number.isFinite, number >= 0, number <= 9_007_199_254_740_991,
                  number.rounded() == number else { return nil }
            return UInt64(number)
        default: return nil
        }
    }

    private func validVerificationPhase(_ value: JSONValue) -> Bool {
        guard case .object(let fields) = value else { return false }
        return Set(fields.keys) == Set(["outcome", "reason"])
    }

    func setWarmAlternatives(_ enabled: Bool) {
        action("policy.set", params: ["sticky_routes": .bool(true), "warm_alternatives": .bool(enabled)])
    }

    func discoverNative() {
        guard connected else { nativeDiscoveryMessage = "Reconnect before native discovery."; return }
        nativeThreads = []
        Task {
            do {
                let result = try await connection.request("integrations.discover", params:
                    ["adapter": .string("codex")])
                guard case .array(let owners) = result["owners"], owners.count <= 256 else {
                    throw ControlError.invalidFrame
                }
                var discovered: [StateRow] = []
                var identities: Set<String> = []
                for owner in owners {
                    guard nativeHex(owner["owner_id"]), nativeHex(owner["process_nonce"]),
                          nativeGeneration(owner["endpoint_generation"]),
                          let endpoint = owner["owner_endpoint"].string, endpoint.hasPrefix("/"),
                          endpoint.utf8.count <= 107, !endpoint.utf8.contains(0),
                          let version = owner["native_version"].string, !version.isEmpty, version.utf8.count <= 256,
                          owner["support"].string != nil,
                          case .array(let threads) = owner["threads"] else { throw ControlError.invalidFrame }
                    for thread in threads {
                        guard case .object(var fields) = thread,
                              let id = thread["thread_id"].string, !id.isEmpty, id.utf8.count <= 256,
                              id.utf8.allSatisfy({ $0 >= 32 }),
                              nativeGeneration(thread["thread_instance_generation"]),
                              nativeGeneration(thread["attachment_generation"]), discovered.count < 1024 else {
                            throw ControlError.invalidFrame
                        }
                        for field in ["owner_id", "process_nonce", "endpoint_generation", "owner_endpoint"] {
                            fields[field] = owner[field]
                        }
                        fields["version"] = owner["native_version"]
                        fields["support"] = owner["support"]
                        let tuple = [owner["owner_id"], owner["process_nonce"], owner["endpoint_generation"],
                                     thread["thread_instance_generation"], thread["attachment_generation"], .string(id)]
                        let key = String(decoding: try JSONEncoder().encode(tuple), as: UTF8.self)
                        guard identities.insert(key).inserted else { throw ControlError.invalidFrame }
                        fields["id"] = .string(key)
                        let row = StateRow(id: key, value: .object(fields))
                        if thread["native_ref"] != .null && !nativeReference(thread["native_ref"], row: row.value) {
                            throw ControlError.invalidFrame
                        }
                        discovered.append(row)
                    }
                }
                nativeThreads = discovered
                nativeDiscoveryMessage = "Hook compatibility is experimental; live continuity remains unproved. Processes: \(owners.count). Loaded threads: \(nativeThreads.count)."
            } catch { nativeDiscoveryMessage = "Native discovery failed: \(error.localizedDescription)" }
        }
    }

    func nativeAction(_ method: String, threadID: String) {
        guard let row = nativeThreads.first(where: { $0.id == threadID }),
              row.value["support"].string == "compatible_hook" else {
            message = "Discover a compatible native process and select its thread first."; return
        }
        var params: [String: JSONValue] = ["adapter": .string("codex"), "thread_id": row.value["thread_id"]]
        for field in ["owner_endpoint", "owner_id", "process_nonce", "endpoint_generation", "thread_instance_generation"] {
            params[field] = row.value[field]
        }
        if method == "integrations.detach" {
            guard nativeReference(row.value["native_ref"], row: row.value) else {
                message = "This thread has no verified committed attachment to detach. Discover again after attachment."; return
            }
            params["native_ref"] = row.value["native_ref"]
        }
        action(method, params: params)
    }

    func canActOnNative(_ threadID: String?, detaching: Bool = false) -> Bool {
        guard canMutate, let threadID else { return false }
        return nativeThreads.contains { row in
            row.id == threadID && row.value["support"].string == "compatible_hook"
                && (!detaching || nativeReference(row.value["native_ref"], row: row.value))
        }
    }

    private func nativeHex(_ value: JSONValue) -> Bool {
        guard let text = value.string, text.utf8.count == 64 else { return false }
        return text != String(repeating: "0", count: 64)
            && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    private func nativeGeneration(_ value: JSONValue) -> Bool {
        guard let text = value.string, !text.isEmpty, text.utf8.count <= 20,
              text.utf8.first != 48, text.utf8.allSatisfy({ (48...57).contains($0) }),
              let generation = UInt64(text) else { return false }
        return generation != 0
    }

    private func nativeReference(_ value: JSONValue, row: JSONValue) -> Bool {
        guard case .object = value, value["owner_id"] == row["owner_id"] else { return false }
        return ["adapter_epoch", "endpoint_generation", "thread_instance_generation", "attachment_generation"]
            .allSatisfy { nativeGeneration(value[$0]) }
            && value["endpoint_generation"] == row["endpoint_generation"]
            && value["thread_instance_generation"] == row["thread_instance_generation"]
            && value["attachment_generation"] == row["attachment_generation"]
    }

    func integrationPath(_ adapter: String) -> String {
        let environment = ProcessInfo.processInfo.environment
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        switch adapter {
        case "git": return environment["GIT_CONFIG_GLOBAL"] ?? home + "/.gitconfig"
        case "codex": return (environment["CODEX_HOME"] ?? home + "/.codex") + "/config.toml"
        case "claude": return (environment["CLAUDE_CONFIG_DIR"] ?? home + "/.claude") + "/settings.json"
        default: return ""
        }
    }

    func setServiceEnabled(_ enabled: Bool) {
        updateServiceStatus()
        guard !serviceExternallyManaged else {
            message = serviceGuidance
            return
        }
        do {
            if enabled { try service.register() }
            else { try service.unregister() }
            updateServiceStatus()
            Task { await refresh() }
        } catch { message = error.localizedDescription }
    }

    func updateServiceStatus() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let external = home + "/Library/LaunchAgents/" + RuntimePaths.serviceLabel + ".plist"
        // A fleet launch agent and the bundled SMAppService must never compete.
        // Existing external definitions are reported, never rewritten here.
        var metadata = stat()
        let hasExternalDefinition = external.withCString { lstat($0, &metadata) == 0 }
        serviceExternallyManaged = hasExternalDefinition || RuntimePaths.isDevelopment
            || ProcessInfo.processInfo.environment["OMUX_SOCKET"] != nil
        if serviceExternallyManaged {
            serviceRegistered = connected
            serviceStatus = hasExternalDefinition ? "External launch agent configured; activation unverified" : "Selected instance is externally managed"
            serviceGuidance = "Update the selected instance's package, service and browser registration through its declarative deployment configuration, then activate that generation and reconnect. These controls do not install a second login service. Darwin Home Manager activation remains unproved."
            return
        }
        serviceGuidance = "Standalone app installation uses macOS Login Items. Fleet-managed installations must activate their declarative service instead."
        serviceRegistered = service.status == .enabled || service.status == .requiresApproval
        switch service.status {
        case .enabled: serviceStatus = "Enabled"
        case .requiresApproval: serviceStatus = "Approval required in System Settings"
        case .notRegistered: serviceStatus = "Not enabled"
        case .notFound: serviceStatus = "Service helper is missing from this app bundle"
        @unknown default: serviceStatus = "Unknown"
        }
    }

    func openServiceSettings() { SMAppService.openSystemSettingsLoginItems() }
}
