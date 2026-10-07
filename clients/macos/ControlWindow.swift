import Foundation
import SwiftUI

@MainActor
struct ControlWindow: View {
    @ObservedObject var store: DaemonStore
    @State private var account: String?
    @State private var source: String?
    @State private var operation: String?
    @State private var integration: String?
    @State private var nativeThread: String?
    @State private var sourceSheet = false
    @State private var integrationSheet = false
    @State private var forgetConfirmation = false
    @State private var disconnectConfirmation = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label(store.connectionMessage, systemImage: store.connected ? "checkmark.circle" : "exclamationmark.circle")
                    .foregroundStyle(store.connected ? .secondary : .primary)
                Spacer()
                Button("Reconnect") { Task { await store.refresh() } }
                    .disabled(store.refreshing)
            }
            if !store.connected {
                Text("Displayed account data may be stale until the service reconnects.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if store.connected && !store.custodyAvailable {
                Text("Credential custody is unavailable. Account data may be stale; account and routing changes are disabled until custody is restored.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Unlock or restore the existing Keychain key. If the key is permanently lost, preserve this installation and arrange explicit fresh enrollment into separate custody. Fresh-custody recovery is not implemented in these controls; never replace the key over the existing database.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if !store.message.isEmpty {
                Text(store.message).font(.callout).textSelection(.enabled)
            }
            TabView {
                onboardingTab.tabItem { Text("Setup") }
                accountTab.tabItem { Text("Accounts") }
                sourceTab.tabItem { Text("Sources") }
                grantTab.tabItem { Text("Grants") }
                capacityTab.tabItem { Text("Capacity") }
                bindingTab.tabItem { Text("Active routes") }
                leaseTab.tabItem { Text("Leases") }
                operationsTab.tabItem { Text("Actions") }
                integrationTab.tabItem { Text("Integrations") }
                serviceTab.tabItem { Text("Service") }
            }
            HStack {
                Toggle("Keep alternatives ready", isOn: Binding(
                    get: { store.warmAlternatives }, set: { store.setWarmAlternatives($0) }))
                    .disabled(!store.canMutate)
                Spacer()
                Text("Routes stay sticky. All compatible accounts are eligible.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .sheet(isPresented: $sourceSheet) { SourceSheet(store: store) }
        .sheet(isPresented: $integrationSheet) {
            IntegrationPathSheet(defaultPath: store.integrationPath) { adapter, path in
                store.action("integrations.install", params: ["adapter": .string(adapter), "config_path": .string(path)])
            }
        }
        .confirmationDialog("Forget this account and remove its retained grants?", isPresented: $forgetConfirmation) {
            Button("Forget account", role: .destructive) { accountAction("account.forget") }
        } message: {
            Text("Removes this account's retained secrets and leaves a re-enrollment tombstone. Automatic discovery will not enroll it again. Native conversation history remains with the application. This does not revoke authorization upstream.")
        }
        .confirmationDialog("Disconnect the selected source context?", isPresented: $disconnectConfirmation) {
            Button("Disconnect source", role: .destructive) { sourceAction("source.disconnect") }
        } message: {
            Text("Ends acquisition authority for this source and removes secrets retained through it. Independent grants and native conversation history retain their own authority. Browser disappearance alone uses detachment semantics.")
        }
    }

    private var onboardingTab: some View {
        Form {
            Text("Selected instance: \(RuntimePaths.isDevelopment ? "Development" : "Release")")
            Text("Install and activate → connect Chromium → verify identity and usable authority → maintain renewal → integrate ordinary applications → prove same-process handoff.")
            Text(store.readinessMessage)
            Button("Verify setup") { store.verifySetup() }.disabled(!store.canVerifySetup)
            if let operationID = store.verificationOperationID {
                Text("Verification operation: \(operationID)").textSelection(.enabled)
            }
            Text("Verification checks local setup facts. It does not install, activate, enroll accounts or prove native handoff. Refresh reads existing observations without starting verification.")
                .foregroundStyle(.secondary)
            ForEach(store.readiness) { row in
                Text("\(row.text("phase").replacingOccurrences(of: "_", with: " ")): \(row.text("reason").replacingOccurrences(of: "_", with: " ")) · \(row.text("action").replacingOccurrences(of: "_", with: " "))")
            }
            Text("Service: \(store.connectionMessage)")
            Text("Custody: \(store.custodyAvailable && store.connected ? "Available" : "Unavailable or unverified")")
            Text("Sources: \(store.connected ? String(store.rows("sources").count) : "Unverified")")
            Text("These counts do not establish usable grants, renewal ownership or native continuity. Inspect Sources, Grants and Integrations for separate evidence.")
                .foregroundStyle(.secondary)
            Text("Chromium enrollment starts in the extension after native host registration. Browser read consent does not authorize application calls. Omux owns each application adapter; Codex candidates are experimental and unmodified Codex continuity is unproved.")
                .foregroundStyle(.secondary)
        }.padding(20)
    }

    private var accountTab: some View {
        VStack {
            Table(store.rows("accounts"), selection: $account) {
                TableColumn("Account") { Text($0.text("label")) }
                TableColumn("Provider") { Text($0.text("identity.provider")) }
                TableColumn("Type") { Text($0.text("account_type")) }
                TableColumn("Lifecycle") { Text($0.text("lifecycle")) }
            }
            HStack {
                Button("Repair") { accountAction("repair.start") }.disabled(account == nil)
                Button("Pause") { accountAction("account.pause") }.disabled(account == nil)
                Button("Resume") { accountAction("account.resume") }.disabled(account == nil)
                Button("Drain") { accountAction("account.drain") }.disabled(account == nil)
                Button("Forget…") { forgetConfirmation = true }.disabled(account == nil)
                Spacer()
            }.disabled(!store.canMutate)
        }.padding(10)
    }

    private var sourceTab: some View {
        VStack {
            Table(store.rows("sources"), selection: $source) {
                TableColumn("Source") { Text($0.text("label")) }
                TableColumn("Provider") { Text($0.text("provider")) }
                TableColumn("Kind") { Text($0.text("kind")) }
                TableColumn("State") { Text($0.text("status")) }
            }
            Text(sourceReconcileNotice).font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("Connect source…") { sourceSheet = true }
                Button("Enroll from source") { enrollFromSource() }.disabled(!canEnrollFromSource)
                Button("Reconcile") { sourceAction("source.reconcile") }.disabled(!canReconcileSource)
                Button("Disconnect…") { disconnectConfirmation = true }
                    .disabled(selectedSource == nil || selectedSource?.value["status"].string == "disconnected")
                Spacer()
            }.disabled(!store.canMutate)
        }.padding(10)
    }

    private var capacityTab: some View {
        VStack(alignment: .leading) {
            Table(store.capacities) {
                TableColumn("Provider") { Text($0.text("provider")) }
                TableColumn("Resource") { Text($0.text("resource.target")) }
                TableColumn("Scope") { Text($0.text("resource.scope")) }
                TableColumn("Remaining") { Text($0.text("remaining")) }
                TableColumn("Unit") { Text($0.text("resource.unit")) }
                TableColumn("Window") { Text($0.text("window")) }
                TableColumn("Freshness") { Text(store.connected && store.custodyAvailable ? $0.text("freshness") : "Stale: service or custody unavailable") }
            }
            Text("Totals include compatible units, scopes and windows only. Unknown or stale values are shown explicitly.")
                .font(.caption).foregroundStyle(.secondary)
        }.padding(10)
    }

    private var grantTab: some View {
        VStack(alignment: .leading) {
            Table(store.rows("grants")) {
                TableColumn("Account") { Text(store.accountLabel($0.text("account_id"))) }
                TableColumn("Credential type") { Text($0.text("credential_kind")) }
                TableColumn("Renewal owner") { Text($0.text("ownership")) }
                TableColumn("Purposes") { Text($0.text("purposes")) }
                TableColumn("Provider validity") { Text($0.text("provider_expires_at")) }
                TableColumn("Custody validity") { Text($0.text("custody_expires_at")) }
            }
            Text("Authorization metadata only. Provider validity and custody authorization are independent.")
                .font(.caption).foregroundStyle(.secondary)
        }.padding(10)
    }

    private var leaseTab: some View {
        VStack(alignment: .leading) {
            Table(store.rows("leases")) {
                TableColumn("Route") { Text($0.text("binding_id")) }
                TableColumn("Account") { Text(store.accountLabel($0.text("account_id"))) }
                TableColumn("Purpose") { Text($0.text("purpose")) }
                TableColumn("Started") { Text($0.text("started_at")) }
                TableColumn("Expires") { Text($0.text("expires_at")) }
            }
            Text("Leases authorize bounded use; they do not extend provider credentials.")
                .font(.caption).foregroundStyle(.secondary)
        }.padding(10)
    }

    private var bindingTab: some View {
        VStack(alignment: .leading) {
            Table(store.rows("bindings")) {
                TableColumn("Application") { Text($0.text("application")) }
                TableColumn("Session") { Text($0.text("session_id")) }
                TableColumn("Account") { Text(store.accountLabel($0.text("account_id"))) }
                TableColumn("In flight") { Text($0.text("in_flight")) }
            }
            Text("Native application history stays with the application.")
                .font(.caption).foregroundStyle(.secondary)
        }.padding(10)
    }

    private var operationsTab: some View {
        VStack {
            Table(store.rows("jobs"), selection: $operation) {
                TableColumn("Action") { Text($0.text("kind")) }
                TableColumn("Status") { Text($0.text("status")) }
                TableColumn("Account") { Text(store.accountLabel($0.text("account_id"))) }
            }
            HStack {
                Button("Cancel action") {
                    if let operation { store.action("operation.cancel", params: ["target_operation_id": .string(operation)]) }
                }.disabled(operation == nil || !store.canMutate)
                Spacer()
            }
        }.padding(10)
    }

    private var integrationTab: some View {
        VStack {
            if !store.integrationMessage.isEmpty {
                Text(store.integrationMessage).font(.caption).foregroundStyle(.secondary)
            }
            Table(store.integrations, selection: $integration) {
                TableColumn("Application") { Text($0.text("adapter")) }
                TableColumn("Installed") { Text($0.text("installed")) }
                TableColumn("Capability") { Text($0.text("capability")).help($0.text("limitation")) }
                TableColumn("Version") { Text($0.text("version")) }
            }
            Text(store.nativeDiscoveryMessage).font(.caption).foregroundStyle(.secondary)
            Table(store.nativeThreads, selection: $nativeThread) {
                TableColumn("Native thread") { Text($0.text("thread_id")) }
                TableColumn("Process") { Text($0.text("owner_id")) }
                TableColumn("Version") { Text($0.text("version")) }
                TableColumn("Hook compatibility") { Text($0.text("support")) }
            }
            HStack {
                Button("Discover Codex") { store.discoverNative() }
                Button("Attach selected thread") {
                    if let nativeThread { store.nativeAction("integrations.attach", threadID: nativeThread) }
                }.disabled(!store.canActOnNative(nativeThread))
                Button("Detach selected thread") {
                    if let nativeThread { store.nativeAction("integrations.detach", threadID: nativeThread) }
                }.disabled(!store.canActOnNative(nativeThread, detaching: true))
                Button("Install integration…") { integrationSheet = true }.disabled(!store.canMutate)
                Button("Remove integration") {
                    guard let row = store.integrations.first(where: { $0.id == integration }),
                          let adapter = row.value["adapter"].string else { return }
                    let path = row.value["config_path"].string ?? store.integrationPath(adapter)
                    store.action("integrations.remove", params: ["adapter": .string(adapter), "config_path": .string(path)])
                }.disabled(integration == nil || !store.canMutate)
                Spacer()
            }.disabled(!store.connected)
        }.padding(10)
    }

    private var serviceTab: some View {
        Form {
            Text("User service: \(store.serviceStatus)")
            Toggle("Run the Omux service at login", isOn: Binding(
                get: { store.serviceRegistered }, set: { store.setServiceEnabled($0) }))
                .disabled(store.serviceExternallyManaged)
            Text(store.serviceGuidance).foregroundStyle(.secondary)
            Button("Open Login Items settings") { store.openServiceSettings() }
            Text("The user service runs independently of these controls. Closing this window or quitting controls keeps the service running.")
                .foregroundStyle(.secondary)
        }.padding(20)
    }

    private func accountAction(_ method: String) {
        if let account { store.action(method, params: ["account_id": .string(account)]) }
    }
    private func sourceAction(_ method: String) {
        guard let selectedSource, method != "source.reconcile" || canReconcileSource else { return }
        store.action(method, params: ["source_id": .string(selectedSource.id)])
    }
    private var selectedSource: StateRow? {
        store.rows("sources").first { $0.id == source && $0.value["id"].string == source }
    }
    private var canReconcileSource: Bool {
        guard let row = selectedSource, let status = row.value["status"].string,
              ["connected", "detached"].contains(status),
              let kind = row.value["kind"].string, let provider = row.value["provider"].string else { return false }
        return ["native_store", "explicit"].contains(kind) && ["codex", "github"].contains(provider)
    }
    private var canEnrollFromSource: Bool {
        canReconcileSource && selectedSource?.value["status"].string == "connected"
    }
    private var sourceReconcileNotice: String {
        guard let row = selectedSource else {
            return "Select a source. Enrollment requires a connected source; Reconcile can recheck a detached source."
        }
        if row.value["status"].string == "disconnected" {
            return "This source is disconnected. Its acquisition authorization has ended."
        }
        guard let status = row.value["status"].string, ["connected", "detached"].contains(status) else {
            return "This source's state is unavailable. Refresh before requesting reconciliation."
        }
        guard let kind = row.value["kind"].string, ["native_store", "explicit"].contains(kind) else {
            return "Browser and OAuth source acquisition are unavailable. This source cannot enroll accounts here."
        }
        guard canReconcileSource else {
            return "This source's provider requires an acquisition adapter before accounts can be enrolled."
        }
        if status == "detached" {
            return "This source is detached. Reconcile rechecks its authorized file and may reconnect it when available. Enrollment requires a connected source. The daemon validates acquisition authorization."
        }
        return "Enroll from source requests identity verification for \(row.text("provider")) using this connected source. Reconcile refreshes the same source; neither opens a provider sign-in flow. The daemon validates acquisition authorization."
    }
    private func enrollFromSource() {
        guard store.canMutate, canEnrollFromSource, let row = selectedSource,
              let provider = row.value["provider"].string else { return }
        store.action("enrollment.start", params: ["source_id": .string(row.id), "provider": .string(provider)])
    }
}

@MainActor
private struct SourceSheet: View {
    @ObservedObject var store: DaemonStore
    @Environment(\.dismiss) private var dismiss
    @State private var kind = "native_store"
    @State private var provider = "codex"
    @State private var label = ""
    @State private var sourcePath = ""
    private var trimmedSourcePath: String { sourcePath.trimmingCharacters(in: .whitespacesAndNewlines) }
    private var sourcePathValid: Bool {
        let path = trimmedSourcePath
        if path.isEmpty { return provider == "codex" }
        guard path.hasPrefix("/"), path.count > 1, !path.contains("\0") else { return false }
        return path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
            .allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
    }
    var body: some View {
        Form {
            Text("Connect an account source").font(.headline)
            Picker("Source type", selection: $kind) {
                Text("Native application store").tag("native_store")
            }
            Picker("Provider", selection: $provider) {
                Text("Codex").tag("codex"); Text("GitHub").tag("github")
            }
            TextField("Name", text: $label)
            TextField("Native source file (absolute path)", text: $sourcePath)
            Text("Connect authorizes an existing native source; it does not sign in or verify an account. Browser and OAuth source acquisition are unavailable. Account enrollment requires source reconciliation and identity verification.")
                .font(.caption).foregroundStyle(.secondary)
            Text("GitHub requires an explicit source file. Leaving the Codex path blank authorizes the daemon's native Codex source. The controls do not read or search source files.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("Cancel") { dismiss() }
                Spacer()
                Button("Connect") {
                    let name = label.trimmingCharacters(in: .whitespacesAndNewlines)
                    var params: [String: JSONValue] = ["kind": .string(kind), "provider": .string(provider),
                        "label": .string(name.isEmpty ? "\(provider) \(kind)" : name)]
                    if !trimmedSourcePath.isEmpty { params["source_path"] = .string(trimmedSourcePath) }
                    store.action("source.connect", params: params)
                    dismiss()
                }.keyboardShortcut(.defaultAction).disabled(!store.canMutate || !sourcePathValid)
            }
        }.padding(20).frame(width: 430)
    }
}

@MainActor
private struct IntegrationPathSheet: View {
    let defaultPath: @MainActor (String) -> String
    let submit: @MainActor (String, String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var path = ""
    @State private var adapter = "codex"
    var body: some View {
        Form {
            Text("Install a native integration").font(.headline)
            Picker("Application", selection: $adapter) {
                Text("Codex").tag("codex"); Text("Claude").tag("claude"); Text("Git HTTPS").tag("git")
            }.onChange(of: adapter) { value in path = defaultPath(value) }
            TextField("Configuration file", text: $path)
            Text("Omux preserves the native configuration and restores only changes it owns.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("Cancel") { dismiss() }
                Spacer()
                Button("Install") { submit(adapter, path); dismiss() }
                    .keyboardShortcut(.defaultAction).disabled(!path.hasPrefix("/"))
            }
        }.padding(20).frame(width: 500).onAppear { path = defaultPath(adapter) }
    }
}
