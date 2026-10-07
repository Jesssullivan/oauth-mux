import AppKit
import SwiftUI

@main
@MainActor
struct OmuxApp: App {
    @StateObject private var store = DaemonStore()
    var body: some Scene {
        MenuBarExtra("Omux", systemImage: store.connected ? "arrow.triangle.branch" : "exclamationmark.circle") {
            MenuControls(store: store)
        }
        Window("Omux account and route controls", id: "omux-controls") {
            ControlWindow(store: store)
        }
        .defaultSize(width: 930, height: 560)
    }
}

@MainActor
private struct MenuControls: View {
    @ObservedObject var store: DaemonStore
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Text(store.connected ? "Omux connected" : "Omux service unavailable")
        ForEach(store.rows("accounts").prefix(8)) { account in
            Menu(account.text("label")) {
                Text(account.text("lifecycle"))
                Button("Repair account") {
                    store.action("repair.start", params: ["account_id": .string(account.id)])
                }.disabled(!store.canMutate)
            }
        }
        Divider()
        Button("Accounts and routes…") {
            openWindow(id: "omux-controls")
            NSApplication.shared.activate(ignoringOtherApps: true)
        }
        Button("Refresh") { Task { await store.refresh() } }
        Toggle("Keep alternatives ready", isOn: Binding(
            get: { store.warmAlternatives }, set: { store.setWarmAlternatives($0) }))
            .disabled(!store.canMutate)
        Divider()
        Button("Quit controls") { NSApplication.shared.terminate(nil) }
    }
}
