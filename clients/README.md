# Native Omux controls

The macOS menu-bar app uses SwiftUI and the Linux tray/settings app uses Qt6.
Both are clients of the per-user daemon's versioned local control API. They
manage sources, account lifecycle, enrollment/repair actions and native
integrations, and display active bindings and compatible capacity totals.
Credential material is absent from the control protocol and UI.

The Linux Setup view's explicit "Resume after vault unlock" action uses the
advertised `custody.reopen` capability. Unlock the normal platform vault first;
the action retries custody initialization in the same daemon, without source
enrollment, provider requests or a service restart. Older installed services
without that capability report the required update. Startup-locked health is
cached daemon state, not a fresh platform-lock observation. Its unloaded account
count is null; a loaded count comes from the authenticated retained snapshot.
This source boundary requires separately qualified package and installed proof;
it supplies no native application continuity or Darwin unlock proof.

The Integrations view asks the daemon to discover native owner endpoints in its
selected Codex home; the controls do not scan sockets or select the legacy
WebSocket path. Each loaded thread retains its process identity, endpoint and
exact generation descriptors. Two processes loading the same thread remain
separate rows. Attach supplies that selected owner tuple for fresh daemon
verification; detach additionally requires a committed attachment reference
returned by the daemon. Diagnostic attachment generations never grant custody.
Reported hook compatibility is experimental metadata, not live support.
Unsupported hooks and unsafe active contexts retain their explicit failure.
Custody-unavailable snapshots remain inspectable while
account and routing mutations are disabled and capacity is marked stale.

The clients verify the socket peer's user ID, enforce a 1 MiB frame limit,
negotiate control protocol version 2, and refresh redacted state every three seconds.
Mutations carry a stable operation ID and expected revision. A lost reply or
daemon-declared mutation failure retains that identity before the original error
callback and queries its outcome. A valid completed result releases the hold;
an authoritative `UnknownOperation` confirms preflight refusal or local rollback.
Started, indeterminate, malformed and unavailable outcomes keep new mutations
blocked while metadata reads and outcome queries remain available. The original
error remains visible during reconciliation. Clients never automatically replay
the action or submit a new mutation identity. Poisoned custody refuses uncertain
outcome queries.

This reconciliation is scoped to the same daemon installation, whose durable
operation IDs are never retired. Socket peer checks establish the local user;
they do not prove installation identity after installation replacement or a full
user-state rollback. Those cases are outside this client evidence boundary.

The one-shot CLI preserves its normal stdout JSON and emits a separate redacted
stderr JSON guide with the original operation ID after a declared or malformed
mutation reply. The guide names `operation.status` and its same-ID parameters;
it does not issue that query or replay the action. A later CLI process can query
that identity, but the CLI cannot gate independent future invocations. Explicit
caller-provided operation IDs remain unchanged.
Disconnection marks displayed data as potentially stale.
Unknown observations remain unknown. The clients display per-account
observations separately from daemon-computed compatible totals, without summing
incompatible units or windows. Codex percentages and provider permission flags
retain their custom units; unspecified shared buckets do not yield additive
quota or establish exact-model readiness.

The Linux app falls back to a normal settings window when the desktop has no
system tray. Closing a tray-enabled window hides it; quitting either client
leaves the independently running daemon alone. `OMUX_SOCKET` selects an
explicit private control socket for testing; the Linux app also has `--socket`.
Linux defaults match the daemon's validated private `XDG_RUNTIME_DIR` and
installation-specific child. An absent variable selects `state/run`; unsafe or
empty supplied runtime paths fail closed. macOS uses its private Library state.

`omux.service` is an opt-in systemd user unit. Packaging places the daemon in a
standard executable path before installing the unit. Linux service controls use
the fixed `/usr/bin/systemctl` host platform boundary with fixed user-unit
arguments; they never search `PATH`. Host font and XKB data are read-only desktop
resources. Packaged plugin paths replace compiled Qt defaults. The macOS app bundle
places `ai.xoxd.omux.daemon.plist` in `Contents/Library/LaunchAgents` and the daemon
in `Contents/MacOS/omux`. The Service tab registers that helper through
`SMAppService`; registration is never performed merely by launching the app.

Enrollment reconciles an existing connected authorized source through the
daemon; it does not start provider sign-in. Reconcile can recheck a detached
authorized source. Pending verification and `needs_user` remain unfinished.
These clients do not collect passwords, security-key responses, OTPs, browser
storage or tokens. Unsupported acquisition and repair report the daemon's reason.

Current installed native interoperability evidence proves the configured
candidate app-server's registration and zero-acquire removal with initialized
zero-turn history preserved. It does not prove ordinary CLI/TUI launch, native
resume, accepted history or live handoff. `native_support` remains false; stock
Codex and production Darwin client/runtime behavior remain unproved. The new
automatic-discovery control path needs its own current-source gate.

Build and test targets are provided by the repository's Bazel graph inside the
locked Nix development environment. macOS compilation and service approval
checks require a macOS execution platform with its authorized Apple SDK; Linux
validation does not establish a successful macOS build.

`nix develop --command bazelisk run //clients/linux:control -- --self-check` constructs the real
controls offscreen, processes a local event cycle, prints
`OMUX_CONTROL_SELF_CHECK_OK`, and exits. It suppresses daemon connections,
provider/vault work and service-manager queries. This proves widget/plugin
startup; installed X11/Wayland desktop interaction requires a separate gate.
