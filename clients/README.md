# Native Omux controls

The macOS menu-bar app uses SwiftUI and the Linux tray/settings app uses Qt6.
Both are clients of the per-user daemon's versioned local control API. They
manage sources, account lifecycle, enrollment/repair actions and native
integrations, and display active bindings and retained observation totals.
Credential material is absent from snapshots and status views. The negotiated
daemon-owned SIWC enrollment flow delivers one private authorization URL once,
directly to the default browser; it is never displayed or written to CLI output.

Linux Accounts → Add account is the primary first-account journey when the
daemon advertises the typed experimental SIWC descriptor. Native consent gives
the flow one finite duration (1–3600 seconds). The daemon owns registration,
loopback callback, provider identity verification, encrypted paired commit and
renewal. This is separate API Responses authority, not native Codex sign-in or
application continuity. The open panel automatically reads redacted transaction
status within the original bound, stopping at terminal outcomes or closure.
Status refresh and reconnect never extend consent or repeat authorization.
Closing the controls leaves a valid flow with the daemon; pending opaque handles
can be inspected when controls reopen. Paired enrollment and current request
grant usability remain distinct. Vault-unavailable status is Unknown; unlock the
normal OS vault, then explicitly Resume after vault unlock. No key is regenerated,
no plaintext fallback is introduced, and the OS determines any required factor.

The shared CLI exposes the same operations without credential JSON:
`omux sign-in providers`, `omux sign-in start --consent-seconds 600 --confirm`,
`omux sign-in pending`, `omux sign-in status <opaque-transaction-id>`, and
`omux sign-in cancel <opaque-transaction-id>` (or `remove`). Browser delivery uses
a private stdin pipe to the packaged Linux Qt control and its closed URL/profile
policy; the URL is absent from CLI/helper process arguments and CLI stdout/stderr.
The approved OS/browser handler receives the authorization URL. Raw RPC
authorization output is refused. An unknown mutation retains its printed opaque
operation; `omux operation status <opaque-operation-id>` reads that original
outcome. No operation, authorization delivery or provider issue is replayed.
Cancellation/removal targets only that enrollment/source's local consent and
paired grants; issued work may have occurred and provider revocation is not
claimed. New enrollment needs fresh explicit consent. CLI browser dispatch is
Linux-only in this source proposal; Darwin UI/support remains unproved.

Experimental native-profile acquisition and credential-JSON import remain
separate external-source operations with their existing external renewal owner.
They are not the default first-account sign-in and do not transfer renewal
authority by copying native authentication files. All new source paths and
declared fixtures require separate compiler, installed UI and live enrollment
qualification; source and synthetic success do not prove provider/native support.

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
observations separately from daemon-computed retained totals. Totals describe
observed capacity rather than request eligibility; only matching units, scopes
and windows combine, and shared buckets count once. Codex percentages and provider
permission flags retain their custom units; unspecified shared buckets do not yield additive
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

The existing-source Enrollment/Reconcile actions reconcile a connected
authorized source through the daemon; those actions do not start provider
sign-in. The separate Linux Add account journey above starts owned SIWC sign-in. Reconcile can recheck a detached
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
