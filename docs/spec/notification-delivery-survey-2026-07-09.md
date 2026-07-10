# Notification Delivery Survey (2026-07-09)

Status: SURVEY NOTE. Read-only research; no runtime code in this change.
Trackers: Linear TIN-2061, TIN-2719.

This note answers one narrow question before any notification code lands in
oauth-mux: does the operator already have a reusable notification primitive,
and if so, what shape should oauth-mux's own notify seam take to stay
consistent with `AGENTS.md`'s std-only, shell-out-for-platform-services rule.

## What exists today

The operator's GitHub account (`jesssullivan`) has one repo matching
`notif|notify|alert` in name or description:

- **`zig-notify`** — "Cross-platform notifications in Zig with C FFI — macOS
  osascript / Linux libnotify." Dual-licensed Zlib/MIT. Last pushed
  2026-04-29.

### What it does

`zig-notify` is a small, comptime-dispatched notification abstraction with a
4-function C FFI surface (`zig_notify_init`, `zig_notify_send`,
`zig_notify_request_permission`, `zig_notify_deinit`) plus a direct Zig API
(`notify.send(title, body, urgency) !void`, `notify.init(app_name) !void`,
`notify.deinit() void`).

Per-platform backends (read from `src/notify_macos.zig` and
`src/notify_linux.zig`):

- **macOS**: shells out to `osascript -e 'display notification "<body>" with
  title "<title>"'` via `std.process.Child`. No frameworks or system
  libraries linked; deliberately avoids `UNUserNotificationCenter` because
  that API requires an app-bundle identifier and doesn't work from bare CLI
  tools or daemons. Escapes `"` and `\` for the AppleScript string literal.
  Urgency is accepted but ignored (macOS `display notification` has no
  urgency concept). This backend is **pure `std`** — no C import, no linked
  library, just a subprocess call. It is architecturally identical to
  oauth-mux's own `security(1)` shell-out pattern (see below).

- **Linux**: calls into libnotify (`notify_init`, `notify_notification_new`,
  `notify_notification_set_urgency`, `notify_notification_show`) through a
  `@cImport("libnotify/notify.h")`. This is a genuine build-time dependency —
  it requires `libnotify-dev`/`libnotify-devel` headers, links
  `glib-2.0`/`gobject-2.0`, and needs a running notification daemon (dunst,
  mako, GNOME Shell, etc.) at runtime. This is **not** a subprocess shell-out;
  it's C FFI against a system library.

- Package installation is `zig fetch --save git+https://github.com/...` (Zig
  package manager) or a git submodule + static-lib link. Requires Zig
  0.15.2+.

### Verdict: reuse as pattern, not as a dependency

oauth-mux cannot add `zig-notify` as a `build.zig.zon` dependency:

1. **`AGENTS.md` hard rule**: "No external Zig dependencies. Everything from
   `std`." (`AGENTS.md` §Hard Rules). `zig-notify` is external, full stop —
   this rule alone rules out the package-manager and submodule installation
   paths regardless of any other factor.
2. **Zig version mismatch**: `zig-notify` targets Zig 0.15.2+; this repo
   builds on 0.14.1 (`nix develop --command zig ...`, per this repo's
   toolchain pin). Vendoring the actual source would require a porting pass
   before it would even compile here.
3. **The Linux backend is C FFI against a system library**, not a subprocess
   call. `AGENTS.md` says "Shell out for platform services (Keychain,
   secret-tool) rather than FFI" (`AGENTS.md` §Hard Rules) — the Linux half
   of `zig-notify` is exactly the pattern this repo has already rejected for
   secrets (see `src/secret.zig`, which shells out to `/usr/bin/security` on
   macOS and `secret-tool` on Linux rather than linking Keychain Services or
   libsecret).

What **is** worth reusing is the *shape* of the macOS backend: build a short
command string, spawn `osascript -e <script>` via `std.process.Child`, don't
link anything. That part is std-only already and needs no porting — only
transcription into oauth-mux's own subprocess helper.

For Linux, the honest std-only equivalent is not "vendor the libnotify FFI"
but "shell out to the `notify-send` CLI binary" (part of the same
libnotify package, but invoked as a subprocess rather than linked) — the
same shell-out-not-FFI move oauth-mux already makes for Linux secrets
(`secret-tool` instead of linking libsecret). This note does not commit to
that Linux shape; it is flagged as an open item below because no oauth-mux
notification code exists yet to make the call concrete.

## The repo's existing shell-out pattern to mirror

`src/secret.zig`'s `writeKeychain` (~:283) is the reference pattern any
notify seam should parallel exactly:

```zig
fn writeKeychain(ref: types.SecretBackend.KeychainRef, bytes: []const u8, allocator: std.mem.Allocator) WriteError!void {
    if (comptime builtin.os.tag != .macos) return error.UnsupportedBackend;

    const result = runProcess(allocator, &.{
        "/usr/bin/security",
        "add-generic-password",
        "-U", "-s", ref.service, "-a", ref.account, "-w", bytes,
    }) catch return error.IoError;
    defer allocator.free(result.stdout);
    defer if (result.stderr.len > 0) allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) {
            log.debug("keychain: add-generic-password exited {d}", .{code});
            return error.AccessDenied;
        },
        else => return error.IoError,
    }
}
```

Notable properties a notify seam should copy:

- `comptime builtin.os.tag` gate, returning a typed `error.UnsupportedBackend`
  on platforms with no implementation yet, rather than silently no-op'ing.
- The actual subprocess call goes through a single shared `runProcess`
  helper (`src/secret.zig` ~:456) that wraps `std.process.Child`, pipes
  stdout/stderr, and returns a `ProcessResult{ stdout, stderr, term }` — the
  notify seam should reuse this helper (or an equivalent) rather than
  hand-rolling `Child.spawn`/`wait` again.
- Absolute binary path (`/usr/bin/security`) where the binary is guaranteed
  to exist at a fixed location; `osascript` is the macOS analog
  (`/usr/bin/osascript`, also always present on macOS 13+).
- Failure is a typed error (`error.AccessDenied`, `error.IoError`), logged at
  `debug` with the exit code only — never the payload. A notify seam should
  follow the same discipline: log the exit code, never the notification body
  (which may echo account labels or class names).

## Recommended shape for oauth-mux

A `notify()` effect seam, e.g. `src/notify.zig`, exactly parallel to
`secret.zig`'s keychain write:

```zig
pub fn notify(allocator: std.mem.Allocator, title: []const u8, body: ?[]const u8) NotifyError!void {
    if (comptime builtin.os.tag != .macos) return error.UnsupportedPlatform; // Linux: open item, see below

    var buf: [2048]u8 = undefined; // AppleScript command buffer, same bound as zig-notify
    const script = try buildAppleScript(&buf, title, body); // escape `"` and `\`

    const result = runProcess(allocator, &.{ "/usr/bin/osascript", "-e", script }) catch return error.IoError;
    defer allocator.free(result.stdout);
    defer if (result.stderr.len > 0) allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) return error.NotifyFailed,
        else => return error.IoError,
    }
}
```

Firing points (illustrative, not yet wired): the keepalive tick, when the
`advise.zig` advisor (`src/quota/advise.zig`, TIN-2719 M0 PR1, merged in
#449) flips a `ClassSummary.status` from `.available` to `.waiting` /
`.plan_gated` for a class the operator has declared demand for, or when a
credential repair attempt (`repair-plan` / `stay-afloat refresh`) fails.
Both firing points already exist as typed transitions in the codebase today
(`bucket.EffectiveStatus`, repair-plan exit codes) — this note only proposes
the delivery seam, not the wiring, which is out of scope for this docs-only
change.

## What this does NOT cover

TIN-2061's full scope is a general alerting channel, not just "one
`osascript` call." Explicitly out of scope for this survey and left as open
items for the implementation ticket:

- **Escalation.** A single missed notification (e.g. operator's machine
  asleep, terminal not focused) has no retry or secondary channel today.
- **Dedupe / rate limiting.** Nothing here prevents firing one notification
  per keepalive tick while a class sits in `.waiting` — needs a
  last-notified-at guard, likely keyed off the same route key
  (`provider:account#capability`) the health store already uses.
- **Quiet hours / do-not-disturb.** No operator-configurable window during
  which notifications are suppressed.
- **Linux delivery mechanism.** Whether Linux goes through `notify-send`
  (subprocess, matches the repo's shell-out convention) or is deferred
  entirely until an operator actually runs oauth-mux headless-with-a-desktop
  on Linux. No Linux notification code exists in this repo yet.
- **Windows.** Not evaluated. oauth-mux ships Windows binaries
  (`AGENTS.md` §Distribution) but neither `zig-notify` nor this survey
  considers a Windows notification backend (`toast`/`BurntToast`-equivalent).
- **Notification content policy.** What is safe to put in a title/body given
  the "never log token payloads" discipline elsewhere in the repo — e.g.
  should the body ever include an account label, or only a route key hash.
- **User opt-out.** No config flag proposed here to disable notifications
  entirely.

None of the above blocks landing the seam itself; they are the reasons this
stays a survey note rather than a committed implementation plan.
