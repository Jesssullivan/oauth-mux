//! CLI wiring for the unshipped managed Claude launch verb (`omux claude`).
//!
//! This module is the fail-closed boundary between the CLI and the internal
//! managed-child launcher in `main.zig`. While production forwarding is
//! compile-disabled (`wire_proxy.production_forwarding_enabled == false`) the
//! verb aborts during preflight before any child spawn: no launcher is invoked,
//! no child is launched, and no credential is read. The forwarding composition
//! is present and type-checked on every build so that flipping the compile flag
//! reaches `managed_child.run` with a bound authenticated sidecar — it is gated
//! behind a comptime check, never a runtime flag.

const std = @import("std");
const config_mod = @import("../../config.zig");
const managed_child = @import("main.zig");
const wire_proxy = @import("wire_proxy.zig");

/// Operator-facing refusal for the compile-disabled managed launch. The wording
/// tracks the v0.2 evaluation ladder vocabulary ("experimental", "unshipped")
/// and states plainly that no child ran and no credential was read.
pub const unshipped_refusal =
    "omux claude: the managed Claude launch is experimental and unshipped " ++
    "(v0.2 evaluation ladder); production forwarding is compile-disabled, so " ++
    "no child was launched and no credential was read.\n";

pub const RunError = error{
    /// Preflight refused because production forwarding is compile-disabled.
    ManagedLaunchUnshipped,
    /// The fail-closed refusal could not be delivered to the caller.
    RefusalWriteFailed,
} || managed_child.RunError;

/// One managed-launch request. Owns nothing; every referenced slice, env map,
/// and config must outlive the call.
pub const Request = struct {
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    cwd: ?[]const u8 = null,
    inherited_env: *const std.process.EnvMap,
    active_config: *const config_mod.Config,
    event_writer: std.io.AnyWriter = std.io.null_writer.any(),
};

/// Fail-closed managed-launch entry. While forwarding is compile-disabled this
/// writes `unshipped_refusal` to `message_writer` and returns the typed error
/// before any launcher invocation. When forwarding is later enabled the same
/// path composes RunOptions and hands the bound authenticated sidecar to the
/// internal managed-child launcher (`composeAndLaunch`).
pub fn run(
    request: Request,
    message_writer: std.io.AnyWriter,
) RunError!std.process.Child.Term {
    return runWithLauncher(request, message_writer, DefaultLauncher{});
}

/// Refuse a compile-disabled managed launch before the caller loads inherited
/// environment, configuration, argv, or any other launch authority.
pub fn requireAvailable(message_writer: std.io.AnyWriter) RunError!void {
    if (comptime wire_proxy.production_forwarding_enabled) return;
    message_writer.writeAll(unshipped_refusal) catch return error.RefusalWriteFailed;
    return error.ManagedLaunchUnshipped;
}

/// The forwarding composition: build RunOptions from the request and launch the
/// managed child. Unreachable while `production_forwarding_enabled` is false;
/// kept `pub` so the test graph type-checks it on every build even though the
/// comptime gate in `runWithLauncher` elides the call site today.
pub fn composeAndLaunch(request: Request) managed_child.RunError!std.process.Child.Term {
    return managed_child.run(.{
        .allocator = request.allocator,
        .argv = request.argv,
        .cwd = request.cwd,
        .inherited_env = request.inherited_env,
        .active_config = request.active_config,
        .event_writer = request.event_writer,
    });
}

const DefaultLauncher = struct {
    fn launch(_: DefaultLauncher, request: Request) managed_child.RunError!std.process.Child.Term {
        return composeAndLaunch(request);
    }
};

/// Seam-injectable core. The launcher is invoked only once forwarding is
/// compile-enabled; the comptime gate keeps the launcher call out of the
/// generated code today, so a compile-disabled build cannot spawn a child.
/// Program §2.1: any preflight failure aborts before child launch and unmanaged
/// fallback is never silent.
fn runWithLauncher(
    request: Request,
    message_writer: std.io.AnyWriter,
    launcher: anytype,
) RunError!std.process.Child.Term {
    try requireAvailable(message_writer);
    return launcher.launch(request);
}

const CountingLauncher = struct {
    launches: *usize,

    fn launch(self: CountingLauncher, _: Request) RunError!std.process.Child.Term {
        self.launches.* += 1;
        return .{ .Exited = 0 };
    }
};

fn testRequest(env: *const std.process.EnvMap, active_config: *const config_mod.Config) Request {
    return .{
        .allocator = std.testing.allocator,
        .argv = &.{ "synthetic-claude", "--print", "hello" },
        .inherited_env = env,
        .active_config = active_config,
    };
}

test "fail-closed verb refuses, returns the typed error, and never launches" {
    const allocator = std.testing.allocator;
    var env = std.process.EnvMap.init(allocator);
    defer env.deinit();
    var active_config = config_mod.Config{};

    var message = std.ArrayList(u8).init(allocator);
    defer message.deinit();

    var launches: usize = 0;
    try std.testing.expectError(error.ManagedLaunchUnshipped, runWithLauncher(
        testRequest(&env, &active_config),
        message.writer().any(),
        CountingLauncher{ .launches = &launches },
    ));

    // Same zero-spawn technique as the managed-child tests: the launcher seam
    // is never invoked while forwarding is compile-disabled.
    try std.testing.expectEqual(@as(usize, 0), launches);
    try std.testing.expect(std.mem.indexOf(u8, message.items, "experimental") != null);
    try std.testing.expect(std.mem.indexOf(u8, message.items, "unshipped") != null);
    try std.testing.expect(std.mem.indexOf(u8, message.items, "no child was launched") != null);
    try std.testing.expect(std.mem.indexOf(u8, message.items, "no credential was read") != null);
}

test "public run entry stays fail-closed while forwarding is compile-disabled" {
    // Guards the compile flag itself: as long as production forwarding is off,
    // the default entry must refuse without touching any launch machinery.
    try std.testing.expect(!wire_proxy.production_forwarding_enabled);

    const allocator = std.testing.allocator;
    var env = std.process.EnvMap.init(allocator);
    defer env.deinit();
    var active_config = config_mod.Config{};

    var message = std.ArrayList(u8).init(allocator);
    defer message.deinit();

    try std.testing.expectError(error.ManagedLaunchUnshipped, run(
        testRequest(&env, &active_config),
        message.writer().any(),
    ));
    try std.testing.expectEqualStrings(unshipped_refusal, message.items);
}

test "fail-closed verb reports refusal delivery failure" {
    var storage: [0]u8 = .{};
    var message = std.io.fixedBufferStream(&storage);

    try std.testing.expectError(
        error.RefusalWriteFailed,
        requireAvailable(message.writer().any()),
    );
}
