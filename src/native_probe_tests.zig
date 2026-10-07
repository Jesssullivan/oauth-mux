test {
    _ = @import("integrations/native_probe.zig");
}

// R-N13: WebSocket remains inspection only. The owner protocol's actual
// packet transport and exact acknowledgement predicates have a separate gate.
test "legacy WebSocket custody refuses before path or deadline I/O" {
    const std = @import("std");
    const probe = @import("integrations/native_probe.zig");
    const expired = std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromMilliseconds(-1) });
    try std.testing.expectError(error.NativeOwnerProtocolRequired, probe.attachWithDeadline(std.testing.io, std.testing.allocator, "/tmp/../unread-socket", "fixture", "thread", "binding", .{ .broker_socket = "/tmp/fixture/adapter.sock", .capability_path = "/tmp/fixture/capability" }, expired));
    try std.testing.expectError(error.NativeOwnerProtocolRequired, probe.detachWithDeadline(std.testing.io, std.testing.allocator, "/tmp/../unread-socket", "fixture", "thread", expired));
}
