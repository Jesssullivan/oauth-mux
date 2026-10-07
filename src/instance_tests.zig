//! Focused launch-selection predicates; these are not installed coexistence proof.
const std = @import("std");
const builtin = @import("builtin");
const instance = @import("instance.zig");
const paths = @import("paths.zig");

test "instance selection defaults only when absent and rejects malformed choices" {
    try std.testing.expectEqual(instance.Selection.default, try instance.Selection.parse(null));
    try std.testing.expectEqual(instance.Selection.default, try instance.Selection.parse("default"));
    try std.testing.expectEqual(instance.Selection.dev, try instance.Selection.parse("dev"));
    for ([_][]const u8{ "", "release", "DEV", " dev", "dev/other" }) |value| {
        try std.testing.expectError(error.InvalidInstance, instance.Selection.parse(value));
    }
    try std.testing.expect(!std.mem.eql(u8, instance.Selection.default.vaultRoot(), instance.Selection.dev.vaultRoot()));
}

test "instance defaults isolate state and sockets while preserving legacy default" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env = std.process.Environ.Map.init(a);
    defer env.deinit();
    try env.put("HOME", "/fixture-home");
    try env.put("XDG_STATE_HOME", "/fixture-state");
    const release = try paths.defaultStateForInstance(a, &env, .default);
    const dev = try paths.defaultStateForInstance(a, &env, .dev);
    try std.testing.expectEqualStrings(try paths.defaultState(a, &env), release);
    try std.testing.expectEqualStrings(if (builtin.os.tag == .linux) "/fixture-state/omux-dev" else "/fixture-home/Library/Application Support/Omux-dev", dev);
    const release_locations = try paths.Locations.fromEnvironmentForInstance(a, release, &env, .default);
    const dev_locations = try paths.Locations.fromEnvironmentForInstance(a, dev, &env, .dev);
    try std.testing.expectEqual(instance.Selection.dev, dev_locations.instance);
    try std.testing.expect(!std.mem.eql(u8, release_locations.control, dev_locations.control));
    try std.testing.expect(!std.mem.eql(u8, release_locations.browser, dev_locations.browser));
    try std.testing.expect(!std.mem.eql(u8, release_locations.adapter, dev_locations.adapter));
    try std.testing.expectEqualStrings("/fixture-home", env.get("HOME").?);
}

test "environment choice is explicit and path safety remains fail closed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env = std.process.Environ.Map.init(a);
    defer env.deinit();
    try std.testing.expectEqual(instance.Selection.default, try instance.Selection.fromEnvironment(&env));
    try env.put("OMUX_INSTANCE", "dev");
    try std.testing.expectEqual(instance.Selection.dev, try instance.Selection.fromEnvironment(&env));
    try std.testing.expectError(error.UnsafePath, paths.Locations.fromEnvironmentForInstance(a, "/tmp/../shared", &env, .dev));
    try env.put("OMUX_INSTANCE", "");
    try std.testing.expectError(error.InvalidInstance, instance.Selection.fromEnvironment(&env));
}
