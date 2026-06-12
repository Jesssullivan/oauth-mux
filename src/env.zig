const std = @import("std");
const builtin = @import("builtin");

/// Test-only env injection seam. Zig cannot portably mutate the real process
/// environment in-process (setenv needs libc), so unit tests that need the
/// OMUX_CONFIG_DIR / OMUX_STATE_DIR / OMUX_RUNTIME_DIR path seams inject
/// overrides here instead of writing into the developer's real directories.
/// Keys absent from the map fall through to the real environment. Always
/// null outside `zig build test`; release builds never consult it.
pub var test_overrides: ?*const std.process.EnvMap = null;

pub fn get(allocator: std.mem.Allocator, name: []const u8) !?[]u8 {
    if (comptime builtin.is_test) {
        if (test_overrides) |map| {
            if (map.get(name)) |value| return try allocator.dupe(u8, value);
        }
    }
    return std.process.getEnvVarOwned(allocator, name) catch |e| switch (e) {
        error.EnvironmentVariableNotFound => null,
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
}

pub fn has(name: []const u8) bool {
    const allocator = std.heap.page_allocator;
    const value = get(allocator, name) catch return false;
    if (value) |v| {
        allocator.free(v);
        return true;
    }
    return false;
}
