const std = @import("std");

pub fn get(allocator: std.mem.Allocator, name: []const u8) !?[]u8 {
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
