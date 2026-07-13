const std = @import("std");

/// Zig-owned executable naming contract. The release manifest lane consumes
/// this mapping rather than defining a second package or version authority.
pub const primary_executable_name = "omux";
pub const compatibility_executable_names = &[_][]const u8{"oauth-mux"};
pub const package_name = "oauth-mux";

/// Renaming the executable must not fork existing config, state, or runtime
/// directories. Both entrypoints continue to use the shipped namespace.
pub const storage_namespace = "oauth-mux";

pub fn invocationName(argv0: []const u8) []const u8 {
    const stem = executableStem(argv0);

    for (compatibility_executable_names) |name| {
        if (std.mem.eql(u8, stem, name)) return name;
    }
    return primary_executable_name;
}

pub fn isExecutableName(value: []const u8) bool {
    const stem = executableStem(value);
    if (std.mem.eql(u8, stem, primary_executable_name)) return true;
    for (compatibility_executable_names) |name| {
        if (std.mem.eql(u8, stem, name)) return true;
    }
    return false;
}

fn executableStem(value: []const u8) []const u8 {
    const basename_start = if (std.mem.lastIndexOfAny(u8, value, "/\\")) |index| index + 1 else 0;
    const basename = value[basename_start..];
    return if (std.mem.endsWith(u8, basename, ".exe"))
        basename[0 .. basename.len - ".exe".len]
    else
        basename;
}

test "executable naming keeps one persistent namespace" {
    try std.testing.expectEqualStrings("omux", primary_executable_name);
    try std.testing.expectEqual(@as(usize, 1), compatibility_executable_names.len);
    try std.testing.expectEqualStrings("oauth-mux", compatibility_executable_names[0]);
    try std.testing.expectEqualStrings("oauth-mux", package_name);
    try std.testing.expectEqualStrings(compatibility_executable_names[0], storage_namespace);
}

test "invocation name preserves the compatibility spelling" {
    try std.testing.expectEqualStrings("omux", invocationName("/tmp/omux"));
    try std.testing.expectEqualStrings("omux", invocationName("C:\\bin\\omux.exe"));
    try std.testing.expectEqualStrings("oauth-mux", invocationName("/tmp/oauth-mux"));
    try std.testing.expectEqualStrings("oauth-mux", invocationName("oauth-mux.exe"));
    try std.testing.expect(isExecutableName("C:\\bin\\omux.exe"));
    try std.testing.expect(isExecutableName("/tmp/oauth-mux"));
    try std.testing.expect(!isExecutableName("/tmp/not-omux"));
}
