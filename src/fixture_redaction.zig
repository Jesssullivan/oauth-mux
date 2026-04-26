const std = @import("std");

const max_fixture_bytes = 1024 * 1024;

const forbidden_markers = [_][]const u8{
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "authorization:",
    "authorization=",
    "bearer ",
    "bearer%20",
    "set-cookie:",
    "cookie:",
    "sk-",
    "sess-",
};

fn assertRedactedFixture(path: []const u8, bytes: []const u8) !void {
    for (forbidden_markers) |marker| {
        if (indexOfIgnoreCase(bytes, marker) != null) {
            std.debug.print("fixture redaction error: {s} contains forbidden marker '{s}'\n", .{ path, marker });
            return error.UnredactedFixture;
        }
    }
}

fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0) return 0;
    if (needle.len > haystack.len) return null;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return i;
    }

    return null;
}

test "test fixtures contain no obvious OAuth secrets" {
    var root = std.fs.cwd().openDir("test/fixtures", .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return error.FixtureDirectoryMissing,
        else => return err,
    };
    defer root.close();

    var walker = try root.walk(std.testing.allocator);
    defer walker.deinit();

    var scanned: usize = 0;
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        scanned += 1;

        const bytes = try root.readFileAlloc(std.testing.allocator, entry.path, max_fixture_bytes);
        defer std.testing.allocator.free(bytes);

        try assertRedactedFixture(entry.path, bytes);
    }

    try std.testing.expect(scanned > 0);
}
