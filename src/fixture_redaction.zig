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

/// Walks `root_path` and asserts every file is free of forbidden secret
/// markers. Returns the number of files scanned. A missing directory is
/// only tolerated when `require_present` is false — `test/evidence/`
/// (TIN-2722) is a second walk root that may be empty or absent until a
/// capture is reviewed and promoted into it.
fn scanRootForSecrets(root_path: []const u8, require_present: bool) !usize {
    var root = std.fs.cwd().openDir(root_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => {
            if (require_present) return error.FixtureDirectoryMissing;
            return 0;
        },
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

    return scanned;
}

test "test fixtures contain no obvious OAuth secrets" {
    const scanned = try scanRootForSecrets("test/fixtures", true);
    try std.testing.expect(scanned > 0);
}

test "evidence captures contain no obvious OAuth secrets" {
    // test/evidence/ (TIN-2722) is the committed, redacted quota-observation
    // fixture root. It may be empty or absent until a capture is promoted
    // into it, so only an unredacted secret marker fails this test — not
    // an empty or missing directory.
    _ = try scanRootForSecrets("test/evidence", false);
}
