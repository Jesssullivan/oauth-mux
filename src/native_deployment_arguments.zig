//! Explicit operator-selected deployment locators; never authority by themselves.
const std = @import("std");

pub const Selection = struct {
    registered_package_root: []const u8,
    installation_root: []const u8,
};
pub const Arguments = struct {
    remaining: std.ArrayList([]const u8) = .empty,
    state_override: ?[]const u8 = null,
    deployment: ?Selection = null,

    pub fn deinit(self: *Arguments, allocator: std.mem.Allocator) void {
        self.remaining.deinit(allocator);
    }
    pub fn forCommand(self: Arguments, command: []const u8) !?Selection {
        if (self.deployment != null and !std.mem.eql(u8, command, "daemon")) return error.InvalidArguments;
        return self.deployment;
    }
};

fn validateLocator(value: []const u8) !void {
    // Matches the protected constructor setup_collector.max_path_bytes.
    if (value.len > 4096 or value.len < 2 or value[0] != '/' or value[value.len - 1] == '/') return error.InvalidArguments;
    for (value) |byte| if (byte < 32 or byte == 127) return error.InvalidArguments;
    var parts = std.mem.splitScalar(u8, value[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidArguments;
    }
}

pub fn parse(allocator: std.mem.Allocator, arguments: []const []const u8) !Arguments {
    var result: Arguments = .{};
    errdefer result.deinit(allocator);
    var package: ?[]const u8 = null;
    var installation: ?[]const u8 = null;
    var i: usize = 0;
    while (i < arguments.len) : (i += 1) {
        const flag = arguments[i];
        const slot: ?*?[]const u8 = if (std.mem.eql(u8, flag, "--state-dir")) &result.state_override else if (std.mem.eql(u8, flag, "--native-package-root")) &package else if (std.mem.eql(u8, flag, "--native-installation-root")) &installation else null;
        if (slot) |selected| {
            if (selected.* != null or i + 1 == arguments.len) return error.InvalidArguments;
            i += 1;
            selected.* = arguments[i];
            if (!std.mem.eql(u8, flag, "--state-dir")) try validateLocator(arguments[i]);
        } else try result.remaining.append(allocator, flag);
    }
    if ((package == null) != (installation == null)) return error.InvalidArguments;
    if (package) |root| result.deployment = .{ .registered_package_root = root, .installation_root = installation.? };
    return result;
}

test "explicit pair preserves state selection and remaining daemon command" {
    var args = try parse(std.testing.allocator, &.{ "--native-installation-root", "/configured/install space%$", "daemon", "--state-dir", "/state", "--native-package-root", "/nix/store/configured-package" });
    defer args.deinit(std.testing.allocator);
    const selected = (try args.forCommand("daemon")).?;
    try std.testing.expectEqualStrings("/nix/store/configured-package", selected.registered_package_root);
    try std.testing.expectEqualStrings("/configured/install space%$", selected.installation_root);
    try std.testing.expectEqualStrings("/state", args.state_override.?);
    try std.testing.expectEqual(@as(usize, 1), args.remaining.items.len);
    try std.testing.expectEqualStrings("daemon", args.remaining.items[0]);
    try std.testing.expectError(error.InvalidArguments, args.forCommand("status"));
    try std.testing.expectError(error.InvalidArguments, args.forCommand("native-host"));
    try std.testing.expectError(error.InvalidArguments, args.forCommand("help"));
}

test "absent deployment retains ordinary command behavior" {
    var args = try parse(std.testing.allocator, &.{ "status", "--state-dir", "/state" });
    defer args.deinit(std.testing.allocator);
    try std.testing.expect((try args.forCommand("status")) == null);
    try std.testing.expect((try args.forCommand("daemon")) == null);
}

test "partial duplicate missing and unsafe locators refuse" {
    const invalid = [_][]const []const u8{
        &.{ "--native-package-root", "/package" },
        &.{ "--native-installation-root", "/install" },
        &.{ "--native-package-root" },
        &.{ "--native-package-root", "/package", "--native-package-root", "/other", "--native-installation-root", "/install" },
        &.{ "--native-package-root", "/package", "--native-installation-root", "/install", "--native-installation-root", "/other" },
        &.{ "--native-package-root", "relative", "--native-installation-root", "/install" },
        &.{ "--native-package-root", "/package", "--native-installation-root", "/install/../other" },
        &.{ "--native-package-root", "/package", "--native-installation-root", "/install//other" },
        &.{ "--native-package-root", "/package", "--native-installation-root", "/install/" },
        &.{ "--native-package-root", "/package", "--native-installation-root", "/install\nother" },
    };
    for (invalid) |arguments| try std.testing.expectError(error.InvalidArguments, parse(std.testing.allocator, arguments));
}

test "deployment locator byte bound matches protected constructor" {
    var boundary: [4096]u8 = @splat('a');
    boundary[0] = '/';
    var args = try parse(std.testing.allocator, &.{ "--native-package-root", &boundary, "--native-installation-root", "/install" });
    defer args.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 4096), args.deployment.?.registered_package_root.len);
    var oversized: [4097]u8 = @splat('a');
    oversized[0] = '/';
    try std.testing.expectError(error.InvalidArguments, parse(std.testing.allocator, &.{ "--native-package-root", &oversized, "--native-installation-root", "/install" }));
    try std.testing.expectError(error.InvalidArguments, parse(std.testing.allocator, &.{ "--native-package-root", "/package", "--native-installation-root", &oversized }));
}
