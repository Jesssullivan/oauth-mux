//! Reversible native Claude settings integration, not a process wrapper.
//! Endpoint configuration does not prove live proxy continuity or transfer the
//! native credential writer. Those are independent activation prerequisites.
const std = @import("std");

pub const Activation = struct {
    authenticated_proxy_available: bool = false,
    scoped_credentials_available: bool = false,
    native_renewal_retired: bool = false,
    safe_preacceptance_handoff: bool = false,
    pub fn ready(self: Activation) bool {
        return self.authenticated_proxy_available and self.scoped_credentials_available and self.native_renewal_retired and self.safe_preacceptance_handoff;
    }
};
pub const Backup = struct {
    prior_endpoint: ?[]u8,
    installed_endpoint: []u8,
    env_existed: bool,
    pub fn deinit(self: Backup, allocator: std.mem.Allocator) void {
        if (self.prior_endpoint) |value| allocator.free(value);
        allocator.free(self.installed_endpoint);
    }
};
pub const Edit = struct {
    content: []u8,
    backup: Backup,
    pub fn deinit(self: Edit, allocator: std.mem.Allocator) void {
        allocator.free(self.content);
        self.backup.deinit(allocator);
    }
};

pub fn validateEndpoint(endpoint: []const u8) !void {
    const prefix = "http://127.0.0.1:";
    if (!std.mem.startsWith(u8, endpoint, prefix)) return error.NonLocalEndpoint;
    const suffix = endpoint[prefix.len..];
    const port_text = if (suffix.len > 0 and suffix[suffix.len - 1] == '/') suffix[0 .. suffix.len - 1] else suffix;
    if (port_text.len == 0) return error.InvalidEndpoint;
    const port = std.fmt.parseInt(u16, port_text, 10) catch return error.InvalidEndpoint;
    if (port == 0) return error.InvalidEndpoint;
    for (port_text) |c| if (!std.ascii.isDigit(c)) return error.InvalidEndpoint;
}

fn parseSettings(allocator: std.mem.Allocator, original: []const u8) !std.json.Parsed(std.json.Value) {
    if (original.len > 1024 * 1024) return error.SettingsTooLarge;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, if (original.len == 0) "{}" else original, .{ .allocate = .alloc_always });
    errdefer parsed.deinit();
    if (parsed.value != .object) return error.InvalidSettings;
    return parsed;
}

/// Writes only the native endpoint setting. Never copies provider credentials
/// into settings.json, alters the native history store, or changes HOME.
pub fn install(allocator: std.mem.Allocator, original: []const u8, endpoint: []const u8, activation: Activation) !Edit {
    if (!activation.ready()) return error.ActivationUnproven;
    try validateEndpoint(endpoint);
    var parsed = try parseSettings(allocator, original);
    defer parsed.deinit();
    const env_existed = parsed.value.object.contains("env");
    if (!env_existed) try parsed.value.object.put(parsed.arena.allocator(), "env", .{ .object = .empty });
    const env = parsed.value.object.getPtr("env").?;
    if (env.* != .object) return error.InvalidSettings;
    var prior: ?[]u8 = null;
    if (env.object.get("ANTHROPIC_BASE_URL")) |value| {
        if (value != .string) return error.InvalidSettings;
        prior = try allocator.dupe(u8, value.string);
    }
    errdefer if (prior) |value| allocator.free(value);
    const installed_endpoint = try allocator.dupe(u8, endpoint);
    errdefer allocator.free(installed_endpoint);
    try env.object.put(parsed.arena.allocator(), "ANTHROPIC_BASE_URL", .{ .string = endpoint });
    return .{
        .content = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{ .whitespace = .indent_2 }),
        .backup = .{ .prior_endpoint = prior, .installed_endpoint = installed_endpoint, .env_existed = env_existed },
    };
}

pub fn remove(allocator: std.mem.Allocator, current: []const u8, backup: Backup) ![]u8 {
    var parsed = try parseSettings(allocator, current);
    defer parsed.deinit();
    const env = parsed.value.object.getPtr("env") orelse return error.IntegrationModified;
    if (env.* != .object) return error.IntegrationModified;
    const endpoint = env.object.get("ANTHROPIC_BASE_URL") orelse return error.IntegrationModified;
    if (endpoint != .string or !std.mem.eql(u8, endpoint.string, backup.installed_endpoint)) return error.IntegrationModified;
    if (backup.prior_endpoint) |prior| {
        try env.object.put(parsed.arena.allocator(), "ANTHROPIC_BASE_URL", .{ .string = prior });
    } else {
        _ = env.object.swapRemove("ANTHROPIC_BASE_URL");
        if (!backup.env_existed and env.object.count() == 0) _ = parsed.value.object.swapRemove("env");
    }
    return std.json.Stringify.valueAlloc(allocator, parsed.value, .{ .whitespace = .indent_2 });
}

const fixture_activation: Activation = .{ .authenticated_proxy_available = true, .scoped_credentials_available = true, .native_renewal_retired = true, .safe_preacceptance_handoff = true };

test "Claude activation fails closed until proxy and exclusive grant writer are proved" {
    try std.testing.expectError(error.ActivationUnproven, install(std.testing.allocator, "{}", "http://127.0.0.1:7413", .{}));
    try std.testing.expectError(error.NonLocalEndpoint, validateEndpoint("http://provider.example:7413"));
    try std.testing.expectError(error.InvalidEndpoint, validateEndpoint("http://127.0.0.1:7413/anything"));
    try validateEndpoint("http://127.0.0.1:7413/");
}

test "Claude changes endpoint while preserving native settings and credentials" {
    const allocator = std.testing.allocator;
    const original = "{\"theme\":\"dark\",\"env\":{\"ANTHROPIC_BASE_URL\":\"https://old.example\",\"KEEP\":\"yes\"}}";
    const edit = try install(allocator, original, "http://127.0.0.1:7413", fixture_activation);
    defer edit.deinit(allocator);
    const restored = try remove(allocator, edit.content, edit.backup);
    defer allocator.free(restored);
    const parsed = try parseSettings(allocator, restored);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("dark", parsed.value.object.get("theme").?.string);
    const env = parsed.value.object.get("env").?.object;
    try std.testing.expectEqualStrings("https://old.example", env.get("ANTHROPIC_BASE_URL").?.string);
    try std.testing.expectEqualStrings("yes", env.get("KEEP").?.string);
    try std.testing.expect(!env.contains("ANTHROPIC_AUTH_TOKEN"));
    try std.testing.expectError(error.IntegrationModified, remove(allocator, "{\"env\":{\"ANTHROPIC_BASE_URL\":\"http://127.0.0.1:9000\"}}", edit.backup));
}

test "Claude uninstall removes only the installed field and keeps later user changes" {
    const allocator = std.testing.allocator;
    const edit = try install(allocator, "{}", "http://127.0.0.1:7413", fixture_activation);
    defer edit.deinit(allocator);
    const current = "{\"theme\":\"light\",\"env\":{\"ANTHROPIC_BASE_URL\":\"http://127.0.0.1:7413\",\"USER_ADDED\":\"kept\"}}";
    const removed = try remove(allocator, current, edit.backup);
    defer allocator.free(removed);
    const parsed = try parseSettings(allocator, removed);
    defer parsed.deinit();
    try std.testing.expect(!parsed.value.object.get("env").?.object.contains("ANTHROPIC_BASE_URL"));
    try std.testing.expectEqualStrings("kept", parsed.value.object.get("env").?.object.get("USER_ADDED").?.string);
}
