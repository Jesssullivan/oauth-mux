const std = @import("std");

const capability_encoded_len = 43;
const loopback_proxy_bypass = "127.0.0.1,localhost";
const test_capability = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Owns the managed child environment, including its capability copy. The
/// caller retains the sidecar's canonical capability and must zero that at
/// session teardown; this wrapper zeroes the independent child-env copy.
pub const ManagedChildEnv = struct {
    map: std.process.EnvMap,

    pub fn deinit(self: *ManagedChildEnv) void {
        if (self.map.getPtr("ANTHROPIC_AUTH_TOKEN")) |value_ptr| {
            std.crypto.secureZero(u8, @constCast(value_ptr.*));
        }
        self.map.deinit();
    }
};

/// Builds the complete environment for a managed Claude child. The returned
/// map owns every key and value and must be deinitialized by the caller.
pub fn buildChildEnv(
    allocator: std.mem.Allocator,
    inherited: *const std.process.EnvMap,
    loopback_url: []const u8,
    capability: []const u8,
) !ManagedChildEnv {
    const home = inherited.get("HOME") orelse return error.MissingHome;
    if (home.len == 0) return error.EmptyHome;
    try validateLoopbackUrl(loopback_url);
    if (!isCanonicalCapability(capability)) return error.InvalidCapability;

    var child = std.process.EnvMap.init(allocator);
    errdefer child.deinit();

    var entries = inherited.iterator();
    while (entries.next()) |entry| {
        const name = entry.key_ptr.*;
        if (isClaudeAuthoritySelector(name)) continue;
        try child.put(name, entry.value_ptr.*);
    }

    try child.put("ANTHROPIC_BASE_URL", loopback_url);
    try child.put("NO_PROXY", loopback_proxy_bypass);
    try child.put("no_proxy", loopback_proxy_bypass);
    // Install an explicitly owned secret copy last. EnvMap.put can allocate,
    // copy, and ordinary-free internally on OOM; putMove keeps failure cleanup
    // under this function's zeroing errdefer until ownership transfers.
    const capability_key = try allocator.dupe(u8, "ANTHROPIC_AUTH_TOKEN");
    errdefer allocator.free(capability_key);
    const capability_copy = try allocator.dupe(u8, capability);
    errdefer {
        std.crypto.secureZero(u8, capability_copy);
        allocator.free(capability_copy);
    }
    try child.putMove(capability_key, capability_copy);
    return .{ .map = child };
}

fn isClaudeAuthoritySelector(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "CLAUDE_CONFIG_DIR") or
        std.ascii.startsWithIgnoreCase(name, "ANTHROPIC_") or
        std.ascii.startsWithIgnoreCase(name, "CLAUDE_CODE_") or
        std.ascii.eqlIgnoreCase(name, "HTTP_PROXY") or
        std.ascii.eqlIgnoreCase(name, "HTTPS_PROXY") or
        std.ascii.eqlIgnoreCase(name, "ALL_PROXY") or
        std.ascii.eqlIgnoreCase(name, "NO_PROXY");
}

fn validateLoopbackUrl(url: []const u8) !void {
    if (url.len == 0) return error.EmptyLoopbackUrl;
    const uri = std.Uri.parse(url) catch return error.InvalidLoopbackUrl;
    if (!std.mem.eql(u8, uri.scheme, "http")) return error.InvalidLoopbackUrl;
    if (uri.user != null or uri.password != null) return error.InvalidLoopbackUrl;
    const host_component = uri.host orelse return error.InvalidLoopbackUrl;
    const host = switch (host_component) {
        .raw, .percent_encoded => |value| value,
    };
    if (!std.mem.eql(u8, host, "127.0.0.1")) return error.InvalidLoopbackUrl;
    const port = uri.port orelse return error.InvalidLoopbackUrl;
    if (port == 0) return error.InvalidLoopbackUrl;
    if (!uri.path.isEmpty() or uri.query != null or uri.fragment != null) {
        return error.InvalidLoopbackUrl;
    }
}

fn isCanonicalCapability(capability: []const u8) bool {
    if (capability.len != capability_encoded_len) return false;
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(capability) catch return false;
    if (decoded_len != 32) return false;

    var decoded: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &decoded);
    decoder.decode(&decoded, capability) catch return false;
    return true;
}

test "buildChildEnv preserves HOME and unrelated inherited entries" {
    const allocator = std.testing.allocator;
    var inherited = std.process.EnvMap.init(allocator);
    defer inherited.deinit();
    try inherited.put("HOME", "/tmp/managed-home");
    try inherited.put("PATH", "/usr/bin");
    try inherited.put("UNRELATED_SENTINEL", "inherited-value");

    var child = try buildChildEnv(
        allocator,
        &inherited,
        "http://127.0.0.1:43123",
        test_capability,
    );
    defer child.deinit();

    try std.testing.expectEqualStrings("/tmp/managed-home", child.map.get("HOME").?);
    try std.testing.expectEqualStrings("/usr/bin", child.map.get("PATH").?);
    try std.testing.expectEqualStrings("inherited-value", child.map.get("UNRELATED_SENTINEL").?);

    try inherited.put("UNRELATED_SENTINEL", "changed-after-build");
    try std.testing.expectEqualStrings("inherited-value", child.map.get("UNRELATED_SENTINEL").?);
}

test "buildChildEnv scrubs every inherited Claude authority prefix" {
    const allocator = std.testing.allocator;
    var inherited = std.process.EnvMap.init(allocator);
    defer inherited.deinit();
    try inherited.put("HOME", "/tmp/managed-home");
    try inherited.put("UNRELATED_SENTINEL", "preserved");
    try inherited.put("CLAUDE_CONFIG_DIR", "/tmp/account-config");
    try inherited.put("ANTHROPIC_API_KEY", "inherited-api-key");
    try inherited.put("ANTHROPIC_CUSTOM_HEADERS", "inherited-headers");
    try inherited.put("ANTHROPIC_BASE_URL", "https://inherited.invalid");
    try inherited.put("ANTHROPIC_AUTH_TOKEN", "inherited-token");
    try inherited.put("CLAUDE_CODE_USE_BEDROCK", "1");
    try inherited.put("CLAUDE_CODE_USE_VERTEX", "1");
    try inherited.put("CLAUDE_CODE_SENTINEL", "inherited-selector");
    try inherited.put("anthropic_lowercase_sentinel", "inherited-selector");
    try inherited.put("claude_code_lowercase_sentinel", "inherited-selector");
    try inherited.put("HTTP_PROXY", "http://proxy.invalid:8080");
    try inherited.put("https_proxy", "http://proxy.invalid:8080");
    try inherited.put("ALL_PROXY", "socks5://proxy.invalid:1080");
    try inherited.put("NO_PROXY", "inherited.invalid");

    var child = try buildChildEnv(
        allocator,
        &inherited,
        "http://127.0.0.1:43123",
        test_capability,
    );
    defer child.deinit();

    try std.testing.expect(child.map.get("CLAUDE_CONFIG_DIR") == null);
    try std.testing.expect(child.map.get("ANTHROPIC_API_KEY") == null);
    try std.testing.expect(child.map.get("ANTHROPIC_CUSTOM_HEADERS") == null);
    try std.testing.expect(child.map.get("CLAUDE_CODE_USE_BEDROCK") == null);
    try std.testing.expect(child.map.get("CLAUDE_CODE_USE_VERTEX") == null);
    try std.testing.expect(child.map.get("CLAUDE_CODE_SENTINEL") == null);
    try std.testing.expect(child.map.get("anthropic_lowercase_sentinel") == null);
    try std.testing.expect(child.map.get("claude_code_lowercase_sentinel") == null);
    try std.testing.expect(child.map.get("HTTP_PROXY") == null);
    try std.testing.expect(child.map.get("HTTPS_PROXY") == null);
    try std.testing.expect(child.map.get("ALL_PROXY") == null);
    try std.testing.expectEqualStrings(loopback_proxy_bypass, child.map.get("NO_PROXY").?);
    try std.testing.expectEqualStrings(loopback_proxy_bypass, child.map.get("no_proxy").?);

    var entries = child.map.iterator();
    while (entries.next()) |entry| {
        const name = entry.key_ptr.*;
        try std.testing.expect(!std.ascii.eqlIgnoreCase(name, "CLAUDE_CONFIG_DIR"));
        try std.testing.expect(!std.ascii.startsWithIgnoreCase(name, "CLAUDE_CODE_"));
        if (std.ascii.startsWithIgnoreCase(name, "ANTHROPIC_")) {
            try std.testing.expect(
                std.mem.eql(u8, name, "ANTHROPIC_BASE_URL") or
                    std.mem.eql(u8, name, "ANTHROPIC_AUTH_TOKEN"),
            );
        }
    }
}

test "buildChildEnv installs only managed Anthropic carriers" {
    const allocator = std.testing.allocator;
    var inherited = std.process.EnvMap.init(allocator);
    defer inherited.deinit();
    try inherited.put("HOME", "/tmp/managed-home");
    try inherited.put("ANTHROPIC_BASE_URL", "https://inherited.invalid");
    try inherited.put("ANTHROPIC_AUTH_TOKEN", "inherited-token");

    var child = try buildChildEnv(
        allocator,
        &inherited,
        "http://127.0.0.1:43123",
        test_capability,
    );
    defer child.deinit();

    try std.testing.expectEqualStrings(
        "http://127.0.0.1:43123",
        child.map.get("ANTHROPIC_BASE_URL").?,
    );
    try std.testing.expectEqualStrings(
        test_capability,
        child.map.get("ANTHROPIC_AUTH_TOKEN").?,
    );
}

test "buildChildEnv rejects missing and empty HOME" {
    const allocator = std.testing.allocator;
    var inherited = std.process.EnvMap.init(allocator);
    defer inherited.deinit();

    try std.testing.expectError(
        error.MissingHome,
        buildChildEnv(allocator, &inherited, "http://127.0.0.1:43123", test_capability),
    );

    try inherited.put("HOME", "");
    try std.testing.expectError(
        error.EmptyHome,
        buildChildEnv(allocator, &inherited, "http://127.0.0.1:43123", test_capability),
    );
}

test "buildChildEnv rejects non-loopback URLs and invalid capabilities" {
    const allocator = std.testing.allocator;
    var inherited = std.process.EnvMap.init(allocator);
    defer inherited.deinit();
    try inherited.put("HOME", "/tmp/managed-home");

    try std.testing.expectError(
        error.EmptyLoopbackUrl,
        buildChildEnv(allocator, &inherited, "", test_capability),
    );
    try std.testing.expectError(
        error.InvalidLoopbackUrl,
        buildChildEnv(allocator, &inherited, "https://127.0.0.1:43123", test_capability),
    );
    try std.testing.expectError(
        error.InvalidLoopbackUrl,
        buildChildEnv(allocator, &inherited, "http://localhost:43123", test_capability),
    );
    try std.testing.expectError(
        error.InvalidLoopbackUrl,
        buildChildEnv(allocator, &inherited, "http://127.0.0.1", test_capability),
    );
    try std.testing.expectError(
        error.InvalidLoopbackUrl,
        buildChildEnv(allocator, &inherited, "http://127.0.0.1:43123/path", test_capability),
    );
    try std.testing.expectError(
        error.InvalidCapability,
        buildChildEnv(allocator, &inherited, "http://127.0.0.1:43123", ""),
    );
    try std.testing.expectError(
        error.InvalidCapability,
        buildChildEnv(allocator, &inherited, "http://127.0.0.1:43123", "too-short"),
    );
    try std.testing.expectError(
        error.InvalidCapability,
        buildChildEnv(
            allocator,
            &inherited,
            "http://127.0.0.1:43123",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
    );
}
