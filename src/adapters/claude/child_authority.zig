const std = @import("std");
const builtin = @import("builtin");
const config_mod = @import("../../config.zig");

const capability_encoded_len = 43;
const loopback_proxy_bypass = "127.0.0.1,localhost";
const test_capability = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const test_managed_config_dir = "/tmp/omux-claude-neutral-session";

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
    active_config: config_mod.Config,
    managed_config_dir: []const u8,
    loopback_url: []const u8,
    capability: []const u8,
) !ManagedChildEnv {
    const home = inherited.get("HOME") orelse return error.MissingHome;
    if (home.len == 0) return error.EmptyHome;
    if (!std.fs.path.isAbsolute(home)) return error.HomeMustBeAbsolute;
    try validateLoopbackUrl(loopback_url);
    if (!isCanonicalCapability(capability)) return error.InvalidCapability;
    const managed_config_dir_absolute = try validateManagedConfigDir(
        allocator,
        home,
        active_config,
        managed_config_dir,
    );
    defer allocator.free(managed_config_dir_absolute);

    var child = std.process.EnvMap.init(allocator);
    errdefer child.deinit();

    var entries = inherited.iterator();
    while (entries.next()) |entry| {
        const name = entry.key_ptr.*;
        if (shouldScrubInheritedEnv(active_config, name)) continue;
        try child.put(name, entry.value_ptr.*);
    }

    try child.put("ANTHROPIC_BASE_URL", loopback_url);
    try child.put("CLAUDE_CONFIG_DIR", managed_config_dir_absolute);
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

pub fn validateManagedConfigDir(
    allocator: std.mem.Allocator,
    home: []const u8,
    active_config: config_mod.Config,
    raw_managed_config_dir: []const u8,
) ![]u8 {
    const managed = try absoluteConfigDir(allocator, raw_managed_config_dir, home);
    errdefer allocator.free(managed);

    const canonical = try std.fs.path.join(allocator, &.{ home, ".claude" });
    defer allocator.free(canonical);
    try refuseConfigDirOverlap(allocator, managed, canonical);

    var provider_it = active_config.providers.map.iterator();
    while (provider_it.next()) |provider_entry| {
        const provider_name = provider_entry.key_ptr.*;
        if (config_mod.resolveProviderKind(active_config, provider_name) != .claude) continue;
        var account_it = provider_entry.value_ptr.accounts.map.iterator();
        while (account_it.next()) |account_entry| {
            const raw_forbidden = account_entry.value_ptr.config_dir orelse continue;
            const forbidden = try absoluteConfigDir(allocator, raw_forbidden, home);
            defer allocator.free(forbidden);
            try refuseConfigDirOverlap(allocator, managed, forbidden);
        }
    }
    return managed;
}

fn absoluteConfigDir(
    allocator: std.mem.Allocator,
    raw: []const u8,
    home: []const u8,
) ![]u8 {
    if (raw.len == 0) return error.EmptyManagedConfigDir;
    if (!std.fs.path.isAbsolute(home)) return error.HomeMustBeAbsolute;

    const candidate = if (std.mem.eql(u8, raw, "~"))
        try allocator.dupe(u8, home)
    else if (std.mem.startsWith(u8, raw, "~/"))
        try std.fs.path.join(allocator, &.{ home, raw[2..] })
    else if (std.fs.path.isAbsolute(raw))
        try allocator.dupe(u8, raw)
    else
        return error.ManagedConfigDirMustBeAbsolute;
    defer allocator.free(candidate);

    if (!std.fs.path.isAbsolute(candidate)) return error.ManagedConfigDirMustBeAbsolute;
    const normalized = try std.fs.path.resolve(allocator, &.{candidate});
    errdefer allocator.free(normalized);
    if (!std.fs.path.isAbsolute(normalized)) return error.ManagedConfigDirMustBeAbsolute;
    return normalized;
}

pub fn refuseConfigDirOverlap(
    allocator: std.mem.Allocator,
    managed: []const u8,
    forbidden: []const u8,
) !void {
    if (configDirPathsOverlap(managed, forbidden)) {
        return error.ManagedConfigDirOverlap;
    }

    const managed_real = (try realpathLongestExisting(allocator, managed)) orelse
        return error.ManagedConfigDirUncheckable;
    defer allocator.free(managed_real);
    const forbidden_real = (try realpathLongestExisting(allocator, forbidden)) orelse
        return error.ManagedConfigDirUncheckable;
    defer allocator.free(forbidden_real);
    if (configDirPathsOverlap(managed_real, forbidden_real)) {
        return error.ManagedConfigDirOverlap;
    }
}

pub fn configDirPathsOverlap(a_in: []const u8, b_in: []const u8) bool {
    const a = a_in;
    const b = b_in;
    if (!std.fs.path.isAbsolute(a) or !std.fs.path.isAbsolute(b)) return true;
    if (caseInsensitivePathPlatform() and (!isAsciiPath(a) or !isAsciiPath(b))) {
        // std has no Unicode filesystem case-folding primitive. APFS can map
        // distinct UTF-8 spellings to one inode while preserving each spelling
        // through realpath, so the foundation fails closed instead of guessing.
        return true;
    }
    if (pathBytesEqual(a, b)) return true;
    if (isFilesystemRoot(a) or isFilesystemRoot(b)) {
        return pathBytesEqual(
            std.fs.path.diskDesignator(a),
            std.fs.path.diskDesignator(b),
        );
    }
    if (a.len > b.len and pathStartsWith(a, b) and std.fs.path.isSep(a[b.len])) return true;
    if (b.len > a.len and pathStartsWith(b, a) and std.fs.path.isSep(b[a.len])) return true;
    return false;
}

fn pathBytesEqual(a: []const u8, b: []const u8) bool {
    if (comptime caseInsensitivePathPlatform()) {
        // Managed authority must be safe on the common case-insensitive
        // filesystems. Over-rejecting a case-sensitive volume is preferable to
        // admitting two spellings of one credential store.
        return std.ascii.eqlIgnoreCase(a, b);
    }
    return std.mem.eql(u8, a, b);
}

fn pathStartsWith(haystack: []const u8, prefix: []const u8) bool {
    if (comptime caseInsensitivePathPlatform()) {
        return std.ascii.startsWithIgnoreCase(haystack, prefix);
    }
    return std.mem.startsWith(u8, haystack, prefix);
}

fn caseInsensitivePathPlatform() bool {
    return builtin.os.tag == .macos or builtin.os.tag == .windows;
}

fn isAsciiPath(path: []const u8) bool {
    for (path) |byte| {
        if (byte >= 0x80) return false;
    }
    return true;
}

fn isFilesystemRoot(path: []const u8) bool {
    return std.fs.path.isAbsolute(path) and std.fs.path.dirname(path) == null;
}

/// Resolve the longest existing prefix so symlink aliases cannot bypass the
/// overlap guard while still permitting a launcher-created final component.
pub fn realpathLongestExisting(allocator: std.mem.Allocator, path: []const u8) !?[]u8 {
    if (std.fs.realpathAlloc(allocator, path)) |resolved| {
        if (!std.fs.path.isAbsolute(resolved)) {
            allocator.free(resolved);
            return null;
        }
        return resolved;
    } else |err| switch (err) {
        error.FileNotFound => {},
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    }
    const parent = std.fs.path.dirname(path) orelse return null;
    if (parent.len == path.len) return null;
    const tail = path[parent.len..];
    const resolved_parent = (try realpathLongestExisting(allocator, parent)) orelse return null;
    defer allocator.free(resolved_parent);
    const reconstructed = try std.fmt.allocPrint(allocator, "{s}{s}", .{ resolved_parent, tail });
    if (!std.fs.path.isAbsolute(reconstructed)) {
        allocator.free(reconstructed);
        return null;
    }
    return reconstructed;
}

fn buildTestChildEnv(
    allocator: std.mem.Allocator,
    inherited: *const std.process.EnvMap,
    loopback_url: []const u8,
    capability: []const u8,
) !ManagedChildEnv {
    return buildChildEnv(
        allocator,
        inherited,
        .{},
        test_managed_config_dir,
        loopback_url,
        capability,
    );
}

pub fn shouldScrubInheritedEnv(active_config: config_mod.Config, name: []const u8) bool {
    return isClaudeAuthoritySelector(name) or isConfiguredEnvSecret(active_config, name);
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

fn isConfiguredEnvSecret(active_config: config_mod.Config, name: []const u8) bool {
    var provider_it = active_config.providers.map.iterator();
    while (provider_it.next()) |provider_entry| {
        var account_it = provider_entry.value_ptr.accounts.map.iterator();
        while (account_it.next()) |account_entry| {
            const secret = account_entry.value_ptr.secret;
            if (!std.mem.eql(u8, secret.backend, "env")) continue;
            const variable = secret.variable orelse continue;
            if (envNameEqual(name, variable)) return true;
        }
    }
    return false;
}

fn envNameEqual(a: []const u8, b: []const u8) bool {
    return if (comptime builtin.os.tag == .windows)
        std.ascii.eqlIgnoreCase(a, b)
    else
        std.mem.eql(u8, a, b);
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
    try inherited.put("HOME", "/tmp");
    try inherited.put("PATH", "/usr/bin");
    try inherited.put("UNRELATED_SENTINEL", "inherited-value");

    var child = try buildTestChildEnv(
        allocator,
        &inherited,
        "http://127.0.0.1:43123",
        test_capability,
    );
    defer child.deinit();

    try std.testing.expectEqualStrings("/tmp", child.map.get("HOME").?);
    try std.testing.expectEqualStrings("/usr/bin", child.map.get("PATH").?);
    try std.testing.expectEqualStrings("inherited-value", child.map.get("UNRELATED_SENTINEL").?);

    try inherited.put("UNRELATED_SENTINEL", "changed-after-build");
    try std.testing.expectEqualStrings("inherited-value", child.map.get("UNRELATED_SENTINEL").?);
}

test "buildChildEnv scrubs env secrets referenced by every active account" {
    const allocator = std.testing.allocator;
    var inherited = std.process.EnvMap.init(allocator);
    defer inherited.deinit();
    try inherited.put("HOME", "/tmp");
    try inherited.put("CLAUDE_ACCOUNT_SECRET", "must-not-reach-child");
    try inherited.put("CODEX_ACCOUNT_SECRET", "must-not-reach-child");
    try inherited.put("UNRELATED_SENTINEL", "preserved");

    var parsed = try config_mod.loadFromBytes(allocator,
        \\{"version":1,"providers":{"claude":{"kind":"claude","accounts":{"a":{"secret":{"backend":"env","variable":"CLAUDE_ACCOUNT_SECRET"}}}},"codex":{"kind":"codex","accounts":{"b":{"secret":{"backend":"env","variable":"CODEX_ACCOUNT_SECRET"}}}}}}
    );
    defer parsed.deinit();

    var child = try buildChildEnv(
        allocator,
        &inherited,
        parsed.value,
        test_managed_config_dir,
        "http://127.0.0.1:43123",
        test_capability,
    );
    defer child.deinit();

    try std.testing.expect(child.map.get("CLAUDE_ACCOUNT_SECRET") == null);
    try std.testing.expect(child.map.get("CODEX_ACCOUNT_SECRET") == null);
    try std.testing.expectEqualStrings("preserved", child.map.get("UNRELATED_SENTINEL").?);
}

test "buildChildEnv scrubs every inherited Claude authority prefix" {
    const allocator = std.testing.allocator;
    var inherited = std.process.EnvMap.init(allocator);
    defer inherited.deinit();
    try inherited.put("HOME", "/tmp");
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

    var child = try buildTestChildEnv(
        allocator,
        &inherited,
        "http://127.0.0.1:43123",
        test_capability,
    );
    defer child.deinit();

    try std.testing.expectEqualStrings(
        test_managed_config_dir,
        child.map.get("CLAUDE_CONFIG_DIR").?,
    );
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
        if (std.ascii.eqlIgnoreCase(name, "CLAUDE_CONFIG_DIR")) {
            try std.testing.expect(std.mem.eql(u8, name, "CLAUDE_CONFIG_DIR"));
        }
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
    try inherited.put("HOME", "/tmp");
    try inherited.put("ANTHROPIC_BASE_URL", "https://inherited.invalid");
    try inherited.put("ANTHROPIC_AUTH_TOKEN", "inherited-token");

    var child = try buildTestChildEnv(
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
        buildTestChildEnv(allocator, &inherited, "http://127.0.0.1:43123", test_capability),
    );

    try inherited.put("HOME", "");
    try std.testing.expectError(
        error.EmptyHome,
        buildTestChildEnv(allocator, &inherited, "http://127.0.0.1:43123", test_capability),
    );

    try inherited.put("HOME", "relative/home");
    try std.testing.expectError(
        error.HomeMustBeAbsolute,
        buildTestChildEnv(allocator, &inherited, "http://127.0.0.1:43123", test_capability),
    );
}

test "buildChildEnv rejects non-loopback URLs and invalid capabilities" {
    const allocator = std.testing.allocator;
    var inherited = std.process.EnvMap.init(allocator);
    defer inherited.deinit();
    try inherited.put("HOME", "/tmp");

    try std.testing.expectError(
        error.EmptyLoopbackUrl,
        buildTestChildEnv(allocator, &inherited, "", test_capability),
    );
    try std.testing.expectError(
        error.InvalidLoopbackUrl,
        buildTestChildEnv(allocator, &inherited, "https://127.0.0.1:43123", test_capability),
    );
    try std.testing.expectError(
        error.InvalidLoopbackUrl,
        buildTestChildEnv(allocator, &inherited, "http://localhost:43123", test_capability),
    );
    try std.testing.expectError(
        error.InvalidLoopbackUrl,
        buildTestChildEnv(allocator, &inherited, "http://127.0.0.1", test_capability),
    );
    try std.testing.expectError(
        error.InvalidLoopbackUrl,
        buildTestChildEnv(allocator, &inherited, "http://127.0.0.1:43123/path", test_capability),
    );
    try std.testing.expectError(
        error.InvalidCapability,
        buildTestChildEnv(allocator, &inherited, "http://127.0.0.1:43123", ""),
    );
    try std.testing.expectError(
        error.InvalidCapability,
        buildTestChildEnv(allocator, &inherited, "http://127.0.0.1:43123", "too-short"),
    );
    try std.testing.expectError(
        error.InvalidCapability,
        buildTestChildEnv(
            allocator,
            &inherited,
            "http://127.0.0.1:43123",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
    );
}

test "buildChildEnv requires a neutral config dir outside canonical and enrolled stores" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("home/.claude");
    try tmp.dir.makeDir("managed");
    try tmp.dir.makeDir("enrolled");

    const home = try tmp.dir.realpathAlloc(allocator, "home");
    defer allocator.free(home);
    const canonical = try tmp.dir.realpathAlloc(allocator, "home/.claude");
    defer allocator.free(canonical);
    const managed = try tmp.dir.realpathAlloc(allocator, "managed");
    defer allocator.free(managed);
    const enrolled = try tmp.dir.realpathAlloc(allocator, "enrolled");
    defer allocator.free(enrolled);

    var inherited = std.process.EnvMap.init(allocator);
    defer inherited.deinit();
    try inherited.put("HOME", home);
    const cfg_json = try std.fmt.allocPrint(
        allocator,
        \\{{"version":1,"providers":{{"claude":{{"kind":"claude","accounts":{{"enrolled":{{"secret":{{"backend":"env","variable":"TEST_CLAUDE_TOKEN"}},"config_dir":"{s}"}}}}}}}}}}
    ,
        .{enrolled},
    );
    defer allocator.free(cfg_json);
    var parsed = try config_mod.loadFromBytes(allocator, cfg_json);
    defer parsed.deinit();

    var child = try buildChildEnv(
        allocator,
        &inherited,
        parsed.value,
        managed,
        "http://127.0.0.1:43123",
        test_capability,
    );
    defer child.deinit();
    try std.testing.expectEqualStrings(managed, child.map.get("CLAUDE_CONFIG_DIR").?);

    try std.testing.expectError(
        error.ManagedConfigDirOverlap,
        buildChildEnv(
            allocator,
            &inherited,
            parsed.value,
            canonical,
            "http://127.0.0.1:43123",
            test_capability,
        ),
    );
    try std.testing.expectError(
        error.ManagedConfigDirOverlap,
        buildChildEnv(
            allocator,
            &inherited,
            parsed.value,
            enrolled,
            "http://127.0.0.1:43123",
            test_capability,
        ),
    );
    if (comptime builtin.os.tag != .windows) {
        const root = try tmp.dir.realpathAlloc(allocator, ".");
        defer allocator.free(root);
        const alias = try std.fs.path.join(allocator, &.{ root, "managed-alias" });
        defer allocator.free(alias);
        try std.fs.symLinkAbsolute(enrolled, alias, .{ .is_directory = true });
        try std.testing.expectError(
            error.ManagedConfigDirOverlap,
            buildChildEnv(
                allocator,
                &inherited,
                parsed.value,
                alias,
                "http://127.0.0.1:43123",
                test_capability,
            ),
        );
        const nested_alias = try std.fs.path.join(allocator, &.{ alias, "missing", "nested" });
        defer allocator.free(nested_alias);
        try std.testing.expectError(
            error.ManagedConfigDirOverlap,
            buildChildEnv(
                allocator,
                &inherited,
                parsed.value,
                nested_alias,
                "http://127.0.0.1:43123",
                test_capability,
            ),
        );
    }
    if (comptime builtin.os.tag == .macos) {
        const case_alias = try std.ascii.allocUpperString(allocator, enrolled);
        defer allocator.free(case_alias);
        try std.testing.expectError(
            error.ManagedConfigDirOverlap,
            buildChildEnv(
                allocator,
                &inherited,
                parsed.value,
                case_alias,
                "http://127.0.0.1:43123",
                test_capability,
            ),
        );
        try std.testing.expect(configDirPathsOverlap(
            "/tmp/\xc3\xa9",
            "/tmp/\xc3\x89",
        ));
    }
    try std.testing.expectError(
        error.EmptyManagedConfigDir,
        buildChildEnv(
            allocator,
            &inherited,
            parsed.value,
            "",
            "http://127.0.0.1:43123",
            test_capability,
        ),
    );
    try std.testing.expectError(
        error.ManagedConfigDirMustBeAbsolute,
        buildChildEnv(
            allocator,
            &inherited,
            parsed.value,
            "relative/session",
            "http://127.0.0.1:43123",
            test_capability,
        ),
    );
    try std.testing.expectError(
        error.ManagedConfigDirOverlap,
        buildChildEnv(
            allocator,
            &inherited,
            parsed.value,
            std.fs.path.sep_str,
            "http://127.0.0.1:43123",
            test_capability,
        ),
    );
}
