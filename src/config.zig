const std = @import("std");
const types = @import("types.zig");
const paths = @import("paths.zig");

pub const Config = struct {
    version: u32 = 1,
    defaults: Defaults = .{},
    providers: std.json.ArrayHashMap(ProviderConfig) = .{},
    profiles: std.json.ArrayHashMap(ProfileConfig) = .{},
    strategies: std.json.ArrayHashMap(StrategyConfig) = .{},
};

pub const Defaults = struct {
    provider: ?[]const u8 = null,
    strategy: ?[]const u8 = null,
    shell: ?[]const u8 = null,
    daemon: bool = false,
};

pub const ProviderConfig = struct {
    kind: []const u8,
    config_dir_env: ?[]const u8 = null,
    accounts: std.json.ArrayHashMap(AccountConfig) = .{},
};

pub const AccountConfig = struct {
    priority: i32 = 0,
    secret: SecretConfig,
    config_dir: ?[]const u8 = null,
    quota: ?QuotaConfig = null,
    tags: ?[]const []const u8 = null,
};

pub const SecretConfig = struct {
    backend: []const u8,
    service: ?[]const u8 = null,
    account: ?[]const u8 = null,
    path: ?[]const u8 = null,
    key: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
    variable: ?[]const u8 = null,
    command: ?[]const []const u8 = null,
    identity: ?[]const u8 = null,
};

pub const QuotaConfig = struct {
    monthly_limit: ?u64 = null,
    warn_at_pct: u32 = 5,
};

pub const ProfileConfig = struct {
    providers: []const []const u8,
    strategy: ?[]const u8 = null,
    affinity_ttl_minutes: u32 = 20,
};

pub const StrategyConfig = struct {
    kind: []const u8,
    max_retries: u32 = 2,
    health_decay_per_hour: ?i32 = null,
    rate_limit_penalty: ?i32 = null,
    failure_penalty: ?i32 = null,
    success_bonus: ?i32 = null,
};

pub fn load(allocator: std.mem.Allocator) !std.json.Parsed(Config) {
    const path = try paths.configFilePath(allocator);
    defer allocator.free(path);
    return loadFromPath(allocator, path);
}

pub fn loadFromPath(allocator: std.mem.Allocator, path: []const u8) !std.json.Parsed(Config) {
    const file = std.fs.openFileAbsolute(path, .{}) catch |e| switch (e) {
        error.FileNotFound => return error.FileNotFound,
        else => return error.Unexpected,
    };
    defer file.close();

    const bytes = file.readToEndAlloc(allocator, 1024 * 1024) catch return error.Unexpected;
    defer allocator.free(bytes);

    return loadFromBytes(allocator, bytes);
}

pub fn loadFromBytes(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(Config) {
    return std.json.parseFromSlice(Config, allocator, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

pub fn resolveSecretBackend(secret: SecretConfig) !types.SecretBackend {
    const map = std.StaticStringMap(enum { keychain, sops, age, env, file, command, stdin }).initComptime(.{
        .{ "keychain", .keychain },
        .{ "sops", .sops },
        .{ "age", .age },
        .{ "env", .env },
        .{ "file", .file },
        .{ "command", .command },
        .{ "stdin", .stdin },
    });

    const kind = map.get(secret.backend) orelse return error.InvalidCharacter;

    return switch (kind) {
        .keychain => .{ .keychain = .{
            .service = secret.service orelse return error.InvalidCharacter,
            .account = secret.account orelse return error.InvalidCharacter,
        } },
        .sops => .{ .sops = .{
            .path = secret.path orelse return error.InvalidCharacter,
            .key_path = secret.key_path,
        } },
        .age => .{ .age = .{
            .path = secret.path orelse return error.InvalidCharacter,
            .identity = secret.identity orelse return error.InvalidCharacter,
        } },
        .env => .{ .env = .{
            .variable = secret.variable orelse return error.InvalidCharacter,
        } },
        .file => .{ .file = .{
            .path = secret.path orelse return error.InvalidCharacter,
        } },
        .command => .{ .command = .{
            .argv = secret.command orelse return error.InvalidCharacter,
        } },
        .stdin => .stdin,
    };
}

test "loadFromBytes minimal config" {
    const json =
        \\{
        \\  "version": 1,
        \\  "defaults": { "provider": "claude" },
        \\  "providers": {
        \\    "claude": {
        \\      "kind": "claude",
        \\      "config_dir_env": "CLAUDE_CONFIG_DIR",
        \\      "accounts": {
        \\        "work": {
        \\          "priority": 10,
        \\          "secret": { "backend": "env", "variable": "CLAUDE_TOKEN" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u32, 1), parsed.value.version);
    try std.testing.expectEqualStrings("claude", parsed.value.defaults.provider.?);

    const providers = parsed.value.providers.map;
    try std.testing.expectEqual(@as(usize, 1), providers.count());
    const claude = providers.get("claude").?;
    try std.testing.expectEqualStrings("claude", claude.kind);

    const accounts = claude.accounts.map;
    try std.testing.expectEqual(@as(usize, 1), accounts.count());
    const work = accounts.get("work").?;
    try std.testing.expectEqual(@as(i32, 10), work.priority);
    try std.testing.expectEqualStrings("env", work.secret.backend);
    try std.testing.expectEqualStrings("CLAUDE_TOKEN", work.secret.variable.?);
}

test "resolveSecretBackend keychain" {
    const secret = SecretConfig{
        .backend = "keychain",
        .service = "Claude Code-credentials",
        .account = "jess",
    };
    const backend = try resolveSecretBackend(secret);
    switch (backend) {
        .keychain => |ref| {
            try std.testing.expectEqualStrings("Claude Code-credentials", ref.service);
            try std.testing.expectEqualStrings("jess", ref.account);
        },
        else => return error.InvalidCharacter,
    }
}

test "resolveSecretBackend env" {
    const secret = SecretConfig{
        .backend = "env",
        .variable = "MY_TOKEN",
    };
    const backend = try resolveSecretBackend(secret);
    switch (backend) {
        .env => |ref| try std.testing.expectEqualStrings("MY_TOKEN", ref.variable),
        else => return error.InvalidCharacter,
    }
}
