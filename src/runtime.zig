const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");
const paths = @import("paths.zig");
const provider_schema = @import("provider_schema.zig");
const repair_state = @import("repair_state.zig");
const types = @import("types.zig");

pub const RouteRef = struct {
    provider: []const u8,
    account: []const u8,
    capability: ?[]const u8 = null,
};

pub const AccountInfo = struct {
    readiness: types.RuntimeReadiness = .ready,
    config_dir_set: bool = false,
    config_dir_exists: bool = false,
    config_dir_writable: bool = false,
    session_paths_total: usize = 0,
    session_paths_present: usize = 0,

    pub fn ready(self: AccountInfo) bool {
        return self.readiness.isReady();
    }
};

pub fn providerReadiness(
    allocator: std.mem.Allocator,
    def: provider_schema.ProviderDefinition,
    capability: ?[]const u8,
) !types.RuntimeReadiness {
    for (def.runtime.required_binaries) |binary_name| {
        if (!try commandAvailable(allocator, binary_name)) {
            return .{ .missing_binary = binary_name };
        }
    }

    if (capability) |capability_name| {
        if (provider_schema.probePlanForCapability(def, capability_name)) |plan| {
            if (plan.transport == .command) {
                const argv = plan.command orelse return .{ .session_unavailable = "probe command missing" };
                if (argv.len == 0) return .{ .session_unavailable = "probe command empty" };
                if (!try commandAvailable(allocator, argv[0])) {
                    return .{ .missing_binary = argv[0] };
                }
            }
        }
    }

    return .ready;
}

pub fn routeReadiness(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    route: RouteRef,
    def: provider_schema.ProviderDefinition,
) !types.RuntimeReadiness {
    const provider_runtime = try providerReadiness(allocator, def, route.capability);
    if (!provider_runtime.isReady()) return provider_runtime;

    const prov = cfg.providers.map.get(route.provider) orelse return .{ .session_unavailable = "provider_config_missing" };
    const account = prov.accounts.map.get(route.account) orelse return .{ .session_unavailable = "account_config_missing" };
    if (try repair_state.probeRepairLock(allocator, route.provider, route.account)) |progress| {
        return .{ .repair_in_progress = progress };
    }
    const info = try accountInfo(allocator, prov, account, def, config.resolveProviderKind(cfg, route.provider));
    return info.readiness;
}

pub fn accountInfo(
    allocator: std.mem.Allocator,
    prov: config.ProviderConfig,
    account: config.AccountConfig,
    def: provider_schema.ProviderDefinition,
    kind: ?types.ProviderKind,
) !AccountInfo {
    var info = AccountInfo{
        .config_dir_set = account.config_dir != null,
        .session_paths_total = def.runtime.session_paths.len,
    };

    for (def.runtime.required_binaries) |binary_name| {
        if (!try commandAvailable(allocator, binary_name)) {
            info.readiness = .{ .missing_binary = binary_name };
            return info;
        }
    }

    const env_var = configDirEnv(prov, def, kind);
    if (account.config_dir == null) {
        if (env_var != null and (def.runtime.writable_paths.len != 0 or def.runtime.session_paths.len != 0)) {
            info.readiness = .{ .session_unavailable = "account_config_dir_missing" };
        }
        return info;
    }

    const config_dir = try paths.expandTilde(allocator, account.config_dir.?);
    defer allocator.free(config_dir);

    const dir_state = checkDirectory(config_dir);
    switch (dir_state) {
        .ok => info.config_dir_exists = true,
        .missing => {
            info.readiness = .{ .session_unavailable = "config_dir_missing" };
            return info;
        },
        .access_denied => {
            info.readiness = .{ .permission_denied = .{ .path = "config_dir", .operation = "open" } };
            return info;
        },
        .not_directory => {
            info.readiness = .{ .session_unavailable = "config_dir_not_directory" };
            return info;
        },
        .other_error => {
            info.readiness = .{ .session_unavailable = "config_dir_unavailable" };
            return info;
        },
    }

    if (def.runtime.writable_paths.len != 0) {
        for (def.runtime.writable_paths) |path_spec| {
            const resolved = try resolvePath(allocator, path_spec, env_var, config_dir) orelse continue;
            defer allocator.free(resolved);
            if (!canWriteDirectoryMarker(allocator, resolved)) {
                info.readiness = .{ .unwritable_store = "config_dir" };
                return info;
            }
        }
        info.config_dir_writable = true;
    } else {
        info.config_dir_writable = true;
    }

    for (def.runtime.session_paths) |session_spec| {
        const resolved = try resolvePath(allocator, session_spec, env_var, config_dir) orelse continue;
        defer allocator.free(resolved);
        switch (checkFile(resolved)) {
            .exists => info.session_paths_present += 1,
            .missing => {
                info.readiness = .{ .needs_reauth = .{
                    .methods = reauthMethodsFor(def),
                    .reason = "session_file_missing",
                } };
                return info;
            },
            .access_denied => {
                info.readiness = .{ .permission_denied = .{ .path = "session_file", .operation = "read" } };
                return info;
            },
            .other_error => {
                info.readiness = .{ .session_unavailable = "session_file_unavailable" };
                return info;
            },
        }
    }

    info.readiness = .ready;
    return info;
}

pub fn configDirEnv(prov: config.ProviderConfig, def: provider_schema.ProviderDefinition, kind: ?types.ProviderKind) ?[]const u8 {
    if (prov.config_dir_env) |env_var| return env_var;
    if (def.injection.config_dir_env) |env_var| return env_var;
    if (kind) |provider_kind| return provider_kind.configDirEnv();
    return null;
}

pub fn countMissingBinaries(allocator: std.mem.Allocator, def: provider_schema.ProviderDefinition) !usize {
    var missing: usize = 0;
    for (def.runtime.required_binaries) |binary_name| {
        if (!try commandAvailable(allocator, binary_name)) missing += 1;
    }
    return missing;
}

pub fn commandAvailable(allocator: std.mem.Allocator, binary_name: []const u8) !bool {
    if (binary_name.len == 0) return false;

    if (std.mem.indexOfScalar(u8, binary_name, '/') != null or std.mem.indexOfScalar(u8, binary_name, '\\') != null) {
        return fileExists(binary_name);
    }

    const path_env = std.process.getEnvVarOwned(allocator, "PATH") catch return false;
    defer allocator.free(path_env);

    var dirs = std.mem.splitScalar(u8, path_env, pathDelimiter());
    while (dirs.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = try std.fs.path.join(allocator, &.{ dir, binary_name });
        defer allocator.free(candidate);
        if (fileExists(candidate)) return true;

        if (comptime builtin.os.tag == .windows) {
            if (!std.ascii.endsWithIgnoreCase(binary_name, ".exe")) {
                const exe_name = try std.fmt.allocPrint(allocator, "{s}.exe", .{binary_name});
                defer allocator.free(exe_name);
                const exe_candidate = try std.fs.path.join(allocator, &.{ dir, exe_name });
                defer allocator.free(exe_candidate);
                if (fileExists(exe_candidate)) return true;
            }
        }
    }

    return false;
}

pub fn summary(readiness: types.RuntimeReadiness) []const u8 {
    return switch (readiness) {
        .ready => "ready",
        .missing_binary => "missing_binary",
        .permission_denied => "permission_denied",
        .unwritable_store => "unwritable_store",
        .session_unavailable => "session_unavailable",
        .sandbox_blocked => "sandbox_blocked",
        .needs_reauth => "needs_reauth",
        .repair_in_progress => "repair_in_progress",
    };
}

pub fn resolvePath(
    allocator: std.mem.Allocator,
    spec: []const u8,
    env_var: ?[]const u8,
    config_dir: []const u8,
) !?[]const u8 {
    if (env_var) |name| {
        if (std.mem.eql(u8, spec, name)) return try allocator.dupe(u8, config_dir);
        if (std.mem.startsWith(u8, spec, name) and spec.len > name.len and (spec[name.len] == '/' or spec[name.len] == '\\')) {
            return try std.fs.path.join(allocator, &.{ config_dir, spec[name.len + 1 ..] });
        }
    }
    if (std.fs.path.isAbsolute(spec) or (spec.len > 0 and spec[0] == '~')) {
        return try paths.expandTilde(allocator, spec);
    }
    return null;
}

fn reauthMethodsFor(def: provider_schema.ProviderDefinition) []const []const u8 {
    return switch (def.repair.owner) {
        .upstream_cli_login => &.{"upstream_cli_login"},
        .oauth_mux_refresh => &.{"oauth_mux_refresh"},
        .external_secret_owner => &.{"external_secret_owner"},
        .manual_only => &.{"manual"},
    };
}

const DirectoryState = enum {
    ok,
    missing,
    access_denied,
    not_directory,
    other_error,
};

const FileState = enum {
    exists,
    missing,
    access_denied,
    other_error,
};

fn checkDirectory(path_value: []const u8) DirectoryState {
    var dir = openDirectory(path_value) catch |e| return switch (e) {
        error.FileNotFound => .missing,
        error.AccessDenied => .access_denied,
        error.NotDir => .not_directory,
        else => .other_error,
    };
    dir.close();
    return .ok;
}

fn checkFile(path_value: []const u8) FileState {
    const file = if (std.fs.path.isAbsolute(path_value))
        std.fs.openFileAbsolute(path_value, .{}) catch |e| return switch (e) {
            error.FileNotFound => .missing,
            error.AccessDenied => .access_denied,
            else => .other_error,
        }
    else
        std.fs.cwd().openFile(path_value, .{}) catch |e| return switch (e) {
            error.FileNotFound => .missing,
            error.AccessDenied => .access_denied,
            else => .other_error,
        };
    file.close();
    return .exists;
}

fn openDirectory(path_value: []const u8) !std.fs.Dir {
    if (std.fs.path.isAbsolute(path_value)) {
        return std.fs.openDirAbsolute(path_value, .{});
    }
    return std.fs.cwd().openDir(path_value, .{});
}

fn canWriteDirectoryMarker(allocator: std.mem.Allocator, path_value: []const u8) bool {
    var dir = openDirectory(path_value) catch return false;
    defer dir.close();

    const marker = std.fmt.allocPrint(allocator, ".oauth-mux-runtime-check-{d}", .{std.time.nanoTimestamp()}) catch return false;
    defer allocator.free(marker);

    const file = dir.createFile(marker, .{ .exclusive = true }) catch return false;
    file.close();
    dir.deleteFile(marker) catch {};
    return true;
}

pub fn fileExists(path_value: []const u8) bool {
    const file = if (std.fs.path.isAbsolute(path_value))
        std.fs.openFileAbsolute(path_value, .{}) catch return false
    else
        std.fs.cwd().openFile(path_value, .{}) catch return false;
    file.close();
    return true;
}

fn pathDelimiter() u8 {
    return if (builtin.os.tag == .windows) ';' else ':';
}

test "routeReadiness reports missing command capability binary" {
    const missing_binary = "omux-runtime-missing-command-fixture";
    const def = provider_schema.ProviderDefinition{
        .name = "toy",
        .runtime = .{},
        .capabilities = &.{
            .{
                .name = "status",
                .probe = .{
                    .transport = .command,
                    .auth = .none,
                    .command = &.{missing_binary},
                    .budget = .free_command,
                },
            },
        },
    };

    const readiness = try providerReadiness(std.testing.allocator, def, "status");
    switch (readiness) {
        .missing_binary => |binary| try std.testing.expectEqualStrings(missing_binary, binary),
        else => return error.TestUnexpectedResult,
    }
}
