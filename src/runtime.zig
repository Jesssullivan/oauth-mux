const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");
const env = @import("env.zig");
const paths = @import("paths.zig");
const provider_schema = @import("provider_schema.zig");
const product_identity = @import("product_identity.zig");
const repair_state = @import("repair_state.zig");
const types = @import("types.zig");

pub const OauthMuxRuntimeIdentity = struct {
    binary_path: []const u8,
    binary_source: []const u8,
    binary_sha256: ?[]const u8,
    build_id: []const u8,
    version: []const u8,

    pub fn deinit(self: OauthMuxRuntimeIdentity, allocator: std.mem.Allocator) void {
        allocator.free(self.binary_path);
        if (self.binary_sha256) |sha| allocator.free(sha);
        allocator.free(self.build_id);
    }

    pub fn writeJson(self: OauthMuxRuntimeIdentity, writer: anytype) !void {
        try writer.writeByte('{');
        try self.writeJsonFields(writer);
        try writer.writeByte('}');
    }

    pub fn writeJsonFields(self: OauthMuxRuntimeIdentity, writer: anytype) !void {
        try writer.writeAll("\"binary_path\":");
        try std.json.stringify(self.binary_path, .{}, writer);
        try writer.writeAll(",\"binary_source\":");
        try std.json.stringify(self.binary_source, .{}, writer);
        try writer.writeAll(",\"binary_sha256\":");
        if (self.binary_sha256) |sha| {
            try std.json.stringify(sha, .{}, writer);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"build_id\":");
        try std.json.stringify(self.build_id, .{}, writer);
        try writer.writeAll(",\"version\":");
        try std.json.stringify(self.version, .{}, writer);
        try writer.writeAll(",\"path_printed\":true,\"binary_sha256_available\":");
        try writer.writeAll(if (self.binary_sha256 != null) "true" else "false");
    }
};

pub fn oauthMuxRuntimeIdentity(allocator: std.mem.Allocator, version: []const u8, default_build_id: []const u8) !OauthMuxRuntimeIdentity {
    const binary_path = std.fs.selfExePathAlloc(allocator) catch try allocator.dupe(u8, "unknown");
    errdefer allocator.free(binary_path);

    const binary_sha256 = hashFileSha256Hex(allocator, binary_path) catch null;
    errdefer if (binary_sha256) |sha| allocator.free(sha);

    const build_id = try allocator.dupe(u8, default_build_id);
    errdefer allocator.free(build_id);

    return .{
        .binary_path = binary_path,
        .binary_source = classifyOauthMuxBinarySource(binary_path),
        .binary_sha256 = binary_sha256,
        .build_id = build_id,
        .version = version,
    };
}

pub fn classifyOauthMuxBinarySource(path_value: []const u8) []const u8 {
    const known_executable = product_identity.isExecutableName(path_value);
    if (known_executable and std.mem.indexOf(u8, path_value, "/zig-out/bin/") != null) return "repo_local";
    if (known_executable and std.mem.indexOf(u8, path_value, "/.local/bin/") != null) return "user_local";
    if (known_executable and std.mem.indexOf(u8, path_value, "/Cellar/oauth-mux/") != null) return "homebrew";
    if (known_executable and std.mem.indexOf(u8, path_value, "/opt/homebrew/bin/") != null) return "homebrew";
    if (known_executable and std.mem.indexOf(u8, path_value, "/usr/local/bin/") != null) return "homebrew";
    if (std.mem.startsWith(u8, path_value, "/nix/store/")) return "nix_store";
    if (std.mem.indexOf(u8, path_value, "/node_modules/") != null) return "npm";
    return "path_or_installed";
}

pub fn hashFileSha256Hex(allocator: std.mem.Allocator, path_value: []const u8) ![]u8 {
    if (std.mem.eql(u8, path_value, "unknown")) return error.UnknownPath;

    const file = try std.fs.openFileAbsolute(path_value, .{});
    defer file.close();

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) break;
        hasher.update(buf[0..n]);
    }

    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    const hex = try allocator.alloc(u8, digest.len * 2);
    _ = std.fmt.bufPrint(hex, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch unreachable;
    return hex;
}

pub const RouteRef = struct {
    provider: []const u8,
    account: []const u8,
    capability: ?[]const u8 = null,
};

pub const RefreshRecovery = enum {
    none,
    retry,
    provider_reenroll,
};

pub const RefreshDisposition = struct {
    retryable: bool,
    quarantined: bool,
    recovery: RefreshRecovery,
    provider_reenroll_required: bool,
    stale_backup_restore_allowed: bool = false,
};

/// Exhaustive runtime policy for the shared refresh outcome. The stale backup
/// flag is false for every tag; a hard lineage can only recover through a
/// provider-owned re-enrollment action.
pub fn refreshDisposition(outcome: types.RefreshOutcome) RefreshDisposition {
    return switch (outcome) {
        .refreshed => .{
            .retryable = false,
            .quarantined = false,
            .recovery = .none,
            .provider_reenroll_required = false,
        },
        .transient_lock,
        .transient_network,
        .transient_store,
        .transient_endpoint,
        => .{
            .retryable = true,
            .quarantined = false,
            .recovery = .retry,
            .provider_reenroll_required = false,
        },
        .hard_lineage_invalidated => .{
            .retryable = false,
            .quarantined = true,
            .recovery = .provider_reenroll,
            .provider_reenroll_required = true,
        },
    };
}

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

fn refreshLineageReadiness(
    allocator: std.mem.Allocator,
    route: RouteRef,
) !?types.RuntimeReadiness {
    if (try repair_state.effectiveRefreshQuarantineForRoute(
        allocator,
        route.provider,
        route.account,
    )) |state| {
        return .{ .needs_reauth = .{
            .methods = &.{"provider_reenroll"},
            .reason = switch (state) {
                .indeterminate_lineage => "refresh_lineage_indeterminate",
                .hard_lineage_invalidated => "refresh_lineage_quarantined",
            },
        } };
    }
    const outcome = (try repair_state.refreshOutcomeForRoute(
        allocator,
        route.provider,
        route.account,
    )) orelse return null;
    const disposition = refreshDisposition(outcome);
    if (!disposition.quarantined) return null;
    return .{ .needs_reauth = .{
        .methods = &.{"provider_reenroll"},
        .reason = "refresh_lineage_quarantined",
    } };
}

pub fn routeReadiness(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    route: RouteRef,
    def: provider_schema.ProviderDefinition,
) !types.RuntimeReadiness {
    const prov = cfg.providers.map.get(route.provider) orelse return .{ .session_unavailable = "provider_config_missing" };
    const account = prov.accounts.map.get(route.account) orelse return .{ .session_unavailable = "account_config_missing" };
    if (try refreshLineageReadiness(allocator, route)) |readiness| return readiness;
    const provider_runtime = try providerReadiness(allocator, def, route.capability);
    if (!provider_runtime.isReady()) return provider_runtime;
    if (try repair_state.pendingHandoffProgress(allocator, .{
        .provider = route.provider,
        .account = route.account,
        .capability = route.capability,
    })) |progress| {
        return .{ .reauth_in_progress = progress };
    }
    if (try repair_state.probeRepairLock(allocator, route.provider, route.account)) |progress| {
        return .{ .repair_in_progress = progress };
    }
    const info = try accountInfo(allocator, prov, account, def, config.resolveProviderKind(cfg, route.provider));
    return info.readiness;
}

// TIN-2039: binary/path readiness WITHOUT the advisory repair-lock probe.
// For callers that have ALREADY acquired the per-account lock (the
// command-probe store guard), probing it again would falsely report
// repair_in_progress for the caller's own held lock. Same as routeReadiness
// minus that middle check.
pub fn routeReadinessHoldingLock(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    route: RouteRef,
    def: provider_schema.ProviderDefinition,
) !types.RuntimeReadiness {
    const prov = cfg.providers.map.get(route.provider) orelse return .{ .session_unavailable = "provider_config_missing" };
    const account = prov.accounts.map.get(route.account) orelse return .{ .session_unavailable = "account_config_missing" };
    if (try refreshLineageReadiness(allocator, route)) |readiness| return readiness;
    const provider_runtime = try providerReadiness(allocator, def, route.capability);
    if (!provider_runtime.isReady()) return provider_runtime;
    if (try repair_state.pendingHandoffProgress(allocator, .{
        .provider = route.provider,
        .account = route.account,
        .capability = route.capability,
    })) |progress| {
        return .{ .reauth_in_progress = progress };
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
        .reauth_in_progress => "reauth_in_progress",
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

test "classify oauth mux binary source" {
    try std.testing.expectEqualStrings("repo_local", classifyOauthMuxBinarySource("/repo/zig-out/bin/oauth-mux"));
    try std.testing.expectEqualStrings("repo_local", classifyOauthMuxBinarySource("/repo/zig-out/bin/omux"));
    try std.testing.expectEqualStrings("user_local", classifyOauthMuxBinarySource("/Users/me/.local/bin/oauth-mux"));
    try std.testing.expectEqualStrings("user_local", classifyOauthMuxBinarySource("/Users/me/.local/bin/omux"));
    try std.testing.expectEqualStrings("homebrew", classifyOauthMuxBinarySource("/opt/homebrew/Cellar/oauth-mux/0.1.7/bin/oauth-mux"));
    try std.testing.expectEqualStrings("homebrew", classifyOauthMuxBinarySource("/opt/homebrew/Cellar/oauth-mux/0.2.0/bin/omux"));
    try std.testing.expectEqualStrings("nix_store", classifyOauthMuxBinarySource("/nix/store/abc-oauth-mux-0.1.7/bin/oauth-mux"));
    try std.testing.expectEqualStrings("npm", classifyOauthMuxBinarySource("/tmp/app/node_modules/.bin/oauth-mux"));
    try std.testing.expectEqualStrings("path_or_installed", classifyOauthMuxBinarySource("/usr/bin/oauth-mux"));
}

test "refresh disposition exhaustively maps quarantine and recovery policy" {
    inline for (std.meta.fields(types.RefreshOutcome)) |field| {
        const outcome: types.RefreshOutcome = @enumFromInt(field.value);
        const disposition = refreshDisposition(outcome);
        try std.testing.expect(!disposition.stale_backup_restore_allowed);
        switch (outcome) {
            .refreshed => {
                try std.testing.expect(!disposition.retryable);
                try std.testing.expect(!disposition.quarantined);
                try std.testing.expectEqual(RefreshRecovery.none, disposition.recovery);
            },
            .transient_lock, .transient_network, .transient_store, .transient_endpoint => {
                try std.testing.expect(disposition.retryable);
                try std.testing.expect(!disposition.quarantined);
                try std.testing.expectEqual(RefreshRecovery.retry, disposition.recovery);
            },
            .hard_lineage_invalidated => {
                try std.testing.expect(!disposition.retryable);
                try std.testing.expect(disposition.quarantined);
                try std.testing.expect(disposition.provider_reenroll_required);
                try std.testing.expectEqual(RefreshRecovery.provider_reenroll, disposition.recovery);
            },
        }
    }
}

test "route readiness maps hard lineage to provider reenrollment only" {
    const allocator = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer scope.deinit(std.testing.allocator);
    scope.activate();

    const credential_path = try std.fs.path.join(
        allocator,
        &.{ scope.root, "lineage.json" },
    );
    defer allocator.free(credential_path);
    {
        const credential = try std.fs.createFileAbsolute(credential_path, .{
            .mode = 0o600,
        });
        defer credential.close();
        try credential.writeAll(
            "{\"access_token\":\"at\",\"refresh_token\":\"rt\",\"account_id\":\"identity\"}",
        );
    }
    const cfg_json = try std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "oauth_mux_refresh", "proactive_refresh": "oauth_refresh_token" }},
        \\      "credential": {{
        \\        "access_token_path": "access_token",
        \\        "refresh_token_path": "refresh_token",
        \\        "identity_claim_path": "account_id"
        \\      }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{ "kind": "toy", "accounts": {{
        \\      "transient": {{ "secret": {{ "backend": "env", "variable": "OMUX_UNUSED" }} }},
        \\      "lineage": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\    }} }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{credential_path},
    );
    defer allocator.free(cfg_json);
    const parsed = try config.loadFromBytes(allocator, cfg_json);
    defer parsed.deinit();
    try repair_state.appendEvent(allocator, repair_state.refreshEvent(.{
        .provider = "toy",
        .account = "transient",
        .outcome = .transient_endpoint,
    }));
    const acct_cfg = parsed.value.providers.map.get("toy").?.accounts.map.get("lineage").?;
    try repair_state.establishHardRefreshQuarantineForTest(
        allocator,
        "toy",
        "lineage",
        try config.resolveSecretBackend(acct_cfg.secret),
        config.resolveProviderDefinition(parsed.value, "toy"),
    );
    try std.fs.deleteFileAbsolute(credential_path);

    const def = config.resolveProviderDefinition(parsed.value, "toy");
    const transient = try routeReadiness(allocator, parsed.value, .{
        .provider = "toy",
        .account = "transient",
    }, def);
    try std.testing.expect(transient.isReady());

    const hard = try routeReadiness(allocator, parsed.value, .{
        .provider = "toy",
        .account = "lineage",
    }, def);
    switch (hard) {
        .needs_reauth => |info| {
            try std.testing.expectEqualStrings("refresh_lineage_quarantined", info.reason);
            try std.testing.expectEqual(@as(usize, 1), info.methods.len);
            try std.testing.expectEqualStrings("provider_reenroll", info.methods[0]);
        },
        else => return error.TestUnexpectedResult,
    }
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

test "routeReadiness reports pending reauth handoff distinctly" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    var overrides = std.process.EnvMap.init(std.testing.allocator);
    defer overrides.deinit();
    try overrides.put("OMUX_STATE_DIR", root);
    try overrides.put("OMUX_RUNTIME_DIR", root);
    env.test_overrides = &overrides;
    defer env.test_overrides = null;

    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": { "secret": { "backend": "env", "variable": "OMUX_TEST_SECRET_THAT_IS_NOT_SET" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    try repair_state.appendEvent(std.testing.allocator, .{
        .kind = "daemon_handoff",
        .provider = "toy",
        .account = "default",
        .capability = "status",
        .action = "reauth_start",
        .outcome = "handoff_queued",
        .reason = "reauth_user_mediated",
        .interactive = true,
        .mutating = true,
    });

    const readiness = try routeReadiness(std.testing.allocator, parsed.value, .{
        .provider = "toy",
        .account = "default",
        .capability = "status",
    }, .{ .name = "toy" });
    switch (readiness) {
        .reauth_in_progress => |info| {
            try std.testing.expectEqualStrings("default", info.account);
            try std.testing.expect(info.started_at > 0);
        },
        else => return error.TestUnexpectedResult,
    }
}
