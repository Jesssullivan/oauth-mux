//! Experimental account-scoped Claude login through an owned browser helper.
//!
//! Preview rendering lives at the CLI boundary and never calls this module.
//! Confirmed execution resolves one configured account, requires a noncanonical
//! CLAUDE_CONFIG_DIR, acquires account and credential-store repair flocks, and
//! runs the provider's own `claude auth login`. Official Claude must honor
//! BROWSER/PATH and invoke the owned helper; environment shims cannot sandbox
//! an absolute opener bypass.
//! Post-spawn workspaces are preserved for explicit manual cleanup because the
//! immediate browser launcher process does not prove descendant quiescence.

const std = @import("std");
const builtin = @import("builtin");
const browser_launch = @import("browser_launch.zig");
const child_authority = @import("../adapters/claude/child_authority.zig");
const config = @import("../config.zig");
const env_mod = @import("../env.zig");
const os_account = @import("../os_account.zig");
const paths = @import("../paths.zig");
const provider_schema = @import("../provider_schema.zig");
const repair_state = @import("../repair_state.zig");

pub const LoginError = error{
    UnsupportedProvider,
    ProviderNotConfigured,
    ProviderKindMismatch,
    AccountNotConfigured,
    ConfigDirMissing,
    ConfigDirNotAbsolute,
    ConfigDirCanonical,
    ConfigDirEnvMismatch,
    ConfigDirUnavailable,
    ConfigDirSymlink,
    ConfigDirChanged,
    ConfigDirCustodyViolation,
    AccountConfigDirOverlap,
    SecretStoreMismatch,
    BrowserUnavailable,
    RuntimeCustodyViolation,
    RepairInProgress,
    LockFailed,
    WorkspaceCreateFailed,
    WorkspaceCleanupFailed,
    ProviderSpawnFailed,
    UnsupportedPlatform,
    AccountAuthorityUnavailable,
    OutOfMemory,
};

pub const ConfigDirIdentity = struct {
    device: u64,
    inode: u64,
    parent_device: u64,
    parent_inode: u64,
};

pub const ProviderTermination = union(enum) {
    exited: u8,
    terminated,
};

pub const WorkspaceDisposition = enum {
    preserved_manual_cleanup,
};

pub const RunOutcome = struct {
    provider: ProviderTermination,
    browser_helper_observed: bool,
    workspace_path: []u8,
    workspace_disposition: WorkspaceDisposition = .preserved_manual_cleanup,

    pub fn deinit(self: *RunOutcome, allocator: std.mem.Allocator) void {
        allocator.free(self.workspace_path);
        self.* = undefined;
    }
};

pub const ConfiguredAccount = struct {
    config_dir: []u8,
    canonical_dir: []u8,
    store_lock_key: [64]u8,
    effective_account: ?[]u8,

    pub fn deinit(self: *ConfiguredAccount, allocator: std.mem.Allocator) void {
        if (self.effective_account) |account| allocator.free(account);
        allocator.free(self.canonical_dir);
        allocator.free(self.config_dir);
        self.* = undefined;
    }
};

/// Resolve the account without reading its credential backend. The path used as
/// CLAUDE_CONFIG_DIR is intentionally not realpath'd: Claude's keychain service
/// hash is derived from this exact expanded string.
pub fn resolveConfiguredAccount(
    allocator: std.mem.Allocator,
    home: []const u8,
    cfg: config.Config,
    provider_name: []const u8,
    label: []const u8,
) LoginError!ConfiguredAccount {
    var effective_account: ?[]u8 = null;
    if (comptime builtin.os.tag == .macos) {
        effective_account = os_account.effectiveUserNameAlloc(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.AccountAuthorityUnavailable,
        };
    }
    defer if (effective_account) |account| allocator.free(account);
    return resolveConfiguredAccountWithAuthority(
        allocator,
        home,
        effective_account,
        cfg,
        provider_name,
        label,
    );
}

fn resolveConfiguredAccountWithAuthority(
    allocator: std.mem.Allocator,
    home: []const u8,
    effective_account: ?[]const u8,
    cfg: config.Config,
    provider_name: []const u8,
    label: []const u8,
) LoginError!ConfiguredAccount {
    if (!std.mem.eql(u8, provider_name, "claude")) return error.UnsupportedProvider;
    if (!std.fs.path.isAbsolute(home)) return error.ConfigDirNotAbsolute;

    const provider_cfg = cfg.providers.map.get(provider_name) orelse
        return error.ProviderNotConfigured;
    if (!std.mem.eql(u8, provider_cfg.kind, "claude"))
        return error.ProviderKindMismatch;
    const config_dir_env = provider_cfg.config_dir_env orelse "CLAUDE_CONFIG_DIR";
    if (!std.mem.eql(u8, config_dir_env, "CLAUDE_CONFIG_DIR"))
        return error.ConfigDirEnvMismatch;

    const account_cfg = provider_cfg.accounts.map.get(label) orelse
        return error.AccountNotConfigured;
    const raw_dir = account_cfg.config_dir orelse return error.ConfigDirMissing;
    const expanded = try expandHomeAlloc(allocator, home, raw_dir);
    errdefer allocator.free(expanded);
    if (!std.fs.path.isAbsolute(expanded)) return error.ConfigDirNotAbsolute;

    const normalized_for_compare = std.fs.path.resolve(allocator, &.{expanded}) catch
        return error.OutOfMemory;
    defer allocator.free(normalized_for_compare);
    const canonical = std.fs.path.resolve(allocator, &.{ home, ".claude" }) catch
        return error.OutOfMemory;
    errdefer allocator.free(canonical);
    if (child_authority.configDirPathsOverlap(normalized_for_compare, canonical))
        return error.ConfigDirCanonical;

    try validateClaudeAccountStore(allocator, home, effective_account, account_cfg, expanded, canonical);
    try rejectSiblingClaudeConfigOverlap(
        allocator,
        home,
        effective_account,
        cfg,
        provider_name,
        label,
        normalized_for_compare,
        canonical,
    );

    const backend = config.resolveSecretBackend(account_cfg.secret) catch
        return error.SecretStoreMismatch;
    const store_lock_key = repair_state.refreshStoreFingerprint(
        allocator,
        provider_name,
        backend,
    ) catch return error.OutOfMemory;
    const owned_effective_account = if (effective_account) |account|
        allocator.dupe(u8, account) catch return error.OutOfMemory
    else
        null;
    errdefer if (owned_effective_account) |account| allocator.free(account);
    return .{
        .config_dir = expanded,
        .canonical_dir = canonical,
        .store_lock_key = store_lock_key,
        .effective_account = owned_effective_account,
    };
}

fn rejectSiblingClaudeConfigOverlap(
    allocator: std.mem.Allocator,
    home: []const u8,
    effective_account: ?[]const u8,
    cfg: config.Config,
    selected_provider: []const u8,
    selected_label: []const u8,
    selected_dir: []const u8,
    canonical_dir: []const u8,
) LoginError!void {
    var provider_it = cfg.providers.map.iterator();
    while (provider_it.next()) |provider_entry| {
        const provider_name = provider_entry.key_ptr.*;
        if (config.resolveProviderKind(cfg, provider_name) != .claude) continue;
        var account_it = provider_entry.value_ptr.accounts.map.iterator();
        while (account_it.next()) |account_entry| {
            const account_label = account_entry.key_ptr.*;
            if (std.mem.eql(u8, provider_name, selected_provider) and
                std.mem.eql(u8, account_label, selected_label)) continue;
            const raw_sibling_dir = account_entry.value_ptr.config_dir orelse continue;
            const sibling_exact = try expandHomeAlloc(allocator, home, raw_sibling_dir);
            defer allocator.free(sibling_exact);
            if (!std.fs.path.isAbsolute(sibling_exact)) return error.ConfigDirNotAbsolute;
            try validateClaudeAccountStore(
                allocator,
                home,
                effective_account,
                account_entry.value_ptr.*,
                sibling_exact,
                canonical_dir,
            );
            const sibling_dir = std.fs.path.resolve(allocator, &.{sibling_exact}) catch
                return error.OutOfMemory;
            defer allocator.free(sibling_dir);
            child_authority.refuseConfigDirOverlap(
                allocator,
                selected_dir,
                sibling_dir,
            ) catch |err| switch (err) {
                error.ManagedConfigDirOverlap => return error.AccountConfigDirOverlap,
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.ConfigDirUnavailable,
            };
        }
    }
}

fn validateClaudeAccountStore(
    allocator: std.mem.Allocator,
    home: []const u8,
    effective_account: ?[]const u8,
    account: config.AccountConfig,
    exact_config_dir: []const u8,
    canonical_dir: []const u8,
) LoginError!void {
    const secret = account.secret;
    if (comptime builtin.os.tag == .macos) {
        if (!std.mem.eql(u8, secret.backend, "keychain")) return error.SecretStoreMismatch;
        const normalized = std.fs.path.resolve(allocator, &.{exact_config_dir}) catch
            return error.OutOfMemory;
        defer allocator.free(normalized);
        const expected_service = if (child_authority.configDirPathsOverlap(normalized, canonical_dir))
            provider_schema.claude_keychain_service_base
        else blk: {
            const derived = provider_schema.claudeKeychainService(allocator, exact_config_dir) catch
                return error.OutOfMemory;
            defer allocator.free(derived);
            const configured = secret.service orelse return error.SecretStoreMismatch;
            if (!std.mem.eql(u8, configured, derived)) return error.SecretStoreMismatch;
            break :blk configured;
        };
        const configured_service = secret.service orelse return error.SecretStoreMismatch;
        const expected_account = effective_account orelse return error.SecretStoreMismatch;
        if (!std.mem.eql(u8, configured_service, expected_service) or
            secret.account == null or
            !std.mem.eql(u8, secret.account.?, expected_account) or
            secret.path != null or secret.variable != null or secret.command != null or
            secret.key != null or secret.key_path != null)
        {
            return error.SecretStoreMismatch;
        }
        return;
    }
    if (comptime builtin.os.tag == .linux) {
        if (!std.mem.eql(u8, secret.backend, "file")) return error.SecretStoreMismatch;
        const raw_path = secret.path orelse return error.SecretStoreMismatch;
        const configured_path = try expandHomeAlloc(allocator, home, raw_path);
        defer allocator.free(configured_path);
        const configured_normalized = std.fs.path.resolve(allocator, &.{configured_path}) catch
            return error.OutOfMemory;
        defer allocator.free(configured_normalized);
        const expected_path = std.fs.path.join(allocator, &.{ exact_config_dir, ".credentials.json" }) catch
            return error.OutOfMemory;
        defer allocator.free(expected_path);
        const expected_normalized = std.fs.path.resolve(allocator, &.{expected_path}) catch
            return error.OutOfMemory;
        defer allocator.free(expected_normalized);
        if (!std.mem.eql(u8, configured_normalized, expected_normalized) or
            secret.service != null or secret.account != null or secret.variable != null or
            secret.command != null or secret.key != null or secret.key_path != null)
        {
            return error.SecretStoreMismatch;
        }
        return;
    }
    return error.UnsupportedPlatform;
}

fn expandHomeAlloc(
    allocator: std.mem.Allocator,
    home: []const u8,
    value: []const u8,
) LoginError![]u8 {
    if (value.len == 0) return error.ConfigDirMissing;
    if (value[0] != '~') return allocator.dupe(u8, value) catch error.OutOfMemory;
    if (value.len == 1) return allocator.dupe(u8, home) catch error.OutOfMemory;
    if (value.len < 2 or (value[1] != '/' and value[1] != '\\'))
        return error.ConfigDirNotAbsolute;
    return std.fs.path.join(allocator, &.{ home, value[2..] }) catch
        error.OutOfMemory;
}

pub const Workspace = struct {
    root: []u8,
    shim_dir: []u8,
    open_shim: []u8,
    profile_dir: []u8,
    browser_marker: []u8,

    pub fn deinit(self: *Workspace, allocator: std.mem.Allocator) void {
        allocator.free(self.browser_marker);
        allocator.free(self.profile_dir);
        allocator.free(self.open_shim);
        allocator.free(self.shim_dir);
        allocator.free(self.root);
        self.* = undefined;
    }
};

pub const EnvPair = struct {
    key: []const u8,
    value: []const u8,
};

pub const RunSpec = struct {
    argv: []const []const u8,
    env: []const EnvPair,
};

pub const FindBrowserFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
) error{ BrowserUnavailable, OutOfMemory }![]const u8;
pub const ValidateDirFn = *const fn (
    ctx: *anyopaque,
    path: []const u8,
    canonical_path: []const u8,
    expected: ?ConfigDirIdentity,
) error{ ConfigDirUnavailable, ConfigDirCanonical, ConfigDirSymlink, ConfigDirChanged, ConfigDirCustodyViolation }!ConfigDirIdentity;
pub const ValidateRuntimeFn = *const fn (
    ctx: *anyopaque,
) error{ RuntimeCustodyViolation, UnsupportedPlatform, OutOfMemory }!void;
pub const PrepareWorkspaceFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
) error{ WorkspaceCreateFailed, RuntimeCustodyViolation, UnsupportedPlatform, OutOfMemory }!Workspace;
pub const CleanupWorkspaceFn = *const fn (
    ctx: *anyopaque,
    root: []const u8,
) error{WorkspaceCleanupFailed}!void;
pub const VerifyBrowserFn = *const fn (
    ctx: *anyopaque,
    marker_path: []const u8,
) bool;
pub const AcquireLocksFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    provider: []const u8,
    label: []const u8,
    store_lock_key: []const u8,
) error{ RepairInProgress, LockFailed, OutOfMemory }!void;
pub const ReleaseLocksFn = *const fn (ctx: *anyopaque) void;
pub const RunProviderFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    spec: RunSpec,
) error{ ProviderSpawnFailed, OutOfMemory }!ProviderTermination;

pub const Seams = struct {
    find_browser: FindBrowserFn,
    validate_dir: ValidateDirFn,
    validate_runtime: ValidateRuntimeFn,
    prepare_workspace: PrepareWorkspaceFn,
    cleanup_workspace: CleanupWorkspaceFn,
    verify_browser: VerifyBrowserFn,
    acquire_locks: AcquireLocksFn,
    release_locks: ReleaseLocksFn,
    run_provider: RunProviderFn,
    browser_ctx: *anyopaque,
    fs_ctx: *anyopaque,
    lock_ctx: *anyopaque,
    process_ctx: *anyopaque,
};

pub const RunOptions = struct {
    label: []const u8,
    config_dir: []const u8,
    canonical_dir: []const u8,
    store_lock_key: []const u8 = "",
    effective_account: ?[]const u8 = null,
    inherited_path: []const u8,
};

const open_shim_body =
    \\#!/bin/sh
    \\set -eu
    \\url=""
    \\for arg in "$@"; do
    \\  case "$arg" in
    \\    http://*|https://*) url="$arg" ;;
    \\  esac
    \\done
    \\if [ -z "$url" ]; then
    \\  echo "omux: owned Claude browser helper refused an invocation without an http(s) URL" >&2
    \\  exit 1
    \\fi
    \\: "${OMUX_CLAUDE_BROWSER_BIN:?}"
    \\: "${OMUX_CLAUDE_BROWSER_PROFILE:?}"
    \\: "${OMUX_CLAUDE_BROWSER_MARKER:?}"
    \\umask 077
    \\"$OMUX_CLAUDE_BROWSER_BIN" --user-data-dir="$OMUX_CLAUDE_BROWSER_PROFILE" --incognito --new-window --no-first-run --no-default-browser-check --disable-background-mode "$url" >/dev/null 2>&1 &
    \\browser_pid=$!
    \\if wait "$browser_pid"; then
    \\  browser_status=0
    \\else
    \\  browser_status=$?
    \\fi
    \\: >"$OMUX_CLAUDE_BROWSER_MARKER"
    \\exit "$browser_status"
;

pub fn runWithSeams(
    allocator: std.mem.Allocator,
    options: RunOptions,
    seams: Seams,
) LoginError!RunOutcome {
    if (!std.fs.path.isAbsolute(options.config_dir)) return error.ConfigDirNotAbsolute;

    const config_identity = seams.validate_dir(
        seams.fs_ctx,
        options.config_dir,
        options.canonical_dir,
        null,
    ) catch |err| switch (err) {
        error.ConfigDirUnavailable => return error.ConfigDirUnavailable,
        error.ConfigDirCanonical => return error.ConfigDirCanonical,
        error.ConfigDirSymlink => return error.ConfigDirSymlink,
        error.ConfigDirChanged => return error.ConfigDirChanged,
        error.ConfigDirCustodyViolation => return error.ConfigDirCustodyViolation,
    };
    seams.validate_runtime(seams.fs_ctx) catch |err| switch (err) {
        error.RuntimeCustodyViolation => return error.RuntimeCustodyViolation,
        error.UnsupportedPlatform => return error.UnsupportedPlatform,
        error.OutOfMemory => return error.OutOfMemory,
    };
    const browser_path = seams.find_browser(allocator, seams.browser_ctx) catch |err| switch (err) {
        error.BrowserUnavailable => return error.BrowserUnavailable,
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer allocator.free(browser_path);

    if (options.store_lock_key.len == 0) return error.LockFailed;
    seams.acquire_locks(
        allocator,
        seams.lock_ctx,
        "claude",
        options.label,
        options.store_lock_key,
    ) catch |err| switch (err) {
        error.RepairInProgress => return error.RepairInProgress,
        error.OutOfMemory => return error.OutOfMemory,
        error.LockFailed => return error.LockFailed,
    };
    defer seams.release_locks(seams.lock_ctx);

    var workspace = seams.prepare_workspace(allocator, seams.fs_ctx) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.UnsupportedPlatform => return error.UnsupportedPlatform,
        error.WorkspaceCreateFailed => return error.WorkspaceCreateFailed,
        error.RuntimeCustodyViolation => return error.RuntimeCustodyViolation,
    };
    defer workspace.deinit(allocator);
    var cleanup_pending = true;
    defer if (cleanup_pending) {
        seams.cleanup_workspace(seams.fs_ctx, workspace.root) catch {};
    };

    const child_path = try sanitizedChildPathAlloc(allocator, workspace.shim_dir, options.inherited_path);
    defer allocator.free(child_path);
    const preserved_workspace = allocator.dupe(u8, workspace.root) catch return error.OutOfMemory;
    var preserved_workspace_pending = true;
    defer if (preserved_workspace_pending) allocator.free(preserved_workspace);

    const argv = [_][]const u8{ "claude", "auth", "login" };
    const env = [_]EnvPair{
        .{ .key = "CLAUDE_CONFIG_DIR", .value = options.config_dir },
        .{ .key = "PATH", .value = child_path },
        .{ .key = "BROWSER", .value = workspace.open_shim },
        .{ .key = "OMUX_CLAUDE_BROWSER_BIN", .value = browser_path },
        .{ .key = "OMUX_CLAUDE_BROWSER_PROFILE", .value = workspace.profile_dir },
        .{ .key = "OMUX_CLAUDE_BROWSER_MARKER", .value = workspace.browser_marker },
        .{ .key = "USER", .value = options.effective_account orelse "" },
        .{ .key = "LOGNAME", .value = options.effective_account orelse "" },
    };
    const child_env = env[0..if (options.effective_account == null) 6 else env.len];
    // Re-open and identity-check the configured directory immediately before
    // spawn. This detects changes visible at that check; it does not bind the
    // string path that the provider resolves after spawn.
    _ = seams.validate_dir(
        seams.fs_ctx,
        options.config_dir,
        options.canonical_dir,
        config_identity,
    ) catch |err| switch (err) {
        error.ConfigDirUnavailable => return error.ConfigDirUnavailable,
        error.ConfigDirCanonical => return error.ConfigDirCanonical,
        error.ConfigDirSymlink => return error.ConfigDirSymlink,
        error.ConfigDirChanged => return error.ConfigDirChanged,
        error.ConfigDirCustodyViolation => return error.ConfigDirCustodyViolation,
    };

    const process_result = seams.run_provider(
        allocator,
        seams.process_ctx,
        .{ .argv = &argv, .env = child_env },
    );
    if (process_result) |provider| {
        // A launcher PID exiting does not prove that Chromium descendants or
        // the profile are quiescent. Preserve every post-spawn workspace and
        // make manual cleanup explicit at the CLI boundary.
        const helper_observed = seams.verify_browser(seams.fs_ctx, workspace.browser_marker);
        cleanup_pending = false;
        preserved_workspace_pending = false;
        return .{
            .provider = provider,
            .browser_helper_observed = helper_observed,
            .workspace_path = preserved_workspace,
        };
    } else |process_err| switch (process_err) {
        error.OutOfMemory, error.ProviderSpawnFailed => {
            const cleanup_result = seams.cleanup_workspace(seams.fs_ctx, workspace.root);
            cleanup_pending = false;
            cleanup_result catch return error.WorkspaceCleanupFailed;
            return process_err;
        },
    }
}

fn sanitizedChildPathAlloc(
    allocator: std.mem.Allocator,
    shim_dir: []const u8,
    inherited_path: []const u8,
) LoginError![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    result.appendSlice(shim_dir) catch return error.OutOfMemory;
    var entries = std.mem.splitScalar(u8, inherited_path, std.fs.path.delimiter);
    while (entries.next()) |entry| {
        if (entry.len == 0 or !std.fs.path.isAbsolute(entry)) continue;
        result.append(std.fs.path.delimiter) catch return error.OutOfMemory;
        result.appendSlice(entry) catch return error.OutOfMemory;
    }
    return result.toOwnedSlice() catch error.OutOfMemory;
}

const SystemContext = struct {
    allocator: std.mem.Allocator,
    inherited_env: *const std.process.EnvMap,
    active_config: config.Config,
    account_lock: ?repair_state.RepairLock = null,
    store_lock: ?repair_state.RepairLock = null,
    held_config_dir: ?std.fs.Dir = null,
    held_config_parent: ?std.fs.Dir = null,
    runtime_dir: ?[]const u8 = null,
    workspace_parent: ?std.fs.Dir = null,
    workspace_name: ?[]u8 = null,
};

pub fn run(
    allocator: std.mem.Allocator,
    options: RunOptions,
    inherited_env: *const std.process.EnvMap,
    active_config: *const config.Config,
) LoginError!RunOutcome {
    var system = SystemContext{
        .allocator = allocator,
        .inherited_env = inherited_env,
        .active_config = active_config.*,
    };
    defer if (system.held_config_dir) |*dir| dir.close();
    defer if (system.held_config_parent) |*dir| dir.close();
    defer if (system.workspace_parent) |*dir| dir.close();
    defer if (system.workspace_name) |name| allocator.free(name);
    defer if (system.runtime_dir) |runtime_dir| allocator.free(runtime_dir);
    return runWithSeams(allocator, options, .{
        .find_browser = systemFindBrowser,
        .validate_dir = systemValidateDir,
        .validate_runtime = systemValidateRuntime,
        .prepare_workspace = systemPrepareWorkspace,
        .cleanup_workspace = systemCleanupWorkspace,
        .verify_browser = systemVerifyBrowser,
        .acquire_locks = systemAcquireLocks,
        .release_locks = systemReleaseLocks,
        .run_provider = systemRunProvider,
        .browser_ctx = @ptrCast(&system),
        .fs_ctx = @ptrCast(&system),
        .lock_ctx = @ptrCast(&system),
        .process_ctx = @ptrCast(&system),
    });
}

fn systemFindBrowser(
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
) error{ BrowserUnavailable, OutOfMemory }![]const u8 {
    const system: *SystemContext = @ptrCast(@alignCast(ctx));
    return browser_launch.requireValidatedChromiumAlloc(
        allocator,
        systemWhich,
        @ptrCast(system),
        systemValidateChromium,
        @ptrCast(system),
    ) catch |err| switch (err) {
        error.BrowserNotFound => error.BrowserUnavailable,
        error.OutOfMemory => error.OutOfMemory,
        else => unreachable,
    };
}

fn systemWhich(
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    requested: []const u8,
) error{OutOfMemory}!?[]const u8 {
    const system: *SystemContext = @ptrCast(@alignCast(ctx));
    if (std.mem.startsWith(u8, requested, "~/")) {
        const home = system.inherited_env.get("HOME") orelse return null;
        const candidate = std.fs.path.join(allocator, &.{ home, requested[2..] }) catch
            return error.OutOfMemory;
        defer allocator.free(candidate);
        if (isExecutable(candidate))
            return std.fs.path.resolve(allocator, &.{candidate}) catch error.OutOfMemory;
        return null;
    }
    if (std.fs.path.isAbsolute(requested)) {
        if (!isExecutable(requested)) return null;
        return std.fs.path.resolve(allocator, &.{requested}) catch error.OutOfMemory;
    }
    const search_path = system.inherited_env.get("PATH") orelse return null;
    var dirs = std.mem.splitScalar(u8, search_path, std.fs.path.delimiter);
    while (nextAbsolutePathEntry(&dirs)) |raw_dir| {
        const candidate = std.fs.path.join(allocator, &.{ raw_dir, requested }) catch
            return error.OutOfMemory;
        defer allocator.free(candidate);
        if (isExecutable(candidate))
            return std.fs.path.resolve(allocator, &.{candidate}) catch error.OutOfMemory;
    }
    return null;
}

fn systemValidateChromium(
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    executable: []const u8,
) error{ OutOfMemory, ValidationFailed }!bool {
    const system: *SystemContext = @ptrCast(@alignCast(ctx));
    var validation_env = buildProviderLoginEnv(
        allocator,
        system.inherited_env,
        system.active_config,
        &.{},
    ) catch return error.OutOfMemory;
    defer validation_env.deinit();
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ executable, "--version" },
        .env_map = &validation_env,
        .max_output_bytes = 4096,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.ValidationFailed,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    const clean_exit = switch (result.term) {
        .Exited => |code| code == 0,
        else => false,
    };
    if (!clean_exit) return false;
    const signatures = [_][]const u8{
        "google chrome",
        "chromium",
        "brave browser",
        "microsoft edge",
    };
    for (signatures) |signature| {
        if (std.ascii.indexOfIgnoreCase(result.stdout, signature) != null or
            std.ascii.indexOfIgnoreCase(result.stderr, signature) != null)
        {
            return true;
        }
    }
    return false;
}

fn nextAbsolutePathEntry(
    entries: *std.mem.SplitIterator(u8, .scalar),
) ?[]const u8 {
    while (entries.next()) |entry| {
        if (entry.len != 0 and std.fs.path.isAbsolute(entry)) return entry;
    }
    return null;
}

fn isExecutable(path: []const u8) bool {
    const stat = std.fs.cwd().statFile(path) catch return false;
    if (stat.kind != .file) return false;
    if (comptime builtin.os.tag == .windows) return true;
    std.posix.access(path, std.posix.X_OK) catch return false;
    return true;
}

const PosixIdentity = struct {
    extern "c" fn geteuid() std.c.uid_t;
};

fn effectiveUid() std.posix.uid_t {
    if (comptime builtin.os.tag == .linux and !builtin.link_libc) {
        return std.os.linux.geteuid();
    }
    return @intCast(PosixIdentity.geteuid());
}

fn validateOwnedDirectoryStat(stat: anytype, require_private: bool) bool {
    if (stat.mode & std.posix.S.IFMT != std.posix.S.IFDIR) return false;
    if (stat.nlink == 0 or stat.uid != effectiveUid()) return false;
    if (stat.mode & 0o022 != 0) return false;
    if (require_private and stat.mode & 0o077 != 0) return false;
    return true;
}

fn validateNearestExistingRuntimeAncestor(
    allocator: std.mem.Allocator,
    runtime_dir: []const u8,
) error{ RuntimeCustodyViolation, OutOfMemory }!void {
    var candidate = allocator.dupe(u8, runtime_dir) catch return error.OutOfMemory;
    defer allocator.free(candidate);
    while (true) {
        if (std.fs.realpathAlloc(allocator, candidate)) |resolved| {
            defer allocator.free(resolved);
            var dir = std.fs.openDirAbsolute(resolved, .{ .no_follow = true }) catch
                return error.RuntimeCustodyViolation;
            defer dir.close();
            const stat = std.posix.fstat(dir.fd) catch return error.RuntimeCustodyViolation;
            if (!validateOwnedDirectoryStat(stat, false)) return error.RuntimeCustodyViolation;
            return;
        } else |err| switch (err) {
            error.FileNotFound => {},
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.RuntimeCustodyViolation,
        }
        const parent = std.fs.path.dirname(candidate) orelse
            return error.RuntimeCustodyViolation;
        if (parent.len == candidate.len) return error.RuntimeCustodyViolation;
        const next = allocator.dupe(u8, parent) catch return error.OutOfMemory;
        allocator.free(candidate);
        candidate = next;
    }
}

fn systemValidateRuntime(
    ctx: *anyopaque,
) error{ RuntimeCustodyViolation, UnsupportedPlatform, OutOfMemory }!void {
    const system: *SystemContext = @ptrCast(@alignCast(ctx));
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi)
        return error.UnsupportedPlatform;
    if (system.runtime_dir != null) return error.RuntimeCustodyViolation;
    const runtime_dir = paths.runtimeDir(system.allocator) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.RuntimeCustodyViolation,
    };
    errdefer system.allocator.free(runtime_dir);
    if (!std.fs.path.isAbsolute(runtime_dir)) return error.RuntimeCustodyViolation;
    try validateNearestExistingRuntimeAncestor(system.allocator, runtime_dir);
    system.runtime_dir = runtime_dir;
}

fn systemValidateDir(
    ctx: *anyopaque,
    path: []const u8,
    canonical_path: []const u8,
    expected: ?ConfigDirIdentity,
) error{ ConfigDirUnavailable, ConfigDirCanonical, ConfigDirSymlink, ConfigDirChanged, ConfigDirCustodyViolation }!ConfigDirIdentity {
    const system: *SystemContext = @ptrCast(@alignCast(ctx));
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi)
        return error.ConfigDirUnavailable;
    if (child_authority.configDirPathsOverlap(path, canonical_path))
        return error.ConfigDirCanonical;

    const path_stat = std.posix.fstatat(
        std.posix.AT.FDCWD,
        path,
        std.posix.AT.SYMLINK_NOFOLLOW,
    ) catch return error.ConfigDirUnavailable;
    if (path_stat.mode & std.posix.S.IFMT == std.posix.S.IFLNK)
        return error.ConfigDirSymlink;

    const base = std.fs.path.basename(path);
    const parent_path = std.fs.path.dirname(path) orelse return error.ConfigDirUnavailable;
    if (base.len == 0 or parent_path.len == 0) return error.ConfigDirUnavailable;
    const resolved_parent = std.fs.realpathAlloc(system.allocator, parent_path) catch
        return error.ConfigDirUnavailable;
    defer system.allocator.free(resolved_parent);
    const resolved = std.fs.realpathAlloc(system.allocator, path) catch
        return error.ConfigDirUnavailable;
    defer system.allocator.free(resolved);
    const actual_parent = std.fs.path.dirname(resolved) orelse return error.ConfigDirUnavailable;
    if (!std.mem.eql(u8, actual_parent, resolved_parent)) return error.ConfigDirChanged;

    const canonical_resolved = (child_authority.realpathLongestExisting(system.allocator, canonical_path) catch
        return error.ConfigDirUnavailable) orelse return error.ConfigDirUnavailable;
    defer system.allocator.free(canonical_resolved);
    if (child_authority.configDirPathsOverlap(resolved, canonical_resolved))
        return error.ConfigDirCanonical;

    var parent = std.fs.openDirAbsolute(resolved_parent, .{ .no_follow = true }) catch
        return error.ConfigDirUnavailable;
    var parent_owned = true;
    defer if (parent_owned) parent.close();
    const parent_stat = std.posix.fstat(parent.fd) catch return error.ConfigDirUnavailable;
    if (!validateOwnedDirectoryStat(parent_stat, false))
        return error.ConfigDirCustodyViolation;

    var candidate = parent.openDir(base, .{ .no_follow = true }) catch
        return error.ConfigDirUnavailable;
    var candidate_owned = true;
    defer if (candidate_owned) candidate.close();
    const stat = std.posix.fstat(candidate.fd) catch return error.ConfigDirUnavailable;
    if (!validateOwnedDirectoryStat(stat, false)) return error.ConfigDirCustodyViolation;
    const identity = ConfigDirIdentity{
        .device = @intCast(stat.dev),
        .inode = @intCast(stat.ino),
        .parent_device = @intCast(parent_stat.dev),
        .parent_inode = @intCast(parent_stat.ino),
    };

    if (expected) |expected_identity| {
        const held = if (system.held_config_dir) |*dir| dir else return error.ConfigDirChanged;
        const held_parent = if (system.held_config_parent) |*dir| dir else return error.ConfigDirChanged;
        const held_stat = std.posix.fstat(held.fd) catch
            return error.ConfigDirChanged;
        const held_parent_stat = std.posix.fstat(held_parent.fd) catch
            return error.ConfigDirChanged;
        const held_identity = ConfigDirIdentity{
            .device = @intCast(held_stat.dev),
            .inode = @intCast(held_stat.ino),
            .parent_device = @intCast(held_parent_stat.dev),
            .parent_inode = @intCast(held_parent_stat.ino),
        };
        if (!std.meta.eql(expected_identity, held_identity) or
            !std.meta.eql(expected_identity, identity))
        {
            return error.ConfigDirChanged;
        }
    } else {
        if (system.held_config_dir != null or system.held_config_parent != null)
            return error.ConfigDirChanged;
        system.held_config_parent = parent;
        parent_owned = false;
        system.held_config_dir = candidate;
        candidate_owned = false;
    }
    return identity;
}

fn systemPrepareWorkspace(
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
) error{ WorkspaceCreateFailed, RuntimeCustodyViolation, UnsupportedPlatform, OutOfMemory }!Workspace {
    const system: *SystemContext = @ptrCast(@alignCast(ctx));
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi)
        return error.UnsupportedPlatform;
    const runtime_dir = system.runtime_dir orelse return error.RuntimeCustodyViolation;
    if (system.workspace_parent != null or system.workspace_name != null)
        return error.RuntimeCustodyViolation;
    std.fs.cwd().makePath(runtime_dir) catch return error.WorkspaceCreateFailed;

    const runtime_stat = std.posix.fstatat(
        std.posix.AT.FDCWD,
        runtime_dir,
        std.posix.AT.SYMLINK_NOFOLLOW,
    ) catch return error.RuntimeCustodyViolation;
    if (runtime_stat.mode & std.posix.S.IFMT == std.posix.S.IFLNK)
        return error.RuntimeCustodyViolation;
    const resolved_runtime = std.fs.realpathAlloc(allocator, runtime_dir) catch
        return error.RuntimeCustodyViolation;
    defer allocator.free(resolved_runtime);
    var runtime = std.fs.openDirAbsolute(resolved_runtime, .{ .iterate = true, .no_follow = true }) catch
        return error.RuntimeCustodyViolation;
    var runtime_owned = true;
    defer if (runtime_owned) runtime.close();
    const opened_runtime_stat = std.posix.fstat(runtime.fd) catch
        return error.RuntimeCustodyViolation;
    if (!validateOwnedDirectoryStat(opened_runtime_stat, false))
        return error.RuntimeCustodyViolation;

    var root_name: ?[]u8 = null;
    for (0..16) |_| {
        var random_bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        const candidate_name = std.fmt.allocPrint(
            allocator,
            "claude-login-{s}",
            .{std.fmt.fmtSliceHexLower(&random_bytes)},
        ) catch return error.OutOfMemory;
        std.posix.mkdirat(runtime.fd, candidate_name, 0o700) catch |err| {
            allocator.free(candidate_name);
            if (err == error.PathAlreadyExists) continue;
            return error.WorkspaceCreateFailed;
        };
        root_name = candidate_name;
        break;
    }
    const name = root_name orelse return error.WorkspaceCreateFailed;
    var created = true;
    defer if (created) runtime.deleteTree(name) catch {};
    errdefer allocator.free(name);
    const root_path = std.fs.path.join(allocator, &.{ resolved_runtime, name }) catch
        return error.OutOfMemory;
    errdefer allocator.free(root_path);
    const root_parent = std.fs.path.dirname(root_path) orelse return error.RuntimeCustodyViolation;
    if (!std.mem.eql(u8, root_parent, resolved_runtime)) return error.RuntimeCustodyViolation;

    var root_dir = runtime.openDir(name, .{ .iterate = true, .no_follow = true }) catch
        return error.WorkspaceCreateFailed;
    defer root_dir.close();
    root_dir.chmod(0o700) catch return error.WorkspaceCreateFailed;
    const root_stat = std.posix.fstat(root_dir.fd) catch return error.RuntimeCustodyViolation;
    if (!validateOwnedDirectoryStat(root_stat, true)) return error.RuntimeCustodyViolation;
    root_dir.makeDir("shim") catch return error.WorkspaceCreateFailed;
    root_dir.makeDir("profile") catch return error.WorkspaceCreateFailed;
    var shim_dir_handle = root_dir.openDir("shim", .{ .no_follow = true }) catch
        return error.WorkspaceCreateFailed;
    defer shim_dir_handle.close();
    shim_dir_handle.chmod(0o700) catch return error.WorkspaceCreateFailed;
    const shim_stat = std.posix.fstat(shim_dir_handle.fd) catch return error.RuntimeCustodyViolation;
    if (!validateOwnedDirectoryStat(shim_stat, true)) return error.RuntimeCustodyViolation;
    var profile_handle = root_dir.openDir("profile", .{ .no_follow = true }) catch
        return error.WorkspaceCreateFailed;
    defer profile_handle.close();
    profile_handle.chmod(0o700) catch return error.WorkspaceCreateFailed;
    const profile_stat = std.posix.fstat(profile_handle.fd) catch return error.RuntimeCustodyViolation;
    if (!validateOwnedDirectoryStat(profile_stat, true)) return error.RuntimeCustodyViolation;

    const open_file = root_dir.createFile("shim/open", .{
        .exclusive = true,
        .mode = 0o700,
    }) catch return error.WorkspaceCreateFailed;
    defer open_file.close();
    open_file.writeAll(open_shim_body) catch return error.WorkspaceCreateFailed;
    const xdg_file = root_dir.createFile("shim/xdg-open", .{
        .exclusive = true,
        .mode = 0o700,
    }) catch return error.WorkspaceCreateFailed;
    defer xdg_file.close();
    xdg_file.writeAll(open_shim_body) catch return error.WorkspaceCreateFailed;

    const shim_dir = std.fs.path.join(allocator, &.{ root_path, "shim" }) catch
        return error.OutOfMemory;
    errdefer allocator.free(shim_dir);
    const open_shim = std.fs.path.join(allocator, &.{ shim_dir, "open" }) catch
        return error.OutOfMemory;
    errdefer allocator.free(open_shim);
    const profile_dir = std.fs.path.join(allocator, &.{ root_path, "profile" }) catch
        return error.OutOfMemory;
    errdefer allocator.free(profile_dir);
    const browser_marker = std.fs.path.join(allocator, &.{ root_path, "owned-helper-returned" }) catch
        return error.OutOfMemory;
    errdefer allocator.free(browser_marker);
    system.workspace_parent = runtime;
    runtime_owned = false;
    system.workspace_name = name;
    created = false;
    return .{
        .root = root_path,
        .shim_dir = shim_dir,
        .open_shim = open_shim,
        .profile_dir = profile_dir,
        .browser_marker = browser_marker,
    };
}

fn systemVerifyBrowser(ctx: *anyopaque, marker_path: []const u8) bool {
    _ = ctx;
    const stat = std.fs.cwd().statFile(marker_path) catch return false;
    return stat.kind == .file;
}

fn systemCleanupWorkspace(ctx: *anyopaque, root: []const u8) error{WorkspaceCleanupFailed}!void {
    const system: *SystemContext = @ptrCast(@alignCast(ctx));
    const parent = if (system.workspace_parent) |*dir| dir else return error.WorkspaceCleanupFailed;
    const name = system.workspace_name orelse return error.WorkspaceCleanupFailed;
    if (!std.mem.eql(u8, std.fs.path.basename(root), name))
        return error.WorkspaceCleanupFailed;
    parent.deleteTree(name) catch return error.WorkspaceCleanupFailed;
    parent.close();
    system.workspace_parent = null;
    system.allocator.free(name);
    system.workspace_name = null;
}

fn systemAcquireLocks(
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    provider: []const u8,
    label: []const u8,
    store_lock_key: []const u8,
) error{ RepairInProgress, LockFailed, OutOfMemory }!void {
    const system: *SystemContext = @ptrCast(@alignCast(ctx));
    if (system.account_lock != null or system.store_lock != null) return error.LockFailed;

    // Every caller takes the label lock before the canonical store lock. The
    // store lock reuses the refresh path's namespace, so login and keepalive
    // cannot mutate one rotating credential concurrently through aliases.
    var account_lock = repair_state.acquireRepairLock(allocator, provider, label) catch |err| switch (err) {
        error.RepairInProgress => return error.RepairInProgress,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.LockFailed,
    };
    errdefer account_lock.release();
    const store_lock = repair_state.acquireRepairLock(
        allocator,
        "refresh-store",
        store_lock_key,
    ) catch |err| switch (err) {
        error.RepairInProgress => return error.RepairInProgress,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.LockFailed,
    };
    system.account_lock = account_lock;
    system.store_lock = store_lock;
}

fn systemReleaseLocks(ctx: *anyopaque) void {
    const system: *SystemContext = @ptrCast(@alignCast(ctx));
    if (system.store_lock) |*lock| lock.release();
    system.store_lock = null;
    if (system.account_lock) |*lock| lock.release();
    system.account_lock = null;
}

fn systemRunProvider(
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    spec: RunSpec,
) error{ ProviderSpawnFailed, OutOfMemory }!ProviderTermination {
    const system: *SystemContext = @ptrCast(@alignCast(ctx));
    var child_env = buildProviderLoginEnv(
        allocator,
        system.inherited_env,
        system.active_config,
        spec.env,
    ) catch return error.OutOfMemory;
    defer child_env.deinit();

    var child = std.process.Child.init(spec.argv, allocator);
    child.env_map = &child_env;
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    child.spawn() catch return error.ProviderSpawnFailed;
    const term = child.wait() catch return .terminated;
    return switch (term) {
        .Exited => |code| .{ .exited = code },
        else => .terminated,
    };
}

fn buildProviderLoginEnv(
    allocator: std.mem.Allocator,
    inherited_env: *const std.process.EnvMap,
    active_config: config.Config,
    fixed: []const EnvPair,
) error{OutOfMemory}!std.process.EnvMap {
    var child_env = std.process.EnvMap.init(allocator);
    errdefer child_env.deinit();
    var inherited = inherited_env.iterator();
    while (inherited.next()) |entry| {
        const name = entry.key_ptr.*;
        if (!isLoginInheritedEnvAllowed(name)) continue;
        if (child_authority.shouldScrubInheritedEnv(active_config, name)) continue;
        child_env.put(name, entry.value_ptr.*) catch return error.OutOfMemory;
    }
    for (fixed) |pair| {
        child_env.put(pair.key, pair.value) catch return error.OutOfMemory;
    }
    return child_env;
}

fn isLoginInheritedEnvAllowed(name: []const u8) bool {
    const exact = [_][]const u8{
        "HOME",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LANG",
        "TERM",
        "COLORTERM",
        "NO_COLOR",
        "FORCE_COLOR",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "__CF_USER_TEXT_ENCODING",
    };
    for (exact) |allowed| if (envNameEqual(name, allowed)) return true;
    return if (comptime builtin.os.tag == .windows)
        std.ascii.startsWithIgnoreCase(name, "LC_")
    else
        std.mem.startsWith(u8, name, "LC_");
}

fn envNameEqual(a: []const u8, b: []const u8) bool {
    return if (comptime builtin.os.tag == .windows)
        std.ascii.eqlIgnoreCase(a, b)
    else
        std.mem.eql(u8, a, b);
}

const ProcessFailure = enum { spawn };

const Spy = struct {
    browser_present: bool = true,
    runtime_safe: bool = true,
    lock_busy: bool = false,
    process_error: ?ProcessFailure = null,
    process_exit: u8 = 0,
    process_terminated: bool = false,
    browser_marker_written: bool = true,
    canonical_alias: bool = false,
    swap_on_revalidate: bool = false,
    validate_calls: usize = 0,
    runtime_validate_calls: usize = 0,
    workspace_calls: usize = 0,
    cleanup_calls: usize = 0,
    verify_calls: usize = 0,
    lock_calls: usize = 0,
    release_calls: usize = 0,
    process_calls: usize = 0,
    sequence: usize = 0,
    last_label: ?[]const u8 = null,
    last_store_lock_key: ?[]const u8 = null,
    captured_argv: std.ArrayList([]const u8),
    captured_env: std.ArrayList(EnvPair),
    arena: std.mem.Allocator,

    fn init(arena: std.mem.Allocator) Spy {
        return .{
            .captured_argv = std.ArrayList([]const u8).init(arena),
            .captured_env = std.ArrayList(EnvPair).init(arena),
            .arena = arena,
        };
    }

    fn findBrowser(allocator: std.mem.Allocator, ctx: *anyopaque) error{ BrowserUnavailable, OutOfMemory }![]const u8 {
        const self: *Spy = @ptrCast(@alignCast(ctx));
        if (!self.browser_present) return error.BrowserUnavailable;
        return allocator.dupe(u8, "/fake/chrome") catch error.OutOfMemory;
    }

    fn validateDir(
        ctx: *anyopaque,
        path: []const u8,
        canonical_path: []const u8,
        expected: ?ConfigDirIdentity,
    ) error{ ConfigDirUnavailable, ConfigDirCanonical, ConfigDirSymlink, ConfigDirChanged, ConfigDirCustodyViolation }!ConfigDirIdentity {
        const self: *Spy = @ptrCast(@alignCast(ctx));
        self.validate_calls += 1;
        if (!std.fs.path.isAbsolute(path) or !std.fs.path.isAbsolute(canonical_path)) return error.ConfigDirUnavailable;
        if (self.canonical_alias) return error.ConfigDirCanonical;
        const identity = ConfigDirIdentity{
            .device = 7,
            .inode = 11,
            .parent_device = 7,
            .parent_inode = 10,
        };
        if (expected) |expected_identity| {
            if (self.swap_on_revalidate or !std.meta.eql(expected_identity, identity))
                return error.ConfigDirChanged;
        }
        return identity;
    }

    fn validateRuntime(ctx: *anyopaque) error{ RuntimeCustodyViolation, UnsupportedPlatform, OutOfMemory }!void {
        const self: *Spy = @ptrCast(@alignCast(ctx));
        self.runtime_validate_calls += 1;
        if (!self.runtime_safe) return error.RuntimeCustodyViolation;
    }

    fn prepare(allocator: std.mem.Allocator, ctx: *anyopaque) error{ WorkspaceCreateFailed, UnsupportedPlatform, OutOfMemory }!Workspace {
        const self: *Spy = @ptrCast(@alignCast(ctx));
        self.workspace_calls += 1;
        self.sequence += 1;
        const root = std.fmt.allocPrint(allocator, "/virtual/login-{d}", .{self.sequence}) catch return error.OutOfMemory;
        errdefer allocator.free(root);
        const shim = std.fmt.allocPrint(allocator, "{s}/shim", .{root}) catch return error.OutOfMemory;
        errdefer allocator.free(shim);
        const open = std.fmt.allocPrint(allocator, "{s}/open", .{shim}) catch return error.OutOfMemory;
        errdefer allocator.free(open);
        const profile = std.fmt.allocPrint(allocator, "{s}/profile", .{root}) catch return error.OutOfMemory;
        errdefer allocator.free(profile);
        const marker = std.fmt.allocPrint(allocator, "{s}/owned-helper-returned", .{root}) catch return error.OutOfMemory;
        errdefer allocator.free(marker);
        return .{
            .root = root,
            .shim_dir = shim,
            .open_shim = open,
            .profile_dir = profile,
            .browser_marker = marker,
        };
    }

    fn cleanup(ctx: *anyopaque, root: []const u8) error{WorkspaceCleanupFailed}!void {
        _ = root;
        const self: *Spy = @ptrCast(@alignCast(ctx));
        self.cleanup_calls += 1;
    }

    fn verifyBrowser(ctx: *anyopaque, marker_path: []const u8) bool {
        _ = marker_path;
        const self: *Spy = @ptrCast(@alignCast(ctx));
        self.verify_calls += 1;
        return self.browser_marker_written;
    }

    fn acquire(
        allocator: std.mem.Allocator,
        ctx: *anyopaque,
        provider: []const u8,
        label: []const u8,
        store_lock_key: []const u8,
    ) error{ RepairInProgress, LockFailed, OutOfMemory }!void {
        _ = allocator;
        const self: *Spy = @ptrCast(@alignCast(ctx));
        self.lock_calls += 1;
        if (!std.mem.eql(u8, provider, "claude") or store_lock_key.len == 0)
            return error.LockFailed;
        if (self.lock_busy) return error.RepairInProgress;
        self.last_label = self.arena.dupe(u8, label) catch return error.OutOfMemory;
        self.last_store_lock_key = self.arena.dupe(u8, store_lock_key) catch
            return error.OutOfMemory;
    }

    fn release(ctx: *anyopaque) void {
        const self: *Spy = @ptrCast(@alignCast(ctx));
        self.release_calls += 1;
    }

    fn runProvider(allocator: std.mem.Allocator, ctx: *anyopaque, spec: RunSpec) error{ ProviderSpawnFailed, OutOfMemory }!ProviderTermination {
        _ = allocator;
        const self: *Spy = @ptrCast(@alignCast(ctx));
        self.process_calls += 1;
        for (spec.argv) |arg| {
            const value = self.arena.dupe(u8, arg) catch return error.OutOfMemory;
            self.captured_argv.append(value) catch return error.OutOfMemory;
        }
        for (spec.env) |pair| {
            const key = self.arena.dupe(u8, pair.key) catch return error.OutOfMemory;
            const value = self.arena.dupe(u8, pair.value) catch return error.OutOfMemory;
            self.captured_env.append(.{ .key = key, .value = value }) catch return error.OutOfMemory;
        }
        if (self.process_error) |failure| switch (failure) {
            .spawn => return error.ProviderSpawnFailed,
        };
        if (self.process_terminated) return .terminated;
        return .{ .exited = self.process_exit };
    }

    fn seams(self: *Spy) Seams {
        return .{
            .find_browser = Spy.findBrowser,
            .validate_dir = Spy.validateDir,
            .validate_runtime = Spy.validateRuntime,
            .prepare_workspace = Spy.prepare,
            .cleanup_workspace = Spy.cleanup,
            .verify_browser = Spy.verifyBrowser,
            .acquire_locks = Spy.acquire,
            .release_locks = Spy.release,
            .run_provider = Spy.runProvider,
            .browser_ctx = @ptrCast(self),
            .fs_ctx = @ptrCast(self),
            .lock_ctx = @ptrCast(self),
            .process_ctx = @ptrCast(self),
        };
    }
};

fn envValue(env: []const EnvPair, key: []const u8) ?[]const u8 {
    for (env) |pair| if (std.mem.eql(u8, pair.key, key)) return pair.value;
    return null;
}

test "confirmed login uses fixed argv and preserves its post-spawn workspace" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var spy = Spy.init(arena_state.allocator());

    var outcome = try runWithSeams(std.testing.allocator, .{
        .label = "work; touch /tmp/not-run",
        .config_dir = "/accounts/work",
        .canonical_dir = "/home/user/.claude",
        .store_lock_key = "test-store",
        .effective_account = "effective-user",
        .inherited_path = "/usr/bin",
    }, spy.seams());
    defer outcome.deinit(std.testing.allocator);
    switch (outcome.provider) {
        .exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .terminated => return error.Unexpected,
    }
    try std.testing.expect(outcome.browser_helper_observed);
    try std.testing.expect(outcome.workspace_disposition == .preserved_manual_cleanup);
    try std.testing.expectEqualStrings("/virtual/login-1", outcome.workspace_path);
    try std.testing.expectEqual(@as(usize, 1), spy.lock_calls);
    try std.testing.expectEqual(@as(usize, 1), spy.release_calls);
    try std.testing.expectEqual(@as(usize, 0), spy.cleanup_calls);
    try std.testing.expectEqual(@as(usize, 1), spy.verify_calls);
    try std.testing.expectEqual(@as(usize, 2), spy.validate_calls);
    const expected_argv = [_][]const u8{ "claude", "auth", "login" };
    try std.testing.expectEqual(expected_argv.len, spy.captured_argv.items.len);
    for (expected_argv, spy.captured_argv.items) |expected, actual| {
        try std.testing.expectEqualStrings(expected, actual);
    }
    try std.testing.expectEqualStrings("work; touch /tmp/not-run", spy.last_label.?);
    try std.testing.expectEqualStrings("test-store", spy.last_store_lock_key.?);
    for (spy.captured_argv.items) |arg| {
        try std.testing.expect(std.mem.indexOf(u8, arg, spy.last_label.?) == null);
    }
    try std.testing.expectEqualStrings("/accounts/work", envValue(spy.captured_env.items, "CLAUDE_CONFIG_DIR").?);
    try std.testing.expectEqualStrings("effective-user", envValue(spy.captured_env.items, "USER").?);
    try std.testing.expectEqualStrings("effective-user", envValue(spy.captured_env.items, "LOGNAME").?);
    try std.testing.expectEqualStrings("/fake/chrome", envValue(spy.captured_env.items, "OMUX_CLAUDE_BROWSER_BIN").?);
    try std.testing.expect(std.mem.startsWith(u8, envValue(spy.captured_env.items, "PATH").?, "/virtual/login-1/shim"));
    try std.testing.expectEqualStrings("/virtual/login-1/owned-helper-returned", envValue(spy.captured_env.items, "OMUX_CLAUDE_BROWSER_MARKER").?);
}

test "missing validated browser fails after custody checks and before lock or provider effects" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var spy = Spy.init(arena_state.allocator());
    spy.browser_present = false;
    try std.testing.expectError(error.BrowserUnavailable, runWithSeams(std.testing.allocator, .{
        .label = "work",
        .config_dir = "/accounts/work",
        .canonical_dir = "/home/user/.claude",
        .store_lock_key = "test-store",
        .inherited_path = "/usr/bin",
    }, spy.seams()));
    try std.testing.expectEqual(@as(usize, 1), spy.validate_calls);
    try std.testing.expectEqual(@as(usize, 1), spy.runtime_validate_calls);
    try std.testing.expectEqual(@as(usize, 0), spy.lock_calls);
    try std.testing.expectEqual(@as(usize, 0), spy.process_calls);
}

test "unsafe runtime custody fails before browser lock workspace or provider effects" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var spy = Spy.init(arena_state.allocator());
    spy.runtime_safe = false;
    try std.testing.expectError(error.RuntimeCustodyViolation, runWithSeams(std.testing.allocator, .{
        .label = "work",
        .config_dir = "/accounts/work",
        .canonical_dir = "/home/user/.claude",
        .store_lock_key = "test-store",
        .inherited_path = "/usr/bin",
    }, spy.seams()));
    try std.testing.expectEqual(@as(usize, 1), spy.validate_calls);
    try std.testing.expectEqual(@as(usize, 1), spy.runtime_validate_calls);
    try std.testing.expectEqual(@as(usize, 0), spy.lock_calls);
    try std.testing.expectEqual(@as(usize, 0), spy.workspace_calls);
    try std.testing.expectEqual(@as(usize, 0), spy.process_calls);
}

test "concurrent account repair lock prevents workspace and provider launch" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var spy = Spy.init(arena_state.allocator());
    spy.lock_busy = true;
    try std.testing.expectError(error.RepairInProgress, runWithSeams(std.testing.allocator, .{
        .label = "work",
        .config_dir = "/accounts/work",
        .canonical_dir = "/home/user/.claude",
        .store_lock_key = "test-store",
        .inherited_path = "/usr/bin",
    }, spy.seams()));
    try std.testing.expectEqual(@as(usize, 0), spy.workspace_calls);
    try std.testing.expectEqual(@as(usize, 0), spy.process_calls);
    try std.testing.expectEqual(@as(usize, 0), spy.release_calls);
}

test "workspace cleanup is limited to provider spawn failure" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var spawn_spy = Spy.init(arena_state.allocator());
    spawn_spy.process_error = .spawn;
    try std.testing.expectError(error.ProviderSpawnFailed, runWithSeams(std.testing.allocator, .{
        .label = "work",
        .config_dir = "/accounts/work",
        .canonical_dir = "/home/user/.claude",
        .store_lock_key = "test-store",
        .inherited_path = "/usr/bin",
    }, spawn_spy.seams()));
    try std.testing.expectEqual(@as(usize, 1), spawn_spy.cleanup_calls);
    try std.testing.expectEqual(@as(usize, 1), spawn_spy.release_calls);

    var terminated_spy = Spy.init(arena_state.allocator());
    terminated_spy.process_terminated = true;
    var outcome = try runWithSeams(std.testing.allocator, .{
        .label = "work",
        .config_dir = "/accounts/work",
        .canonical_dir = "/home/user/.claude",
        .store_lock_key = "test-store",
        .inherited_path = "/usr/bin",
    }, terminated_spy.seams());
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expect(outcome.provider == .terminated);
    try std.testing.expectEqual(@as(usize, 0), terminated_spy.cleanup_calls);
}

test "consecutive accounts receive distinct ephemeral browser profiles" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var spy = Spy.init(arena_state.allocator());
    var first = try runWithSeams(std.testing.allocator, .{
        .label = "one",
        .config_dir = "/accounts/one",
        .canonical_dir = "/home/user/.claude",
        .store_lock_key = "test-store-one",
        .inherited_path = "/usr/bin",
    }, spy.seams());
    defer first.deinit(std.testing.allocator);
    const first_profile = envValue(spy.captured_env.items, "OMUX_CLAUDE_BROWSER_PROFILE").?;
    spy.captured_env.clearRetainingCapacity();
    spy.captured_argv.clearRetainingCapacity();
    var second = try runWithSeams(std.testing.allocator, .{
        .label = "two",
        .config_dir = "/accounts/two",
        .canonical_dir = "/home/user/.claude",
        .store_lock_key = "test-store-two",
        .inherited_path = "/usr/bin",
    }, spy.seams());
    defer second.deinit(std.testing.allocator);
    const second_profile = envValue(spy.captured_env.items, "OMUX_CLAUDE_BROWSER_PROFILE").?;
    try std.testing.expect(!std.mem.eql(u8, first_profile, second_profile));
}

test "child and browser PATH lookup remove empty and relative segments" {
    const sanitized = try sanitizedChildPathAlloc(
        std.testing.allocator,
        "/isolated/shim",
        ":relative:/usr/bin:.:/bin:",
    );
    defer std.testing.allocator.free(sanitized);
    try std.testing.expectEqualStrings("/isolated/shim:/usr/bin:/bin", sanitized);

    const empty = try sanitizedChildPathAlloc(std.testing.allocator, "/isolated/shim", "");
    defer std.testing.allocator.free(empty);
    try std.testing.expectEqualStrings("/isolated/shim", empty);

    var entries = std.mem.splitScalar(u8, ":relative:/usr/bin:.:/bin:", std.fs.path.delimiter);
    try std.testing.expectEqualStrings("/usr/bin", nextAbsolutePathEntry(&entries).?);
    try std.testing.expectEqualStrings("/bin", nextAbsolutePathEntry(&entries).?);
    try std.testing.expect(nextAbsolutePathEntry(&entries) == null);
}

test "provider login environment is allowlisted scrubbed and fixed-authority only" {
    const allocator = std.testing.allocator;
    var inherited = std.process.EnvMap.init(allocator);
    defer inherited.deinit();
    try inherited.put("HOME", "/home/test");
    try inherited.put("USER", "spoofed-user");
    try inherited.put("LOGNAME", "spoofed-logname");
    try inherited.put("LANG", "en_US.UTF-8");
    try inherited.put("LC_TEST", "preserved-locale");
    try inherited.put("DISPLAY", "configured-secret-must-not-survive");
    try inherited.put("PATH", "/attacker/bin");
    try inherited.put("BROWSER", "/shared/browser");
    try inherited.put("ANTHROPIC_API_KEY", "secret");
    try inherited.put("ANTHROPIC_BASE_URL", "https://wrong.invalid");
    try inherited.put("CLAUDE_CONFIG_DIR", "/wrong/config");
    try inherited.put("CLAUDE_CODE_USE_BEDROCK", "1");
    try inherited.put("HTTP_PROXY", "http://wrong.invalid");
    try inherited.put("AWS_ACCESS_KEY_ID", "secret");
    try inherited.put("OMUX_CLAUDE_BROWSER_BIN", "/wrong/browser");
    try inherited.put("UNRELATED_SENTINEL", "not-allowlisted");

    const bytes =
        \\{"version":1,"providers":{"toy":{"kind":"figma","accounts":{"env":{"secret":{"backend":"env","variable":"DISPLAY"}}}}}}
    ;
    var parsed = try config.loadFromBytes(allocator, bytes);
    defer parsed.deinit();
    const fixed = [_]EnvPair{
        .{ .key = "CLAUDE_CONFIG_DIR", .value = "/accounts/work" },
        .{ .key = "PATH", .value = "/owned/shim:/usr/bin" },
        .{ .key = "BROWSER", .value = "/owned/shim/open" },
        .{ .key = "OMUX_CLAUDE_BROWSER_BIN", .value = "/validated/chrome" },
        .{ .key = "USER", .value = "effective-user" },
        .{ .key = "LOGNAME", .value = "effective-user" },
    };
    var child = try buildProviderLoginEnv(allocator, &inherited, parsed.value, &fixed);
    defer child.deinit();

    try std.testing.expectEqualStrings("/home/test", child.get("HOME").?);
    try std.testing.expectEqualStrings("effective-user", child.get("USER").?);
    try std.testing.expectEqualStrings("effective-user", child.get("LOGNAME").?);
    try std.testing.expectEqualStrings("en_US.UTF-8", child.get("LANG").?);
    try std.testing.expectEqualStrings("preserved-locale", child.get("LC_TEST").?);
    try std.testing.expectEqualStrings("/accounts/work", child.get("CLAUDE_CONFIG_DIR").?);
    try std.testing.expectEqualStrings("/owned/shim:/usr/bin", child.get("PATH").?);
    try std.testing.expectEqualStrings("/owned/shim/open", child.get("BROWSER").?);
    try std.testing.expectEqualStrings("/validated/chrome", child.get("OMUX_CLAUDE_BROWSER_BIN").?);
    try std.testing.expect(child.get("DISPLAY") == null);
    try std.testing.expect(child.get("ANTHROPIC_API_KEY") == null);
    try std.testing.expect(child.get("ANTHROPIC_BASE_URL") == null);
    try std.testing.expect(child.get("CLAUDE_CODE_USE_BEDROCK") == null);
    try std.testing.expect(child.get("HTTP_PROXY") == null);
    try std.testing.expect(child.get("AWS_ACCESS_KEY_ID") == null);
    try std.testing.expect(child.get("UNRELATED_SENTINEL") == null);
}

test "browser shim records only that its immediate owned helper returned" {
    const wait_index = std.mem.indexOf(u8, open_shim_body, "wait \"$browser_pid\"").?;
    const marker_index = std.mem.indexOf(u8, open_shim_body, ": >\"$OMUX_CLAUDE_BROWSER_MARKER\"").?;
    try std.testing.expect(wait_index < marker_index);
    try std.testing.expect(std.mem.indexOf(u8, open_shim_body, "kill ") == null);
}

test "canonical alias and missing browser helper marker remain explicit" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var alias_spy = Spy.init(arena_state.allocator());
    alias_spy.canonical_alias = true;
    try std.testing.expectError(error.ConfigDirCanonical, runWithSeams(std.testing.allocator, .{
        .label = "alias",
        .config_dir = "/accounts/alias",
        .canonical_dir = "/home/user/.claude",
        .inherited_path = "/usr/bin",
    }, alias_spy.seams()));
    try std.testing.expectEqual(@as(usize, 0), alias_spy.lock_calls);
    try std.testing.expectEqual(@as(usize, 0), alias_spy.process_calls);

    var marker_spy = Spy.init(arena_state.allocator());
    marker_spy.browser_marker_written = false;
    var marker_outcome = try runWithSeams(std.testing.allocator, .{
        .label = "work",
        .config_dir = "/accounts/work",
        .canonical_dir = "/home/user/.claude",
        .store_lock_key = "test-store",
        .inherited_path = "/usr/bin",
    }, marker_spy.seams());
    defer marker_outcome.deinit(std.testing.allocator);
    try std.testing.expect(!marker_outcome.browser_helper_observed);
    try std.testing.expectEqual(@as(usize, 1), marker_spy.process_calls);
    try std.testing.expectEqual(@as(usize, 0), marker_spy.cleanup_calls);
    try std.testing.expectEqual(@as(usize, 1), marker_spy.release_calls);
}

test "daemonized descendant counterexample never permits automatic cleanup" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var spy = Spy.init(arena_state.allocator());
    // The marker proves only that the immediate helper returned. A browser may
    // have daemonized a descendant that still owns the profile.
    spy.browser_marker_written = true;
    var outcome = try runWithSeams(std.testing.allocator, .{
        .label = "daemonized",
        .config_dir = "/accounts/daemonized",
        .canonical_dir = "/home/user/.claude",
        .store_lock_key = "test-store-daemonized",
        .inherited_path = "/usr/bin",
    }, spy.seams());
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expect(outcome.browser_helper_observed);
    try std.testing.expect(outcome.workspace_disposition == .preserved_manual_cleanup);
    try std.testing.expectEqual(@as(usize, 0), spy.cleanup_calls);
}

test "provider nonzero exit survives a missing browser helper marker" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var spy = Spy.init(arena_state.allocator());
    spy.process_exit = 37;
    spy.browser_marker_written = false;
    var outcome = try runWithSeams(std.testing.allocator, .{
        .label = "nonzero",
        .config_dir = "/accounts/nonzero",
        .canonical_dir = "/home/user/.claude",
        .store_lock_key = "test-store-nonzero",
        .inherited_path = "/usr/bin",
    }, spy.seams());
    defer outcome.deinit(std.testing.allocator);
    switch (outcome.provider) {
        .exited => |code| try std.testing.expectEqual(@as(u8, 37), code),
        .terminated => return error.Unexpected,
    }
    try std.testing.expect(!outcome.browser_helper_observed);
}

test "config directory identity swap is rejected immediately before spawn" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var spy = Spy.init(arena_state.allocator());
    spy.swap_on_revalidate = true;
    try std.testing.expectError(error.ConfigDirChanged, runWithSeams(std.testing.allocator, .{
        .label = "swapped",
        .config_dir = "/accounts/swapped",
        .canonical_dir = "/home/user/.claude",
        .store_lock_key = "test-store-swapped",
        .inherited_path = "/usr/bin",
    }, spy.seams()));
    try std.testing.expectEqual(@as(usize, 2), spy.validate_calls);
    try std.testing.expectEqual(@as(usize, 0), spy.process_calls);
    try std.testing.expectEqual(@as(usize, 1), spy.cleanup_calls);
}

test "system directory validation rejects a real symlink to canonical config" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("home/.claude");
    try tmp.dir.symLink("home/.claude", "alias", .{ .is_directory = true });

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const alias_path = try std.fs.path.join(std.testing.allocator, &.{ root, "alias" });
    defer std.testing.allocator.free(alias_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root, "home", ".claude" });
    defer std.testing.allocator.free(canonical_path);
    var env = std.process.EnvMap.init(std.testing.allocator);
    defer env.deinit();
    var system = SystemContext{
        .allocator = std.testing.allocator,
        .inherited_env = &env,
        .active_config = .{},
    };
    defer if (system.held_config_dir) |*dir| dir.close();
    defer if (system.held_config_parent) |*dir| dir.close();
    try std.testing.expectError(
        error.ConfigDirSymlink,
        systemValidateDir(@ptrCast(&system), alias_path, canonical_path, null),
    );
}

test "system directory validation rejects writable config dir and parent custody" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi)
        return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("home/.claude");
    try tmp.dir.makePath("accounts/work");
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const accounts = try std.fs.path.join(allocator, &.{ root, "accounts" });
    defer allocator.free(accounts);
    const configured = try std.fs.path.join(allocator, &.{ accounts, "work" });
    defer allocator.free(configured);
    const canonical = try std.fs.path.join(allocator, &.{ root, "home", ".claude" });
    defer allocator.free(canonical);
    var env = std.process.EnvMap.init(allocator);
    defer env.deinit();

    try std.posix.fchmodat(std.posix.AT.FDCWD, configured, 0o777, 0);
    defer std.posix.fchmodat(std.posix.AT.FDCWD, configured, 0o700, 0) catch {};
    var unsafe_dir = SystemContext{
        .allocator = allocator,
        .inherited_env = &env,
        .active_config = .{},
    };
    try std.testing.expectError(
        error.ConfigDirCustodyViolation,
        systemValidateDir(@ptrCast(&unsafe_dir), configured, canonical, null),
    );

    try std.posix.fchmodat(std.posix.AT.FDCWD, configured, 0o700, 0);
    try std.posix.fchmodat(std.posix.AT.FDCWD, accounts, 0o777, 0);
    defer std.posix.fchmodat(std.posix.AT.FDCWD, accounts, 0o700, 0) catch {};
    var unsafe_parent = SystemContext{
        .allocator = allocator,
        .inherited_env = &env,
        .active_config = .{},
    };
    try std.testing.expectError(
        error.ConfigDirCustodyViolation,
        systemValidateDir(@ptrCast(&unsafe_parent), configured, canonical, null),
    );
}

test "pre-spawn revalidation detects a directory swapped at the configured path" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("home/.claude");
    try tmp.dir.makePath("configured");
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const configured = try std.fs.path.join(std.testing.allocator, &.{ root, "configured" });
    defer std.testing.allocator.free(configured);
    const canonical = try std.fs.path.join(std.testing.allocator, &.{ root, "home", ".claude" });
    defer std.testing.allocator.free(canonical);

    var env = std.process.EnvMap.init(std.testing.allocator);
    defer env.deinit();
    var system = SystemContext{
        .allocator = std.testing.allocator,
        .inherited_env = &env,
        .active_config = .{},
    };
    defer if (system.held_config_dir) |*dir| dir.close();
    defer if (system.held_config_parent) |*dir| dir.close();
    const expected_identity = try systemValidateDir(@ptrCast(&system), configured, canonical, null);

    try tmp.dir.rename("configured", "configured-original");
    try tmp.dir.makeDir("configured");
    try std.testing.expectError(
        error.ConfigDirChanged,
        systemValidateDir(@ptrCast(&system), configured, canonical, expected_identity),
    );
}

test "runtime custody rejects 0777 ancestor and workspace stays parent-contained" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi)
        return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const runtime = try std.fs.path.join(allocator, &.{ root, "runtime" });
    defer allocator.free(runtime);

    try std.posix.fchmodat(std.posix.AT.FDCWD, root, 0o777, 0);
    try std.testing.expectError(
        error.RuntimeCustodyViolation,
        validateNearestExistingRuntimeAncestor(allocator, runtime),
    );
    try std.posix.fchmodat(std.posix.AT.FDCWD, root, 0o700, 0);
    try tmp.dir.makeDir("runtime");

    var env = std.process.EnvMap.init(allocator);
    defer env.deinit();
    var system = SystemContext{
        .allocator = allocator,
        .inherited_env = &env,
        .active_config = .{},
        .runtime_dir = runtime,
    };
    defer if (system.workspace_parent) |*dir| dir.close();
    defer if (system.workspace_name) |name| allocator.free(name);
    var workspace = try systemPrepareWorkspace(allocator, @ptrCast(&system));
    defer workspace.deinit(allocator);
    try std.testing.expectEqualStrings(runtime, std.fs.path.dirname(workspace.root).?);
    const root_stat = try std.fs.cwd().statFile(workspace.root);
    try std.testing.expect(root_stat.kind == .directory);
    try std.testing.expectEqual(@as(u32, 0), root_stat.mode & 0o077);
    try systemCleanupWorkspace(@ptrCast(&system), workspace.root);

    try tmp.dir.makeDir("unsafe-runtime");
    const unsafe_runtime = try std.fs.path.join(allocator, &.{ root, "unsafe-runtime" });
    defer allocator.free(unsafe_runtime);
    try std.posix.fchmodat(std.posix.AT.FDCWD, unsafe_runtime, 0o777, 0);
    defer std.posix.fchmodat(std.posix.AT.FDCWD, unsafe_runtime, 0o700, 0) catch {};
    var unsafe_system = SystemContext{
        .allocator = allocator,
        .inherited_env = &env,
        .active_config = .{},
        .runtime_dir = unsafe_runtime,
    };
    try std.testing.expectError(
        error.RuntimeCustodyViolation,
        systemPrepareWorkspace(allocator, @ptrCast(&unsafe_system)),
    );
}

fn testClaudeSecretJsonAlloc(
    allocator: std.mem.Allocator,
    exact_config_dir: []const u8,
    canonical: bool,
    mismatch: bool,
) ![]u8 {
    if (comptime builtin.os.tag == .macos) {
        const derived = if (canonical)
            try allocator.dupe(u8, provider_schema.claude_keychain_service_base)
        else
            try provider_schema.claudeKeychainService(allocator, exact_config_dir);
        defer allocator.free(derived);
        const service = if (mismatch) "Claude Code-credentials-wrong" else derived;
        return std.fmt.allocPrint(
            allocator,
            "{{\"backend\":\"keychain\",\"service\":\"{s}\"}}",
            .{service},
        );
    }
    if (comptime builtin.os.tag == .linux) {
        const expected = try std.fs.path.join(allocator, &.{ exact_config_dir, ".credentials.json" });
        defer allocator.free(expected);
        const path = if (mismatch) "/definitely/not/the/derived/store.json" else expected;
        return std.fmt.allocPrint(
            allocator,
            "{{\"backend\":\"file\",\"path\":\"{s}\"}}",
            .{path},
        );
    }
    return error.SkipZigTest;
}

fn testAccountAuthorityAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (comptime builtin.os.tag == .macos)
        return os_account.effectiveUserNameAlloc(allocator);
    return allocator.dupe(u8, "test-user");
}

const TestClaudeAccount = struct {
    label: []const u8,
    secret_json: []const u8,
    config_dir: ?[]const u8,
};

fn testClaudeConfigJsonAlloc(
    allocator: std.mem.Allocator,
    accounts: []const TestClaudeAccount,
) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    const writer = out.writer();
    try writer.writeAll("{\"version\":1,\"providers\":{\"claude\":{\"kind\":\"claude\",\"config_dir_env\":\"CLAUDE_CONFIG_DIR\",\"accounts\":{");
    for (accounts, 0..) |account, index| {
        if (index != 0) try writer.writeByte(',');
        try std.json.stringify(account.label, .{}, writer);
        try writer.writeAll(":{\"secret\":");
        try writer.writeAll(account.secret_json);
        if (account.config_dir) |config_dir| {
            try writer.writeAll(",\"config_dir\":");
            try std.json.stringify(config_dir, .{}, writer);
        }
        try writer.writeByte('}');
    }
    try writer.writeAll("}}}}");
    return out.toOwnedSlice();
}

test "configured account resolver accepts matching store metadata and rejects canonical or missing targets" {
    if (comptime builtin.os.tag != .macos and builtin.os.tag != .linux)
        return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const authority = try testAccountAuthorityAlloc(allocator);
    defer allocator.free(authority);
    const isolated_dir = "/home/user/.local/../share/oauth-mux/claude/isolated";
    const canonical_dir = "/home/user/.claude";
    const isolated_secret = try testClaudeSecretJsonAlloc(allocator, isolated_dir, false, false);
    defer allocator.free(isolated_secret);
    const canonical_secret = try testClaudeSecretJsonAlloc(allocator, canonical_dir, true, false);
    defer allocator.free(canonical_secret);
    const bytes = try testClaudeConfigJsonAlloc(allocator, &.{
        .{ .label = "isolated", .secret_json = isolated_secret, .config_dir = isolated_dir },
        .{ .label = "canonical", .secret_json = canonical_secret, .config_dir = canonical_dir },
        .{ .label = "missing", .secret_json = canonical_secret, .config_dir = null },
    });
    defer allocator.free(bytes);
    var parsed = try config.loadFromBytes(allocator, bytes);
    defer parsed.deinit();
    var isolated = try resolveConfiguredAccountWithAuthority(allocator, "/home/user", authority, parsed.value, "claude", "isolated");
    defer isolated.deinit(allocator);
    try std.testing.expectEqualStrings(isolated_dir, isolated.config_dir);
    try std.testing.expectEqualStrings("/home/user/.claude", isolated.canonical_dir);
    if (comptime builtin.os.tag == .macos) {
        try std.testing.expectError(
            error.SecretStoreMismatch,
            resolveConfiguredAccountWithAuthority(allocator, "/home/user", "other-user", parsed.value, "claude", "isolated"),
        );
    }
    try std.testing.expectError(error.ConfigDirCanonical, resolveConfiguredAccountWithAuthority(allocator, "/home/user", authority, parsed.value, "claude", "canonical"));
    try std.testing.expectError(error.ConfigDirMissing, resolveConfiguredAccountWithAuthority(allocator, "/home/user", authority, parsed.value, "claude", "missing"));
    try std.testing.expectError(error.AccountNotConfigured, resolveConfiguredAccountWithAuthority(allocator, "/home/user", authority, parsed.value, "claude", "other"));
}

test "configured account resolver rejects store metadata that disagrees with config dir" {
    if (comptime builtin.os.tag != .macos and builtin.os.tag != .linux)
        return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const authority = try testAccountAuthorityAlloc(allocator);
    defer allocator.free(authority);
    const config_dir = "/home/user/.local/share/oauth-mux/claude/work";
    const wrong_secret = try testClaudeSecretJsonAlloc(allocator, config_dir, false, true);
    defer allocator.free(wrong_secret);
    const bytes = try testClaudeConfigJsonAlloc(allocator, &.{
        .{ .label = "work", .secret_json = wrong_secret, .config_dir = config_dir },
    });
    defer allocator.free(bytes);
    var parsed = try config.loadFromBytes(allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectError(
        error.SecretStoreMismatch,
        resolveConfiguredAccountWithAuthority(allocator, "/home/user", authority, parsed.value, "claude", "work"),
    );
}

test "configured account resolver rejects equal and nested sibling Claude stores" {
    if (comptime builtin.os.tag != .macos and builtin.os.tag != .linux)
        return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const authority = try testAccountAuthorityAlloc(allocator);
    defer allocator.free(authority);
    const selected_dir = "/home/user/.local/share/oauth-mux/claude/work";
    const nested_dir = "/home/user/.local/share/oauth-mux/claude/work/nested";
    const selected_secret = try testClaudeSecretJsonAlloc(allocator, selected_dir, false, false);
    defer allocator.free(selected_secret);
    const nested_secret = try testClaudeSecretJsonAlloc(allocator, nested_dir, false, false);
    defer allocator.free(nested_secret);

    const same_bytes = try testClaudeConfigJsonAlloc(allocator, &.{
        .{ .label = "work", .secret_json = selected_secret, .config_dir = selected_dir },
        .{ .label = "other", .secret_json = selected_secret, .config_dir = selected_dir },
    });
    defer allocator.free(same_bytes);
    var same = try config.loadFromBytes(allocator, same_bytes);
    defer same.deinit();
    try std.testing.expectError(
        error.AccountConfigDirOverlap,
        resolveConfiguredAccountWithAuthority(allocator, "/home/user", authority, same.value, "claude", "work"),
    );

    const nested_bytes = try testClaudeConfigJsonAlloc(allocator, &.{
        .{ .label = "work", .secret_json = selected_secret, .config_dir = selected_dir },
        .{ .label = "nested", .secret_json = nested_secret, .config_dir = nested_dir },
    });
    defer allocator.free(nested_bytes);
    var nested = try config.loadFromBytes(allocator, nested_bytes);
    defer nested.deinit();
    try std.testing.expectError(
        error.AccountConfigDirOverlap,
        resolveConfiguredAccountWithAuthority(allocator, "/home/user", authority, nested.value, "claude", "work"),
    );
}

test "configured account resolver rejects a real sibling symlink alias" {
    if (comptime builtin.os.tag != .macos and builtin.os.tag != .linux)
        return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const authority = try testAccountAuthorityAlloc(allocator);
    defer allocator.free(authority);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("home/.claude");
    try tmp.dir.makePath("accounts/work");
    try tmp.dir.symLink("work", "accounts/alias", .{ .is_directory = true });
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const home = try std.fs.path.join(allocator, &.{ root, "home" });
    defer allocator.free(home);
    const selected_dir = try std.fs.path.join(allocator, &.{ root, "accounts", "work" });
    defer allocator.free(selected_dir);
    const alias_dir = try std.fs.path.join(allocator, &.{ root, "accounts", "alias" });
    defer allocator.free(alias_dir);
    const selected_secret = try testClaudeSecretJsonAlloc(allocator, selected_dir, false, false);
    defer allocator.free(selected_secret);
    const alias_secret = try testClaudeSecretJsonAlloc(allocator, alias_dir, false, false);
    defer allocator.free(alias_secret);
    const bytes = try testClaudeConfigJsonAlloc(allocator, &.{
        .{ .label = "work", .secret_json = selected_secret, .config_dir = selected_dir },
        .{ .label = "alias", .secret_json = alias_secret, .config_dir = alias_dir },
    });
    defer allocator.free(bytes);
    var parsed = try config.loadFromBytes(allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectError(
        error.AccountConfigDirOverlap,
        resolveConfiguredAccountWithAuthority(allocator, home, authority, parsed.value, "claude", "work"),
    );
}

test "spoofed login environment cannot split config backend and refresh-store authority" {
    if (comptime builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var overrides = std.process.EnvMap.init(allocator);
    defer overrides.deinit();
    try overrides.put("USER", "spoofed-user");
    try overrides.put("LOGNAME", "spoofed-logname");
    env_mod.test_overrides = &overrides;
    defer env_mod.test_overrides = null;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("home/.claude");
    try tmp.dir.makePath("accounts/work");
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const home = try std.fs.path.join(allocator, &.{ root, "home" });
    defer allocator.free(home);
    const config_dir = try std.fs.path.join(allocator, &.{ root, "accounts", "work" });
    defer allocator.free(config_dir);
    const secret_json = try testClaudeSecretJsonAlloc(allocator, config_dir, false, false);
    defer allocator.free(secret_json);
    const bytes = try testClaudeConfigJsonAlloc(allocator, &.{
        .{ .label = "work", .secret_json = secret_json, .config_dir = config_dir },
    });
    defer allocator.free(bytes);
    var parsed = try config.loadFromBytes(allocator, bytes);
    defer parsed.deinit();

    const effective_account = try os_account.effectiveUserNameAlloc(allocator);
    defer allocator.free(effective_account);
    const account_cfg = parsed.value.providers.map.get("claude").?.accounts.map.get("work").?;
    const backend = try config.resolveSecretBackend(account_cfg.secret);
    switch (backend) {
        .keychain => |ref| try std.testing.expectEqualStrings(effective_account, ref.account),
        else => return error.TestUnexpectedResult,
    }
    var resolved = try resolveConfiguredAccount(
        allocator,
        home,
        parsed.value,
        "claude",
        "work",
    );
    defer resolved.deinit(allocator);
    try std.testing.expectEqualStrings(effective_account, resolved.effective_account.?);
    const refresh_fingerprint = try repair_state.refreshStoreFingerprint(
        allocator,
        "claude",
        backend,
    );
    try std.testing.expectEqualSlices(
        u8,
        &refresh_fingerprint,
        &resolved.store_lock_key,
    );
}

test "independent config snapshots targeting one credential store cannot enter concurrently" {
    if (comptime builtin.os.tag != .macos and builtin.os.tag != .linux)
        return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const authority = try testAccountAuthorityAlloc(allocator);
    defer allocator.free(authority);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("home/.claude");
    try tmp.dir.makePath("accounts/shared");
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const home = try std.fs.path.join(allocator, &.{ root, "home" });
    defer allocator.free(home);
    const shared_dir = try std.fs.path.join(allocator, &.{ root, "accounts", "shared" });
    defer allocator.free(shared_dir);
    const secret_json = try testClaudeSecretJsonAlloc(allocator, shared_dir, false, false);
    defer allocator.free(secret_json);

    const first_bytes = try testClaudeConfigJsonAlloc(allocator, &.{
        .{ .label = "snapshot-a", .secret_json = secret_json, .config_dir = shared_dir },
    });
    defer allocator.free(first_bytes);
    var first_config = try config.loadFromBytes(allocator, first_bytes);
    defer first_config.deinit();
    const second_bytes = try testClaudeConfigJsonAlloc(allocator, &.{
        .{ .label = "snapshot-b", .secret_json = secret_json, .config_dir = shared_dir },
    });
    defer allocator.free(second_bytes);
    var second_config = try config.loadFromBytes(allocator, second_bytes);
    defer second_config.deinit();

    var first = try resolveConfiguredAccountWithAuthority(
        allocator,
        home,
        authority,
        first_config.value,
        "claude",
        "snapshot-a",
    );
    defer first.deinit(allocator);
    var second = try resolveConfiguredAccountWithAuthority(
        allocator,
        home,
        authority,
        second_config.value,
        "claude",
        "snapshot-b",
    );
    defer second.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &first.store_lock_key, &second.store_lock_key);

    var scope = try repair_state.TestRuntimeDirScope.init(allocator);
    defer scope.deinit(allocator);
    scope.activate();
    var inherited = std.process.EnvMap.init(allocator);
    defer inherited.deinit();
    var first_system = SystemContext{
        .allocator = allocator,
        .inherited_env = &inherited,
        .active_config = first_config.value,
    };
    var second_system = SystemContext{
        .allocator = allocator,
        .inherited_env = &inherited,
        .active_config = second_config.value,
    };
    try systemAcquireLocks(
        allocator,
        @ptrCast(&first_system),
        "claude",
        "snapshot-a",
        &first.store_lock_key,
    );
    defer systemReleaseLocks(@ptrCast(&first_system));

    const Probe = struct {
        const blocked: u8 = 1;
        const acquired: u8 = 2;
        const failed: u8 = 3;

        fn run(
            system: *SystemContext,
            store_lock_key: []const u8,
            outcome: *std.atomic.Value(u8),
        ) void {
            systemAcquireLocks(
                std.heap.page_allocator,
                @ptrCast(system),
                "claude",
                "snapshot-b",
                store_lock_key,
            ) catch |err| {
                outcome.store(
                    if (err == error.RepairInProgress) blocked else failed,
                    .seq_cst,
                );
                return;
            };
            systemReleaseLocks(@ptrCast(system));
            outcome.store(acquired, .seq_cst);
        }
    };
    var outcome = std.atomic.Value(u8).init(0);
    const worker = try std.Thread.spawn(
        .{},
        Probe.run,
        .{ &second_system, &second.store_lock_key, &outcome },
    );
    worker.join();
    try std.testing.expectEqual(Probe.blocked, outcome.load(.seq_cst));
    try std.testing.expect(second_system.account_lock == null);
    try std.testing.expect(second_system.store_lock == null);

    // The failed second acquisition unwinds its distinct label lock instead of
    // leaving the snapshot wedged behind the shared-store refusal.
    var second_label_lock = try repair_state.acquireRepairLock(
        allocator,
        "claude",
        "snapshot-b",
    );
    second_label_lock.release();
}
