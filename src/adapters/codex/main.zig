//! Codex adapter — `oauth-mux codex run`.
//!
//! Anchor: docs/spec/codex-adapter-contract-2026-05-03.md.
//!
//! Skeleton model: child-owned codex session. This gives
//! users the unmodified codex TUI/exec experience — we don't render a
//! TUI, don't drive JSON-RPC, don't spawn `codex app-server`. We:
//!   1. broker.populatePool from the active oauth-mux Config (profile
//!      filtered).
//!   2. account/select to pick a credited account.
//!   3. Resolve that account's auth.json source from the oauth-mux
//!      account store.
//!   4. Create a per-session CODEX_HOME overlay with copied auth material,
//!      generated proxy config.toml, and bridged session-authority paths.
//!   5. spawn `codex` with CODEX_HOME pointed at that overlay.
//!      The user sees real codex while oauth-mux keeps owning the
//!      proxy/broker boundary.
//!
//! The adapter writes a generated config.toml that points Codex at a
//! localhost wire proxy owned by oauth-mux. The parent process stays
//! alive to broker HTTP traffic and account selection while the Codex
//! child keeps the same process id.
//!
//! The JSON-RPC IDE-role client in app_server_client.zig stays for
//! future broker-mediated automation (the broker-* surfaces, scripted
//! use, Phase 4 demolition follow-ups). It is not on the
//! `oauth-mux codex run` default path.

const std = @import("std");
const builtin = @import("builtin");
const broker = @import("../../broker/mod.zig");
const broker_types = @import("../../broker/types.zig");
const broker_loader = @import("../../broker_loader.zig");
const cli = @import("../../cli.zig");
const config_mod = @import("../../config.zig");
const health_mod = @import("../../health.zig");
const paths = @import("../../paths.zig");
const pipeline = @import("../../pipeline.zig");
const runtime_mod = @import("../../runtime.zig");
const shell = @import("../../shell.zig");
const trace = @import("../../trace.zig");
const types = @import("../../types.zig");
const wire_proxy = @import("wire_proxy.zig");

pub const RunOptions = struct {
    profile: ?[]const u8 = null,
    capability: ?[]const u8 = null,
    account: ?[]const u8 = null,
    /// Optional canonical Codex session authority home. Defaults to the
    /// parent CODEX_HOME when set, otherwise ~/.codex.
    session_home: ?[]const u8 = null,
    /// If true, do not bridge canonical sessions/history into the
    /// managed CODEX_HOME overlay.
    isolated_session_store: bool = false,
    /// If true, emit NDJSON status frames to stderr.
    json_status: bool = false,
    /// Optional file path for NDJSON status frames. When set, status
    /// frames are written here instead of stderr so real Codex terminal
    /// output cannot corrupt the evidence stream.
    json_status_file: ?[]const u8 = null,
    /// Args after `--` to forward to codex unchanged.
    forward_argv: []const []const u8 = &.{},
};

pub const RunError = error{
    NoConfig,
    PoolPopulateFailed,
    NoAccountSelectable,
    NoCodexHome,
    SessionAuthorityUnavailable,
    SessionAuthorityLocked,
    ConfigOverrideUnavailable,
    CodexShimRecursion,
};

const SessionAuthorityMode = enum {
    canonical_bridge,
    isolated,

    fn toString(self: SessionAuthorityMode) []const u8 {
        return switch (self) {
            .canonical_bridge => "canonical_bridge",
            .isolated => "isolated",
        };
    }
};

const CodexSqliteAuthorityMode = enum {
    canonical_env,
    isolated_overlay,

    fn toString(self: CodexSqliteAuthorityMode) []const u8 {
        return switch (self) {
            .canonical_env => "canonical_env",
            .isolated_overlay => "isolated_overlay",
        };
    }
};

const SessionCodexHome = struct {
    path: []u8,
    session_authority: SessionAuthorityMode,
    sqlite_authority: CodexSqliteAuthorityMode,
    authority_home: ?[]u8 = null,
    config_authority_home: ?[]u8 = null,
    auth_initial_hash: [32]u8,
    config_source_present: bool = false,
    config_passthrough: bool = false,
    config_overridden_keys: usize = 0,
    experimental_feature_defaults_injected: usize = 0,
    mcp_stdio_unsupported_fields_removed: usize = 0,
    config_layout: []const u8 = "root_partitioned",

    fn deinit(self: SessionCodexHome, allocator: std.mem.Allocator) void {
        std.fs.cwd().deleteTree(self.path) catch {};
        allocator.free(self.path);
        if (self.authority_home) |home| allocator.free(home);
        if (self.config_authority_home) |home| allocator.free(home);
    }
};

const ResumeMode = enum {
    none,
    chooser,
    last,
    explicit,

    fn toString(self: ResumeMode) []const u8 {
        return switch (self) {
            .none => "none",
            .chooser => "chooser",
            .last => "last",
            .explicit => "explicit",
        };
    }
};

const ResumeRequest = struct {
    mode: ResumeMode = .none,
    explicit_id: ?[]const u8 = null,

    fn requested(self: ResumeRequest) bool {
        return self.mode != .none;
    }
};

const RolloutEntry = struct {
    size: u64,
    mtime: i128,
};

const RolloutSnapshot = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMapUnmanaged(RolloutEntry) = .{},

    fn init(allocator: std.mem.Allocator) RolloutSnapshot {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *RolloutSnapshot) void {
        var it = self.entries.keyIterator();
        while (it.next()) |key| self.allocator.free(key.*);
        self.entries.deinit(self.allocator);
    }

    fn count(self: *const RolloutSnapshot) usize {
        return self.entries.count();
    }
};

const ResumeLookupSource = enum {
    state_db,
    logs_db,
    session_index,
    filename_scan,
    not_scanned,

    fn toString(self: ResumeLookupSource) []const u8 {
        return switch (self) {
            .state_db => "state_db",
            .logs_db => "logs_db",
            .session_index => "session_index",
            .filename_scan => "filename_scan",
            .not_scanned => "not_scanned",
        };
    }
};

const RolloutTargetSnapshot = struct {
    allocator: std.mem.Allocator,
    path: []u8,
    entry: RolloutEntry,

    fn deinit(self: *RolloutTargetSnapshot) void {
        self.allocator.free(self.path);
    }
};

const ResumePreflightObservation = struct {
    lookup_source: ResumeLookupSource = .not_scanned,
    explicit_target_found_before: ?bool = null,
    target_snapshot: ?RolloutTargetSnapshot = null,

    fn deinit(self: *ResumePreflightObservation) void {
        if (self.target_snapshot) |*snapshot| snapshot.deinit();
    }

    fn rolloutsBefore(self: *const ResumePreflightObservation) usize {
        return if (self.target_snapshot != null) 1 else 0;
    }
};

const ResumeObservation = struct {
    rollouts_before: usize = 0,
    rollouts_after: usize = 0,
    changed_existing: usize = 0,
    created: usize = 0,
    explicit_target_found_before: ?bool = null,
    explicit_target_changed: ?bool = null,
    lookup_source: ResumeLookupSource = .not_scanned,
};

const ManagedConfigObservation = struct {
    source_present: bool = false,
    passthrough: bool = false,
    overridden_keys: usize = 0,
    experimental_feature_defaults_injected: usize = 0,
    mcp_stdio_unsupported_fields_removed: usize = 0,
    layout: []const u8 = "root_partitioned",
};

const codex_experimental_feature_defaults = [_][]const u8{
    "terminal_resize_reflow",
    "memories",
    "external_migration",
    "goals",
    "prevent_idle_sleep",
};

const CodexExperimentalFeatureDefaults = struct {
    seen: [codex_experimental_feature_defaults.len]bool = [_]bool{false} ** codex_experimental_feature_defaults.len,

    fn mark(self: *CodexExperimentalFeatureDefaults, key: []const u8) void {
        const normalized = std.mem.trim(u8, key, " \t\r\n\"'");
        inline for (codex_experimental_feature_defaults, 0..) |feature, idx| {
            if (std.mem.eql(u8, normalized, feature)) {
                self.seen[idx] = true;
                return;
            }
        }
    }

    fn writeMissingAsTableEntries(self: *CodexExperimentalFeatureDefaults, writer: anytype) !usize {
        var injected: usize = 0;
        inline for (codex_experimental_feature_defaults, 0..) |feature, idx| {
            if (!self.seen[idx]) {
                try writer.print("{s} = true\n", .{feature});
                self.seen[idx] = true;
                injected += 1;
            }
        }
        return injected;
    }

    fn writeMissingAsRootDotted(self: *CodexExperimentalFeatureDefaults, writer: anytype) !usize {
        var injected: usize = 0;
        inline for (codex_experimental_feature_defaults, 0..) |feature, idx| {
            if (!self.seen[idx]) {
                try writer.print("features.{s} = true\n", .{feature});
                self.seen[idx] = true;
                injected += 1;
            }
        }
        return injected;
    }
};

const ConfigOverrideCheck = struct {
    ok: bool = true,
    total_config_overrides: usize = 0,
    mux_owned_overrides: usize = 0,
    model_provider_override: bool = false,
    openai_base_url_override: bool = false,
    managed_provider_override: bool = false,
};

const TomlBufferedTable = struct {
    active: bool = false,
    skip: bool = false,
    features: bool = false,
    mcp_server: bool = false,
    mcp_has_command: bool = false,
    mcp_unsupported_stdio_fields: usize = 0,
    lines: std.ArrayListUnmanaged(u8) = .{},

    fn deinit(self: *TomlBufferedTable, allocator: std.mem.Allocator) void {
        self.lines.deinit(allocator);
    }

    fn reset(self: *TomlBufferedTable) void {
        self.active = false;
        self.skip = false;
        self.features = false;
        self.mcp_server = false;
        self.mcp_has_command = false;
        self.mcp_unsupported_stdio_fields = 0;
        self.lines.clearRetainingCapacity();
    }

    fn start(
        self: *TomlBufferedTable,
        allocator: std.mem.Allocator,
        header: []const u8,
        skip: bool,
        features: bool,
        mcp_server: bool,
    ) !void {
        self.reset();
        self.active = true;
        self.skip = skip;
        self.features = features;
        self.mcp_server = mcp_server;
        if (!skip) {
            try self.lines.writer(allocator).writeAll(header);
            try self.lines.writer(allocator).writeAll("\n");
        }
    }

    fn appendLine(self: *TomlBufferedTable, allocator: std.mem.Allocator, line: []const u8) !void {
        if (self.skip) return;
        try self.lines.writer(allocator).writeAll(line);
        try self.lines.writer(allocator).writeAll("\n");
    }
};

const LaunchTimer = struct {
    started_ns: i128,
    last_ns: i128,

    fn start() LaunchTimer {
        const now = std.time.nanoTimestamp();
        return .{ .started_ns = now, .last_ns = now };
    }

    fn mark(self: *LaunchTimer, writer: anytype, emit: bool, phase: []const u8) !void {
        const now = std.time.nanoTimestamp();
        const duration_ms = @divTrunc(now - self.last_ns, std.time.ns_per_ms);
        const elapsed_ms = @divTrunc(now - self.started_ns, std.time.ns_per_ms);
        self.last_ns = now;
        if (!emit) return;
        try writer.print(
            "{{\"kind\":\"launch_timing\",\"phase\":\"{s}\",\"duration_ms\":{d},\"elapsed_ms\":{d},\"path_printed\":false,\"token_material_printed\":false,\"session_id_printed\":false}}\n",
            .{ phase, duration_ms, elapsed_ms },
        );
    }
};

const AuthWritebackObservation = struct {
    overlay_auth_present: bool = false,
    source_auth_present: bool = false,
    changed: bool = false,
    written: bool = false,
    source_conflict: bool = false,
    ok: bool = true,
    error_name: ?[]const u8 = null,
};

const ManagedAuthHealthObservation = struct {
    recorded: bool = false,
    reason: []const u8 = "not_observed",
};

const SqliteAuthorityLockObservation = struct {
    checked: bool = false,
    ok: bool = true,
    diagnostic: []const u8 = "not_checked",
    sqlite_authority: CodexSqliteAuthorityMode = .isolated_overlay,
    db_basename: []const u8 = "state_5.sqlite",
    sqlite_error_class: ?[]const u8 = null,
    sqlite_error_code: ?u8 = null,
    next_action: []const u8 = "none",

    fn locked(self: SqliteAuthorityLockObservation) bool {
        return self.checked and !self.ok;
    }
};

const FinalSessionStatus = struct {
    aborted: bool = false,
    reason: []const u8 = "child_exit",
    term: ?std.process.Child.Term = null,
    wait_error: ?[]const u8 = null,
};

fn childTermKind(term: std.process.Child.Term) []const u8 {
    return switch (term) {
        .Exited => "exited",
        .Signal => "signal",
        .Stopped => "stopped",
        .Unknown => "unknown",
    };
}

fn childTermCode(term: std.process.Child.Term) u32 {
    return switch (term) {
        .Exited => |code| code,
        .Signal => |signal| signal,
        .Stopped => |signal| signal,
        .Unknown => |code| code,
    };
}

fn childTermAbortReason(term: std.process.Child.Term) ?[]const u8 {
    return switch (term) {
        .Exited => |code| if (code == 0) null else "child_exit_nonzero",
        .Signal => "child_signal",
        .Stopped => "child_stopped",
        .Unknown => "child_unknown",
    };
}

fn childSignalName(code: u32) ?[]const u8 {
    return switch (code) {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        6 => "SIGABRT",
        9 => "SIGKILL",
        15 => "SIGTERM",
        else => null,
    };
}

const SessionAuthorityEntryKind = enum {
    directory,
    file,
};

const SessionAuthorityEntry = struct {
    name: []const u8,
    kind: SessionAuthorityEntryKind,
};

const codex_session_authority_entries = [_]SessionAuthorityEntry{
    .{ .name = "sessions", .kind = .directory },
    .{ .name = "shell_snapshots", .kind = .directory },
    .{ .name = "history.jsonl", .kind = .file },
    .{ .name = "session_index.jsonl", .kind = .file },
};

const codex_optional_state_authority_entries = [_]SessionAuthorityEntry{
    .{ .name = "state_5.sqlite", .kind = .file },
    .{ .name = "state_5.sqlite-wal", .kind = .file },
    .{ .name = "state_5.sqlite-shm", .kind = .file },
};

const codex_optional_logs_authority_entries = [_]SessionAuthorityEntry{
    .{ .name = "logs_2.sqlite", .kind = .file },
    .{ .name = "logs_2.sqlite-wal", .kind = .file },
    .{ .name = "logs_2.sqlite-shm", .kind = .file },
};

const legacy_codex_provider_namespace = "oauth_mux_openai";

const ResumeAuthorityCheck = struct {
    mode: ResumeMode,
    authority: SessionAuthorityMode,
    sqlite_authority: CodexSqliteAuthorityMode,
    required_total: usize = codex_session_authority_entries.len,
    canonical_present: usize = 0,
    overlay_present: usize = 0,
    state_db_canonical_present: bool = false,
    state_db_overlay_present: bool = false,
    state_db_bridged: bool = false,
    logs_db_canonical_present: bool = false,
    logs_db_overlay_present: bool = false,
    logs_db_bridged: bool = false,
    legacy_provider_namespace_detected: bool = false,
    legacy_provider_namespace_state_db_detected: bool = false,
    legacy_provider_namespace_logs_db_detected: bool = false,
    legacy_provider_namespace_scan_truncated: bool = false,
    legacy_provider_namespace_scan_errors: usize = 0,
    ok: bool = false,
    diagnostic: []const u8 = "not_checked",
};

const LegacyProviderNamespaceScan = struct {
    detected: bool = false,
    state_db_detected: bool = false,
    logs_db_detected: bool = false,
    truncated: bool = false,
    errors: usize = 0,
};

const FileNeedleScan = struct {
    found: bool = false,
    truncated: bool = false,
};

const max_legacy_provider_namespace_scan_bytes: u64 = 32 * 1024 * 1024;

/// Resolve the account's source auth.json path. Order:
///   1. secret.path when secret.backend == "file" (the normal
///      oauth-mux enrollment shape).
///   2. AccountConfig.config_dir/auth.json when config_dir exists.
fn resolveCodexAuthPath(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    account_id: []const u8,
) !?[]u8 {
    const colon = std.mem.indexOfScalar(u8, account_id, ':') orelse return null;
    const provider = account_id[0..colon];
    const account = account_id[colon + 1 ..];

    const provider_cfg = cfg.providers.map.get(provider) orelse return null;
    const acct_cfg = provider_cfg.accounts.map.get(account) orelse return null;

    if (std.mem.eql(u8, acct_cfg.secret.backend, "file")) {
        const path = acct_cfg.secret.path orelse return null;
        return try expandTilde(allocator, path);
    }
    if (acct_cfg.config_dir) |cd| {
        const dir = try expandTilde(allocator, cd);
        defer allocator.free(dir);
        return try std.fs.path.join(allocator, &.{ dir, "auth.json" });
    }
    return null;
}

fn expandTilde(allocator: std.mem.Allocator, p: []const u8) ![]u8 {
    if (!std.mem.startsWith(u8, p, "~/")) return try allocator.dupe(u8, p);
    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    return try std.fmt.allocPrint(allocator, "{s}{s}", .{ home, p[1..] });
}

fn getEnvOwnedOrDefault(
    allocator: std.mem.Allocator,
    name: []const u8,
    fallback: []const u8,
) ![]u8 {
    return std.process.getEnvVarOwned(allocator, name) catch |e| switch (e) {
        error.EnvironmentVariableNotFound => try allocator.dupe(u8, fallback),
        else => return e,
    };
}

fn envFlag(name: []const u8) bool {
    const value = std.process.getEnvVarOwned(std.heap.page_allocator, name) catch return false;
    defer std.heap.page_allocator.free(value);
    return std.mem.eql(u8, value, "1") or std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "yes");
}

fn isCodexAccountId(account_id: []const u8) bool {
    return std.mem.startsWith(u8, account_id, "codex:");
}

const ManagedCapabilityResolution = union(enum) {
    none,
    capability: []const u8,
    ambiguous,
};

fn managedRouteCapability(
    cfg: config_mod.Config,
    explicit_capability: ?[]const u8,
    profile_name: ?[]const u8,
) ManagedCapabilityResolution {
    if (explicit_capability) |capability| return .{ .capability = capability };
    const profile = cfg.profiles.map.get(profile_name orelse return .none) orelse return .none;

    var found: ?[]const u8 = null;
    for (profile.providers) |entry| {
        const hash = std.mem.indexOfScalar(u8, entry, '#') orelse continue;
        const head = entry[0..hash];
        if (!std.mem.startsWith(u8, head, "codex:")) continue;
        const capability = entry[hash + 1 ..];
        if (found) |existing| {
            if (!std.mem.eql(u8, existing, capability)) return .ambiguous;
        } else {
            found = capability;
        }
    }
    if (found) |capability| return .{ .capability = capability };
    return .none;
}

fn codexAccountLabel(account_id: []const u8) []const u8 {
    const colon = std.mem.indexOfScalar(u8, account_id, ':') orelse return account_id;
    if (colon + 1 >= account_id.len) return account_id;
    return account_id[colon + 1 ..];
}

fn traceManagedOverlay(
    allocator: std.mem.Allocator,
    account_id: []const u8,
    profile: ?[]const u8,
    proxy_port: u16,
    codex_home: *const SessionCodexHome,
) void {
    trace.append(allocator, "codex.managed.overlay", .info, &.{
        trace.string("provider", "codex"),
        trace.string("account_label", codexAccountLabel(account_id)),
        trace.string("profile", profile orelse "none"),
        trace.string("auth_authority", "mux_owned_overlay"),
        trace.string("managed_config", "mux_owned_overlay"),
        trace.string("config_layout", codex_home.config_layout),
        trace.string("session_authority", codex_home.session_authority.toString()),
        trace.string("sqlite_authority", codex_home.sqlite_authority.toString()),
        trace.boolean("config_passthrough", codex_home.config_passthrough),
        trace.boolean("user_config_present", codex_home.config_source_present),
        trace.uint("config_overridden_keys", @intCast(codex_home.config_overridden_keys)),
        trace.uint("experimental_feature_defaults_injected", @intCast(codex_home.experimental_feature_defaults_injected)),
        trace.uint("mcp_stdio_unsupported_fields_removed", @intCast(codex_home.mcp_stdio_unsupported_fields_removed)),
        trace.uint("proxy_port", proxy_port),
        trace.boolean("codex_home_path_printed", false),
        trace.boolean("config_paths_printed", false),
        trace.boolean("session_paths_printed", false),
        trace.boolean("token_material_printed", false),
    });
}

fn traceManagedSessionStart(
    allocator: std.mem.Allocator,
    account_id: []const u8,
    profile: ?[]const u8,
    forwarded_arg_count: usize,
    resume_mode: ResumeMode,
    codex_home: *const SessionCodexHome,
) void {
    trace.append(allocator, "codex.managed.session_start", .info, &.{
        trace.string("provider", "codex"),
        trace.string("account_label", codexAccountLabel(account_id)),
        trace.string("profile", profile orelse "none"),
        trace.string("claim_level", "broker_owned"),
        trace.string("resume_mode", resume_mode.toString()),
        trace.string("session_authority", codex_home.session_authority.toString()),
        trace.string("sqlite_authority", codex_home.sqlite_authority.toString()),
        trace.uint("forwarded_arg_count", @intCast(forwarded_arg_count)),
        trace.boolean("child_stdio_inherited", true),
        trace.boolean("codex_home_path_printed", false),
        trace.boolean("session_ids_printed", false),
        trace.boolean("token_material_printed", false),
    });
}

fn traceManagedSessionEnd(
    allocator: std.mem.Allocator,
    proxy: *const wire_proxy.Proxy,
    codex_home: *const SessionCodexHome,
    aborted: bool,
    reason: []const u8,
    exit_code: i32,
    term: ?std.process.Child.Term,
) void {
    trace.append(allocator, "codex.managed.session_end", if (aborted) .warn else .info, &.{
        trace.string("provider", "codex"),
        trace.string("terminal_event", if (aborted) "session_aborted" else "session_ended"),
        trace.string("reason", reason),
        trace.int("exit_code", exit_code),
        trace.string("term_kind", if (term) |value| childTermKind(value) else "none"),
        trace.int("term_code", if (term) |value| childTermCode(value) else -1),
        trace.string("final_claim_level", proxy.peakClaimLevel().toString()),
        trace.string("session_authority", codex_home.session_authority.toString()),
        trace.string("sqlite_authority", codex_home.sqlite_authority.toString()),
        trace.boolean("synthetic_swap_observed", proxy.syntheticSwapSeen()),
        trace.boolean("codex_home_path_printed", false),
        trace.boolean("token_material_printed", false),
    });
}

fn traceManagedCodexBinaryResolution(
    allocator: std.mem.Allocator,
    source: []const u8,
    requested: []const u8,
    selected: bool,
    reason: []const u8,
) void {
    trace.append(allocator, "codex.native_binary.resolve", if (selected) .info else .warn, &.{
        trace.string("adapter", "managed_codex"),
        trace.string("source", source),
        trace.string("requested_kind", if (hasPathSeparator(requested)) "path" else "search_name"),
        trace.boolean("selected", selected),
        trace.string("reason", reason),
        trace.boolean("path_printed", false),
        trace.boolean("native_binary_path_printed", false),
    });
}

fn restrictPoolToCodex(pool: *broker.AccountPool) void {
    for (pool.accounts.items) |*entry| {
        if (isCodexAccountId(entry.id)) continue;
        entry.selectable = false;
        entry.liveness = .unknown;
        entry.availability = .unknown;
        entry.next_eligible_at = null;
    }
}

fn codexSelectableCount(pool: *const broker.AccountPool) usize {
    var count: usize = 0;
    for (pool.accounts.items) |entry| {
        if (isCodexAccountId(entry.id) and entry.selectable and entry.availability == .available) count += 1;
    }
    return count;
}

const AutoRevalidationRoute = struct {
    account: []const u8,
    capability: []const u8,
};

const AutoRevalidationSummary = struct {
    admitted: bool = false,
    attempted: usize = 0,
    provider_evidence_routes: usize = 0,
    available_after: usize = 0,
    blocked_after: usize = 0,
    probe_errors: usize = 0,
    skipped: usize = 0,
    reason: []const u8 = "not_attempted",

    fn changedRouteHealth(self: AutoRevalidationSummary) bool {
        return self.provider_evidence_routes != 0 or self.available_after != 0 or self.blocked_after != 0;
    }
};

fn maybeAutoRevalidateCodexRoutes(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    store: *health_mod.HealthStore,
    profile: ?[]const u8,
    capability_filter: ?[]const u8,
    account_filter: ?[]const u8,
    initial_selectable_routes: usize,
    target_selectable_routes: usize,
    writer: anytype,
    emit_status: bool,
) !AutoRevalidationSummary {
    if (!cfg.policy.codex.auto_stay_afloat) return .{ .reason = "codex_auto_stay_afloat_disabled" };
    if (!cfg.policy.codex.allow_provider_spend) return .{ .reason = "provider_spend_not_allowed" };

    var seen = std.StringHashMap(void).init(allocator);
    defer {
        var key_it = seen.keyIterator();
        while (key_it.next()) |key| allocator.free(key.*);
        seen.deinit();
    }
    var candidates = std.ArrayList(AutoRevalidationRoute).init(allocator);
    defer {
        for (candidates.items) |route| {
            allocator.free(route.account);
            allocator.free(route.capability);
        }
        candidates.deinit();
    }

    try collectProfileCodexAutoRevalidationRoutes(allocator, cfg, profile, capability_filter, account_filter, &seen, &candidates);
    try collectHealthCodexAutoRevalidationRoutes(allocator, cfg, store, capability_filter, account_filter, &seen, &candidates);

    var summary = AutoRevalidationSummary{ .admitted = true };
    if (candidates.items.len == 0) {
        summary.reason = "no_expired_codex_routes";
        if (emit_status) try writeAutoRevalidationStatus(writer, summary);
        return summary;
    }

    for (candidates.items) |route| {
        if (initial_selectable_routes + summary.available_after >= target_selectable_routes) break;
        const key = health_mod.capabilityKey("codex", route.account, route.capability);
        const health = store.accounts.get(key.slice()) orelse {
            summary.skipped += 1;
            continue;
        };
        if (!codexHealthNeedsAutoRevalidation(health)) {
            summary.skipped += 1;
            continue;
        }

        summary.attempted += 1;
        const previous = takeHealthEntry(store, key.slice());

        var ctx = pipeline.Context.init(allocator, cfg, store);
        defer ctx.deinit();
        ctx.provider_name = "codex";
        ctx.account_name = route.account;
        ctx.capability_name = route.capability;

        const probe_result = pipeline.runProbe(&ctx);
        var recorded_provider_evidence = true;
        if (probe_result) |_| {} else |e| {
            if (autoRevalidationErrorRecordedEvidence(e)) {
                summary.provider_evidence_routes += 1;
            } else {
                recorded_provider_evidence = false;
                summary.probe_errors += 1;
                if (store.accounts.get(key.slice()) == null) {
                    if (previous) |prev| {
                        try putHealthEntryCopy(store, key.slice(), prev);
                    }
                }
            }
        }

        if (probe_result) |_| {
            summary.provider_evidence_routes += 1;
        } else |_| {}
        if (recorded_provider_evidence) {
            if (store.accounts.get(key.slice())) |after| {
                if (codexHealthAvailable(after)) {
                    summary.available_after += 1;
                } else if (codexHealthBlocksRoute(after)) {
                    summary.blocked_after += 1;
                }
            }
        }
    }

    store.persist();
    summary.reason = if (summary.attempted == 0)
        "no_expired_codex_routes"
    else if (summary.probe_errors != 0)
        "auto_revalidation_probe_errors"
    else if (summary.available_after != 0)
        "auto_revalidation_found_available_route"
    else
        "provider_evidence_still_blocked";

    if (emit_status) try writeAutoRevalidationStatus(writer, summary);
    return summary;
}

fn collectProfileCodexAutoRevalidationRoutes(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    profile: ?[]const u8,
    capability_filter: ?[]const u8,
    account_filter: ?[]const u8,
    seen: *std.StringHashMap(void),
    out: *std.ArrayList(AutoRevalidationRoute),
) !void {
    if (profile) |name| {
        if (cfg.profiles.map.get(name)) |profile_cfg| {
            try collectProfileEntriesForCodexAutoRevalidation(allocator, cfg, profile_cfg.providers, capability_filter, account_filter, seen, out);
        }
        return;
    }

    var profiles = cfg.profiles.map.iterator();
    while (profiles.next()) |entry| {
        try collectProfileEntriesForCodexAutoRevalidation(allocator, cfg, entry.value_ptr.providers, capability_filter, account_filter, seen, out);
    }
}

fn collectProfileEntriesForCodexAutoRevalidation(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    entries: []const []const u8,
    capability_filter: ?[]const u8,
    account_filter: ?[]const u8,
    seen: *std.StringHashMap(void),
    out: *std.ArrayList(AutoRevalidationRoute),
) !void {
    const provider = cfg.providers.map.get("codex") orelse return;
    for (entries) |entry| {
        const parsed = health_mod.parseHealthKey(entry) orelse continue;
        if (!std.mem.eql(u8, parsed.provider, "codex")) continue;
        const capability = parsed.capability orelse continue;
        if (capability_filter) |filter| {
            if (!std.mem.eql(u8, filter, capability)) continue;
        }
        if (account_filter) |filter| {
            if (!codexAccountFilterMatches(filter, parsed.account)) continue;
        }
        if (provider.accounts.map.get(parsed.account) == null) continue;
        try appendAutoRevalidationRoute(allocator, seen, out, parsed.account, capability);
    }
}

fn collectHealthCodexAutoRevalidationRoutes(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    store: *health_mod.HealthStore,
    capability_filter: ?[]const u8,
    account_filter: ?[]const u8,
    seen: *std.StringHashMap(void),
    out: *std.ArrayList(AutoRevalidationRoute),
) !void {
    const provider = cfg.providers.map.get("codex") orelse return;
    var it = store.accounts.iterator();
    while (it.next()) |entry| {
        const parsed = health_mod.parseHealthKey(entry.key_ptr.*) orelse continue;
        if (!std.mem.eql(u8, parsed.provider, "codex")) continue;
        const capability = parsed.capability orelse continue;
        if (capability_filter) |filter| {
            if (!std.mem.eql(u8, filter, capability)) continue;
        }
        if (account_filter) |filter| {
            if (!codexAccountFilterMatches(filter, parsed.account)) continue;
        }
        if (provider.accounts.map.get(parsed.account) == null) continue;
        if (!codexHealthNeedsAutoRevalidation(entry.value_ptr.*)) continue;
        try appendAutoRevalidationRoute(allocator, seen, out, parsed.account, capability);
    }
}

fn appendAutoRevalidationRoute(
    allocator: std.mem.Allocator,
    seen: *std.StringHashMap(void),
    out: *std.ArrayList(AutoRevalidationRoute),
    account: []const u8,
    capability: []const u8,
) !void {
    const key = try std.fmt.allocPrint(allocator, "codex:{s}#{s}", .{ account, capability });
    defer allocator.free(key);
    if (seen.contains(key)) return;
    const account_copy = try allocator.dupe(u8, account);
    errdefer allocator.free(account_copy);
    const capability_copy = try allocator.dupe(u8, capability);
    errdefer allocator.free(capability_copy);
    try seen.put(try allocator.dupe(u8, key), {});
    try out.append(.{ .account = account_copy, .capability = capability_copy });
}

fn codexAccountFilterMatches(filter: []const u8, account: []const u8) bool {
    if (std.mem.eql(u8, filter, account)) return true;
    if (std.mem.startsWith(u8, filter, "codex:")) return std.mem.eql(u8, filter["codex:".len..], account);
    return false;
}

fn codexHealthNeedsAutoRevalidation(health: health_mod.AccountHealth) bool {
    const now = std.time.timestamp();
    return switch (health.liveness) {
        .live => |live| switch (live.availability) {
            .quota_exhausted => |quota| if (quota.window_resets_at) |reset| reset <= now else false,
            .rate_limited => health.rate_limited_until != null and health.rate_limited_until.? <= now,
            .available, .cooldown => false,
        },
        .dead, .degraded => false,
    };
}

fn codexHealthAvailable(health: health_mod.AccountHealth) bool {
    return switch (health.liveness) {
        .live => |live| live.availability == .available,
        .dead, .degraded => false,
    };
}

fn codexHealthBlocksRoute(health: health_mod.AccountHealth) bool {
    return switch (health.liveness) {
        .dead, .degraded => true,
        .live => |live| live.availability != .available,
    };
}

fn autoRevalidationErrorRecordedEvidence(e: types.PipelineError) bool {
    return switch (e) {
        error.AllAccountsExhausted => true,
        else => false,
    };
}

fn takeHealthEntry(store: *health_mod.HealthStore, key: []const u8) ?health_mod.AccountHealth {
    if (store.accounts.fetchRemove(key)) |kv| {
        defer store.allocator.free(kv.key);
        return kv.value;
    }
    return null;
}

fn putHealthEntryCopy(store: *health_mod.HealthStore, key: []const u8, health: health_mod.AccountHealth) !void {
    const result = try store.accounts.getOrPut(key);
    if (!result.found_existing) {
        result.key_ptr.* = try store.allocator.dupe(u8, key);
    }
    result.value_ptr.* = health;
}

fn writeAutoRevalidationStatus(writer: anytype, summary: AutoRevalidationSummary) !void {
    try writer.print(
        "{{\"kind\":\"codex_auto_revalidation\",\"admitted\":{any},\"attempted\":{d},\"provider_evidence_routes\":{d},\"available_after\":{d},\"blocked_after\":{d},\"probe_errors\":{d},\"skipped\":{d},\"reason\":\"{s}\",\"spends_provider_calls\":{any},\"mutates_route_health\":{any}}}\n",
        .{ summary.admitted, summary.attempted, summary.provider_evidence_routes, summary.available_after, summary.blocked_after, summary.probe_errors, summary.skipped, summary.reason, summary.attempted != 0, summary.changedRouteHealth() },
    );
}

fn hasPathSeparator(value: []const u8) bool {
    return std.mem.indexOfScalar(u8, value, '/') != null or std.mem.indexOfScalar(u8, value, '\\') != null;
}

fn fileExists(path: []const u8) bool {
    if (std.fs.path.isAbsolute(path)) {
        std.fs.accessAbsolute(path, .{}) catch return false;
    } else {
        std.fs.cwd().access(path, .{}) catch return false;
    }
    return true;
}

fn readFilePrefix(path: []const u8, buf: []u8) !usize {
    var file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{})
    else
        try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try file.read(buf);
}

fn isOauthMuxCodexShim(path: []const u8) bool {
    var buf: [4096]u8 = undefined;
    const len = readFilePrefix(path, &buf) catch return false;
    const data = buf[0..len];
    return std.mem.indexOf(u8, data, "OMUX_CODEX_SHIM") != null;
}

fn resolveExecutableFromSearchPath(
    allocator: std.mem.Allocator,
    name: []const u8,
    search_path: []const u8,
) !?[]u8 {
    var it = std.mem.tokenizeScalar(u8, search_path, std.fs.path.delimiter);
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = try std.fs.path.join(allocator, &.{ dir, name });
        errdefer allocator.free(candidate);
        if (fileExists(candidate)) {
            if (isOauthMuxCodexShim(candidate)) {
                allocator.free(candidate);
                continue;
            }
            return candidate;
        }
        allocator.free(candidate);
    }
    return null;
}

fn appendFallbackExecutableDirs(
    allocator: std.mem.Allocator,
    list: *std.ArrayListUnmanaged([]const u8),
) !void {
    if (std.process.getEnvVarOwned(allocator, "HOME")) |home| {
        defer allocator.free(home);
        try list.append(allocator, try std.fs.path.join(allocator, &.{ home, ".local", "bin" }));
        try list.append(allocator, try std.fs.path.join(allocator, &.{ home, ".nix-profile", "bin" }));
    } else |_| {}
    try list.append(allocator, try allocator.dupe(u8, "/opt/homebrew/bin"));
    try list.append(allocator, try allocator.dupe(u8, "/usr/local/bin"));
    try list.append(allocator, try allocator.dupe(u8, "/usr/bin"));
    try list.append(allocator, try allocator.dupe(u8, "/bin"));
}

fn resolveCodexBinary(
    allocator: std.mem.Allocator,
    requested: []const u8,
) ![]u8 {
    if (hasPathSeparator(requested)) {
        const expanded = try expandTilde(allocator, requested);
        if (!fileExists(expanded)) {
            allocator.free(expanded);
            return error.FileNotFound;
        }
        if (isOauthMuxCodexShim(expanded)) {
            allocator.free(expanded);
            return RunError.CodexShimRecursion;
        }
        return expanded;
    }

    if (std.process.getEnvVarOwned(allocator, "PATH")) |path_env| {
        defer allocator.free(path_env);
        if (try resolveExecutableFromSearchPath(allocator, requested, path_env)) |resolved| return resolved;
    } else |_| {}

    var fallback_dirs = std.ArrayListUnmanaged([]const u8){};
    defer {
        for (fallback_dirs.items) |dir| allocator.free(dir);
        fallback_dirs.deinit(allocator);
    }
    try appendFallbackExecutableDirs(allocator, &fallback_dirs);
    for (fallback_dirs.items) |dir| {
        const candidate = try std.fs.path.join(allocator, &.{ dir, requested });
        errdefer allocator.free(candidate);
        if (fileExists(candidate)) {
            if (isOauthMuxCodexShim(candidate)) {
                allocator.free(candidate);
                continue;
            }
            return candidate;
        }
        allocator.free(candidate);
    }

    return error.FileNotFound;
}

fn defaultStatusFilePath(allocator: std.mem.Allocator) ![]u8 {
    const state_dir = try paths.stateDir(allocator);
    defer allocator.free(state_dir);
    return std.fmt.allocPrint(
        allocator,
        "{s}/codex/status/managed-{d}.ndjson",
        .{ state_dir, std.time.milliTimestamp() },
    );
}

pub fn run(allocator: std.mem.Allocator, opts: RunOptions) !void {
    const stderr = std.io.getStdErr().writer();
    var launch_timer = LaunchTimer.start();
    var emit_status = opts.json_status or opts.json_status_file != null;
    var session_started_emitted = false;

    var status_file: ?std.fs.File = null;
    defer if (status_file) |*file| file.close();
    var owned_status_path: ?[]u8 = null;
    defer if (owned_status_path) |path| allocator.free(path);
    var status_file_path: ?[]const u8 = null;
    if (opts.json_status_file) |path| {
        status_file_path = path;
    } else if (!opts.json_status) {
        owned_status_path = defaultStatusFilePath(allocator) catch |e| path_err: {
            try stderr.print("oauth-mux codex: default status file unavailable: {s}\n", .{@errorName(e)});
            break :path_err null;
        };
        status_file_path = owned_status_path;
    }
    var status_writer = stderr.any();
    if (status_file_path) |path| {
        status_file = openStatusFile(path) catch |e| open_err: {
            if (opts.json_status_file != null) {
                try stderr.print("oauth-mux codex: cannot open --json-status-file: {s}\n", .{@errorName(e)});
                return e;
            }
            try stderr.print("oauth-mux codex: default status file unavailable: {s}\n", .{@errorName(e)});
            status_file_path = null;
            break :open_err null;
        };
        if (status_file) |*file| {
            status_writer = file.writer().any();
            emit_status = true;
        }
    }

    // 1. Load oauth-mux config + populate broker pool.
    const parsed = config_mod.load(allocator) catch |e| {
        try stderr.print("oauth-mux codex: config load: {s}\n", .{@errorName(e)});
        try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "config_load_failed", "config_load", @errorName(e), session_started_emitted);
        return RunError.NoConfig;
    };
    defer parsed.deinit();

    const route_capability = switch (managedRouteCapability(parsed.value, opts.capability, opts.profile)) {
        .capability => |capability| capability,
        .none => null,
        .ambiguous => {
            try stderr.writeAll("oauth-mux codex: profile has multiple Codex capabilities; pass --capability for managed launch\n");
            try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "no_account_selectable", "route_election", "NoAccountSelectable", session_started_emitted);
            return RunError.NoAccountSelectable;
        },
    };

    var server = broker.Server.init(allocator);
    defer server.deinit();
    var route_health = health_mod.HealthStore.load(allocator, .{});
    defer route_health.deinit();
    broker_loader.populatePoolFromRouteHealthScoped(&server.pool, parsed.value, opts.profile, route_capability, &route_health) catch {
        try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "pool_populate_failed", "config_health_load", "PoolPopulateFailed", session_started_emitted);
        return RunError.PoolPopulateFailed;
    };
    restrictPoolToCodex(&server.pool);
    try launch_timer.mark(status_writer, emit_status, "config_health_load");

    const initial_selectable_routes = codexSelectableCount(&server.pool);
    const target_selectable_routes: usize = if (opts.account != null) 1 else 2;
    if (initial_selectable_routes < target_selectable_routes) {
        const revalidation = try maybeAutoRevalidateCodexRoutes(
            allocator,
            parsed.value,
            &route_health,
            opts.profile,
            route_capability,
            opts.account,
            initial_selectable_routes,
            target_selectable_routes,
            status_writer,
            emit_status,
        );
        if (revalidation.changedRouteHealth()) {
            server.pool.deinit();
            server.pool = broker.AccountPool.init(allocator);
            broker_loader.populatePoolFromRouteHealthScoped(&server.pool, parsed.value, opts.profile, route_capability, &route_health) catch {
                try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "pool_populate_failed", "codex_auto_revalidation", "PoolPopulateFailed", session_started_emitted);
                return RunError.PoolPopulateFailed;
            };
            restrictPoolToCodex(&server.pool);
        }
        try launch_timer.mark(status_writer, emit_status, "codex_auto_revalidation");
    }

    // 2. Elect an account (honoring --account pin if set).
    const elected = if (opts.account) |pin| pin: {
        if (!isCodexAccountId(pin)) {
            try stderr.print("oauth-mux codex: --account {s} is not a codex account\n", .{pin});
            try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "no_account_selectable", "route_election", "NoAccountSelectable", session_started_emitted);
            return RunError.NoAccountSelectable;
        }
        for (server.pool.accounts.items) |a| {
            if (std.mem.eql(u8, a.id, pin)) {
                if (!a.selectable or a.availability != .available) {
                    try stderr.print("oauth-mux codex: --account {s} is not selectable for the requested profile/capability\n", .{pin});
                    try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "no_account_selectable", "route_election", "NoAccountSelectable", session_started_emitted);
                    return RunError.NoAccountSelectable;
                }
                break :pin a;
            }
        }
        try stderr.print("oauth-mux codex: --account {s} not in profile\n", .{pin});
        try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "no_account_selectable", "route_election", "NoAccountSelectable", session_started_emitted);
        return RunError.NoAccountSelectable;
    } else server.pool.elect(opts.profile, route_capability, &.{}) catch |e| switch (e) {
        broker_types.BrokerError.NoAccountSelectable => {
            try stderr.writeAll("oauth-mux codex: no selectable account in profile\n");
            try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "no_account_selectable", "route_election", "NoAccountSelectable", session_started_emitted);
            return RunError.NoAccountSelectable;
        },
        else => return e,
    };
    try launch_timer.mark(status_writer, emit_status, "route_election");

    // 3. Resolve the selected account auth source. Runtime CODEX_HOME
    // is a per-session overlay, never the shared account store.
    const source_auth_path = (try resolveCodexAuthPath(allocator, parsed.value, elected.id)) orelse {
        try stderr.print(
            "oauth-mux codex: cannot resolve auth.json for {s}; account needs config_dir or file secret\n",
            .{elected.id},
        );
        try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "codex_home_unavailable", "auth_refresh_preflight", "NoCodexHome", session_started_emitted);
        return RunError.NoCodexHome;
    };
    defer allocator.free(source_auth_path);
    try launch_timer.mark(status_writer, emit_status, "auth_refresh_preflight");

    // 4. Bind the wire-layer reverse proxy. The adapter stays alive
    // as the broker/proxy owner while the codex child runs with
    // inherited stdio. This is not a restart fallback; the same child
    // process makes the synthetic post-swap request in the smoke.
    var mat_ctx = broker_loader.ChatgptMaterializerCtx{ .cfg = &parsed.value };
    var proxy = wire_proxy.Proxy.bind(
        allocator,
        &server.pool,
        mat_ctx.vtable(),
        status_writer,
    ) catch |e| {
        try stderr.print("oauth-mux codex: proxy bind: {s}\n", .{@errorName(e)});
        try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "proxy_bind_failed", "proxy_bind", @errorName(e), session_started_emitted);
        return e;
    };
    defer proxy.deinit();
    proxy.profile = opts.profile;
    proxy.capability = route_capability;
    const proxy_port = proxy.port();
    try launch_timer.mark(status_writer, emit_status, "proxy_bind");
    const managed_frame_id = try std.fmt.allocPrint(allocator, "omux-codex-{d}-{d}", .{ std.time.milliTimestamp(), proxy_port });
    defer allocator.free(managed_frame_id);

    // 5. Create a per-session CODEX_HOME overlay containing copied
    // auth material, generated proxy config, and canonical session
    // authority references unless isolation was explicitly requested.
    // This prevents concurrent adapter sessions from clobbering
    // auth/config while keeping resume/history behavior aligned with
    // bare Codex.
    const codex_home = try makeSessionCodexHome(
        allocator,
        source_auth_path,
        proxy_port,
        opts.session_home,
        opts.isolated_session_store,
    );
    defer codex_home.deinit(allocator);
    traceManagedOverlay(allocator, elected.id, opts.profile, proxy_port, &codex_home);
    try launch_timer.mark(status_writer, emit_status, "overlay_creation");

    const resume_request = detectResumeRequest(opts.forward_argv);
    const resume_authority_check = try checkResumeAuthority(allocator, &codex_home, resume_request);
    if (emit_status and resume_request.mode == .chooser) {
        try writeResumeAuthorityCheckStatus(status_writer, resume_authority_check);
    }
    try launch_timer.mark(status_writer, emit_status, "resume_authority_check");
    if (resume_request.mode == .chooser and !resume_authority_check.ok) {
        try stderr.print("oauth-mux codex: resume chooser unavailable: {s}\n", .{resume_authority_check.diagnostic});
        try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "session_authority_unavailable", "resume_authority_check", "SessionAuthorityUnavailable", session_started_emitted);
        return RunError.SessionAuthorityUnavailable;
    }

    const config_override_check = checkForwardedConfigOverrides(opts.forward_argv);
    if (emit_status) {
        try writeConfigOverrideCheckStatus(status_writer, config_override_check);
    }
    try launch_timer.mark(status_writer, emit_status, "config_passthrough_check");
    if (!config_override_check.ok) {
        try stderr.writeAll("oauth-mux codex: forwarded Codex --config attempts to override managed provider settings\n");
        try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "config_override_unavailable", "config_passthrough_check", "ConfigOverrideUnavailable", session_started_emitted);
        return RunError.ConfigOverrideUnavailable;
    }

    const sqlite_lock_check = try checkResumeSqliteAuthorityLock(allocator, &codex_home, resume_request);
    if (emit_status and sqlite_lock_check.checked) {
        try writeSqliteAuthorityCheckStatus(status_writer, sqlite_lock_check);
    }
    try launch_timer.mark(status_writer, emit_status, "sqlite_authority_check");
    if (sqlite_lock_check.locked()) {
        try stderr.writeAll("oauth-mux codex: canonical Codex sqlite state is locked by another Codex process; close or wait for that process, then retry\n");
        try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "session_authority_locked", "sqlite_authority_check", "SqliteStateLocked", session_started_emitted);
        return RunError.SessionAuthorityLocked;
    }

    var resume_preflight = ResumePreflightObservation{};
    defer resume_preflight.deinit();
    if (resume_request.mode == .explicit) {
        if (codex_home.authority_home) |authority_home| {
            resume_preflight = try lookupExplicitResumePreflight(allocator, authority_home, resume_request.explicit_id.?);
        } else {
            resume_preflight.explicit_target_found_before = false;
        }
    }

    if (emit_status) {
        const runtime_identity = try runtime_mod.oauthMuxRuntimeIdentity(allocator, cli.version, cli.build_id);
        defer runtime_identity.deinit(allocator);
        const command_spelling = try getEnvOwnedOrDefault(allocator, "OMUX_COMMAND_SPELLING", "oauth-mux codex");
        defer allocator.free(command_spelling);
        const installed_local_mismatch = envFlag("OMUX_INSTALLED_LOCAL_MISMATCH");

        try status_writer.print(
            "{{\"kind\":\"session_started\",\"adapter\":\"codex\",\"adapter_version\":\"{s}\",\"managed_frame_id\":\"{s}\",\"selected_account\":\"{s}\",\"codex_home_path_printed\":false,\"proxy_port\":{d},\"claim_level\":\"broker_owned\",\"auth_authority\":\"mux_owned_overlay\",\"managed_config\":\"mux_owned_overlay\",\"config_layout\":\"{s}\",\"config_passthrough\":{any},\"user_config_present\":{any},\"config_overridden_keys\":{d},\"experimental_feature_defaults_injected\":{d},\"mcp_stdio_unsupported_fields_removed\":{d},\"config_paths_printed\":false,\"session_authority\":\"{s}\",\"sqlite_authority\":\"{s}\",\"session_paths_printed\":false,\"pre_spawn_network_refresh\":false,\"status_file_present\":{any},\"runtime_identity\":{{",
            .{ cli.version, managed_frame_id, elected.id, proxy_port, codex_home.config_layout, codex_home.config_passthrough, codex_home.config_source_present, codex_home.config_overridden_keys, codex_home.experimental_feature_defaults_injected, codex_home.mcp_stdio_unsupported_fields_removed, codex_home.session_authority.toString(), codex_home.sqlite_authority.toString(), status_file_path != null },
        );
        try runtime_identity.writeJsonFields(status_writer);
        try status_writer.writeAll(",\"command_spelling\":");
        try std.json.stringify(command_spelling, .{}, status_writer);
        try status_writer.print(",\"installed_local_mismatch_detected\":{any}", .{installed_local_mismatch});
        try status_writer.writeAll("}}\n");
        session_started_emitted = true;
        if (resume_request.requested()) {
            try writeResumePreflightStatus(
                status_writer,
                resume_request,
                codex_home.session_authority,
                resume_preflight.rolloutsBefore(),
                resume_preflight.explicit_target_found_before,
                resume_preflight.lookup_source,
            );
        }
    }

    // 6. Build argv: `codex` plus any forwarded user args.
    const requested_codex_bin_from_env = std.process.getEnvVarOwned(allocator, "OMUX_CODEX_BIN") catch |e| switch (e) {
        error.EnvironmentVariableNotFound => null,
        else => return e,
    };
    const requested_codex_bin_source: []const u8 = if (requested_codex_bin_from_env == null) "PATH" else "OMUX_CODEX_BIN";
    const requested_codex_bin = requested_codex_bin_from_env orelse try allocator.dupe(u8, "codex");
    defer allocator.free(requested_codex_bin);
    const codex_bin = resolveCodexBinary(allocator, requested_codex_bin) catch |e| {
        traceManagedCodexBinaryResolution(allocator, requested_codex_bin_source, requested_codex_bin, false, @errorName(e));
        if (e == RunError.CodexShimRecursion) {
            try stderr.print("oauth-mux codex: resolved Codex CLI {s} is an oauth-mux codex shim; set OMUX_CODEX_BIN to the native Codex executable\n", .{requested_codex_bin});
        } else {
            try stderr.print("oauth-mux codex: cannot find Codex CLI {s}; set OMUX_CODEX_BIN to an executable path\n", .{requested_codex_bin});
        }
        try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "binary_resolution_failed", "binary_resolution", @errorName(e), session_started_emitted);
        return e;
    };
    defer allocator.free(codex_bin);
    traceManagedCodexBinaryResolution(allocator, requested_codex_bin_source, requested_codex_bin, true, "selected");
    try launch_timer.mark(status_writer, emit_status, "binary_resolution");

    var argv = std.ArrayListUnmanaged([]const u8){};
    defer argv.deinit(allocator);
    try argv.append(allocator, codex_bin);
    for (opts.forward_argv) |a| try argv.append(allocator, a);

    // 7. Build env: copy current, set CODEX_HOME and OMUX_ACTIVE_*.
    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("CODEX_HOME", codex_home.path);
    if (codex_home.authority_home) |authority_home| {
        try env_map.put("OMUX_CODEX_SESSION_HOME", authority_home);
    }
    switch (codex_home.sqlite_authority) {
        .canonical_env => {
            if (codex_home.authority_home) |authority_home| {
                try env_map.put("CODEX_SQLITE_HOME", authority_home);
            }
        },
        .isolated_overlay => {
            _ = env_map.remove("CODEX_SQLITE_HOME");
        },
    }
    if (codex_home.config_authority_home) |config_home| {
        try env_map.put("OMUX_CODEX_CONFIG_HOME", config_home);
    }
    try env_map.put("OMUX_ACTIVE_PROVIDER", "codex");
    try env_map.put("OMUX_MANAGED_FRAME_ID", managed_frame_id);
    try env_map.put("OMUX_CLAIM_LEVEL", "broker_owned");
    if (status_file_path) |path| try env_map.put("OMUX_STATUS_FILE", path);
    const account_only = elected.id[std.mem.indexOfScalar(u8, elected.id, ':').? + 1 ..];
    try env_map.put("OMUX_ACTIVE_ACCOUNT", account_only);
    if (opts.profile) |p| try env_map.put("OMUX_ACTIVE_PROFILE", p);
    try launch_timer.mark(status_writer, emit_status, "env_build");

    traceManagedSessionStart(allocator, elected.id, opts.profile, opts.forward_argv.len, resume_request.mode, &codex_home);

    // 8. Spawn codex as child with inherited stdio (so the user gets
    // the real codex TUI). The adapter stays alive in parent.
    var child = std.process.Child.init(argv.items, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    child.env_map = &env_map;
    child.spawn() catch |e| {
        try stderr.print("oauth-mux codex: spawn: {s}\n", .{@errorName(e)});
        trace.append(allocator, "codex.managed.child_spawn", .err, &.{
            trace.string("provider", "codex"),
            trace.string("account_label", codexAccountLabel(elected.id)),
            trace.string("error", @errorName(e)),
            trace.boolean("codex_home_path_printed", false),
            trace.boolean("token_material_printed", false),
        });
        try writeManagedPreSpawnAbortStatus(status_writer, emit_status, "child_spawn_failed", "child_spawn", @errorName(e), session_started_emitted);
        return e;
    };
    trace.append(allocator, "codex.managed.child_spawn", .info, &.{
        trace.string("provider", "codex"),
        trace.string("account_label", codexAccountLabel(elected.id)),
        trace.boolean("stdio_inherited", true),
        trace.boolean("codex_home_path_printed", false),
        trace.boolean("token_material_printed", false),
    });
    try launch_timer.mark(status_writer, emit_status, "child_spawn");

    // 9. Start the proxy thread. It loops on serveOne until the
    // shutdown flag is set after the child exits.
    var shutdown = std.atomic.Value(bool).init(false);
    const proxy_thread = try std.Thread.spawn(
        .{},
        proxyThreadMain,
        .{ &proxy, &shutdown },
    );

    // 10. Wait for codex to exit; signal proxy to stop.
    const term = child.wait() catch |e| {
        try stderr.print("oauth-mux codex: child wait: {s}\n", .{@errorName(e)});
        shutdown.store(true, .release);
        tickleProxy(proxy_port);
        proxy_thread.join();
        try finalizeManagedSession(
            allocator,
            stderr,
            status_writer,
            emit_status,
            &proxy,
            &codex_home,
            source_auth_path,
            resume_request,
            &resume_preflight,
            .{ .aborted = true, .reason = "child_wait_error", .wait_error = @errorName(e) },
        );
        return e;
    };

    shutdown.store(true, .release);
    // Tickle the proxy thread out of accept() by connecting once.
    tickleProxy(proxy_port);
    proxy_thread.join();

    try finalizeManagedSession(
        allocator,
        stderr,
        status_writer,
        emit_status,
        &proxy,
        &codex_home,
        source_auth_path,
        resume_request,
        &resume_preflight,
        .{ .term = term },
    );

    // Propagate exit code.
    switch (term) {
        .Exited => |c| if (c != 0) std.process.exit(c),
        else => std.process.exit(1),
    }
}

fn openStatusFile(path: []const u8) !std.fs.File {
    if (std.fs.path.dirname(path)) |dir| {
        try std.fs.cwd().makePath(dir);
    }
    return try std.fs.cwd().createFile(path, .{ .mode = 0o600, .truncate = true });
}

fn checkResumeSqliteAuthorityLock(
    allocator: std.mem.Allocator,
    codex_home: *const SessionCodexHome,
    resume_request: ResumeRequest,
) !SqliteAuthorityLockObservation {
    var observation = SqliteAuthorityLockObservation{
        .sqlite_authority = codex_home.sqlite_authority,
    };
    if (!resume_request.requested()) {
        observation.diagnostic = "not_resume";
        return observation;
    }
    if (codex_home.sqlite_authority != .canonical_env) {
        observation.diagnostic = "not_canonical_sqlite_authority";
        return observation;
    }
    const authority_home = codex_home.authority_home orelse {
        observation.diagnostic = "missing_authority_home";
        return observation;
    };

    const db_path = try std.fs.path.join(allocator, &.{ authority_home, observation.db_basename });
    defer allocator.free(db_path);

    var file = std.fs.openFileAbsolute(db_path, .{ .mode = .read_write }) catch |e| switch (e) {
        error.FileNotFound => {
            observation.diagnostic = "state_db_absent";
            return observation;
        },
        error.AccessDenied => {
            observation.checked = true;
            observation.diagnostic = "state_db_probe_unavailable";
            observation.next_action = "retry_without_lock_probe_or_check_file_permissions";
            return observation;
        },
        else => {
            observation.checked = true;
            observation.diagnostic = "state_db_probe_unavailable";
            observation.next_action = "retry_or_inspect_codex_state";
            return observation;
        },
    };
    defer file.close();

    observation.checked = true;
    const probe = try probeSqliteLockBytes(file);
    switch (probe) {
        .clear => {
            observation.ok = true;
            observation.diagnostic = "clear";
        },
        .locked => {
            observation.ok = false;
            observation.diagnostic = "database_locked";
            observation.sqlite_error_class = "database_locked";
            observation.sqlite_error_code = 5;
            observation.next_action = "close_or_wait_for_other_codex_process_then_retry";
        },
        .unsupported => {
            observation.ok = true;
            observation.diagnostic = "lock_probe_unsupported";
            observation.next_action = "retry_if_codex_reports_database_locked";
        },
    }
    return observation;
}

const SqliteLockProbeResult = enum {
    clear,
    locked,
    unsupported,
};

fn probeSqliteLockBytes(file: std.fs.File) !SqliteLockProbeResult {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return .unsupported;
    }

    const sqlite_pending_byte: u64 = 0x40000000;
    const sqlite_lock_span: u64 = 512;
    var lock = std.mem.zeroes(std.c.Flock);
    lock.type = @intCast(std.c.F.WRLCK);
    lock.whence = @intCast(std.c.SEEK.SET);
    lock.start = @intCast(sqlite_pending_byte);
    lock.len = @intCast(sqlite_lock_span);

    _ = std.posix.fcntl(file.handle, std.c.F.SETLK, @intFromPtr(&lock)) catch |e| switch (e) {
        error.Locked => return .locked,
        error.FileBusy => return .locked,
        error.LockedRegionLimitExceeded,
        error.DeadLock,
        error.PermissionDenied,
        error.ProcessFdQuotaExceeded,
        => return .unsupported,
        else => return e,
    };
    lock.type = @intCast(std.c.F.UNLCK);
    _ = std.posix.fcntl(file.handle, std.c.F.SETLK, @intFromPtr(&lock)) catch {};
    return .clear;
}

fn writeSqliteAuthorityCheckStatus(writer: anytype, check: SqliteAuthorityLockObservation) !void {
    try writer.print(
        "{{\"kind\":\"sqlite_authority_check\",\"mode\":\"resume\",\"sqlite_authority\":\"{s}\",\"ok\":{any},\"diagnostic\":\"{s}\",\"db_basename\":\"{s}\",\"next_action\":\"{s}\",\"sqlite_error_class\":",
        .{ check.sqlite_authority.toString(), check.ok, check.diagnostic, check.db_basename, check.next_action },
    );
    if (check.sqlite_error_class) |class| {
        try std.json.stringify(class, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"sqlite_error_code\":");
    if (check.sqlite_error_code) |code| {
        try writer.print("{d}", .{code});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"path_printed\":false,\"token_material_printed\":false,\"session_id_printed\":false}\n");
}

fn writeManagedPreSpawnAbortStatus(
    writer: anytype,
    emit_status: bool,
    reason: []const u8,
    phase: []const u8,
    error_name: []const u8,
    session_started_emitted: bool,
) !void {
    if (!emit_status) return;
    try writer.print(
        "{{\"kind\":\"session_aborted\",\"adapter\":\"codex\",\"reason\":\"{s}\",\"phase\":\"{s}\",\"error\":\"{s}\",\"exit_code\":-1,\"term_kind\":null,\"term_code\":null,\"signal_name\":null,\"final_claim_level\":\"{s}\",\"synthetic_swap_observed\":false,\"pre_spawn\":true,\"child_spawned\":false,\"path_printed\":false,\"token_material_printed\":false,\"session_id_printed\":false}}\n",
        .{ reason, phase, error_name, if (session_started_emitted) "broker_owned" else "none" },
    );
}

fn finalizeManagedSession(
    allocator: std.mem.Allocator,
    stderr: anytype,
    status_writer: anytype,
    emit_status: bool,
    proxy: *wire_proxy.Proxy,
    codex_home: *const SessionCodexHome,
    source_auth_path: []const u8,
    resume_request: ResumeRequest,
    resume_preflight: *const ResumePreflightObservation,
    final_status: FinalSessionStatus,
) !void {
    const auth_writeback = observeAuthWriteback(allocator, codex_home.path, source_auth_path, codex_home.auth_initial_hash) catch |e| failed: {
        try stderr.print("oauth-mux codex: auth writeback failed: {s}\n", .{@errorName(e)});
        break :failed AuthWritebackObservation{
            .ok = false,
            .error_name = @errorName(e),
        };
    };
    if (auth_writeback.source_conflict) {
        try stderr.writeAll("oauth-mux codex: auth writeback conflict; not overwriting newer account auth\n");
    }
    const auth_failure = proxy.authFailureObservation();

    const exit_code: i32 = if (final_status.term) |term| switch (term) {
        .Exited => |c| c,
        else => -1,
    } else -1;

    var terminal_aborted = final_status.aborted;
    var terminal_reason = final_status.reason;
    if (!terminal_aborted) {
        if (final_status.term) |term| {
            if (childTermAbortReason(term)) |reason| {
                terminal_aborted = true;
                terminal_reason = reason;
            }
        }
    }

    traceManagedSessionEnd(
        allocator,
        proxy,
        codex_home,
        terminal_aborted,
        terminal_reason,
        exit_code,
        final_status.term,
    );

    if (!emit_status) return;

    try writeAuthWritebackStatus(status_writer, auth_writeback);
    for (auth_failure.accounts) |account_observation| {
        if (account_observation.auth_unauthorized_turns == 0) continue;
        const auth_health = recordManagedAuthFailureHealth(allocator, account_observation, auth_writeback);
        try writeManagedAuthHealthStatus(status_writer, account_observation, auth_health);
    }
    if (resume_request.requested()) {
        const observation = if (codex_home.authority_home) |authority_home|
            try observeResumeWriteback(allocator, authority_home, resume_preflight, resume_request)
        else
            ResumeObservation{};
        try writeResumeWritebackStatus(status_writer, resume_request, codex_home.session_authority, observation);
    }

    if (terminal_aborted) {
        try status_writer.print(
            "{{\"kind\":\"session_aborted\",\"adapter\":\"codex\",\"reason\":\"{s}\",\"exit_code\":{d}",
            .{ terminal_reason, exit_code },
        );
        try writeChildTermStatusFields(status_writer, final_status.term);
        try status_writer.print(
            ",\"final_claim_level\":\"{s}\",\"synthetic_swap_observed\":{any}",
            .{ proxy.peakClaimLevel().toString(), proxy.syntheticSwapSeen() },
        );
        if (final_status.wait_error) |err| {
            try status_writer.print(",\"wait_error\":\"{s}\"", .{err});
        }
        try status_writer.writeAll("}\n");
    } else {
        try status_writer.print(
            "{{\"kind\":\"session_ended\",\"adapter\":\"codex\",\"exit_code\":{d}",
            .{exit_code},
        );
        try writeChildTermStatusFields(status_writer, final_status.term);
        try status_writer.print(
            ",\"final_claim_level\":\"{s}\",\"synthetic_swap_observed\":{any}}}\n",
            .{ proxy.peakClaimLevel().toString(), proxy.syntheticSwapSeen() },
        );
    }
}

fn writeChildTermStatusFields(writer: anytype, term: ?std.process.Child.Term) !void {
    try writer.writeAll(",\"term_kind\":");
    if (term) |value| {
        try std.json.stringify(childTermKind(value), .{}, writer);
    } else {
        try writer.writeAll("null");
    }

    try writer.writeAll(",\"term_code\":");
    if (term) |value| {
        try writer.print("{d}", .{childTermCode(value)});
    } else {
        try writer.writeAll("null");
    }

    try writer.writeAll(",\"signal_name\":");
    if (term) |value| {
        if (value == .Signal) {
            if (childSignalName(childTermCode(value))) |name| {
                try std.json.stringify(name, .{}, writer);
                return;
            }
        }
    }
    try writer.writeAll("null");
}

fn proxyThreadMain(p: *wire_proxy.Proxy, shutdown: *std.atomic.Value(bool)) void {
    while (!shutdown.load(.acquire)) {
        p.serveOne() catch |e| {
            // Server error or accept failure; if shutting down, exit.
            if (shutdown.load(.acquire)) return;
            if (isBenignProxyConnectionClose(e)) continue;
            std.debug.print("proxy: serveOne: {s}\n", .{@errorName(e)});
            // Continue serving; transient errors should not kill the
            // proxy mid-session.
        };
    }
}

fn isBenignProxyConnectionClose(err: anyerror) bool {
    return err == error.BrokenPipe or
        err == error.ConnectionResetByPeer or
        err == error.ConnectionTimedOut or
        err == error.EndOfStream;
}

test "proxy thread suppresses expected localhost connection close errors" {
    try std.testing.expect(isBenignProxyConnectionClose(error.BrokenPipe));
    try std.testing.expect(isBenignProxyConnectionClose(error.ConnectionResetByPeer));
    try std.testing.expect(isBenignProxyConnectionClose(error.ConnectionTimedOut));
    try std.testing.expect(isBenignProxyConnectionClose(error.EndOfStream));
    try std.testing.expect(!isBenignProxyConnectionClose(error.Unexpected));
}

test "nonzero Codex child exit is an aborted managed session" {
    try std.testing.expect(childTermAbortReason(.{ .Exited = 0 }) == null);
    try std.testing.expectEqualStrings("child_exit_nonzero", childTermAbortReason(.{ .Exited = 1 }).?);
    try std.testing.expectEqualStrings("child_exit_nonzero", childTermAbortReason(.{ .Exited = 2 }).?);
}

/// Open a TCP connection to the proxy and immediately close it. This
/// wakes the proxy thread out of a blocking accept() during shutdown.
fn tickleProxy(port: u16) void {
    const addr = std.net.Address.parseIp("127.0.0.1", port) catch return;
    const sock = std.net.tcpConnectToAddress(addr) catch return;
    sock.close();
}

fn makeSessionCodexHome(
    allocator: std.mem.Allocator,
    source_auth_path: []const u8,
    proxy_port: u16,
    session_home_override: ?[]const u8,
    isolated_session_store: bool,
) !SessionCodexHome {
    const tmp_root = std.process.getEnvVarOwned(allocator, "TMPDIR") catch
        try allocator.dupe(u8, "/tmp");
    defer allocator.free(tmp_root);
    const session_authority_home = try resolveCodexSessionAuthorityHome(allocator, session_home_override, isolated_session_store);
    defer if (session_authority_home) |path| allocator.free(path);
    const config_authority_home = try resolveCodexConfigAuthorityHome(allocator);
    defer if (config_authority_home) |path| allocator.free(path);
    return try createSessionCodexHomeUnder(allocator, tmp_root, source_auth_path, proxy_port, session_authority_home, config_authority_home);
}

fn createSessionCodexHomeUnder(
    allocator: std.mem.Allocator,
    tmp_root: []const u8,
    source_auth_path: []const u8,
    proxy_port: u16,
    session_authority_home: ?[]const u8,
    config_authority_home: ?[]const u8,
) !SessionCodexHome {
    var nonce: [8]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    const hex = std.fmt.bytesToHex(nonce, .lower);
    const name = try std.fmt.allocPrint(allocator, "oauth-mux-codex-{s}", .{hex[0..]});
    defer allocator.free(name);

    const session_home = try std.fs.path.join(allocator, &.{ tmp_root, name });
    errdefer allocator.free(session_home);
    try std.fs.cwd().makePath(session_home);
    errdefer std.fs.cwd().deleteTree(session_home) catch {};

    const auth_dst = try std.fs.path.join(allocator, &.{ session_home, "auth.json" });
    defer allocator.free(auth_dst);
    try copyFileContents(allocator, source_auth_path, auth_dst);
    const auth_initial_hash = try hashFileContents(allocator, auth_dst);

    if (std.fs.path.dirname(source_auth_path)) |source_dir| {
        const install_src = try std.fs.path.join(allocator, &.{ source_dir, "installation_id" });
        defer allocator.free(install_src);
        const install_dst = try std.fs.path.join(allocator, &.{ session_home, "installation_id" });
        defer allocator.free(install_dst);
        copyFileContents(allocator, install_src, install_dst) catch |e| switch (e) {
            error.FileNotFound => {},
            else => return e,
        };
    }

    const config_observation = try writeManagedConfigToml(allocator, session_home, proxy_port, config_authority_home);
    const session_authority = if (session_authority_home) |home| mode: {
        try bridgeCodexSessionAuthority(allocator, session_home, home);
        break :mode SessionAuthorityMode.canonical_bridge;
    } else SessionAuthorityMode.isolated;

    return .{
        .path = session_home,
        .session_authority = session_authority,
        .sqlite_authority = if (session_authority == .canonical_bridge) .canonical_env else .isolated_overlay,
        .authority_home = if (session_authority_home) |home| try allocator.dupe(u8, home) else null,
        .config_authority_home = if (config_authority_home) |home| try allocator.dupe(u8, home) else null,
        .auth_initial_hash = auth_initial_hash,
        .config_source_present = config_observation.source_present,
        .config_passthrough = config_observation.passthrough,
        .config_overridden_keys = config_observation.overridden_keys,
        .experimental_feature_defaults_injected = config_observation.experimental_feature_defaults_injected,
        .mcp_stdio_unsupported_fields_removed = config_observation.mcp_stdio_unsupported_fields_removed,
        .config_layout = config_observation.layout,
    };
}

fn resolveCodexSessionAuthorityHome(
    allocator: std.mem.Allocator,
    session_home_override: ?[]const u8,
    isolated_session_store: bool,
) !?[]u8 {
    if (isolated_session_store) return null;
    if (session_home_override) |path| return try expandTilde(allocator, path);
    if (std.process.getEnvVarOwned(allocator, "OMUX_CODEX_SESSION_HOME")) |path| {
        return path;
    } else |_| {}
    if (std.process.getEnvVarOwned(allocator, "CODEX_HOME")) |path| {
        if (try isManagedCodexOverlayHome(allocator, path)) {
            allocator.free(path);
        } else {
            return path;
        }
    } else |_| {}
    return try defaultCodexHome(allocator);
}

fn resolveCodexConfigAuthorityHome(allocator: std.mem.Allocator) !?[]u8 {
    if (std.process.getEnvVarOwned(allocator, "OMUX_CODEX_CONFIG_HOME")) |path| {
        return path;
    } else |_| {}
    if (std.process.getEnvVarOwned(allocator, "CODEX_HOME")) |path| {
        if (try isManagedCodexOverlayHome(allocator, path)) {
            allocator.free(path);
        } else {
            return path;
        }
    } else |_| {}
    return try defaultCodexHome(allocator);
}

fn defaultCodexHome(allocator: std.mem.Allocator) !?[]u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch |e| switch (e) {
        error.EnvironmentVariableNotFound => return null,
        else => return e,
    };
    defer allocator.free(home);
    return try std.fs.path.join(allocator, &.{ home, ".codex" });
}

fn isManagedCodexOverlayHome(allocator: std.mem.Allocator, path: []const u8) !bool {
    const base = std.fs.path.basename(path);
    if (std.mem.startsWith(u8, base, "oauth-mux-codex-")) return true;

    const config_path = try std.fs.path.join(allocator, &.{ path, "config.toml" });
    defer allocator.free(config_path);
    const bytes = std.fs.cwd().readFileAlloc(allocator, config_path, 2 * 1024 * 1024) catch |e| switch (e) {
        error.FileNotFound => return false,
        else => return e,
    };
    defer allocator.free(bytes);

    return std.mem.indexOf(u8, bytes, "Managed by oauth-mux") != null or
        std.mem.indexOf(u8, bytes, "model_provider = \"oauth_mux_openai\"") != null or
        std.mem.indexOf(u8, bytes, "[model_providers.oauth_mux_openai]") != null;
}

fn bridgeCodexSessionAuthority(
    allocator: std.mem.Allocator,
    session_home: []const u8,
    authority_home: []const u8,
) !void {
    try std.fs.cwd().makePath(authority_home);
    for (codex_session_authority_entries) |entry| {
        const target = try std.fs.path.join(allocator, &.{ authority_home, entry.name });
        defer allocator.free(target);
        const link = try std.fs.path.join(allocator, &.{ session_home, entry.name });
        defer allocator.free(link);
        try std.fs.symLinkAbsolute(target, link, .{ .is_directory = entry.kind == .directory });
    }
    for (codex_optional_state_authority_entries) |entry| {
        const target = try std.fs.path.join(allocator, &.{ authority_home, entry.name });
        defer allocator.free(target);
        if (!authorityEntryPresent(target, entry.kind)) continue;
        const link = try std.fs.path.join(allocator, &.{ session_home, entry.name });
        defer allocator.free(link);
        try std.fs.symLinkAbsolute(target, link, .{ .is_directory = entry.kind == .directory });
    }
    for (codex_optional_logs_authority_entries) |entry| {
        const target = try std.fs.path.join(allocator, &.{ authority_home, entry.name });
        defer allocator.free(target);
        if (!authorityEntryPresent(target, entry.kind)) continue;
        const link = try std.fs.path.join(allocator, &.{ session_home, entry.name });
        defer allocator.free(link);
        try std.fs.symLinkAbsolute(target, link, .{ .is_directory = entry.kind == .directory });
    }
}

fn checkResumeAuthority(
    allocator: std.mem.Allocator,
    codex_home: *const SessionCodexHome,
    request: ResumeRequest,
) !ResumeAuthorityCheck {
    var result = ResumeAuthorityCheck{
        .mode = request.mode,
        .authority = codex_home.session_authority,
        .sqlite_authority = codex_home.sqlite_authority,
        .ok = true,
        .diagnostic = "not_required",
    };
    if (!request.requested()) return result;
    if (codex_home.session_authority == .isolated) {
        result.ok = request.mode != .chooser;
        result.diagnostic = if (result.ok) "isolated_session_store_explicit" else "chooser_requires_canonical_session_authority";
        return result;
    }

    const authority_home = codex_home.authority_home orelse {
        result.ok = false;
        result.diagnostic = "canonical_authority_missing";
        return result;
    };

    result.ok = true;
    result.diagnostic = "available";
    result.state_db_canonical_present = authorityStateDbPresent(allocator, authority_home) catch false;
    result.state_db_overlay_present = authorityStateDbPresent(allocator, codex_home.path) catch false;
    result.state_db_bridged = result.state_db_canonical_present and result.state_db_overlay_present;
    result.logs_db_canonical_present = authorityLogsDbPresent(allocator, authority_home) catch false;
    result.logs_db_overlay_present = authorityLogsDbPresent(allocator, codex_home.path) catch false;
    result.logs_db_bridged = result.logs_db_canonical_present and result.logs_db_overlay_present;
    const legacy_namespace = scanLegacyProviderNamespace(allocator, authority_home);
    result.legacy_provider_namespace_detected = legacy_namespace.detected;
    result.legacy_provider_namespace_state_db_detected = legacy_namespace.state_db_detected;
    result.legacy_provider_namespace_logs_db_detected = legacy_namespace.logs_db_detected;
    result.legacy_provider_namespace_scan_truncated = legacy_namespace.truncated;
    result.legacy_provider_namespace_scan_errors = legacy_namespace.errors;

    var legacy_ok = true;
    for (codex_session_authority_entries) |entry| {
        const canonical = try std.fs.path.join(allocator, &.{ authority_home, entry.name });
        defer allocator.free(canonical);
        const overlay = try std.fs.path.join(allocator, &.{ codex_home.path, entry.name });
        defer allocator.free(overlay);

        if (authorityEntryPresent(canonical, entry.kind)) {
            result.canonical_present += 1;
        } else {
            legacy_ok = false;
            result.diagnostic = "canonical_entry_missing";
        }
        if (authorityEntryPresent(overlay, entry.kind)) {
            result.overlay_present += 1;
        } else {
            legacy_ok = false;
            result.diagnostic = "overlay_entry_missing";
        }
    }
    result.ok = result.logs_db_bridged or result.state_db_bridged or legacy_ok;
    if (result.ok) {
        result.diagnostic = if (result.logs_db_bridged) "logs_db_available" else if (result.state_db_bridged) "state_db_available" else "available";
    }
    return result;
}

fn scanLegacyProviderNamespace(
    allocator: std.mem.Allocator,
    authority_home: []const u8,
) LegacyProviderNamespaceScan {
    var result = LegacyProviderNamespaceScan{};
    scanLegacyProviderNamespaceEntries(
        allocator,
        authority_home,
        &codex_optional_state_authority_entries,
        true,
        &result,
    );
    scanLegacyProviderNamespaceEntries(
        allocator,
        authority_home,
        &codex_optional_logs_authority_entries,
        false,
        &result,
    );
    result.detected = result.state_db_detected or result.logs_db_detected;
    return result;
}

fn scanLegacyProviderNamespaceEntries(
    allocator: std.mem.Allocator,
    authority_home: []const u8,
    entries: []const SessionAuthorityEntry,
    state_db: bool,
    result: *LegacyProviderNamespaceScan,
) void {
    for (entries) |entry| {
        const path = std.fs.path.join(allocator, &.{ authority_home, entry.name }) catch {
            result.errors += 1;
            continue;
        };
        defer allocator.free(path);
        const scan = fileContainsLegacyProviderNamespaceBounded(allocator, path) catch |e| switch (e) {
            error.FileNotFound, error.AccessDenied, error.NotDir => FileNeedleScan{},
            else => {
                result.errors += 1;
                continue;
            },
        };
        result.truncated = result.truncated or scan.truncated;
        if (!scan.found) continue;
        if (state_db) {
            result.state_db_detected = true;
        } else {
            result.logs_db_detected = true;
        }
    }
}

fn fileContainsLegacyProviderNamespaceBounded(
    allocator: std.mem.Allocator,
    path: []const u8,
) !FileNeedleScan {
    const file = std.fs.cwd().openFile(path, .{}) catch |e| switch (e) {
        error.FileNotFound, error.AccessDenied, error.NotDir => return .{},
        else => return e,
    };
    defer file.close();

    const stat = try file.stat();
    var result = FileNeedleScan{ .truncated = stat.size > max_legacy_provider_namespace_scan_bytes };
    var previous = std.ArrayListUnmanaged(u8){};
    defer previous.deinit(allocator);

    var buf: [8192]u8 = undefined;
    var scanned: u64 = 0;
    while (scanned < max_legacy_provider_namespace_scan_bytes) {
        const remaining = max_legacy_provider_namespace_scan_bytes - scanned;
        const limit: usize = @intCast(@min(@as(u64, buf.len), remaining));
        const n = try file.read(buf[0..limit]);
        if (n == 0) break;
        scanned += n;

        var haystack = std.ArrayListUnmanaged(u8){};
        defer haystack.deinit(allocator);
        try haystack.appendSlice(allocator, previous.items);
        try haystack.appendSlice(allocator, buf[0..n]);
        if (std.mem.indexOf(u8, haystack.items, legacy_codex_provider_namespace) != null) {
            result.found = true;
            result.truncated = false;
            return result;
        }

        previous.clearRetainingCapacity();
        const keep = @min(legacy_codex_provider_namespace.len - 1, haystack.items.len);
        if (keep != 0) try previous.appendSlice(allocator, haystack.items[haystack.items.len - keep ..]);
    }
    return result;
}

fn authorityEntryPresent(path: []const u8, kind: SessionAuthorityEntryKind) bool {
    const stat = std.fs.cwd().statFile(path) catch return false;
    return switch (kind) {
        .directory => stat.kind == .directory,
        .file => stat.kind == .file,
    };
}

fn authorityStateDbPresent(allocator: std.mem.Allocator, home: []const u8) !bool {
    const path = try std.fs.path.join(allocator, &.{ home, "state_5.sqlite" });
    defer allocator.free(path);
    return authorityEntryPresent(path, .file);
}

fn authorityLogsDbPresent(allocator: std.mem.Allocator, home: []const u8) !bool {
    const path = try std.fs.path.join(allocator, &.{ home, "logs_2.sqlite" });
    defer allocator.free(path);
    return authorityEntryPresent(path, .file);
}

fn detectResumeRequest(argv: []const []const u8) ResumeRequest {
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        if (!std.mem.eql(u8, argv[i], "resume")) continue;
        if (i + 1 >= argv.len) return .{ .mode = .chooser };
        const next = argv[i + 1];
        if (std.mem.eql(u8, next, "--last") or std.mem.eql(u8, next, "-l")) {
            return .{ .mode = .last };
        }
        if (std.mem.startsWith(u8, next, "-")) {
            return .{ .mode = .chooser };
        }
        return .{ .mode = .explicit, .explicit_id = next };
    }
    return .{};
}

fn snapshotRollouts(allocator: std.mem.Allocator, authority_home: []const u8) !RolloutSnapshot {
    var snapshot = RolloutSnapshot.init(allocator);
    errdefer snapshot.deinit();
    const sessions_dir = try std.fs.path.join(allocator, &.{ authority_home, "sessions" });
    defer allocator.free(sessions_dir);
    try snapshotRolloutsUnder(allocator, sessions_dir, &snapshot);
    return snapshot;
}

fn snapshotRolloutsUnder(
    allocator: std.mem.Allocator,
    dir_path: []const u8,
    snapshot: *RolloutSnapshot,
) !void {
    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound => return,
        else => return e,
    };
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        const path = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        defer allocator.free(path);
        switch (entry.kind) {
            .directory => try snapshotRolloutsUnder(allocator, path, snapshot),
            .file, .sym_link => {
                if (!std.mem.endsWith(u8, entry.name, ".jsonl")) continue;
                const stat = std.fs.cwd().statFile(path) catch continue;
                const owned_path = try allocator.dupe(u8, path);
                errdefer allocator.free(owned_path);
                try snapshot.entries.put(allocator, owned_path, .{
                    .size = stat.size,
                    .mtime = stat.mtime,
                });
            },
            else => {},
        }
    }
}

fn lookupExplicitResumePreflight(
    allocator: std.mem.Allocator,
    authority_home: []const u8,
    explicit_id: []const u8,
) !ResumePreflightObservation {
    var result = ResumePreflightObservation{
        .explicit_target_found_before = false,
    };
    errdefer result.deinit();

    if (try stateDbContainsResumeId(allocator, authority_home, explicit_id)) {
        result.lookup_source = .state_db;
        result.explicit_target_found_before = true;
        result.target_snapshot = try findRolloutTargetByFilename(allocator, authority_home, explicit_id);
        return result;
    }

    if (try logsDbContainsResumeId(allocator, authority_home, explicit_id)) {
        result.lookup_source = .logs_db;
        result.explicit_target_found_before = true;
        result.target_snapshot = try findRolloutTargetByFilename(allocator, authority_home, explicit_id);
        return result;
    }

    if (try sessionIndexContainsResumeId(allocator, authority_home, explicit_id)) {
        result.lookup_source = .session_index;
        result.explicit_target_found_before = true;
        result.target_snapshot = try findRolloutTargetByFilename(allocator, authority_home, explicit_id);
        return result;
    }

    result.lookup_source = .filename_scan;
    if (try findRolloutTargetByFilename(allocator, authority_home, explicit_id)) |target| {
        result.explicit_target_found_before = true;
        result.target_snapshot = target;
    }
    return result;
}

fn stateDbContainsResumeId(
    allocator: std.mem.Allocator,
    authority_home: []const u8,
    explicit_id: []const u8,
) !bool {
    for (codex_optional_state_authority_entries) |entry| {
        const path = try std.fs.path.join(allocator, &.{ authority_home, entry.name });
        defer allocator.free(path);
        if (try fileContainsNeedleBounded(allocator, path, explicit_id)) return true;
    }
    return false;
}

fn logsDbContainsResumeId(
    allocator: std.mem.Allocator,
    authority_home: []const u8,
    explicit_id: []const u8,
) !bool {
    for (codex_optional_logs_authority_entries) |entry| {
        const path = try std.fs.path.join(allocator, &.{ authority_home, entry.name });
        defer allocator.free(path);
        if (try fileContainsNeedleBounded(allocator, path, explicit_id)) return true;
    }
    return false;
}

fn sessionIndexContainsResumeId(
    allocator: std.mem.Allocator,
    authority_home: []const u8,
    explicit_id: []const u8,
) !bool {
    const path = try std.fs.path.join(allocator, &.{ authority_home, "session_index.jsonl" });
    defer allocator.free(path);
    return try fileContainsNeedleBounded(allocator, path, explicit_id);
}

fn fileContainsNeedleBounded(
    allocator: std.mem.Allocator,
    path: []const u8,
    needle: []const u8,
) !bool {
    if (needle.len == 0) return false;
    const file = std.fs.cwd().openFile(path, .{}) catch |e| switch (e) {
        error.FileNotFound, error.AccessDenied, error.NotDir => return false,
        else => return e,
    };
    defer file.close();

    var previous = std.ArrayListUnmanaged(u8){};
    defer previous.deinit(allocator);

    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) break;

        var haystack = std.ArrayListUnmanaged(u8){};
        defer haystack.deinit(allocator);
        try haystack.appendSlice(allocator, previous.items);
        try haystack.appendSlice(allocator, buf[0..n]);
        if (std.mem.indexOf(u8, haystack.items, needle) != null) return true;

        previous.clearRetainingCapacity();
        const keep = @min(needle.len - 1, haystack.items.len);
        if (keep != 0) try previous.appendSlice(allocator, haystack.items[haystack.items.len - keep ..]);
    }
    return false;
}

fn findRolloutTargetByFilename(
    allocator: std.mem.Allocator,
    authority_home: []const u8,
    explicit_id: []const u8,
) !?RolloutTargetSnapshot {
    if (explicit_id.len == 0) return null;
    const sessions_dir = try std.fs.path.join(allocator, &.{ authority_home, "sessions" });
    defer allocator.free(sessions_dir);
    return try findRolloutTargetByFilenameUnder(allocator, sessions_dir, explicit_id, 0);
}

fn findRolloutTargetByFilenameUnder(
    allocator: std.mem.Allocator,
    dir_path: []const u8,
    explicit_id: []const u8,
    depth: usize,
) !?RolloutTargetSnapshot {
    if (depth > 16) return null;
    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound, error.AccessDenied, error.NotDir => return null,
        else => return e,
    };
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        const path = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        defer allocator.free(path);
        switch (entry.kind) {
            .directory => {
                if (try findRolloutTargetByFilenameUnder(allocator, path, explicit_id, depth + 1)) |found| return found;
            },
            .file, .sym_link => {
                if (!std.mem.endsWith(u8, entry.name, ".jsonl")) continue;
                if (std.mem.indexOf(u8, entry.name, explicit_id) == null) continue;
                return try snapshotSingleRolloutTarget(allocator, path);
            },
            else => {},
        }
    }
    return null;
}

fn snapshotSingleRolloutTarget(
    allocator: std.mem.Allocator,
    path: []const u8,
) !RolloutTargetSnapshot {
    const stat = try std.fs.cwd().statFile(path);
    return .{
        .allocator = allocator,
        .path = try allocator.dupe(u8, path),
        .entry = .{
            .size = stat.size,
            .mtime = stat.mtime,
        },
    };
}

fn observeResumeWriteback(
    allocator: std.mem.Allocator,
    authority_home: []const u8,
    preflight: *const ResumePreflightObservation,
    request: ResumeRequest,
) !ResumeObservation {
    if (request.mode == .explicit) {
        var observation = ResumeObservation{
            .rollouts_before = preflight.rolloutsBefore(),
            .rollouts_after = 0,
            .explicit_target_found_before = preflight.explicit_target_found_before,
            .explicit_target_changed = false,
            .lookup_source = preflight.lookup_source,
        };
        if (preflight.target_snapshot) |target| {
            const after = snapshotSingleRolloutTarget(allocator, target.path) catch |e| switch (e) {
                error.FileNotFound, error.AccessDenied, error.NotDir => return observation,
                else => return e,
            };
            var after_mut = after;
            defer after_mut.deinit();

            observation.rollouts_after = 1;
            const changed = target.entry.size != after.entry.size or target.entry.mtime != after.entry.mtime;
            if (changed) {
                observation.changed_existing = 1;
                observation.explicit_target_changed = true;
            }
        }
        return observation;
    }

    var after = try snapshotRollouts(allocator, authority_home);
    defer after.deinit();

    var observation = ResumeObservation{
        .rollouts_before = 0,
        .rollouts_after = after.count(),
        .explicit_target_found_before = null,
        .explicit_target_changed = if (request.explicit_id != null) false else null,
        .lookup_source = preflight.lookup_source,
    };

    var it = after.entries.iterator();
    while (it.next()) |after_entry| {
        _ = after_entry;
        observation.created += 1;
    }

    return observation;
}

fn writeOptionalBool(writer: anytype, value: ?bool) !void {
    if (value) |v| {
        try writer.writeAll(if (v) "true" else "false");
    } else {
        try writer.writeAll("null");
    }
}

fn writeResumePreflightStatus(
    writer: anytype,
    request: ResumeRequest,
    authority: SessionAuthorityMode,
    rollouts_before: usize,
    explicit_target_found_before: ?bool,
    lookup_source: ResumeLookupSource,
) !void {
    try writer.print(
        "{{\"kind\":\"resume_preflight\",\"mode\":\"{s}\",\"session_authority\":\"{s}\",\"rollouts_before\":{d},\"explicit_id_provided\":{s},\"explicit_target_found_before\":",
        .{
            request.mode.toString(),
            authority.toString(),
            rollouts_before,
            if (request.explicit_id != null) "true" else "false",
        },
    );
    try writeOptionalBool(writer, explicit_target_found_before);
    try writer.print(",\"resume_lookup_source\":\"{s}\",\"session_id_printed\":false,\"path_printed\":false}}\n", .{lookup_source.toString()});
}

fn writeResumeAuthorityCheckStatus(
    writer: anytype,
    check: ResumeAuthorityCheck,
) !void {
    try writer.print(
        "{{\"kind\":\"resume_authority_check\",\"mode\":\"{s}\",\"session_authority\":\"{s}\",\"sqlite_authority\":\"{s}\",\"ok\":{any},\"diagnostic\":\"{s}\",\"required_entries\":{d},\"canonical_present\":{d},\"overlay_present\":{d},\"resume_authority_state_db_bridged\":{any},\"state_db_canonical_present\":{any},\"state_db_overlay_present\":{any},\"resume_authority_logs_db_bridged\":{any},\"logs_db_canonical_present\":{any},\"logs_db_overlay_present\":{any},\"legacy_provider_namespace_detected\":{any},\"legacy_provider_namespace_state_db_detected\":{any},\"legacy_provider_namespace_logs_db_detected\":{any},\"legacy_provider_namespace_scan_truncated\":{any},\"legacy_provider_namespace_scan_errors\":{d},\"legacy_provider_namespace_repair\":\"operator_explicit_backup_required\",\"session_id_printed\":false,\"path_printed\":false}}\n",
        .{
            check.mode.toString(),
            check.authority.toString(),
            check.sqlite_authority.toString(),
            check.ok,
            check.diagnostic,
            check.required_total,
            check.canonical_present,
            check.overlay_present,
            check.state_db_bridged,
            check.state_db_canonical_present,
            check.state_db_overlay_present,
            check.logs_db_bridged,
            check.logs_db_canonical_present,
            check.logs_db_overlay_present,
            check.legacy_provider_namespace_detected,
            check.legacy_provider_namespace_state_db_detected,
            check.legacy_provider_namespace_logs_db_detected,
            check.legacy_provider_namespace_scan_truncated,
            check.legacy_provider_namespace_scan_errors,
        },
    );
}

fn writeResumeWritebackStatus(
    writer: anytype,
    request: ResumeRequest,
    authority: SessionAuthorityMode,
    observation: ResumeObservation,
) !void {
    try writer.print(
        "{{\"kind\":\"resume_writeback\",\"mode\":\"{s}\",\"session_authority\":\"{s}\",\"rollouts_before\":{d},\"rollouts_after\":{d},\"changed_existing\":{d},\"created\":{d},\"explicit_target_found_before\":",
        .{
            request.mode.toString(),
            authority.toString(),
            observation.rollouts_before,
            observation.rollouts_after,
            observation.changed_existing,
            observation.created,
        },
    );
    try writeOptionalBool(writer, observation.explicit_target_found_before);
    try writer.writeAll(",\"explicit_target_changed\":");
    try writeOptionalBool(writer, observation.explicit_target_changed);
    try writer.print(",\"resume_lookup_source\":\"{s}\",\"session_id_printed\":false,\"path_printed\":false}}\n", .{observation.lookup_source.toString()});
}

fn writeAuthWritebackStatus(
    writer: anytype,
    observation: AuthWritebackObservation,
) !void {
    try writer.print(
        "{{\"kind\":\"auth_writeback\",\"auth_authority\":\"mux_owned_overlay\",\"overlay_auth_present\":{any},\"source_auth_present\":{any},\"changed\":{any},\"written\":{any},\"source_conflict\":{any},\"ok\":{any},\"token_material_printed\":false,\"path_printed\":false",
        .{
            observation.overlay_auth_present,
            observation.source_auth_present,
            observation.changed,
            observation.written,
            observation.source_conflict,
            observation.ok,
        },
    );
    if (observation.error_name) |name| {
        try writer.print(",\"error\":\"{s}\"", .{name});
    }
    try writer.writeAll("}\n");
}

fn recordManagedAuthFailureHealth(
    allocator: std.mem.Allocator,
    observation: wire_proxy.AuthAccountObservation,
    auth_writeback: AuthWritebackObservation,
) ManagedAuthHealthObservation {
    if (!observation.unrecovered()) {
        return .{ .recorded = false, .reason = "recovered_or_absent" };
    }
    if (!auth_writeback.ok) {
        return .{ .recorded = false, .reason = "auth_writeback_observation_failed" };
    }
    if (auth_writeback.changed) {
        return .{ .recorded = false, .reason = "child_auth_changed" };
    }

    const account_id = observation.account;
    const colon = std.mem.indexOfScalar(u8, account_id, ':') orelse return .{ .recorded = false, .reason = "invalid_account_id" };
    if (colon == 0 or colon + 1 >= account_id.len) return .{ .recorded = false, .reason = "invalid_account_id" };

    const provider = account_id[0..colon];
    const account = account_id[colon + 1 ..];
    const key = health_mod.accountKey(provider, account);

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();
    store.recordHttpStatus(key.slice(), 401, null);
    store.recordProbeEvidence(key.slice(), .broker_run_live, null, .auth_dead, .try_next_account);
    store.persist();

    return .{ .recorded = true, .reason = "unrecovered_401_no_writeback" };
}

fn writeManagedAuthHealthStatus(
    writer: anytype,
    observation: wire_proxy.AuthAccountObservation,
    health: ManagedAuthHealthObservation,
) !void {
    try writer.writeAll("{\"kind\":\"auth_health_observed\",\"account\":");
    try std.json.stringify(observation.account, .{}, writer);
    try writer.print(
        ",\"auth_unauthorized_turns\":{d},\"responses_401_turns\":{d},\"recovered_after_401\":{any},\"recorded\":{any},\"reason\":\"{s}\",\"scope\":\"account_credential\",\"quota_claim\":false,\"token_material_printed\":false,\"path_printed\":false}}\n",
        .{
            observation.auth_unauthorized_turns,
            observation.responses_401_turns,
            observation.recovered_after_401,
            health.recorded,
            health.reason,
        },
    );
}

fn copyFileContents(
    allocator: std.mem.Allocator,
    source_path: []const u8,
    dest_path: []const u8,
) !void {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, source_path, 2 * 1024 * 1024);
    defer allocator.free(bytes);
    const f = try std.fs.cwd().createFile(dest_path, .{ .mode = 0o600, .truncate = true });
    defer f.close();
    try f.writeAll(bytes);
}

fn observeAuthWriteback(
    allocator: std.mem.Allocator,
    session_home: []const u8,
    source_auth_path: []const u8,
    initial_auth_hash: [32]u8,
) !AuthWritebackObservation {
    var observation = AuthWritebackObservation{};

    const overlay_auth_path = try std.fs.path.join(allocator, &.{ session_home, "auth.json" });
    defer allocator.free(overlay_auth_path);

    const overlay_bytes = std.fs.cwd().readFileAlloc(allocator, overlay_auth_path, 2 * 1024 * 1024) catch |e| switch (e) {
        error.FileNotFound => return observation,
        else => return e,
    };
    defer allocator.free(overlay_bytes);
    observation.overlay_auth_present = true;

    const overlay_hash = hashBytes(overlay_bytes);
    observation.changed = !std.mem.eql(u8, overlay_hash[0..], initial_auth_hash[0..]);

    var source_bytes: ?[]u8 = null;
    defer if (source_bytes) |bytes| allocator.free(bytes);
    source_bytes = std.fs.cwd().readFileAlloc(allocator, source_auth_path, 2 * 1024 * 1024) catch |e| switch (e) {
        error.FileNotFound => null,
        else => return e,
    };
    observation.source_auth_present = source_bytes != null;

    if (!observation.changed) return observation;

    if (source_bytes) |bytes| {
        if (std.mem.eql(u8, overlay_bytes, bytes)) {
            return observation;
        }
        const source_hash = hashBytes(bytes);
        if (!std.mem.eql(u8, source_hash[0..], initial_auth_hash[0..])) {
            observation.source_conflict = true;
            observation.ok = false;
            return observation;
        }
    }

    if (observation.changed) {
        try writeFileReplaceBytes(allocator, source_auth_path, overlay_bytes);
        observation.written = true;
    }

    return observation;
}

fn hashFileContents(
    allocator: std.mem.Allocator,
    path: []const u8,
) ![32]u8 {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 2 * 1024 * 1024);
    defer allocator.free(bytes);
    return hashBytes(bytes);
}

fn hashBytes(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

fn writeFileReplaceBytes(
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes: []const u8,
) !void {
    if (std.fs.path.dirname(path)) |dir| {
        try std.fs.cwd().makePath(dir);
    }

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp-{x}", .{ path, std.crypto.random.int(u64) });
    defer allocator.free(tmp_path);

    const is_absolute = std.fs.path.isAbsolute(path);
    const file = if (is_absolute)
        try std.fs.createFileAbsolute(tmp_path, .{ .exclusive = true, .mode = 0o600 })
    else
        try std.fs.cwd().createFile(tmp_path, .{ .exclusive = true, .mode = 0o600 });
    errdefer {
        if (is_absolute) {
            std.fs.deleteFileAbsolute(tmp_path) catch {};
        } else {
            std.fs.cwd().deleteFile(tmp_path) catch {};
        }
    }

    {
        defer file.close();
        try file.writeAll(bytes);
        try file.sync();
    }

    if (is_absolute) {
        try std.fs.renameAbsolute(tmp_path, path);
    } else {
        try std.fs.cwd().rename(tmp_path, path);
    }
}

fn writeManagedConfigToml(
    allocator: std.mem.Allocator,
    codex_home: []const u8,
    proxy_port: u16,
    source_config_home: ?[]const u8,
) !ManagedConfigObservation {
    const path = try std.fmt.allocPrint(allocator, "{s}/config.toml", .{codex_home});
    defer allocator.free(path);

    var observation = ManagedConfigObservation{};
    var contents = std.ArrayListUnmanaged(u8){};
    defer contents.deinit(allocator);
    const w = contents.writer(allocator);
    var managed_root_written = false;
    var feature_defaults = CodexExperimentalFeatureDefaults{};

    if (source_config_home) |home| {
        const source_path = try std.fs.path.join(allocator, &.{ home, "config.toml" });
        defer allocator.free(source_path);
        if (std.fs.cwd().readFileAlloc(allocator, source_path, 2 * 1024 * 1024)) |source_bytes| {
            defer allocator.free(source_bytes);
            observation.source_present = true;
            observation.passthrough = true;
            observation.overridden_keys = try writeConfigPassthrough(
                allocator,
                w,
                source_bytes,
                &feature_defaults,
                &observation.experimental_feature_defaults_injected,
                &observation.mcp_stdio_unsupported_fields_removed,
                proxy_port,
            );
            managed_root_written = true;
            if (contents.items.len != 0 and contents.items[contents.items.len - 1] != '\n') try w.writeAll("\n");
            try w.writeAll("\n");
        } else |e| switch (e) {
            error.FileNotFound => {},
            else => return e,
        }
    }

    if (!managed_root_written) {
        observation.experimental_feature_defaults_injected += try feature_defaults.writeMissingAsRootDotted(w);
        if (observation.experimental_feature_defaults_injected != 0) try w.writeAll("\n");
        try writeManagedConfigRoot(w, proxy_port);
    }
    observation.overridden_keys += 2;

    const f = try std.fs.cwd().createFile(path, .{ .mode = 0o600, .truncate = true });
    defer f.close();
    try f.writeAll(contents.items);
    return observation;
}

fn writeManagedConfigRoot(writer: anytype, proxy_port: u16) !void {
    try writer.writeAll("# Managed by oauth-mux. Proxy override; unrelated Codex config above is preserved.\n");
    try writer.writeAll("# Anchor: docs/spec/codex-adapter-contract-2026-05-03.md §4\n\n");
    try writer.writeAll("model_provider = \"openai\"\n");
    try writer.print("openai_base_url = \"http://127.0.0.1:{d}/backend-api\"\n\n", .{proxy_port});
}

fn writeConfigPassthrough(
    allocator: std.mem.Allocator,
    writer: anytype,
    source_bytes: []const u8,
    feature_defaults: *CodexExperimentalFeatureDefaults,
    experimental_feature_defaults_injected: *usize,
    mcp_stdio_unsupported_fields_removed: *usize,
    proxy_port: u16,
) !usize {
    var overridden: usize = 0;
    var root = std.ArrayListUnmanaged(u8){};
    defer root.deinit(allocator);
    var tables = std.ArrayListUnmanaged(u8){};
    defer tables.deinit(allocator);
    var current_table = TomlBufferedTable{};
    defer current_table.deinit(allocator);

    var in_root = true;
    var in_features_table = false;
    var features_table_seen = false;
    var skip_table = false;
    var lines = std.mem.splitScalar(u8, source_bytes, '\n');
    while (lines.next()) |line| {
        const trimmed_left = std.mem.trimLeft(u8, line, " \t");
        const trimmed = std.mem.trim(u8, line, " \t\r");
        const starts_table = isTomlTableHeader(trimmed);
        if (starts_table) {
            try flushConfigPassthroughTable(
                allocator,
                &tables,
                &current_table,
                feature_defaults,
                experimental_feature_defaults_injected,
                mcp_stdio_unsupported_fields_removed,
            );
            in_root = false;
            in_features_table = isTomlTableHeaderNamed(trimmed, "features");
            features_table_seen = features_table_seen or in_features_table;
            skip_table = isManagedProviderTable(trimmed);
            if (skip_table) {
                overridden += 1;
            }
            try current_table.start(allocator, line, skip_table, in_features_table, isMcpServerTable(trimmed));
            continue;
        }

        if (in_root) {
            markExperimentalFeatureAssignment(feature_defaults, trimmed_left, true, false);
            if (configAssignmentOverridesMuxProvider(trimmed_left)) |classification| {
                switch (classification) {
                    .model_provider, .managed_provider => {
                        overridden += 1;
                        continue;
                    },
                    .openai_base_url => {
                        overridden += 1;
                        continue;
                    },
                }
            }
            try root.writer(allocator).writeAll(line);
            try root.writer(allocator).writeAll("\n");
            continue;
        }

        if (skip_table) continue;
        markExperimentalFeatureAssignment(feature_defaults, trimmed_left, false, in_features_table);
        if (configAssignmentOverridesMuxProvider(trimmed_left)) |classification| {
            switch (classification) {
                .model_provider, .managed_provider => {
                    overridden += 1;
                    continue;
                },
                .openai_base_url => {
                    overridden += 1;
                    continue;
                },
            }
        }
        if (current_table.mcp_server) {
            if (tomlAssignmentKey(trimmed_left)) |key| {
                if (std.mem.eql(u8, key, "command")) {
                    current_table.mcp_has_command = true;
                } else if (isUnsupportedStdioMcpFieldKey(key)) {
                    current_table.mcp_unsupported_stdio_fields += 1;
                }
            }
        }
        try current_table.appendLine(allocator, line);
    }
    try flushConfigPassthroughTable(
        allocator,
        &tables,
        &current_table,
        feature_defaults,
        experimental_feature_defaults_injected,
        mcp_stdio_unsupported_fields_removed,
    );
    if (!features_table_seen) {
        experimental_feature_defaults_injected.* += try feature_defaults.writeMissingAsRootDotted(root.writer(allocator));
    }

    if (root.items.len != 0) {
        try writer.writeAll(root.items);
        if (root.items[root.items.len - 1] != '\n') try writer.writeAll("\n");
    }
    try writeManagedConfigRoot(writer, proxy_port);
    if (tables.items.len != 0) {
        try writer.writeAll(tables.items);
        if (tables.items[tables.items.len - 1] != '\n') try writer.writeAll("\n");
    }
    return overridden;
}

fn flushConfigPassthroughTable(
    allocator: std.mem.Allocator,
    tables: *std.ArrayListUnmanaged(u8),
    table: *TomlBufferedTable,
    feature_defaults: *CodexExperimentalFeatureDefaults,
    experimental_feature_defaults_injected: *usize,
    mcp_stdio_unsupported_fields_removed: *usize,
) !void {
    if (!table.active) return;
    defer table.reset();
    if (table.skip) return;
    if (table.features) {
        experimental_feature_defaults_injected.* += try feature_defaults.writeMissingAsTableEntries(table.lines.writer(allocator));
    }
    const sanitize_stdio_mcp = table.mcp_server and table.mcp_has_command and table.mcp_unsupported_stdio_fields != 0;
    if (!sanitize_stdio_mcp) {
        try tables.writer(allocator).writeAll(table.lines.items);
        return;
    }

    var start: usize = 0;
    while (start < table.lines.items.len) {
        const next = std.mem.indexOfScalarPos(u8, table.lines.items, start, '\n') orelse table.lines.items.len;
        const line = table.lines.items[start..next];
        const had_newline = next < table.lines.items.len;
        if (isUnsupportedStdioMcpFieldLine(line)) {
            mcp_stdio_unsupported_fields_removed.* += 1;
        } else {
            try tables.writer(allocator).writeAll(line);
            if (had_newline) try tables.writer(allocator).writeByte('\n');
        }
        start = if (had_newline) next + 1 else next;
    }
}

fn isTomlTableHeader(trimmed_line: []const u8) bool {
    var line = trimmed_line;
    if (std.mem.indexOfScalar(u8, line, '#')) |idx| line = std.mem.trim(u8, line[0..idx], " \t\r");
    return std.mem.startsWith(u8, line, "[") and std.mem.endsWith(u8, line, "]");
}

fn isTomlTableHeaderNamed(trimmed_line: []const u8, table_name: []const u8) bool {
    var line = trimmed_line;
    if (std.mem.indexOfScalar(u8, line, '#')) |idx| line = std.mem.trim(u8, line[0..idx], " \t\r");
    if (!std.mem.startsWith(u8, line, "[") or !std.mem.endsWith(u8, line, "]")) return false;
    if (std.mem.startsWith(u8, line, "[[")) return false;
    const body = std.mem.trim(u8, line[1 .. line.len - 1], " \t\r");
    return std.mem.eql(u8, body, table_name);
}

fn isManagedProviderTable(trimmed_line: []const u8) bool {
    var line = trimmed_line;
    if (std.mem.indexOfScalar(u8, line, '#')) |idx| line = std.mem.trim(u8, line[0..idx], " \t\r");
    if (std.mem.startsWith(u8, line, "[[") and std.mem.endsWith(u8, line, "]]")) {
        line = line[1 .. line.len - 1];
    }
    return std.mem.eql(u8, line, "[model_providers.oauth_mux_openai]") or
        (std.mem.startsWith(u8, line, "[model_providers.oauth_mux_openai.") and std.mem.endsWith(u8, line, "]"));
}

fn isMcpServerTable(trimmed_line: []const u8) bool {
    var line = trimmed_line;
    if (std.mem.indexOfScalar(u8, line, '#')) |idx| line = std.mem.trim(u8, line[0..idx], " \t\r");
    if (!std.mem.startsWith(u8, line, "[") or !std.mem.endsWith(u8, line, "]")) return false;
    if (std.mem.startsWith(u8, line, "[[")) return false;
    const body = std.mem.trim(u8, line[1 .. line.len - 1], " \t\r");
    return std.mem.startsWith(u8, body, "mcp_servers.");
}

fn tomlAssignmentKey(assignment: []const u8) ?[]const u8 {
    const eq = std.mem.indexOfScalar(u8, assignment, '=') orelse return null;
    var key = std.mem.trim(u8, assignment[0..eq], " \t\r\n");
    if (key.len == 0 or std.mem.startsWith(u8, key, "#")) return null;
    key = std.mem.trim(u8, key, "\"'");
    return key;
}

fn isUnsupportedStdioMcpFieldKey(key: []const u8) bool {
    return std.mem.eql(u8, key, "url") or std.mem.eql(u8, key, "bearer_token_env_var");
}

fn isUnsupportedStdioMcpFieldLine(line: []const u8) bool {
    const key = tomlAssignmentKey(std.mem.trimLeft(u8, line, " \t")) orelse return false;
    return isUnsupportedStdioMcpFieldKey(key);
}

fn markExperimentalFeatureAssignment(
    feature_defaults: *CodexExperimentalFeatureDefaults,
    assignment: []const u8,
    in_root: bool,
    in_features_table: bool,
) void {
    const key = tomlAssignmentKey(assignment) orelse return;
    if (in_features_table) {
        feature_defaults.mark(key);
        return;
    }
    if (in_root and std.mem.startsWith(u8, key, "features.")) {
        var feature_key = key["features.".len..];
        feature_key = std.mem.trim(u8, feature_key, "\"'");
        feature_defaults.mark(feature_key);
    }
}

fn checkForwardedConfigOverrides(argv: []const []const u8) ConfigOverrideCheck {
    var result = ConfigOverrideCheck{};
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--config") or std.mem.eql(u8, arg, "-c")) {
            if (i + 1 < argv.len) {
                recordConfigOverride(&result, argv[i + 1]);
                i += 1;
            }
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--config=")) {
            recordConfigOverride(&result, arg["--config=".len..]);
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-c=")) {
            recordConfigOverride(&result, arg["-c=".len..]);
            continue;
        }
    }
    result.ok = result.mux_owned_overrides == 0;
    return result;
}

fn recordConfigOverride(result: *ConfigOverrideCheck, assignment: []const u8) void {
    result.total_config_overrides += 1;
    if (configAssignmentOverridesMuxProvider(assignment)) |classification| {
        result.mux_owned_overrides += 1;
        switch (classification) {
            .model_provider => result.model_provider_override = true,
            .openai_base_url => result.openai_base_url_override = true,
            .managed_provider => result.managed_provider_override = true,
        }
    }
}

const ConfigOverrideClassification = enum {
    model_provider,
    openai_base_url,
    managed_provider,
};

fn configAssignmentOverridesMuxProvider(assignment: []const u8) ?ConfigOverrideClassification {
    const key = tomlAssignmentKey(assignment) orelse return null;
    if (std.mem.eql(u8, key, "model_provider") or std.mem.endsWith(u8, key, ".model_provider")) {
        return .model_provider;
    }
    if (std.mem.eql(u8, key, "openai_base_url")) {
        return .openai_base_url;
    }
    if (std.mem.eql(u8, key, "model_providers.oauth_mux_openai") or
        std.mem.startsWith(u8, key, "model_providers.oauth_mux_openai."))
    {
        return .managed_provider;
    }
    return null;
}

fn writeConfigOverrideCheckStatus(writer: anytype, check: ConfigOverrideCheck) !void {
    try writer.print(
        "{{\"kind\":\"config_passthrough_check\",\"ok\":{any},\"total_config_overrides\":{d},\"mux_owned_overrides\":{d},\"model_provider_override\":{any},\"openai_base_url_override\":{any},\"managed_provider_override\":{any},\"paths_printed\":false,\"values_printed\":false}}\n",
        .{
            check.ok,
            check.total_config_overrides,
            check.mux_owned_overrides,
            check.model_provider_override,
            check.openai_base_url_override,
            check.managed_provider_override,
        },
    );
}

test "RunOptions defaults" {
    const opts = RunOptions{};
    try std.testing.expect(opts.profile == null);
    try std.testing.expect(opts.capability == null);
    try std.testing.expect(opts.session_home == null);
    try std.testing.expect(!opts.isolated_session_store);
    try std.testing.expect(!opts.json_status);
    try std.testing.expect(opts.json_status_file == null);
    try std.testing.expectEqual(@as(usize, 0), opts.forward_argv.len);
}

test "managedRouteCapability infers unique profile capability and rejects ambiguous profiles" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 20, "secret": { "backend": "file", "path": "/tmp/a" } },
        \\        "max-2": { "priority": 10, "secret": { "backend": "file", "path": "/tmp/b" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max"] },
        \\    "mixed": { "providers": ["codex:max-1#codex-mini", "codex:max-2#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    const inferred = managedRouteCapability(parsed.value, null, "codex-max");
    switch (inferred) {
        .capability => |capability| try std.testing.expectEqualStrings("codex-max", capability),
        else => return error.Unexpected,
    }
    switch (managedRouteCapability(parsed.value, null, "mixed")) {
        .ambiguous => {},
        else => return error.Unexpected,
    }
    switch (managedRouteCapability(parsed.value, "codex-mini", "mixed")) {
        .capability => |capability| try std.testing.expectEqualStrings("codex-mini", capability),
        else => return error.Unexpected,
    }
    switch (managedRouteCapability(parsed.value, null, null)) {
        .none => {},
        else => return error.Unexpected,
    }
}

test "expandTilde no-op when no tilde" {
    const a = try expandTilde(std.testing.allocator, "/no/tilde/here");
    defer std.testing.allocator.free(a);
    try std.testing.expectEqualStrings("/no/tilde/here", a);
}

test "resolveExecutableFromSearchPath finds executable by basename" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("codex", .{ .mode = 0o755 });
    file.close();

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);

    const resolved = (try resolveExecutableFromSearchPath(std.testing.allocator, "codex", root_path)).?;
    defer std.testing.allocator.free(resolved);
    const expected = try std.fs.path.join(std.testing.allocator, &.{ root_path, "codex" });
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, resolved);
}

test "resolveCodexBinary accepts explicit existing path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("codex", .{ .mode = 0o755 });
    file.close();

    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex");
    defer std.testing.allocator.free(path);
    const resolved = try resolveCodexBinary(std.testing.allocator, path);
    defer std.testing.allocator.free(resolved);
    try std.testing.expectEqualStrings(path, resolved);
}

test "resolveCodexBinary rejects explicit oauth-mux codex shim" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("codex", .{ .mode = 0o755 });
    try file.writeAll("#!/bin/sh\n# OMUX_CODEX_SHIM\nexec oauth-mux codex \"$@\"\n");
    file.close();

    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex");
    defer std.testing.allocator.free(path);
    try std.testing.expectError(RunError.CodexShimRecursion, resolveCodexBinary(std.testing.allocator, path));
}

test "resolveExecutableFromSearchPath skips oauth-mux codex shim" {
    var shim_tmp = std.testing.tmpDir(.{});
    defer shim_tmp.cleanup();
    var native_tmp = std.testing.tmpDir(.{});
    defer native_tmp.cleanup();

    const shim = try shim_tmp.dir.createFile("codex", .{ .mode = 0o755 });
    try shim.writeAll("#!/bin/sh\n# OMUX_CODEX_SHIM\nexec oauth-mux codex \"$@\"\n");
    shim.close();
    const native = try native_tmp.dir.createFile("codex", .{ .mode = 0o755 });
    try native.writeAll("#!/bin/sh\nexit 0\n");
    native.close();

    const shim_root = try shim_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(shim_root);
    const native_root = try native_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(native_root);
    const search_path = try std.fmt.allocPrint(std.testing.allocator, "{s}{c}{s}", .{ shim_root, std.fs.path.delimiter, native_root });
    defer std.testing.allocator.free(search_path);

    const resolved = (try resolveExecutableFromSearchPath(std.testing.allocator, "codex", search_path)).?;
    defer std.testing.allocator.free(resolved);
    const expected = try std.fs.path.join(std.testing.allocator, &.{ native_root, "codex" });
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, resolved);
}

test "restrictPoolToCodex blocks non-codex routes" {
    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try pool.add(.{ .id = "claude:personal", .selectable = true, .liveness = .live, .availability = .available });
    try pool.add(.{ .id = "github:default", .selectable = true, .liveness = .live, .availability = .available });
    try pool.add(.{ .id = "codex:default", .selectable = true, .liveness = .live, .availability = .available });

    restrictPoolToCodex(&pool);
    const elected = try pool.elect(null, null, &.{});
    try std.testing.expectEqualStrings("codex:default", elected.id);

    for (pool.accounts.items) |entry| {
        if (isCodexAccountId(entry.id)) {
            try std.testing.expect(entry.selectable);
        } else {
            try std.testing.expect(!entry.selectable);
            try std.testing.expectEqual(broker.account_pool_mod.Liveness.unknown, entry.liveness);
            try std.testing.expectEqual(broker.account_pool_mod.Availability.unknown, entry.availability);
        }
    }
}

test "openStatusFile property: nested parents are created" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const cases = [_][]const u8{
        "status.ndjson",
        "one/status.ndjson",
        "one/two/status.ndjson",
        "one/two/three/status.ndjson",
    };

    for (cases) |relative| {
        const status_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, relative });
        defer std.testing.allocator.free(status_path);
        const file = try openStatusFile(status_path);
        try file.writeAll("{\"ok\":true}\n");
        file.close();

        const bytes = try std.fs.cwd().readFileAlloc(std.testing.allocator, status_path, 1024);
        defer std.testing.allocator.free(bytes);
        try std.testing.expectEqualStrings("{\"ok\":true}\n", bytes);
    }
}

test "detectResumeRequest classifies forwarded Codex resume shapes" {
    const none = detectResumeRequest(&.{ "--model", "gpt-5.5" });
    try std.testing.expectEqual(ResumeMode.none, none.mode);

    const chooser = detectResumeRequest(&.{"resume"});
    try std.testing.expectEqual(ResumeMode.chooser, chooser.mode);

    const last = detectResumeRequest(&.{ "--no-alt-screen", "resume", "--last" });
    try std.testing.expectEqual(ResumeMode.last, last.mode);

    const short_last = detectResumeRequest(&.{ "resume", "-l" });
    try std.testing.expectEqual(ResumeMode.last, short_last.mode);

    const explicit = detectResumeRequest(&.{ "resume", "019dea53-49a0-7890-9580-e88decb97af0" });
    try std.testing.expectEqual(ResumeMode.explicit, explicit.mode);
    try std.testing.expectEqualStrings("019dea53-49a0-7890-9580-e88decb97af0", explicit.explicit_id.?);
}

test "resume writeback observation reports existing rollout changes without printing paths" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("canonical/sessions/2026/05/06");
    {
        const rollout = try tmp.dir.createFile("canonical/sessions/2026/05/06/rollout-managed-good-session.jsonl", .{ .mode = 0o600 });
        defer rollout.close();
        try rollout.writeAll("{\"fixture\":true}\n");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "canonical" });
    defer std.testing.allocator.free(canonical_path);
    const rollout_path = try std.fs.path.join(std.testing.allocator, &.{ canonical_path, "sessions", "2026", "05", "06", "rollout-managed-good-session.jsonl" });
    defer std.testing.allocator.free(rollout_path);

    var preflight = try lookupExplicitResumePreflight(std.testing.allocator, canonical_path, "managed-good-session");
    defer preflight.deinit();
    try std.testing.expectEqual(ResumeLookupSource.filename_scan, preflight.lookup_source);
    try std.testing.expectEqual(true, preflight.explicit_target_found_before.?);
    try std.testing.expectEqual(@as(usize, 1), preflight.rolloutsBefore());

    {
        const rollout = try std.fs.cwd().openFile(rollout_path, .{ .mode = .write_only });
        defer rollout.close();
        try rollout.seekFromEnd(0);
        try rollout.writeAll("{\"managed\":true}\n");
    }

    const request = ResumeRequest{ .mode = .explicit, .explicit_id = "managed-good-session" };
    const observation = try observeResumeWriteback(std.testing.allocator, canonical_path, &preflight, request);
    try std.testing.expectEqual(@as(usize, 1), observation.rollouts_before);
    try std.testing.expectEqual(@as(usize, 1), observation.rollouts_after);
    try std.testing.expectEqual(@as(usize, 1), observation.changed_existing);
    try std.testing.expectEqual(@as(usize, 0), observation.created);
    try std.testing.expectEqual(true, observation.explicit_target_found_before.?);
    try std.testing.expectEqual(true, observation.explicit_target_changed.?);
    try std.testing.expectEqual(ResumeLookupSource.filename_scan, observation.lookup_source);
}

test "createSessionCodexHomeUnder copies auth and does not clobber source config" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"fixture\"}}\n");
    }
    {
        const install = try tmp.dir.createFile("account/installation_id", .{ .mode = 0o600 });
        defer install.close();
        try install.writeAll("install-fixture\n");
    }
    {
        const cfg = try tmp.dir.createFile("account/config.toml", .{ .mode = 0o600 });
        defer cfg.close();
        try cfg.writeAll("preexisting = true\n");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, null, null);
    defer codex_home.deinit(std.testing.allocator);
    try std.testing.expectEqual(SessionAuthorityMode.isolated, codex_home.session_authority);
    try std.testing.expectEqual(CodexSqliteAuthorityMode.isolated_overlay, codex_home.sqlite_authority);

    const session_auth = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "auth.json" });
    defer std.testing.allocator.free(session_auth);
    const copied_auth = try std.fs.cwd().readFileAlloc(std.testing.allocator, session_auth, 1024);
    defer std.testing.allocator.free(copied_auth);
    try std.testing.expectEqualStrings("{\"tokens\":{\"access_token\":\"fixture\"}}\n", copied_auth);

    const session_install = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "installation_id" });
    defer std.testing.allocator.free(session_install);
    const copied_install = try std.fs.cwd().readFileAlloc(std.testing.allocator, session_install, 1024);
    defer std.testing.allocator.free(copied_install);
    try std.testing.expectEqualStrings("install-fixture\n", copied_install);

    const session_config = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "config.toml" });
    defer std.testing.allocator.free(session_config);
    const generated_config = try std.fs.cwd().readFileAlloc(std.testing.allocator, session_config, 4096);
    defer std.testing.allocator.free(generated_config);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "127.0.0.1:45678") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "model_provider = \"openai\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "openai_base_url = \"http://127.0.0.1:45678/backend-api\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "[model_providers.oauth_mux_openai]") == null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "[model_providers.openai]") == null);
    try std.testing.expectEqual(@as(usize, 5), codex_home.experimental_feature_defaults_injected);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "features.terminal_resize_reflow = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "features.memories = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "features.external_migration = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "features.goals = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "features.prevent_idle_sleep = true") != null);

    const source_config = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "config.toml" });
    defer std.testing.allocator.free(source_config);
    const original_config = try std.fs.cwd().readFileAlloc(std.testing.allocator, source_config, 1024);
    defer std.testing.allocator.free(original_config);
    try std.testing.expectEqualStrings("preexisting = true\n", original_config);
}

test "createSessionCodexHomeUnder preserves canonical config behavior settings" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    try tmp.dir.makePath("canonical");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"fixture\"}}\n");
    }
    {
        const cfg = try tmp.dir.createFile("canonical/config.toml", .{ .mode = 0o600 });
        defer cfg.close();
        try cfg.writeAll(
            \\model = "gpt-5.5"
            \\model_provider = "user_provider"
            \\approval_policy = "on-request"
            \\sandbox_mode = "workspace-write"
            \\experimental_legacy_flag = true
            \\
            \\[features]
            \\apps = true
            \\memories = true
            \\multi_agent = true
            \\
            \\[mcp_servers.design]
            \\url = "https://figma.invalid/mcp"
            \\bearer_token_env_var = "FIGMA_ACCESS_TOKEN"
            \\command = "figma-mcp"
            \\
            \\[mcp_servers.linear]
            \\url = "https://mcp.linear.app/mcp"
            \\bearer_token_env_var = "LINEAR_API_KEY"
            \\
            \\[model_providers.user_provider]
            \\name = "User Provider"
            \\base_url = "https://example.invalid/api"
            \\
            \\[model_providers.oauth_mux_openai]
            \\name = "stale mux"
            \\base_url = "https://stale.invalid"
            \\
            \\[tui.model_availability_nux]
            \\"gpt-5.5" = 2
            \\
        );
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "canonical" });
    defer std.testing.allocator.free(canonical_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, canonical_path, canonical_path);
    defer codex_home.deinit(std.testing.allocator);
    try std.testing.expect(codex_home.config_source_present);
    try std.testing.expect(codex_home.config_passthrough);
    try std.testing.expect(codex_home.config_overridden_keys >= 2);
    try std.testing.expectEqual(@as(usize, 4), codex_home.experimental_feature_defaults_injected);
    try std.testing.expectEqual(@as(usize, 2), codex_home.mcp_stdio_unsupported_fields_removed);

    const overlay_config = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "config.toml" });
    defer std.testing.allocator.free(overlay_config);
    const generated_config = try std.fs.cwd().readFileAlloc(std.testing.allocator, overlay_config, 8192);
    defer std.testing.allocator.free(generated_config);

    try std.testing.expect(std.mem.indexOf(u8, generated_config, "model = \"gpt-5.5\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "approval_policy = \"on-request\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "sandbox_mode = \"workspace-write\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "experimental_legacy_flag = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "[features]") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "terminal_resize_reflow = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "multi_agent = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "external_migration = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "goals = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "prevent_idle_sleep = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "[mcp_servers.design]") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "https://figma.invalid/mcp") == null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "FIGMA_ACCESS_TOKEN") == null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "[mcp_servers.linear]") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "https://mcp.linear.app/mcp") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "LINEAR_API_KEY") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "[model_providers.user_provider]") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "https://example.invalid/api") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "[tui.model_availability_nux]") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "\"gpt-5.5\" = 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "https://stale.invalid") == null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "model_provider = \"user_provider\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "model_provider = \"openai\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "openai_base_url = \"http://127.0.0.1:45678/backend-api\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "[model_providers.oauth_mux_openai]") == null);
    const managed_provider_idx = std.mem.indexOf(u8, generated_config, "model_provider = \"openai\"").?;
    const tui_table_idx = std.mem.indexOf(u8, generated_config, "[tui.model_availability_nux]").?;
    const features_idx = std.mem.indexOf(u8, generated_config, "[features]").?;
    const mcp_idx = std.mem.indexOf(u8, generated_config, "[mcp_servers.design]").?;
    try std.testing.expect(managed_provider_idx < tui_table_idx);
    try std.testing.expect(features_idx < mcp_idx);
    try std.testing.expect(std.mem.indexOf(u8, generated_config[features_idx..mcp_idx], "terminal_resize_reflow = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "http://127.0.0.1:45678/backend-api") != null);
}

test "config passthrough preserves explicit experimental feature choices" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    try tmp.dir.makePath("canonical");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"fixture\"}}\n");
    }
    {
        const cfg = try tmp.dir.createFile("canonical/config.toml", .{ .mode = 0o600 });
        defer cfg.close();
        try cfg.writeAll(
            \\[features]
            \\goals = false
            \\memories = true
            \\
        );
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "canonical" });
    defer std.testing.allocator.free(canonical_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, null, canonical_path);
    defer codex_home.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), codex_home.experimental_feature_defaults_injected);

    const overlay_config = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "config.toml" });
    defer std.testing.allocator.free(overlay_config);
    const generated_config = try std.fs.cwd().readFileAlloc(std.testing.allocator, overlay_config, 8192);
    defer std.testing.allocator.free(generated_config);

    try std.testing.expect(std.mem.indexOf(u8, generated_config, "goals = false") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "goals = true") == null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "terminal_resize_reflow = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "external_migration = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "prevent_idle_sleep = true") != null);
}

test "config passthrough partitions root model provider before trailing table" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    try tmp.dir.makePath("canonical");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"fixture\"}}\n");
    }
    {
        const cfg = try tmp.dir.createFile("canonical/config.toml", .{ .mode = 0o600 });
        defer cfg.close();
        try cfg.writeAll(
            \\model = "gpt-5.5"
            \\
            \\[tui.model_availability_nux]
            \\"gpt-5.5" = 2
            \\
        );
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "canonical" });
    defer std.testing.allocator.free(canonical_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, null, canonical_path);
    defer codex_home.deinit(std.testing.allocator);

    const overlay_config = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "config.toml" });
    defer std.testing.allocator.free(overlay_config);
    const generated_config = try std.fs.cwd().readFileAlloc(std.testing.allocator, overlay_config, 8192);
    defer std.testing.allocator.free(generated_config);

    const provider_idx = std.mem.indexOf(u8, generated_config, "model_provider = \"openai\"").?;
    const base_url_idx = std.mem.indexOf(u8, generated_config, "openai_base_url = \"http://127.0.0.1:45678/backend-api\"").?;
    const tui_idx = std.mem.indexOf(u8, generated_config, "[tui.model_availability_nux]").?;
    try std.testing.expect(provider_idx < tui_idx);
    try std.testing.expect(provider_idx < base_url_idx);
    try std.testing.expect(base_url_idx < tui_idx);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "[model_providers.oauth_mux_openai]") == null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "\"gpt-5.5\" = 2") != null);
}

test "config passthrough strips profile-scoped model_provider overrides" {
    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(std.testing.allocator);
    var feature_defaults = CodexExperimentalFeatureDefaults{};
    var experimental_feature_defaults_injected: usize = 0;
    var mcp_stdio_unsupported_fields_removed: usize = 0;
    const source =
        \\[profiles.work]
        \\model = "gpt-5.5"
        \\model_provider = "user_provider"
        \\approval_policy = "on-request"
        \\
        \\[profiles.work.features]
        \\experimental_apply_patch = true
        \\
    ;
    const overridden = try writeConfigPassthrough(std.testing.allocator, buf.writer(std.testing.allocator), source, &feature_defaults, &experimental_feature_defaults_injected, &mcp_stdio_unsupported_fields_removed, 45678);

    try std.testing.expectEqual(@as(usize, 1), overridden);
    try std.testing.expectEqual(@as(usize, 5), experimental_feature_defaults_injected);
    try std.testing.expectEqual(@as(usize, 0), mcp_stdio_unsupported_fields_removed);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "[profiles.work]") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "model = \"gpt-5.5\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "approval_policy = \"on-request\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "experimental_apply_patch = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "model_provider = \"user_provider\"") == null);
}

test "forwarded Codex config overrides cannot replace managed provider" {
    const safe_argv = [_][]const u8{
        "--config", "model=\"gpt-5.5\"",
        "-c",       "profiles.work.approval_policy=\"on-request\"",
    };
    const safe = checkForwardedConfigOverrides(&safe_argv);
    try std.testing.expect(safe.ok);
    try std.testing.expectEqual(@as(usize, 2), safe.total_config_overrides);
    try std.testing.expectEqual(@as(usize, 0), safe.mux_owned_overrides);

    const unsafe_argv = [_][]const u8{
        "--config",                                         "model_provider=\"openai\"",
        "--config=profiles.work.model_provider=\"custom\"", "-c=model_providers.oauth_mux_openai.base_url=\"https://example.invalid\"",
        "-c",                                               "openai_base_url=\"https://example.invalid\"",
        "--model",                                          "gpt-5.5",
    };
    const unsafe = checkForwardedConfigOverrides(&unsafe_argv);
    try std.testing.expect(!unsafe.ok);
    try std.testing.expectEqual(@as(usize, 4), unsafe.total_config_overrides);
    try std.testing.expectEqual(@as(usize, 4), unsafe.mux_owned_overrides);
    try std.testing.expect(unsafe.model_provider_override);
    try std.testing.expect(unsafe.openai_base_url_override);
    try std.testing.expect(unsafe.managed_provider_override);
}

test "config passthrough is independent from session authority" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    try tmp.dir.makePath("config-home");
    try tmp.dir.makePath("session-home/sessions");
    try tmp.dir.makePath("session-home/shell_snapshots");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"fixture\"}}\n");
    }
    {
        const cfg = try tmp.dir.createFile("config-home/config.toml", .{ .mode = 0o600 });
        defer cfg.close();
        try cfg.writeAll(
            \\model = "gpt-5.4"
            \\experimental_legacy_flag = true
            \\
            \\[features]
            \\unified_exec = true
            \\
            \\[model_providers.oauth_mux_openai.env]
            \\SHOULD_NOT_SURVIVE = "1"
            \\
            \\[model_providers.keep_me]
            \\name = "Keep Me"
            \\
        );
    }
    {
        const cfg = try tmp.dir.createFile("session-home/config.toml", .{ .mode = 0o600 });
        defer cfg.close();
        try cfg.writeAll("model = \"wrong-session-config\"\n");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);
    const config_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "config-home" });
    defer std.testing.allocator.free(config_path);
    const session_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "session-home" });
    defer std.testing.allocator.free(session_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, session_path, config_path);
    defer codex_home.deinit(std.testing.allocator);
    try std.testing.expectEqual(SessionAuthorityMode.canonical_bridge, codex_home.session_authority);
    try std.testing.expectEqual(CodexSqliteAuthorityMode.canonical_env, codex_home.sqlite_authority);
    try std.testing.expect(codex_home.config_source_present);
    try std.testing.expect(codex_home.config_passthrough);

    const overlay_config = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "config.toml" });
    defer std.testing.allocator.free(overlay_config);
    const generated_config = try std.fs.cwd().readFileAlloc(std.testing.allocator, overlay_config, 8192);
    defer std.testing.allocator.free(generated_config);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "model = \"gpt-5.4\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "unified_exec = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "[model_providers.keep_me]") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "wrong-session-config") == null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "SHOULD_NOT_SURVIVE") == null);
}

test "managed Codex overlay homes are not reusable authority homes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("oauth-mux-codex-fixture");
    try tmp.dir.makePath("canonical");
    {
        const cfg = try tmp.dir.createFile("oauth-mux-codex-fixture/config.toml", .{ .mode = 0o600 });
        defer cfg.close();
        try cfg.writeAll(
            \\# Managed by oauth-mux. Proxy override; unrelated Codex config above is preserved.
            \\model_provider = "oauth_mux_openai"
            \\
            \\[model_providers.oauth_mux_openai]
            \\name = "managed"
            \\
        );
    }
    {
        const cfg = try tmp.dir.createFile("canonical/config.toml", .{ .mode = 0o600 });
        defer cfg.close();
        try cfg.writeAll(
            \\model = "gpt-5.5"
            \\
            \\[mcp_servers.linear]
            \\url = "https://mcp.linear.app/mcp"
            \\
        );
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const overlay_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "oauth-mux-codex-fixture" });
    defer std.testing.allocator.free(overlay_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "canonical" });
    defer std.testing.allocator.free(canonical_path);

    try std.testing.expect(try isManagedCodexOverlayHome(std.testing.allocator, overlay_path));
    try std.testing.expect(!try isManagedCodexOverlayHome(std.testing.allocator, canonical_path));
}

test "observeAuthWriteback imports changed overlay auth into mux source" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"old\",\"refresh_token\":\"old-rt\"}}\n");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, null, null);
    defer codex_home.deinit(std.testing.allocator);

    const overlay_auth = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "auth.json" });
    defer std.testing.allocator.free(overlay_auth);
    {
        const auth = try std.fs.cwd().createFile(overlay_auth, .{ .mode = 0o600, .truncate = true });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"new\",\"refresh_token\":\"new-rt\"}}\n");
    }

    const observation = try observeAuthWriteback(std.testing.allocator, codex_home.path, auth_path, codex_home.auth_initial_hash);
    try std.testing.expect(observation.overlay_auth_present);
    try std.testing.expect(observation.source_auth_present);
    try std.testing.expect(observation.changed);
    try std.testing.expect(observation.written);
    try std.testing.expect(!observation.source_conflict);
    try std.testing.expect(observation.ok);
    try std.testing.expect(observation.error_name == null);

    const source_auth = try std.fs.cwd().readFileAlloc(std.testing.allocator, auth_path, 1024);
    defer std.testing.allocator.free(source_auth);
    try std.testing.expectEqualStrings("{\"tokens\":{\"access_token\":\"new\",\"refresh_token\":\"new-rt\"}}\n", source_auth);
}

test "observeAuthWriteback leaves unchanged overlay auth alone" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"same\"}}\n");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, null, null);
    defer codex_home.deinit(std.testing.allocator);

    const observation = try observeAuthWriteback(std.testing.allocator, codex_home.path, auth_path, codex_home.auth_initial_hash);
    try std.testing.expect(observation.overlay_auth_present);
    try std.testing.expect(observation.source_auth_present);
    try std.testing.expect(!observation.changed);
    try std.testing.expect(!observation.written);
    try std.testing.expect(!observation.source_conflict);
    try std.testing.expect(observation.ok);
    try std.testing.expect(observation.error_name == null);
}

test "observeAuthWriteback refuses to overwrite independently changed mux source" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"old\",\"refresh_token\":\"old-rt\"}}\n");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, null, null);
    defer codex_home.deinit(std.testing.allocator);

    const overlay_auth = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "auth.json" });
    defer std.testing.allocator.free(overlay_auth);
    {
        const auth = try std.fs.cwd().createFile(overlay_auth, .{ .mode = 0o600, .truncate = true });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"overlay-new\",\"refresh_token\":\"overlay-rt\"}}\n");
    }
    {
        const auth = try std.fs.cwd().createFile(auth_path, .{ .mode = 0o600, .truncate = true });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"source-new\",\"refresh_token\":\"source-rt\"}}\n");
    }

    const observation = try observeAuthWriteback(std.testing.allocator, codex_home.path, auth_path, codex_home.auth_initial_hash);
    try std.testing.expect(observation.overlay_auth_present);
    try std.testing.expect(observation.source_auth_present);
    try std.testing.expect(observation.changed);
    try std.testing.expect(!observation.written);
    try std.testing.expect(observation.source_conflict);
    try std.testing.expect(!observation.ok);

    const source_auth = try std.fs.cwd().readFileAlloc(std.testing.allocator, auth_path, 1024);
    defer std.testing.allocator.free(source_auth);
    try std.testing.expectEqualStrings("{\"tokens\":{\"access_token\":\"source-new\",\"refresh_token\":\"source-rt\"}}\n", source_auth);
}

test "createSessionCodexHomeUnder bridges canonical session authority without copying" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"fixture\"}}\n");
    }
    try tmp.dir.makePath("canonical/sessions/2026/05/05");
    try tmp.dir.makePath("canonical/shell_snapshots");
    {
        const session = try tmp.dir.createFile("canonical/sessions/2026/05/05/session.jsonl", .{ .mode = 0o600 });
        defer session.close();
        try session.writeAll("{\"fixture\":true}\n");
    }
    {
        const state = try tmp.dir.createFile("canonical/state_5.sqlite", .{ .mode = 0o600 });
        defer state.close();
        try state.writeAll("managed-good-session");
    }
    {
        const wal = try tmp.dir.createFile("canonical/state_5.sqlite-wal", .{ .mode = 0o600 });
        defer wal.close();
        try wal.writeAll("wal");
    }
    {
        const logs = try tmp.dir.createFile("canonical/logs_2.sqlite", .{ .mode = 0o600 });
        defer logs.close();
        try logs.writeAll("managed-good-session");
    }
    {
        const logs_wal = try tmp.dir.createFile("canonical/logs_2.sqlite-wal", .{ .mode = 0o600 });
        defer logs_wal.close();
        try logs_wal.writeAll("logs-wal");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "canonical" });
    defer std.testing.allocator.free(canonical_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, canonical_path, canonical_path);
    defer codex_home.deinit(std.testing.allocator);
    try std.testing.expectEqual(SessionAuthorityMode.canonical_bridge, codex_home.session_authority);
    try std.testing.expectEqual(CodexSqliteAuthorityMode.canonical_env, codex_home.sqlite_authority);

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sessions_link = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "sessions" });
    defer std.testing.allocator.free(sessions_link);
    const sessions_target = try std.fs.readLinkAbsolute(sessions_link, &link_buf);
    const expected_sessions_target = try std.fs.path.join(std.testing.allocator, &.{ canonical_path, "sessions" });
    defer std.testing.allocator.free(expected_sessions_target);
    try std.testing.expectEqualStrings(expected_sessions_target, sessions_target);

    var state_link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const state_link = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "state_5.sqlite" });
    defer std.testing.allocator.free(state_link);
    const state_target = try std.fs.readLinkAbsolute(state_link, &state_link_buf);
    const expected_state_target = try std.fs.path.join(std.testing.allocator, &.{ canonical_path, "state_5.sqlite" });
    defer std.testing.allocator.free(expected_state_target);
    try std.testing.expectEqualStrings(expected_state_target, state_target);

    const wal_link = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "state_5.sqlite-wal" });
    defer std.testing.allocator.free(wal_link);
    var wal_link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const wal_target = try std.fs.readLinkAbsolute(wal_link, &wal_link_buf);
    const expected_wal_target = try std.fs.path.join(std.testing.allocator, &.{ canonical_path, "state_5.sqlite-wal" });
    defer std.testing.allocator.free(expected_wal_target);
    try std.testing.expectEqualStrings(expected_wal_target, wal_target);

    const logs_link = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "logs_2.sqlite" });
    defer std.testing.allocator.free(logs_link);
    var logs_link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const logs_target = try std.fs.readLinkAbsolute(logs_link, &logs_link_buf);
    const expected_logs_target = try std.fs.path.join(std.testing.allocator, &.{ canonical_path, "logs_2.sqlite" });
    defer std.testing.allocator.free(expected_logs_target);
    try std.testing.expectEqualStrings(expected_logs_target, logs_target);

    const logs_wal_link = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "logs_2.sqlite-wal" });
    defer std.testing.allocator.free(logs_wal_link);
    var logs_wal_link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const logs_wal_target = try std.fs.readLinkAbsolute(logs_wal_link, &logs_wal_link_buf);
    const expected_logs_wal_target = try std.fs.path.join(std.testing.allocator, &.{ canonical_path, "logs_2.sqlite-wal" });
    defer std.testing.allocator.free(expected_logs_wal_target);
    try std.testing.expectEqualStrings(expected_logs_wal_target, logs_wal_target);

    const bridged_session = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "sessions", "2026", "05", "05", "session.jsonl" });
    defer std.testing.allocator.free(bridged_session);
    const session_bytes = try std.fs.cwd().readFileAlloc(std.testing.allocator, bridged_session, 1024);
    defer std.testing.allocator.free(session_bytes);
    try std.testing.expectEqualStrings("{\"fixture\":true}\n", session_bytes);

    const overlay_marker = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "sessions", "managed-write.jsonl" });
    defer std.testing.allocator.free(overlay_marker);
    {
        const marker = try std.fs.cwd().createFile(overlay_marker, .{ .mode = 0o600 });
        defer marker.close();
        try marker.writeAll("via overlay\n");
    }
    const canonical_marker = try std.fs.path.join(std.testing.allocator, &.{ canonical_path, "sessions", "managed-write.jsonl" });
    defer std.testing.allocator.free(canonical_marker);
    const marker_bytes = try std.fs.cwd().readFileAlloc(std.testing.allocator, canonical_marker, 1024);
    defer std.testing.allocator.free(marker_bytes);
    try std.testing.expectEqualStrings("via overlay\n", marker_bytes);

    try std.fs.cwd().deleteTree(codex_home.path);
    const marker_after_overlay_delete = try std.fs.cwd().readFileAlloc(std.testing.allocator, canonical_marker, 1024);
    defer std.testing.allocator.free(marker_after_overlay_delete);
    try std.testing.expectEqualStrings("via overlay\n", marker_after_overlay_delete);
}

test "resume authority accepts bridged state db as chooser authority" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    try tmp.dir.makePath("canonical");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"fixture\"}}\n");
    }
    {
        const state = try tmp.dir.createFile("canonical/state_5.sqlite", .{ .mode = 0o600 });
        defer state.close();
        try state.writeAll("managed-good-session");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "canonical" });
    defer std.testing.allocator.free(canonical_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, canonical_path, canonical_path);
    defer codex_home.deinit(std.testing.allocator);

    const check = try checkResumeAuthority(std.testing.allocator, &codex_home, .{ .mode = .chooser });
    try std.testing.expect(check.ok);
    try std.testing.expect(check.state_db_bridged);
    try std.testing.expect(!check.logs_db_bridged);
    try std.testing.expectEqualStrings("state_db_available", check.diagnostic);
}

test "resume authority accepts bridged logs db as chooser authority" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    try tmp.dir.makePath("canonical");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"fixture\"}}\n");
    }
    {
        const logs = try tmp.dir.createFile("canonical/logs_2.sqlite", .{ .mode = 0o600 });
        defer logs.close();
        try logs.writeAll("managed-good-session");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "canonical" });
    defer std.testing.allocator.free(canonical_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, canonical_path, canonical_path);
    defer codex_home.deinit(std.testing.allocator);

    const check = try checkResumeAuthority(std.testing.allocator, &codex_home, .{ .mode = .chooser });
    try std.testing.expect(check.ok);
    try std.testing.expect(!check.state_db_bridged);
    try std.testing.expect(check.logs_db_bridged);
    try std.testing.expectEqual(CodexSqliteAuthorityMode.canonical_env, check.sqlite_authority);
    try std.testing.expectEqualStrings("logs_db_available", check.diagnostic);
}

test "resume authority reports legacy provider namespace residue without failing chooser" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    try tmp.dir.makePath("canonical");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"fixture\"}}\n");
    }
    {
        const state = try tmp.dir.createFile("canonical/state_5.sqlite", .{ .mode = 0o600 });
        defer state.close();
        try state.writeAll("threads model_provider openai");
    }
    {
        const logs = try tmp.dir.createFile("canonical/logs_2.sqlite", .{ .mode = 0o600 });
        defer logs.close();
        try logs.writeAll("threads model_provider oauth_mux_openai");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "canonical" });
    defer std.testing.allocator.free(canonical_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, canonical_path, canonical_path);
    defer codex_home.deinit(std.testing.allocator);

    const check = try checkResumeAuthority(std.testing.allocator, &codex_home, .{ .mode = .chooser });
    try std.testing.expect(check.ok);
    try std.testing.expect(check.legacy_provider_namespace_detected);
    try std.testing.expect(!check.legacy_provider_namespace_state_db_detected);
    try std.testing.expect(check.legacy_provider_namespace_logs_db_detected);
    try std.testing.expect(!check.legacy_provider_namespace_scan_truncated);
    try std.testing.expectEqual(@as(usize, 0), check.legacy_provider_namespace_scan_errors);

    var status = std.ArrayListUnmanaged(u8){};
    defer status.deinit(std.testing.allocator);
    try writeResumeAuthorityCheckStatus(status.writer(std.testing.allocator), check);
    try std.testing.expect(std.mem.indexOf(u8, status.items, "\"legacy_provider_namespace_detected\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, status.items, "\"legacy_provider_namespace_logs_db_detected\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, status.items, "oauth_mux_openai") == null);
    try std.testing.expect(std.mem.indexOf(u8, status.items, canonical_path) == null);
}

test "explicit resume preflight prefers state db and targeted rollout stat" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("canonical/sessions/2026/05/06");
    {
        const state = try tmp.dir.createFile("canonical/state_5.sqlite", .{ .mode = 0o600 });
        defer state.close();
        try state.writeAll("managed-good-session");
    }
    {
        const rollout = try tmp.dir.createFile("canonical/sessions/2026/05/06/rollout-managed-good-session.jsonl", .{ .mode = 0o600 });
        defer rollout.close();
        try rollout.writeAll("{\"fixture\":true}\n");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "canonical" });
    defer std.testing.allocator.free(canonical_path);

    var preflight = try lookupExplicitResumePreflight(std.testing.allocator, canonical_path, "managed-good-session");
    defer preflight.deinit();
    try std.testing.expectEqual(ResumeLookupSource.state_db, preflight.lookup_source);
    try std.testing.expectEqual(true, preflight.explicit_target_found_before.?);
    try std.testing.expect(preflight.target_snapshot != null);
    try std.testing.expectEqual(@as(usize, 1), preflight.rolloutsBefore());
}

test "explicit resume preflight can use state db without scanning rollout files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("canonical");
    {
        const state = try tmp.dir.createFile("canonical/state_5.sqlite", .{ .mode = 0o600 });
        defer state.close();
        try state.writeAll("state-only-session");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "canonical" });
    defer std.testing.allocator.free(canonical_path);

    var preflight = try lookupExplicitResumePreflight(std.testing.allocator, canonical_path, "state-only-session");
    defer preflight.deinit();
    try std.testing.expectEqual(ResumeLookupSource.state_db, preflight.lookup_source);
    try std.testing.expectEqual(true, preflight.explicit_target_found_before.?);
    try std.testing.expect(preflight.target_snapshot == null);
    try std.testing.expectEqual(@as(usize, 0), preflight.rolloutsBefore());
}

test "explicit resume preflight can use logs db without scanning rollout files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("canonical");
    {
        const logs = try tmp.dir.createFile("canonical/logs_2.sqlite", .{ .mode = 0o600 });
        defer logs.close();
        try logs.writeAll("logs-only-session");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "canonical" });
    defer std.testing.allocator.free(canonical_path);

    var preflight = try lookupExplicitResumePreflight(std.testing.allocator, canonical_path, "logs-only-session");
    defer preflight.deinit();
    try std.testing.expectEqual(ResumeLookupSource.logs_db, preflight.lookup_source);
    try std.testing.expectEqual(true, preflight.explicit_target_found_before.?);
    try std.testing.expect(preflight.target_snapshot == null);
    try std.testing.expectEqual(@as(usize, 0), preflight.rolloutsBefore());
}
