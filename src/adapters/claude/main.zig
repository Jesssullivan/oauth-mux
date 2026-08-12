//! Internal managed-child launcher for the unshipped Claude broker.
//!
//! This module owns process lifetime only. It deliberately has no CLI entry,
//! credential backend, provider routing, account election, or upstream client.

const std = @import("std");
const builtin = @import("builtin");
const config_mod = @import("../../config.zig");
const paths = @import("../../paths.zig");
const lease_runtime_mod = @import("../../broker/lease_runtime.zig");
const child_authority = @import("child_authority.zig");
const capability_mod = @import("session_capability.zig");
const fake_upstream_mod = @import("fake_upstream.zig");
const wire_proxy = @import("wire_proxy.zig");

const FakeUpstream = fake_upstream_mod.FakeUpstream;
const SessionCapability = capability_mod.SessionCapability;
const LeaseRuntime = lease_runtime_mod.LeaseRuntime;
const neutral_dir_prefix = "claude-neutral-";
const neutral_dir_entropy_len = 16;
const neutral_dir_token_len = std.base64.url_safe_no_pad.Encoder.calcSize(neutral_dir_entropy_len);
const neutral_dir_attempts = 16;

pub const RunOptions = struct {
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    cwd: ?[]const u8 = null,
    inherited_env: *const std.process.EnvMap,
    active_config: *const config_mod.Config,
    event_writer: std.io.AnyWriter = std.io.null_writer.any(),
};

pub const RunError = error{
    EmptyArgv,
    EmptyExecutable,
    PreflightFailed,
    ChildSpawnFailed,
    ChildWaitFailed,
    ChildCleanupFailed,
    LeaseTeardownFailed,
    NeutralConfigCleanupFailed,
};

const ChildSpec = struct {
    argv: []const []const u8,
    cwd: ?[]const u8,
    env_map: *const std.process.EnvMap,
    stdin_behavior: std.process.Child.StdIo = .Inherit,
    stdout_behavior: std.process.Child.StdIo = .Inherit,
    stderr_behavior: std.process.Child.StdIo = .Inherit,
};

const PosixIdentity = struct {
    extern "c" fn geteuid() std.c.uid_t;
};

fn allocateNeutralDirName(allocator: std.mem.Allocator) ![]u8 {
    var entropy: [neutral_dir_entropy_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &entropy);
    std.crypto.random.bytes(&entropy);

    var encoded: [neutral_dir_token_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &encoded);
    const token = std.base64.url_safe_no_pad.Encoder.encode(&encoded, &entropy);
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ neutral_dir_prefix, token });
}

fn effectiveUid() std.posix.uid_t {
    if (comptime builtin.os.tag == .linux and !builtin.link_libc) {
        return std.os.linux.geteuid();
    }
    return @intCast(PosixIdentity.geteuid());
}

fn validateRuntimeParent(runtime: *const std.fs.Dir) !void {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.ManagedRuntimeUnsupported;
    }
    const stat = try std.posix.fstat(runtime.fd);
    if (stat.uid != effectiveUid()) return error.RuntimeParentOwnerMismatch;
    if (stat.mode & 0o022 != 0) return error.RuntimeParentWritableByOthers;
}

fn validateNearestExistingRuntimeAncestor(
    allocator: std.mem.Allocator,
    runtime_dir: []const u8,
) !void {
    var candidate = try allocator.dupe(u8, runtime_dir);
    defer allocator.free(candidate);

    while (true) {
        if (std.fs.realpathAlloc(allocator, candidate)) |resolved| {
            defer allocator.free(resolved);
            var dir = try std.fs.openDirAbsolute(resolved, .{ .no_follow = true });
            defer dir.close();
            return validateRuntimeParent(&dir);
        } else |err| switch (err) {
            error.FileNotFound => {},
            error.OutOfMemory => return error.OutOfMemory,
            else => return err,
        }

        const parent = std.fs.path.dirname(candidate) orelse
            return error.RuntimeParentUncheckable;
        if (parent.len == candidate.len) return error.RuntimeParentUncheckable;
        const next = try allocator.dupe(u8, parent);
        allocator.free(candidate);
        candidate = next;
    }
}

fn hasPathSeparator(value: []const u8) bool {
    return std.mem.indexOfScalar(u8, value, '/') != null or
        std.mem.indexOfScalar(u8, value, '\\') != null;
}

fn isRegularExecutable(path: []const u8) bool {
    const stat = std.fs.cwd().statFile(path) catch return false;
    if (stat.kind != .file) return false;
    if (comptime builtin.os.tag == .windows) return true;
    std.posix.access(path, std.posix.X_OK) catch return false;
    return true;
}

fn resolveExecutablePathAlloc(
    allocator: std.mem.Allocator,
    requested: []const u8,
    inherited: *const std.process.EnvMap,
) ![]u8 {
    if (hasPathSeparator(requested)) {
        if (!isRegularExecutable(requested)) return error.ExecutableNotFound;
        return std.fs.path.resolve(allocator, &.{requested});
    }

    const search_path = inherited.get("PATH") orelse return error.ExecutableNotFound;
    var dirs = std.mem.splitScalar(u8, search_path, std.fs.path.delimiter);
    while (dirs.next()) |raw_dir| {
        const dir = if (raw_dir.len == 0) "." else raw_dir;
        const candidate = try std.fs.path.join(allocator, &.{ dir, requested });
        defer allocator.free(candidate);
        if (isRegularExecutable(candidate)) return std.fs.path.resolve(allocator, &.{candidate});

        if (comptime builtin.os.tag == .windows) {
            if (!std.ascii.endsWithIgnoreCase(requested, ".exe")) {
                const exe_candidate = try std.fmt.allocPrint(allocator, "{s}.exe", .{candidate});
                defer allocator.free(exe_candidate);
                if (isRegularExecutable(exe_candidate)) {
                    return std.fs.path.resolve(allocator, &.{exe_candidate});
                }
            }
        }
    }
    return error.ExecutableNotFound;
}

/// Owns one exclusive, private config directory beneath the resolved runtime
/// directory. The open parent handle keeps cleanup anchored to that directory.
const ManagedConfigDir = struct {
    allocator: std.mem.Allocator,
    runtime: std.fs.Dir,
    name: []u8,
    path: []u8,
    removed: bool = false,

    fn createUnder(
        allocator: std.mem.Allocator,
        runtime_dir: []const u8,
        home: []const u8,
        active_config: config_mod.Config,
    ) !ManagedConfigDir {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
            return error.ManagedRuntimeUnsupported;
        }
        if (!std.fs.path.isAbsolute(runtime_dir)) return error.RuntimeDirMustBeAbsolute;

        var first_name: ?[]u8 = try allocateNeutralDirName(allocator);
        defer if (first_name) |name| allocator.free(name);
        const prospective_path = try std.fs.path.join(allocator, &.{ runtime_dir, first_name.? });
        defer allocator.free(prospective_path);
        const prospective_validated = try child_authority.validateManagedConfigDir(
            allocator,
            home,
            active_config,
            prospective_path,
        );
        allocator.free(prospective_validated);

        try validateNearestExistingRuntimeAncestor(allocator, runtime_dir);
        try std.fs.cwd().makePath(runtime_dir);

        const resolved_runtime = try std.fs.realpathAlloc(allocator, runtime_dir);
        defer allocator.free(resolved_runtime);
        if (!std.fs.path.isAbsolute(resolved_runtime)) return error.RuntimeDirMustBeAbsolute;

        var runtime = try std.fs.openDirAbsolute(resolved_runtime, .{
            .iterate = true,
            .no_follow = true,
        });
        errdefer runtime.close();
        try validateRuntimeParent(&runtime);

        for (0..neutral_dir_attempts) |attempt| {
            const name = if (attempt == 0)
                first_name.?
            else
                try allocateNeutralDirName(allocator);
            if (attempt == 0) first_name = null;
            var name_owned = true;
            defer if (name_owned) allocator.free(name);

            const candidate_path = try std.fs.path.join(allocator, &.{ resolved_runtime, name });
            defer allocator.free(candidate_path);
            const candidate_validated = try child_authority.validateManagedConfigDir(
                allocator,
                home,
                active_config,
                candidate_path,
            );
            allocator.free(candidate_validated);

            std.posix.mkdirat(runtime.fd, name, 0o700) catch |err| {
                if (err == error.PathAlreadyExists) continue;
                return err;
            };
            var keep = false;
            defer if (!keep) {
                runtime.deleteTree(name) catch {};
            };

            if (comptime builtin.os.tag != .windows and builtin.os.tag != .wasi) {
                var created = try runtime.openDir(name, .{
                    .iterate = true,
                    .no_follow = true,
                });
                defer created.close();
                try created.chmod(0o700);
                const stat = try runtime.statFile(name);
                if (stat.mode & 0o077 != 0) return error.ManagedConfigDirNotPrivate;
            }

            const absolute_path = try allocator.dupe(u8, candidate_path);
            keep = true;
            name_owned = false;
            return .{
                .allocator = allocator,
                .runtime = runtime,
                .name = name,
                .path = absolute_path,
            };
        }
        return error.UniqueManagedConfigDirUnavailable;
    }

    fn remove(self: *ManagedConfigDir) !void {
        if (self.removed) return;
        try self.runtime.deleteTree(self.name);
        self.removed = true;
    }

    fn deinit(self: *ManagedConfigDir) void {
        if (!self.removed) self.runtime.deleteTree(self.name) catch {};
        self.runtime.close();
        self.allocator.free(self.path);
        self.allocator.free(self.name);
        self.* = undefined;
    }
};

/// Real internal entrypoint. Nothing in the CLI imports or calls it yet.
pub fn run(options: RunOptions) RunError!std.process.Child.Term {
    var seams = SystemSeams{};
    return runWithSeams(options, &seams);
}

fn runWithSeams(options: RunOptions, seams: anytype) RunError!std.process.Child.Term {
    if (options.argv.len == 0) return error.EmptyArgv;
    if (options.argv[0].len == 0) return error.EmptyExecutable;
    const resolved_executable = seams.resolveExecutableAlloc(
        options.allocator,
        options.argv[0],
        options.inherited_env,
    ) catch
        return error.PreflightFailed;
    defer options.allocator.free(resolved_executable);

    const resolved_argv = options.allocator.alloc([]const u8, options.argv.len) catch
        return error.PreflightFailed;
    defer options.allocator.free(resolved_argv);
    @memcpy(resolved_argv, options.argv);
    resolved_argv[0] = resolved_executable;
    var resolved_options = options;
    resolved_options.argv = resolved_argv;

    const home = options.inherited_env.get("HOME") orelse return error.PreflightFailed;
    if (home.len == 0 or !std.fs.path.isAbsolute(home)) return error.PreflightFailed;

    const runtime_dir = seams.runtimeDirAlloc(options.allocator) catch
        return error.PreflightFailed;
    defer options.allocator.free(runtime_dir);

    var managed_config = ManagedConfigDir.createUnder(
        options.allocator,
        runtime_dir,
        home,
        options.active_config.*,
    ) catch
        return error.PreflightFailed;
    defer managed_config.deinit();

    const result = runPrepared(resolved_options, managed_config.path, runtime_dir, seams);
    managed_config.remove() catch return error.NeutralConfigCleanupFailed;
    return result;
}

fn runPrepared(
    options: RunOptions,
    managed_config_dir: []const u8,
    runtime_dir: []const u8,
    seams: anytype,
) RunError!std.process.Child.Term {
    const capability = seams.generateCapability(options.allocator) catch
        return error.PreflightFailed;
    defer capability.deinit();

    var carrier = [_]u8{0} ** capability_mod.carrier_len;
    defer {
        std.crypto.secureZero(u8, &carrier);
        seams.carrierCleared(&carrier);
    }
    defer capability.revoke();
    capability.copyCarrier(&carrier) catch return error.PreflightFailed;

    const lease_runtime = seams.startLeaseRuntime(options.allocator, runtime_dir) catch
        return error.PreflightFailed;

    const listener = seams.startListener(
        options.allocator,
        capability,
        options.event_writer,
        lease_runtime,
    ) catch {
        var teardown_budget = seams.beginTeardownBudget(lease_runtime) catch
            return error.LeaseTeardownFailed;
        seams.stopLeaseRuntime(lease_runtime, &teardown_budget) catch
            return error.LeaseTeardownFailed;
        return error.PreflightFailed;
    };
    // Unexpected listener-death monitoring is deferred and is not claimed by
    // this internal slice.

    const loopback_url = std.fmt.allocPrint(
        options.allocator,
        "http://127.0.0.1:{d}",
        .{seams.listenerPort(listener)},
    ) catch {
        if (!stopManagedBoundary(capability, listener, lease_runtime, seams)) {
            return error.LeaseTeardownFailed;
        }
        return error.PreflightFailed;
    };
    defer options.allocator.free(loopback_url);

    var child_env = child_authority.buildChildEnv(
        options.allocator,
        options.inherited_env,
        options.active_config.*,
        managed_config_dir,
        loopback_url,
        &carrier,
    ) catch {
        if (!stopManagedBoundary(capability, listener, lease_runtime, seams)) {
            return error.LeaseTeardownFailed;
        }
        return error.PreflightFailed;
    };
    var child_env_live = true;
    defer if (child_env_live) {
        child_env.deinit();
        seams.childEnvCleared();
    };

    const outcome = spawnAndWait(options, &child_env.map, seams);

    const teardown_clean = stopManagedBoundary(capability, listener, lease_runtime, seams);
    child_env.deinit();
    seams.childEnvCleared();
    child_env_live = false;
    if (!teardown_clean) return error.LeaseTeardownFailed;
    return outcome;
}

fn stopManagedBoundary(
    capability: anytype,
    listener: anytype,
    lease_runtime: anytype,
    seams: anytype,
) bool {
    capability.revoke();
    var budget = seams.beginTeardownBudget(lease_runtime) catch {
        logManagedTeardownFailure("budget", error.LeaseTeardownBudgetUnavailable);
        return false;
    };
    var teardown_failed = false;
    seams.stopListener(listener, &budget) catch |err| {
        logManagedTeardownFailure("listener", err);
        teardown_failed = true;
    };
    seams.stopLeaseRuntime(lease_runtime, &budget) catch |err| {
        logManagedTeardownFailure("lease_runtime", err);
        teardown_failed = true;
    };
    return !teardown_failed;
}

fn logManagedTeardownFailure(component: []const u8, err: anyerror) void {
    if (builtin.is_test) {
        std.log.warn("managed Claude {s} teardown failed: {s}", .{ component, @errorName(err) });
    } else {
        std.log.err("managed Claude {s} teardown failed: {s}", .{ component, @errorName(err) });
    }
}

fn spawnAndWait(
    options: RunOptions,
    env_map: *const std.process.EnvMap,
    seams: anytype,
) RunError!std.process.Child.Term {
    var child = seams.spawn(options.allocator, .{
        .argv = options.argv,
        .cwd = options.cwd,
        .env_map = env_map,
    }) catch return error.ChildSpawnFailed;

    return seams.wait(&child) catch {
        const deferred_spawn_failure = seams.deferredSpawnFailure(&child);
        seams.abortAndReap(&child) catch return error.ChildCleanupFailed;
        return if (deferred_spawn_failure) error.ChildSpawnFailed else error.ChildWaitFailed;
    };
}

const SystemSeams = struct {
    fn resolveExecutableAlloc(
        _: *SystemSeams,
        allocator: std.mem.Allocator,
        requested: []const u8,
        inherited: *const std.process.EnvMap,
    ) ![]u8 {
        return resolveExecutablePathAlloc(allocator, requested, inherited);
    }

    fn runtimeDirAlloc(_: *SystemSeams, allocator: std.mem.Allocator) ![]const u8 {
        return paths.runtimeDir(allocator);
    }

    fn generateCapability(
        _: *SystemSeams,
        allocator: std.mem.Allocator,
    ) !*SessionCapability {
        return SessionCapability.generate(allocator);
    }

    fn startLeaseRuntime(
        _: *SystemSeams,
        allocator: std.mem.Allocator,
        runtime_dir: []const u8,
    ) !?*LeaseRuntime {
        const broker_root = try std.fs.path.join(allocator, &.{ runtime_dir, "broker" });
        defer allocator.free(broker_root);
        const runtime = try allocator.create(LeaseRuntime);
        runtime.* = LeaseRuntime.init(allocator, broker_root, .{}) catch |err| {
            allocator.destroy(runtime);
            if (lease_runtime_mod.isAdvisoryUnavailableError(err)) return null;
            return err;
        };
        return runtime;
    }

    fn beginTeardownBudget(
        _: *SystemSeams,
        maybe_runtime: ?*LeaseRuntime,
    ) !lease_runtime_mod.WorkBudget {
        if (maybe_runtime) |runtime| return runtime.beginTeardownBudget();
        return lease_runtime_mod.startTeardownBudget(null);
    }

    fn stopLeaseRuntime(
        _: *SystemSeams,
        maybe_runtime: ?*LeaseRuntime,
        budget: *lease_runtime_mod.WorkBudget,
    ) !void {
        const runtime = maybe_runtime orelse return;
        const allocator = runtime.allocator;
        const result = runtime.deinitCheckedWithBudget(budget);
        allocator.destroy(runtime);
        try result;
    }

    fn startListener(
        _: *SystemSeams,
        allocator: std.mem.Allocator,
        capability: *SessionCapability,
        event_writer: std.io.AnyWriter,
        lease_runtime: ?*LeaseRuntime,
    ) !*wire_proxy.Listener {
        return wire_proxy.Listener.startManaged(allocator, capability, event_writer, lease_runtime);
    }

    fn listenerPort(_: *SystemSeams, listener: *wire_proxy.Listener) u16 {
        return listener.port();
    }

    fn stopListener(
        _: *SystemSeams,
        listener: *wire_proxy.Listener,
        budget: *lease_runtime_mod.WorkBudget,
    ) !void {
        _ = try listener.deinitCheckedWithBudget(budget);
    }

    fn spawn(
        _: *SystemSeams,
        allocator: std.mem.Allocator,
        spec: ChildSpec,
    ) !std.process.Child {
        var child = std.process.Child.init(spec.argv, allocator);
        child.cwd = spec.cwd;
        child.env_map = spec.env_map;
        child.stdin_behavior = spec.stdin_behavior;
        child.stdout_behavior = spec.stdout_behavior;
        child.stderr_behavior = spec.stderr_behavior;
        try child.spawn();
        return child;
    }

    fn wait(_: *SystemSeams, child: *std.process.Child) !std.process.Child.Term {
        return child.wait();
    }

    fn deferredSpawnFailure(_: *SystemSeams, child: *const std.process.Child) bool {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return false;
        const term_result = child.term orelse return false;
        _ = term_result catch return true;
        return false;
    }

    fn abortAndReap(_: *SystemSeams, child: *std.process.Child) !void {
        if (comptime builtin.os.tag != .windows and builtin.os.tag != .wasi) {
            if (child.term) |term_result| {
                if (term_result) |_| {
                    return;
                } else |_| {
                    const child_id = child.id;
                    const waited = std.posix.waitpid(child_id, 0);
                    if (waited.pid != child_id) return error.ChildReapUnverified;
                    child.id = undefined;
                    return;
                }
            }
        }
        _ = child.kill() catch |err| switch (err) {
            error.AlreadyTerminated => {
                _ = try child.wait();
                return;
            },
            else => return err,
        };
    }

    fn carrierCleared(_: *SystemSeams, _: []const u8) void {}
    fn childEnvCleared(_: *SystemSeams) void {}
};

const test_carrier = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

const FakeState = struct {
    allocator: std.mem.Allocator,
    runtime_dir: []const u8,
    expected_argv: []const []const u8 = &.{},
    expected_cwd: ?[]const u8 = null,
    expected_home: ?[]const u8 = null,
    term: std.process.Child.Term = .{ .Exited = 0 },
    fail_executable_preflight: bool = false,
    fail_runtime_dir: bool = false,
    fail_capability_generation: bool = false,
    fail_capability_copy: bool = false,
    fail_listener: bool = false,
    fail_listener_stop: bool = false,
    fail_runtime_stop: bool = false,
    fail_spawn: bool = false,
    fail_deferred_spawn: bool = false,
    fail_wait: bool = false,
    fail_cleanup: bool = false,
    listener_teardown_cost_ns: i128 = 0,
    runtime_teardown_cost_ns: i128 = 0,
    teardown_clock_ns: i128 = 0,
    teardown_budget_exhausted: bool = false,

    executable_resolution_count: usize = 0,
    runtime_dir_count: usize = 0,
    capability_generated: bool = false,
    capability_revoked: bool = false,
    capability_zeroed: bool = false,
    capability_deinitialized: bool = false,
    carrier_cleared: bool = false,
    child_env_cleared: bool = false,
    listener_started: bool = false,
    listener_stopped: bool = false,
    listener_stopped_after_revoke: bool = false,
    lease_runtime_started: bool = false,
    lease_runtime_stopped: bool = false,
    lease_runtime_stopped_after_listener: bool = false,
    spawn_count: usize = 0,
    wait_count: usize = 0,
    abort_count: usize = 0,
    reaped: bool = false,
    argv_preserved: bool = false,
    cwd_preserved: bool = false,
    stdio_inherited: bool = false,
    env_preserved_and_scrubbed: bool = false,
    managed_dir_private: bool = false,
    managed_dir_under_runtime: bool = false,
    managed_config_dir: ?[]u8 = null,
    provider_calls: usize = 0,
    credential_calls: usize = 0,
    upstream_calls: usize = 0,

    fn deinit(self: *FakeState) void {
        if (self.managed_config_dir) |path| self.allocator.free(path);
    }

    fn observeSpawn(self: *FakeState, spec: ChildSpec) !void {
        self.argv_preserved = stringSlicesEqual(spec.argv, self.expected_argv);
        self.cwd_preserved = optionalStringEqual(spec.cwd, self.expected_cwd);
        self.stdio_inherited = spec.stdin_behavior == .Inherit and
            spec.stdout_behavior == .Inherit and
            spec.stderr_behavior == .Inherit;

        const env_map = spec.env_map;
        const config_dir = env_map.get("CLAUDE_CONFIG_DIR") orelse return;
        self.managed_config_dir = try self.allocator.dupe(u8, config_dir);
        self.managed_dir_under_runtime = std.fs.path.isAbsolute(config_dir) and
            std.mem.startsWith(u8, config_dir, self.runtime_dir) and
            config_dir.len > self.runtime_dir.len and
            std.fs.path.isSep(config_dir[self.runtime_dir.len]);
        const stat = std.fs.cwd().statFile(config_dir) catch return;
        self.managed_dir_private = if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi)
            true
        else
            stat.mode & 0o077 == 0;

        const home_preserved = if (self.expected_home) |home|
            optionalValueEqual(env_map.get("HOME"), home)
        else
            env_map.get("HOME") != null;
        self.env_preserved_and_scrubbed =
            home_preserved and
            optionalValueEqual(env_map.get("UNRELATED_SENTINEL"), "preserved") and
            optionalValueEqual(env_map.get("ANTHROPIC_BASE_URL"), "http://127.0.0.1:43123") and
            optionalValueEqual(env_map.get("ANTHROPIC_AUTH_TOKEN"), test_carrier) and
            optionalValueEqual(env_map.get("NO_PROXY"), "127.0.0.1,localhost") and
            optionalValueEqual(env_map.get("no_proxy"), "127.0.0.1,localhost") and
            env_map.get("ACTIVE_ACCOUNT_SECRET") == null and
            env_map.get("ANTHROPIC_API_KEY") == null and
            env_map.get("CLAUDE_CODE_USE_BEDROCK") == null and
            env_map.get("HTTP_PROXY") == null and
            env_map.get("HTTPS_PROXY") == null and
            env_map.get("ALL_PROXY") == null;
    }
};

const FakeCapability = struct {
    allocator: std.mem.Allocator,
    state: *FakeState,
    encoded: [capability_mod.carrier_len]u8 = test_carrier.*,
    revoked: bool = false,

    fn copyCarrier(self: *FakeCapability, destination: *[capability_mod.carrier_len]u8) !void {
        if (self.revoked) return error.Revoked;
        if (self.state.fail_capability_copy) return error.SyntheticCapabilityCopyFailure;
        @memcpy(destination, &self.encoded);
    }

    fn revoke(self: *FakeCapability) void {
        if (!self.revoked) std.crypto.secureZero(u8, &self.encoded);
        self.revoked = true;
        self.state.capability_revoked = true;
        self.state.capability_zeroed = allZero(&self.encoded);
    }

    fn deinit(self: *FakeCapability) void {
        self.revoke();
        self.state.capability_deinitialized = true;
        const allocator = self.allocator;
        allocator.destroy(self);
    }
};

const FakeListener = struct {
    allocator: std.mem.Allocator,
    state: *FakeState,
    capability: *FakeCapability,
};

const FakeChild = struct {
    state: *FakeState,
};

const FakeLeaseRuntime = struct {
    allocator: std.mem.Allocator,
    state: *FakeState,
};

const FakeSeams = struct {
    state: *FakeState,

    fn resolveExecutableAlloc(
        self: *FakeSeams,
        allocator: std.mem.Allocator,
        requested: []const u8,
        _: *const std.process.EnvMap,
    ) ![]u8 {
        self.state.executable_resolution_count += 1;
        if (self.state.fail_executable_preflight) return error.SyntheticExecutableMissing;
        return allocator.dupe(u8, requested);
    }

    fn runtimeDirAlloc(self: *FakeSeams, allocator: std.mem.Allocator) ![]const u8 {
        self.state.runtime_dir_count += 1;
        if (self.state.fail_runtime_dir) return error.SyntheticRuntimeDirFailure;
        return allocator.dupe(u8, self.state.runtime_dir);
    }

    fn generateCapability(
        self: *FakeSeams,
        allocator: std.mem.Allocator,
    ) !*FakeCapability {
        if (self.state.fail_capability_generation) return error.SyntheticCapabilityGenerationFailure;
        const capability = try allocator.create(FakeCapability);
        capability.* = .{ .allocator = allocator, .state = self.state };
        self.state.capability_generated = true;
        return capability;
    }

    fn startLeaseRuntime(
        self: *FakeSeams,
        allocator: std.mem.Allocator,
        _: []const u8,
    ) !*FakeLeaseRuntime {
        const runtime = try allocator.create(FakeLeaseRuntime);
        runtime.* = .{ .allocator = allocator, .state = self.state };
        self.state.lease_runtime_started = true;
        return runtime;
    }

    fn teardownNow(raw: ?*anyopaque) i128 {
        const state: *FakeState = @ptrCast(@alignCast(raw.?));
        return state.teardown_clock_ns;
    }

    fn beginTeardownBudget(
        self: *FakeSeams,
        _: *FakeLeaseRuntime,
    ) !lease_runtime_mod.WorkBudget {
        self.state.teardown_clock_ns = 0;
        return lease_runtime_mod.startTeardownBudget(.{
            .ctx = @ptrCast(self.state),
            .nowFn = teardownNow,
        });
    }

    fn stopLeaseRuntime(
        _: *FakeSeams,
        runtime: *FakeLeaseRuntime,
        budget: *lease_runtime_mod.WorkBudget,
    ) !void {
        const state = runtime.state;
        state.lease_runtime_stopped = true;
        state.lease_runtime_stopped_after_listener = state.listener_stopped;
        state.teardown_clock_ns += state.runtime_teardown_cost_ns;
        const budget_result = budget.remainingNs();
        const fail = state.fail_runtime_stop;
        const allocator = runtime.allocator;
        allocator.destroy(runtime);
        if (fail) return error.SyntheticRuntimeStopFailure;
        _ = budget_result catch |err| {
            state.teardown_budget_exhausted = true;
            return err;
        };
    }

    fn startListener(
        self: *FakeSeams,
        allocator: std.mem.Allocator,
        capability: *FakeCapability,
        _: std.io.AnyWriter,
        _: *FakeLeaseRuntime,
    ) !*FakeListener {
        if (self.state.fail_listener) return error.SyntheticListenerStartFailure;
        const listener = try allocator.create(FakeListener);
        listener.* = .{
            .allocator = allocator,
            .state = self.state,
            .capability = capability,
        };
        self.state.listener_started = true;
        return listener;
    }

    fn listenerPort(_: *FakeSeams, _: *FakeListener) u16 {
        return 43123;
    }

    fn stopListener(
        _: *FakeSeams,
        listener: *FakeListener,
        budget: *lease_runtime_mod.WorkBudget,
    ) !void {
        listener.state.listener_stopped = true;
        listener.state.listener_stopped_after_revoke = listener.capability.revoked;
        listener.state.teardown_clock_ns += listener.state.listener_teardown_cost_ns;
        const budget_result = budget.remainingNs();
        const fail = listener.state.fail_listener_stop;
        const state = listener.state;
        const allocator = listener.allocator;
        allocator.destroy(listener);
        if (fail) return error.SyntheticListenerStopFailure;
        _ = budget_result catch |err| {
            state.teardown_budget_exhausted = true;
            return err;
        };
    }

    fn spawn(
        self: *FakeSeams,
        _: std.mem.Allocator,
        spec: ChildSpec,
    ) !FakeChild {
        self.state.spawn_count += 1;
        try self.state.observeSpawn(spec);
        if (self.state.fail_spawn) return error.SyntheticSpawnFailure;
        return .{ .state = self.state };
    }

    fn wait(_: *FakeSeams, child: *FakeChild) !std.process.Child.Term {
        child.state.wait_count += 1;
        if (child.state.fail_deferred_spawn) return error.SyntheticDeferredSpawnFailure;
        if (child.state.fail_wait) return error.SyntheticWaitFailure;
        child.state.reaped = true;
        return child.state.term;
    }

    fn deferredSpawnFailure(_: *FakeSeams, child: *const FakeChild) bool {
        return child.state.fail_deferred_spawn;
    }

    fn abortAndReap(_: *FakeSeams, child: *FakeChild) !void {
        child.state.abort_count += 1;
        if (child.state.fail_cleanup) return error.SyntheticCleanupFailure;
        child.state.reaped = true;
    }

    fn carrierCleared(self: *FakeSeams, carrier: []const u8) void {
        self.state.carrier_cleared = allZero(carrier);
    }

    fn childEnvCleared(self: *FakeSeams) void {
        self.state.child_env_cleared = true;
    }

    // Deliberate non-seams: a launcher regression must not touch these.
    fn readCredential(self: *FakeSeams) void {
        self.state.credential_calls += 1;
    }

    fn electProvider(self: *FakeSeams) void {
        self.state.provider_calls += 1;
    }

    fn reachUpstream(self: *FakeSeams) void {
        self.state.upstream_calls += 1;
    }
};

const Stage2CapabilityProbeState = if (builtin.is_test) struct {
    runtime_dir: []const u8,
    upstream: *FakeUpstream,
    capability: ?*SessionCapability = null,
    spawn_count: usize = 0,
    wait_count: usize = 0,
    listener_started: bool = false,
    listener_stopped: bool = false,
    listener_stopped_after_revoke: bool = false,
    carrier_cleared: bool = false,
    child_env_cleared: bool = false,
    managed_dir_under_runtime: bool = false,
    missing_rejected: bool = false,
    wrong_rejected: bool = false,
    valid_accepted: bool = false,
    lease_runtime_started: bool = false,
    lease_runtime_stopped: bool = false,
    lease_runtime_stopped_after_listener: bool = false,
} else struct {};

const Stage2CapabilityProbeChild = if (builtin.is_test) struct {
    state: *Stage2CapabilityProbeState,
} else struct {};

const Stage2CapabilityProbeLeaseRuntime = if (builtin.is_test) struct {
    allocator: std.mem.Allocator,
    state: *Stage2CapabilityProbeState,
} else struct {};

const Stage2CapabilityProbeSeams = if (builtin.is_test) struct {
    state: *Stage2CapabilityProbeState,

    fn resolveExecutableAlloc(
        _: *@This(),
        allocator: std.mem.Allocator,
        requested: []const u8,
        _: *const std.process.EnvMap,
    ) ![]u8 {
        return allocator.dupe(u8, requested);
    }

    fn runtimeDirAlloc(self: *@This(), allocator: std.mem.Allocator) ![]const u8 {
        return allocator.dupe(u8, self.state.runtime_dir);
    }

    fn generateCapability(
        self: *@This(),
        allocator: std.mem.Allocator,
    ) !*SessionCapability {
        const capability = try SessionCapability.generate(allocator);
        self.state.capability = capability;
        return capability;
    }

    fn startLeaseRuntime(
        self: *@This(),
        allocator: std.mem.Allocator,
        _: []const u8,
    ) !*Stage2CapabilityProbeLeaseRuntime {
        const runtime = try allocator.create(Stage2CapabilityProbeLeaseRuntime);
        runtime.* = .{ .allocator = allocator, .state = self.state };
        self.state.lease_runtime_started = true;
        return runtime;
    }

    fn beginTeardownBudget(
        _: *@This(),
        _: *Stage2CapabilityProbeLeaseRuntime,
    ) !lease_runtime_mod.WorkBudget {
        return lease_runtime_mod.startTeardownBudget(null);
    }

    fn stopLeaseRuntime(
        _: *@This(),
        runtime: *Stage2CapabilityProbeLeaseRuntime,
        _: *lease_runtime_mod.WorkBudget,
    ) !void {
        runtime.state.lease_runtime_stopped = true;
        runtime.state.lease_runtime_stopped_after_listener = runtime.state.listener_stopped;
        const allocator = runtime.allocator;
        allocator.destroy(runtime);
    }

    fn startListener(
        self: *@This(),
        allocator: std.mem.Allocator,
        capability: *SessionCapability,
        event_writer: std.io.AnyWriter,
        _: *Stage2CapabilityProbeLeaseRuntime,
    ) !*wire_proxy.Listener {
        const listener = try wire_proxy.testing.startWithFake(
            allocator,
            capability,
            self.state.upstream,
            event_writer,
        );
        self.state.listener_started = true;
        return listener;
    }

    fn listenerPort(_: *@This(), listener: *wire_proxy.Listener) u16 {
        return listener.port();
    }

    fn stopListener(
        self: *@This(),
        listener: *wire_proxy.Listener,
        budget: *lease_runtime_mod.WorkBudget,
    ) !void {
        const capability = self.state.capability orelse unreachable;
        self.state.listener_stopped_after_revoke = capability.isRevoked();
        _ = try listener.deinitCheckedWithBudget(budget);
        self.state.capability = null;
        self.state.listener_stopped = true;
    }

    fn spawn(
        self: *@This(),
        allocator: std.mem.Allocator,
        spec: ChildSpec,
    ) !Stage2CapabilityProbeChild {
        self.state.spawn_count += 1;
        const base_url = spec.env_map.get("ANTHROPIC_BASE_URL") orelse
            return error.MissingManagedBaseUrl;
        const carrier = spec.env_map.get("ANTHROPIC_AUTH_TOKEN") orelse
            return error.MissingManagedCarrier;
        if (carrier.len != capability_mod.carrier_len) return error.InvalidManagedCarrier;

        const config_dir = spec.env_map.get("CLAUDE_CONFIG_DIR") orelse
            return error.MissingManagedConfigDir;
        self.state.managed_dir_under_runtime =
            std.fs.path.isAbsolute(config_dir) and
            std.mem.startsWith(u8, config_dir, self.state.runtime_dir) and
            config_dir.len > self.state.runtime_dir.len and
            std.fs.path.isSep(config_dir[self.state.runtime_dir.len]);

        const missing = try requestManagedBoundaryAlloc(allocator, base_url, null);
        defer {
            std.crypto.secureZero(u8, missing);
            allocator.free(missing);
        }
        self.state.missing_rejected = std.mem.startsWith(
            u8,
            missing,
            "HTTP/1.1 401 Unauthorized\r\n",
        );

        var wrong: [capability_mod.carrier_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &wrong);
        @memcpy(&wrong, carrier);
        wrong[0] = if (wrong[0] == 'A') 'B' else 'A';
        const wrong_response = try requestManagedBoundaryAlloc(allocator, base_url, &wrong);
        defer {
            std.crypto.secureZero(u8, wrong_response);
            allocator.free(wrong_response);
        }
        self.state.wrong_rejected = std.mem.startsWith(
            u8,
            wrong_response,
            "HTTP/1.1 401 Unauthorized\r\n",
        );

        const accepted = try requestManagedBoundaryAlloc(allocator, base_url, carrier);
        defer {
            std.crypto.secureZero(u8, accepted);
            allocator.free(accepted);
        }
        self.state.valid_accepted = std.mem.startsWith(
            u8,
            accepted,
            "HTTP/1.1 204 No Content\r\n",
        );
        return .{ .state = self.state };
    }

    fn wait(_: *@This(), child: *Stage2CapabilityProbeChild) !std.process.Child.Term {
        child.state.wait_count += 1;
        return .{ .Exited = 0 };
    }

    fn deferredSpawnFailure(_: *@This(), _: *const Stage2CapabilityProbeChild) bool {
        return false;
    }

    fn abortAndReap(_: *@This(), _: *Stage2CapabilityProbeChild) !void {}

    fn carrierCleared(self: *@This(), carrier: []const u8) void {
        self.state.carrier_cleared = allZero(carrier);
    }

    fn childEnvCleared(self: *@This()) void {
        self.state.child_env_cleared = true;
    }
} else struct {};

fn requestManagedBoundaryAlloc(
    allocator: std.mem.Allocator,
    base_url: []const u8,
    carrier: ?[]const u8,
) ![]u8 {
    return requestManagedBoundaryAllocWithLimits(allocator, base_url, carrier, .{});
}

const ManagedBoundaryRequestLimits = struct {
    max_response_bytes: usize = 16 * 1024,
    timeout_ms: u32 = 5_000,
};

fn requestManagedBoundaryAllocWithLimits(
    allocator: std.mem.Allocator,
    base_url: []const u8,
    carrier: ?[]const u8,
    limits: ManagedBoundaryRequestLimits,
) ![]u8 {
    if (!builtin.is_test) @compileError("managed-boundary requests are test-only");
    if (limits.max_response_bytes == 0 or limits.timeout_ms == 0) {
        return error.InvalidManagedBoundaryRequestLimits;
    }
    const prefix = "http://127.0.0.1:";
    if (!std.mem.startsWith(u8, base_url, prefix)) return error.InvalidManagedBaseUrl;
    const port_text = base_url[prefix.len..];
    if (port_text.len == 0 or std.mem.indexOfScalar(u8, port_text, '/') != null) {
        return error.InvalidManagedBaseUrl;
    }
    const port = std.fmt.parseInt(u16, port_text, 10) catch
        return error.InvalidManagedBaseUrl;
    if (port == 0) return error.InvalidManagedBaseUrl;

    const auth_line = if (carrier) |value|
        try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}\r\n", .{value})
    else
        try allocator.dupe(u8, "");
    defer {
        std.crypto.secureZero(u8, auth_line);
        allocator.free(auth_line);
    }

    const request = try std.fmt.allocPrint(
        allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\n{s}Connection: close\r\n\r\n",
        .{ port, auth_line },
    );
    defer {
        std.crypto.secureZero(u8, request);
        allocator.free(request);
    }

    const address = try std.net.Address.parseIp("127.0.0.1", port);
    var timer = try std.time.Timer.start();
    var stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();
    try stream.writeAll(request);

    var response = std.ArrayList(u8).init(allocator);
    errdefer response.deinit();
    var buffer: [1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    while (true) {
        const elapsed_ms = timer.read() / std.time.ns_per_ms;
        if (elapsed_ms >= limits.timeout_ms) return error.ManagedBoundaryRequestTimedOut;
        const remaining_ms: i32 = @intCast(limits.timeout_ms - elapsed_ms);
        var poll_fds = [_]std.posix.pollfd{.{
            .fd = stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        if (try std.posix.poll(&poll_fds, remaining_ms) == 0) {
            return error.ManagedBoundaryRequestTimedOut;
        }
        if (poll_fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.NVAL) != 0) {
            return error.ManagedBoundaryConnectionFailed;
        }

        const remaining_bytes = limits.max_response_bytes - response.items.len;
        const read_len = @min(buffer.len, remaining_bytes +| 1);
        const count = try stream.read(buffer[0..read_len]);
        if (count == 0) break;
        if (count > remaining_bytes) return error.ManagedBoundaryResponseTooLarge;
        try response.appendSlice(buffer[0..count]);
    }
    return response.toOwnedSlice();
}

fn stringSlicesEqual(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |a_value, b_value| {
        if (!std.mem.eql(u8, a_value, b_value)) return false;
    }
    return true;
}

fn optionalStringEqual(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

fn optionalValueEqual(actual: ?[]const u8, expected: []const u8) bool {
    return if (actual) |value| std.mem.eql(u8, value, expected) else false;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

fn testInheritedEnv(allocator: std.mem.Allocator, home: ?[]const u8) !std.process.EnvMap {
    var inherited = std.process.EnvMap.init(allocator);
    errdefer inherited.deinit();
    if (home) |value| try inherited.put("HOME", value);
    try inherited.put("UNRELATED_SENTINEL", "preserved");
    try inherited.put("ACTIVE_ACCOUNT_SECRET", "must-not-survive");
    try inherited.put("ANTHROPIC_API_KEY", "must-not-survive");
    try inherited.put("ANTHROPIC_AUTH_TOKEN", "must-not-survive");
    try inherited.put("ANTHROPIC_BASE_URL", "https://must-not-survive.invalid");
    try inherited.put("CLAUDE_CONFIG_DIR", "/synthetic/enrolled");
    try inherited.put("CLAUDE_CODE_USE_BEDROCK", "1");
    try inherited.put("HTTP_PROXY", "http://must-not-survive.invalid");
    try inherited.put("HTTPS_PROXY", "http://must-not-survive.invalid");
    try inherited.put("ALL_PROXY", "socks5://must-not-survive.invalid");
    try inherited.put("NO_PROXY", "must-not-survive.invalid");
    return inherited;
}

fn expectRuntimeEmpty(path: []const u8) !void {
    var dir = try std.fs.openDirAbsolute(path, .{ .iterate = true });
    defer dir.close();
    var iterator = dir.iterate();
    try std.testing.expect(try iterator.next() == null);
}

fn expectCleanLifecycle(state: *const FakeState, expect_listener: bool) !void {
    try std.testing.expect(state.capability_generated);
    try std.testing.expect(state.capability_revoked);
    try std.testing.expect(state.capability_zeroed);
    try std.testing.expect(state.capability_deinitialized);
    try std.testing.expect(state.carrier_cleared);
    try std.testing.expectEqual(expect_listener, state.listener_started);
    try std.testing.expectEqual(expect_listener, state.listener_stopped);
    if (expect_listener) try std.testing.expect(state.listener_stopped_after_revoke);
    if (expect_listener) try std.testing.expect(state.lease_runtime_started);
    if (state.lease_runtime_started) {
        try std.testing.expect(state.lease_runtime_stopped);
        if (expect_listener) try std.testing.expect(state.lease_runtime_stopped_after_listener);
    }
    try expectRuntimeEmpty(state.runtime_dir);
}

fn expectNoPreparedResources(state: *const FakeState) !void {
    try std.testing.expectEqual(@as(usize, 0), state.spawn_count);
    try std.testing.expect(!state.capability_generated);
    try std.testing.expect(!state.listener_started);
    try std.testing.expect(!state.lease_runtime_started);
}

test "managed child preserves argv cwd stdio and scrubbed environment with one spawn" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try tmp.dir.makeDir("home");
    const home = try tmp.dir.realpathAlloc(allocator, "home");
    defer allocator.free(home);
    const runtime_dir = try std.fs.path.join(allocator, &.{ root, "runtime" });
    defer allocator.free(runtime_dir);

    var inherited = try testInheritedEnv(allocator, home);
    defer inherited.deinit();
    var parsed_config = try config_mod.loadFromBytes(allocator,
        \\{"version":1,"providers":{"claude":{"kind":"claude","accounts":{"active":{"secret":{"backend":"env","variable":"ACTIVE_ACCOUNT_SECRET"}}}}}}
    );
    defer parsed_config.deinit();
    const argv = &.{ "synthetic-claude", "--print", "hello" };
    var state = FakeState{
        .allocator = allocator,
        .runtime_dir = runtime_dir,
        .expected_argv = argv,
        .expected_cwd = "/synthetic/workspace",
        .expected_home = home,
    };
    defer state.deinit();
    var seams = FakeSeams{ .state = &state };

    const term = try runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .cwd = "/synthetic/workspace",
        .inherited_env = &inherited,
        .active_config = &parsed_config.value,
    }, &seams);

    try std.testing.expectEqualDeep(std.process.Child.Term{ .Exited = 0 }, term);
    try std.testing.expectEqual(@as(usize, 1), state.spawn_count);
    try std.testing.expectEqual(@as(usize, 1), state.wait_count);
    try std.testing.expectEqual(@as(usize, 0), state.abort_count);
    try std.testing.expect(state.reaped);
    try std.testing.expect(state.argv_preserved);
    try std.testing.expect(state.cwd_preserved);
    try std.testing.expect(state.stdio_inherited);
    try std.testing.expect(state.env_preserved_and_scrubbed);
    try std.testing.expect(state.managed_dir_private);
    try std.testing.expect(state.managed_dir_under_runtime);
    try std.testing.expect(state.child_env_cleared);
    try std.testing.expectEqual(@as(usize, 0), state.provider_calls);
    try std.testing.expectEqual(@as(usize, 0), state.credential_calls);
    try std.testing.expectEqual(@as(usize, 0), state.upstream_calls);
    try expectCleanLifecycle(&state, true);
}

fn runOrderlyListenerTeardownFailureDiagnostic() !void {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try tmp.dir.makeDir("home");
    const home = try tmp.dir.realpathAlloc(allocator, "home");
    defer allocator.free(home);
    const runtime_dir = try std.fs.path.join(allocator, &.{ root, "runtime" });
    defer allocator.free(runtime_dir);
    var inherited = try testInheritedEnv(allocator, home);
    defer inherited.deinit();
    var active_config = config_mod.Config{};
    const argv = &.{"synthetic-claude"};
    var state = FakeState{
        .allocator = allocator,
        .runtime_dir = runtime_dir,
        .expected_argv = argv,
        .expected_home = home,
        .fail_listener_stop = true,
    };
    defer state.deinit();
    var seams = FakeSeams{ .state = &state };

    try std.testing.expectError(error.LeaseTeardownFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &active_config,
    }, &seams));
    try std.testing.expectEqual(@as(usize, 1), state.spawn_count);
    try std.testing.expectEqual(@as(usize, 1), state.wait_count);
    try std.testing.expectEqual(@as(usize, 0), state.provider_calls);
    try std.testing.expectEqual(@as(usize, 0), state.credential_calls);
    try std.testing.expectEqual(@as(usize, 0), state.upstream_calls);
    try expectCleanLifecycle(&state, true);
}

test "managed child propagates a typed listener teardown failure after orderly cleanup" {
    try runOrderlyListenerTeardownFailureDiagnostic();
}

fn runListenerStartTeardownFailureDiagnostic() !void {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try tmp.dir.makeDir("home");
    const home = try tmp.dir.realpathAlloc(allocator, "home");
    defer allocator.free(home);
    const runtime_dir = try std.fs.path.join(allocator, &.{ root, "runtime" });
    defer allocator.free(runtime_dir);
    var inherited = try testInheritedEnv(allocator, home);
    defer inherited.deinit();
    var active_config = config_mod.Config{};
    const argv = &.{"synthetic-claude"};
    var state = FakeState{
        .allocator = allocator,
        .runtime_dir = runtime_dir,
        .expected_argv = argv,
        .expected_home = home,
        .fail_listener = true,
        .fail_runtime_stop = true,
    };
    defer state.deinit();
    var seams = FakeSeams{ .state = &state };

    try std.testing.expectError(error.LeaseTeardownFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &active_config,
    }, &seams));
    try std.testing.expectEqual(@as(usize, 0), state.spawn_count);
    try std.testing.expectEqual(@as(usize, 0), state.provider_calls);
    try std.testing.expectEqual(@as(usize, 0), state.credential_calls);
    try std.testing.expectEqual(@as(usize, 0), state.upstream_calls);
    try expectCleanLifecycle(&state, false);
}

test "listener-start failure cannot suppress lease runtime teardown failure" {
    try runListenerStartTeardownFailureDiagnostic();
}

fn runCumulativeTeardownBudgetDiagnostic() !void {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try tmp.dir.makeDir("home");
    const home = try tmp.dir.realpathAlloc(allocator, "home");
    defer allocator.free(home);
    const runtime_dir = try std.fs.path.join(allocator, &.{ root, "runtime" });
    defer allocator.free(runtime_dir);
    var inherited = try testInheritedEnv(allocator, home);
    defer inherited.deinit();
    var active_config = config_mod.Config{};
    const argv = &.{"synthetic-claude"};
    var state = FakeState{
        .allocator = allocator,
        .runtime_dir = runtime_dir,
        .expected_argv = argv,
        .expected_home = home,
        .listener_teardown_cost_ns = 300 * std.time.ns_per_ms,
        .runtime_teardown_cost_ns = 300 * std.time.ns_per_ms,
    };
    defer state.deinit();
    var seams = FakeSeams{ .state = &state };

    try std.testing.expectError(error.LeaseTeardownFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &active_config,
    }, &seams));
    try std.testing.expect(state.listener_stopped);
    try std.testing.expect(state.lease_runtime_stopped);
    try std.testing.expect(state.lease_runtime_stopped_after_listener);
    try std.testing.expect(state.teardown_budget_exhausted);
    try std.testing.expectEqual(@as(usize, 0), state.provider_calls);
    try std.testing.expectEqual(@as(usize, 0), state.credential_calls);
    try std.testing.expectEqual(@as(usize, 0), state.upstream_calls);
}

test "listener and lease runtime share one cumulative teardown budget" {
    try runCumulativeTeardownBudgetDiagnostic();
}

pub const testing = if (builtin.is_test) struct {
    /// Source-only launcher teardown diagnostics for the focused TIN-3320 root.
    /// Fake seams assert that no provider, credential, install, or service path
    /// is reachable.
    pub fn runFocusedTeardownDiagnostics() !void {
        try runOrderlyListenerTeardownFailureDiagnostic();
        try runListenerStartTeardownFailureDiagnostic();
        try runCumulativeTeardownBudgetDiagnostic();
    }
} else struct {};

test "stage2 synthetic managed capability round trip reconciles accepted and rejected requests" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try tmp.dir.makeDir("home");
    const home = try tmp.dir.realpathAlloc(allocator, "home");
    defer allocator.free(home);
    const runtime_dir = try std.fs.path.join(allocator, &.{ root, "runtime" });
    defer allocator.free(runtime_dir);

    var inherited = try testInheritedEnv(allocator, home);
    defer inherited.deinit();
    var parsed_config = try config_mod.loadFromBytes(allocator,
        \\{"version":1,"providers":{"claude":{"kind":"claude","accounts":{"active":{"secret":{"backend":"env","variable":"ACTIVE_ACCOUNT_SECRET"}}}}}}
    );
    defer parsed_config.deinit();

    var upstream = try FakeUpstream.start(allocator, &.{.{ .status = .no_content }});
    defer upstream.deinit();
    var event_buffer: [512]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    var state = Stage2CapabilityProbeState{
        .runtime_dir = runtime_dir,
        .upstream = &upstream,
    };
    var seams = Stage2CapabilityProbeSeams{ .state = &state };

    const term = try runWithSeams(.{
        .allocator = allocator,
        .argv = &.{"synthetic-claude"},
        .inherited_env = &inherited,
        .active_config = &parsed_config.value,
        .event_writer = event_stream.writer().any(),
    }, &seams);

    try std.testing.expectEqualDeep(std.process.Child.Term{ .Exited = 0 }, term);
    try std.testing.expectEqual(@as(usize, 1), state.spawn_count);
    try std.testing.expectEqual(@as(usize, 1), state.wait_count);
    try std.testing.expect(state.listener_started);
    try std.testing.expect(state.listener_stopped);
    try std.testing.expect(state.listener_stopped_after_revoke);
    try std.testing.expect(state.carrier_cleared);
    try std.testing.expect(state.child_env_cleared);
    try std.testing.expect(state.managed_dir_under_runtime);
    try std.testing.expect(state.missing_rejected);
    try std.testing.expect(state.wrong_rejected);
    try std.testing.expect(state.valid_accepted);
    try std.testing.expectEqualDeep(fake_upstream_mod.Snapshot{
        .attempt_count = 1,
        .call_count = 1,
    }, upstream.snapshot());
    const rejected_event = "{\"kind\":\"claude_proxy_capability_rejected\"}\n";
    try std.testing.expectEqualStrings(
        rejected_event ++ rejected_event,
        event_stream.getWritten(),
    );
    try std.testing.expect(!wire_proxy.production_forwarding_enabled);
    try expectRuntimeEmpty(runtime_dir);
}

test "managed-boundary request rejects an oversized synthetic response" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;
    var body: [1024]u8 = undefined;
    @memset(&body, 'x');
    var upstream = try FakeUpstream.start(allocator, &.{.{
        .status = .ok,
        .body = &body,
    }});
    defer upstream.deinit();

    try std.testing.expectError(
        error.ManagedBoundaryResponseTooLarge,
        requestManagedBoundaryAllocWithLimits(
            allocator,
            upstream.baseUrl(),
            null,
            .{ .max_response_bytes = 256, .timeout_ms = 1_000 },
        ),
    );
}

test "managed-boundary request times out on a stalled synthetic response" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }

    const StallingServer = struct {
        fn run(server: *std.net.Server) void {
            const connection = server.accept() catch return;
            defer connection.stream.close();
            std.Thread.sleep(200 * std.time.ns_per_ms);
        }
    };

    const allocator = std.testing.allocator;
    const loopback = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try loopback.listen(.{ .reuse_address = true });
    defer server.deinit();
    const base_url = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}",
        .{server.listen_address.getPort()},
    );
    defer allocator.free(base_url);
    const thread = try std.Thread.spawn(.{}, StallingServer.run, .{&server});
    defer thread.join();

    try std.testing.expectError(
        error.ManagedBoundaryRequestTimedOut,
        requestManagedBoundaryAllocWithLimits(
            allocator,
            base_url,
            null,
            .{ .max_response_bytes = 16 * 1024, .timeout_ms = 25 },
        ),
    );
}

test "managed config directories are unique absolute private runtime children" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const runtime_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(runtime_dir);

    var first = try ManagedConfigDir.createUnder(allocator, runtime_dir, runtime_dir, .{});
    defer first.deinit();
    var second = try ManagedConfigDir.createUnder(allocator, runtime_dir, runtime_dir, .{});
    defer second.deinit();

    try std.testing.expect(std.fs.path.isAbsolute(first.path));
    try std.testing.expect(std.fs.path.isAbsolute(second.path));
    try std.testing.expect(!std.mem.eql(u8, first.path, second.path));
    try std.testing.expect(std.mem.startsWith(u8, first.path, runtime_dir));
    try std.testing.expect(std.mem.startsWith(u8, second.path, runtime_dir));
    if (comptime builtin.os.tag != .windows and builtin.os.tag != .wasi) {
        const first_stat = try std.fs.cwd().statFile(first.path);
        const second_stat = try std.fs.cwd().statFile(second.path);
        try std.testing.expectEqual(@as(u32, 0), first_stat.mode & 0o077);
        try std.testing.expectEqual(@as(u32, 0), second_stat.mode & 0o077);
    }

    try first.remove();
    try second.remove();
}

test "executable preflight uses inherited PATH and explicit paths" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const executable = try tmp.dir.createFile("synthetic-claude", .{ .mode = 0o700 });
    executable.close();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const explicit = try std.fs.path.join(allocator, &.{ root, "synthetic-claude" });
    defer allocator.free(explicit);

    var inherited = std.process.EnvMap.init(allocator);
    defer inherited.deinit();
    try inherited.put("PATH", root);

    const from_path = try resolveExecutablePathAlloc(allocator, "synthetic-claude", &inherited);
    defer allocator.free(from_path);
    const from_explicit = try resolveExecutablePathAlloc(allocator, explicit, &inherited);
    defer allocator.free(from_explicit);
    try std.testing.expectError(
        error.ExecutableNotFound,
        resolveExecutablePathAlloc(allocator, "missing-claude", &inherited),
    );
}

test "writable runtime ancestor fails before filesystem mutation" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try std.posix.fchmodat(std.posix.AT.FDCWD, root, 0o777, 0);
    defer std.posix.fchmodat(std.posix.AT.FDCWD, root, 0o700, 0) catch {};

    const runtime_dir = try std.fs.path.join(allocator, &.{ root, "runtime" });
    defer allocator.free(runtime_dir);
    var inherited = try testInheritedEnv(allocator, root);
    defer inherited.deinit();
    var active_config = config_mod.Config{};
    var state = FakeState{
        .allocator = allocator,
        .runtime_dir = runtime_dir,
        .expected_argv = &.{"synthetic-claude"},
    };
    defer state.deinit();
    var seams = FakeSeams{ .state = &state };

    try std.testing.expectError(error.PreflightFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = &.{"synthetic-claude"},
        .inherited_env = &inherited,
        .active_config = &active_config,
    }, &seams));
    try expectNoPreparedResources(&state);
    try std.testing.expectError(error.FileNotFound, std.fs.cwd().access(runtime_dir, .{}));
}

test "bounded preflight failures are zero-spawn and clean prepared state" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const argv = &.{"synthetic-claude"};
    var active_config = config_mod.Config{};

    const missing_binary_runtime = try std.fs.path.join(allocator, &.{ root, "missing-binary-runtime" });
    defer allocator.free(missing_binary_runtime);
    var inherited = try testInheritedEnv(allocator, root);
    defer inherited.deinit();
    var missing_binary_state = FakeState{
        .allocator = allocator,
        .runtime_dir = missing_binary_runtime,
        .expected_argv = argv,
        .fail_executable_preflight = true,
    };
    defer missing_binary_state.deinit();
    var missing_binary_seams = FakeSeams{ .state = &missing_binary_state };
    try std.testing.expectError(error.PreflightFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &active_config,
    }, &missing_binary_seams));
    try std.testing.expectEqual(@as(usize, 1), missing_binary_state.executable_resolution_count);
    try std.testing.expectEqual(@as(usize, 0), missing_binary_state.runtime_dir_count);
    try expectNoPreparedResources(&missing_binary_state);
    try std.testing.expectError(error.FileNotFound, std.fs.cwd().access(missing_binary_runtime, .{}));

    const runtime_failure_path = try std.fs.path.join(allocator, &.{ root, "runtime-resolution-failure" });
    defer allocator.free(runtime_failure_path);
    var runtime_failure_state = FakeState{
        .allocator = allocator,
        .runtime_dir = runtime_failure_path,
        .expected_argv = argv,
        .fail_runtime_dir = true,
    };
    defer runtime_failure_state.deinit();
    var runtime_failure_seams = FakeSeams{ .state = &runtime_failure_state };
    try std.testing.expectError(error.PreflightFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &active_config,
    }, &runtime_failure_seams));
    try std.testing.expectEqual(@as(usize, 1), runtime_failure_state.runtime_dir_count);
    try expectNoPreparedResources(&runtime_failure_state);
    try std.testing.expectError(error.FileNotFound, std.fs.cwd().access(runtime_failure_path, .{}));

    const runtime_missing_home = try std.fs.path.join(allocator, &.{ root, "missing-home-runtime" });
    defer allocator.free(runtime_missing_home);
    var missing_home_env = try testInheritedEnv(allocator, null);
    defer missing_home_env.deinit();
    var missing_home_state = FakeState{
        .allocator = allocator,
        .runtime_dir = runtime_missing_home,
        .expected_argv = argv,
    };
    defer missing_home_state.deinit();
    var missing_home_seams = FakeSeams{ .state = &missing_home_state };
    try std.testing.expectError(error.PreflightFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &missing_home_env,
        .active_config = &active_config,
    }, &missing_home_seams));
    try std.testing.expectEqual(@as(usize, 0), missing_home_state.runtime_dir_count);
    try expectNoPreparedResources(&missing_home_state);
    try std.testing.expect(!missing_home_state.child_env_cleared);
    try std.testing.expectError(error.FileNotFound, std.fs.cwd().access(runtime_missing_home, .{}));

    const capability_generation_runtime = try std.fs.path.join(allocator, &.{ root, "capability-generation-fail" });
    defer allocator.free(capability_generation_runtime);
    var capability_generation_state = FakeState{
        .allocator = allocator,
        .runtime_dir = capability_generation_runtime,
        .expected_argv = argv,
        .fail_capability_generation = true,
    };
    defer capability_generation_state.deinit();
    var capability_generation_seams = FakeSeams{ .state = &capability_generation_state };
    try std.testing.expectError(error.PreflightFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &active_config,
    }, &capability_generation_seams));
    try expectNoPreparedResources(&capability_generation_state);
    try expectRuntimeEmpty(capability_generation_runtime);

    const capability_copy_runtime = try std.fs.path.join(allocator, &.{ root, "capability-copy-fail" });
    defer allocator.free(capability_copy_runtime);
    var capability_copy_state = FakeState{
        .allocator = allocator,
        .runtime_dir = capability_copy_runtime,
        .expected_argv = argv,
        .fail_capability_copy = true,
    };
    defer capability_copy_state.deinit();
    var capability_copy_seams = FakeSeams{ .state = &capability_copy_state };
    try std.testing.expectError(error.PreflightFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &active_config,
    }, &capability_copy_seams));
    try std.testing.expectEqual(@as(usize, 0), capability_copy_state.spawn_count);
    try expectCleanLifecycle(&capability_copy_state, false);

    const runtime_listener_fail = try std.fs.path.join(allocator, &.{ root, "listener-fail-runtime" });
    defer allocator.free(runtime_listener_fail);
    var listener_fail_state = FakeState{
        .allocator = allocator,
        .runtime_dir = runtime_listener_fail,
        .expected_argv = argv,
        .fail_listener = true,
    };
    defer listener_fail_state.deinit();
    var listener_fail_seams = FakeSeams{ .state = &listener_fail_state };
    try std.testing.expectError(error.PreflightFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &active_config,
    }, &listener_fail_seams));
    try std.testing.expectEqual(@as(usize, 0), listener_fail_state.spawn_count);
    try expectCleanLifecycle(&listener_fail_state, false);
}

test "canonical and enrolled config overlap abort before spawn" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("home/.claude/runtime");
    try tmp.dir.makePath("enrolled/runtime");
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const home = try tmp.dir.realpathAlloc(allocator, "home");
    defer allocator.free(home);
    const canonical_runtime = try tmp.dir.realpathAlloc(allocator, "home/.claude/runtime");
    defer allocator.free(canonical_runtime);
    const enrolled = try tmp.dir.realpathAlloc(allocator, "enrolled");
    defer allocator.free(enrolled);
    const enrolled_runtime = try tmp.dir.realpathAlloc(allocator, "enrolled/runtime");
    defer allocator.free(enrolled_runtime);
    const argv = &.{"synthetic-claude"};

    var inherited = try testInheritedEnv(allocator, home);
    defer inherited.deinit();

    var empty_config = config_mod.Config{};
    var canonical_state = FakeState{
        .allocator = allocator,
        .runtime_dir = canonical_runtime,
        .expected_argv = argv,
    };
    defer canonical_state.deinit();
    var canonical_seams = FakeSeams{ .state = &canonical_state };
    try std.testing.expectError(error.PreflightFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &empty_config,
    }, &canonical_seams));
    try expectNoPreparedResources(&canonical_state);
    try expectRuntimeEmpty(canonical_runtime);

    const config_json = try std.fmt.allocPrint(
        allocator,
        \\{{"version":1,"providers":{{"claude":{{"kind":"claude","accounts":{{"enrolled":{{"secret":{{"backend":"env","variable":"UNREACHABLE_TOKEN"}},"config_dir":"{s}"}}}}}}}}}}
    ,
        .{enrolled},
    );
    defer allocator.free(config_json);
    var parsed = try config_mod.loadFromBytes(allocator, config_json);
    defer parsed.deinit();
    var enrolled_state = FakeState{
        .allocator = allocator,
        .runtime_dir = enrolled_runtime,
        .expected_argv = argv,
    };
    defer enrolled_state.deinit();
    var enrolled_seams = FakeSeams{ .state = &enrolled_state };
    try std.testing.expectError(error.PreflightFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &parsed.value,
    }, &enrolled_seams));
    try expectNoPreparedResources(&enrolled_state);
    try std.testing.expectEqual(@as(usize, 0), enrolled_state.credential_calls);
    try expectRuntimeEmpty(enrolled_runtime);

    const forbidden_missing_runtime = try std.fs.path.join(
        allocator,
        &.{ enrolled, "not-created", "runtime" },
    );
    defer allocator.free(forbidden_missing_runtime);
    var forbidden_missing_state = FakeState{
        .allocator = allocator,
        .runtime_dir = forbidden_missing_runtime,
        .expected_argv = argv,
    };
    defer forbidden_missing_state.deinit();
    var forbidden_missing_seams = FakeSeams{ .state = &forbidden_missing_state };
    try std.testing.expectError(error.PreflightFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &parsed.value,
    }, &forbidden_missing_seams));
    try expectNoPreparedResources(&forbidden_missing_state);
    try std.testing.expectError(error.FileNotFound, std.fs.cwd().access(forbidden_missing_runtime, .{}));
}

test "zero nonzero and signal terms propagate without restart" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var inherited = try testInheritedEnv(allocator, root);
    defer inherited.deinit();
    var active_config = config_mod.Config{};
    const argv = &.{"synthetic-claude"};
    const terms = [_]std.process.Child.Term{
        .{ .Exited = 0 },
        .{ .Exited = 23 },
        .{ .Signal = 15 },
    };

    for (terms, 0..) |expected, index| {
        const runtime_dir = try std.fmt.allocPrint(allocator, "{s}/term-{d}", .{ root, index });
        defer allocator.free(runtime_dir);
        var state = FakeState{
            .allocator = allocator,
            .runtime_dir = runtime_dir,
            .expected_argv = argv,
            .expected_home = root,
            .term = expected,
        };
        defer state.deinit();
        var seams = FakeSeams{ .state = &state };

        const actual = try runWithSeams(.{
            .allocator = allocator,
            .argv = argv,
            .inherited_env = &inherited,
            .active_config = &active_config,
        }, &seams);
        try std.testing.expectEqualDeep(expected, actual);
        try std.testing.expectEqual(@as(usize, 1), state.spawn_count);
        try std.testing.expectEqual(@as(usize, 1), state.wait_count);
        try std.testing.expectEqual(@as(usize, 0), state.abort_count);
        try std.testing.expect(state.reaped);
        try expectCleanLifecycle(&state, true);
    }
}

test "spawn wait deferred-exec and cleanup failures remain distinct" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var inherited = try testInheritedEnv(allocator, root);
    defer inherited.deinit();
    var active_config = config_mod.Config{};
    const argv = &.{"synthetic-claude"};

    const spawn_runtime = try std.fs.path.join(allocator, &.{ root, "spawn-error" });
    defer allocator.free(spawn_runtime);
    var spawn_state = FakeState{
        .allocator = allocator,
        .runtime_dir = spawn_runtime,
        .expected_argv = argv,
        .expected_home = root,
        .fail_spawn = true,
    };
    defer spawn_state.deinit();
    var spawn_seams = FakeSeams{ .state = &spawn_state };
    try std.testing.expectError(error.ChildSpawnFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &active_config,
    }, &spawn_seams));
    try std.testing.expectEqual(@as(usize, 1), spawn_state.spawn_count);
    try std.testing.expectEqual(@as(usize, 0), spawn_state.wait_count);
    try std.testing.expectEqual(@as(usize, 0), spawn_state.abort_count);
    try expectCleanLifecycle(&spawn_state, true);

    const wait_runtime = try std.fs.path.join(allocator, &.{ root, "wait-error" });
    defer allocator.free(wait_runtime);
    var wait_state = FakeState{
        .allocator = allocator,
        .runtime_dir = wait_runtime,
        .expected_argv = argv,
        .expected_home = root,
        .fail_wait = true,
    };
    defer wait_state.deinit();
    var wait_seams = FakeSeams{ .state = &wait_state };
    try std.testing.expectError(error.ChildWaitFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &active_config,
    }, &wait_seams));
    try std.testing.expectEqual(@as(usize, 1), wait_state.spawn_count);
    try std.testing.expectEqual(@as(usize, 1), wait_state.wait_count);
    try std.testing.expectEqual(@as(usize, 1), wait_state.abort_count);
    try std.testing.expect(wait_state.reaped);
    try expectCleanLifecycle(&wait_state, true);

    const deferred_runtime = try std.fs.path.join(allocator, &.{ root, "deferred-spawn-error" });
    defer allocator.free(deferred_runtime);
    var deferred_state = FakeState{
        .allocator = allocator,
        .runtime_dir = deferred_runtime,
        .expected_argv = argv,
        .expected_home = root,
        .fail_deferred_spawn = true,
    };
    defer deferred_state.deinit();
    var deferred_seams = FakeSeams{ .state = &deferred_state };
    try std.testing.expectError(error.ChildSpawnFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &active_config,
    }, &deferred_seams));
    try std.testing.expectEqual(@as(usize, 1), deferred_state.spawn_count);
    try std.testing.expectEqual(@as(usize, 1), deferred_state.wait_count);
    try std.testing.expectEqual(@as(usize, 1), deferred_state.abort_count);
    try std.testing.expect(deferred_state.reaped);
    try expectCleanLifecycle(&deferred_state, true);

    const cleanup_runtime = try std.fs.path.join(allocator, &.{ root, "cleanup-error" });
    defer allocator.free(cleanup_runtime);
    var cleanup_state = FakeState{
        .allocator = allocator,
        .runtime_dir = cleanup_runtime,
        .expected_argv = argv,
        .expected_home = root,
        .fail_wait = true,
        .fail_cleanup = true,
    };
    defer cleanup_state.deinit();
    var cleanup_seams = FakeSeams{ .state = &cleanup_state };
    try std.testing.expectError(error.ChildCleanupFailed, runWithSeams(.{
        .allocator = allocator,
        .argv = argv,
        .inherited_env = &inherited,
        .active_config = &active_config,
    }, &cleanup_seams));
    try std.testing.expectEqual(@as(usize, 1), cleanup_state.spawn_count);
    try std.testing.expectEqual(@as(usize, 1), cleanup_state.wait_count);
    try std.testing.expectEqual(@as(usize, 1), cleanup_state.abort_count);
    try std.testing.expect(!cleanup_state.reaped);
    try expectCleanLifecycle(&cleanup_state, true);
}
