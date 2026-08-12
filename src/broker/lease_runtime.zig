//! Per-sidecar runtime over the persisted cross-process lease store.
//!
//! This module owns only advisory routing leases. It has no provider, credential,
//! request-body, event, or child-process authority. Every store operation is
//! complete before the caller performs upstream I/O. Missing/unavailable shared
//! state degrades to the same reactive route reducer with an empty lease view;
//! it never invents route readiness or persisted capacity.

const std = @import("std");
const builtin = @import("builtin");
const decision = @import("decision.zig");
const identifiers = @import("identifiers.zig");
const lease_owner = @import("lease_owner.zig");
const lease_state = @import("lease_state.zig");
const lease_store = @import("lease_store.zig");
const lock_wait = @import("../lock_wait.zig");
const model_demand = @import("model_demand.zig");
const route_observation = @import("route_observation.zig");

pub const Store = lease_store.LeaseStore(256, 256);
const max_active_models = 256;
const max_reprojection_attempts = 4;
// Persisted-snapshot admission must fit below the managed listener's standard
// 16 MiB thread stack; this stricter worker keeps the regression executable.
const request_stack_regression_bytes = 8 * 1024 * 1024;
const release_stack_bytes = 32 * 1024 * 1024;
/// Active request traffic renews this lease. There is deliberately no idle
/// heartbeat thread: the timestamp is a dead/unknown-owner reclamation bound,
/// not permission to evict an exact owner incarnation that is still alive.
const lease_ttl_ms: lease_state.TimestampMs = 120_000;
pub const advisory_lock_timeout_ns: u64 = 500 * std.time.ns_per_ms;

pub const WorkClock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (ctx: ?*anyopaque) i128,

    fn now(self: WorkClock) i128 {
        return self.nowFn(self.ctx);
    }
};

/// One cumulative advisory lease-work budget shared by every lease operation
/// for one managed request, including a possible alternate transition.
pub const WorkBudget = struct {
    clock: ?WorkClock,
    limit_ns: u64,
    spent_ns: u64 = 0,
    timer: ?std.time.Timer = null,
    injected_started_ns: i128 = 0,
    active: bool = false,

    fn start(clock: ?WorkClock, limit_ns: u64) !WorkBudget {
        return .{ .clock = clock, .limit_ns = limit_ns };
    }

    fn beginSlice(self: *WorkBudget) !void {
        if (self.active) return;
        if (self.clock) |clock| {
            const started_ns = clock.now();
            if (started_ns < 0) return error.MonotonicClockUnavailable;
            self.injected_started_ns = started_ns;
        } else {
            self.timer = std.time.Timer.start() catch
                return error.MonotonicClockUnavailable;
        }
        self.active = true;
    }

    fn endSlice(self: *WorkBudget) !void {
        if (!self.active) return;
        const elapsed_ns = try self.activeElapsedNs();
        self.spent_ns = std.math.add(u64, self.spent_ns, elapsed_ns) catch
            std.math.maxInt(u64);
        self.timer = null;
        self.active = false;
    }

    pub fn remainingNs(self: *WorkBudget) !u64 {
        const active_elapsed_ns = if (self.active) try self.activeElapsedNs() else 0;
        const total_ns = std.math.add(u64, self.spent_ns, active_elapsed_ns) catch
            return error.LeaseWorkBudgetExceeded;
        if (total_ns >= self.limit_ns) return error.LeaseWorkBudgetExceeded;
        return self.limit_ns - total_ns;
    }

    fn activeElapsedNs(self: *WorkBudget) !u64 {
        if (self.clock) |clock| {
            const now_ns = clock.now();
            if (now_ns < self.injected_started_ns) return error.MonotonicClockUnavailable;
            const elapsed_i128 = now_ns - self.injected_started_ns;
            if (elapsed_i128 > std.math.maxInt(u64)) return error.LeaseWorkBudgetExceeded;
            return @intCast(elapsed_i128);
        }
        if (self.timer) |*timer| return timer.read();
        return error.MonotonicClockUnavailable;
    }
};

pub fn startTeardownBudget(clock: ?WorkClock) !WorkBudget {
    var budget = try WorkBudget.start(clock, advisory_lock_timeout_ns);
    try budget.beginSlice();
    return budget;
}

fn ownerBudgetRemaining(raw: *anyopaque) anyerror!u64 {
    const budget: *WorkBudget = @ptrCast(@alignCast(raw));
    return budget.remainingNs();
}

fn ownerBudget(budget: *WorkBudget) lease_owner.Budget {
    return .{ .ctx = @ptrCast(budget), .remaining_ns = ownerBudgetRemaining };
}

pub const Options = struct {
    store: lease_store.Options = .{},
    /// Request-path lease participation gets its own short budget. It must
    /// leave almost all of the managed request deadline available for useful
    /// upstream work.
    advisory_wait: lock_wait.WaitOptions = .{
        .poll_interval_ns = 5 * std.time.ns_per_ms,
        .heartbeat_ns = std.time.ns_per_hour,
        .timeout_ns = advisory_lock_timeout_ns,
    },
    /// Monotonic request-budget clock. Tests inject the same virtual clock used
    /// by the provider retry machine so deadline separation is executable.
    work_clock: ?WorkClock = null,
    /// Test/lifecycle seam invoked once after a decision projection and before
    /// its first admission mutation. It never runs while the store flock is held.
    before_first_admission: ?AdmissionHook = null,
    /// Test/lifecycle seam invoked before every admission mutation attempt. It
    /// makes the bounded reprojection contract executable without introducing
    /// clocks or concurrency into the reducer.
    before_admission_attempt: ?AdmissionHook = null,
    /// Test-only race seam invoked immediately before each persisted decision
    /// projection, while no store flock is held.
    before_projection: ?AdmissionHook = null,
    /// Test-only race seam invoked immediately before route registration,
    /// while no store flock is held.
    before_registration: ?AdmissionHook = null,
    /// Test/lifecycle seam before owner-registry cleanup. The registry work is
    /// still charged to the same request budget and remains custody-checked.
    before_owner_cleanup: ?AdmissionHook = null,
    /// Test-only elapsed-work seam invoked after each successful request-scoped
    /// store operation. Production leaves this null.
    after_store_operation: ?StoreOperationHook = null,
};

pub const AdmissionHook = struct {
    ctx: *anyopaque,
    run: *const fn (ctx: *anyopaque) anyerror!void,
};

pub const StoreOperation = enum {
    cleanup,
    registration,
    projection,
    acquire,
    transition,
    renew,
    release,
    reconcile,
};

pub const StoreOperationHook = struct {
    ctx: *anyopaque,
    run: *const fn (ctx: *anyopaque, operation: StoreOperation) anyerror!void,
};

/// Adapter-owned validation of the selected opaque route. It runs after every
/// projection and before any acquire/transition mutation, so credential-slot
/// identity remains authoritative without leaking it into the pure reducer.
pub const ChoiceValidator = struct {
    ctx: *anyopaque,
    validate: *const fn (ctx: *anyopaque, route: lease_state.RouteHandle) anyerror!void,
};

/// One policy for failures in the advisory shared-lease view. These failures
/// mean persistence cannot currently participate, so routing continues from
/// reactive candidate evidence without writing or inventing shared capacity.
/// Input/coherence errors (identity, revision fencing, malformed state, owner
/// mismatch, and route/catalog conflicts) are intentionally absent and remain
/// fail-closed.
pub fn isAdvisoryUnavailableError(err: anyerror) bool {
    return switch (err) {
        error.LeaseStateUnavailable,
        error.LockWaitTimeout,
        error.LeaseWorkBudgetExceeded,
        => true,
        else => false,
    };
}

pub const Candidate = struct {
    observation: route_observation.RouteObservation,
    account: lease_state.AccountHandle,
};

pub const Selection = struct {
    route_buf: [identifiers.max_handle_len]u8 = [_]u8{0} ** identifiers.max_handle_len,
    route_len: u16 = 0,
    persisted: bool = false,
    quality: lease_state.ProjectionQuality = .unavailable,
    /// The canonical mutation and local lease agree, but the advisory lease
    /// budget expired while confirming the final operation. Routing may proceed
    /// with this committed choice; callers must not recompute another route.
    committed_after_budget: bool = false,
    reconciled_commit_uncertain: bool = false,

    pub fn route(self: *const Selection) lease_state.RouteHandle {
        return lease_state.RouteHandle.parse(self.route_buf[0..self.route_len]) catch unreachable;
    }
};

const OwnedHandle = struct {
    buf: [identifiers.max_handle_len]u8 = [_]u8{0} ** identifiers.max_handle_len,
    len: u16 = 0,

    fn init(value: []const u8) !OwnedHandle {
        _ = try lease_state.RouteHandle.parse(value);
        var result = OwnedHandle{};
        @memcpy(result.buf[0..value.len], value);
        result.len = @intCast(value.len);
        return result;
    }

    fn text(self: *const OwnedHandle) []const u8 {
        return self.buf[0..self.len];
    }
};

const OwnedIdentity = struct {
    buf: [identifiers.max_handle_len]u8 = [_]u8{0} ** identifiers.max_handle_len,
    len: u16 = 0,

    fn init(value: []const u8) !OwnedIdentity {
        if (value.len == 0 or value.len > identifiers.max_handle_len) {
            return error.InvalidIdentityEvidence;
        }
        var result = OwnedIdentity{};
        @memcpy(result.buf[0..value.len], value);
        result.len = @intCast(value.len);
        return result;
    }

    fn text(self: *const OwnedIdentity) []const u8 {
        return self.buf[0..self.len];
    }
};

const ActiveLease = struct {
    exact_model: model_demand.ExactModel,
    lease: OwnedHandle,
    account: OwnedHandle,
    route: OwnedHandle,
    generation: lease_state.Generation,
};

const Choice = struct {
    route: lease_state.RouteHandle,
    account: lease_state.AccountHandle,
    identity: route_observation.IdentityEvidence,
    revision: lease_state.Revision,
    quality: lease_state.ProjectionQuality,
};

const PendingTransitionOrigin = struct {
    lease: OwnedHandle,
    account: OwnedHandle,
    route: OwnedHandle,
    generation: lease_state.Generation,
};

const PendingMutation = struct {
    kind: enum { acquire, transition },
    exact_model: model_demand.ExactModel,
    lease: OwnedHandle,
    account: OwnedHandle,
    route: OwnedHandle,
    identity: OwnedIdentity,
    transition_origin: ?PendingTransitionOrigin = null,
};

const MutationOutcome = enum {
    within_budget,
    committed_after_budget,
};

const DecisionProjection = struct {
    rows: [256]decision.LeaseObservation = undefined,
    row_count: usize = 0,
    sticky: ?lease_state.RouteHandle = null,

    fn fromStore(projection: *const Store.Projection) !DecisionProjection {
        var result = DecisionProjection{};
        for (projection.routeRows()) |*row| {
            result.rows[result.row_count] = .{
                .route = try lease_state.RouteHandle.parse(row.routeText()),
                .active_leases = row.active_leases,
                .last_selected_at = row.last_selected_at,
            };
            result.row_count += 1;
        }
        if (projection.stickyRouteText()) |sticky| {
            result.sticky = try lease_state.RouteHandle.parse(sticky);
        }
        return result;
    }

    fn view(self: *const DecisionProjection) decision.LeaseView {
        return .{ .sticky_route = self.sticky, .routes = self.rows[0..self.row_count] };
    }
};

pub const LeaseRuntime = struct {
    allocator: std.mem.Allocator,
    store: Store,
    registry: lease_owner.Registry,
    owner: lease_owner.Guard,
    session: OwnedHandle,
    active: [max_active_models]ActiveLease = undefined,
    active_count: usize = 0,
    mutex: std.Thread.Mutex = .{},
    admission_hook: ?AdmissionHook = null,
    admission_attempt_hook: ?AdmissionHook = null,
    projection_hook: ?AdmissionHook = null,
    registration_hook: ?AdmissionHook = null,
    owner_cleanup_hook: ?AdmissionHook = null,
    store_operation_hook: ?StoreOperationHook = null,
    admission_hook_fired: bool = false,
    reprojection_count: usize = 0,
    advisory_wait: lock_wait.WaitOptions,
    work_clock: ?WorkClock,
    commit_uncertain: [max_active_models]PendingMutation = undefined,
    commit_uncertain_count: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        absolute_broker_root: []const u8,
        options: Options,
    ) !LeaseRuntime {
        return initInternal(allocator, absolute_broker_root, options, null, null);
    }

    fn initInternal(
        allocator: std.mem.Allocator,
        absolute_broker_root: []const u8,
        options: Options,
        owner_override: ?lease_store.OwnerIdentity,
        session_override: ?[]const u8,
    ) !LeaseRuntime {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
            return error.UnsupportedLeaseRuntimePlatform;
        }
        var store_options = options.store;
        store_options.wait = options.advisory_wait;
        var store = try Store.init(allocator, absolute_broker_root, store_options);
        errdefer store.deinit();
        var registry = try lease_owner.Registry.init(absolute_broker_root);
        errdefer registry.deinit();
        var owner = if (owner_override) |identity|
            try registry.acquireExactForTest(identity)
        else
            try registry.acquireRandom();
        errdefer owner.deinit();

        var session_buf: [identifiers.max_handle_len]u8 = undefined;
        const session_text = session_override orelse try randomHandle(&session_buf, "session");
        return .{
            .allocator = allocator,
            .store = store,
            .registry = registry,
            .owner = owner,
            .session = try OwnedHandle.init(session_text),
            .admission_hook = options.before_first_admission,
            .admission_attempt_hook = options.before_admission_attempt,
            .projection_hook = options.before_projection,
            .registration_hook = options.before_registration,
            .owner_cleanup_hook = options.before_owner_cleanup,
            .store_operation_hook = options.after_store_operation,
            .advisory_wait = options.advisory_wait,
            .work_clock = options.work_clock,
        };
    }

    pub fn beginRequestBudget(self: *const LeaseRuntime) !WorkBudget {
        return WorkBudget.start(self.work_clock, advisory_lock_timeout_ns);
    }

    pub fn beginTeardownBudget(self: *const LeaseRuntime) !WorkBudget {
        return startTeardownBudget(self.work_clock);
    }

    /// The listener must already be joined. Release failures are bounded and
    /// leave persisted state for exact-owner cleanup after the owner flock drops.
    pub fn deinit(self: *LeaseRuntime) void {
        self.deinitChecked() catch {};
    }

    pub fn deinitChecked(self: *LeaseRuntime) !void {
        var budget = self.beginTeardownBudget() catch {
            self.owner.deinit();
            self.registry.deinit();
            self.store.deinit();
            self.* = undefined;
            return error.LeaseTeardownBudgetUnavailable;
        };
        defer budget.endSlice() catch {};
        return self.deinitCheckedWithBudget(&budget);
    }

    pub fn deinitCheckedWithBudget(self: *LeaseRuntime, budget: *WorkBudget) !void {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
            return error.UnsupportedLeaseRuntimePlatform;
        }
        var teardown_error: ?anyerror = null;
        self.releaseAllWithBudget(budget) catch |err| {
            std.log.err("broker lease release failed during teardown: {s}", .{@errorName(err)});
            teardown_error = error.LeaseReleaseFailed;
        };
        if (teardown_error == null) self.registry.retireGuardBounded(
            &self.owner,
            self.advisory_wait,
            ownerBudget(budget),
        ) catch |err| {
            std.log.err("broker lease owner retirement failed: {s}", .{@errorName(err)});
            teardown_error = error.LeaseOwnerRetirementFailed;
        };
        self.owner.deinit();
        self.registry.deinit();
        self.store.deinit();
        self.* = undefined;
        if (teardown_error) |err| return err;
    }

    pub fn selectAndAcquire(
        self: *LeaseRuntime,
        candidates: []const Candidate,
        demand: model_demand.ModelDemand,
        now_ms: lease_state.TimestampMs,
    ) !Selection {
        var budget = try self.beginRequestBudget();
        return self.selectAndAcquireValidatedWithBudget(candidates, demand, now_ms, null, &budget);
    }

    pub fn selectAndAcquireValidated(
        self: *LeaseRuntime,
        candidates: []const Candidate,
        demand: model_demand.ModelDemand,
        now_ms: lease_state.TimestampMs,
        validator: ?ChoiceValidator,
    ) !Selection {
        var budget = try self.beginRequestBudget();
        return self.selectAndAcquireValidatedWithBudget(candidates, demand, now_ms, validator, &budget);
    }

    pub fn selectAndAcquireValidatedWithBudget(
        self: *LeaseRuntime,
        candidates: []const Candidate,
        demand: model_demand.ModelDemand,
        now_ms: lease_state.TimestampMs,
        validator: ?ChoiceValidator,
        budget: *WorkBudget,
    ) !Selection {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
            return error.UnsupportedLeaseRuntimePlatform;
        }
        try budget.beginSlice();
        const result = self.selectAndAcquireBudgetActive(
            candidates,
            demand,
            now_ms,
            validator,
            budget,
        );
        try budget.endSlice();
        return result;
    }

    fn selectAndAcquireBudgetActive(
        self: *LeaseRuntime,
        candidates: []const Candidate,
        demand: model_demand.ModelDemand,
        now_ms: lease_state.TimestampMs,
        validator: ?ChoiceValidator,
        budget: *WorkBudget,
    ) !Selection {
        self.mutex.lock();
        defer self.mutex.unlock();
        const previous_wait = self.store.replaceWaitOptions(self.advisory_wait);
        defer _ = self.store.replaceWaitOptions(previous_wait);
        try validateInput(candidates, demand, now_ms);
        if (try self.reconcilePending(candidates, demand, validator, budget)) |recovered| {
            return recovered;
        }
        _ = self.cleanupStaleUnlocked(now_ms, budget) catch |err| {
            if (isAdvisoryUnavailableError(err)) {
                return self.selectWithoutPersistence(candidates, demand, now_ms, null, validator);
            }
            return err;
        };
        const registration_available = self.registerCandidates(candidates, budget) catch |err| switch (err) {
            else => if (isAdvisoryUnavailableError(err)) false else return err,
        };
        if (!registration_available) {
            return self.selectWithoutPersistence(candidates, demand, now_ms, null, validator);
        }

        var attempt: usize = 0;
        while (attempt < max_reprojection_attempts) : (attempt += 1) {
            const active_index = self.findActive(demand.exact_model);
            if (active_index) |index| {
                if (validator) |check| {
                    try check.validate(
                        check.ctx,
                        try lease_state.RouteHandle.parse(self.active[index].route.text()),
                    );
                }
                _ = self.renewIndex(index, now_ms, budget) catch |err| switch (err) {
                    error.StaleLease, error.LeaseNotFound => {
                        self.releaseIndex(index, budget) catch |release_err| switch (release_err) {
                            error.LeaseNotFound => {},
                            else => {
                                if (isAdvisoryUnavailableError(release_err)) {
                                    return self.selectWithoutPersistence(candidates, demand, now_ms, null, validator);
                                }
                                return release_err;
                            },
                        };
                        self.removeActive(index);
                        continue;
                    },
                    else => {
                        if (isAdvisoryUnavailableError(err)) {
                            return self.selectWithoutPersistence(candidates, demand, now_ms, null, validator);
                        }
                        return err;
                    },
                };
            }

            const choice = self.choose(candidates, demand, now_ms, null, budget) catch |err| {
                if (isAdvisoryUnavailableError(err)) {
                    return self.selectWithoutPersistence(candidates, demand, now_ms, null, validator);
                }
                return err;
            };
            if (validator) |check| try check.validate(check.ctx, choice.route);
            if (choice.quality == .unavailable) {
                return selectionFromChoice(choice, false);
            }

            if (self.findActive(demand.exact_model)) |index| {
                if (std.mem.eql(u8, self.active[index].route.text(), choice.route.text)) {
                    return selectionFromChoice(choice, true);
                }
                const mutation = self.transitionIndex(index, choice, demand, now_ms, budget) catch |err| switch (err) {
                    error.StateChanged => {
                        self.reprojection_count += 1;
                        continue;
                    },
                    else => if (isAdvisoryUnavailableError(err))
                        return self.selectWithoutPersistence(candidates, demand, now_ms, null, validator)
                    else
                        return err,
                };
                var selected = try selectionFromChoice(choice, true);
                selected.committed_after_budget = mutation == .committed_after_budget;
                return selected;
            }

            const mutation = self.acquireChoice(choice, demand, now_ms, budget) catch |err| switch (err) {
                error.StateChanged => {
                    self.reprojection_count += 1;
                    continue;
                },
                else => if (isAdvisoryUnavailableError(err))
                    return self.selectWithoutPersistence(candidates, demand, now_ms, null, validator)
                else
                    return err,
            };
            var selected = try selectionFromChoice(choice, true);
            selected.committed_after_budget = mutation == .committed_after_budget;
            return selected;
        }
        return error.StateChanged;
    }

    /// Atomically moves the current exact-model session lease to one alternate.
    /// Callers invoke this only after replayability and bounded-wait checks pass.
    pub fn selectAndTransition(
        self: *LeaseRuntime,
        candidates: []const Candidate,
        demand: model_demand.ModelDemand,
        current_route: lease_state.RouteHandle,
        now_ms: lease_state.TimestampMs,
    ) !?Selection {
        var budget = try self.beginRequestBudget();
        return self.selectAndTransitionValidatedWithBudget(
            candidates,
            demand,
            current_route,
            now_ms,
            null,
            &budget,
        );
    }

    pub fn selectAndTransitionValidated(
        self: *LeaseRuntime,
        candidates: []const Candidate,
        demand: model_demand.ModelDemand,
        current_route: lease_state.RouteHandle,
        now_ms: lease_state.TimestampMs,
        validator: ?ChoiceValidator,
    ) !?Selection {
        var budget = try self.beginRequestBudget();
        return self.selectAndTransitionValidatedWithBudget(
            candidates,
            demand,
            current_route,
            now_ms,
            validator,
            &budget,
        );
    }

    pub fn selectAndTransitionValidatedWithBudget(
        self: *LeaseRuntime,
        candidates: []const Candidate,
        demand: model_demand.ModelDemand,
        current_route: lease_state.RouteHandle,
        now_ms: lease_state.TimestampMs,
        validator: ?ChoiceValidator,
        budget: *WorkBudget,
    ) !?Selection {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
            return error.UnsupportedLeaseRuntimePlatform;
        }
        try budget.beginSlice();
        const result = self.selectAndTransitionBudgetActive(
            candidates,
            demand,
            current_route,
            now_ms,
            validator,
            budget,
        );
        try budget.endSlice();
        return result;
    }

    fn selectAndTransitionBudgetActive(
        self: *LeaseRuntime,
        candidates: []const Candidate,
        demand: model_demand.ModelDemand,
        current_route: lease_state.RouteHandle,
        now_ms: lease_state.TimestampMs,
        validator: ?ChoiceValidator,
        budget: *WorkBudget,
    ) !?Selection {
        self.mutex.lock();
        defer self.mutex.unlock();
        const previous_wait = self.store.replaceWaitOptions(self.advisory_wait);
        defer _ = self.store.replaceWaitOptions(previous_wait);
        try validateInput(candidates, demand, now_ms);
        if (try self.reconcilePending(candidates, demand, validator, budget)) |recovered| {
            return @as(?Selection, recovered);
        }
        _ = self.cleanupStaleUnlocked(now_ms, budget) catch |err| {
            if (isAdvisoryUnavailableError(err)) {
                return @as(?Selection, self.selectWithoutPersistence(
                    candidates,
                    demand,
                    now_ms,
                    current_route,
                    validator,
                ) catch |fallback_err| switch (fallback_err) {
                    error.NoEligibleRoute => return null,
                    else => return fallback_err,
                });
            }
            return err;
        };
        var attempt: usize = 0;
        while (attempt < max_reprojection_attempts) : (attempt += 1) {
            const choice = self.choose(candidates, demand, now_ms, current_route, budget) catch |err| {
                if (err == error.NoEligibleRoute) return null;
                if (isAdvisoryUnavailableError(err)) {
                    return @as(?Selection, self.selectWithoutPersistence(
                        candidates,
                        demand,
                        now_ms,
                        current_route,
                        validator,
                    ) catch |fallback_err| switch (fallback_err) {
                        error.NoEligibleRoute => return null,
                        else => return fallback_err,
                    });
                }
                return err;
            };
            if (validator) |check| try check.validate(check.ctx, choice.route);
            const active_index = self.findActive(demand.exact_model);
            if (active_index == null or choice.quality == .unavailable) {
                return @as(?Selection, try selectionFromChoice(choice, false));
            }
            const mutation = self.transitionIndex(active_index.?, choice, demand, now_ms, budget) catch |err| switch (err) {
                error.StateChanged => {
                    self.reprojection_count += 1;
                    continue;
                },
                else => if (isAdvisoryUnavailableError(err))
                    return self.selectReactiveAlternate(candidates, demand, current_route, now_ms, validator)
                else
                    return err,
            };
            var selected = try selectionFromChoice(choice, true);
            selected.committed_after_budget = mutation == .committed_after_budget;
            return @as(?Selection, selected);
        }
        return error.StateChanged;
    }

    pub fn renew(self: *LeaseRuntime, exact_model: model_demand.ExactModel, now_ms: lease_state.TimestampMs) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const index = self.findActive(exact_model) orelse return false;
        _ = try self.renewIndex(index, now_ms, null);
        return true;
    }

    pub fn cleanupStale(self: *LeaseRuntime, now_ms: lease_state.TimestampMs) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.cleanupStaleUnlocked(now_ms, null);
    }

    fn cleanupStaleUnlocked(
        self: *LeaseRuntime,
        now_ms: lease_state.TimestampMs,
        budget: ?*WorkBudget,
    ) !usize {
        try self.armStoreWait(budget);
        var owners: [256]lease_store.OwnerIdentity = undefined;
        const report = try self.store.cleanupStaleReportingOwners(
            now_ms,
            self.registry.livenessSource(),
            &owners,
        );
        if (budget) |request_budget| {
            if (self.owner_cleanup_hook) |hook| try hook.run(hook.ctx);
            _ = try self.registry.retireDeadAndOrphanedBounded(
                owners[0..report.owner_count],
                self.advisory_wait,
                ownerBudget(request_budget),
            );
        } else {
            for (owners[0..report.owner_count]) |owner| {
                _ = try self.registry.retireDead(owner);
            }
            _ = try self.registry.retireOrphanedDead(owners[0..report.owner_count]);
        }
        try self.finishStoreOperation(budget, .cleanup);
        return report.removed_count;
    }

    pub fn releaseAll(self: *LeaseRuntime) !void {
        var budget = try self.beginTeardownBudget();
        defer budget.endSlice() catch {};
        return self.releaseAllWithBudget(&budget);
    }

    pub fn releaseAllWithBudget(self: *LeaseRuntime, budget: *WorkBudget) !void {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
            return error.UnsupportedLeaseRuntimePlatform;
        }
        var job = ReleaseAllJob{ .runtime = self, .budget = budget };
        const thread = try std.Thread.spawn(
            .{ .stack_size = release_stack_bytes },
            ReleaseAllJob.run,
            .{&job},
        );
        thread.join();
        if (job.failure) |err| return err;
    }

    fn releaseAllInline(self: *LeaseRuntime, budget: *WorkBudget) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var first_error: ?anyerror = null;
        var retained: usize = 0;
        for (self.active[0..self.active_count], 0..) |active, index| {
            self.armStoreWait(budget) catch |err| {
                if (first_error == null) first_error = err;
                for (self.active[index..self.active_count]) |remaining| {
                    self.active[retained] = remaining;
                    retained += 1;
                }
                break;
            };
            const release_result = self.store.release(.{
                .lease = try lease_state.LeaseHandle.parse(active.lease.text()),
                .session = try lease_state.SessionHandle.parse(self.session.text()),
                .owner = self.owner.identity,
                .generation = active.generation,
            });
            release_result catch |err| switch (err) {
                error.LeaseNotFound => {},
                else => {
                    self.active[retained] = active;
                    retained += 1;
                    if (first_error == null) first_error = err;
                    continue;
                },
            };
            self.finishStoreOperation(budget, .release) catch |err| {
                if (first_error == null) first_error = err;
            };
        }
        self.active_count = retained;
        if (first_error) |err| return err;
    }

    pub fn activeLeaseCount(self: *LeaseRuntime) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.active_count;
    }

    pub fn reprojectionCount(self: *LeaseRuntime) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.reprojection_count;
    }

    pub fn projectedActiveLeaseCount(
        self: *LeaseRuntime,
        demand: model_demand.ModelDemand,
        now_ms: lease_state.TimestampMs,
    ) ?u64 {
        const projection = self.store.project(
            lease_state.SessionHandle.parse(self.session.text()) catch return null,
            demand,
            now_ms,
            self.registry.livenessSource(),
        ) catch return null;
        if (projection.quality == .unavailable) return null;
        var total: u64 = 0;
        for (projection.routeRows()) |row| total +|= row.active_leases;
        return total;
    }

    fn projectedLoadsForRoutes(
        self: *LeaseRuntime,
        demand: model_demand.ModelDemand,
        now_ms: lease_state.TimestampMs,
        routes: [2]lease_state.RouteHandle,
    ) ?[2]u64 {
        const projection = self.store.project(
            lease_state.SessionHandle.parse(self.session.text()) catch return null,
            demand,
            now_ms,
            self.registry.livenessSource(),
        ) catch return null;
        if (projection.quality == .unavailable) return null;
        var loads = [_]u64{ 0, 0 };
        for (projection.routeRows()) |row| {
            for (routes, 0..) |route, index| {
                if (std.mem.eql(u8, row.routeText(), route.text)) {
                    loads[index] +|= row.active_leases;
                }
            }
        }
        return loads;
    }

    pub fn ownerIdentityForTest(self: *const LeaseRuntime) lease_store.OwnerIdentity {
        return self.owner.identity;
    }

    fn registerCandidates(
        self: *LeaseRuntime,
        candidates: []const Candidate,
        budget: ?*WorkBudget,
    ) !bool {
        var registrations: [256]lease_state.RouteRegistration = undefined;
        var count: usize = 0;
        for (candidates) |candidate| {
            registrations[count] = .{
                .route = candidate.observation.route,
                .exact_model = candidate.observation.exact_model,
            };
            count += 1;
        }
        if (self.registration_hook) |hook| try hook.run(hook.ctx);
        try self.armStoreWait(budget);
        try self.store.registerRoutes(registrations[0..count]);
        try self.finishStoreOperation(budget, .registration);
        return true;
    }

    fn choose(
        self: *LeaseRuntime,
        candidates: []const Candidate,
        demand: model_demand.ModelDemand,
        now_ms: lease_state.TimestampMs,
        excluded: ?lease_state.RouteHandle,
        budget: ?*WorkBudget,
    ) !Choice {
        if (self.projection_hook) |hook| try hook.run(hook.ctx);
        try self.armStoreWait(budget);
        const projection = try self.store.project(
            try lease_state.SessionHandle.parse(self.session.text()),
            demand,
            now_ms,
            self.registry.livenessSource(),
        );
        try self.finishStoreOperation(budget, .projection);
        var view = try DecisionProjection.fromStore(&projection);
        var evidence: [256]route_observation.RouteEvidence = undefined;
        for (candidates, 0..) |candidate, index| {
            var observation = candidate.observation;
            if (excluded) |route| {
                if (std.mem.eql(u8, route.text, observation.route.text)) {
                    observation.admission = .unavailable;
                }
            }
            evidence[index] = route_observation.project(observation, @divTrunc(now_ms, 1000));
        }
        const selected = switch (decision.reduce(demand, evidence[0..candidates.len], view.view())) {
            .select_route => |route| route,
            .no_route => return error.NoEligibleRoute,
        };
        const candidate = try exactCandidate(candidates, demand.exact_model, selected);
        const identity = candidate.observation.identity orelse
            return error.MissingIdentityEvidence;
        if (!identity.isValid() or identity.bytes.len > identifiers.max_handle_len) {
            return error.InvalidIdentityEvidence;
        }
        return .{
            .route = selected,
            .account = candidate.account,
            .identity = identity,
            .revision = projection.revision,
            .quality = projection.quality,
        };
    }

    fn selectWithoutPersistence(
        self: *LeaseRuntime,
        candidates: []const Candidate,
        demand: model_demand.ModelDemand,
        now_ms: lease_state.TimestampMs,
        excluded: ?lease_state.RouteHandle,
        validator: ?ChoiceValidator,
    ) !Selection {
        _ = self;
        var evidence: [256]route_observation.RouteEvidence = undefined;
        for (candidates, 0..) |candidate, index| {
            var observation = candidate.observation;
            if (excluded) |route| {
                if (std.mem.eql(u8, route.text, observation.route.text)) {
                    observation.admission = .unavailable;
                }
            }
            evidence[index] = route_observation.project(observation, @divTrunc(now_ms, 1000));
        }
        const selected = switch (decision.reduce(demand, evidence[0..candidates.len], .{})) {
            .select_route => |route| route,
            .no_route => return error.NoEligibleRoute,
        };
        if (validator) |check| try check.validate(check.ctx, selected);
        return selectionFromRoute(selected, false, .unavailable);
    }

    fn acquireChoice(
        self: *LeaseRuntime,
        choice: Choice,
        demand: model_demand.ModelDemand,
        now_ms: lease_state.TimestampMs,
        budget: ?*WorkBudget,
    ) !MutationOutcome {
        if (self.active_count == max_active_models) return error.LeaseCapacityExceeded;
        var lease_buf: [identifiers.max_handle_len]u8 = undefined;
        const lease_text = try randomHandle(&lease_buf, "lease");
        const pending = PendingMutation{
            .kind = .acquire,
            .exact_model = demand.exact_model,
            .lease = try OwnedHandle.init(lease_text),
            .account = try OwnedHandle.init(choice.account.text),
            .route = try OwnedHandle.init(choice.route.text),
            .identity = try OwnedIdentity.init(choice.identity.bytes),
        };
        try self.runAdmissionHooks();
        try self.armStoreWait(budget);
        const outcome = self.store.acquire(.{
            .lease = try lease_state.LeaseHandle.parse(lease_text),
            .session = try lease_state.SessionHandle.parse(self.session.text()),
            .account = choice.account,
            .route = choice.route,
            .exact_model = demand.exact_model,
            .owner = self.owner.identity,
            .expected_revision = choice.revision,
            .now_ms = now_ms,
            .selected_at_ms = now_ms,
            .heartbeat_at_ms = now_ms,
            .expires_at_ms = leaseExpiry(now_ms),
        }, self.registry.livenessSource()) catch |err| {
            if (err == error.LeaseStateCommitUncertain) self.markCommitUncertain(pending);
            return err;
        };
        const generation = switch (outcome) {
            .acquired, .already_active => |grant| grant.generation,
        };
        self.active[self.active_count] = .{
            .exact_model = demand.exact_model,
            .lease = try OwnedHandle.init(lease_text),
            .account = try OwnedHandle.init(choice.account.text),
            .route = try OwnedHandle.init(choice.route.text),
            .generation = generation,
        };
        self.active_count += 1;
        self.finishStoreOperation(budget, .acquire) catch |err| switch (err) {
            error.LeaseWorkBudgetExceeded => return .committed_after_budget,
            else => return err,
        };
        return .within_budget;
    }

    fn transitionIndex(
        self: *LeaseRuntime,
        index: usize,
        choice: Choice,
        demand: model_demand.ModelDemand,
        now_ms: lease_state.TimestampMs,
        budget: ?*WorkBudget,
    ) !MutationOutcome {
        const current = self.active[index];
        var lease_buf: [identifiers.max_handle_len]u8 = undefined;
        const lease_text = try randomHandle(&lease_buf, "lease");
        const pending = PendingMutation{
            .kind = .transition,
            .exact_model = demand.exact_model,
            .lease = try OwnedHandle.init(lease_text),
            .account = try OwnedHandle.init(choice.account.text),
            .route = try OwnedHandle.init(choice.route.text),
            .identity = try OwnedIdentity.init(choice.identity.bytes),
            .transition_origin = .{
                .lease = current.lease,
                .account = current.account,
                .route = current.route,
                .generation = current.generation,
            },
        };
        try self.runAdmissionHooks();
        try self.armStoreWait(budget);
        const grant = self.store.transition(.{
            .current_lease = try lease_state.LeaseHandle.parse(current.lease.text()),
            .current_generation = current.generation,
            .next = .{
                .lease = try lease_state.LeaseHandle.parse(lease_text),
                .session = try lease_state.SessionHandle.parse(self.session.text()),
                .account = choice.account,
                .route = choice.route,
                .exact_model = demand.exact_model,
                .owner = self.owner.identity,
                .expected_revision = choice.revision,
                .now_ms = now_ms,
                .selected_at_ms = now_ms,
                .heartbeat_at_ms = now_ms,
                .expires_at_ms = leaseExpiry(now_ms),
            },
        }, self.registry.livenessSource()) catch |err| {
            if (err == error.LeaseStateCommitUncertain) self.markCommitUncertain(pending);
            return err;
        };
        self.active[index] = .{
            .exact_model = demand.exact_model,
            .lease = try OwnedHandle.init(lease_text),
            .account = try OwnedHandle.init(choice.account.text),
            .route = try OwnedHandle.init(choice.route.text),
            .generation = grant.generation,
        };
        self.finishStoreOperation(budget, .transition) catch |err| switch (err) {
            error.LeaseWorkBudgetExceeded => return .committed_after_budget,
            else => return err,
        };
        return .within_budget;
    }

    fn reconcilePending(
        self: *LeaseRuntime,
        candidates: []const Candidate,
        demand: model_demand.ModelDemand,
        validator: ?ChoiceValidator,
        budget: *WorkBudget,
    ) !?Selection {
        const pending_index = self.findCommitUncertain(demand.exact_model) orelse return null;
        const pending = self.commit_uncertain[pending_index];

        switch (pending.kind) {
            .acquire => if (self.findActive(demand.exact_model) != null) {
                return error.LeaseMutationReconciliationMismatch;
            },
            .transition => {
                const origin = pending.transition_origin orelse
                    return error.LeaseMutationReconciliationMismatch;
                const active_index = self.findActive(demand.exact_model) orelse
                    return error.LeaseMutationReconciliationMismatch;
                if (!activeMatchesOrigin(&self.active[active_index], &origin)) {
                    return error.LeaseMutationReconciliationMismatch;
                }
            },
        }

        const intended_candidate = exactCandidate(
            candidates,
            demand.exact_model,
            try lease_state.RouteHandle.parse(pending.route.text()),
        ) catch return error.LeaseMutationReconciliationMismatch;
        if (!candidateMatchesPending(&intended_candidate, &pending)) {
            return error.LeaseMutationReconciliationMismatch;
        }

        try self.armStoreWait(budget);
        const recovered = try self.store.reconcileSessionLease(
            try lease_state.SessionHandle.parse(self.session.text()),
            demand.exact_model,
            self.owner.identity,
        );
        try self.finishStoreOperation(budget, .reconcile);
        const canonical = recovered orelse {
            if (pending.kind != .acquire) return error.LeaseMutationReconciliationMismatch;
            self.clearCommitUncertain(pending_index);
            return null; // pre-mutation acquire failure: retry normal admission
        };

        if (!canonicalMatchesPending(&canonical, &pending)) {
            if (pending.transition_origin) |origin| {
                if (canonicalMatchesOrigin(&canonical, &origin)) {
                    self.clearCommitUncertain(pending_index);
                    return null; // watermark committed; A->B did not, so retry B
                }
            }
            return error.LeaseMutationReconciliationMismatch;
        }
        const route = canonical.route();
        if (validator) |check| try check.validate(check.ctx, route);

        const active = ActiveLease{
            .exact_model = demand.exact_model,
            .lease = try OwnedHandle.init(canonical.lease().text),
            .account = try OwnedHandle.init(canonical.account().text),
            .route = try OwnedHandle.init(route.text),
            .generation = canonical.generation,
        };
        if (self.findActive(demand.exact_model)) |index| {
            self.active[index] = active;
        } else {
            if (self.active_count == max_active_models) return error.LeaseCapacityExceeded;
            self.active[self.active_count] = active;
            self.active_count += 1;
        }
        self.clearCommitUncertain(pending_index);
        var selected = try selectionFromRoute(route, true, .complete);
        selected.reconciled_commit_uncertain = true;
        return selected;
    }

    fn findCommitUncertain(
        self: *const LeaseRuntime,
        exact_model: model_demand.ExactModel,
    ) ?usize {
        for (self.commit_uncertain[0..self.commit_uncertain_count], 0..) |pending, index| {
            if (pending.exact_model.eql(exact_model)) return index;
        }
        return null;
    }

    fn markCommitUncertain(self: *LeaseRuntime, pending: PendingMutation) void {
        if (self.findCommitUncertain(pending.exact_model)) |index| {
            self.commit_uncertain[index] = pending;
            return;
        }
        if (self.commit_uncertain_count == max_active_models) return;
        self.commit_uncertain[self.commit_uncertain_count] = pending;
        self.commit_uncertain_count += 1;
    }

    fn clearCommitUncertain(self: *LeaseRuntime, index: usize) void {
        if (index + 1 < self.commit_uncertain_count) {
            self.commit_uncertain[index] = self.commit_uncertain[self.commit_uncertain_count - 1];
        }
        self.commit_uncertain_count -= 1;
    }

    fn canonicalMatchesPending(
        canonical: *const lease_store.ReconciledLease,
        pending: *const PendingMutation,
    ) bool {
        if (!canonical.exact_model.eql(pending.exact_model) or
            !std.mem.eql(u8, canonical.lease().text, pending.lease.text()) or
            !std.mem.eql(u8, canonical.account().text, pending.account.text()) or
            !std.mem.eql(u8, canonical.route().text, pending.route.text())) return false;
        return switch (pending.kind) {
            .acquire => canonical.transition_origin_generation == null and
                canonical.transitionOriginLease() == null,
            .transition => if (pending.transition_origin) |origin|
                canonical.transition_origin_generation == origin.generation and
                    canonical.transitionOriginLease() != null and
                    std.mem.eql(
                        u8,
                        canonical.transitionOriginLease().?.text,
                        origin.lease.text(),
                    )
            else
                false,
        };
    }

    fn candidateMatchesPending(candidate: *const Candidate, pending: *const PendingMutation) bool {
        const identity = candidate.observation.identity orelse return false;
        return candidate.observation.exact_model.eql(pending.exact_model) and
            std.mem.eql(u8, candidate.observation.route.text, pending.route.text()) and
            std.mem.eql(u8, candidate.account.text, pending.account.text()) and
            std.mem.eql(u8, identity.bytes, pending.identity.text());
    }

    fn activeMatchesOrigin(active: *const ActiveLease, origin: *const PendingTransitionOrigin) bool {
        return active.generation == origin.generation and
            std.mem.eql(u8, active.lease.text(), origin.lease.text()) and
            std.mem.eql(u8, active.account.text(), origin.account.text()) and
            std.mem.eql(u8, active.route.text(), origin.route.text());
    }

    fn canonicalMatchesOrigin(
        canonical: *const lease_store.ReconciledLease,
        origin: *const PendingTransitionOrigin,
    ) bool {
        return canonical.generation == origin.generation and
            std.mem.eql(u8, canonical.lease().text, origin.lease.text()) and
            std.mem.eql(u8, canonical.account().text, origin.account.text()) and
            std.mem.eql(u8, canonical.route().text, origin.route.text());
    }

    fn renewIndex(
        self: *LeaseRuntime,
        index: usize,
        now_ms: lease_state.TimestampMs,
        budget: ?*WorkBudget,
    ) !lease_store.RenewOutcome {
        try self.armStoreWait(budget);
        const active = &self.active[index];
        const outcome = try self.store.renew(.{
            .lease = try lease_state.LeaseHandle.parse(active.lease.text()),
            .session = try lease_state.SessionHandle.parse(self.session.text()),
            .owner = self.owner.identity,
            .generation = active.generation,
            .now_ms = now_ms,
            .heartbeat_at_ms = now_ms,
            .expires_at_ms = leaseExpiry(now_ms),
        }, self.registry.livenessSource());
        try self.finishStoreOperation(budget, .renew);
        return outcome;
    }

    fn releaseIndex(self: *LeaseRuntime, index: usize, budget: ?*WorkBudget) !void {
        try self.armStoreWait(budget);
        const active = &self.active[index];
        try self.store.release(.{
            .lease = try lease_state.LeaseHandle.parse(active.lease.text()),
            .session = try lease_state.SessionHandle.parse(self.session.text()),
            .owner = self.owner.identity,
            .generation = active.generation,
        });
        try self.finishStoreOperation(budget, .release);
    }

    fn findActive(self: *const LeaseRuntime, exact_model: model_demand.ExactModel) ?usize {
        for (self.active[0..self.active_count], 0..) |active, index| {
            if (active.exact_model.eql(exact_model)) return index;
        }
        return null;
    }

    fn removeActive(self: *LeaseRuntime, index: usize) void {
        if (index + 1 < self.active_count) {
            self.active[index] = self.active[self.active_count - 1];
        }
        self.active_count -= 1;
    }

    fn runAdmissionHooks(self: *LeaseRuntime) !void {
        if (!self.admission_hook_fired) {
            self.admission_hook_fired = true;
            if (self.admission_hook) |hook| try hook.run(hook.ctx);
        }
        if (self.admission_attempt_hook) |hook| try hook.run(hook.ctx);
    }

    fn selectReactiveAlternate(
        self: *LeaseRuntime,
        candidates: []const Candidate,
        demand: model_demand.ModelDemand,
        current_route: lease_state.RouteHandle,
        now_ms: lease_state.TimestampMs,
        validator: ?ChoiceValidator,
    ) !?Selection {
        return self.selectWithoutPersistence(
            candidates,
            demand,
            now_ms,
            current_route,
            validator,
        ) catch |err| switch (err) {
            error.NoEligibleRoute => null,
            else => return err,
        };
    }

    fn finishStoreOperation(
        self: *LeaseRuntime,
        budget: ?*WorkBudget,
        operation: StoreOperation,
    ) !void {
        const request_budget = budget orelse return;
        if (self.store_operation_hook) |hook| try hook.run(hook.ctx, operation);
        _ = try request_budget.remainingNs();
    }

    fn armStoreWait(self: *LeaseRuntime, budget: ?*WorkBudget) !void {
        var wait = self.advisory_wait;
        if (budget) |request_budget| {
            const remaining_ns = try request_budget.remainingNs();
            wait.timeout_ns = @min(wait.timeout_ns, remaining_ns);
            wait.poll_interval_ns = @min(wait.poll_interval_ns, remaining_ns);
        }
        _ = self.store.replaceWaitOptions(wait);
    }
};

const ReleaseAllJob = struct {
    runtime: *LeaseRuntime,
    budget: *WorkBudget,
    failure: ?anyerror = null,

    fn run(self: *ReleaseAllJob) void {
        self.runtime.releaseAllInline(self.budget) catch |err| {
            self.failure = err;
        };
    }
};

pub const testing = if (builtin.is_test) struct {
    const FocusedDiagnosticsJob = struct {
        root: []const u8,
        failure: ?anyerror = null,
        result: bool = false,

        fn run(self: *FocusedDiagnosticsJob) void {
            self.result = runFocusedDiagnosticsInline(self.root) catch |err| {
                self.failure = err;
                return;
            };
        }
    };

    const LockRaceHook = struct {
        root: []const u8,
        target_call: usize,
        calls: usize = 0,
        holder: ?std.fs.File = null,

        fn run(raw: *anyopaque) !void {
            const self: *LockRaceHook = @ptrCast(@alignCast(raw));
            self.calls += 1;
            if (self.calls != self.target_call) return;
            const path = try std.fs.path.join(
                std.heap.page_allocator,
                &.{ self.root, "broker-leases-v2.lock" },
            );
            defer std.heap.page_allocator.free(path);
            var holder = try std.fs.createFileAbsolute(path, .{
                .read = true,
                .truncate = false,
                .mode = 0o600,
            });
            errdefer holder.close();
            if (!(try lock_wait.tryLockFile(holder))) return error.LeaseRaceHookLockUnavailable;
            self.holder = holder;
        }

        fn release(self: *LockRaceHook) void {
            if (self.holder) |holder| {
                holder.unlock();
                holder.close();
                self.holder = null;
            }
        }
    };

    const OwnerLockRaceHook = struct {
        root: []const u8,
        holder: ?std.fs.File = null,

        fn run(raw: *anyopaque) !void {
            const self: *OwnerLockRaceHook = @ptrCast(@alignCast(raw));
            const path = try std.fs.path.join(
                std.heap.page_allocator,
                &.{ self.root, "lease-owners-v1", ".registry.lock" },
            );
            defer std.heap.page_allocator.free(path);
            var holder = try std.fs.createFileAbsolute(path, .{
                .read = true,
                .truncate = false,
                .mode = 0o600,
            });
            errdefer holder.close();
            if (!(try lock_wait.tryLockFile(holder))) return error.LeaseRaceHookLockUnavailable;
            self.holder = holder;
        }

        fn release(self: *OwnerLockRaceHook) void {
            if (self.holder) |holder| {
                holder.unlock();
                holder.close();
                self.holder = null;
            }
        }
    };

    const CommitUncertainHook = struct {
        target_admission: usize,
        admissions: usize = 0,
        armed: bool = false,
        failed: bool = false,

        fn arm(raw: *anyopaque) !void {
            const self: *CommitUncertainHook = @ptrCast(@alignCast(raw));
            self.admissions += 1;
            if (self.admissions == self.target_admission) self.armed = true;
        }

        fn afterRename(raw: *anyopaque) !void {
            const self: *CommitUncertainHook = @ptrCast(@alignCast(raw));
            if (!self.armed or self.failed) return;
            self.failed = true;
            self.armed = false;
            return error.SyntheticPostRenameFailure;
        }
    };

    const ControlledWallClock = struct {
        now_ms: lease_state.TimestampMs = 0,

        fn read(
            raw: ?*const anyopaque,
            _: ?lease_state.TimestampMs,
        ) anyerror!lease_state.TimestampMs {
            const self: *const ControlledWallClock = @ptrCast(@alignCast(raw.?));
            return self.now_ms;
        }
    };

    const ArmWatermarkFailure = struct {
        clock: *ControlledWallClock,
        commit: *CommitUncertainHook,
        target_admission: usize,
        admissions: usize = 0,

        fn run(raw: *anyopaque) !void {
            const self: *ArmWatermarkFailure = @ptrCast(@alignCast(raw));
            self.admissions += 1;
            if (self.admissions != self.target_admission) return;
            self.clock.now_ms = 1;
            self.commit.armed = true;
        }
    };

    const ProjectionCounter = struct {
        calls: usize = 0,

        fn run(raw: *anyopaque) !void {
            const self: *ProjectionCounter = @ptrCast(@alignCast(raw));
            self.calls += 1;
        }
    };

    const InjectedClock = struct {
        now_ns: i128 = 0,

        fn now(raw: ?*anyopaque) i128 {
            const self: *InjectedClock = @ptrCast(@alignCast(raw.?));
            return self.now_ns;
        }

        fn workClock(self: *InjectedClock) WorkClock {
            return .{ .ctx = @ptrCast(self), .nowFn = now };
        }
    };

    const FinalStoreAdvance = struct {
        clock: *InjectedClock,
        target: StoreOperation,
        total_calls: usize = 0,
        target_calls: usize = 0,

        fn run(raw: *anyopaque, operation: StoreOperation) !void {
            const self: *FinalStoreAdvance = @ptrCast(@alignCast(raw));
            self.total_calls += 1;
            if (operation != self.target) return;
            self.target_calls += 1;
            self.clock.now_ns += @as(i128, advisory_lock_timeout_ns + 1);
        }
    };

    /// Narrow source-only diagnostics used by the TIN-3320 focused root and
    /// Stage 2. The worker stack contains the large fixed lease projections;
    /// no provider, credential, installer, or service seam is reachable.
    pub fn runFocusedDiagnostics(root: []const u8) !bool {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return;
        var job = FocusedDiagnosticsJob{ .root = root };
        const thread = try std.Thread.spawn(
            .{ .stack_size = release_stack_bytes },
            FocusedDiagnosticsJob.run,
            .{&job},
        );
        thread.join();
        if (job.failure) |err| return err;
        return job.result;
    }

    fn runFocusedDiagnosticsInline(root: []const u8) !bool {
        try staleAcquireChoiceRecomputesReactively(root);
        try staleTransitionChoiceRecomputesReactively(root);
        try finalAcquireCommitKeepsPersistedRoute(root);
        try finalTransitionCommitKeepsPersistedRoute(root);
        try registrationContentionReturnsBeforeProjection(root);
        try ownerRegistryContentionDegradesReactively(root);
        std.testing.expect(try lease_owner.testing.runControlCustodyDiagnostics(root)) catch |err| {
            std.log.err("TIN-3320 owner control custody diagnostic failed: {s}", .{@errorName(err)});
            return err;
        };
        acquireCommitUncertainReconcilesCanonicalLease(root) catch |err| {
            std.log.err("TIN-3320 acquire reconciliation diagnostic failed: {s}", .{@errorName(err)});
            return err;
        };
        transitionWatermarkUncertainRetriesExactMutation(root) catch |err| {
            std.log.err("TIN-3320 transition watermark diagnostic failed: {s}", .{@errorName(err)});
            return err;
        };
        transitionFinalMutationUncertainReconcilesExactIntent(root) catch |err| {
            std.log.err("TIN-3320 transition final-mutation diagnostic failed: {s}", .{@errorName(err)});
            return err;
        };
        try std.testing.expect(!isAdvisoryUnavailableError(error.InvalidLeaseState));
        try std.testing.expect(!isAdvisoryUnavailableError(error.InsecureLeaseStateCustody));
        try std.testing.expect(!isAdvisoryUnavailableError(error.InsecureLeaseOwnerCustody));
        try std.testing.expect(!isAdvisoryUnavailableError(error.InvalidClockSample));
        try std.testing.expect(!isAdvisoryUnavailableError(error.LeaseStateCommitUncertain));
        return true;
    }

    fn immediateOptions() Options {
        var options = testOptions();
        options.advisory_wait = .{
            .poll_interval_ns = 0,
            .heartbeat_ns = std.time.ns_per_hour,
            .timeout_ns = 0,
        };
        return options;
    }

    fn diagnosticRoot(parent: []const u8, name: []const u8) ![]u8 {
        const root = try std.fs.path.join(std.testing.allocator, &.{ parent, name });
        errdefer std.testing.allocator.free(root);
        try std.fs.makeDirAbsolute(root);
        return root;
    }

    fn staleAcquireChoiceRecomputesReactively(parent: []const u8) !void {
        const root = try diagnosticRoot(parent, "stale-acquire");
        defer std.testing.allocator.free(root);
        const demand = try model_demand.ModelDemand.init("claude-opus-4");
        const route_a = testCandidate("route-a", "account-a", "identity-a", demand.exact_model);
        const route_b = testCandidate("route-b", "account-b", "identity-b", demand.exact_model);

        var seeder = try LeaseRuntime.init(std.testing.allocator, root, testOptions());
        defer seeder.deinit();
        const seeded = try seeder.selectAndAcquire(&.{route_a}, demand, 1_000);
        try std.testing.expectEqualStrings("route-a", seeded.route().text);

        var hook = LockRaceHook{ .root = root, .target_call = 1 };
        var options = immediateOptions();
        options.before_admission_attempt = .{ .ctx = @ptrCast(&hook), .run = LockRaceHook.run };
        var runtime = try LeaseRuntime.init(std.testing.allocator, root, options);
        defer runtime.deinit();
        defer hook.release();

        const selected = try runtime.selectAndAcquire(&.{ route_b, route_a }, demand, 1_001);
        try std.testing.expectEqualStrings("route-a", selected.route().text);
        try std.testing.expect(!selected.persisted);
        try std.testing.expectEqual(@as(usize, 0), runtime.activeLeaseCount());
        try std.testing.expectEqual(@as(usize, 1), hook.calls);
        try std.testing.expect(hook.holder != null);
    }

    fn staleTransitionChoiceRecomputesReactively(parent: []const u8) !void {
        const root = try diagnosticRoot(parent, "stale-transition");
        defer std.testing.allocator.free(root);
        const demand = try model_demand.ModelDemand.init("claude-opus-4");
        const current = testCandidate("route-current", "account-current", "identity-current", demand.exact_model);
        const route_a = testCandidate("route-a", "account-a", "identity-a", demand.exact_model);
        const route_b = testCandidate("route-b", "account-b", "identity-b", demand.exact_model);

        var seeder = try LeaseRuntime.init(std.testing.allocator, root, testOptions());
        defer seeder.deinit();
        _ = try seeder.selectAndAcquire(&.{route_a}, demand, 2_000);

        var hook = LockRaceHook{ .root = root, .target_call = 2 };
        var options = immediateOptions();
        options.before_admission_attempt = .{ .ctx = @ptrCast(&hook), .run = LockRaceHook.run };
        var runtime = try LeaseRuntime.init(std.testing.allocator, root, options);
        defer runtime.deinit();
        defer hook.release();
        const initial = try runtime.selectAndAcquire(&.{current}, demand, 2_001);
        try std.testing.expect(initial.persisted);

        const selected = (try runtime.selectAndTransition(
            &.{ current, route_b, route_a },
            demand,
            current.observation.route,
            2_002,
        )) orelse return error.ExpectedReactiveAlternate;
        try std.testing.expectEqualStrings("route-a", selected.route().text);
        try std.testing.expect(!selected.persisted);
        try std.testing.expectEqual(@as(usize, 1), runtime.activeLeaseCount());
        try std.testing.expectEqual(@as(usize, 2), hook.calls);
        try std.testing.expect(hook.holder != null);
    }

    fn finalAcquireCommitKeepsPersistedRoute(parent: []const u8) !void {
        const root = try diagnosticRoot(parent, "final-acquire");
        defer std.testing.allocator.free(root);
        const demand = try model_demand.ModelDemand.init("claude-opus-4");
        const route_a = testCandidate("route-a", "account-a", "identity-a", demand.exact_model);
        const route_b = testCandidate("route-b", "account-b", "identity-b", demand.exact_model);
        var seeder = try LeaseRuntime.init(std.testing.allocator, root, testOptions());
        defer seeder.deinit();
        const seeded = try seeder.selectAndAcquire(&.{route_a}, demand, 3_000);
        try std.testing.expectEqualStrings("route-a", seeded.route().text);
        var clock = InjectedClock{};
        var advance = FinalStoreAdvance{ .clock = &clock, .target = .acquire };
        var options = testOptions();
        options.work_clock = clock.workClock();
        options.after_store_operation = .{ .ctx = @ptrCast(&advance), .run = FinalStoreAdvance.run };
        var runtime = try LeaseRuntime.init(std.testing.allocator, root, options);
        defer runtime.deinit();

        const selected = try runtime.selectAndAcquire(&.{ route_b, route_a }, demand, 3_001);
        try std.testing.expectEqualStrings("route-b", selected.route().text);
        try std.testing.expect(selected.persisted);
        try std.testing.expect(selected.committed_after_budget);
        try std.testing.expectEqual(@as(usize, 1), runtime.activeLeaseCount());
        try std.testing.expectEqualStrings("route-b", activeRoute(&runtime, demand.exact_model).?.text);
        try std.testing.expectEqual(@as(usize, 4), advance.total_calls);
        try std.testing.expectEqual(@as(usize, 1), advance.target_calls);
    }

    fn finalTransitionCommitKeepsPersistedRoute(parent: []const u8) !void {
        const root = try diagnosticRoot(parent, "final-transition");
        defer std.testing.allocator.free(root);
        const demand = try model_demand.ModelDemand.init("claude-opus-4");
        const current = testCandidate("route-current", "account-current", "identity-current", demand.exact_model);
        const route_a = testCandidate("route-a", "account-a", "identity-a", demand.exact_model);
        const route_b = testCandidate("route-b", "account-b", "identity-b", demand.exact_model);
        var seeder = try LeaseRuntime.init(std.testing.allocator, root, testOptions());
        defer seeder.deinit();
        _ = try seeder.selectAndAcquire(&.{route_a}, demand, 4_000);
        var clock = InjectedClock{};
        var advance = FinalStoreAdvance{ .clock = &clock, .target = .transition };
        var options = testOptions();
        options.work_clock = clock.workClock();
        options.after_store_operation = .{ .ctx = @ptrCast(&advance), .run = FinalStoreAdvance.run };
        var runtime = try LeaseRuntime.init(std.testing.allocator, root, options);
        defer runtime.deinit();
        const initial = try runtime.selectAndAcquire(&.{current}, demand, 4_001);
        try std.testing.expect(initial.persisted);
        var registrar = try Store.init(std.testing.allocator, root, testOptions().store);
        defer registrar.deinit();
        try registrar.registerRoutes(&.{
            .{ .route = route_a.observation.route, .exact_model = demand.exact_model },
            .{ .route = route_b.observation.route, .exact_model = demand.exact_model },
        });

        const selected = (try runtime.selectAndTransition(
            &.{ current, route_b, route_a },
            demand,
            current.observation.route,
            4_002,
        )) orelse return error.ExpectedReactiveAlternate;
        try std.testing.expectEqualStrings("route-b", selected.route().text);
        try std.testing.expect(selected.persisted);
        try std.testing.expect(selected.committed_after_budget);
        try std.testing.expectEqual(@as(usize, 1), runtime.activeLeaseCount());
        try std.testing.expectEqualStrings("route-b", activeRoute(&runtime, demand.exact_model).?.text);
        try std.testing.expectEqual(@as(usize, 7), advance.total_calls);
        try std.testing.expectEqual(@as(usize, 1), advance.target_calls);
    }

    fn registrationContentionReturnsBeforeProjection(parent: []const u8) !void {
        const root = try diagnosticRoot(parent, "registration-contention");
        defer std.testing.allocator.free(root);
        const demand = try model_demand.ModelDemand.init("claude-opus-4");
        const route_a = testCandidate("route-a", "account-a", "identity-a", demand.exact_model);
        const route_b = testCandidate("route-b", "account-b", "identity-b", demand.exact_model);
        var lock_hook = LockRaceHook{ .root = root, .target_call = 1 };
        var projection = ProjectionCounter{};
        var options = immediateOptions();
        options.before_registration = .{ .ctx = @ptrCast(&lock_hook), .run = LockRaceHook.run };
        options.before_projection = .{ .ctx = @ptrCast(&projection), .run = ProjectionCounter.run };
        var runtime = try LeaseRuntime.init(std.testing.allocator, root, options);
        defer runtime.deinit();
        defer lock_hook.release();

        const selected = try runtime.selectAndAcquire(&.{ route_b, route_a }, demand, 5_000);
        try std.testing.expectEqualStrings("route-a", selected.route().text);
        try std.testing.expect(!selected.persisted);
        try std.testing.expectEqual(@as(usize, 0), runtime.activeLeaseCount());
        try std.testing.expectEqual(@as(usize, 1), lock_hook.calls);
        try std.testing.expect(lock_hook.holder != null);
        try std.testing.expectEqual(@as(usize, 0), projection.calls);
    }

    fn ownerRegistryContentionDegradesReactively(parent: []const u8) !void {
        const root = try diagnosticRoot(parent, "owner-registry-contention");
        defer std.testing.allocator.free(root);
        const demand = try model_demand.ModelDemand.init("claude-opus-4");
        const route_b = testCandidate("route-b", "account-b", "identity-b", demand.exact_model);
        const route_a = testCandidate("route-a", "account-a", "identity-a", demand.exact_model);
        var hook = OwnerLockRaceHook{ .root = root };
        var options = immediateOptions();
        options.before_owner_cleanup = .{ .ctx = @ptrCast(&hook), .run = OwnerLockRaceHook.run };
        var runtime = try LeaseRuntime.init(std.testing.allocator, root, options);
        defer runtime.deinit();
        defer hook.release();

        const selected = try runtime.selectAndAcquire(&.{ route_b, route_a }, demand, 5_100);
        try std.testing.expectEqualStrings("route-a", selected.route().text);
        try std.testing.expect(!selected.persisted);
        try std.testing.expectEqual(@as(usize, 0), runtime.activeLeaseCount());
        try std.testing.expect(hook.holder != null);
    }

    fn acquireCommitUncertainReconcilesCanonicalLease(parent: []const u8) !void {
        const root = try diagnosticRoot(parent, "acquire-commit-uncertain");
        defer std.testing.allocator.free(root);
        const demand = try model_demand.ModelDemand.init("claude-opus-4");
        const route = testCandidate("route-a", "account-a", "identity-a", demand.exact_model);
        var hook = CommitUncertainHook{ .target_admission = 1 };
        var options = testOptions();
        options.before_admission_attempt = .{ .ctx = @ptrCast(&hook), .run = CommitUncertainHook.arm };
        options.store.post_rename_hook = .{ .ctx = @ptrCast(&hook), .run = CommitUncertainHook.afterRename };
        var runtime = try LeaseRuntime.init(std.testing.allocator, root, options);
        defer runtime.deinit();

        try std.testing.expectError(
            error.LeaseStateCommitUncertain,
            runtime.selectAndAcquire(&.{route}, demand, 0),
        );
        try std.testing.expectEqual(@as(usize, 0), runtime.activeLeaseCount());
        const recovered = try runtime.selectAndAcquire(&.{route}, demand, 0);
        try std.testing.expect(recovered.persisted);
        try std.testing.expect(recovered.reconciled_commit_uncertain);
        try std.testing.expectEqualStrings("route-a", recovered.route().text);
        try std.testing.expectEqual(@as(usize, 1), runtime.activeLeaseCount());
    }

    fn transitionWatermarkUncertainRetriesExactMutation(parent: []const u8) !void {
        const root = try diagnosticRoot(parent, "transition-watermark-uncertain");
        defer std.testing.allocator.free(root);
        const demand = try model_demand.ModelDemand.init("claude-opus-4");
        const current = testCandidate("route-current", "account-current", "identity-current", demand.exact_model);
        const alternate = testCandidate("route-alternate", "account-alternate", "identity-alternate", demand.exact_model);
        var clock = ControlledWallClock{};
        var hook = CommitUncertainHook{ .target_admission = std.math.maxInt(usize) };
        var arm = ArmWatermarkFailure{
            .clock = &clock,
            .commit = &hook,
            .target_admission = 2,
        };
        var options = testOptions();
        options.store.time = .{ .ctx = @ptrCast(&clock), .read = ControlledWallClock.read };
        options.before_admission_attempt = .{ .ctx = @ptrCast(&arm), .run = ArmWatermarkFailure.run };
        options.store.post_rename_hook = .{ .ctx = @ptrCast(&hook), .run = CommitUncertainHook.afterRename };
        var runtime = try LeaseRuntime.init(std.testing.allocator, root, options);
        defer runtime.deinit();

        const initial = try runtime.selectAndAcquire(&.{current}, demand, 0);
        try std.testing.expect(initial.persisted);
        var registrar = try Store.init(std.testing.allocator, root, testOptions().store);
        defer registrar.deinit();
        try registrar.registerRoute(.{
            .route = alternate.observation.route,
            .exact_model = demand.exact_model,
        });
        try std.testing.expectError(
            error.LeaseStateCommitUncertain,
            runtime.selectAndTransition(
                &.{ current, alternate },
                demand,
                current.observation.route,
                1, // forces the pre-mutation watermark persist
            ),
        );
        try std.testing.expectEqualStrings("route-current", activeRoute(&runtime, demand.exact_model).?.text);
        try std.testing.expectEqual(@as(usize, 1), runtime.commit_uncertain_count);
        try std.testing.expect(hook.failed);
        try std.testing.expectEqual(@as(usize, 2), arm.admissions);
        const pending = runtime.commit_uncertain[0];
        const canonical = (try runtime.store.reconcileSessionLease(
            try lease_state.SessionHandle.parse(runtime.session.text()),
            demand.exact_model,
            runtime.owner.identity,
        )).?;
        try std.testing.expect(LeaseRuntime.canonicalMatchesOrigin(&canonical, &pending.transition_origin.?));
        try std.testing.expect(!LeaseRuntime.canonicalMatchesPending(&canonical, &pending));

        const retried = (try runtime.selectAndTransition(
            &.{ current, alternate },
            demand,
            current.observation.route,
            1,
        )) orelse return error.ExpectedRetriedAlternate;
        try std.testing.expect(retried.persisted);
        try std.testing.expect(!retried.reconciled_commit_uncertain);
        try std.testing.expectEqualStrings("route-alternate", retried.route().text);
        try std.testing.expectEqualStrings("route-alternate", activeRoute(&runtime, demand.exact_model).?.text);
    }

    fn transitionFinalMutationUncertainReconcilesExactIntent(parent: []const u8) !void {
        const root = try diagnosticRoot(parent, "transition-final-uncertain");
        defer std.testing.allocator.free(root);
        const demand = try model_demand.ModelDemand.init("claude-opus-4");
        const current = testCandidate("route-current", "account-current", "identity-current", demand.exact_model);
        const alternate = testCandidate("route-alternate", "account-alternate", "identity-alternate", demand.exact_model);
        var hook = CommitUncertainHook{ .target_admission = 2 };
        var options = testOptions();
        options.before_admission_attempt = .{ .ctx = @ptrCast(&hook), .run = CommitUncertainHook.arm };
        options.store.post_rename_hook = .{ .ctx = @ptrCast(&hook), .run = CommitUncertainHook.afterRename };
        var runtime = try LeaseRuntime.init(std.testing.allocator, root, options);
        defer runtime.deinit();

        const initial = try runtime.selectAndAcquire(&.{current}, demand, 0);
        try std.testing.expect(initial.persisted);
        var registrar = try Store.init(std.testing.allocator, root, testOptions().store);
        defer registrar.deinit();
        try registrar.registerRoute(.{
            .route = alternate.observation.route,
            .exact_model = demand.exact_model,
        });
        try std.testing.expectError(
            error.LeaseStateCommitUncertain,
            runtime.selectAndTransition(
                &.{ current, alternate },
                demand,
                current.observation.route,
                0,
            ),
        );
        try std.testing.expectEqualStrings("route-current", activeRoute(&runtime, demand.exact_model).?.text);
        try std.testing.expectEqual(@as(usize, 1), runtime.commit_uncertain_count);
        try std.testing.expect(hook.failed);
        const pending = runtime.commit_uncertain[0];
        try std.testing.expectEqual(.transition, pending.kind);
        try std.testing.expectEqualStrings("route-alternate", pending.route.text());
        try std.testing.expectEqualStrings("account-alternate", pending.account.text());
        try std.testing.expectEqualStrings("identity-alternate", pending.identity.text());
        try std.testing.expectEqualStrings("route-current", pending.transition_origin.?.route.text());
        try std.testing.expect(LeaseRuntime.candidateMatchesPending(&alternate, &pending));
        const active_index = runtime.findActive(demand.exact_model) orelse
            return error.ExpectedActiveOrigin;
        try std.testing.expect(LeaseRuntime.activeMatchesOrigin(
            &runtime.active[active_index],
            &pending.transition_origin.?,
        ));
        const canonical = (try runtime.store.reconcileSessionLease(
            try lease_state.SessionHandle.parse(runtime.session.text()),
            demand.exact_model,
            runtime.owner.identity,
        )).?;
        try std.testing.expect(LeaseRuntime.canonicalMatchesPending(&canonical, &pending));
        var wrong_lease = pending;
        wrong_lease.lease = try OwnedHandle.init("lease-targeted-broken-form");
        try std.testing.expect(!LeaseRuntime.canonicalMatchesPending(&canonical, &wrong_lease));
        var wrong_kind = pending;
        wrong_kind.kind = .acquire;
        try std.testing.expect(!LeaseRuntime.canonicalMatchesPending(&canonical, &wrong_kind));
        var wrong_account = pending;
        wrong_account.account = try OwnedHandle.init("account-targeted-broken-form");
        try std.testing.expect(!LeaseRuntime.canonicalMatchesPending(&canonical, &wrong_account));
        var wrong_route = pending;
        wrong_route.route = try OwnedHandle.init("route-targeted-broken-form");
        try std.testing.expect(!LeaseRuntime.canonicalMatchesPending(&canonical, &wrong_route));
        var wrong_model = pending;
        wrong_model.exact_model = (try model_demand.ModelDemand.init("claude-sonnet-4")).exact_model;
        try std.testing.expect(!LeaseRuntime.canonicalMatchesPending(&canonical, &wrong_model));
        var wrong_candidate_identity = alternate;
        wrong_candidate_identity.observation.identity =
            route_observation.IdentityEvidence.fromBorrowed("identity-targeted-broken-form");
        try std.testing.expect(!LeaseRuntime.candidateMatchesPending(
            &wrong_candidate_identity,
            &pending,
        ));
        var wrong_origin = pending;
        var mutated_origin = wrong_origin.transition_origin.?;
        mutated_origin.generation += 1;
        wrong_origin.transition_origin = mutated_origin;
        try std.testing.expect(!LeaseRuntime.canonicalMatchesPending(&canonical, &wrong_origin));
        var wrong_origin_account = pending.transition_origin.?;
        wrong_origin_account.account = try OwnedHandle.init("account-origin-broken-form");
        try std.testing.expect(!LeaseRuntime.activeMatchesOrigin(
            &runtime.active[active_index],
            &wrong_origin_account,
        ));
        var wrong_origin_route = pending.transition_origin.?;
        wrong_origin_route.route = try OwnedHandle.init("route-origin-broken-form");
        try std.testing.expect(!LeaseRuntime.activeMatchesOrigin(
            &runtime.active[active_index],
            &wrong_origin_route,
        ));
        const recovered = (try runtime.selectAndTransition(
            &.{ current, alternate },
            demand,
            current.observation.route,
            0,
        )) orelse return error.ExpectedReconciledAlternate;
        try std.testing.expect(recovered.persisted);
        try std.testing.expect(recovered.reconciled_commit_uncertain);
        try std.testing.expectEqualStrings("route-alternate", recovered.route().text);
        try std.testing.expectEqualStrings("route-alternate", activeRoute(&runtime, demand.exact_model).?.text);
    }

    fn activeRoute(runtime: *const LeaseRuntime, exact_model: model_demand.ExactModel) ?lease_state.RouteHandle {
        const index = runtime.findActive(exact_model) orelse return null;
        return lease_state.RouteHandle.parse(runtime.active[index].route.text()) catch null;
    }

    pub fn initWithOwner(
        allocator: std.mem.Allocator,
        absolute_broker_root: []const u8,
        options: Options,
        owner: lease_store.OwnerIdentity,
        session: []const u8,
    ) !LeaseRuntime {
        return LeaseRuntime.initInternal(allocator, absolute_broker_root, options, owner, session);
    }

    pub fn projectedLoadsForRoutes(
        runtime: *LeaseRuntime,
        demand: model_demand.ModelDemand,
        now_ms: lease_state.TimestampMs,
        routes: [2]lease_state.RouteHandle,
    ) ?[2]u64 {
        return runtime.projectedLoadsForRoutes(demand, now_ms, routes);
    }

    pub fn ownerCustodyExists(
        runtime: *const LeaseRuntime,
        owner: lease_store.OwnerIdentity,
    ) !bool {
        return lease_owner.testing.ownerPathExists(&runtime.registry, owner);
    }

    pub fn snapshotBytesAlloc(
        runtime: *const LeaseRuntime,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        const path = try std.fs.path.join(allocator, &.{ runtime.store.root, "broker-leases-v2.json" });
        defer allocator.free(path);
        return std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024);
    }
} else struct {};

fn validateInput(candidates: []const Candidate, demand: model_demand.ModelDemand, now_ms: i64) !void {
    if (candidates.len == 0 or candidates.len > 256) return error.InvalidRouteCatalog;
    if (!demand.isValid()) return error.InvalidExactModel;
    if (now_ms < 0 or now_ms > lease_state.max_timestamp_ms) return error.InvalidClockSample;
    for (candidates) |candidate| {
        _ = try lease_state.RouteHandle.parse(candidate.observation.route.text);
        _ = try lease_state.AccountHandle.parse(candidate.account.text);
        if (!candidate.observation.exact_model.isValid()) return error.InvalidExactModel;
    }
}

fn exactCandidate(
    candidates: []const Candidate,
    exact_model: model_demand.ExactModel,
    route: lease_state.RouteHandle,
) !Candidate {
    var result: ?Candidate = null;
    for (candidates) |candidate| {
        if (!candidate.observation.exact_model.eql(exact_model)) continue;
        if (!std.mem.eql(u8, candidate.observation.route.text, route.text)) continue;
        if (result) |existing| {
            if (!std.mem.eql(u8, existing.account.text, candidate.account.text)) {
                return error.ConflictingRouteAccount;
            }
        } else {
            result = candidate;
        }
    }
    return result orelse error.UnmappedRoute;
}

fn selectionFromChoice(choice: Choice, persisted: bool) !Selection {
    return selectionFromRoute(choice.route, persisted, choice.quality);
}

fn selectionFromRoute(
    route: lease_state.RouteHandle,
    persisted: bool,
    quality: lease_state.ProjectionQuality,
) !Selection {
    _ = try lease_state.RouteHandle.parse(route.text);
    var result = Selection{ .persisted = persisted, .quality = quality };
    @memcpy(result.route_buf[0..route.text.len], route.text);
    result.route_len = @intCast(route.text.len);
    return result;
}

fn randomHandle(buffer: []u8, prefix: []const u8) ![]const u8 {
    var entropy: [16]u8 = undefined;
    defer std.crypto.secureZero(u8, &entropy);
    std.crypto.random.bytes(&entropy);
    const entropy_hex = std.fmt.bytesToHex(entropy, .lower);
    return std.fmt.bufPrint(buffer, "{s}-{s}", .{ prefix, entropy_hex });
}

fn leaseExpiry(now_ms: lease_state.TimestampMs) lease_state.TimestampMs {
    return std.math.add(lease_state.TimestampMs, now_ms, lease_ttl_ms) catch
        lease_state.max_timestamp_ms;
}

test "TIN-3320 advisory-unavailable classifier preserves coherence failures" {
    try std.testing.expect(isAdvisoryUnavailableError(error.LeaseStateUnavailable));
    try std.testing.expect(isAdvisoryUnavailableError(error.LockWaitTimeout));
    try std.testing.expect(isAdvisoryUnavailableError(error.LeaseWorkBudgetExceeded));
    try std.testing.expect(!isAdvisoryUnavailableError(error.MonotonicClockUnavailable));
    try std.testing.expect(!isAdvisoryUnavailableError(error.NoSpaceLeft));
    try std.testing.expect(!isAdvisoryUnavailableError(error.LeaseStateCommitUncertain));
    try std.testing.expect(!isAdvisoryUnavailableError(error.StateChanged));
    try std.testing.expect(!isAdvisoryUnavailableError(error.InvalidLeaseState));
    try std.testing.expect(!isAdvisoryUnavailableError(error.OwnerMismatch));
    try std.testing.expect(!isAdvisoryUnavailableError(error.LeaseStatePathChanged));
}

const SharedRuntimeSpreadJob = struct {
    a: *LeaseRuntime,
    b: *LeaseRuntime,
    observations: []const Candidate,
    demand: model_demand.ModelDemand,
    failure: ?anyerror = null,

    fn run(self: *SharedRuntimeSpreadJob) void {
        self.runInline() catch |err| {
            self.failure = err;
        };
    }

    fn runInline(self: *SharedRuntimeSpreadJob) !void {
        const selected_a = try self.a.selectAndAcquire(self.observations, self.demand, 1_000);
        const selected_b = try self.b.selectAndAcquire(self.observations, self.demand, 1_001);
        try std.testing.expect(!std.mem.eql(u8, selected_a.route().text, selected_b.route().text));
        try std.testing.expectEqual(@as(usize, 1), self.a.activeLeaseCount());
        try std.testing.expectEqual(@as(usize, 1), self.b.activeLeaseCount());
        try self.a.releaseAll();
        try self.b.releaseAll();
        try std.testing.expectEqual(@as(usize, 0), self.a.activeLeaseCount());
        try std.testing.expectEqual(@as(usize, 0), self.b.activeLeaseCount());
    }
};

test "shared runtime leases spread equal routes and release cleanly" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const demand = try model_demand.ModelDemand.init("claude-opus-4");
    const observations = [_]Candidate{
        testCandidate("route-a", "account-a", "identity-a", demand.exact_model),
        testCandidate("route-b", "account-b", "identity-b", demand.exact_model),
    };

    const a = try std.testing.allocator.create(LeaseRuntime);
    defer std.testing.allocator.destroy(a);
    a.* = try LeaseRuntime.init(std.testing.allocator, root, testOptions());
    defer a.deinit();
    const b = try std.testing.allocator.create(LeaseRuntime);
    defer std.testing.allocator.destroy(b);
    b.* = try LeaseRuntime.init(std.testing.allocator, root, testOptions());
    defer b.deinit();

    var job = SharedRuntimeSpreadJob{
        .a = a,
        .b = b,
        .observations = &observations,
        .demand = demand,
    };
    const thread = try std.Thread.spawn(
        .{ .stack_size = request_stack_regression_bytes },
        SharedRuntimeSpreadJob.run,
        .{&job},
    );
    thread.join();
    if (job.failure) |err| return err;
}

test "idle live owner keeps its sticky lease beyond the fallback expiry" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const demand = try model_demand.ModelDemand.init("claude-opus-4");
    const candidates = [_]Candidate{
        testCandidate("route-a", "account-a", "identity-a", demand.exact_model),
        testCandidate("route-b", "account-b", "identity-b", demand.exact_model),
    };
    var runtime = try LeaseRuntime.init(std.testing.allocator, root, testOptions());
    defer runtime.deinit();
    const initial = try runtime.selectAndAcquire(&candidates, demand, 1_000);
    try std.testing.expectEqual(@as(?u64, 1), runtime.projectedActiveLeaseCount(demand, 120_999));
    try std.testing.expectEqual(@as(?u64, 1), runtime.projectedActiveLeaseCount(demand, 121_000));

    const reacquired = try runtime.selectAndAcquire(&candidates, demand, 121_000);
    try std.testing.expect(reacquired.persisted);
    try std.testing.expectEqualStrings(initial.route().text, reacquired.route().text);
    try std.testing.expectEqual(@as(usize, 1), runtime.activeLeaseCount());
    try std.testing.expectEqual(@as(?u64, 1), runtime.projectedActiveLeaseCount(demand, 121_000));
}

const RevisionRaceHook = struct {
    store: *Store,
    demand: model_demand.ModelDemand,

    fn run(raw: *anyopaque) !void {
        const self: *RevisionRaceHook = @ptrCast(@alignCast(raw));
        try self.store.registerRoute(.{
            .route = try lease_state.RouteHandle.parse("route-revision-race"),
            .exact_model = self.demand.exact_model,
        });
    }
};

test "one concurrent admission mutation forces bounded reprojection" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const demand = try model_demand.ModelDemand.init("claude-opus-4");
    const candidates = [_]Candidate{
        testCandidate("route-a", "account-a", "identity-a", demand.exact_model),
        testCandidate("route-b", "account-b", "identity-b", demand.exact_model),
    };
    var mutator = try Store.init(std.testing.allocator, root, testOptions().store);
    defer mutator.deinit();
    var hook = RevisionRaceHook{ .store = &mutator, .demand = demand };
    var runtime = try LeaseRuntime.init(std.testing.allocator, root, .{
        .store = testOptions().store,
        .before_first_admission = .{ .ctx = @ptrCast(&hook), .run = RevisionRaceHook.run },
    });
    defer runtime.deinit();

    const selected = try runtime.selectAndAcquire(&candidates, demand, 5_000);
    try std.testing.expect(selected.persisted);
    try std.testing.expectEqual(@as(usize, 1), runtime.reprojectionCount());
    try std.testing.expectEqual(@as(usize, 1), runtime.activeLeaseCount());
}

fn requestedTestTime(_: ?*const anyopaque, requested_ms: ?lease_state.TimestampMs) !lease_state.TimestampMs {
    return requested_ms orelse 0;
}

fn testOptions() Options {
    return .{ .store = .{ .time = .{ .read = requestedTestTime } } };
}

fn testCandidate(
    route: []const u8,
    account: []const u8,
    identity: []const u8,
    exact_model: model_demand.ExactModel,
) Candidate {
    return .{
        .observation = .{
            .route = lease_state.RouteHandle.parse(route) catch unreachable,
            .identity = route_observation.IdentityEvidence.fromBorrowed(identity),
            .exact_model = exact_model,
            .admission = .admitted,
            .reactive = .{ .readiness = .available, .resets_at_s = 10_000 },
        },
        .account = lease_state.AccountHandle.parse(account) catch unreachable,
    };
}
