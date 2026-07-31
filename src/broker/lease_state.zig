//! Pure in-process lease state for shared broker election.
//!
//! The state owns no allocator, clock, process probe, filesystem, lock,
//! network, provider, adapter, or credential access. Callers inject opaque
//! active-v2 handles, timestamps, and owner-liveness observations; the state
//! copies every borrowed handle before retaining it.
//!
//! Projection and admission mutation form a revision-checked serialized contract:
//! `Projection.revision` must be returned as `AcquireInput.expected_revision`.
//! A changed admission revision returns `StateChanged`, requiring re-projection
//! and re-election. Heartbeat-only renewals advance the full mutation revision
//! for persistence/observability, but do not invalidate a projection because
//! they cannot change load, current eligibility at the renewal timestamp,
//! ownership, capacity, generation, or selection history. An exact retry with a
//! currently live owner is recognized before the revision check so a lost reply
//! is idempotent. The caller still owns synchronization around this state; this
//! module records one state-wide injected-time watermark and rejects regressions;
//! it detects stale sequential snapshots but is not the deferred cross-process
//! flock/persistence implementation.

const std = @import("std");
const broker_types = @import("types.zig");
const decision = @import("decision.zig");
const identifiers = @import("identifiers.zig");
const managed_contract = @import("../managed_harness_contract.zig");
const model_demand = @import("model_demand.zig");

pub const SessionHandle = broker_types.SessionHandle;
pub const AccountHandle = broker_types.AccountHandle;
pub const RouteHandle = broker_types.RouteHandle;
pub const ExactModel = model_demand.ExactModel;
pub const ModelDemand = model_demand.ModelDemand;
pub const LeaseObservation = decision.LeaseObservation;
pub const LeaseView = decision.LeaseView;

pub const LeaseHandle = struct {
    text: []const u8,

    pub fn parse(text: []const u8) error{InvalidIdentifier}!LeaseHandle {
        _ = try SessionHandle.parse(text);
        return .{ .text = text };
    }
};

pub const OwnerPid = u32;
pub const TimestampMs = i64;
pub const Generation = u64;
pub const Revision = u64;
pub const max_timestamp_ms = managed_contract.max_json_safe_integer;

pub const OwnerLiveness = enum {
    alive,
    dead,
};

pub const OwnerObservation = struct {
    /// Group 2 accepts an injected PID/liveness fact but does not prove process
    /// incarnation. Cross-process persistence must add a start-time or nonce
    /// before it can claim protection against PID reuse.
    owner_pid: OwnerPid,
    liveness: OwnerLiveness,
};

pub const RouteRegistration = struct {
    route: RouteHandle,
    exact_model: ExactModel,
};

pub const AcquireInput = struct {
    lease: LeaseHandle,
    session: SessionHandle,
    account: AccountHandle,
    route: RouteHandle,
    exact_model: ExactModel,
    owner_pid: OwnerPid,
    expected_revision: Revision,
    now_ms: TimestampMs,
    selected_at_ms: TimestampMs,
    heartbeat_at_ms: TimestampMs,
    expires_at_ms: TimestampMs,
};

pub const RenewInput = struct {
    lease: LeaseHandle,
    session: SessionHandle,
    owner_pid: OwnerPid,
    generation: Generation,
    now_ms: TimestampMs,
    heartbeat_at_ms: TimestampMs,
    expires_at_ms: TimestampMs,
};

pub const ReleaseInput = struct {
    lease: LeaseHandle,
    session: SessionHandle,
    owner_pid: OwnerPid,
    generation: Generation,
};

/// Atomically move one session's exact-model lease to another route. A session
/// may hold independent leases for different exact models, but one exact-model
/// lease must transition rather than overlap.
pub const TransitionInput = struct {
    current_lease: LeaseHandle,
    current_generation: Generation,
    next: AcquireInput,
};

pub const LeaseGrant = struct {
    generation: Generation,
};

pub const AcquireOutcome = union(enum) {
    acquired: LeaseGrant,
    already_active: LeaseGrant,
};

pub const RenewOutcome = enum {
    renewed,
    unchanged,
};

pub const LeaseError = error{
    InvalidLease,
    LeaseConflict,
    SessionConflict,
    LeaseCapacityExceeded,
    RouteCapacityExceeded,
    LeaseNotFound,
    OwnerMismatch,
    GenerationMismatch,
    GenerationExhausted,
    RevisionExhausted,
    StateChanged,
    StaleLease,
    NonMonotonicObservation,
    NonMonotonicRenewal,
    OwnerUnavailable,
    RouteNotRegistered,
};

pub const ProjectionQuality = enum {
    complete,
    degraded,
    unavailable,
};

/// The public projection exposes only the existing route/count/last-selected
/// rows plus demand-scoped stickiness. `unavailable` always carries an empty
/// advisory view, so missing lease state cannot create `no_route`.
pub const Projection = struct {
    revision: Revision,
    quality: ProjectionQuality,
    view: LeaseView,
};

/// Persistence callers must hold the same serialization lock while taking
/// this snapshot and copying the state payload. Reading the counters through
/// separate accessors is not a persistence boundary: only this pair identifies
/// one lock-scoped state version. `mutation` covers every persisted change,
/// including the observed-time watermark; `admission` is the projection fence.
pub const RevisionSnapshot = struct {
    mutation: Revision,
    admission: Revision,
};

fn OwnedHandle(comptime Handle: type) type {
    return struct {
        const Self = @This();

        buf: [identifiers.max_handle_len]u8 = [_]u8{0} ** identifiers.max_handle_len,
        len: u16 = 0,

        fn init(handle: Handle) error{InvalidIdentifier}!Self {
            _ = try Handle.parse(handle.text);
            var owned = Self{};
            @memcpy(owned.buf[0..handle.text.len], handle.text);
            owned.len = @intCast(handle.text.len);
            return owned;
        }

        fn bytes(self: *const Self) []const u8 {
            return self.buf[0..self.len];
        }

        fn view(self: *const Self) Handle {
            return Handle.parse(self.bytes()) catch unreachable;
        }

        fn eqlBorrowed(self: *const Self, handle: Handle) bool {
            return handleEql(self.bytes(), handle.text);
        }
    };
}

const OwnedLeaseHandle = OwnedHandle(LeaseHandle);
const OwnedSessionHandle = OwnedHandle(SessionHandle);
const OwnedAccountHandle = OwnedHandle(AccountHandle);
const OwnedRouteHandle = OwnedHandle(RouteHandle);

const TransitionOrigin = struct {
    lease: OwnedLeaseHandle,
    generation: Generation,
};

/// Internal state is a closed, owned routing-state shape. The adapter boundary
/// remains responsible for semantic redaction and opaque handle minting; this
/// module enforces only the bounded active-handle grammar and has no fields for
/// provider payloads, credentials, paths, or request bodies. `exact_model` is
/// the one admitted, non-secret routing value.
const StoredLease = struct {
    lease: OwnedLeaseHandle,
    session: OwnedSessionHandle,
    account: OwnedAccountHandle,
    route: OwnedRouteHandle,
    exact_model: ExactModel,
    owner_pid: OwnerPid,
    generation: Generation,
    selected_at_ms: TimestampMs,
    heartbeat_at_ms: TimestampMs,
    expires_at_ms: TimestampMs,
    transition_from: ?TransitionOrigin = null,
};

const RouteHistory = struct {
    route: OwnedRouteHandle,
    exact_model: ExactModel,
    last_selected_at: ?TimestampMs,
};

const ResolvedLiveness = enum {
    alive,
    dead,
    unknown,
};

pub fn missingProjection() Projection {
    return .{
        .revision = 0,
        .quality = .unavailable,
        .view = .{},
    };
}

/// Fixed-capacity, allocation-free in-process lease state.
pub fn LeaseState(
    comptime lease_capacity: usize,
    comptime route_capacity: usize,
) type {
    return struct {
        const Self = @This();

        records: [lease_capacity]StoredLease = undefined,
        record_count: usize = 0,
        histories: [route_capacity]RouteHistory = undefined,
        history_count: usize = 0,
        mutation_revision_value: Revision = 0,
        admission_revision_value: Revision = 0,
        last_observed_at_ms: ?TimestampMs = null,
        next_generation: Generation = 1,

        pub fn init() Self {
            return .{};
        }

        pub fn len(self: *const Self) usize {
            return self.record_count;
        }

        /// Revision used by projection/acquire and projection/transition.
        /// Kept under the original name because callers use it to construct
        /// `expected_revision`; full persistence sequencing is exposed below.
        pub fn currentRevision(self: *const Self) Revision {
            return self.admission_revision_value;
        }

        pub fn currentMutationRevision(self: *const Self) Revision {
            return self.mutation_revision_value;
        }

        pub fn revisionSnapshot(self: *const Self) RevisionSnapshot {
            return .{
                .mutation = self.mutation_revision_value,
                .admission = self.admission_revision_value,
            };
        }

        /// Register the fixed eligible route catalog for this state lifetime.
        /// Registration copies the borrowed route handle and creates the
        /// zero-load row that projection retains before first selection.
        /// Dynamic catalog replacement is deferred to the adapter integration;
        /// acquire never grows route history from arbitrary input.
        pub fn registerRoute(
            self: *Self,
            input: RouteRegistration,
        ) LeaseError!void {
            if (!validRouteHandle(input.route) or !input.exact_model.isValid()) {
                return error.InvalidLease;
            }
            if (self.findHistory(input.route, input.exact_model) != null) return;
            if (self.history_count == route_capacity) {
                return error.RouteCapacityExceeded;
            }
            try self.ensureAdmissionMutationAvailable();

            self.insertHistory(.{
                .route = OwnedRouteHandle.init(input.route) catch
                    return error.InvalidLease,
                .exact_model = input.exact_model,
                .last_selected_at = null,
            });
            self.bumpAdmissionMutation();
        }

        /// Acquire after a projection/reduction step. Definitely stale records
        /// are cleaned before revision and capacity checks. Exact retries are
        /// idempotent with a live owner even if unrelated state changed. Exact
        /// means lease/session/account/route/model/owner and the selected,
        /// heartbeat, and expiry timestamps still match; `expected_revision`
        /// may be stale and `now_ms` may advance monotonically before expiry.
        /// A different route for the same session/model must use `transition`.
        pub fn acquire(
            self: *Self,
            input: AcquireInput,
            owners: []const OwnerObservation,
        ) LeaseError!AcquireOutcome {
            if (!validAcquire(input)) return error.InvalidLease;
            _ = try self.cleanupStale(input.now_ms, owners);
            if (comptime lease_capacity == 0) {
                return error.LeaseCapacityExceeded;
            }
            if (resolveOwner(input.owner_pid, owners) != .alive) {
                return error.OwnerUnavailable;
            }

            if (self.findLease(input.lease)) |index| {
                const record = &self.records[index];
                if (recordEqlInput(record, input)) {
                    if (record.transition_from != null) {
                        return error.LeaseConflict;
                    }
                    return .{ .already_active = .{ .generation = record.generation } };
                }
                return error.LeaseConflict;
            }
            if (input.expected_revision != self.admission_revision_value) {
                return error.StateChanged;
            }

            for (self.records[0..self.record_count]) |*existing| {
                if (existing.session.eqlBorrowed(input.session) and
                    existing.exact_model.eql(input.exact_model))
                {
                    return error.SessionConflict;
                }
            }

            const history_index = self.findHistory(
                input.route,
                input.exact_model,
            ) orelse return error.RouteNotRegistered;
            if (self.record_count == lease_capacity) {
                return error.LeaseCapacityExceeded;
            }
            try self.ensureAdmissionMutationAvailable();
            if (self.next_generation == std.math.maxInt(Generation)) {
                return error.GenerationExhausted;
            }

            const generation = self.next_generation;
            const stored = storedLease(input, generation) catch
                return error.InvalidLease;
            const previous = self.histories[history_index].last_selected_at;
            if (previous == null or input.selected_at_ms > previous.?) {
                self.histories[history_index].last_selected_at = input.selected_at_ms;
            }

            self.records[self.record_count] = stored;
            self.record_count += 1;
            self.next_generation += 1;
            self.bumpAdmissionMutation();
            return .{ .acquired = .{ .generation = generation } };
        }

        pub fn transition(
            self: *Self,
            input: TransitionInput,
            owners: []const OwnerObservation,
        ) LeaseError!LeaseGrant {
            if (!validLeaseHandle(input.current_lease) or
                input.current_generation == 0 or
                !validAcquire(input.next))
            {
                return error.InvalidLease;
            }
            if (comptime lease_capacity == 0) return error.LeaseNotFound;

            _ = try self.cleanupStale(input.next.now_ms, owners);
            if (resolveOwner(input.next.owner_pid, owners) != .alive) {
                return error.OwnerUnavailable;
            }
            if (self.findLease(input.next.lease)) |next_index| {
                const next_record = &self.records[next_index];
                if (recordEqlInput(next_record, input.next)) {
                    const origin = next_record.transition_from orelse
                        return error.LeaseConflict;
                    if (!origin.lease.eqlBorrowed(input.current_lease)) {
                        return error.LeaseConflict;
                    }
                    if (origin.generation != input.current_generation) {
                        return error.GenerationMismatch;
                    }
                    return .{ .generation = next_record.generation };
                }
                if (!next_record.lease.eqlBorrowed(input.current_lease)) {
                    return error.LeaseConflict;
                }
            }
            if (input.next.expected_revision != self.admission_revision_value) {
                return error.StateChanged;
            }

            const current_index = self.findLease(input.current_lease) orelse
                return error.LeaseNotFound;
            const current = &self.records[current_index];
            try authorizeMutation(
                current,
                input.next.session,
                input.next.owner_pid,
                input.current_generation,
            );
            if (!current.exact_model.eql(input.next.exact_model)) {
                return error.SessionConflict;
            }

            const history_index = self.findHistory(
                input.next.route,
                input.next.exact_model,
            ) orelse return error.RouteNotRegistered;
            try self.ensureAdmissionMutationAvailable();
            if (self.next_generation == std.math.maxInt(Generation)) {
                return error.GenerationExhausted;
            }

            const generation = self.next_generation;
            var stored = storedLease(input.next, generation) catch
                return error.InvalidLease;
            stored.transition_from = .{
                .lease = OwnedLeaseHandle.init(input.current_lease) catch
                    return error.InvalidLease,
                .generation = input.current_generation,
            };
            const previous = self.histories[history_index].last_selected_at;
            if (previous == null or input.next.selected_at_ms > previous.?) {
                self.histories[history_index].last_selected_at =
                    input.next.selected_at_ms;
            }
            self.records[current_index] = stored;
            self.next_generation += 1;
            self.bumpAdmissionMutation();
            return .{ .generation = generation };
        }

        pub fn renew(self: *Self, input: RenewInput) LeaseError!RenewOutcome {
            if (!validLeaseHandle(input.lease) or
                !validSessionHandle(input.session) or
                !validOwnerPid(input.owner_pid) or
                !validRenewTimes(input))
            {
                return error.InvalidLease;
            }
            if (comptime lease_capacity == 0) return error.LeaseNotFound;

            const index = self.findLease(input.lease) orelse
                return error.LeaseNotFound;
            var record = &self.records[index];
            try authorizeMutation(record, input.session, input.owner_pid, input.generation);
            if (input.heartbeat_at_ms < record.heartbeat_at_ms or
                input.expires_at_ms < record.expires_at_ms)
            {
                return error.NonMonotonicRenewal;
            }
            try self.observeTime(input.now_ms);
            if (record.expires_at_ms <= input.now_ms) return error.StaleLease;
            if (input.heartbeat_at_ms == record.heartbeat_at_ms and
                input.expires_at_ms == record.expires_at_ms)
            {
                return .unchanged;
            }
            // A valid renewal only extends an authorized, currently unexpired
            // lease. It cannot change admission eligibility at `now_ms`, route
            // load, ownership, capacity, generation, or selection history.
            try self.ensureMutationRevisionAvailable();

            record.heartbeat_at_ms = input.heartbeat_at_ms;
            record.expires_at_ms = input.expires_at_ms;
            self.bumpMutationRevision();
            return .renewed;
        }

        pub fn release(self: *Self, input: ReleaseInput) LeaseError!void {
            if (!validLeaseHandle(input.lease) or
                !validSessionHandle(input.session) or
                !validOwnerPid(input.owner_pid))
            {
                return error.InvalidLease;
            }
            if (comptime lease_capacity == 0) return error.LeaseNotFound;

            const index = self.findLease(input.lease) orelse
                return error.LeaseNotFound;
            try authorizeMutation(
                &self.records[index],
                input.session,
                input.owner_pid,
                input.generation,
            );
            try self.ensureAdmissionMutationAvailable();
            self.removeRecord(index);
            self.bumpAdmissionMutation();
        }

        /// Stale means exactly `now >= expires_at` or a definitively dead
        /// injected owner. Unknown/conflicting liveness is retained but cannot
        /// contribute load or stickiness.
        pub fn cleanupStale(
            self: *Self,
            now_ms: TimestampMs,
            owners: []const OwnerObservation,
        ) LeaseError!usize {
            try self.observeTime(now_ms);
            if (comptime lease_capacity == 0) return 0;

            var stale_count: usize = 0;
            for (self.records[0..self.record_count]) |*record| {
                if (isStale(record, now_ms, owners)) stale_count += 1;
            }
            if (stale_count == 0) return 0;
            try self.ensureAdmissionMutationAvailable();

            var index: usize = 0;
            while (index < self.record_count) {
                if (!isStale(&self.records[index], now_ms, owners)) {
                    index += 1;
                    continue;
                }
                self.removeRecord(index);
            }
            self.bumpAdmissionMutation();
            return stale_count;
        }

        /// Deterministic read-only projection into the group-1 reducer. Route
        /// handles borrow state-owned bytes and rows borrow caller scratch;
        /// either the next admission-relevant mutation or scratch reuse
        /// invalidates the returned view.
        pub fn project(
            self: *Self,
            session: SessionHandle,
            demand: ModelDemand,
            now_ms: TimestampMs,
            owners: []const OwnerObservation,
            scratch: []LeaseObservation,
        ) LeaseError!Projection {
            if (!validSessionHandle(session) or !demand.isValid()) {
                return unavailableProjection(self.admission_revision_value);
            }
            try self.observeTime(now_ms);

            var required: usize = 0;
            for (self.histories[0..self.history_count]) |*history| {
                if (demand.accepts(history.exact_model)) required += 1;
            }
            if (required > scratch.len) {
                return unavailableProjection(self.admission_revision_value);
            }

            var output_count: usize = 0;
            for (self.histories[0..self.history_count]) |*history| {
                if (!demand.accepts(history.exact_model)) continue;
                scratch[output_count] = .{
                    .route = history.route.view(),
                    .active_leases = 0,
                    .last_selected_at = history.last_selected_at,
                };
                output_count += 1;
            }

            var quality: ProjectionQuality = .complete;
            var sticky: ?RouteHandle = null;
            for (self.records[0..self.record_count]) |*record| {
                if (!demand.accepts(record.exact_model)) continue;
                if (record.expires_at_ms <= now_ms) continue;

                const owner = resolveOwner(record.owner_pid, owners);
                if (owner == .unknown) {
                    quality = .degraded;
                    continue;
                }
                if (owner == .dead) continue;

                const route = record.route.view();
                const row_index = findProjectedRoute(
                    scratch[0..output_count],
                    route,
                ) orelse return unavailableProjection(self.admission_revision_value);
                scratch[row_index].active_leases +|= 1;
                if (record.session.eqlBorrowed(session)) sticky = route;
            }

            return .{
                .revision = self.admission_revision_value,
                .quality = quality,
                .view = .{
                    .sticky_route = sticky,
                    .routes = scratch[0..output_count],
                },
            };
        }

        fn findLease(self: *const Self, lease: LeaseHandle) ?usize {
            for (self.records[0..self.record_count], 0..) |*record, index| {
                if (record.lease.eqlBorrowed(lease)) return index;
            }
            return null;
        }

        fn findHistory(
            self: *const Self,
            route: RouteHandle,
            exact_model: ExactModel,
        ) ?usize {
            for (self.histories[0..self.history_count], 0..) |*history, index| {
                if (history.route.eqlBorrowed(route) and
                    history.exact_model.eql(exact_model))
                {
                    return index;
                }
            }
            return null;
        }

        fn insertHistory(self: *Self, history: RouteHistory) void {
            var insert_at = self.history_count;
            while (insert_at > 0 and
                historyOrder(&self.histories[insert_at - 1], &history) == .gt)
            {
                self.histories[insert_at] = self.histories[insert_at - 1];
                insert_at -= 1;
            }
            self.histories[insert_at] = history;
            self.history_count += 1;
        }

        fn removeRecord(self: *Self, index: usize) void {
            self.record_count -= 1;
            if (index != self.record_count) {
                self.records[index] = self.records[self.record_count];
            }
        }

        fn ensureMutationRevisionAvailable(self: *const Self) LeaseError!void {
            if (self.mutation_revision_value == std.math.maxInt(Revision)) {
                return error.RevisionExhausted;
            }
        }

        fn ensureAdmissionMutationAvailable(self: *const Self) LeaseError!void {
            try self.ensureMutationRevisionAvailable();
            if (self.admission_revision_value == std.math.maxInt(Revision)) {
                return error.RevisionExhausted;
            }
        }

        fn bumpMutationRevision(self: *Self) void {
            self.mutation_revision_value += 1;
        }

        fn bumpAdmissionMutation(self: *Self) void {
            self.mutation_revision_value += 1;
            self.admission_revision_value += 1;
        }

        fn observeTime(self: *Self, now_ms: TimestampMs) LeaseError!void {
            if (!validTimestamp(now_ms)) return error.InvalidLease;
            if (self.last_observed_at_ms) |last_observed_at_ms| {
                if (now_ms < last_observed_at_ms) {
                    return error.NonMonotonicObservation;
                }
                if (now_ms == last_observed_at_ms) return;
            }

            try self.ensureMutationRevisionAvailable();
            self.last_observed_at_ms = now_ms;
            self.bumpMutationRevision();
        }
    };
}

fn validAcquire(input: AcquireInput) bool {
    return validLeaseHandle(input.lease) and
        validSessionHandle(input.session) and
        validAccountHandle(input.account) and
        validRouteHandle(input.route) and
        input.exact_model.isValid() and
        validOwnerPid(input.owner_pid) and
        validTimestamp(input.now_ms) and
        validTimestamp(input.selected_at_ms) and
        validTimestamp(input.heartbeat_at_ms) and
        validTimestamp(input.expires_at_ms) and
        input.selected_at_ms <= input.heartbeat_at_ms and
        input.heartbeat_at_ms <= input.now_ms and
        input.now_ms < input.expires_at_ms;
}

fn validRenewTimes(input: RenewInput) bool {
    return input.generation > 0 and
        validTimestamp(input.now_ms) and
        validTimestamp(input.heartbeat_at_ms) and
        validTimestamp(input.expires_at_ms) and
        input.heartbeat_at_ms <= input.now_ms and
        input.now_ms < input.expires_at_ms;
}

fn validTimestamp(value: TimestampMs) bool {
    return value >= 0 and value <= max_timestamp_ms;
}

fn validOwnerPid(pid: OwnerPid) bool {
    return pid > 0 and pid <= std.math.maxInt(i32);
}

fn validLeaseHandle(handle: LeaseHandle) bool {
    _ = LeaseHandle.parse(handle.text) catch return false;
    return true;
}

fn validSessionHandle(handle: SessionHandle) bool {
    _ = SessionHandle.parse(handle.text) catch return false;
    return true;
}

fn validAccountHandle(handle: AccountHandle) bool {
    _ = AccountHandle.parse(handle.text) catch return false;
    return true;
}

fn validRouteHandle(handle: RouteHandle) bool {
    _ = RouteHandle.parse(handle.text) catch return false;
    return true;
}

fn storedLease(
    input: AcquireInput,
    generation: Generation,
) error{InvalidIdentifier}!StoredLease {
    return .{
        .lease = try OwnedLeaseHandle.init(input.lease),
        .session = try OwnedSessionHandle.init(input.session),
        .account = try OwnedAccountHandle.init(input.account),
        .route = try OwnedRouteHandle.init(input.route),
        .exact_model = input.exact_model,
        .owner_pid = input.owner_pid,
        .generation = generation,
        .selected_at_ms = input.selected_at_ms,
        .heartbeat_at_ms = input.heartbeat_at_ms,
        .expires_at_ms = input.expires_at_ms,
    };
}

fn recordEqlInput(record: *const StoredLease, input: AcquireInput) bool {
    return record.lease.eqlBorrowed(input.lease) and
        record.session.eqlBorrowed(input.session) and
        record.account.eqlBorrowed(input.account) and
        record.route.eqlBorrowed(input.route) and
        record.exact_model.eql(input.exact_model) and
        record.owner_pid == input.owner_pid and
        record.selected_at_ms == input.selected_at_ms and
        record.heartbeat_at_ms == input.heartbeat_at_ms and
        record.expires_at_ms == input.expires_at_ms;
}

fn authorizeMutation(
    record: *const StoredLease,
    session: SessionHandle,
    owner_pid: OwnerPid,
    generation: Generation,
) LeaseError!void {
    if (!record.session.eqlBorrowed(session) or record.owner_pid != owner_pid) {
        return error.OwnerMismatch;
    }
    if (record.generation != generation) return error.GenerationMismatch;
}

fn isStale(
    record: *const StoredLease,
    now_ms: TimestampMs,
    owners: []const OwnerObservation,
) bool {
    return now_ms >= record.expires_at_ms or
        resolveOwner(record.owner_pid, owners) == .dead;
}

fn historyOrder(a: *const RouteHistory, b: *const RouteHistory) std.math.Order {
    const model_order = std.mem.order(
        u8,
        a.exact_model.bytes(),
        b.exact_model.bytes(),
    );
    if (model_order != .eq) return model_order;
    return std.mem.order(u8, a.route.bytes(), b.route.bytes());
}

fn handleEql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn resolveOwner(
    owner_pid: OwnerPid,
    observations: []const OwnerObservation,
) ResolvedLiveness {
    if (!validOwnerPid(owner_pid)) return .unknown;

    var resolved: ?OwnerLiveness = null;
    for (observations) |observation| {
        if (observation.owner_pid != owner_pid) continue;
        if (!validOwnerPid(observation.owner_pid)) continue;
        if (resolved) |existing| {
            if (existing != observation.liveness) return .unknown;
        } else {
            resolved = observation.liveness;
        }
    }
    return if (resolved) |value|
        switch (value) {
            .alive => .alive,
            .dead => .dead,
        }
    else
        .unknown;
}

fn findProjectedRoute(rows: []const LeaseObservation, route: RouteHandle) ?usize {
    for (rows, 0..) |row, index| {
        if (handleEql(row.route.text, route.text)) return index;
    }
    return null;
}

fn unavailableProjection(revision: Revision) Projection {
    return .{
        .revision = revision,
        .quality = .unavailable,
        .view = .{},
    };
}

test {
    std.testing.refAllDeclsRecursive(@This());
}

const testing = std.testing;

fn leaseHandle(text: []const u8) LeaseHandle {
    return LeaseHandle.parse(text) catch unreachable;
}

fn sessionHandle(text: []const u8) SessionHandle {
    return SessionHandle.parse(text) catch unreachable;
}

fn accountHandle(text: []const u8) AccountHandle {
    return AccountHandle.parse(text) catch unreachable;
}

fn routeHandle(text: []const u8) RouteHandle {
    return RouteHandle.parse(text) catch unreachable;
}

fn exactModel(text: []const u8) ExactModel {
    return ExactModel.init(text) catch unreachable;
}

fn acquireInput(
    lease_text: []const u8,
    session_text: []const u8,
    account_text: []const u8,
    route_text: []const u8,
    model_text: []const u8,
    owner_pid: OwnerPid,
    now_ms: TimestampMs,
    expires_at_ms: TimestampMs,
) AcquireInput {
    return .{
        .lease = leaseHandle(lease_text),
        .session = sessionHandle(session_text),
        .account = accountHandle(account_text),
        .route = routeHandle(route_text),
        .exact_model = exactModel(model_text),
        .owner_pid = owner_pid,
        .expected_revision = 0,
        .now_ms = now_ms,
        .selected_at_ms = now_ms,
        .heartbeat_at_ms = now_ms,
        .expires_at_ms = expires_at_ms,
    };
}

fn atRevision(input: AcquireInput, revision: Revision) AcquireInput {
    var revised = input;
    revised.expected_revision = revision;
    return revised;
}

fn grantFromAcquire(outcome: AcquireOutcome) LeaseGrant {
    return switch (outcome) {
        .acquired => |grant| grant,
        .already_active => |grant| grant,
    };
}

fn routeEvidence(
    route_text: []const u8,
    identity_text: []const u8,
    model_text: []const u8,
) decision.RouteEvidence {
    const route_observation = @import("route_observation.zig");
    return .{
        .route = routeHandle(route_text),
        .identity = route_observation.IdentityEvidence.fromBorrowed(identity_text),
        .exact_model = exactModel(model_text),
        .admission = .admitted,
        .readiness = .available,
        .provenance = .proven,
        .resets_at_s = null,
    };
}

fn expectSelected(actual: decision.BrokerDecision) !RouteHandle {
    return switch (actual) {
        .select_route => |route| route,
        .no_route => error.TestUnexpectedResult,
    };
}

fn projectedLoad(view: LeaseView, route: RouteHandle) u64 {
    for (view.routes) |row| {
        if (handleEql(row.route.text, route.text)) return row.active_leases;
    }
    return 0;
}

test "lease record exposes only the closed owned routing shape" {
    const fields = @typeInfo(StoredLease).@"struct".fields;
    const expected_names = [_][]const u8{
        "lease",
        "session",
        "account",
        "route",
        "exact_model",
        "owner_pid",
        "generation",
        "selected_at_ms",
        "heartbeat_at_ms",
        "expires_at_ms",
        "transition_from",
    };
    try testing.expectEqual(expected_names.len, fields.len);
    inline for (expected_names, 0..) |expected, index| {
        try testing.expectEqualStrings(expected, fields[index].name);
    }
    try testing.expect(fields[0].type == OwnedLeaseHandle);
    try testing.expect(fields[1].type == OwnedSessionHandle);
    try testing.expect(fields[2].type == OwnedAccountHandle);
    try testing.expect(fields[3].type == OwnedRouteHandle);
    try testing.expect(fields[4].type == ExactModel);
    try testing.expect(fields[5].type == OwnerPid);

    const projection_fields = @typeInfo(LeaseObservation).@"struct".fields;
    const projection_names = [_][]const u8{
        "route",
        "active_leases",
        "last_selected_at",
    };
    try testing.expectEqual(projection_names.len, projection_fields.len);
    inline for (projection_names, 0..) |expected, index| {
        try testing.expectEqualStrings(expected, projection_fields[index].name);
    }
}

test "acquire renew release is bounded idempotent and ownership checked" {
    var state = LeaseState(2, 2).init();
    try state.registerRoute(.{
        .route = routeHandle("route-1"),
        .exact_model = exactModel("model-1"),
    });
    try state.registerRoute(.{
        .route = routeHandle("route-2"),
        .exact_model = exactModel("model-1"),
    });
    const first = atRevision(acquireInput(
        "lease-1",
        "session-1",
        "account-1",
        "route-1",
        "model-1",
        11,
        10,
        20,
    ), state.currentRevision());

    const owners = [_]OwnerObservation{
        .{ .owner_pid = first.owner_pid, .liveness = .alive },
        .{ .owner_pid = 12, .liveness = .alive },
    };
    const acquired = try state.acquire(first, &owners);
    const grant = grantFromAcquire(acquired);
    try testing.expect(acquired == .acquired);
    const duplicate = try state.acquire(first, &owners);
    try testing.expect(duplicate == .already_active);
    try testing.expectEqual(grant.generation, grantFromAcquire(duplicate).generation);
    try testing.expectEqual(@as(usize, 1), state.len());
    const stable_revision = state.currentRevision();

    var conflicting = first;
    conflicting.route = routeHandle("route-2");
    conflicting.expected_revision = state.currentRevision();
    try testing.expectError(error.LeaseConflict, state.acquire(conflicting, &owners));

    const session_conflict = acquireInput(
        "lease-2",
        "session-1",
        "account-2",
        "route-2",
        "model-1",
        12,
        11,
        21,
    );
    try testing.expectError(error.SessionConflict, state.acquire(
        atRevision(session_conflict, state.currentRevision()),
        &owners,
    ));
    try testing.expectEqual(stable_revision, state.currentRevision());
    try testing.expectEqual(@as(usize, 1), state.len());

    try testing.expectEqual(RenewOutcome.unchanged, try state.renew(.{
        .lease = first.lease,
        .session = first.session,
        .owner_pid = first.owner_pid,
        .generation = grant.generation,
        .now_ms = 11,
        .heartbeat_at_ms = 10,
        .expires_at_ms = 20,
    }));
    try testing.expectEqual(RenewOutcome.renewed, try state.renew(.{
        .lease = first.lease,
        .session = first.session,
        .owner_pid = first.owner_pid,
        .generation = grant.generation,
        .now_ms = 15,
        .heartbeat_at_ms = 15,
        .expires_at_ms = 25,
    }));
    try testing.expectError(error.NonMonotonicRenewal, state.renew(.{
        .lease = first.lease,
        .session = first.session,
        .owner_pid = first.owner_pid,
        .generation = grant.generation,
        .now_ms = 16,
        .heartbeat_at_ms = 14,
        .expires_at_ms = 26,
    }));
    try testing.expectError(error.OwnerMismatch, state.release(.{
        .lease = first.lease,
        .session = first.session,
        .owner_pid = 99,
        .generation = grant.generation,
    }));

    try state.release(.{
        .lease = first.lease,
        .session = first.session,
        .owner_pid = first.owner_pid,
        .generation = grant.generation,
    });
    try testing.expectEqual(@as(usize, 0), state.len());

    var scratch: [2]LeaseObservation = undefined;
    const projection = try state.project(
        first.session,
        try ModelDemand.init("model-1"),
        16,
        &.{},
        &scratch,
    );
    try testing.expectEqual(ProjectionQuality.complete, projection.quality);
    try testing.expect(projection.view.sticky_route == null);
    try testing.expectEqual(@as(usize, 2), projection.view.routes.len);
    try testing.expectEqual(@as(u64, 0), projection.view.routes[0].active_leases);
    try testing.expectEqual(@as(?i64, 10), projection.view.routes[0].last_selected_at);
}

test "retained handles are owned and stickiness is demand scoped" {
    var lease_bytes = [_]u8{ 'l', 'e', 'a', 's', 'e', '-', 'a' };
    var session_bytes = [_]u8{ 's', 'e', 's', 's', 'i', 'o', 'n', '-', 'a' };
    var account_bytes = [_]u8{ 'a', 'c', 'c', 'o', 'u', 'n', 't', '-', 'a' };
    var route_bytes = [_]u8{ 'r', 'o', 'u', 't', 'e', '-', 'a' };

    var state = LeaseState(2, 2).init();
    try state.registerRoute(.{
        .route = try RouteHandle.parse(&route_bytes),
        .exact_model = try ExactModel.init("model-1"),
    });
    try state.registerRoute(.{
        .route = try RouteHandle.parse("route-b"),
        .exact_model = try ExactModel.init("model-2"),
    });

    const owners = [_]OwnerObservation{
        .{ .owner_pid = 1, .liveness = .alive },
    };
    const before = try state.project(
        try SessionHandle.parse(&session_bytes),
        try ModelDemand.init("model-1"),
        1,
        &owners,
        &.{},
    );
    const outcome = try state.acquire(.{
        .lease = try LeaseHandle.parse(&lease_bytes),
        .session = try SessionHandle.parse(&session_bytes),
        .account = try AccountHandle.parse(&account_bytes),
        .route = try RouteHandle.parse(&route_bytes),
        .exact_model = try ExactModel.init("model-1"),
        .owner_pid = 1,
        .expected_revision = before.revision,
        .now_ms = 1,
        .selected_at_ms = 1,
        .heartbeat_at_ms = 1,
        .expires_at_ms = 100,
    }, &owners);
    const grant = grantFromAcquire(outcome);

    @memset(&lease_bytes, 'x');
    @memset(&session_bytes, 'x');
    @memset(&account_bytes, 'x');
    @memset(&route_bytes, 'x');

    var scratch: [2]LeaseObservation = undefined;
    const model_one = try state.project(
        sessionHandle("session-a"),
        try ModelDemand.init("model-1"),
        2,
        &owners,
        &scratch,
    );
    try testing.expectEqualStrings("route-a", model_one.view.sticky_route.?.text);
    try testing.expectEqualStrings("route-a", model_one.view.routes[0].route.text);
    try testing.expectEqual(@as(u64, 1), model_one.view.routes[0].active_leases);

    const model_two = try state.project(
        sessionHandle("session-a"),
        try ModelDemand.init("model-2"),
        2,
        &owners,
        &scratch,
    );
    try testing.expect(model_two.view.sticky_route == null);
    try testing.expectEqual(@as(usize, 1), model_two.view.routes.len);
    try testing.expectEqualStrings("route-b", model_two.view.routes[0].route.text);
    const model_two_outcome = try state.acquire(.{
        .lease = leaseHandle("lease-b"),
        .session = sessionHandle("session-a"),
        .account = accountHandle("account-b"),
        .route = routeHandle("route-b"),
        .exact_model = exactModel("model-2"),
        .owner_pid = 1,
        .expected_revision = model_two.revision,
        .now_ms = 2,
        .selected_at_ms = 2,
        .heartbeat_at_ms = 2,
        .expires_at_ms = 100,
    }, &owners);
    try testing.expect(model_two_outcome == .acquired);
    try testing.expectEqual(@as(usize, 2), state.len());

    try testing.expectEqual(RenewOutcome.renewed, try state.renew(.{
        .lease = leaseHandle("lease-a"),
        .session = sessionHandle("session-a"),
        .owner_pid = 1,
        .generation = grant.generation,
        .now_ms = 3,
        .heartbeat_at_ms = 3,
        .expires_at_ms = 101,
    }));
}

test "acquire rejects dead unknown and conflicting incoming owners" {
    var state = LeaseState(1, 1).init();
    const input = acquireInput(
        "lease-1",
        "session-1",
        "account-1",
        "route-1",
        "model-1",
        7,
        1,
        100,
    );
    try state.registerRoute(.{
        .route = input.route,
        .exact_model = input.exact_model,
    });
    const candidate = atRevision(input, state.currentRevision());
    const initial_revision = state.currentRevision();

    try testing.expectError(error.OwnerUnavailable, state.acquire(candidate, &.{}));
    try testing.expectError(error.OwnerUnavailable, state.acquire(
        candidate,
        &.{.{ .owner_pid = 7, .liveness = .dead }},
    ));
    try testing.expectError(error.OwnerUnavailable, state.acquire(
        candidate,
        &.{
            .{ .owner_pid = 7, .liveness = .alive },
            .{ .owner_pid = 7, .liveness = .dead },
        },
    ));
    try testing.expectEqual(initial_revision, state.currentRevision());
    try testing.expectEqual(@as(usize, 0), state.len());

    _ = try state.acquire(
        candidate,
        &.{.{ .owner_pid = 7, .liveness = .alive }},
    );
    try testing.expectEqual(@as(usize, 1), state.len());
    try testing.expectError(error.OwnerUnavailable, state.acquire(candidate, &.{}));
    try testing.expectEqual(@as(usize, 1), state.len());
    const duplicate = try state.acquire(
        candidate,
        &.{.{ .owner_pid = 7, .liveness = .alive }},
    );
    try testing.expect(duplicate == .already_active);
}

test "opaque handle grammar rejects email path and provider-key separators" {
    try testing.expectError(
        error.InvalidIdentifier,
        SessionHandle.parse("person@example.com"),
    );
    try testing.expectError(
        error.InvalidIdentifier,
        AccountHandle.parse("/Users/person/.config"),
    );
    try testing.expectError(
        error.InvalidIdentifier,
        RouteHandle.parse("provider:account"),
    );
}

test "revision conflicts and atomic transition preserve one lease per session model" {
    var state = LeaseState(2, 2).init();
    const model = try ModelDemand.init("model-1");
    try state.registerRoute(.{
        .route = routeHandle("route-1"),
        .exact_model = model.exact_model,
    });
    try state.registerRoute(.{
        .route = routeHandle("route-2"),
        .exact_model = model.exact_model,
    });
    const owners = [_]OwnerObservation{
        .{ .owner_pid = 1, .liveness = .alive },
        .{ .owner_pid = 2, .liveness = .alive },
    };
    var scratch: [1]LeaseObservation = undefined;
    const snapshot_a = try state.project(
        sessionHandle("session-1"),
        model,
        1,
        &owners,
        &scratch,
    );
    const snapshot_b = try state.project(
        sessionHandle("session-2"),
        model,
        1,
        &owners,
        &scratch,
    );
    try testing.expectEqual(snapshot_a.revision, snapshot_b.revision);

    const first_input = atRevision(acquireInput(
        "lease-1",
        "session-1",
        "account-1",
        "route-1",
        "model-1",
        1,
        1,
        100,
    ), snapshot_a.revision);
    const first_grant = grantFromAcquire(try state.acquire(first_input, &owners));

    const raced_input = atRevision(acquireInput(
        "lease-2",
        "session-2",
        "account-2",
        "route-1",
        "model-1",
        2,
        1,
        100,
    ), snapshot_b.revision);
    try testing.expectError(error.StateChanged, state.acquire(raced_input, &owners));
    try testing.expectEqual(@as(usize, 1), state.len());

    const next_snapshot = try state.project(
        first_input.session,
        model,
        2,
        &owners,
        &scratch,
    );
    var second_input = first_input;
    second_input.lease = leaseHandle("lease-next");
    second_input.account = accountHandle("account-2");
    second_input.route = routeHandle("route-2");
    second_input.expected_revision = next_snapshot.revision;
    second_input.now_ms = 2;
    second_input.selected_at_ms = 2;
    second_input.heartbeat_at_ms = 2;
    second_input.expires_at_ms = 101;
    try testing.expectError(error.SessionConflict, state.acquire(second_input, &owners));
    const second_grant = try state.transition(.{
        .current_lease = first_input.lease,
        .current_generation = first_grant.generation,
        .next = second_input,
    }, &owners);
    try testing.expect(second_grant.generation > first_grant.generation);
    try testing.expectEqual(@as(usize, 1), state.len());

    const transition_retry = try state.transition(.{
        .current_lease = first_input.lease,
        .current_generation = first_grant.generation,
        .next = second_input,
    }, &owners);
    try testing.expectEqual(second_grant.generation, transition_retry.generation);
    try testing.expectError(error.OwnerUnavailable, state.transition(.{
        .current_lease = first_input.lease,
        .current_generation = first_grant.generation,
        .next = second_input,
    }, &.{}));
    try testing.expectError(
        error.LeaseConflict,
        state.acquire(second_input, &owners),
    );

    try testing.expectError(error.LeaseConflict, state.transition(.{
        .current_lease = leaseHandle("lease-unrelated"),
        .current_generation = first_grant.generation,
        .next = second_input,
    }, &owners));
    try testing.expectError(error.GenerationMismatch, state.transition(.{
        .current_lease = first_input.lease,
        .current_generation = first_grant.generation + 1,
        .next = second_input,
    }, &owners));
    try testing.expectEqual(@as(usize, 1), state.len());

    try testing.expectError(error.GenerationMismatch, state.renew(.{
        .lease = second_input.lease,
        .session = first_input.session,
        .owner_pid = first_input.owner_pid,
        .generation = first_grant.generation,
        .now_ms = 3,
        .heartbeat_at_ms = 3,
        .expires_at_ms = 102,
    }));
    try testing.expectError(error.GenerationMismatch, state.release(.{
        .lease = second_input.lease,
        .session = first_input.session,
        .owner_pid = first_input.owner_pid,
        .generation = first_grant.generation,
    }));
    try testing.expectEqual(@as(usize, 1), state.len());
}

test "unrelated heartbeat renewals cannot starve admission" {
    var state = LeaseState(2, 2).init();
    const demand = try ModelDemand.init("model-1");
    try state.registerRoute(.{
        .route = routeHandle("route-active"),
        .exact_model = demand.exact_model,
    });
    try state.registerRoute(.{
        .route = routeHandle("route-candidate"),
        .exact_model = demand.exact_model,
    });
    const owners = [_]OwnerObservation{
        .{ .owner_pid = 1, .liveness = .alive },
        .{ .owner_pid = 2, .liveness = .alive },
    };
    const active = atRevision(acquireInput(
        "lease-active",
        "session-active",
        "account-active",
        "route-active",
        "model-1",
        1,
        0,
        10_000,
    ), state.currentRevision());
    const active_grant = grantFromAcquire(try state.acquire(active, &owners));

    var scratch: [2]LeaseObservation = undefined;
    var admitted: usize = 0;
    for (0..1000) |iteration| {
        const now_ms: TimestampMs = @intCast(iteration + 1);
        const projection = try state.project(
            sessionHandle("session-candidate"),
            demand,
            now_ms,
            &owners,
            &scratch,
        );
        try testing.expectEqual(ProjectionQuality.complete, projection.quality);
        try testing.expectEqual(
            @as(u64, 1),
            projectedLoad(projection.view, active.route),
        );
        try testing.expectEqual(
            @as(u64, 0),
            projectedLoad(projection.view, routeHandle("route-candidate")),
        );
        const revisions_before_renew = state.revisionSnapshot();

        try testing.expectEqual(RenewOutcome.renewed, try state.renew(.{
            .lease = active.lease,
            .session = active.session,
            .owner_pid = active.owner_pid,
            .generation = active_grant.generation,
            .now_ms = now_ms,
            .heartbeat_at_ms = now_ms,
            .expires_at_ms = 10_000 + now_ms,
        }));
        const revisions_after_renew = state.revisionSnapshot();
        try testing.expectEqual(
            revisions_before_renew.mutation + 1,
            revisions_after_renew.mutation,
        );
        try testing.expectEqual(
            revisions_before_renew.admission,
            revisions_after_renew.admission,
        );
        try testing.expectEqual(projection.revision, revisions_after_renew.admission);
        const after_renew = try state.project(
            sessionHandle("session-candidate"),
            demand,
            now_ms,
            &owners,
            &scratch,
        );
        try testing.expectEqual(ProjectionQuality.complete, after_renew.quality);
        try testing.expectEqual(projection.revision, after_renew.revision);
        try testing.expectEqual(
            @as(u64, 1),
            projectedLoad(after_renew.view, active.route),
        );
        try testing.expectEqual(
            @as(u64, 0),
            projectedLoad(after_renew.view, routeHandle("route-candidate")),
        );

        const candidate = atRevision(acquireInput(
            "lease-candidate",
            "session-candidate",
            "account-candidate",
            "route-candidate",
            "model-1",
            2,
            now_ms,
            now_ms + 1000,
        ), projection.revision);
        const outcome = state.acquire(candidate, &owners) catch |err| {
            if (err == error.StateChanged) continue;
            return err;
        };
        const grant = grantFromAcquire(outcome);
        admitted += 1;
        try state.release(.{
            .lease = candidate.lease,
            .session = candidate.session,
            .owner_pid = candidate.owner_pid,
            .generation = grant.generation,
        });
    }

    try testing.expectEqual(@as(usize, 1000), admitted);
    const final_revisions = state.revisionSnapshot();
    try testing.expect(final_revisions.mutation > final_revisions.admission);
}

test "observed time cannot regress and resurrect an expired projection" {
    var state = LeaseState(1, 1).init();
    const demand = try ModelDemand.init("model-1");
    try state.registerRoute(.{
        .route = routeHandle("route-1"),
        .exact_model = demand.exact_model,
    });
    const owners = [_]OwnerObservation{
        .{ .owner_pid = 1, .liveness = .alive },
    };
    const input = atRevision(acquireInput(
        "lease-1",
        "session-1",
        "account-1",
        "route-1",
        "model-1",
        1,
        10,
        80,
    ), state.currentRevision());
    const grant = grantFromAcquire(try state.acquire(input, &owners));
    var scratch: [1]LeaseObservation = undefined;
    const expired = try state.project(
        input.session,
        demand,
        100,
        &owners,
        &scratch,
    );
    try testing.expectEqual(@as(u64, 0), projectedLoad(expired.view, input.route));
    const revisions_after_expiry = state.revisionSnapshot();

    try testing.expectError(error.NonMonotonicObservation, state.project(
        input.session,
        demand,
        90,
        &owners,
        &scratch,
    ));
    try testing.expectEqual(
        revisions_after_expiry,
        state.revisionSnapshot(),
    );

    try testing.expectError(error.NonMonotonicObservation, state.renew(.{
        .lease = input.lease,
        .session = input.session,
        .owner_pid = input.owner_pid,
        .generation = grant.generation,
        .now_ms = 40,
        .heartbeat_at_ms = 40,
        .expires_at_ms = 200,
    }));
    try testing.expectEqual(
        revisions_after_expiry,
        state.revisionSnapshot(),
    );

    const still_expired = try state.project(
        input.session,
        demand,
        100,
        &owners,
        &scratch,
    );
    try testing.expectEqual(
        @as(u64, 0),
        projectedLoad(still_expired.view, input.route),
    );
    try testing.expectEqual(@as(usize, 1), try state.cleanupStale(100, &owners));
    try testing.expectEqual(@as(usize, 0), state.len());
}

test "transition and release each invalidate stale admission projections" {
    var state = LeaseState(2, 2).init();
    const demand = try ModelDemand.init("model-1");
    try state.registerRoute(.{
        .route = routeHandle("route-1"),
        .exact_model = demand.exact_model,
    });
    try state.registerRoute(.{
        .route = routeHandle("route-2"),
        .exact_model = demand.exact_model,
    });
    const owners = [_]OwnerObservation{
        .{ .owner_pid = 1, .liveness = .alive },
        .{ .owner_pid = 2, .liveness = .alive },
    };
    const current = atRevision(acquireInput(
        "lease-current",
        "session-current",
        "account-1",
        "route-1",
        "model-1",
        1,
        1,
        100,
    ), state.currentRevision());
    const current_grant = grantFromAcquire(try state.acquire(current, &owners));
    var scratch: [2]LeaseObservation = undefined;
    const before_transition = try state.project(
        sessionHandle("session-candidate"),
        demand,
        2,
        &owners,
        &scratch,
    );
    const next = atRevision(acquireInput(
        "lease-next",
        "session-current",
        "account-2",
        "route-2",
        "model-1",
        1,
        2,
        101,
    ), before_transition.revision);
    const next_grant = try state.transition(.{
        .current_lease = current.lease,
        .current_generation = current_grant.generation,
        .next = next,
    }, &owners);

    const candidate_after_transition = atRevision(acquireInput(
        "lease-candidate",
        "session-candidate",
        "account-1",
        "route-1",
        "model-1",
        2,
        2,
        100,
    ), before_transition.revision);
    try testing.expectError(
        error.StateChanged,
        state.acquire(candidate_after_transition, &owners),
    );

    const before_release = try state.project(
        candidate_after_transition.session,
        demand,
        3,
        &owners,
        &scratch,
    );
    try state.release(.{
        .lease = next.lease,
        .session = next.session,
        .owner_pid = next.owner_pid,
        .generation = next_grant.generation,
    });
    var candidate_after_release = candidate_after_transition;
    candidate_after_release.expected_revision = before_release.revision;
    candidate_after_release.now_ms = 3;
    candidate_after_release.selected_at_ms = 3;
    candidate_after_release.heartbeat_at_ms = 3;
    try testing.expectError(
        error.StateChanged,
        state.acquire(candidate_after_release, &owners),
    );
}

test "exact lost acquire reply retries before the admission fence" {
    var state = LeaseState(1, 2).init();
    const demand = try ModelDemand.init("model-1");
    try state.registerRoute(.{
        .route = routeHandle("route-1"),
        .exact_model = demand.exact_model,
    });
    const owners = [_]OwnerObservation{
        .{ .owner_pid = 1, .liveness = .alive },
    };
    const input = atRevision(acquireInput(
        "lease-1",
        "session-1",
        "account-1",
        "route-1",
        "model-1",
        1,
        1,
        100,
    ), state.currentRevision());
    const first = grantFromAcquire(try state.acquire(input, &owners));
    try state.registerRoute(.{
        .route = routeHandle("route-2"),
        .exact_model = demand.exact_model,
    });

    var retry = input;
    retry.now_ms = 2;
    const repeated = try state.acquire(retry, &owners);
    try testing.expect(repeated == .already_active);
    try testing.expectEqual(first.generation, grantFromAcquire(repeated).generation);

    retry.expires_at_ms += 1;
    try testing.expectError(error.LeaseConflict, state.acquire(retry, &owners));
}

test "admission-relevant route mutation invalidates stale projection" {
    var state = LeaseState(1, 2).init();
    const demand = try ModelDemand.init("model-1");
    try state.registerRoute(.{
        .route = routeHandle("route-1"),
        .exact_model = demand.exact_model,
    });
    const owners = [_]OwnerObservation{
        .{ .owner_pid = 1, .liveness = .alive },
    };
    var scratch: [2]LeaseObservation = undefined;
    const stale_projection = try state.project(
        sessionHandle("session-1"),
        demand,
        1,
        &owners,
        &scratch,
    );

    try state.registerRoute(.{
        .route = routeHandle("route-2"),
        .exact_model = demand.exact_model,
    });
    const input = atRevision(acquireInput(
        "lease-1",
        "session-1",
        "account-1",
        "route-1",
        "model-1",
        1,
        1,
        100,
    ), stale_projection.revision);
    try testing.expectError(error.StateChanged, state.acquire(input, &owners));
    try testing.expectEqual(@as(usize, 0), state.len());

    const fresh_projection = try state.project(
        input.session,
        demand,
        1,
        &owners,
        &scratch,
    );
    _ = try state.acquire(atRevision(input, fresh_projection.revision), &owners);
    try testing.expectEqual(@as(usize, 1), state.len());
}

test "expiry boundary cleanup precedes capacity and renewal cannot resurrect" {
    var state = LeaseState(1, 2).init();
    try state.registerRoute(.{
        .route = routeHandle("route-1"),
        .exact_model = exactModel("model-1"),
    });
    try state.registerRoute(.{
        .route = routeHandle("route-2"),
        .exact_model = exactModel("model-1"),
    });
    const owners = [_]OwnerObservation{
        .{ .owner_pid = 1, .liveness = .alive },
        .{ .owner_pid = 2, .liveness = .alive },
    };
    const first = atRevision(acquireInput(
        "lease-1",
        "session-1",
        "account-1",
        "route-1",
        "model-1",
        1,
        1,
        10,
    ), state.currentRevision());
    const first_grant = grantFromAcquire(try state.acquire(first, &owners));

    const full_revision = state.currentRevision();
    const second = atRevision(acquireInput(
        "lease-2",
        "session-2",
        "account-2",
        "route-2",
        "model-1",
        2,
        9,
        100,
    ), full_revision);
    try testing.expectError(error.LeaseCapacityExceeded, state.acquire(second, &owners));
    try testing.expectEqual(full_revision, state.currentRevision());
    try testing.expectEqual(@as(usize, 1), state.len());

    try testing.expectError(error.StaleLease, state.renew(.{
        .lease = first.lease,
        .session = first.session,
        .owner_pid = first.owner_pid,
        .generation = first_grant.generation,
        .now_ms = 10,
        .heartbeat_at_ms = 10,
        .expires_at_ms = 20,
    }));

    var at_boundary = second;
    at_boundary.now_ms = 10;
    at_boundary.heartbeat_at_ms = 10;
    at_boundary.expected_revision = state.currentRevision();
    try testing.expectError(error.StateChanged, state.acquire(at_boundary, &owners));
    try testing.expectEqual(@as(usize, 0), state.len());

    at_boundary.expected_revision = state.currentRevision();
    _ = try state.acquire(at_boundary, &owners);
    try testing.expectEqual(@as(usize, 1), state.len());
}

test "negative control: erasing released route history changes least-recent choice" {
    var state = LeaseState(1, 2).init();
    const demand = try ModelDemand.init("model-1");
    try state.registerRoute(.{
        .route = routeHandle("route-a"),
        .exact_model = demand.exact_model,
    });
    try state.registerRoute(.{
        .route = routeHandle("route-b"),
        .exact_model = demand.exact_model,
    });
    const owners = [_]OwnerObservation{
        .{ .owner_pid = 1, .liveness = .alive },
    };
    var scratch: [2]LeaseObservation = undefined;
    const before = try state.project(
        sessionHandle("session-a"),
        demand,
        10,
        &owners,
        &scratch,
    );
    const input = atRevision(acquireInput(
        "lease-a",
        "session-a",
        "account-a",
        "route-a",
        "model-1",
        1,
        10,
        100,
    ), before.revision);
    const grant = grantFromAcquire(try state.acquire(input, &owners));
    try state.release(.{
        .lease = input.lease,
        .session = input.session,
        .owner_pid = input.owner_pid,
        .generation = grant.generation,
    });

    const routes = [_]decision.RouteEvidence{
        routeEvidence("route-a", "identity-a", "model-1"),
        routeEvidence("route-b", "identity-b", "model-1"),
    };
    const retained = try state.project(
        sessionHandle("session-other"),
        demand,
        11,
        &owners,
        &scratch,
    );
    const actual = try expectSelected(decision.reduce(demand, &routes, retained.view));
    try testing.expectEqualStrings("route-b", actual.text);

    const erased = try expectSelected(decision.reduce(demand, &routes, .{}));
    try testing.expectEqualStrings("route-a", erased.text);
}

test "stale dead and unknown owners cannot create load or sticky routing" {
    var state = LeaseState(4, 4).init();
    const model = "model-1";
    const inputs = [_]AcquireInput{
        acquireInput("lease-a", "session-a", "account-a", "route-a", model, 1, 1, 10),
        acquireInput("lease-b", "session-b", "account-b", "route-b", model, 2, 2, 100),
        acquireInput("lease-c", "session-c", "account-c", "route-c", model, 3, 3, 100),
        acquireInput("lease-d", "session-d", "account-d", "route-d", model, 4, 4, 100),
    };
    const acquisition_owners = [_]OwnerObservation{
        .{ .owner_pid = 1, .liveness = .alive },
        .{ .owner_pid = 2, .liveness = .alive },
        .{ .owner_pid = 3, .liveness = .alive },
        .{ .owner_pid = 4, .liveness = .alive },
    };
    for (inputs) |input| try state.registerRoute(.{
        .route = input.route,
        .exact_model = input.exact_model,
    });
    for (inputs) |input| {
        _ = try state.acquire(
            atRevision(input, state.currentRevision()),
            &acquisition_owners,
        );
    }

    const owners = [_]OwnerObservation{
        .{ .owner_pid = 2, .liveness = .dead },
        .{ .owner_pid = 4, .liveness = .alive },
    };
    var scratch: [4]LeaseObservation = undefined;
    const projection = try state.project(
        sessionHandle("session-c"),
        try ModelDemand.init(model),
        20,
        &owners,
        &scratch,
    );
    try testing.expectEqual(ProjectionQuality.degraded, projection.quality);
    try testing.expect(projection.view.sticky_route == null);
    try testing.expectEqual(@as(u64, 0), projectedLoad(projection.view, routeHandle("route-a")));
    try testing.expectEqual(@as(u64, 0), projectedLoad(projection.view, routeHandle("route-b")));
    try testing.expectEqual(@as(u64, 0), projectedLoad(projection.view, routeHandle("route-c")));
    try testing.expectEqual(@as(u64, 1), projectedLoad(projection.view, routeHandle("route-d")));

    const live_projection = try state.project(
        sessionHandle("session-d"),
        try ModelDemand.init(model),
        20,
        &owners,
        &scratch,
    );
    try testing.expectEqualStrings(
        "route-d",
        live_projection.view.sticky_route.?.text,
    );

    try testing.expectEqual(@as(usize, 2), try state.cleanupStale(20, &owners));
    try testing.expectEqual(@as(usize, 2), state.len());

    const routes = [_]decision.RouteEvidence{
        routeEvidence("route-a", "identity-a", model),
        routeEvidence("route-b", "identity-b", model),
        routeEvidence("route-c", "identity-c", model),
        routeEvidence("route-d", "identity-d", model),
    };
    const after_cleanup = try state.project(
        sessionHandle("session-other"),
        try ModelDemand.init(model),
        20,
        &owners,
        &scratch,
    );
    const selected = try expectSelected(decision.reduce(
        try ModelDemand.init(model),
        &routes,
        after_cleanup.view,
    ));
    try testing.expectEqualStrings("route-a", selected.text);

    const unavailable = try state.project(
        sessionHandle("session-other"),
        try ModelDemand.init(model),
        20,
        &.{},
        &scratch,
    );
    try testing.expectEqual(ProjectionQuality.degraded, unavailable.quality);
    const reactive = try expectSelected(decision.reduce(
        try ModelDemand.init(model),
        &routes,
        unavailable.view,
    ));
    try testing.expectEqualStrings("route-a", reactive.text);
}

test "duplicate owner facts fold deterministically and conflicts fail unknown" {
    var state = LeaseState(1, 1).init();
    const input = acquireInput(
        "lease-1",
        "session-1",
        "account-1",
        "route-1",
        "model-1",
        7,
        10,
        100,
    );
    try state.registerRoute(.{
        .route = input.route,
        .exact_model = input.exact_model,
    });
    _ = try state.acquire(
        atRevision(input, state.currentRevision()),
        &.{.{ .owner_pid = input.owner_pid, .liveness = .alive }},
    );

    const equal_duplicates = [_]OwnerObservation{
        .{ .owner_pid = 7, .liveness = .alive },
        .{ .owner_pid = 7, .liveness = .alive },
    };
    const conflicts_a = [_]OwnerObservation{
        .{ .owner_pid = 7, .liveness = .alive },
        .{ .owner_pid = 7, .liveness = .dead },
    };
    const conflicts_b = [_]OwnerObservation{
        conflicts_a[1],
        conflicts_a[0],
    };
    var scratch_a: [1]LeaseObservation = undefined;
    var scratch_b: [1]LeaseObservation = undefined;

    const live = try state.project(
        input.session,
        try ModelDemand.init("model-1"),
        20,
        &equal_duplicates,
        &scratch_a,
    );
    try testing.expectEqual(ProjectionQuality.complete, live.quality);
    try testing.expectEqual(@as(u64, 1), live.view.routes[0].active_leases);
    try testing.expect(live.view.sticky_route != null);

    const conflict_a = try state.project(
        input.session,
        try ModelDemand.init("model-1"),
        20,
        &conflicts_a,
        &scratch_a,
    );
    const conflict_b = try state.project(
        input.session,
        try ModelDemand.init("model-1"),
        20,
        &conflicts_b,
        &scratch_b,
    );
    try testing.expectEqual(ProjectionQuality.degraded, conflict_a.quality);
    try testing.expectEqual(conflict_a.quality, conflict_b.quality);
    try testing.expect(conflict_a.view.sticky_route == null);
    try testing.expect(conflict_b.view.sticky_route == null);
    try testing.expectEqual(@as(u64, 0), conflict_a.view.routes[0].active_leases);
    try testing.expectEqual(
        conflict_a.view.routes[0].active_leases,
        conflict_b.view.routes[0].active_leases,
    );
}

test "capacity and timestamp extremes fail explicitly without partial mutation" {
    const max_time = max_timestamp_ms;
    var state = LeaseState(1, 1).init();
    try state.registerRoute(.{
        .route = routeHandle("route-max"),
        .exact_model = exactModel("model-max"),
    });
    const first = AcquireInput{
        .lease = leaseHandle("lease-max"),
        .session = sessionHandle("session-max"),
        .account = accountHandle("account-max"),
        .route = routeHandle("route-max"),
        .exact_model = exactModel("model-max"),
        .owner_pid = @intCast(std.math.maxInt(i32)),
        .expected_revision = state.currentRevision(),
        .now_ms = max_time - 1,
        .selected_at_ms = max_time - 2,
        .heartbeat_at_ms = max_time - 1,
        .expires_at_ms = max_time,
    };
    const max_owner = [_]OwnerObservation{
        .{ .owner_pid = first.owner_pid, .liveness = .alive },
        .{ .owner_pid = 2, .liveness = .alive },
    };
    const first_grant = grantFromAcquire(try state.acquire(first, &max_owner));
    try testing.expectEqual(@as(usize, 1), state.len());
    try testing.expectEqual(RenewOutcome.unchanged, try state.renew(.{
        .lease = first.lease,
        .session = first.session,
        .owner_pid = first.owner_pid,
        .generation = first_grant.generation,
        .now_ms = max_time - 1,
        .heartbeat_at_ms = max_time - 1,
        .expires_at_ms = max_time,
    }));

    const second_same_route = acquireInput(
        "lease-2",
        "session-2",
        "account-2",
        "route-max",
        "model-max",
        2,
        max_time - 1,
        max_time,
    );
    try testing.expectError(
        error.LeaseCapacityExceeded,
        state.acquire(
            atRevision(second_same_route, state.currentRevision()),
            &max_owner,
        ),
    );
    try testing.expectEqual(@as(usize, 1), state.len());

    var too_large = first;
    too_large.lease = leaseHandle("lease-too-large");
    too_large.session = sessionHandle("session-too-large");
    too_large.now_ms = max_timestamp_ms + 1;
    too_large.selected_at_ms = max_timestamp_ms + 1;
    too_large.heartbeat_at_ms = max_timestamp_ms + 1;
    too_large.expires_at_ms = max_timestamp_ms + 2;
    try testing.expectError(error.InvalidLease, state.acquire(too_large, &max_owner));

    var route_limited = LeaseState(2, 1).init();
    const route_owners = [_]OwnerObservation{
        .{ .owner_pid = 1, .liveness = .alive },
        .{ .owner_pid = 2, .liveness = .alive },
    };
    try route_limited.registerRoute(.{
        .route = routeHandle("route-1"),
        .exact_model = exactModel("model-1"),
    });
    _ = try route_limited.acquire(atRevision(acquireInput(
        "lease-1",
        "session-1",
        "account-1",
        "route-1",
        "model-1",
        1,
        1,
        2,
    ), route_limited.currentRevision()), &route_owners);
    try testing.expectError(error.RouteCapacityExceeded, route_limited.registerRoute(.{
        .route = routeHandle("route-2"),
        .exact_model = exactModel("model-1"),
    }));
    try testing.expectError(error.RouteNotRegistered, route_limited.acquire(
        atRevision(acquireInput(
            "lease-2",
            "session-2",
            "account-2",
            "route-2",
            "model-1",
            2,
            1,
            2,
        ), route_limited.currentRevision()),
        &route_owners,
    ));
    try testing.expectEqual(@as(usize, 1), route_limited.len());

    var zero = LeaseState(0, 0).init();
    try testing.expectError(error.LeaseCapacityExceeded, zero.acquire(
        acquireInput(
            "lease-1",
            "session-1",
            "account-1",
            "route-1",
            "model-1",
            1,
            1,
            2,
        ),
        &.{.{ .owner_pid = 1, .liveness = .alive }},
    ));

    var no_scratch: [0]LeaseObservation = .{};
    const unavailable = try state.project(
        first.session,
        try ModelDemand.init("model-max"),
        max_time - 1,
        &.{.{ .owner_pid = first.owner_pid, .liveness = .alive }},
        &no_scratch,
    );
    try testing.expectEqual(ProjectionQuality.unavailable, unavailable.quality);
    try testing.expect(unavailable.view.sticky_route == null);
    try testing.expectEqual(@as(usize, 0), unavailable.view.routes.len);

    const routes = [_]decision.RouteEvidence{
        routeEvidence("route-max", "identity-max", "model-max"),
    };
    const selected = try expectSelected(decision.reduce(
        try ModelDemand.init("model-max"),
        &routes,
        unavailable.view,
    ));
    try testing.expectEqualStrings("route-max", selected.text);

    var revision_exhausted = LeaseState(1, 1).init();
    revision_exhausted.mutation_revision_value = std.math.maxInt(Revision);
    const exhausted_admission_revision = revision_exhausted.currentRevision();
    try testing.expectError(error.RevisionExhausted, revision_exhausted.registerRoute(.{
        .route = routeHandle("route-1"),
        .exact_model = exactModel("model-1"),
    }));
    try testing.expectEqual(@as(usize, 0), revision_exhausted.history_count);
    try testing.expectEqual(
        std.math.maxInt(Revision),
        revision_exhausted.currentMutationRevision(),
    );
    try testing.expectEqual(
        exhausted_admission_revision,
        revision_exhausted.currentRevision(),
    );

    var final_mutation = LeaseState(1, 1).init();
    final_mutation.mutation_revision_value = std.math.maxInt(Revision) - 1;
    try final_mutation.registerRoute(.{
        .route = routeHandle("route-1"),
        .exact_model = exactModel("model-1"),
    });
    try testing.expectEqual(
        std.math.maxInt(Revision),
        final_mutation.currentMutationRevision(),
    );
    const final_admission_revision = final_mutation.currentRevision();
    try testing.expectError(error.RevisionExhausted, final_mutation.acquire(
        atRevision(acquireInput(
            "lease-1",
            "session-1",
            "account-1",
            "route-1",
            "model-1",
            1,
            1,
            2,
        ), final_admission_revision),
        &.{.{ .owner_pid = 1, .liveness = .alive }},
    ));
    try testing.expectEqual(@as(usize, 0), final_mutation.len());
    try testing.expectEqual(
        final_admission_revision,
        final_mutation.currentRevision(),
    );

    var generation_exhausted = LeaseState(1, 1).init();
    try generation_exhausted.registerRoute(.{
        .route = routeHandle("route-1"),
        .exact_model = exactModel("model-1"),
    });
    generation_exhausted.next_generation = std.math.maxInt(Generation);
    const generation_revision = generation_exhausted.currentRevision();
    try testing.expectError(error.GenerationExhausted, generation_exhausted.acquire(
        atRevision(acquireInput(
            "lease-1",
            "session-1",
            "account-1",
            "route-1",
            "model-1",
            1,
            1,
            2,
        ), generation_revision),
        &.{.{ .owner_pid = 1, .liveness = .alive }},
    ));
    try testing.expectEqual(generation_revision, generation_exhausted.currentRevision());
    try testing.expectEqual(@as(usize, 0), generation_exhausted.len());
}

const persistent_session_count = 20;
const persistent_route_count = 50;
const persistent_cycle_count = 100;
const persistent_logical_deadline_rounds =
    persistent_session_count + persistent_cycle_count;

const PersistentMetrics = struct {
    completed: [persistent_session_count]u16,
    sticky_stable: bool,
    max_active_load_spread: u64,
    distinct_initial_routes: usize,
    every_checkpoint_has_all_routes: bool,
    every_checkpoint_load_sum: bool,
    all_sessions_acquired: bool,
    state_changed_retries: u32,
    max_acquire_attempts: u16,
    logical_rounds: usize,
    finished_within_logical_deadline: bool,
};

fn runPersistentWorkload(
    comptime broken_ignore_leases: bool,
    comptime retry_state_changes: bool,
    logical_deadline_rounds: usize,
) !PersistentMetrics {
    const State = LeaseState(persistent_session_count, persistent_route_count);
    var state = State.init();
    const demand = try ModelDemand.init("model-exact");

    var route_name_storage: [persistent_route_count][24]u8 = undefined;
    var account_name_storage: [persistent_route_count][24]u8 = undefined;
    var route_rows: [persistent_route_count]decision.RouteEvidence = undefined;
    var route_handles: [persistent_route_count]RouteHandle = undefined;
    var account_handles: [persistent_route_count]AccountHandle = undefined;
    for (0..persistent_route_count) |index| {
        const route_text = try std.fmt.bufPrint(
            &route_name_storage[index],
            "route-{d}",
            .{index},
        );
        const account_text = try std.fmt.bufPrint(
            &account_name_storage[index],
            "identity-{d}",
            .{index},
        );
        route_handles[index] = try RouteHandle.parse(route_text);
        account_handles[index] = try AccountHandle.parse(account_text);
        route_rows[index] = routeEvidence(route_text, account_text, "model-exact");
        try state.registerRoute(.{
            .route = route_handles[index],
            .exact_model = demand.exact_model,
        });
    }

    var session_name_storage: [persistent_session_count][24]u8 = undefined;
    var lease_name_storage: [persistent_session_count][24]u8 = undefined;
    var sessions: [persistent_session_count]SessionHandle = undefined;
    var leases: [persistent_session_count]LeaseHandle = undefined;
    var owners: [persistent_session_count]OwnerObservation = undefined;
    for (0..persistent_session_count) |index| {
        sessions[index] = try SessionHandle.parse(try std.fmt.bufPrint(
            &session_name_storage[index],
            "session-{d}",
            .{index},
        ));
        leases[index] = try LeaseHandle.parse(try std.fmt.bufPrint(
            &lease_name_storage[index],
            "lease-{d}",
            .{index},
        ));
        owners[index] = .{
            .owner_pid = @intCast(index + 1),
            .liveness = .alive,
        };
    }

    var order: [persistent_session_count]usize = undefined;
    for (&order, 0..) |*entry, index| entry.* = index;
    var prng = std.Random.DefaultPrng.init(0x85_1790_1ea5);
    const random = prng.random();

    var initial_routes: [persistent_session_count]?usize =
        [_]?usize{null} ** persistent_session_count;
    var completed = [_]u16{0} ** persistent_session_count;
    var generations = [_]Generation{0} ** persistent_session_count;
    var pending = [_]bool{true} ** persistent_session_count;
    var acquire_attempts = [_]u16{0} ** persistent_session_count;
    var selected_routes = [_]usize{0} ** persistent_session_count;
    var expected_revisions = [_]Revision{0} ** persistent_session_count;
    var scratch: [persistent_route_count]LeaseObservation = undefined;
    var max_active_load_spread: u64 = 0;
    var sticky_stable = true;
    var every_checkpoint_has_all_routes = true;
    var every_checkpoint_load_sum = true;
    var state_changed_retries: u32 = 0;
    var acquisition_rounds: usize = 0;

    // Every pending session first elects from the same immutable revision.
    // Commits are then interleaved in a shuffled order: one wins and every
    // other stale snapshot must reproject. This is a deterministic pure-state
    // conflict schedule, not a claim of threaded or cross-process safety.
    const acquisition_round_limit =
        if (retry_state_changes) persistent_session_count else 1;
    for (0..acquisition_round_limit) |round| {
        var pending_count: usize = 0;
        for (0..persistent_session_count) |session_index| {
            if (!pending[session_index]) continue;
            pending_count += 1;

            const now_ms: i64 = @intCast(round);
            const projection = try state.project(
                sessions[session_index],
                demand,
                now_ms,
                &owners,
                &scratch,
            );
            try testing.expect(projection.quality != .unavailable);
            const selected = if (broken_ignore_leases)
                route_handles[0]
            else
                try expectSelected(decision.reduce(
                    demand,
                    &route_rows,
                    projection.view,
                ));
            const route_index = findRouteIndex(&route_handles, selected) orelse
                return error.TestUnexpectedResult;
            try testing.expect(demand.accepts(route_rows[route_index].exact_model));
            try testing.expect(route_rows[route_index].readiness == .available);

            selected_routes[session_index] = route_index;
            expected_revisions[session_index] = projection.revision;
            acquire_attempts[session_index] += 1;
        }
        if (pending_count == 0) break;
        acquisition_rounds = round + 1;

        random.shuffle(usize, &order);
        for (order) |session_index| {
            if (!pending[session_index]) continue;
            const route_index = selected_routes[session_index];
            const now_ms: i64 = @intCast(round);
            const outcome = state.acquire(.{
                .lease = leases[session_index],
                .session = sessions[session_index],
                .account = account_handles[route_index],
                .route = route_handles[route_index],
                .exact_model = demand.exact_model,
                .owner_pid = owners[session_index].owner_pid,
                .expected_revision = expected_revisions[session_index],
                .now_ms = now_ms,
                .selected_at_ms = now_ms,
                .heartbeat_at_ms = now_ms,
                .expires_at_ms = now_ms + 2000,
            }, &owners) catch |err| {
                if (err == error.StateChanged) {
                    state_changed_retries += 1;
                    continue;
                }
                return err;
            };
            initial_routes[session_index] = route_index;
            generations[session_index] = grantFromAcquire(outcome).generation;
            pending[session_index] = false;
        }
    }

    for (0..persistent_cycle_count) |cycle| {
        random.shuffle(usize, &order);
        for (order, 0..) |session_index, step| {
            if (pending[session_index]) continue;
            const now_ms: i64 = @intCast(1000 + cycle * 1000 + step);
            const projection = try state.project(
                sessions[session_index],
                demand,
                now_ms,
                &owners,
                &scratch,
            );
            try testing.expect(projection.quality != .unavailable);

            const selected = if (broken_ignore_leases)
                route_handles[0]
            else
                try expectSelected(decision.reduce(demand, &route_rows, projection.view));
            const route_index = findRouteIndex(&route_handles, selected) orelse
                return error.TestUnexpectedResult;
            try testing.expect(demand.accepts(route_rows[route_index].exact_model));
            try testing.expect(route_rows[route_index].readiness == .available);

            if (initial_routes[session_index].? != route_index) {
                sticky_stable = false;
            }
            _ = try state.renew(.{
                .lease = leases[session_index],
                .session = sessions[session_index],
                .owner_pid = owners[session_index].owner_pid,
                .generation = generations[session_index],
                .now_ms = now_ms,
                .heartbeat_at_ms = now_ms,
                .expires_at_ms = now_ms + 2000,
            });
            completed[session_index] += 1;
        }

        const checkpoint_now: i64 =
            @intCast(1000 + cycle * 1000 + persistent_session_count);
        const checkpoint = try state.project(
            sessions[0],
            demand,
            checkpoint_now,
            &owners,
            &scratch,
        );
        try testing.expect(checkpoint.quality != .unavailable);
        if (checkpoint.view.routes.len != persistent_route_count) {
            every_checkpoint_has_all_routes = false;
        }
        var minimum: u64 = std.math.maxInt(u64);
        var maximum: u64 = 0;
        var load_sum: u64 = 0;
        for (route_handles) |route_handle| {
            const load = projectedLoad(checkpoint.view, route_handle);
            minimum = @min(minimum, load);
            maximum = @max(maximum, load);
            load_sum += load;
        }
        if (load_sum != persistent_session_count) every_checkpoint_load_sum = false;
        max_active_load_spread = @max(
            max_active_load_spread,
            maximum - minimum,
        );
    }

    var distinct_initial_routes: usize = 0;
    for (0..persistent_route_count) |route_index| {
        for (initial_routes) |selected| {
            if (selected != null and selected.? == route_index) {
                distinct_initial_routes += 1;
                break;
            }
        }
    }
    var all_sessions_acquired = true;
    var all_cycles_completed = true;
    var max_acquire_attempts: u16 = 0;
    for (pending, acquire_attempts, completed) |is_pending, attempts, cycles| {
        if (is_pending) all_sessions_acquired = false;
        if (cycles != persistent_cycle_count) all_cycles_completed = false;
        max_acquire_attempts = @max(max_acquire_attempts, attempts);
    }
    const logical_rounds = acquisition_rounds + persistent_cycle_count;

    return .{
        .completed = completed,
        .sticky_stable = sticky_stable,
        .max_active_load_spread = max_active_load_spread,
        .distinct_initial_routes = distinct_initial_routes,
        .every_checkpoint_has_all_routes = every_checkpoint_has_all_routes,
        .every_checkpoint_load_sum = every_checkpoint_load_sum,
        .all_sessions_acquired = all_sessions_acquired,
        .state_changed_retries = state_changed_retries,
        .max_acquire_attempts = max_acquire_attempts,
        .logical_rounds = logical_rounds,
        .finished_within_logical_deadline = all_sessions_acquired and
            all_cycles_completed and
            logical_rounds <= logical_deadline_rounds,
    };
}

fn findRouteIndex(routes: []const RouteHandle, needle: RouteHandle) ?usize {
    for (routes, 0..) |route, index| {
        if (handleEql(route.text, needle.text)) return index;
    }
    return null;
}

test "stale-snapshot retries admit 20 persistent sessions without starvation" {
    const metrics = try runPersistentWorkload(
        false,
        true,
        persistent_logical_deadline_rounds,
    );
    try testing.expect(metrics.all_sessions_acquired);
    try testing.expect(metrics.state_changed_retries > 0);
    try testing.expectEqual(
        @as(u16, persistent_session_count),
        metrics.max_acquire_attempts,
    );
    try testing.expectEqual(
        @as(usize, persistent_logical_deadline_rounds),
        metrics.logical_rounds,
    );
    try testing.expect(metrics.finished_within_logical_deadline);
    for (metrics.completed) |cycles| {
        try testing.expectEqual(
            @as(u16, persistent_cycle_count),
            cycles,
        );
    }
    try testing.expect(metrics.sticky_stable);
    try testing.expectEqual(
        @as(usize, persistent_session_count),
        metrics.distinct_initial_routes,
    );
    try testing.expect(metrics.max_active_load_spread <= 1);
    try testing.expect(metrics.every_checkpoint_has_all_routes);
    try testing.expect(metrics.every_checkpoint_load_sum);
}

test "negative control: ignoring lease load violates the persistent workload bound" {
    const broken = try runPersistentWorkload(
        true,
        true,
        persistent_logical_deadline_rounds,
    );
    try testing.expect(broken.all_sessions_acquired);
    try testing.expect(broken.state_changed_retries > 0);
    try testing.expect(broken.finished_within_logical_deadline);
    for (broken.completed) |cycles| {
        try testing.expectEqual(
            @as(u16, persistent_cycle_count),
            cycles,
        );
    }
    try testing.expect(broken.sticky_stable);
    try testing.expectEqual(@as(usize, 1), broken.distinct_initial_routes);
    try testing.expect(broken.max_active_load_spread > 1);
}

test "negative controls reject nonzero-only load and omitted state-change retry" {
    const loads = [_]u64{ 1, 1, 0, 0 };
    var true_minimum: u64 = std.math.maxInt(u64);
    var true_maximum: u64 = 0;
    var nonzero_minimum: u64 = std.math.maxInt(u64);
    var nonzero_maximum: u64 = 0;
    for (loads) |load| {
        true_minimum = @min(true_minimum, load);
        true_maximum = @max(true_maximum, load);
        if (load != 0) {
            nonzero_minimum = @min(nonzero_minimum, load);
            nonzero_maximum = @max(nonzero_maximum, load);
        }
    }
    try testing.expectEqual(@as(u64, 1), true_maximum - true_minimum);
    try testing.expectEqual(@as(u64, 0), nonzero_maximum - nonzero_minimum);

    const no_retry = try runPersistentWorkload(
        false,
        false,
        persistent_logical_deadline_rounds,
    );
    try testing.expect(!no_retry.all_sessions_acquired);
    try testing.expectEqual(
        @as(u32, persistent_session_count - 1),
        no_retry.state_changed_retries,
    );
    try testing.expectEqual(@as(u16, 1), no_retry.max_acquire_attempts);
    var completed_sessions: usize = 0;
    for (no_retry.completed) |cycles| {
        if (cycles == persistent_cycle_count) completed_sessions += 1;
    }
    try testing.expectEqual(@as(usize, 1), completed_sessions);
    try testing.expect(!no_retry.every_checkpoint_load_sum);
    try testing.expect(!no_retry.finished_within_logical_deadline);

    const too_tight = try runPersistentWorkload(
        false,
        true,
        persistent_logical_deadline_rounds - 1,
    );
    try testing.expect(too_tight.all_sessions_acquired);
    try testing.expectEqual(
        @as(usize, persistent_logical_deadline_rounds),
        too_tight.logical_rounds,
    );
    try testing.expect(!too_tight.finished_within_logical_deadline);
}

test "ended-session churn balances selection history without weakening stickiness" {
    const session_count = 20;
    const route_count = 50;
    const cycle_count = 100;
    var state = LeaseState(session_count, route_count).init();
    const demand = try ModelDemand.init("model-exact");

    var route_name_storage: [route_count][24]u8 = undefined;
    var account_name_storage: [route_count][24]u8 = undefined;
    var route_rows: [route_count]decision.RouteEvidence = undefined;
    var route_handles: [route_count]RouteHandle = undefined;
    var account_handles: [route_count]AccountHandle = undefined;
    for (0..route_count) |index| {
        const route_text = try std.fmt.bufPrint(
            &route_name_storage[index],
            "route-{d}",
            .{index},
        );
        const account_text = try std.fmt.bufPrint(
            &account_name_storage[index],
            "identity-{d}",
            .{index},
        );
        route_handles[index] = try RouteHandle.parse(route_text);
        account_handles[index] = try AccountHandle.parse(account_text);
        route_rows[index] = routeEvidence(route_text, account_text, "model-exact");
        try state.registerRoute(.{
            .route = route_handles[index],
            .exact_model = demand.exact_model,
        });
    }

    var owners: [session_count]OwnerObservation = undefined;
    for (&owners, 0..) |*owner, index| {
        owner.* = .{ .owner_pid = @intCast(index + 1), .liveness = .alive };
    }
    var selection_counts = [_]u32{0} ** route_count;
    var scratch: [route_count]LeaseObservation = undefined;
    var session_names: [session_count][32]u8 = undefined;
    var lease_names: [session_count][32]u8 = undefined;

    for (0..cycle_count) |cycle| {
        var active_sessions: [session_count]SessionHandle = undefined;
        var active_leases: [session_count]LeaseHandle = undefined;
        var active_generations: [session_count]Generation = undefined;
        for (0..session_count) |slot| {
            active_sessions[slot] = try SessionHandle.parse(try std.fmt.bufPrint(
                &session_names[slot],
                "session-{d}-{d}",
                .{ cycle, slot },
            ));
            active_leases[slot] = try LeaseHandle.parse(try std.fmt.bufPrint(
                &lease_names[slot],
                "lease-{d}-{d}",
                .{ cycle, slot },
            ));
            const now_ms: i64 = @intCast(cycle * session_count + slot);
            const projection = try state.project(
                active_sessions[slot],
                demand,
                now_ms,
                &owners,
                &scratch,
            );
            const selected = try expectSelected(decision.reduce(
                demand,
                &route_rows,
                projection.view,
            ));
            const route_index = findRouteIndex(&route_handles, selected) orelse
                return error.TestUnexpectedResult;
            selection_counts[route_index] += 1;
            active_generations[slot] = grantFromAcquire(try state.acquire(.{
                .lease = active_leases[slot],
                .session = active_sessions[slot],
                .account = account_handles[route_index],
                .route = selected,
                .exact_model = demand.exact_model,
                .owner_pid = owners[slot].owner_pid,
                .expected_revision = projection.revision,
                .now_ms = now_ms,
                .selected_at_ms = now_ms,
                .heartbeat_at_ms = now_ms,
                .expires_at_ms = now_ms + 1000,
            }, &owners)).generation;
        }

        const checkpoint = try state.project(
            active_sessions[0],
            demand,
            @intCast(cycle * session_count + session_count),
            &owners,
            &scratch,
        );
        var minimum_load: u64 = std.math.maxInt(u64);
        var maximum_load: u64 = 0;
        for (route_handles) |route_handle| {
            const load = projectedLoad(checkpoint.view, route_handle);
            minimum_load = @min(minimum_load, load);
            maximum_load = @max(maximum_load, load);
        }
        try testing.expect(maximum_load - minimum_load <= 1);

        for (0..session_count) |slot| {
            try state.release(.{
                .lease = active_leases[slot],
                .session = active_sessions[slot],
                .owner_pid = owners[slot].owner_pid,
                .generation = active_generations[slot],
            });
        }
        try testing.expectEqual(@as(usize, 0), state.len());
        const after_release = try state.project(
            active_sessions[0],
            demand,
            @intCast(cycle * session_count + session_count),
            &owners,
            &scratch,
        );
        try testing.expectEqual(@as(usize, route_count), after_release.view.routes.len);
        var after_release_sum: u64 = 0;
        for (after_release.view.routes) |row| {
            after_release_sum += row.active_leases;
        }
        // A post-release checkpoint has a deceptively perfect spread but is
        // not the synchronized 20-live-session acceptance checkpoint.
        try testing.expectEqual(@as(u64, 0), after_release_sum);
    }

    var minimum_selections: u32 = std.math.maxInt(u32);
    var maximum_selections: u32 = 0;
    for (selection_counts) |count| {
        minimum_selections = @min(minimum_selections, count);
        maximum_selections = @max(maximum_selections, count);
    }
    try testing.expect(maximum_selections - minimum_selections <= 1);
}

test "seeded acquisition and liveness permutations preserve projection" {
    const record_count = 8;
    const route_count = 4;
    var session_storage: [record_count][24]u8 = undefined;
    var lease_storage: [record_count][24]u8 = undefined;
    var route_storage: [route_count][24]u8 = undefined;
    var account_storage: [route_count][24]u8 = undefined;
    var routes: [route_count]RouteHandle = undefined;
    var accounts: [route_count]AccountHandle = undefined;
    for (0..route_count) |index| {
        routes[index] = try RouteHandle.parse(try std.fmt.bufPrint(
            &route_storage[index],
            "route-{d}",
            .{index},
        ));
        accounts[index] = try AccountHandle.parse(try std.fmt.bufPrint(
            &account_storage[index],
            "account-{d}",
            .{index},
        ));
    }

    var inputs: [record_count]AcquireInput = undefined;
    var owners: [record_count]OwnerObservation = undefined;
    for (0..record_count) |index| {
        const selected_at: i64 = @intCast(index + 1);
        inputs[index] = .{
            .lease = try LeaseHandle.parse(try std.fmt.bufPrint(
                &lease_storage[index],
                "lease-{d}",
                .{index},
            )),
            .session = try SessionHandle.parse(try std.fmt.bufPrint(
                &session_storage[index],
                "session-{d}",
                .{index},
            )),
            .account = accounts[index % route_count],
            .route = routes[index % route_count],
            .exact_model = try ExactModel.init("model-exact"),
            .owner_pid = @intCast(index + 1),
            .expected_revision = 0,
            .now_ms = 20,
            .selected_at_ms = selected_at,
            .heartbeat_at_ms = 20,
            .expires_at_ms = 100,
        };
        owners[index] = .{
            .owner_pid = @intCast(index + 1),
            .liveness = .alive,
        };
    }

    var baseline_state = LeaseState(record_count, route_count).init();
    for (routes) |route| try baseline_state.registerRoute(.{
        .route = route,
        .exact_model = try ExactModel.init("model-exact"),
    });
    for (inputs) |input| _ = try baseline_state.acquire(
        atRevision(input, baseline_state.currentRevision()),
        &owners,
    );
    var baseline_scratch: [route_count]LeaseObservation = undefined;
    const baseline = try baseline_state.project(
        inputs[0].session,
        try ModelDemand.init("model-exact"),
        30,
        &owners,
        &baseline_scratch,
    );

    var order: [record_count]usize = undefined;
    for (&order, 0..) |*entry, index| entry.* = index;
    var shuffled_owners = owners;
    var prng = std.Random.DefaultPrng.init(0x85_1790_5eed);
    const random = prng.random();

    for (0..128) |_| {
        random.shuffle(usize, &order);
        random.shuffle(OwnerObservation, &shuffled_owners);
        var state = LeaseState(record_count, route_count).init();
        for (routes) |route| try state.registerRoute(.{
            .route = route,
            .exact_model = try ExactModel.init("model-exact"),
        });
        for (order) |index| _ = try state.acquire(
            atRevision(inputs[index], state.currentRevision()),
            &shuffled_owners,
        );

        var scratch: [route_count]LeaseObservation = undefined;
        const actual = try state.project(
            inputs[0].session,
            try ModelDemand.init("model-exact"),
            30,
            &shuffled_owners,
            &scratch,
        );
        try testing.expectEqual(baseline.quality, actual.quality);
        try testing.expectEqual(baseline.view.routes.len, actual.view.routes.len);
        try testing.expectEqualStrings(
            baseline.view.sticky_route.?.text,
            actual.view.sticky_route.?.text,
        );
        for (baseline.view.routes, actual.view.routes) |expected, observed| {
            try testing.expectEqualStrings(expected.route.text, observed.route.text);
            try testing.expectEqual(expected.active_leases, observed.active_leases);
            try testing.expectEqual(expected.last_selected_at, observed.last_selected_at);
        }
    }
}

test "negative control: cleanup disabled changes reactive election" {
    const demand = try ModelDemand.init("model-1");
    const routes = [_]decision.RouteEvidence{
        routeEvidence("route-a", "identity-a", "model-1"),
        routeEvidence("route-b", "identity-b", "model-1"),
    };
    var state = LeaseState(2, 2).init();
    const owners = [_]OwnerObservation{
        .{ .owner_pid = 1, .liveness = .alive },
        .{ .owner_pid = 2, .liveness = .alive },
    };
    try state.registerRoute(.{
        .route = routeHandle("route-a"),
        .exact_model = demand.exact_model,
    });
    try state.registerRoute(.{
        .route = routeHandle("route-b"),
        .exact_model = demand.exact_model,
    });
    const live = acquireInput(
        "lease-b",
        "session-b",
        "account-b",
        "route-b",
        "model-1",
        2,
        1,
        100,
    );
    _ = try state.acquire(atRevision(live, state.currentRevision()), &owners);
    const stale = acquireInput(
        "lease-a",
        "session-a",
        "account-a",
        "route-a",
        "model-1",
        1,
        2,
        10,
    );
    _ = try state.acquire(
        atRevision(stale, state.currentRevision()),
        &owners,
    );

    var scratch: [2]LeaseObservation = undefined;
    const actual = try state.project(
        sessionHandle("session-other"),
        demand,
        20,
        &owners,
        &scratch,
    );
    try testing.expectEqual(@as(u64, 0), projectedLoad(actual.view, routeHandle("route-a")));
    try testing.expectEqual(@as(u64, 1), projectedLoad(actual.view, routeHandle("route-b")));
    const selected = try expectSelected(decision.reduce(demand, &routes, actual.view));
    try testing.expectEqualStrings("route-a", selected.text);

    const broken_rows = [_]LeaseObservation{
        .{
            .route = routeHandle("route-a"),
            .active_leases = 1,
            .last_selected_at = 2,
        },
        .{
            .route = routeHandle("route-b"),
            .active_leases = 1,
            .last_selected_at = 1,
        },
    };
    const broken = try expectSelected(decision.reduce(demand, &routes, .{
        .routes = &broken_rows,
    }));
    try testing.expectEqualStrings("route-b", broken.text);
}
