//! Redacted cross-process persistence around the pure broker lease state.
//!
//! The file is advisory routing state, never credential authority. Callers
//! inject an absolute runtime/state root, time, and exact process-incarnation
//! liveness. Missing state is an empty advisory view until a mutation
//! initializes the store. Lock contention may degrade to reactive routing at
//! the runtime boundary; corrupt, incompatible, or custody-uncertain state
//! fails closed and never becomes invented capacity.

const std = @import("std");
const builtin = @import("builtin");
const identifiers = @import("identifiers.zig");
const lease_state = @import("lease_state.zig");
const lock_wait = @import("../lock_wait.zig");

pub const OwnerLiveness = enum { alive, dead, unknown };

/// `incarnation` is stable process-start evidence supplied by the platform
/// adapter. A PID alone is never an owner identity. `generation` lets a live
/// process deliberately supersede an earlier ownership epoch without allowing
/// the earlier epoch's leases to be inherited.
pub const OwnerIdentity = struct {
    pid: lease_state.OwnerPid,
    incarnation: u64,
    generation: u64,

    pub fn isValid(self: OwnerIdentity) bool {
        return self.pid > 0 and
            self.pid <= std.math.maxInt(i32) and
            self.incarnation > 0 and
            self.incarnation <= lease_state.max_timestamp_ms and
            self.generation > 0 and
            self.generation <= lease_state.max_timestamp_ms;
    }

    pub fn eql(a: OwnerIdentity, b: OwnerIdentity) bool {
        return a.pid == b.pid and
            a.incarnation == b.incarnation and
            a.generation == b.generation;
    }
};

pub const LivenessFn = *const fn (ctx: *const anyopaque, owner: OwnerIdentity) OwnerLiveness;

pub const LivenessSource = struct {
    ctx: *const anyopaque,
    resolve: LivenessFn,

    pub fn status(self: LivenessSource, owner: OwnerIdentity) OwnerLiveness {
        return self.resolve(self.ctx, owner);
    }
};

pub const TimeReadFn = *const fn (
    ctx: ?*const anyopaque,
    requested_ms: ?lease_state.TimestampMs,
) anyerror!lease_state.TimestampMs;

pub const TimeSource = struct {
    ctx: ?*const anyopaque = null,
    read: TimeReadFn = systemTimeMs,

    fn sample(
        self: TimeSource,
        requested_ms: ?lease_state.TimestampMs,
    ) !lease_state.TimestampMs {
        const value = try self.read(self.ctx, requested_ms);
        if (!timestampValid(value)) return error.InvalidClockSample;
        return value;
    }
};

pub const MonotonicStartFn = *const fn () anyerror!std.time.Timer;

pub const PostRenameHook = struct {
    ctx: *anyopaque,
    run: *const fn (ctx: *anyopaque) anyerror!void,
};

pub const Options = struct {
    wait: lock_wait.WaitOptions = .{},
    time: TimeSource = .{},
    monotonic_start: MonotonicStartFn = startMonotonicTimer,
    /// Null uses stderr, matching the resident lock convention. Tests inject a
    /// temporary file so no operator log or real runtime path is touched.
    log_file: ?std.fs.File = null,
    /// Test-only persistence fault seam. It runs after the canonical rename,
    /// where any failure has commit-uncertain semantics.
    post_rename_hook: ?PostRenameHook = null,
};

pub const AcquireInput = struct {
    lease: lease_state.LeaseHandle,
    session: lease_state.SessionHandle,
    account: lease_state.AccountHandle,
    route: lease_state.RouteHandle,
    exact_model: lease_state.ExactModel,
    owner: OwnerIdentity,
    expected_revision: lease_state.Revision,
    now_ms: lease_state.TimestampMs,
    selected_at_ms: lease_state.TimestampMs,
    heartbeat_at_ms: lease_state.TimestampMs,
    expires_at_ms: lease_state.TimestampMs,
};

pub const RenewInput = struct {
    lease: lease_state.LeaseHandle,
    session: lease_state.SessionHandle,
    owner: OwnerIdentity,
    generation: lease_state.Generation,
    now_ms: lease_state.TimestampMs,
    heartbeat_at_ms: lease_state.TimestampMs,
    expires_at_ms: lease_state.TimestampMs,
};

pub const ReleaseInput = struct {
    lease: lease_state.LeaseHandle,
    session: lease_state.SessionHandle,
    owner: OwnerIdentity,
    generation: lease_state.Generation,
};

pub const TransitionInput = struct {
    current_lease: lease_state.LeaseHandle,
    current_generation: lease_state.Generation,
    next: AcquireInput,
};

pub const AcquireOutcome = lease_state.AcquireOutcome;
pub const RenewOutcome = lease_state.RenewOutcome;
pub const LeaseGrant = lease_state.LeaseGrant;
pub const ProjectionQuality = lease_state.ProjectionQuality;

/// Custody-validated canonical lease used only to reconcile a mutation whose
/// post-rename durability acknowledgement was lost. The fixed buffers keep the
/// result allocator-free and prevent borrowed snapshot memory escaping.
pub const ReconciledLease = struct {
    lease_buf: [identifiers.max_handle_len]u8 = [_]u8{0} ** identifiers.max_handle_len,
    lease_len: u16 = 0,
    account_buf: [identifiers.max_handle_len]u8 = [_]u8{0} ** identifiers.max_handle_len,
    account_len: u16 = 0,
    route_buf: [identifiers.max_handle_len]u8 = [_]u8{0} ** identifiers.max_handle_len,
    route_len: u16 = 0,
    exact_model: lease_state.ExactModel,
    generation: lease_state.Generation,
    transition_origin_lease_buf: [identifiers.max_handle_len]u8 = [_]u8{0} ** identifiers.max_handle_len,
    transition_origin_lease_len: u16 = 0,
    transition_origin_generation: ?lease_state.Generation = null,

    pub fn lease(self: *const ReconciledLease) lease_state.LeaseHandle {
        return lease_state.LeaseHandle.parse(self.lease_buf[0..self.lease_len]) catch unreachable;
    }

    pub fn account(self: *const ReconciledLease) lease_state.AccountHandle {
        return lease_state.AccountHandle.parse(self.account_buf[0..self.account_len]) catch unreachable;
    }

    pub fn route(self: *const ReconciledLease) lease_state.RouteHandle {
        return lease_state.RouteHandle.parse(self.route_buf[0..self.route_len]) catch unreachable;
    }

    pub fn transitionOriginLease(self: *const ReconciledLease) ?lease_state.LeaseHandle {
        if (self.transition_origin_generation == null) return null;
        return lease_state.LeaseHandle.parse(
            self.transition_origin_lease_buf[0..self.transition_origin_lease_len],
        ) catch unreachable;
    }
};

const snapshot_version: u8 = 2;
const snapshot_contract_fingerprint =
    "b97b10e3f2a9b42f137655559e8d9366bd10d8edf05ff04836484a64ed98f21d";
const state_file_name = "broker-leases-v2.json";
const lock_file_name = "broker-leases-v2.lock";
const max_snapshot_bytes: usize = 1024 * 1024;
const max_store_capacity: usize = 256;
const clock_recovery_window_ms: lease_state.TimestampMs = 30_000;

fn OwnedText(comptime max_len: usize) type {
    return struct {
        const Self = @This();

        buf: [max_len]u8 = [_]u8{0} ** max_len,
        len: u16 = 0,

        fn init(value: []const u8) error{InvalidLeaseState}!Self {
            if (value.len == 0 or value.len > max_len) return error.InvalidLeaseState;
            var result = Self{};
            @memcpy(result.buf[0..value.len], value);
            result.len = @intCast(value.len);
            return result;
        }

        fn bytes(self: *const Self) []const u8 {
            return self.buf[0..self.len];
        }

        fn eql(self: *const Self, value: []const u8) bool {
            return std.mem.eql(u8, self.bytes(), value);
        }
    };
}

const OwnedHandle = OwnedText(identifiers.max_handle_len);

const StoredRoute = struct {
    route: OwnedHandle,
    exact_model: lease_state.ExactModel,
    last_selected_at_ms: ?lease_state.TimestampMs,
};

const TransitionOrigin = struct {
    lease: OwnedHandle,
    generation: lease_state.Generation,
};

const StoredLease = struct {
    lease: OwnedHandle,
    session: OwnedHandle,
    account: OwnedHandle,
    route: OwnedHandle,
    exact_model: lease_state.ExactModel,
    owner: OwnerIdentity,
    generation: lease_state.Generation,
    selected_at_ms: lease_state.TimestampMs,
    heartbeat_at_ms: lease_state.TimestampMs,
    expires_at_ms: lease_state.TimestampMs,
    transition_from: ?TransitionOrigin,
};

fn emptyStoredLease() StoredLease {
    return std.mem.zeroes(StoredLease);
}

const WireOwner = struct {
    pid: u32,
    incarnation: u64,
    generation: u64,
};

const WireRoute = struct {
    route: []const u8,
    exact_model: []const u8,
    last_selected_at_ms: ?i64 = null,
};

const WireOrigin = struct {
    lease: []const u8,
    generation: u64,
};

const WireLease = struct {
    lease: []const u8,
    session: []const u8,
    account: []const u8,
    route: []const u8,
    exact_model: []const u8,
    owner: WireOwner,
    generation: u64,
    selected_at_ms: i64,
    heartbeat_at_ms: i64,
    expires_at_ms: i64,
    transition_from: ?WireOrigin = null,
};

const WireSnapshot = struct {
    version: u8,
    contract_fingerprint: []const u8,
    lease_capacity: usize,
    route_capacity: usize,
    mutation_revision: u64,
    admission_revision: u64,
    last_observed_at_ms: ?i64,
    clock_recovery_until_ms: ?i64,
    next_generation: u64,
    routes: []const WireRoute,
    leases: []const WireLease,
};

const LoadQuality = enum { present, missing };

const FileIdentity = struct {
    device: u64,
    inode: u64,

    fn eql(a: FileIdentity, b: FileIdentity) bool {
        return a.device == b.device and a.inode == b.inode;
    }
};

const FilePurpose = enum { lock, state, temporary };

const ObservationOutcome = enum { ready, quarantined };

fn systemTimeMs(
    _: ?*const anyopaque,
    _: ?lease_state.TimestampMs,
) !lease_state.TimestampMs {
    return std.time.milliTimestamp();
}

fn startMonotonicTimer() !std.time.Timer {
    return std.time.Timer.start();
}

fn timestampValid(value: i64) bool {
    return value >= 0 and value <= lease_state.max_timestamp_ms;
}

fn generationValid(value: u64) bool {
    return value > 0 and value <= @as(u64, @intCast(lease_state.max_timestamp_ms));
}

fn ownerStatus(source: LivenessSource, owner: OwnerIdentity) OwnerLiveness {
    if (!owner.isValid()) return .unknown;
    return source.status(owner);
}

pub fn LeaseStore(comptime lease_capacity: usize, comptime route_capacity: usize) type {
    if (lease_capacity == 0 or lease_capacity > max_store_capacity) {
        @compileError("lease store capacity must be in 1...256");
    }
    if (route_capacity == 0 or route_capacity > max_store_capacity) {
        @compileError("route store capacity must be in 1...256");
    }

    return struct {
        const Self = @This();
        const PureState = lease_state.LeaseState(lease_capacity, route_capacity);

        const Snapshot = struct {
            mutation_revision: lease_state.Revision = 0,
            admission_revision: lease_state.Revision = 0,
            last_observed_at_ms: ?lease_state.TimestampMs = null,
            clock_recovery_until_ms: ?lease_state.TimestampMs = null,
            next_generation: lease_state.Generation = 1,
            routes: [route_capacity]StoredRoute = undefined,
            route_count: usize = 0,
            leases: [lease_capacity]StoredLease = undefined,
            lease_count: usize = 0,

            fn initInPlace(self: *Snapshot) void {
                @memset(std.mem.asBytes(&self.routes), 0);
                @memset(std.mem.asBytes(&self.leases), 0);
                self.mutation_revision = 0;
                self.admission_revision = 0;
                self.last_observed_at_ms = null;
                self.clock_recovery_until_ms = null;
                self.next_generation = 1;
                self.route_count = 0;
                self.lease_count = 0;
            }
        };

        const Loaded = struct {
            quality: LoadQuality,
            snapshot: *Snapshot,
            identity: ?FileIdentity = null,

            fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
                allocator.destroy(self.snapshot);
                self.* = undefined;
            }
        };

        pub const ProjectionRow = struct {
            route: OwnedHandle,
            active_leases: u64,
            last_selected_at: ?lease_state.TimestampMs,

            pub fn routeText(self: *const ProjectionRow) []const u8 {
                return self.route.bytes();
            }
        };

        pub const Projection = struct {
            revision: lease_state.Revision = 0,
            quality: ProjectionQuality = .unavailable,
            sticky_route: ?OwnedHandle = null,
            rows: [route_capacity]ProjectionRow = undefined,
            row_count: usize = 0,

            pub fn routeRows(self: *const Projection) []const ProjectionRow {
                return self.rows[0..self.row_count];
            }

            pub fn stickyRouteText(self: *const Projection) ?[]const u8 {
                if (self.sticky_route) |*sticky| return sticky.bytes();
                return null;
            }
        };

        pub const CleanupReport = struct {
            removed_count: usize,
            owner_count: usize,
        };

        const Rebuilt = struct {
            state: PureState,
            pure_generations: [lease_capacity]lease_state.Generation,
            synthetic_pids: [lease_capacity]lease_state.OwnerPid,
        };

        const ReplayEvent = struct {
            at_ms: lease_state.TimestampMs,
            kind: enum { history, lease },
            index: usize,
        };

        allocator: std.mem.Allocator,
        root: []const u8,
        dir: std.fs.Dir,
        root_owner: u64,
        options: Options,

        pub fn init(
            allocator: std.mem.Allocator,
            absolute_root: []const u8,
            options: Options,
        ) !Self {
            if (!std.fs.path.isAbsolute(absolute_root)) return error.InvalidRuntimeRoot;
            if (absolute_root.len == 0) return error.InvalidRuntimeRoot;
            try ensureDurableDirectoryAbsolute(absolute_root);
            var dir = try std.fs.openDirAbsolute(absolute_root, .{
                .iterate = true,
                .no_follow = true,
            });
            errdefer dir.close();
            const root_owner = try validateDirectoryCustody(dir);
            return .{
                .allocator = allocator,
                .root = try allocator.dupe(u8, absolute_root),
                .dir = dir,
                .root_owner = root_owner,
                .options = options,
            };
        }

        pub fn deinit(self: *Self) void {
            self.dir.close();
            self.allocator.free(self.root);
            self.* = undefined;
        }

        /// The request runtime narrows each flock wait to the remaining
        /// request-scoped advisory budget. The runtime serializes access to its
        /// store instance and restores the configured wait after the request.
        pub fn replaceWaitOptions(
            self: *Self,
            wait: lock_wait.WaitOptions,
        ) lock_wait.WaitOptions {
            const previous = self.options.wait;
            self.options.wait = wait;
            return previous;
        }

        pub fn registerRoute(self: *Self, input: lease_state.RouteRegistration) !void {
            return self.registerRoutes(&.{input});
        }

        /// Registers one complete adapter route catalog under a single flock and
        /// persists it as one admission mutation. Validation and capacity checks
        /// finish before the snapshot changes, so readers never observe a partial
        /// first-use catalog.
        pub fn registerRoutes(self: *Self, inputs: []const lease_state.RouteRegistration) !void {
            if (inputs.len == 0) return;
            var lock = try self.acquireLock();
            defer lock.deinit();
            var loaded = try self.loadForMutation();
            defer loaded.deinit(self.allocator);
            _ = try self.observeAndPersist(&loaded, null);
            const snapshot = loaded.snapshot;

            var missing_count: usize = 0;
            for (inputs, 0..) |input, input_index| {
                _ = try lease_state.RouteHandle.parse(input.route.text);
                if (!input.exact_model.isValid()) return error.InvalidLease;
                if (findRoute(snapshot, input.route, input.exact_model) != null) continue;
                var duplicate = false;
                for (inputs[0..input_index]) |earlier| {
                    if (std.mem.eql(u8, earlier.route.text, input.route.text) and
                        earlier.exact_model.eql(input.exact_model))
                    {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate) missing_count += 1;
            }
            if (missing_count == 0) return;
            if (missing_count > route_capacity - snapshot.route_count) {
                return error.RouteCapacityExceeded;
            }
            try ensureAdmissionMutationAvailable(snapshot);

            const pure = try rebuildAlloc(self.allocator, snapshot);
            defer self.allocator.destroy(pure);
            for (inputs, 0..) |input, input_index| {
                if (findRoute(snapshot, input.route, input.exact_model) != null) continue;
                var duplicate = false;
                for (inputs[0..input_index]) |earlier| {
                    if (std.mem.eql(u8, earlier.route.text, input.route.text) and
                        earlier.exact_model.eql(input.exact_model))
                    {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate) continue;
                try pure.state.registerRoute(input);
                snapshot.routes[snapshot.route_count] = .{
                    .route = try ownedHandle(input.route.text),
                    .exact_model = input.exact_model,
                    .last_selected_at_ms = null,
                };
                snapshot.route_count += 1;
            }
            sortRoutes(snapshot);
            bumpAdmissionMutation(snapshot);
            loaded.identity = try self.persist(snapshot, loaded.identity);
        }

        pub fn acquire(
            self: *Self,
            input: AcquireInput,
            liveness: LivenessSource,
        ) !AcquireOutcome {
            var lock = try self.acquireLock();
            defer lock.deinit();
            var loaded = try self.loadForMutation();
            defer loaded.deinit(self.allocator);
            const now_ms = try self.observeAndPersist(&loaded, input.now_ms);
            const snapshot = loaded.snapshot;

            try validateAcquire(input, now_ms);
            var ignored_owner_count: usize = 0;
            const stale_removed = try pruneStale(
                snapshot,
                now_ms,
                liveness,
                null,
                &ignored_owner_count,
            );
            if (stale_removed != 0) {
                loaded.identity = try self.persist(snapshot, loaded.identity);
            }

            if (ownerStatus(liveness, input.owner) != .alive) return error.OwnerUnavailable;
            if (findLease(snapshot, input.lease)) |index| {
                const existing = &snapshot.leases[index];
                if (storedLeaseMatchesAcquire(existing, input)) {
                    if (existing.transition_from != null) return error.LeaseConflict;
                    return .{ .already_active = .{ .generation = existing.generation } };
                }
                return error.LeaseConflict;
            }
            if (input.expected_revision != snapshot.admission_revision) return error.StateChanged;
            if (snapshot.lease_count == lease_capacity) return error.LeaseCapacityExceeded;
            if (findRoute(snapshot, input.route, input.exact_model) == null) {
                return error.RouteNotRegistered;
            }
            for (snapshot.leases[0..snapshot.lease_count]) |*existing| {
                if (existing.session.eql(input.session.text) and
                    existing.exact_model.eql(input.exact_model))
                {
                    return error.SessionConflict;
                }
            }
            try ensureGenerationAvailable(snapshot);
            try ensureAdmissionMutationAvailable(snapshot);

            const pure = try rebuildAlloc(self.allocator, snapshot);
            defer self.allocator.destroy(pure);
            const pure_owner = try syntheticPidForOwner(snapshot, input.owner);
            var owners: [lease_capacity]lease_state.OwnerObservation = undefined;
            var owner_count = aliveOwnerObservations(snapshot, &owners);
            var incoming_seen = false;
            for (owners[0..owner_count]) |owner| {
                if (owner.owner_pid == pure_owner) incoming_seen = true;
            }
            if (!incoming_seen) {
                owners[owner_count] = .{ .owner_pid = pure_owner, .liveness = .alive };
                owner_count += 1;
            }
            const result = try pure.state.acquire(.{
                .lease = input.lease,
                .session = input.session,
                .account = input.account,
                .route = input.route,
                .exact_model = input.exact_model,
                .owner_pid = pure_owner,
                .expected_revision = pure.state.currentRevision(),
                .now_ms = now_ms,
                .selected_at_ms = input.selected_at_ms,
                .heartbeat_at_ms = input.heartbeat_at_ms,
                .expires_at_ms = input.expires_at_ms,
            }, owners[0..owner_count]);
            if (result != .acquired) return error.InvalidLeaseState;

            const generation = snapshot.next_generation;
            snapshot.leases[snapshot.lease_count] = try storedLeaseFromAcquire(input, generation, null);
            snapshot.lease_count += 1;
            updateHistory(snapshot, input.route, input.exact_model, input.selected_at_ms);
            snapshot.next_generation += 1;
            bumpAdmissionMutation(snapshot);
            sortLeases(snapshot);
            loaded.identity = try self.persist(snapshot, loaded.identity);
            return .{ .acquired = .{ .generation = generation } };
        }

        pub fn renew(
            self: *Self,
            input: RenewInput,
            liveness: LivenessSource,
        ) !RenewOutcome {
            var lock = try self.acquireLock();
            defer lock.deinit();
            var loaded = try self.loadForMutation();
            defer loaded.deinit(self.allocator);
            const now_ms = try self.observeAndPersist(&loaded, input.now_ms);
            const snapshot = loaded.snapshot;
            try validateRenew(input, now_ms);

            const index = findLease(snapshot, input.lease) orelse return error.LeaseNotFound;
            var stored = &snapshot.leases[index];
            try authorizeStored(stored, input.session, input.owner, input.generation);
            // Expiry is the fallback for an owner whose exact incarnation can
            // no longer be proven alive. A live owner may renew after an idle
            // interval without losing its sticky route.
            if (ownerStatus(liveness, stored.owner) != .alive) {
                return error.OwnerUnavailable;
            }
            if (input.heartbeat_at_ms < stored.heartbeat_at_ms or
                input.expires_at_ms < stored.expires_at_ms)
            {
                return error.NonMonotonicRenewal;
            }
            if (input.heartbeat_at_ms == stored.heartbeat_at_ms and
                input.expires_at_ms == stored.expires_at_ms)
            {
                return .unchanged;
            }
            try ensureMutationRevisionAvailable(snapshot);

            const rebuilt = try rebuildAlloc(self.allocator, snapshot);
            defer self.allocator.destroy(rebuilt);
            _ = try rebuilt.state.renew(.{
                .lease = input.lease,
                .session = input.session,
                .owner_pid = rebuilt.synthetic_pids[index],
                .generation = rebuilt.pure_generations[index],
                .now_ms = now_ms,
                .heartbeat_at_ms = input.heartbeat_at_ms,
                .expires_at_ms = input.expires_at_ms,
            });
            stored.heartbeat_at_ms = input.heartbeat_at_ms;
            stored.expires_at_ms = input.expires_at_ms;
            bumpMutation(snapshot);
            loaded.identity = try self.persist(snapshot, loaded.identity);
            return .renewed;
        }

        pub fn release(self: *Self, input: ReleaseInput) !void {
            var lock = try self.acquireLock();
            defer lock.deinit();
            var loaded = try self.loadForMutation();
            defer loaded.deinit(self.allocator);
            const now_ms = try self.observeAndPersist(&loaded, null);
            const snapshot = loaded.snapshot;
            const index = findLease(snapshot, input.lease) orelse return error.LeaseNotFound;
            try authorizeStored(&snapshot.leases[index], input.session, input.owner, input.generation);
            try ensureAdmissionMutationAvailable(snapshot);

            // Release remains an authorized cleanup operation after expiry.
            // Rebuilding through the pure core can legitimately omit an
            // expired record, so remove it directly under the same lock.
            if (snapshot.leases[index].expires_at_ms <= now_ms) {
                removeLease(snapshot, index);
                bumpAdmissionMutation(snapshot);
                loaded.identity = try self.persist(snapshot, loaded.identity);
                return;
            }

            const rebuilt = try rebuildAlloc(self.allocator, snapshot);
            defer self.allocator.destroy(rebuilt);
            try rebuilt.state.release(.{
                .lease = input.lease,
                .session = input.session,
                .owner_pid = rebuilt.synthetic_pids[index],
                .generation = rebuilt.pure_generations[index],
            });
            removeLease(snapshot, index);
            bumpAdmissionMutation(snapshot);
            loaded.identity = try self.persist(snapshot, loaded.identity);
        }

        pub fn transition(
            self: *Self,
            input: TransitionInput,
            liveness: LivenessSource,
        ) !LeaseGrant {
            var lock = try self.acquireLock();
            defer lock.deinit();
            var loaded = try self.loadForMutation();
            defer loaded.deinit(self.allocator);
            const now_ms = try self.observeAndPersist(&loaded, input.next.now_ms);
            const snapshot = loaded.snapshot;
            try validateAcquire(input.next, now_ms);
            if (input.current_generation == 0) return error.InvalidLease;
            if (std.mem.eql(u8, input.current_lease.text, input.next.lease.text)) {
                return error.LeaseConflict;
            }
            var ignored_owner_count: usize = 0;
            const stale_removed = try pruneStale(
                snapshot,
                now_ms,
                liveness,
                null,
                &ignored_owner_count,
            );
            if (stale_removed != 0) {
                loaded.identity = try self.persist(snapshot, loaded.identity);
            }

            if (ownerStatus(liveness, input.next.owner) != .alive) return error.OwnerUnavailable;
            if (findLease(snapshot, input.next.lease)) |next_index| {
                const existing = &snapshot.leases[next_index];
                if (!storedLeaseMatchesAcquire(existing, input.next)) return error.LeaseConflict;
                const origin = existing.transition_from orelse return error.LeaseConflict;
                if (!origin.lease.eql(input.current_lease.text)) return error.LeaseConflict;
                if (origin.generation != input.current_generation) return error.GenerationMismatch;
                return .{ .generation = existing.generation };
            }
            if (input.next.expected_revision != snapshot.admission_revision) return error.StateChanged;
            const current_index = findLease(snapshot, input.current_lease) orelse
                return error.LeaseNotFound;
            const current = &snapshot.leases[current_index];
            try authorizeStored(
                current,
                input.next.session,
                input.next.owner,
                input.current_generation,
            );
            if (!current.exact_model.eql(input.next.exact_model)) return error.SessionConflict;
            if (input.next.selected_at_ms < current.selected_at_ms) {
                return error.NonMonotonicTransition;
            }
            if (findRoute(snapshot, input.next.route, input.next.exact_model) == null) {
                return error.RouteNotRegistered;
            }
            try ensureGenerationAvailable(snapshot);
            try ensureAdmissionMutationAvailable(snapshot);

            const rebuilt = try rebuildAlloc(self.allocator, snapshot);
            defer self.allocator.destroy(rebuilt);
            const pure_owner = rebuilt.synthetic_pids[current_index];
            var owners: [lease_capacity]lease_state.OwnerObservation = undefined;
            const owner_count = aliveOwnerObservations(snapshot, &owners);
            _ = try rebuilt.state.transition(.{
                .current_lease = input.current_lease,
                .current_generation = rebuilt.pure_generations[current_index],
                .next = .{
                    .lease = input.next.lease,
                    .session = input.next.session,
                    .account = input.next.account,
                    .route = input.next.route,
                    .exact_model = input.next.exact_model,
                    .owner_pid = pure_owner,
                    .expected_revision = rebuilt.state.currentRevision(),
                    .now_ms = now_ms,
                    .selected_at_ms = input.next.selected_at_ms,
                    .heartbeat_at_ms = input.next.heartbeat_at_ms,
                    .expires_at_ms = input.next.expires_at_ms,
                },
            }, owners[0..owner_count]);

            const generation = snapshot.next_generation;
            snapshot.leases[current_index] = try storedLeaseFromAcquire(
                input.next,
                generation,
                .{ .lease = try ownedHandle(input.current_lease.text), .generation = input.current_generation },
            );
            updateHistory(snapshot, input.next.route, input.next.exact_model, input.next.selected_at_ms);
            snapshot.next_generation += 1;
            bumpAdmissionMutation(snapshot);
            sortLeases(snapshot);
            loaded.identity = try self.persist(snapshot, loaded.identity);
            return .{ .generation = generation };
        }

        pub fn cleanupStale(
            self: *Self,
            now_ms: lease_state.TimestampMs,
            liveness: LivenessSource,
        ) !usize {
            return (try self.cleanupStaleInternal(now_ms, liveness, null)).removed_count;
        }

        /// Reports the exact owner incarnations whose final stale records were
        /// durably removed. Callers may retire their custody files only after
        /// this method returns successfully.
        pub fn cleanupStaleReportingOwners(
            self: *Self,
            now_ms: lease_state.TimestampMs,
            liveness: LivenessSource,
            removed_owners: []OwnerIdentity,
        ) !CleanupReport {
            return self.cleanupStaleInternal(now_ms, liveness, removed_owners);
        }

        fn cleanupStaleInternal(
            self: *Self,
            now_ms: lease_state.TimestampMs,
            liveness: LivenessSource,
            removed_owners: ?[]OwnerIdentity,
        ) !CleanupReport {
            var lock = try self.acquireLock();
            defer lock.deinit();
            var loaded = try self.loadForMutation();
            defer loaded.deinit(self.allocator);
            const sampled_now_ms = try self.observeAndPersist(&loaded, now_ms);
            var owner_count: usize = 0;
            const removed = try pruneStale(
                loaded.snapshot,
                sampled_now_ms,
                liveness,
                removed_owners,
                &owner_count,
            );
            if (removed != 0) {
                loaded.identity = try self.persist(loaded.snapshot, loaded.identity);
            }
            return .{ .removed_count = removed, .owner_count = owner_count };
        }

        /// Missing state is an empty advisory view. Contention is surfaced as
        /// `LockWaitTimeout` so the request runtime may degrade deliberately;
        /// custody, parse, clock, and persistence failures remain typed and
        /// fail closed.
        pub fn project(
            self: *Self,
            session: lease_state.SessionHandle,
            demand: lease_state.ModelDemand,
            now_ms: lease_state.TimestampMs,
            liveness: LivenessSource,
        ) !Projection {
            if (!timestampValid(now_ms)) return error.InvalidClockSample;
            if (!demand.isValid()) return error.InvalidExactModel;
            _ = try lease_state.SessionHandle.parse(session.text);

            var lock = try self.acquireLock();
            defer lock.deinit();
            var loaded = try self.loadSnapshot();
            defer loaded.deinit(self.allocator);
            if (loaded.quality != .present) return .{};
            // The persisted wall-clock watermark makes this read a serialized
            // write whenever time advances. This is deliberate until G4 can
            // justify a different cross-process clock authority.
            const sampled_now_ms = try self.observeAndPersist(&loaded, now_ms);
            const snapshot = loaded.snapshot;
            const rebuilt = try rebuildAlloc(self.allocator, snapshot);
            defer self.allocator.destroy(rebuilt);

            var owner_observations: [lease_capacity]lease_state.OwnerObservation = undefined;
            var owner_count: usize = 0;
            for (snapshot.leases[0..snapshot.lease_count], 0..) |*record, index| {
                const status = ownerStatus(liveness, record.owner);
                if (status == .unknown) continue;
                owner_observations[owner_count] = .{
                    .owner_pid = rebuilt.synthetic_pids[index],
                    .liveness = if (status == .alive) .alive else .dead,
                };
                owner_count += 1;
            }
            var scratch: [route_capacity]lease_state.LeaseObservation = undefined;
            const pure_projection = try rebuilt.state.project(
                session,
                demand,
                sampled_now_ms,
                owner_observations[0..owner_count],
                &scratch,
            );
            if (pure_projection.quality == .unavailable) return .{};

            var result = Projection{
                .revision = snapshot.admission_revision,
                .quality = pure_projection.quality,
            };
            for (pure_projection.view.routes) |row| {
                result.rows[result.row_count] = .{
                    .route = try ownedHandle(row.route.text),
                    .active_leases = row.active_leases,
                    .last_selected_at = row.last_selected_at,
                };
                result.row_count += 1;
            }
            if (pure_projection.view.sticky_route) |sticky| {
                result.sticky_route = try ownedHandle(sticky.text);
            }
            return result;
        }

        /// Reads the one canonical lease for an exact session/model/owner
        /// tuple. This is deliberately narrower than a general snapshot API:
        /// callers may use it only to recover from `LeaseStateCommitUncertain`.
        /// A lease owned by another incarnation is a conflict, never something
        /// the request runtime may guess through.
        pub fn reconcileSessionLease(
            self: *Self,
            session: lease_state.SessionHandle,
            exact_model: lease_state.ExactModel,
            owner: OwnerIdentity,
        ) !?ReconciledLease {
            _ = try lease_state.SessionHandle.parse(session.text);
            if (!exact_model.isValid()) return error.InvalidExactModel;
            if (!owner.isValid()) return error.InvalidOwnerIdentity;

            var lock = try self.acquireLock();
            defer lock.deinit();
            var loaded = try self.loadSnapshot();
            defer loaded.deinit(self.allocator);
            if (loaded.quality != .present) return null;

            var found: ?ReconciledLease = null;
            for (loaded.snapshot.leases[0..loaded.snapshot.lease_count]) |*stored| {
                if (!stored.session.eql(session.text) or
                    !stored.exact_model.eql(exact_model)) continue;
                if (!stored.owner.eql(owner)) return error.OwnerMismatch;
                if (found != null) return error.InvalidLeaseState;

                var recovered = ReconciledLease{
                    .exact_model = stored.exact_model,
                    .generation = stored.generation,
                };
                const lease_text = stored.lease.bytes();
                const account_text = stored.account.bytes();
                const route_text = stored.route.bytes();
                @memcpy(recovered.lease_buf[0..lease_text.len], lease_text);
                recovered.lease_len = @intCast(lease_text.len);
                @memcpy(recovered.account_buf[0..account_text.len], account_text);
                recovered.account_len = @intCast(account_text.len);
                @memcpy(recovered.route_buf[0..route_text.len], route_text);
                recovered.route_len = @intCast(route_text.len);
                if (stored.transition_from) |origin| {
                    const origin_text = origin.lease.bytes();
                    @memcpy(
                        recovered.transition_origin_lease_buf[0..origin_text.len],
                        origin_text,
                    );
                    recovered.transition_origin_lease_len = @intCast(origin_text.len);
                    recovered.transition_origin_generation = origin.generation;
                }
                found = recovered;
            }
            return found;
        }

        /// Explicitly discard a syntactically or semantically invalid advisory
        /// snapshot. Broad read/custody failures are never interpreted as
        /// corruption and therefore cannot delete canonical state.
        pub fn repairUnavailableState(self: *Self) !bool {
            var lock = try self.acquireLock();
            defer lock.deinit();
            const file = self.openCustodiedFile(state_file_name, .state, false) catch |err| switch (err) {
                error.FileNotFound => return false,
                else => return err,
            };
            defer file.close();
            const identity = try self.validateFileCustody(file, .state);
            const bytes = try file.readToEndAlloc(self.allocator, max_snapshot_bytes);
            defer self.allocator.free(bytes);
            try self.verifyCanonicalIdentity(state_file_name, identity);

            var invalid = false;
            if (std.json.parseFromSlice(WireSnapshot, self.allocator, bytes, .{})) |parsed_value| {
                var parsed = parsed_value;
                defer parsed.deinit();
                if (snapshotFromWire(self.allocator, parsed.value)) |snapshot| {
                    self.allocator.destroy(snapshot);
                } else |err| switch (err) {
                    error.OutOfMemory => return err,
                    error.IncompatibleLeaseState => return error.IncompatibleLeaseState,
                    else => invalid = true,
                }
            } else |err| {
                if (err == error.OutOfMemory) return err;
                invalid = true;
            }
            if (!invalid) return false;

            try self.verifyCanonicalIdentity(state_file_name, identity);
            try self.deleteRelative(state_file_name);
            try syncDirectoryHandle(self.dir);
            return true;
        }

        const LockedFile = struct {
            file: std.fs.File,

            fn deinit(self: *LockedFile) void {
                self.file.close();
                self.* = undefined;
            }
        };

        fn acquireLock(self: *Self) !LockedFile {
            const file = try self.openCustodiedFile(lock_file_name, .lock, true);
            errdefer file.close();
            const sink = self.options.log_file orelse std.io.getStdErr();
            try lockFileAnnouncedBounded(
                file,
                lock_file_name,
                sink.writer(),
                self.options.wait,
                self.options.monotonic_start,
            );
            const identity = try self.validateFileCustody(file, .lock);
            try self.verifyCanonicalIdentity(lock_file_name, identity);
            return .{ .file = file };
        }

        fn observeAndPersist(
            self: *Self,
            loaded: *Loaded,
            requested_ms: ?lease_state.TimestampMs,
        ) !lease_state.TimestampMs {
            const now_ms = try self.options.time.sample(
                requested_ms orelse loaded.snapshot.last_observed_at_ms,
            );
            const observation = try observeSnapshotTime(loaded.snapshot, now_ms);
            if (observation.changed) {
                loaded.identity = try self.persist(loaded.snapshot, loaded.identity);
                loaded.quality = .present;
            }
            if (observation.outcome == .quarantined) {
                return error.ClockSkewQuarantined;
            }
            return now_ms;
        }

        fn openCustodiedFile(
            self: *Self,
            name: []const u8,
            purpose: FilePurpose,
            create: bool,
        ) !std.fs.File {
            if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
                return error.UnsupportedLeaseStorePlatform;
            }
            const flags: std.posix.O = .{
                .ACCMODE = if (purpose == .state) .RDONLY else .RDWR,
                .CREAT = create,
                .EXCL = purpose == .temporary,
                .NONBLOCK = true,
                .NOFOLLOW = true,
                .CLOEXEC = true,
            };
            const fd = try std.posix.openat(self.dir.fd, name, flags, 0o600);
            return .{ .handle = fd };
        }

        fn validateFileCustody(
            self: *const Self,
            file: std.fs.File,
            _: FilePurpose,
        ) !FileIdentity {
            if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
                return error.UnsupportedLeaseStorePlatform;
            }
            const stat = try std.posix.fstat(file.handle);
            if ((stat.mode & std.posix.S.IFMT) != std.posix.S.IFREG) {
                return error.NonRegularLeaseState;
            }
            if ((stat.mode & 0o077) != 0 or @as(u64, @intCast(stat.uid)) != self.root_owner) {
                return error.InsecureLeaseStateCustody;
            }
            return .{
                .device = @intCast(stat.dev),
                .inode = @intCast(stat.ino),
            };
        }

        fn verifyCanonicalIdentity(
            self: *const Self,
            name: []const u8,
            expected: FileIdentity,
        ) !void {
            if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
                return error.UnsupportedLeaseStorePlatform;
            }
            const stat = try std.posix.fstatat(
                self.dir.fd,
                name,
                std.posix.AT.SYMLINK_NOFOLLOW,
            );
            if ((stat.mode & std.posix.S.IFMT) != std.posix.S.IFREG) {
                return error.NonRegularLeaseState;
            }
            const actual = FileIdentity{
                .device = @intCast(stat.dev),
                .inode = @intCast(stat.ino),
            };
            if (!actual.eql(expected)) return error.LeaseStatePathChanged;
        }

        fn verifyExpectedCanonicalIdentity(
            self: *const Self,
            name: []const u8,
            expected: ?FileIdentity,
        ) !void {
            if (expected) |identity| return self.verifyCanonicalIdentity(name, identity);
            if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
                return error.UnsupportedLeaseStorePlatform;
            }
            _ = std.posix.fstatat(
                self.dir.fd,
                name,
                std.posix.AT.SYMLINK_NOFOLLOW,
            ) catch |err| switch (err) {
                error.FileNotFound => return,
                else => return err,
            };
            return error.LeaseStatePathChanged;
        }

        fn deleteRelative(self: *const Self, name: []const u8) !void {
            if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
                return error.UnsupportedLeaseStorePlatform;
            }
            try std.posix.unlinkat(self.dir.fd, name, 0);
        }

        fn renameRelative(self: *const Self, from: []const u8, to: []const u8) !void {
            if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
                return error.UnsupportedLeaseStorePlatform;
            }
            try std.posix.renameat(self.dir.fd, from, self.dir.fd, to);
        }

        fn loadForMutation(self: *Self) !Loaded {
            return self.loadSnapshot();
        }

        fn loadSnapshot(self: *Self) !Loaded {
            if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
                return error.UnsupportedLeaseStorePlatform;
            }
            const file = self.openCustodiedFile(state_file_name, .state, false) catch |err| switch (err) {
                error.FileNotFound => return .{
                    .quality = .missing,
                    .snapshot = try allocEmptySnapshot(self.allocator),
                    .identity = null,
                },
                else => return err,
            };
            defer file.close();
            const identity = try self.validateFileCustody(file, .state);
            const bytes = try file.readToEndAlloc(self.allocator, max_snapshot_bytes);
            defer self.allocator.free(bytes);
            try self.verifyCanonicalIdentity(state_file_name, identity);
            var parsed = std.json.parseFromSlice(WireSnapshot, self.allocator, bytes, .{}) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => return error.InvalidLeaseState,
            };
            defer parsed.deinit();
            const snapshot = try snapshotFromWire(self.allocator, parsed.value);
            return .{
                .quality = .present,
                .snapshot = snapshot,
                .identity = identity,
            };
        }

        fn persist(
            self: *Self,
            snapshot: *const Snapshot,
            expected_identity: ?FileIdentity,
        ) !FileIdentity {
            try self.verifyExpectedCanonicalIdentity(state_file_name, expected_identity);
            const tmp_name = try std.fmt.allocPrint(
                self.allocator,
                "{s}.tmp-{x}",
                .{ state_file_name, std.crypto.random.int(u64) },
            );
            defer self.allocator.free(tmp_name);
            var renamed = false;
            defer if (!renamed) self.deleteRelative(tmp_name) catch {};

            var counting = std.io.countingWriter(std.io.null_writer);
            try writeSnapshot(snapshot, counting.writer());
            if (counting.bytes_written > max_snapshot_bytes) return error.LeaseStateTooLarge;
            {
                const file = try self.openCustodiedFile(tmp_name, .temporary, true);
                defer file.close();
                _ = try self.validateFileCustody(file, .temporary);
                try writeSnapshot(snapshot, file.writer());
                try file.sync();
            }
            try self.verifyExpectedCanonicalIdentity(state_file_name, expected_identity);
            try self.renameRelative(tmp_name, state_file_name);
            renamed = true;
            if (self.options.post_rename_hook) |hook| {
                hook.run(hook.ctx) catch return error.LeaseStateCommitUncertain;
            }
            syncDirectoryHandle(self.dir) catch return error.LeaseStateCommitUncertain;

            const state = self.openCustodiedFile(state_file_name, .state, false) catch
                return error.LeaseStateCommitUncertain;
            defer state.close();
            const identity = self.validateFileCustody(state, .state) catch
                return error.LeaseStateCommitUncertain;
            self.verifyCanonicalIdentity(state_file_name, identity) catch
                return error.LeaseStateCommitUncertain;
            return identity;
        }

        fn allocEmptySnapshot(allocator: std.mem.Allocator) !*Snapshot {
            const snapshot = try allocator.create(Snapshot);
            snapshot.initInPlace();
            return snapshot;
        }

        fn snapshotFromWire(allocator: std.mem.Allocator, wire: WireSnapshot) !*Snapshot {
            if (wire.version != snapshot_version or
                !std.mem.eql(u8, wire.contract_fingerprint, snapshot_contract_fingerprint) or
                wire.lease_capacity != lease_capacity or
                wire.route_capacity != route_capacity)
            {
                return error.IncompatibleLeaseState;
            }
            if (wire.routes.len > route_capacity or
                wire.leases.len > lease_capacity or
                wire.admission_revision > wire.mutation_revision or
                !generationValid(wire.next_generation))
            {
                return error.InvalidLeaseState;
            }
            if (wire.last_observed_at_ms) |observed| {
                if (!timestampValid(observed)) return error.InvalidLeaseState;
            } else if (wire.clock_recovery_until_ms != null) {
                return error.InvalidLeaseState;
            }
            if (wire.last_observed_at_ms == null and
                (wire.mutation_revision != 0 or wire.admission_revision != 0 or
                    wire.routes.len != 0 or wire.leases.len != 0))
            {
                return error.InvalidLeaseState;
            }
            if (wire.clock_recovery_until_ms) |until| {
                if (!timestampValid(until) or
                    until <= wire.last_observed_at_ms.?)
                {
                    return error.InvalidLeaseState;
                }
            }
            const snapshot = try allocEmptySnapshot(allocator);
            errdefer allocator.destroy(snapshot);
            snapshot.mutation_revision = wire.mutation_revision;
            snapshot.admission_revision = wire.admission_revision;
            snapshot.last_observed_at_ms = wire.last_observed_at_ms;
            snapshot.clock_recovery_until_ms = wire.clock_recovery_until_ms;
            snapshot.next_generation = wire.next_generation;
            for (wire.routes) |route| {
                const parsed_route = lease_state.RouteHandle.parse(route.route) catch
                    return error.InvalidLeaseState;
                const model = lease_state.ExactModel.init(route.exact_model) catch
                    return error.InvalidLeaseState;
                if (route.last_selected_at_ms) |selected| {
                    if (!timestampValid(selected) or
                        (snapshot.last_observed_at_ms != null and
                            selected > snapshot.last_observed_at_ms.?))
                    {
                        return error.InvalidLeaseState;
                    }
                }
                if (findRoute(snapshot, parsed_route, model) != null) {
                    return error.InvalidLeaseState;
                }
                snapshot.routes[snapshot.route_count] = .{
                    .route = try ownedHandle(route.route),
                    .exact_model = model,
                    .last_selected_at_ms = route.last_selected_at_ms,
                };
                snapshot.route_count += 1;
            }
            for (wire.leases) |record| {
                const lease = lease_state.LeaseHandle.parse(record.lease) catch
                    return error.InvalidLeaseState;
                const session = lease_state.SessionHandle.parse(record.session) catch
                    return error.InvalidLeaseState;
                _ = lease_state.AccountHandle.parse(record.account) catch
                    return error.InvalidLeaseState;
                const route = lease_state.RouteHandle.parse(record.route) catch
                    return error.InvalidLeaseState;
                const model = lease_state.ExactModel.init(record.exact_model) catch
                    return error.InvalidLeaseState;
                const owner: OwnerIdentity = .{
                    .pid = record.owner.pid,
                    .incarnation = record.owner.incarnation,
                    .generation = record.owner.generation,
                };
                if (!owner.isValid() or
                    !generationValid(record.generation) or
                    record.generation >= snapshot.next_generation or
                    !timestampValid(record.selected_at_ms) or
                    !timestampValid(record.heartbeat_at_ms) or
                    !timestampValid(record.expires_at_ms) or
                    record.selected_at_ms > record.heartbeat_at_ms or
                    record.heartbeat_at_ms >= record.expires_at_ms or
                    (snapshot.last_observed_at_ms != null and
                        record.heartbeat_at_ms > snapshot.last_observed_at_ms.?) or
                    findLease(snapshot, lease) != null or
                    findRoute(snapshot, route, model) == null)
                {
                    return error.InvalidLeaseState;
                }
                for (snapshot.leases[0..snapshot.lease_count]) |*existing| {
                    if (existing.generation == record.generation) {
                        return error.InvalidLeaseState;
                    }
                    if (existing.session.eql(session.text) and existing.exact_model.eql(model)) {
                        return error.InvalidLeaseState;
                    }
                }
                var origin: ?TransitionOrigin = null;
                if (record.transition_from) |from| {
                    _ = lease_state.LeaseHandle.parse(from.lease) catch
                        return error.InvalidLeaseState;
                    if (!generationValid(from.generation) or
                        from.generation >= record.generation or
                        std.mem.eql(u8, from.lease, record.lease))
                    {
                        return error.InvalidLeaseState;
                    }
                    origin = .{
                        .lease = try ownedHandle(from.lease),
                        .generation = from.generation,
                    };
                }
                snapshot.leases[snapshot.lease_count] = .{
                    .lease = try ownedHandle(record.lease),
                    .session = try ownedHandle(record.session),
                    .account = try ownedHandle(record.account),
                    .route = try ownedHandle(record.route),
                    .exact_model = model,
                    .owner = owner,
                    .generation = record.generation,
                    .selected_at_ms = record.selected_at_ms,
                    .heartbeat_at_ms = record.heartbeat_at_ms,
                    .expires_at_ms = record.expires_at_ms,
                    .transition_from = origin,
                };
                snapshot.lease_count += 1;
            }
            sortRoutes(snapshot);
            sortLeases(snapshot);
            const rebuilt = try rebuildAlloc(allocator, snapshot);
            allocator.destroy(rebuilt);
            return snapshot;
        }

        fn rebuildAlloc(allocator: std.mem.Allocator, snapshot: *const Snapshot) !*Rebuilt {
            const result = try allocator.create(Rebuilt);
            errdefer allocator.destroy(result);
            result.state.initInPlace();
            @memset(std.mem.asBytes(&result.pure_generations), 0);
            @memset(std.mem.asBytes(&result.synthetic_pids), 0);
            for (snapshot.routes[0..snapshot.route_count]) |*route| {
                try result.state.registerRoute(.{
                    .route = try lease_state.RouteHandle.parse(route.route.bytes()),
                    .exact_model = route.exact_model,
                });
            }

            // Replay history and active leases in observed-time order. The pure
            // core rejects backdated observation, so reconstructing all route
            // history first would poison a valid snapshot whose older active
            // lease coexists with a newer released-route history row.
            var events: [lease_capacity + route_capacity]ReplayEvent = undefined;
            var event_count: usize = 0;
            for (snapshot.routes[0..snapshot.route_count], 0..) |*route, index| {
                const selected = route.last_selected_at_ms orelse continue;
                events[event_count] = .{ .at_ms = selected, .kind = .history, .index = index };
                event_count += 1;
            }
            for (snapshot.leases[0..snapshot.lease_count], 0..) |*record, index| {
                events[event_count] = .{ .at_ms = record.heartbeat_at_ms, .kind = .lease, .index = index };
                event_count += 1;
            }
            std.mem.sort(ReplayEvent, events[0..event_count], {}, struct {
                fn lessThan(_: void, a: ReplayEvent, b: ReplayEvent) bool {
                    if (a.at_ms != b.at_ms) return a.at_ms < b.at_ms;
                    if (a.kind != b.kind) return @intFromEnum(a.kind) < @intFromEnum(b.kind);
                    return a.index < b.index;
                }
            }.lessThan);

            for (events[0..event_count]) |event| switch (event.kind) {
                .history => {
                    const route = &snapshot.routes[event.index];
                    if (event.at_ms >= lease_state.max_timestamp_ms) return error.InvalidLeaseState;
                    var lease_buf: [96]u8 = undefined;
                    var session_buf: [96]u8 = undefined;
                    var account_buf: [96]u8 = undefined;
                    var attempt: usize = 0;
                    while (attempt <= lease_capacity) : (attempt += 1) {
                        const lease_text = try std.fmt.bufPrint(
                            &lease_buf,
                            "history-replay-{d}-{d}",
                            .{ event.index, attempt },
                        );
                        const session_text = try std.fmt.bufPrint(
                            &session_buf,
                            "history-session-{d}-{d}",
                            .{ event.index, attempt },
                        );
                        var collides = false;
                        for (snapshot.leases[0..snapshot.lease_count]) |*active| {
                            if (active.lease.eql(lease_text) or
                                (active.session.eql(session_text) and
                                    active.exact_model.eql(route.exact_model)))
                            {
                                collides = true;
                                break;
                            }
                        }
                        if (collides) continue;
                        const account_text = try std.fmt.bufPrint(
                            &account_buf,
                            "history-account-{d}-{d}",
                            .{ event.index, attempt },
                        );
                        const grant = try result.state.acquire(.{
                            .lease = try lease_state.LeaseHandle.parse(lease_text),
                            .session = try lease_state.SessionHandle.parse(session_text),
                            .account = try lease_state.AccountHandle.parse(account_text),
                            .route = try lease_state.RouteHandle.parse(route.route.bytes()),
                            .exact_model = route.exact_model,
                            .owner_pid = 1,
                            .expected_revision = result.state.currentRevision(),
                            .now_ms = event.at_ms,
                            .selected_at_ms = event.at_ms,
                            .heartbeat_at_ms = event.at_ms,
                            .expires_at_ms = event.at_ms + 1,
                        }, &.{.{ .owner_pid = 1, .liveness = .alive }});
                        const generation = switch (grant) {
                            .acquired => |value| value.generation,
                            .already_active => return error.InvalidLeaseState,
                        };
                        try result.state.release(.{
                            .lease = try lease_state.LeaseHandle.parse(lease_text),
                            .session = try lease_state.SessionHandle.parse(session_text),
                            .owner_pid = 1,
                            .generation = generation,
                        });
                        break;
                    } else return error.InvalidLeaseState;
                },
                .lease => {
                    const index = event.index;
                    const record = &snapshot.leases[index];
                    const synthetic_pid = try syntheticPidForOwner(snapshot, record.owner);
                    result.synthetic_pids[index] = synthetic_pid;
                    var owners: [lease_capacity]lease_state.OwnerObservation = undefined;
                    const owner_count = aliveOwnerObservations(snapshot, &owners);
                    var replay_input = lease_state.AcquireInput{
                        .lease = try lease_state.LeaseHandle.parse(record.lease.bytes()),
                        .session = try lease_state.SessionHandle.parse(record.session.bytes()),
                        .account = try lease_state.AccountHandle.parse(record.account.bytes()),
                        .route = try lease_state.RouteHandle.parse(record.route.bytes()),
                        .exact_model = record.exact_model,
                        .owner_pid = synthetic_pid,
                        .expected_revision = result.state.currentRevision(),
                        .now_ms = event.at_ms,
                        .selected_at_ms = record.selected_at_ms,
                        .heartbeat_at_ms = record.heartbeat_at_ms,
                        .expires_at_ms = record.expires_at_ms,
                    };
                    const acquired = result.state.acquire(
                        replay_input,
                        owners[0..owner_count],
                    ) catch |err| switch (err) {
                        // The pure core prunes older expired records before its
                        // admission fence. Reconstruction owns this serialized
                        // snapshot, so retry once against that post-prune fence.
                        error.StateChanged => retry: {
                            replay_input.expected_revision = result.state.currentRevision();
                            break :retry try result.state.acquire(
                                replay_input,
                                owners[0..owner_count],
                            );
                        },
                        else => return err,
                    };
                    result.pure_generations[index] = switch (acquired) {
                        .acquired => |grant| grant.generation,
                        .already_active => return error.InvalidLeaseState,
                    };
                },
            };
            return result;
        }

        fn aliveOwnerObservations(
            snapshot: *const Snapshot,
            output: *[lease_capacity]lease_state.OwnerObservation,
        ) usize {
            var count: usize = 0;
            for (snapshot.leases[0..snapshot.lease_count]) |*record| {
                const pid = syntheticPidForOwner(snapshot, record.owner) catch continue;
                var seen = false;
                for (output[0..count]) |existing| {
                    if (existing.owner_pid == pid) seen = true;
                }
                if (seen) continue;
                output[count] = .{ .owner_pid = pid, .liveness = .alive };
                count += 1;
            }
            return count;
        }

        fn syntheticPidForOwner(snapshot: *const Snapshot, owner: OwnerIdentity) !lease_state.OwnerPid {
            var owners: [lease_capacity]OwnerIdentity = undefined;
            var count: usize = 0;
            for (snapshot.leases[0..snapshot.lease_count]) |*record| {
                var found: ?usize = null;
                for (owners[0..count], 0..) |existing, index| {
                    if (existing.eql(record.owner)) found = index;
                }
                if (found == null) {
                    owners[count] = record.owner;
                    found = count;
                    count += 1;
                }
                if (record.owner.eql(owner)) return @intCast(found.? + 2);
            }
            if (count == lease_capacity) return error.LeaseCapacityExceeded;
            return @intCast(count + 2);
        }

        fn pruneStale(
            snapshot: *Snapshot,
            now_ms: lease_state.TimestampMs,
            liveness: LivenessSource,
            removed_owners: ?[]OwnerIdentity,
            owner_count: *usize,
        ) !usize {
            if (!timestampValid(now_ms)) return error.InvalidLease;
            var write_index: usize = 0;
            var removed: usize = 0;
            const previous_count = snapshot.lease_count;
            for (snapshot.leases[0..previous_count]) |record| {
                const owner = ownerStatus(liveness, record.owner);
                const stale = owner == .dead or
                    (owner != .alive and record.expires_at_ms <= now_ms);
                if (stale) {
                    if (removed_owners) |owners| {
                        var seen = false;
                        for (owners[0..owner_count.*]) |reported_owner| {
                            if (reported_owner.eql(record.owner)) {
                                seen = true;
                                break;
                            }
                        }
                        if (!seen) {
                            if (owner_count.* == owners.len) return error.OwnerReportCapacityExceeded;
                            owners[owner_count.*] = record.owner;
                            owner_count.* += 1;
                        }
                    }
                    removed += 1;
                    continue;
                }
                snapshot.leases[write_index] = record;
                write_index += 1;
            }
            if (removed != 0) {
                try ensureAdmissionMutationAvailable(snapshot);
                for (snapshot.leases[write_index..previous_count]) |*removed_slot| {
                    removed_slot.* = emptyStoredLease();
                }
                snapshot.lease_count = write_index;
                bumpAdmissionMutation(snapshot);
            }
            return removed;
        }

        fn findRoute(
            snapshot: *const Snapshot,
            route: lease_state.RouteHandle,
            model: lease_state.ExactModel,
        ) ?usize {
            for (snapshot.routes[0..snapshot.route_count], 0..) |*stored, index| {
                if (stored.route.eql(route.text) and stored.exact_model.eql(model)) return index;
            }
            return null;
        }

        fn findLease(snapshot: *const Snapshot, lease: lease_state.LeaseHandle) ?usize {
            for (snapshot.leases[0..snapshot.lease_count], 0..) |*stored, index| {
                if (stored.lease.eql(lease.text)) return index;
            }
            return null;
        }

        fn updateHistory(
            snapshot: *Snapshot,
            route: lease_state.RouteHandle,
            model: lease_state.ExactModel,
            selected_at_ms: lease_state.TimestampMs,
        ) void {
            const index = findRoute(snapshot, route, model) orelse unreachable;
            const previous = snapshot.routes[index].last_selected_at_ms;
            if (previous == null or selected_at_ms > previous.?) {
                snapshot.routes[index].last_selected_at_ms = selected_at_ms;
            }
        }

        fn removeLease(snapshot: *Snapshot, index: usize) void {
            snapshot.lease_count -= 1;
            if (index != snapshot.lease_count) snapshot.leases[index] = snapshot.leases[snapshot.lease_count];
            snapshot.leases[snapshot.lease_count] = emptyStoredLease();
            sortLeases(snapshot);
        }

        fn sortRoutes(snapshot: *Snapshot) void {
            if (snapshot.route_count < 2) return;
            std.mem.sort(StoredRoute, snapshot.routes[0..snapshot.route_count], {}, struct {
                fn lessThan(_: void, a: StoredRoute, b: StoredRoute) bool {
                    const route_order = std.mem.order(u8, a.route.bytes(), b.route.bytes());
                    if (route_order != .eq) return route_order == .lt;
                    return std.mem.order(u8, a.exact_model.bytes(), b.exact_model.bytes()) == .lt;
                }
            }.lessThan);
        }

        fn sortLeases(snapshot: *Snapshot) void {
            if (snapshot.lease_count < 2) return;
            std.mem.sort(StoredLease, snapshot.leases[0..snapshot.lease_count], {}, struct {
                fn lessThan(_: void, a: StoredLease, b: StoredLease) bool {
                    return std.mem.order(u8, a.lease.bytes(), b.lease.bytes()) == .lt;
                }
            }.lessThan);
        }

        fn ensureMutationRevisionAvailable(snapshot: *const Snapshot) !void {
            if (snapshot.mutation_revision == std.math.maxInt(lease_state.Revision)) {
                return error.RevisionExhausted;
            }
        }

        fn ensureAdmissionMutationAvailable(snapshot: *const Snapshot) !void {
            try ensureMutationRevisionAvailable(snapshot);
            if (snapshot.admission_revision == std.math.maxInt(lease_state.Revision)) {
                return error.RevisionExhausted;
            }
        }

        fn bumpMutation(snapshot: *Snapshot) void {
            snapshot.mutation_revision += 1;
        }

        fn bumpAdmissionMutation(snapshot: *Snapshot) void {
            snapshot.mutation_revision += 1;
            snapshot.admission_revision += 1;
        }

        fn ensureGenerationAvailable(snapshot: *const Snapshot) !void {
            if (!generationValid(snapshot.next_generation) or
                snapshot.next_generation == @as(u64, @intCast(lease_state.max_timestamp_ms)))
            {
                return error.GenerationExhausted;
            }
        }

        const ObserveResult = struct {
            outcome: ObservationOutcome,
            changed: bool,
        };

        fn observeSnapshotTime(
            snapshot: *Snapshot,
            now_ms: lease_state.TimestampMs,
        ) !ObserveResult {
            if (!timestampValid(now_ms)) return error.InvalidClockSample;

            if (snapshot.clock_recovery_until_ms) |recovery_until_ms| {
                const observed = snapshot.last_observed_at_ms orelse
                    return error.InvalidLeaseState;
                if (now_ms < observed) {
                    try rebaseSnapshotClock(snapshot, observed, now_ms);
                    return .{ .outcome = .quarantined, .changed = true };
                }
                if (now_ms < recovery_until_ms) {
                    return .{ .outcome = .quarantined, .changed = false };
                }
                try ensureAdmissionMutationAvailable(snapshot);
                snapshot.last_observed_at_ms = now_ms;
                snapshot.clock_recovery_until_ms = null;
                bumpAdmissionMutation(snapshot);
                return .{ .outcome = .ready, .changed = true };
            }

            if (snapshot.last_observed_at_ms) |observed| {
                if (now_ms < observed) {
                    try rebaseSnapshotClock(snapshot, observed, now_ms);
                    return .{ .outcome = .quarantined, .changed = true };
                }
                if (now_ms == observed) {
                    return .{ .outcome = .ready, .changed = false };
                }
            }

            try ensureMutationRevisionAvailable(snapshot);
            snapshot.last_observed_at_ms = now_ms;
            bumpMutation(snapshot);
            return .{ .outcome = .ready, .changed = true };
        }

        fn rebaseSnapshotClock(
            snapshot: *Snapshot,
            observed_ms: lease_state.TimestampMs,
            now_ms: lease_state.TimestampMs,
        ) !void {
            if (!timestampValid(observed_ms) or !timestampValid(now_ms) or now_ms >= observed_ms) {
                return error.InvalidClockSample;
            }
            try ensureAdmissionMutationAvailable(snapshot);

            for (snapshot.routes[0..snapshot.route_count]) |*route| {
                if (route.last_selected_at_ms) |selected| {
                    route.last_selected_at_ms = rebaseObservedTimestamp(
                        selected,
                        observed_ms,
                        now_ms,
                    );
                }
            }

            var write_index: usize = 0;
            const previous_count = snapshot.lease_count;
            for (snapshot.leases[0..previous_count]) |record| {
                // Already-expired leases have no trustworthy future duration
                // to preserve in the new wall-clock epoch.
                if (record.expires_at_ms <= observed_ms) continue;
                var shifted = record;
                shifted.selected_at_ms = rebaseObservedTimestamp(
                    record.selected_at_ms,
                    observed_ms,
                    now_ms,
                );
                shifted.heartbeat_at_ms = rebaseObservedTimestamp(
                    record.heartbeat_at_ms,
                    observed_ms,
                    now_ms,
                );
                shifted.expires_at_ms = now_ms + (record.expires_at_ms - observed_ms);
                snapshot.leases[write_index] = shifted;
                write_index += 1;
            }
            for (snapshot.leases[write_index..previous_count]) |*removed_slot| {
                removed_slot.* = emptyStoredLease();
            }
            snapshot.lease_count = write_index;
            sortLeases(snapshot);
            snapshot.last_observed_at_ms = now_ms;
            snapshot.clock_recovery_until_ms = recoveryDeadline(now_ms);
            bumpAdmissionMutation(snapshot);
        }

        fn rebaseObservedTimestamp(
            value_ms: lease_state.TimestampMs,
            observed_ms: lease_state.TimestampMs,
            now_ms: lease_state.TimestampMs,
        ) lease_state.TimestampMs {
            std.debug.assert(value_ms <= observed_ms);
            return @max(0, now_ms -| (observed_ms - value_ms));
        }

        fn recoveryDeadline(now_ms: lease_state.TimestampMs) lease_state.TimestampMs {
            if (now_ms > lease_state.max_timestamp_ms - clock_recovery_window_ms) {
                return lease_state.max_timestamp_ms;
            }
            return now_ms + clock_recovery_window_ms;
        }

        fn writeSnapshot(snapshot: *const Snapshot, writer: anytype) !void {
            try writer.print(
                "{{\"version\":{d},\"contract_fingerprint\":\"{s}\",\"lease_capacity\":{d},\"route_capacity\":{d},\"mutation_revision\":{d},\"admission_revision\":{d},\"last_observed_at_ms\":",
                .{
                    snapshot_version,
                    snapshot_contract_fingerprint,
                    lease_capacity,
                    route_capacity,
                    snapshot.mutation_revision,
                    snapshot.admission_revision,
                },
            );
            if (snapshot.last_observed_at_ms) |value| {
                try writer.print("{d}", .{value});
            } else try writer.writeAll("null");
            try writer.writeAll(",\"clock_recovery_until_ms\":");
            if (snapshot.clock_recovery_until_ms) |value| {
                try writer.print("{d}", .{value});
            } else try writer.writeAll("null");
            try writer.print(",\"next_generation\":{d},\"routes\":[", .{snapshot.next_generation});
            for (snapshot.routes[0..snapshot.route_count], 0..) |*route, index| {
                if (index != 0) try writer.writeByte(',');
                try writer.writeAll("{\"route\":");
                try std.json.stringify(route.route.bytes(), .{}, writer);
                try writer.writeAll(",\"exact_model\":");
                try std.json.stringify(route.exact_model.bytes(), .{}, writer);
                try writer.writeAll(",\"last_selected_at_ms\":");
                if (route.last_selected_at_ms) |value| {
                    try writer.print("{d}", .{value});
                } else try writer.writeAll("null");
                try writer.writeByte('}');
            }
            try writer.writeAll("],\"leases\":[");
            for (snapshot.leases[0..snapshot.lease_count], 0..) |*record, index| {
                if (index != 0) try writer.writeByte(',');
                try writer.writeAll("{\"lease\":");
                try std.json.stringify(record.lease.bytes(), .{}, writer);
                try writer.writeAll(",\"session\":");
                try std.json.stringify(record.session.bytes(), .{}, writer);
                try writer.writeAll(",\"account\":");
                try std.json.stringify(record.account.bytes(), .{}, writer);
                try writer.writeAll(",\"route\":");
                try std.json.stringify(record.route.bytes(), .{}, writer);
                try writer.writeAll(",\"exact_model\":");
                try std.json.stringify(record.exact_model.bytes(), .{}, writer);
                try writer.print(
                    ",\"owner\":{{\"pid\":{d},\"incarnation\":{d},\"generation\":{d}}},\"generation\":{d},\"selected_at_ms\":{d},\"heartbeat_at_ms\":{d},\"expires_at_ms\":{d},\"transition_from\":",
                    .{
                        record.owner.pid,
                        record.owner.incarnation,
                        record.owner.generation,
                        record.generation,
                        record.selected_at_ms,
                        record.heartbeat_at_ms,
                        record.expires_at_ms,
                    },
                );
                if (record.transition_from) |*origin| {
                    try writer.writeAll("{\"lease\":");
                    try std.json.stringify(origin.lease.bytes(), .{}, writer);
                    try writer.print(",\"generation\":{d}}}", .{origin.generation});
                } else try writer.writeAll("null");
                try writer.writeByte('}');
            }
            try writer.writeAll("]}\n");
        }
    };
}

fn ownedHandle(value: []const u8) !OwnedHandle {
    _ = identifiers.SessionHandle.parse(value) catch return error.InvalidLeaseState;
    return OwnedHandle.init(value);
}

fn validateAcquire(
    input: AcquireInput,
    sampled_now_ms: lease_state.TimestampMs,
) !void {
    _ = try lease_state.LeaseHandle.parse(input.lease.text);
    _ = try lease_state.SessionHandle.parse(input.session.text);
    _ = try lease_state.AccountHandle.parse(input.account.text);
    _ = try lease_state.RouteHandle.parse(input.route.text);
    if (!input.exact_model.isValid() or !input.owner.isValid() or
        !timestampValid(input.selected_at_ms) or
        !timestampValid(input.heartbeat_at_ms) or
        !timestampValid(input.expires_at_ms) or
        input.selected_at_ms > input.heartbeat_at_ms or
        input.heartbeat_at_ms > sampled_now_ms or
        sampled_now_ms >= input.expires_at_ms)
    {
        return error.InvalidLease;
    }
}

fn validateRenew(
    input: RenewInput,
    sampled_now_ms: lease_state.TimestampMs,
) !void {
    _ = try lease_state.LeaseHandle.parse(input.lease.text);
    _ = try lease_state.SessionHandle.parse(input.session.text);
    if (!input.owner.isValid() or !generationValid(input.generation) or
        !timestampValid(input.heartbeat_at_ms) or
        !timestampValid(input.expires_at_ms) or
        input.heartbeat_at_ms > sampled_now_ms or
        sampled_now_ms >= input.expires_at_ms)
    {
        return error.InvalidLease;
    }
}

fn storedLeaseFromAcquire(
    input: AcquireInput,
    generation: lease_state.Generation,
    transition_from: ?TransitionOrigin,
) !StoredLease {
    return .{
        .lease = try ownedHandle(input.lease.text),
        .session = try ownedHandle(input.session.text),
        .account = try ownedHandle(input.account.text),
        .route = try ownedHandle(input.route.text),
        .exact_model = input.exact_model,
        .owner = input.owner,
        .generation = generation,
        .selected_at_ms = input.selected_at_ms,
        .heartbeat_at_ms = input.heartbeat_at_ms,
        .expires_at_ms = input.expires_at_ms,
        .transition_from = transition_from,
    };
}

fn storedLeaseMatchesAcquire(stored: *const StoredLease, input: AcquireInput) bool {
    return stored.lease.eql(input.lease.text) and
        stored.session.eql(input.session.text) and
        stored.account.eql(input.account.text) and
        stored.route.eql(input.route.text) and
        stored.exact_model.eql(input.exact_model) and
        stored.owner.eql(input.owner) and
        stored.selected_at_ms == input.selected_at_ms and
        stored.heartbeat_at_ms == input.heartbeat_at_ms and
        stored.expires_at_ms == input.expires_at_ms;
}

fn authorizeStored(
    stored: *const StoredLease,
    session: lease_state.SessionHandle,
    owner: OwnerIdentity,
    generation: lease_state.Generation,
) !void {
    _ = try lease_state.SessionHandle.parse(session.text);
    if (!owner.isValid()) return error.InvalidLease;
    if (!stored.session.eql(session.text) or !stored.owner.eql(owner)) return error.OwnerMismatch;
    if (stored.generation != generation) return error.GenerationMismatch;
}

fn ensureDurableDirectoryAbsolute(path: []const u8) !void {
    if (comptime builtin.os.tag == .windows) {
        try std.fs.cwd().makePath(path);
        return;
    }
    var existing = std.fs.openDirAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse return error.InvalidRuntimeRoot;
            if (std.mem.eql(u8, parent, path)) return err;
            try ensureDurableDirectoryAbsolute(parent);
            std.fs.makeDirAbsolute(path) catch |mkdir_err| switch (mkdir_err) {
                error.PathAlreadyExists => {},
                else => return mkdir_err,
            };
            try syncDirectory(path);
            try syncDirectory(parent);
            return;
        },
        else => return err,
    };
    existing.close();
}

fn validateDirectoryCustody(dir: std.fs.Dir) !u64 {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.UnsupportedLeaseStorePlatform;
    }
    const stat = try std.posix.fstat(dir.fd);
    if ((stat.mode & std.posix.S.IFMT) != std.posix.S.IFDIR) {
        return error.InvalidRuntimeRoot;
    }
    if ((stat.mode & 0o022) != 0) return error.InsecureLeaseStateCustody;
    return @intCast(stat.uid);
}

fn syncDirectoryHandle(dir: std.fs.Dir) !void {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return;
    try std.posix.fsync(dir.fd);
}

fn syncDirectory(path: []const u8) !void {
    if (comptime builtin.os.tag == .windows) return;
    var dir = try std.fs.openDirAbsolute(path, .{ .iterate = true });
    defer dir.close();
    try std.posix.fsync(dir.fd);
}

fn lockFileAnnouncedBounded(
    file: std.fs.File,
    path: []const u8,
    log: anytype,
    opts: lock_wait.WaitOptions,
    monotonic_start: MonotonicStartFn,
) !void {
    if (try lock_wait.tryLockFile(file)) return;
    try log.print("[INF] waiting on lock {s}\n", .{path});

    var timer = monotonic_start() catch return error.MonotonicClockUnavailable;
    var last_heartbeat_ns: u64 = 0;
    while (true) {
        const before_sleep_ns = timer.read();
        if (before_sleep_ns >= opts.timeout_ns) {
            log.print(
                "[INF] gave up waiting on lock {s} after {d}s\n",
                .{ path, before_sleep_ns / std.time.ns_per_s },
            ) catch {};
            return error.LockWaitTimeout;
        }
        const remaining_ns = opts.timeout_ns - before_sleep_ns;
        std.Thread.sleep(@min(opts.poll_interval_ns, remaining_ns));
        if (try lock_wait.tryLockFile(file)) return;

        const elapsed_ns = timer.read();
        if (elapsed_ns >= opts.timeout_ns) {
            log.print(
                "[INF] gave up waiting on lock {s} after {d}s\n",
                .{ path, elapsed_ns / std.time.ns_per_s },
            ) catch {};
            return error.LockWaitTimeout;
        }
        if (elapsed_ns -| last_heartbeat_ns >= opts.heartbeat_ns) {
            last_heartbeat_ns = elapsed_ns;
            log.print(
                "[INF] still waiting on lock {s} ({d}s elapsed)\n",
                .{ path, elapsed_ns / std.time.ns_per_s },
            ) catch {};
        }
    }
}

fn alwaysAlive(_: *const anyopaque, _: OwnerIdentity) OwnerLiveness {
    return .alive;
}

const testing = std.testing;

fn testRoot(tmp: *std.testing.TmpDir) ![]const u8 {
    return tmp.dir.realpathAlloc(testing.allocator, ".");
}

fn testLog(tmp: *std.testing.TmpDir) !std.fs.File {
    return tmp.dir.createFile("lease-store.log", .{ .read = true, .truncate = false, .mode = 0o600 });
}

fn requestedTestTime(
    _: ?*const anyopaque,
    requested_ms: ?lease_state.TimestampMs,
) !lease_state.TimestampMs {
    return requested_ms orelse 0;
}

fn testOptions(log: ?std.fs.File) Options {
    return .{
        .log_file = log,
        .time = .{ .read = requestedTestTime },
    };
}

const MutableClock = struct {
    now_ms: lease_state.TimestampMs,

    fn read(
        ctx: ?*const anyopaque,
        _: ?lease_state.TimestampMs,
    ) !lease_state.TimestampMs {
        const self: *const MutableClock = @ptrCast(@alignCast(ctx.?));
        return self.now_ms;
    }
};

fn mutableClockOptions(log: ?std.fs.File, clock: *const MutableClock) Options {
    return .{
        .log_file = log,
        .time = .{ .ctx = @ptrCast(clock), .read = MutableClock.read },
    };
}

fn unavailableMonotonicTimer() !std.time.Timer {
    return error.TestMonotonicClockUnavailable;
}

fn routeHandle(value: []const u8) lease_state.RouteHandle {
    return lease_state.RouteHandle.parse(value) catch unreachable;
}

fn sessionHandle(value: []const u8) lease_state.SessionHandle {
    return lease_state.SessionHandle.parse(value) catch unreachable;
}

fn accountHandle(value: []const u8) lease_state.AccountHandle {
    return lease_state.AccountHandle.parse(value) catch unreachable;
}

fn leaseHandle(value: []const u8) lease_state.LeaseHandle {
    return lease_state.LeaseHandle.parse(value) catch unreachable;
}

fn exactModel(value: []const u8) lease_state.ExactModel {
    return lease_state.ExactModel.init(value) catch unreachable;
}

fn acquireInput(
    lease_text: []const u8,
    session_text: []const u8,
    account_text: []const u8,
    route_text: []const u8,
    owner: OwnerIdentity,
    revision: u64,
) AcquireInput {
    return .{
        .lease = leaseHandle(lease_text),
        .session = sessionHandle(session_text),
        .account = accountHandle(account_text),
        .route = routeHandle(route_text),
        .exact_model = exactModel("claude-opus-4"),
        .owner = owner,
        .expected_revision = revision,
        .now_ms = 100,
        .selected_at_ms = 90,
        .heartbeat_at_ms = 100,
        .expires_at_ms = 1_000,
    };
}

fn leaseGeneration(outcome: AcquireOutcome) lease_state.Generation {
    return switch (outcome) {
        .acquired => |value| value.generation,
        .already_active => |value| value.generation,
    };
}

test "TIN-3320 persisted lease view is redacted closed and reusable across store instances" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Store = LeaseStore(4, 4);
    try testing.expectError(
        error.InvalidRuntimeRoot,
        Store.init(testing.allocator, "relative/runtime", .{}),
    );
    var first = try Store.init(testing.allocator, root, testOptions(log));
    defer first.deinit();
    try first.registerRoute(.{ .route = routeHandle("route-a"), .exact_model = exactModel("claude-opus-4") });
    const live: LivenessSource = .{ .ctx = @ptrCast(&first), .resolve = alwaysAlive };
    const owner: OwnerIdentity = .{ .pid = 101, .incarnation = 7001, .generation = 1 };
    const before = try first.project(sessionHandle("session-a"), try lease_state.ModelDemand.init("claude-opus-4"), 100, live);
    const acquired = try first.acquire(
        acquireInput("lease-a", "session-a", "account-a", "route-a", owner, before.revision),
        live,
    );
    try testing.expectEqual(@as(u64, 1), leaseGeneration(acquired));

    var second = try Store.init(testing.allocator, root, testOptions(log));
    defer second.deinit();
    const projection = try second.project(sessionHandle("session-a"), try lease_state.ModelDemand.init("claude-opus-4"), 101, live);
    try testing.expectEqual(ProjectionQuality.complete, projection.quality);
    try testing.expectEqual(@as(usize, 1), projection.row_count);
    try testing.expectEqual(@as(u64, 1), projection.rows[0].active_leases);
    try testing.expect(projection.sticky_route != null);
    try testing.expectEqualStrings("route-a", projection.sticky_route.?.bytes());

    const state_bytes = try tmp.dir.readFileAlloc(testing.allocator, state_file_name, max_snapshot_bytes);
    defer testing.allocator.free(state_bytes);
    var parsed = try std.json.parseFromSlice(WireSnapshot, testing.allocator, state_bytes, .{});
    defer parsed.deinit();
    try testing.expectEqual(snapshot_version, parsed.value.version);
    try testing.expectEqualStrings(snapshot_contract_fingerprint, parsed.value.contract_fingerprint);
    try testing.expectEqual(@as(usize, 4), parsed.value.lease_capacity);
    try testing.expectEqual(@as(usize, 4), parsed.value.route_capacity);
    try testing.expect(parsed.value.mutation_revision > parsed.value.admission_revision);
    try testing.expectEqual(@as(?i64, 101), parsed.value.last_observed_at_ms);
    try testing.expect(parsed.value.clock_recovery_until_ms == null);
    for ([_][]const u8{
        "oat01-secret-canary",
        "user@example.com",
        "/Users/operator/.claude",
        "request-body-canary",
        "provider-payload-canary",
    }) |canary| {
        try testing.expect(std.mem.indexOf(u8, state_bytes, canary) == null);
    }
    const lease_fields = @typeInfo(StoredLease).@"struct".fields;
    const expected = [_][]const u8{
        "lease",      "session",        "account",         "route",         "exact_model",     "owner",
        "generation", "selected_at_ms", "heartbeat_at_ms", "expires_at_ms", "transition_from",
    };
    try testing.expectEqual(expected.len, lease_fields.len);
    inline for (expected, 0..) |name, index| {
        try testing.expectEqualStrings(name, lease_fields[index].name);
    }
    const projection_fields = @typeInfo(Store.Projection).@"struct".fields;
    const expected_projection = [_][]const u8{
        "revision", "quality", "sticky_route", "rows", "row_count",
    };
    try testing.expectEqual(expected_projection.len, projection_fields.len);
    inline for (expected_projection, 0..) |name, index| {
        try testing.expectEqualStrings(name, projection_fields[index].name);
    }
}

test "TIN-3320 PID reuse and predecessor generation cannot inherit or mutate a lease" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Store = LeaseStore(4, 2);
    var store = try Store.init(testing.allocator, root, testOptions(log));
    defer store.deinit();
    try store.registerRoute(.{ .route = routeHandle("route-a"), .exact_model = exactModel("claude-opus-4") });

    const old_owner: OwnerIdentity = .{ .pid = 202, .incarnation = 9001, .generation = 1 };
    const reused_pid: OwnerIdentity = .{ .pid = 202, .incarnation = 9002, .generation = 1 };
    const live: LivenessSource = .{ .ctx = @ptrCast(&store), .resolve = alwaysAlive };
    const projection = try store.project(sessionHandle("session-a"), try lease_state.ModelDemand.init("claude-opus-4"), 100, live);
    const acquired = try store.acquire(
        acquireInput("lease-a", "session-a", "account-a", "route-a", old_owner, projection.revision),
        live,
    );
    try testing.expectError(
        error.OwnerUnavailable,
        store.acquire(
            acquireInput("lease-a", "session-a", "account-a", "route-a", old_owner, projection.revision),
            .{ .ctx = @ptrCast(&store), .resolve = alwaysUnknown },
        ),
    );
    try testing.expectError(error.OwnerMismatch, store.release(.{
        .lease = leaseHandle("lease-a"),
        .session = sessionHandle("session-a"),
        .owner = reused_pid,
        .generation = leaseGeneration(acquired),
    }));
    try testing.expectError(error.OwnerMismatch, store.renew(.{
        .lease = leaseHandle("lease-a"),
        .session = sessionHandle("session-a"),
        .owner = .{ .pid = 202, .incarnation = 9001, .generation = 2 },
        .generation = leaseGeneration(acquired),
        .now_ms = 110,
        .heartbeat_at_ms = 110,
        .expires_at_ms = 1_100,
    }, live));
}

test "TIN-3320 renew advances mutation revision without starving stale admission" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Store = LeaseStore(4, 2);
    var store = try Store.init(testing.allocator, root, testOptions(log));
    defer store.deinit();
    try store.registerRoute(.{ .route = routeHandle("route-a"), .exact_model = exactModel("claude-opus-4") });
    const live: LivenessSource = .{ .ctx = @ptrCast(&store), .resolve = alwaysAlive };
    const owner_a: OwnerIdentity = .{ .pid = 211, .incarnation = 1, .generation = 1 };
    const owner_b: OwnerIdentity = .{ .pid = 212, .incarnation = 1, .generation = 1 };
    var projection = try store.project(
        sessionHandle("session-a"),
        try lease_state.ModelDemand.init("claude-opus-4"),
        100,
        live,
    );
    const first = try store.acquire(
        acquireInput("lease-a", "session-a", "account-a", "route-a", owner_a, projection.revision),
        live,
    );
    projection = try store.project(
        sessionHandle("session-b"),
        try lease_state.ModelDemand.init("claude-opus-4"),
        101,
        live,
    );
    const admission_before_renew = projection.revision;
    try testing.expectEqual(RenewOutcome.renewed, try store.renew(.{
        .lease = leaseHandle("lease-a"),
        .session = sessionHandle("session-a"),
        .owner = owner_a,
        .generation = leaseGeneration(first),
        .now_ms = 110,
        .heartbeat_at_ms = 110,
        .expires_at_ms = 1_100,
    }, live));

    var after_renew = try store.loadSnapshot();
    defer after_renew.deinit(testing.allocator);
    try testing.expectEqual(admission_before_renew, after_renew.snapshot.admission_revision);
    try testing.expect(after_renew.snapshot.mutation_revision > after_renew.snapshot.admission_revision);
    var second = acquireInput(
        "lease-b",
        "session-b",
        "account-b",
        "route-a",
        owner_b,
        admission_before_renew,
    );
    second.now_ms = 110;
    second.heartbeat_at_ms = 110;
    second.expires_at_ms = 1_100;
    _ = try store.acquire(second, live);
}

test "TIN-3320 authorized release removes an expired lease after sibling time advances" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Store = LeaseStore(4, 2);
    var store = try Store.init(testing.allocator, root, testOptions(log));
    defer store.deinit();
    try store.registerRoute(.{ .route = routeHandle("route-a"), .exact_model = exactModel("claude-opus-4") });
    const live: LivenessSource = .{ .ctx = @ptrCast(&store), .resolve = alwaysAlive };
    const owner_a: OwnerIdentity = .{ .pid = 213, .incarnation = 1, .generation = 1 };
    const owner_b: OwnerIdentity = .{ .pid = 214, .incarnation = 1, .generation = 1 };

    var projection = try store.project(
        sessionHandle("session-a"),
        try lease_state.ModelDemand.init("claude-opus-4"),
        100,
        live,
    );
    var first_input = acquireInput(
        "lease-a",
        "session-a",
        "account-a",
        "route-a",
        owner_a,
        projection.revision,
    );
    first_input.expires_at_ms = 105;
    const first = try store.acquire(first_input, live);

    projection = try store.project(
        sessionHandle("session-b"),
        try lease_state.ModelDemand.init("claude-opus-4"),
        100,
        live,
    );
    const second = try store.acquire(
        acquireInput("lease-b", "session-b", "account-b", "route-a", owner_b, projection.revision),
        live,
    );
    try testing.expectEqual(RenewOutcome.renewed, try store.renew(.{
        .lease = leaseHandle("lease-b"),
        .session = sessionHandle("session-b"),
        .owner = owner_b,
        .generation = leaseGeneration(second),
        .now_ms = 110,
        .heartbeat_at_ms = 110,
        .expires_at_ms = 1_100,
    }, live));

    const state_bytes = try tmp.dir.readFileAlloc(testing.allocator, state_file_name, max_snapshot_bytes);
    defer testing.allocator.free(state_bytes);
    var parsed = try std.json.parseFromSlice(WireSnapshot, testing.allocator, state_bytes, .{});
    defer parsed.deinit();
    const decoded = try Store.snapshotFromWire(testing.allocator, parsed.value);
    testing.allocator.destroy(decoded);

    try store.release(.{
        .lease = leaseHandle("lease-a"),
        .session = sessionHandle("session-a"),
        .owner = owner_a,
        .generation = leaseGeneration(first),
    });
    var loaded = try store.loadSnapshot();
    defer loaded.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), loaded.snapshot.lease_count);
    try testing.expect(loaded.snapshot.leases[0].lease.eql("lease-b"));
}

test "TIN-3320 future watermark fails closed across restart then recovers boundedly" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Store = LeaseStore(2, 2);
    var clock = MutableClock{ .now_ms = 100 };
    var first = try Store.init(testing.allocator, root, mutableClockOptions(log, &clock));
    try first.registerRoute(.{ .route = routeHandle("route-a"), .exact_model = exactModel("claude-opus-4") });
    const owner: OwnerIdentity = .{ .pid = 221, .incarnation = 2, .generation = 1 };
    const first_live: LivenessSource = .{ .ctx = @ptrCast(&first), .resolve = alwaysAlive };
    const before = try first.project(
        sessionHandle("session-a"),
        try lease_state.ModelDemand.init("claude-opus-4"),
        100,
        first_live,
    );
    var active = acquireInput(
        "lease-a",
        "session-a",
        "account-a",
        "route-a",
        owner,
        before.revision,
    );
    active.expires_at_ms = 100_000;
    active.selected_at_ms = 1;
    _ = try first.acquire(active, first_live);
    var initial = try first.loadSnapshot();
    defer initial.deinit(testing.allocator);
    const initial_admission = initial.snapshot.admission_revision;
    const initial_mutation = initial.snapshot.mutation_revision;
    try testing.expectEqual(@as(usize, 1), initial.snapshot.lease_count);
    try testing.expectEqual(@as(?i64, 100), initial.snapshot.last_observed_at_ms);
    first.deinit();

    clock.now_ms = 90;
    var skewed = try Store.init(testing.allocator, root, mutableClockOptions(log, &clock));
    const live: LivenessSource = .{ .ctx = @ptrCast(&skewed), .resolve = alwaysAlive };
    try testing.expectError(error.ClockSkewQuarantined, skewed.project(
        sessionHandle("session-a"),
        try lease_state.ModelDemand.init("claude-opus-4"),
        999,
        live,
    ));
    var quarantined = try skewed.loadSnapshot();
    defer quarantined.deinit(testing.allocator);
    try testing.expect(quarantined.snapshot.admission_revision > initial_admission);
    try testing.expect(quarantined.snapshot.mutation_revision > initial_mutation);
    try testing.expectEqual(@as(?i64, 90), quarantined.snapshot.last_observed_at_ms);
    try testing.expectEqual(
        @as(?i64, 90 + clock_recovery_window_ms),
        quarantined.snapshot.clock_recovery_until_ms,
    );
    try testing.expectEqual(@as(?i64, 0), quarantined.snapshot.routes[0].last_selected_at_ms);
    try testing.expectEqual(@as(usize, 1), quarantined.snapshot.lease_count);
    try testing.expectEqual(@as(i64, 0), quarantined.snapshot.leases[0].selected_at_ms);
    try testing.expectEqual(@as(i64, 90), quarantined.snapshot.leases[0].heartbeat_at_ms);
    try testing.expectEqual(@as(i64, 99_990), quarantined.snapshot.leases[0].expires_at_ms);
    skewed.deinit();

    clock.now_ms = 90 + clock_recovery_window_ms - 1;
    var waiting = try Store.init(testing.allocator, root, mutableClockOptions(log, &clock));
    try testing.expectError(
        error.ClockSkewQuarantined,
        waiting.project(
            sessionHandle("session-a"),
            try lease_state.ModelDemand.init("claude-opus-4"),
            0,
            .{ .ctx = @ptrCast(&waiting), .resolve = alwaysAlive },
        ),
    );
    waiting.deinit();

    clock.now_ms = 90 + clock_recovery_window_ms;
    var recovered = try Store.init(testing.allocator, root, mutableClockOptions(log, &clock));
    defer recovered.deinit();
    const projection = try recovered.project(
        sessionHandle("session-a"),
        try lease_state.ModelDemand.init("claude-opus-4"),
        0,
        .{ .ctx = @ptrCast(&recovered), .resolve = alwaysAlive },
    );
    try testing.expectEqual(ProjectionQuality.complete, projection.quality);
    try testing.expectEqual(@as(u64, 1), projection.rows[0].active_leases);
    var final = try recovered.loadSnapshot();
    defer final.deinit(testing.allocator);
    try testing.expect(final.snapshot.clock_recovery_until_ms == null);
    try testing.expectEqual(@as(?i64, clock.now_ms), final.snapshot.last_observed_at_ms);
    try testing.expect(final.snapshot.admission_revision > quarantined.snapshot.admission_revision);
}

const ExactLiveness = struct {
    alive_owner: OwnerIdentity,

    fn resolve(ctx: *const anyopaque, owner: OwnerIdentity) OwnerLiveness {
        const self: *const ExactLiveness = @ptrCast(@alignCast(ctx));
        if (owner.eql(self.alive_owner)) return .alive;
        return .dead;
    }
};

fn alwaysUnknown(_: *const anyopaque, _: OwnerIdentity) OwnerLiveness {
    return .unknown;
}

test "TIN-3320 stale dead owners are removed deterministically and cleanup is idempotent" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Store = LeaseStore(4, 2);
    var store = try Store.init(testing.allocator, root, testOptions(log));
    defer store.deinit();
    try store.registerRoute(.{ .route = routeHandle("route-a"), .exact_model = exactModel("claude-opus-4") });
    const owner_a: OwnerIdentity = .{ .pid = 301, .incarnation = 1, .generation = 1 };
    const owner_b: OwnerIdentity = .{ .pid = 301, .incarnation = 2, .generation = 1 };
    const all_live: LivenessSource = .{ .ctx = @ptrCast(&store), .resolve = alwaysAlive };
    var p = try store.project(sessionHandle("session-a"), try lease_state.ModelDemand.init("claude-opus-4"), 100, all_live);
    _ = try store.acquire(acquireInput("lease-a", "session-a", "account-a", "route-a", owner_a, p.revision), all_live);
    p = try store.project(sessionHandle("session-b"), try lease_state.ModelDemand.init("claude-opus-4"), 100, all_live);
    _ = try store.acquire(acquireInput("lease-b", "session-b", "account-b", "route-a", owner_b, p.revision), all_live);

    const exact = ExactLiveness{ .alive_owner = owner_b };
    const one_live: LivenessSource = .{ .ctx = @ptrCast(&exact), .resolve = ExactLiveness.resolve };
    try testing.expectEqual(@as(usize, 1), try store.cleanupStale(101, one_live));
    try testing.expectEqual(@as(usize, 0), try store.cleanupStale(101, one_live));
    const after = try store.project(sessionHandle("session-b"), try lease_state.ModelDemand.init("claude-opus-4"), 101, one_live);
    try testing.expectEqual(@as(u64, 1), after.rows[0].active_leases);
    try testing.expectEqualStrings("route-a", after.sticky_route.?.bytes());
    var persisted = try store.loadSnapshot();
    defer persisted.deinit(testing.allocator);
    try testing.expectEqual(LoadQuality.present, persisted.quality);
    try testing.expectEqual(@as(usize, 1), persisted.snapshot.lease_count);
    for (std.mem.asBytes(&persisted.snapshot.leases[1])) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "TIN-3320 unknown owners contribute neither load nor stickiness" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Store = LeaseStore(2, 2);
    var store = try Store.init(testing.allocator, root, testOptions(log));
    defer store.deinit();
    try store.registerRoute(.{ .route = routeHandle("route-a"), .exact_model = exactModel("claude-opus-4") });
    const owner: OwnerIdentity = .{ .pid = 401, .incarnation = 4, .generation = 1 };
    const live: LivenessSource = .{ .ctx = @ptrCast(&store), .resolve = alwaysAlive };
    const before = try store.project(sessionHandle("session-a"), try lease_state.ModelDemand.init("claude-opus-4"), 100, live);
    _ = try store.acquire(
        acquireInput("lease-a", "session-a", "account-a", "route-a", owner, before.revision),
        live,
    );

    const unknown: LivenessSource = .{ .ctx = @ptrCast(&store), .resolve = alwaysUnknown };
    const projection = try store.project(
        sessionHandle("session-a"),
        try lease_state.ModelDemand.init("claude-opus-4"),
        101,
        unknown,
    );
    try testing.expectEqual(ProjectionQuality.degraded, projection.quality);
    try testing.expectEqual(@as(u64, 0), projection.rows[0].active_leases);
    try testing.expect(projection.sticky_route == null);
}

test "TIN-3320 atomic transition survives reload and exact retry is idempotent" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Store = LeaseStore(3, 3);
    var store = try Store.init(testing.allocator, root, testOptions(log));
    defer store.deinit();
    try store.registerRoute(.{ .route = routeHandle("route-a"), .exact_model = exactModel("claude-opus-4") });
    try store.registerRoute(.{ .route = routeHandle("route-b"), .exact_model = exactModel("claude-opus-4") });
    const owner: OwnerIdentity = .{ .pid = 501, .incarnation = 5, .generation = 1 };
    const live: LivenessSource = .{ .ctx = @ptrCast(&store), .resolve = alwaysAlive };
    var projection = try store.project(
        sessionHandle("session-a"),
        try lease_state.ModelDemand.init("claude-opus-4"),
        100,
        live,
    );
    const first = try store.acquire(
        acquireInput("lease-a", "session-a", "account-a", "route-a", owner, projection.revision),
        live,
    );
    projection = try store.project(
        sessionHandle("session-a"),
        try lease_state.ModelDemand.init("claude-opus-4"),
        100,
        live,
    );
    var next = acquireInput(
        "lease-b",
        "session-a",
        "account-a",
        "route-b",
        owner,
        projection.revision,
    );
    next.selected_at_ms = 95;
    var same_handle = next;
    same_handle.lease = leaseHandle("lease-a");
    try testing.expectError(error.LeaseConflict, store.transition(.{
        .current_lease = leaseHandle("lease-a"),
        .current_generation = leaseGeneration(first),
        .next = same_handle,
    }, live));
    var regressed = next;
    regressed.selected_at_ms = 89;
    try testing.expectError(error.NonMonotonicTransition, store.transition(.{
        .current_lease = leaseHandle("lease-a"),
        .current_generation = leaseGeneration(first),
        .next = regressed,
    }, live));
    const transition_input: TransitionInput = .{
        .current_lease = leaseHandle("lease-a"),
        .current_generation = leaseGeneration(first),
        .next = next,
    };
    const moved = try store.transition(transition_input, live);
    try testing.expectError(
        error.OwnerUnavailable,
        store.transition(
            transition_input,
            .{ .ctx = @ptrCast(&store), .resolve = alwaysUnknown },
        ),
    );
    const duplicate = try store.transition(transition_input, live);
    try testing.expectEqual(moved.generation, duplicate.generation);

    var reopened = try Store.init(testing.allocator, root, testOptions(log));
    defer reopened.deinit();
    const after = try reopened.project(
        sessionHandle("session-a"),
        try lease_state.ModelDemand.init("claude-opus-4"),
        101,
        live,
    );
    try testing.expectEqualStrings("route-b", after.stickyRouteText().?);
    try testing.expectEqual(@as(usize, 2), after.row_count);
    try testing.expectEqual(@as(u64, 0), after.rows[0].active_leases);
    try testing.expectEqual(@as(u64, 1), after.rows[1].active_leases);
}

test "TIN-3320 corrupt state fails closed and requires explicit repair" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Store = LeaseStore(2, 2);
    var store = try Store.init(testing.allocator, root, testOptions(log));
    defer store.deinit();
    const corrupt_bytes = "{malformed:oat01-secret-canary}";
    const malformed = try tmp.dir.createFile(state_file_name, .{ .truncate = true, .mode = 0o600 });
    try malformed.writeAll(corrupt_bytes);
    malformed.close();
    const live: LivenessSource = .{ .ctx = @ptrCast(&store), .resolve = alwaysAlive };
    try testing.expectError(
        error.InvalidLeaseState,
        store.project(sessionHandle("session-a"), try lease_state.ModelDemand.init("claude-opus-4"), 10, live),
    );
    const preserved = try tmp.dir.readFileAlloc(testing.allocator, state_file_name, max_snapshot_bytes);
    defer testing.allocator.free(preserved);
    try testing.expectEqualStrings(corrupt_bytes, preserved);
    try testing.expectError(error.InvalidLeaseState, store.registerRoute(.{
        .route = routeHandle("route-a"),
        .exact_model = exactModel("claude-opus-4"),
    }));
    try testing.expect(try store.repairUnavailableState());
    try testing.expectError(error.FileNotFound, tmp.dir.access(state_file_name, .{}));

    const wrong_contract =
        \\{"version":2,"contract_fingerprint":"wrong","lease_capacity":2,"route_capacity":2,"mutation_revision":1,"admission_revision":0,"last_observed_at_ms":0,"clock_recovery_until_ms":null,"next_generation":1,"routes":[],"leases":[]}
    ;
    const incompatible = try tmp.dir.createFile(state_file_name, .{ .truncate = true, .mode = 0o600 });
    try incompatible.writeAll(wrong_contract);
    incompatible.close();
    try testing.expectError(
        error.IncompatibleLeaseState,
        store.project(sessionHandle("session-a"), try lease_state.ModelDemand.init("claude-opus-4"), 10, live),
    );
    const incompatible_preserved = try tmp.dir.readFileAlloc(testing.allocator, state_file_name, max_snapshot_bytes);
    defer testing.allocator.free(incompatible_preserved);
    try testing.expectEqualStrings(wrong_contract, incompatible_preserved);
    try testing.expectError(error.IncompatibleLeaseState, store.repairUnavailableState());
    const incompatible_after_repair = try tmp.dir.readFileAlloc(
        testing.allocator,
        state_file_name,
        max_snapshot_bytes,
    );
    defer testing.allocator.free(incompatible_after_repair);
    try testing.expectEqualStrings(wrong_contract, incompatible_after_repair);
    try tmp.dir.deleteFile(state_file_name);

    try store.registerRoute(.{ .route = routeHandle("route-a"), .exact_model = exactModel("claude-opus-4") });
    const recovered = try store.project(sessionHandle("session-a"), try lease_state.ModelDemand.init("claude-opus-4"), 10, live);
    try testing.expectEqual(ProjectionQuality.complete, recovered.quality);
    try testing.expectEqual(@as(usize, 1), recovered.row_count);

    const interrupted = try tmp.dir.createFile(
        state_file_name ++ ".tmp-interrupted",
        .{ .truncate = true, .mode = 0o600 },
    );
    try interrupted.writeAll("{malformed:oat01-secret-canary}");
    interrupted.close();
    const after_interruption = try store.project(
        sessionHandle("session-a"),
        try lease_state.ModelDemand.init("claude-opus-4"),
        10,
        live,
    );
    try testing.expectEqual(ProjectionQuality.complete, after_interruption.quality);
    try testing.expectEqual(@as(usize, 1), after_interruption.row_count);
    try testing.expect(!(try store.repairUnavailableState()));
}

test "TIN-3320 repair preserves valid state across allocator exhaustion" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Store = LeaseStore(2, 2);
    var store = try Store.init(testing.allocator, root, testOptions(log));
    defer store.deinit();
    try store.registerRoute(.{
        .route = routeHandle("route-a"),
        .exact_model = exactModel("claude-opus-4"),
    });
    const before = try tmp.dir.readFileAlloc(testing.allocator, state_file_name, max_snapshot_bytes);
    defer testing.allocator.free(before);

    var fail_index: usize = 0;
    var reached_success = false;
    while (fail_index < 64) : (fail_index += 1) {
        var failing = testing.FailingAllocator.init(testing.allocator, .{
            .fail_index = fail_index,
        });
        const original_allocator = store.allocator;
        store.allocator = failing.allocator();
        const repair_result = store.repairUnavailableState();
        store.allocator = original_allocator;

        if (repair_result) |removed| {
            try testing.expect(!removed);
            try testing.expect(!failing.has_induced_failure);
            reached_success = true;
        } else |err| {
            try testing.expect(err == error.OutOfMemory);
            try testing.expect(failing.has_induced_failure);
        }

        const after = try tmp.dir.readFileAlloc(
            testing.allocator,
            state_file_name,
            max_snapshot_bytes,
        );
        defer testing.allocator.free(after);
        try testing.expectEqualSlices(u8, before, after);
        if (reached_success) break;
    }
    try testing.expect(reached_success);
}

test "TIN-3320 capacity and contract drift fail closed without changing canonical state" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Wide = LeaseStore(4, 4);
    var wide = try Wide.init(testing.allocator, root, testOptions(log));
    try wide.registerRoute(.{ .route = routeHandle("route-a"), .exact_model = exactModel("claude-opus-4") });
    wide.deinit();
    const before = try tmp.dir.readFileAlloc(testing.allocator, state_file_name, max_snapshot_bytes);
    defer testing.allocator.free(before);

    const Narrow = LeaseStore(2, 2);
    var narrow = try Narrow.init(testing.allocator, root, testOptions(log));
    defer narrow.deinit();
    try testing.expectError(error.IncompatibleLeaseState, narrow.project(
        sessionHandle("session-a"),
        try lease_state.ModelDemand.init("claude-opus-4"),
        10,
        .{ .ctx = @ptrCast(&narrow), .resolve = alwaysAlive },
    ));
    try testing.expectError(error.IncompatibleLeaseState, narrow.registerRoute(.{
        .route = routeHandle("route-b"),
        .exact_model = exactModel("claude-opus-4"),
    }));
    try testing.expectError(error.IncompatibleLeaseState, narrow.repairUnavailableState());
    const after = try tmp.dir.readFileAlloc(testing.allocator, state_file_name, max_snapshot_bytes);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "TIN-3320 symlink special and insecure canonical files fail closed" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Store = LeaseStore(2, 2);
    var store = try Store.init(testing.allocator, root, testOptions(log));
    defer store.deinit();
    const live: LivenessSource = .{ .ctx = @ptrCast(&store), .resolve = alwaysAlive };

    const target = try tmp.dir.createFile("state-target", .{ .truncate = true, .mode = 0o600 });
    try target.writeAll("not-state");
    target.close();
    try tmp.dir.symLink("state-target", state_file_name, .{});
    try testing.expectError(
        error.SymLinkLoop,
        store.project(sessionHandle("session-a"), try lease_state.ModelDemand.init("claude-opus-4"), 10, live),
    );
    try testing.expectError(error.SymLinkLoop, store.registerRoute(.{
        .route = routeHandle("route-a"),
        .exact_model = exactModel("claude-opus-4"),
    }));
    try tmp.dir.deleteFile(state_file_name);

    try tmp.dir.makeDir(state_file_name);
    try testing.expectError(
        error.NonRegularLeaseState,
        store.project(sessionHandle("session-a"), try lease_state.ModelDemand.init("claude-opus-4"), 10, live),
    );
    try testing.expectError(error.NonRegularLeaseState, store.registerRoute(.{
        .route = routeHandle("route-a"),
        .exact_model = exactModel("claude-opus-4"),
    }));
    try tmp.dir.deleteDir(state_file_name);

    const insecure = try tmp.dir.createFile(state_file_name, .{ .truncate = true, .mode = 0o644 });
    try insecure.writeAll("{}");
    insecure.close();
    try testing.expectError(
        error.InsecureLeaseStateCustody,
        store.project(sessionHandle("session-a"), try lease_state.ModelDemand.init("claude-opus-4"), 10, live),
    );
    try tmp.dir.deleteFile(state_file_name);
}

test "TIN-3320 canonical replacement race cannot overwrite a new inode" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Store = LeaseStore(2, 2);
    var store = try Store.init(testing.allocator, root, testOptions(log));
    defer store.deinit();
    try store.registerRoute(.{ .route = routeHandle("route-a"), .exact_model = exactModel("claude-opus-4") });
    var loaded = try store.loadSnapshot();
    defer loaded.deinit(testing.allocator);
    try testing.expect(loaded.identity != null);
    const original = try tmp.dir.readFileAlloc(testing.allocator, state_file_name, max_snapshot_bytes);
    defer testing.allocator.free(original);
    try tmp.dir.rename(state_file_name, "displaced-state.json");
    const replacement = try tmp.dir.createFile(state_file_name, .{ .truncate = true, .mode = 0o600 });
    try replacement.writeAll(original);
    replacement.close();

    try testing.expectError(
        error.LeaseStatePathChanged,
        store.persist(loaded.snapshot, loaded.identity),
    );
    const after = try tmp.dir.readFileAlloc(testing.allocator, state_file_name, max_snapshot_bytes);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, original, after);
}

const ArmedPostRenameFailure = struct {
    armed: bool = false,

    fn run(raw: *anyopaque) !void {
        const self: *ArmedPostRenameFailure = @ptrCast(@alignCast(raw));
        if (self.armed) return error.InjectedPostRenameFailure;
    }
};

test "TIN-3320 post-rename failure is commit-uncertain and canonical state remains readable" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    var failure = ArmedPostRenameFailure{};
    const Store = LeaseStore(2, 2);
    var store = try Store.init(testing.allocator, root, .{
        .log_file = log,
        .time = .{ .read = requestedTestTime },
        .post_rename_hook = .{
            .ctx = @ptrCast(&failure),
            .run = ArmedPostRenameFailure.run,
        },
    });
    defer store.deinit();
    try store.registerRoute(.{
        .route = routeHandle("route-a"),
        .exact_model = exactModel("claude-opus-4"),
    });

    failure.armed = true;
    try testing.expectError(error.LeaseStateCommitUncertain, store.registerRoute(.{
        .route = routeHandle("route-b"),
        .exact_model = exactModel("claude-opus-4"),
    }));
    failure.armed = false;

    const projection = try store.project(
        sessionHandle("observer"),
        try lease_state.ModelDemand.init("claude-opus-4"),
        0,
        .{ .ctx = @ptrCast(&store), .resolve = alwaysAlive },
    );
    try testing.expectEqual(ProjectionQuality.complete, projection.quality);
    try testing.expectEqual(@as(usize, 2), projection.row_count);
}

test "TIN-3320 lock path symlink and special file never block" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Store = LeaseStore(2, 2);
    var store = try Store.init(testing.allocator, root, testOptions(log));
    defer store.deinit();
    const target = try tmp.dir.createFile("lock-target", .{ .truncate = false, .mode = 0o600 });
    target.close();
    try tmp.dir.symLink("lock-target", lock_file_name, .{});
    try testing.expectError(error.SymLinkLoop, store.registerRoute(.{
        .route = routeHandle("route-a"),
        .exact_model = exactModel("claude-opus-4"),
    }));
    try tmp.dir.deleteFile(lock_file_name);
    try tmp.dir.makeDir(lock_file_name);
    try testing.expectError(error.IsDir, store.registerRoute(.{
        .route = routeHandle("route-a"),
        .exact_model = exactModel("claude-opus-4"),
    }));
}

test "TIN-3320 bounded lock timeout is the precise advisory fallback class" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const lock_path = try std.fs.path.join(testing.allocator, &.{ root, lock_file_name });
    defer testing.allocator.free(lock_path);
    var holder = try std.fs.createFileAbsolute(lock_path, .{ .read = true, .truncate = false, .mode = 0o600 });
    defer holder.close();
    try testing.expect(try lock_wait.tryLockFile(holder));

    const Store = LeaseStore(2, 2);
    var store = try Store.init(testing.allocator, root, .{
        .log_file = log,
        .time = .{ .read = requestedTestTime },
        .wait = .{
            .poll_interval_ns = 2 * std.time.ns_per_ms,
            .heartbeat_ns = std.time.ns_per_hour,
            .timeout_ns = 30 * std.time.ns_per_ms,
        },
    });
    defer store.deinit();
    const live: LivenessSource = .{ .ctx = @ptrCast(&store), .resolve = alwaysAlive };
    try testing.expectError(
        error.LockWaitTimeout,
        store.project(sessionHandle("session-a"), try lease_state.ModelDemand.init("claude-opus-4"), 10, live),
    );
    try testing.expectError(error.LockWaitTimeout, store.registerRoute(.{
        .route = routeHandle("route-a"),
        .exact_model = exactModel("claude-opus-4"),
    }));

    var no_clock = try Store.init(testing.allocator, root, .{
        .log_file = log,
        .time = .{ .read = requestedTestTime },
        .monotonic_start = unavailableMonotonicTimer,
        .wait = .{
            .poll_interval_ns = 2 * std.time.ns_per_ms,
            .heartbeat_ns = std.time.ns_per_hour,
            .timeout_ns = 30 * std.time.ns_per_ms,
        },
    });
    defer no_clock.deinit();
    try testing.expectError(
        error.MonotonicClockUnavailable,
        no_clock.project(
            sessionHandle("session-a"),
            try lease_state.ModelDemand.init("claude-opus-4"),
            10,
            .{ .ctx = @ptrCast(&no_clock), .resolve = alwaysAlive },
        ),
    );
    try testing.expectError(error.MonotonicClockUnavailable, no_clock.registerRoute(.{
        .route = routeHandle("route-a"),
        .exact_model = exactModel("claude-opus-4"),
    }));
}

fn childAcquire(root: []const u8, owner: OwnerIdentity, suffix: u8) !void {
    const Store = LeaseStore(8, 2);
    var store = try Store.init(std.heap.page_allocator, root, .{
        .time = .{ .read = requestedTestTime },
        .wait = .{
            .poll_interval_ns = 2 * std.time.ns_per_ms,
            .heartbeat_ns = std.time.ns_per_s,
            .timeout_ns = 5 * std.time.ns_per_s,
        },
    });
    defer store.deinit();
    const live: LivenessSource = .{ .ctx = @ptrCast(&store), .resolve = alwaysAlive };
    var lease_buf: [32]u8 = undefined;
    var session_buf: [32]u8 = undefined;
    var account_buf: [32]u8 = undefined;
    const lease_text = try std.fmt.bufPrint(&lease_buf, "lease-{c}", .{suffix});
    const session_text = try std.fmt.bufPrint(&session_buf, "session-{c}", .{suffix});
    const account_text = try std.fmt.bufPrint(&account_buf, "account-{c}", .{suffix});
    var attempts: usize = 0;
    while (attempts < 8) : (attempts += 1) {
        const projection = try store.project(
            sessionHandle(session_text),
            try lease_state.ModelDemand.init("claude-opus-4"),
            100,
            live,
        );
        if (projection.quality == .unavailable) continue;
        _ = store.acquire(
            acquireInput(lease_text, session_text, account_text, "route-a", owner, projection.revision),
            live,
        ) catch |err| switch (err) {
            error.StateChanged => continue,
            else => return err,
        };
        return;
    }
    return error.StateChanged;
}

fn testProcessPid() lease_state.OwnerPid {
    return switch (builtin.os.tag) {
        .linux => @intCast(std.os.linux.getpid()),
        .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => @intCast(std.c.getpid()),
        else => unreachable,
    };
}

test "TIN-3320 two real processes contend on one store without lost updates or corruption" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer testing.allocator.free(root);
    var log = try testLog(&tmp);
    defer log.close();
    const Store = LeaseStore(8, 2);
    var store = try Store.init(testing.allocator, root, testOptions(log));
    defer store.deinit();
    try store.registerRoute(.{ .route = routeHandle("route-a"), .exact_model = exactModel("claude-opus-4") });

    const lock_path = try std.fs.path.join(testing.allocator, &.{ root, lock_file_name });
    defer testing.allocator.free(lock_path);
    var holder = try std.fs.createFileAbsolute(lock_path, .{ .read = true, .truncate = false, .mode = 0o600 });
    defer holder.close();
    try testing.expect(try lock_wait.tryLockFile(holder));

    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[1]);
    const Child = struct {
        fn run(read_fd: std.posix.fd_t, root_path: []const u8, owner: OwnerIdentity, suffix: u8) noreturn {
            var byte: [1]u8 = undefined;
            _ = std.posix.read(read_fd, &byte) catch std.posix.exit(91);
            std.posix.close(read_fd);
            childAcquire(root_path, owner, suffix) catch std.posix.exit(92);
            std.posix.exit(0);
        }
    };
    const first_pid = try std.posix.fork();
    if (first_pid == 0) Child.run(pipe[0], root, .{
        .pid = testProcessPid(),
        .incarnation = 11,
        .generation = 1,
    }, 'a');
    const second_pid = try std.posix.fork();
    if (second_pid == 0) Child.run(pipe[0], root, .{
        .pid = testProcessPid(),
        .incarnation = 12,
        .generation = 1,
    }, 'b');
    std.posix.close(pipe[0]);
    try testing.expectEqual(@as(usize, 2), try std.posix.write(pipe[1], "go"));
    std.Thread.sleep(40 * std.time.ns_per_ms);
    holder.unlock();

    const first_status = std.posix.waitpid(first_pid, 0);
    const second_status = std.posix.waitpid(second_pid, 0);
    try testing.expectEqual(@as(u32, 0), first_status.status);
    try testing.expectEqual(@as(u32, 0), second_status.status);

    const live: LivenessSource = .{ .ctx = @ptrCast(&store), .resolve = alwaysAlive };
    const projection = try store.project(sessionHandle("observer"), try lease_state.ModelDemand.init("claude-opus-4"), 101, live);
    try testing.expectEqual(ProjectionQuality.complete, projection.quality);
    try testing.expectEqual(@as(usize, 1), projection.row_count);
    try testing.expectEqual(@as(u64, 2), projection.rows[0].active_leases);
    const state_bytes = try tmp.dir.readFileAlloc(testing.allocator, state_file_name, max_snapshot_bytes);
    defer testing.allocator.free(state_bytes);
    var parsed = try std.json.parseFromSlice(WireSnapshot, testing.allocator, state_bytes, .{});
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 2), parsed.value.leases.len);
}
