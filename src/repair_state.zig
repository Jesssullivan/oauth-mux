const std = @import("std");
const builtin = @import("builtin");
const env = @import("env.zig");
const paths = @import("paths.zig");
const types = @import("types.zig");
const lock_wait = @import("lock_wait.zig");
const oauth = @import("oauth.zig");
const provider_schema = @import("provider_schema.zig");
const secret = @import("secret.zig");
const identity_hash = @import("identity_hash.zig");

pub const RepairEvent = struct {
    ts: i64 = 0,
    kind: []const u8 = "repair_run",
    profile: ?[]const u8 = null,
    provider: ?[]const u8 = null,
    account: ?[]const u8 = null,
    capability: ?[]const u8 = null,
    action: ?[]const u8 = null,
    command: ?[]const u8 = null,
    engine_run_available: ?bool = null,
    execution: ?[]const u8 = null,
    agent_safe: ?bool = null,
    spends_provider_calls: ?bool = null,
    budget: ?[]const u8 = null,
    repair_owner: ?[]const u8 = null,
    fresh_browser_context_required: ?bool = null,
    browser_context: ?[]const u8 = null,
    writeback_capability: ?[]const u8 = null,
    automatic_refresh_admitted: ?bool = null,
    refresh_outcome: ?types.RefreshOutcome = null,
    outcome: []const u8,
    reason: ?[]const u8 = null,
    ok: bool = false,
    executed: bool = false,
    interactive: bool = false,
    mutating: bool = false,
};

pub const RefreshEventInput = struct {
    ts: i64 = 0,
    profile: ?[]const u8 = null,
    provider: []const u8,
    account: []const u8,
    capability: ?[]const u8 = null,
    writeback_capability: ?[]const u8 = null,
    automatic_refresh_admitted: ?bool = null,
    outcome: types.RefreshOutcome,
    ok: bool = false,
    executed: bool = false,
    mutating: bool = false,
};

pub const HardRefreshEventMetadata = struct {
    profile: ?[]const u8 = null,
    capability: ?[]const u8 = null,
    writeback_capability: ?[]const u8 = null,
    automatic_refresh_admitted: ?bool = null,
};

pub const LockedRefreshFailure = struct {
    outcome: types.RefreshOutcome,
    endpoint_executed: bool,
    lineage_quarantined: bool = false,
};

pub const RefreshTokenDisposition = enum {
    endpoint_rotated,
    submitted_reused,
};

pub const LockedRefreshSuccess = struct {
    result: oauth.RefreshResult,
    refresh_token_disposition: RefreshTokenDisposition,
    provider: []const u8,
    account: []const u8,
    store_lock: ?RepairLock,

    /// The caller must invoke this only after the refreshed credential has been
    /// durably persisted to the canonical store. Until it succeeds, restart
    /// paths remain quarantined and cannot replay the submitted refresh token.
    pub fn credentialPersisted(self: *LockedRefreshSuccess, allocator: std.mem.Allocator) !void {
        try clearIndeterminateRefreshQuarantine(allocator, self.provider, self.account);
    }

    /// Keep aliases of one canonical store serialized through writeback and
    /// quarantine clear. Every caller releases this on success and error.
    pub fn releaseStoreLock(self: *LockedRefreshSuccess) void {
        if (self.store_lock) |*lock| lock.release();
        self.store_lock = null;
    }
};

pub const LockedRefreshAttempt = union(enum) {
    refreshed: LockedRefreshSuccess,
    failed: LockedRefreshFailure,
};

pub const LockedRefreshError = error{
    OutOfMemory,
    RefreshQuarantinePersistenceFailed,
};

/// The only constructor used for persisted typed refresh events. It binds the
/// generic `outcome` field to the same closed tag and deliberately omits a
/// free-form reason so endpoint/store text cannot enter the journal. The
/// canonical Claude keychain refusal remains an exact legacy `not_admitted`
/// row and is validated separately at the append boundary.
pub fn refreshEvent(input: RefreshEventInput) RepairEvent {
    return .{
        .ts = input.ts,
        .kind = "token_refresh",
        .profile = input.profile,
        .provider = input.provider,
        .account = input.account,
        .capability = input.capability,
        .action = "refresh",
        .writeback_capability = input.writeback_capability,
        .automatic_refresh_admitted = input.automatic_refresh_admitted,
        .refresh_outcome = input.outcome,
        .outcome = @tagName(input.outcome),
        .ok = input.ok,
        .executed = input.executed,
        .interactive = false,
        .mutating = input.mutating,
    };
}

pub const HandoffKey = struct {
    profile: ?[]const u8 = null,
    provider: []const u8,
    account: []const u8,
    capability: ?[]const u8 = null,
};

// ── Process-local actor gate (TIN-1851 no-self-deadlock, TIN-2059 no-self-race) ──
// The repair lock is an OS flock (createFileAbsolute .lock=.exclusive), which is
// per-open-file-description. A SECOND acquire of the same (provider,account) key
// from the SAME process — e.g. the in-process proxy materializer thread refreshing
// while the session main thread already holds the account's repair lock — opens a
// new fd and flock() would block on itself: a self-deadlock. We therefore hold
// exactly ONE real flock per key per process; a condition variable serializes the
// first-acquire so two threads never race the real flock for the same key.
// Cross-process serialization is unchanged: the OS flock still blocks (or returns
// RepairInProgress) for a different process.
//
// TIN-2059: plain refcounting made the in-process side re-entrant for EVERYONE —
// a daemon hosting a warm-scheduler tick AND a live session / broker materializer
// for one provider:account re-entered (`entry.count += 1`) and raced itself: two
// logical actors, one process, zero serialization, double-spend of a single-use
// refresh-token chain. The registry therefore tracks the OWNING ACTOR of each
// held key and only the same actor may nest:
//
//   - actor = the acquiring thread, unless the thread acts on behalf of another
//     actor via a cooperative blocking join (below);
//   - same-actor re-acquire → refcount join (one actor is sequential; it cannot
//     race itself);
//   - cross-actor NONBLOCKING acquire → error.RepairInProgress — the same typed
//     lock_busy/deferred contract every nonblocking caller already implements
//     for the cross-process case (pipeline probe/refresh/identity, CLI
//     repair/reauth/daemon-tick, broker + adapter identity guards);
//   - cross-actor BLOCKING acquire of a BLOCKING-held key → cooperative join +
//     actor adoption. The only blocking pair in the tree is the managed codex
//     session (adapters/codex/main.zig, holds across spawn→wait→finalize) and
//     the broker materializer refresh (broker_loader.refreshCodexAccountAuthFile)
//     running mid-session on the proxy thread ON BEHALF OF that session. The
//     joiner adopts the owner's actor for the duration of the hold so its nested
//     identity-lock acquire is recognized as the same actor;
//   - cross-actor BLOCKING acquire of a NONBLOCKING-held key → wait for full
//     release, then take the real flock. A nonblocking holder is a short-hold
//     typed writer (warm tick, probe, CLI repair), never a parent actor: the
//     materializer serializes BEHIND it, and its under-lock revalidation then
//     sees the freshly rotated credential (lock-then-revalidate, TIN-2073).

const ActorId = u64;

const HeldLock = struct {
    count: usize,
    acquiring: bool,
    owner_actor: ActorId,
    owner_blocking: bool,
    file: ?std.fs.File = null,
};

var held_mutex: std.Thread.Mutex = .{};
var held_cond: std.Thread.Condition = .{};
var held_locks: std.StringHashMapUnmanaged(HeldLock) = .{};
const held_gpa = std.heap.page_allocator; // process-global; mutated only under held_mutex

/// Actor identity this thread acts as. Defaults to the thread itself; a
/// cooperative blocking join temporarily adopts the lock owner's actor
/// (materializer-on-behalf-of-session), restored by release() in LIFO order.
threadlocal var adopted_actor: ?ActorId = null;

fn currentActor() ActorId {
    if (adopted_actor) |actor| return actor;
    return @intCast(std.Thread.getCurrentId());
}

pub const RepairLock = struct {
    allocator: std.mem.Allocator,
    key: []const u8, // caller-allocator-owned sanitized lock name
    /// Set on a cooperative blocking join: this hold adopted the owner's actor.
    /// release() restores the previous binding; every caller releases via defer
    /// in the acquiring frame, so restoration runs on the acquiring thread and
    /// unwinds LIFO with any nested holds.
    adopted: bool = false,
    prev_actor: ?ActorId = null,

    pub fn release(self: *RepairLock) void {
        held_mutex.lock();
        if (held_locks.getPtr(self.key)) |entry| {
            if (entry.count > 0) entry.count -= 1;
            if (entry.count == 0) {
                // Real-lock teardown: closing the fd drops the OS flock, and the
                // lock FILE deliberately persists (TIN-2041). Unlinking it here
                // raced waiters: a waiter blocked on the old inode acquires the
                // kernel flock the instant the fd closes, the unlink then orphans
                // the name it holds, and a later acquirer creates a NEW inode at
                // the same path and locks immediately — two concurrent holders.
                // flock(2) state is the only mutual-exclusion authority: stale
                // lock files are simply re-locked on the next acquire, and
                // probeRepairLock reports unlocked files as no repair in
                // progress.
                if (entry.file) |f| f.close();
                if (held_locks.fetchRemove(self.key)) |kv| held_gpa.free(kv.key);
                // Wake cross-actor blocking acquirers serialized behind this
                // hold (TIN-2059): they re-check the registry and take the
                // real flock only after full release.
                held_cond.broadcast();
            }
        }
        held_mutex.unlock();
        if (self.adopted) adopted_actor = self.prev_actor;
        self.allocator.free(self.key);
    }
};

// The append-only repair-events log is read back whole by every reader
// (hasPendingHandoff / writeEvents / writePendingHandoffView), each of which caps
// the read at 1 MiB and FAILS with FileTooBig past that. Bound the file so reads
// stay correct and O(tail): rotate to the most recent ~512 KiB once it grows past
// 768 KiB, and reject a serialized row larger than the remaining 256 KiB
// headroom. Repair handoffs resolve within a handful of events, so the retained
// tail covers every realistically-live pending handoff.
const events_read_cap_bytes: u64 = 1024 * 1024;
const events_soft_cap_bytes: u64 = 768 * 1024;
const events_retain_tail_bytes: usize = 512 * 1024;
const events_max_row_bytes: u64 = events_read_cap_bytes - events_soft_cap_bytes;

pub fn appendEvent(allocator: std.mem.Allocator, event: RepairEvent) !void {
    if (event.refresh_outcome == .hard_lineage_invalidated) {
        return error.HardRefreshRequiresLockedLineageProof;
    }
    return appendEventAuthorized(allocator, event, false);
}

fn appendEventAuthorized(
    allocator: std.mem.Allocator,
    event: RepairEvent,
    hard_lineage_authorized: bool,
) !void {
    return appendEventAuthorizedWithCaps(
        allocator,
        event,
        hard_lineage_authorized,
        events_soft_cap_bytes,
        events_retain_tail_bytes,
    );
}

fn appendEventAuthorizedWithCaps(
    allocator: std.mem.Allocator,
    event: RepairEvent,
    hard_lineage_authorized: bool,
    soft_cap: u64,
    retain_tail: usize,
) !void {
    try validateRepairEvent(event, hard_lineage_authorized);
    var counting = std.io.countingWriter(std.io.null_writer);
    try writeEventJsonAuthorized(
        counting.writer(),
        event,
        hard_lineage_authorized,
    );
    const row_bytes = std.math.add(
        u64,
        counting.bytes_written,
        1,
    ) catch return error.RepairEventTooLarge;
    if (row_bytes > events_max_row_bytes) return error.RepairEventTooLarge;

    const path = try eventsPath(allocator);
    defer allocator.free(path);
    if (hard_lineage_authorized) {
        try ensureDurableParentDirectory(path);
    } else {
        try ensureParentDir(path);
    }

    const file = try std.fs.createFileAbsolute(path, .{
        .read = true,
        .truncate = false,
        .mode = 0o600,
        .lock = .exclusive,
    });
    defer file.close();

    if (try file.getEndPos() > soft_cap) {
        if (hard_lineage_authorized) {
            // Maintenance cannot veto a newly proven hard outcome. Existing
            // hard rows are materialized when possible, then the new durable
            // row is always the final mutation.
            rotateRepairEventsTailInPlace(
                allocator,
                file,
                path,
                soft_cap,
                retain_tail,
            ) catch {};
        } else {
            // Once malformed state blocks rotation, refuse additional soft
            // growth instead of driving every reader past its 1 MiB cap.
            try rotateRepairEventsTailInPlace(
                allocator,
                file,
                path,
                soft_cap,
                retain_tail,
            );
        }
    }

    try file.seekFromEnd(0);
    try writeEventJsonAuthorized(file.writer(), event, hard_lineage_authorized);
    try file.writeAll("\n");
    if (hard_lineage_authorized) {
        // Final operation: never perform fallible destructive maintenance after
        // the new hard authority is committed.
        try file.sync();
        try syncParentDirectory(path);
        return;
    }

    // Best-effort: a rotation hiccup must not drop the event we just recorded.
    rotateRepairEventsTailInPlace(
        allocator,
        file,
        path,
        soft_cap,
        retain_tail,
    ) catch {};
}

pub const RefreshJournalSummary = struct {
    valid: bool = true,
    typed_events: usize = 0,
    invalid_events: usize = 0,
    hard_lineage_events: usize = 0,
    indeterminate_lineage_markers: usize = 0,
    latest_outcome: ?types.RefreshOutcome = null,
};

const PersistedRefreshEvent = struct {
    kind: ?[]const u8 = null,
    provider: ?[]const u8 = null,
    account: ?[]const u8 = null,
    refresh_outcome: ?[]const u8 = null,
    outcome: ?[]const u8 = null,
    ok: ?bool = null,
    executed: ?bool = null,
    mutating: ?bool = null,
};

fn lineLooksLikeTypedRefreshEvent(line: []const u8) bool {
    return std.mem.indexOf(u8, line, "\"refresh_outcome\"") != null and
        std.mem.indexOf(u8, line, "token_refresh") != null;
}

const TypedRefreshRow = struct {
    provider: []const u8,
    account: []const u8,
    raw_outcome: []const u8,
};

const RefreshRouteIdentity = struct {
    provider: []const u8,
    account: []const u8,
};

const RefreshRouteIdentityContext = struct {
    pub fn hash(_: @This(), route: RefreshRouteIdentity) u64 {
        const provider_hash = std.hash.Wyhash.hash(0, route.provider);
        return std.hash.Wyhash.hash(provider_hash, route.account);
    }

    pub fn eql(
        _: @This(),
        a: RefreshRouteIdentity,
        b: RefreshRouteIdentity,
    ) bool {
        return std.mem.eql(u8, a.provider, b.provider) and
            std.mem.eql(u8, a.account, b.account);
    }
};

const HardRefreshRouteMap = std.HashMap(
    RefreshRouteIdentity,
    void,
    RefreshRouteIdentityContext,
    std.hash_map.default_max_load_percentage,
);

const HardRefreshRouteSet = struct {
    allocator: std.mem.Allocator,
    routes: HardRefreshRouteMap,

    fn init(allocator: std.mem.Allocator) HardRefreshRouteSet {
        return .{
            .allocator = allocator,
            .routes = HardRefreshRouteMap.init(allocator),
        };
    }

    fn deinit(self: *HardRefreshRouteSet) void {
        var keys = self.routes.keyIterator();
        while (keys.next()) |route| {
            self.allocator.free(route.provider);
            self.allocator.free(route.account);
        }
        self.routes.deinit();
    }

    fn add(
        self: *HardRefreshRouteSet,
        provider: []const u8,
        account: []const u8,
    ) !void {
        const route = RefreshRouteIdentity{
            .provider = provider,
            .account = account,
        };
        if (self.routes.contains(route)) return;

        const owned_provider = try self.allocator.dupe(u8, provider);
        errdefer self.allocator.free(owned_provider);
        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try self.routes.put(.{
            .provider = owned_provider,
            .account = owned_account,
        }, {});
    }

    fn count(self: HardRefreshRouteSet) usize {
        return self.routes.count();
    }
};

fn collectHardRefreshRoutesFromJournalBytes(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !HardRefreshRouteSet {
    var hard_routes = HardRefreshRouteSet.init(allocator);
    errdefer hard_routes.deinit();

    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        const parsed = std.json.parseFromSlice(
            PersistedRefreshEvent,
            allocator,
            line,
            .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
        ) catch {
            if (lineLooksLikeTypedRefreshEvent(line)) {
                return error.InvalidRefreshJournal;
            }
            continue;
        };
        defer parsed.deinit();

        const row = (typedRefreshRow(parsed.value) catch
            return error.InvalidRefreshJournal) orelse continue;
        const outcome = types.RefreshOutcome.parse(row.raw_outcome) catch
            return error.InvalidRefreshJournal;
        if (outcome == .hard_lineage_invalidated) {
            try hard_routes.add(row.provider, row.account);
        }
    }
    return hard_routes;
}

fn typedRefreshRow(event: PersistedRefreshEvent) !?TypedRefreshRow {
    const kind = event.kind orelse return null;
    if (!std.mem.eql(u8, kind, "token_refresh")) return null;
    const raw_outcome = event.refresh_outcome orelse return null;
    const provider = event.provider orelse return error.InvalidRefreshJournal;
    const account = event.account orelse return error.InvalidRefreshJournal;
    const legacy_outcome = event.outcome orelse return error.InvalidRefreshJournal;
    const ok = event.ok orelse return error.InvalidRefreshJournal;
    const executed = event.executed orelse return error.InvalidRefreshJournal;
    const mutating = event.mutating orelse return error.InvalidRefreshJournal;
    if (provider.len == 0 or account.len == 0 or
        !std.mem.eql(u8, raw_outcome, legacy_outcome) or
        ok != std.mem.eql(u8, raw_outcome, "refreshed") or
        mutating != executed or
        (std.mem.eql(u8, raw_outcome, "hard_lineage_invalidated") and !executed))
    {
        return error.InvalidRefreshJournal;
    }
    return .{
        .provider = provider,
        .account = account,
        .raw_outcome = raw_outcome,
    };
}

pub const RefreshQuarantineState = enum {
    indeterminate_lineage,
    hard_lineage_invalidated,

    fn parse(value: []const u8) !RefreshQuarantineState {
        inline for (std.meta.fields(RefreshQuarantineState)) |field| {
            if (std.mem.eql(u8, value, field.name)) {
                return @enumFromInt(field.value);
            }
        }
        return error.InvalidRefreshQuarantine;
    }
};

const PersistedRefreshQuarantine = struct {
    version: u8,
    provider: []const u8,
    account: []const u8,
    state: ?[]const u8 = null,
    outcome: ?[]const u8 = null,
    recovery: []const u8,
    stale_backup_restore_allowed: bool,
    store_fingerprint: ?[]const u8 = null,
    identity_fingerprint: ?[]const u8 = null,
};

fn refreshQuarantineDir(allocator: std.mem.Allocator) ![]const u8 {
    const dir = try paths.stateDir(allocator);
    defer allocator.free(dir);
    return std.fs.path.join(allocator, &.{ dir, "refresh-quarantine" });
}

fn refreshQuarantinePath(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) ![]const u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(provider);
    hasher.update(&.{0});
    hasher.update(account);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    const dir = try refreshQuarantineDir(allocator);
    defer allocator.free(dir);
    const file_name = try std.fmt.allocPrint(
        allocator,
        "{s}.json",
        .{std.fmt.fmtSliceHexLower(&digest)},
    );
    defer allocator.free(file_name);
    return std.fs.path.join(allocator, &.{ dir, file_name });
}

pub fn refreshQuarantineMarkerPathForTest(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) ![]const u8 {
    if (!builtin.is_test) @compileError("test-only refresh quarantine path");
    return refreshQuarantinePath(allocator, provider, account);
}

fn syncParentDirectory(path: []const u8) !void {
    if (comptime builtin.os.tag == .windows) return;
    const parent = std.fs.path.dirname(path) orelse return error.InvalidRefreshQuarantine;
    // Zig uses O_PATH for non-iterable Linux directory handles; fsync requires
    // a real readable directory descriptor.
    var dir = try std.fs.openDirAbsolute(parent, .{ .iterate = true });
    defer dir.close();
    try std.posix.fsync(dir.fd);
}

fn ensureDurableDirectoryAbsolute(path: []const u8) !void {
    if (comptime builtin.os.tag == .windows) {
        try std.fs.cwd().makePath(path);
        return;
    }
    var existing = std.fs.openDirAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse
                return error.InvalidRefreshQuarantine;
            if (std.mem.eql(u8, parent, path)) return err;
            try ensureDurableDirectoryAbsolute(parent);
            std.fs.makeDirAbsolute(path) catch |mkdir_err| switch (mkdir_err) {
                error.PathAlreadyExists => {},
                else => return mkdir_err,
            };
            var created = try std.fs.openDirAbsolute(path, .{ .iterate = true });
            defer created.close();
            try std.posix.fsync(created.fd);
            try syncParentDirectory(path);
            return;
        },
        else => return err,
    };
    existing.close();
}

fn ensureDurableParentDirectory(path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse
        return error.InvalidRefreshQuarantine;
    try ensureDurableDirectoryAbsolute(parent);
}

fn writeRefreshQuarantineMarker(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
    state: RefreshQuarantineState,
    store_fingerprint: ?[]const u8,
    identity_fingerprint: ?[]const u8,
) !void {
    const path = try refreshQuarantinePath(allocator, provider, account);
    defer allocator.free(path);
    try ensureDurableParentDirectory(path);

    const tmp_path = try std.fmt.allocPrint(
        allocator,
        "{s}.tmp-{x}",
        .{ path, std.crypto.random.int(u64) },
    );
    defer allocator.free(tmp_path);
    var renamed = false;
    defer if (!renamed) std.fs.deleteFileAbsolute(tmp_path) catch {};

    {
        const file = try std.fs.createFileAbsolute(tmp_path, .{
            .exclusive = true,
            .mode = 0o600,
        });
        defer file.close();
        const writer = file.writer();
        try writer.writeAll("{\"version\":1,\"provider\":");
        try std.json.stringify(provider, .{}, writer);
        try writer.writeAll(",\"account\":");
        try std.json.stringify(account, .{}, writer);
        try writer.writeAll(",\"state\":");
        try std.json.stringify(@tagName(state), .{}, writer);
        try writer.writeAll(",\"outcome\":");
        if (state == .hard_lineage_invalidated) {
            try std.json.stringify("hard_lineage_invalidated", .{}, writer);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(
            ",\"recovery\":\"provider_reenroll\",\"stale_backup_restore_allowed\":false,\"store_fingerprint\":",
        );
        if (store_fingerprint) |fingerprint| {
            try std.json.stringify(fingerprint, .{}, writer);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"identity_fingerprint\":");
        if (identity_fingerprint) |fingerprint| {
            try std.json.stringify(fingerprint, .{}, writer);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll("}\n");
        try file.sync();
    }

    try std.fs.renameAbsolute(tmp_path, path);
    renamed = true;
    try syncParentDirectory(path);
}

pub fn persistIndeterminateRefreshQuarantine(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) !void {
    if (try effectiveRefreshQuarantineForRoute(
        allocator,
        provider,
        account,
    ) != null) {
        return;
    }
    try writeRefreshQuarantineMarker(
        allocator,
        provider,
        account,
        .indeterminate_lineage,
        null,
        null,
    );
}

fn persistHardRefreshQuarantine(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
    metadata: HardRefreshEventMetadata,
    store_fingerprint: ?[]const u8,
    identity_fingerprint: ?[]const u8,
) LockedRefreshError!void {
    const event = refreshEvent(.{
        .profile = metadata.profile,
        .provider = provider,
        .account = account,
        .capability = metadata.capability,
        .writeback_capability = metadata.writeback_capability,
        .automatic_refresh_admitted = metadata.automatic_refresh_admitted,
        .outcome = .hard_lineage_invalidated,
        .executed = true,
        .mutating = true,
    });

    // Keep two independent sticky authorities. Either one blocks resurrection;
    // both writes are attempted, and any failure is returned to the caller.
    var persistence_failed = false;
    writeRefreshQuarantineMarker(
        allocator,
        provider,
        account,
        .hard_lineage_invalidated,
        store_fingerprint,
        identity_fingerprint,
    ) catch {
        persistence_failed = true;
    };
    appendEventAuthorized(allocator, event, true) catch {
        persistence_failed = true;
    };
    if (persistence_failed) return error.RefreshQuarantinePersistenceFailed;
}

const CanonicalRefreshLineage = struct {
    refresh_token: []const u8,
    identity: ?[]const u8,

    fn deinit(self: CanonicalRefreshLineage, allocator: std.mem.Allocator) void {
        allocator.free(self.refresh_token);
        if (self.identity) |identity| allocator.free(identity);
    }
};

fn hashFingerprintPart(
    hasher: *std.crypto.hash.sha2.Sha256,
    value: []const u8,
) void {
    hasher.update(value);
    hasher.update(&.{0});
}

fn digestHex(hasher: *std.crypto.hash.sha2.Sha256) [64]u8 {
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

fn refreshStoreFingerprint(
    allocator: std.mem.Allocator,
    provider: []const u8,
    backend: types.SecretBackend,
) ![64]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hashFingerprintPart(&hasher, provider);
    hashFingerprintPart(&hasher, @tagName(std.meta.activeTag(backend)));
    switch (backend) {
        .keychain => |ref| {
            hashFingerprintPart(&hasher, ref.service);
            hashFingerprintPart(&hasher, ref.account);
        },
        .sops => |ref| {
            hashFingerprintPart(&hasher, ref.path);
            if (ref.key_path) |key_path| hashFingerprintPart(&hasher, key_path);
        },
        .age => |ref| {
            hashFingerprintPart(&hasher, ref.path);
            hashFingerprintPart(&hasher, ref.identity);
        },
        .env => |ref| hashFingerprintPart(&hasher, ref.variable),
        .file => |ref| {
            const expanded = try paths.expandTilde(allocator, ref.path);
            defer allocator.free(expanded);
            const canonical = std.fs.realpathAlloc(allocator, expanded) catch null;
            defer if (canonical) |path| allocator.free(path);
            hashFingerprintPart(&hasher, canonical orelse expanded);
        },
        .command => |ref| for (ref.argv) |arg| hashFingerprintPart(&hasher, arg),
        .stdin => {},
    }
    return digestHex(&hasher);
}

fn refreshIdentityFingerprint(identity: []const u8) [64]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hashFingerprintPart(&hasher, identity);
    return digestHex(&hasher);
}

fn readCanonicalRefreshLineage(
    allocator: std.mem.Allocator,
    backend: types.SecretBackend,
    def: provider_schema.ProviderDefinition,
) !CanonicalRefreshLineage {
    const raw = try secret.read(backend, allocator);
    defer allocator.free(raw);

    const token = try provider_schema.parseTokenGeneric(def, raw, allocator);
    defer allocator.free(token.access_token);
    const refresh_token = token.refresh_token orelse return error.RefreshTokenMissing;
    errdefer allocator.free(refresh_token);
    const identity = try provider_schema.identityClaimFromCredential(def, raw, allocator);
    return .{
        .refresh_token = refresh_token,
        .identity = identity,
    };
}

fn lockedRefreshFailure(
    outcome: types.RefreshOutcome,
    endpoint_executed: bool,
) LockedRefreshAttempt {
    return .{ .failed = .{
        .outcome = outcome,
        .endpoint_executed = endpoint_executed,
    } };
}

fn lockedQuarantinedRefreshFailure(
    outcome: types.RefreshOutcome,
    endpoint_executed: bool,
) LockedRefreshAttempt {
    return .{ .failed = .{
        .outcome = outcome,
        .endpoint_executed = endpoint_executed,
        .lineage_quarantined = true,
    } };
}

fn freeRefreshResult(allocator: std.mem.Allocator, result: oauth.RefreshResult) void {
    allocator.free(result.access_token);
    if (result.refresh_token) |refresh_token| allocator.free(refresh_token);
}

const IndeterminateRefreshBoundary = struct {
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
    store_fingerprint: []const u8,
    identity_fingerprint: ?[]const u8,
    armed: bool = false,

    fn beforeSend(ctx: *anyopaque) oauth.RefreshError!void {
        const self: *IndeterminateRefreshBoundary = @ptrCast(@alignCast(ctx));
        writeRefreshQuarantineMarker(
            self.allocator,
            self.provider,
            self.account,
            .indeterminate_lineage,
            self.store_fingerprint,
            self.identity_fingerprint,
        ) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return error.BoundaryPersistenceFailed;
        };
        self.armed = true;
    }
};

/// Execute a refresh under the configured canonical store and live flock
/// lineage. The hard tag is created and persisted only inside this operation:
/// a private proof binds the submitted token and upstream identity before and
/// after the real endpoint response, while the same actor owns both the account
/// and exact identity flocks. Ordinary event appenders cannot manufacture it.
pub fn refreshTokenWithLockedLineage(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
    backend: types.SecretBackend,
    def: provider_schema.ProviderDefinition,
    token_url: []const u8,
    submitted_refresh_token: []const u8,
    client_id: ?[]const u8,
    metadata: HardRefreshEventMetadata,
) LockedRefreshError!LockedRefreshAttempt {
    const mux_refresh_authorized =
        def.repair.owner == .oauth_mux_refresh or
        (def.repair.owner == .upstream_cli_login and
            def.repair.proactive_refresh == .oauth_refresh_token);
    if (!mux_refresh_authorized) {
        return lockedRefreshFailure(.transient_endpoint, false);
    }
    if (!(currentActorOwnsRepairLock(allocator, provider, account) catch
        return error.OutOfMemory))
    {
        return lockedRefreshFailure(.transient_lock, false);
    }
    const route_quarantine = effectiveRefreshQuarantineForRoute(
        allocator,
        provider,
        account,
    ) catch return lockedRefreshFailure(.transient_store, false);
    if (route_quarantine) |state| {
        return switch (state) {
            .hard_lineage_invalidated => lockedQuarantinedRefreshFailure(
                .hard_lineage_invalidated,
                false,
            ),
            .indeterminate_lineage => lockedQuarantinedRefreshFailure(
                .transient_store,
                false,
            ),
        };
    }

    const before = readCanonicalRefreshLineage(allocator, backend, def) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return lockedRefreshFailure(.transient_store, false);
    };
    defer before.deinit(allocator);
    if (!std.mem.eql(u8, before.refresh_token, submitted_refresh_token)) {
        return lockedRefreshFailure(.transient_store, false);
    }
    const store_fingerprint = refreshStoreFingerprint(
        allocator,
        provider,
        backend,
    ) catch return error.OutOfMemory;
    // Account labels are not canonical-store identities. Serialize aliases
    // that resolve to the same backend before scanning/arming lineage state so
    // two labels cannot both pass a clear scan and submit one rotating token.
    var store_lock: ?RepairLock = acquireRepairLock(
        allocator,
        "refresh-store",
        &store_fingerprint,
    ) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return lockedRefreshFailure(.transient_lock, false);
    };
    defer if (store_lock) |*lock| lock.release();
    var identity_fingerprint_storage: [64]u8 = undefined;
    const identity_fingerprint: ?[]const u8 = if (before.identity) |identity| blk: {
        identity_fingerprint_storage = refreshIdentityFingerprint(identity);
        break :blk &identity_fingerprint_storage;
    } else null;
    const lineage_quarantine = refreshQuarantineForLineage(
        allocator,
        provider,
        account,
        &store_fingerprint,
        identity_fingerprint,
    ) catch return lockedRefreshFailure(.transient_store, false);
    if (lineage_quarantine) |state| {
        return switch (state) {
            .hard_lineage_invalidated => lockedQuarantinedRefreshFailure(
                .hard_lineage_invalidated,
                false,
            ),
            .indeterminate_lineage => lockedQuarantinedRefreshFailure(
                .transient_store,
                false,
            ),
        };
    }

    var identity_domain: ?[]const u8 = null;
    defer if (identity_domain) |value| allocator.free(value);
    var identity_key: ?[]const u8 = null;
    defer if (identity_key) |value| allocator.free(value);

    if (before.identity) |identity| {
        identity_domain = std.fmt.allocPrint(
            allocator,
            "{s}-identity",
            .{provider},
        ) catch return error.OutOfMemory;
        identity_key = identity_hash.sha256_12hex(
            allocator,
            identity,
        ) catch return error.OutOfMemory;
        if (!(currentActorOwnsRepairLock(
            allocator,
            identity_domain.?,
            identity_key.?,
        ) catch return error.OutOfMemory)) {
            return lockedRefreshFailure(.transient_lock, false);
        }
    }

    var boundary = IndeterminateRefreshBoundary{
        .allocator = allocator,
        .provider = provider,
        .account = account,
        .store_fingerprint = &store_fingerprint,
        .identity_fingerprint = identity_fingerprint,
    };
    const attempt = oauth.refreshTokenWithBoundary(
        allocator,
        token_url,
        submitted_refresh_token,
        client_id,
        .{
            .ctx = &boundary,
            .before_send = IndeterminateRefreshBoundary.beforeSend,
        },
    ) catch |err| {
        const outcome: types.RefreshOutcome = switch (err) {
            error.NetworkError => .transient_network,
            error.InvalidResponse, error.RefreshDenied => .transient_endpoint,
            error.BoundaryPersistenceFailed, error.OutOfMemory => .transient_store,
        };
        return if (boundary.armed)
            lockedQuarantinedRefreshFailure(outcome, true)
        else
            lockedRefreshFailure(outcome, false);
    };
    return switch (attempt) {
        .refreshed => |result| blk: {
            const disposition: RefreshTokenDisposition = if (result.refresh_token != null)
                .endpoint_rotated
            else switch (def.repair.refresh_token_response) {
                .require_rotated => {
                    freeRefreshResult(allocator, result);
                    break :blk lockedQuarantinedRefreshFailure(
                        .transient_endpoint,
                        true,
                    );
                },
                .reuse_submitted_if_omitted => .submitted_reused,
            };
            const transferred_store_lock = store_lock.?;
            store_lock = null;
            break :blk .{ .refreshed = .{
                .result = result,
                .refresh_token_disposition = disposition,
                .provider = provider,
                .account = account,
                .store_lock = transferred_store_lock,
            } };
        },
        .endpoint_failure => |endpoint_failure| blk: {
            if (endpoint_failure == .indeterminate_success or
                endpoint_failure == .unproven)
            {
                break :blk lockedQuarantinedRefreshFailure(
                    .transient_endpoint,
                    true,
                );
            }
            const expected_identity = before.identity orelse
                break :blk lockedQuarantinedRefreshFailure(.transient_store, true);

            if (!(currentActorOwnsRepairLock(allocator, provider, account) catch
                break :blk lockedQuarantinedRefreshFailure(.transient_store, true)))
            {
                break :blk lockedQuarantinedRefreshFailure(.transient_lock, true);
            }
            if (!(currentActorOwnsRepairLock(
                allocator,
                identity_domain.?,
                identity_key.?,
            ) catch break :blk lockedQuarantinedRefreshFailure(.transient_store, true))) {
                break :blk lockedQuarantinedRefreshFailure(.transient_lock, true);
            }

            const after = readCanonicalRefreshLineage(allocator, backend, def) catch {
                break :blk lockedQuarantinedRefreshFailure(.transient_store, true);
            };
            defer after.deinit(allocator);
            const after_identity = after.identity orelse
                break :blk lockedQuarantinedRefreshFailure(.transient_store, true);
            if (!std.mem.eql(u8, expected_identity, after_identity) or
                !std.mem.eql(u8, before.refresh_token, after.refresh_token))
            {
                break :blk lockedQuarantinedRefreshFailure(.transient_store, true);
            }

            // Recheck both capabilities immediately before the durable commit.
            if (!(currentActorOwnsRepairLock(allocator, provider, account) catch
                break :blk lockedQuarantinedRefreshFailure(.transient_store, true)) or
                !(currentActorOwnsRepairLock(
                    allocator,
                    identity_domain.?,
                    identity_key.?,
                ) catch break :blk lockedQuarantinedRefreshFailure(.transient_store, true)))
            {
                break :blk lockedQuarantinedRefreshFailure(.transient_lock, true);
            }
            try persistHardRefreshQuarantine(
                allocator,
                provider,
                account,
                metadata,
                &store_fingerprint,
                identity_fingerprint,
            );
            break :blk lockedQuarantinedRefreshFailure(
                .hard_lineage_invalidated,
                true,
            );
        },
    };
}

fn validRefreshFingerprint(value: []const u8) bool {
    if (value.len != 64) return false;
    for (value) |byte| {
        if (!std.ascii.isHex(byte) or std.ascii.isUpper(byte)) return false;
    }
    return true;
}

fn refreshQuarantineState(
    value: PersistedRefreshQuarantine,
) !RefreshQuarantineState {
    if (value.provider.len == 0 or
        value.account.len == 0 or
        value.version != 1 or
        !std.mem.eql(u8, value.recovery, "provider_reenroll") or
        value.stale_backup_restore_allowed)
    {
        return error.InvalidRefreshQuarantine;
    }
    if (value.store_fingerprint) |fingerprint| {
        if (!validRefreshFingerprint(fingerprint)) return error.InvalidRefreshQuarantine;
    }
    if (value.identity_fingerprint) |fingerprint| {
        if (!validRefreshFingerprint(fingerprint)) return error.InvalidRefreshQuarantine;
    }

    if (value.state) |raw_state| {
        const state = try RefreshQuarantineState.parse(raw_state);
        switch (state) {
            .indeterminate_lineage => {
                if (value.outcome != null) return error.InvalidRefreshQuarantine;
            },
            .hard_lineage_invalidated => {
                const raw_outcome = value.outcome orelse
                    return error.InvalidRefreshQuarantine;
                const outcome = try types.RefreshOutcome.parse(raw_outcome);
                if (outcome != .hard_lineage_invalidated) {
                    return error.InvalidRefreshQuarantine;
                }
            },
        }
        return state;
    }

    // Version-1 hard markers from the initial TIN-2990 candidate had no
    // private `state` field. Keep those sticky and readable.
    const raw_outcome = value.outcome orelse return error.InvalidRefreshQuarantine;
    const outcome = try types.RefreshOutcome.parse(raw_outcome);
    if (outcome != .hard_lineage_invalidated) {
        return error.InvalidRefreshQuarantine;
    }
    return .hard_lineage_invalidated;
}

fn parseRefreshQuarantineBytes(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected_provider: ?[]const u8,
    expected_account: ?[]const u8,
) !RefreshQuarantineState {
    const parsed = try std.json.parseFromSlice(
        PersistedRefreshQuarantine,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = false, .allocate = .alloc_always },
    );
    defer parsed.deinit();
    const value = parsed.value;
    const state = try refreshQuarantineState(value);
    if (expected_provider) |provider| {
        if (!std.mem.eql(u8, value.provider, provider)) return error.InvalidRefreshQuarantine;
    }
    if (expected_account) |account| {
        if (!std.mem.eql(u8, value.account, account)) return error.InvalidRefreshQuarantine;
    }
    return state;
}

fn ensureHardMarkerForJournalRoute(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) !void {
    const path = try refreshQuarantinePath(allocator, provider, account);
    defer allocator.free(path);
    const file = std.fs.openFileAbsolute(path, .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => {
            try writeRefreshQuarantineMarker(
                allocator,
                provider,
                account,
                .hard_lineage_invalidated,
                null,
                null,
            );
            return;
        },
        else => return err,
    };
    defer file.close();
    const bytes = try file.readToEndAlloc(allocator, 4 * 1024);
    defer allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(
        PersistedRefreshQuarantine,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = false, .allocate = .alloc_always },
    );
    defer parsed.deinit();
    const value = parsed.value;
    if (!std.mem.eql(u8, value.provider, provider) or
        !std.mem.eql(u8, value.account, account))
    {
        return error.InvalidRefreshQuarantine;
    }
    switch (try refreshQuarantineState(value)) {
        .hard_lineage_invalidated => {
            // Close the rename-before-directory-fsync window of a concurrent
            // marker publisher before allowing its journal authority to leave
            // the retained tail.
            try file.sync();
            try syncParentDirectory(path);
            return;
        },
        .indeterminate_lineage => try writeRefreshQuarantineMarker(
            allocator,
            provider,
            account,
            .hard_lineage_invalidated,
            value.store_fingerprint,
            value.identity_fingerprint,
        ),
    }
}

pub fn refreshQuarantineForRoute(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) !?RefreshQuarantineState {
    const path = try refreshQuarantinePath(allocator, provider, account);
    defer allocator.free(path);
    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close();
    const bytes = try file.readToEndAlloc(allocator, 4 * 1024);
    defer allocator.free(bytes);
    return try parseRefreshQuarantineBytes(
        allocator,
        bytes,
        provider,
        account,
    );
}

/// Resolve both sticky authorities. Markers carry private indeterminate state;
/// the append-only journal remains an independent hard-invalid-grant authority
/// if hard-marker persistence failed after proof.
pub fn effectiveRefreshQuarantineForRoute(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) !?RefreshQuarantineState {
    const marker = try refreshQuarantineForRoute(allocator, provider, account);
    if (marker == .hard_lineage_invalidated) return .hard_lineage_invalidated;
    const outcome = try refreshOutcomeForRoute(allocator, provider, account);
    if (outcome == .hard_lineage_invalidated) {
        // Repair a missing or downgraded marker from the independently durable
        // hard journal. Failure still returns the hard gate; no read path may
        // turn proven invalid-grant lineage into a selectable route.
        writeRefreshQuarantineMarker(
            allocator,
            provider,
            account,
            .hard_lineage_invalidated,
            null,
            null,
        ) catch {};
        return .hard_lineage_invalidated;
    }
    return marker;
}

fn clearIndeterminateRefreshQuarantine(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) !void {
    if (!(try currentActorOwnsRepairLock(allocator, provider, account))) {
        return error.RepairLockRequired;
    }
    const state = (try refreshQuarantineForRoute(
        allocator,
        provider,
        account,
    )) orelse return error.RefreshQuarantineMissing;
    if (state != .indeterminate_lineage) {
        return error.HardRefreshQuarantineCannotBeCleared;
    }
    const path = try refreshQuarantinePath(allocator, provider, account);
    defer allocator.free(path);
    try std.fs.deleteFileAbsolute(path);
    try syncParentDirectory(path);
}

/// A successful provider-owned re-enrollment is an explicit lineage reset for
/// indeterminate submissions. Hard invalid-grant evidence remains sticky; its
/// append-only journal authority must never be erased by this recovery path.
pub fn resolveIndeterminateRefreshQuarantineAfterProviderReenroll(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) !bool {
    if (!(try currentActorOwnsRepairLock(allocator, provider, account))) {
        return error.RepairLockRequired;
    }
    if (try refreshOutcomeForRoute(allocator, provider, account) ==
        .hard_lineage_invalidated)
    {
        return error.HardRefreshQuarantineCannotBeCleared;
    }
    const state = (try refreshQuarantineForRoute(
        allocator,
        provider,
        account,
    )) orelse return false;
    if (state != .indeterminate_lineage) {
        return error.HardRefreshQuarantineCannotBeCleared;
    }
    try clearIndeterminateRefreshQuarantine(allocator, provider, account);
    return true;
}

fn refreshQuarantineForLineage(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
    store_fingerprint: []const u8,
    identity_fingerprint: ?[]const u8,
) !?RefreshQuarantineState {
    if (try effectiveRefreshQuarantineForRoute(
        allocator,
        provider,
        account,
    )) |state| {
        return state;
    }

    const dir_path = try refreshQuarantineDir(allocator);
    defer allocator.free(dir_path);
    var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer dir.close();

    var matched: ?RefreshQuarantineState = null;
    var iterator = dir.iterate();
    while (try iterator.next()) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".json")) continue;
        // A damaged marker may be the only durable evidence that an alias
        // submitted this canonical store's rotating token. Never skip it and
        // guess that the lineage is clear.
        const file = try dir.openFile(entry.name, .{});
        defer file.close();
        const bytes = try file.readToEndAlloc(allocator, 4 * 1024);
        defer allocator.free(bytes);
        const parsed = try std.json.parseFromSlice(
            PersistedRefreshQuarantine,
            allocator,
            bytes,
            .{ .ignore_unknown_fields = false, .allocate = .alloc_always },
        );
        defer parsed.deinit();
        const value = parsed.value;
        const state = try refreshQuarantineState(value);
        if (!std.mem.eql(u8, value.provider, provider)) continue;
        const store_matches = if (value.store_fingerprint) |fingerprint|
            std.mem.eql(u8, fingerprint, store_fingerprint)
        else
            false;
        const identity_matches = if (identity_fingerprint) |identity|
            if (value.identity_fingerprint) |fingerprint|
                std.mem.eql(u8, fingerprint, identity)
            else
                false
        else
            false;
        if (!store_matches and !identity_matches) continue;
        if (state == .hard_lineage_invalidated) return state;
        matched = state;
    }
    return matched;
}

fn summarizeRefreshQuarantines(
    allocator: std.mem.Allocator,
    summary: *RefreshJournalSummary,
    hard_routes: *HardRefreshRouteSet,
) !void {
    const dir_path = try refreshQuarantineDir(allocator);
    defer allocator.free(dir_path);
    var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer dir.close();

    var iterator = dir.iterate();
    while (try iterator.next()) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".json")) continue;
        const file = dir.openFile(entry.name, .{}) catch {
            summary.valid = false;
            summary.invalid_events += 1;
            continue;
        };
        defer file.close();
        const bytes = file.readToEndAlloc(allocator, 4 * 1024) catch {
            summary.valid = false;
            summary.invalid_events += 1;
            continue;
        };
        defer allocator.free(bytes);
        const parsed = std.json.parseFromSlice(
            PersistedRefreshQuarantine,
            allocator,
            bytes,
            .{ .ignore_unknown_fields = false, .allocate = .alloc_always },
        ) catch {
            summary.valid = false;
            summary.invalid_events += 1;
            continue;
        };
        defer parsed.deinit();
        const state = refreshQuarantineState(parsed.value) catch {
            summary.valid = false;
            summary.invalid_events += 1;
            continue;
        };
        switch (state) {
            .hard_lineage_invalidated => try hard_routes.add(
                parsed.value.provider,
                parsed.value.account,
            ),
            .indeterminate_lineage => summary.indeterminate_lineage_markers += 1,
        }
    }
}

/// Summarize only typed refresh rows. Legacy token-refresh rows, including the
/// canonical Claude keychain refusal, remain readable but make no typed claim.
/// Unknown or malformed new rows invalidate the summary rather than being
/// guessed into a known outcome.
pub fn refreshJournalSummary(allocator: std.mem.Allocator) !RefreshJournalSummary {
    const path = try eventsPath(allocator);
    defer allocator.free(path);

    var summary = RefreshJournalSummary{};
    var hard_routes = HardRefreshRouteSet.init(allocator);
    defer hard_routes.deinit();

    const file = std.fs.openFileAbsolute(path, .{}) catch |e| switch (e) {
        error.FileNotFound => {
            try summarizeRefreshQuarantines(allocator, &summary, &hard_routes);
            summary.hard_lineage_events = hard_routes.count();
            return summary;
        },
        else => return e,
    };
    defer file.close();

    const bytes = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(bytes);

    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        const parsed = std.json.parseFromSlice(PersistedRefreshEvent, allocator, line, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            if (lineLooksLikeTypedRefreshEvent(line)) {
                summary.valid = false;
                summary.invalid_events += 1;
            }
            continue;
        };
        defer parsed.deinit();

        const row = typedRefreshRow(parsed.value) catch {
            summary.valid = false;
            summary.invalid_events += 1;
            continue;
        } orelse continue;
        const outcome = types.RefreshOutcome.parse(row.raw_outcome) catch {
            summary.valid = false;
            summary.invalid_events += 1;
            continue;
        };
        summary.typed_events += 1;
        summary.latest_outcome = outcome;
        if (outcome == .hard_lineage_invalidated) {
            try hard_routes.add(row.provider, row.account);
        }
    }
    try summarizeRefreshQuarantines(allocator, &summary, &hard_routes);
    summary.hard_lineage_events = hard_routes.count();
    return summary;
}

/// Reduce account-wide refresh state. Hard-lineage invalidation is sticky:
/// later automatic refresh rows cannot clear quarantine. A future
/// provider-owned re-enrollment flow must add its own explicit resolving event;
/// stale rotating-token restoration is never interpreted as recovery here.
pub fn refreshOutcomeForRoute(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) !?types.RefreshOutcome {
    if (try refreshQuarantineForRoute(allocator, provider, account)) |state| {
        if (state == .hard_lineage_invalidated) {
            return .hard_lineage_invalidated;
        }
    }

    const path = try eventsPath(allocator);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer file.close();

    const bytes = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(bytes);

    var latest: ?types.RefreshOutcome = null;
    var quarantined = false;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        const parsed = std.json.parseFromSlice(PersistedRefreshEvent, allocator, line, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            if (lineLooksLikeTypedRefreshEvent(line)) return error.InvalidRefreshJournal;
            continue;
        };
        defer parsed.deinit();

        const row = (try typedRefreshRow(parsed.value)) orelse continue;
        if (!std.mem.eql(u8, row.provider, provider) or
            !std.mem.eql(u8, row.account, account))
        {
            continue;
        }

        const outcome = try types.RefreshOutcome.parse(row.raw_outcome);
        if (outcome == .hard_lineage_invalidated) quarantined = true;
        if (!quarantined) latest = outcome;
    }
    return if (quarantined) .hard_lineage_invalidated else latest;
}

/// If `file` exceeds `soft_cap`, rewrite it in place keeping only the last
/// ~`retain_tail` bytes, trimmed forward to the next line boundary so no JSONL
/// record is split. Operates on the already-exclusively-locked handle. Pure of
/// global state so it is unit-testable with small caps.
fn rotateEventsTailInPlace(
    allocator: std.mem.Allocator,
    file: std.fs.File,
    soft_cap: u64,
    retain_tail: usize,
) !void {
    const size = try file.getEndPos();
    if (size <= soft_cap) return;

    try file.seekTo(0);
    const all = try file.readToEndAlloc(allocator, size + 1);
    defer allocator.free(all);

    var start: usize = if (all.len > retain_tail) all.len - retain_tail else 0;
    if (start > 0) {
        // Advance to just after the next newline so the kept tail starts on a
        // record boundary; if none remains, keep nothing rather than a torn line.
        start = if (std.mem.indexOfScalarPos(u8, all, start, '\n')) |nl| nl + 1 else all.len;
    }

    try file.seekTo(0);
    try file.setEndPos(0);
    try file.writeAll(all[start..]);
}

fn rotateRepairEventsTailInPlace(
    allocator: std.mem.Allocator,
    file: std.fs.File,
    path: []const u8,
    soft_cap: u64,
    retain_tail: usize,
) !void {
    const size = try file.getEndPos();
    if (size <= soft_cap) return;

    try file.seekTo(0);
    const all = try file.readToEndAlloc(allocator, size + 1);
    defer allocator.free(all);
    var hard_routes = try collectHardRefreshRoutesFromJournalBytes(
        allocator,
        all,
    );
    defer hard_routes.deinit();

    var routes = hard_routes.routes.keyIterator();
    while (routes.next()) |route| {
        try ensureHardMarkerForJournalRoute(
            allocator,
            route.provider,
            route.account,
        );
    }

    // No journal byte may be discarded until both the journal prefix and its
    // replacement hard-marker authorities are durable.
    try file.sync();
    try syncParentDirectory(path);
    try rotateEventsTailInPlace(allocator, file, soft_cap, retain_tail);
    try file.sync();
}

test "rotateEventsTailInPlace bounds the file to the recent tail on a record boundary" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try tmp.dir.createFile("ev.jsonl", .{ .read = true, .truncate = true });
    defer f.close();
    var i: usize = 0;
    while (i < 100) : (i += 1) try f.writer().print("rec{d:0>4}\n", .{i}); // 800 bytes total

    try rotateEventsTailInPlace(std.testing.allocator, f, 200, 100);

    try f.seekTo(0);
    const out = try f.readToEndAlloc(std.testing.allocator, 1 << 20);
    defer std.testing.allocator.free(out);
    try std.testing.expect(out.len <= 100); // bounded to the retain tail
    try std.testing.expect(out.len > 0 and out[0] == 'r'); // starts on a record boundary
    try std.testing.expect(out[out.len - 1] == '\n'); // ends clean, no torn line
    try std.testing.expect(std.mem.indexOf(u8, out, "rec0099") != null); // most recent kept
    try std.testing.expect(std.mem.indexOf(u8, out, "rec0000") == null); // oldest dropped
}

test "rotateEventsTailInPlace is a no-op below the cap" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try tmp.dir.createFile("ev2.jsonl", .{ .read = true, .truncate = true });
    defer f.close();
    try f.writeAll("a\nb\nc\n");
    try rotateEventsTailInPlace(std.testing.allocator, f, 1024, 512);
    try f.seekTo(0);
    const out = try f.readToEndAlloc(std.testing.allocator, 1024);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("a\nb\nc\n", out);
}

test "repair event rotation materializes hard markers before truncation" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    const store_fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const identity_fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    try writeRefreshQuarantineMarker(
        a,
        "toy",
        "upgrade",
        .indeterminate_lineage,
        store_fingerprint,
        identity_fingerprint,
    );

    const path = try eventsPath(a);
    defer a.free(path);
    try ensureParentDir(path);
    const file = try std.fs.createFileAbsolute(path, .{
        .read = true,
        .truncate = true,
        .mode = 0o600,
    });
    defer file.close();
    const hard_missing =
        "{\"kind\":\"token_refresh\",\"provider\":\"toy\",\"account\":\"missing\",\"refresh_outcome\":\"hard_lineage_invalidated\",\"outcome\":\"hard_lineage_invalidated\",\"ok\":false,\"executed\":true,\"mutating\":true}\n";
    const hard_upgrade =
        "{\"kind\":\"token_refresh\",\"provider\":\"toy\",\"account\":\"upgrade\",\"refresh_outcome\":\"hard_lineage_invalidated\",\"outcome\":\"hard_lineage_invalidated\",\"ok\":false,\"executed\":true,\"mutating\":true}\n";
    try file.writeAll(hard_missing);
    try file.writeAll(hard_upgrade);
    try file.writeAll(hard_missing); // duplicate route must remain one marker.

    try rotateRepairEventsTailInPlace(a, file, path, 1, 1);

    try std.testing.expectEqual(
        RefreshQuarantineState.hard_lineage_invalidated,
        (try refreshQuarantineForRoute(a, "toy", "missing")).?,
    );
    try std.testing.expectEqual(
        RefreshQuarantineState.hard_lineage_invalidated,
        (try refreshQuarantineForRoute(a, "toy", "upgrade")).?,
    );
    const upgraded_path = try refreshQuarantinePath(a, "toy", "upgrade");
    defer a.free(upgraded_path);
    const upgraded = try std.fs.openFileAbsolute(upgraded_path, .{});
    defer upgraded.close();
    const upgraded_bytes = try upgraded.readToEndAlloc(a, 4 * 1024);
    defer a.free(upgraded_bytes);
    try std.testing.expect(
        std.mem.indexOf(u8, upgraded_bytes, store_fingerprint) != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, upgraded_bytes, identity_fingerprint) != null,
    );
}

test "repair event rotation leaves journal byte-identical when marker repair fails" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    const marker_path = try refreshQuarantinePath(a, "toy", "blocked");
    defer a.free(marker_path);
    try ensureParentDir(marker_path);
    {
        const marker = try std.fs.createFileAbsolute(marker_path, .{
            .truncate = true,
            .mode = 0o600,
        });
        defer marker.close();
        try marker.writeAll("{\"torn\":");
    }

    const path = try eventsPath(a);
    defer a.free(path);
    try ensureParentDir(path);
    const row =
        "{\"kind\":\"token_refresh\",\"provider\":\"toy\",\"account\":\"blocked\",\"refresh_outcome\":\"hard_lineage_invalidated\",\"outcome\":\"hard_lineage_invalidated\",\"ok\":false,\"executed\":true,\"mutating\":true}\n";
    const file = try std.fs.createFileAbsolute(path, .{
        .read = true,
        .truncate = true,
        .mode = 0o600,
    });
    defer file.close();
    try file.writeAll(row);
    const before = try a.dupe(u8, row);
    defer a.free(before);

    try std.testing.expectError(
        error.UnknownField,
        rotateRepairEventsTailInPlace(a, file, path, 1, 1),
    );
    try file.seekTo(0);
    const after = try file.readToEndAlloc(a, 4 * 1024);
    defer a.free(after);
    try std.testing.expectEqualStrings(before, after);
}

test "repair event rotation refuses malformed typed rows without truncation" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    const path = try eventsPath(a);
    defer a.free(path);
    try ensureParentDir(path);
    const row =
        "{\"kind\":\"token_refresh\",\"provider\":\"toy\",\"account\":\"broken\",\"refresh_outcome\":\"future_tag\",\"outcome\":\"future_tag\",\"ok\":false,\"executed\":false,\"mutating\":false}\n";
    const file = try std.fs.createFileAbsolute(path, .{
        .read = true,
        .truncate = true,
        .mode = 0o600,
    });
    defer file.close();
    try file.writeAll(row);

    try std.testing.expectError(
        error.InvalidRefreshJournal,
        rotateRepairEventsTailInPlace(a, file, path, 1, 1),
    );
    try file.seekTo(0);
    const after = try file.readToEndAlloc(a, 4 * 1024);
    defer a.free(after);
    try std.testing.expectEqualStrings(row, after);
}

test "soft append refuses growth when malformed state blocks preflight rotation" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    const path = try eventsPath(a);
    defer a.free(path);
    try ensureParentDir(path);
    const malformed =
        "{\"kind\":\"token_refresh\",\"provider\":\"toy\",\"account\":\"broken\",\"refresh_outcome\":\"future_tag\",\"outcome\":\"future_tag\",\"ok\":false,\"executed\":false,\"mutating\":false}\n";
    {
        const file = try std.fs.createFileAbsolute(path, .{
            .truncate = true,
            .mode = 0o600,
        });
        defer file.close();
        try file.writeAll(malformed);
    }

    try std.testing.expectError(
        error.InvalidRefreshJournal,
        appendEventAuthorizedWithCaps(
            a,
            refreshEvent(.{
                .provider = "toy",
                .account = "healthy",
                .outcome = .transient_network,
            }),
            false,
            1,
            1,
        ),
    );
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const after = try file.readToEndAlloc(a, 4 * 1024);
    defer a.free(after);
    try std.testing.expectEqualStrings(malformed, after);
}

test "hard append remains the final durable mutation when maintenance is blocked" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    const path = try eventsPath(a);
    defer a.free(path);
    try ensureParentDir(path);
    const malformed =
        "{\"kind\":\"token_refresh\",\"provider\":\"toy\",\"account\":\"broken\",\"refresh_outcome\":\"future_tag\",\"outcome\":\"future_tag\",\"ok\":false,\"executed\":false,\"mutating\":false}\n";
    {
        const file = try std.fs.createFileAbsolute(path, .{
            .truncate = true,
            .mode = 0o600,
        });
        defer file.close();
        try file.writeAll(malformed);
    }
    try writeRefreshQuarantineMarker(
        a,
        "toy",
        "hard",
        .hard_lineage_invalidated,
        null,
        null,
    );

    try appendEventAuthorizedWithCaps(
        a,
        refreshEvent(.{
            .provider = "toy",
            .account = "hard",
            .outcome = .hard_lineage_invalidated,
            .executed = true,
            .mutating = true,
        }),
        true,
        1,
        1,
    );
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const after = try file.readToEndAlloc(a, 8 * 1024);
    defer a.free(after);
    try std.testing.expect(std.mem.startsWith(u8, after, malformed));
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            after,
            "\"refresh_outcome\":\"hard_lineage_invalidated\"",
        ) != null,
    );
}

test "repair event append rejects rows larger than the reader headroom" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    const oversized = try a.alloc(u8, events_max_row_bytes);
    defer a.free(oversized);
    @memset(oversized, 'x');

    try std.testing.expectError(
        error.RepairEventTooLarge,
        appendEvent(a, .{
            .outcome = oversized,
        }),
    );

    const path = try eventsPath(a);
    defer a.free(path);
    try std.testing.expectError(
        error.FileNotFound,
        std.fs.openFileAbsolute(path, .{}),
    );
}

pub fn writeEvents(allocator: std.mem.Allocator, writer: anytype, json: bool, limit: usize) !void {
    try writeEventView(allocator, writer, json, limit, "events", null, "no repair events recorded");
}

pub fn writeHandoffs(allocator: std.mem.Allocator, writer: anytype, json: bool, limit: usize, all: bool) !void {
    if (all) {
        try writeEventView(allocator, writer, json, limit, "handoffs", "daemon_handoff", "no daemon handoffs recorded");
        return;
    }
    try writePendingHandoffView(allocator, writer, json, limit);
}

pub fn writeDaemonSnapshot(allocator: std.mem.Allocator, bytes: []const u8) !void {
    const path = try daemonSnapshotPath(allocator);
    defer allocator.free(path);
    try ensureParentDir(path);

    const file = try std.fs.createFileAbsolute(path, .{
        .truncate = true,
        .mode = 0o600,
    });
    defer file.close();
    try file.writeAll(bytes);
    if (bytes.len == 0 or bytes[bytes.len - 1] != '\n') try file.writeAll("\n");
}

pub fn readDaemonSnapshotAlloc(allocator: std.mem.Allocator) !?[]const u8 {
    const path = try daemonSnapshotPath(allocator);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer file.close();
    return try file.readToEndAlloc(allocator, 64 * 1024);
}

pub fn hasPendingHandoff(allocator: std.mem.Allocator, key: HandoffKey) !bool {
    return (try pendingHandoffProgress(allocator, key)) != null;
}

pub fn pendingHandoffProgress(allocator: std.mem.Allocator, key: HandoffKey) !?types.RuntimeReadiness.RepairProgress {
    const path = try eventsPath(allocator);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer file.close();

    const bytes = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(bytes);

    var pending_started_at: ?i64 = null;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or !eventRouteKeyMatchesHandoffKey(trimmed, key)) continue;
        if (isQueuedHandoffEvent(trimmed)) {
            pending_started_at = eventFieldInt(trimmed, "ts") orelse 0;
        } else if (eventResolvesHandoff(trimmed)) {
            pending_started_at = null;
        }
    }

    if (pending_started_at) |started_at| {
        return .{
            .account = key.account,
            .started_at = started_at,
        };
    }
    return null;
}

fn writeEventView(
    allocator: std.mem.Allocator,
    writer: anytype,
    json: bool,
    limit: usize,
    root_key: []const u8,
    filter_kind: ?[]const u8,
    empty_text: []const u8,
) !void {
    const path = try eventsPath(allocator);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |e| switch (e) {
        error.FileNotFound => {
            if (json) {
                try writeEmptyJsonView(writer, root_key);
            } else {
                try writer.print("{s}\n", .{empty_text});
            }
            return;
        },
        else => return e,
    };
    defer file.close();

    const bytes = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(bytes);

    var lines = std.ArrayList([]const u8).init(allocator);
    defer lines.deinit();
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len != 0 and eventLineMatchesKind(trimmed, filter_kind)) try lines.append(trimmed);
    }

    if (lines.items.len == 0 and !json) {
        try writer.print("{s}\n", .{empty_text});
        return;
    }

    const start = if (limit != 0 and lines.items.len > limit) lines.items.len - limit else 0;

    if (!json) {
        try writeTextLines(writer, lines.items[start..]);
        return;
    }

    try writer.print("{{\"{s}\":[", .{root_key});
    for (lines.items[start..], 0..) |line, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll(line);
    }
    try writer.writeAll("]}\n");
}

fn writeEmptyJsonView(writer: anytype, root_key: []const u8) !void {
    try writer.print("{{\"{s}\":[]}}\n", .{root_key});
}

fn writePendingHandoffView(
    allocator: std.mem.Allocator,
    writer: anytype,
    json: bool,
    limit: usize,
) !void {
    const path = try eventsPath(allocator);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |e| switch (e) {
        error.FileNotFound => {
            if (json) {
                try writeEmptyJsonView(writer, "handoffs");
            } else {
                try writer.writeAll("no pending daemon handoffs recorded\n");
            }
            return;
        },
        else => return e,
    };
    defer file.close();

    const bytes = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(bytes);

    var pending = std.ArrayList([]const u8).init(allocator);
    defer pending.deinit();
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        if (isQueuedHandoffEvent(trimmed)) {
            try upsertPendingHandoff(&pending, trimmed);
        } else {
            removeResolvedHandoffs(&pending, trimmed);
        }
    }

    if (pending.items.len == 0 and !json) {
        try writer.writeAll("no pending daemon handoffs recorded\n");
        return;
    }

    const start = if (limit != 0 and pending.items.len > limit) pending.items.len - limit else 0;
    if (!json) {
        try writeTextLines(writer, pending.items[start..]);
        return;
    }

    try writer.writeAll("{\"handoffs\":[");
    for (pending.items[start..], 0..) |line, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll(line);
    }
    try writer.writeAll("]}\n");
}

fn eventLineMatchesKind(line: []const u8, filter_kind: ?[]const u8) bool {
    const kind = filter_kind orelse return true;
    const marker = "\"kind\":\"";
    const pos = std.mem.indexOf(u8, line, marker) orelse return false;
    const value_start = pos + marker.len;
    const value_end_delta = std.mem.indexOfScalar(u8, line[value_start..], '"') orelse return false;
    return std.mem.eql(u8, line[value_start .. value_start + value_end_delta], kind);
}

fn isQueuedHandoffEvent(line: []const u8) bool {
    return eventLineMatchesKind(line, "daemon_handoff") and eventFieldEquals(line, "outcome", "handoff_queued");
}

fn upsertPendingHandoff(pending: *std.ArrayList([]const u8), line: []const u8) !void {
    var idx: usize = 0;
    while (idx < pending.items.len) {
        if (eventRouteKeyMatches(pending.items[idx], line)) {
            _ = pending.orderedRemove(idx);
            continue;
        }
        idx += 1;
    }
    try pending.append(line);
}

fn removeResolvedHandoffs(pending: *std.ArrayList([]const u8), event_line: []const u8) void {
    if (!eventResolvesHandoff(event_line)) return;
    var idx: usize = 0;
    while (idx < pending.items.len) {
        if (eventRouteKeyMatches(pending.items[idx], event_line)) {
            _ = pending.orderedRemove(idx);
            continue;
        }
        idx += 1;
    }
}

fn eventResolvesHandoff(line: []const u8) bool {
    if (eventFieldEquals(line, "outcome", "route_selectable")) return true;
    if (eventFieldEquals(line, "outcome", "handoff_resolved")) return true;
    if (eventFieldBool(line, "ok") == true and eventFieldEquals(line, "outcome", "executed")) return true;
    if (eventFieldBool(line, "ok") == true and eventFieldEquals(line, "outcome", "noop")) return true;
    return false;
}

fn eventRouteKeyMatches(a: []const u8, b: []const u8) bool {
    return eventOptionalFieldEquals(a, b, "profile") and
        eventOptionalFieldEquals(a, b, "provider") and
        eventOptionalFieldEquals(a, b, "account") and
        eventOptionalFieldEquals(a, b, "capability");
}

fn eventRouteKeyMatchesHandoffKey(line: []const u8, key: HandoffKey) bool {
    return eventOptionalFieldMatches(line, "profile", key.profile) and
        eventFieldEquals(line, "provider", key.provider) and
        eventFieldEquals(line, "account", key.account) and
        eventOptionalFieldMatches(line, "capability", key.capability);
}

fn eventOptionalFieldEquals(a: []const u8, b: []const u8, field: []const u8) bool {
    const av = eventFieldString(a, field);
    const bv = eventFieldString(b, field);
    if (av == null and bv == null) return true;
    if (av == null or bv == null) return false;
    return std.mem.eql(u8, av.?, bv.?);
}

fn eventOptionalFieldMatches(line: []const u8, field: []const u8, expected: ?[]const u8) bool {
    const actual = eventFieldString(line, field);
    if (actual == null and expected == null) return true;
    if (actual == null or expected == null) return false;
    return std.mem.eql(u8, actual.?, expected.?);
}

fn eventFieldEquals(line: []const u8, field: []const u8, expected: []const u8) bool {
    const value = eventFieldString(line, field) orelse return false;
    return std.mem.eql(u8, value, expected);
}

fn eventFieldBool(line: []const u8, field: []const u8) ?bool {
    const start = eventFieldValueStart(line, field) orelse return null;
    if (std.mem.startsWith(u8, line[start..], "true")) return true;
    if (std.mem.startsWith(u8, line[start..], "false")) return false;
    return null;
}

fn eventFieldInt(line: []const u8, field: []const u8) ?i64 {
    var idx = eventFieldValueStart(line, field) orelse return null;
    while (idx < line.len and line[idx] == ' ') : (idx += 1) {}
    const start = idx;
    if (idx < line.len and line[idx] == '-') idx += 1;
    while (idx < line.len and std.ascii.isDigit(line[idx])) : (idx += 1) {}
    if (idx == start or (idx == start + 1 and line[start] == '-')) return null;
    return std.fmt.parseInt(i64, line[start..idx], 10) catch null;
}

fn eventFieldString(line: []const u8, field: []const u8) ?[]const u8 {
    var idx = eventFieldValueStart(line, field) orelse return null;
    if (std.mem.startsWith(u8, line[idx..], "null")) return null;
    if (idx >= line.len or line[idx] != '"') return null;
    idx += 1;
    const start = idx;
    while (idx < line.len) : (idx += 1) {
        if (line[idx] == '\\') {
            idx += 1;
            continue;
        }
        if (line[idx] == '"') return line[start..idx];
    }
    return null;
}

fn eventFieldValueStart(line: []const u8, field: []const u8) ?usize {
    var search_start: usize = 0;
    while (search_start < line.len) {
        const quote_delta = std.mem.indexOfScalar(u8, line[search_start..], '"') orelse return null;
        const key_start = search_start + quote_delta + 1;
        if (key_start + field.len + 2 <= line.len and
            std.mem.eql(u8, line[key_start .. key_start + field.len], field) and
            line[key_start + field.len] == '"' and
            line[key_start + field.len + 1] == ':')
        {
            return key_start + field.len + 2;
        }
        search_start = key_start;
    }
    return null;
}

/// Tuning + sink for a BLOCKING acquire's wait announcements (TIN-2049). The
/// blocking acquire is otherwise identical; this only controls how a cross-
/// process wait is surfaced and bounded. `log` = null routes wait lines to
/// stderr (a daemon's stderr is its log, so daemon/non-interactive use stays
/// safe by construction).
pub const BlockingWaitConfig = struct {
    log: ?std.fs.File = null,
    opts: lock_wait.WaitOptions = .{},
};

pub fn acquireRepairLock(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) !RepairLock {
    return acquireRepairLockWithMode(allocator, provider, account, true, null);
}

pub fn acquireRepairLockBlocking(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) !RepairLock {
    // null cfg → BlockingWaitConfig{} defaults (stderr, 120s bound): every
    // blocking acquire announces + bounds its cross-process wait; a genuinely
    // long-held lock fails with error.LockWaitTimeout rather than hanging.
    return acquireRepairLockWithMode(allocator, provider, account, false, null);
}

/// Blocking acquire with caller-tuned wait announcements (TIN-2049) — same lock,
/// same semantics, explicit sink/timeout. Operator-facing sites use this to
/// route wait lines and, on timeout, name the lock in their structured output.
pub fn acquireRepairLockBlockingAnnounced(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
    cfg: BlockingWaitConfig,
) !RepairLock {
    return acquireRepairLockWithMode(allocator, provider, account, false, cfg);
}

/// Verify that the current logical actor owns the exact per-account flock.
/// This is intentionally a query, not a proof token: callers cannot construct
/// ownership, and releasing the flock immediately makes the predicate false.
pub fn currentActorOwnsRepairLock(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) !bool {
    const key = try sanitizedLockFileName(allocator, provider, account);
    defer allocator.free(key);
    const actor = currentActor();

    held_mutex.lock();
    defer held_mutex.unlock();
    const entry = held_locks.get(key) orelse return false;
    return !entry.acquiring and entry.count != 0 and entry.owner_actor == actor;
}

const RealRepairLock = struct { file: std.fs.File, path: []const u8 };

/// Best-effort holder description for a wait line, derived from the lock file's
/// own `started_at` metadata (the convention stores no pid; do NOT platform-dig
/// for one). Returns null when the file is empty/mid-write or unreadable.
fn holderHint(file: std.fs.File, buf: []u8) ?[]const u8 {
    file.seekTo(0) catch return null;
    var raw: [256]u8 = undefined;
    const n = file.read(&raw) catch return null;
    const started = parseStartedAt(raw[0..n]) orelse return null;
    return std.fmt.bufPrint(buf, "another process since epoch {d}", .{started}) catch null;
}

fn acquireRealRepairLock(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
    nonblocking: bool,
    wait_cfg: ?BlockingWaitConfig,
) !RealRepairLock {
    const path = try lockPath(allocator, provider, account);
    errdefer allocator.free(path);
    try ensureParentDir(path);

    // Open WITHOUT taking the lock at open time so the blocking path can poll a
    // non-blocking flock and announce (TIN-2049); the persisted inode is reused
    // (truncate=false), preserving TIN-2041 handoff semantics.
    const file = try std.fs.createFileAbsolute(path, .{
        .truncate = false,
        .read = true,
        .mode = 0o600,
    });
    errdefer file.close();

    if (nonblocking) {
        if (!(try lock_wait.tryLockFile(file))) return error.RepairInProgress;
    } else if (try lock_wait.tryLockFile(file)) {
        // Uncontended blocking acquire: fast path, no holder lookup, no output.
    } else {
        const cfg = wait_cfg orelse BlockingWaitConfig{};
        var hint_buf: [96]u8 = undefined;
        const hint = holderHint(file, &hint_buf);
        const sink = cfg.log orelse std.io.getStdErr();
        try lock_wait.waitForLock(file, path, sink.writer(), hint, cfg.opts);
    }

    const now = std.time.timestamp();
    try file.setEndPos(0);
    try file.seekTo(0);
    const writer = file.writer();
    try writer.writeAll("{\"provider\":");
    try std.json.stringify(provider, .{}, writer);
    try writer.writeAll(",\"account\":");
    try std.json.stringify(account, .{}, writer);
    try writer.print(",\"started_at\":{d}}}\n", .{now});

    return .{ .file = file, .path = path };
}

fn acquireRepairLockWithMode(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
    nonblocking: bool,
    wait_cfg: ?BlockingWaitConfig,
) !RepairLock {
    const key = try sanitizedLockFileName(allocator, provider, account);
    errdefer allocator.free(key);
    const self_actor = currentActor();

    held_mutex.lock();
    while (true) {
        if (held_locks.getPtr(key)) |entry| {
            if (entry.acquiring) {
                if (nonblocking) {
                    // A sibling thread is mid-flock for this key. Waiting
                    // would silently turn the caller's typed
                    // refuse-on-held contract into an unbounded block
                    // behind the sibling's (possibly blocking) acquire.
                    held_mutex.unlock();
                    return error.RepairInProgress;
                }
                // Blocking caller: wait for the sibling's flock to resolve.
                held_cond.wait(&held_mutex);
                continue;
            }
            if (entry.owner_actor == self_actor) {
                // Same logical actor: genuine nesting (a single actor is
                // sequential and cannot race itself). Refcount, no new flock.
                entry.count += 1;
                held_mutex.unlock();
                return .{ .allocator = allocator, .key = key };
            }
            if (nonblocking) {
                // TIN-2059: a DIFFERENT in-process actor holds this key.
                // The old unconditional `entry.count += 1` join here is what
                // let a warm tick race a live session/materializer inside one
                // process. Refuse typed instead — identical contract to the
                // cross-process flock's WouldBlock arm.
                held_mutex.unlock();
                return error.RepairInProgress;
            }
            if (entry.owner_blocking) {
                // Cooperative hierarchical join (TIN-1851): a blocking
                // acquirer joining a blocking hold is the proxy materializer
                // refreshing on behalf of the live session that owns this
                // key. Adopt the owner's actor for the duration of the hold
                // so nested acquires (the identity lock) match the session.
                entry.count += 1;
                const prev = adopted_actor;
                adopted_actor = entry.owner_actor;
                held_mutex.unlock();
                return .{ .allocator = allocator, .key = key, .adopted = true, .prev_actor = prev };
            }
            // Blocking acquirer vs a short-hold typed writer (warm tick,
            // probe, CLI repair): serialize BEHIND it — wait for the full
            // release, then take the real flock and revalidate under it.
            held_cond.wait(&held_mutex);
            continue;
        }
        break;
    }
    // Reserve the key as 'acquiring', then take the (possibly blocking) real
    // flock OUTSIDE the mutex so other threads/keys are not stalled.
    const reg_key = held_gpa.dupe(u8, key) catch {
        held_mutex.unlock();
        return error.OutOfMemory;
    };
    held_locks.put(held_gpa, reg_key, .{
        .count = 1,
        .acquiring = true,
        .owner_actor = self_actor,
        .owner_blocking = !nonblocking,
    }) catch {
        held_gpa.free(reg_key);
        held_mutex.unlock();
        return error.OutOfMemory;
    };
    held_mutex.unlock();

    const real = acquireRealRepairLock(allocator, provider, account, nonblocking, wait_cfg) catch |e| {
        held_mutex.lock();
        if (held_locks.fetchRemove(key)) |kv| held_gpa.free(kv.key);
        held_cond.broadcast();
        held_mutex.unlock();
        return e;
    };

    allocator.free(real.path);

    held_mutex.lock();
    if (held_locks.getPtr(key)) |entry| {
        entry.file = real.file;
        entry.acquiring = false;
    } else {
        // Should not happen (we own the 'acquiring' reservation), but stay safe.
        // Close only — the lock file itself persists (see release()).
        real.file.close();
    }
    held_cond.broadcast();
    held_mutex.unlock();

    return .{ .allocator = allocator, .key = key };
}

pub fn probeRepairLock(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) !?types.RuntimeReadiness.RepairProgress {
    const path = try lockPath(allocator, provider, account);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{
        .mode = .read_write,
        .lock = .exclusive,
        .lock_nonblocking = true,
    }) catch |e| switch (e) {
        error.FileNotFound => return null,
        error.WouldBlock => return try readRepairProgress(allocator, path, account),
        else => return e,
    };
    file.close();
    return null;
}

fn eventsPath(allocator: std.mem.Allocator) ![]const u8 {
    const dir = try paths.stateDir(allocator);
    defer allocator.free(dir);
    return std.fs.path.join(allocator, &.{ dir, "repair-events.jsonl" });
}

fn daemonSnapshotPath(allocator: std.mem.Allocator) ![]const u8 {
    const dir = try paths.stateDir(allocator);
    defer allocator.free(dir);
    return std.fs.path.join(allocator, &.{ dir, "daemon-snapshot.json" });
}

fn locksDir(allocator: std.mem.Allocator) ![]const u8 {
    const dir = try paths.runtimeDir(allocator);
    defer allocator.free(dir);
    return std.fs.path.join(allocator, &.{ dir, "repair-locks" });
}

// TIN-1806: reauth jobs serialize against the same per-account flock domain as
// refresh/session/repair. Exporting this as "reauth" metadata gives child
// processes and probes a stable place to coordinate without inventing a second
// lock namespace that would fail to protect the credential store.
pub fn reauthLocksDir(allocator: std.mem.Allocator) ![]const u8 {
    return locksDir(allocator);
}

pub fn reauthJobAlloc(allocator: std.mem.Allocator, provider: []const u8, account: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}:{s}", .{ provider, account });
}

pub fn lockPath(allocator: std.mem.Allocator, provider: []const u8, account: []const u8) ![]const u8 {
    const dir = try locksDir(allocator);
    defer allocator.free(dir);
    const file_name = try sanitizedLockFileName(allocator, provider, account);
    defer allocator.free(file_name);
    return std.fs.path.join(allocator, &.{ dir, file_name });
}

fn sanitizedLockFileName(allocator: std.mem.Allocator, provider: []const u8, account: []const u8) ![]const u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try appendLockNamePart(&out, provider);
    try out.append('-');
    try appendLockNamePart(&out, account);
    try out.appendSlice(".lock");
    return try out.toOwnedSlice();
}

fn appendLockNamePart(out: *std.ArrayList(u8), value: []const u8) !void {
    for (value) |c| {
        const safe = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.';
        try out.append(if (safe) c else '_');
    }
}

fn readRepairProgress(
    allocator: std.mem.Allocator,
    path: []const u8,
    fallback_account: []const u8,
) !types.RuntimeReadiness.RepairProgress {
    const file = std.fs.openFileAbsolute(path, .{}) catch return .{
        .account = fallback_account,
        .started_at = 0,
    };
    defer file.close();

    const bytes = file.readToEndAlloc(allocator, 16 * 1024) catch return .{
        .account = fallback_account,
        .started_at = 0,
    };
    defer allocator.free(bytes);

    return .{
        .account = fallback_account,
        .started_at = parseStartedAt(bytes) orelse 0,
    };
}

fn parseStartedAt(bytes: []const u8) ?i64 {
    const marker = "\"started_at\":";
    const start = std.mem.indexOf(u8, bytes, marker) orelse return null;
    var idx = start + marker.len;
    while (idx < bytes.len and bytes[idx] == ' ') : (idx += 1) {}
    const value_start = idx;
    while (idx < bytes.len and std.ascii.isDigit(bytes[idx])) : (idx += 1) {}
    if (idx == value_start) return null;
    return std.fmt.parseInt(i64, bytes[value_start..idx], 10) catch null;
}

fn ensureParentDir(path: []const u8) !void {
    if (std.fs.path.dirname(path)) |dir| {
        std.fs.cwd().makePath(dir) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return e,
        };
    }
}

fn validateRepairEvent(
    event: RepairEvent,
    hard_lineage_authorized: bool,
) !void {
    if (!std.mem.eql(u8, event.kind, "token_refresh")) {
        if (event.refresh_outcome != null) return error.InvalidRefreshEvent;
        return;
    }

    const refresh_outcome = event.refresh_outcome orelse {
        const provider = event.provider orelse return error.InvalidRefreshEvent;
        const account = event.account orelse return error.InvalidRefreshEvent;
        const action = event.action orelse return error.InvalidRefreshEvent;
        const reason = event.reason orelse return error.InvalidRefreshEvent;
        const writeback_capability = event.writeback_capability orelse
            return error.InvalidRefreshEvent;
        const automatic_refresh_admitted =
            event.automatic_refresh_admitted orelse return error.InvalidRefreshEvent;
        if (provider.len == 0 or
            account.len == 0 or
            writeback_capability.len == 0 or
            !std.mem.eql(u8, action, "refresh") or
            !std.mem.eql(u8, event.outcome, "not_admitted") or
            !std.mem.eql(
                u8,
                reason,
                "writeback_refused_canonical_keychain_item",
            ) or
            automatic_refresh_admitted or
            event.ok or
            event.executed or
            event.interactive or
            event.mutating)
        {
            return error.InvalidRefreshEvent;
        }
        return;
    };
    const provider = event.provider orelse return error.InvalidRefreshEvent;
    const account = event.account orelse return error.InvalidRefreshEvent;
    if (provider.len == 0 or account.len == 0 or
        !std.mem.eql(u8, event.outcome, @tagName(refresh_outcome)) or
        event.reason != null or
        event.ok != (refresh_outcome == .refreshed) or
        event.mutating != event.executed or
        (refresh_outcome == .hard_lineage_invalidated and !event.executed))
    {
        return error.InvalidRefreshEvent;
    }
    if (refresh_outcome == .hard_lineage_invalidated and
        !hard_lineage_authorized)
    {
        return error.HardRefreshRequiresLockedLineageProof;
    }
}

fn writeEventJson(writer: anytype, event: RepairEvent) !void {
    return writeEventJsonAuthorized(writer, event, false);
}

fn writeEventJsonAuthorized(
    writer: anytype,
    event: RepairEvent,
    hard_lineage_authorized: bool,
) !void {
    try validateRepairEvent(event, hard_lineage_authorized);
    const ts = if (event.ts == 0) std.time.timestamp() else event.ts;
    try writer.print("{{\"ts\":{d},\"kind\":", .{ts});
    try std.json.stringify(event.kind, .{}, writer);
    try writer.writeAll(",\"profile\":");
    if (event.profile) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"provider\":");
    if (event.provider) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"account\":");
    if (event.account) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (event.capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"action\":");
    if (event.action) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"command\":");
    if (event.command) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"engine_run_available\":");
    if (event.engine_run_available) |value| try writer.writeAll(if (value) "true" else "false") else try writer.writeAll("null");
    try writer.writeAll(",\"execution\":");
    if (event.execution) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"agent_safe\":");
    if (event.agent_safe) |value| try writer.writeAll(if (value) "true" else "false") else try writer.writeAll("null");
    try writer.writeAll(",\"spends_provider_calls\":");
    if (event.spends_provider_calls) |value| try writer.writeAll(if (value) "true" else "false") else try writer.writeAll("null");
    try writer.writeAll(",\"budget\":");
    if (event.budget) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"repair_owner\":");
    if (event.repair_owner) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"fresh_browser_context_required\":");
    if (event.fresh_browser_context_required) |value| try writer.writeAll(if (value) "true" else "false") else try writer.writeAll("null");
    try writer.writeAll(",\"browser_context\":");
    if (event.browser_context) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"writeback_capability\":");
    if (event.writeback_capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"automatic_refresh_admitted\":");
    if (event.automatic_refresh_admitted) |value| try writer.writeAll(if (value) "true" else "false") else try writer.writeAll("null");
    try writer.writeAll(",\"refresh_outcome\":");
    if (event.refresh_outcome) |value| try std.json.stringify(@tagName(value), .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"outcome\":");
    try std.json.stringify(event.outcome, .{}, writer);
    try writer.writeAll(",\"reason\":");
    if (event.reason) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"ok\":");
    try writer.writeAll(if (event.ok) "true" else "false");
    try writer.writeAll(",\"executed\":");
    try writer.writeAll(if (event.executed) "true" else "false");
    try writer.writeAll(",\"interactive\":");
    try writer.writeAll(if (event.interactive) "true" else "false");
    try writer.writeAll(",\"mutating\":");
    try writer.writeAll(if (event.mutating) "true" else "false");
    try writer.writeByte('}');
}

fn writeTextLines(writer: anytype, lines: []const []const u8) !void {
    for (lines) |line| {
        try writer.writeAll(line);
        try writer.writeByte('\n');
    }
}

/// Test helper: scope lock and repair-event files to one per-test directory so
/// unit tests never write into the user's real runtime/state directories.
/// Pub so other modules' refresh/probe tests can reuse the same isolation.
pub const TestRuntimeDirScope = struct {
    tmp: std.testing.TmpDir,
    root: []const u8,
    overrides: std.process.EnvMap,

    pub fn init(allocator: std.mem.Allocator) !TestRuntimeDirScope {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(allocator, ".");
        errdefer allocator.free(root);
        var overrides = std.process.EnvMap.init(allocator);
        errdefer overrides.deinit();
        try overrides.put("OMUX_RUNTIME_DIR", root);
        try overrides.put("OMUX_STATE_DIR", root);
        return .{ .tmp = tmp, .root = root, .overrides = overrides };
    }

    pub fn activate(self: *TestRuntimeDirScope) void {
        env.test_overrides = &self.overrides;
    }

    pub fn deinit(self: *TestRuntimeDirScope, allocator: std.mem.Allocator) void {
        env.test_overrides = null;
        self.overrides.deinit();
        allocator.free(self.root);
        self.tmp.cleanup();
    }
};

const TestInvalidGrantServerArgs = struct {
    server: std.net.Server,
    mutation_path: ?[]const u8 = null,
    mutation_bytes: ?[]const u8 = null,
    quarantine_dir_to_block: ?[]const u8 = null,
    journal_path_to_block: ?[]const u8 = null,
    response_status: std.http.Status = .bad_request,
    response_body: []const u8 = "{\"error\":\"invalid_grant\"}",
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

const TestInvalidGrantServer = struct {
    allocator: std.mem.Allocator,
    args: *TestInvalidGrantServerArgs,
    thread: std.Thread,
    port: u16,
    joined: bool = false,

    fn start(
        allocator: std.mem.Allocator,
        mutation_path: ?[]const u8,
        mutation_bytes: ?[]const u8,
    ) !TestInvalidGrantServer {
        return startWithQuarantineBlocker(
            allocator,
            mutation_path,
            mutation_bytes,
            null,
            null,
        );
    }

    fn startWithQuarantineBlocker(
        allocator: std.mem.Allocator,
        mutation_path: ?[]const u8,
        mutation_bytes: ?[]const u8,
        quarantine_dir_to_block: ?[]const u8,
        journal_path_to_block: ?[]const u8,
    ) !TestInvalidGrantServer {
        return startConfigured(
            allocator,
            mutation_path,
            mutation_bytes,
            quarantine_dir_to_block,
            journal_path_to_block,
            .bad_request,
            "{\"error\":\"invalid_grant\"}",
        );
    }

    fn startWithResponse(
        allocator: std.mem.Allocator,
        status: std.http.Status,
        body: []const u8,
    ) !TestInvalidGrantServer {
        return startConfigured(
            allocator,
            null,
            null,
            null,
            null,
            status,
            body,
        );
    }

    fn startConfigured(
        allocator: std.mem.Allocator,
        mutation_path: ?[]const u8,
        mutation_bytes: ?[]const u8,
        quarantine_dir_to_block: ?[]const u8,
        journal_path_to_block: ?[]const u8,
        response_status: std.http.Status,
        response_body: []const u8,
    ) !TestInvalidGrantServer {
        const address = try std.net.Address.parseIp("127.0.0.1", 0);
        var server = try address.listen(.{ .reuse_address = true });
        errdefer server.deinit();
        const args = try allocator.create(TestInvalidGrantServerArgs);
        errdefer allocator.destroy(args);
        args.* = .{
            .server = server,
            .mutation_path = mutation_path,
            .mutation_bytes = mutation_bytes,
            .quarantine_dir_to_block = quarantine_dir_to_block,
            .journal_path_to_block = journal_path_to_block,
            .response_status = response_status,
            .response_body = response_body,
        };
        const thread = try std.Thread.spawn(.{}, runTestInvalidGrantServer, .{args});
        return .{
            .allocator = allocator,
            .args = args,
            .thread = thread,
            .port = server.listen_address.getPort(),
        };
    }

    fn join(self: *TestInvalidGrantServer) bool {
        if (!self.joined) {
            self.thread.join();
            self.joined = true;
        }
        return self.args.failed.load(.seq_cst);
    }

    fn deinit(self: *TestInvalidGrantServer) void {
        _ = self.join();
        self.allocator.destroy(self.args);
    }
};

const TestStoreLockProbe = struct {
    const blocked: u8 = 1;
    const acquired: u8 = 2;
    const failed: u8 = 3;

    fn run(
        store_fingerprint: [64]u8,
        outcome: *std.atomic.Value(u8),
    ) void {
        var lock = acquireRepairLock(
            std.heap.page_allocator,
            "refresh-store",
            &store_fingerprint,
        ) catch |err| {
            outcome.store(
                if (err == error.RepairInProgress) blocked else failed,
                .seq_cst,
            );
            return;
        };
        defer lock.release();
        outcome.store(acquired, .seq_cst);
    }
};

fn runTestInvalidGrantServer(args: *TestInvalidGrantServerArgs) void {
    defer args.server.deinit();
    runTestInvalidGrantServerInner(args) catch {
        args.failed.store(true, .seq_cst);
    };
}

fn runTestInvalidGrantServerInner(args: *TestInvalidGrantServerArgs) !void {
    const connection = try args.server.accept();
    defer connection.stream.close();
    var head_buffer: [4096]u8 = undefined;
    var server = std.http.Server.init(connection, &head_buffer);
    var request = try server.receiveHead();
    const body_reader = try request.reader();
    var discard: [1024]u8 = undefined;
    while (try body_reader.read(&discard) != 0) {}

    if (args.mutation_path) |path| {
        const replacement = args.mutation_bytes orelse return error.TestMissingMutation;
        const file = try std.fs.createFileAbsolute(path, .{
            .truncate = true,
            .mode = 0o600,
        });
        defer file.close();
        try file.writeAll(replacement);
    }
    if (args.quarantine_dir_to_block) |path| {
        try std.fs.deleteTreeAbsolute(path);
        const blocker = try std.fs.createFileAbsolute(path, .{ .mode = 0o600 });
        blocker.close();
    }
    if (args.journal_path_to_block) |path| {
        try std.fs.makeDirAbsolute(path);
    }

    try request.respond(args.response_body, .{
        .status = args.response_status,
        .keep_alive = false,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
}

/// Test fixture that establishes a real sticky hard quarantine through the
/// production proof path: configured canonical-store reads, account then
/// identity flocks, a loopback HTTP invalid_grant response, before/after
/// lineage checks, and durable marker + journal writes. It is not a marker
/// injection or a privileged event sink.
pub fn establishHardRefreshQuarantineForTest(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
    backend: types.SecretBackend,
    def: provider_schema.ProviderDefinition,
) !void {
    return establishHardRefreshQuarantineForTestWithBlocker(
        allocator,
        provider,
        account,
        backend,
        def,
        null,
        null,
    );
}

fn establishHardRefreshQuarantineForTestWithBlocker(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
    backend: types.SecretBackend,
    def: provider_schema.ProviderDefinition,
    quarantine_dir_to_block: ?[]const u8,
    journal_path_to_block: ?[]const u8,
) !void {
    if (!builtin.is_test) @compileError("test-only refresh quarantine fixture");

    const canonical = try readCanonicalRefreshLineage(allocator, backend, def);
    defer canonical.deinit(allocator);
    const identity = canonical.identity orelse return error.TestIdentityRequired;

    var account_lock = try acquireRepairLock(allocator, provider, account);
    defer account_lock.release();
    const identity_domain = try std.fmt.allocPrint(
        allocator,
        "{s}-identity",
        .{provider},
    );
    defer allocator.free(identity_domain);
    const identity_key = try identity_hash.sha256_12hex(allocator, identity);
    defer allocator.free(identity_key);
    var identity_lock = try acquireRepairLock(
        allocator,
        identity_domain,
        identity_key,
    );
    defer identity_lock.release();

    var server = try TestInvalidGrantServer.startWithQuarantineBlocker(
        allocator,
        null,
        null,
        quarantine_dir_to_block,
        journal_path_to_block,
    );
    defer server.deinit();
    const token_url = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/token",
        .{server.port},
    );
    defer allocator.free(token_url);

    const attempt = try refreshTokenWithLockedLineage(
        allocator,
        provider,
        account,
        backend,
        def,
        token_url,
        canonical.refresh_token,
        null,
        .{},
    );
    if (server.join()) return error.TestInvalidGrantServerFailed;
    switch (attempt) {
        .failed => |failure| {
            if (failure.outcome != .hard_lineage_invalidated or
                !failure.endpoint_executed)
            {
                return error.TestHardQuarantineNotEstablished;
            }
        },
        .refreshed => |success_value| {
            var success = success_value;
            defer success.releaseStoreLock();
            allocator.free(success.result.access_token);
            if (success.result.refresh_token) |refresh_token| allocator.free(refresh_token);
            return error.TestUnexpectedRefreshSuccess;
        },
    }
}

test "repair lock is re-entrant within one actor (TIN-1851 no self-deadlock)" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();
    // First acquire takes the real OS flock.
    var l1 = try acquireRepairLockBlocking(a, "codex", "tin1851-reentrancy-test");
    // A second acquire of the SAME key from the SAME actor (this thread) must
    // return immediately (re-entrant) rather than self-deadlock on the per-fd
    // flock.
    var l2 = try acquireRepairLockBlocking(a, "codex", "tin1851-reentrancy-test");
    // A nonblocking acquire from the same actor is also re-entrant (already
    // serialized by the held lock), NOT RepairInProgress.
    var l3 = try acquireRepairLock(a, "codex", "tin1851-reentrancy-test");
    l3.release();
    l2.release();
    l1.release();
    // Fully released: a fresh acquire succeeds and the registry entry is gone.
    var l4 = try acquireRepairLockBlocking(a, "codex", "tin1851-reentrancy-test");
    l4.release();
}

test "repair flock ownership cannot be asserted without the live actor hold" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    try std.testing.expect(!try currentActorOwnsRepairLock(a, "toy", "lineage"));
    var lock = try acquireRepairLock(a, "toy", "lineage");
    try std.testing.expect(try currentActorOwnsRepairLock(a, "toy", "lineage"));
    try std.testing.expect(!try currentActorOwnsRepairLock(a, "toy", "other"));
    lock.release();
    try std.testing.expect(!try currentActorOwnsRepairLock(a, "toy", "lineage"));
}

test "cross-actor in-process nonblocking acquire is refused, not re-entrant (TIN-2059)" {
    // Two logical actors in ONE process contending for one provider:account:
    // the second (warm-tick-shaped, nonblocking) actor must get the typed
    // RepairInProgress busy result while the first holds — never a refcount
    // join. Deterministic: the worker thread is joined BEFORE the holder
    // releases, so the hold provably spans the worker's attempt.
    //
    // FAILS-against-old proof: with the actor gate temporarily reverted to the
    // pre-TIN-2059 unconditional `entry.count += 1` join (removing the
    // owner_actor check so any in-process acquire refcounts), the expect below
    // failed — the worker's acquire SUCCEEDED while the main thread held the
    // key. Verified 2026-07-02 by reverting the gate locally, observing this
    // test fail, then restoring the gate.
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    var holder = try acquireRepairLock(a, "codex", "tin2059-cross-actor-nonblocking");

    const Worker = struct {
        fn run(refused: *bool) void {
            // Distinct thread = distinct actor. Must be refused while held.
            if (acquireRepairLock(std.testing.allocator, "codex", "tin2059-cross-actor-nonblocking")) |lock| {
                var l = lock;
                l.release();
                refused.* = false; // joined a cross-actor hold: the TIN-2059 defect
            } else |e| {
                refused.* = (e == error.RepairInProgress);
            }
        }
    };
    var refused = false;
    const worker = try std.Thread.spawn(.{}, Worker.run, .{&refused});
    worker.join();
    try std.testing.expect(refused);

    holder.release();
    // Fully released: the key is free again for any actor.
    var again = try acquireRepairLock(a, "codex", "tin2059-cross-actor-nonblocking");
    again.release();
}

test "blocking join adopts the session actor so materializer nesting works (TIN-1851/TIN-2059)" {
    // The managed-session shape from the real call graph: the session main
    // thread holds the account lock (blocking, adapters/codex/main.zig:1440
    // shape) AND the identity lock (nonblocking, :1452 shape). The proxy
    // materializer thread blocking-joins the account hold
    // (broker_loader.zig:368 shape) and must then be recognized as the SAME
    // actor for its nested identity acquire (:404 shape) — while a third,
    // unrelated actor is still refused on both keys.
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    var account_hold = try acquireRepairLockBlocking(a, "codex", "tin2059-adopt-account");
    var identity_hold = try acquireRepairLock(a, "codex-identity", "tin2059-adopt-id");

    const Materializer = struct {
        fn run(ok: *bool) void {
            const ta = std.testing.allocator;
            // Blocking join of the blocking-held account key: immediate (no
            // self-deadlock), adopting the session's actor for the hold.
            var acct = acquireRepairLockBlocking(ta, "codex", "tin2059-adopt-account") catch {
                ok.* = false;
                return;
            };
            defer acct.release();
            // Nested identity acquire is now same-actor: allowed.
            var ident = acquireRepairLock(ta, "codex-identity", "tin2059-adopt-id") catch {
                ok.* = false;
                return;
            };
            ident.release();
            ok.* = true;
        }
    };
    var materializer_ok = false;
    const mt = try std.Thread.spawn(.{}, Materializer.run, .{&materializer_ok});
    mt.join(); // joined while the session still holds both keys
    try std.testing.expect(materializer_ok);

    const Stranger = struct {
        fn run(refused: *bool) void {
            if (acquireRepairLock(std.testing.allocator, "codex-identity", "tin2059-adopt-id")) |lock| {
                var l = lock;
                l.release();
                refused.* = false;
            } else |e| {
                refused.* = (e == error.RepairInProgress);
            }
        }
    };
    var stranger_refused = false;
    const st = try std.Thread.spawn(.{}, Stranger.run, .{&stranger_refused});
    st.join();
    try std.testing.expect(stranger_refused);

    identity_hold.release();
    account_hold.release();
}

test "cross-actor blocking acquire serializes BEHIND a nonblocking hold (TIN-2059)" {
    // The warm-tick-holds / materializer-arrives shape: a blocking acquirer
    // hitting a NONBLOCKING (short-hold typed writer) hold must WAIT for full
    // release — never cooperative-join it — so its under-lock revalidation
    // runs strictly after the holder's rotation. Under the actor gate the
    // waiter can only acquire after release, so `overlapped` stays false by
    // construction. Against the old unconditional join this leg failed
    // whenever the waiter got scheduled inside the yield window (near-always;
    // the deterministic old-behavior witness is the cross-actor nonblocking
    // test above).
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    var holder = try acquireRepairLock(a, "codex", "tin2059-serialize-behind");
    var holder_released = std.atomic.Value(bool).init(false);
    var overlapped = std.atomic.Value(bool).init(false);

    const Waiter = struct {
        fn run(released: *std.atomic.Value(bool), ov: *std.atomic.Value(bool)) void {
            var l = acquireRepairLockBlocking(std.testing.allocator, "codex", "tin2059-serialize-behind") catch {
                ov.store(true, .seq_cst); // a blocking acquire must not fail here
                return;
            };
            if (!released.load(.seq_cst)) ov.store(true, .seq_cst);
            l.release();
        }
    };
    const waiter = try std.Thread.spawn(.{}, Waiter.run, .{ &holder_released, &overlapped });
    // Give an (incorrect) instant join every chance to happen before release.
    var i: usize = 0;
    while (i < 200) : (i += 1) std.Thread.yield() catch {};
    holder_released.store(true, .seq_cst);
    holder.release();
    waiter.join();
    try std.testing.expect(!overlapped.load(.seq_cst));
}

test "lock file path persists after acquire+release (TIN-2041 no unlink-on-release)" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();
    const path = try lockPath(a, "codex", "tin2041-lockfile-persists");
    defer a.free(path);
    std.fs.deleteFileAbsolute(path) catch {}; // start from a clean slate

    var lock = try acquireRepairLockBlocking(a, "codex", "tin2041-lockfile-persists");
    try std.fs.accessAbsolute(path, .{});
    lock.release();
    // The lock file must STILL exist: release only drops the flock. Unlinking
    // here is what orphaned the inode under a waiter (TIN-2041).
    try std.fs.accessAbsolute(path, .{});
}

test "release hands the SAME inode to the next acquirer under kernel flock conflict (TIN-2041)" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();
    const provider = "codex";
    const account = "tin2041-ofd-conflict";

    const path = try lockPath(a, provider, account);
    defer a.free(path);
    std.fs.deleteFileAbsolute(path) catch {}; // start from a clean slate

    // A: public-API acquire takes the real OS flock for this process.
    var lock_a = try acquireRepairLock(a, provider, account);

    const ino_before = blk: {
        const f = try std.fs.openFileAbsolute(path, .{});
        defer f.close();
        break :blk (try f.stat()).inode;
    };

    // B: a second, distinct open-file-description on the same path. flock is
    // per-OFD, so this conflicts even within one process; the public API would
    // refcount-share, so go below it to create a real kernel conflict.
    try std.testing.expectError(error.RepairInProgress, acquireRealRepairLock(a, provider, account, true, null));

    lock_a.release();

    // B now acquires — and must get the SAME inode A held. The old
    // unlink-on-release orphaned A's inode under any blocked waiter and a
    // fresh acquire created a new inode at the path: two concurrent holders.
    const lock_b = try acquireRealRepairLock(a, provider, account, true, null);
    defer {
        lock_b.file.close();
        a.free(lock_b.path);
    }
    try std.testing.expectEqual(ino_before, (try lock_b.file.stat()).inode);

    // Mutual exclusion holds while B owns the lock: a third distinct-OFD
    // try-acquire fails.
    try std.testing.expectError(error.RepairInProgress, acquireRealRepairLock(a, provider, account, true, null));
}

test "parseStartedAt reads lock metadata timestamp" {
    try std.testing.expectEqual(@as(?i64, 42), parseStartedAt("{\"started_at\":42}\n"));
    try std.testing.expectEqual(@as(?i64, null), parseStartedAt("{\"started_at\":\"42\"}\n"));
}

test "announced blocking acquire announces to its sink, times out naming the lock, and recovers (TIN-2049)" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    const provider = "codex";
    const account = "tin2049-announce-timeout";
    const path = try lockPath(a, provider, account);
    defer a.free(path);
    if (std.fs.path.dirname(path)) |dir| try std.fs.cwd().makePath(dir);
    std.fs.deleteFileAbsolute(path) catch {};

    // A FOREIGN holder: a raw exclusive flock on the lock path via a distinct
    // open-file-description (flock is per-OFD, so this is the cross-process
    // second-launch shape even within the test process).
    var holder = try std.fs.createFileAbsolute(path, .{
        .truncate = false,
        .mode = 0o600,
        .lock = .exclusive,
        .lock_nonblocking = true,
    });

    // Route wait lines to a temp-file sink — the daemon-to-log path — so the
    // announcement is asserted without stderr noise.
    var log_tmp = std.testing.tmpDir(.{});
    defer log_tmp.cleanup();
    const log_file = try log_tmp.dir.createFile("wait.log", .{ .read = true, .truncate = true, .mode = 0o600 });
    defer log_file.close();

    const cfg: BlockingWaitConfig = .{
        .log = log_file,
        .opts = .{
            .poll_interval_ns = 2 * std.time.ns_per_ms,
            .heartbeat_ns = 1 * std.time.ns_per_hour,
            .timeout_ns = 40 * std.time.ns_per_ms,
        },
    };
    // Bounded, not an unbounded silent hang: fails typed while the lock is held.
    try std.testing.expectError(
        error.LockWaitTimeout,
        acquireRepairLockBlockingAnnounced(a, provider, account, cfg),
    );

    try log_file.seekTo(0);
    const logged = try log_file.readToEndAlloc(a, 8 * 1024);
    defer a.free(logged);
    try std.testing.expect(std.mem.indexOf(u8, logged, "waiting on lock") != null);
    try std.testing.expect(std.mem.indexOf(u8, logged, path) != null); // names the lock

    // The typed failure did not leak the in-process registry key: with the
    // foreign flock dropped, a fresh acquire succeeds on the fast path.
    holder.close();
    var recovered = try acquireRepairLockBlocking(a, provider, account);
    recovered.release();
}

test "repair event json is redacted and structured" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeEventJson(buf.writer(), .{
        .ts = 42,
        .profile = "codex-max",
        .provider = "codex",
        .account = "max-1",
        .capability = "codex-max",
        .action = "reauth",
        .command = "oauth-mux codex login-device max-1",
        .outcome = "confirmation_required",
        .reason = "missing_session",
        .ok = false,
        .executed = false,
        .interactive = true,
        .mutating = true,
    });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"provider\":\"codex\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"repair_run\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"command\":\"oauth-mux codex login-device max-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"profile\":\"codex-max\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"account\":\"max-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "token") == null);
}

test "event kind filtering keeps daemon handoffs only" {
    try std.testing.expect(eventLineMatchesKind("{\"kind\":\"daemon_handoff\"}", "daemon_handoff"));
    try std.testing.expect(!eventLineMatchesKind("{\"kind\":\"repair_run\"}", "daemon_handoff"));
    try std.testing.expect(!eventLineMatchesKind("{\"kind\":\"repair_run\",\"reason\":\"daemon_handoff\"}", "daemon_handoff"));
    try std.testing.expect(eventLineMatchesKind("{\"kind\":\"repair_run\"}", null));
}

test "pending handoff queue resolves by later route event" {
    var pending = std.ArrayList([]const u8).init(std.testing.allocator);
    defer pending.deinit();

    const handoff =
        "{\"kind\":\"daemon_handoff\",\"profile\":\"codex-max\",\"provider\":\"codex\",\"account\":\"max-1\",\"capability\":\"codex-max\",\"outcome\":\"handoff_queued\",\"ok\":false}";
    const unrelated =
        "{\"kind\":\"daemon_action\",\"profile\":\"codex-max\",\"provider\":\"codex\",\"account\":\"max-2\",\"capability\":\"codex-max\",\"outcome\":\"route_selectable\",\"ok\":true}";
    const resolved =
        "{\"kind\":\"daemon_action\",\"profile\":\"codex-max\",\"provider\":\"codex\",\"account\":\"max-1\",\"capability\":\"codex-max\",\"outcome\":\"route_selectable\",\"ok\":true}";

    try upsertPendingHandoff(&pending, handoff);
    try std.testing.expectEqual(@as(usize, 1), pending.items.len);
    removeResolvedHandoffs(&pending, unrelated);
    try std.testing.expectEqual(@as(usize, 1), pending.items.len);
    removeResolvedHandoffs(&pending, resolved);
    try std.testing.expectEqual(@as(usize, 0), pending.items.len);
}

test "pending handoff queue resolves by explicit handoff event" {
    var pending = std.ArrayList([]const u8).init(std.testing.allocator);
    defer pending.deinit();

    const handoff =
        "{\"kind\":\"daemon_handoff\",\"profile\":\"codex-max\",\"provider\":\"codex\",\"account\":\"max-1\",\"capability\":\"codex-max\",\"outcome\":\"handoff_queued\",\"ok\":false}";
    const acknowledged =
        "{\"kind\":\"daemon_handoff\",\"profile\":\"codex-max\",\"provider\":\"codex\",\"account\":\"max-1\",\"capability\":\"codex-max\",\"outcome\":\"handoff_acknowledged\",\"ok\":true}";
    const resolved =
        "{\"kind\":\"daemon_handoff\",\"profile\":\"codex-max\",\"provider\":\"codex\",\"account\":\"max-1\",\"capability\":\"codex-max\",\"outcome\":\"handoff_resolved\",\"ok\":true}";

    try upsertPendingHandoff(&pending, handoff);
    removeResolvedHandoffs(&pending, acknowledged);
    try std.testing.expectEqual(@as(usize, 1), pending.items.len);
    removeResolvedHandoffs(&pending, resolved);
    try std.testing.expectEqual(@as(usize, 0), pending.items.len);
}

test "handoff key matching distinguishes pending route" {
    const handoff =
        "{\"kind\":\"daemon_handoff\",\"profile\":\"codex-max\",\"provider\":\"codex\",\"account\":\"max-1\",\"capability\":\"codex-max\",\"outcome\":\"handoff_queued\",\"ok\":false}";

    try std.testing.expect(eventRouteKeyMatchesHandoffKey(handoff, .{
        .profile = "codex-max",
        .provider = "codex",
        .account = "max-1",
        .capability = "codex-max",
    }));
    try std.testing.expect(!eventRouteKeyMatchesHandoffKey(handoff, .{
        .profile = "codex-max",
        .provider = "codex",
        .account = "max-2",
        .capability = "codex-max",
    }));
    try std.testing.expect(!eventRouteKeyMatchesHandoffKey(handoff, .{
        .profile = "codex-max",
        .provider = "codex",
        .account = "max-1",
        .capability = "codex-mini",
    }));
}

test "refresh event json carries redacted writeback evidence" {
    inline for (std.meta.fields(types.RefreshOutcome)) |field| {
        const outcome: types.RefreshOutcome = @enumFromInt(field.value);
        var buf = std.ArrayList(u8).init(std.testing.allocator);
        defer buf.deinit();

        const event = refreshEvent(.{
            .ts = 43,
            .profile = "work",
            .provider = "figma",
            .account = "design",
            .writeback_capability = "replace_file",
            .automatic_refresh_admitted = true,
            .outcome = outcome,
            .ok = outcome == .refreshed,
            .executed = true,
            .mutating = true,
        });
        if (outcome == .hard_lineage_invalidated) {
            try std.testing.expectError(
                error.HardRefreshRequiresLockedLineageProof,
                writeEventJson(buf.writer(), event),
            );
            continue;
        }
        try writeEventJson(buf.writer(), event);

        try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"token_refresh\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"writeback_capability\":\"replace_file\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"automatic_refresh_admitted\":true") != null);
        const marker = try std.fmt.allocPrint(std.testing.allocator, "\"refresh_outcome\":\"{s}\"", .{field.name});
        defer std.testing.allocator.free(marker);
        try std.testing.expect(std.mem.indexOf(u8, buf.items, marker) != null);
        try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"reason\":null") != null);
        try std.testing.expect(std.mem.indexOf(u8, buf.items, "access_token") == null);
        try std.testing.expect(std.mem.indexOf(u8, buf.items, "refresh_token") == null);
        try std.testing.expect(std.mem.indexOf(u8, buf.items, "invalid_grant") == null);
    }
}

test "refresh event persistence rejects missing, mismatched, and free-form outcome data" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try std.testing.expectError(error.InvalidRefreshEvent, writeEventJson(buf.writer(), .{
        .kind = "token_refresh",
        .provider = "toy",
        .account = "lineage",
        .outcome = "transient_endpoint",
    }));
    try std.testing.expectError(error.InvalidRefreshEvent, writeEventJson(buf.writer(), .{
        .kind = "token_refresh",
        .provider = "toy",
        .account = "lineage",
        .refresh_outcome = .transient_endpoint,
        .outcome = "hard_lineage_invalidated",
    }));
    try std.testing.expectError(error.InvalidRefreshEvent, writeEventJson(buf.writer(), .{
        .kind = "token_refresh",
        .provider = "toy",
        .account = "lineage",
        .refresh_outcome = .transient_endpoint,
        .outcome = "transient_endpoint",
        .reason = "provider body text",
    }));
    try std.testing.expectError(error.InvalidRefreshEvent, writeEventJson(buf.writer(), .{
        .kind = "token_refresh",
        .provider = "toy",
        .account = "lineage",
        .refresh_outcome = .transient_store,
        .outcome = "transient_store",
        .ok = true,
    }));
    try std.testing.expectError(error.InvalidRefreshEvent, writeEventJson(buf.writer(), .{
        .kind = "token_refresh",
        .provider = "toy",
        .account = "lineage",
        .refresh_outcome = .transient_store,
        .outcome = "transient_store",
        .executed = true,
        .mutating = false,
    }));
    // A peer rotation adopted from the canonical store is refreshed without
    // this process executing or mutating the endpoint.
    try writeEventJson(buf.writer(), .{
        .kind = "token_refresh",
        .provider = "toy",
        .account = "lineage",
        .refresh_outcome = .refreshed,
        .outcome = "refreshed",
        .ok = true,
        .executed = false,
        .mutating = false,
    });
}

test "refresh journal rejects persisted boolean and outcome invariant violations" {
    const allocator = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(allocator);
    defer scope.deinit(allocator);
    scope.activate();
    const path = try eventsPath(allocator);
    defer allocator.free(path);
    try ensureParentDir(path);
    const file = try std.fs.createFileAbsolute(
        path,
        .{ .truncate = true, .mode = 0o600 },
    );
    defer file.close();
    try file.writeAll(
        "{\"kind\":\"token_refresh\",\"provider\":\"toy\",\"account\":\"bad-ok\",\"refresh_outcome\":\"transient_store\",\"outcome\":\"transient_store\",\"ok\":true,\"executed\":false,\"mutating\":false}\n" ++
            "{\"kind\":\"token_refresh\",\"provider\":\"toy\",\"account\":\"bad-mutating\",\"refresh_outcome\":\"transient_endpoint\",\"outcome\":\"transient_endpoint\",\"ok\":false,\"executed\":true,\"mutating\":false}\n" ++
            "{\"kind\":\"token_refresh\",\"provider\":\"toy\",\"account\":\"bad-hard\",\"refresh_outcome\":\"hard_lineage_invalidated\",\"outcome\":\"hard_lineage_invalidated\",\"ok\":false,\"executed\":false,\"mutating\":false}\n",
    );

    const summary = try refreshJournalSummary(allocator);
    try std.testing.expect(!summary.valid);
    try std.testing.expectEqual(@as(usize, 3), summary.invalid_events);
    try std.testing.expectEqual(@as(usize, 0), summary.typed_events);
    try std.testing.expectError(
        error.InvalidRefreshJournal,
        refreshOutcomeForRoute(allocator, "toy", "bad-ok"),
    );
}

test "provider re-enrollment resolves only indeterminate refresh quarantine" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    try persistIndeterminateRefreshQuarantine(a, "codex", "max-1");
    try std.testing.expectError(
        error.RepairLockRequired,
        resolveIndeterminateRefreshQuarantineAfterProviderReenroll(
            a,
            "codex",
            "max-1",
        ),
    );
    var account_lock = try acquireRepairLock(a, "codex", "max-1");
    defer account_lock.release();
    try std.testing.expect(try resolveIndeterminateRefreshQuarantineAfterProviderReenroll(
        a,
        "codex",
        "max-1",
    ));
    try std.testing.expect(
        (try refreshQuarantineForRoute(a, "codex", "max-1")) == null,
    );

    try writeRefreshQuarantineMarker(
        a,
        "codex",
        "max-1",
        .hard_lineage_invalidated,
        null,
        null,
    );
    try std.testing.expectError(
        error.HardRefreshQuarantineCannotBeCleared,
        resolveIndeterminateRefreshQuarantineAfterProviderReenroll(
            a,
            "codex",
            "max-1",
        ),
    );
    try std.testing.expectEqual(
        RefreshQuarantineState.hard_lineage_invalidated,
        (try effectiveRefreshQuarantineForRoute(a, "codex", "max-1")).?,
    );
    try std.testing.expectEqual(
        RefreshQuarantineState.hard_lineage_invalidated,
        (try refreshQuarantineForRoute(a, "codex", "max-1")).?,
    );
}

test "hard journal authority dominates a later indeterminate marker" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();
    var account_lock = try acquireRepairLock(a, "codex", "max-1");
    defer account_lock.release();

    try appendEventAuthorized(a, refreshEvent(.{
        .provider = "codex",
        .account = "max-1",
        .outcome = .hard_lineage_invalidated,
        .executed = true,
        .mutating = true,
    }), true);
    try writeRefreshQuarantineMarker(
        a,
        "codex",
        "max-1",
        .indeterminate_lineage,
        null,
        null,
    );

    try std.testing.expectEqual(
        RefreshQuarantineState.hard_lineage_invalidated,
        (try effectiveRefreshQuarantineForRoute(a, "codex", "max-1")).?,
    );
    try std.testing.expectError(
        error.HardRefreshQuarantineCannotBeCleared,
        resolveIndeterminateRefreshQuarantineAfterProviderReenroll(
            a,
            "codex",
            "max-1",
        ),
    );
}

test "unproven endpoint response keeps indeterminate lineage across restart" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    const credential_path = try std.fs.path.join(
        a,
        &.{ scope.root, "unproven.json" },
    );
    defer a.free(credential_path);
    const credential =
        "{\"access_token\":\"at-old\",\"refresh_token\":\"rt-old\",\"account_id\":\"identity\"}";
    {
        const file = try std.fs.createFileAbsolute(credential_path, .{
            .mode = 0o600,
        });
        defer file.close();
        try file.writeAll(credential);
    }
    const def = provider_schema.ProviderDefinition{
        .name = "toy",
        .credential = .{
            .access_token_path = "access_token",
            .refresh_token_path = "refresh_token",
            .identity_claim_path = "account_id",
        },
        .repair = .{
            .owner = .oauth_mux_refresh,
            .proactive_refresh = .oauth_refresh_token,
        },
    };
    const backend = types.SecretBackend{
        .file = .{ .path = credential_path },
    };

    var account_lock = try acquireRepairLock(a, "toy", "unproven");
    defer account_lock.release();
    const identity_key = try identity_hash.sha256_12hex(a, "identity");
    defer a.free(identity_key);
    var identity_lock = try acquireRepairLock(
        a,
        "toy-identity",
        identity_key,
    );
    defer identity_lock.release();

    var server = try TestInvalidGrantServer.startWithResponse(
        a,
        .service_unavailable,
        "{\"error\":\"temporarily_unavailable\"}",
    );
    defer server.deinit();
    const token_url = try std.fmt.allocPrint(
        a,
        "http://127.0.0.1:{d}/token",
        .{server.port},
    );
    defer a.free(token_url);

    const attempt = try refreshTokenWithLockedLineage(
        a,
        "toy",
        "unproven",
        backend,
        def,
        token_url,
        "rt-old",
        null,
        .{},
    );
    try std.testing.expect(!server.join());
    switch (attempt) {
        .failed => |failure| {
            try std.testing.expectEqual(
                types.RefreshOutcome.transient_endpoint,
                failure.outcome,
            );
            try std.testing.expect(failure.endpoint_executed);
            try std.testing.expect(failure.lineage_quarantined);
        },
        .refreshed => |success_value| {
            var success = success_value;
            defer success.releaseStoreLock();
            defer freeRefreshResult(a, success.result);
            return error.TestUnexpectedRefreshSuccess;
        },
    }
    try std.testing.expectEqual(
        RefreshQuarantineState.indeterminate_lineage,
        (try refreshQuarantineForRoute(a, "toy", "unproven")).?,
    );

    // The closed one-shot endpoint must not be contacted on a fresh attempt;
    // the durable marker blocks before request setup or token replay.
    const restart = try refreshTokenWithLockedLineage(
        a,
        "toy",
        "unproven",
        backend,
        def,
        token_url,
        "rt-old",
        null,
        .{},
    );
    switch (restart) {
        .failed => |failure| {
            try std.testing.expectEqual(
                types.RefreshOutcome.transient_store,
                failure.outcome,
            );
            try std.testing.expect(!failure.endpoint_executed);
            try std.testing.expect(failure.lineage_quarantined);
        },
        .refreshed => |success_value| {
            var success = success_value;
            defer success.releaseStoreLock();
            defer freeRefreshResult(a, success.result);
            return error.TestUnexpectedRefreshSuccess;
        },
    }
}

test "refresh-token omission follows the provider's closed response policy" {
    const Case = struct {
        fn run(
            policy: provider_schema.RefreshTokenResponsePolicy,
            expect_reuse: bool,
        ) !void {
            const a = std.testing.allocator;
            var scope = try TestRuntimeDirScope.init(a);
            defer scope.deinit(a);
            scope.activate();

            const credential_path = try std.fs.path.join(
                a,
                &.{ scope.root, "credential.json" },
            );
            defer a.free(credential_path);
            {
                const credential = try std.fs.createFileAbsolute(
                    credential_path,
                    .{ .mode = 0o600 },
                );
                defer credential.close();
                try credential.writeAll(
                    "{\"access_token\":\"at-old\",\"refresh_token\":\"rt-reusable\",\"account_id\":\"identity\"}",
                );
            }
            const def = provider_schema.ProviderDefinition{
                .name = "toy",
                .credential = .{
                    .access_token_path = "access_token",
                    .refresh_token_path = "refresh_token",
                    .identity_claim_path = "account_id",
                },
                .repair = .{
                    .owner = .oauth_mux_refresh,
                    .proactive_refresh = .oauth_refresh_token,
                    .refresh_token_response = policy,
                },
            };
            const backend = types.SecretBackend{
                .file = .{ .path = credential_path },
            };
            const store_fingerprint = try refreshStoreFingerprint(
                a,
                "toy",
                backend,
            );

            var account_lock = try acquireRepairLock(a, "toy", "policy");
            defer account_lock.release();
            const identity_key = try identity_hash.sha256_12hex(a, "identity");
            defer a.free(identity_key);
            var identity_lock = try acquireRepairLock(
                a,
                "toy-identity",
                identity_key,
            );
            defer identity_lock.release();

            var server = try TestInvalidGrantServer.startWithResponse(
                a,
                .ok,
                "{\"access_token\":\"at-new\",\"expires_in\":3600}",
            );
            defer server.deinit();
            const token_url = try std.fmt.allocPrint(
                a,
                "http://127.0.0.1:{d}/token",
                .{server.port},
            );
            defer a.free(token_url);

            const attempt = try refreshTokenWithLockedLineage(
                a,
                "toy",
                "policy",
                backend,
                def,
                token_url,
                "rt-reusable",
                null,
                .{},
            );
            try std.testing.expect(!server.join());
            switch (attempt) {
                .failed => |failure| {
                    try std.testing.expect(!expect_reuse);
                    try std.testing.expectEqual(
                        types.RefreshOutcome.transient_endpoint,
                        failure.outcome,
                    );
                    try std.testing.expect(failure.endpoint_executed);
                    try std.testing.expect(failure.lineage_quarantined);
                },
                .refreshed => |success_value| {
                    var success = success_value;
                    defer success.releaseStoreLock();
                    defer freeRefreshResult(a, success.result);
                    try std.testing.expect(expect_reuse);
                    try std.testing.expectEqual(
                        RefreshTokenDisposition.submitted_reused,
                        success.refresh_token_disposition,
                    );
                    try std.testing.expect(success.result.refresh_token == null);

                    var probe_outcome = std.atomic.Value(u8).init(0);
                    const probe = try std.Thread.spawn(
                        .{},
                        TestStoreLockProbe.run,
                        .{ store_fingerprint, &probe_outcome },
                    );
                    probe.join();
                    try std.testing.expectEqual(
                        TestStoreLockProbe.blocked,
                        probe_outcome.load(.seq_cst),
                    );

                    success.releaseStoreLock();
                    var reacquired = try acquireRepairLock(
                        a,
                        "refresh-store",
                        &store_fingerprint,
                    );
                    reacquired.release();
                },
            }
        }
    };

    try Case.run(.require_rotated, false);
    try Case.run(.reuse_submitted_if_omitted, true);
}

test "refresh journal propagates typed outcomes and keeps hard quarantine sticky" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();
    const credential_path = try std.fs.path.join(
        a,
        &.{ scope.root, "lineage.json" },
    );
    defer a.free(credential_path);
    {
        const credential = try std.fs.createFileAbsolute(credential_path, .{
            .mode = 0o600,
        });
        defer credential.close();
        try credential.writeAll(
            "{\"access_token\":\"at\",\"refresh_token\":\"rt-current\",\"account_id\":\"identity-current\"}",
        );
    }
    const def = provider_schema.ProviderDefinition{
        .name = "toy",
        .credential = .{
            .access_token_path = "access_token",
            .refresh_token_path = "refresh_token",
            .identity_claim_path = "account_id",
        },
        .repair = .{
            .owner = .oauth_mux_refresh,
            .proactive_refresh = .oauth_refresh_token,
        },
    };
    const backend = types.SecretBackend{ .file = .{ .path = credential_path } };

    try appendEvent(a, refreshEvent(.{
        .provider = "toy",
        .account = "other",
        .outcome = .transient_network,
    }));

    var account_lock = try acquireRepairLock(a, "toy", "lineage");
    const identity_key = try identity_hash.sha256_12hex(a, "identity-current");
    defer a.free(identity_key);
    var identity_lock = try acquireRepairLock(a, "toy-identity", identity_key);
    try std.testing.expectError(
        error.HardRefreshRequiresLockedLineageProof,
        appendEvent(a, refreshEvent(.{
            .provider = "toy",
            .account = "lineage",
            .outcome = .hard_lineage_invalidated,
            .executed = true,
        })),
    );
    identity_lock.release();
    account_lock.release();

    try establishHardRefreshQuarantineForTest(
        a,
        "toy",
        "lineage",
        backend,
        def,
    );
    const marker_path = try refreshQuarantinePath(a, "toy", "lineage");
    defer a.free(marker_path);
    const marker = try std.fs.openFileAbsolute(marker_path, .{});
    defer marker.close();
    const marker_bytes = try marker.readToEndAlloc(a, 4 * 1024);
    defer a.free(marker_bytes);
    try std.testing.expect(std.mem.indexOf(u8, marker_bytes, "\"recovery\":\"provider_reenroll\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, marker_bytes, "\"stale_backup_restore_allowed\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, marker_bytes, "access_token") == null);
    try std.testing.expect(std.mem.indexOf(u8, marker_bytes, "refresh_token") == null);
    // An automatic/stale refresh row cannot clear a hard lineage quarantine.
    try appendEvent(a, refreshEvent(.{
        .provider = "toy",
        .account = "lineage",
        .outcome = .refreshed,
        .ok = true,
        .executed = true,
        .mutating = true,
    }));

    try std.testing.expectEqual(
        types.RefreshOutcome.hard_lineage_invalidated,
        (try refreshOutcomeForRoute(a, "toy", "lineage")).?,
    );
    try std.testing.expectEqual(
        types.RefreshOutcome.transient_network,
        (try refreshOutcomeForRoute(a, "toy", "other")).?,
    );
    try std.testing.expect((try refreshOutcomeForRoute(a, "toy", "missing")) == null);

    // The durable marker keeps quarantine after the bounded event journal no
    // longer contains the original hard row.
    const path = try eventsPath(a);
    defer a.free(path);
    const empty = try std.fs.createFileAbsolute(path, .{ .truncate = true, .mode = 0o600 });
    empty.close();
    try std.testing.expectEqual(
        types.RefreshOutcome.hard_lineage_invalidated,
        (try refreshOutcomeForRoute(a, "toy", "lineage")).?,
    );

    const summary = try refreshJournalSummary(a);
    try std.testing.expect(summary.valid);
    try std.testing.expectEqual(@as(usize, 0), summary.typed_events);
    try std.testing.expectEqual(@as(usize, 1), summary.hard_lineage_events);
    try std.testing.expect(summary.latest_outcome == null);
}

test "hard lineage proof rejects missing identity flock and locked lineage drift" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();
    const credential_path = try std.fs.path.join(
        a,
        &.{ scope.root, "identity-drift.json" },
    );
    defer a.free(credential_path);
    const original =
        "{\"access_token\":\"at\",\"refresh_token\":\"rt-current\",\"account_id\":\"identity-before\"}";
    {
        const credential = try std.fs.createFileAbsolute(credential_path, .{
            .mode = 0o600,
        });
        defer credential.close();
        try credential.writeAll(original);
    }
    const def = provider_schema.ProviderDefinition{
        .name = "toy",
        .credential = .{
            .access_token_path = "access_token",
            .refresh_token_path = "refresh_token",
            .identity_claim_path = "account_id",
        },
        .repair = .{
            .owner = .oauth_mux_refresh,
            .proactive_refresh = .oauth_refresh_token,
        },
    };
    const backend = types.SecretBackend{ .file = .{ .path = credential_path } };

    var account_lock = try acquireRepairLock(a, "toy", "identity-drift");
    defer account_lock.release();
    const missing_identity_attempt = try refreshTokenWithLockedLineage(
        a,
        "toy",
        "identity-drift",
        backend,
        def,
        "http://127.0.0.1:9/token",
        "rt-current",
        null,
        .{},
    );
    try std.testing.expectEqual(
        types.RefreshOutcome.transient_lock,
        missing_identity_attempt.failed.outcome,
    );
    try std.testing.expect(!missing_identity_attempt.failed.endpoint_executed);

    const identity_key = try identity_hash.sha256_12hex(a, "identity-before");
    defer a.free(identity_key);
    var identity_lock = try acquireRepairLock(a, "toy-identity", identity_key);
    defer identity_lock.release();
    const replacement =
        "{\"access_token\":\"at\",\"refresh_token\":\"rt-current\",\"account_id\":\"identity-after\"}";
    var server = try TestInvalidGrantServer.start(
        a,
        credential_path,
        replacement,
    );
    defer server.deinit();
    const token_url = try std.fmt.allocPrint(
        a,
        "http://127.0.0.1:{d}/token",
        .{server.port},
    );
    defer a.free(token_url);
    const drift_attempt = try refreshTokenWithLockedLineage(
        a,
        "toy",
        "identity-drift",
        backend,
        def,
        token_url,
        "rt-current",
        null,
        .{},
    );
    try std.testing.expect(!server.join());
    try std.testing.expectEqual(
        types.RefreshOutcome.transient_store,
        drift_attempt.failed.outcome,
    );
    try std.testing.expect(drift_attempt.failed.endpoint_executed);
    try std.testing.expect(
        (try refreshOutcomeForRoute(a, "toy", "identity-drift")) == null,
    );
    try std.testing.expectEqual(
        RefreshQuarantineState.indeterminate_lineage,
        (try refreshQuarantineForRoute(a, "toy", "identity-drift")).?,
    );

    // Restore the original identity, then simulate a peer rotating only the
    // canonical refresh token while the invalid-grant response is in flight.
    // The submitted lineage is no longer current, so this is transient store
    // evidence rather than proof that the active lineage is dead.
    {
        const credential = try std.fs.createFileAbsolute(credential_path, .{
            .truncate = true,
            .mode = 0o600,
        });
        defer credential.close();
        try credential.writeAll(original);
    }
    // Isolate the second proof case. Production recovery never clears this
    // marker by restoring stale bytes; only successful canonical persistence or
    // provider-owned re-enrollment may do so.
    try clearIndeterminateRefreshQuarantine(a, "toy", "identity-drift");
    const rotated =
        "{\"access_token\":\"at-new\",\"refresh_token\":\"rt-peer\",\"account_id\":\"identity-before\"}";
    var rotation_server = try TestInvalidGrantServer.start(
        a,
        credential_path,
        rotated,
    );
    defer rotation_server.deinit();
    const rotation_url = try std.fmt.allocPrint(
        a,
        "http://127.0.0.1:{d}/token",
        .{rotation_server.port},
    );
    defer a.free(rotation_url);
    const rotation_attempt = try refreshTokenWithLockedLineage(
        a,
        "toy",
        "identity-drift",
        backend,
        def,
        rotation_url,
        "rt-current",
        null,
        .{},
    );
    try std.testing.expect(!rotation_server.join());
    try std.testing.expectEqual(
        types.RefreshOutcome.transient_store,
        rotation_attempt.failed.outcome,
    );
    try std.testing.expect(rotation_attempt.failed.endpoint_executed);
    try std.testing.expect(rotation_attempt.failed.lineage_quarantined);
    try std.testing.expect(
        (try refreshOutcomeForRoute(a, "toy", "identity-drift")) == null,
    );
    try std.testing.expectEqual(
        RefreshQuarantineState.indeterminate_lineage,
        (try refreshQuarantineForRoute(a, "toy", "identity-drift")).?,
    );
}

test "hard quarantine marker and journal failures each propagate from the proof path" {
    const Case = struct {
        const Failure = enum { marker, journal };

        fn run(failure: Failure) !void {
            const a = std.testing.allocator;
            var scope = try TestRuntimeDirScope.init(a);
            defer scope.deinit(a);
            scope.activate();
            const credential_path = try std.fs.path.join(
                a,
                &.{ scope.root, "persistence.json" },
            );
            defer a.free(credential_path);
            {
                const credential = try std.fs.createFileAbsolute(credential_path, .{
                    .mode = 0o600,
                });
                defer credential.close();
                try credential.writeAll(
                    "{\"access_token\":\"at\",\"refresh_token\":\"rt-current\",\"account_id\":\"identity-current\"}",
                );
            }
            const def = provider_schema.ProviderDefinition{
                .name = "toy",
                .credential = .{
                    .access_token_path = "access_token",
                    .refresh_token_path = "refresh_token",
                    .identity_claim_path = "account_id",
                },
                .repair = .{
                    .owner = .oauth_mux_refresh,
                    .proactive_refresh = .oauth_refresh_token,
                },
            };

            var quarantine_dir_to_block: ?[]const u8 = null;
            defer if (quarantine_dir_to_block) |path| a.free(path);
            var journal_path_to_block: ?[]const u8 = null;
            defer if (journal_path_to_block) |path| a.free(path);
            switch (failure) {
                .marker => {
                    quarantine_dir_to_block = try std.fs.path.join(
                        a,
                        &.{ scope.root, "refresh-quarantine" },
                    );
                },
                .journal => {
                    journal_path_to_block = try eventsPath(a);
                },
            }

            try std.testing.expectError(
                error.RefreshQuarantinePersistenceFailed,
                establishHardRefreshQuarantineForTestWithBlocker(
                    a,
                    "toy",
                    "persistence",
                    .{ .file = .{ .path = credential_path } },
                    def,
                    quarantine_dir_to_block,
                    journal_path_to_block,
                ),
            );

            switch (failure) {
                .marker => {
                    const journal_path = try eventsPath(a);
                    defer a.free(journal_path);
                    const journal = try std.fs.openFileAbsolute(journal_path, .{});
                    defer journal.close();
                    const bytes = try journal.readToEndAlloc(a, 1024 * 1024);
                    defer a.free(bytes);
                    try std.testing.expect(
                        std.mem.indexOf(
                            u8,
                            bytes,
                            "\"refresh_outcome\":\"hard_lineage_invalidated\"",
                        ) != null,
                    );
                    // The injected marker failure leaves the quarantine-dir
                    // path as a file. Once storage access recovers on restart,
                    // the independent journal must still restore the hard gate.
                    try std.fs.deleteFileAbsolute(quarantine_dir_to_block.?);
                    try std.fs.makeDirAbsolute(quarantine_dir_to_block.?);
                    try std.testing.expectEqual(
                        RefreshQuarantineState.hard_lineage_invalidated,
                        (try effectiveRefreshQuarantineForRoute(
                            a,
                            "toy",
                            "persistence",
                        )).?,
                    );
                },
                .journal => try std.testing.expectEqual(
                    types.RefreshOutcome.hard_lineage_invalidated,
                    (try refreshOutcomeForRoute(
                        a,
                        "toy",
                        "persistence",
                    )).?,
                ),
            }
        }
    };

    try Case.run(.marker);
    try Case.run(.journal);
}

test "refresh journal fails closed on unknown new tags and ignores legacy rows" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    const path = try eventsPath(a);
    defer a.free(path);
    try ensureParentDir(path);
    const file = try std.fs.createFileAbsolute(path, .{ .truncate = true, .mode = 0o600 });
    defer file.close();
    try file.writeAll(
        "{\"kind\":\"token_refresh\",\"provider\":\"toy\",\"account\":\"legacy\",\"outcome\":\"persisted\"}\n" ++
            "{\"kind\":\"token_refresh\",\"provider\":\"toy\",\"account\":\"lineage\",\"refresh_outcome\":\"endpoint_body_claimed_dead\",\"outcome\":\"endpoint_body_claimed_dead\",\"ok\":false,\"executed\":false,\"mutating\":false}\n",
    );
    const marker_path = try refreshQuarantinePath(a, "toy", "marker");
    defer a.free(marker_path);
    try ensureParentDir(marker_path);
    const marker = try std.fs.createFileAbsolute(marker_path, .{ .truncate = true, .mode = 0o600 });
    defer marker.close();
    try marker.writeAll(
        "{\"version\":1,\"provider\":\"toy\",\"account\":\"marker\",\"outcome\":\"future_hard_tag\",\"recovery\":\"provider_reenroll\",\"stale_backup_restore_allowed\":false}\n",
    );

    const summary = try refreshJournalSummary(a);
    try std.testing.expect(!summary.valid);
    try std.testing.expectEqual(@as(usize, 0), summary.typed_events);
    try std.testing.expectEqual(@as(usize, 2), summary.invalid_events);
    try std.testing.expectError(
        error.UnknownRefreshOutcome,
        refreshOutcomeForRoute(a, "toy", "lineage"),
    );
    try std.testing.expectError(
        error.UnknownRefreshOutcome,
        refreshOutcomeForRoute(a, "toy", "marker"),
    );
    try std.testing.expect((try refreshOutcomeForRoute(a, "toy", "legacy")) == null);
}

test "handoff event json carries redacted consent metadata" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeEventJson(buf.writer(), .{
        .ts = 44,
        .kind = "daemon_handoff",
        .provider = "codex",
        .account = "max-1",
        .action = "reauth_start",
        .command = "oauth-mux codex login-device max-1",
        .engine_run_available = false,
        .execution = "command_owned",
        .agent_safe = false,
        .spends_provider_calls = false,
        .budget = "1 interactive login",
        .repair_owner = "upstream_cli_login",
        .fresh_browser_context_required = true,
        .browser_context = "fresh_incognito_or_isolated_profile",
        .outcome = "handoff_queued",
        .reason = "reauth_user_mediated",
        .interactive = true,
        .mutating = true,
    });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"daemon_handoff\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"engine_run_available\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"execution\":\"command_owned\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"fresh_browser_context_required\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"browser_context\":\"fresh_incognito_or_isolated_profile\"") != null);
}

test "sanitized lock file names do not preserve path separators" {
    const name = try sanitizedLockFileName(std.testing.allocator, "co/dex", "max:1");
    defer std.testing.allocator.free(name);
    try std.testing.expectEqualStrings("co_dex-max_1.lock", name);
}
