//! R-N13: actor-owned whole-envelope admission. Credits reserve future metadata
//! growth; they are not replay authority and never replace the original work key.
//! Reserve and persist before effects. Consume/release only in the same durable
//! candidate as the owner's bounded growth or terminal/fenced outcome.
const std = @import("std");

pub const maximum_snapshot_bytes: usize = 16 * 1024 * 1024;
pub const maximum_credits: usize = 4096;
pub const maximum_domain_records: usize = 1024;
pub const maximum_account_sources: usize = 64;
pub const Kind = enum { mutation, request, import, observation, rotation, native_registration, native_detach };
pub const Key = struct { kind: Kind, id: [32]u8, generation: u64 };
pub const State = enum { reserved, indeterminate };
pub const Counts = struct {
    sources: usize = 0,
    accounts: usize = 0,
    grants: usize = 0,
    observations: usize = 0,
    bindings: usize = 0,
    leases: usize = 0,
    tombstones: usize = 0,
    quarantined_imports: usize = 0,
    jobs: usize = 0,
    source_descriptions: usize = 0,
    /// Unknown identities may all resolve to one existing account. These slots
    /// are conservatively protected against every account's current link count.
    source_links: usize = 0,
    native_owners: usize = 0,
    /// Attachments and application-removal fences share retained lifetime slots.
    native_authority_records: usize = 0,
};
pub const Credit = struct { key: Key, bytes: usize, counts: Counts = .{}, state: State = .reserved };
pub const Snapshot = struct { version: u32 = 1, credits: []const Credit = &.{} };
pub const Usage = struct {
    exact_snapshot_bytes: usize,
    /// Includes envelope and credit metadata; excludes authority ledger encodings.
    nonledger_bytes: usize,
    /// Complete committed-plus-promised footprint, including ledger reservations.
    reserved_bytes: usize,
    credits_bytes: usize,
    credit_metadata_growth_bytes: usize,
    maintenance_growth_bytes: usize,
    maintenance_metadata_growth_bytes: usize,
    native_ledger_reserved_bytes: usize,
    counts_reserved: Counts,
    remaining_bytes: usize,
};

const Counter = struct {
    writer: std.Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },
    bytes: usize = 0,
    limit: usize,

    fn drain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Counter = @alignCast(@fieldParentPtr("writer", writer));
        var written: usize = 0;
        for (data[0 .. data.len - 1]) |part| {
            if (part.len > self.limit - self.bytes - written) return error.WriteFailed;
            written += part.len;
        }
        const last = data[data.len - 1];
        const repeated = std.math.mul(usize, last.len, splat) catch return error.WriteFailed;
        if (repeated > self.limit - self.bytes - written) return error.WriteFailed;
        written += repeated;
        self.bytes += written;
        return written;
    }
};

/// Counts the actual locked default serializer, including byte-array coercion,
/// escaping, punctuation and integer widths. No serialized buffer is allocated.
pub fn countJson(value: anytype, limit: usize) !usize {
    var counter: Counter = .{ .limit = @min(limit, maximum_snapshot_bytes) };
    std.json.Stringify.value(value, .{}, &counter.writer) catch return error.SnapshotTooLarge;
    return counter.bytes;
}

fn sameKey(a: Key, b: Key) bool {
    return a.kind == b.kind and a.generation == b.generation and std.mem.eql(u8, &a.id, &b.id);
}

fn validateKey(key: Key) !void {
    for (key.id) |byte| if (byte != 0) return;
    return error.InvalidSnapshotCredit;
}

fn countLimit(comptime name: []const u8) usize {
    return if (std.mem.eql(u8, name, "source_links")) maximum_account_sources else if (std.mem.eql(u8, name, "native_owners")) 256 else if (std.mem.eql(u8, name, "native_authority_records")) 4096 else maximum_domain_records;
}

fn addCounts(a: Counts, b: Counts) !Counts {
    var result = a;
    inline for (@typeInfo(Counts).@"struct".field_names) |name| {
        const previous = @field(result, name);
        const addition = @field(b, name);
        if (previous > countLimit(name) or addition > countLimit(name) - previous) return error.SnapshotCardinalityExceeded;
        @field(result, name) += addition;
    }
    return result;
}

fn totals(saved: Snapshot) !struct { bytes: usize, metadata_growth: usize, counts: Counts } {
    if (saved.version != 1 or saved.credits.len > maximum_credits) return error.InvalidSnapshotAdmission;
    // This exact metadata obligation ensures restart's uncertainty label fits.
    const reserved_state = try countJson(State.reserved, maximum_snapshot_bytes);
    const indeterminate_state = try countJson(State.indeterminate, maximum_snapshot_bytes);
    const state_growth = indeterminate_state - reserved_state;
    var bytes: usize = 0;
    var metadata_growth: usize = 0;
    var counts: Counts = .{};
    for (saved.credits) |credit| {
        try validateKey(credit.key);
        if (credit.bytes > maximum_snapshot_bytes - bytes) return error.InvalidSnapshotAdmission;
        bytes += credit.bytes;
        counts = try addCounts(counts, credit.counts);
        if (credit.state == .reserved) metadata_growth += state_growth;
    }
    return .{ .bytes = bytes, .metadata_growth = metadata_growth, .counts = counts };
}

fn checkCardinality(full: anytype, held: Counts) !void {
    inline for (@typeInfo(Counts).@"struct".field_names) |name| {
        if (comptime std.mem.eql(u8, name, "source_links")) {
            var most_links: usize = 0;
            for (full.state.accounts) |account| most_links = @max(most_links, account.source_ids.len);
            if (most_links > maximum_account_sources or held.source_links > maximum_account_sources - most_links) return error.SnapshotCardinalityExceeded;
        } else if (comptime std.mem.eql(u8, name, "native_owners") or std.mem.eql(u8, name, "native_authority_records")) {
            const actual = if (comptime @hasField(@TypeOf(full), "native_owner_authority")) (if (comptime std.mem.eql(u8, name, "native_owners")) full.native_owner_authority.owners.len else try std.math.add(usize, full.native_owner_authority.attachments.len, full.native_owner_authority.removals.len)) else 0;
            if (comptime !@hasField(@TypeOf(full), "native_owner_authority")) {
                if (@field(held, name) != 0) return error.InvalidSnapshotReservation;
            }
            if (actual > countLimit(name) or @field(held, name) > countLimit(name) - actual) return error.SnapshotCardinalityExceeded;
        } else {
            const actual = if (comptime std.mem.eql(u8, name, "source_descriptions")) full.source_descriptions.len else @field(full.state, name).len;
            if (actual > maximum_domain_records or @field(held, name) > maximum_domain_records - actual) return error.SnapshotCardinalityExceeded;
        }
    }
}

/// `full` is the exact candidate passed to storage, with request_authority,
/// mutation_authority and snapshot_admission fields. Measure every writer here.
/// The supplied ledger reservations must belong to that same candidate.
pub fn checkEnvelope(full: anytype, request_reserved: usize, mutation_reserved: usize) !Usage {
    if (comptime @hasField(@TypeOf(full), "native_owner_authority")) return error.MissingNativeReservation;
    return checkEnvelopeInternal(full, request_reserved, mutation_reserved, 0);
}

/// Native ledger retirement headroom belongs to the same exact candidate.
/// Effect outcome credits remain independent and cannot debit this reservation.
pub fn checkEnvelopeWithNative(full: anytype, request_reserved: usize, mutation_reserved: usize, native_reserved: usize) !Usage {
    if (comptime !@hasField(@TypeOf(full), "native_owner_authority")) return error.MissingNativeReservation;
    return checkEnvelopeInternal(full, request_reserved, mutation_reserved, native_reserved);
}

fn checkEnvelopeInternal(full: anytype, request_reserved: usize, mutation_reserved: usize, native_reserved: usize) !Usage {
    // A v2 owner must verify this against its typed whole-domain capacity bound.
    // Missing/null reservation is an explicit repair gate, never an inferred zero.
    const maintenance = if (comptime @hasField(@TypeOf(full), "maintenance_growth_bytes")) blk: {
        const supplied = full.maintenance_growth_bytes;
        break :blk if (comptime @TypeOf(supplied) == ?usize) supplied orelse return error.MissingMaintenanceReservation else supplied;
    } else return error.MissingMaintenanceReservation;
    const exact = try countJson(full, maximum_snapshot_bytes);
    const request_actual = try countJson(full.request_authority, maximum_snapshot_bytes);
    const mutation_actual = try countJson(full.mutation_authority, maximum_snapshot_bytes);
    const native_actual = if (comptime @hasField(@TypeOf(full), "native_owner_authority")) try countJson(full.native_owner_authority, maximum_snapshot_bytes) else 0;
    if (request_actual > request_reserved or mutation_actual > mutation_reserved or native_actual > native_reserved) return error.InvalidSnapshotReservation;
    if (request_actual > exact or mutation_actual > exact - request_actual) return error.InvalidSnapshotReservation;
    if (native_actual > exact - request_actual - mutation_actual) return error.InvalidSnapshotReservation;
    const nonledger = exact - request_actual - mutation_actual - native_actual;
    const future = try totals(full.snapshot_admission);
    try checkCardinality(full, future.counts);
    // Moving bytes between a scalar and its remaining maintenance obligation
    // can widen this field at a decimal boundary. Its widest admissible value
    // is the physical envelope limit; prepay that actual encoding as well.
    if (maintenance > maximum_snapshot_bytes) return error.SnapshotTooLarge;
    const maintenance_metadata_growth = (try countJson(maximum_snapshot_bytes, maximum_snapshot_bytes)) - (try countJson(maintenance, maximum_snapshot_bytes));
    var reserved = nonledger;
    for ([_]usize{ request_reserved, mutation_reserved, native_reserved, future.bytes, future.metadata_growth, maintenance, maintenance_metadata_growth }) |part| {
        if (part > maximum_snapshot_bytes - reserved) return error.SnapshotTooLarge;
        reserved += part;
    }
    return .{
        .exact_snapshot_bytes = exact,
        .nonledger_bytes = nonledger,
        .reserved_bytes = reserved,
        .credits_bytes = future.bytes,
        .credit_metadata_growth_bytes = future.metadata_growth,
        .maintenance_growth_bytes = maintenance,
        .maintenance_metadata_growth_bytes = maintenance_metadata_growth,
        .native_ledger_reserved_bytes = native_reserved,
        .counts_reserved = future.counts,
        .remaining_bytes = maximum_snapshot_bytes - reserved,
    };
}

pub const Ledger = struct {
    allocator: std.mem.Allocator,
    credits: std.ArrayList(Credit) = .empty,
    future_bytes: usize = 0,
    future_counts: Counts = .{},

    pub fn init(allocator: std.mem.Allocator) Ledger {
        return .{ .allocator = allocator };
    }
    pub fn deinit(self: *Ledger) void {
        self.credits.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn snapshot(self: *const Ledger) Snapshot {
        // Borrowed view: rebuild the complete candidate after every ledger
        // mutation. Reserve/release may reallocate or change slice length.
        return .{ .credits = self.credits.items };
    }
    pub fn futureGrowthBytes(self: *const Ledger) usize {
        return self.future_bytes;
    }
    pub fn countsRemaining(self: *const Ledger) Counts {
        return self.future_counts;
    }
    fn index(self: *const Ledger, key: Key) ?usize {
        for (self.credits.items, 0..) |credit, i| if (sameKey(credit.key, key)) return i;
        return null;
    }
    pub fn lookup(self: *const Ledger, key: Key) ?*const Credit {
        return if (self.index(key)) |i| &self.credits.items[i] else null;
    }
    /// Reversible staging only: the caller must check/persist the entire
    /// candidate before I/O. Duplicate admission never authorizes another effect.
    pub fn reserve(self: *Ledger, key: Key, bytes: usize) !void {
        return self.reserveWithCounts(key, bytes, .{});
    }
    pub fn reserveWithCounts(self: *Ledger, key: Key, bytes: usize, counts: Counts) !void {
        try validateKey(key);
        if (bytes == 0) return error.InvalidSnapshotCredit;
        if (self.index(key)) |i| {
            return if (self.credits.items[i].bytes == bytes and std.meta.eql(self.credits.items[i].counts, counts)) error.DuplicateSnapshotCredit else error.SnapshotCreditConflict;
        }
        if (self.credits.items.len == maximum_credits or bytes > maximum_snapshot_bytes - self.future_bytes) return error.SnapshotTooLarge;
        const future_counts = try addCounts(self.future_counts, counts);
        try self.credits.append(self.allocator, .{ .key = key, .bytes = bytes, .counts = counts });
        self.future_bytes += bytes;
        self.future_counts = future_counts;
    }
    /// Debit only growth belonging to this original owner, in the same commit
    /// as that bounded intermediate outcome. Zero remaining bytes retain custody.
    pub fn consume(self: *Ledger, key: Key, bytes: usize) !void {
        return self.consumeWithCounts(key, bytes, .{});
    }
    pub fn consumeWithCounts(self: *Ledger, key: Key, bytes: usize, counts: Counts) !void {
        const i = self.index(key) orelse return error.UnknownSnapshotCredit;
        if (bytes > self.credits.items[i].bytes) return error.SnapshotCreditExceeded;
        inline for (@typeInfo(Counts).@"struct".field_names) |name| {
            if (@field(counts, name) > @field(self.credits.items[i].counts, name)) return error.SnapshotCreditExceeded;
        }
        self.credits.items[i].bytes -= bytes;
        self.future_bytes -= bytes;
        inline for (@typeInfo(Counts).@"struct".field_names) |name| {
            @field(self.credits.items[i].counts, name) -= @field(counts, name);
            @field(self.future_counts, name) -= @field(counts, name);
        }
    }
    /// Call only while preparing an atomic terminal outcome or a cancellation
    /// fence that rejects every delayed completion. Never call merely on timeout.
    pub fn release(self: *Ledger, key: Key) !void {
        const i = self.index(key) orelse return error.UnknownSnapshotCredit;
        self.future_bytes -= self.credits.items[i].bytes;
        inline for (@typeInfo(Counts).@"struct".field_names) |name| @field(self.future_counts, name) -= @field(self.credits.items[i].counts, name);
        _ = self.credits.orderedRemove(i);
    }
    pub fn markIndeterminate(self: *Ledger, key: Key) !void {
        const i = self.index(key) orelse return error.UnknownSnapshotCredit;
        self.credits.items[i].state = .indeterminate;
    }
    pub fn recoverAfterRestart(self: *Ledger) void {
        for (self.credits.items) |*credit| credit.state = .indeterminate;
    }
    /// Restore only through the validated private metadata/recovery boundary.
    /// The selected FileAuthority v2 additionally binds exact metadata bytes
    /// and SQL revision; the owner must separately reconcile
    /// every credit with original mutation/request/import authority and plan;
    /// this structural restore never infers an obligation from legacy state.
    pub fn fromSnapshot(allocator: std.mem.Allocator, saved: Snapshot) !Ledger {
        const future = try totals(saved);
        for (saved.credits, 0..) |credit, i| {
            for (saved.credits[0..i]) |previous| if (sameKey(credit.key, previous.key)) return error.InvalidSnapshotAdmission;
        }
        var self = init(allocator);
        errdefer self.deinit();
        try self.credits.appendSlice(allocator, saved.credits);
        self.future_bytes = future.bytes;
        self.future_counts = future.counts;
        return self;
    }
};

const TestEnvelope = struct {
    schema_version: u32 = 2,
    maintenance_growth_bytes: usize = 0,
    padding: []const u8 = "",
    state: struct {
        sources: []const u8 = "",
        accounts: []const struct { source_ids: []const []const u8 = &.{} } = &.{},
        grants: []const u8 = "",
        observations: []const u8 = "",
        bindings: []const u8 = "",
        leases: []const u8 = "",
        tombstones: []const u8 = "",
        quarantined_imports: []const u8 = "",
        jobs: []const u8 = "",
    } = .{},
    source_descriptions: []const u8 = "",
    request_authority: struct { records: []const u8 = "" } = .{},
    mutation_authority: struct { version: u32 = 1, count: usize = 0 } = .{},
    snapshot_admission: Snapshot = .{},
};
const test_key: Key = .{ .kind = .import, .id = @splat(0x51), .generation = 1 };

test "actual bounded JSON counting matches escaped slices arrays and maximum integer widths" {
    const value = .{
        .text = "quote\" slash\\ newline\n utf8\xc3\xa9",
        .invalid_utf8 = [_]u8{ 0xff, 0, 10, 99, 100 },
        .zero_padding = [_]u8{ 0, 0, 0 },
        .maximum = std.math.maxInt(u64),
        .minimum = std.math.minInt(i64),
        .optional = @as(?u64, null),
    };
    const serialized = try std.json.Stringify.valueAlloc(std.testing.allocator, value, .{});
    defer std.testing.allocator.free(serialized);
    try std.testing.expectEqual(serialized.len, try countJson(value, serialized.len));
    try std.testing.expectError(error.SnapshotTooLarge, countJson(value, serialized.len - 1));
    try std.testing.expectError(error.SnapshotTooLarge, countJson(null, 0));
}

test "whole envelope reaches the real sixteen MiB limit and rejects the next byte" {
    const padding = try std.testing.allocator.alloc(u8, maximum_snapshot_bytes);
    defer std.testing.allocator.free(padding);
    @memset(padding, 'a');
    var candidate: TestEnvelope = .{};
    const empty = try checkEnvelope(candidate, 256, 128);
    candidate.padding = padding[0..empty.remaining_bytes];
    const full = try checkEnvelope(candidate, 256, 128);
    try std.testing.expectEqual(maximum_snapshot_bytes, full.reserved_bytes);
    try std.testing.expectEqual(@as(usize, 0), full.remaining_bytes);
    candidate.padding = padding[0 .. empty.remaining_bytes + 1];
    try std.testing.expectError(error.SnapshotTooLarge, checkEnvelope(candidate, 256, 128));
    try std.testing.expectError(error.InvalidSnapshotReservation, checkEnvelope(TestEnvelope{}, 1, 128));
}

test "maintenance obligation is prepaid at saturation and cannot default from missing state" {
    const padding = try std.testing.allocator.alloc(u8, maximum_snapshot_bytes);
    defer std.testing.allocator.free(padding);
    @memset(padding, 'a');
    var candidate: TestEnvelope = .{ .maintenance_growth_bytes = 4096 };
    const initial = try checkEnvelope(candidate, 256, 128);
    candidate.padding = padding[0..initial.remaining_bytes];
    const admitted = try checkEnvelope(candidate, 256, 128);
    try std.testing.expectEqual(maximum_snapshot_bytes, admitted.reserved_bytes);
    try std.testing.expectEqual(@as(usize, 4096), admitted.maintenance_growth_bytes);
    candidate.maintenance_growth_bytes += 1;
    try std.testing.expectError(error.SnapshotTooLarge, checkEnvelope(candidate, 256, 128));
    const missing = .{
        .state = candidate.state,
        .source_descriptions = candidate.source_descriptions,
        .request_authority = candidate.request_authority,
        .mutation_authority = candidate.mutation_authority,
        .snapshot_admission = candidate.snapshot_admission,
    };
    try std.testing.expectError(error.MissingMaintenanceReservation, checkEnvelope(missing, 256, 128));
    const unknown = .{
        .maintenance_growth_bytes = @as(?usize, null),
        .state = candidate.state,
        .source_descriptions = candidate.source_descriptions,
        .request_authority = candidate.request_authority,
        .mutation_authority = candidate.mutation_authority,
        .snapshot_admission = candidate.snapshot_admission,
    };
    try std.testing.expectError(error.MissingMaintenanceReservation, checkEnvelope(unknown, 256, 128));
}

test "maintenance field width is prepaid when a scalar shrink replenishes its reserve" {
    const padding = try std.testing.allocator.alloc(u8, maximum_snapshot_bytes);
    defer std.testing.allocator.free(padding);
    @memset(padding, 'a');
    var candidate: TestEnvelope = .{ .maintenance_growth_bytes = 999 };
    const initial = try checkEnvelope(candidate, 256, 128);
    candidate.padding = padding[0..initial.remaining_bytes];
    const before = try checkEnvelope(candidate, 256, 128);
    try std.testing.expectEqual(maximum_snapshot_bytes, before.reserved_bytes);
    // One scalar/padding byte disappears and becomes a future obligation.
    // The reserve value's new fourth digit uses its prepaid metadata byte.
    candidate.padding = padding[0 .. initial.remaining_bytes - 1];
    candidate.maintenance_growth_bytes = 1000;
    const after = try checkEnvelope(candidate, 256, 128);
    try std.testing.expectEqual(maximum_snapshot_bytes, after.reserved_bytes);
    try std.testing.expectEqual(before.exact_snapshot_bytes, after.exact_snapshot_bytes);
    try std.testing.expectEqual(before.maintenance_metadata_growth_bytes - 1, after.maintenance_metadata_growth_bytes);
    // The inverse transition also preserves the complete promised footprint.
    candidate.padding = padding[0..initial.remaining_bytes];
    candidate.maintenance_growth_bytes = 999;
    const inverse = try checkEnvelope(candidate, 256, 128);
    try std.testing.expectEqual(before.reserved_bytes, inverse.reserved_bytes);
    candidate.padding = padding[0 .. initial.remaining_bytes + 1];
    try std.testing.expectError(error.SnapshotTooLarge, checkEnvelope(candidate, 256, 128));
}

test "held credit protects completion from unrelated growth and survives restart uncertainty" {
    var ledger = Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    try ledger.reserve(test_key, 1024);
    const padding = try std.testing.allocator.alloc(u8, maximum_snapshot_bytes);
    defer std.testing.allocator.free(padding);
    @memset(padding, 'a');
    var candidate: TestEnvelope = .{ .snapshot_admission = ledger.snapshot() };
    const initial = try checkEnvelope(candidate, 256, 128);
    candidate.padding = padding[0..initial.remaining_bytes];
    _ = try checkEnvelope(candidate, 256, 128);
    candidate.padding = padding[0 .. initial.remaining_bytes + 1];
    try std.testing.expectError(error.SnapshotTooLarge, checkEnvelope(candidate, 256, 128));
    candidate.padding = padding[0..initial.remaining_bytes];
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, ledger.snapshot(), .{});
    defer std.testing.allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(Snapshot, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    var restarted = try Ledger.fromSnapshot(std.testing.allocator, parsed.value);
    defer restarted.deinit();
    restarted.recoverAfterRestart();
    candidate.snapshot_admission = restarted.snapshot();
    const recovered = try checkEnvelope(candidate, 256, 128);
    try std.testing.expectEqual(@as(usize, 1024), recovered.credits_bytes);
    try std.testing.expectEqual(maximum_snapshot_bytes, recovered.reserved_bytes);
    try std.testing.expectEqual(State.indeterminate, restarted.lookup(test_key).?.state);
    try restarted.consume(test_key, 512);
    candidate.padding = padding[0 .. initial.remaining_bytes + 512];
    candidate.snapshot_admission = restarted.snapshot();
    _ = try checkEnvelope(candidate, 256, 128);
    try restarted.release(test_key);
    candidate.padding = padding[0 .. initial.remaining_bytes + 1024];
    candidate.snapshot_admission = restarted.snapshot();
    _ = try checkEnvelope(candidate, 256, 128);
    try std.testing.expectEqual(@as(usize, 0), restarted.futureGrowthBytes());
}

test "credit restoration rejects collisions invalid keys versions and overcommit" {
    const credit: Credit = .{ .key = test_key, .bytes = 1 };
    try std.testing.expectError(error.InvalidSnapshotAdmission, Ledger.fromSnapshot(std.testing.allocator, .{ .version = 2 }));
    try std.testing.expectError(error.InvalidSnapshotAdmission, Ledger.fromSnapshot(std.testing.allocator, .{ .credits = &.{ credit, credit } }));
    try std.testing.expectError(error.InvalidSnapshotCredit, Ledger.fromSnapshot(std.testing.allocator, .{ .credits = &.{.{ .key = .{ .kind = .request, .id = @splat(0), .generation = 1 }, .bytes = 1 }} }));
    var other = credit;
    other.key.generation += 1;
    other.bytes = maximum_snapshot_bytes;
    try std.testing.expectError(error.InvalidSnapshotAdmission, Ledger.fromSnapshot(std.testing.allocator, .{ .credits = &.{ credit, other } }));
    var ledger = Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    try ledger.reserve(test_key, 7);
    try std.testing.expectError(error.DuplicateSnapshotCredit, ledger.reserve(test_key, 7));
    try std.testing.expectError(error.SnapshotCreditConflict, ledger.reserve(test_key, 8));
    try std.testing.expectError(error.SnapshotCreditExceeded, ledger.consume(test_key, 8));
    try std.testing.expectEqual(@as(usize, 7), ledger.futureGrowthBytes());
    try ledger.consume(test_key, 7);
    try std.testing.expect(ledger.lookup(test_key) != null);
    var copied = try Ledger.fromSnapshot(std.testing.allocator, ledger.snapshot());
    defer copied.deinit();
    copied.recoverAfterRestart();
    try std.testing.expect(copied.lookup(test_key) != null);
    try std.testing.expectEqual(@as(usize, 0), copied.futureGrowthBytes());
}

test "outstanding cardinality protects imports from unrelated writers and restores exactly" {
    var ledger = Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    try ledger.reserveWithCounts(test_key, 1024, .{ .accounts = 1, .grants = 1, .observations = 100, .source_links = 1 });
    const rows: [maximum_domain_records]u8 = @splat('a');
    var candidate: TestEnvelope = .{ .snapshot_admission = ledger.snapshot() };
    candidate.state.observations = rows[0 .. maximum_domain_records - 100];
    const held = try checkEnvelope(candidate, 256, 128);
    try std.testing.expectEqual(@as(usize, 100), held.counts_reserved.observations);
    candidate.state.observations = rows[0 .. maximum_domain_records - 99];
    try std.testing.expectError(error.SnapshotCardinalityExceeded, checkEnvelope(candidate, 256, 128));
    var restored = try Ledger.fromSnapshot(std.testing.allocator, ledger.snapshot());
    defer restored.deinit();
    restored.recoverAfterRestart();
    try std.testing.expectEqual(@as(usize, 100), restored.countsRemaining().observations);
    try std.testing.expectError(error.SnapshotCreditExceeded, restored.consumeWithCounts(test_key, 1, .{ .observations = 101 }));
    try std.testing.expectEqual(@as(usize, 1024), restored.futureGrowthBytes());
    try std.testing.expectEqual(@as(usize, 100), restored.countsRemaining().observations);
    try restored.consumeWithCounts(test_key, 512, .{ .observations = 50 });
    candidate.state.observations = rows[0 .. maximum_domain_records - 50];
    candidate.snapshot_admission = restored.snapshot();
    _ = try checkEnvelope(candidate, 256, 128);
    try restored.release(test_key);
    candidate.state.observations = &rows;
    candidate.snapshot_admission = restored.snapshot();
    _ = try checkEnvelope(candidate, 256, 128);
}

test "unknown identity source links preserve every bounded account association" {
    var ledger = Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    try ledger.reserveWithCounts(test_key, 32, .{ .source_links = 1 });
    const sources: [maximum_account_sources][]const u8 = @splat("source");
    var candidate: TestEnvelope = .{ .snapshot_admission = ledger.snapshot() };
    candidate.state.accounts = &.{.{ .source_ids = sources[0 .. maximum_account_sources - 1] }};
    _ = try checkEnvelope(candidate, 256, 128);
    candidate.state.accounts = &.{.{ .source_ids = &sources }};
    try std.testing.expectError(error.SnapshotCardinalityExceeded, checkEnvelope(candidate, 256, 128));
    try ledger.release(test_key);
    candidate.snapshot_admission = ledger.snapshot();
    _ = try checkEnvelope(candidate, 256, 128);
    const bad: Credit = .{ .key = test_key, .bytes = 1, .counts = .{ .observations = maximum_domain_records + 1 } };
    try std.testing.expectError(error.SnapshotCardinalityExceeded, Ledger.fromSnapshot(std.testing.allocator, .{ .credits = &.{bad} }));
}
