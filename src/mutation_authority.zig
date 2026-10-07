//! Bounded mutation deduplication authority. JSON-RPC correlation IDs never
//! enter this ledger. The daemon supplies an HMAC of normalized intent using
//! its private fingerprint key; plaintext intent is never retained here.
//! Single owner only. Persist started before external effects. Local atomic
//! effects and completion must commit in one database transaction/snapshot.
//! Only an audited redacted control-result serializer may call complete;
//! credential materialization responses MUST NOT be cached in this ledger.
const std = @import("std");
const lifecycle_witness = @import("reliability_lifecycle_witness.zig");
const native_removal_witness = @import("reliability_lifecycle_native_removal_witness.zig");
const snapshot_admission = @import("snapshot_admission.zig");

pub const max_records = 4096;
pub const max_id_bytes = 64;
pub const max_method_bytes = 64;
pub const max_result_bytes = 1024;
/// Reserve completion space before an external effect. No result shape is
/// supplied at begin, so every record must accommodate its largest legal result
/// after JSON escaping. Other persisted sections need independent owner bounds.
pub const maximum_snapshot_bytes = 6 * 1024 * 1024;
const maximum_record_metadata_bytes = 1536;
pub const maximum_record_snapshot_bytes = maximum_record_metadata_bytes + 2 * "null".len + max_result_bytes * 6 + 2;
const snapshot_overhead = 128;
pub const Kind = enum { local_atomic, external };
pub const State = enum { started, completed, indeterminate };
pub const Begin = union(enum) { execute: usize, replay: []const u8, indeterminate: void };

pub const Record = struct {
    id: [max_id_bytes]u8 = @splat(0),
    id_len: usize = 0,
    method: [max_method_bytes]u8 = @splat(0),
    method_len: usize = 0,
    fingerprint: [32]u8 = @splat(0),
    expected_revision: u64 = 0,
    kind: Kind = .local_atomic,
    state: State = .started,
    result: []u8 = &.{},
    result_len: usize = 0,
    /// Optional measurement promise, never execution/replay authority. The
    /// original cached result stays immutable when measurement is appended.
    lifecycle_witness_reserved: bool = false,
    lifecycle_witness: ?lifecycle_witness.Witness = null,
    native_removal_witness_reserved: bool = false,
    native_removal_witness: ?native_removal_witness.Witness = null,
};

pub const Snapshot = struct {
    version: u32 = 1,
    count: usize = 0,
    capacity: usize = max_records,
    records: []const Record = &.{},
};

pub const Ledger = struct {
    allocator: std.mem.Allocator,
    data: struct { count: usize = 0, records: []Record },
    reserved_snapshot_bytes: usize = snapshot_overhead,
    witness_ceiling: usize,
    native_witness_ceiling: usize,

    pub fn init(allocator: std.mem.Allocator, record_capacity: usize) !Ledger {
        if (record_capacity == 0 or record_capacity > max_records) return error.InvalidMutationCapacity;
        const records = try allocator.alloc(Record, record_capacity);
        errdefer allocator.free(records);
        @memset(records, .{});
        return .{ .allocator = allocator, .data = .{ .records = records }, .witness_ceiling = try lifecycle_witness.maximumSerializedBytes(), .native_witness_ceiling = try native_removal_witness.maximumSerializedBytes() };
    }

    pub fn deinit(self: *Ledger) void {
        for (self.data.records[0..self.data.count]) |record| self.allocator.free(record.result);
        self.allocator.free(self.data.records);
        self.* = undefined;
    }

    pub fn capacity(self: *const Ledger) usize {
        return self.data.records.len;
    }
    pub fn remainingCapacity(self: *const Ledger) usize {
        return self.capacity() - self.data.count;
    }
    pub fn reservedSnapshotBytes(self: *const Ledger) usize {
        return self.reserved_snapshot_bytes;
    }
    pub fn remainingSnapshotBytes(self: *const Ledger) usize {
        return maximum_snapshot_bytes - self.reservedSnapshotBytes();
    }
    /// IDs and bytes are separate bounds. Existing replay remains available
    /// after either is exhausted; neither expiry nor completion retires IDs.
    /// This is a conservative guarantee for unknown future intents; begin can
    /// admit a smaller known record even when this guarantee reaches zero.
    pub fn remainingAdmissionCapacity(self: *const Ledger) usize {
        return @min(self.remainingCapacity(), self.remainingSnapshotBytes() / maximum_record_snapshot_bytes);
    }

    pub fn lookup(self: *const Ledger, id: []const u8) !?*const Record {
        if (!validId(id)) return error.InvalidOperationId;
        for (self.data.records[0..self.data.count]) |*record| {
            if (std.mem.eql(u8, record.id[0..record.id_len], id)) return record;
        }
        return null;
    }

    pub fn begin(self: *Ledger, id: []const u8, method: []const u8, fingerprint: [32]u8, expected_revision: ?u64, current_revision: u64, kind: Kind) !Begin {
        if (!validId(id)) return error.InvalidOperationId;
        if (!validMethod(method)) return error.InvalidMutationMethod;
        const revision = expected_revision orelse return error.ExpectedRevisionRequired;
        for (self.data.records[0..self.data.count]) |*record| {
            if (!std.mem.eql(u8, record.id[0..record.id_len], id)) continue;
            if (!std.mem.eql(u8, record.method[0..record.method_len], method) or
                !std.mem.eql(u8, &record.fingerprint, &fingerprint) or
                record.expected_revision != revision or record.kind != kind)
                return error.OperationIdConflict;
            return switch (record.state) {
                .completed => .{ .replay = record.result[0..record.result_len] },
                .started, .indeterminate => .indeterminate,
            };
        }
        if (revision != current_revision) return error.StaleRevision;
        const slot = self.data.count;
        var record: Record = .{ .id_len = id.len, .method_len = method.len, .fingerprint = fingerprint, .expected_revision = revision, .kind = kind };
        @memcpy(record.id[0..id.len], id);
        @memcpy(record.method[0..method.len], method);
        const reservation = try recordReservation(record, self.witness_ceiling, self.native_witness_ceiling);
        if (self.remainingCapacity() == 0 or reservation > self.remainingSnapshotBytes()) return error.ServiceBusy;
        self.data.records[slot] = record;
        self.data.count += 1;
        self.reserved_snapshot_bytes += reservation;
        return .{ .execute = slot };
    }

    pub fn complete(self: *Ledger, slot: usize, redacted_result: []const u8) !void {
        if (slot >= self.data.count) return error.UnknownOperation;
        if (redacted_result.len > max_result_bytes) return error.ResultTooLarge;
        const record = &self.data.records[slot];
        if (record.state != .started) return error.OperationNotStarted;
        // Allocation failure leaves the started authority unchanged, so its
        // owner can durably fence uncertainty without accepting a partial result.
        record.result = try self.allocator.dupe(u8, redacted_result);
        record.result_len = redacted_result.len;
        record.state = .completed;
        // Completion never retires authority. Its immutable cached bytes let
        // us release only the unused future-result reservation after allocation.
        self.reserved_snapshot_bytes -= max_result_bytes * 6 + 2 - stringReservation(redacted_result);
    }

    pub fn markIndeterminate(self: *Ledger, slot: usize) !void {
        if (slot >= self.data.count) return error.UnknownOperation;
        if (self.data.records[slot].state != .started) return error.OperationNotStarted;
        self.data.records[slot].state = .indeterminate;
    }

    /// Lack of optional telemetry headroom does not block a source removal.
    /// The actor also tests this promise against the entire persisted envelope
    /// before the first effect and cancels it there if that shared budget fails.
    pub fn tryReserveLifecycleWitness(self: *Ledger, slot: usize) !bool {
        if (slot >= self.data.count) return error.UnknownOperation;
        const record = &self.data.records[slot];
        _ = try lifecycle_witness.anchor(record.*);
        if (record.state != .started or record.lifecycle_witness != null) return error.OperationNotStarted;
        if (record.lifecycle_witness_reserved) return true;
        const additional = self.witness_ceiling - "null".len;
        if (additional > self.remainingSnapshotBytes()) return false;
        record.lifecycle_witness_reserved = true;
        self.reserved_snapshot_bytes += additional;
        return true;
    }

    /// Drop only measurement capacity; original operation state, ID, intent,
    /// result and credential effects are never changed by this method.
    pub fn abandonLifecycleWitness(self: *Ledger, slot: usize) !void {
        if (slot >= self.data.count) return error.UnknownOperation;
        const record = &self.data.records[slot];
        if (record.lifecycle_witness != null) return error.LifecycleMeasurementAlreadyCaptured;
        const before = try recordReservation(record.*, self.witness_ceiling, self.native_witness_ceiling);
        record.lifecycle_witness_reserved = false;
        self.reserved_snapshot_bytes -= before - try recordReservation(record.*, self.witness_ceiling, self.native_witness_ceiling);
    }

    pub fn setLifecycleWitnessOnce(self: *Ledger, slot: usize, fact: lifecycle_witness.Witness, current_revision: u64) !void {
        if (slot >= self.data.count) return error.UnknownOperation;
        const record = &self.data.records[slot];
        if (record.lifecycle_witness != null) return error.LifecycleMeasurementAlreadyCaptured;
        if (!record.lifecycle_witness_reserved) return error.LifecycleMeasurementNotReserved;
        try fact.validateForRecord(self.allocator, record.*, current_revision);
        const before = try recordReservation(record.*, self.witness_ceiling, self.native_witness_ceiling);
        record.lifecycle_witness = fact;
        record.lifecycle_witness_reserved = false;
        const after = recordReservation(record.*, self.witness_ceiling, self.native_witness_ceiling) catch |err| {
            record.lifecycle_witness = null;
            record.lifecycle_witness_reserved = true;
            return err;
        };
        if (after > before) {
            record.lifecycle_witness = null;
            record.lifecycle_witness_reserved = true;
            return error.LifecycleMeasurementReservationExceeded;
        }
        self.reserved_snapshot_bytes -= before - after;
    }

    /// Borrowed view, valid only until ledger mutation/deinit. Serialize it
    /// Lack of optional telemetry headroom does not block a source removal.
    /// The actor also tests this promise against the entire persisted envelope
    /// before the first effect and cancels it there if that shared budget fails.
    pub fn tryReserveNativeRemovalWitness(self: *Ledger, slot: usize) !bool {
        if (slot >= self.data.count) return error.UnknownOperation;
        const record = &self.data.records[slot];
        _ = try native_removal_witness.anchor(record.*);
        if (record.state != .started or record.native_removal_witness != null) return error.OperationNotStarted;
        if (record.native_removal_witness_reserved) return true;
        const additional = self.native_witness_ceiling - "null".len;
        if (additional > self.remainingSnapshotBytes()) return false;
        record.native_removal_witness_reserved = true;
        self.reserved_snapshot_bytes += additional;
        return true;
    }

    /// Drop only measurement capacity; original operation state, ID, intent,
    /// result and credential effects are never changed by this method.
    pub fn abandonNativeRemovalWitness(self: *Ledger, slot: usize) !void {
        if (slot >= self.data.count) return error.UnknownOperation;
        const record = &self.data.records[slot];
        if (record.native_removal_witness != null) return error.LifecycleMeasurementAlreadyCaptured;
        const before = try recordReservation(record.*, self.witness_ceiling, self.native_witness_ceiling);
        record.native_removal_witness_reserved = false;
        self.reserved_snapshot_bytes -= before - try recordReservation(record.*, self.witness_ceiling, self.native_witness_ceiling);
    }

    pub fn setNativeRemovalWitnessOnce(self: *Ledger, slot: usize, fact: native_removal_witness.Witness, current_revision: u64) !void {
        if (slot >= self.data.count) return error.UnknownOperation;
        const record = &self.data.records[slot];
        if (record.native_removal_witness != null) return error.LifecycleMeasurementAlreadyCaptured;
        if (!record.native_removal_witness_reserved) return error.LifecycleMeasurementNotReserved;
        try fact.validateForRecord(self.allocator, record.*, current_revision);
        const before = try recordReservation(record.*, self.witness_ceiling, self.native_witness_ceiling);
        record.native_removal_witness = fact;
        record.native_removal_witness_reserved = false;
        const after = recordReservation(record.*, self.witness_ceiling, self.native_witness_ceiling) catch |err| {
            record.native_removal_witness = null;
            record.native_removal_witness_reserved = true;
            return err;
        };
        if (after > before) {
            record.native_removal_witness = null;
            record.native_removal_witness_reserved = true;
            return error.LifecycleMeasurementReservationExceeded;
        }
        self.reserved_snapshot_bytes -= before - after;
    }

    /// Borrowed view, valid only until ledger mutation/deinit. Serialize it
    /// before performing an effect; it is not a retained independent checkpoint.
    pub fn snapshot(self: *const Ledger) Snapshot {
        return .{ .count = self.data.count, .capacity = self.capacity(), .records = self.data.records[0..self.data.count] };
    }

    /// Decode the typed snapshot only after authenticating its storage envelope.
    /// Restart recovery is explicit, allowing the owner to persist the fence.
    pub fn fromSnapshot(allocator: std.mem.Allocator, value: Snapshot) !Ledger {
        for (value.records) |record| if ((record.lifecycle_witness != null or record.native_removal_witness != null)) return error.LifecycleRevisionRequired;
        return fromSnapshotAtRevision(allocator, value, 0);
    }

    pub fn fromSnapshotAtRevision(allocator: std.mem.Allocator, value: Snapshot, current_revision: u64) !Ledger {
        if (value.version != 1 or value.capacity == 0 or value.capacity > max_records or value.count > value.capacity or value.count != value.records.len) return error.InvalidMutationSnapshot;
        var reserved_bytes: usize = snapshot_overhead;
        const ceiling = try lifecycle_witness.maximumSerializedBytes();
        const native_ceiling = try native_removal_witness.maximumSerializedBytes();
        for (value.records[0..value.count], 0..) |record, index| {
            if (record.id_len > max_id_bytes or record.method_len > max_method_bytes or record.result_len > max_result_bytes or record.result_len != record.result.len) return error.InvalidMutationSnapshot;
            if (!validId(record.id[0..record.id_len]) or !validMethod(record.method[0..record.method_len])) return error.InvalidMutationSnapshot;
            if (record.state != .completed and record.result_len != 0) return error.InvalidMutationSnapshot;
            if (record.lifecycle_witness_reserved) {
                _ = try lifecycle_witness.anchor(record);
                if (record.lifecycle_witness != null) return error.InvalidMutationSnapshot;
            }
            if (record.lifecycle_witness) |fact| try fact.validateForRecord(allocator, record, current_revision);
            if (record.native_removal_witness_reserved) {
                _ = try native_removal_witness.anchor(record);
                if (record.native_removal_witness != null or record.lifecycle_witness != null or record.lifecycle_witness_reserved) return error.InvalidMutationSnapshot;
            }
            if (record.native_removal_witness) |fact| try fact.validateForRecord(allocator, record, current_revision);
            const reservation = try recordReservation(record, ceiling, native_ceiling);
            if (reservation > maximum_snapshot_bytes - reserved_bytes) return error.InvalidMutationSnapshot;
            reserved_bytes += reservation;
            for (value.records[0..index]) |previous| {
                if (std.mem.eql(u8, previous.id[0..previous.id_len], record.id[0..record.id_len])) return error.InvalidMutationSnapshot;
            }
        }
        var ledger = try Ledger.init(allocator, value.capacity);
        errdefer ledger.deinit();
        for (value.records) |record| {
            const result = try allocator.dupe(u8, record.result);
            ledger.data.records[ledger.data.count] = record;
            ledger.data.records[ledger.data.count].result = result;
            ledger.data.count += 1;
        }
        ledger.reserved_snapshot_bytes = reserved_bytes;
        return ledger;
    }

    pub fn recoverAfterRestart(self: *Ledger) void {
        for (self.data.records[0..self.data.count]) |*record| {
            if (record.state == .started) record.state = .indeterminate;
            // No Session is restored. Releasing this optional clock promise
            // does not release or recreate the original effect authority.
            if (record.native_removal_witness_reserved) {
                self.reserved_snapshot_bytes -= self.native_witness_ceiling - "null".len;
                record.native_removal_witness_reserved = false;
            }
            if (record.lifecycle_witness_reserved) {
                self.reserved_snapshot_bytes -= self.witness_ceiling - "null".len;
                record.lifecycle_witness_reserved = false;
            }
        }
    }
};

fn decimalWidth(value: usize) usize {
    var remaining = value;
    var width: usize = 1;
    while (remaining >= 10) : (remaining /= 10) width += 1;
    return width;
}

fn arrayReservation(value: []const u8) usize {
    // The locked default Zig serializer coerces byte arrays to slices: valid
    // UTF-8 uses a JSON string, including initialized zero padding; otherwise
    // it emits the byte values as a numeric array.
    return stringReservation(value);
}

fn stringReservation(value: []const u8) usize {
    if (!std.unicode.utf8ValidateSlice(value)) {
        var bytes: usize = 2;
        for (value) |byte| bytes += decimalWidth(byte) + 1;
        return bytes - @intFromBool(value.len != 0);
    }
    var bytes: usize = 2;
    for (value) |byte| bytes += switch (byte) {
        '"', '\\', '\n', '\r', '\t', 0x08, 0x0c => 2,
        0...7, 0x0b, 0x0e...0x1f, 0x80...0xff => 6,
        else => 1,
    };
    return bytes;
}

fn recordReservation(record: Record, witness_ceiling: usize, native_witness_ceiling: usize) !usize {
    // Fixed field names and longest enum strings; integer lengths reserve the
    // full revision/result widths. Every initialized array byte is accounted.
    const fixed = "{\"id\":,\"id_len\":,\"method\":,\"method_len\":,\"fingerprint\":,\"expected_revision\":,\"kind\":\"local_atomic\",\"state\":\"indeterminate\",\"result\":,\"result_len\":,\"lifecycle_witness_reserved\":false,\"lifecycle_witness\":,\"native_removal_witness_reserved\":false,\"native_removal_witness\":}";
    const metadata = fixed.len + arrayReservation(&record.id) + arrayReservation(&record.method) +
        arrayReservation(&record.fingerprint) + decimalWidth(record.id_len) + decimalWidth(record.method_len) + 20 + 4;
    std.debug.assert(metadata <= maximum_record_metadata_bytes);
    const witness_bytes = if (record.lifecycle_witness_reserved) witness_ceiling else if (record.lifecycle_witness) |fact| try snapshot_admission.countJson(fact, witness_ceiling) else "null".len;
    const native_bytes = if (record.native_removal_witness_reserved) native_witness_ceiling else if (record.native_removal_witness) |fact| try snapshot_admission.countJson(fact, native_witness_ceiling) else "null".len;
    return metadata + witness_bytes + native_bytes + (if (record.state == .completed) stringReservation(record.result) else max_result_bytes * 6 + 2);
}

fn validId(id: []const u8) bool {
    if (id.len == 0 or id.len > max_id_bytes) return false;
    for (id) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return false;
    return true;
}

fn validMethod(method: []const u8) bool {
    if (method.len == 0 or method.len > max_method_bytes) return false;
    for (method) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '.') return false;
    return true;
}

test "duplicate source connect preserves result and performs effect once across restart" {
    var ledger = try Ledger.init(std.testing.allocator, 8);
    defer ledger.deinit();
    var effects: usize = 0;
    const request = try ledger.begin("connect-1", "source.connect", @splat(1), 7, 7, .external);
    const slot = request.execute;
    // Owner persists this snapshot before calling the external source.
    var crash = try Ledger.fromSnapshot(std.testing.allocator, ledger.snapshot());
    defer crash.deinit();
    effects += 1;
    try ledger.complete(slot, "{\"revision\":8,\"source_handle\":\"opaque\"}");
    var restarted = try Ledger.fromSnapshot(std.testing.allocator, ledger.snapshot());
    defer restarted.deinit();
    restarted.recoverAfterRestart();
    const replay = try restarted.begin("connect-1", "source.connect", @splat(1), 7, 8, .external);
    try std.testing.expectEqualStrings("{\"revision\":8,\"source_handle\":\"opaque\"}", replay.replay);
    crash.recoverAfterRestart();
    try std.testing.expect((try crash.begin("connect-1", "source.connect", @splat(1), 7, 7, .external)) == .indeterminate);
    try std.testing.expectEqual(@as(usize, 1), effects);
}

test "revision and intent admission precede effects and IDs pin method and intent" {
    var ledger = try Ledger.init(std.testing.allocator, 8);
    defer ledger.deinit();
    try std.testing.expectError(error.ExpectedRevisionRequired, ledger.begin("op", "pause", @splat(0), null, 2, .local_atomic));
    try std.testing.expectError(error.StaleRevision, ledger.begin("op", "pause", @splat(0), 1, 2, .local_atomic));
    try std.testing.expectEqual(@as(usize, 0), ledger.data.count);
    _ = try ledger.begin("op", "pause", @splat(0), 2, 2, .local_atomic);
    try std.testing.expectError(error.OperationIdConflict, ledger.begin("op", "forget", @splat(0), 2, 2, .local_atomic));
    try std.testing.expectError(error.OperationIdConflict, ledger.begin("op", "pause", @splat(1), 2, 2, .local_atomic));
    try std.testing.expectError(error.OperationIdConflict, ledger.begin("op", "pause", @splat(0), 3, 3, .local_atomic));
}

test "bounded results and saturation never discard active authority" {
    var ledger = try Ledger.init(std.testing.allocator, 8);
    defer ledger.deinit();
    var id_buffer: [64]u8 = undefined;
    for (0..ledger.capacity()) |i| {
        const id = try std.fmt.bufPrint(&id_buffer, "op-{d}", .{i});
        _ = try ledger.begin(id, "pause", @splat(0), 0, 0, .local_atomic);
    }
    try std.testing.expectError(error.ServiceBusy, ledger.begin("overflow", "pause", @splat(0), 0, 0, .local_atomic));
    const oversized: [max_result_bytes + 1]u8 = @splat('x');
    try std.testing.expectError(error.ResultTooLarge, ledger.complete(0, &oversized));
    try std.testing.expectEqual(State.started, ledger.data.records[0].state);
    try std.testing.expectError(error.InvalidOperationId, ledger.begin("bad\nID", "pause", @splat(0), 0, 0, .local_atomic));
}

test "invalid duplicate snapshot records are rejected" {
    var ledger = try Ledger.init(std.testing.allocator, 8);
    defer ledger.deinit();
    _ = try ledger.begin("op", "pause", @splat(0), 0, 0, .local_atomic);
    const records = [_]Record{ ledger.data.records[0], ledger.data.records[0] };
    const corrupt: Snapshot = .{ .count = 2, .capacity = 8, .records = &records };
    try std.testing.expectError(error.InvalidMutationSnapshot, Ledger.fromSnapshot(std.testing.allocator, corrupt));
}

test "local atomic completion survives restart while unfinished authority never reissues" {
    var ledger = try Ledger.init(std.testing.allocator, 8);
    defer ledger.deinit();
    const slot = (try ledger.begin("local", "pause", @splat(2), 4, 4, .local_atomic)).execute;
    try std.testing.expect((try ledger.begin("local", "pause", @splat(2), 4, 4, .local_atomic)) == .indeterminate);
    try ledger.complete(slot, "{\"ok\":true}");
    // The engine commits the local effect and this snapshot together.
    var restored = try Ledger.fromSnapshot(std.testing.allocator, ledger.snapshot());
    defer restored.deinit();
    restored.recoverAfterRestart();
    try std.testing.expectEqualStrings("{\"ok\":true}", (try restored.begin("local", "pause", @splat(2), 4, 5, .local_atomic)).replay);
    try std.testing.expectEqual(State.completed, (try restored.lookup("local")).?.state);
    try std.testing.expect((try restored.lookup("unknown")) == null);
    try std.testing.expectError(error.OperationNotStarted, restored.complete(slot, "different"));
    try std.testing.expectError(error.UnknownOperation, restored.markIndeterminate(max_records));
}

fn allocationRecovery(allocator: std.mem.Allocator) !void {
    var ledger = try Ledger.init(allocator, 4);
    defer ledger.deinit();
    const completed = (try ledger.begin("done", "pause", @splat(1), 2, 2, .local_atomic)).execute;
    ledger.complete(completed, "{\"ok\":true}") catch |err| {
        try std.testing.expectEqual(State.started, ledger.data.records[completed].state);
        try std.testing.expectEqual(@as(usize, 0), ledger.data.records[completed].result.len);
        return err;
    };
    const second = (try ledger.begin("done-second", "pause", @splat(3), 2, 2, .local_atomic)).execute;
    try ledger.complete(second, "{\"ok\":false}");
    _ = try ledger.begin("uncertain", "source.connect", @splat(2), 3, 3, .external);
    var restored = Ledger.fromSnapshot(allocator, ledger.snapshot()) catch |err| {
        // Failed restore leaves the original authority and result intact.
        try std.testing.expectEqual(State.started, (try ledger.lookup("uncertain")).?.state);
        try std.testing.expectEqualStrings("{\"ok\":true}", (try ledger.begin("done", "pause", @splat(1), 2, 3, .local_atomic)).replay);
        return err;
    };
    defer restored.deinit();
    restored.recoverAfterRestart();
    try std.testing.expect((try restored.begin("uncertain", "source.connect", @splat(2), 3, 3, .external)) == .indeterminate);
    try std.testing.expectEqual(@as(usize, 4), restored.capacity());
    try std.testing.expectEqual(@as(usize, 1), restored.remainingCapacity());
}

test "allocation failures never lose completed or uncertain operation authority" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationRecovery, .{});
}

test "configured capacity persists and saturation keeps completed replay available" {
    var ledger = try Ledger.init(std.testing.allocator, 1);
    defer ledger.deinit();
    const slot = (try ledger.begin("last", "pause", @splat(0), 0, 0, .local_atomic)).execute;
    try ledger.complete(slot, "redacted");
    try std.testing.expectError(error.ServiceBusy, ledger.begin("new", "pause", @splat(0), 1, 1, .local_atomic));
    var restored = try Ledger.fromSnapshot(std.testing.allocator, ledger.snapshot());
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 0), restored.remainingCapacity());
    try std.testing.expectEqualStrings("redacted", (try restored.begin("last", "pause", @splat(0), 0, 1, .local_atomic)).replay);
    try std.testing.expectError(error.InvalidMutationCapacity, Ledger.init(std.testing.allocator, max_records + 1));
}

test "byte reservation admits maximum escaped results before effects and preserves replay on restart" {
    var ledger = try Ledger.init(std.testing.allocator, max_records);
    defer ledger.deinit();
    var id_buffer: [64]u8 = undefined;
    try std.testing.expect(ledger.remainingAdmissionCapacity() < max_records);
    const worst_result: [max_result_bytes]u8 = @splat(0);
    var refused = false;
    for (0..max_records) |index| {
        const id = try std.fmt.bufPrint(&id_buffer, "compact-{d}", .{index});
        const admitted = ledger.begin(id, "pause", @splat(0), 0, 0, .local_atomic) catch |err| {
            try std.testing.expectEqual(error.ServiceBusy, err);
            refused = true;
            break;
        };
        const slot = admitted.execute;
        try ledger.complete(slot, &worst_result);
    }
    try std.testing.expect(refused);
    const admission_capacity = ledger.data.count;
    try std.testing.expectEqual(@as(usize, 0), ledger.remainingAdmissionCapacity());
    try std.testing.expect(ledger.remainingCapacity() > 0);
    try std.testing.expectError(error.ServiceBusy, ledger.begin("overflow", "pause", @splat(0), 0, 0, .local_atomic));
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, ledger.snapshot(), .{});
    defer std.testing.allocator.free(json);
    try std.testing.expect(json.len <= ledger.reservedSnapshotBytes());
    try std.testing.expect(ledger.reservedSnapshotBytes() <= maximum_snapshot_bytes);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"result\":[") == null);
    const decoded = try std.json.parseFromSlice(Snapshot, std.testing.allocator, json, .{});
    defer decoded.deinit();
    try std.testing.expectEqual(admission_capacity, decoded.value.records.len);
    for (decoded.value.records) |record| {
        try std.testing.expectEqualSlices(u8, &worst_result, record.result);
        try std.testing.expectEqual(record.result.len, record.result_len);
    }
    var restored = try Ledger.fromSnapshot(std.testing.allocator, decoded.value);
    defer restored.deinit();
    try std.testing.expectEqual(ledger.reservedSnapshotBytes(), restored.reservedSnapshotBytes());
    try std.testing.expectEqualSlices(u8, &worst_result, (try restored.begin("compact-0", "pause", @splat(0), 0, 1, .local_atomic)).replay);
    try std.testing.expectError(error.OperationIdConflict, restored.begin("compact-0", "forget", @splat(0), 0, 1, .local_atomic));
    try std.testing.expectError(error.ServiceBusy, restored.begin("new", "pause", @splat(0), 1, 1, .local_atomic));
}

test "immutable small completions release unused bytes without retiring lifetime IDs" {
    var ledger = try Ledger.init(std.testing.allocator, max_records);
    defer ledger.deinit();
    var id_buffer: [64]u8 = undefined;
    for (0..max_records) |index| {
        const id = try std.fmt.bufPrint(&id_buffer, "small-{d}", .{index});
        const slot = (try ledger.begin(id, "pause", @splat(0), 0, 0, .local_atomic)).execute;
        const reserved = ledger.reservedSnapshotBytes();
        try ledger.complete(slot, "{\"ok\":true}");
        try std.testing.expect(ledger.reservedSnapshotBytes() < reserved);
    }
    try std.testing.expectEqual(@as(usize, 0), ledger.remainingCapacity());
    try std.testing.expect(ledger.remainingSnapshotBytes() > 0);
    try std.testing.expectError(error.ServiceBusy, ledger.begin("new", "pause", @splat(0), 0, 0, .local_atomic));
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, ledger.snapshot(), .{});
    defer std.testing.allocator.free(json);
    try std.testing.expect(json.len <= ledger.reservedSnapshotBytes());
    var restored = try Ledger.fromSnapshot(std.testing.allocator, ledger.snapshot());
    defer restored.deinit();
    restored.recoverAfterRestart();
    try std.testing.expectEqual(ledger.reservedSnapshotBytes(), restored.reservedSnapshotBytes());
    try std.testing.expectEqualStrings("{\"ok\":true}", (try restored.begin("small-4095", "pause", @splat(0), 0, 1, .local_atomic)).replay);
    try std.testing.expectError(error.ServiceBusy, restored.begin("new", "pause", @splat(0), 1, 1, .local_atomic));
}

test "reservation accounts for maximum numeric and initialized metadata widths" {
    var ledger = try Ledger.init(std.testing.allocator, 1);
    defer ledger.deinit();
    const id: [max_id_bytes]u8 = @splat('z');
    const method: [max_method_bytes]u8 = @splat('z');
    const slot = (try ledger.begin(&id, &method, @splat(255), std.math.maxInt(u64), std.math.maxInt(u64), .external)).execute;
    const worst_result: [max_result_bytes]u8 = @splat(0);
    try ledger.complete(slot, &worst_result);
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, ledger.snapshot(), .{});
    defer std.testing.allocator.free(json);
    try std.testing.expect(json.len <= ledger.reservedSnapshotBytes());
}

test "invalid UTF8 result bytes reserve numeric array encoding without weakening replay" {
    var ledger = try Ledger.init(std.testing.allocator, 1);
    defer ledger.deinit();
    const slot = (try ledger.begin("bytes", "pause", @splat(255), 0, 0, .local_atomic)).execute;
    var result: [max_result_bytes]u8 = @splat('x');
    result[0] = 255;
    try ledger.complete(slot, &result);
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, ledger.snapshot(), .{});
    defer std.testing.allocator.free(json);
    try std.testing.expect(json.len <= ledger.reservedSnapshotBytes());
    const parsed = try std.json.parseFromSlice(Snapshot, std.testing.allocator, json, .{});
    defer parsed.deinit();
    var restored = try Ledger.fromSnapshot(std.testing.allocator, parsed.value);
    defer restored.deinit();
    try std.testing.expectEqual(ledger.reservedSnapshotBytes(), restored.reservedSnapshotBytes());
    try std.testing.expectEqualSlices(u8, &result, (try restored.begin("bytes", "pause", @splat(255), 0, 1, .local_atomic)).replay);
}

test "snapshot result length mismatches and noncompleted results reject" {
    var ledger = try Ledger.init(std.testing.allocator, 2);
    defer ledger.deinit();
    const slot = (try ledger.begin("op", "pause", @splat(0), 0, 0, .local_atomic)).execute;
    try ledger.complete(slot, "ok");
    var corrupt = [_]Record{ledger.data.records[slot]};
    corrupt[0].result_len += 1;
    try std.testing.expectError(error.InvalidMutationSnapshot, Ledger.fromSnapshot(std.testing.allocator, .{ .count = 1, .capacity = 2, .records = &corrupt }));
    corrupt[0].result_len = corrupt[0].result.len;
    corrupt[0].state = .started;
    try std.testing.expectError(error.InvalidMutationSnapshot, Ledger.fromSnapshot(std.testing.allocator, .{ .count = 1, .capacity = 2, .records = &corrupt }));
}
