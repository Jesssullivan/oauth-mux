//! Optional original source-removal timing, retained on its mutation record.
//! The caller invokes afterCommitted only after the ORIGINAL terminal commit.
//! A later measurement-only commit cannot change its cached result or authorize
//! another effect. A crash without that measurement leaves timing unobserved.
const std = @import("std");
const admission = @import("snapshot_admission.zig");

pub const method = "source.disconnect";
pub const Missing = enum { unobserved, clock_anomaly, duration_out_of_range, original_process_lost };
pub const Duration = struct {
    ns: ?u64 = null,
    missing: ?Missing = .unobserved,
    pub fn validate(self: Duration) !void {
        if ((self.ns == null) == (self.missing == null)) return error.InvalidLifecycleDuration;
    }
};
pub const Provenance = struct {
    status: enum { unknown, verified_deployment } = .unknown,
    artifact_sha256: ?[32]u8 = null,
    source_commit: ?[40]u8 = null,
    os: enum { unknown, linux, macos, other } = .unknown,
    architecture: enum { unknown, x86_64, aarch64, other } = .unknown,
    channel: enum { unknown, development, release } = .unknown,

    /// Structural validation only. The actor must derive verified_deployment
    /// from an actual immutable runtime receipt; caller text is not evidence.
    pub fn validate(self: Provenance) !void {
        if (self.artifact_sha256) |digest| if (std.mem.allEqual(u8, &digest, 0)) return error.InvalidLifecycleProvenance;
        if (self.source_commit) |commit| {
            if (std.mem.allEqual(u8, &commit, '0')) return error.InvalidLifecycleProvenance;
            for (commit) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidLifecycleProvenance;
        }
        if (self.status == .verified_deployment and (self.artifact_sha256 == null or self.source_commit == null or self.os == .unknown or self.architecture == .unknown or self.channel == .unknown)) return error.InvalidLifecycleProvenance;
    }
};
pub const Anchor = struct {
    operation_digest: [32]u8,
    expected_revision: u64,
};
pub const Witness = struct {
    schema_version: u8 = 1,
    scope: enum { actor_admission_to_committed_source_disconnect } = .actor_admission_to_committed_source_disconnect,
    outcome: enum { source_disconnected } = .source_disconnected,
    anchor: Anchor,
    result_sha256: [32]u8,
    /// Revision of the ORIGINAL terminal outcome, not the later snapshot that
    /// optionally contains this measurement. The original reply is unchanged.
    outcome_revision: u64,
    observed_at_utc_s: ?i64,
    elapsed: Duration,
    local_work: Duration = .{},
    user_provider_wait: Duration = .{},
    provenance: Provenance,
    user_end_to_end_measured: bool = false,
    complete_user_demand_denominator: bool = false,
    application_provenance_measured: bool = false,
    achieved_slo: bool = false,

    pub fn validate(self: Witness) !void {
        if (self.schema_version != 1 or self.outcome_revision <= self.anchor.expected_revision or std.mem.allEqual(u8, &self.anchor.operation_digest, 0) or std.mem.allEqual(u8, &self.result_sha256, 0)) return error.InvalidLifecycleWitness;
        if (self.observed_at_utc_s) |utc_s| if (utc_s < 0) return error.InvalidLifecycleWitness;
        try self.elapsed.validate();
        try self.local_work.validate();
        try self.user_provider_wait.validate();
        // No local-work/wait producer is included in this first source slice.
        // Absence cannot be converted to a fabricated zero-duration wait.
        if (self.local_work.ns != null or self.local_work.missing != .unobserved or self.user_provider_wait.ns != null or self.user_provider_wait.missing != .unobserved or self.user_end_to_end_measured or self.complete_user_demand_denominator or self.application_provenance_measured or self.achieved_slo) return error.InvalidLifecycleWitness;
        try self.provenance.validate();
    }

    /// Generic over the actual existing mutation.Record to avoid an import
    /// cycle if that ledger later owns an optional Witness field. No ID set or
    /// parallel mutation ledger is created here.
    pub fn validateForRecord(self: Witness, allocator: std.mem.Allocator, record: anytype, current_revision: u64) !void {
        try self.validate();
        const original = try anchor(record);
        if (!std.mem.eql(u8, &original.operation_digest, &self.anchor.operation_digest) or original.expected_revision != self.anchor.expected_revision or self.outcome_revision > current_revision) return error.LifecycleAuthorityMismatch;
        try requireTerminal(allocator, record);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(record.result, &digest, .{});
        if (!std.mem.eql(u8, &digest, &self.result_sha256)) return error.LifecycleAuthorityMismatch;
    }
};

pub fn anchor(record: anytype) !Anchor {
    if (record.id_len == 0 or record.id_len > 64 or record.method_len != method.len or !std.mem.eql(u8, record.method[0..record.method_len], method) or record.kind != .external or record.result_len != record.result.len or record.result_len > 1024) return error.InvalidLifecycleAuthority;
    for (record.id[0..record.id_len]) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return error.InvalidLifecycleAuthority;
    for (record.id[record.id_len..]) |byte| if (byte != 0) return error.InvalidLifecycleAuthority;
    for (record.method[record.method_len..]) |byte| if (byte != 0) return error.InvalidLifecycleAuthority;
    if (record.state != .completed and record.result_len != 0) return error.InvalidLifecycleAuthority;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("omux.lifecycle.source-disconnect.v1\x00");
    var number: [8]u8 = undefined;
    std.mem.writeInt(u64, &number, @intCast(record.id_len), .little);
    hash.update(&number);
    hash.update(record.id[0..record.id_len]);
    hash.update(&record.fingerprint);
    std.mem.writeInt(u64, &number, record.expected_revision, .little);
    hash.update(&number);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return .{ .operation_digest = digest, .expected_revision = record.expected_revision };
}
pub fn requireTerminal(allocator: std.mem.Allocator, record: anytype) !void {
    if (record.state != .completed) return error.NonterminalLifecycleAuthority;
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, record.result, .{ .duplicate_field_behavior = .@"error", .max_value_len = 1024 }) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidLifecycleOutcome,
    };
    defer parsed.deinit();
    if (parsed.value != .object or parsed.value.object.count() != 1) return error.InvalidLifecycleOutcome;
    const disconnected = parsed.value.object.get("disconnected") orelse return error.InvalidLifecycleOutcome;
    if (disconnected != .bool or !disconnected.bool) return error.InvalidLifecycleOutcome;
}

/// Process-local state only. It cannot be restored from a persisted timestamp,
/// continued after restart, or used to resume the original operation.
pub const Session = struct {
    original: Anchor,
    started: std.Io.Timestamp,
    provenance: Provenance,
    finished: bool = false,

    pub fn begin(io: std.Io, record: anytype, provenance: Provenance) !Session {
        if (record.state != .started) return error.NonstartedLifecycleAuthority;
        try provenance.validate();
        return .{ .original = try anchor(record), .started = std.Io.Clock.awake.now(io), .provenance = provenance };
    }
    pub fn afterCommitted(self: *Session, io: std.Io, allocator: std.mem.Allocator, record: anytype, outcome_revision: u64) !Witness {
        // Capture at entry, immediately after the caller's original commit
        // return. Hashing/parsing below does not enter the measured interval.
        const committed = std.Io.Clock.awake.now(io);
        const utc_s = std.Io.Clock.real.now(io).toSeconds();
        if (self.finished) return error.LifecycleMeasurementAlreadyCaptured;
        const original = try anchor(record);
        if (!std.mem.eql(u8, &original.operation_digest, &self.original.operation_digest)) return error.LifecycleAuthorityMismatch;
        try requireTerminal(allocator, record);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(record.result, &digest, .{});
        const raw = self.started.durationTo(committed).toNanoseconds();
        const duration: Duration = if (raw < 0) .{ .missing = .clock_anomaly } else if (raw > std.math.maxInt(u64)) .{ .missing = .duration_out_of_range } else .{ .ns = @intCast(raw), .missing = null };
        const result: Witness = .{ .anchor = original, .result_sha256 = digest, .outcome_revision = outcome_revision, .observed_at_utc_s = if (utc_s >= 0) utc_s else null, .elapsed = duration, .provenance = self.provenance };
        try result.validateForRecord(allocator, record, outcome_revision);
        self.finished = true;
        return result;
    }
};

fn exactFields(comptime T: type, value: std.json.Value) !void {
    if (value != .object or value.object.count() != @typeInfo(T).@"struct".field_names.len) return error.InvalidLifecycleWitness;
    inline for (@typeInfo(T).@"struct".field_names) |name| if (!value.object.contains(name)) return error.InvalidLifecycleWitness;
}
/// Startup integration must validate the RAW optional ledger field here before
/// default-valued typed snapshot decoding could hide missing persisted facts.
/// Null/absent means missing coverage, not a synthesized witness. This decoder
/// handles an existing nonnull witness only and never captures a new duration.
pub fn read(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(Witness) {
    const maximum = try maximumSerializedBytes();
    if (bytes.len > maximum) return error.InvalidLifecycleWitness;
    const shape = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error", .max_value_len = maximum }) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidLifecycleWitness,
    };
    defer shape.deinit();
    try exactFields(Witness, shape.value);
    try exactFields(Anchor, shape.value.object.get("anchor").?);
    try exactFields(Provenance, shape.value.object.get("provenance").?);
    inline for (.{ "elapsed", "local_work", "user_provider_wait" }) |name| try exactFields(Duration, shape.value.object.get(name).?);
    const parsed = std.json.parseFromValue(Witness, allocator, shape.value, .{ .allocate = .alloc_always }) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidLifecycleWitness,
    };
    errdefer parsed.deinit();
    try parsed.value.validate();
    return parsed;
}

/// Before-effect callers must prepay this legal encoded ceiling as part of the
/// EXISTING record reservation, including its optional field wrapper. Digest
/// byte 0x01 measures the worst valid-UTF8 escaping, not a numeric byte array.
/// This helper measures typed legal variants with the production serializer;
/// it supplies neither an independent budget nor runtime provenance evidence.
pub fn maximumSerializedBytes() !usize {
    var largest: usize = 0;
    const durations = [_]Duration{ .{ .ns = std.math.maxInt(u64), .missing = null }, .{ .missing = .unobserved }, .{ .missing = .clock_anomaly }, .{ .missing = .duration_out_of_range }, .{ .missing = .original_process_lost } };
    inline for (@typeInfo(@FieldType(Provenance, "status")).@"enum".field_names) |status| {
        inline for (@typeInfo(@FieldType(Provenance, "os")).@"enum".field_names) |os| {
            inline for (@typeInfo(@FieldType(Provenance, "architecture")).@"enum".field_names) |architecture| {
                inline for (@typeInfo(@FieldType(Provenance, "channel")).@"enum".field_names) |channel| {
                    const provenance: Provenance = .{ .status = @field(@FieldType(Provenance, "status"), status), .artifact_sha256 = @as([32]u8, @splat(1)), .source_commit = @as([40]u8, @splat('f')), .os = @field(@FieldType(Provenance, "os"), os), .architecture = @field(@FieldType(Provenance, "architecture"), architecture), .channel = @field(@FieldType(Provenance, "channel"), channel) };
                    if (provenance.validate()) |_| {
                        for (durations) |elapsed| {
                            const maximum: Witness = .{ .anchor = .{ .operation_digest = @splat(1), .expected_revision = std.math.maxInt(u64) - 1 }, .result_sha256 = @splat(1), .outcome_revision = std.math.maxInt(u64), .observed_at_utc_s = std.math.maxInt(i64), .elapsed = elapsed, .provenance = provenance };
                            try maximum.validate();
                            largest = @max(largest, try admission.countJson(maximum, admission.maximum_snapshot_bytes));
                        }
                    } else |err| switch (err) {
                        error.InvalidLifecycleProvenance => {},
                    }
                }
            }
        }
    }
    return largest;
}

/// Additional bytes when adding this optional field to an existing nonempty
/// record object. Includes the exact key/colon and comma; callers must not
/// confuse the witness value ceiling with the containing ledger reservation.
pub fn maximumAddedFieldBytes() !usize {
    const null_wrapper = try admission.countJson(.{ .lifecycle_witness = @as(?u8, null) }, admission.maximum_snapshot_bytes);
    return null_wrapper - 2 - "null".len + try maximumSerializedBytes() + 1;
}
