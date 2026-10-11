//! Helper contract tests only. No production writer is wired by these tests,
//! and an in-memory completed record does not prove its SQLite commit occurred.
const std = @import("std");
const mutation = @import("mutation_authority.zig");
const witness = @import("reliability_lifecycle_witness.zig");
const admission = @import("snapshot_admission.zig");
const allocator = std.testing.allocator;
const io = std.testing.io;

test "lifecycle helper captures one original same-process terminal observation and leaves waits unknown" {
    var ledger = try mutation.Ledger.init(allocator, 2);
    defer ledger.deinit();
    const slot = (try ledger.begin("generated-original", witness.method, @splat(8), 7, 7, .external)).execute;
    var session = try witness.Session.begin(io, ledger.data.records[slot], .{});
    try std.testing.expectError(error.NonterminalLifecycleAuthority, session.afterCommitted(io, allocator, ledger.data.records[slot], 8));
    try ledger.complete(slot, "{\"disconnected\":true}");
    const fact = try session.afterCommitted(io, allocator, ledger.data.records[slot], 8);
    try std.testing.expect(fact.elapsed.ns != null);
    try std.testing.expect(fact.local_work.ns == null and fact.user_provider_wait.ns == null);
    try std.testing.expect(!fact.user_end_to_end_measured and !fact.complete_user_demand_denominator and !fact.application_provenance_measured and !fact.achieved_slo);
    try std.testing.expectEqual(@as(u64, 8), fact.outcome_revision);
    try std.testing.expectError(error.LifecycleMeasurementAlreadyCaptured, session.afterCommitted(io, allocator, ledger.data.records[slot], 9));
    try std.testing.expectEqualStrings("{\"disconnected\":true}", ledger.data.records[slot].result);
}

test "lifecycle witness rejects unrelated retired optimistic and changed original authority" {
    var ledger = try mutation.Ledger.init(allocator, 2);
    defer ledger.deinit();
    const slot = (try ledger.begin("generated-original", witness.method, @splat(8), 7, 7, .external)).execute;
    var session = try witness.Session.begin(io, ledger.data.records[slot], .{});
    try ledger.markIndeterminate(slot);
    try std.testing.expectError(error.NonterminalLifecycleAuthority, session.afterCommitted(io, allocator, ledger.data.records[slot], 8));
    const other = (try ledger.begin("generated-other", witness.method, @splat(8), 7, 7, .external)).execute;
    try ledger.complete(other, "{\"disconnected\":true}");
    try std.testing.expectError(error.LifecycleAuthorityMismatch, session.afterCommitted(io, allocator, ledger.data.records[other], 8));
    var unrelated = ledger.data.records[other];
    unrelated.kind = .local_atomic;
    try std.testing.expectError(error.InvalidLifecycleAuthority, witness.anchor(unrelated));
    try std.testing.expectError(error.NonstartedLifecycleAuthority, witness.Session.begin(io, ledger.data.records[other], .{}));
}

test "lifecycle source outcome shape cannot promote false duplicate or extra facts" {
    const invalid = [_][]const u8{ "{\"disconnected\":false}", "{\"disconnected\":true,\"success\":true}", "{\"disconnected\":true,\"disconnected\":true}", "{\"disconnected\":1}", "{}" };
    for (invalid) |bytes| {
        var ledger = try mutation.Ledger.init(allocator, 1);
        defer ledger.deinit();
        const slot = (try ledger.begin("generated-original", witness.method, @splat(8), 7, 7, .external)).execute;
        var session = try witness.Session.begin(io, ledger.data.records[slot], .{});
        try ledger.complete(slot, bytes);
        try std.testing.expectError(error.InvalidLifecycleOutcome, session.afterCommitted(io, allocator, ledger.data.records[slot], 8));
    }
}

test "lifecycle witness restoration preserves original result revision without recreating missing coverage" {
    var ledger = try mutation.Ledger.init(allocator, 1);
    defer ledger.deinit();
    const slot = (try ledger.begin("generated-original", witness.method, @splat(8), 7, 7, .external)).execute;
    var session = try witness.Session.begin(io, ledger.data.records[slot], .{});
    try ledger.complete(slot, "{\"disconnected\":true}");
    const fact = try session.afterCommitted(io, allocator, ledger.data.records[slot], 8);
    const bytes = try std.json.Stringify.valueAlloc(allocator, fact, .{});
    defer allocator.free(bytes);
    const parsed = try witness.read(allocator, bytes);
    defer parsed.deinit();
    try parsed.value.validateForRecord(allocator, ledger.data.records[slot], 9);
    try std.testing.expectEqual(@as(u64, 8), parsed.value.outcome_revision);
    try std.testing.expectError(error.LifecycleAuthorityMismatch, parsed.value.validateForRecord(allocator, ledger.data.records[slot], 7));
    var changed = ledger.data.records[slot];
    changed.fingerprint[0] ^= 1;
    try std.testing.expectError(error.LifecycleAuthorityMismatch, parsed.value.validateForRecord(allocator, changed, 9));
    var optimistic = parsed.value;
    optimistic.user_provider_wait = .{ .ns = 0, .missing = null };
    try std.testing.expectError(error.InvalidLifecycleWitness, optimistic.validate());
    optimistic = parsed.value;
    optimistic.provenance.status = .verified_deployment;
    try std.testing.expectError(error.InvalidLifecycleProvenance, optimistic.validate());
    var missing = parsed.value;
    missing.elapsed = .{ .missing = .original_process_lost };
    try missing.validateForRecord(allocator, ledger.data.records[slot], 9);
    const measured = try admission.countJson(parsed.value, admission.maximum_snapshot_bytes);
    const unknown = try admission.countJson(missing, admission.maximum_snapshot_bytes);
    const bound = try witness.maximumSerializedBytes();
    try std.testing.expect(measured <= bound and unknown <= bound);
}

test "lifecycle persisted witness omission cannot inherit optimistic typed defaults" {
    var ledger = try mutation.Ledger.init(allocator, 1);
    defer ledger.deinit();
    const request_start = std.Io.Clock.awake.now(io);
    const slot = (try ledger.begin("generated-original", witness.method, @splat(8), 7, 7, .external)).execute;
    var legacy_session = try witness.Session.begin(io, ledger.data.records[slot], .{});
    var owned_session = try witness.Session.beginOwnedRequest(io, ledger.data.records[slot], .{}, request_start);
    try ledger.complete(slot, "{\"disconnected\":true}");
    const facts = [_]witness.Witness{
        try legacy_session.afterCommitted(io, allocator, ledger.data.records[slot], 8),
        try owned_session.afterCommitted(io, allocator, ledger.data.records[slot], 8),
    };
    for (facts) |fact| {
        const encoded = try std.json.Stringify.valueAlloc(allocator, fact, .{});
        defer allocator.free(encoded);
        inline for (@typeInfo(witness.Witness).@"struct".field_names) |name| {
            var shape = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{ .allocate = .alloc_always });
            defer shape.deinit();
            try std.testing.expect(shape.value.object.swapRemove(name));
            const missing = try std.json.Stringify.valueAlloc(allocator, shape.value, .{});
            defer allocator.free(missing);
            if (fact.schema_version == 1 and std.mem.eql(u8, name, "daemon_request_elapsed")) {
                const accepted = try witness.read(allocator, missing);
                defer accepted.deinit();
                try std.testing.expectEqualDeep(witness.Duration{}, accepted.value.daemon_request_elapsed);
                try std.testing.expectEqualDeep(fact, accepted.value);
            } else try std.testing.expectError(error.InvalidLifecycleWitness, witness.read(allocator, missing));
        }
        inline for (.{ "elapsed", "local_work", "user_provider_wait", "daemon_request_elapsed" }) |name| {
            inline for (.{ "ns", "missing" }) |field| {
                var shape = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{ .allocate = .alloc_always });
                defer shape.deinit();
                const duration = shape.value.object.getPtr(name).?;
                try std.testing.expect(duration.object.swapRemove(field));
                const missing = try std.json.Stringify.valueAlloc(allocator, shape.value, .{});
                defer allocator.free(missing);
                try std.testing.expectError(error.InvalidLifecycleWitness, witness.read(allocator, missing));
            }
        }
    }
}

test "lifecycle legal escaped digest and widest counters fit exact optional field reservation" {
    const digests = [_][32]u8{ @splat(1), @splat(255), @splat('\\') };
    const bound = try witness.maximumSerializedBytes();
    const field_bound = try witness.maximumAddedFieldBytes();
    for (digests) |digest| {
        const fact: witness.Witness = .{ .anchor = .{ .operation_digest = digest, .expected_revision = std.math.maxInt(u64) - 1 }, .result_sha256 = digest, .outcome_revision = std.math.maxInt(u64), .observed_at_utc_s = std.math.maxInt(i64), .elapsed = .{ .ns = std.math.maxInt(u64), .missing = null }, .provenance = .{ .status = .verified_deployment, .artifact_sha256 = digest, .source_commit = @as([40]u8, @splat('f')), .os = .linux, .architecture = .x86_64, .channel = .development } };
        try fact.validate();
        const actual = try admission.countJson(fact, admission.maximum_snapshot_bytes);
        try std.testing.expect(actual <= bound);
        const ordinary_field = try admission.countJson(.{ .prior = @as(u64, 1) }, admission.maximum_snapshot_bytes);
        const expanded = try admission.countJson(.{ .prior = @as(u64, 1), .lifecycle_witness = fact }, admission.maximum_snapshot_bytes);
        try std.testing.expect(expanded - ordinary_field <= field_bound);
    }
}

test "existing ledger prepays witness restore requires authenticated revision and telemetry cleanup cannot erase a captured fact" {
    var ledger = try mutation.Ledger.init(allocator, 2);
    defer ledger.deinit();
    const slot = (try ledger.begin("generated-original", witness.method, @splat(8), 7, 7, .external)).execute;
    const before = ledger.reservedSnapshotBytes();
    try std.testing.expect(try ledger.tryReserveLifecycleWitness(slot));
    try std.testing.expectEqual(before + try witness.maximumSerializedBytes() - "null".len, ledger.reservedSnapshotBytes());
    var session = try witness.Session.begin(io, ledger.data.records[slot], .{});
    try ledger.complete(slot, "{\"disconnected\":true}");
    const fact = try session.afterCommitted(io, allocator, ledger.data.records[slot], 8);
    try ledger.setLifecycleWitnessOnce(slot, fact, 8);
    const actual = try admission.countJson(ledger.snapshot(), admission.maximum_snapshot_bytes);
    try std.testing.expect(actual <= ledger.reservedSnapshotBytes());
    try std.testing.expectError(error.LifecycleMeasurementAlreadyCaptured, ledger.abandonLifecycleWitness(slot));
    try std.testing.expectError(error.LifecycleRevisionRequired, mutation.Ledger.fromSnapshot(allocator, ledger.snapshot()));
    try std.testing.expectError(error.LifecycleAuthorityMismatch, mutation.Ledger.fromSnapshotAtRevision(allocator, ledger.snapshot(), 7));
    var restored = try mutation.Ledger.fromSnapshotAtRevision(allocator, ledger.snapshot(), 9);
    defer restored.deinit();
    restored.recoverAfterRestart();
    try std.testing.expectEqualDeep(fact, restored.data.records[slot].lifecycle_witness.?);
    try std.testing.expectEqualStrings(ledger.data.records[slot].result, (try restored.begin("generated-original", witness.method, @splat(8), 7, 9, .external)).replay);
    const unknown = (try ledger.begin("generated-unknown", witness.method, @splat(8), 9, 9, .external)).execute;
    try std.testing.expect(try ledger.tryReserveLifecycleWitness(unknown));
    const retained = ledger.reservedSnapshotBytes();
    ledger.recoverAfterRestart();
    try std.testing.expectEqual(mutation.State.indeterminate, ledger.data.records[unknown].state);
    try std.testing.expect(ledger.data.records[unknown].lifecycle_witness == null);
    try std.testing.expect(!ledger.data.records[unknown].lifecycle_witness_reserved);
    try std.testing.expectEqual(retained - (try witness.maximumSerializedBytes() - "null".len), ledger.reservedSnapshotBytes());
}

test "owned daemon request producer captures real clock subinterval and preserves unknown external waits" {
    var ledger = try mutation.Ledger.init(allocator, 1);
    defer ledger.deinit();
    const request_start = std.Io.Clock.awake.now(io);
    const slot = (try ledger.begin("owned-request", witness.method, @splat(8), 7, 7, .external)).execute;
    var session = try witness.Session.beginOwnedRequest(io, ledger.data.records[slot], .{}, request_start);
    try ledger.complete(slot, "{\"disconnected\":true}");
    const fact = try session.afterCommitted(io, allocator, ledger.data.records[slot], 8);
    try std.testing.expectEqual(@as(u8, 2), fact.schema_version);
    try std.testing.expect(fact.local_work.ns != null and fact.daemon_request_elapsed.ns != null);
    try std.testing.expect(fact.local_work.ns.? <= fact.daemon_request_elapsed.ns.?);
    try std.testing.expect(fact.user_provider_wait.ns == null and !fact.user_end_to_end_measured);
    const encoded = try std.json.Stringify.valueAlloc(allocator, fact, .{});
    defer allocator.free(encoded);
    const restored = try witness.read(allocator, encoded);
    defer restored.deinit();
    try std.testing.expectEqualDeep(fact, restored.value);
    var invalid = fact;
    invalid.local_work = .{ .ns = std.math.maxInt(u64), .missing = null };
    invalid.elapsed = invalid.local_work;
    invalid.daemon_request_elapsed = .{ .ns = 0, .missing = null };
    try std.testing.expectError(error.InvalidLifecycleWitness, invalid.validate());
    invalid = fact;
    invalid.user_provider_wait = .{ .ns = 0, .missing = null };
    try std.testing.expectError(error.InvalidLifecycleWitness, invalid.validate());
}

test "historical raw schema1 preserves absent request timing and schema2 requires it" {
    var ledger = try mutation.Ledger.init(allocator, 1);
    defer ledger.deinit();
    const slot = (try ledger.begin("legacy-request", witness.method, @splat(8), 7, 7, .external)).execute;
    var session = try witness.Session.begin(io, ledger.data.records[slot], .{});
    try ledger.complete(slot, "{\"disconnected\":true}");
    const fact = try session.afterCommitted(io, allocator, ledger.data.records[slot], 8);
    const bytes = try std.json.Stringify.valueAlloc(allocator, fact, .{});
    defer allocator.free(bytes);
    var shape = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always });
    defer shape.deinit();
    try std.testing.expect(shape.value.object.swapRemove("daemon_request_elapsed"));
    const historical = try std.json.Stringify.valueAlloc(allocator, shape.value, .{});
    defer allocator.free(historical);
    const restored = try witness.read(allocator, historical);
    defer restored.deinit();
    try std.testing.expect(restored.value.daemon_request_elapsed.ns == null);
    shape.value.object.getPtr("schema_version").?.* = .{ .integer = 2 };
    const incomplete = try std.json.Stringify.valueAlloc(allocator, shape.value, .{});
    defer allocator.free(incomplete);
    try std.testing.expectError(error.InvalidLifecycleWitness, witness.read(allocator, incomplete));
}
