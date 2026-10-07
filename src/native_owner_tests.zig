//! R-N13: structural custody and exact admission predicates only. These tests
//! do not prove live peer authentication, native ACKs or seamless continuity.
const std = @import("std");
const native = @import("native_owner.zig");
const admission = @import("snapshot_admission.zig");
const peer = @import("platform/peer.zig");
const requests = @import("request_authority.zig");
const allocator = std.testing.allocator;
const operation: native.OperationId = @splat('a');
const detach: native.OperationId = @splat('b');
const removal: native.OperationId = @splat('c');

fn witness() peer.Witness {
    return .{ .profile = .linux_pidfs64_v1, .boot_id = @splat(1), .pidfs_device = 0, .pidfs_inode = 42, .user_namespace = .{ .device = 0, .inode = 2 }, .pid_namespace = .{ .device = 0, .inode = 3 }, .uid = 42, .gid = 42 };
}
fn owner() native.Owner {
    return .{ .id = @splat(7), .application = "codex", .adapter_epoch = 1, .endpoint_generation = 1, .witness = witness(), .native_nonce = @splat(8), .endpoint_path = "/private/native-owner.sock" };
}
fn reference() native.NativeRef {
    return .{ .owner_id = owner().id, .adapter_epoch = 1, .endpoint_generation = 1, .thread_instance_generation = 1, .attachment_generation = 1 };
}
fn attachment() native.Attachment {
    return .{ .reference = reference(), .thread_id = "native-thread", .registration_operation = operation };
}
const Envelope = struct {
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
    request_authority: struct { version: u32 = 1 } = .{},
    mutation_authority: struct { version: u32 = 1 } = .{},
    native_owner_authority: native.Snapshot = .{},
    snapshot_admission: admission.Snapshot = .{},
};

test "native owner attribution is copied and generations cannot alias another thread" {
    var ledger = native.Ledger.init(allocator);
    defer ledger.deinit();
    var endpoint = "/private/native-owner.sock".*;
    var input = owner();
    input.endpoint_path = &endpoint;
    try ledger.admitOwner(input);
    endpoint[1] = 'x';
    try std.testing.expectEqualStrings(owner().endpoint_path, ledger.lookupOwner(input.id).?.endpoint_path);
    try ledger.admitAttachment(attachment());
    var pending_replacement = attachment();
    pending_replacement.reference.attachment_generation = 2;
    try std.testing.expectError(error.NativeAttachmentPending, ledger.admitAttachment(pending_replacement));
    var alias = attachment();
    alias.thread_id = "another-thread";
    alias.reference.attachment_generation = 2;
    try std.testing.expectError(error.NativeGenerationConflict, ledger.admitAttachment(alias));
    alias.reference.thread_instance_generation = 3;
    try ledger.admitAttachment(alias);
    alias.thread_id = "third-thread";
    alias.reference.thread_instance_generation = 2;
    try std.testing.expectError(error.NativeGenerationConflict, ledger.admitAttachment(alias));
    var replacement = owner();
    replacement.id[0] += 1;
    try std.testing.expectError(error.NativeGenerationConflict, ledger.admitOwner(replacement));
    replacement.endpoint_generation = 2;
    try ledger.admitOwner(replacement);
    try std.testing.expectEqual(@as(usize, 2), ledger.owners.items.len);
    try std.testing.expectEqual(@as(u64, 1), ledger.lookupOwner(input.id).?.endpoint_generation);
}

test "restart retains exact lost ACK operations and cannot infer retirement" {
    var ledger = native.Ledger.init(allocator);
    defer ledger.deinit();
    try ledger.admitOwner(owner());
    try ledger.admitAttachment(attachment());
    const encoded = try std.json.Stringify.valueAlloc(allocator, ledger.snapshot(), .{});
    defer allocator.free(encoded);
    const parsed = try std.json.parseFromSlice(native.Snapshot, allocator, encoded, .{});
    defer parsed.deinit();
    var restored = try native.Ledger.fromSnapshot(allocator, parsed.value);
    defer restored.deinit();
    restored.recoverAfterRestart();
    try std.testing.expectEqual(native.AttachmentPhase.unresolved, restored.lookupAttachment(reference()).?.phase);
    try std.testing.expectEqual(native.UnresolvedFrom.registration, restored.lookupAttachment(reference()).?.unresolved_from);
    try std.testing.expectError(error.NativeOperationMismatch, restored.completeRegistration(reference(), detach));
    try restored.completeRegistration(reference(), operation);
    try restored.beginApplicationRemoval("codex", 1, removal);
    try std.testing.expectError(error.NativeRetirementPending, restored.retireOwner(owner().id, removal));
    try restored.beginDetach(reference(), detach);
    restored.recoverAfterRestart();
    try std.testing.expectEqual(native.UnresolvedFrom.detachment, restored.lookupAttachment(reference()).?.unresolved_from);
    try std.testing.expectError(error.NativeOperationAlreadyPending, restored.beginDetach(reference(), operation));
    try std.testing.expectError(error.NativeOperationMismatch, restored.completeDetach(reference(), operation));
    try std.testing.expect(!restored.removalReady("codex", 1, removal));
    try restored.completeDetach(reference(), detach);
    try restored.retireOwner(owner().id, removal);
    try std.testing.expect(restored.removalReady("codex", 1, removal));
    try restored.completeApplicationRemoval("codex", 1, removal);
    try std.testing.expectEqual(@as(usize, 1), restored.attachments.items.len);
    try std.testing.expectEqual(@as(usize, 1), restored.removals.items.len);
}

test "zero owner application removal is durable and excludes new same epoch owners" {
    var ledger = native.Ledger.init(allocator);
    defer ledger.deinit();
    try std.testing.expect(!ledger.removalReady("codex", 1, removal));
    try ledger.beginApplicationRemoval("codex", 1, removal);
    try std.testing.expectError(error.NativeRemovalPending, ledger.admitOwner(owner()));
    try std.testing.expectError(error.NativeOperationMismatch, ledger.beginApplicationRemoval("codex", 1, detach));
    try ledger.completeApplicationRemoval("codex", 1, removal);
    var restored = try native.Ledger.fromSnapshot(allocator, ledger.snapshot());
    defer restored.deinit();
    try std.testing.expectError(error.NativeRemovalPending, restored.admitOwner(owner()));
    var later = owner();
    later.adapter_epoch = 2;
    try restored.admitOwner(later);
}

test "application removal preserves immutable earlier owner retirement operations" {
    var ledger = native.Ledger.init(allocator);
    defer ledger.deinit();
    try ledger.admitOwner(owner());
    try ledger.beginRemoval(owner().id, detach);
    try ledger.retireOwner(owner().id, detach);
    const original = try std.json.Stringify.valueAlloc(allocator, ledger.lookupOwner(owner().id).?.*, .{});
    defer allocator.free(original);
    var live = owner();
    live.id[0] += 1;
    live.native_nonce[0] += 1;
    try ledger.admitOwner(live);
    try ledger.beginApplicationRemoval("codex", 1, removal);
    const after = try std.json.Stringify.valueAlloc(allocator, ledger.lookupOwner(owner().id).?.*, .{});
    defer allocator.free(after);
    try std.testing.expectEqualStrings(original, after);
    try std.testing.expect(!ledger.removalReady("codex", 1, removal));
    try std.testing.expectError(error.NativeOperationMismatch, ledger.retireOwner(live.id, detach));
    try std.testing.expectError(error.NativeOperationMismatch, ledger.retireOwner(owner().id, removal));
    try ledger.retireOwner(live.id, removal);
    try ledger.completeApplicationRemoval("codex", 1, removal);
    var restored = try native.Ledger.fromSnapshot(allocator, ledger.snapshot());
    defer restored.deinit();
    try std.testing.expect(restored.removalReady("codex", 1, removal));
    try std.testing.expectEqual(detach, restored.lookupOwner(owner().id).?.removal_operation.?);
}

test "only exact no effect registration acknowledgement can retire an unresolved row" {
    var ledger = native.Ledger.init(allocator);
    defer ledger.deinit();
    try ledger.admitOwner(owner());
    try ledger.admitAttachment(attachment());
    const reserved = try ledger.reservedSnapshotBytes();
    ledger.recoverAfterRestart();
    try std.testing.expectError(error.NativeOperationMismatch, ledger.completeRegistrationNoEffect(reference(), detach));
    try std.testing.expectEqual(native.AttachmentPhase.unresolved, ledger.lookupAttachment(reference()).?.phase);
    try ledger.completeRegistrationNoEffect(reference(), operation);
    try std.testing.expectEqual(native.Retirement.verified_registration_no_effect, ledger.lookupAttachment(reference()).?.retirement);
    try std.testing.expect(ledger.lookupAttachment(reference()).?.detach_operation == null);
    try std.testing.expect((try admission.countJson(ledger.snapshot(), admission.maximum_snapshot_bytes)) <= reserved);
    var restored = try native.Ledger.fromSnapshot(allocator, ledger.snapshot());
    defer restored.deinit();
    restored.recoverAfterRestart();
    try std.testing.expectEqual(native.AttachmentPhase.retired, restored.lookupAttachment(reference()).?.phase);
    try std.testing.expectError(error.InvalidNativeTransition, restored.completeRegistration(reference(), operation));
}

test "sealed structural restore rejects foreign references invalid paths and contradictory retirement" {
    var ledger = native.Ledger.init(allocator);
    defer ledger.deinit();
    var unsafe = owner();
    unsafe.endpoint_path = "/private/../native.sock";
    try std.testing.expectError(error.UnsafePath, ledger.admitOwner(unsafe));
    try ledger.admitOwner(owner());
    try ledger.admitAttachment(attachment());
    var foreign = attachment();
    foreign.reference.endpoint_generation = 2;
    try std.testing.expectError(error.NativeOwnerMismatch, native.Ledger.fromSnapshot(allocator, .{ .owners = ledger.owners.items, .attachments = &.{foreign} }));
    var retired = owner();
    retired.phase = .retired;
    retired.removal_operation = removal;
    try std.testing.expectError(error.NativeOwnerMismatch, native.Ledger.fromSnapshot(allocator, .{ .owners = &.{retired}, .attachments = ledger.attachments.items }));
    try std.testing.expectError(error.InvalidNativeOwnerSnapshot, native.Ledger.fromSnapshot(allocator, .{ .owners = ledger.owners.items, .removals = &.{.{ .application = "codex", .adapter_epoch = 1, .operation = removal }} }));
}

test "exact sixteen MiB admission prepays native retirement and cannot use old ledger bypass" {
    var ledger = native.Ledger.init(allocator);
    defer ledger.deinit();
    var wide = owner();
    wide.id = @splat(255);
    wide.native_nonce = @splat(255);
    wide.adapter_epoch = std.math.maxInt(u64);
    wide.endpoint_generation = std.math.maxInt(u64);
    try ledger.admitOwner(wide);
    var row = attachment();
    row.reference.owner_id = wide.id;
    row.reference.adapter_epoch = wide.adapter_epoch;
    row.reference.endpoint_generation = wide.endpoint_generation;
    row.reference.thread_instance_generation = std.math.maxInt(u64);
    row.reference.attachment_generation = std.math.maxInt(u64);
    try ledger.admitAttachment(row);
    const reserved = try ledger.reservedSnapshotBytes();
    var full: Envelope = .{ .native_owner_authority = ledger.snapshot() };
    try std.testing.expectError(error.MissingNativeReservation, admission.checkEnvelope(full, 256, 128));
    const initial = try admission.checkEnvelopeWithNative(full, 256, 128, reserved);
    const padding = try allocator.alloc(u8, initial.remaining_bytes + 1);
    defer allocator.free(padding);
    @memset(padding, 'x');
    full.padding = padding[0..initial.remaining_bytes];
    const saturated = try admission.checkEnvelopeWithNative(full, 256, 128, reserved);
    try std.testing.expectEqual(admission.maximum_snapshot_bytes, saturated.reserved_bytes);
    try ledger.completeRegistration(row.reference, operation);
    try ledger.beginApplicationRemoval("codex", wide.adapter_epoch, removal);
    // A new permanent fence is a fresh admission, not already-owned row growth.
    full.native_owner_authority = ledger.snapshot();
    try std.testing.expectError(error.SnapshotTooLarge, admission.checkEnvelopeWithNative(full, 256, 128, try ledger.reservedSnapshotBytes()));
    try ledger.beginDetach(row.reference, detach);
    ledger.recoverAfterRestart();
    // Remove only this test's newly admitted fence from the measured view.
    var held = ledger.snapshot();
    held.removals = &.{};
    full.native_owner_authority = held;
    try std.testing.expect((try admission.countJson(held, admission.maximum_snapshot_bytes)) <= reserved);
    _ = try admission.checkEnvelopeWithNative(full, 256, 128, reserved);
    try ledger.completeDetach(row.reference, detach);
    try ledger.retireOwner(wide.id, removal);
    held = ledger.snapshot();
    held.removals = &.{};
    full.native_owner_authority = held;
    _ = try admission.checkEnvelopeWithNative(full, 256, 128, reserved);
    full.padding = padding;
    try std.testing.expectError(error.SnapshotTooLarge, admission.checkEnvelopeWithNative(full, 256, 128, reserved));
}

test "native lifetime and outstanding cardinality promises are not freed by retirement" {
    var ledger = native.Ledger.init(allocator);
    defer ledger.deinit();
    var unrelated = owner();
    unrelated.adapter_epoch = std.math.maxInt(u64);
    try ledger.admitOwner(unrelated);
    for (0..native.maximum_attachments) |i| {
        try ledger.beginApplicationRemoval("codex", @intCast(i + 1), removal);
        try ledger.completeApplicationRemoval("codex", @intCast(i + 1), removal);
    }
    try std.testing.expectError(error.NativeAttachmentCapacity, ledger.beginApplicationRemoval("codex", native.maximum_attachments + 1, removal));
    var row = attachment();
    row.reference.adapter_epoch = unrelated.adapter_epoch;
    try std.testing.expectError(error.NativeAttachmentCapacity, ledger.admitAttachment(row));
    var credits = admission.Ledger.init(allocator);
    defer credits.deinit();
    const key: admission.Key = .{ .kind = .native_registration, .id = @splat(1), .generation = 1 };
    try credits.reserveWithCounts(key, 1, .{ .native_authority_records = 1 });
    var full: Envelope = .{ .native_owner_authority = ledger.snapshot(), .snapshot_admission = credits.snapshot() };
    try std.testing.expectError(error.SnapshotCardinalityExceeded, admission.checkEnvelopeWithNative(full, 256, 128, try ledger.reservedSnapshotBytes()));
    var restored = try admission.Ledger.fromSnapshot(allocator, credits.snapshot());
    defer restored.deinit();
    restored.recoverAfterRestart();
    full.snapshot_admission = restored.snapshot();
    try std.testing.expectError(error.SnapshotCardinalityExceeded, admission.checkEnvelopeWithNative(full, 256, 128, try ledger.reservedSnapshotBytes()));
    try std.testing.expectEqual(@as(usize, 1), restored.lookup(key).?.counts.native_authority_records);
}

test "256 lifetime owner identities remain bounded and cannot evict retired rows" {
    var ledger = native.Ledger.init(allocator);
    defer ledger.deinit();
    for (0..native.maximum_owners) |i| {
        var input = owner();
        input.id[0] = @intCast(i & 255);
        input.id[1] = @intCast((i >> 8) + 1);
        input.native_nonce = input.id;
        try ledger.admitOwner(input);
        try ledger.beginRemoval(input.id, removal);
        try ledger.retireOwner(input.id, removal);
    }
    var extra = owner();
    extra.id[0] = 1;
    extra.id[1] = 2;
    extra.native_nonce = extra.id;
    try std.testing.expectError(error.NativeOwnerCapacity, ledger.admitOwner(extra));
    try std.testing.expectEqual(@as(usize, 256), ledger.snapshot().owners.len);
}

test "same process owner incarnation replacement preserves qualified original rows and ACKs" {
    var ledger = native.Ledger.init(allocator);
    defer ledger.deinit();
    var work = requests.Ledger.init(allocator, 8);
    defer work.deinit();
    const original = owner();
    const original_ref = reference();
    const handle: [64]u8 = @splat('1');
    const fingerprint: [64]u8 = @splat('2');
    const intent: requests.Intent = .{ .key = .{ .application = "codex", .session_id = "native-thread", .request_id = "original-model-work" }, .binding_id = "original-binding", .demand_fingerprint = &fingerprint, .native_ref = original_ref };
    try ledger.admitOwner(original);
    try ledger.admitAttachment(attachment());
    var next = original;
    next.adapter_epoch = 2;
    try std.testing.expectError(error.NativeOwnerStillLive, ledger.admitOwner(next));
    try ledger.completeRegistration(original_ref, operation);
    _ = try work.issue(intent, &handle, "fixture-account", 1);
    _ = try work.reportForOwner("codex", &handle, original_ref, .{ .event = .accepted });
    _ = try work.reportForOwner("codex", &handle, original_ref, .{ .event = .completed });
    const work_json = try std.json.Stringify.valueAlloc(allocator, work.snapshot(), .{});
    defer allocator.free(work_json);
    try ledger.beginApplicationRemoval("codex", 1, removal);
    try ledger.beginDetach(original_ref, detach);
    try ledger.completeDetach(original_ref, detach);
    try ledger.retireOwnerForRef(original_ref, removal);
    try ledger.completeApplicationRemoval("codex", 1, removal);
    const original_json = try std.json.Stringify.valueAlloc(allocator, ledger.lookupOwnerForRef(original_ref).?.*, .{});
    defer allocator.free(original_json);
    try ledger.admitOwner(next);
    try std.testing.expect(ledger.lookupOwner(original.id) == null);
    try std.testing.expectEqual(@as(u64, 1), ledger.lookupOwnerForRef(original_ref).?.adapter_epoch);
    try std.testing.expectEqual(@as(u64, 2), ledger.lookupOwnerQualified(original.id, 2, 1).?.adapter_epoch);
    var new_row = attachment();
    new_row.reference.adapter_epoch = 2;
    try ledger.admitAttachment(new_row);
    var changed_work = intent;
    changed_work.native_ref = new_row.reference;
    try std.testing.expectError(error.NativeOwnerMismatch, work.checkIssue(changed_work));
    try std.testing.expectError(error.NativeOwnerMismatch, work.reportForOwner("codex", &handle, new_row.reference, .{ .event = .completed }));
    try std.testing.expect(!try work.reportForOwner("codex", &handle, original_ref, .{ .event = .completed }));
    const after_work = try std.json.Stringify.valueAlloc(allocator, work.snapshot(), .{});
    defer allocator.free(after_work);
    try std.testing.expectEqualStrings(work_json, after_work);
    try std.testing.expectError(error.InvalidNativeTransition, ledger.completeRegistration(original_ref, operation));
    try std.testing.expectError(error.NativeOperationMismatch, ledger.completeDetach(original_ref, removal));
    try std.testing.expectError(error.NativeOwnerAmbiguous, ledger.beginRemoval(original.id, removal));
    try std.testing.expectEqual(native.AttachmentPhase.pending_registration, ledger.lookupAttachment(new_row.reference).?.phase);
    try ledger.completeRegistrationNoEffect(new_row.reference, operation);
    try ledger.beginRemovalForOwner(next.key(), operation);
    try ledger.retireOwnerForOwner(next.key(), operation);
    var endpoint = next;
    endpoint.endpoint_generation = 2;
    try ledger.admitOwner(endpoint);
    try std.testing.expectError(error.NativeOwnerConflict, ledger.admitOwner(original));
    const after_json = try std.json.Stringify.valueAlloc(allocator, ledger.lookupOwnerForRef(original_ref).?.*, .{});
    defer allocator.free(after_json);
    try std.testing.expectEqualStrings(original_json, after_json);
    var restored = try native.Ledger.fromSnapshot(allocator, ledger.snapshot());
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 3), restored.owners.items.len);
    try std.testing.expect(restored.lookupOwner(original.id) == null);
    try std.testing.expectEqual(native.OwnerPhase.open, restored.lookupOwnerQualified(original.id, 2, 2).?.phase);
    try std.testing.expectEqual(native.AttachmentPhase.retired, restored.lookupAttachment(original_ref).?.phase);
    try std.testing.expectError(error.NativeOwnerConflict, restored.admitOwner(endpoint));
}
