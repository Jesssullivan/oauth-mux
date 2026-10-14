//! Local actor/storage predicates only. No provider access or browser export.
const std = @import("std");
const engine = @import("engine.zig");
const control = @import("control.zig");
const allocator = std.testing.allocator;

const Reply = struct {
    bytes: []u8,
    parsed: std.json.Parsed(std.json.Value),
    fn deinit(self: *Reply) void {
        control.wipeJson(self.parsed.value);
        self.parsed.deinit();
        allocator.free(self.bytes);
    }
    fn code(self: *const Reply) ![]const u8 {
        return control.string(control.get(self.parsed.value, "error") orelse return error.ExpectedRefusal, "code");
    }
};
fn dispatch(actor: *engine.Engine, channel: engine.Channel, payload: []const u8) !Reply {
    const bytes = try actor.dispatch(allocator, payload, channel);
    errdefer allocator.free(bytes);
    return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always }) };
}
fn controlCall(actor: *engine.Engine, method: []const u8, params: anytype) !Reply {
    const payload = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = params }, .{});
    defer allocator.free(payload);
    return dispatch(actor, .control, payload);
}
fn browserMessage(method: []const u8, id: []const u8, extension: []const u8, changed: bool) ![]u8 {
    const provenance = .{ .browser = "chromium", .extensionId = extension, .channel = "release" };
    if (std.mem.eql(u8, method, "browser.connect") or std.mem.eql(u8, method, "browser.disconnect") or std.mem.eql(u8, method, "browser.reconcile")) return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = id, .method = method, .params = .{ .sourceId = "opaque-browser-source", .adapter = "codex", .origin = "https://chatgpt.com", .provenance = provenance } }, .{});
    return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = id, .method = method, .params = .{ .sourceId = "opaque-browser-source", .adapter = "codex", .origin = "https://chatgpt.com", .provenance = provenance, .capsule = .{ .changed = changed } } }, .{});
}
fn counts(actor: *engine.Engine) ![3]u64 {
    var reply = try controlCall(actor, "reliability.lifecycle", @as(?u8, null));
    defer reply.deinit();
    const result = control.get(reply.parsed.value, "result") orelse return error.MissingResult;
    try std.testing.expect(!try control.boolean(result, "achieved_slo", true));
    const measurements = control.get(result, "measurements") orelse return error.MissingMeasurements;
    if (measurements == .null) return .{ 0, 0, 0 };
    var total: [3]u64 = .{ 0, 0, 0 };
    for (control.get(measurements, "days").?.array.items) |day| {
        const outcomes = control.get(day, "cells").?.array.items[1].array.items;
        for (&total, 0..) |*value, index| value.* += @intCast(control.get(outcomes[index], "count").?.integer);
        // Every recorded browser refusal has unknown end-to-end timing.
        const refusal_total = control.get(outcomes[1], "total").?;
        try std.testing.expectEqual(control.get(outcomes[1], "count").?.integer, control.get(refusal_total, "missing_latency").?.integer);
    }
    return total;
}
const Fixture = struct {
    directory: std.testing.TmpDir,
    path: [:0]u8,
    actor: ?*engine.Engine,
    fn init() !Fixture {
        var directory = std.testing.tmpDir(.{});
        errdefer directory.cleanup();
        if (std.c.fchmodat(directory.dir.handle, ".", 0o700, 0) != 0) return error.PermissionChangeFailed;
        const path = try directory.dir.realPathFileAlloc(std.testing.io, ".", allocator);
        errdefer allocator.free(path);
        return .{ .directory = directory, .path = path, .actor = try engine.Engine.openWithKey(std.testing.io, allocator, path, @splat(67)) };
    }
    fn restart(self: *Fixture) !void {
        self.actor.?.deinit();
        self.actor = null;
        self.actor = try engine.Engine.openWithKey(std.testing.io, allocator, self.path, @splat(67));
    }
    fn deinit(self: *Fixture) void {
        if (self.actor) |actor| actor.deinit();
        allocator.free(self.path);
        self.directory.cleanup();
    }
    fn connect(self: *Fixture) !void {
        const payload = try browserMessage("browser.connect", "connect-1", "extension-a", false);
        defer allocator.free(payload);
        var reply = try dispatch(self.actor.?, .browser, payload);
        defer reply.deinit();
        try std.testing.expect(control.get(reply.parsed.value, "result") != null);
    }
};

fn outcomeMessage(method: []const u8, id: []const u8, source_id: []const u8, operation_id: []const u8, revision: ?u64, generation: ?u64) ![]u8 {
    const provenance = .{ .browser = "chromium", .extensionId = "extension-a", .channel = "release" };
    const revision_text = if (revision) |value| try std.fmt.allocPrint(allocator, "{d}", .{value}) else null;
    defer if (revision_text) |value| allocator.free(value);
    const generation_text = if (generation) |value| try std.fmt.allocPrint(allocator, "{d}", .{value}) else null;
    defer if (generation_text) |value| allocator.free(value);
    if (generation_text) |value| return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = id, .method = method, .params = .{ .sourceId = source_id, .adapter = "codex", .origin = "https://chatgpt.com", .provenance = provenance, .operationId = operation_id, .expectedRevision = revision_text.?, .expectedGeneration = value } }, .{});
    if (revision_text) |value| return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = id, .method = method, .params = .{ .sourceId = source_id, .adapter = "codex", .origin = "https://chatgpt.com", .provenance = provenance, .operationId = operation_id, .expectedRevision = value } }, .{});
    return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = id, .method = method, .params = .{ .sourceId = source_id, .adapter = "codex", .origin = "https://chatgpt.com", .provenance = provenance, .operationId = operation_id } }, .{});
}

test "browser Connect immutable outcome survives lost reply and restart without changing current authority" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const initial_revision = fixture.actor.?.revision;
    const connect = try outcomeMessage("browser.connect", "correlation-original", "outcome-source", "connect-operation", initial_revision, null);
    defer allocator.free(connect);
    var original = try dispatch(fixture.actor.?, .browser, connect);
    defer original.deinit();
    const receipt = control.get(original.parsed.value, "result") orelse return error.MissingResult;
    try std.testing.expect(try control.boolean(receipt, "accepted", false));
    try std.testing.expectEqualStrings("1", try control.string(receipt, "generation"));
    const original_result = try std.json.Stringify.valueAlloc(allocator, receipt, .{});
    defer allocator.free(original_result);
    // Drop/restart the transport owner after the actual actor commit. No reply
    // replay is needed to learn the immutable original outcome.
    try fixture.restart();
    const actor = fixture.actor.?;
    const query = try outcomeMessage("browser.connectOutcome", "query-after-restart", "outcome-source", "connect-operation", initial_revision, null);
    defer allocator.free(query);
    const snapshot = try std.json.Stringify.valueAlloc(allocator, actor.state.snapshot(), .{});
    defer allocator.free(snapshot);
    const revision = actor.revision;
    const checkpoint = actor.db.?.checkpoint;
    const cohorts = try counts(actor);
    var recovered = try dispatch(actor, .browser, query);
    defer recovered.deinit();
    const outcome = control.get(recovered.parsed.value, "result") orelse return error.MissingResult;
    try std.testing.expectEqualStrings("committed", try control.string(outcome, "outcome"));
    try std.testing.expectEqualStrings("1", try control.string(outcome, "connect_generation"));
    try std.testing.expectEqualStrings("1", try control.string(outcome, "current_generation"));
    try std.testing.expect(try control.boolean(outcome, "authorized", false));
    const exact_retry = try outcomeMessage("browser.connect", "correlation-retry", "outcome-source", "connect-operation", initial_revision, null);
    defer allocator.free(exact_retry);
    var retried = try dispatch(actor, .browser, exact_retry);
    defer retried.deinit();
    const retried_result = try std.json.Stringify.valueAlloc(allocator, control.get(retried.parsed.value, "result").?, .{});
    defer allocator.free(retried_result);
    try std.testing.expectEqualStrings(original_result, retried_result);
    const unchanged = try std.json.Stringify.valueAlloc(allocator, actor.state.snapshot(), .{});
    defer allocator.free(unchanged);
    try std.testing.expectEqualStrings(snapshot, unchanged);
    try std.testing.expectEqual(revision, actor.revision);
    try std.testing.expectEqualDeep(checkpoint, actor.db.?.checkpoint);
    try std.testing.expectEqual(cohorts, try counts(actor));
    const changed = try outcomeMessage("browser.connect", "different-intent", "different-source", "connect-operation", initial_revision, null);
    defer allocator.free(changed);
    var refused = try dispatch(actor, .browser, changed);
    defer refused.deinit();
    try std.testing.expectEqualStrings("OperationIdConflict", try refused.code());
    try std.testing.expectEqual(revision, actor.revision);
    try std.testing.expectEqual(@as(usize, 1), actor.state.sources.items.len);
    const foreign_query = try outcomeMessage("browser.connectOutcome", "foreign-query", "different-source", "connect-operation", initial_revision, null);
    defer allocator.free(foreign_query);
    var foreign = try dispatch(actor, .browser, foreign_query);
    defer foreign.deinit();
    try std.testing.expectEqualStrings("OperationIdConflict", try foreign.code());
    const changed_revision = try outcomeMessage("browser.connectOutcome", "changed-revision", "outcome-source", "connect-operation", initial_revision + 1, null);
    defer allocator.free(changed_revision);
    var changed_intent = try dispatch(actor, .browser, changed_revision);
    defer changed_intent.deinit();
    try std.testing.expectEqualStrings("OperationIdConflict", try changed_intent.code());
    try std.testing.expectEqual(revision, actor.revision);
    try std.testing.expectEqualDeep(checkpoint, actor.db.?.checkpoint);
    try std.testing.expectEqual(cohorts, try counts(actor));
}

test "recovered browser removal is generation bound and its immutable ACK never reactivates or repeats" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const initial_revision = fixture.actor.?.revision;
    const connect = try outcomeMessage("browser.connect", "original-reply-lost", "outcome-source", "original-connect", initial_revision, null);
    defer allocator.free(connect);
    {
        var reply = try dispatch(fixture.actor.?, .browser, connect);
        defer reply.deinit();
        try std.testing.expect(control.get(reply.parsed.value, "result") != null);
    }
    const independent_revision = fixture.actor.?.revision;
    const independent = try outcomeMessage("browser.connect", "independent", "independent-source", "independent-operation", independent_revision, null);
    defer allocator.free(independent);
    {
        var reply = try dispatch(fixture.actor.?, .browser, independent);
        defer reply.deinit();
        try std.testing.expect(control.get(reply.parsed.value, "result") != null);
    }
    const query = try outcomeMessage("browser.connectOutcome", "source-readback", "outcome-source", "original-connect", initial_revision, null);
    defer allocator.free(query);
    {
        var reply = try dispatch(fixture.actor.?, .browser, query);
        defer reply.deinit();
        try std.testing.expectEqualStrings("1", try control.string(control.get(reply.parsed.value, "result").?, "current_generation"));
    }
    const removal = try outcomeMessage("browser.disconnect", "removal-reply-lost", "outcome-source", "removal-operation", fixture.actor.?.revision, 1);
    defer allocator.free(removal);
    var removed = try dispatch(fixture.actor.?, .browser, removal);
    defer removed.deinit();
    const removed_result = try std.json.Stringify.valueAlloc(allocator, control.get(removed.parsed.value, "result").?, .{});
    defer allocator.free(removed_result);
    try fixture.restart();
    const actor = fixture.actor.?;
    const revision = actor.revision;
    const checkpoint = actor.db.?.checkpoint;
    var repeated = try dispatch(actor, .browser, removal);
    defer repeated.deinit();
    const repeated_result = try std.json.Stringify.valueAlloc(allocator, control.get(repeated.parsed.value, "result").?, .{});
    defer allocator.free(repeated_result);
    try std.testing.expectEqualStrings(removed_result, repeated_result);
    var delayed_original = try dispatch(actor, .browser, connect);
    defer delayed_original.deinit();
    try std.testing.expect(control.get(delayed_original.parsed.value, "result") != null);
    try std.testing.expectEqual(@import("domain.zig").SourceStatus.disconnected, actor.state.sources.items[0].status);
    try std.testing.expectEqual(@as(u64, 2), actor.import_sources.items[0].generation);
    try std.testing.expectEqual(@import("domain.zig").SourceStatus.connected, actor.state.sources.items[1].status);
    try std.testing.expectEqual(@as(u64, 1), actor.import_sources.items[1].generation);
    var stale = try dispatch(actor, .browser, query);
    defer stale.deinit();
    const stale_result = control.get(stale.parsed.value, "result").?;
    try std.testing.expectEqualStrings("committed", try control.string(stale_result, "outcome"));
    try std.testing.expectEqualStrings("1", try control.string(stale_result, "connect_generation"));
    try std.testing.expectEqualStrings("2", try control.string(stale_result, "current_generation"));
    try std.testing.expect(!try control.boolean(stale_result, "authorized", true));
    const wrong_generation = try outcomeMessage("browser.disconnect", "stale-removal", "outcome-source", "different-removal", revision, 1);
    defer allocator.free(wrong_generation);
    var refused = try dispatch(actor, .browser, wrong_generation);
    defer refused.deinit();
    try std.testing.expectEqualStrings("GenerationConflict", try refused.code());
    try std.testing.expectEqual(revision, actor.revision);
    try std.testing.expectEqualDeep(checkpoint, actor.db.?.checkpoint);
}

test "original Connect outcome never upgrades detached expired or future current source authority" {
    for ([_][]const u8{ "detach", "expire", "future" }) |transition| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        const initial_revision = fixture.actor.?.revision;
        const connect = try outcomeMessage("browser.connect", "original-connect", "outcome-source", "clock-operation", initial_revision, null);
        defer allocator.free(connect);
        {
            var reply = try dispatch(fixture.actor.?, .browser, connect);
            defer reply.deinit();
            try std.testing.expect(control.get(reply.parsed.value, "result") != null);
        }
        const capability = try fixture.actor.?.capabilityForTest("enrollment");
        const change = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = "fixture.importSource", .params = .{ .application = "enrollment", .capability = capability[0..], .source_id = "outcome-source", .transition = transition } }, .{});
        defer allocator.free(change);
        {
            var reply = try dispatch(fixture.actor.?, .adapter, change);
            defer reply.deinit();
            try std.testing.expect(control.get(reply.parsed.value, "result") != null);
        }
        try fixture.restart();
        const actor = fixture.actor.?;
        const revision = actor.revision;
        const checkpoint = actor.db.?.checkpoint;
        const generation = actor.import_sources.items[0].generation;
        const query = try outcomeMessage("browser.connectOutcome", "read-expired", "outcome-source", "clock-operation", initial_revision, null);
        defer allocator.free(query);
        var result = try dispatch(actor, .browser, query);
        defer result.deinit();
        const metadata = control.get(result.parsed.value, "result").?;
        try std.testing.expectEqualStrings("committed", try control.string(metadata, "outcome"));
        try std.testing.expect(!try control.boolean(metadata, "authorized", true));
        try std.testing.expectEqual(revision, actor.revision);
        try std.testing.expectEqual(generation, actor.import_sources.items[0].generation);
        try std.testing.expectEqualDeep(checkpoint, actor.db.?.checkpoint);
    }
}

test "failed browser Connect transaction exposes no committed receipt and custody-unavailable query stays refused" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const initial_revision = fixture.actor.?.revision;
    const connect = try outcomeMessage("browser.connect", "interrupted-connect", "outcome-source", "interrupted-operation", initial_revision, null);
    defer allocator.free(connect);
    const capability = try fixture.actor.?.capabilityForTest("enrollment");
    const fault = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = "fixture.storageReadOnly", .params = .{ .application = "enrollment", .capability = capability[0..] } }, .{});
    defer allocator.free(fault);
    var armed = try dispatch(fixture.actor.?, .adapter, fault);
    defer armed.deinit();
    var failed = try dispatch(fixture.actor.?, .browser, connect);
    defer failed.deinit();
    _ = try failed.code();
    const query = try outcomeMessage("browser.connectOutcome", "query-unavailable", "outcome-source", "interrupted-operation", initial_revision, null);
    defer allocator.free(query);
    var unavailable = try dispatch(fixture.actor.?, .browser, query);
    defer unavailable.deinit();
    try std.testing.expectEqualStrings("CustodyUnavailable", try unavailable.code());
    try fixture.restart();
    const actor = fixture.actor.?;
    const revision = actor.revision;
    const checkpoint = actor.db.?.checkpoint;
    var unknown = try dispatch(actor, .browser, query);
    defer unknown.deinit();
    try std.testing.expectEqualStrings("unknown", try control.string(control.get(unknown.parsed.value, "result").?, "outcome"));
    try std.testing.expectEqual(@as(usize, 0), actor.state.sources.items.len);
    try std.testing.expectEqual(@as(usize, 0), actor.mutations.snapshot().count);
    try std.testing.expectEqual(revision, actor.revision);
    try std.testing.expectEqualDeep(checkpoint, actor.db.?.checkpoint);
    try std.testing.expectEqual([3]u64{ 0, 0, 0 }, try counts(actor));
}

test "browser refusal authority and counter recover atomically and exact retries do not recount" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.connect();
    const payload = try browserMessage("browser.importGrant", "attempt-1", "extension-a", false);
    defer allocator.free(payload);
    {
        var first = try dispatch(fixture.actor.?, .browser, payload);
        defer first.deinit();
        try std.testing.expectEqualStrings("NeedsProviderAdapterProof", try first.code());
        var retry = try dispatch(fixture.actor.?, .browser, payload);
        defer retry.deinit();
        try std.testing.expectEqualStrings("NeedsProviderAdapterProof", try retry.code());
        try std.testing.expectEqual([3]u64{ 0, 1, 0 }, try counts(fixture.actor.?));
    }
    try fixture.restart();
    var recovered = try dispatch(fixture.actor.?, .browser, payload);
    defer recovered.deinit();
    try std.testing.expectEqualStrings("NeedsProviderAdapterProof", try recovered.code());
    try std.testing.expectEqual([3]u64{ 0, 1, 0 }, try counts(fixture.actor.?));
    const changed = try browserMessage("browser.importGrant", "attempt-1", "extension-a", true);
    defer allocator.free(changed);
    var conflict = try dispatch(fixture.actor.?, .browser, changed);
    defer conflict.deinit();
    try std.testing.expectEqualStrings("BrowserAttemptConflict", try conflict.code());
    const different_context = try browserMessage("browser.importGrant", "attempt-2", "extension-b", false);
    defer allocator.free(different_context);
    var stale = try dispatch(fixture.actor.?, .browser, different_context);
    defer stale.deinit();
    try std.testing.expectEqualStrings("NeedsProviderAdapterProof", try stale.code());
    try std.testing.expectEqual([3]u64{ 0, 1, 0 }, try counts(fixture.actor.?));
}

test "explicit browser disconnect fences a retained import attempt across restart without touching another context" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.connect();
    const independent_payload = try std.json.Stringify.valueAlloc(allocator, .{
        .version = 1,
        .id = "independent-connect",
        .method = "browser.connect",
        .params = .{ .sourceId = "independent-browser-source", .adapter = "codex", .origin = "https://chatgpt.com", .provenance = .{ .browser = "chromium", .extensionId = "extension-a", .channel = "release" } },
    }, .{});
    defer allocator.free(independent_payload);
    {
        var independent = try dispatch(fixture.actor.?, .browser, independent_payload);
        defer independent.deinit();
        try std.testing.expect(control.get(independent.parsed.value, "result") != null);
    }
    const pending = try browserMessage("browser.importGrant", "unobserved-import-ack", "extension-a", false);
    defer allocator.free(pending);
    {
        var original = try dispatch(fixture.actor.?, .browser, pending);
        defer original.deinit();
        try std.testing.expectEqualStrings("NeedsProviderAdapterProof", try original.code());
    }
    const wrong = try browserMessage("browser.disconnect", "wrong-context-removal", "extension-b", false);
    defer allocator.free(wrong);
    {
        var mismatch = try dispatch(fixture.actor.?, .browser, wrong);
        defer mismatch.deinit();
        try std.testing.expectEqualStrings("BrowserContextMismatch", try mismatch.code());
        try std.testing.expectEqual(@import("domain.zig").SourceStatus.connected, fixture.actor.?.state.sources.items[0].status);
    }
    const removal = try browserMessage("browser.disconnect", "fresh-removal-id", "extension-a", false);
    defer allocator.free(removal);
    {
        var removed = try dispatch(fixture.actor.?, .browser, removal);
        defer removed.deinit();
        try std.testing.expect(try control.boolean(control.get(removed.parsed.value, "result").?, "accepted", false));
    }
    try fixture.restart();
    const actor = fixture.actor.?;
    try std.testing.expectEqual(@import("domain.zig").SourceStatus.disconnected, actor.state.sources.items[0].status);
    try std.testing.expectEqual(@import("domain.zig").SourceStatus.connected, actor.state.sources.items[1].status);
    try std.testing.expectEqual(@as(usize, 0), actor.state.grants.items.len);
    const generation = actor.import_sources.items[0].generation;
    try std.testing.expect(generation > 1);
    const before_counts = try counts(actor);
    const revision = actor.revision;
    const checkpoint = actor.db.?.checkpoint;
    {
        var late = try dispatch(actor, .browser, pending);
        defer late.deinit();
        try std.testing.expectEqualStrings("NeedsProviderAdapterProof", try late.code());
    }
    try std.testing.expectEqual(revision, actor.revision);
    try std.testing.expectEqualDeep(checkpoint, actor.db.?.checkpoint);
    try std.testing.expectEqual(before_counts, try counts(actor));
    try std.testing.expectEqual(generation, actor.import_sources.items[0].generation);
    try std.testing.expectEqual(@import("domain.zig").SourceStatus.disconnected, actor.state.sources.items[0].status);
    try std.testing.expectEqual(@import("domain.zig").SourceStatus.connected, actor.state.sources.items[1].status);
}

test "browser reconciliation observes current source authority without reconnecting or mutation" {
    const transitions = [_][]const u8{ "disconnect", "detach", "expire", "future" };
    for (transitions) |transition| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        try fixture.connect();
        const reconcile = try browserMessage("browser.reconcile", "reconcile-current", "extension-a", false);
        defer allocator.free(reconcile);
        {
            var accepted = try dispatch(fixture.actor.?, .browser, reconcile);
            defer accepted.deinit();
            try std.testing.expect(try control.boolean(control.get(accepted.parsed.value, "result").?, "accepted", false));
        }
        if (std.mem.eql(u8, transition, "disconnect")) {
            const payload = try browserMessage("browser.disconnect", "disconnect-current", "extension-a", false);
            defer allocator.free(payload);
            var disconnected = try dispatch(fixture.actor.?, .browser, payload);
            defer disconnected.deinit();
            try std.testing.expect(try control.boolean(control.get(disconnected.parsed.value, "result").?, "accepted", false));
        } else {
            const capability = try fixture.actor.?.capabilityForTest("enrollment");
            const payload = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = "fixture.importSource", .params = .{ .application = "enrollment", .capability = capability[0..], .source_id = "opaque-browser-source", .transition = transition } }, .{});
            defer allocator.free(payload);
            var changed = try dispatch(fixture.actor.?, .adapter, payload);
            defer changed.deinit();
            try std.testing.expect(try control.boolean(control.get(changed.parsed.value, "result").?, "updated", false));
        }
        const snapshot = try std.json.Stringify.valueAlloc(allocator, fixture.actor.?.state.snapshot(), .{});
        defer allocator.free(snapshot);
        const generation = fixture.actor.?.import_sources.items[0].generation;
        for (0..2) |attempt| {
            if (attempt == 1) try fixture.restart();
            const restored = try std.json.Stringify.valueAlloc(allocator, fixture.actor.?.state.snapshot(), .{});
            defer allocator.free(restored);
            try std.testing.expectEqualStrings(snapshot, restored);
            try std.testing.expectEqual(generation, fixture.actor.?.import_sources.items[0].generation);
            // Startup commits recovery before serving requests. Its revision
            // and checkpoint are the baseline for this request's no-write fence.
            const revision = fixture.actor.?.revision;
            const checkpoint = fixture.actor.?.db.?.checkpoint;
            var refused = try dispatch(fixture.actor.?, .browser, reconcile);
            defer refused.deinit();
            try std.testing.expectEqualStrings("SourceUnauthorized", try refused.code());
            const unchanged = try std.json.Stringify.valueAlloc(allocator, fixture.actor.?.state.snapshot(), .{});
            defer allocator.free(unchanged);
            try std.testing.expectEqualStrings(snapshot, unchanged);
            try std.testing.expectEqual(revision, fixture.actor.?.revision);
            try std.testing.expectEqual(generation, fixture.actor.?.import_sources.items[0].generation);
            try std.testing.expectEqualDeep(checkpoint, fixture.actor.?.db.?.checkpoint);
        }
    }
}

test "refusal storage failure cannot retain a counter without durable refusal authority" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.connect();
    const capability = try fixture.actor.?.capabilityForTest("enrollment");
    const fault = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = "fixture.storageReadOnly", .params = .{ .application = "enrollment", .capability = capability[0..] } }, .{});
    defer allocator.free(fault);
    var fault_reply = try dispatch(fixture.actor.?, .adapter, fault);
    defer fault_reply.deinit();
    try std.testing.expect(control.get(fault_reply.parsed.value, "result") != null);
    const payload = try browserMessage("browser.importGrant", "attempt-1", "extension-a", false);
    defer allocator.free(payload);
    var failed = try dispatch(fixture.actor.?, .browser, payload);
    defer failed.deinit();
    _ = try failed.code();
    try fixture.restart();
    try std.testing.expectEqual([3]u64{ 0, 0, 0 }, try counts(fixture.actor.?));
    var fresh = try dispatch(fixture.actor.?, .browser, payload);
    defer fresh.deinit();
    try std.testing.expectEqualStrings("NeedsProviderAdapterProof", try fresh.code());
    try std.testing.expectEqual([3]u64{ 0, 1, 0 }, try counts(fixture.actor.?));
}

test "browser channel fence precedes health mutations and provider refusal accounting" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.connect();
    const actor = fixture.actor.?;
    const revision = actor.revision;
    const checkpoint = actor.db.?.checkpoint;
    const source_count = actor.state.sources.items.len;
    const grant_count = actor.state.grants.items.len;
    const before_counts = try counts(actor);
    const attempts_before = actor.browser_attempts != null;
    const requests = [_][]const u8{
        "{\"version\":1,\"id\":\"wrong-health\",\"method\":\"browser.health\",\"params\":{\"provenance\":{\"browser\":\"chromium\",\"extensionId\":\"extension-a\",\"channel\":\"development\"}}}",
        "{\"version\":1,\"id\":\"wrong-connect\",\"method\":\"browser.connect\",\"params\":{\"sourceId\":\"opaque-browser-source\",\"adapter\":\"codex\",\"origin\":\"https://chatgpt.com\",\"provenance\":{\"browser\":\"chromium\",\"extensionId\":\"extension-a\",\"channel\":\"development\"}}}",
        "{\"version\":1,\"id\":\"wrong-import\",\"method\":\"browser.importGrant\",\"params\":{\"sourceId\":\"opaque-browser-source\",\"adapter\":\"codex\",\"origin\":\"https://chatgpt.com\",\"provenance\":{\"browser\":\"chromium\",\"extensionId\":\"extension-a\",\"channel\":\"development\"},\"capsule\":{}}}",
        "{\"version\":1,\"id\":\"missing-channel\",\"method\":\"browser.importGrant\",\"params\":{\"sourceId\":\"opaque-browser-source\",\"adapter\":\"codex\",\"origin\":\"https://chatgpt.com\",\"provenance\":{\"browser\":\"chromium\",\"extensionId\":\"extension-a\"},\"capsule\":{}}}",
    };
    for (requests, 0..) |payload, index| {
        var reply = try dispatch(actor, .browser, payload);
        defer reply.deinit();
        try std.testing.expectEqualStrings(if (index == 3) "InvalidRequest" else "BrowserChannelMismatch", try reply.code());
        try std.testing.expectEqual(revision, actor.revision);
        try std.testing.expectEqualDeep(checkpoint, actor.db.?.checkpoint);
        try std.testing.expectEqual(source_count, actor.state.sources.items.len);
        try std.testing.expectEqual(grant_count, actor.state.grants.items.len);
        try std.testing.expectEqual(before_counts, try counts(actor));
        try std.testing.expectEqual(attempts_before, actor.browser_attempts != null);
    }
}
