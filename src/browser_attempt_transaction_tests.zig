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
    if (std.mem.eql(u8, method, "browser.connect") or std.mem.eql(u8, method, "browser.disconnect")) return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = id, .method = method, .params = .{ .sourceId = "opaque-browser-source", .adapter = "codex", .origin = "https://chatgpt.com", .provenance = provenance } }, .{});
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
