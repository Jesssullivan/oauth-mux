const std = @import("std");
const support = @import("engine_shard_support.zig");
const valid: support.Raw = .{
    .index = "0", .total = "3", .status = "/private/shard-status",
    .outputs = "/private/outputs", .bazel = "1",
    .test_target = support.target, .timeout = "300",
};
const Names = struct {
    allocator: std.mem.Allocator,
    functions: [support.full_count]struct { name: []const u8 },
    fn init(a: std.mem.Allocator) !Names {
        var names: Names = undefined;
        names.allocator = a;
        var initialized: usize = 0;
        errdefer for (names.functions[0..initialized]) |function| a.free(function.name);
        for (&names.functions, 0..) |*function, index| {
            function.name = try std.fmt.allocPrint(a, "engine-shard-model-function-{d}", .{index});
            initialized += 1;
        }
        return names;
    }
    fn deinit(names: *Names) void {
        for (names.functions) |function| names.allocator.free(function.name);
    }
};
test "engine shard admission requires exact complete original geometry and unsupported modes refuse" {
    try std.testing.expect((try support.parse(.{}, false)) == null);
    try std.testing.expectEqual(@as(usize, 0), (try support.parse(valid, true)).?.index);
    try std.testing.expectError(error.UnsupportedEngineShardMode, support.parse(valid, false));
    inline for (.{ "index", "total", "status", "outputs", "bazel", "test_target", "timeout" }) |field| {
        var absent = valid;
        @field(absent, field) = null;
        try std.testing.expectError(error.InvalidEngineShardConfig, support.parse(absent, true));
    }
    for ([_][]const u8{ "", "00", "3", "-1", "1 ", "true" }) |index| {
        var changed = valid;
        changed.index = index;
        try std.testing.expectError(error.InvalidEngineShardConfig, support.parse(changed, true));
    }
    var changed = valid;
    changed.total = "2";
    try std.testing.expectError(error.InvalidEngineShardConfig, support.parse(changed, true));
    changed = valid;
    changed.timeout = "301";
    try std.testing.expectError(error.InvalidEngineShardConfig, support.parse(changed, true));
    changed = valid;
    changed.outputs = "/private/../other";
    try std.testing.expectError(error.InvalidEngineShardPath, support.parse(changed, true));
}
test "engine shard disjoint union covers every actual inventory slot and repeat or foreign completions refuse" {
    var names = try Names.init(std.testing.allocator);
    defer names.deinit();
    var visited: [support.full_count]u8 = @splat(0);
    var digest: ?[32]u8 = null;
    for (0..support.shard_count) |index| {
        const config: support.Config = .{ .index = index, .status = valid.status.?, .outputs = valid.outputs.? };
        var session = try support.Session.begin(config, &names.functions);
        if (digest) |prior| try std.testing.expectEqualDeep(prior, session.inventory) else digest = session.inventory;
        try std.testing.expectEqual(@as(usize, 149), session.count);
        try std.testing.expectError(error.IncompleteEngineShard, session.validateCompleted());
        for (0..support.full_count) |slot| {
            if (support.selected(config, slot)) {
                try session.record(slot, .pass, 0, 0, false, null);
                visited[slot] += 1;
                try std.testing.expectError(error.InvalidEngineShardTransition, session.record(slot, .pass, 0, 0, false, 0));
            } else try std.testing.expectError(error.InvalidEngineShardTransition, session.record(slot, .pass, 0, 0, false, null));
        }
        try session.validateCompleted();
    }
    for (visited) |count| try std.testing.expectEqual(@as(u8, 1), count);
    const duplicate = names.functions[2].name;
    names.functions[2].name = names.functions[1].name;
    defer names.functions[2].name = duplicate;
    try std.testing.expectError(error.InvalidEngineShardInventory, support.Session.begin(.{ .index = 0, .status = valid.status.?, .outputs = valid.outputs.? }, &names.functions));
    try std.testing.expectError(error.InvalidEngineShardInventory, support.Session.begin(.{ .index = 0, .status = valid.status.?, .outputs = valid.outputs.? }, names.functions[0..446]));
}
test "engine shard publishes original failure skip log and leak evidence only after all selected terminals and keeps exclusive custody" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const root = try directory.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const status = try std.fmt.allocPrint(a, "{s}/status", .{root});
    defer a.free(status);
    const config: support.Config = .{ .index = 0, .status = status, .outputs = root };
    try support.acknowledge(io, config);
    try std.testing.expectError(error.PathAlreadyExists, support.acknowledge(io, config));
    var names = try Names.init(a);
    defer names.deinit();
    var session = try support.Session.begin(config, &names.functions);
    try std.testing.expectError(error.IncompleteEngineShard, session.write(io, "0.17.0", 0, 0));
    for (0..support.full_count) |index| if (support.selected(config, index)) {
        try session.record(index, if (index == 0) .fail else if (index == 3) .skip else .pass,
            if (index == 6) 1 else 0, if (index == 9) 1 else 0, false, null);
    };
    try session.write(io, "0.17.0", 1, 1);
    const encoded = try directory.dir.readFileAlloc(io, support.receipt_name, a, .limited(support.receipt_limit));
    defer a.free(encoded);
    const parsed = try std.json.parseFromSlice(std.json.Value, a, encoded, .{});
    defer parsed.deinit();
    const rows = parsed.value.object.get("results").?.array.items;
    try std.testing.expectEqualStrings("fail", rows[0].object.get("status").?.string);
    try std.testing.expectEqualStrings("skip", rows[3].object.get("status").?.string);
    try std.testing.expectEqual(@as(i64, 1), rows[6].object.get("log_errors").?.integer);
    try std.testing.expectEqual(@as(i64, 1), rows[9].object.get("allocator_leaks").?.integer);
    try std.testing.expectError(error.PathAlreadyExists, session.write(io, "0.17.0", 1, 1));
    const unchanged = try directory.dir.readFileAlloc(io, support.receipt_name, a, .limited(support.receipt_limit));
    defer a.free(unchanged);
    try std.testing.expect(std.mem.eql(u8, encoded, unchanged));
}
