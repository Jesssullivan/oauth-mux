//! Engine-only Bazel shard attribution. Never selects a compiler filter.
//! No tests live in this imported file: the original compiled set stays whole.
const std = @import("std");
const builtin = @import("builtin");
pub const full_count = 447;
pub const shard_count = 3;
pub const receipt_limit = 512 * 1024;
pub const receipt_name = "engine-shard-coverage.json";
pub const target = "//:engine_sharded_test";
pub const Raw = struct {
    index: ?[]const u8 = null,
    total: ?[]const u8 = null,
    status: ?[]const u8 = null,
    outputs: ?[]const u8 = null,
    bazel: ?[]const u8 = null,
    test_target: ?[]const u8 = null,
    timeout: ?[]const u8 = null,
};
pub const Config = struct {
    index: usize,
    status: []const u8,
    outputs: []const u8,
};
fn path(value: []const u8) !void {
    if (value.len == 0 or value.len > 4096 or value[0] != '/' or std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidEngineShardPath;
    var parts = std.mem.splitScalar(u8, value, '/');
    _ = parts.next();
    while (parts.next()) |part| if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidEngineShardPath;
}
pub fn parse(raw: Raw, supported: bool) !?Config {
    if (raw.index == null and raw.total == null and raw.status == null) return null;
    if (!supported) return error.UnsupportedEngineShardMode;
    const index = raw.index orelse return error.InvalidEngineShardConfig;
    const total = raw.total orelse return error.InvalidEngineShardConfig;
    const status = raw.status orelse return error.InvalidEngineShardConfig;
    const outputs = raw.outputs orelse return error.InvalidEngineShardConfig;
    if (!std.mem.eql(u8, total, "3") or index.len != 1 or index[0] < '0' or index[0] > '2' or
        !std.mem.eql(u8, raw.bazel orelse "", "1") or !std.mem.eql(u8, raw.test_target orelse "", target) or
        !std.mem.eql(u8, raw.timeout orelse "", "300")) return error.InvalidEngineShardConfig;
    try path(status);
    try path(outputs);
    return .{ .index = index[0] - '0', .status = status, .outputs = outputs };
}
fn get(env: std.process.Environ, key: []const u8) !?[]const u8 {
    // Qualified target is Linux; other POSIX modes may only forward unsharded.
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi or builtin.os.tag == .emscripten or builtin.os.tag == .freestanding or builtin.os.tag == .other) {
        const value = env.getAlloc(std.heap.page_allocator, key) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => return null,
            else => return err,
        };
        defer std.heap.page_allocator.free(value);
        return error.UnsupportedEngineShardMode;
    } else {
        var result: ?[]const u8 = null;
        for (env.block.view().slice) |entry| {
            const text = std.mem.span(entry);
            if (text.len > key.len and std.mem.startsWith(u8, text, key) and text[key.len] == '=') {
                if (result != null) return error.InvalidEngineShardConfig;
                result = text[key.len + 1 ..];
            }
        }
        return result;
    }
}
pub fn configure(env: std.process.Environ, supported: bool) !?Config {
    const index = try get(env, "TEST_SHARD_INDEX");
    const total = try get(env, "TEST_TOTAL_SHARDS");
    const status = try get(env, "TEST_SHARD_STATUS_FILE");
    if (index == null and total == null and status == null) return null;
    return parse(.{
        .index = index,
        .total = total,
        .status = status,
        .outputs = try get(env, "TEST_UNDECLARED_OUTPUTS_DIR"),
        .bazel = try get(env, "BAZEL_TEST"),
        .test_target = try get(env, "TEST_TARGET"),
        .timeout = try get(env, "TEST_TIMEOUT"),
    }, supported);
}
pub fn selected(config: Config, index: usize) bool {
    return index % shard_count == config.index;
}
pub const Status = enum { unselected, pending, pass, fail, skip };
pub const Result = struct {
    index: usize,
    status: Status,
    log_errors: usize = 0,
    allocator_leaks: usize = 0,
    fuzz: bool = false,
    elapsed_ns: ?u64 = null,
};
pub const Session = struct {
    config: Config,
    names: [full_count][]const u8,
    results: [full_count]Result,
    inventory: [32]u8,
    count: usize = 0,
    pub fn begin(config: Config, functions: anytype) !Session {
        if (functions.len != full_count or config.index >= shard_count) return error.InvalidEngineShardInventory;
        var value: Session = undefined;
        value.config = config;
        value.count = 0;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("omux.engine-test-inventory.v1\x00");
        var number: [4]u8 = undefined;
        std.mem.writeInt(u32, &number, full_count, .little);
        hash.update(&number);
        for (functions, 0..) |function, index| {
            const name = function.name;
            if (name.len == 0 or name.len > 512) return error.InvalidEngineShardInventory;
            for (name) |byte| if (!std.ascii.isPrint(byte)) return error.InvalidEngineShardInventory;
            for (value.names[0..index]) |prior| if (std.mem.eql(u8, prior, name)) return error.InvalidEngineShardInventory;
            value.names[index] = name;
            value.results[index] = .{ .index = index, .status = if (selected(config, index)) .pending else .unselected };
            value.count += @intFromBool(selected(config, index));
            std.mem.writeInt(u32, &number, @intCast(index), .little);
            hash.update(&number);
            std.mem.writeInt(u32, &number, @intCast(name.len), .little);
            hash.update(&number);
            hash.update(name);
        }
        hash.final(&value.inventory);
        return value;
    }
    pub fn record(self: *Session, index: usize, status: Status, log_errors: usize, allocator_leaks: usize, fuzz: bool, elapsed_ns_value: ?u64) !void {
        if (index >= full_count or !selected(self.config, index) or self.results[index].status != .pending or
            (status != .pass and status != .fail and status != .skip)) return error.InvalidEngineShardTransition;
        self.results[index] = .{ .index = index, .status = status, .log_errors = log_errors, .allocator_leaks = allocator_leaks, .fuzz = fuzz, .elapsed_ns = elapsed_ns_value };
    }
    pub fn validateCompleted(self: Session) !void {
        for (self.results, 0..) |result, index| {
            if (result.index != index) return error.InvalidEngineShardTransition;
            if (selected(self.config, index)) {
                if (result.status != .pass and result.status != .fail and result.status != .skip) return error.IncompleteEngineShard;
            } else if (result.status != .unselected or result.log_errors != 0 or result.allocator_leaks != 0 or result.fuzz or result.elapsed_ns != null) return error.InvalidEngineShardTransition;
        }
    }
    pub fn write(self: *const Session, io: std.Io, sdk_version: []const u8, sdk_log_errors: usize, sdk_leaked_tests: usize) !void {
        try self.validateCompleted();
        const digest = std.fmt.bytesToHex(self.inventory, .lower);
        const encoded = try std.json.Stringify.valueAlloc(std.heap.page_allocator, .{
            .schema_version = 1,
            .kind = "omux-engine-test-shard-v1",
            .target = target,
            .full_count = full_count,
            .shard_count = shard_count,
            .shard_index = self.config.index,
            .selected_count = self.count,
            .inventory_sha256 = @as([]const u8, &digest),
            .names = @as([]const []const u8, &self.names),
            .results = @as([]const Result, &self.results),
            .sdk_version = sdk_version,
            .sdk_log_errors = sdk_log_errors,
            .sdk_leaked_tests = sdk_leaked_tests,
            .scope = "fixture-function-execution-and-original-sdk-teardown",
            .user_outcome_measured = false,
        }, .{});
        defer std.heap.page_allocator.free(encoded);
        if (encoded.len > receipt_limit) return error.EngineShardReceiptTooLarge;
        var output = try std.Io.Dir.openDirAbsolute(io, self.config.outputs, .{ .follow_symlinks = false });
        defer output.close(io);
        var file = try output.createFile(io, receipt_name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writeStreamingAll(io, encoded);
        try file.sync(io);
        // Receipt is complete only after every selected test's ORIGINAL IO/
        // allocator teardown returned. The collector retains original failures.
    }
};
pub fn acknowledge(io: std.Io, config: Config) !void {
    // Exact Bazel-provided status file, never an arbitrary caller path. No
    // truncation/overwrite: an appeared file is a configuration failure.
    var file = try std.Io.Dir.createFileAbsolute(io, config.status, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.sync(io);
}
pub fn elapsed(start: std.Io.Timestamp, finish: std.Io.Timestamp) ?u64 {
    const value = start.durationTo(finish).toNanoseconds();
    return if (value < 0 or value > std.math.maxInt(u64)) null else @intCast(value);
}
