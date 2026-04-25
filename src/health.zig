const std = @import("std");
const types = @import("types.zig");
const paths = @import("paths.zig");
const log = @import("log.zig");

pub const AccountHealth = struct {
    score: types.HealthScore = .{},
    circuit: types.CircuitState = .closed,
    bucket: types.TokenBucket = .{},
};

pub const HealthStore = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(AccountHealth),
    config: types.HealthConfig,

    pub fn init(allocator: std.mem.Allocator, hc: types.HealthConfig) HealthStore {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(AccountHealth).init(allocator),
            .config = hc,
        };
    }

    pub fn deinit(self: *HealthStore) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.accounts.deinit();
    }

    pub fn getOrCreate(self: *HealthStore, key: []const u8) !*AccountHealth {
        const result = self.accounts.getOrPut(key) catch return error.OutOfMemory;
        if (!result.found_existing) {
            result.key_ptr.* = self.allocator.dupe(u8, key) catch return error.OutOfMemory;
            result.value_ptr.* = .{
                .score = .{ .score = self.config.initial_score },
            };
        }
        return result.value_ptr;
    }

    pub fn recordSuccess(self: *HealthStore, key: []const u8) void {
        const health = self.getOrCreate(key) catch return;
        health.score.score += self.config.success_bonus;
        health.score.successes += 1;
        health.score.clamp();
        health.score.last_updated = std.time.timestamp();

        switch (health.circuit) {
            .half_open => |*ho| {
                ho.successes_so_far += 1;
                if (ho.successes_so_far >= ho.successes_needed) {
                    health.circuit = .closed;
                    log.debug("health: {s} circuit closed", .{key});
                }
            },
            else => {},
        }
    }

    pub fn recordFailure(self: *HealthStore, key: []const u8, kind: FailureKind) void {
        const health = self.getOrCreate(key) catch return;
        const now = std.time.timestamp();

        const penalty = switch (kind) {
            .rate_limited => blk: {
                health.score.rate_limits += 1;
                break :blk self.config.rate_limit_penalty;
            },
            else => blk: {
                health.score.failures += 1;
                break :blk self.config.failure_penalty;
            },
        };
        health.score.score += penalty;
        health.score.clamp();
        health.score.last_updated = now;

        // Check circuit breaker threshold: 3 failures in 60s window
        if (now - health.score.window_start > 60) {
            health.score.window_start = now;
            health.score.failures = 1;
        }
        if (health.score.failures >= 3) {
            health.circuit = .{ .open = .{
                .opened_at = now,
                .failure_count = health.score.failures,
                .retry_at = now + 30,
            } };
            log.debug("health: {s} circuit opened", .{key});
        }

        // Half-open → open on any failure
        switch (health.circuit) {
            .half_open => {
                health.circuit = .{ .open = .{
                    .opened_at = now,
                    .failure_count = health.score.failures,
                    .retry_at = now + 30,
                } };
            },
            else => {},
        }
    }

    pub fn isAvailable(self: *HealthStore, key: []const u8) bool {
        const health = self.getOrCreate(key) catch return true;
        const now = std.time.timestamp();
        const now_ns: i128 = @as(i128, now) * 1_000_000_000;

        switch (health.circuit) {
            .closed => {},
            .open => |oc| {
                if (now >= oc.retry_at) {
                    health.circuit = .{ .half_open = .{
                        .probe_started_at = now,
                    } };
                } else {
                    return false;
                }
            },
            .half_open => {},
        }

        return health.bucket.tryConsume(now_ns);
    }

    pub fn passiveRecovery(self: *HealthStore) void {
        const now = std.time.timestamp();
        var it = self.accounts.valueIterator();
        while (it.next()) |health| {
            if (health.score.last_updated > 0) {
                const elapsed_hours = @divFloor(now - health.score.last_updated, 3600);
                if (elapsed_hours > 0) {
                    health.score.score += self.config.decay_per_hour * @as(i32, @intCast(@min(elapsed_hours, 100)));
                    health.score.clamp();
                }
            }
        }
    }

    pub fn load(allocator: std.mem.Allocator, hc: types.HealthConfig) HealthStore {
        var store = init(allocator, hc);

        const path = paths.healthFilePath(allocator) catch return store;
        defer allocator.free(path);

        const file = std.fs.openFileAbsolute(path, .{}) catch return store;
        defer file.close();

        const bytes = file.readToEndAlloc(allocator, 256 * 1024) catch return store;
        defer allocator.free(bytes);

        const parsed = std.json.parseFromSlice(HealthFile, allocator, bytes, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch return store;
        defer parsed.deinit();

        for (parsed.value.accounts) |entry| {
            const key = allocator.dupe(u8, entry.key) catch continue;
            store.accounts.put(key, .{
                .score = .{
                    .score = entry.score,
                    .successes = entry.successes,
                    .failures = entry.failures,
                    .rate_limits = entry.rate_limits,
                    .last_updated = entry.last_updated,
                },
                .circuit = if (entry.circuit_open) .{ .open = .{
                    .opened_at = entry.last_updated,
                    .failure_count = entry.failures,
                    .retry_at = entry.last_updated + 30,
                } } else .closed,
            }) catch {
                allocator.free(key);
                continue;
            };
        }

        log.debug("health: loaded {d} accounts from {s}", .{ store.accounts.count(), path });
        return store;
    }

    pub fn persist(self: *HealthStore) void {
        const path = paths.healthFilePath(self.allocator) catch return;
        defer self.allocator.free(path);

        if (std.fs.path.dirname(path)) |dir| {
            std.fs.makeDirAbsolute(dir) catch |e| switch (e) {
                error.PathAlreadyExists => {},
                else => return,
            };
        }

        const file = std.fs.createFileAbsolute(path, .{ .mode = 0o600 }) catch return;
        defer file.close();

        const writer = file.writer();
        writer.writeAll("{\"accounts\":[") catch return;
        var first = true;
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            if (!first) writer.writeByte(',') catch return;
            first = false;
            const h = entry.value_ptr.*;
            writer.print(
                "{{\"key\":\"{s}\",\"score\":{d},\"successes\":{d},\"failures\":{d},\"rate_limits\":{d},\"last_updated\":{d},\"circuit_open\":{s}}}",
                .{
                    entry.key_ptr.*,
                    h.score.score,
                    h.score.successes,
                    h.score.failures,
                    h.score.rate_limits,
                    h.score.last_updated,
                    if (h.circuit.isClosed()) "false" else "true",
                },
            ) catch return;
        }
        writer.writeAll("]}") catch return;

        log.debug("health: persisted {d} accounts to {s}", .{ self.accounts.count(), path });
    }

    const HealthFile = struct {
        accounts: []const HealthEntry = &.{},
    };

    const HealthEntry = struct {
        key: []const u8,
        score: i32 = 50,
        successes: u32 = 0,
        failures: u32 = 0,
        rate_limits: u32 = 0,
        last_updated: i64 = 0,
        circuit_open: bool = false,
    };

    pub const FailureKind = enum {
        error_response,
        rate_limited,
        timeout,
        auth_failure,
    };
};

test "HealthStore basic lifecycle" {
    var store = HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    store.recordSuccess("claude:work");
    const health = store.accounts.get("claude:work").?;
    try std.testing.expectEqual(@as(i32, 51), health.score.score);
    try std.testing.expectEqual(@as(u32, 1), health.score.successes);
    try std.testing.expect(health.circuit.isClosed());
}

test "HealthStore circuit breaker opens after failures" {
    var store = HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    store.recordFailure("codex:main", .error_response);
    store.recordFailure("codex:main", .error_response);
    store.recordFailure("codex:main", .error_response);

    const health = store.accounts.get("codex:main").?;
    try std.testing.expect(!health.circuit.isClosed());
}

test "HealthStore rate limit penalty" {
    var store = HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    store.recordFailure("gemini:default", .rate_limited);
    const health = store.accounts.get("gemini:default").?;
    try std.testing.expectEqual(@as(i32, 40), health.score.score); // 50 + (-10)
    try std.testing.expectEqual(@as(u32, 1), health.score.rate_limits);
}
