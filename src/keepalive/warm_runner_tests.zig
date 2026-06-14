//! Unit tests for the keepalive warm-loop runner glue. Exercises the pool
//! enumeration and the DoRefreshFn→pipeline mapping against the toy provider
//! over a file-backed credential store; the timed-wait + CLI command are the
//! untested-by-design wrapper.

const std = @import("std");
const testing = std.testing;
const ws = @import("warm_scheduler.zig");
const runner = @import("warm_runner.zig");
const pipeline = @import("../pipeline.zig");
const config_mod = @import("../config.zig");
const health_mod = @import("../health.zig");
const repair_state = @import("../repair_state.zig");

test {
    testing.refAllDeclsRecursive(runner);
}

// Two toy accounts ("a","b"); the credential file path is templated per account.
fn twoAccountConfig(allocator: std.mem.Allocator, owner: []const u8, path_a: []const u8, path_b: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "{s}" }},
        \\      "auth": {{ "token_endpoint": "http://127.0.0.1:9/token" }},
        \\      "credential": {{
        \\        "access_token_path": "access_token",
        \\        "refresh_token_path": "refresh_token",
        \\        "expires_at_path": "expires_at"
        \\      }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "a": {{ "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "b": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    , .{ owner, path_a, path_b });
}

fn writeCred(path: []const u8, rt: []const u8, exp_s: i64) !void {
    const f = try std.fs.createFileAbsolute(path, .{});
    defer f.close();
    var buf: [256]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{{\"access_token\":\"at\",\"refresh_token\":\"{s}\",\"expires_at\":{d}}}", .{ rt, exp_s });
    try f.writeAll(s);
}

test "enumeratePool includes accounts with a readable expiry, skips unreadable, keys+ms correct" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const path_a = try std.fmt.allocPrint(testing.allocator, "{s}/a.json", .{root});
    defer testing.allocator.free(path_a);
    const path_b = try std.fmt.allocPrint(testing.allocator, "{s}/b.json", .{root});
    defer testing.allocator.free(path_b);

    // Account "a" has a credential (expiry 9_000_000_000 s); "b"'s file is absent.
    try writeCred(path_a, "rt-a", 9_000_000_000);

    const json = try twoAccountConfig(testing.allocator, "oauth_mux_refresh", path_a, path_b);
    defer testing.allocator.free(json);
    const parsed = try config_mod.loadFromBytes(testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(testing.allocator, .{});
    defer store.deinit();

    var pool = try runner.enumeratePool(testing.allocator, parsed.value, &store);
    defer pool.deinit();

    // Only "a" is readable → exactly one row, keyed "toy:a", expiry in ms.
    try testing.expectEqual(@as(usize, 1), pool.observed.len);
    try testing.expectEqualStrings("toy:a", pool.observed[0].key);
    try testing.expectEqual(@as(i64, 9_000_000_000 * std.time.ms_per_s), pool.observed[0].expires_at_ms);
}

test "doRefresh maps a failed proactive refresh to RefreshFailed (admitted account, dead endpoint)" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(testing.allocator);
    defer rt_scope.deinit(testing.allocator);
    rt_scope.activate();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const path_a = try std.fmt.allocPrint(testing.allocator, "{s}/a.json", .{root});
    defer testing.allocator.free(path_a);
    const path_b = try std.fmt.allocPrint(testing.allocator, "{s}/b.json", .{root});
    defer testing.allocator.free(path_b);
    try writeCred(path_a, "rt-a", 9_000_000_000); // still-valid → proactive rotate attempt

    const json = try twoAccountConfig(testing.allocator, "oauth_mux_refresh", path_a, path_b);
    defer testing.allocator.free(json);
    const parsed = try config_mod.loadFromBytes(testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(testing.allocator, .{});
    defer store.deinit();

    var wr = runner.WarmRunner{ .allocator = testing.allocator, .cfg = parsed.value, .health = &store };
    // The proactive rotation proceeds past the adopt (same RT) and hits the dead
    // endpoint → the pipeline returns a typed failure → mapped to RefreshFailed.
    try testing.expectError(ws.RefreshError.RefreshFailed, runner.WarmRunner.doRefresh(&wr, "toy", "a"));
}

test "doRefresh on an un-admitted (builtin-posture) account is RefreshFailed (grant-gate refusal)" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(testing.allocator);
    defer rt_scope.deinit(testing.allocator);
    rt_scope.activate();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const path_a = try std.fmt.allocPrint(testing.allocator, "{s}/a.json", .{root});
    defer testing.allocator.free(path_a);
    const path_b = try std.fmt.allocPrint(testing.allocator, "{s}/b.json", .{root});
    defer testing.allocator.free(path_b);
    try writeCred(path_a, "rt-a", 9_000_000_000);

    // upstream_cli_login owner + no opt-in = builtin posture → grant gate refuses.
    const json = try twoAccountConfig(testing.allocator, "upstream_cli_login", path_a, path_b);
    defer testing.allocator.free(json);
    const parsed = try config_mod.loadFromBytes(testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(testing.allocator, .{});
    defer store.deinit();

    var wr = runner.WarmRunner{ .allocator = testing.allocator, .cfg = parsed.value, .health = &store };
    try testing.expectError(ws.RefreshError.RefreshFailed, runner.WarmRunner.doRefresh(&wr, "toy", "a"));
}

// ── TIN-2113: shared-identity exclusion ──────────────────────────────────────

fn idConfig(allocator: std.mem.Allocator, path_a: []const u8, path_b: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "oauth_mux_refresh" }},
        \\      "auth": {{ "token_endpoint": "http://127.0.0.1:9/token" }},
        \\      "credential": {{
        \\        "access_token_path": "access_token",
        \\        "refresh_token_path": "refresh_token",
        \\        "expires_at_path": "expires_at",
        \\        "identity_claim_path": "account_id"
        \\      }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "a": {{ "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "b": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    , .{ path_a, path_b });
}

fn writeIdCred(path: []const u8, account_id: []const u8) !void {
    const f = try std.fs.createFileAbsolute(path, .{});
    defer f.close();
    var buf: [256]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{{\"access_token\":\"at\",\"refresh_token\":\"rt\",\"expires_at\":9000000000,\"account_id\":\"{s}\"}}", .{account_id});
    try f.writeAll(s);
}

fn idPoolLen(account_id_a: []const u8, account_id_b: []const u8) !usize {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const pa = try std.fmt.allocPrint(testing.allocator, "{s}/a.json", .{root});
    defer testing.allocator.free(pa);
    const pb = try std.fmt.allocPrint(testing.allocator, "{s}/b.json", .{root});
    defer testing.allocator.free(pb);
    try writeIdCred(pa, account_id_a);
    try writeIdCred(pb, account_id_b);
    const json = try idConfig(testing.allocator, pa, pb);
    defer testing.allocator.free(json);
    const parsed = try config_mod.loadFromBytes(testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(testing.allocator, .{});
    defer store.deinit();
    var pool = try runner.enumeratePool(testing.allocator, parsed.value, &store);
    defer pool.deinit();
    return pool.observed.len;
}

test "enumeratePool EXCLUDES both accounts sharing an OAuth identity (TIN-2113)" {
    // Same account_id => one single-use RT family => both excluded from the pool.
    try testing.expectEqual(@as(usize, 0), try idPoolLen("same-id", "same-id"));
}

test "enumeratePool KEEPS accounts with distinct identities (TIN-2113)" {
    try testing.expectEqual(@as(usize, 2), try idPoolLen("id-a", "id-b"));
}

fn idConfig3(allocator: std.mem.Allocator, pa: []const u8, pb: []const u8, pc: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "oauth_mux_refresh" }},
        \\      "auth": {{ "token_endpoint": "http://127.0.0.1:9/token" }},
        \\      "credential": {{
        \\        "access_token_path": "access_token", "refresh_token_path": "refresh_token",
        \\        "expires_at_path": "expires_at", "identity_claim_path": "account_id"
        \\      }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{ "kind": "toy", "accounts": {{
        \\      "a": {{ "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\      "b": {{ "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\      "c": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\    }} }}
        \\  }},
        \\  "profiles": {{}}, "strategies": {{}}
        \\}}
    , .{ pa, pb, pc });
}

test "enumeratePool excludes a shared pair but KEEPS a distinct sibling (TIN-2113, no over-exclusion)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const pa = try std.fmt.allocPrint(testing.allocator, "{s}/a.json", .{root});
    defer testing.allocator.free(pa);
    const pb = try std.fmt.allocPrint(testing.allocator, "{s}/b.json", .{root});
    defer testing.allocator.free(pb);
    const pc = try std.fmt.allocPrint(testing.allocator, "{s}/c.json", .{root});
    defer testing.allocator.free(pc);
    try writeIdCred(pa, "dup");
    try writeIdCred(pb, "dup"); // a,b share identity
    try writeIdCred(pc, "solo"); // c distinct
    const json = try idConfig3(testing.allocator, pa, pb, pc);
    defer testing.allocator.free(json);
    const parsed = try config_mod.loadFromBytes(testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(testing.allocator, .{});
    defer store.deinit();
    var pool = try runner.enumeratePool(testing.allocator, parsed.value, &store);
    defer pool.deinit();
    // Only the distinct sibling survives; the shared pair is excluded.
    try testing.expectEqual(@as(usize, 1), pool.observed.len);
    try testing.expectEqualStrings("toy:c", pool.observed[0].key);
}

test "enumeratePool excludes ALL members of a 3-way identity collision (TIN-2113)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const pa = try std.fmt.allocPrint(testing.allocator, "{s}/a.json", .{root});
    defer testing.allocator.free(pa);
    const pb = try std.fmt.allocPrint(testing.allocator, "{s}/b.json", .{root});
    defer testing.allocator.free(pb);
    const pc = try std.fmt.allocPrint(testing.allocator, "{s}/c.json", .{root});
    defer testing.allocator.free(pc);
    try writeIdCred(pa, "tri");
    try writeIdCred(pb, "tri");
    try writeIdCred(pc, "tri");
    const json = try idConfig3(testing.allocator, pa, pb, pc);
    defer testing.allocator.free(json);
    const parsed = try config_mod.loadFromBytes(testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(testing.allocator, .{});
    defer store.deinit();
    var pool = try runner.enumeratePool(testing.allocator, parsed.value, &store);
    defer pool.deinit();
    try testing.expectEqual(@as(usize, 0), pool.observed.len);
}

test "enumeratePool does NOT exclude accounts with no identity claim (claude-style, TIN-2113)" {
    // twoAccountConfig declares NO identity_claim_path -> both accounts key opaquely
    // (null identity) -> no false collision -> both kept.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const pa = try std.fmt.allocPrint(testing.allocator, "{s}/a.json", .{root});
    defer testing.allocator.free(pa);
    const pb = try std.fmt.allocPrint(testing.allocator, "{s}/b.json", .{root});
    defer testing.allocator.free(pb);
    try writeCred(pa, "rt-a", 9_000_000_000); // no account_id field; def has no identity_claim_path
    try writeCred(pb, "rt-b", 9_000_000_000);
    const json = try twoAccountConfig(testing.allocator, "oauth_mux_refresh", pa, pb);
    defer testing.allocator.free(json);
    const parsed = try config_mod.loadFromBytes(testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(testing.allocator, .{});
    defer store.deinit();
    var pool = try runner.enumeratePool(testing.allocator, parsed.value, &store);
    defer pool.deinit();
    try testing.expectEqual(@as(usize, 2), pool.observed.len);
}
