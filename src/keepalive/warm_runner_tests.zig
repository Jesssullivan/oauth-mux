//! Unit tests for the keepalive warm-loop runner glue. Exercises the pool
//! enumeration and the DoRefreshFn→pipeline mapping against the toy provider
//! over a file-backed credential store; the timed-wait + CLI command are the
//! untested-by-design wrapper.

const std = @import("std");
const testing = std.testing;
const ws = @import("warm_scheduler.zig");
const runner = @import("warm_runner.zig");
const bind = @import("warm_binding.zig");
const pipeline = @import("../pipeline.zig");
const config_mod = @import("../config.zig");
const health_mod = @import("../health.zig");
const repair_state = @import("../repair_state.zig");
const types = @import("../types.zig");

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

test "pipeline success with typed lock transient stays transient through the scheduler" {
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
    const expires_at = std.time.timestamp() + 29;
    try writeCred(path_a, "rt-a", expires_at);

    const json = try twoAccountConfig(
        testing.allocator,
        "oauth_mux_refresh",
        path_a,
        path_b,
    );
    defer testing.allocator.free(json);
    const parsed = try config_mod.loadFromBytes(testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(testing.allocator, .{});
    defer store.deinit();

    // A foreign flock makes pipeline.refreshAccount record transient_lock but
    // return success while the still-valid access token remains usable.
    const lock_path = try repair_state.lockPath(testing.allocator, "toy", "a");
    defer testing.allocator.free(lock_path);
    if (std.fs.path.dirname(lock_path)) |dir| try std.fs.cwd().makePath(dir);
    const holder = try std.fs.createFileAbsolute(lock_path, .{
        .truncate = false,
        .mode = 0o600,
        .lock = .exclusive,
        .lock_nonblocking = true,
    });
    defer holder.close();

    var wr = runner.WarmRunner{
        .allocator = testing.allocator,
        .cfg = parsed.value,
        .health = &store,
    };
    var binding = bind.RefreshBinding{
        .do_refresh = runner.WarmRunner.doRefresh,
        .do_refresh_ctx = &wr,
        .do_refresh_outcome = runner.WarmRunner.refreshOutcome,
    };
    const scheduler = ws.Scheduler{
        .clock = runner.WarmRunner.clock,
        .clock_ctx = &wr,
        .refresh = bind.RefreshBinding.refresh,
        .refresh_ctx = &binding,
        .refresh_outcome = bind.RefreshBinding.refreshOutcome,
    };
    const original_last_refresh_ms: i64 = 0;
    const original_expires_at_ms = expires_at * std.time.ms_per_s;
    var accounts = [_]ws.Account{.{
        .key = "toy:a",
        .last_refresh_ms = original_last_refresh_ms,
        .expires_at_ms = original_expires_at_ms,
        .failures = 3,
    }};

    const report = scheduler.tick(&accounts);
    try testing.expectEqual(@as(u32, 0), report.refreshed);
    try testing.expectEqual(@as(u32, 1), report.transient);
    try testing.expectEqual(@as(u32, 0), report.failed);
    try testing.expectEqual(@as(u32, 3), accounts[0].failures);
    try testing.expectEqual(original_last_refresh_ms, accounts[0].last_refresh_ms);
    try testing.expectEqual(original_expires_at_ms, accounts[0].expires_at_ms);
    try testing.expectEqual(
        types.RefreshOutcome.transient_lock,
        wr.last_refresh_outcome.?,
    );
    try testing.expectEqual(
        types.RefreshOutcome.transient_lock,
        binding.last_refresh_outcome.?,
    );
    try testing.expectEqual(
        types.RefreshOutcome.transient_lock,
        accounts[0].last_refresh_outcome.?,
    );
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

test "enumeratePool does NOT exclude custom providers with no identity claim (opaque identities, TIN-2113)" {
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

fn writeClaudeCred(path: []const u8, refresh_token: []const u8) !void {
    const f = try std.fs.createFileAbsolute(path, .{});
    defer f.close();
    var buf: [512]u8 = undefined;
    const s = try std.fmt.bufPrint(
        &buf,
        "{{\"claudeAiOauth\":{{\"accessToken\":\"at\",\"refreshToken\":\"{s}\",\"expiresAt\":9000000000000}}}}",
        .{refresh_token},
    );
    try f.writeAll(s);
}

fn writeClaudeProfile(dir: []const u8, account_uuid: []const u8) !void {
    const path = try std.fs.path.join(testing.allocator, &.{ dir, ".claude.json" });
    defer testing.allocator.free(path);
    const f = try std.fs.createFileAbsolute(path, .{});
    defer f.close();
    var buf: [256]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{{\"oauthAccount\":{{\"accountUuid\":\"{s}\"}}}}", .{account_uuid});
    try f.writeAll(s);
}

fn claudeConfig(
    allocator: std.mem.Allocator,
    cred_a: []const u8,
    dir_a: []const u8,
    cred_b: []const u8,
    dir_b: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\{{
        \\  "version": 1,
        \\  "providers": {{
        \\    "claude": {{
        \\      "kind": "claude",
        \\      "accounts": {{
        \\        "a": {{ "secret": {{ "backend": "file", "path": "{s}" }}, "config_dir": "{s}" }},
        \\        "b": {{ "secret": {{ "backend": "file", "path": "{s}" }}, "config_dir": "{s}" }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    , .{ cred_a, dir_a, cred_b, dir_b });
}

fn claudePoolLen(account_uuid_a: ?[]const u8, account_uuid_b: ?[]const u8) !usize {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("a");
    try tmp.dir.makeDir("b");
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const dir_a = try tmp.dir.realpathAlloc(testing.allocator, "a");
    defer testing.allocator.free(dir_a);
    const dir_b = try tmp.dir.realpathAlloc(testing.allocator, "b");
    defer testing.allocator.free(dir_b);
    const cred_a = try std.fs.path.join(testing.allocator, &.{ root, "a.json" });
    defer testing.allocator.free(cred_a);
    const cred_b = try std.fs.path.join(testing.allocator, &.{ root, "b.json" });
    defer testing.allocator.free(cred_b);
    try writeClaudeCred(cred_a, "rt-a");
    try writeClaudeCred(cred_b, "rt-b");
    if (account_uuid_a) |uuid| try writeClaudeProfile(dir_a, uuid);
    if (account_uuid_b) |uuid| try writeClaudeProfile(dir_b, uuid);

    const json = try claudeConfig(testing.allocator, cred_a, dir_a, cred_b, dir_b);
    defer testing.allocator.free(json);
    const parsed = try config_mod.loadFromBytes(testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(testing.allocator, .{});
    defer store.deinit();
    var pool = try runner.enumeratePool(testing.allocator, parsed.value, &store);
    defer pool.deinit();
    return pool.observed.len;
}

test "enumeratePool EXCLUDES Claude config dirs sharing oauthAccount.accountUuid (TIN-2057/TIN-1825)" {
    try testing.expectEqual(@as(usize, 0), try claudePoolLen("same-claude-account", "same-claude-account"));
}

test "enumeratePool KEEPS Claude config dirs with distinct oauthAccount.accountUuid values" {
    try testing.expectEqual(@as(usize, 2), try claudePoolLen("claude-account-a", "claude-account-b"));
}

test "enumeratePool keeps Claude accounts opaque when .claude.json identity is absent" {
    try testing.expectEqual(@as(usize, 2), try claudePoolLen(null, null));
}
