//! Method dispatch + handlers for the broker MCP surface.
//! Anchor: docs/spec/broker-mcp-contract-2026-05-03.md §2.
//!
//! TIN-941 scope: surface lifecycle, account list/select/swap,
//! credential/materialize, quota observe/status, and policy/get are live.
//! Refresh, event subscriptions, and admission control remain explicit typed
//! not_implemented responses for later slices.

const std = @import("std");
const types = @import("types.zig");
const session_mod = @import("session.zig");
const account_pool_mod = @import("account_pool.zig");

// Avoid an import cycle: the Context is defined in server.zig and
// passed in by reference.
const Context = @import("server.zig").Context;

pub const DispatchOutcome = union(enum) {
    ok: std.json.Value,
    err: BrokerErrWithMessage,
};

pub const BrokerErrWithMessage = struct {
    err: types.BrokerError,
    message: []const u8,
    data: ?std.json.Value = null,
};

const SessionLookup = union(enum) {
    ok: []const u8,
    err: BrokerErrWithMessage,
};

/// Top-level dispatch by method string.
pub fn dispatch(
    ctx: *Context,
    method: []const u8,
    params: ?std.json.Value,
) DispatchOutcome {
    if (std.mem.eql(u8, method, "surface/info")) return surfaceInfo(ctx);
    if (std.mem.eql(u8, method, "surface/handshake")) return surfaceHandshake(ctx, params);
    if (std.mem.eql(u8, method, "surface/teardown")) return surfaceTeardown(ctx, params);

    if (std.mem.eql(u8, method, "account/list")) return accountList(ctx, params);
    if (std.mem.eql(u8, method, "account/select")) return accountSelect(ctx, params);
    if (std.mem.eql(u8, method, "account/swap")) return accountSwap(ctx, params);

    if (std.mem.eql(u8, method, "credential/materialize")) return credentialMaterialize(ctx, params);
    if (std.mem.eql(u8, method, "credential/refresh")) return notImpl("credential/refresh is Phase 3 (task #27)");

    if (std.mem.eql(u8, method, "quota/observe")) return quotaObserve(ctx, params);
    if (std.mem.eql(u8, method, "quota/status")) return quotaStatus(ctx, params);

    if (std.mem.eql(u8, method, "events/append")) return notImpl("events/append is Phase 1 follow-up");
    if (std.mem.eql(u8, method, "events/subscribe")) return notImpl("events/subscribe is Phase 2");

    if (std.mem.eql(u8, method, "policy/get")) return policyGet(ctx, params);
    if (std.mem.eql(u8, method, "policy/request_admission")) return notImpl("policy/request_admission is Phase 3");

    return .{ .err = .{ .err = error.NotImplemented, .message = "unknown method" } };
}

fn notImpl(msg: []const u8) DispatchOutcome {
    return .{ .err = .{ .err = error.NotImplemented, .message = msg } };
}

// ── surface/* ──────────────────────────────────────────────────────────

fn surfaceInfo(ctx: *Context) DispatchOutcome {
    var obj = std.json.ObjectMap.init(ctx.allocator);
    obj.put("surface_version", .{ .integer = 1 }) catch return oom();
    obj.put("build", .{ .string = @import("mod.zig").BUILD_TAG }) catch return oom();

    var transports = std.json.Array.init(ctx.allocator);
    transports.append(.{ .string = "stdio" }) catch return oom();
    obj.put("transports", .{ .array = transports }) catch return oom();

    var transport_detail = std.json.ObjectMap.init(ctx.allocator);
    transport_detail.put("stdio_broker", .{ .bool = true }) catch return oom();
    transport_detail.put("unix_broker", .{ .bool = false }) catch return oom();
    transport_detail.put("daemon_socket_contract", .{ .string = "experimental_socket_stub" }) catch return oom();
    transport_detail.put("daemon_hosts_broker", .{ .bool = false }) catch return oom();
    obj.put("transport_detail", .{ .object = transport_detail }) catch return oom();

    var caps = std.json.Array.init(ctx.allocator);
    inline for (.{ "accounts", "quota", "credentials", "policy" }) |c| {
        caps.append(.{ .string = c }) catch return oom();
    }
    obj.put("capabilities", .{ .array = caps }) catch return oom();

    var detail = std.json.ObjectMap.init(ctx.allocator);
    detail.put("account_list", .{ .bool = true }) catch return oom();
    detail.put("account_select", .{ .bool = true }) catch return oom();
    detail.put("account_swap", .{ .bool = true }) catch return oom();
    detail.put("credential_materialize", .{ .bool = true }) catch return oom();
    detail.put("credential_materialize_scope", .{ .string = "adapter_stdio_only" }) catch return oom();
    detail.put("credential_refresh", .{ .bool = false }) catch return oom();
    detail.put("quota_observe", .{ .bool = true }) catch return oom();
    detail.put("quota_status", .{ .bool = true }) catch return oom();
    detail.put("events_append", .{ .bool = false }) catch return oom();
    detail.put("events_subscribe", .{ .bool = false }) catch return oom();
    detail.put("policy_get", .{ .bool = true }) catch return oom();
    detail.put("policy_request_admission", .{ .bool = false }) catch return oom();
    obj.put("capabilities_detail", .{ .object = detail }) catch return oom();

    return .{ .ok = .{ .object = obj } };
}

fn surfaceHandshake(ctx: *Context, params: ?std.json.Value) DispatchOutcome {
    const p = params orelse return invalidParams("missing params");
    if (p != .object) return invalidParams("params must be object");
    const obj = p.object;

    const adapter = strField(obj, "adapter") orelse return invalidParams("missing adapter");
    const adapter_version = strField(obj, "adapter_version") orelse "0.0.0";
    const harness_target = strField(obj, "harness_target") orelse "";
    const session_pid: u32 = blk: {
        const v = obj.get("session_pid") orelse break :blk 0;
        break :blk if (v == .integer) @intCast(v.integer) else 0;
    };

    const sid = ctx.sessions.newId() catch return oom();
    defer ctx.sessions.allocator.free(sid);

    ctx.sessions.create(.{
        .id = sid,
        .adapter = adapter,
        .adapter_version = adapter_version,
        .harness_target = harness_target,
        .session_pid = session_pid,
        .claim_floor = .broker_owned,
        .started_at_ms = std.time.milliTimestamp(),
    }) catch return oom();

    var out = std.json.ObjectMap.init(ctx.allocator);
    out.put("session_id", .{ .string = ctx.allocator.dupe(u8, sid) catch return oom() }) catch return oom();

    var policy_obj = std.json.ObjectMap.init(ctx.allocator);
    policy_obj.put("allow_interactive", .{ .bool = false }) catch return oom();
    policy_obj.put("allow_mutating", .{ .bool = false }) catch return oom();
    policy_obj.put("spend_admitted_for_session", .{ .bool = false }) catch return oom();
    out.put("policy", .{ .object = policy_obj }) catch return oom();

    out.put("claim_floor", .{ .string = "broker_owned" }) catch return oom();

    return .{ .ok = .{ .object = out } };
}

fn surfaceTeardown(ctx: *Context, params: ?std.json.Value) DispatchOutcome {
    const p = params orelse return invalidParams("missing params");
    if (p != .object) return invalidParams("params must be object");
    const sid = switch (requireSessionId(ctx, p.object)) {
        .ok => |v| v,
        .err => |e| return .{ .err = e },
    };
    _ = ctx.sessions.drop(sid);

    var out = std.json.ObjectMap.init(ctx.allocator);
    out.put("ok", .{ .bool = true }) catch return oom();
    return .{ .ok = .{ .object = out } };
}

// ── account/* ─────────────────────────────────────────────────────────

fn accountList(ctx: *Context, params: ?std.json.Value) DispatchOutcome {
    const p = params orelse return invalidParams("missing params");
    if (p != .object) return invalidParams("params must be object");
    _ = switch (requireSessionId(ctx, p.object)) {
        .ok => |v| v,
        .err => |e| return .{ .err = e },
    };

    // Phase 1 scope: profile/capability params are accepted but per-call
    // filtering is not applied here. The pool was already populated for
    // the session's profile in `oauth-mux mcp` startup
    // (broker_loader.populatePool). Accounts not in the loaded profile
    // are present in the list with `selectable:false`.
    const profile = strField(p.object, "profile");
    const capability = strField(p.object, "capability");

    var list_buf = std.ArrayListUnmanaged(account_pool_mod.AccountSummary){};
    defer list_buf.deinit(ctx.allocator);
    ctx.pool.list(&list_buf, ctx.allocator, profile, capability) catch return oom();

    var arr = std.json.Array.init(ctx.allocator);
    for (list_buf.items) |a| {
        var entry = std.json.ObjectMap.init(ctx.allocator);
        entry.put("id", .{ .string = a.id }) catch return oom();
        entry.put("selectable", .{ .bool = a.selectable }) catch return oom();
        entry.put("liveness", .{ .string = @tagName(a.liveness) }) catch return oom();
        entry.put("availability", .{ .string = @tagName(a.availability) }) catch return oom();
        entry.put(
            "next_eligible_at",
            if (a.next_eligible_at) |t| std.json.Value{ .integer = t } else std.json.Value{ .null = {} },
        ) catch return oom();
        arr.append(.{ .object = entry }) catch return oom();
    }

    var out = std.json.ObjectMap.init(ctx.allocator);
    out.put("accounts", .{ .array = arr }) catch return oom();
    return .{ .ok = .{ .object = out } };
}

fn accountSelect(ctx: *Context, params: ?std.json.Value) DispatchOutcome {
    const p = params orelse return invalidParams("missing params");
    if (p != .object) return invalidParams("params must be object");
    const sid = switch (requireSessionId(ctx, p.object)) {
        .ok => |v| v,
        .err => |e| return .{ .err = e },
    };

    const profile = strField(p.object, "profile");
    const capability = strField(p.object, "capability");

    // exclude is optional []string
    var excl_buf = std.ArrayListUnmanaged([]const u8){};
    defer excl_buf.deinit(ctx.allocator);
    if (p.object.get("exclude")) |ex_v| {
        if (ex_v == .array) {
            for (ex_v.array.items) |item| {
                if (item == .string) excl_buf.append(ctx.allocator, item.string) catch return oom();
            }
        }
    }

    const elected = ctx.pool.elect(profile, capability, excl_buf.items) catch |e| switch (e) {
        error.NoAccountSelectable => return noAccountSelectable(ctx, "no selectable account", profile, capability),
        else => return .{ .err = .{ .err = e, .message = "account election failed" } },
    };
    ctx.sessions.setCurrentAccount(sid, elected.id) catch |e| return .{
        .err = .{ .err = e, .message = "session update failed" },
    };

    var out = std.json.ObjectMap.init(ctx.allocator);
    out.put("account", .{ .string = elected.id }) catch return oom();

    // Phase 1 returns a placeholder credential_handle. Real materialization
    // happens in task #18 (credential/materialize).
    const handle = std.fmt.allocPrint(
        ctx.allocator,
        "ch:{s}:{x}",
        .{ elected.id, std.time.milliTimestamp() },
    ) catch return oom();
    out.put("credential_handle", .{ .string = handle }) catch return oom();

    var claim_obj = std.json.ObjectMap.init(ctx.allocator);
    claim_obj.put("level", .{ .string = "broker_owned" }) catch return oom();
    claim_obj.put("spare_fallback_ready", .{ .bool = anotherSelectableExists(ctx.pool, elected.id) }) catch return oom();
    out.put("claim", .{ .object = claim_obj }) catch return oom();

    return .{ .ok = .{ .object = out } };
}

/// Parse a `reason` string into a SwapReason, defaulting to
/// quota_exhausted (the most common Phase 2 case) for unknown values.
fn parseSwapReason(s: []const u8) types.SwapReason {
    if (std.mem.eql(u8, s, "quota_exhausted")) return .quota_exhausted;
    if (std.mem.eql(u8, s, "rate_limited_long")) return .rate_limited_long;
    if (std.mem.eql(u8, s, "auth_unauthorized")) return .auth_unauthorized;
    if (std.mem.eql(u8, s, "operator_requested")) return .operator_requested;
    return .quota_exhausted;
}

fn parseQuotaKind(s: []const u8) ?types.QuotaKind {
    if (std.mem.eql(u8, s, "ok")) return .ok;
    if (std.mem.eql(u8, s, "rate_limited")) return .rate_limited;
    if (std.mem.eql(u8, s, "quota_exhausted")) return .quota_exhausted;
    if (std.mem.eql(u8, s, "auth_unauthorized")) return .auth_unauthorized;
    if (std.mem.eql(u8, s, "tier_insufficient")) return .tier_insufficient;
    if (std.mem.eql(u8, s, "provider_5xx")) return .provider_5xx;
    return null;
}

fn intField(obj: std.json.ObjectMap, key: []const u8) ?i64 {
    const v = obj.get(key) orelse return null;
    return if (v == .integer) v.integer else null;
}

/// account/swap: mark `current_account` as failed for the given typed
/// reason, then elect a fresh account.
fn accountSwap(ctx: *Context, params: ?std.json.Value) DispatchOutcome {
    const p = params orelse return invalidParams("missing params");
    if (p != .object) return invalidParams("params must be object");
    const sid = switch (requireSessionId(ctx, p.object)) {
        .ok => |v| v,
        .err => |e| return .{ .err = e },
    };

    const current = strField(p.object, "current_account") orelse
        return invalidParams("missing current_account");
    const profile = strField(p.object, "profile");
    const capability = strField(p.object, "capability");
    const reason_str = strField(p.object, "reason") orelse "quota_exhausted";
    const reason = parseSwapReason(reason_str);

    // Pull resets_at / retry_after from the evidence object if present.
    var resets_at: ?i64 = null;
    if (p.object.get("evidence")) |ev| {
        if (ev == .object) {
            resets_at = intField(ev.object, "resets_at") orelse intField(ev.object, "retry_after_at");
        }
    }

    // Apply the typed mark to the pool. Default reset window = 7 days
    // (weekly quota) when not provided; rate_limited gets a 60s default.
    const now_unix = std.time.timestamp();
    const default_quota_until = now_unix + 7 * 24 * 60 * 60;
    const default_rate_until = now_unix + 60;

    switch (reason) {
        .quota_exhausted => {
            ctx.pool.markQuotaExhausted(current, resets_at orelse default_quota_until) catch |e|
                return .{ .err = .{ .err = e, .message = "current_account not in pool" } };
        },
        .rate_limited_long => {
            ctx.pool.markRateLimited(current, resets_at orelse default_rate_until) catch |e|
                return .{ .err = .{ .err = e, .message = "current_account not in pool" } };
        },
        .auth_unauthorized => {
            ctx.pool.markUnauthorized(current) catch |e|
                return .{ .err = .{ .err = e, .message = "current_account not in pool" } };
        },
        .operator_requested => {
            // Operator-requested swaps don't permanently mark the
            // current account; we just exclude it from this elect.
        },
    }

    // Elect a replacement, excluding the current account.
    const exclude = [_][]const u8{current};
    const elected = ctx.pool.elect(profile, capability, exclude[0..]) catch |e| switch (e) {
        error.NoAccountSelectable => return noAccountSelectable(ctx, "no replacement account selectable", profile, capability),
        else => return .{ .err = .{ .err = e, .message = "replacement election failed" } },
    };
    ctx.sessions.setCurrentAccount(sid, elected.id) catch |e| return .{
        .err = .{ .err = e, .message = "session update failed" },
    };

    // Build response.
    var out = std.json.ObjectMap.init(ctx.allocator);
    out.put("account", .{ .string = elected.id }) catch return oom();
    const handle = std.fmt.allocPrint(
        ctx.allocator,
        "ch:{s}:{x}",
        .{ elected.id, std.time.milliTimestamp() },
    ) catch return oom();
    out.put("credential_handle", .{ .string = handle }) catch return oom();

    var claim_obj = std.json.ObjectMap.init(ctx.allocator);
    claim_obj.put("level", .{ .string = "broker_owned" }) catch return oom();
    claim_obj.put("spare_fallback_ready", .{ .bool = anotherSelectableExists(ctx.pool, elected.id) }) catch return oom();
    claim_obj.put("replacement_selected", .{ .bool = true }) catch return oom();
    claim_obj.put("requires_adapter_turn_completion", .{ .bool = true }) catch return oom();
    claim_obj.put("next_turn_seamless_claimed", .{ .bool = false }) catch return oom();
    claim_obj.put("pending_success_level", .{ .string = "next_turn_seamless" }) catch return oom();
    out.put("claim", .{ .object = claim_obj }) catch return oom();

    var prev_obj = std.json.ObjectMap.init(ctx.allocator);
    prev_obj.put("as", .{ .string = @tagName(reason) }) catch return oom();
    if (resets_at) |t| {
        prev_obj.put("until", .{ .integer = t }) catch return oom();
    } else {
        prev_obj.put("until", .{ .null = {} }) catch return oom();
    }
    out.put("previous_marked", .{ .object = prev_obj }) catch return oom();

    return .{ .ok = .{ .object = out } };
}

fn anotherSelectableExists(pool: anytype, except_id: []const u8) bool {
    var count: usize = 0;
    for (pool.accounts.items) |a| {
        if (a.selectable and a.availability == .available and !std.mem.eql(u8, a.id, except_id)) {
            count += 1;
            if (count >= 1) return true;
        }
    }
    return false;
}

/// quota/observe: record an observation on the current account
/// without forcing a swap. Used by the wire proxy on EVERY response,
/// so the broker has up-to-date quota state for the next elect.
fn quotaObserve(ctx: *Context, params: ?std.json.Value) DispatchOutcome {
    const p = params orelse return invalidParams("missing params");
    if (p != .object) return invalidParams("params must be object");
    _ = switch (requireSessionId(ctx, p.object)) {
        .ok => |v| v,
        .err => |e| return .{ .err = e },
    };

    const account = strField(p.object, "account") orelse
        return invalidParams("missing account");
    const kind_str = strField(p.object, "kind") orelse
        return invalidParams("missing kind");
    const kind = parseQuotaKind(kind_str) orelse
        return invalidParams("unknown quota kind");
    const resets_at = intField(p.object, "resets_at");

    var now_selectable = true;
    var next_eligible_at: ?i64 = null;

    const now_unix = std.time.timestamp();
    switch (kind) {
        .ok => {
            // Healthy turn — opportunity to clear stale rate-limit
            // marks. Phase 2 keeps this lean: only restore time-based
            // entries that are already past their reset.
            ctx.pool.refreshTimeBased(now_unix);
        },
        .rate_limited => {
            const until = resets_at orelse (now_unix + 60);
            ctx.pool.markRateLimited(account, until) catch |e|
                return .{ .err = .{ .err = e, .message = "account not in pool" } };
            next_eligible_at = until;
            // rate_limited keeps selectable=true (short window); see
            // AccountPool.markRateLimited.
        },
        .quota_exhausted => {
            const until = resets_at orelse (now_unix + 7 * 24 * 60 * 60);
            ctx.pool.markQuotaExhausted(account, until) catch |e|
                return .{ .err = .{ .err = e, .message = "account not in pool" } };
            now_selectable = false;
            next_eligible_at = until;
        },
        .auth_unauthorized => {
            ctx.pool.markUnauthorized(account) catch |e|
                return .{ .err = .{ .err = e, .message = "account not in pool" } };
            now_selectable = false;
        },
        .tier_insufficient, .provider_5xx => {
            // Recorded for telemetry; no pool mutation in Phase 2.
        },
    }

    var out = std.json.ObjectMap.init(ctx.allocator);
    out.put("recorded", .{ .bool = true }) catch return oom();
    out.put("now_selectable", .{ .bool = now_selectable }) catch return oom();
    if (next_eligible_at) |t| {
        out.put("next_eligible_at", .{ .integer = t }) catch return oom();
    } else {
        out.put("next_eligible_at", .{ .null = {} }) catch return oom();
    }
    return .{ .ok = .{ .object = out } };
}

/// quota/status: snapshot of pool availability for the calling
/// session's profile. Used by the proxy on session start to know
/// the spare-fallback count without driving extra account/list calls.
fn quotaStatus(ctx: *Context, params: ?std.json.Value) DispatchOutcome {
    const p = params orelse return invalidParams("missing params");
    if (p != .object) return invalidParams("params must be object");
    _ = switch (requireSessionId(ctx, p.object)) {
        .ok => |v| v,
        .err => |e| return .{ .err = e },
    };

    var arr = std.json.Array.init(ctx.allocator);
    var selectable_count: usize = 0;
    for (ctx.pool.accounts.items) |a| {
        var entry = std.json.ObjectMap.init(ctx.allocator);
        entry.put("id", .{ .string = a.id }) catch return oom();
        entry.put("availability", .{ .string = @tagName(a.availability) }) catch return oom();
        if (a.next_eligible_at) |t| {
            entry.put("next_eligible_at", .{ .integer = t }) catch return oom();
        } else {
            entry.put("next_eligible_at", .{ .null = {} }) catch return oom();
        }
        arr.append(.{ .object = entry }) catch return oom();
        if (a.selectable) selectable_count += 1;
    }

    var out = std.json.ObjectMap.init(ctx.allocator);
    out.put("accounts", .{ .array = arr }) catch return oom();
    out.put("selectable_count", .{ .integer = @intCast(selectable_count) }) catch return oom();
    return .{ .ok = .{ .object = out } };
}

// ── credential/* ──────────────────────────────────────────────────────

/// Parse the `ch:<provider>:<account>:<ts>` shape minted by accountSelect.
/// Returns the `<provider>:<account>` head, or null if the handle format
/// is unrecognized.
fn accountIdFromHandle(handle: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, handle, "ch:")) return null;
    const after = handle[3..];
    // Find the LAST ':' to strip the timestamp suffix.
    const last_colon = std.mem.lastIndexOfScalar(u8, after, ':') orelse return null;
    return after[0..last_colon];
}

fn credentialMaterialize(ctx: *Context, params: ?std.json.Value) DispatchOutcome {
    const p = params orelse return invalidParams("missing params");
    if (p != .object) return invalidParams("params must be object");
    _ = switch (requireSessionId(ctx, p.object)) {
        .ok => |v| v,
        .err => |e| return .{ .err = e },
    };

    const handle = strField(p.object, "credential_handle") orelse
        return invalidParams("missing credential_handle");
    const shape = strField(p.object, "shape") orelse "chatgpt_auth_tokens";

    if (!std.mem.eql(u8, shape, "chatgpt_auth_tokens")) {
        return .{ .err = .{
            .err = error.UnsupportedShape,
            .message = "only chatgpt_auth_tokens supported in Phase 1",
        } };
    }

    const account_id = accountIdFromHandle(handle) orelse
        return invalidParams("malformed credential_handle");

    const mat = ctx.materializer orelse return .{ .err = .{
        .err = error.NotImplemented,
        .message = "no credential materializer wired (broker started without one)",
    } };

    const tokens = mat.materialize_chatgpt(mat.ctx, ctx.allocator, account_id) catch |e| return .{
        .err = .{ .err = e, .message = "materialize failed" },
    };

    var out = std.json.ObjectMap.init(ctx.allocator);
    out.put("shape", .{ .string = "chatgpt_auth_tokens" }) catch return oom();
    out.put("access_token", .{ .string = tokens.access_token }) catch return oom();
    out.put("account_id", .{ .string = tokens.account_id }) catch return oom();
    if (tokens.plan_type) |pt| {
        out.put("plan_type", .{ .string = pt }) catch return oom();
    } else {
        out.put("plan_type", .{ .null = {} }) catch return oom();
    }
    out.put("fedramp", .{ .bool = tokens.fedramp }) catch return oom();
    return .{ .ok = .{ .object = out } };
}

// ── policy/* ──────────────────────────────────────────────────────────

fn policyGet(ctx: *Context, params: ?std.json.Value) DispatchOutcome {
    const p = params orelse return invalidParams("missing params");
    if (p != .object) return invalidParams("params must be object");
    _ = switch (requireSessionId(ctx, p.object)) {
        .ok => |v| v,
        .err => |e| return .{ .err = e },
    };
    var out = std.json.ObjectMap.init(ctx.allocator);
    var budgets = std.json.Array.init(ctx.allocator);
    budgets.append(.{ .string = "free_local" }) catch return oom();
    budgets.append(.{ .string = "free_command" }) catch return oom();
    out.put("allowed_budgets", .{ .array = budgets }) catch return oom();
    out.put("allow_interactive", .{ .bool = false }) catch return oom();
    out.put("allow_mutating", .{ .bool = false }) catch return oom();
    out.put("spend_admitted_for_session", .{ .bool = false }) catch return oom();
    return .{ .ok = .{ .object = out } };
}

// ── helpers ───────────────────────────────────────────────────────────

fn strField(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return if (v == .string) v.string else null;
}

fn requireSessionId(ctx: *Context, obj: std.json.ObjectMap) SessionLookup {
    const sid = strField(obj, "session_id") orelse return .{
        .err = .{ .err = error.InvalidParams, .message = "missing session_id" },
    };
    if (ctx.sessions.getPtr(sid) == null) return .{
        .err = .{ .err = error.SessionNotFound, .message = "unknown session_id" },
    };
    return .{ .ok = sid };
}

fn invalidParams(msg: []const u8) DispatchOutcome {
    return .{ .err = .{ .err = error.InvalidParams, .message = msg } };
}

fn oom() DispatchOutcome {
    return .{ .err = .{ .err = error.OutOfMemory, .message = "out of memory" } };
}

fn noAccountSelectable(
    ctx: *Context,
    msg: []const u8,
    profile: ?[]const u8,
    capability: ?[]const u8,
) DispatchOutcome {
    var summary = std.json.ObjectMap.init(ctx.allocator);
    var total: i64 = 0;
    var selectable: i64 = 0;
    var available: i64 = 0;
    var quota_exhausted: i64 = 0;
    var rate_limited: i64 = 0;
    var dead: i64 = 0;
    var degraded: i64 = 0;
    var unknown: i64 = 0;
    var hidden: i64 = 0;

    for (ctx.pool.accounts.items) |a| {
        if (!a.selectable and a.liveness == .unknown and a.availability == .available) {
            hidden += 1;
            continue;
        }
        total += 1;
        if (a.selectable) selectable += 1;
        switch (a.availability) {
            .available => available += 1,
            .quota_exhausted => quota_exhausted += 1,
            .rate_limited => rate_limited += 1,
            .cooldown => rate_limited += 1,
            .unknown => {},
        }
        switch (a.liveness) {
            .dead => dead += 1,
            .degraded => degraded += 1,
            .unknown => unknown += 1,
            .live => {},
        }
    }

    summary.put("total_routes", .{ .integer = total }) catch return oom();
    summary.put("selectable_routes", .{ .integer = selectable }) catch return oom();
    summary.put("available_routes", .{ .integer = available }) catch return oom();
    summary.put("quota_exhausted_routes", .{ .integer = quota_exhausted }) catch return oom();
    summary.put("rate_limited_routes", .{ .integer = rate_limited }) catch return oom();
    summary.put("dead_routes", .{ .integer = dead }) catch return oom();
    summary.put("degraded_routes", .{ .integer = degraded }) catch return oom();
    summary.put("unknown_routes", .{ .integer = unknown }) catch return oom();
    summary.put("hidden_routes", .{ .integer = hidden }) catch return oom();

    var data = std.json.ObjectMap.init(ctx.allocator);
    data.put("error_name", .{ .string = "no_account_selectable" }) catch return oom();
    if (profile) |p| {
        data.put("profile", .{ .string = p }) catch return oom();
    } else {
        data.put("profile", .{ .null = {} }) catch return oom();
    }
    if (capability) |c| {
        data.put("capability", .{ .string = c }) catch return oom();
    } else {
        data.put("capability", .{ .null = {} }) catch return oom();
    }
    data.put("rejection_summary", .{ .object = summary }) catch return oom();

    var actions = std.json.Array.init(ctx.allocator);
    actions.append(.{ .string = routeDiagnosticCommand(ctx.allocator, "route explain", profile, capability) catch return oom() }) catch return oom();
    actions.append(.{ .string = routeDiagnosticCommand(ctx.allocator, "repair-plan", profile, capability) catch return oom() }) catch return oom();
    data.put("agent_safe_next_actions", .{ .array = actions }) catch return oom();

    return .{ .err = .{
        .err = error.NoAccountSelectable,
        .message = msg,
        .data = .{ .object = data },
    } };
}

fn routeDiagnosticCommand(
    allocator: std.mem.Allocator,
    base: []const u8,
    profile: ?[]const u8,
    capability: ?[]const u8,
) ![]const u8 {
    if (profile) |p| {
        if (capability) |c| {
            return std.fmt.allocPrint(allocator, "oauth-mux {s} --profile {s} --capability {s} --json", .{ base, p, c });
        }
        return std.fmt.allocPrint(allocator, "oauth-mux {s} --profile {s} --json", .{ base, p });
    }
    if (capability) |c| {
        return std.fmt.allocPrint(allocator, "oauth-mux {s} --capability {s} --json", .{ base, c });
    }
    return std.fmt.allocPrint(allocator, "oauth-mux {s} --json", .{base});
}

test "dispatch surface/info returns object with surface_version=1" {
    // Use an arena so leak-checking doesn't trip on the response's
    // intentionally-borrowed-by-server allocations. In the real server,
    // the buffered stdout writer flushes the JSON and the arena is
    // dropped per-request.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var sessions = session_mod.SessionTable.init(arena.allocator());
    var pool = account_pool_mod.AccountPool.init(arena.allocator());

    var stderr_buf: [0]u8 = undefined;
    var fbs = std.io.fixedBufferStream(stderr_buf[0..]);
    var ctx = Context{
        .allocator = arena.allocator(),
        .sessions = &sessions,
        .pool = &pool,
        .materializer = null,
        .log_writer = fbs.writer().any(),
    };

    const out = dispatch(&ctx, "surface/info", null);
    switch (out) {
        .ok => |v| {
            try std.testing.expect(v == .object);
            const sv = v.object.get("surface_version") orelse return error.TestFailed;
            try std.testing.expect(sv == .integer);
            try std.testing.expectEqual(@as(i64, 1), sv.integer);

            const transports = v.object.get("transports") orelse return error.TestFailed;
            try std.testing.expect(transports == .array);
            try std.testing.expectEqual(@as(usize, 1), transports.array.items.len);
            try std.testing.expectEqualStrings("stdio", transports.array.items[0].string);

            const transport_detail = v.object.get("transport_detail") orelse return error.TestFailed;
            try std.testing.expect(transport_detail == .object);
            try std.testing.expectEqual(false, transport_detail.object.get("unix_broker").?.bool);
            try std.testing.expectEqual(false, transport_detail.object.get("daemon_hosts_broker").?.bool);
            try std.testing.expectEqualStrings(
                "experimental_socket_stub",
                transport_detail.object.get("daemon_socket_contract").?.string,
            );

            const caps = v.object.get("capabilities") orelse return error.TestFailed;
            try std.testing.expect(caps == .array);
            for (caps.array.items) |cap| {
                try std.testing.expect(cap == .string);
                try std.testing.expect(!std.mem.eql(u8, cap.string, "refresh"));
                try std.testing.expect(!std.mem.eql(u8, cap.string, "events"));
            }
            const detail = v.object.get("capabilities_detail") orelse return error.TestFailed;
            try std.testing.expect(detail == .object);
            try std.testing.expectEqual(false, detail.object.get("credential_refresh").?.bool);
            try std.testing.expectEqual(false, detail.object.get("events_append").?.bool);
            try std.testing.expectEqual(false, detail.object.get("events_subscribe").?.bool);
        },
        .err => return error.TestFailed,
    }
}

test "surface/handshake mints session and stores it; teardown drops it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var sessions = session_mod.SessionTable.init(arena.allocator());
    var pool = account_pool_mod.AccountPool.init(arena.allocator());
    var stderr_buf: [0]u8 = undefined;
    var fbs = std.io.fixedBufferStream(stderr_buf[0..]);
    var ctx = Context{
        .allocator = arena.allocator(),
        .sessions = &sessions,
        .pool = &pool,
        .materializer = null,
        .log_writer = fbs.writer().any(),
    };

    // handshake — params.adapter required
    var hs_obj = std.json.ObjectMap.init(arena.allocator());
    try hs_obj.put("adapter", .{ .string = "smoke" });
    try hs_obj.put("adapter_version", .{ .string = "0.0" });
    try hs_obj.put("harness_target", .{ .string = "codex" });
    try hs_obj.put("session_pid", .{ .integer = 12345 });
    const out = dispatch(&ctx, "surface/handshake", .{ .object = hs_obj });
    const sid_v = switch (out) {
        .ok => |v| v.object.get("session_id") orelse return error.TestFailed,
        .err => return error.TestFailed,
    };
    try std.testing.expect(sid_v == .string);
    try std.testing.expect(sid_v.string.len > 0);

    // session must now be retrievable from the long-lived table
    try std.testing.expect(sessions.get(sid_v.string) != null);

    // teardown drops it
    var td_obj = std.json.ObjectMap.init(arena.allocator());
    try td_obj.put("session_id", .{ .string = sid_v.string });
    const td_out = dispatch(&ctx, "surface/teardown", .{ .object = td_obj });
    try std.testing.expect(td_out == .ok);
    try std.testing.expect(sessions.get(sid_v.string) == null);
}

test "surface/handshake without adapter returns InvalidParams" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var sessions = session_mod.SessionTable.init(arena.allocator());
    var pool = account_pool_mod.AccountPool.init(arena.allocator());
    var stderr_buf: [0]u8 = undefined;
    var fbs = std.io.fixedBufferStream(stderr_buf[0..]);
    var ctx = Context{
        .allocator = arena.allocator(),
        .sessions = &sessions,
        .pool = &pool,
        .materializer = null,
        .log_writer = fbs.writer().any(),
    };

    var bad_obj = std.json.ObjectMap.init(arena.allocator());
    try bad_obj.put("foo", .{ .string = "bar" });
    const out = dispatch(&ctx, "surface/handshake", .{ .object = bad_obj });
    switch (out) {
        .err => |e| try std.testing.expectEqual(error.InvalidParams, e.err),
        else => return error.TestFailed,
    }
}

test "account methods reject unknown session ids" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var sessions = session_mod.SessionTable.init(arena.allocator());
    var pool = account_pool_mod.AccountPool.init(arena.allocator());
    var stderr_buf: [0]u8 = undefined;
    var fbs = std.io.fixedBufferStream(stderr_buf[0..]);
    var ctx = Context{
        .allocator = arena.allocator(),
        .sessions = &sessions,
        .pool = &pool,
        .materializer = null,
        .log_writer = fbs.writer().any(),
    };

    var obj = std.json.ObjectMap.init(arena.allocator());
    try obj.put("session_id", .{ .string = "not-real" });
    const out = dispatch(&ctx, "account/list", .{ .object = obj });
    switch (out) {
        .err => |e| try std.testing.expectEqual(error.SessionNotFound, e.err),
        .ok => return error.TestFailed,
    }
}

test "account/select records current account on the broker session" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var sessions = session_mod.SessionTable.init(arena.allocator());
    var pool = account_pool_mod.AccountPool.init(arena.allocator());
    try pool.add(.{ .id = "codex:max-1", .selectable = true, .liveness = .live, .availability = .available });
    try pool.add(.{ .id = "codex:max-2", .selectable = true, .liveness = .live, .availability = .available });
    var stderr_buf: [0]u8 = undefined;
    var fbs = std.io.fixedBufferStream(stderr_buf[0..]);
    var ctx = Context{
        .allocator = arena.allocator(),
        .sessions = &sessions,
        .pool = &pool,
        .materializer = null,
        .log_writer = fbs.writer().any(),
    };

    const sid = try sessions.newId();
    defer sessions.allocator.free(sid);
    try sessions.create(.{
        .id = sid,
        .adapter = "smoke",
        .adapter_version = "0",
        .harness_target = "codex",
        .session_pid = 1,
        .claim_floor = .broker_owned,
        .started_at_ms = std.time.milliTimestamp(),
    });

    var obj = std.json.ObjectMap.init(arena.allocator());
    try obj.put("session_id", .{ .string = sid });
    const out = dispatch(&ctx, "account/select", .{ .object = obj });
    switch (out) {
        .ok => {},
        .err => return error.TestFailed,
    }
    try std.testing.expectEqualStrings("codex:max-1", sessions.get(sid).?.current_account.?);
}

test "accountIdFromHandle property: round-trip with 200 random ids" {
    // PBT: for any provider:account-shaped string, mint a handle of
    // the documented format `ch:<id>:<ts>`, then assert
    // accountIdFromHandle recovers exactly the original id. Catches
    // off-by-one in the last-colon lookup and edge cases like
    // multi-segment account names (e.g. codex:max-1, codex:org/team).
    var prng = std.Random.DefaultPrng.init(0xCAFEF00D);
    const r = prng.random();
    const providers = [_][]const u8{ "codex", "claude", "anthropic", "cursor", "p" };
    const accounts = [_][]const u8{ "a", "max-1", "max-99", "personal-2026", "team/work" };

    var i: usize = 0;
    while (i < 200) : (i += 1) {
        const provider = providers[r.uintLessThan(usize, providers.len)];
        const account = accounts[r.uintLessThan(usize, accounts.len)];
        const ts = r.int(u32);

        const id_only = try std.fmt.allocPrint(std.testing.allocator, "{s}:{s}", .{ provider, account });
        defer std.testing.allocator.free(id_only);
        const handle = try std.fmt.allocPrint(std.testing.allocator, "ch:{s}:{x}", .{ id_only, ts });
        defer std.testing.allocator.free(handle);

        const recovered = accountIdFromHandle(handle) orelse {
            std.debug.print("failed to parse handle: {s}\n", .{handle});
            return error.ParseFailed;
        };
        try std.testing.expectEqualStrings(id_only, recovered);
    }
}

test "accountIdFromHandle parses ch:provider:account:ts shape" {
    try std.testing.expectEqualStrings("codex:max-1", accountIdFromHandle("ch:codex:max-1:19def8fe019").?);
    try std.testing.expect(accountIdFromHandle("nope") == null);
    try std.testing.expect(accountIdFromHandle("ch:no-second-colon") == null);
    try std.testing.expect(accountIdFromHandle("") == null);
}

test "ErrorCode.fromBrokerError covers all variants" {
    // Smoke each BrokerError variant against the mapping. If a future
    // variant is added without a switch arm in fromBrokerError, the
    // underlying switch becomes non-exhaustive and the build fails;
    // this test just confirms the runtime mapping is sane for known
    // variants.
    const server_mod = @import("server.zig");
    const variants = [_]types.BrokerError{
        error.NotImplemented,    error.NoAccountSelectable,
        error.AccountNotFound,   error.SessionNotFound,
        error.PolicyDenied,      error.InvalidParams,
        error.InvalidShape,      error.ParseError,
        error.RefreshFailed,     error.UnsupportedShape,
        error.SecretUnavailable, error.OutOfMemory,
    };
    for (variants) |v| {
        const code = server_mod.ErrorCode.fromBrokerError(v);
        _ = @intFromEnum(code);
    }
    // OutOfMemory specifically maps to internal_error, not invalid_params.
    try std.testing.expectEqual(
        server_mod.ErrorCode.internal_error,
        server_mod.ErrorCode.fromBrokerError(error.OutOfMemory),
    );
}

test "dispatch unknown method returns NotImplemented" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var sessions = session_mod.SessionTable.init(arena.allocator());
    var pool = account_pool_mod.AccountPool.init(arena.allocator());
    var stderr_buf: [0]u8 = undefined;
    var fbs = std.io.fixedBufferStream(stderr_buf[0..]);
    var ctx = Context{
        .allocator = arena.allocator(),
        .sessions = &sessions,
        .pool = &pool,
        .materializer = null,
        .log_writer = fbs.writer().any(),
    };

    const out = dispatch(&ctx, "no/such/method", null);
    switch (out) {
        .ok => return error.TestFailed,
        .err => |e| try std.testing.expectEqual(error.NotImplemented, e.err),
    }
}
