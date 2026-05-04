//! Bridge between the existing oauth-mux Config and the broker
//! AccountPool + CredentialMaterializer. Lives at the same level as
//! main.zig so it can import both `config.zig` and `broker/mod.zig`
//! without leaking either side across module boundaries.
//!
//! Anchor: docs/spec/broker-mcp-contract-2026-05-03.md §2.2 / §2.3.
//! Adapter consumer: src/broker/account_pool.zig + Server.materializer.

const std = @import("std");
const config_mod = @import("config.zig");
const broker = @import("broker/mod.zig");
const broker_types = @import("broker/types.zig");

/// Populate `pool` with one entry per `<provider>:<account>` defined in
/// the active Config. Liveness is `.unknown` and availability is
/// `.available`; Phase 2 wires real health correlation.
///
/// `profile_name` (optional) restricts visible accounts to those listed
/// in the named profile. Profile entries may be `provider:account` or
/// `provider:account#capability`; we match the `provider:account`
/// prefix. Out-of-profile accounts stay in the pool but are marked
/// non-selectable so callers can introspect why they're hidden.
pub fn populatePool(
    pool: *broker.AccountPool,
    cfg: config_mod.Config,
    profile_name: ?[]const u8,
) !void {
    var prov_it = cfg.providers.map.iterator();
    while (prov_it.next()) |prov_entry| {
        const provider_name = prov_entry.key_ptr.*;
        const provider_cfg = prov_entry.value_ptr.*;
        var acc_it = provider_cfg.accounts.map.iterator();
        while (acc_it.next()) |acc_entry| {
            const account_name = acc_entry.key_ptr.*;
            const id_buf = try std.fmt.allocPrint(
                pool.allocator,
                "{s}:{s}",
                .{ provider_name, account_name },
            );
            defer pool.allocator.free(id_buf);
            try pool.add(.{
                .id = id_buf,
                .selectable = true,
                .liveness = .unknown,
                .availability = .available,
            });
        }
    }

    if (profile_name) |pname| {
        if (cfg.profiles.map.get(pname)) |profile| {
            // Build a slice-of-slices into the original profile entries,
            // each trimmed to the `provider:account` prefix. No
            // allocation; restrictToAllowList only reads.
            var allow_buf = std.ArrayListUnmanaged([]const u8){};
            defer allow_buf.deinit(pool.allocator);
            for (profile.providers) |entry| {
                const head = if (std.mem.indexOfScalar(u8, entry, '#')) |idx| entry[0..idx] else entry;
                try allow_buf.append(pool.allocator, head);
            }
            pool.restrictToAllowList(allow_buf.items);
        }
    }
}

// ── credential materializer ──────────────────────────────────────────

/// Holds a borrowed reference to a loaded Config so the broker's
/// CredentialMaterializer vtable can find an account's configured
/// secret store. Lifetime: must outlive the broker server.
pub const ChatgptMaterializerCtx = struct {
    cfg: *const config_mod.Config,

    /// Cast to/from the broker's opaque ctx pointer.
    pub fn vtable(self: *ChatgptMaterializerCtx) broker_types.CredentialMaterializer {
        return .{
            .ctx = @as(*anyopaque, @ptrCast(self)),
            .materialize_chatgpt = chatgptThunk,
        };
    }
};

fn chatgptThunk(
    raw: *anyopaque,
    allocator: std.mem.Allocator,
    account_id: []const u8,
) broker_types.BrokerError!broker_types.ChatgptAuthTokens {
    const self: *ChatgptMaterializerCtx = @ptrCast(@alignCast(raw));
    return materializeChatgpt(self.cfg.*, allocator, account_id);
}

/// Resolve a `provider:account` to a chatgpt_auth_tokens tuple by
/// reading the account's configured secret store. Phase 1 supports the
/// `backend: "file"` shape, which is what oauth-mux uses for managed
/// codex accounts under ~/.config/oauth-mux/codex/<account>/auth.json.
pub fn materializeChatgpt(
    cfg: config_mod.Config,
    allocator: std.mem.Allocator,
    account_id: []const u8,
) broker_types.BrokerError!broker_types.ChatgptAuthTokens {
    const colon = std.mem.indexOfScalar(u8, account_id, ':') orelse
        return broker_types.BrokerError.InvalidParams;
    const provider = account_id[0..colon];
    const account = account_id[colon + 1 ..];

    const provider_cfg = cfg.providers.map.get(provider) orelse
        return broker_types.BrokerError.AccountNotFound;
    const acct_cfg = provider_cfg.accounts.map.get(account) orelse
        return broker_types.BrokerError.AccountNotFound;

    if (!std.mem.eql(u8, acct_cfg.secret.backend, "file")) {
        // Phase 1: only file-backend is wired. Other backends
        // (keychain, sops/age, command, env, stdin) need their own
        // secret/*.zig invocations, follow-up.
        return broker_types.BrokerError.SecretUnavailable;
    }
    const path_raw = acct_cfg.secret.path orelse
        return broker_types.BrokerError.SecretUnavailable;

    // Tilde-expand a leading ~ for ergonomics; otherwise use the path
    // as-is.
    const path = if (std.mem.startsWith(u8, path_raw, "~/")) blk: {
        const home = std.process.getEnvVarOwned(allocator, "HOME") catch
            return broker_types.BrokerError.SecretUnavailable;
        defer allocator.free(home);
        break :blk std.fmt.allocPrint(allocator, "{s}{s}", .{ home, path_raw[1..] }) catch
            return broker_types.BrokerError.OutOfMemory;
    } else allocator.dupe(u8, path_raw) catch
        return broker_types.BrokerError.OutOfMemory;
    defer allocator.free(path);

    const file = (if (std.fs.path.isAbsolute(path))
        std.fs.openFileAbsolute(path, .{})
    else
        std.fs.cwd().openFile(path, .{})) catch
        return broker_types.BrokerError.SecretUnavailable;
    defer file.close();

    const max_bytes = 1 << 20; // 1 MiB cap on auth.json
    const bytes = file.readToEndAlloc(allocator, max_bytes) catch
        return broker_types.BrokerError.SecretUnavailable;
    defer allocator.free(bytes);

    return parseAuthJson(allocator, bytes);
}

/// Parse a codex-shaped auth.json into ChatgptAuthTokens. Schema
/// reference: codex-rs/login/src/auth/storage.rs (AuthDotJson).
fn parseAuthJson(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) broker_types.BrokerError!broker_types.ChatgptAuthTokens {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch
        return broker_types.BrokerError.ParseError;
    defer parsed.deinit();

    if (parsed.value != .object) return broker_types.BrokerError.InvalidShape;
    const tokens_v = parsed.value.object.get("tokens") orelse return broker_types.BrokerError.InvalidShape;
    if (tokens_v != .object) return broker_types.BrokerError.InvalidShape;

    const access_v = tokens_v.object.get("access_token") orelse return broker_types.BrokerError.InvalidShape;
    if (access_v != .string) return broker_types.BrokerError.InvalidShape;
    const account_v = tokens_v.object.get("account_id") orelse return broker_types.BrokerError.InvalidShape;
    if (account_v != .string) return broker_types.BrokerError.InvalidShape;

    const access_token = allocator.dupe(u8, access_v.string) catch return broker_types.BrokerError.OutOfMemory;
    errdefer allocator.free(access_token);
    const acct_id = allocator.dupe(u8, account_v.string) catch return broker_types.BrokerError.OutOfMemory;
    errdefer allocator.free(acct_id);

    // Best-effort: extract chatgpt_plan_type and chatgpt_account_is_fedramp
    // from the id_token JWT's "https://api.openai.com/auth" claim. JWT
    // body is the second base64url-encoded segment; we decode it and
    // look up the nested field. Failure is non-fatal: plan_type stays
    // null, fedramp stays false.
    var plan_type: ?[]const u8 = null;
    var fedramp = false;
    if (tokens_v.object.get("id_token")) |id_v| {
        if (id_v == .string) {
            extractIdTokenClaims(allocator, id_v.string, &plan_type, &fedramp) catch {};
        }
    }

    return broker_types.ChatgptAuthTokens{
        .access_token = access_token,
        .account_id = acct_id,
        .plan_type = plan_type,
        .fedramp = fedramp,
    };
}

fn extractIdTokenClaims(
    allocator: std.mem.Allocator,
    jwt: []const u8,
    out_plan_type: *?[]const u8,
    out_fedramp: *bool,
) !void {
    // JWT shape: header.payload.signature, all base64url-no-padding.
    const dot1 = std.mem.indexOfScalar(u8, jwt, '.') orelse return error.BadJwt;
    const after_header = jwt[dot1 + 1 ..];
    const dot2 = std.mem.indexOfScalar(u8, after_header, '.') orelse return error.BadJwt;
    const payload_b64 = after_header[0..dot2];

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const payload_len = try decoder.calcSizeForSlice(payload_b64);
    const payload_buf = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload_buf);
    try decoder.decode(payload_buf, payload_b64);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_buf, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return;

    const auth_claim = parsed.value.object.get("https://api.openai.com/auth") orelse return;
    if (auth_claim != .object) return;

    if (auth_claim.object.get("chatgpt_plan_type")) |pt| {
        if (pt == .string) {
            out_plan_type.* = try allocator.dupe(u8, pt.string);
        }
    }
    if (auth_claim.object.get("chatgpt_account_is_fedramp")) |f| {
        if (f == .bool) out_fedramp.* = f.bool;
    }
}

test "parseAuthJson minimal shape" {
    const bytes =
        \\{
        \\  "OPENAI_API_KEY": null,
        \\  "tokens": {
        \\    "id_token": "ignored.eyJ9.x",
        \\    "access_token": "AT-1234",
        \\    "refresh_token": "RT-5678",
        \\    "account_id": "acc-abc"
        \\  },
        \\  "last_refresh": "now",
        \\  "auth_mode": "Chatgpt"
        \\}
    ;
    var tokens = try parseAuthJson(std.testing.allocator, bytes);
    defer tokens.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("AT-1234", tokens.access_token);
    try std.testing.expectEqualStrings("acc-abc", tokens.account_id);
    try std.testing.expect(tokens.plan_type == null);
    try std.testing.expect(!tokens.fedramp);
}

test "parseAuthJson rejects missing tokens key" {
    const bytes = "{\"OPENAI_API_KEY\":null,\"auth_mode\":\"Chatgpt\"}";
    const result = parseAuthJson(std.testing.allocator, bytes);
    try std.testing.expectError(broker_types.BrokerError.InvalidShape, result);
}

test "parseAuthJson tolerates malformed id_token (silent fallback)" {
    // Single dot instead of two — JWT extractor returns BadJwt, but we
    // swallow it and keep plan_type/fedramp at defaults.
    const bytes =
        \\{"tokens":{"access_token":"AT","account_id":"AID","id_token":"only-one-dot"}}
    ;
    var tokens = try parseAuthJson(std.testing.allocator, bytes);
    defer tokens.deinit(std.testing.allocator);
    try std.testing.expect(tokens.plan_type == null);
    try std.testing.expect(!tokens.fedramp);
    try std.testing.expectEqualStrings("AT", tokens.access_token);
}

test "parseAuthJson with plan_type from id_token" {
    // id_token payload: {"https://api.openai.com/auth":{"chatgpt_plan_type":"pro","chatgpt_account_is_fedramp":true}}
    // base64url-no-pad encoded:
    const id_token = "h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6dHJ1ZX19.s";
    const bytes = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"tokens":{{"access_token":"a","account_id":"b","id_token":"{s}"}}}}
    , .{id_token});
    defer std.testing.allocator.free(bytes);

    var tokens = try parseAuthJson(std.testing.allocator, bytes);
    defer tokens.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("pro", tokens.plan_type.?);
    try std.testing.expect(tokens.fedramp);
}

// ── pool population (above) ──────────────────────────────────────────

test "populatePool from JSON config" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } },
        \\        "max-2": { "priority": 20, "secret": { "backend": "file", "path": "/tmp/b" } }
        \\      }
        \\    },
        \\    "claude": {
        \\      "kind": "claude-command",
        \\      "accounts": {
        \\        "personal": { "priority": 10, "secret": { "backend": "command", "command": ["true"] } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePool(&pool, parsed.value, null);

    try std.testing.expectEqual(@as(usize, 3), pool.accounts.items.len);
}

test "populatePool with profile filter narrows selectable" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } },
        \\        "max-2": { "priority": 20, "secret": { "backend": "file", "path": "/tmp/b" } }
        \\      }
        \\    },
        \\    "claude": {
        \\      "kind": "claude-command",
        \\      "accounts": {
        \\        "personal": { "priority": 10, "secret": { "backend": "command", "command": ["true"] } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePool(&pool, parsed.value, "codex-max");

    try std.testing.expectEqual(@as(usize, 3), pool.accounts.items.len);

    const elected = try pool.elect(null, null, &.{});
    try std.testing.expect(std.mem.eql(u8, elected.id, "codex:max-1") or std.mem.eql(u8, elected.id, "codex:max-2"));

    var claude_present_and_blocked = false;
    for (pool.accounts.items) |a| {
        if (std.mem.eql(u8, a.id, "claude:personal")) {
            try std.testing.expect(!a.selectable);
            claude_present_and_blocked = true;
        }
    }
    try std.testing.expect(claude_present_and_blocked);
}
