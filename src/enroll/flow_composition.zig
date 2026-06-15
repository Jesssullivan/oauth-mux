//! flow_composition.zig — the production `RunFlowFn` for the reauth engine
//! (flow-composition train car; successor to the #378 orchestrator graduation,
//! TIN-2048/TIN-2064).
//!
//! It is the seam-binding glue between the engine (`reauth.zig`) and the flow
//! sub-modules. The engine's `begin()` calls ONE `RunFlowFn`; in production this
//! module's `runFlow` IS that function. It dispatches on the engine's `Flow`
//! enum and drives the matching sub-module THROUGH that module's own injected
//! seam bundle — so the composition itself stays PURE: it opens no socket, makes
//! no HTTP call, holds no real clock. Tests bind deterministic fakes, exactly
//! like `device_code.zig` / `orchestrator.zig` / the warm loop.
//!
//! Mediation-not-control (in-agent-reauth-handoff contract): `runFlow` only ever
//! executes INSIDE the engine's `begin()`, which runs only after operator
//! approval. There is no other caller and no bypass. `command_owned` and
//! `pat_paste` are NOT engine-run (vendor-CLI delegation / manual paste) and are
//! refused BEFORE the flow config is unpacked or any seam is touched — no
//! browser, no process spawn, no network. `redirect_loopback` composition needs
//! a LIVE loopback socket to obtain the parsed callback (the callback_server
//! pure core only handles an already-parsed request); that live `awaitCallback`
//! seam is the next sub-car, so loopback is refused here too. The device_code
//! flow composes end-to-end through pure seams and is fully wired.
//!
//! Secrets: `runFlow` moves the sub-module's owned token slices straight into the
//! engine's `FlowOutcome` and returns them; it logs nothing token-bearing. The
//! engine frees them on reject/store-failure or returns them on success.

const std = @import("std");
const engine = @import("reauth.zig");
const device_code = @import("device_code.zig");

const log = std.log.scoped(.flow_composition);

/// The opaque `flow_ctx` the engine passes to `runFlow` points at this. It
/// carries the per-flow bindings (provider endpoints + the sub-module's own seam
/// bundle). A binding is `null` when that flow is not configured for the account.
pub const FlowConfig = struct {
    /// device_code (RFC 8628) binding. Required when `Flow.device_code` is run.
    device: ?DeviceCodeBinding = null,
    // loopback: ?LoopbackBinding — next sub-car (needs a live awaitCallback seam).
};

/// Everything the device-code arm needs: the provider endpoints/client and the
/// device_code sub-module's own injected seam bundle (authorize / poll / extract
/// / display / clock / sleep — every one fake-able, so this stays pure).
pub const DeviceCodeBinding = struct {
    device_auth_url: []const u8,
    token_url: []const u8,
    client_id: []const u8,
    scope: []const u8,
    seams: device_code.DeviceCodeSeams,
};

/// Production `engine.RunFlowFn`. Bind into `engine.Seams.run_flow` with a
/// `*const FlowConfig` as `flow_ctx`. Exhaustive over `engine.Flow` — every
/// variant is handled, so a new `Flow` member is a compile error here (the
/// dispatcher can never silently drop a flow).
pub fn runFlow(
    allocator: std.mem.Allocator,
    flow: engine.Flow,
    flow_ctx: *anyopaque,
) error{ FlowFailed, OutOfMemory }!engine.FlowOutcome {
    // Refuse the non-engine-run flows BEFORE unpacking the config or touching any
    // seam: no spawn, no browser, no network can occur on these paths.
    switch (flow) {
        .command_owned, .pat_paste => {
            log.debug("flow '{s}' is not engine-run (vendor-CLI delegation / manual paste); refusing", .{@tagName(flow)});
            return error.FlowFailed;
        },
        .redirect_loopback => {
            log.debug("redirect_loopback composition needs a live awaitCallback seam (next sub-car); refusing", .{});
            return error.FlowFailed;
        },
        .device_code => {},
    }

    const cfg: *const FlowConfig = @ptrCast(@alignCast(flow_ctx));
    const binding = cfg.device orelse {
        log.warn("device_code flow selected but no device binding is configured", .{});
        return error.FlowFailed;
    };

    const dcf = device_code.DeviceCodeFlow.init(
        allocator,
        binding.seams,
        binding.device_auth_url,
        binding.token_url,
        binding.client_id,
        binding.scope,
    );
    const result = dcf.run() catch |e| switch (e) {
        // Host pressure, not the account's fault — surface as-is so the engine
        // can retry rather than charge a flow failure.
        error.OutOfMemory => return error.OutOfMemory,
        // Every other DeviceCodeError (AuthorizationDenied / Timeout / HttpFailed
        // / InvalidResponse / InvalidToken / ...) is a flow failure.
        else => return error.FlowFailed,
    };

    // device_code.FlowResult is field-identical to engine.FlowOutcome; ownership
    // of every owned slice transfers straight through to the engine.
    return .{
        .access_token = result.access_token,
        .refresh_token = result.refresh_token,
        .expires_at = result.expires_at,
        .email = result.email,
        .account_id = result.account_id,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — deterministic fakes; std.testing.allocator leak-checked. No network,
// no socket, no real clock. A `*FlowConfig` is the engine's opaque flow_ctx.
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A spy bound to all six device_code seams that records if ANY is invoked, so
/// the "refused before any seam" claim is ENFORCED, not just documented:
/// command_owned / pat_paste / loopback must return FlowFailed with zero seam
/// calls. (Its fn bodies never run in those tests; they only need to type-check
/// against the exact seam signatures.)
const NoSeamSpy = struct {
    touched: bool = false,

    fn deviceAuthorize(_: std.mem.Allocator, ctx: *anyopaque, _: []const u8, _: []const u8, _: []const u8) error{ HttpFailed, InvalidResponse, OutOfMemory }!device_code.DeviceAuthResponse {
        const self: *NoSeamSpy = @ptrCast(@alignCast(ctx));
        self.touched = true;
        return error.HttpFailed;
    }
    fn pollToken(_: std.mem.Allocator, ctx: *anyopaque, _: []const u8, _: []const u8, _: []const u8) error{ HttpFailed, InvalidResponse, OutOfMemory, AuthorizationPending, SlowDown, AuthorizationDenied }!device_code.TokenExchangeResponse {
        const self: *NoSeamSpy = @ptrCast(@alignCast(ctx));
        self.touched = true;
        return error.HttpFailed;
    }
    fn extractIdentity(_: std.mem.Allocator, ctx: *anyopaque, _: ?[]const u8, _: []const u8) error{ InvalidToken, OutOfMemory }!device_code.IdentityInfo {
        const self: *NoSeamSpy = @ptrCast(@alignCast(ctx));
        self.touched = true;
        return error.InvalidToken;
    }
    fn display(_: std.mem.Allocator, ctx: *anyopaque, _: []const u8, _: []const u8, _: ?[]const u8) error{OutOfMemory}!void {
        const self: *NoSeamSpy = @ptrCast(@alignCast(ctx));
        self.touched = true;
    }
    fn clock(ctx: *anyopaque) i64 {
        const self: *NoSeamSpy = @ptrCast(@alignCast(ctx));
        self.touched = true;
        return 0;
    }
    fn sleep(ctx: *anyopaque, _: i64) void {
        const self: *NoSeamSpy = @ptrCast(@alignCast(ctx));
        self.touched = true;
    }

    fn seams(self: *NoSeamSpy) device_code.DeviceCodeSeams {
        return .{
            .device_authorize = deviceAuthorize,
            .poll_token = pollToken,
            .extract_identity = extractIdentity,
            .display_instructions = display,
            .clock = clock,
            .sleep = sleep,
            .device_authorize_ctx = self,
            .poll_token_ctx = self,
            .extract_identity_ctx = self,
            .display_instructions_ctx = self,
            .clock_ctx = self,
            .sleep_ctx = self,
        };
    }
};

fn deviceConfig(spy: *NoSeamSpy) FlowConfig {
    return .{ .device = .{
        .device_auth_url = "https://example.invalid/device",
        .token_url = "https://example.invalid/token",
        .client_id = "cid",
        .scope = "openid",
        .seams = spy.seams(),
    } };
}

test "command_owned is refused before any seam is touched (no spawn/browser/network)" {
    var spy = NoSeamSpy{};
    var cfg = deviceConfig(&spy);
    try testing.expectError(error.FlowFailed, runFlow(testing.allocator, .command_owned, &cfg));
    try testing.expect(!spy.touched); // structurally: refused before unpacking cfg
}

test "pat_paste is refused before any seam is touched" {
    var spy = NoSeamSpy{};
    var cfg = deviceConfig(&spy);
    try testing.expectError(error.FlowFailed, runFlow(testing.allocator, .pat_paste, &cfg));
    try testing.expect(!spy.touched);
}

test "redirect_loopback is refused (composition is the next sub-car), no seam touched" {
    var spy = NoSeamSpy{};
    var cfg = deviceConfig(&spy);
    try testing.expectError(error.FlowFailed, runFlow(testing.allocator, .redirect_loopback, &cfg));
    try testing.expect(!spy.touched);
}

test "device_code with no binding configured returns FlowFailed" {
    var cfg = FlowConfig{}; // device = null
    try testing.expectError(error.FlowFailed, runFlow(testing.allocator, .device_code, &cfg));
}

// ── A scripted device_code fake that drives run() to SUCCESS, so the device_code
//    arm is exercised end-to-end through the composition (authorize → display →
//    poll(success) → extract identity → FlowResult → FlowOutcome). Every returned
//    slice is allocator-owned so the leak checker proves the ownership transfer.
const HappyDevice = struct {
    alloc: std.mem.Allocator,
    fn dup(self: *HappyDevice, s: []const u8) []const u8 {
        return self.alloc.dupe(u8, s) catch unreachable;
    }
    fn deviceAuthorize(_: std.mem.Allocator, ctx: *anyopaque, _: []const u8, _: []const u8, _: []const u8) error{ HttpFailed, InvalidResponse, OutOfMemory }!device_code.DeviceAuthResponse {
        const self: *HappyDevice = @ptrCast(@alignCast(ctx));
        return .{
            .device_code = self.dup("DEV-CODE"),
            .user_code = self.dup("WXYZ-1234"),
            .verification_uri = self.dup("https://example.invalid/activate"),
            .verification_uri_complete = null,
            .expires_in = 1800,
            .interval = 5,
        };
    }
    fn pollToken(_: std.mem.Allocator, ctx: *anyopaque, _: []const u8, _: []const u8, _: []const u8) error{ HttpFailed, InvalidResponse, OutOfMemory, AuthorizationPending, SlowDown, AuthorizationDenied }!device_code.TokenExchangeResponse {
        const self: *HappyDevice = @ptrCast(@alignCast(ctx));
        return .{
            .access_token = self.dup("ACCESS-TOK"),
            .token_type = self.dup("Bearer"),
            .expires_in = 3600,
            .refresh_token = self.dup("REFRESH-TOK"),
            .scope = null,
            .id_token = self.dup("ID.JWT.TOK"),
        };
    }
    fn extractIdentity(_: std.mem.Allocator, ctx: *anyopaque, _: ?[]const u8, _: []const u8) error{ InvalidToken, OutOfMemory }!device_code.IdentityInfo {
        const self: *HappyDevice = @ptrCast(@alignCast(ctx));
        return .{ .email = self.dup("alice@example.com"), .account_id = self.dup("acct-123") };
    }
    fn display(_: std.mem.Allocator, _: *anyopaque, _: []const u8, _: []const u8, _: ?[]const u8) error{OutOfMemory}!void {}
    fn clock(_: *anyopaque) i64 {
        return 1_000_000;
    }
    fn sleep(_: *anyopaque, _: i64) void {}

    fn seams(self: *HappyDevice) device_code.DeviceCodeSeams {
        return .{
            .device_authorize = deviceAuthorize,
            .poll_token = pollToken,
            .extract_identity = extractIdentity,
            .display_instructions = display,
            .clock = clock,
            .sleep = sleep,
            .device_authorize_ctx = self,
            .poll_token_ctx = self,
            .extract_identity_ctx = self,
            .display_instructions_ctx = self,
            .clock_ctx = self,
            .sleep_ctx = self,
        };
    }
};

test "device_code happy path composes end-to-end into a filled FlowOutcome" {
    var dev = HappyDevice{ .alloc = testing.allocator };
    var cfg = FlowConfig{ .device = .{
        .device_auth_url = "https://example.invalid/device",
        .token_url = "https://example.invalid/token",
        .client_id = "cid",
        .scope = "openid",
        .seams = dev.seams(),
    } };

    const outcome = try runFlow(testing.allocator, .device_code, &cfg);
    defer {
        testing.allocator.free(outcome.access_token);
        if (outcome.refresh_token) |rt| testing.allocator.free(rt);
        testing.allocator.free(outcome.email);
        testing.allocator.free(outcome.account_id);
    }

    // Required fields are present (composition-correctness: no field left null).
    try testing.expectEqualStrings("ACCESS-TOK", outcome.access_token);
    try testing.expectEqualStrings("REFRESH-TOK", outcome.refresh_token.?);
    try testing.expectEqualStrings("alice@example.com", outcome.email);
    try testing.expectEqualStrings("acct-123", outcome.account_id);
    try testing.expectEqual(@as(?i64, 1_000_000 + 3600), outcome.expires_at);
}
