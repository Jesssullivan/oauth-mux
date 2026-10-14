//! Closed native SIWC Responses profile. Provider errors are diagnostics,
//! never enrollment, renewal, quota-reset or accepted-work replay authority.
const std = @import("std");
const domain = @import("domain.zig");
const request_authority = @import("request_authority.zig");

pub const profile = "openai_siwc_responses_v1";
pub const provider = "openai_siwc";
pub const issuer = "https://auth.openai.com";
pub const audience = "https://api.openai.com/v1";
pub const auth_mode = "openai_siwc_access_token";
pub const Profile = enum { native, siwc_responses };
pub const Cause = enum { credential_rejected, policy_or_region, usage_limit, unknown };
pub const Stamp = struct {
    activation: [32]u8,
    family_generation: u64,
    writer_generation: u64,
    source_generation: u64,
    consent_generation: u64,
};

pub fn onlyFields(params: std.json.Value, fields: []const []const u8) !void {
    if (params != .object) return error.InvalidSiwcParams;
    for (params.object.keys()) |name| {
        var known = false;
        for (fields) |field| {
            if (std.mem.eql(u8, name, field)) {
                known = true;
                break;
            }
        }
        if (!known) return error.InvalidSiwcParams;
    }
}

pub fn selected(application: []const u8, declared: ?[]const u8) !Profile {
    const value = declared orelse return .native;
    if (!std.mem.eql(u8, application, "codex") or !std.mem.eql(u8, value, profile)) return error.SiwcProfileMismatch;
    return .siwc_responses;
}
pub fn validateDemand(route: Profile, application: []const u8, demand_provider: []const u8, demand_audience: []const u8, purpose: domain.Purpose, resource: domain.Resource) !void {
    if (route != .siwc_responses) return;
    if (!std.mem.eql(u8, application, "codex") or !std.mem.eql(u8, demand_provider, provider) or
        !std.mem.eql(u8, demand_audience, audience) or purpose != .request or
        !std.mem.eql(u8, resource.kind, "model") or resource.target.len == 0 or
        resource.unit != .tokens or resource.unit_name.len != 0 or resource.scope.len != 0)
        return error.SiwcProfileMismatch;
}
pub fn sameStamp(a: Stamp, b: Stamp) bool {
    return std.crypto.timing_safe.eql([32]u8, a.activation, b.activation) and
        a.family_generation == b.family_generation and a.writer_generation == b.writer_generation and
        a.source_generation == b.source_generation and a.consent_generation == b.consent_generation;
}
pub fn validStamp(value: Stamp) bool {
    return !std.mem.allEqual(u8, &value.activation, 0) and value.family_generation != 0 and
        value.writer_generation == value.family_generation and value.source_generation != 0 and value.consent_generation != 0;
}
fn diagnostic(value: ?[]const u8, maximum: usize) !void {
    if (value) |text| {
        if (text.len > maximum) return error.InvalidSiwcRejection;
        for (text) |byte| if (byte < 0x20 or byte > 0x7e) return error.InvalidSiwcRejection;
    }
}
pub fn rejection(status: u16, code: ?[]const u8, param: ?[]const u8, provider_request_id: ?[]const u8, pre_acceptance: bool, response_started: bool) !Cause {
    if (!pre_acceptance or response_started) return error.UnsafeReplay;
    if (status < 400 or status > 599) return error.InvalidSiwcRejection;
    try diagnostic(code, 128);
    try diagnostic(param, 256);
    try diagnostic(provider_request_id, 256);
    if (provider_request_id) |value| {
        if (!std.mem.startsWith(u8, value, "req_")) return error.InvalidSiwcRejection;
        for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return error.InvalidSiwcRejection;
    }
    const exact = code orelse return .unknown;
    if (status == 401 and std.mem.eql(u8, exact, "subscription_sharing_invalid_user")) return .credential_rejected;
    if (status == 403 and (std.mem.eql(u8, exact, "policy_violation") or std.mem.eql(u8, exact, "unsupported_country_region_territory"))) return .policy_or_region;
    if (status == 429 and std.mem.eql(u8, exact, "subscription_sharing_usage_limit_exceeded")) return .usage_limit;
    return .unknown;
}
// No quota/reset/window constructor is exported. Even a recognized cause and
// literal param cannot establish that another account has independent quota.
pub fn disposition(_: Cause) enum { stop } {
    return .stop;
}

test "SIWC is distinct from native chatgpt and rejects cross-profile demand" {
    try std.testing.expectEqual(Profile.native, try selected("codex", null));
    try std.testing.expectEqual(Profile.siwc_responses, try selected("codex", profile));
    try std.testing.expectError(error.SiwcProfileMismatch, selected("git", profile));
    try std.testing.expectError(error.SiwcProfileMismatch, selected("codex", "https://api.openai.com/v1"));
    const resource: domain.Resource = .{ .kind = "model", .target = "synthetic-model", .unit = .tokens };
    try validateDemand(.siwc_responses, "codex", provider, audience, .request, resource);
    try std.testing.expectError(error.SiwcProfileMismatch, validateDemand(.siwc_responses, "codex", "codex", "https://chatgpt.com", .request, resource));
    try std.testing.expectError(error.SiwcProfileMismatch, validateDemand(.siwc_responses, "codex", provider, audience, .renewal, resource));
    var wrong = resource;
    wrong.unit = .calls;
    try std.testing.expectError(error.SiwcProfileMismatch, validateDemand(.siwc_responses, "codex", provider, audience, .request, wrong));
}
test "structured rejection never upgrades status or model parameter to retry or refresh" {
    try std.testing.expectEqual(Cause.unknown, try rejection(401, null, null, null, true, false));
    try std.testing.expectEqual(Cause.credential_rejected, try rejection(401, "subscription_sharing_invalid_user", null, "req_synthetic", true, false));
    try std.testing.expectEqual(Cause.policy_or_region, try rejection(403, "unsupported_country_region_territory", null, "req_synthetic", true, false));
    try std.testing.expectEqual(Cause.usage_limit, try rejection(429, "subscription_sharing_usage_limit_exceeded", "model", "req_synthetic", true, false));
    try std.testing.expectEqual(Cause.usage_limit, try rejection(429, "subscription_sharing_usage_limit_exceeded", "", null, true, false));
    try std.testing.expectEqual(Cause.unknown, try rejection(401, "invalid_user", null, "req_synthetic", true, false));
    try std.testing.expectEqual(Cause.unknown, try rejection(429, "usage_limit", "model", "req_synthetic", true, false));
    for ([_]Cause{ .credential_rejected, .policy_or_region, .usage_limit, .unknown }) |cause| try std.testing.expect(disposition(cause) == .stop);
    try std.testing.expectEqual(Cause.unknown, try rejection(429, "rate_limit_exceeded", null, null, true, false));
    try std.testing.expectError(error.UnsafeReplay, rejection(429, "subscription_sharing_usage_limit_exceeded", "model", "req_synthetic", false, true));
    try std.testing.expectError(error.InvalidSiwcRejection, rejection(200, "subscription_sharing_usage_limit_exceeded", null, null, true, false));
    try std.testing.expectError(error.InvalidSiwcRejection, rejection(429, "subscription_sharing_usage_limit_exceeded", "model\n", null, true, false));
    try std.testing.expectError(error.InvalidSiwcRejection, rejection(429, "subscription_sharing_usage_limit_exceeded", "model", "account-label", true, false));
}

test "public verified or native copy consent claims do not enter the SIWC request API" {
    const a = std.testing.allocator;
    var forged = try std.json.parseFromSlice(std.json.Value, a, "{\"request_profile\":\"openai_siwc_responses_v1\",\"verified\":true}", .{});
    defer forged.deinit();
    try std.testing.expectError(error.InvalidSiwcParams, onlyFields(forged.value, &.{"request_profile"}));
    var copy = try std.json.parseFromSlice(std.json.Value, a, "{\"request_profile\":\"openai_siwc_responses_v1\",\"credential_acquisition_authorized\":true}", .{});
    defer copy.deinit();
    try std.testing.expectError(error.InvalidSiwcParams, onlyFields(copy.value, &.{"request_profile"}));
}

test "ordinary new request policy selection permits unknown quota and preserves sticky routes without replay" {
    const a = std.testing.allocator;
    var state = domain.State.init(a);
    defer state.deinit();
    _ = try state.connectSource(.{ .id = "source", .kind = .oauth, .provider = provider });
    for ([_][]const u8{ "account-a", "account-b" }) |id| {
        _ = try state.enroll(.{ .account_id = id, .source_id = "source", .identity = .{ .provider = provider, .issuer = issuer, .subject = id, .verified = true } }, 100);
        _ = try state.addGrant(.{ .id = id, .account_id = id, .source_id = "source", .credential_kind = .oauth_access, .ownership = .omux, .purposes = &.{.request}, .audience = audience, .provider_expires_at = 1000 });
    }
    // Domain metadata fixtures alone are not paired activation authority. The
    // actor additionally requires opaque currentPair proof on every request.
    const demand: domain.Demand = .{ .provider = provider, .issuer = issuer, .audience = audience, .resource = .{ .kind = "model", .target = "synthetic-model", .unit = .tokens }, .now = 100 };
    const first = try state.select(demand, null);
    try std.testing.expectEqualStrings("account-a", first.account_id);
    _ = try state.bind(.{ .id = "route", .application = "codex", .session_id = "thread", .account_id = first.account_id, .grant_id = first.grant_id, .grant_generation = first.generation });
    try std.testing.expect((try state.select(demand, "route")).sticky);
    _ = try state.beginLease(.{ .id = "first-lease", .binding_id = "route", .account_id = first.account_id, .grant_id = first.grant_id, .grant_generation = first.generation, .route_generation = 1, .started_at = 100, .expires_at = 200 }, 100);
    try state.pause("account-a", true);
    const other = try state.select(demand, "route");
    try std.testing.expectEqualStrings("account-b", other.account_id);
    try std.testing.expectError(error.InFlight, state.bind(.{ .id = "route", .application = "codex", .session_id = "thread", .account_id = other.account_id, .grant_id = other.grant_id, .grant_generation = other.generation, .route_generation = 2 }));
    try state.completeLease("first-lease");
    _ = try state.bind(.{ .id = "route", .application = "codex", .session_id = "thread", .account_id = other.account_id, .grant_id = other.grant_id, .grant_generation = other.generation, .route_generation = 2 });
    try std.testing.expect((try state.select(demand, "route")).sticky);
    try state.drain("account-b");
    try std.testing.expectError(error.NoEligibleAccount, state.select(demand, "route"));
    try state.pause("account-a", false);
    try std.testing.expectEqualStrings("account-a", (try state.select(demand, "route")).account_id);
    var expired = demand;
    expired.now = 1001;
    try std.testing.expectError(error.NoEligibleAccount, state.select(expired, "route"));
    try std.testing.expectEqual(@as(usize, 0), state.observations.items.len);
}

test "accepted or closed SIWC work cannot borrow a new request budget after lifecycle selection" {
    const a = std.testing.allocator;
    var ledger = request_authority.Ledger.init(a, 8);
    defer ledger.deinit();
    const fingerprint: [64]u8 = @splat('f');
    const first_handle: [64]u8 = @splat('a');
    const second_handle: [64]u8 = @splat('b');
    const stop_handle: [64]u8 = @splat('c');
    const reference: @import("native_owner.zig").NativeRef = .{ .owner_id = @splat(7), .adapter_epoch = 1, .endpoint_generation = 1, .thread_instance_generation = 1, .attachment_generation = 1 };
    var intent: request_authority.Intent = .{ .key = .{ .application = "codex", .session_id = "synthetic-thread", .request_id = "accepted-request" }, .binding_id = "route", .demand_fingerprint = &fingerprint, .native_ref = reference };
    _ = try ledger.issue(intent, &first_handle, "account-a", 200);
    _ = try ledger.reportForOwner("codex", &first_handle, reference, .{ .event = .accepted, .status = 200 });
    try std.testing.expectError(error.AttemptBudgetExhausted, ledger.checkIssue(intent));
    try std.testing.expectError(error.UnsafeReplay, ledger.reportForOwner("codex", &first_handle, reference, .{ .event = .rejected, .status = 429, .pre_acceptance = true, .response_started = false }));
    _ = try ledger.reportForOwner("codex", &first_handle, reference, .{ .event = .completed });
    try std.testing.expectError(error.AttemptBudgetExhausted, ledger.checkIssue(intent));
    intent.key.request_id = "new-independent-request";
    try std.testing.expectEqual(@as(u8, 1), try ledger.issue(intent, &second_handle, "account-b", 200));
    intent.key.request_id = "stopped-usage-request";
    _ = try ledger.issue(intent, &stop_handle, "account-a", 200);
    _ = try ledger.reportForOwner("codex", &stop_handle, reference, .{ .event = .abandoned, .status = 429, .pre_acceptance = true, .response_started = false });
    try std.testing.expectError(error.AttemptBudgetExhausted, ledger.checkIssue(intent));
    var restored = try request_authority.Ledger.fromSnapshot(a, 8, ledger.snapshot());
    defer restored.deinit();
    try std.testing.expectError(error.AttemptBudgetExhausted, restored.checkIssue(intent));
}
