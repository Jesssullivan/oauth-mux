//! Read-only application-context projection. Inputs are actor-owned metadata,
//! not client assertions; this creates no grant, route, lease or authority.
const std = @import("std");
const domain = @import("domain.zig");

pub const method = "setup.applicationReadiness";
pub const Application = enum { codex, git, claude };
pub const State = enum { unknown, ready, action_required };
pub const Reason = enum {
    ready,
    context_required,
    revision_changed,
    source_required,
    source_unauthorized,
    source_detached,
    acquisition_unverified,
    acquisition_unsupported,
    identity_required,
    compatible_authority_required,
    custody_unavailable,
    custody_generation_mismatch,
    renewal_owner_mismatch,
    renewal_owner_unverified,
    adapter_configuration_required,
    ordinary_launch_unverified,
    native_unsupported,
    capacity_unknown,
    capacity_unavailable,
};
pub const Action = enum {
    none,
    select_application_context,
    refresh_context,
    connect_source,
    reconcile_source,
    inspect_acquisition,
    verify_identity,
    enroll_compatible_authority,
    repair_custody,
    inspect_renewal_owner,
    install_adapter,
    verify_native_capability,
    inspect_capacity,
};
pub const Observation = struct { state: State = .unknown, reason: Reason, action: Action };
pub const RenewalOwner = enum { none, external, omux };
pub const CustodyState = enum { ready, refreshing, quarantined };
/// Borrowed private keys and SQL metadata. No credential decryption is needed.
pub const Custody = struct {
    account_id: []const u8,
    grant_id: []const u8,
    generation: u64,
    state: CustodyState,
    renewal_owner: RenewalOwner,
};
pub const Configuration = enum { unknown, installed, absent };
pub const OrdinaryLaunch = enum { unknown, verified, unsupported };
pub const Acquisition = enum { unknown, available, unsupported };
/// The actor supplies current, independently observed context-bound facts.
/// Installed configuration and a catalog declaration do not verify launch.
pub const AdapterEvidence = struct {
    application: ?Application = null,
    revision: ?u64 = null,
    configuration: Configuration = .unknown,
    ordinary_launch: OrdinaryLaunch = .unknown,
    acquisition: Acquisition = .unknown,
};
pub const Input = struct {
    application: Application,
    revision: u64,
    expected_revision: ?u64 = null,
    /// Actor-created keyed opaque context digest; never a path or identity.
    context_ref: ?[]const u8 = null,
    /// Optional private source constraint resolved by the actor, not a wire ID.
    source_id: ?[]const u8 = null,
    demand: ?domain.Demand = null,
    custody: []const Custody = &.{},
    custody_available: bool = true,
    adapter: AdapterEvidence = .{},
};
pub const Report = struct {
    schema_version: u8 = 1,
    scope: enum { joined_request_authority_and_adapter_diagnostics } = .joined_request_authority_and_adapter_diagnostics,
    application: Application,
    revision: u64,
    context_ref: ?[]const u8 = null,
    /// Actor evaluation clock for this observation, never a cached permit.
    evaluated_at: ?i64 = null,
    ready: bool = false,
    state: State = .unknown,
    reason: Reason = .context_required,
    action: Action = .select_application_context,
    source: Observation = .{ .reason = .source_required, .action = .connect_source },
    enrollment: Observation = .{ .reason = .acquisition_unverified, .action = .inspect_acquisition },
    identity: Observation = .{ .reason = .identity_required, .action = .verify_identity },
    authority: Observation = .{ .reason = .compatible_authority_required, .action = .enroll_compatible_authority },
    adapter: Observation = .{ .reason = .ordinary_launch_unverified, .action = .verify_native_capability },
    ordinary_launch: Observation = .{ .reason = .ordinary_launch_unverified, .action = .verify_native_capability },
    capacity: Observation = .{ .reason = .capacity_unknown, .action = .inspect_capacity },
    renewal_owner: enum { unknown, external, omux } = .unknown,
    provider_access: bool = false,
    enrollment_success_proven: bool = false,
    seamless_handoff_proven: bool = false,
};

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
fn ready() Observation {
    return .{ .state = .ready, .reason = .ready, .action = .none };
}
fn needs(reason: Reason, action: Action) Observation {
    return .{ .state = .action_required, .reason = reason, .action = action };
}
pub fn validContextRef(value: []const u8) bool {
    if (value.len != 64) return false;
    for (value) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    return !std.mem.allEqual(u8, value, '0');
}
fn validateContext(input: Input, demand: domain.Demand) !void {
    if (demand.purpose != .request or demand.now < 0) return error.InvalidApplicationContext;
    switch (input.application) {
        .codex => if (!eql(demand.provider, "codex") or !eql(demand.audience, "https://chatgpt.com") or !eql(demand.resource.kind, "model")) return error.InvalidApplicationContext,
        .git => if (!eql(demand.provider, "github") or !eql(demand.audience, "https://github.com") or !eql(demand.resource.kind, "repository")) return error.InvalidApplicationContext,
        .claude => if (!eql(demand.provider, "claude")) return error.InvalidApplicationContext,
    }
}
fn sourceFor(state: *const domain.State, id: []const u8) ?domain.Source {
    for (state.sources.items) |source| if (eql(source.id, id)) return source;
    return null;
}
fn contains(values: []const []const u8, value: []const u8) bool {
    for (values) |item| if (eql(item, value)) return true;
    return false;
}
fn contextSource(input: Input, demand: domain.Demand, source: domain.Source) bool {
    if (input.source_id) |id| if (!eql(id, source.id)) return false;
    return source.provider.len == 0 or eql(source.provider, demand.provider);
}
fn authorized(source: domain.Source, now: i64) bool {
    return source.status != .disconnected and source.authorized_at <= now and (source.authorized_until == null or source.authorized_until.? > now);
}
fn applySource(result: *Report, input: Input, source: domain.Source, now: i64) void {
    if (!authorized(source, now)) {
        result.source = needs(.source_unauthorized, .connect_source);
        result.enrollment = result.source;
        return;
    }
    result.source = ready();
    if (source.status == .detached) {
        // Detached sources may retain independently valid request grants.
        result.enrollment = needs(.source_detached, .reconcile_source);
        return;
    }
    if (input.adapter.application != input.application or input.adapter.revision != input.revision) return;
    result.enrollment = switch (input.adapter.acquisition) {
        .available => ready(),
        .unknown => .{ .reason = .acquisition_unverified, .action = .inspect_acquisition },
        .unsupported => needs(.acquisition_unsupported, .inspect_acquisition),
    };
}
fn applyAdapter(result: *Report, input: Input) void {
    if (input.adapter.application != input.application or input.adapter.revision != input.revision) return;
    result.adapter = switch (input.adapter.configuration) {
        .installed => ready(),
        .absent => needs(.adapter_configuration_required, .install_adapter),
        .unknown => .{ .reason = .ordinary_launch_unverified, .action = .verify_native_capability },
    };
    result.ordinary_launch = switch (input.adapter.ordinary_launch) {
        .verified => ready(),
        .unknown => .{ .reason = .ordinary_launch_unverified, .action = .verify_native_capability },
        // Unsupported capability is an explicit limitation, never readiness.
        .unsupported => .{ .reason = .native_unsupported, .action = .verify_native_capability },
    };
}
fn custodyFor(input: Input, grant: domain.Grant) ?Custody {
    for (input.custody) |row| if (eql(row.account_id, grant.account_id) and eql(row.grant_id, grant.id)) return row;
    return null;
}
fn custodyObservation(input: Input, grant: domain.Grant) Observation {
    const held = custodyFor(input, grant) orelse return .{ .reason = .custody_unavailable, .action = .repair_custody };
    if (held.state != .ready) return .{ .reason = .custody_unavailable, .action = .repair_custody };
    if (held.generation != grant.generation) return needs(.custody_generation_mismatch, .repair_custody);
    const expected: RenewalOwner = switch (grant.ownership) {
        .external => .external,
        .omux => .omux,
        // An adopted label does not establish retirement of the old writer.
        .adopted => return .{ .reason = .renewal_owner_unverified, .action = .inspect_renewal_owner },
    };
    if (held.renewal_owner != expected) return needs(.renewal_owner_mismatch, .inspect_renewal_owner);
    return ready();
}
fn finish(result: *Report, capacity_required: bool) void {
    // Enrollment and optional capacity are separate observations. Usable
    // retained authority need not reacquire its original source.
    for ([_]Observation{ result.source, result.identity, result.authority, result.adapter, result.ordinary_launch }) |observation| {
        if (observation.state == .action_required) {
            result.state = .action_required;
            result.reason = observation.reason;
            result.action = observation.action;
            return;
        }
    }
    if (result.capacity.state == .action_required or (capacity_required and result.capacity.state != .ready)) {
        result.state = result.capacity.state;
        result.reason = result.capacity.reason;
        result.action = result.capacity.action;
        return;
    }
    for ([_]Observation{ result.source, result.identity, result.authority, result.adapter, result.ordinary_launch }) |observation| {
        if (observation.state != .ready) {
            result.reason = observation.reason;
            result.action = observation.action;
            return;
        }
    }
    result.ready = true;
    result.state = .ready;
    result.reason = .ready;
    result.action = .none;
}

/// One actor revision, one explicit demand, and one grant's lineage. The
/// singleton borrowed view invokes the exact ordinary routing predicate.
/// It never selects a lease, binds a route, decrypts or renews a credential.
pub fn project(state: *const domain.State, input: Input) !Report {
    if (state.sources.items.len > domain.max_records or state.accounts.items.len > domain.max_records or state.grants.items.len > domain.max_records or state.observations.items.len > domain.max_records or input.custody.len > domain.max_records) return error.ApplicationReadinessLimit;
    for (input.custody, 0..) |row, index| {
        if (row.generation == 0) return error.InvalidApplicationCustody;
        for (input.custody[0..index]) |prior| if (eql(row.account_id, prior.account_id) and eql(row.grant_id, prior.grant_id)) return error.InvalidApplicationCustody;
    }
    var result: Report = .{ .application = input.application, .revision = input.revision };
    if (input.context_ref) |reference| {
        if (!validContextRef(reference)) return error.InvalidApplicationContext;
        result.context_ref = reference;
    }
    if (input.expected_revision) |expected| if (expected != input.revision) {
        result.reason = .revision_changed;
        result.action = .refresh_context;
        return result;
    };
    const demand = input.demand orelse return result;
    if (input.context_ref == null) return result;
    try validateContext(input, demand);
    result.evaluated_at = demand.now;
    if (!input.custody_available) {
        result.reason = .custody_unavailable;
        result.action = .repair_custody;
        result.authority = .{ .reason = .custody_unavailable, .action = .repair_custody };
        return result;
    }
    // Validate the demand even with an empty source/grant set.
    if (state.select(demand, null)) |_| {} else |err| {
        switch (err) {
            error.NoEligibleAccount => {},
            else => return err,
        }
    }
    applyAdapter(&result, input);
    result.source = needs(.source_required, .connect_source);
    result.identity = needs(.identity_required, .verify_identity);
    result.authority = needs(.compatible_authority_required, .enroll_compatible_authority);
    const base = result;
    var best_score: u8 = 0;
    var have_partial = false;
    for (state.sources.items) |source| {
        if (!contextSource(input, demand, source)) continue;
        var partial = base;
        applySource(&partial, input, source, demand.now);
        var score: u8 = if (authorized(source, demand.now)) 1 else 0;
        for (state.accounts.items) |account| {
            if (!contains(account.source_ids, source.id) or !account.identity.verified or !eql(account.identity.provider, demand.provider) or account.lifecycle != .active) continue;
            if (demand.issuer) |issuer| if (!eql(account.identity.issuer, issuer)) continue;
            if (demand.allowed_account_ids.len > 0 and !contains(demand.allowed_account_ids, account.id)) continue;
            partial.identity = ready();
            score = if (authorized(source, demand.now)) 2 else 0;
            for (state.grants.items) |grant| {
                if (!eql(grant.source_id, source.id) or !eql(grant.account_id, account.id)) continue;
                var candidate = grant;
                var view = state.*;
                view.grants = std.ArrayList(domain.Grant).initBuffer((&candidate)[0..1]);
                view.grants.items.len = 1;
                // Credential compatibility/custody and resource availability
                // are separate facts. Keep source/purpose/scope/lifecycle
                // checks, without disguising missing quota as enrollment.
                var authority_view = view;
                authority_view.observations = .empty;
                var authority_demand = demand;
                authority_demand.requires_capacity = false;
                _ = authority_view.select(authority_demand, null) catch |err| switch (err) {
                    error.NoEligibleAccount => continue,
                    else => return err,
                };
                const authority = custodyObservation(input, grant);
                if (authority.state == .ready) {
                    var joined = base;
                    applySource(&joined, input, source, demand.now);
                    joined.identity = ready();
                    joined.authority = authority;
                    joined.renewal_owner = switch (custodyFor(input, grant).?.renewal_owner) {
                        .external => .external,
                        .omux => .omux,
                        .none => unreachable,
                    };
                    var capacity_demand = demand;
                    capacity_demand.requires_capacity = true;
                    _ = view.select(capacity_demand, null) catch |err| switch (err) {
                        error.NoEligibleAccount => {
                            if (view.select(authority_demand, null)) |_| {} else |capacity_err| {
                                switch (capacity_err) {
                                    error.NoEligibleAccount => joined.capacity = needs(.capacity_unavailable, .inspect_capacity),
                                    else => return capacity_err,
                                }
                            }
                            const candidate_score: u8 = if (joined.capacity.state == .action_required) 4 else 5;
                            if (candidate_score > best_score) {
                                result = joined;
                                best_score = candidate_score;
                                have_partial = true;
                            }
                            continue;
                        },
                        else => return err,
                    };
                    joined.capacity = ready();
                    finish(&joined, demand.requires_capacity);
                    return joined;
                }
                if (best_score < 3) {
                    partial.authority = authority;
                    result = partial;
                    best_score = 3;
                    have_partial = true;
                }
            }
        }
        if (!have_partial or score > best_score) {
            result = partial;
            best_score = score;
            have_partial = true;
        }
    }
    finish(&result, demand.requires_capacity);
    return result;
}
