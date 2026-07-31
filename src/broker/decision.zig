//! Total deterministic route election for the shared broker core.
//!
//! The reducer consumes exact-model demand, projected route evidence, and a
//! borrowed read-only lease snapshot. It performs no allocation, I/O, clock
//! access, persistence, locking, provider call, or adapter behavior.

const std = @import("std");
const model_demand = @import("model_demand.zig");
const route_observation = @import("route_observation.zig");

pub const ModelDemand = model_demand.ModelDemand;
pub const RouteEvidence = route_observation.RouteEvidence;
pub const RouteHandle = route_observation.RouteHandle;

/// Value-free per-route lease projection supplied by the synchronization owner.
/// Duplicate rows are folded conservatively and deterministically by the query:
/// active loads saturating-add and the latest known selection wins.
pub const LeaseObservation = struct {
    route: RouteHandle,
    active_leases: u64,
    last_selected_at: ?i64,
};

/// Session-relative, read-only lease view. Missing lease rows mean zero active
/// load and no prior selection; the reducer never mutates this snapshot.
pub const LeaseView = struct {
    sticky_route: ?RouteHandle = null,
    routes: []const LeaseObservation = &.{},
};

/// The complete result of broker election. No-route is an ordinary total result,
/// not an error or panic.
pub const BrokerDecision = union(enum) {
    select_route: RouteHandle,
    no_route,
};

/// Elect one exact-model route using this strict order:
///
/// 1. admitted, identity-clear, non-conflicting exact-model routes only;
/// 2. retain an eligible sticky route even when its availability aged to
///    `unknown`; explicit exhausted/dead/unavailable evidence breaks stickiness;
/// 3. for a new selection, known-good (`available`) above `unknown`;
/// 4. least active lease load;
/// 5. least-recently selected (`null` means never selected);
/// 6. lowest stable opaque route handle.
pub fn reduce(
    demand: ModelDemand,
    routes: []const RouteEvidence,
    leases: LeaseView,
) BrokerDecision {
    if (!demand.isValid()) return .no_route;

    if (leases.sticky_route) |sticky| {
        for (routes, 0..) |candidate, index| {
            if (!routeEql(candidate.route, sticky)) continue;
            if (!isEligible(demand, routes, index)) continue;
            return .{ .select_route = candidate.route };
        }
    }

    var best_index: ?usize = null;

    for (routes, 0..) |candidate, index| {
        if (!isEligible(demand, routes, index)) continue;
        if (best_index == null or prefers(candidate, routes[best_index.?], leases)) {
            best_index = index;
        }
    }

    if (best_index) |index| {
        return .{ .select_route = routes[index].route };
    }
    return .no_route;
}

fn isEligible(demand: ModelDemand, routes: []const RouteEvidence, index: usize) bool {
    const candidate = routes[index];
    if (!candidate.exact_model.isValid()) return false;
    if (!demand.accepts(candidate.exact_model)) return false;
    if (candidate.admission != .admitted) return false;
    if (candidate.identity == null) return false;
    if (!candidate.identity.?.isValid()) return false;
    if (readinessTier(candidate.readiness) == null) return false;
    if (hasRouteEvidenceConflict(routes, index)) return false;
    return !hasIdentityConflict(routes, index, candidate.identity.?);
}

/// Multiple observations for one route/model are accepted only when every
/// decision-relevant field agrees. A same handle may legitimately expose other
/// exact models, but contradictory identity, admission, or readiness evidence
/// for one exact-model route fails closed.
fn hasRouteEvidenceConflict(routes: []const RouteEvidence, candidate_index: usize) bool {
    const candidate = routes[candidate_index];
    for (routes, 0..) |other, other_index| {
        if (other_index == candidate_index) continue;
        if (!routeEql(other.route, candidate.route)) continue;
        if (!other.exact_model.eql(candidate.exact_model)) continue;

        if (candidate.identity == null or other.identity == null) return true;
        if (!candidate.identity.?.eql(other.identity.?)) return true;
        if (candidate.admission != other.admission) return true;
        if (candidate.readiness != other.readiness) return true;
        if (candidate.provenance != other.provenance) return true;
        if (candidate.resets_at_s != other.resets_at_s) return true;
    }
    return false;
}

fn hasIdentityConflict(
    routes: []const RouteEvidence,
    candidate_index: usize,
    identity: route_observation.IdentityEvidence,
) bool {
    const candidate = routes[candidate_index];
    for (routes, 0..) |other, other_index| {
        if (other_index == candidate_index) continue;
        if (routeEql(other.route, candidate.route)) continue;
        if (!other.exact_model.eql(candidate.exact_model)) continue;
        if (other.identity != null and other.identity.?.eql(identity)) return true;
    }
    return false;
}

fn readinessTier(readiness: route_observation.Readiness) ?u1 {
    return switch (readiness) {
        .available => 1,
        .unknown => 0,
        .exhausted => null,
    };
}

const LeaseRank = struct {
    active_leases: u64 = 0,
    last_selected_at: ?i64 = null,
};

fn leaseRank(view: LeaseView, route_handle: RouteHandle) LeaseRank {
    var rank: LeaseRank = .{};
    for (view.routes) |entry| {
        if (!routeEql(entry.route, route_handle)) continue;
        rank.active_leases +|= entry.active_leases;
        if (entry.last_selected_at) |observed_at| {
            if (rank.last_selected_at == null or observed_at > rank.last_selected_at.?) {
                rank.last_selected_at = observed_at;
            }
        }
    }
    return rank;
}

fn prefers(candidate: RouteEvidence, incumbent: RouteEvidence, leases: LeaseView) bool {
    const candidate_tier = readinessTier(candidate.readiness).?;
    const incumbent_tier = readinessTier(incumbent.readiness).?;
    if (candidate_tier != incumbent_tier) return candidate_tier > incumbent_tier;

    const candidate_lease = leaseRank(leases, candidate.route);
    const incumbent_lease = leaseRank(leases, incumbent.route);
    if (candidate_lease.active_leases != incumbent_lease.active_leases) {
        return candidate_lease.active_leases < incumbent_lease.active_leases;
    }

    if (candidate_lease.last_selected_at == null and incumbent_lease.last_selected_at != null) {
        return true;
    }
    if (candidate_lease.last_selected_at != null and incumbent_lease.last_selected_at == null) {
        return false;
    }
    if (candidate_lease.last_selected_at) |candidate_at| {
        const incumbent_at = incumbent_lease.last_selected_at.?;
        if (candidate_at != incumbent_at) return candidate_at < incumbent_at;
    }

    return std.mem.order(u8, candidate.route.text, incumbent.route.text) == .lt;
}

fn routeEql(a: RouteHandle, b: RouteHandle) bool {
    return std.mem.eql(u8, a.text, b.text);
}

test {
    std.testing.refAllDeclsRecursive(@This());
}

const testing = std.testing;

fn route(
    route_value: []const u8,
    identity_value: ?[]const u8,
    model_value: []const u8,
    admission: route_observation.RouteAdmission,
    readiness: route_observation.Readiness,
) RouteEvidence {
    return .{
        .route = RouteHandle.parse(route_value) catch unreachable,
        .identity = if (identity_value) |value|
            route_observation.IdentityEvidence.fromBorrowed(value)
        else
            null,
        .exact_model = model_demand.ExactModel.init(model_value) catch unreachable,
        .admission = admission,
        .readiness = readiness,
        .provenance = switch (readiness) {
            .available, .exhausted => .proven,
            .unknown => .unobserved,
        },
        .resets_at_s = if (readiness == .exhausted) 100 else null,
    };
}

fn routeHandle(bytes: []const u8) RouteHandle {
    return RouteHandle.parse(bytes) catch unreachable;
}

fn expectRoute(expected: []const u8, actual: BrokerDecision) !void {
    switch (actual) {
        .select_route => |selected| try testing.expectEqualStrings(expected, selected.text),
        .no_route => return error.TestUnexpectedResult,
    }
}

fn expectNoRoute(actual: BrokerDecision) !void {
    switch (actual) {
        .select_route => return error.TestUnexpectedResult,
        .no_route => {},
    }
}

fn expectDecisionEqual(expected: BrokerDecision, actual: BrokerDecision) !void {
    switch (expected) {
        .select_route => |expected_route| switch (actual) {
            .select_route => |actual_route| try testing.expectEqualStrings(
                expected_route.text,
                actual_route.text,
            ),
            .no_route => return error.TestUnexpectedResult,
        },
        .no_route => try expectNoRoute(actual),
    }
}

test "admission and readiness cross product is total and fail closed" {
    const admissions = std.meta.tags(route_observation.RouteAdmission);
    const readiness_values = std.meta.tags(route_observation.Readiness);
    const demand = try ModelDemand.init("model-7");

    for (admissions) |admission| {
        for (readiness_values) |readiness| {
            const routes = [_]RouteEvidence{
                route("route-1", "identity-10", "model-7", admission, readiness),
            };
            const actual = reduce(demand, &routes, .{});
            if (admission == .admitted and readiness != .exhausted) {
                try expectRoute("route-1", actual);
            } else {
                try expectNoRoute(actual);
            }
        }
    }

    const missing_identity = [_]RouteEvidence{
        route("route-1", null, "model-7", .admitted, .available),
    };
    try expectNoRoute(reduce(demand, &missing_identity, .{}));

    const empty_identity = [_]RouteEvidence{
        route("route-1", "", "model-7", .admitted, .available),
    };
    try expectNoRoute(reduce(demand, &empty_identity, .{}));

    var invalid_model = route("route-1", "identity-10", "model-7", .admitted, .available);
    invalid_model.exact_model = .{};
    try expectNoRoute(reduce(demand, &.{invalid_model}, .{}));
    try expectNoRoute(reduce(.{ .exact_model = .{} }, &.{
        route("route-1", "identity-10", "model-7", .admitted, .available),
    }, .{}));
}

test "exact-model demand is never substituted" {
    const demand = try ModelDemand.init("model-7");
    const routes = [_]RouteEvidence{
        route("route-1", "identity-10", "model-8", .admitted, .available),
        route("route-2", "identity-20", "model-7", .admitted, .unknown),
        route("route-3", "identity-30", "model-9", .admitted, .available),
    };
    try expectRoute("route-2", reduce(demand, &routes, .{}));

    const mismatches = [_]RouteEvidence{
        route("route-1", "identity-10", "model-8", .admitted, .available),
        route("route-3", "identity-30", "model-9", .admitted, .unknown),
    };
    try expectNoRoute(reduce(demand, &mismatches, .{}));
}

test "duplicate identity conflicts fail closed for every affected route" {
    const demand = try ModelDemand.init("model-7");
    const routes = [_]RouteEvidence{
        route("route-1", "identity-10", "model-7", .admitted, .available),
        route("route-2", "identity-10", "model-7", .admitted, .available),
        route("route-3", "identity-30", "model-7", .admitted, .unknown),
    };
    try expectRoute("route-3", reduce(demand, &routes, .{}));

    const only_duplicates = routes[0..2];
    try expectNoRoute(reduce(demand, only_duplicates, .{}));
}

test "one identity may expose distinct exact-model routes" {
    const demand = try ModelDemand.init("model-7");
    const routes = [_]RouteEvidence{
        route("route-opus", "identity-10", "model-7", .admitted, .available),
        route("route-haiku", "identity-10", "model-8", .admitted, .available),
        route("route-other", "identity-30", "model-7", .admitted, .unknown),
    };
    try expectRoute("route-opus", reduce(demand, &routes, .{}));

    const same_handle = [_]RouteEvidence{
        route("route-shared", "identity-10", "model-7", .admitted, .available),
        route("route-shared", "identity-10", "model-8", .admitted, .available),
    };
    try expectRoute("route-shared", reduce(demand, &same_handle, .{}));
}

test "contradictory evidence for one route and model fails closed" {
    const demand = try ModelDemand.init("model-7");

    const identity_conflict = [_]RouteEvidence{
        route("route-1", "identity-10", "model-7", .admitted, .available),
        route("route-1", "identity-20", "model-7", .admitted, .available),
        route("route-2", "identity-30", "model-7", .admitted, .unknown),
    };
    try expectRoute("route-2", reduce(demand, &identity_conflict, .{}));
    try expectNoRoute(reduce(demand, identity_conflict[0..2], .{}));

    const admission_conflict = [_]RouteEvidence{
        route("route-1", "identity-10", "model-7", .admitted, .available),
        route("route-1", "identity-10", "model-7", .dead, .available),
    };
    try expectNoRoute(reduce(demand, &admission_conflict, .{}));

    const readiness_conflict = [_]RouteEvidence{
        route("route-1", "identity-10", "model-7", .admitted, .available),
        route("route-1", "identity-10", "model-7", .admitted, .exhausted),
    };
    try expectNoRoute(reduce(demand, &readiness_conflict, .{}));

    var inferred = route("route-1", "identity-10", "model-7", .admitted, .available);
    inferred.provenance = .inferred;
    const provenance_conflict = [_]RouteEvidence{
        route("route-1", "identity-10", "model-7", .admitted, .available),
        inferred,
    };
    try expectNoRoute(reduce(demand, &provenance_conflict, .{}));

    var different_reset = route("route-1", "identity-10", "model-7", .admitted, .available);
    different_reset.resets_at_s = 200;
    const reset_conflict = [_]RouteEvidence{
        route("route-1", "identity-10", "model-7", .admitted, .available),
        different_reset,
    };
    try expectNoRoute(reduce(demand, &reset_conflict, .{}));

    const identical = [_]RouteEvidence{
        route("route-1", "identity-10", "model-7", .admitted, .available),
        route("route-1", "identity-10", "model-7", .admitted, .available),
    };
    try expectRoute("route-1", reduce(demand, &identical, .{}));
}

test "eligible sticky route survives availability staleness" {
    const demand = try ModelDemand.init("model-7");
    const routes = [_]RouteEvidence{
        route("route-1", "identity-10", "model-7", .admitted, .unknown),
        route("route-2", "identity-20", "model-7", .admitted, .available),
    };
    const leases: LeaseView = .{ .sticky_route = routeHandle("route-1") };
    try expectRoute("route-1", reduce(demand, &routes, leases));

    try expectRoute("route-2", reduce(demand, &routes, .{}));
}

test "explicit route unavailability breaks stickiness" {
    const demand = try ModelDemand.init("model-7");
    inline for (.{route_observation.Readiness.exhausted}) |readiness| {
        const routes = [_]RouteEvidence{
            route("route-1", "identity-10", "model-7", .admitted, readiness),
            route("route-2", "identity-20", "model-7", .admitted, .available),
        };
        try expectRoute("route-2", reduce(demand, &routes, .{
            .sticky_route = routeHandle("route-1"),
        }));
    }

    const dead_routes = [_]RouteEvidence{
        route("route-1", "identity-10", "model-7", .dead, .available),
        route("route-2", "identity-20", "model-7", .admitted, .available),
    };
    try expectRoute("route-2", reduce(demand, &dead_routes, .{
        .sticky_route = routeHandle("route-1"),
    }));
}

test "sticky then least loaded then least recent then handle ordering" {
    const demand = try ModelDemand.init("model-7");
    const routes = [_]RouteEvidence{
        route("route-40", "identity-10", "model-7", .admitted, .available),
        route("route-30", "identity-20", "model-7", .admitted, .available),
        route("route-20", "identity-30", "model-7", .admitted, .available),
        route("route-10", "identity-40", "model-7", .admitted, .available),
    };
    const lease_rows = [_]LeaseObservation{
        .{ .route = routeHandle("route-40"), .active_leases = 99, .last_selected_at = 99 },
        .{ .route = routeHandle("route-30"), .active_leases = 0, .last_selected_at = 30 },
        .{ .route = routeHandle("route-20"), .active_leases = 0, .last_selected_at = 20 },
        .{ .route = routeHandle("route-10"), .active_leases = 0, .last_selected_at = 20 },
    };

    try expectRoute("route-40", reduce(demand, &routes, .{
        .sticky_route = routeHandle("route-40"),
        .routes = &lease_rows,
    }));
    try expectRoute("route-10", reduce(demand, &routes, .{ .routes = &lease_rows }));

    const least_loaded_rows = [_]LeaseObservation{
        .{ .route = routeHandle("route-10"), .active_leases = 2, .last_selected_at = null },
        .{ .route = routeHandle("route-20"), .active_leases = 1, .last_selected_at = 999 },
        .{ .route = routeHandle("route-30"), .active_leases = 3, .last_selected_at = null },
        .{ .route = routeHandle("route-40"), .active_leases = 4, .last_selected_at = null },
    };
    try expectRoute("route-20", reduce(demand, &routes, .{ .routes = &least_loaded_rows }));
}

test "never selected is less recent than every injected selection instant" {
    const demand = try ModelDemand.init("model-7");
    const routes = [_]RouteEvidence{
        route("route-1", "identity-10", "model-7", .admitted, .available),
        route("route-2", "identity-20", "model-7", .admitted, .available),
    };
    const lease_rows = [_]LeaseObservation{
        .{ .route = routeHandle("route-1"), .active_leases = 0, .last_selected_at = std.math.minInt(i64) },
        .{ .route = routeHandle("route-2"), .active_leases = 0, .last_selected_at = null },
    };
    try expectRoute("route-2", reduce(demand, &routes, .{ .routes = &lease_rows }));
}

test "duplicate lease rows fold deterministically without overflow" {
    const demand = try ModelDemand.init("model-7");
    const routes = [_]RouteEvidence{
        route("route-1", "identity-10", "model-7", .admitted, .available),
        route("route-2", "identity-20", "model-7", .admitted, .available),
    };
    const lease_rows = [_]LeaseObservation{
        .{ .route = routeHandle("route-1"), .active_leases = std.math.maxInt(u64), .last_selected_at = 1 },
        .{ .route = routeHandle("route-1"), .active_leases = 1, .last_selected_at = 5 },
        .{ .route = routeHandle("route-2"), .active_leases = 10, .last_selected_at = 100 },
    };
    try expectRoute("route-2", reduce(demand, &routes, .{ .routes = &lease_rows }));
}

test "seeded route and lease permutations preserve the decision" {
    var routes = [_]RouteEvidence{
        route("route-5", "identity-50", "model-7", .admitted, .available),
        route("route-2", "identity-20", "model-7", .admitted, .available),
        route("route-8", "identity-80", "model-7", .admitted, .unknown),
        route("route-1", "identity-10", "model-8", .admitted, .available),
        route("route-9", "identity-90", "model-7", .dead, .available),
    };
    var lease_rows = [_]LeaseObservation{
        .{ .route = routeHandle("route-5"), .active_leases = 1, .last_selected_at = 50 },
        .{ .route = routeHandle("route-2"), .active_leases = 1, .last_selected_at = 20 },
        .{ .route = routeHandle("route-8"), .active_leases = 0, .last_selected_at = null },
        .{ .route = routeHandle("route-2"), .active_leases = 0, .last_selected_at = 10 },
    };
    const demand = try ModelDemand.init("model-7");
    const expected = reduce(demand, &routes, .{ .routes = &lease_rows });
    try expectRoute("route-2", expected);

    var prng = std.Random.DefaultPrng.init(0x85_1790_0001);
    const random = prng.random();
    for (0..256) |_| {
        random.shuffle(RouteEvidence, &routes);
        random.shuffle(LeaseObservation, &lease_rows);
        try expectDecisionEqual(expected, reduce(demand, &routes, .{ .routes = &lease_rows }));
    }
}

test "seeded bounded inputs are deterministic total and permutation invariant" {
    const admissions = std.meta.tags(route_observation.RouteAdmission);
    const readiness_values = std.meta.tags(route_observation.Readiness);
    const route_values = [_][]const u8{
        "route-00", "route-01", "route-02", "route-03",
        "route-04", "route-05", "route-06", "route-07",
        "route-08", "route-09", "route-10", "route-11",
    };
    const identity_values = [_][]const u8{
        "identity-00", "identity-01", "identity-02", "identity-03",
        "identity-04", "identity-05", "identity-06", "identity-07",
        "identity-08", "identity-09", "identity-10", "identity-11",
    };
    const model_values = [_][]const u8{ "model-0", "model-1", "model-2", "model-3" };
    var route_rows: [16]RouteEvidence = undefined;
    var lease_rows: [16]LeaseObservation = undefined;
    var prng = std.Random.DefaultPrng.init(0x85_1790_b0ad);
    const random = prng.random();

    for (0..2048) |_| {
        const route_count = random.uintLessThan(usize, route_rows.len + 1);
        const lease_count = random.uintLessThan(usize, lease_rows.len + 1);
        const model_value = model_values[random.uintLessThan(usize, model_values.len)];

        for (route_rows[0..route_count]) |*entry| {
            const readiness = readiness_values[random.uintLessThan(usize, readiness_values.len)];
            entry.* = route(
                route_values[random.uintLessThan(usize, route_values.len)],
                if (random.uintLessThan(u8, 5) == 0)
                    null
                else
                    identity_values[random.uintLessThan(usize, identity_values.len)],
                model_values[random.uintLessThan(usize, model_values.len)],
                admissions[random.uintLessThan(usize, admissions.len)],
                readiness,
            );
        }
        for (lease_rows[0..lease_count]) |*entry| {
            entry.* = .{
                .route = routeHandle(route_values[random.uintLessThan(usize, route_values.len)]),
                .active_leases = random.int(u64),
                .last_selected_at = if (random.uintLessThan(u8, 4) == 0)
                    null
                else
                    random.int(i64),
            };
        }

        const demand = try ModelDemand.init(model_value);
        const view: LeaseView = .{
            .sticky_route = if (random.boolean())
                routeHandle(route_values[random.uintLessThan(usize, route_values.len)])
            else
                null,
            .routes = lease_rows[0..lease_count],
        };
        const expected = reduce(demand, route_rows[0..route_count], view);
        try expectDecisionEqual(expected, reduce(demand, route_rows[0..route_count], view));

        random.shuffle(RouteEvidence, route_rows[0..route_count]);
        random.shuffle(LeaseObservation, lease_rows[0..lease_count]);
        try expectDecisionEqual(expected, reduce(demand, route_rows[0..route_count], view));
    }
}

fn reduceFirstEligible(demand: ModelDemand, routes: []const RouteEvidence) BrokerDecision {
    for (routes) |candidate| {
        if (!demand.accepts(candidate.exact_model)) continue;
        if (candidate.admission != .admitted) continue;
        if (candidate.identity == null or !candidate.identity.?.isValid()) continue;
        if (readinessTier(candidate.readiness) == null) continue;
        return .{ .select_route = candidate.route };
    }
    return .no_route;
}

test "negative control: first-eligible election is input-order dependent" {
    const demand = try ModelDemand.init("model-7");
    const forward = [_]RouteEvidence{
        route("route-2", "identity-20", "model-7", .admitted, .available),
        route("route-1", "identity-10", "model-7", .admitted, .available),
    };
    const reverse = [_]RouteEvidence{ forward[1], forward[0] };

    try expectRoute("route-2", reduceFirstEligible(demand, &forward));
    try expectRoute("route-1", reduceFirstEligible(demand, &reverse));
    try expectRoute("route-1", reduce(demand, &forward, .{}));
    try expectRoute("route-1", reduce(demand, &reverse, .{}));
}
