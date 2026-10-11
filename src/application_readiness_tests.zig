const std = @import("std");
const domain = @import("domain.zig");
const readiness = @import("application_readiness.zig");

const context = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const Fixture = struct {
    state: domain.State,
    custody: [1]readiness.Custody = .{.{ .account_id = "private-account-fixture", .grant_id = "private-grant-fixture", .generation = 1, .state = .ready, .renewal_owner = .external }},

    fn init() !Fixture {
        var state = domain.State.init(std.testing.allocator);
        errdefer state.deinit();
        _ = try state.connectSource(.{ .id = "private-source-fixture", .provider = "codex", .kind = .native_store, .authorized_at = 1, .authorized_until = 100 });
        _ = try state.enroll(.{ .account_id = "private-account-fixture", .source_id = "private-source-fixture", .identity = .{ .provider = "codex", .issuer = "https://chatgpt.com", .subject = "synthetic-private-subject", .verified = true }, .label = "synthetic-private-label" }, 10);
        _ = try state.addGrant(.{ .id = "private-grant-fixture", .account_id = "private-account-fixture", .source_id = "private-source-fixture", .credential_kind = .oauth_access, .ownership = .external, .purposes = &.{.request}, .audience = "https://chatgpt.com", .scopes = &.{"model.read"}, .provider_expires_at = 90, .custody_expires_at = 80 });
        return .{ .state = state };
    }
    fn deinit(self: *Fixture) void {
        self.state.deinit();
    }
    fn input(self: *const Fixture) readiness.Input {
        return .{
            .application = .codex,
            .revision = 7,
            .expected_revision = 7,
            .context_ref = context,
            .demand = .{ .provider = "codex", .issuer = "https://chatgpt.com", .audience = "https://chatgpt.com", .scopes = &.{"model.read"}, .resource = .{ .kind = "model", .target = "synthetic-model" }, .now = 10 },
            .custody = &self.custody,
            .adapter = .{ .application = .codex, .revision = 7, .configuration = .installed },
        };
    }
    fn withGrant(self: *const Fixture, grant: *domain.Grant, input_value: readiness.Input) !readiness.Report {
        var view = self.state;
        view.grants = std.ArrayList(domain.Grant).initBuffer(grant[0..1]);
        view.grants.items.len = 1;
        return readiness.project(&view, input_value);
    }
};

test "same lineage compatible authority is diagnostic and unsupported native launch stays unknown" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const before = fixture.state.revision;
    const report = try readiness.project(&fixture.state, fixture.input());
    try std.testing.expectEqual(readiness.State.ready, report.source.state);
    try std.testing.expectEqual(readiness.State.ready, report.identity.state);
    try std.testing.expectEqual(readiness.State.ready, report.authority.state);
    try std.testing.expectEqual(readiness.State.unknown, report.ordinary_launch.state);
    try std.testing.expect(!report.ready and !report.provider_access and !report.seamless_handoff_proven and !report.enrollment_success_proven);
    try std.testing.expectEqual(before, fixture.state.revision);
    try std.testing.expectEqual(@as(usize, 0), fixture.state.bindings.items.len);
    try std.testing.expectEqual(@as(usize, 0), fixture.state.leases.items.len);
    var input_value = fixture.input();
    input_value.adapter.ordinary_launch = .unsupported;
    const unsupported = try readiness.project(&fixture.state, input_value);
    try std.testing.expectEqual(readiness.State.unknown, unsupported.ordinary_launch.state);
    try std.testing.expectEqual(readiness.Reason.native_unsupported, unsupported.reason);
    input_value.adapter.ordinary_launch = .verified; // Synthetic actor evidence only.
    input_value.adapter.application = .git;
    try std.testing.expect(!(try readiness.project(&fixture.state, input_value)).ready);
    input_value.adapter.application = .codex;
    input_value.adapter.revision = 6;
    try std.testing.expect(!(try readiness.project(&fixture.state, input_value)).ready);
}

test "explicit context and revision are fenced before ready metadata can count" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var input_value = fixture.input();
    input_value.expected_revision = 6;
    const stale = try readiness.project(&fixture.state, input_value);
    try std.testing.expectEqual(readiness.Reason.revision_changed, stale.reason);
    try std.testing.expectEqual(readiness.State.unknown, stale.authority.state);
    input_value = fixture.input();
    input_value.context_ref = null;
    try std.testing.expectEqual(readiness.Reason.context_required, (try readiness.project(&fixture.state, input_value)).reason);
    input_value.context_ref = "/synthetic/private/path";
    try std.testing.expectError(error.InvalidApplicationContext, readiness.project(&fixture.state, input_value));
    input_value = fixture.input();
    input_value.custody_available = false;
    const unavailable = try readiness.project(&fixture.state, input_value);
    try std.testing.expectEqual(readiness.Reason.custody_unavailable, unavailable.reason);
    try std.testing.expectEqual(readiness.State.unknown, unavailable.identity.state);
}

test "unrelated provider audience issuer scopes and selected source cannot stitch readiness" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var grant = fixture.state.grants.items[0];
    grant.audience = "https://github.com";
    try std.testing.expect((try fixture.withGrant(&grant, fixture.input())).authority.state != .ready);
    var input_value = fixture.input();
    input_value.demand.?.scopes = &.{"missing.scope"};
    grant = fixture.state.grants.items[0];
    try std.testing.expect((try fixture.withGrant(&grant, input_value)).authority.state != .ready);
    input_value = fixture.input();
    input_value.demand.?.issuer = "https://synthetic.invalid";
    try std.testing.expect((try readiness.project(&fixture.state, input_value)).identity.state != .ready);
    input_value = fixture.input();
    input_value.source_id = "different-source";
    try std.testing.expect((try readiness.project(&fixture.state, input_value)).source.state != .ready);
    input_value = fixture.input();
    input_value.application = .git;
    input_value.demand = .{ .provider = "github", .issuer = "https://github.com", .audience = "https://github.com", .resource = .{ .kind = "repository" }, .now = 10 };
    const unrelated = try readiness.project(&fixture.state, input_value);
    try std.testing.expect(unrelated.source.state != .ready and unrelated.identity.state != .ready and unrelated.authority.state != .ready);
    input_value = fixture.input();
    input_value.demand.?.audience = "https://github.com";
    try std.testing.expectError(error.InvalidApplicationContext, readiness.project(&fixture.state, input_value));
}

test "grant and custody must reference the same account and generation" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var grant = fixture.state.grants.items[0];
    grant.account_id = "other-account";
    try std.testing.expect((try fixture.withGrant(&grant, fixture.input())).authority.state != .ready);
    var held = fixture.custody;
    held[0].account_id = "other-account";
    var input_value = fixture.input();
    input_value.custody = &held;
    try std.testing.expectEqual(readiness.Reason.custody_unavailable, (try readiness.project(&fixture.state, input_value)).authority.reason);
    held[0] = fixture.custody[0];
    held[0].generation = 2;
    try std.testing.expectEqual(readiness.Reason.custody_generation_mismatch, (try readiness.project(&fixture.state, input_value)).authority.reason);
    input_value.custody = &.{}; // Actual actor receives null for missing ciphertext.
    try std.testing.expectEqual(readiness.State.unknown, (try readiness.project(&fixture.state, input_value)).authority.state);
    held[0] = fixture.custody[0];
    held[0].state = .quarantined;
    input_value.custody = &held;
    try std.testing.expectEqual(readiness.Reason.custody_unavailable, (try readiness.project(&fixture.state, input_value)).authority.reason);
    const duplicate = [_]readiness.Custody{ held[0], held[0] };
    input_value.custody = &duplicate;
    try std.testing.expectError(error.InvalidApplicationCustody, readiness.project(&fixture.state, input_value));
}

test "renewal writer remains external and adopted labels do not establish transfer" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const external = try readiness.project(&fixture.state, fixture.input());
    try std.testing.expectEqual(@TypeOf(external.renewal_owner).external, external.renewal_owner);
    var held = fixture.custody;
    held[0].renewal_owner = .omux;
    var input_value = fixture.input();
    input_value.custody = &held;
    try std.testing.expectEqual(readiness.Reason.renewal_owner_mismatch, (try readiness.project(&fixture.state, input_value)).authority.reason);
    var grant = fixture.state.grants.items[0];
    grant.ownership = .adopted;
    const adopted = try fixture.withGrant(&grant, input_value);
    try std.testing.expectEqual(readiness.State.unknown, adopted.authority.state);
    try std.testing.expectEqual(readiness.Reason.renewal_owner_unverified, adopted.authority.reason);
    grant.ownership = .omux;
    try std.testing.expectEqual(readiness.State.ready, (try fixture.withGrant(&grant, input_value)).authority.state);
}

test "detached authorized source preserves independently valid authority but cannot enroll" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.state.detachSource("private-source-fixture");
    var input_value = fixture.input();
    input_value.adapter.ordinary_launch = .verified; // Pure synthetic proof predicate.
    const detached = try readiness.project(&fixture.state, input_value);
    try std.testing.expect(detached.ready and detached.authority.state == .ready);
    try std.testing.expectEqual(readiness.Reason.source_detached, detached.enrollment.reason);
    try std.testing.expectEqual(readiness.State.action_required, detached.enrollment.state);
    try fixture.state.disconnectSource("private-source-fixture");
    const disconnected = try readiness.project(&fixture.state, input_value);
    try std.testing.expect(!disconnected.ready and disconnected.authority.state != .ready);
}

test "expired paused and browser restricted authority cannot count" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var grant = fixture.state.grants.items[0];
    grant.provider_expires_at = 10;
    try std.testing.expect((try fixture.withGrant(&grant, fixture.input())).authority.state != .ready);
    grant = fixture.state.grants.items[0];
    grant.custody_expires_at = 10;
    try std.testing.expect((try fixture.withGrant(&grant, fixture.input())).authority.state != .ready);
    grant = fixture.state.grants.items[0];
    grant.credential_kind = .browser_bound;
    try std.testing.expect((try fixture.withGrant(&grant, fixture.input())).authority.state != .ready);
    fixture.state.sources.items[0].authorized_until = 10;
    try std.testing.expect((try readiness.project(&fixture.state, fixture.input())).authority.state != .ready);
    fixture.state.sources.items[0].authorized_until = 100;
    try fixture.state.pause("private-account-fixture", true);
    const paused = try readiness.project(&fixture.state, fixture.input());
    try std.testing.expect(paused.identity.state != .ready and paused.authority.state != .ready);
}

test "required missing capacity stays unknown separately from compatible authority" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var input_value = fixture.input();
    input_value.demand.?.requires_capacity = true;
    input_value.adapter.ordinary_launch = .verified;
    const missing = try readiness.project(&fixture.state, input_value);
    try std.testing.expectEqual(readiness.State.ready, missing.authority.state);
    try std.testing.expectEqual(readiness.State.unknown, missing.capacity.state);
    try std.testing.expect(!missing.ready and missing.reason == .capacity_unknown);
    try fixture.state.observe(.{ .account_id = "private-account-fixture", .resource = input_value.demand.?.resource, .bucket_id = "synthetic-bucket", .remaining = 0, .window_start = 1, .window_end = 100, .observed_at = 9, .expires_at = 50, .status = .unavailable, .provenance = .fixture });
    const exhausted = try readiness.project(&fixture.state, input_value);
    try std.testing.expectEqual(readiness.State.ready, exhausted.authority.state);
    try std.testing.expectEqual(readiness.Reason.capacity_unavailable, exhausted.reason);
    input_value.demand.?.requires_capacity = false;
    try std.testing.expect(!(try readiness.project(&fixture.state, input_value)).ready);
}

test "available alternative wins over exhausted or unobserved first account without stitching" {
    for ([_]bool{ false, true }) |first_exhausted| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        _ = try fixture.state.enroll(.{ .account_id = "second-private-account", .source_id = "private-source-fixture", .identity = .{ .provider = "codex", .issuer = "https://chatgpt.com", .subject = "second-synthetic-subject", .verified = true } }, 10);
        _ = try fixture.state.addGrant(.{ .id = "second-private-grant", .account_id = "second-private-account", .source_id = "private-source-fixture", .credential_kind = .oauth_access, .ownership = .external, .purposes = &.{.request}, .audience = "https://chatgpt.com", .scopes = &.{"model.read"} });
        var input_value = fixture.input();
        input_value.adapter.ordinary_launch = .verified;
        input_value.demand.?.requires_capacity = true;
        const custody = [_]readiness.Custody{ fixture.custody[0], .{ .account_id = "second-private-account", .grant_id = "second-private-grant", .generation = 1, .state = .ready, .renewal_owner = .external } };
        input_value.custody = &custody;
        if (first_exhausted) try fixture.state.observe(.{ .account_id = "private-account-fixture", .resource = input_value.demand.?.resource, .bucket_id = "synthetic-bucket-A", .remaining = 0, .window_start = 1, .window_end = 100, .observed_at = 9, .expires_at = 50, .status = .unavailable, .provenance = .fixture });
        try fixture.state.observe(.{ .account_id = "second-private-account", .resource = input_value.demand.?.resource, .bucket_id = "synthetic-bucket-B", .remaining = 5, .window_start = 1, .window_end = 100, .observed_at = 9, .expires_at = 50, .provenance = .fixture });
        const available = try readiness.project(&fixture.state, input_value);
        try std.testing.expect(available.ready and available.authority.state == .ready and available.capacity.state == .ready);
        input_value.custody = custody[0..1];
        try std.testing.expect(!(try readiness.project(&fixture.state, input_value)).ready);
    }
}

test "report serialization exposes only finite facts and an opaque context reference" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const report = try readiness.project(&fixture.state, fixture.input());
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, report, .{});
    defer std.testing.allocator.free(bytes);
    for ([_][]const u8{ "private-account-fixture", "private-grant-fixture", "private-source-fixture", "synthetic-private-subject", "synthetic-private-label", "synthetic-model", "chatgpt.com", "model.read" }) |private| {
        try std.testing.expect(std.mem.indexOf(u8, bytes, private) == null);
    }
    try std.testing.expect(std.mem.indexOf(u8, bytes, context) != null);
}

fn addReadinessAlternative(state: *domain.State) !void {
    _ = try state.connectSource(.{ .id = "second-source", .provider = "codex", .kind = .explicit, .authorized_at = 1, .authorized_until = 100 });
    _ = try state.enroll(.{ .account_id = "second-account", .source_id = "second-source", .identity = .{ .provider = "codex", .issuer = "https://chatgpt.com", .subject = "second-generated-subject", .verified = true } }, 10);
    _ = try state.addGrant(.{ .id = "second-grant", .account_id = "second-account", .source_id = "second-source", .credential_kind = .oauth_access, .ownership = .external, .purposes = &.{.request}, .audience = "https://chatgpt.com", .scopes = &.{"model.read"} });
}
fn selectedInput(fixture: *const Fixture, account_id: []const u8, constraint: []const []const u8) readiness.Input {
    var input_value = fixture.input();
    input_value.account_id = account_id;
    input_value.demand.?.allowed_account_ids = constraint;
    return input_value;
}

test "selected account cannot borrow alternative source identity grant custody or capacity" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try addReadinessAlternative(&fixture.state);
    const rows = [_]readiness.Custody{ fixture.custody[0], .{ .account_id = "second-account", .grant_id = "second-grant", .generation = 1, .state = .ready, .renewal_owner = .external } };
    try fixture.state.disconnectSource("private-source-fixture");
    const before = try std.json.Stringify.valueAlloc(std.testing.allocator, fixture.state.snapshot(), .{});
    defer std.testing.allocator.free(before);
    var chosen = selectedInput(&fixture, "private-account-fixture", &.{"private-account-fixture"});
    chosen.custody = &rows;
    const unavailable = try readiness.project(&fixture.state, chosen);
    try std.testing.expectEqual(readiness.Reason.source_unauthorized, unavailable.source.reason);
    try std.testing.expectEqual(readiness.Reason.source_unauthorized, unavailable.enrollment.reason);
    try std.testing.expect(unavailable.authority.state != .ready and !unavailable.ready);
    var alternative = selectedInput(&fixture, "second-account", &.{"second-account"});
    alternative.custody = &rows;
    const available = try readiness.project(&fixture.state, alternative);
    try std.testing.expectEqual(readiness.State.ready, available.authority.state);
    try std.testing.expectEqual(readiness.State.ready, available.source.state);
    var global = fixture.input();
    global.custody = &rows;
    try std.testing.expectEqual(readiness.State.ready, (try readiness.project(&fixture.state, global)).authority.state);
    const after = try std.json.Stringify.valueAlloc(std.testing.allocator, fixture.state.snapshot(), .{});
    defer std.testing.allocator.free(after);
    try std.testing.expect(std.mem.eql(u8, before, after));
}

test "selected readiness requires exact singleton account and revision without inferring unavailable membership" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var chosen = selectedInput(&fixture, "private-account-fixture", &.{"private-account-fixture"});
    chosen.expected_revision = null;
    try std.testing.expectError(error.InvalidApplicationContext, readiness.project(&fixture.state, chosen));
    chosen = selectedInput(&fixture, "private-account-fixture", &.{});
    try std.testing.expectError(error.InvalidApplicationContext, readiness.project(&fixture.state, chosen));
    chosen = selectedInput(&fixture, "private-account-fixture", &.{"private-account-fixture", "second-account"});
    try std.testing.expectError(error.InvalidApplicationContext, readiness.project(&fixture.state, chosen));
    chosen = selectedInput(&fixture, "unknown-account", &.{"unknown-account"});
    chosen.context_ref = null;
    const unknown = try readiness.project(&fixture.state, chosen);
    try std.testing.expectEqual(readiness.Reason.account_unavailable, unknown.reason);
    try std.testing.expectEqual(readiness.State.unknown, unknown.source.state);
    chosen.expected_revision = 6;
    try std.testing.expectEqual(readiness.Reason.revision_changed, (try readiness.project(&fixture.state, chosen)).reason);
    chosen.expected_revision = 7;
    chosen.custody_available = false;
    try std.testing.expectEqual(readiness.Reason.custody_unavailable, (try readiness.project(&fixture.state, chosen)).reason);
}

test "selected account retains shared bucket contradictions and never spends a cross-account aggregate" {
    for ([_]bool{ true, false }) |shared| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        try addReadinessAlternative(&fixture.state);
        var chosen = selectedInput(&fixture, "private-account-fixture", &.{"private-account-fixture"});
        chosen.demand.?.requires_capacity = true;
        chosen.demand.?.required = if (shared) 1 else 5;
        try fixture.state.observe(.{ .account_id = "private-account-fixture", .resource = chosen.demand.?.resource, .bucket_id = "bucket-A", .remaining = if (shared) 5 else 4, .window_start = 1, .window_end = 100, .observed_at = 9, .expires_at = 50, .provenance = .provider_api });
        try fixture.state.observe(.{ .account_id = "second-account", .resource = chosen.demand.?.resource, .bucket_id = if (shared) "bucket-A" else "bucket-B", .remaining = if (shared) 0 else 4, .window_start = 1, .window_end = 100, .observed_at = 9, .expires_at = 50, .status = if (shared) .unavailable else .ready, .provenance = .provider_api });
        const report = try readiness.project(&fixture.state, chosen);
        try std.testing.expectEqual(readiness.State.ready, report.authority.state);
        try std.testing.expectEqual(readiness.Reason.capacity_unavailable, report.capacity.reason);
        try std.testing.expect(!report.ready);
        if (!shared) try std.testing.expectEqual(@as(f64, 8), fixture.state.aggregate("codex", "https://chatgpt.com", chosen.demand.?.resource, 1, 100, 10).remaining);
    }
}
