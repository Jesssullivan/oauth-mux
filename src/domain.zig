//! Omux's credential-free, provider-independent account and routing model.
//! Authentication factors (passwords, passkeys, security keys and OTP) are
//! enrollment inputs; they are never grants and are never stored in this model.
const std = @import("std");
const native_owner = @import("native_owner.zig");
const snapshot_admission = @import("snapshot_admission.zig");

pub const schema_version: u32 = 1;
pub const max_records: usize = 1024;
pub const max_text_bytes: usize = 4096;
pub const max_list_items: usize = 64;

pub const Identity = struct {
    provider: []const u8,
    issuer: []const u8,
    subject: []const u8,
    tenant: []const u8 = "",
    verified: bool = false,
};
pub const AccountLifecycle = enum { active, paused, draining };
pub const Account = struct {
    id: []const u8,
    identity: Identity,
    label: []const u8 = "",
    account_type: []const u8 = "generic",
    lifecycle: AccountLifecycle = .active,
    source_ids: []const []const u8 = &.{},
};
pub const SourceKind = enum { native_store, oauth, browser, explicit };
pub const SourceStatus = enum { connected, detached, disconnected };
pub const Source = struct {
    id: []const u8,
    provider: []const u8 = "",
    label: []const u8 = "",
    kind: SourceKind,
    status: SourceStatus = .connected,
    authorized_at: i64 = 0,
    authorized_until: ?i64 = null,
};
pub const Enrollment = struct {
    account_id: []const u8,
    source_id: []const u8,
    identity: Identity,
    label: []const u8 = "",
    /// Descriptive verified metadata; omission preserves an existing account's type.
    account_type: ?[]const u8 = null,
};
pub const EnrollmentResult = struct {
    status: enum { enrolled, existing, quarantined, tombstoned },
    account_id: ?[]const u8 = null,
};
/// Factor requirements guide enrollment UI. Factor values never enter custody.
pub const AuthenticationFactor = enum { password, otp, security_key, passkey, push_approval, recovery_code };
pub const EnrollmentInteraction = enum { browser, device_code, native_vault, explicit_input };
pub const Purpose = enum { request, account_read, renewal };
pub const CredentialKind = enum { oauth_access, oauth_refresh, api_key, cookie_session, browser_bound };
pub const RenewalOwnership = enum { external, adopted, omux };
pub const GrantStatus = enum { ready, invalid, quarantined, refreshing };
/// Metadata only. Credential bytes belong to the encrypted custody subsystem.
pub const Grant = struct {
    id: []const u8,
    account_id: []const u8,
    source_id: []const u8,
    credential_kind: CredentialKind,
    ownership: RenewalOwnership = .external,
    purposes: []const Purpose,
    audience: []const u8,
    scopes: []const []const u8 = &.{},
    generation: u64 = 1,
    status: GrantStatus = .ready,
    provider_expires_at: ?i64 = null,
    custody_expires_at: ?i64 = null,
};
pub const Unit = enum { calls, bytes, seconds, uploads, tokens, custom };
/// Scope and target are opaque adapter-declared descriptors, not LLM assumptions.
pub const Resource = struct {
    kind: []const u8,
    target: []const u8 = "",
    unit: Unit = .calls,
    unit_name: []const u8 = "",
    scope: []const u8 = "",
};
pub const ObservationStatus = enum { ready, unavailable, unknown };
pub const ObservationProvenance = enum { provider_api, native_application, browser_fetch, browser_page, user_declared, fixture };
pub const Observation = struct {
    account_id: []const u8,
    resource: Resource,
    /// Provider-issued shared quota identity; unknown bucket IDs cannot aggregate.
    bucket_id: []const u8,
    remaining: f64,
    limit: ?f64 = null,
    window_start: i64,
    window_end: i64,
    observed_at: i64,
    expires_at: i64,
    status: ObservationStatus = .ready,
    provenance: ObservationProvenance,
};
pub const Demand = struct {
    provider: []const u8,
    issuer: ?[]const u8 = null,
    audience: []const u8,
    purpose: Purpose = .request,
    scopes: []const []const u8 = &.{},
    resource: Resource,
    required: f64 = 1,
    now: i64,
    requires_capacity: bool = false,
    allow_browser_bound: bool = false,
    allowed_account_ids: []const []const u8 = &.{},
};
pub const Selection = struct {
    account_id: []const u8,
    grant_id: []const u8,
    generation: u64,
    sticky: bool = false,
};
pub const Binding = struct {
    id: []const u8,
    application: []const u8,
    session_id: []const u8,
    /// R-N13: null retains ownerless legacy/non-native route metadata only.
    /// Native authorization requires the actor's verified attachment ledger.
    native_ref: ?native_owner.NativeRef = null,
    account_id: []const u8,
    grant_id: []const u8,
    grant_generation: u64,
    route_generation: u64 = 1,
    in_flight: u32 = 0,
    /// Durable snapshot revision for explicitly cached Git contexts. Native
    /// bindings leave this zero; recency alone never proves process termination.
    last_used_revision: u64 = 0,
};
pub const Lease = struct {
    id: []const u8,
    binding_id: []const u8,
    native_ref: ?native_owner.NativeRef = null,
    account_id: []const u8,
    grant_id: []const u8,
    grant_generation: u64,
    route_generation: u64,
    purpose: Purpose = .request,
    audience: []const u8 = "",
    scopes: []const []const u8 = &.{},
    resource: ?Resource = null,
    required: f64 = 1,
    requires_capacity: bool = false,
    browser_context: bool = false,
    started_at: i64,
    expires_at: i64,
};
pub const Tombstone = struct { identity: Identity, source_id: []const u8 };
pub const QuarantinedImport = struct {
    source_id: []const u8,
    candidate_id: []const u8,
    identity: Identity,
    reason: enum { unverified_identity, conflicting_identity },
};
pub const Job = struct {
    id: []const u8,
    kind: enum { enrollment, repair, revocation, reconciliation },
    account_id: []const u8 = "",
    status: enum { pending, running, completed, failed } = .pending,
    /// Explicit repeat intent advances this counter; replayed puts do not.
    operation_generation: u64 = 1,
};
pub const Reconciliation = struct {
    grant_id: []const u8,
    expected_generation: u64,
    next_generation: u64,
    status: GrantStatus,
    provider_expires_at: ?i64 = null,
    custody_expires_at: ?i64 = null,
};
pub const Aggregation = struct {
    /// False means the numeric fields are partial observations, not a known total.
    complete: bool = false,
    remaining: f64 = 0,
    limit: ?f64 = 0,
    buckets: usize = 0,
    unknown_buckets: usize = 0,
};
/// Snapshot contains no access tokens, refresh tokens, cookies or factor material.
pub const Snapshot = struct {
    schema_version: u32 = 1,
    revision: u64 = 0,
    sources: []const Source = &.{},
    accounts: []const Account = &.{},
    grants: []const Grant = &.{},
    observations: []const Observation = &.{},
    bindings: []const Binding = &.{},
    leases: []const Lease = &.{},
    tombstones: []const Tombstone = &.{},
    quarantined_imports: []const QuarantinedImport = &.{},
    jobs: []const Job = &.{},
};

/// R-N13: future additions are obligations for both encoded bytes and bounded
/// record lists. Replacement/removal never makes an outstanding promise smaller.
pub const OutcomeGrowth = struct {
    bytes: usize = 0,
    accounts: usize = 0,
    grants: usize = 0,
    observations: usize = 0,
    bindings: usize = 0,
    leases: usize = 0,
    tombstones: usize = 0,
    quarantined_imports: usize = 0,
    source_links: usize = 0,

    pub fn counts(self: OutcomeGrowth) snapshot_admission.Counts {
        return .{
            .accounts = self.accounts,
            .grants = self.grants,
            .observations = self.observations,
            .bindings = self.bindings,
            .leases = self.leases,
            .tombstones = self.tombstones,
            .quarantined_imports = self.quarantined_imports,
            .source_links = self.source_links,
        };
    }
};

// R-N13: 20 decimal digits cover a future u64 snapshot revision. Each counted
// record includes one comma, which also covers insertion into an empty array.
const revision_growth_bytes = 20;
fn recordGrowth(value: anytype) !usize {
    return try std.math.add(usize, try snapshot_admission.countJson(value, snapshot_admission.maximum_snapshot_bytes), 1);
}

/// R-N13: these maxima follow transport's currently accepted identity/usage
/// fields and observer's emitted records. A provider without that contract has
/// no usable plan. Labels and authorized source IDs are already known inputs.
pub fn importGrowth(provider: []const u8, source_id: []const u8, label: []const u8) !OutcomeGrowth {
    try requireId(source_id);
    try validate(label);
    const is_codex = eql(provider, "codex");
    if (!is_codex and !eql(provider, "github")) return error.MissingOutcomeBound;
    const issuer = if (is_codex) "https://chatgpt.com" else "https://github.com";
    const resolved_label = if (label.len != 0) label else if (is_codex) "Codex account" else "GitHub account";
    const identifier: [64]u8 = @splat('a');
    // Enrollment may resolve to any preexisting canonical account, whose local
    // ID has the domain text bound rather than the generated-handle width.
    const canonical_id: [max_text_bytes]u8 = @splat(1);
    const subject: [256]u8 = @splat('a');
    const tenant: [256]u8 = @splat('a');
    const kind: [128]u8 = @splat('a');
    const identity: Identity = .{
        .provider = provider,
        .issuer = issuer,
        .subject = subject[0..if (is_codex) 256 else 20],
        .tenant = if (is_codex) &tenant else "",
        .verified = true,
    };
    const account_fixture: Account = .{
        .id = &identifier,
        .identity = identity,
        .label = resolved_label,
        .account_type = kind[0..if (is_codex) 64 else 128],
        .source_ids = &.{source_id},
    };
    const account_bytes = try recordGrowth(account_fixture);
    const grant_fixture: Grant = .{
        .id = &canonical_id,
        .account_id = &canonical_id,
        .source_id = source_id,
        .credential_kind = .oauth_access,
        .purposes = &.{ .request, .account_read },
        .audience = issuer,
        .generation = std.math.maxInt(u64),
        .status = .quarantined,
        .provider_expires_at = std.math.minInt(i64),
        .custody_expires_at = std.math.minInt(i64),
    };
    const grant_bytes = try recordGrowth(grant_fixture);
    const quarantine_bytes = try recordGrowth(QuarantinedImport{
        .source_id = source_id,
        .candidate_id = &identifier,
        .identity = identity,
        .reason = .conflicting_identity,
    });
    // Also allow adding the known source association to an existing identity.
    var bytes = try std.math.add(usize, account_bytes, try recordGrowth(source_id));
    bytes = try std.math.add(usize, bytes, grant_bytes);
    bytes = try std.math.add(usize, bytes, quarantine_bytes);
    const observations = if (is_codex) try observationGrowth(provider, &canonical_id) else OutcomeGrowth{};
    bytes = try std.math.add(usize, bytes, observations.bytes);
    // The whole-envelope gate also retains maintenance widening obligations.
    // New rows increase that reserve. A valid generation/status and single-digit
    // expiries give its maximum increase, measured by the same typed serializer.
    var narrow_grant = grant_fixture;
    narrow_grant.generation = 1;
    narrow_grant.status = .ready;
    narrow_grant.provider_expires_at = 0;
    narrow_grant.custody_expires_at = 0;
    const maintenance = try maintenanceGrowth(.{ .accounts = &.{account_fixture}, .grants = &.{narrow_grant} });
    bytes = try std.math.add(usize, bytes, maintenance.bytes);
    // The already-retained enrollment job can grow pending/running -> completed.
    return .{ .bytes = try std.math.add(usize, bytes, revision_growth_bytes + ("completed".len - "pending".len)), .accounts = 1, .grants = 1, .observations = observations.observations, .quarantined_imports = 1, .source_links = 1 };
}

/// R-N13: observation completion bounds come from the accepted provider shape,
/// including all future quota entries rather than only the ordinary Codex limit.
pub fn observationGrowth(provider: []const u8, account_id: []const u8) !OutcomeGrowth {
    try requireId(account_id);
    if (eql(provider, "codex")) {
        // 1 ordinary + 32 additional limits, each access + two windows; one
        // spend-control record. Accepted durations are positive i32 (10 digits),
        // so the longest emitted scope is 13 + 256 + 11 + 10 + 1 = 291 bytes.
        // The 300-byte fixture conservatively keeps space for 19 duration digits.
        const count = (1 + 32) * (1 + 2) + 1;
        const feature: [256]u8 = @splat('a');
        const scope: [300]u8 = @splat('a');
        const bytes = try recordGrowth(Observation{
            .account_id = account_id,
            .resource = .{ .kind = "subscription-usage", .target = &feature, .unit = .custom, .unit_name = "percent-of-window", .scope = &scope },
            .bucket_id = "",
            .remaining = 100,
            .limit = 100,
            .window_start = std.math.minInt(i64),
            .window_end = std.math.minInt(i64),
            .observed_at = std.math.minInt(i64),
            .expires_at = std.math.minInt(i64),
            .status = .unavailable,
            .provenance = .provider_api,
        });
        return .{ .bytes = try std.math.add(usize, revision_growth_bytes, try std.math.mul(usize, count, bytes)), .observations = count };
    }
    if (eql(provider, "github")) {
        var bucket_buffer: [max_text_bytes + "github::core".len]u8 = undefined;
        const bucket = try std.fmt.bufPrint(&bucket_buffer, "github:{s}:core", .{account_id});
        const bytes = try recordGrowth(Observation{
            .account_id = account_id,
            .resource = .{ .kind = "api-calls", .target = "core", .unit = .calls, .scope = "github:rest:core" },
            .bucket_id = bucket,
            .remaining = std.math.floatMax(f64),
            .limit = std.math.floatMax(f64),
            .window_start = std.math.minInt(i64),
            .window_end = std.math.minInt(i64),
            .observed_at = std.math.minInt(i64),
            .expires_at = std.math.minInt(i64),
            .provenance = .provider_api,
        });
        // The locked JSON writer emits decimal floats. Converted u64 counters
        // are nonnegative integral values <=2^64 (20 decimal digits); the counted
        // largest-finite-f64 decimal fixture is much wider. Retain the additional
        // per-number margin conservatively without assuming scientific notation.
        return .{ .bytes = try std.math.add(usize, bytes, revision_growth_bytes + 2 * (17 + 1 + 1 + 1 + 3)), .observations = 1 };
    }
    return error.MissingOutcomeBound;
}

/// R-N13: retained status/generation/expiry fields may widen independently of
/// appends during maintenance or recovery. Count maxima from the actual records;
/// descriptors, identity associations and leases remain unchanged.
pub fn maintenanceGrowth(saved: Snapshot) !OutcomeGrowth {
    var bytes: usize = revision_growth_bytes;
    for (saved.grants) |grant| {
        var widest = grant;
        widest.generation = std.math.maxInt(u64);
        widest.status = .quarantined;
        widest.provider_expires_at = std.math.minInt(i64);
        widest.custody_expires_at = std.math.minInt(i64);
        bytes = try std.math.add(usize, bytes, try wideningGrowth(grant, widest));
    }
    for (saved.jobs) |job| {
        var widest = job;
        widest.operation_generation = std.math.maxInt(u64);
        widest.status = .completed;
        bytes = try std.math.add(usize, bytes, try wideningGrowth(job, widest));
    }
    for (saved.accounts) |account| {
        var widest = account;
        widest.lifecycle = .draining;
        bytes = try std.math.add(usize, bytes, try wideningGrowth(account, widest));
    }
    for (saved.sources) |source| {
        var widest = source;
        widest.status = .disconnected;
        bytes = try std.math.add(usize, bytes, try wideningGrowth(source, widest));
    }
    return .{ .bytes = bytes };
}

fn wideningGrowth(current: anytype, widest: @TypeOf(current)) !usize {
    return (try recordGrowth(widest)) -| (try recordGrowth(current));
}

/// R-N13: acquire's known demand is retained intact, including every scope and
/// resource descriptor. The caller supplies the resolved audience from its grant.
pub fn acquisitionGrowth(binding: Binding, lease: Lease) !OutcomeGrowth {
    try validate(binding);
    try validate(lease);
    if (!sameNativeRef(binding.native_ref, lease.native_ref)) return error.GenerationConflict;
    if (lease.audience.len == 0) return error.MissingOutcomeBound;
    var widest_binding = binding;
    widest_binding.in_flight = std.math.maxInt(u32);
    widest_binding.grant_generation = std.math.maxInt(u64);
    widest_binding.route_generation = std.math.maxInt(u64);
    widest_binding.last_used_revision = std.math.maxInt(u64);
    if (binding.native_ref) |ref| widest_binding.native_ref = widestNativeRef(ref);
    var widest_lease = lease;
    widest_lease.grant_generation = std.math.maxInt(u64);
    widest_lease.route_generation = std.math.maxInt(u64);
    widest_lease.started_at = std.math.minInt(i64);
    widest_lease.expires_at = std.math.minInt(i64);
    if (lease.native_ref) |ref| widest_lease.native_ref = widestNativeRef(ref);
    const bytes = try std.math.add(usize, try recordGrowth(widest_binding), try recordGrowth(widest_lease));
    return .{ .bytes = try std.math.add(usize, bytes, revision_growth_bytes), .bindings = 1, .leases = 1 };
}

/// R-N13: a pre-acceptance 403/429 report can add one rejection even when no
/// provider bucket exists. Completion removes a lease, but credit cannot depend
/// on those bytes being released before the atomic terminal snapshot commits.
pub fn reportGrowth(lease: Lease) !OutcomeGrowth {
    try validate(lease);
    const resource = lease.resource orelse return .{ .bytes = revision_growth_bytes };
    const bytes = try recordGrowth(Observation{
        .account_id = lease.account_id,
        .resource = resource,
        .bucket_id = "",
        .remaining = 0,
        .window_start = std.math.minInt(i64),
        .window_end = std.math.minInt(i64),
        .observed_at = std.math.minInt(i64),
        .expires_at = std.math.minInt(i64),
        .status = .unavailable,
        .provenance = .native_application,
    });
    return .{ .bytes = try std.math.add(usize, bytes, revision_growth_bytes), .observations = 1 };
}

pub const DomainError = error{
    InvalidRecord,
    UnsupportedSchema,
    TooManyRecords,
    NotFound,
    SourceUnauthorized,
    DuplicateId,
    GenerationConflict,
    NoEligibleAccount,
    InFlight,
    GrantNotReady,
    LeaseExpired,
    OwnershipRequired,
};

/// Single-writer state. The caller serializes mutations and persists snapshots.
pub const State = struct {
    allocator: std.mem.Allocator,
    revision: u64 = 0,
    sources: std.ArrayList(Source) = .empty,
    accounts: std.ArrayList(Account) = .empty,
    grants: std.ArrayList(Grant) = .empty,
    observations: std.ArrayList(Observation) = .empty,
    bindings: std.ArrayList(Binding) = .empty,
    leases: std.ArrayList(Lease) = .empty,
    tombstones: std.ArrayList(Tombstone) = .empty,
    quarantined_imports: std.ArrayList(QuarantinedImport) = .empty,
    jobs: std.ArrayList(Job) = .empty,

    pub fn init(allocator: std.mem.Allocator) State {
        return .{ .allocator = allocator };
    }
    pub fn deinit(self: *State) void {
        inline for (.{ "sources", "accounts", "grants", "observations", "bindings", "leases", "tombstones", "quarantined_imports", "jobs" }) |field| {
            const list = &@field(self, field);
            for (list.items) |value| deepFree(@TypeOf(value), self.allocator, value);
            list.deinit(self.allocator);
        }
        self.* = undefined;
    }
    /// Returned slices remain valid until the next mutation or deinit.
    pub fn snapshot(self: *const State) Snapshot {
        return .{
            .revision = self.revision,
            .sources = self.sources.items,
            .accounts = self.accounts.items,
            .grants = self.grants.items,
            .observations = self.observations.items,
            .bindings = self.bindings.items,
            .leases = self.leases.items,
            .tombstones = self.tombstones.items,
            .quarantined_imports = self.quarantined_imports.items,
            .jobs = self.jobs.items,
        };
    }
    /// R-N13: local planning copies exact records without applying restoration
    /// normalization. Candidate allocation or validation cannot mutate live state.
    pub fn clone(self: *const State, allocator: std.mem.Allocator) !State {
        var candidate = State.init(allocator);
        errdefer candidate.deinit();
        inline for (.{ "sources", "accounts", "grants", "observations", "bindings", "leases", "tombstones", "quarantined_imports", "jobs" }) |field| {
            const source = @field(self, field);
            const target = &@field(candidate, field);
            for (source.items) |value| {
                const owned = try deepClone(@TypeOf(value), allocator, value);
                target.append(allocator, owned) catch |err| {
                    deepFree(@TypeOf(value), allocator, owned);
                    return err;
                };
            }
        }
        candidate.revision = self.revision;
        return candidate;
    }
    /// R-N13: forget duplicates identity once for each associated source. Count
    /// all real tombstones; a fixed one-account credit misses multi-source growth.
    pub fn forgetGrowth(self: *const State, account_id: []const u8) !OutcomeGrowth {
        const owner = self.account(account_id) orelse return error.NotFound;
        var bytes: usize = revision_growth_bytes;
        for (owner.source_ids) |source_id| bytes = try std.math.add(usize, bytes, try recordGrowth(Tombstone{ .identity = owner.identity, .source_id = source_id }));
        return .{ .bytes = bytes, .tombstones = owner.source_ids.len };
    }
    /// Validates foreign keys, identity uniqueness and generations before import.
    pub fn fromSnapshot(allocator: std.mem.Allocator, value: Snapshot) !State {
        if (value.schema_version != schema_version) return error.UnsupportedSchema;
        var state = State.init(allocator);
        errdefer state.deinit();
        for (value.sources) |source| {
            if (state.sourceIndex(source.id) != null) return error.DuplicateId;
            _ = try state.connectSource(source);
        }
        for (value.accounts) |owner| {
            try validate(owner);
            try requireId(owner.id);
            try requireIdentity(owner.identity);
            if (!owner.identity.verified or owner.source_ids.len == 0) return error.InvalidRecord;
            if (state.accountIndex(owner.id) != null) return error.DuplicateId;
            for (state.accounts.items) |other| if (sameIdentity(other.identity, owner.identity)) return error.DuplicateId;
            for (owner.source_ids, 0..) |source_id, i| {
                const source = state.sources.items[state.sourceIndex(source_id) orelse return error.NotFound];
                if (source.provider.len > 0 and !eql(source.provider, owner.identity.provider)) return error.InvalidRecord;
                for (owner.source_ids[0..i]) |previous| if (eql(previous, source_id)) return error.DuplicateId;
            }
            try state.appendOwned(Account, &state.accounts, owner);
        }
        for (value.grants) |g| {
            if (state.grantIndex(g.id) != null) return error.DuplicateId;
            _ = try state.addGrant(g);
        }
        for (value.observations) |observation| try state.observe(observation);
        for (value.bindings) |b| {
            try validate(b);
            if (b.native_ref) |ref| try ref.validate();
            try requireId(b.id);
            try requireId(b.application);
            try requireId(b.session_id);
            if (state.bindingIndex(b.id) != null) return error.DuplicateId;
            const g = state.grant(b.grant_id) orelse return error.NotFound;
            if (!eql(g.account_id, b.account_id) or b.grant_generation == 0 or b.grant_generation > g.generation or b.route_generation == 0) return error.InvalidRecord;
            var restored = b;
            restored.in_flight = 0;
            try state.appendOwned(Binding, &state.bindings, restored);
        }
        for (value.leases) |lease| {
            try validate(lease);
            if (lease.native_ref) |ref| try ref.validate();
            try requireId(lease.id);
            if (lease.expires_at <= lease.started_at or @as(i128, lease.expires_at) - @as(i128, lease.started_at) > 3600) return error.InvalidRecord;
            for (state.leases.items) |existing| if (eql(existing.id, lease.id)) return error.DuplicateId;
            const bi = state.bindingIndex(lease.binding_id) orelse return error.NotFound;
            const b = state.bindings.items[bi];
            if (!sameNativeRef(b.native_ref, lease.native_ref) or !eql(b.account_id, lease.account_id) or !eql(b.grant_id, lease.grant_id) or b.grant_generation != lease.grant_generation or b.route_generation != lease.route_generation) return error.InvalidRecord;
            const g = state.grant(lease.grant_id) orelse return error.NotFound;
            try validateLeaseAuthority(lease, g);
            try state.appendOwned(Lease, &state.leases, lease);
            state.bindings.items[bi].in_flight += 1;
        }
        for (value.bindings) |b| {
            const actual = state.bindings.items[state.bindingIndex(b.id).?];
            if (actual.in_flight != b.in_flight) return error.InvalidRecord;
        }
        for (value.tombstones) |tombstone| {
            try requireIdentity(tombstone.identity);
            try requireId(tombstone.source_id);
            if (!tombstone.identity.verified) return error.InvalidRecord;
            if (state.sourceIndex(tombstone.source_id) == null) return error.NotFound;
            for (state.tombstones.items) |existing| if (sameIdentity(existing.identity, tombstone.identity) and eql(existing.source_id, tombstone.source_id)) return error.DuplicateId;
            for (state.accounts.items) |owner| if (sameIdentity(owner.identity, tombstone.identity)) return error.InvalidRecord;
            try state.appendOwned(Tombstone, &state.tombstones, tombstone);
        }
        for (value.quarantined_imports) |candidate| {
            try requireId(candidate.source_id);
            try requireId(candidate.candidate_id);
            try requireIdentity(candidate.identity);
            if ((candidate.reason == .unverified_identity and candidate.identity.verified) or (candidate.reason == .conflicting_identity and !candidate.identity.verified)) return error.InvalidRecord;
            if (state.sourceIndex(candidate.source_id) == null) return error.NotFound;
            try state.appendOwned(QuarantinedImport, &state.quarantined_imports, candidate);
        }
        for (value.jobs) |job| _ = try state.putJob(job);
        state.revision = value.revision;
        return state;
    }
    pub fn account(self: *const State, id: []const u8) ?Account {
        return if (self.accountIndex(id)) |i| self.accounts.items[i] else null;
    }
    pub fn grant(self: *const State, id: []const u8) ?Grant {
        return if (self.grantIndex(id)) |i| self.grants.items[i] else null;
    }
    pub fn binding(self: *const State, id: []const u8) ?Binding {
        return if (self.bindingIndex(id)) |i| self.bindings.items[i] else null;
    }
    pub fn connectSource(self: *State, source: Source) !Source {
        try requireId(source.id);
        if (source.authorized_until) |expires| if (expires <= source.authorized_at) return error.InvalidRecord;
        const index = if (self.sourceIndex(source.id)) |i| blk: {
            const previous = self.sources.items[i];
            if (previous.kind != source.kind) return error.InvalidRecord;
            if (previous.provider.len > 0 and source.provider.len > 0 and !eql(previous.provider, source.provider)) return error.InvalidRecord;
            for (self.accounts.items) |owner| {
                if (contains(owner.source_ids, source.id) and source.provider.len > 0 and !eql(owner.identity.provider, source.provider)) return error.InvalidRecord;
            }
            var updated = source;
            if (updated.provider.len == 0) updated.provider = previous.provider;
            try self.replaceOwned(Source, &self.sources.items[i], updated);
            break :blk i;
        } else blk: {
            try self.appendOwned(Source, &self.sources, source);
            break :blk self.sources.items.len - 1;
        };
        self.changed();
        return self.sources.items[index];
    }
    /// Source disappearance detaches it; valid adopted grants remain available.
    pub fn detachSource(self: *State, id: []const u8) !void {
        const i = self.sourceIndex(id) orelse return error.NotFound;
        self.sources.items[i].status = .detached;
        self.changed();
    }
    /// Explicit disconnection ends source authorization and invalidates its grants.
    pub fn disconnectSource(self: *State, id: []const u8) !void {
        const i = self.sourceIndex(id) orelse return error.NotFound;
        self.sources.items[i].status = .disconnected;
        for (self.grants.items) |*g| if (eql(g.source_id, id)) {
            g.status = .invalid;
        };
        self.changed();
    }
    /// Automatically admits verified sources and deduplicates verified identities.
    pub fn enroll(self: *State, input: Enrollment, now: i64) !EnrollmentResult {
        try validate(input);
        try requireId(input.account_id);
        try requireIdentity(input.identity);
        const source = self.sources.items[self.sourceIndex(input.source_id) orelse return error.NotFound];
        if (source.status != .connected or source.authorized_at > now or !unexpired(source.authorized_until, now)) return error.SourceUnauthorized;
        if (source.provider.len > 0 and !eql(source.provider, input.identity.provider)) return error.SourceUnauthorized;
        for (self.tombstones.items) |tombstone| {
            if (sameIdentity(tombstone.identity, input.identity)) return .{ .status = .tombstoned };
        }
        if (!input.identity.verified) {
            try self.quarantine(input, .unverified_identity);
            return .{ .status = .quarantined };
        }
        if (self.accountIndex(input.account_id)) |i| {
            if (!sameIdentity(self.accounts.items[i].identity, input.identity)) {
                try self.quarantine(input, .conflicting_identity);
                return .{ .status = .quarantined };
            }
        }
        for (self.accounts.items) |*existing| {
            if (!sameIdentity(existing.identity, input.identity)) continue;
            const add_source = !contains(existing.source_ids, input.source_id);
            const account_type = input.account_type orelse existing.account_type;
            const update_type = !eql(existing.account_type, account_type);
            // A newly verified read may refresh descriptive account metadata.
            // It cannot change identity, labels, lifecycle or grant authority.
            // Stage both fields before publishing either allocation.
            const updated_type: ?[]const u8 = if (update_type) try deepClone([]const u8, self.allocator, account_type) else null;
            errdefer if (updated_type) |updated| deepFree([]const u8, self.allocator, updated);
            const updated_sources: ?[]const []const u8 = if (add_source) blk: {
                if (existing.source_ids.len >= max_list_items) return error.TooManyRecords;
                const ids = try self.allocator.alloc([]const u8, existing.source_ids.len + 1);
                defer self.allocator.free(ids);
                @memcpy(ids[0..existing.source_ids.len], existing.source_ids);
                ids[existing.source_ids.len] = input.source_id;
                break :blk try deepClone([]const []const u8, self.allocator, ids);
            } else null;
            if (updated_sources) |ids| {
                deepFree([]const []const u8, self.allocator, existing.source_ids);
                existing.source_ids = ids;
            }
            if (updated_type) |updated| {
                deepFree([]const u8, self.allocator, existing.account_type);
                existing.account_type = updated;
            }
            if (add_source or update_type) self.changed();
            return .{ .status = .existing, .account_id = existing.id };
        }
        const source_ids = [_][]const u8{input.source_id};
        try self.appendOwned(Account, &self.accounts, .{
            .id = input.account_id,
            .identity = input.identity,
            .label = input.label,
            .account_type = input.account_type orelse "generic",
            .source_ids = &source_ids,
        });
        self.changed();
        return .{ .status = .enrolled, .account_id = self.accounts.items[self.accounts.items.len - 1].id };
    }
    pub fn addGrant(self: *State, input: Grant) !Grant {
        try validateGrant(input);
        const owner = self.account(input.account_id) orelse return error.NotFound;
        if (!contains(owner.source_ids, input.source_id)) return error.SourceUnauthorized;
        if (self.sourceIndex(input.source_id) == null) return error.NotFound;
        const index = if (self.grantIndex(input.id)) |i| blk: {
            const previous = self.grants.items[i];
            if (!eql(previous.account_id, input.account_id) or !eql(previous.source_id, input.source_id)) return error.DuplicateId;
            if (!sameGrantAuthority(previous, input)) return error.InvalidRecord;
            if (previous.generation == std.math.maxInt(u64) or input.generation != previous.generation + 1) return error.GenerationConflict;
            try self.replaceOwned(Grant, &self.grants.items[i], input);
            break :blk i;
        } else blk: {
            try self.appendOwned(Grant, &self.grants, input);
            break :blk self.grants.items.len - 1;
        };
        self.changed();
        return self.grants.items[index];
    }
    /// Compare-and-swap grant state; only Omux-owned grants may rotate themselves.
    pub fn reconcile(self: *State, input: Reconciliation) !void {
        const i = self.grantIndex(input.grant_id) orelse return error.NotFound;
        const g = &self.grants.items[i];
        if (g.generation != input.expected_generation or input.expected_generation == std.math.maxInt(u64) or input.next_generation != input.expected_generation + 1) return error.GenerationConflict;
        if (input.status == .refreshing and g.ownership != .omux) return error.OwnershipRequired;
        g.generation = input.next_generation;
        g.status = input.status;
        g.provider_expires_at = input.provider_expires_at;
        g.custody_expires_at = input.custody_expires_at;
        self.changed();
    }
    pub fn observe(self: *State, input: Observation) !void {
        try validateObservation(input);
        if (self.accountIndex(input.account_id) == null) return error.NotFound;
        for (self.observations.items) |*existing| {
            const same_bucket_resource = eql(existing.account_id, input.account_id) and eql(existing.bucket_id, input.bucket_id) and sameResource(existing.resource, input.resource);
            const same_window = existing.window_start == input.window_start and existing.window_end == input.window_end;
            const expired_predecessor = input.observed_at > existing.observed_at and (existing.expires_at <= input.observed_at or existing.window_end <= input.observed_at);
            if (same_bucket_resource and (same_window or expired_predecessor)) {
                if (input.observed_at < existing.observed_at) return error.GenerationConflict;
                // A failed reader cannot erase a still-fresh provider rejection.
                if (input.status == .unknown and existing.expires_at > input.observed_at and existing.status != .unknown) return;
                try self.replaceOwned(Observation, existing, input);
                const stored = existing.*;
                self.retireOlderRejections(stored);
                self.changed();
                return;
            }
        }
        try self.appendOwned(Observation, &self.observations, input);
        self.retireOlderRejections(self.observations.items[self.observations.items.len - 1]);
        self.changed();
    }
    /// Atomically publish one provider response's observations. Only observation
    /// records are staged; identity/account authority stays borrowed and read-only.
    pub fn observeBatch(self: *State, input: []const Observation) !void {
        if (input.len == 0) return;
        if (input.len > max_records) return error.TooManyRecords;
        var staged = State.init(self.allocator);
        staged.accounts = self.accounts;
        defer {
            for (staged.observations.items) |observation| deepFree(Observation, self.allocator, observation);
            staged.observations.deinit(self.allocator);
        }
        for (self.observations.items) |observation| try staged.appendOwned(Observation, &staged.observations, observation);
        for (input) |observation| try staged.observe(observation);
        if (staged.revision == 0) return;
        const previous = self.observations;
        self.observations = staged.observations;
        staged.observations = previous;
        self.changed();
    }
    /// Expired native rejection cooldowns are transient; retain the latest
    /// stale provider sample for unknown UI and prune superseded history.
    pub fn pruneObservations(self: *State, now: i64) usize {
        var removed: usize = 0;
        var i: usize = 0;
        while (i < self.observations.items.len) {
            const previous = self.observations.items[i];
            var superseded = false;
            if (previous.expires_at <= now or previous.window_end <= now) {
                if (previous.provenance == .native_application and previous.status == .unavailable) {
                    superseded = true;
                } else for (self.observations.items) |newer| {
                    if (eql(previous.account_id, newer.account_id) and sameResource(previous.resource, newer.resource) and eql(previous.bucket_id, newer.bucket_id) and newer.observed_at > previous.observed_at) {
                        superseded = true;
                        break;
                    }
                }
            }
            if (superseded) {
                deepFree(Observation, self.allocator, self.observations.orderedRemove(i));
                removed += 1;
            } else i += 1;
        }
        if (removed > 0) self.changed();
        return removed;
    }
    /// Compatible explicit bucket/window totals only; shared buckets count once.
    pub fn aggregate(self: *const State, provider: []const u8, issuer: []const u8, resource: Resource, window_start: i64, window_end: i64, now: i64) Aggregation {
        var result: Aggregation = .{};
        for (self.observations.items, 0..) |observation, i| {
            const owner = self.account(observation.account_id) orelse continue;
            if (!eql(owner.identity.provider, provider) or !eql(owner.identity.issuer, issuer)) continue;
            if (!sameResource(resource, observation.resource) or observation.window_start != window_start or observation.window_end != window_end) continue;
            if (!freshForAggregation(observation, now)) {
                result.unknown_buckets += 1;
                continue;
            }
            var previous = false;
            for (self.observations.items[0..i]) |other| {
                if (self.sameBucket(other, observation) and freshForAggregation(other, now)) {
                    previous = true;
                    break;
                }
            }
            if (previous) continue;
            var remaining = observation.remaining;
            var limit = observation.limit;
            for (self.observations.items[i + 1 ..]) |other| {
                if (!self.sameBucket(other, observation) or !freshForAggregation(other, now)) continue;
                remaining = @min(remaining, other.remaining);
                if (other.limit) |v| {
                    if (limit) |current| limit = @min(current, v);
                } else limit = null;
            }
            const total_remaining = result.remaining + remaining;
            if (!std.math.isFinite(total_remaining)) {
                result.unknown_buckets += 1;
                continue;
            }
            result.remaining = total_remaining;
            result.buckets += 1;
            if (result.limit) |current| {
                if (limit) |v| {
                    const total_limit = current + v;
                    if (std.math.isFinite(total_limit)) result.limit = total_limit else {
                        result.limit = null;
                        result.unknown_buckets += 1;
                    }
                } else result.limit = null;
            }
        }
        for (self.accounts.items) |owner| {
            if (!eql(owner.identity.provider, provider) or !eql(owner.identity.issuer, issuer)) continue;
            var observed = false;
            for (self.observations.items) |observation| {
                if (eql(observation.account_id, owner.id) and sameResource(observation.resource, resource) and observation.window_start == window_start and observation.window_end == window_end) {
                    observed = true;
                    break;
                }
            }
            if (!observed) result.unknown_buckets += 1;
        }
        result.complete = result.buckets > 0 and result.unknown_buckets == 0;
        return result;
    }
    /// Sticky bindings and all technically compatible accounts are the defaults.
    /// Selection never changes another binding or consumes capacity speculatively.
    pub fn select(self: *const State, demand: Demand, binding_id: ?[]const u8) !Selection {
        try validate(demand);
        try validateScopes(demand.scopes);
        try requireId(demand.provider);
        try requireId(demand.audience);
        try validateResource(demand.resource);
        if (!std.math.isFinite(demand.required) or demand.required < 0) return error.InvalidRecord;
        if (binding_id) |id| {
            const b = self.binding(id) orelse return error.NotFound;
            if (self.grant(b.grant_id)) |g| {
                if (g.generation == b.grant_generation and self.eligible(g, demand)) return .{ .account_id = g.account_id, .grant_id = g.id, .generation = g.generation, .sticky = true };
            }
        }
        for (self.grants.items) |g| if (self.eligible(g, demand)) return .{ .account_id = g.account_id, .grant_id = g.id, .generation = g.generation };
        return error.NoEligibleAccount;
    }
    pub fn bind(self: *State, input: Binding) !Binding {
        try validate(input);
        if (input.native_ref) |ref| try ref.validate();
        try requireId(input.id);
        try requireId(input.application);
        try requireId(input.session_id);
        if (input.in_flight != 0 or input.route_generation == 0) return error.InvalidRecord;
        const g = self.grant(input.grant_id) orelse return error.NotFound;
        if (!eql(g.account_id, input.account_id) or g.generation != input.grant_generation) return error.GenerationConflict;
        const index = if (self.bindingIndex(input.id)) |i| blk: {
            const previous = self.bindings.items[i];
            if (!eql(previous.application, input.application) or !eql(previous.session_id, input.session_id)) return error.DuplicateId;
            // R-N13: route changes cannot replace native attachment authority.
            if (!sameNativeRef(previous.native_ref, input.native_ref)) return error.GenerationConflict;
            if (previous.in_flight != 0) return error.InFlight;
            const route_changed = !eql(previous.grant_id, input.grant_id) or previous.grant_generation != input.grant_generation;
            const expected_route = std.math.add(u64, previous.route_generation, @as(u64, @intFromBool(route_changed))) catch return error.GenerationConflict;
            if (input.route_generation != expected_route) return error.GenerationConflict;
            try self.replaceOwned(Binding, &self.bindings.items[i], input);
            break :blk i;
        } else blk: {
            try self.appendOwned(Binding, &self.bindings, input);
            break :blk self.bindings.items.len - 1;
        };
        self.changed();
        return self.bindings.items[index];
    }
    /// Native unregistration releases a binding only after its leases finish.
    pub fn releaseBinding(self: *State, id: []const u8) !void {
        const i = self.bindingIndex(id) orelse return error.NotFound;
        if (self.bindings.items[i].native_ref != null) return error.NativeOwnerRequired;
        try self.releaseBindingIndex(i);
    }
    pub fn releaseBindingExact(self: *State, id: []const u8, ref: native_owner.NativeRef) !void {
        try ref.validate();
        const i = self.bindingIndex(id) orelse return error.NotFound;
        const retained = self.bindings.items[i].native_ref orelse return error.NativeOwnerRequired;
        if (!retained.same(ref)) return error.GenerationConflict;
        try self.releaseBindingIndex(i);
    }
    fn releaseBindingIndex(self: *State, i: usize) !void {
        if (self.bindings.items[i].in_flight != 0) return error.InFlight;
        deepFree(Binding, self.allocator, self.bindings.orderedRemove(i));
        self.changed();
    }
    pub fn beginLease(self: *State, input: Lease, now: i64) !Lease {
        try validate(input);
        if (input.native_ref) |ref| try ref.validate();
        try requireId(input.id);
        if (input.started_at > now or input.expires_at <= now or input.expires_at <= input.started_at or @as(i128, input.expires_at) - @as(i128, input.started_at) > 3600) return error.LeaseExpired;
        for (self.leases.items) |lease| if (eql(lease.id, input.id)) return error.DuplicateId;
        const bi = self.bindingIndex(input.binding_id) orelse return error.NotFound;
        const b = self.bindings.items[bi];
        if (!sameNativeRef(b.native_ref, input.native_ref) or !eql(b.account_id, input.account_id) or !eql(b.grant_id, input.grant_id) or b.grant_generation != input.grant_generation or b.route_generation != input.route_generation) return error.GenerationConflict;
        const owner = self.account(input.account_id) orelse return error.NotFound;
        const g = self.grant(input.grant_id) orelse return error.NotFound;
        try validateLeaseAuthority(input, g);
        const source = self.sources.items[self.sourceIndex(g.source_id) orelse return error.NotFound];
        if (source.status == .disconnected or source.authorized_at > now or !unexpired(source.authorized_until, input.expires_at - 1) or (g.credential_kind == .browser_bound and source.status != .connected)) return error.SourceUnauthorized;
        if (owner.lifecycle != .active or g.status != .ready or g.generation != input.grant_generation or !hasPurpose(g, input.purpose) or !unexpired(g.provider_expires_at, now) or !unexpired(g.custody_expires_at, now)) return error.GrantNotReady;
        if (!unexpired(g.provider_expires_at, input.expires_at - 1) or !unexpired(g.custody_expires_at, input.expires_at - 1)) return error.LeaseExpired;
        if (input.audience.len > 0 and !eql(input.audience, g.audience)) return error.GrantNotReady;
        for (input.scopes) |scope| if (!contains(g.scopes, scope)) return error.GrantNotReady;
        if (input.resource) |resource| {
            try validateResource(resource);
            const demand: Demand = .{ .provider = owner.identity.provider, .issuer = owner.identity.issuer, .audience = g.audience, .purpose = input.purpose, .scopes = input.scopes, .resource = resource, .required = input.required, .now = now, .requires_capacity = input.requires_capacity, .allow_browser_bound = input.browser_context };
            if (!self.eligible(g, demand)) return error.GrantNotReady;
        }
        var issued = input;
        if (issued.audience.len == 0) issued.audience = g.audience;
        try self.appendOwned(Lease, &self.leases, issued);
        self.bindings.items[bi].in_flight += 1;
        self.changed();
        return self.leases.items[self.leases.items.len - 1];
    }
    pub fn completeLease(self: *State, id: []const u8) !void {
        for (self.leases.items, 0..) |lease, i| {
            if (!eql(lease.id, id)) continue;
            const bi = self.bindingIndex(lease.binding_id) orelse return error.InvalidRecord;
            if (self.bindings.items[bi].in_flight == 0) return error.InvalidRecord;
            self.bindings.items[bi].in_flight -= 1;
            deepFree(Lease, self.allocator, self.leases.orderedRemove(i));
            self.changed();
            return;
        }
        return error.NotFound;
    }
    pub fn pause(self: *State, account_id: []const u8, paused: bool) !void {
        const i = self.accountIndex(account_id) orelse return error.NotFound;
        self.accounts.items[i].lifecycle = if (paused) .paused else .active;
        self.changed();
    }
    pub fn drain(self: *State, account_id: []const u8) !void {
        const i = self.accountIndex(account_id) orelse return error.NotFound;
        self.accounts.items[i].lifecycle = .draining;
        self.changed();
    }
    /// Forget is local custody removal, not an implicit upstream revocation.
    /// Active leases must finish first. Tombstones block automatic re-enrollment.
    pub fn forget(self: *State, account_id: []const u8) !void {
        const ai = self.accountIndex(account_id) orelse return error.NotFound;
        for (self.leases.items) |lease| if (eql(lease.account_id, account_id)) return error.InFlight;
        const owner = self.accounts.items[ai];
        if (self.tombstones.items.len + owner.source_ids.len > max_records) return error.TooManyRecords;
        var staged: std.ArrayList(Tombstone) = .empty;
        defer {
            for (staged.items) |value| deepFree(Tombstone, self.allocator, value);
            staged.deinit(self.allocator);
        }
        for (owner.source_ids) |source_id| {
            const value = try deepClone(Tombstone, self.allocator, .{ .identity = owner.identity, .source_id = source_id });
            errdefer deepFree(Tombstone, self.allocator, value);
            try staged.append(self.allocator, value);
        }
        try self.tombstones.ensureUnusedCapacity(self.allocator, staged.items.len);
        self.tombstones.appendSliceAssumeCapacity(staged.items);
        staged.clearRetainingCapacity();
        self.removeAccountRecords(Grant, &self.grants, owner.id);
        self.removeAccountRecords(Observation, &self.observations, owner.id);
        self.removeAccountRecords(Binding, &self.bindings, owner.id);
        self.removeAccountRecords(Job, &self.jobs, owner.id);
        deepFree(Account, self.allocator, self.accounts.orderedRemove(ai));
        self.changed();
    }
    /// Explicit re-enrollment reauthorizes an identity across its prior sources.
    pub fn permitReenrollment(self: *State, identity: Identity, source_id: []const u8, now: i64) !void {
        try requireIdentity(identity);
        if (!identity.verified) return error.InvalidRecord;
        const source = self.sources.items[self.sourceIndex(source_id) orelse return error.NotFound];
        if (source.status != .connected or source.authorized_at > now or !unexpired(source.authorized_until, now) or (source.provider.len > 0 and !eql(source.provider, identity.provider))) return error.SourceUnauthorized;
        const stable = try deepClone(Identity, self.allocator, identity);
        defer deepFree(Identity, self.allocator, stable);
        var i: usize = 0;
        while (i < self.tombstones.items.len) {
            if (sameIdentity(self.tombstones.items[i].identity, stable)) {
                deepFree(Tombstone, self.allocator, self.tombstones.orderedRemove(i));
                self.changed();
            } else i += 1;
        }
    }
    /// Same ID and same job intent is idempotent; IDs cannot change operation kind.
    pub fn putJob(self: *State, input: Job) !Job {
        try validate(input);
        try requireId(input.id);
        if (input.operation_generation == 0) return error.InvalidRecord;
        if (input.account_id.len > 0 and self.accountIndex(input.account_id) == null) return error.NotFound;
        for (self.jobs.items) |*existing| {
            if (!eql(existing.id, input.id)) continue;
            if (existing.kind != input.kind or !eql(existing.account_id, input.account_id)) return error.DuplicateId;
            if (existing.status == .completed or existing.status == .failed) return existing.*;
            if (input.operation_generation != existing.operation_generation) return error.GenerationConflict;
            if (existing.status == .running and input.status == .pending) return existing.*;
            existing.status = input.status;
            self.changed();
            return existing.*;
        }
        try self.appendOwned(Job, &self.jobs, input);
        self.changed();
        return self.jobs.items[self.jobs.items.len - 1];
    }
    /// Explicitly repeat a completed job while retaining one durable intent row.
    /// Concurrent/replayed active starts stay in the same operation generation.
    pub fn reopenJob(self: *State, input: Job) !Job {
        try validate(input);
        try requireId(input.id);
        if (input.status != .pending and input.status != .running) return error.InvalidRecord;
        if (input.operation_generation == 0) return error.InvalidRecord;
        if (input.account_id.len > 0 and self.accountIndex(input.account_id) == null) return error.NotFound;
        for (self.jobs.items) |*existing| {
            if (!eql(existing.id, input.id)) continue;
            if (existing.kind != input.kind or !eql(existing.account_id, input.account_id)) return error.DuplicateId;
            if (existing.status == .completed or existing.status == .failed) {
                if (existing.operation_generation == std.math.maxInt(u64)) return error.GenerationConflict;
                existing.operation_generation += 1;
                existing.status = input.status;
                self.changed();
            } else if (existing.status == .pending and input.status == .running) {
                existing.status = .running;
                self.changed();
            }
            return existing.*;
        }
        if (input.operation_generation != 1) return error.GenerationConflict;
        return self.putJob(input);
    }
    fn eligible(self: *const State, g: Grant, demand: Demand) bool {
        const owner = self.account(g.account_id) orelse return false;
        if (owner.lifecycle != .active or !owner.identity.verified or !eql(owner.identity.provider, demand.provider) or g.status != .ready or !eql(g.audience, demand.audience) or !hasPurpose(g, demand.purpose) or !unexpired(g.provider_expires_at, demand.now) or !unexpired(g.custody_expires_at, demand.now)) return false;
        const source = self.sources.items[self.sourceIndex(g.source_id) orelse return false];
        if (source.status == .disconnected or source.authorized_at > demand.now or !unexpired(source.authorized_until, demand.now)) return false;
        if (demand.issuer) |issuer| if (!eql(owner.identity.issuer, issuer)) return false;
        if (g.credential_kind == .oauth_refresh) return false;
        if (g.credential_kind == .browser_bound and (!demand.allow_browser_bound or source.status != .connected)) return false;
        if (source.status == .detached and g.ownership == .external and g.credential_kind == .browser_bound) return false;
        if (demand.allowed_account_ids.len > 0 and !contains(demand.allowed_account_ids, owner.id)) return false;
        for (demand.scopes) |scope| if (!contains(g.scopes, scope)) return false;
        // Keep explicit failures until their cooldown ends or a newer provider
        // or native success proves that this exact resource became ready again.
        for (self.observations.items) |negative| {
            if (!eql(negative.account_id, owner.id) or !sameResource(negative.resource, demand.resource) or !freshForDemand(negative, demand)) continue;
            if (negative.status != .unavailable and !(negative.status == .ready and negative.remaining < demand.required)) continue;
            var recovered = false;
            for (self.observations.items) |ready| {
                if (eql(ready.account_id, owner.id) and sameResource(ready.resource, demand.resource) and freshForDemand(ready, demand) and ready.observed_at > negative.observed_at and ready.status == .ready and ready.remaining >= demand.required and (ready.provenance == .provider_api or ready.provenance == .native_application)) {
                    recovered = true;
                    break;
                }
            }
            if (!recovered) return false;
        }
        var newest: ?Observation = null;
        for (self.observations.items) |observation| {
            if (!eql(observation.account_id, owner.id) or !sameResource(observation.resource, demand.resource) or observation.observed_at > demand.now or observation.expires_at <= demand.now or observation.window_start > demand.now or observation.window_end <= demand.now) continue;
            if (newest == null or observation.observed_at >= newest.?.observed_at) newest = observation;
        }
        const observation = newest orelse return !demand.requires_capacity;
        if (observation.status == .unavailable) return false;
        if (observation.status == .unknown) return !demand.requires_capacity;
        if (observation.remaining < demand.required) return false;
        if (observation.bucket_id.len > 0) for (self.observations.items) |shared| {
            if (self.sameBucket(shared, observation) and shared.expires_at > demand.now and shared.observed_at <= demand.now and (shared.status != .ready or shared.remaining < demand.required)) return false;
        };
        return true;
    }
    fn retireOlderRejections(self: *State, ready: Observation) void {
        if (ready.status != .ready or ready.remaining <= 0 or ready.window_start > ready.observed_at or ready.window_end <= ready.observed_at or (ready.provenance != .provider_api and ready.provenance != .native_application)) return;
        var i: usize = 0;
        while (i < self.observations.items.len) {
            const previous = self.observations.items[i];
            if (eql(previous.account_id, ready.account_id) and sameResource(previous.resource, ready.resource) and previous.observed_at < ready.observed_at and (previous.status == .unavailable or (previous.status == .ready and previous.remaining == 0))) {
                deepFree(Observation, self.allocator, self.observations.orderedRemove(i));
            } else i += 1;
        }
    }
    fn sameBucket(self: *const State, a: Observation, b: Observation) bool {
        if (a.bucket_id.len == 0 or !eql(a.bucket_id, b.bucket_id) or !sameResource(a.resource, b.resource) or a.window_start != b.window_start or a.window_end != b.window_end) return false;
        const owner_a = self.account(a.account_id) orelse return false;
        const owner_b = self.account(b.account_id) orelse return false;
        return eql(owner_a.identity.provider, owner_b.identity.provider) and eql(owner_a.identity.issuer, owner_b.identity.issuer) and eql(owner_a.identity.tenant, owner_b.identity.tenant);
    }
    fn quarantine(self: *State, input: Enrollment, reason: @FieldType(QuarantinedImport, "reason")) !void {
        for (self.quarantined_imports.items) |candidate| if (eql(candidate.source_id, input.source_id) and eql(candidate.candidate_id, input.account_id) and sameIdentity(candidate.identity, input.identity)) return;
        try self.appendOwned(QuarantinedImport, &self.quarantined_imports, .{ .source_id = input.source_id, .candidate_id = input.account_id, .identity = input.identity, .reason = reason });
        self.changed();
    }
    fn changed(self: *State) void {
        self.revision +|= 1;
    }
    fn sourceIndex(self: *const State, id: []const u8) ?usize {
        return recordIndex(Source, self.sources.items, id);
    }
    fn accountIndex(self: *const State, id: []const u8) ?usize {
        return recordIndex(Account, self.accounts.items, id);
    }
    fn grantIndex(self: *const State, id: []const u8) ?usize {
        return recordIndex(Grant, self.grants.items, id);
    }
    fn bindingIndex(self: *const State, id: []const u8) ?usize {
        return recordIndex(Binding, self.bindings.items, id);
    }
    fn appendOwned(self: *State, comptime T: type, list: *std.ArrayList(T), value: T) !void {
        if (list.items.len >= max_records) return error.TooManyRecords;
        try validate(value);
        const owned = try deepClone(T, self.allocator, value);
        errdefer deepFree(T, self.allocator, owned);
        try list.append(self.allocator, owned);
    }
    fn replaceOwned(self: *State, comptime T: type, target: *T, value: T) !void {
        try validate(value);
        const replacement = try deepClone(T, self.allocator, value);
        deepFree(T, self.allocator, target.*);
        target.* = replacement;
    }
    fn removeAccountRecords(self: *State, comptime T: type, list: *std.ArrayList(T), account_id: []const u8) void {
        var i: usize = 0;
        while (i < list.items.len) {
            if (eql(list.items[i].account_id, account_id)) deepFree(T, self.allocator, list.orderedRemove(i)) else i += 1;
        }
    }
};

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
pub fn sameIdentity(a: Identity, b: Identity) bool {
    return eql(a.provider, b.provider) and eql(a.issuer, b.issuer) and eql(a.subject, b.subject) and eql(a.tenant, b.tenant);
}
pub fn sameResource(a: Resource, b: Resource) bool {
    return eql(a.kind, b.kind) and eql(a.target, b.target) and a.unit == b.unit and eql(a.unit_name, b.unit_name) and eql(a.scope, b.scope);
}
fn contains(values: []const []const u8, value: []const u8) bool {
    for (values) |item| if (eql(item, value)) return true;
    return false;
}
fn hasPurpose(g: Grant, purpose: Purpose) bool {
    for (g.purposes) |item| if (item == purpose) return true;
    return false;
}
fn unexpired(expiry: ?i64, now: i64) bool {
    return if (expiry) |value| value > now else true;
}
fn freshForDemand(observation: Observation, demand: Demand) bool {
    return observation.observed_at <= demand.now and observation.expires_at > demand.now and observation.window_start <= demand.now and observation.window_end > demand.now;
}
fn freshForAggregation(observation: Observation, now: i64) bool {
    return observation.status == .ready and observation.bucket_id.len > 0 and observation.observed_at <= now and observation.expires_at > now and observation.window_start <= now and observation.window_end > now;
}
fn recordIndex(comptime T: type, records: []const T, id: []const u8) ?usize {
    for (records, 0..) |value, i| if (eql(value.id, id)) return i;
    return null;
}
fn requireId(value: []const u8) !void {
    if (value.len == 0 or value.len > max_text_bytes or !std.unicode.utf8ValidateSlice(value) or std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidRecord;
}
fn requireIdentity(value: Identity) !void {
    try requireId(value.provider);
    try requireId(value.issuer);
    try requireId(value.subject);
}
fn validateGrant(value: Grant) !void {
    try validate(value);
    try requireId(value.id);
    try requireId(value.account_id);
    try requireId(value.source_id);
    try requireId(value.audience);
    if (value.generation == 0 or value.purposes.len == 0) return error.InvalidRecord;
    if (value.credential_kind == .oauth_refresh and (hasPurpose(value, .request) or hasPurpose(value, .account_read))) return error.InvalidRecord;
    for (value.purposes, 0..) |purpose, i| for (value.purposes[0..i]) |previous| {
        if (purpose == previous) return error.InvalidRecord;
    };
    try validateScopes(value.scopes);
}
fn validateScopes(scopes: []const []const u8) !void {
    for (scopes, 0..) |scope, i| {
        try requireId(scope);
        if (contains(scopes[0..i], scope)) return error.InvalidRecord;
    }
}
fn sameGrantAuthority(a: Grant, b: Grant) bool {
    if (a.credential_kind != b.credential_kind or !eql(a.audience, b.audience) or a.scopes.len != b.scopes.len or a.purposes.len != b.purposes.len) return false;
    for (a.scopes) |scope| if (!contains(b.scopes, scope)) return false;
    for (a.purposes) |purpose| if (!hasPurpose(b, purpose)) return false;
    return true;
}
fn sameNativeRef(a: ?native_owner.NativeRef, b: ?native_owner.NativeRef) bool {
    if (a) |left| return if (b) |right| left.same(right) else false;
    return b == null;
}
fn widestNativeRef(ref: native_owner.NativeRef) native_owner.NativeRef {
    var result = ref;
    result.adapter_epoch = std.math.maxInt(u64);
    result.endpoint_generation = std.math.maxInt(u64);
    result.thread_instance_generation = std.math.maxInt(u64);
    result.attachment_generation = std.math.maxInt(u64);
    return result;
}
fn validateLeaseAuthority(value: Lease, g: Grant) !void {
    try validateScopes(value.scopes);
    if (!std.math.isFinite(value.required) or value.required < 0) return error.InvalidRecord;
    if ((g.credential_kind == .browser_bound and !value.browser_context) or g.credential_kind == .oauth_refresh or !hasPurpose(g, value.purpose) or (value.audience.len > 0 and !eql(value.audience, g.audience))) return error.GrantNotReady;
    for (value.scopes) |scope| if (!contains(g.scopes, scope)) return error.GrantNotReady;
    if (value.resource) |resource| try validateResource(resource);
}
fn validateObservation(value: Observation) !void {
    try validate(value);
    try requireId(value.account_id);
    try validateResource(value.resource);
    if (!std.math.isFinite(value.remaining) or value.remaining < 0 or value.window_end <= value.window_start or value.expires_at <= value.observed_at) return error.InvalidRecord;
    if (value.limit) |limit| if (!std.math.isFinite(limit) or limit < value.remaining) return error.InvalidRecord;
}
fn validateResource(value: Resource) !void {
    try validate(value);
    try requireId(value.kind);
    if (value.unit == .custom and value.unit_name.len == 0) return error.InvalidRecord;
    if (value.unit != .custom and value.unit_name.len > 0) return error.InvalidRecord;
}
fn validate(value: anytype) !void {
    const T = @TypeOf(value);
    if (T == native_owner.NativeRef) return value.validate();
    switch (@typeInfo(T)) {
        .pointer => |info| {
            if (info.size != .slice) @compileError("domain records may contain only slices");
            if (info.child == u8) {
                if (value.len > max_text_bytes or !std.unicode.utf8ValidateSlice(value) or std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidRecord;
            } else {
                if (value.len > max_list_items) return error.TooManyRecords;
                for (value) |child| try validate(child);
            }
        },
        .@"struct" => |info| inline for (info.field_names) |field| {
            try validate(@field(value, field));
        },
        .optional => if (value) |child| {
            try validate(child);
        },
        .@"enum", .int, .float, .bool => {},
        else => @compileError("unsupported domain field type"),
    }
}
fn deepClone(comptime T: type, allocator: std.mem.Allocator, value: T) std.mem.Allocator.Error!T {
    if (T == native_owner.NativeRef) return value;
    switch (@typeInfo(T)) {
        .pointer => |info| {
            const owned = try allocator.alloc(info.child, value.len);
            var initialized: usize = 0;
            errdefer {
                for (owned[0..initialized]) |child| deepFree(info.child, allocator, child);
                allocator.free(owned);
            }
            for (value, 0..) |child, i| {
                owned[i] = try deepClone(info.child, allocator, child);
                initialized += 1;
            }
            return owned;
        },
        .@"struct" => |info| {
            var result: T = undefined;
            inline for (info.field_names, info.field_types, 0..) |name, FieldType, i| {
                @field(result, name) = deepClone(FieldType, allocator, @field(value, name)) catch |err| {
                    inline for (info.field_names[0..i], info.field_types[0..i]) |previous, PreviousType| deepFree(PreviousType, allocator, @field(result, previous));
                    return err;
                };
            }
            return result;
        },
        .optional => |info| return if (value) |child| try deepClone(info.child, allocator, child) else null,
        else => return value,
    }
}
fn deepFree(comptime T: type, allocator: std.mem.Allocator, value: T) void {
    switch (@typeInfo(T)) {
        .pointer => |info| {
            for (value) |child| deepFree(info.child, allocator, child);
            allocator.free(value);
        },
        .@"struct" => |info| inline for (info.field_names, info.field_types) |name, FieldType| {
            deepFree(FieldType, allocator, @field(value, name));
        },
        .optional => |info| if (value) |child| {
            deepFree(info.child, allocator, child);
        },
        else => {},
    }
}

fn fixtureIdentity(subject: []const u8) Identity {
    return .{ .provider = "example", .issuer = "https://issuer.example", .subject = subject, .verified = true };
}

test "R-N13 native route generations isolate owners sharing a native thread" {
    var state = try fixtureState();
    defer state.deinit();
    const left: native_owner.NativeRef = .{ .owner_id = @splat(1), .adapter_epoch = 1, .endpoint_generation = 1, .thread_instance_generation = 1, .attachment_generation = 1 };
    var right = left;
    right.owner_id = @splat(2);
    const binding_left: Binding = .{ .id = "owner-left", .application = "codex", .session_id = "same-native-thread", .native_ref = left, .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1 };
    var binding_right = binding_left;
    binding_right.id = "owner-right";
    binding_right.native_ref = right;
    _ = try state.bind(binding_left);
    _ = try state.bind(binding_right);
    var rewritten = binding_left;
    rewritten.native_ref = right;
    try std.testing.expectError(error.GenerationConflict, state.bind(rewritten));
    rewritten.native_ref = null;
    try std.testing.expectError(error.GenerationConflict, state.bind(rewritten));
    const lease: Lease = .{ .id = "native-work", .binding_id = binding_left.id, .native_ref = left, .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1, .route_generation = 1, .started_at = 10, .expires_at = 20 };
    var foreign = lease;
    foreign.native_ref = right;
    try std.testing.expectError(error.GenerationConflict, state.beginLease(foreign, 10));
    _ = try state.beginLease(lease, 10);
    try std.testing.expectError(error.NativeOwnerRequired, state.releaseBinding(binding_left.id));
    try std.testing.expectError(error.GenerationConflict, state.releaseBindingExact(binding_left.id, right));
    try std.testing.expectError(error.InFlight, state.releaseBindingExact(binding_left.id, left));
    try state.completeLease(lease.id);
    try state.releaseBindingExact(binding_left.id, left);
    try std.testing.expect(state.binding(binding_left.id) == null);
    try std.testing.expect(state.binding(binding_right.id).?.native_ref.?.same(right));
}

test "R-N13 restoration retains original native references and rejects foreign lease generations" {
    var state = try fixtureState();
    defer state.deinit();
    const ref: native_owner.NativeRef = .{ .owner_id = @splat(3), .adapter_epoch = 1, .endpoint_generation = 2, .thread_instance_generation = 3, .attachment_generation = 4 };
    _ = try state.bind(.{ .id = "native-binding", .application = "codex", .session_id = "native-thread", .native_ref = ref, .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1 });
    _ = try state.beginLease(.{ .id = "native-lease", .binding_id = "native-binding", .native_ref = ref, .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1, .route_generation = 1, .started_at = 10, .expires_at = 20 }, 10);
    var restored = try State.fromSnapshot(std.testing.allocator, state.snapshot());
    defer restored.deinit();
    try std.testing.expect(restored.binding("native-binding").?.native_ref.?.same(ref));
    var leases = [_]Lease{state.leases.items[0]};
    leases[0].native_ref.?.attachment_generation += 1;
    var corrupt = state.snapshot();
    corrupt.leases = &leases;
    try std.testing.expectError(error.InvalidRecord, State.fromSnapshot(std.testing.allocator, corrupt));
    leases[0].native_ref = null;
    try std.testing.expectError(error.InvalidRecord, State.fromSnapshot(std.testing.allocator, corrupt));
    try std.testing.expectEqual(@as(u32, 1), state.binding("native-binding").?.in_flight);
}

test "R-N13 native acquisition growth includes complete immutable references at widest generations" {
    const ref: native_owner.NativeRef = .{ .owner_id = @splat(255), .adapter_epoch = std.math.maxInt(u64), .endpoint_generation = std.math.maxInt(u64), .thread_instance_generation = std.math.maxInt(u64), .attachment_generation = std.math.maxInt(u64) };
    const binding: Binding = .{ .id = "native-binding", .application = "codex", .session_id = "native-thread", .native_ref = ref, .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1 };
    const lease: Lease = .{ .id = "native-lease", .binding_id = binding.id, .native_ref = ref, .account_id = binding.account_id, .grant_id = binding.grant_id, .grant_generation = 1, .route_generation = 1, .audience = "https://api.example", .started_at = 10, .expires_at = 20 };
    const planned = try acquisitionGrowth(binding, lease);
    try std.testing.expect(planned.bytes >= (try recordGrowth(binding)) + (try recordGrowth(lease)));
    var legacy_binding = binding;
    legacy_binding.native_ref = null;
    var legacy_lease = lease;
    legacy_lease.native_ref = null;
    const legacy = try acquisitionGrowth(legacy_binding, legacy_lease);
    try std.testing.expect(planned.bytes > legacy.bytes);
    try std.testing.expectError(error.GenerationConflict, acquisitionGrowth(binding, legacy_lease));
}
fn fixtureState() !State {
    var state = State.init(std.testing.allocator);
    errdefer state.deinit();
    _ = try state.connectSource(.{ .id = "source", .kind = .oauth });
    _ = try state.enroll(.{ .account_id = "account-a", .source_id = "source", .identity = fixtureIdentity("alice") }, 0);
    _ = try state.enroll(.{ .account_id = "account-b", .source_id = "source", .identity = fixtureIdentity("bob") }, 0);
    _ = try state.addGrant(.{ .id = "grant-a", .account_id = "account-a", .source_id = "source", .credential_kind = .oauth_access, .ownership = .omux, .audience = "https://api.example", .purposes = &.{.request} });
    _ = try state.addGrant(.{ .id = "grant-b", .account_id = "account-b", .source_id = "source", .credential_kind = .oauth_access, .ownership = .omux, .audience = "https://api.example", .purposes = &.{.request} });
    return state;
}
fn fixtureDemand() Demand {
    return .{ .provider = "example", .audience = "https://api.example", .resource = .{ .kind = "requests" }, .now = 10 };
}
fn fixtureObservation(account_id: []const u8, bucket: []const u8, remaining: f64) Observation {
    return .{ .account_id = account_id, .resource = .{ .kind = "requests" }, .bucket_id = bucket, .remaining = remaining, .limit = 100, .window_start = 0, .window_end = 100, .observed_at = 1, .expires_at = 50, .provenance = .fixture };
}

test "R-N13 isolated candidate preserves associations and refuses forget without live changes" {
    var state = try fixtureState();
    defer state.deinit();
    _ = try state.connectSource(.{ .id = "second-source", .kind = .explicit });
    _ = try state.enroll(.{ .account_id = "alternate", .source_id = "second-source", .identity = fixtureIdentity("alice") }, 0);
    _ = try state.bind(.{ .id = "native-binding", .application = "native", .session_id = "thread", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1 });
    _ = try state.beginLease(.{ .id = "held-lease", .binding_id = "native-binding", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1, .route_generation = 1, .started_at = 1, .expires_at = 100 }, 1);
    const before = try std.json.Stringify.valueAlloc(std.testing.allocator, state.snapshot(), .{});
    defer std.testing.allocator.free(before);
    var candidate = try state.clone(std.testing.allocator);
    defer candidate.deinit();
    try std.testing.expectError(error.InFlight, candidate.forget("account-a"));
    try candidate.completeLease("held-lease");
    try candidate.forget("account-a");
    try std.testing.expectEqual(@as(usize, 2), candidate.tombstones.items.len);
    try std.testing.expect(candidate.grant("grant-a") == null);
    const after = try std.json.Stringify.valueAlloc(std.testing.allocator, state.snapshot(), .{});
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualStrings(before, after);
    try std.testing.expectEqual(@as(usize, 1), state.leases.items.len);
    try std.testing.expectEqual(@as(u32, 1), state.binding("native-binding").?.in_flight);
}

fn exerciseCandidateAllocationFailures(allocator: std.mem.Allocator) !void {
    var live = try fixtureState();
    defer live.deinit();
    const before = live.revision;
    var candidate = live.clone(allocator) catch |err| {
        try std.testing.expectEqual(before, live.revision);
        try std.testing.expectEqual(@as(usize, 2), live.accounts.items.len);
        try std.testing.expectEqualStrings("alice", live.account("account-a").?.identity.subject);
        return err;
    };
    defer candidate.deinit();
    try std.testing.expectEqual(before, candidate.revision);
    try std.testing.expectEqual(@as(usize, 2), candidate.grants.items.len);
}

test "R-N13 candidate allocation failures free copies and preserve live metadata" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseCandidateAllocationFailures, .{});
}

test "R-N13 multi-source forget sizes every actual escaped identity tombstone" {
    var state = State.init(std.testing.allocator);
    defer state.deinit();
    const escaped: [max_text_bytes]u8 = @splat(1);
    const identity: Identity = .{ .provider = "example", .issuer = "https://issuer.example", .subject = &escaped, .tenant = &escaped, .verified = true };
    var source_buffers: [max_list_items][32]u8 = undefined;
    for (&source_buffers, 0..) |*buffer, index| {
        const source_id = try std.fmt.bufPrint(buffer, "source-{d}", .{index});
        _ = try state.connectSource(.{ .id = source_id, .kind = .explicit });
        _ = try state.enroll(.{ .account_id = "account", .source_id = source_id, .identity = identity }, 0);
    }
    const plan = try state.forgetGrowth("account");
    try std.testing.expectEqual(@as(usize, max_list_items), plan.tombstones);
    const before = try snapshot_admission.countJson(state.snapshot(), snapshot_admission.maximum_snapshot_bytes);
    var candidate = try state.clone(std.testing.allocator);
    defer candidate.deinit();
    try candidate.forget("account");
    const after = try snapshot_admission.countJson(candidate.snapshot(), snapshot_admission.maximum_snapshot_bytes);
    try std.testing.expect(after > before);
    try std.testing.expect(plan.bytes >= after - before);
    try std.testing.expectEqual(@as(usize, 0), state.tombstones.items.len);
    try std.testing.expectEqual(@as(usize, 1), state.accounts.items.len);
}

test "R-N13 import plans retain parser maxima escaped input and all Codex quota entries" {
    const escaped: [max_text_bytes]u8 = @splat(1);
    const plain: [max_text_bytes]u8 = @splat('a');
    const github = try importGrowth("github", "source", &escaped);
    const codex = try importGrowth("codex", "source", &escaped);
    const unescaped = try importGrowth("codex", "source", &plain);
    try std.testing.expectEqual(@as(usize, 0), github.observations);
    try std.testing.expectEqual(@as(usize, 100), codex.observations);
    try std.testing.expectEqual(@as(usize, 1), codex.accounts);
    try std.testing.expectEqual(@as(usize, 1), codex.grants);
    try std.testing.expectEqual(@as(usize, 1), codex.source_links);
    try std.testing.expectEqual(@as(usize, max_text_bytes * 5), codex.bytes - unescaped.bytes);
    try std.testing.expect(codex.bytes > github.bytes);
    const observations = try observationGrowth("codex", &escaped);
    try std.testing.expect(codex.bytes > observations.bytes);
    try std.testing.expectEqual(@as(usize, 100), observations.counts().observations);
    try std.testing.expectError(error.MissingOutcomeBound, importGrowth("unknown-provider", "source", "label"));
    try std.testing.expectError(error.MissingOutcomeBound, observationGrowth("unknown-provider", "account"));
}

test "R-N13 acquire and rejection growth preserve complete escaped demands" {
    var state = try fixtureState();
    defer state.deinit();
    const escaped: [max_text_bytes]u8 = @splat(1);
    const resource: Resource = .{ .kind = "requests", .target = &escaped, .scope = &escaped };
    const binding: Binding = .{ .id = "binding", .application = "native", .session_id = &escaped, .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1 };
    const lease: Lease = .{ .id = "lease", .binding_id = "binding", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1, .route_generation = 1, .audience = "https://api.example", .resource = resource, .started_at = 1, .expires_at = 100 };
    const plan = try acquisitionGrowth(binding, lease);
    const report = try reportGrowth(lease);
    const before = try snapshot_admission.countJson(state.snapshot(), snapshot_admission.maximum_snapshot_bytes);
    _ = try state.bind(binding);
    _ = try state.beginLease(lease, 1);
    const after = try snapshot_admission.countJson(state.snapshot(), snapshot_admission.maximum_snapshot_bytes);
    try std.testing.expect(plan.bytes >= after - before);
    const prior_report = after;
    try state.observe(.{ .account_id = "account-a", .resource = resource, .bucket_id = "", .remaining = 0, .window_start = 10, .window_end = 310, .observed_at = 10, .expires_at = 310, .status = .unavailable, .provenance = .native_application });
    try state.completeLease("lease");
    const terminal = try snapshot_admission.countJson(state.snapshot(), snapshot_admission.maximum_snapshot_bytes);
    try std.testing.expect(report.bytes >= terminal -| prior_report);
    try std.testing.expectEqual(@as(usize, 1), report.observations);
    try std.testing.expectEqualStrings(&escaped, state.observations.items[0].resource.target);
    var unresolved = lease;
    unresolved.audience = "";
    try std.testing.expectError(error.MissingOutcomeBound, acquisitionGrowth(binding, unresolved));
}

test "R-N13 maintenance sizing covers retained field widening without record additions" {
    var state = try fixtureState();
    defer state.deinit();
    _ = try state.putJob(.{ .id = "job", .kind = .repair, .account_id = "account-a" });
    const plan = try maintenanceGrowth(state.snapshot());
    const before = try snapshot_admission.countJson(state.snapshot(), snapshot_admission.maximum_snapshot_bytes);
    for (state.grants.items) |*grant| {
        grant.generation = std.math.maxInt(u64);
        grant.status = .quarantined;
        grant.provider_expires_at = std.math.minInt(i64);
        grant.custody_expires_at = std.math.minInt(i64);
    }
    state.jobs.items[0].operation_generation = std.math.maxInt(u64);
    state.jobs.items[0].status = .completed;
    state.sources.items[0].status = .disconnected;
    for (state.accounts.items) |*account| account.lifecycle = .draining;
    state.revision = std.math.maxInt(u64);
    const after = try snapshot_admission.countJson(state.snapshot(), snapshot_admission.maximum_snapshot_bytes);
    try std.testing.expect(plan.bytes >= after - before);
    try std.testing.expectEqual(@as(usize, 0), plan.grants);
}

test "verified identities deduplicate across sources; unverified imports quarantine" {
    var state = try fixtureState();
    defer state.deinit();
    _ = try state.connectSource(.{ .id = "browser", .kind = .browser });
    const duplicate = try state.enroll(.{ .account_id = "new-id", .source_id = "browser", .identity = fixtureIdentity("alice") }, 10);
    try std.testing.expectEqual(.existing, duplicate.status);
    try std.testing.expectEqualStrings("account-a", duplicate.account_id.?);
    try std.testing.expectEqual(@as(usize, 2), state.accounts.items.len);
    try std.testing.expectEqual(@as(usize, 2), state.account("account-a").?.source_ids.len);
    var identity = fixtureIdentity("unknown");
    identity.verified = false;
    const uncertain = try state.enroll(.{ .account_id = "uncertain", .source_id = "browser", .identity = identity }, 10);
    try std.testing.expectEqual(.quarantined, uncertain.status);
    try std.testing.expectEqual(@as(usize, 1), state.quarantined_imports.items.len);
}

test "verified account type refresh preserves held native work and independent authority" {
    var state = try fixtureState();
    defer state.deinit();
    var external = state.grant("grant-a").?;
    external.ownership = .external;
    external.generation += 1;
    _ = try state.addGrant(external);
    const before_grant = state.grant("grant-a").?;
    const identity = state.account("account-a").?.identity;
    const native: native_owner.NativeRef = .{ .owner_id = @splat(1), .adapter_epoch = 1, .endpoint_generation = 1, .thread_instance_generation = 1, .attachment_generation = 1 };
    _ = try state.bind(.{ .id = "metadata-thread", .application = "codex", .session_id = "metadata-session", .native_ref = native, .account_id = "account-a", .grant_id = "grant-a", .grant_generation = external.generation });
    _ = try state.beginLease(.{ .id = "metadata-request", .binding_id = "metadata-thread", .native_ref = native, .account_id = "account-a", .grant_id = "grant-a", .grant_generation = external.generation, .route_generation = 1, .started_at = 1, .expires_at = 100 }, 1);
    const before_binding = state.binding("metadata-thread").?;
    const before_lease = state.leases.items[0];
    var demand = fixtureDemand();
    demand.allowed_account_ids = &.{"account-a"};
    demand.requires_capacity = true;
    try std.testing.expectError(error.NoEligibleAccount, state.select(demand, null));
    const revision = state.revision;
    const refreshed = try state.enroll(.{ .account_id = "another-handle", .source_id = "source", .identity = identity, .label = "incoming label", .account_type = "future_plan" }, 10);
    try std.testing.expectEqual(.existing, refreshed.status);
    try std.testing.expectEqualStrings("account-a", refreshed.account_id.?);
    try std.testing.expectEqual(revision + 1, state.revision);
    try std.testing.expectEqualStrings("future_plan", state.account("account-a").?.account_type);
    try std.testing.expectEqualStrings("", state.account("account-a").?.label);
    try std.testing.expectEqualDeep(identity, state.account("account-a").?.identity);
    try std.testing.expectEqualDeep(before_grant, state.grant("grant-a").?);
    try std.testing.expectEqualDeep(before_binding, state.binding("metadata-thread").?);
    try std.testing.expectEqualDeep(before_lease, state.leases.items[0]);
    try std.testing.expectEqual(@as(usize, 0), state.observations.items.len);
    try std.testing.expectError(error.NoEligibleAccount, state.select(demand, null));
    try std.testing.expectError(error.InFlight, state.forget("account-a"));
    try state.pause("account-a", true);
    _ = try state.enroll(.{ .account_id = "another-handle", .source_id = "source", .identity = identity, .account_type = "changed_plan" }, 10);
    try std.testing.expectEqual(AccountLifecycle.paused, state.account("account-a").?.lifecycle);
    const unchanged = state.revision;
    const borrowed = state.account("account-a").?;
    _ = try state.enroll(.{ .account_id = borrowed.id, .source_id = borrowed.source_ids[0], .identity = borrowed.identity, .account_type = borrowed.account_type }, 10);
    try std.testing.expectEqual(unchanged, state.revision);
    _ = try state.connectSource(.{ .id = "metadata-second-source", .kind = .explicit });
    _ = try state.enroll(.{ .account_id = "other-handle", .source_id = "metadata-second-source", .identity = identity }, 10);
    try std.testing.expectEqualStrings("changed_plan", state.account("account-a").?.account_type);
    try std.testing.expectEqual(@as(usize, 2), state.account("account-a").?.source_ids.len);
    var restored = try State.fromSnapshot(std.testing.allocator, state.snapshot());
    defer restored.deinit();
    try std.testing.expectEqualStrings("changed_plan", restored.account("account-a").?.account_type);
    try std.testing.expectEqual(AccountLifecycle.paused, restored.account("account-a").?.lifecycle);
    try std.testing.expectEqualDeep(before_grant, restored.grant("grant-a").?);
    try std.testing.expectEqualDeep(before_binding, restored.binding("metadata-thread").?);
    try std.testing.expectEqualDeep(before_lease, restored.leases.items[0]);
}

test "account type refresh cannot bypass source identity tenant or forget fences" {
    var state = try fixtureState();
    defer state.deinit();
    var uncertain = fixtureIdentity("alice");
    uncertain.verified = false;
    try std.testing.expectEqual(.quarantined, (try state.enroll(.{ .account_id = "account-a", .source_id = "source", .identity = uncertain, .account_type = "unverified_plan" }, 10)).status);
    var tenant = fixtureIdentity("alice");
    tenant.tenant = "fixture-tenant";
    try std.testing.expectEqual(.quarantined, (try state.enroll(.{ .account_id = "account-a", .source_id = "source", .identity = tenant, .account_type = "other_tenant_plan" }, 10)).status);
    try std.testing.expectEqualStrings("generic", state.account("account-a").?.account_type);
    try std.testing.expectEqual(.enrolled, (try state.enroll(.{ .account_id = "tenant-account", .source_id = "source", .identity = tenant, .account_type = "other_tenant_plan" }, 10)).status);
    try std.testing.expectEqualStrings("generic", state.account("account-a").?.account_type);
    try std.testing.expectEqualStrings("fixture-tenant", state.account("tenant-account").?.identity.tenant);
    try state.disconnectSource("source");
    try std.testing.expectError(error.SourceUnauthorized, state.enroll(.{ .account_id = "account-a", .source_id = "source", .identity = fixtureIdentity("alice"), .account_type = "disconnected_plan" }, 10));
    try std.testing.expectEqualStrings("generic", state.account("account-a").?.account_type);
    _ = try state.connectSource(.{ .id = "source", .kind = .oauth });
    try state.forget("account-a");
    try std.testing.expectEqual(.tombstoned, (try state.enroll(.{ .account_id = "new-handle", .source_id = "source", .identity = fixtureIdentity("alice"), .account_type = "forgotten_plan" }, 10)).status);
    try std.testing.expect(state.account("account-a") == null);
    try std.testing.expect(state.account("new-handle") == null);
    try std.testing.expectEqual(@as(usize, 1), state.tombstones.items.len);
}

fn exerciseAccountTypeRefreshAllocationFailures(allocator: std.mem.Allocator) !void {
    var state = State.init(allocator);
    defer state.deinit();
    _ = try state.connectSource(.{ .id = "first", .kind = .explicit });
    _ = try state.connectSource(.{ .id = "second", .kind = .explicit });
    _ = try state.enroll(.{ .account_id = "account", .source_id = "first", .identity = fixtureIdentity("metadata-fixture"), .account_type = "initial_plan" }, 0);
    const revision = state.revision;
    _ = state.enroll(.{ .account_id = "other-handle", .source_id = "second", .identity = state.account("account").?.identity, .account_type = "changed_plan" }, 10) catch |err| {
        try std.testing.expectEqual(revision, state.revision);
        try std.testing.expectEqualStrings("initial_plan", state.account("account").?.account_type);
        try std.testing.expectEqual(@as(usize, 1), state.account("account").?.source_ids.len);
        return err;
    };
    try std.testing.expectEqual(revision + 1, state.revision);
    try std.testing.expectEqualStrings("changed_plan", state.account("account").?.account_type);
    try std.testing.expectEqual(@as(usize, 2), state.account("account").?.source_ids.len);
}

test "account type and new source association publish atomically under allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseAccountTypeRefreshAllocationFailures, .{});
}

test "detach retains adopted grants; forget removes metadata and requires explicit reenrollment" {
    var state = try fixtureState();
    defer state.deinit();
    try state.detachSource("source");
    try std.testing.expectEqualStrings("grant-a", (try state.select(fixtureDemand(), null)).grant_id);
    try state.forget("account-a");
    try std.testing.expect(state.grant("grant-a") == null);
    _ = try state.connectSource(.{ .id = "source", .kind = .oauth });
    const enrollment: Enrollment = .{ .account_id = "again", .source_id = "source", .identity = fixtureIdentity("alice") };
    try std.testing.expectEqual(.tombstoned, (try state.enroll(enrollment, 10)).status);
    try state.permitReenrollment(enrollment.identity, "source", 10);
    try std.testing.expectEqual(.enrolled, (try state.enroll(enrollment, 10)).status);
}
test "route selections remain per binding and account data is never globally selected" {
    var state = try fixtureState();
    defer state.deinit();
    _ = try state.bind(.{ .id = "thread-a", .application = "native", .session_id = "session-a", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1 });
    _ = try state.bind(.{ .id = "thread-b", .application = "native", .session_id = "session-b", .account_id = "account-b", .grant_id = "grant-b", .grant_generation = 1 });
    try std.testing.expectEqualStrings("account-a", (try state.select(fixtureDemand(), "thread-a")).account_id);
    try std.testing.expectEqualStrings("account-b", (try state.select(fixtureDemand(), "thread-b")).account_id);
    try state.pause("account-a", true);
    const alternate = try state.select(fixtureDemand(), "thread-a");
    try std.testing.expectEqualStrings("account-b", alternate.account_id);
    try std.testing.expect(!alternate.sticky);
    try std.testing.expectEqualStrings("account-a", state.binding("thread-a").?.account_id);
}
test "capacity readiness rejects stale unknown and wrong scope; shared bucket aggregates once" {
    var state = try fixtureState();
    defer state.deinit();
    var demand = fixtureDemand();
    demand.requires_capacity = true;
    try std.testing.expectError(error.NoEligibleAccount, state.select(demand, null));
    try state.observe(fixtureObservation("account-a", "shared", 20));
    try state.observe(fixtureObservation("account-b", "shared", 15));
    try std.testing.expectEqualStrings("account-a", (try state.select(demand, null)).account_id);
    const total = state.aggregate("example", "https://issuer.example", demand.resource, 0, 100, 10);
    try std.testing.expectEqual(@as(f64, 15), total.remaining);
    try std.testing.expectEqual(@as(usize, 1), total.buckets);
    demand.resource.scope = "different";
    try std.testing.expectError(error.NoEligibleAccount, state.select(demand, null));
    demand.resource.scope = "";
    demand.now = 50;
    try std.testing.expectError(error.NoEligibleAccount, state.select(demand, null));
}
test "account reading grants and browser-bound sessions cannot authorize terminal requests" {
    var state = try fixtureState();
    defer state.deinit();
    try state.pause("account-b", true);
    try state.reconcile(.{ .grant_id = "grant-a", .expected_generation = 1, .next_generation = 2, .status = .invalid });
    var g = state.grant("grant-a").?;
    g.id = "account-read";
    g.generation = 1;
    g.status = .ready;
    g.purposes = &.{.account_read};
    _ = try state.addGrant(g);
    try std.testing.expectError(error.NoEligibleAccount, state.select(fixtureDemand(), null));
    g = state.grant("account-read").?;
    g.id = "browser-bound";
    g.purposes = &.{.request};
    g.credential_kind = .browser_bound;
    _ = try state.addGrant(g);
    try std.testing.expectError(error.NoEligibleAccount, state.select(fixtureDemand(), null));
}
test "draining prevents new leases while existing leases complete; route generations gate switch" {
    var state = try fixtureState();
    defer state.deinit();
    _ = try state.bind(.{ .id = "thread", .application = "native", .session_id = "session", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1 });
    const lease: Lease = .{ .id = "request", .binding_id = "thread", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1, .route_generation = 1, .started_at = 10, .expires_at = 20 };
    _ = try state.beginLease(lease, 10);
    try state.drain("account-a");
    try std.testing.expectError(error.InFlight, state.forget("account-a"));
    var second = lease;
    second.id = "second";
    try std.testing.expectError(error.GrantNotReady, state.beginLease(second, 10));
    const route: Binding = .{ .id = "thread", .application = "native", .session_id = "session", .account_id = "account-b", .grant_id = "grant-b", .grant_generation = 1, .route_generation = 2 };
    try std.testing.expectError(error.InFlight, state.bind(route));
    try state.completeLease("request");
    _ = try state.bind(route);
    try std.testing.expectEqualStrings("account-b", state.binding("thread").?.account_id);
}
test "external refresh ownership never silently transfers; reconciliation detects stale generation" {
    var state = try fixtureState();
    defer state.deinit();
    var g = state.grant("grant-a").?;
    g.generation = 2;
    g.ownership = .external;
    _ = try state.addGrant(g);
    try std.testing.expectError(error.OwnershipRequired, state.reconcile(.{ .grant_id = "grant-a", .expected_generation = 2, .next_generation = 3, .status = .refreshing }));
    try std.testing.expectError(error.GenerationConflict, state.reconcile(.{ .grant_id = "grant-a", .expected_generation = 1, .next_generation = 3, .status = .quarantined }));
    try state.reconcile(.{ .grant_id = "grant-a", .expected_generation = 2, .next_generation = 3, .status = .quarantined });
    try std.testing.expectEqual(.quarantined, state.grant("grant-a").?.status);
}
test "snapshot is JSON serializable and validates foreign keys and schema" {
    var state = try fixtureState();
    defer state.deinit();
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, state.snapshot(), .{});
    defer std.testing.allocator.free(encoded);
    const parsed = try std.json.parseFromSlice(Snapshot, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    var imported = try State.fromSnapshot(std.testing.allocator, parsed.value);
    defer imported.deinit();
    try std.testing.expectEqualStrings("grant-a", (try imported.select(fixtureDemand(), null)).grant_id);
    var bad = parsed.value;
    bad.schema_version = 999;
    try std.testing.expectError(error.UnsupportedSchema, State.fromSnapshot(std.testing.allocator, bad));
    const orphan = [_]Grant{.{ .id = "orphan", .account_id = "absent", .source_id = "source", .credential_kind = .api_key, .audience = "api", .purposes = &.{.request} }};
    bad = parsed.value;
    bad.grants = &orphan;
    try std.testing.expectError(error.NotFound, State.fromSnapshot(std.testing.allocator, bad));
}
test "jobs are idempotent and cannot change intent under reused operation IDs" {
    var state = try fixtureState();
    defer state.deinit();
    _ = try state.putJob(.{ .id = "job", .kind = .repair, .account_id = "account-a", .status = .completed });
    try std.testing.expectEqual(.completed, (try state.putJob(.{ .id = "job", .kind = .repair, .account_id = "account-a" })).status);
    try std.testing.expectError(error.DuplicateId, state.putJob(.{ .id = "job", .kind = .revocation, .account_id = "account-a" }));
}

test "bucket IDs are namespaced by issuer and stale totals remain explicitly incomplete" {
    var state = try fixtureState();
    defer state.deinit();
    try state.observe(fixtureObservation("account-a", "same-name", 20));
    try state.observe(fixtureObservation("account-b", "same-name", 20));
    var different_issuer = fixtureIdentity("charlie");
    different_issuer.issuer = "https://other-issuer.example";
    _ = try state.enroll(.{ .account_id = "account-c", .source_id = "source", .identity = different_issuer }, 0);
    try state.observe(fixtureObservation("account-c", "same-name", 30));
    const total = state.aggregate("example", "https://issuer.example", .{ .kind = "requests" }, 0, 100, 10);
    try std.testing.expectEqual(@as(f64, 20), total.remaining);
    try std.testing.expect(total.complete);
    const stale = state.aggregate("example", "https://issuer.example", .{ .kind = "requests" }, 0, 100, 50);
    try std.testing.expect(!stale.complete);
    var demand = fixtureDemand();
    demand.issuer = "https://other-issuer.example";
    try std.testing.expectError(error.NoEligibleAccount, state.select(demand, null));
}
test "snapshot preserves draining in-flight requests and rejects forged counters" {
    var state = try fixtureState();
    defer state.deinit();
    _ = try state.bind(.{ .id = "thread", .application = "native", .session_id = "session", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1 });
    _ = try state.beginLease(.{ .id = "request", .binding_id = "thread", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1, .route_generation = 1, .started_at = 10, .expires_at = 20 }, 10);
    try state.drain("account-a");
    var imported = try State.fromSnapshot(std.testing.allocator, state.snapshot());
    defer imported.deinit();
    try std.testing.expectEqual(@as(u32, 1), imported.binding("thread").?.in_flight);
    try imported.completeLease("request");
    try imported.forget("account-a");
    var invalid = state.snapshot();
    invalid.leases = &.{};
    try std.testing.expectError(error.InvalidRecord, State.fromSnapshot(std.testing.allocator, invalid));
}
test "authorization expiry and scope prevent a new lease despite a ready credential" {
    var state = try fixtureState();
    defer state.deinit();
    _ = try state.bind(.{ .id = "thread", .application = "native", .session_id = "session", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1 });
    var lease: Lease = .{ .id = "request", .binding_id = "thread", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1, .route_generation = 1, .started_at = 10, .expires_at = 20, .scopes = &.{"ungranted"} };
    try std.testing.expectError(error.GrantNotReady, state.beginLease(lease, 10));
    lease.scopes = &.{};
    _ = try state.connectSource(.{ .id = "source", .kind = .oauth, .authorized_until = 15 });
    try std.testing.expectError(error.SourceUnauthorized, state.beginLease(lease, 10));
}

test "shared-bucket exhaustion prevents all aliases from routing and capacity separates units" {
    var state = try fixtureState();
    defer state.deinit();
    try state.observe(fixtureObservation("account-a", "shared", 20));
    try state.observe(fixtureObservation("account-b", "shared", 0));
    var demand = fixtureDemand();
    demand.requires_capacity = true;
    try std.testing.expectError(error.NoEligibleAccount, state.select(demand, null));
    var bytes = fixtureObservation("account-a", "bytes", 50);
    bytes.resource.unit = .bytes;
    try state.observe(bytes);
    const calls = state.aggregate("example", "https://issuer.example", demand.resource, 0, 100, 10);
    try std.testing.expectEqual(@as(f64, 0), calls.remaining);
    const byte_total = state.aggregate("example", "https://issuer.example", bytes.resource, 0, 100, 10);
    try std.testing.expectEqual(@as(f64, 50), byte_total.remaining);
}
test "grant rotation retains outstanding lease generation across durable snapshots" {
    var state = try fixtureState();
    defer state.deinit();
    _ = try state.bind(.{ .id = "thread", .application = "native", .session_id = "session", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1 });
    _ = try state.beginLease(.{ .id = "request", .binding_id = "thread", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1, .route_generation = 1, .started_at = 10, .expires_at = 20 }, 10);
    var g = state.grant("grant-a").?;
    g.generation = 2;
    _ = try state.addGrant(g);
    var imported = try State.fromSnapshot(std.testing.allocator, state.snapshot());
    defer imported.deinit();
    try std.testing.expectEqual(@as(u64, 1), imported.leases.items[0].grant_generation);
    try std.testing.expectEqual(@as(u64, 2), imported.grant("grant-a").?.generation);
    try imported.completeLease("request");
}

fn exerciseAllocationFailures(allocator: std.mem.Allocator) !void {
    var state = State.init(allocator);
    defer state.deinit();
    _ = try state.connectSource(.{ .id = "source", .kind = .oauth });
    _ = try state.enroll(.{ .account_id = "account", .source_id = "source", .identity = fixtureIdentity("alice") }, 0);
    _ = try state.addGrant(.{ .id = "grant", .account_id = "account", .source_id = "source", .credential_kind = .oauth_access, .audience = "api", .purposes = &.{.request} });
    _ = try state.bind(.{ .id = "thread", .application = "native", .session_id = "session", .account_id = "account", .grant_id = "grant", .grant_generation = 1 });
    _ = try state.beginLease(.{ .id = "request", .binding_id = "thread", .account_id = "account", .grant_id = "grant", .grant_generation = 1, .route_generation = 1, .started_at = 1, .expires_at = 10 }, 1);
    try state.drain("account");
    var imported = try State.fromSnapshot(allocator, state.snapshot());
    defer imported.deinit();
    try state.completeLease("request");
    try state.forget("account");
}
test "owned metadata and atomic forget release every allocation on failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseAllocationFailures, .{});
}

test "fresh rejection suppresses one exact resource even without capacity prerequisites" {
    var state = try fixtureState();
    defer state.deinit();
    try state.pause("account-b", true);
    var rejection = fixtureObservation("account-a", "", 0);
    rejection.resource.target = "model-a";
    rejection.status = .unavailable;
    rejection.provenance = .native_application;
    try state.observe(rejection);
    var demand = fixtureDemand();
    demand.resource.target = "model-a";
    try std.testing.expectError(error.NoEligibleAccount, state.select(demand, null));
    demand.resource.target = "model-b";
    try std.testing.expectEqualStrings("account-a", (try state.select(demand, null)).account_id);
    demand.resource.target = "model-a";
    demand.now = 50;
    try std.testing.expectEqualStrings("account-a", (try state.select(demand, null)).account_id);
}
test "forget and reenrollment permit accept borrowed model slices safely" {
    var state = try fixtureState();
    defer state.deinit();
    try state.observe(fixtureObservation("account-a", "bucket", 20));
    try state.forget(state.grant("grant-a").?.account_id);
    const tombstone = state.tombstones.items[0];
    try state.permitReenrollment(tombstone.identity, tombstone.source_id, 10);
    try std.testing.expectEqual(@as(usize, 0), state.tombstones.items.len);
    try std.testing.expectEqual(@as(usize, 0), state.observations.items.len);
    try std.testing.expectEqualStrings("account-b", state.accounts.items[0].id);
}
test "partial capacity observations are never a complete total" {
    var state = try fixtureState();
    defer state.deinit();
    try state.observe(fixtureObservation("account-a", "bucket", 20));
    const aggregate = state.aggregate("example", "https://issuer.example", .{ .kind = "requests" }, 0, 100, 10);
    try std.testing.expectEqual(@as(f64, 20), aggregate.remaining);
    try std.testing.expect(!aggregate.complete);
    try std.testing.expectEqual(@as(usize, 1), aggregate.unknown_buckets);
}
test "future shared quota windows remain incomplete until the capacity and selection boundary" {
    var state = try fixtureState();
    defer state.deinit();
    for ([_]struct { account_id: []const u8, remaining: f64 }{ .{ .account_id = "account-a", .remaining = 20 }, .{ .account_id = "account-b", .remaining = 10 } }) |row| {
        var observation = fixtureObservation(row.account_id, "shared-bucket", row.remaining);
        observation.window_start = 20;
        try state.observe(observation);
    }
    var demand = fixtureDemand();
    demand.requires_capacity = true;
    demand.required = 5;
    for ([_]i64{ 10, 19, 20 }) |now| {
        demand.now = now;
        const capacity = state.aggregate("example", "https://issuer.example", demand.resource, 20, 100, now);
        // This is the same redacted capacity value the public snapshot/usage
        // route serializes. Future windows cannot advertise complete totals.
        const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, capacity, .{});
        defer std.testing.allocator.free(encoded);
        const parsed = try std.json.parseFromSlice(Aggregation, std.testing.allocator, encoded, .{});
        defer parsed.deinit();
        if (now < 20) {
            try std.testing.expectError(error.NoEligibleAccount, state.select(demand, null));
            try std.testing.expect(!parsed.value.complete);
            try std.testing.expectEqual(@as(f64, 0), parsed.value.remaining);
            try std.testing.expectEqual(@as(usize, 0), parsed.value.buckets);
            try std.testing.expect(parsed.value.unknown_buckets > 0);
        } else {
            try std.testing.expectEqualStrings("account-a", (try state.select(demand, null)).account_id);
            try std.testing.expect(parsed.value.complete);
            try std.testing.expectEqual(@as(f64, 10), parsed.value.remaining);
            try std.testing.expectEqual(@as(usize, 1), parsed.value.buckets);
            try std.testing.expectEqual(@as(usize, 0), parsed.value.unknown_buckets);
        }
    }
}
test "snapshot rejects incompatible lease authorization and authority changes need a new grant" {
    var state = try fixtureState();
    defer state.deinit();
    _ = try state.bind(.{ .id = "thread", .application = "native", .session_id = "session", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1 });
    _ = try state.beginLease(.{ .id = "request", .binding_id = "thread", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1, .route_generation = 1, .started_at = 10, .expires_at = 20 }, 10);
    var forged = [_]Lease{state.leases.items[0]};
    forged[0].audience = "https://wrong.example";
    var snapshot = state.snapshot();
    snapshot.leases = &forged;
    try std.testing.expectError(error.GrantNotReady, State.fromSnapshot(std.testing.allocator, snapshot));
    var g = state.grant("grant-a").?;
    g.generation = 2;
    g.audience = "https://wrong.example";
    try std.testing.expectError(error.InvalidRecord, state.addGrant(g));
}
test "provider-scoped sources retain their boundary across reconnects" {
    var state = State.init(std.testing.allocator);
    defer state.deinit();
    _ = try state.connectSource(.{ .id = "source", .kind = .oauth, .provider = "example", .label = "Research" });
    _ = try state.connectSource(.{ .id = "source", .kind = .oauth });
    try std.testing.expectEqualStrings("example", state.sources.items[0].provider);
    var identity = fixtureIdentity("alice");
    identity.provider = "other";
    try std.testing.expectError(error.SourceUnauthorized, state.enroll(.{ .account_id = "account", .source_id = "source", .identity = identity }, 0));
}

test "direct lease issuance rechecks resource readiness and requires explicit browser context" {
    var state = try fixtureState();
    defer state.deinit();
    _ = try state.bind(.{ .id = "thread", .application = "native", .session_id = "session", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1 });
    var unavailable = fixtureObservation("account-a", "", 0);
    unavailable.status = .unavailable;
    try state.observe(unavailable);
    const lease: Lease = .{ .id = "request", .binding_id = "thread", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1, .route_generation = 1, .resource = .{ .kind = "requests" }, .started_at = 10, .expires_at = 20 };
    try std.testing.expectError(error.GrantNotReady, state.beginLease(lease, 10));
    _ = try state.addGrant(.{ .id = "browser", .account_id = "account-a", .source_id = "source", .credential_kind = .browser_bound, .purposes = &.{.account_read}, .audience = "browser-account" });
    _ = try state.bind(.{ .id = "browser-thread", .application = "reader", .session_id = "browser-session", .account_id = "account-a", .grant_id = "browser", .grant_generation = 1 });
    const browser_lease: Lease = .{ .id = "browser-request", .binding_id = "browser-thread", .account_id = "account-a", .grant_id = "browser", .grant_generation = 1, .route_generation = 1, .purpose = .account_read, .started_at = 10, .expires_at = 20 };
    try std.testing.expectError(error.GrantNotReady, state.beginLease(browser_lease, 10));
}

test "newer unknown cannot erase a fresh resource rejection; proven recovery or expiry can" {
    var state = try fixtureState();
    defer state.deinit();
    try state.pause("account-b", true);
    var rejection = fixtureObservation("account-a", "", 0);
    rejection.status = .unavailable;
    rejection.provenance = .native_application;
    try state.observe(rejection);
    var unknown = rejection;
    unknown.status = .unknown;
    unknown.observed_at = 2;
    unknown.expires_at = 60;
    unknown.provenance = .provider_api;
    try state.observe(unknown);
    var demand = fixtureDemand();
    try std.testing.expectError(error.NoEligibleAccount, state.select(demand, null));
    // A distinct provider window also cannot replace existing cooldown evidence.
    unknown.window_end = 90;
    try state.observe(unknown);
    try std.testing.expectError(error.NoEligibleAccount, state.select(demand, null));
    var recovery = unknown;
    recovery.observed_at = 3;
    recovery.status = .ready;
    recovery.remaining = 10;
    recovery.provenance = .user_declared;
    recovery.window_end = 80;
    try state.observe(recovery);
    try std.testing.expectError(error.NoEligibleAccount, state.select(demand, null));
    recovery.observed_at = 4;
    recovery.provenance = .provider_api;
    try state.observe(recovery);
    try std.testing.expectEqualStrings("account-a", (try state.select(demand, null)).account_id);
    recovery.status = .unknown;
    recovery.observed_at = 5;
    try state.observe(recovery);
    try std.testing.expectEqualStrings("account-a", (try state.select(demand, null)).account_id);
    demand.now = 50;
    try std.testing.expectEqualStrings("account-a", (try state.select(demand, null)).account_id);
}

test "forgotten identity stays blocked across new sources until explicit authorized reenrollment" {
    var state = try fixtureState();
    defer state.deinit();
    _ = try state.connectSource(.{ .id = "second", .kind = .browser });
    _ = try state.enroll(.{ .account_id = "duplicate", .source_id = "second", .identity = fixtureIdentity("alice") }, 10);
    try state.forget("account-a");
    _ = try state.connectSource(.{ .id = "new", .kind = .oauth, .provider = "example" });
    const enrollment: Enrollment = .{ .account_id = "again", .source_id = "new", .identity = fixtureIdentity("alice") };
    try std.testing.expectEqual(.tombstoned, (try state.enroll(enrollment, 10)).status);
    // A distinct tenant is a different identity, even for the same subject.
    var tenant = fixtureIdentity("alice");
    tenant.tenant = "different-tenant";
    try std.testing.expectEqual(.enrolled, (try state.enroll(.{ .account_id = "tenant", .source_id = "new", .identity = tenant }, 10)).status);
    try state.detachSource("new");
    try std.testing.expectError(error.SourceUnauthorized, state.permitReenrollment(enrollment.identity, "new", 10));
    _ = try state.connectSource(.{ .id = "new", .kind = .oauth });
    const borrowed = state.tombstones.items[0].identity;
    try state.permitReenrollment(borrowed, "new", 10);
    try std.testing.expectEqual(@as(usize, 0), state.tombstones.items.len);
    try std.testing.expectEqual(.enrolled, (try state.enroll(enrollment, 10)).status);
}

test "future-window readiness cannot retire a current resource rejection before the window starts" {
    var state = try fixtureState();
    defer state.deinit();
    try state.pause("account-b", true);
    var rejection = fixtureObservation("account-a", "", 0);
    rejection.status = .unavailable;
    rejection.provenance = .native_application;
    try state.observe(rejection);
    var future = fixtureObservation("account-a", "future", 20);
    future.observed_at = 2;
    future.window_start = 20;
    future.provenance = .provider_api;
    try state.observe(future);
    var demand = fixtureDemand();
    try std.testing.expectError(error.NoEligibleAccount, state.select(demand, null));
    demand.now = 20;
    try std.testing.expectEqualStrings("account-a", (try state.select(demand, null)).account_id);
}
test "observation maintenance bounds history while retaining latest stale and unrelated scopes" {
    var state = try fixtureState();
    defer state.deinit();
    var old = fixtureObservation("account-a", "bucket", 20);
    old.window_end = 10;
    old.expires_at = 5;
    try state.observe(old);
    var latest = old;
    latest.window_start = 10;
    latest.window_end = 20;
    latest.observed_at = 2;
    latest.expires_at = 15;
    try state.observe(latest);
    var other = old;
    other.resource.target = "other";
    try state.observe(other);
    try std.testing.expectEqual(@as(usize, 0), state.pruneObservations(4));
    try std.testing.expectEqual(@as(usize, 1), state.pruneObservations(20));
    try std.testing.expectEqual(@as(usize, 2), state.observations.items.len);
    try std.testing.expectEqual(@as(usize, 0), state.pruneObservations(100));
    var seen_latest = false;
    for (state.observations.items) |observation| if (observation.observed_at == 2) {
        seen_latest = true;
    };
    try std.testing.expect(seen_latest);
}
test "explicit binding release preserves in-flight work and accepts a borrowed binding ID" {
    var state = try fixtureState();
    defer state.deinit();
    _ = try state.bind(.{ .id = "thread", .application = "native", .session_id = "session", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1 });
    _ = try state.beginLease(.{ .id = "request", .binding_id = "thread", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1, .route_generation = 1, .started_at = 10, .expires_at = 20 }, 10);
    try std.testing.expectError(error.InFlight, state.releaseBinding("thread"));
    try state.completeLease("request");
    try state.releaseBinding(state.binding("thread").?.id);
    try std.testing.expect(state.binding("thread") == null);
    try std.testing.expectError(error.NotFound, state.releaseBinding("thread"));
}

test "explicit reconciliation repeat advances its operation generation and keeps ordinary puts idempotent" {
    var state = try fixtureState();
    defer state.deinit();
    const start: Job = .{ .id = "source-reconcile", .kind = .reconciliation, .status = .running };
    _ = try state.putJob(start);
    var complete = start;
    complete.status = .completed;
    _ = try state.putJob(complete);
    try std.testing.expectEqual(.completed, (try state.putJob(start)).status);
    const reopened = try state.reopenJob(start);
    try std.testing.expectEqual(.running, reopened.status);
    try std.testing.expectEqual(@as(u64, 2), reopened.operation_generation);
    try std.testing.expectEqual(@as(u64, 2), (try state.reopenJob(start)).operation_generation);
    try std.testing.expectEqual(@as(usize, 1), state.jobs.items.len);
    try std.testing.expectError(error.GenerationConflict, state.putJob(complete));
    complete.operation_generation = 2;
    _ = try state.putJob(complete);
    try std.testing.expectEqual(.completed, (try state.putJob(start)).status);
    try std.testing.expectEqual(@as(u64, 3), (try state.reopenJob(.{ .id = start.id, .kind = .reconciliation })).operation_generation);
    try std.testing.expectError(error.DuplicateId, state.reopenJob(.{ .id = start.id, .kind = .repair }));
}
test "demand and lease scopes reject duplicates and empty names" {
    var state = try fixtureState();
    defer state.deinit();
    var demand = fixtureDemand();
    demand.scopes = &.{ "read", "read" };
    try std.testing.expectError(error.InvalidRecord, state.select(demand, null));
    demand.scopes = &.{""};
    try std.testing.expectError(error.InvalidRecord, state.select(demand, null));
    _ = try state.bind(.{ .id = "thread", .application = "native", .session_id = "session", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1 });
    const lease: Lease = .{ .id = "request", .binding_id = "thread", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1, .route_generation = 1, .scopes = &.{ "read", "read" }, .started_at = 10, .expires_at = 20 };
    try std.testing.expectError(error.InvalidRecord, state.beginLease(lease, 10));
}

test "provider observation batches publish together and invalid rows roll back" {
    var state = try fixtureState();
    defer state.deinit();
    try state.observe(fixtureObservation("account-a", "existing", 30));
    const before = state.revision;
    var invalid = fixtureObservation("missing-account", "bucket", 10);
    const bad = [_]Observation{ fixtureObservation("account-a", "bucket", 20), invalid };
    try std.testing.expectError(error.NotFound, state.observeBatch(&bad));
    try std.testing.expectEqual(before, state.revision);
    try std.testing.expectEqual(@as(usize, 1), state.observations.items.len);
    try std.testing.expectEqualStrings("existing", state.observations.items[0].bucket_id);
    invalid.account_id = "account-b";
    const good = [_]Observation{ fixtureObservation("account-a", "bucket", 20), invalid };
    try state.observeBatch(&good);
    try std.testing.expectEqual(before + 1, state.revision);
    try std.testing.expectEqual(@as(usize, 3), state.observations.items.len);
}
fn exerciseBatchAllocationFailures(allocator: std.mem.Allocator) !void {
    var state = State.init(allocator);
    defer state.deinit();
    _ = try state.connectSource(.{ .id = "source", .kind = .oauth });
    _ = try state.enroll(.{ .account_id = "account", .source_id = "source", .identity = fixtureIdentity("alice") }, 0);
    try state.observe(fixtureObservation("account", "existing", 30));
    const before = state.revision;
    const batch = [_]Observation{fixtureObservation("account", "second", 20)};
    state.observeBatch(&batch) catch |err| {
        try std.testing.expectEqual(before, state.revision);
        try std.testing.expectEqual(@as(usize, 1), state.observations.items.len);
        try std.testing.expectEqualStrings("existing", state.observations.items[0].bucket_id);
        return err;
    };
    try std.testing.expectEqual(@as(usize, 2), state.observations.items.len);
}
test "batch observation allocation failures leave published state intact" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseBatchAllocationFailures, .{});
}

test "Git binding recency updates independently of its route and survives JSON snapshots" {
    var state = try fixtureState();
    defer state.deinit();
    _ = try state.bind(.{ .id = "git-context", .application = "git", .session_id = "repository", .account_id = "account-a", .grant_id = "grant-a", .grant_generation = 1, .last_used_revision = 42 });
    _ = try state.bind(.{ .id = "native-thread", .application = "native", .session_id = "session", .account_id = "account-b", .grant_id = "grant-b", .grant_generation = 1 });
    var touched = state.binding("git-context").?;
    touched.last_used_revision = 43;
    _ = try state.bind(touched);
    try std.testing.expectEqual(@as(u64, 1), state.binding("git-context").?.route_generation);
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, state.snapshot(), .{});
    defer std.testing.allocator.free(encoded);
    const parsed = try std.json.parseFromSlice(Snapshot, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    var imported = try State.fromSnapshot(std.testing.allocator, parsed.value);
    defer imported.deinit();
    try std.testing.expectEqual(@as(u64, 43), imported.binding("git-context").?.last_used_revision);
    try std.testing.expectEqual(@as(u64, 0), imported.binding("native-thread").?.last_used_revision);
}

test "expired native rejection contexts are transient while active cooldowns and stale provider truth remain" {
    var state = try fixtureState();
    defer state.deinit();
    var expired = fixtureObservation("account-a", "", 0);
    expired.resource.target = "expired-context";
    expired.status = .unavailable;
    expired.provenance = .native_application;
    expired.expires_at = 5;
    try state.observe(expired);
    var ended = expired;
    ended.resource.target = "ended-context";
    ended.expires_at = 50;
    ended.window_end = 5;
    try state.observe(ended);
    var active = expired;
    active.resource.target = "active-context";
    active.expires_at = 50;
    try state.observe(active);
    var stale_provider = expired;
    stale_provider.resource.target = "provider-context";
    stale_provider.provenance = .provider_api;
    try state.observe(stale_provider);
    try std.testing.expectEqual(@as(usize, 2), state.pruneObservations(10));
    try std.testing.expectEqual(@as(usize, 2), state.observations.items.len);
    var found_active = false;
    var found_provider = false;
    for (state.observations.items) |observation| {
        if (eql(observation.resource.target, "active-context")) found_active = true;
        if (eql(observation.resource.target, "provider-context")) found_provider = true;
    }
    try std.testing.expect(found_active and found_provider);
    try std.testing.expectEqual(@as(usize, 1), state.pruneObservations(100));
    try std.testing.expectEqual(@as(usize, 1), state.observations.items.len);
    try std.testing.expectEqual(.provider_api, state.observations.items[0].provenance);
}
