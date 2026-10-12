//! Actor-owned, single-dispatch SIWC model-observation authority. Only actual
//! authenticated paired Store custody can construct a ticket. No native thread
//! or refresh writer is minted, and no token is returned to control/native RPC.
const std = @import("std");
const builtin = @import("builtin");
const storage = @import("storage.zig");
const pair = @import("siwc_pair.zig");
const domain = @import("domain.zig");
const envelope = @import("envelope.zig");
const native_owner = @import("native_owner.zig");

pub const maximum_seconds: i64 = 60;
pub const maximum_token_bytes = 16 * 1024;
pub const Scope = union(enum) {
    bootstrap,
    lease: struct { handle: [64]u8, reference: native_owner.NativeRef },
};
pub const LeaseContext = struct {
    handle: [64]u8,
    reference: native_owner.NativeRef,
    route_generation: u64,
    expires_at: i64,
};
const Window = struct {
    account_lifecycle: domain.AccountLifecycle,
    source_authorized_at: i64,
    source_authorized_until: ?i64,
    access_custody_until: ?i64,
    refresh_provider_until: ?i64,
    refresh_custody_until: ?i64,
    lease: ?LeaseContext,
};
const Phase = enum(u8) { pending, dispatching, cancelled };
const FenceData = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    until: std.Io.Clock.Timestamp,
    captured_unix: i64,
    expires_at: i64,
    phase: std.atomic.Value(Phase) = .init(.pending),
    references: std.atomic.Value(usize) = .init(1),
};
pub const Cancellation = enum { prevented_before_dispatch, dispatched_or_racing };
pub const DispatchFence = opaque {
    pub fn retain(self: *DispatchFence) void {
        _ = fenceData(self).references.fetchAdd(1, .monotonic);
    }
    pub fn deinit(self: *DispatchFence) void {
        const d = fenceData(self);
        if (d.references.fetchSub(1, .acq_rel) == 1) d.allocator.destroy(d);
    }
    pub fn checkActive(self: *const DispatchFence) !void {
        const d = fenceDataConst(self);
        try originalDeadline(d.io, d.until);
        const now = std.Io.Clock.real.now(d.io).toSeconds();
        if (now < d.captured_unix or now >= d.expires_at or d.phase.load(.acquire) == .cancelled) return error.SiwcCatalogRetired;
    }
    pub fn checkBeforeDispatch(self: *const DispatchFence) !void {
        try self.checkActive();
        if (fenceDataConst(self).phase.load(.acquire) != .pending) return error.SiwcCatalogAlreadyDispatched;
    }
    pub fn beginDispatch(self: *DispatchFence) !void {
        try self.checkBeforeDispatch();
        if (fenceData(self).phase.cmpxchgStrong(.pending, .dispatching, .acq_rel, .acquire) != null) return error.SiwcCatalogRetired;
    }
    pub fn checkAfterIo(self: *const DispatchFence) !void {
        try self.checkActive();
        if (fenceDataConst(self).phase.load(.acquire) != .dispatching) return error.SiwcCatalogRetired;
    }
    pub fn invalidate(self: *DispatchFence) Cancellation {
        return if (fenceData(self).phase.swap(.cancelled, .acq_rel) == .pending) .prevented_before_dispatch else .dispatched_or_racing;
    }
};
fn fenceData(self: *DispatchFence) *FenceData {
    return @ptrCast(@alignCast(self));
}
fn fenceDataConst(self: *const DispatchFence) *const FenceData {
    return @ptrCast(@alignCast(self));
}

pub const DispatchMaterial = struct {
    access: envelope.Secret,
    context: pair.CatalogContext,
    lease: ?LeaseContext,
    committed_revision: u64,
    io: std.Io,
    until: std.Io.Clock.Timestamp,
    fence: *DispatchFence,
    fixture_port: u16,
    pub fn deinit(self: *DispatchMaterial) void {
        self.access.deinit();
        self.fence.deinit();
        self.* = undefined;
    }
};
const TicketData = struct {
    allocator: std.mem.Allocator,
    authority: *pair.PairAuthority,
    context: pair.CatalogContext,
    window: Window,
    revision: u64,
    access: envelope.Secret,
    scope: Scope,
    fence: *DispatchFence,
    claimed: std.atomic.Value(bool) = .init(false),
    fixture_port: u16 = 0,
    references: std.atomic.Value(usize) = .init(1),
};
pub const Ticket = opaque {
    pub fn claim(self: *Ticket, a: std.mem.Allocator) !DispatchMaterial {
        const d = ticketData(self);
        if (d.claimed.swap(true, .acq_rel)) return error.SiwcCatalogTicketConsumed;
        try d.fence.checkBeforeDispatch();
        var access: envelope.Secret = .{ .allocator = a, .bytes = try a.dupe(u8, d.access.bytes) };
        errdefer access.deinit();
        try d.fence.checkBeforeDispatch();
        d.fence.retain();
        return .{ .access = access, .context = d.context, .lease = d.window.lease, .committed_revision = d.revision, .io = fenceData(d.fence).io, .until = fenceData(d.fence).until, .fence = d.fence, .fixture_port = if (builtin.is_test) d.fixture_port else 0 };
    }
    pub fn retain(self: *Ticket) void {
        _ = ticketData(self).references.fetchAdd(1, .monotonic);
    }
    pub fn deinit(self: *Ticket) void {
        const d = ticketData(self);
        if (d.references.fetchSub(1, .acq_rel) != 1) return;
        d.access.deinit();
        d.authority.deinit();
        d.fence.deinit();
        d.allocator.destroy(d);
    }
    pub fn invalidate(self: *Ticket) Cancellation {
        return ticketData(self).fence.invalidate();
    }
    pub fn context(self: *const Ticket) pair.CatalogContext {
        return ticketDataConst(self).context;
    }
    pub fn leaseContext(self: *const Ticket) ?LeaseContext {
        return ticketDataConst(self).window.lease;
    }
    pub fn committedRevision(self: *const Ticket) u64 {
        return ticketDataConst(self).revision;
    }
    pub fn clockIo(self: *const Ticket) std.Io {
        return fenceDataConst(ticketDataConst(self).fence).io;
    }
    pub fn originalUntil(self: *const Ticket) std.Io.Clock.Timestamp {
        return fenceDataConst(ticketDataConst(self).fence).until;
    }
    pub fn expiresAt(self: *const Ticket) i64 {
        return fenceDataConst(ticketDataConst(self).fence).expires_at;
    }
    pub fn matchesFence(self: *const Ticket, fence: *const DispatchFence) bool {
        return ticketDataConst(self).fence == fence;
    }
    pub fn checkActive(self: *const Ticket) !void {
        const d = ticketDataConst(self);
        try d.fence.checkActive();
        try checkRenewal(d.context, self.clockIo());
    }
    /// Latest committed semantic authority, not global revision equality.
    /// Label/metrics writes may advance the revision without renewing this read.
    pub fn recheckStore(self: *const Ticket, store: *storage.Store) !void {
        const d = ticketDataConst(self);
        if (!std.meta.eql(store.io, self.clockIo())) return error.SiwcCatalogAuthorityChanged;
        try self.checkActive();
        const fresh = try pair.currentPair(store, &d.context.account_id, &d.context.access_grant_id, d.context.access_generation, std.Io.Clock.real.now(store.io).toSeconds());
        defer fresh.deinit();
        if (fresh.committedRevision() < d.revision or !std.meta.eql(try fresh.catalogContext(), d.context)) return error.SiwcCatalogAuthorityChanged;
        const observed = try readWindow(store, d.context, d.scope);
        if (observed.revision < fresh.committedRevision() or !std.meta.eql(observed.window, d.window)) return error.SiwcCatalogAuthorityChanged;
        try self.checkActive();
    }
    /// Downgrade-only staged actor guard. No supplied State/Record constructs
    /// authority: prepare below independently authenticates Store custody.
    pub fn matchesActorState(self: *const Ticket, state: *const domain.State, record: pair.Record) bool {
        const d = ticketDataConst(self);
        if (!d.authority.matchesCatalogRecord(record)) return false;
        const now = std.Io.Clock.real.now(self.clockIo()).toSeconds();
        const observed = windowFor(state.sources.items, state.accounts.items, state.grants.items, state.bindings.items, state.leases.items, d.context, d.scope, now) catch return false;
        return std.meta.eql(observed, d.window);
    }
};
fn ticketData(self: *Ticket) *TicketData {
    return @ptrCast(@alignCast(self));
}
fn ticketDataConst(self: *const Ticket) *const TicketData {
    return @ptrCast(@alignCast(self));
}

const Retained = struct { schema_version: u32, state: domain.Snapshot };
const ReadWindow = struct { revision: u64, window: Window };
fn readWindow(store: *storage.Store, context: pair.CatalogContext, scope: Scope) !ReadWindow {
    var saved = try store.readSnapshot();
    defer saved.deinit();
    const parsed = try std.json.parseFromSlice(Retained, store.allocator, saved.json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (parsed.value.schema_version != 2) return error.SiwcCatalogAuthorityChanged;
    return .{ .revision = saved.revision, .window = try windowFor(parsed.value.state.sources, parsed.value.state.accounts, parsed.value.state.grants, parsed.value.state.bindings, parsed.value.state.leases, context, scope, std.Io.Clock.real.now(store.io).toSeconds()) };
}
fn windowFor(sources: []const domain.Source, accounts: []const domain.Account, grants: []const domain.Grant, bindings: []const domain.Binding, leases: []const domain.Lease, context: pair.CatalogContext, scope: Scope, now: i64) !Window {
    var window: Window = .{ .account_lifecycle = .active, .source_authorized_at = 0, .source_authorized_until = null, .access_custody_until = null, .refresh_provider_until = null, .refresh_custody_until = null, .lease = null };
    var found_source = false;
    var found_account = false;
    var found_access = false;
    var found_refresh = false;
    for (sources) |source| if (std.mem.eql(u8, source.id, &context.source_id)) {
        if (found_source or source.kind != .oauth or source.status == .disconnected or !std.mem.eql(u8, source.provider, "openai_siwc") or source.authorized_at > now or expired(source.authorized_until, now)) return error.SiwcCatalogAuthorityChanged;
        found_source = true;
        window.source_authorized_at = source.authorized_at;
        window.source_authorized_until = source.authorized_until;
    };
    for (accounts) |account| if (std.mem.eql(u8, account.id, &context.account_id)) {
        if (found_account or account.lifecycle == .paused or (scope == .bootstrap and account.lifecycle != .active)) return error.SiwcCatalogAuthorityChanged;
        const identity = std.fmt.bytesToHex(context.identity_commitment, .lower);
        if (!account.identity.verified or !std.mem.eql(u8, account.identity.provider, "openai_siwc") or !std.mem.eql(u8, account.identity.issuer, pair.issuer_uri) or account.identity.tenant.len != 0 or !std.mem.eql(u8, account.identity.subject, &identity)) return error.SiwcCatalogAuthorityChanged;
        var associated = false;
        for (account.source_ids) |source_id| if (std.mem.eql(u8, source_id, &context.source_id)) {
            associated = true;
        };
        if (!associated) return error.SiwcCatalogAuthorityChanged;
        found_account = true;
        window.account_lifecycle = account.lifecycle;
    };
    for (grants) |grant| {
        if (std.mem.eql(u8, grant.id, &context.access_grant_id)) {
            if (found_access or !std.mem.eql(u8, grant.account_id, &context.account_id) or !std.mem.eql(u8, grant.source_id, &context.source_id) or grant.generation != context.access_generation or grant.status != .ready or grant.ownership != .omux or grant.provider_expires_at != context.access_expires_at or expired(grant.custody_expires_at, now)) return error.SiwcCatalogAuthorityChanged;
            if (grant.credential_kind != .oauth_access or !std.mem.eql(u8, grant.audience, pair.resource_uri)) return error.SiwcCatalogAuthorityChanged;
            var request = false;
            var invoke = false;
            var direct = false;
            for (grant.purposes) |purpose| if (purpose == .request) {
                request = true;
            };
            for (grant.scopes) |scope_name| {
                if (std.mem.eql(u8, scope_name, "resource.invoke")) invoke = true;
                if (std.mem.eql(u8, scope_name, "chatgpt.tokens.use.direct")) direct = true;
            }
            if (!request or !invoke or !direct) return error.SiwcCatalogAuthorityChanged;
            found_access = true;
            window.access_custody_until = grant.custody_expires_at;
        }
        if (std.mem.eql(u8, grant.id, &context.refresh_grant_id)) {
            const required_status: domain.GrantStatus = if (context.status == .refreshing) .refreshing else .ready;
            if (found_refresh or !std.mem.eql(u8, grant.account_id, &context.account_id) or !std.mem.eql(u8, grant.source_id, &context.source_id) or grant.generation != context.refresh_generation or grant.status != required_status or grant.ownership != .omux or expired(grant.provider_expires_at, now) or expired(grant.custody_expires_at, now)) return error.SiwcCatalogAuthorityChanged;
            if (grant.credential_kind != .oauth_refresh or !std.mem.eql(u8, grant.audience, pair.resource_uri)) return error.SiwcCatalogAuthorityChanged;
            var renewal = false;
            for (grant.purposes) |purpose| if (purpose == .renewal) {
                renewal = true;
            };
            if (!renewal) return error.SiwcCatalogAuthorityChanged;
            found_refresh = true;
            window.refresh_provider_until = grant.provider_expires_at;
            window.refresh_custody_until = grant.custody_expires_at;
        }
    }
    if (!found_source or !found_account or !found_access or !found_refresh) return error.SiwcCatalogAuthorityChanged;
    if (context.status == .refreshing) {
        const renewal = context.renewal orelse return error.SiwcCatalogAuthorityChanged;
        const actual: pair.GrantWindow = .{ .access_provider_expires_at = context.access_expires_at, .access_custody_expires_at = window.access_custody_until, .refresh_provider_expires_at = window.refresh_provider_until, .refresh_custody_expires_at = window.refresh_custody_until };
        if (!std.meta.eql(actual, renewal.grant_window) or (window.source_authorized_until orelse 253_402_300_799) != renewal.source_expires_at) return error.SiwcCatalogAuthorityChanged;
        try renewal.grant_window.check(now);
    }
    if (scope == .lease) {
        const expected = scope.lease;
        var found = false;
        for (leases) |lease| if (std.mem.eql(u8, lease.id, &expected.handle)) {
            if (found or lease.native_ref == null or !lease.native_ref.?.same(expected.reference) or !std.mem.eql(u8, lease.account_id, &context.account_id) or !std.mem.eql(u8, lease.grant_id, &context.access_grant_id) or lease.grant_generation != context.access_generation or lease.purpose != .request or !std.mem.eql(u8, lease.audience, pair.resource_uri) or lease.expires_at <= now or lease.started_at > now or lease.route_generation == 0) return error.SiwcCatalogLeaseChanged;
            var bound = false;
            for (bindings) |binding| if (std.mem.eql(u8, binding.id, lease.binding_id)) {
                if (bound or binding.native_ref == null or !binding.native_ref.?.same(expected.reference) or !std.mem.eql(u8, binding.account_id, lease.account_id) or !std.mem.eql(u8, binding.grant_id, lease.grant_id) or binding.grant_generation != lease.grant_generation or binding.route_generation != lease.route_generation) return error.SiwcCatalogLeaseChanged;
                bound = true;
            };
            if (!bound) return error.SiwcCatalogLeaseChanged;
            window.lease = .{ .handle = expected.handle, .reference = expected.reference, .route_generation = lease.route_generation, .expires_at = lease.expires_at };
            found = true;
        };
        if (!found) return error.SiwcCatalogLeaseChanged;
    }
    return window;
}
/// A completed last-operation witness remains metadata on a ready successor.
/// Only the actual authenticated in-flight operation narrows this new read.
fn checkRenewal(context: pair.CatalogContext, io: std.Io) !void {
    if (context.status != .refreshing) return;
    const renewal = context.renewal orelse return error.SiwcCatalogAuthorityChanged;
    const now = std.Io.Clock.real.now(io).toSeconds();
    if (renewal.state != .issued or renewal.family_generation != context.family_generation or renewal.writer_generation != context.writer_generation or renewal.source_generation != context.source_generation or renewal.consent_generation != context.consent_generation or now < renewal.admitted_unix or now >= renewal.source_expires_at) return error.SiwcCatalogAuthorityChanged;
    try renewal.grant_window.check(now);
    try originalDeadline(io, renewal.originalUntil());
}
fn expired(value: ?i64, now: i64) bool {
    return if (value) |until| until <= now else false;
}
fn originalDeadline(io: std.Io, until: std.Io.Clock.Timestamp) !void {
    if (until.clock != .awake) return error.SiwcCatalogDeadline;
    const left = until.durationFromNow(io).raw.toNanoseconds();
    if (left <= 0 or left > 120_000_000_000) return error.SiwcCatalogDeadline;
}
/// Actual actor Store constructor. Caller labels/profile digests/booleans and
/// generic .omux grants cannot bypass currentPair's complete custody checks.
pub fn prepare(store: *storage.Store, account_id: []const u8, access_id: []const u8, generation: u64, until: std.Io.Clock.Timestamp, scope: Scope) !*Ticket {
    const a = store.allocator;
    try originalDeadline(store.io, until);
    const now = std.Io.Clock.real.now(store.io).toSeconds();
    const authority = try pair.currentPair(store, account_id, access_id, generation, now);
    errdefer authority.deinit();
    const context = try authority.catalogContext();
    try checkRenewal(context, store.io);
    var read_until = until;
    if (context.status == .refreshing) {
        const original = context.renewal.?.originalUntil();
        if (original.raw.nanoseconds < read_until.raw.nanoseconds) read_until = original;
    }
    try originalDeadline(store.io, read_until);
    const observed = try readWindow(store, context, scope);
    if (observed.revision < authority.committedRevision()) return error.SiwcCatalogAuthorityChanged;
    var payload = try store.loadGrant(.{ .key_id = store.key_id, .account_id = &context.account_id, .grant_id = &context.access_grant_id, .generation = context.access_generation, .purpose = "request", .scope = pair.resource_uri });
    defer payload.deinit();
    var scratch: [256 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &scratch);
    var fixed = std.heap.FixedBufferAllocator.init(&scratch);
    const parsed = try std.json.parseFromSlice(struct { access_token: []const u8 }, fixed.allocator(), payload.bytes, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
    defer parsed.deinit();
    const token = parsed.value.access_token;
    if (token.len == 0 or token.len > maximum_token_bytes) return error.SiwcCatalogAuthorityChanged;
    for (token) |byte| if (byte < 0x21 or byte > 0x7e) return error.SiwcCatalogAuthorityChanged;
    if (!std.crypto.timing_safe.eql([32]u8, pair.tokenCommitment(store.key, token, .access), context.access_token_commitment)) return error.SiwcCatalogAuthorityChanged;
    var access: envelope.Secret = .{ .allocator = a, .bytes = try a.dupe(u8, token) };
    errdefer access.deinit();
    var expiry = @min(context.access_expires_at, now + maximum_seconds);
    inline for (.{ "source_authorized_until", "access_custody_until", "refresh_provider_until", "refresh_custody_until" }) |name| if (@field(observed.window, name)) |limit| {
        expiry = @min(expiry, limit);
    };
    if (observed.window.lease) |lease| expiry = @min(expiry, lease.expires_at);
    if (context.status == .refreshing) {
        const renewal = context.renewal.?;
        expiry = @min(expiry, renewal.source_expires_at);
        if (renewal.grant_window.limitingExpiry()) |limit| expiry = @min(expiry, limit);
    }
    // Exported wall expiry is a conservative display bound. The exact original
    // awake cutoff is independently retained and never converted/reconstructed.
    const remaining_seconds = read_until.durationFromNow(store.io).raw.toSeconds();
    if (remaining_seconds <= 0) return error.SiwcCatalogDeadline;
    expiry = @min(expiry, now + @as(i64, @intCast(remaining_seconds)));
    if (expiry <= std.Io.Clock.real.now(store.io).toSeconds()) return error.SiwcCatalogDeadline;
    const fd = try a.create(FenceData);
    errdefer a.destroy(fd);
    fd.* = .{ .allocator = a, .io = store.io, .until = read_until, .captured_unix = now, .expires_at = expiry };
    const fence: *DispatchFence = @ptrCast(fd);
    const d = try a.create(TicketData);
    errdefer a.destroy(d);
    d.* = .{ .allocator = a, .authority = authority, .context = context, .window = observed.window, .revision = observed.revision, .access = access, .scope = scope, .fence = fence };
    const result: *Ticket = @ptrCast(d);
    try result.recheckStore(store);
    return result;
}
pub const testing = struct {
    pub fn matchesAuthorization(ticket: *const Ticket, header: []const u8) bool {
        if (!builtin.is_test or !std.mem.startsWith(u8, header, "Bearer ")) return false;
        const d = ticketDataConst(ticket);
        return std.mem.eql(u8, header["Bearer ".len..], d.access.bytes);
    }
    /// Only a genuine Store-backed ticket gets modeled loopback routing. This
    /// helper constructs no pair/profile/token authority and refuses shipping.
    pub fn attachRoute(ticket: *Ticket, port: u16) !void {
        if (!builtin.is_test) return error.TestOnly;
        const d = ticketData(ticket);
        if (port == 0 or d.fixture_port != 0 or d.claimed.load(.acquire)) return error.InvalidModelRoute;
        try ticket.checkActive();
        d.fixture_port = port;
    }
};
