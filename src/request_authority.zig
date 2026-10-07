//! Durable native request fences. Lease expiry releases resources, never replay
//! authority. Persist this snapshot atomically with each lease/report mutation.
const std = @import("std");
const native_owner = @import("native_owner.zig");
const snapshot_admission = @import("snapshot_admission.zig");

pub const maximum_capacity = 4096;
/// Independent authority partition; the owner must also bound other snapshot
/// sections before claiming that the complete storage envelope always fits.
pub const maximum_snapshot_bytes = 4 * 1024 * 1024;
const snapshot_overhead = 32;
const record_overhead = 256;
// Covers both report acknowledgments, state, handle, sequence and expiry at
// their maximum encoded widths. Account strings are counted separately.
const attempt_overhead = 512;
const maximum_account_json_bytes = 4096 * 6 + 2;
pub const Key = struct { application: []const u8, session_id: []const u8, request_id: []const u8 };
pub const Intent = struct {
    key: Key,
    binding_id: []const u8,
    demand_fingerprint: []const u8,
    /// Immutable attribution, never part of the work key or a fresh replay
    /// budget. Legacy null records remain fences without native authority.
    native_ref: ?native_owner.NativeRef = null,
};
pub const Event = enum { accepted, completed, rejected, abandoned };
pub const Status = enum { issued, accepted, completed, rejected, abandoned, unknown };
pub const Report = struct {
    event: Event,
    pre_acceptance: bool = false,
    response_started: bool = true,
    status: u16 = 0,
};
pub const Attempt = struct {
    lease_handle: []const u8,
    account_id: []const u8,
    expires_at: i64,
    issued_sequence: u64 = 0,
    state: Status = .issued,
    /// Retain every event acknowledgment: accepted may be retried after completed.
    accepted_report: ?Report = null,
    terminal_report: ?Report = null,
};
pub const Record = struct { intent: Intent, first: Attempt, alternate: ?Attempt = null };
pub const Snapshot = struct { records: []const Record = &.{} };
pub const maximum_native_audit_records = 6;

pub fn validateRequestId(value: []const u8) !void {
    if (value.len == 0 or value.len > 64) return error.InvalidRequestId;
    for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return error.InvalidRequestId;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
fn sameKey(a: Key, b: Key) bool {
    return eql(a.application, b.application) and eql(a.session_id, b.session_id) and eql(a.request_id, b.request_id);
}
fn validateIntent(intent: Intent) !void {
    if (intent.native_ref) |ref| try ref.validate();
    try validateRequestId(intent.key.request_id);
    for ([_][]const u8{ intent.key.application, intent.key.session_id, intent.binding_id }) |value| {
        if (value.len == 0 or value.len > 4096) return error.InvalidRequestAuthority;
        for (value) |byte| if (byte < 0x20 or byte == 0x7f) return error.InvalidRequestAuthority;
    }
    if (intent.demand_fingerprint.len != 64) return error.InvalidRequestAuthority;
    for (intent.demand_fingerprint) |byte| if (!std.ascii.isHex(byte)) return error.InvalidRequestAuthority;
}

/// JSON escaping, including arbitrary bytes, cannot exceed six bytes per input
/// byte. Count ordinary ASCII exactly and reserve that bound for non-ASCII.
fn stringReservation(value: []const u8) usize {
    // The default serializer emits invalid UTF-8 byte slices as numeric arrays.
    if (!std.unicode.utf8ValidateSlice(value)) {
        var bytes: usize = 2;
        for (value) |byte| bytes += 1 + @as(usize, if (byte >= 100) 3 else if (byte >= 10) 2 else 1);
        return bytes - @intFromBool(value.len != 0);
    }
    var bytes: usize = 2;
    for (value) |byte| bytes += switch (byte) {
        '"', '\\', '\n', '\r', '\t', 0x08, 0x0c => 2,
        0...7, 0x0b, 0x0e...0x1f, 0x80...0xff => 6,
        else => 1,
    };
    return bytes;
}

fn intentReservation(intent: Intent) !usize {
    return record_overhead + stringReservation(intent.key.application) +
        stringReservation(intent.key.session_id) + stringReservation(intent.key.request_id) +
        stringReservation(intent.binding_id) + stringReservation(intent.demand_fingerprint) +
        // Immutable reference fields never grow after admission. Count the
        // pinned serializer's actual byte-array and integer representations.
        try snapshot_admission.countJson(intent.native_ref, maximum_snapshot_bytes);
}

fn sameNativeRef(a: ?native_owner.NativeRef, b: ?native_owner.NativeRef) bool {
    if (a) |left| return if (b) |right| left.same(right) else false;
    return b == null;
}

pub const Ledger = struct {
    allocator: std.mem.Allocator,
    capacity: usize,
    records: std.ArrayList(Record) = .empty,
    last_sequence: u64 = 0,
    reserved_snapshot_bytes: usize = snapshot_overhead,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) Ledger {
        return .{ .allocator = allocator, .capacity = @min(capacity, maximum_capacity) };
    }
    pub fn deinit(self: *Ledger) void {
        for (self.records.items) |item| self.freeRecord(item);
        self.records.deinit(self.allocator);
    }
    pub fn snapshot(self: *const Ledger) Snapshot {
        return .{ .records = self.records.items };
    }
    pub fn reservedSnapshotBytes(self: *const Ledger) usize {
        return self.reserved_snapshot_bytes;
    }
    pub fn remainingSnapshotBytes(self: *const Ledger) usize {
        return maximum_snapshot_bytes - self.reserved_snapshot_bytes;
    }
    pub fn record(self: *const Ledger, key: Key) ?*const Record {
        for (self.records.items) |*item| if (sameKey(item.intent.key, key)) return item;
        return null;
    }
    /// Select immutable native attribution, including terminal fences whose
    /// leases no longer exist. No cursor or partial page may imply completeness.
    /// The actor authenticates the control channel and validates owner custody.
    pub fn nativeAuditRecords(self: *const Ledger, allocator: std.mem.Allocator, application: []const u8, reference: native_owner.NativeRef, thread_id: []const u8) ![]*const Record {
        try reference.validate();
        if (thread_id.len == 0 or thread_id.len > native_owner.maximum_thread_bytes) return error.InvalidNativeAttachment;
        var selected: [maximum_native_audit_records]*const Record = undefined;
        var count: usize = 0;
        for (self.records.items) |*row| {
            const original = row.intent.native_ref orelse continue;
            if (!original.same(reference) or !eql(row.intent.key.application, application) or !eql(row.intent.key.session_id, thread_id)) continue;
            if (count == selected.len) return error.NativeAuditTooManyRecords;
            selected[count] = row;
            count += 1;
        }
        return allocator.dupe(*const Record, selected[0..count]);
    }
    pub fn attempt(self: *const Ledger, application: []const u8, lease_handle: []const u8) ?*const Attempt {
        for (self.records.items) |*item| {
            if (!eql(item.intent.key.application, application)) continue;
            if (eql(item.first.lease_handle, lease_handle)) return &item.first;
            if (item.alternate) |*alternate| if (eql(alternate.lease_handle, lease_handle)) return alternate;
        }
        return null;
    }
    /// Retain original attribution independently of live leases and bindings.
    /// The caller must additionally authenticate the current packet's peer.
    pub fn intentForHandle(self: *const Ledger, application: []const u8, lease_handle: []const u8) ?*const Intent {
        for (self.records.items) |*item| {
            if (!eql(item.intent.key.application, application)) continue;
            if (eql(item.first.lease_handle, lease_handle)) return &item.intent;
            if (item.alternate) |alternate| if (eql(alternate.lease_handle, lease_handle)) return &item.intent;
        }
        return null;
    }
    pub fn latestHandleForBinding(self: *const Ledger, application: []const u8, binding_id: []const u8) ?[]const u8 {
        var latest: ?*const Attempt = null;
        for (self.records.items) |*item| {
            if (!eql(item.intent.key.application, application) or !eql(item.intent.binding_id, binding_id)) continue;
            if (latest == null or item.first.issued_sequence > latest.?.issued_sequence) latest = &item.first;
            if (item.alternate) |*alternate| {
                if (alternate.issued_sequence > latest.?.issued_sequence) latest = alternate;
            }
        }
        return if (latest) |held| held.lease_handle else null;
    }
    /// This preflight is read-only; issue is the sole budget-consuming action.
    pub fn checkIssue(self: *const Ledger, intent: Intent) !u8 {
        const number = try self.checkIntent(intent);
        // Account selection follows this preflight. Reserve its maximum legal
        // JSON footprint before the owner prepares a lease or any other effect.
        try self.checkReservation(intent, number, maximum_account_json_bytes);
        return number;
    }
    fn checkIntent(self: *const Ledger, intent: Intent) !u8 {
        try validateIntent(intent);
        if (self.record(intent.key)) |held| {
            if (!sameNativeRef(held.intent.native_ref, intent.native_ref)) return error.NativeOwnerMismatch;
            if (!eql(held.intent.binding_id, intent.binding_id) or !eql(held.intent.demand_fingerprint, intent.demand_fingerprint)) return error.RequestMismatch;
            if (held.alternate != null or held.first.state != .rejected) return error.AttemptBudgetExhausted;
            return 2;
        }
        if (self.records.items.len >= self.capacity) return error.RequestLedgerFull;
        return 1;
    }
    fn checkReservation(self: *const Ledger, intent: Intent, number: u8, account_bytes: usize) !void {
        const additional = attempt_overhead + account_bytes + if (number == 1) try intentReservation(intent) else 0;
        if (additional > self.remainingSnapshotBytes()) return error.RequestLedgerFull;
    }
    pub fn rejectedAccount(self: *const Ledger, intent: Intent) !?[]const u8 {
        _ = try self.checkIssue(intent);
        return if (self.record(intent.key)) |held| held.first.account_id else null;
    }
    pub fn issue(self: *Ledger, intent: Intent, lease_handle: []const u8, account_id: []const u8, expires_at: i64) !u8 {
        const number = try self.checkIntent(intent);
        const sequence = try std.math.add(u64, self.last_sequence, 1);
        if (lease_handle.len != 64 or account_id.len == 0 or account_id.len > 4096) return error.InvalidRequestAuthority;
        for (lease_handle) |byte| if (!std.ascii.isHex(byte)) return error.InvalidRequestAuthority;
        const account_bytes = stringReservation(account_id);
        try self.checkReservation(intent, number, account_bytes);
        const additional = attempt_overhead + account_bytes + if (number == 1) try intentReservation(intent) else 0;
        for (self.records.items) |item| {
            if (eql(item.first.lease_handle, lease_handle)) return error.DuplicateLease;
            if (item.alternate) |alternate| if (eql(alternate.lease_handle, lease_handle)) return error.DuplicateLease;
        }
        if (number == 2) {
            for (self.records.items) |*item| if (sameKey(item.intent.key, intent.key)) {
                if (eql(item.first.account_id, account_id)) return error.RejectedAccount;
                item.alternate = try self.cloneAttempt(.{ .lease_handle = lease_handle, .account_id = account_id, .expires_at = expires_at, .issued_sequence = sequence });
                self.last_sequence = sequence;
                self.reserved_snapshot_bytes += additional;
                return number;
            };
            unreachable;
        }
        const owned_intent = try self.cloneIntent(intent);
        errdefer self.freeIntent(owned_intent);
        const owned_attempt = try self.cloneAttempt(.{ .lease_handle = lease_handle, .account_id = account_id, .expires_at = expires_at, .issued_sequence = sequence });
        errdefer self.freeAttempt(owned_attempt);
        try self.records.append(self.allocator, .{ .intent = owned_intent, .first = owned_attempt });
        self.last_sequence = sequence;
        self.reserved_snapshot_bytes += additional;
        return number;
    }
    /// A duplicate is an acknowledgment only, never another state transition.
    /// Historical ownerless model only; attributed work requires the owner API.
    pub fn checkReport(self: *const Ledger, application: []const u8, lease_handle: []const u8, evidence: Report) !bool {
        const intent = self.intentForHandle(application, lease_handle) orelse return error.UnknownLease;
        if (intent.native_ref != null) return error.NativeOwnerMismatch;
        var held = (self.attempt(application, lease_handle) orelse return error.UnknownLease).*;
        return applyReport(&held, evidence);
    }
    fn checkOwner(self: *const Ledger, application: []const u8, lease_handle: []const u8, ref: native_owner.NativeRef) !void {
        try ref.validate();
        const intent = self.intentForHandle(application, lease_handle) orelse return error.UnknownLease;
        const original = intent.native_ref orelse return error.NativeOwnerMismatch;
        if (!original.same(ref)) return error.NativeOwnerMismatch;
    }
    /// Owner validation precedes every duplicate and restart-terminal shortcut.
    pub fn checkReportForOwner(self: *const Ledger, application: []const u8, lease_handle: []const u8, ref: native_owner.NativeRef, evidence: Report) !bool {
        try self.checkOwner(application, lease_handle, ref);
        var held = (self.attempt(application, lease_handle) orelse return error.UnknownLease).*;
        return applyReport(&held, evidence);
    }
    /// Mutation repeats the attribution check; a checked result is not a token
    /// permitting a later ownerless report. Peer liveness remains caller-owned.
    pub fn reportForOwner(self: *Ledger, application: []const u8, lease_handle: []const u8, ref: native_owner.NativeRef, evidence: Report) !bool {
        try self.checkOwner(application, lease_handle, ref);
        return self.applyReportForHandle(lease_handle, evidence);
    }
    pub fn report(self: *Ledger, lease_handle: []const u8, evidence: Report) !bool {
        for (self.records.items) |item| {
            const matched = eql(item.first.lease_handle, lease_handle) or
                (if (item.alternate) |alternate| eql(alternate.lease_handle, lease_handle) else false);
            if (matched and item.intent.native_ref != null) return error.NativeOwnerMismatch;
        }
        return self.applyReportForHandle(lease_handle, evidence);
    }
    fn applyReportForHandle(self: *Ledger, lease_handle: []const u8, evidence: Report) !bool {
        for (self.records.items) |*item| {
            if (eql(item.first.lease_handle, lease_handle)) return applyReport(&item.first, evidence);
            if (item.alternate) |*alternate| if (eql(alternate.lease_handle, lease_handle)) return applyReport(alternate, evidence);
        }
        return error.UnknownLease;
    }
    /// Issued work may have been accepted before a lost report. Crash recovery
    /// cannot infer rejection, even when its old access lease has expired.
    pub fn recoverAfterRestart(self: *Ledger) void {
        for (self.records.items) |*item| {
            recoverAttempt(&item.first);
            if (item.alternate) |*alternate| recoverAttempt(alternate);
        }
    }
    pub fn fromSnapshot(allocator: std.mem.Allocator, capacity: usize, saved: Snapshot) !Ledger {
        var self = init(allocator, capacity);
        errdefer self.deinit();
        if (saved.records.len > self.capacity) return error.RequestLedgerFull;
        // Validate global issue ordering before allocation or state restoration.
        var maximum_sequence: u64 = 0;
        for (saved.records, 0..) |item, index| {
            try validateSequence(saved.records, index, item.first.issued_sequence, false);
            maximum_sequence = @max(maximum_sequence, item.first.issued_sequence);
            if (item.alternate) |alternate| {
                try validateSequence(saved.records, index, alternate.issued_sequence, true);
                if (alternate.issued_sequence <= item.first.issued_sequence) return error.InvalidRequestSnapshot;
                maximum_sequence = @max(maximum_sequence, alternate.issued_sequence);
            }
        }
        for (saved.records) |item| {
            if (self.record(item.intent.key) != null) return error.DuplicateRequest;
            _ = try self.issue(item.intent, item.first.lease_handle, item.first.account_id, item.first.expires_at);
            const target = &self.records.items[self.records.items.len - 1];
            try validateAttempt(item.first);
            target.first.state = item.first.state;
            target.first.issued_sequence = item.first.issued_sequence;
            target.first.accepted_report = item.first.accepted_report;
            target.first.terminal_report = item.first.terminal_report;
            if (item.alternate) |alternate| {
                // issue checks the immutable intent and rejected primary fence.
                _ = try self.issue(item.intent, alternate.lease_handle, alternate.account_id, alternate.expires_at);
                try validateAttempt(alternate);
                target.alternate.?.state = alternate.state;
                target.alternate.?.issued_sequence = alternate.issued_sequence;
                target.alternate.?.accepted_report = alternate.accepted_report;
                target.alternate.?.terminal_report = alternate.terminal_report;
            }
        }
        self.last_sequence = maximum_sequence;
        return self;
    }
    fn cloneIntent(self: *Ledger, value: Intent) !Intent {
        const application = try self.allocator.dupe(u8, value.key.application);
        errdefer self.allocator.free(application);
        const session = try self.allocator.dupe(u8, value.key.session_id);
        errdefer self.allocator.free(session);
        const request = try self.allocator.dupe(u8, value.key.request_id);
        errdefer self.allocator.free(request);
        const binding = try self.allocator.dupe(u8, value.binding_id);
        errdefer self.allocator.free(binding);
        const fingerprint = try self.allocator.dupe(u8, value.demand_fingerprint);
        return .{ .key = .{ .application = application, .session_id = session, .request_id = request }, .binding_id = binding, .demand_fingerprint = fingerprint, .native_ref = value.native_ref };
    }
    fn cloneAttempt(self: *Ledger, value: Attempt) !Attempt {
        const handle = try self.allocator.dupe(u8, value.lease_handle);
        errdefer self.allocator.free(handle);
        const account = try self.allocator.dupe(u8, value.account_id);
        var result = value;
        result.lease_handle = handle;
        result.account_id = account;
        return result;
    }
    fn freeIntent(self: *Ledger, value: Intent) void {
        self.allocator.free(value.key.application);
        self.allocator.free(value.key.session_id);
        self.allocator.free(value.key.request_id);
        self.allocator.free(value.binding_id);
        self.allocator.free(value.demand_fingerprint);
    }
    fn freeAttempt(self: *Ledger, value: Attempt) void {
        self.allocator.free(value.lease_handle);
        self.allocator.free(value.account_id);
    }
    fn freeRecord(self: *Ledger, value: Record) void {
        self.freeIntent(value.intent);
        self.freeAttempt(value.first);
        if (value.alternate) |alternate| self.freeAttempt(alternate);
    }
};

fn sameReport(a: Report, b: Report) bool {
    return a.event == b.event and a.pre_acceptance == b.pre_acceptance and a.response_started == b.response_started and a.status == b.status;
}
fn safeRejection(value: Report) bool {
    return value.event == .rejected and value.pre_acceptance and !value.response_started and (value.status == 401 or value.status == 403 or value.status == 429);
}
fn applyReport(attempt: *Attempt, evidence: Report) !bool {
    const previous = if (evidence.event == .accepted) attempt.accepted_report else attempt.terminal_report;
    if (previous) |held| {
        if (sameReport(held, evidence)) return false;
        return error.ReportMismatch;
    }
    switch (evidence.event) {
        .accepted => {
            if (attempt.state != .issued) return error.InvalidTransition;
            attempt.accepted_report = evidence;
            attempt.state = .accepted;
        },
        .completed => {
            if (attempt.state != .accepted and !(attempt.state == .unknown and attempt.accepted_report != null)) return error.InvalidTransition;
            attempt.terminal_report = evidence;
            attempt.state = .completed;
        },
        .abandoned => {
            if (attempt.state != .issued and attempt.state != .accepted and attempt.state != .unknown) return error.InvalidTransition;
            attempt.terminal_report = evidence;
            attempt.state = .abandoned;
        },
        .rejected => {
            if (attempt.state != .issued or !safeRejection(evidence)) return error.UnsafeReplay;
            attempt.terminal_report = evidence;
            attempt.state = .rejected;
        },
    }
    return true;
}
fn validateSequence(records: []const Record, index: usize, sequence: u64, is_alternate: bool) !void {
    if (sequence == 0) return error.InvalidRequestSnapshot;
    for (records[0..index]) |previous| {
        if (previous.first.issued_sequence == sequence) return error.InvalidRequestSnapshot;
        if (previous.alternate) |alternate| if (alternate.issued_sequence == sequence) return error.InvalidRequestSnapshot;
    }
    if (is_alternate and records[index].first.issued_sequence == sequence) return error.InvalidRequestSnapshot;
}
fn recoverAttempt(attempt: *Attempt) void {
    if (attempt.state == .issued or attempt.state == .accepted) attempt.state = .unknown;
}
fn validateAttempt(value: Attempt) !void {
    if (value.accepted_report) |report| if (report.event != .accepted) return error.InvalidRequestSnapshot;
    if (value.terminal_report) |report| {
        if (report.event == .accepted) return error.InvalidRequestSnapshot;
        if (report.event == .rejected and !safeRejection(report)) return error.InvalidRequestSnapshot;
    }
    switch (value.state) {
        .issued => if (value.accepted_report != null or value.terminal_report != null) return error.InvalidRequestSnapshot,
        .accepted => if (value.accepted_report == null or value.terminal_report != null) return error.InvalidRequestSnapshot,
        .completed => if (value.accepted_report == null or value.terminal_report == null or value.terminal_report.?.event != .completed) return error.InvalidRequestSnapshot,
        .rejected => if (value.accepted_report != null or value.terminal_report == null or value.terminal_report.?.event != .rejected) return error.InvalidRequestSnapshot,
        .abandoned => if (value.terminal_report == null or value.terminal_report.?.event != .abandoned) return error.InvalidRequestSnapshot,
        .unknown => if (value.terminal_report != null) return error.InvalidRequestSnapshot,
    }
}

const fixture_a: [64]u8 = @splat('a');
const fixture_b: [64]u8 = @splat('b');
const fixture_1: [64]u8 = @splat('1');
const fixture_2: [64]u8 = @splat('2');
const fixture_3: [64]u8 = @splat('3');
const overlong_id: [129]u8 = @splat('x');
const fixture: Intent = .{ .key = .{ .application = "codex", .session_id = "native-thread", .request_id = "request-1" }, .binding_id = "binding", .demand_fingerprint = &fixture_a };
const rejection: Report = .{ .event = .rejected, .pre_acceptance = true, .response_started = false, .status = 429 };

test "native audit selects exact attribution and refuses partial over-capacity pages without consuming fences" {
    const allocator = std.testing.allocator;
    var ledger = Ledger.init(allocator, 16);
    defer ledger.deinit();
    const reference: native_owner.NativeRef = .{ .owner_id = @splat(1), .adapter_epoch = 1, .endpoint_generation = 1, .thread_instance_generation = 1, .attachment_generation = 1 };
    var attributed = fixture;
    attributed.native_ref = reference;
    for (0..maximum_native_audit_records) |index| {
        const request_id = try std.fmt.allocPrint(allocator, "request-{d}", .{index});
        defer allocator.free(request_id);
        var lease_handle: [64]u8 = @splat('0');
        lease_handle[0] = '1' + @as(u8, @intCast(index));
        attributed.key.request_id = request_id;
        _ = try ledger.issue(attributed, &lease_handle, &fixture_b, 1);
    }
    var foreign_reference = reference;
    foreign_reference.attachment_generation += 1;
    var foreign = fixture;
    foreign.key.request_id = "foreign-request";
    foreign.native_ref = foreign_reference;
    _ = try ledger.issue(foreign, &fixture_a, &fixture_b, 1);
    const reserved = ledger.reservedSnapshotBytes();
    const selected = try ledger.nativeAuditRecords(allocator, "codex", reference, "native-thread");
    defer allocator.free(selected);
    try std.testing.expectEqual(@as(usize, maximum_native_audit_records), selected.len);
    for (selected) |row| try std.testing.expect(row.intent.native_ref.?.same(reference));
    const wrong_thread = try ledger.nativeAuditRecords(allocator, "codex", reference, "another-thread");
    defer allocator.free(wrong_thread);
    try std.testing.expectEqual(@as(usize, 0), wrong_thread.len);
    const wrong_application = try ledger.nativeAuditRecords(allocator, "git", reference, "native-thread");
    defer allocator.free(wrong_application);
    try std.testing.expectEqual(@as(usize, 0), wrong_application.len);
    try std.testing.expectEqual(reserved, ledger.reservedSnapshotBytes());
    attributed.key.request_id = "seventh-request";
    _ = try ledger.issue(attributed, &fixture_b, &fixture_b, 1);
    const full_reserved = ledger.reservedSnapshotBytes();
    try std.testing.expectError(error.NativeAuditTooManyRecords, ledger.nativeAuditRecords(allocator, "codex", reference, "native-thread"));
    try std.testing.expectEqual(full_reserved, ledger.reservedSnapshotBytes());
    try std.testing.expectEqual(@as(usize, 8), ledger.records.items.len);
}

test "safe alternate budget survives JSON snapshot and expired leases" {
    const allocator = std.testing.allocator;
    var ledger = Ledger.init(allocator, 2);
    defer ledger.deinit();
    try std.testing.expectEqual(@as(u8, 1), try ledger.issue(fixture, &fixture_1, "account-a", 1));
    try std.testing.expect(try ledger.report(&fixture_1, rejection));
    try std.testing.expect(!(try ledger.report(&fixture_1, rejection)));
    const json = try std.json.Stringify.valueAlloc(allocator, ledger.snapshot(), .{});
    defer allocator.free(json);
    const parsed = try std.json.parseFromSlice(Snapshot, allocator, json, .{});
    defer parsed.deinit();
    var restored = try Ledger.fromSnapshot(allocator, 2, parsed.value);
    defer restored.deinit();
    restored.recoverAfterRestart();
    try std.testing.expectError(error.RejectedAccount, restored.issue(fixture, &fixture_2, "account-a", 1));
    try std.testing.expectEqual(@as(u8, 2), try restored.issue(fixture, &fixture_2, "account-b", 1));
    try std.testing.expect(try restored.report(&fixture_2, rejection));
    try std.testing.expectError(error.AttemptBudgetExhausted, restored.issue(fixture, &fixture_3, "account-c", 999999));
    var again = try Ledger.fromSnapshot(allocator, 2, restored.snapshot());
    defer again.deinit();
    again.recoverAfterRestart();
    try std.testing.expectError(error.AttemptBudgetExhausted, again.checkIssue(fixture));
}

test "lost acceptance reports restart unknown and never authorize replay" {
    var ledger = Ledger.init(std.testing.allocator, 2);
    defer ledger.deinit();
    _ = try ledger.issue(fixture, &fixture_1, "account-a", 1);
    ledger.recoverAfterRestart();
    try std.testing.expectError(error.AttemptBudgetExhausted, ledger.checkIssue(fixture));
    try std.testing.expectError(error.UnsafeReplay, ledger.report(&fixture_1, rejection));
    try std.testing.expect(try ledger.report(&fixture_1, .{ .event = .abandoned }));
    try std.testing.expectError(error.AttemptBudgetExhausted, ledger.checkIssue(fixture));
}

test "accepted stream completion acknowledges duplicates without reopening" {
    var ledger = Ledger.init(std.testing.allocator, 2);
    defer ledger.deinit();
    _ = try ledger.issue(fixture, &fixture_1, "account-a", 1);
    try std.testing.expect(try ledger.report(&fixture_1, .{ .event = .accepted }));
    try std.testing.expectError(error.UnsafeReplay, ledger.report(&fixture_1, rejection));
    try std.testing.expect(try ledger.report(&fixture_1, .{ .event = .completed }));
    try std.testing.expect(!(try ledger.report(&fixture_1, .{ .event = .accepted })));
    try std.testing.expect(!(try ledger.report(&fixture_1, .{ .event = .completed })));
    try std.testing.expectError(error.ReportMismatch, ledger.report(&fixture_1, .{ .event = .abandoned }));
    ledger.recoverAfterRestart();
    try std.testing.expectError(error.AttemptBudgetExhausted, ledger.checkIssue(fixture));
}

test "request identity pins binding and demand and bounded capacity never evicts" {
    var ledger = Ledger.init(std.testing.allocator, 1);
    defer ledger.deinit();
    _ = try ledger.issue(fixture, &fixture_1, "account-a", 1);
    try std.testing.expectError(error.AttemptBudgetExhausted, ledger.issue(fixture, &fixture_2, "account-b", 100));
    var changed = fixture;
    changed.binding_id = "another-binding";
    try std.testing.expectError(error.RequestMismatch, ledger.checkIssue(changed));
    changed = fixture;
    changed.demand_fingerprint = &fixture_b;
    try std.testing.expectError(error.RequestMismatch, ledger.checkIssue(changed));
    changed = fixture;
    changed.key.request_id = "request-2";
    try std.testing.expectError(error.RequestLedgerFull, ledger.checkIssue(changed));
    changed.key.request_id = "";
    try std.testing.expectError(error.InvalidRequestId, ledger.checkIssue(changed));
    try std.testing.expectError(error.InvalidRequestId, validateRequestId("request/id"));
    try std.testing.expectError(error.InvalidRequestId, validateRequestId(&overlong_id));
}

test "corrupt durable snapshots cannot invent a safe rejection or duplicate authority" {
    const allocator = std.testing.allocator;
    const invented: Record = .{ .intent = fixture, .first = .{ .lease_handle = &fixture_1, .account_id = "account-a", .expires_at = 1, .issued_sequence = 1, .state = .rejected } };
    try std.testing.expectError(error.InvalidRequestSnapshot, Ledger.fromSnapshot(allocator, 2, .{ .records = &.{invented} }));
    var issued = invented;
    issued.first.state = .issued;
    var duplicate = issued;
    duplicate.first.issued_sequence = 2;
    try std.testing.expectError(error.DuplicateRequest, Ledger.fromSnapshot(allocator, 2, .{ .records = &.{ issued, duplicate } }));
    var accepted = issued;
    accepted.first.state = .accepted;
    accepted.first.accepted_report = .{ .event = .accepted };
    var restored = try Ledger.fromSnapshot(allocator, 2, .{ .records = &.{accepted} });
    defer restored.deinit();
    restored.recoverAfterRestart();
    try std.testing.expectEqual(Status.unknown, restored.attempt("codex", &fixture_1).?.state);
    try std.testing.expect(restored.attempt("claude", &fixture_1) == null);
    try std.testing.expectError(error.UnsafeReplay, restored.report(&fixture_1, rejection));
    try std.testing.expectError(error.AttemptBudgetExhausted, restored.checkIssue(fixture));
    try std.testing.expect(try restored.report(&fixture_1, .{ .event = .completed }));
    try std.testing.expectError(error.AttemptBudgetExhausted, restored.checkIssue(fixture));
}

test "binding release authority follows issue order across interleaved request alternates" {
    const allocator = std.testing.allocator;
    var ledger = Ledger.init(allocator, 3);
    defer ledger.deinit();
    _ = try ledger.issue(fixture, &fixture_1, "account-a", 1);
    _ = try ledger.report(&fixture_1, rejection);
    var later = fixture;
    later.key.request_id = "later-request";
    _ = try ledger.issue(later, &fixture_2, "account-b", 1);
    _ = try ledger.issue(fixture, &fixture_3, "account-c", 1);
    try std.testing.expectEqualStrings(&fixture_3, ledger.latestHandleForBinding("codex", "binding").?);
    var restored = try Ledger.fromSnapshot(allocator, 3, ledger.snapshot());
    defer restored.deinit();
    restored.recoverAfterRestart();
    try std.testing.expectEqualStrings(&fixture_3, restored.latestHandleForBinding("codex", "binding").?);
    try std.testing.expect(restored.latestHandleForBinding("claude", "binding") == null);
    try std.testing.expectError(error.InvalidTransition, restored.report(&fixture_2, .{ .event = .completed }));
    try std.testing.expectError(error.AttemptBudgetExhausted, restored.checkIssue(fixture));
    // A persisted sequence collision cannot choose an ambiguous retirement head.
    restored.records.items[1].first.issued_sequence = restored.records.items[0].first.issued_sequence;
    try std.testing.expectError(error.InvalidRequestSnapshot, Ledger.fromSnapshot(allocator, 3, restored.snapshot()));
}

test "escaped authority bytes refuse admission before count exhaustion and retain reports on restart" {
    const allocator = std.testing.allocator;
    var ledger = Ledger.init(allocator, maximum_capacity);
    defer ledger.deinit();
    const wide: [4096]u8 = @splat('"');
    const account: [4096]u8 = @splat(0);
    var request_buffer: [64]u8 = undefined;
    var handle_buffer: [64]u8 = undefined;
    var next = fixture;
    next.key.application = &wide;
    next.key.session_id = &wide;
    next.binding_id = &wide;
    var refused = false;
    for (0..maximum_capacity) |index| {
        next.key.request_id = try std.fmt.bufPrint(&request_buffer, "wide-{d}", .{index});
        _ = ledger.checkIssue(next) catch |err| {
            try std.testing.expectEqual(error.RequestLedgerFull, err);
            refused = true;
            break;
        };
        const before = ledger.reservedSnapshotBytes();
        _ = try ledger.checkIssue(next);
        try std.testing.expectEqual(before, ledger.reservedSnapshotBytes());
        const handle = try std.fmt.bufPrint(&handle_buffer, "{x:0>64}", .{index + 1});
        _ = try ledger.issue(next, handle, &account, std.math.minInt(i64));
        // Reports, expiry extremes and restart recovery never consume new byte
        // authority: their largest encoded representation was reserved at issue.
        const issued_bytes = ledger.reservedSnapshotBytes();
        try std.testing.expect(try ledger.report(handle, .{ .event = .accepted, .status = std.math.maxInt(u16) }));
        try std.testing.expect(try ledger.report(handle, .{ .event = .completed, .status = std.math.maxInt(u16) }));
        try std.testing.expectEqual(issued_bytes, ledger.reservedSnapshotBytes());
    }
    try std.testing.expect(refused);
    try std.testing.expect(ledger.records.items.len < maximum_capacity);
    const json = try std.json.Stringify.valueAlloc(allocator, ledger.snapshot(), .{});
    defer allocator.free(json);
    try std.testing.expect(json.len <= ledger.reservedSnapshotBytes());
    try std.testing.expect(ledger.reservedSnapshotBytes() <= maximum_snapshot_bytes);
    const parsed = try std.json.parseFromSlice(Snapshot, allocator, json, .{});
    defer parsed.deinit();
    var restored = try Ledger.fromSnapshot(allocator, maximum_capacity, parsed.value);
    defer restored.deinit();
    restored.recoverAfterRestart();
    try std.testing.expectEqual(ledger.reservedSnapshotBytes(), restored.reservedSnapshotBytes());
    try std.testing.expectError(error.RequestLedgerFull, restored.checkIssue(next));
    const first = restored.records.items[0];
    try std.testing.expect(!(try restored.report(first.first.lease_handle, .{ .event = .completed, .status = std.math.maxInt(u16) })));
    try std.testing.expectError(error.AttemptBudgetExhausted, restored.checkIssue(first.intent));
}

test "future report and alternate widths fit the first and second reservations" {
    var ledger = Ledger.init(std.testing.allocator, 1);
    defer ledger.deinit();
    _ = try ledger.issue(fixture, &fixture_1, "fixture-account-a", std.math.minInt(i64));
    _ = try ledger.report(&fixture_1, rejection);
    ledger.last_sequence = std.math.maxInt(u64) - 1;
    _ = try ledger.issue(fixture, &fixture_2, "fixture-account-b", std.math.maxInt(i64));
    _ = try ledger.report(&fixture_2, .{ .event = .accepted, .status = std.math.maxInt(u16) });
    _ = try ledger.report(&fixture_2, .{ .event = .completed, .status = std.math.maxInt(u16) });
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, ledger.snapshot(), .{});
    defer std.testing.allocator.free(json);
    try std.testing.expect(json.len <= ledger.reservedSnapshotBytes());
    try std.testing.expectError(error.AttemptBudgetExhausted, ledger.checkIssue(fixture));
}

test "invalid UTF8 authority fields reserve the serializer numeric array representation" {
    var ledger = Ledger.init(std.testing.allocator, 1);
    defer ledger.deinit();
    var bytes: [4096]u8 = @splat('x');
    bytes[0] = 255;
    var intent = fixture;
    intent.key.session_id = &bytes;
    _ = try ledger.checkIssue(intent);
    _ = try ledger.issue(intent, &fixture_1, &bytes, 1);
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, ledger.snapshot(), .{});
    defer std.testing.allocator.free(json);
    try std.testing.expect(json.len <= ledger.reservedSnapshotBytes());
    const parsed = try std.json.parseFromSlice(Snapshot, std.testing.allocator, json, .{});
    defer parsed.deinit();
    var restored = try Ledger.fromSnapshot(std.testing.allocator, 1, parsed.value);
    defer restored.deinit();
    try std.testing.expectEqual(ledger.reservedSnapshotBytes(), restored.reservedSnapshotBytes());
    restored.recoverAfterRestart();
    try std.testing.expectError(error.AttemptBudgetExhausted, restored.checkIssue(intent));
}
