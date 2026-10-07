//! R-N13: bounded structural native custody. Sealed original attribution and
//! fresh socket-derived peer proof are actor preconditions, never JSON flags.
//! These transitions do not issue/replay native effects or reset request keys.
const std = @import("std");
const peer = @import("platform/peer.zig");
const admission = @import("snapshot_admission.zig");
const paths = @import("paths.zig");

pub const maximum_owners = 256;
pub const maximum_attachments = 4096;
pub const maximum_thread_bytes = 256;
pub const OperationId = [64]u8;
pub const OwnerKey = struct {
    owner_id: [32]u8,
    adapter_epoch: u64,
    endpoint_generation: u64,
    pub fn same(self: OwnerKey, other: OwnerKey) bool {
        return std.meta.eql(self, other);
    }
};
pub const NativeRef = struct {
    owner_id: [32]u8,
    adapter_epoch: u64,
    endpoint_generation: u64,
    thread_instance_generation: u64,
    attachment_generation: u64,

    pub fn validate(self: NativeRef) !void {
        if (!nonzero(&self.owner_id) or self.adapter_epoch == 0 or self.endpoint_generation == 0 or self.thread_instance_generation == 0 or self.attachment_generation == 0) return error.InvalidNativeRef;
    }
    pub fn same(self: NativeRef, other: NativeRef) bool {
        return std.meta.eql(self, other);
    }
    pub fn ownerKey(self: NativeRef) OwnerKey {
        return .{ .owner_id = self.owner_id, .adapter_epoch = self.adapter_epoch, .endpoint_generation = self.endpoint_generation };
    }
};
pub const OwnerPhase = enum { open, closing, retired };
pub const AttachmentPhase = enum { pending_registration, attached, pending_detach, unresolved, retired };
pub const UnresolvedFrom = enum { registration, attachment, detachment };
pub const Retirement = enum { none, verified_detach, verified_registration_no_effect };
pub const Owner = struct {
    id: [32]u8,
    application: []const u8,
    adapter_epoch: u64,
    endpoint_generation: u64,
    witness: peer.Witness,
    native_nonce: [32]u8,
    endpoint_path: []const u8,
    phase: OwnerPhase = .open,
    removal_operation: ?OperationId = null,
    pub fn key(self: Owner) OwnerKey {
        return .{ .owner_id = self.id, .adapter_epoch = self.adapter_epoch, .endpoint_generation = self.endpoint_generation };
    }
};
pub const Attachment = struct {
    reference: NativeRef,
    thread_id: []const u8,
    registration_operation: OperationId,
    detach_operation: ?OperationId = null,
    phase: AttachmentPhase = .pending_registration,
    unresolved_from: UnresolvedFrom = .registration,
    retirement: Retirement = .none,
};
pub const Snapshot = struct { version: u32 = 1, owners: []const Owner = &.{}, attachments: []const Attachment = &.{}, removals: []const Removal = &.{} };
pub const Removal = struct { application: []const u8, adapter_epoch: u64, operation: OperationId, phase: enum { pending, retired } = .pending };

fn nonzero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return true;
    return false;
}
pub fn validateOperation(id: OperationId) !void {
    for (id) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return error.InvalidNativeOperation;
}
fn validateRemoval(row: Removal) !void {
    if (row.application.len == 0 or row.application.len > 64 or row.adapter_epoch == 0) return error.InvalidNativeOwner;
    for (row.application) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '_' and byte != '-') return error.InvalidNativeOwner;
    try validateOperation(row.operation);
}
fn validateOwner(owner: Owner) !void {
    if (!nonzero(&owner.id) or !nonzero(&owner.native_nonce) or owner.adapter_epoch == 0 or owner.endpoint_generation == 0 or owner.application.len == 0 or owner.application.len > 64) return error.InvalidNativeOwner;
    for (owner.application) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '_' and byte != '-') return error.InvalidNativeOwner;
    if (owner.endpoint_path.len > 107) return error.InvalidNativeOwner;
    try paths.validateAbsolute(owner.endpoint_path);
    try peer.validateSavedWitness(owner.witness);
    if (owner.removal_operation) |op| try validateOperation(op);
    if ((owner.phase == .open) != (owner.removal_operation == null)) return error.InvalidNativeOwner;
}
fn validateAttachment(row: Attachment) !void {
    try row.reference.validate();
    if (row.thread_id.len == 0 or row.thread_id.len > maximum_thread_bytes) return error.InvalidNativeAttachment;
    try validateOperation(row.registration_operation);
    if (row.detach_operation) |op| try validateOperation(op);
    if ((row.phase == .retired) != (row.retirement != .none)) return error.InvalidNativeAttachment;
    switch (row.phase) {
        .pending_registration => if (row.detach_operation != null or row.unresolved_from != .registration) return error.InvalidNativeAttachment,
        .attached => if (row.detach_operation != null or row.unresolved_from != .attachment) return error.InvalidNativeAttachment,
        .pending_detach => if (row.detach_operation == null or row.unresolved_from != .detachment) return error.InvalidNativeAttachment,
        .retired => switch (row.retirement) {
            .none => return error.InvalidNativeAttachment,
            .verified_detach => if (row.detach_operation == null or row.unresolved_from != .detachment) return error.InvalidNativeAttachment,
            .verified_registration_no_effect => if (row.detach_operation != null or row.unresolved_from != .registration) return error.InvalidNativeAttachment,
        },
        .unresolved => if ((row.unresolved_from == .detachment) != (row.detach_operation != null)) return error.InvalidNativeAttachment,
    }
}

pub const Ledger = struct {
    allocator: std.mem.Allocator,
    owners: std.ArrayList(Owner) = .empty,
    attachments: std.ArrayList(Attachment) = .empty,
    removals: std.ArrayList(Removal) = .empty,

    pub fn init(allocator: std.mem.Allocator) Ledger {
        return .{ .allocator = allocator };
    }
    pub fn deinit(self: *Ledger) void {
        for (self.owners.items) |owner| {
            self.allocator.free(owner.application);
            self.allocator.free(owner.endpoint_path);
        }
        for (self.attachments.items) |row| self.allocator.free(row.thread_id);
        for (self.removals.items) |row| self.allocator.free(row.application);
        self.owners.deinit(self.allocator);
        self.attachments.deinit(self.allocator);
        self.removals.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn snapshot(self: *const Ledger) Snapshot {
        return .{ .owners = self.owners.items, .attachments = self.attachments.items, .removals = self.removals.items };
    }
    pub fn applicationRemoval(self: *const Ledger, application: []const u8, epoch: u64) ?*const Removal {
        for (self.removals.items) |*row| if (row.adapter_epoch == epoch and std.mem.eql(u8, row.application, application)) return row;
        return null;
    }
    pub fn lookupOwner(self: *const Ledger, id: [32]u8) ?*const Owner {
        var found: ?*const Owner = null;
        for (self.owners.items) |*owner| if (std.mem.eql(u8, &owner.id, &id)) {
            if (found != null) return null;
            found = owner;
        };
        return found;
    }
    pub fn lookupOwnerQualified(self: *const Ledger, id: [32]u8, epoch: u64, endpoint_generation: u64) ?*const Owner {
        return self.lookupOwnerKey(.{ .owner_id = id, .adapter_epoch = epoch, .endpoint_generation = endpoint_generation });
    }
    pub fn lookupOwnerKey(self: *const Ledger, key: OwnerKey) ?*const Owner {
        for (self.owners.items) |*owner| if (owner.key().same(key)) return owner;
        return null;
    }
    pub fn lookupOwnerForRef(self: *const Ledger, reference: NativeRef) ?*const Owner {
        return self.lookupOwnerKey(reference.ownerKey());
    }
    fn hasOwnerId(self: *const Ledger, id: [32]u8) bool {
        for (self.owners.items) |owner| if (std.mem.eql(u8, &owner.id, &id)) return true;
        return false;
    }
    pub fn lookupAttachment(self: *const Ledger, reference: NativeRef) ?*const Attachment {
        for (self.attachments.items) |*row| if (row.reference.same(reference)) return row;
        return null;
    }
    fn ownerIndex(self: *const Ledger, id: [32]u8) !usize {
        var found: ?usize = null;
        for (self.owners.items, 0..) |owner, i| if (std.mem.eql(u8, &owner.id, &id)) {
            if (found != null) return error.NativeOwnerAmbiguous;
            found = i;
        };
        return found orelse error.UnknownNativeOwner;
    }
    fn qualifiedOwnerIndex(self: *const Ledger, key: OwnerKey) !usize {
        for (self.owners.items, 0..) |owner, i| if (owner.key().same(key)) return i;
        return error.UnknownNativeOwner;
    }
    fn attachmentIndex(self: *const Ledger, reference: NativeRef) !usize {
        for (self.attachments.items, 0..) |row, i| if (row.reference.same(reference)) return i;
        return error.UnknownNativeAttachment;
    }
    fn appendOwner(self: *Ledger, input: Owner) !void {
        var owned = input;
        owned.application = try self.allocator.dupe(u8, input.application);
        errdefer self.allocator.free(owned.application);
        owned.endpoint_path = try self.allocator.dupe(u8, input.endpoint_path);
        errdefer self.allocator.free(owned.endpoint_path);
        try self.owners.append(self.allocator, owned);
    }
    fn appendAttachment(self: *Ledger, input: Attachment) !void {
        var owned = input;
        owned.thread_id = try self.allocator.dupe(u8, input.thread_id);
        errdefer self.allocator.free(owned.thread_id);
        try self.attachments.append(self.allocator, owned);
    }
    pub fn admitOwner(self: *Ledger, input: Owner) !void {
        try validateOwner(input);
        if (input.phase != .open or input.removal_operation != null) return error.InvalidNativeOwner;
        if (self.lookupOwnerKey(input.key()) != null) return error.NativeOwnerConflict;
        if (self.applicationRemoval(input.application, input.adapter_epoch) != null) return error.NativeRemovalPending;
        for (self.owners.items) |old| {
            if (std.mem.eql(u8, &old.id, &input.id) and old.phase != .retired) return error.NativeOwnerStillLive;
            if (old.adapter_epoch == input.adapter_epoch and std.mem.eql(u8, old.application, input.application) and peer.sameOriginal(old.witness, input.witness) and std.mem.eql(u8, &old.native_nonce, &input.native_nonce) and old.endpoint_generation >= input.endpoint_generation) return error.NativeGenerationConflict;
        }
        if (self.owners.items.len >= maximum_owners) return error.NativeOwnerCapacity;
        try self.appendOwner(input);
    }
    pub fn admitAttachment(self: *Ledger, input: Attachment) !void {
        try validateAttachment(input);
        if (input.phase != .pending_registration or input.unresolved_from != .registration or input.detach_operation != null) return error.InvalidNativeAttachment;
        const owner = self.lookupOwnerForRef(input.reference) orelse return if (self.hasOwnerId(input.reference.owner_id)) error.NativeOwnerMismatch else error.UnknownNativeOwner;
        if (owner.phase != .open or self.applicationRemoval(owner.application, owner.adapter_epoch) != null) return error.NativeRemovalPending;
        if (owner.adapter_epoch != input.reference.adapter_epoch or owner.endpoint_generation != input.reference.endpoint_generation) return error.NativeOwnerMismatch;
        var known_instance = false;
        var greatest_instance: u64 = 0;
        for (self.attachments.items) |row| {
            if (row.reference.same(input.reference)) return error.NativeAttachmentConflict;
            if (row.reference.ownerKey().same(input.reference.ownerKey()) and row.reference.thread_instance_generation == input.reference.thread_instance_generation and !std.mem.eql(u8, row.thread_id, input.thread_id)) return error.NativeGenerationConflict;
            if (row.reference.ownerKey().same(input.reference.ownerKey()) and std.mem.eql(u8, row.thread_id, input.thread_id) and row.reference.thread_instance_generation == input.reference.thread_instance_generation and row.reference.attachment_generation >= input.reference.attachment_generation) return error.NativeGenerationConflict;
            if (row.reference.ownerKey().same(input.reference.ownerKey()) and std.mem.eql(u8, row.thread_id, input.thread_id) and row.phase != .retired) return error.NativeAttachmentPending;
            if (row.reference.ownerKey().same(input.reference.ownerKey())) {
                greatest_instance = @max(greatest_instance, row.reference.thread_instance_generation);
                if (row.reference.thread_instance_generation == input.reference.thread_instance_generation) known_instance = true;
            }
        }
        if (!known_instance and input.reference.thread_instance_generation <= greatest_instance) return error.NativeGenerationConflict;
        if (self.attachments.items.len + self.removals.items.len >= maximum_attachments) return error.NativeAttachmentCapacity;
        try self.appendAttachment(input);
    }
    /// Actor verifies the exact original peer/nonce/ACK before this transition.
    pub fn completeRegistration(self: *Ledger, reference: NativeRef, operation: OperationId) !void {
        const row = &self.attachments.items[try self.attachmentIndex(reference)];
        if (!std.mem.eql(u8, &row.registration_operation, &operation)) return error.NativeOperationMismatch;
        if (row.phase == .attached) return;
        if (row.phase != .pending_registration and !(row.phase == .unresolved and row.unresolved_from == .registration)) return error.InvalidNativeTransition;
        row.phase = .attached;
        row.unresolved_from = .attachment;
    }
    pub fn beginDetach(self: *Ledger, reference: NativeRef, operation: OperationId) !void {
        try validateOperation(operation);
        const row = &self.attachments.items[try self.attachmentIndex(reference)];
        if (row.detach_operation != null) return error.NativeOperationAlreadyPending;
        if (row.phase != .attached and !(row.phase == .unresolved and row.unresolved_from == .attachment)) return error.InvalidNativeTransition;
        row.detach_operation = operation;
        row.phase = .pending_detach;
        row.unresolved_from = .detachment;
    }
    /// Only an exact verified no-effect ACK can close an uncertain registration.
    /// Endpoint absence, timeout and restart never satisfy this precondition.
    pub fn completeRegistrationNoEffect(self: *Ledger, reference: NativeRef, operation: OperationId) !void {
        const row = &self.attachments.items[try self.attachmentIndex(reference)];
        if (!std.mem.eql(u8, &row.registration_operation, &operation)) return error.NativeOperationMismatch;
        if (row.phase == .retired and row.retirement == .verified_registration_no_effect) return;
        if (row.phase != .pending_registration and !(row.phase == .unresolved and row.unresolved_from == .registration)) return error.InvalidNativeTransition;
        row.phase = .retired;
        row.retirement = .verified_registration_no_effect;
    }
    pub fn completeDetach(self: *Ledger, reference: NativeRef, operation: OperationId) !void {
        const row = &self.attachments.items[try self.attachmentIndex(reference)];
        const expected = row.detach_operation orelse return error.InvalidNativeTransition;
        if (!std.mem.eql(u8, &expected, &operation)) return error.NativeOperationMismatch;
        if (row.phase == .retired) return;
        if (row.phase != .pending_detach and !(row.phase == .unresolved and row.unresolved_from == .detachment)) return error.InvalidNativeTransition;
        row.phase = .retired;
        row.retirement = .verified_detach;
    }
    pub fn markUnresolved(self: *Ledger, reference: NativeRef) !void {
        const row = &self.attachments.items[try self.attachmentIndex(reference)];
        switch (row.phase) {
            .pending_registration => row.unresolved_from = .registration,
            .attached => row.unresolved_from = .attachment,
            .pending_detach => row.unresolved_from = .detachment,
            .unresolved, .retired => return,
        }
        row.phase = .unresolved;
    }
    /// No effect dispatch or peer verification follows structural recovery.
    pub fn recoverAfterRestart(self: *Ledger) void {
        for (self.attachments.items) |*row| {
            switch (row.phase) {
                .pending_registration => row.unresolved_from = .registration,
                .attached => row.unresolved_from = .attachment,
                .pending_detach => row.unresolved_from = .detachment,
                .unresolved, .retired => continue,
            }
            row.phase = .unresolved;
        }
    }
    pub fn beginRemoval(self: *Ledger, owner_id: [32]u8, operation: OperationId) !void {
        const key = self.owners.items[try self.ownerIndex(owner_id)].key();
        return self.beginRemovalForOwner(key, operation);
    }
    pub fn beginRemovalForRef(self: *Ledger, reference: NativeRef, operation: OperationId) !void {
        return self.beginRemovalForOwner(reference.ownerKey(), operation);
    }
    pub fn beginRemovalForOwner(self: *Ledger, key: OwnerKey, operation: OperationId) !void {
        try validateOperation(operation);
        const owner = &self.owners.items[try self.qualifiedOwnerIndex(key)];
        if (owner.removal_operation) |expected| {
            if (!std.mem.eql(u8, &expected, &operation)) return error.NativeOperationMismatch;
            return;
        }
        owner.removal_operation = operation;
        owner.phase = .closing;
    }
    /// The application fence is admitted before any detach/setup effect, even
    /// with zero owners. It survives retirement and forbids same-epoch enrollment.
    pub fn beginApplicationRemoval(self: *Ledger, application: []const u8, epoch: u64, operation: OperationId) !void {
        try validateRemoval(.{ .application = application, .adapter_epoch = epoch, .operation = operation });
        if (self.applicationRemoval(application, epoch)) |old| {
            if (!std.mem.eql(u8, &old.operation, &operation)) return error.NativeOperationMismatch;
            return;
        }
        if (self.attachments.items.len + self.removals.items.len >= maximum_attachments) return error.NativeAttachmentCapacity;
        for (self.owners.items) |owner| {
            if (owner.adapter_epoch != epoch or !std.mem.eql(u8, owner.application, application)) continue;
            if (owner.phase == .retired) continue;
            if (owner.removal_operation) |old| if (!std.mem.eql(u8, &old, &operation)) return error.NativeOperationMismatch;
        }
        const owned = try self.allocator.dupe(u8, application);
        errdefer self.allocator.free(owned);
        try self.removals.append(self.allocator, .{ .application = owned, .adapter_epoch = epoch, .operation = operation });
        for (self.owners.items) |*owner| {
            if (owner.adapter_epoch != epoch or !std.mem.eql(u8, owner.application, application)) continue;
            if (owner.phase == .retired) continue;
            owner.removal_operation = operation;
            owner.phase = .closing;
        }
    }
    pub fn completeApplicationRemoval(self: *Ledger, application: []const u8, epoch: u64, operation: OperationId) !void {
        if (!self.removalReady(application, epoch, operation)) return error.NativeRetirementPending;
        for (self.removals.items) |*row| if (row.adapter_epoch == epoch and std.mem.eql(u8, row.application, application)) {
            row.phase = .retired;
            return;
        };
        return error.InvalidNativeTransition;
    }
    pub fn retireOwner(self: *Ledger, owner_id: [32]u8, operation: OperationId) !void {
        const key = self.owners.items[try self.ownerIndex(owner_id)].key();
        return self.retireOwnerForOwner(key, operation);
    }
    pub fn retireOwnerForRef(self: *Ledger, reference: NativeRef, operation: OperationId) !void {
        return self.retireOwnerForOwner(reference.ownerKey(), operation);
    }
    pub fn retireOwnerForOwner(self: *Ledger, key: OwnerKey, operation: OperationId) !void {
        const owner = &self.owners.items[try self.qualifiedOwnerIndex(key)];
        const expected = owner.removal_operation orelse return error.InvalidNativeTransition;
        if (!std.mem.eql(u8, &expected, &operation)) return error.NativeOperationMismatch;
        for (self.attachments.items) |row| if (row.reference.ownerKey().same(key) and row.phase != .retired) return error.NativeRetirementPending;
        owner.phase = .retired;
    }
    /// Structural readiness only. Actor also checks sealed registry, peer ACKs
    /// and surviving request/lease report fences before permitting setup effects.
    pub fn removalReady(self: *const Ledger, application: []const u8, adapter_epoch: u64, operation: OperationId) bool {
        const fence = self.applicationRemoval(application, adapter_epoch) orelse return false;
        if (!std.mem.eql(u8, &fence.operation, &operation)) return false;
        for (self.owners.items) |owner| {
            if (!std.mem.eql(u8, owner.application, application) or owner.adapter_epoch != adapter_epoch) continue;
            if (owner.phase != .retired) return false;
        }
        return true;
    }
    /// All immutable attribution is measured exactly. A conservative Cartesian
    /// ceiling prepays phase/origin/retirement and nullable operation encodings;
    /// it never authorizes those combinations. Retired rows remain forever.
    pub fn reservedSnapshotBytes(self: *const Ledger) !usize {
        var bytes = try admission.countJson(self.snapshot(), admission.maximum_snapshot_bytes);
        const operation: OperationId = @splat('a');
        for (self.owners.items) |owner| {
            if (owner.phase == .retired) continue;
            const actual = try admission.countJson(owner, admission.maximum_snapshot_bytes);
            var widest = actual;
            inline for (@typeInfo(OwnerPhase).@"enum".field_names) |name| {
                var future = owner;
                future.phase = @field(OwnerPhase, name);
                future.removal_operation = operation;
                widest = @max(widest, try admission.countJson(future, admission.maximum_snapshot_bytes));
            }
            bytes = try std.math.add(usize, bytes, widest - actual);
        }
        for (self.attachments.items) |row| {
            if (row.phase == .retired) continue;
            const actual = try admission.countJson(row, admission.maximum_snapshot_bytes);
            var widest = actual;
            inline for (@typeInfo(AttachmentPhase).@"enum".field_names) |name| {
                inline for (@typeInfo(UnresolvedFrom).@"enum".field_names) |origin| {
                    var future = row;
                    future.phase = @field(AttachmentPhase, name);
                    future.unresolved_from = @field(UnresolvedFrom, origin);
                    future.detach_operation = operation;
                    future.retirement = .verified_registration_no_effect;
                    widest = @max(widest, try admission.countJson(future, admission.maximum_snapshot_bytes));
                }
            }
            bytes = try std.math.add(usize, bytes, widest - actual);
        }
        for (self.removals.items) |row| {
            const actual = try admission.countJson(row, admission.maximum_snapshot_bytes);
            var future = row;
            future.phase = .retired;
            bytes = try std.math.add(usize, bytes, (try admission.countJson(future, admission.maximum_snapshot_bytes)) - actual);
        }
        if (bytes > admission.maximum_snapshot_bytes) return error.SnapshotTooLarge;
        return bytes;
    }
    /// Caller verifies v2 independent snapshot commitment first. This validates
    /// structure only and cannot construct a live peer context or resume work.
    pub fn fromSnapshot(allocator: std.mem.Allocator, saved: Snapshot) !Ledger {
        if (saved.version != 1 or saved.owners.len > maximum_owners or saved.attachments.len > maximum_attachments or saved.removals.len > maximum_attachments - saved.attachments.len) return error.InvalidNativeOwnerSnapshot;
        var self = init(allocator);
        errdefer self.deinit();
        for (saved.owners) |owner| {
            try validateOwner(owner);
            if (self.lookupOwnerKey(owner.key()) != null) return error.NativeOwnerConflict;
            for (self.owners.items) |old| if (std.mem.eql(u8, &old.id, &owner.id) and old.phase != .retired and owner.phase != .retired) return error.NativeOwnerStillLive;
            for (self.owners.items) |old| if (old.adapter_epoch == owner.adapter_epoch and old.endpoint_generation == owner.endpoint_generation and std.mem.eql(u8, old.application, owner.application) and peer.sameOriginal(old.witness, owner.witness) and std.mem.eql(u8, &old.native_nonce, &owner.native_nonce)) return error.NativeOwnerConflict;
            try self.appendOwner(owner);
        }
        for (saved.attachments) |row| {
            try validateAttachment(row);
            const owner = self.lookupOwnerForRef(row.reference) orelse return if (self.hasOwnerId(row.reference.owner_id)) error.NativeOwnerMismatch else error.UnknownNativeOwner;
            if (owner.adapter_epoch != row.reference.adapter_epoch or owner.endpoint_generation != row.reference.endpoint_generation or (owner.phase == .retired and row.phase != .retired)) return error.NativeOwnerMismatch;
            if (self.lookupAttachment(row.reference) != null) return error.NativeAttachmentConflict;
            for (self.attachments.items) |previous| if (previous.reference.ownerKey().same(row.reference.ownerKey()) and std.mem.eql(u8, previous.thread_id, row.thread_id) and previous.reference.thread_instance_generation == row.reference.thread_instance_generation and previous.reference.attachment_generation == row.reference.attachment_generation) return error.NativeGenerationConflict;
            for (self.attachments.items) |previous| if (previous.reference.ownerKey().same(row.reference.ownerKey()) and previous.reference.thread_instance_generation == row.reference.thread_instance_generation and !std.mem.eql(u8, previous.thread_id, row.thread_id)) return error.NativeGenerationConflict;
            for (self.attachments.items) |previous| if (previous.reference.ownerKey().same(row.reference.ownerKey()) and std.mem.eql(u8, previous.thread_id, row.thread_id) and previous.phase != .retired and row.phase != .retired) return error.NativeAttachmentPending;
            try self.appendAttachment(row);
        }
        for (saved.removals) |row| {
            try validateRemoval(row);
            if (self.applicationRemoval(row.application, row.adapter_epoch) != null) return error.NativeOwnerConflict;
            for (self.owners.items) |owner| {
                if (owner.adapter_epoch != row.adapter_epoch or !std.mem.eql(u8, owner.application, row.application)) continue;
                if (owner.phase == .retired) continue;
                const operation = owner.removal_operation orelse return error.InvalidNativeOwnerSnapshot;
                if (!std.mem.eql(u8, &operation, &row.operation) or owner.phase == .open or (row.phase == .retired and owner.phase != .retired)) return error.InvalidNativeOwnerSnapshot;
            }
            const application = try allocator.dupe(u8, row.application);
            errdefer allocator.free(application);
            try self.removals.append(allocator, .{ .application = application, .adapter_epoch = row.adapter_epoch, .operation = row.operation, .phase = row.phase });
        }
        _ = try self.reservedSnapshotBytes();
        return self;
    }
};
