//! OS-vault custody of an installation's fixed-length wrapping key.
//!
//! Loading an existing database must never replace a missing or inaccessible
//! key. Grant envelopes retain this public key identity; a new identity is
//! created independently and cannot silently replace a previous root.
const std = @import("std");
const c = @import("c");

pub const key_bytes = 32;
pub const Key = [key_bytes]u8;
pub const installation_root: [:0]const u8 = "installation-v1";

pub const VaultError = error{
    Missing,
    Locked,
    Denied,
    Cancelled,
    Unavailable,
    InvalidKey,
    Conflict,
    BackendFailure,
    InvalidRoot,
};

const Backend = struct {
    context: ?*anyopaque,
    load_fn: *const fn (?*anyopaque, [:0]const u8) VaultError!Key,
    create_fn: *const fn (?*anyopaque, [:0]const u8) VaultError!Key,

    fn load(self: Backend, root_id: [:0]const u8) VaultError!Key {
        return self.load_fn(self.context, root_id);
    }

    fn create(self: Backend, root_id: [:0]const u8) VaultError!Key {
        return self.create_fn(self.context, root_id);
    }
};

fn mapStatus(status: c_int) VaultError!void {
    return switch (status) {
        c.OMUX_VAULT_OK => {},
        c.OMUX_VAULT_MISSING => error.Missing,
        c.OMUX_VAULT_LOCKED => error.Locked,
        c.OMUX_VAULT_DENIED => error.Denied,
        c.OMUX_VAULT_CANCELLED => error.Cancelled,
        c.OMUX_VAULT_UNAVAILABLE => error.Unavailable,
        c.OMUX_VAULT_INVALID_KEY => error.InvalidKey,
        c.OMUX_VAULT_CONFLICT => error.Conflict,
        c.OMUX_VAULT_BACKEND_FAILURE => error.BackendFailure,
        c.OMUX_VAULT_INVALID_ROOT => error.InvalidRoot,
        else => error.BackendFailure,
    };
}

fn nativeLoad(_: ?*anyopaque, root_id: [:0]const u8) VaultError!Key {
    var key: Key = @splat(0);
    defer std.crypto.secureZero(u8, &key);
    try mapStatus(c.omux_vault_load(root_id.ptr, @ptrCast(&key)));
    return key;
}

fn nativeCreate(_: ?*anyopaque, root_id: [:0]const u8) VaultError!Key {
    var key: Key = @splat(0);
    defer std.crypto.secureZero(u8, &key);
    try mapStatus(c.omux_vault_create(root_id.ptr, @ptrCast(&key)));
    return key;
}

const native_backend: Backend = .{
    .context = null,
    .load_fn = nativeLoad,
    .create_fn = nativeCreate,
};

fn validRoot(root_id: []const u8) bool {
    if (root_id.len == 0 or root_id.len > 96) return false;
    for (root_id) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '.' and byte != '-' and byte != '_') return false;
    }
    return true;
}

fn loadOrCreateWith(backend: Backend, root_id: [:0]const u8, existing_database: bool) VaultError!Key {
    if (!validRoot(root_id)) return error.InvalidRoot;
    return backend.load(root_id) catch |failure| switch (failure) {
        error.Missing => {
            if (existing_database) return error.Missing;
            // Creation cannot update an existing root. If another process
            // created it concurrently, read its committed key instead.
            return backend.create(root_id) catch |create_failure| switch (create_failure) {
                error.Conflict => backend.load(root_id),
                else => create_failure,
            };
        },
        else => failure,
    };
}

pub const Vault = struct {
    /// The caller owns returned key material and must securely clear it after
    /// transferring it to the storage owner or when startup fails.
    pub fn load() VaultError!Key {
        return loadRoot(installation_root);
    }

    pub fn loadOrCreate(existing_database: bool) VaultError!Key {
        return loadOrCreateRoot(installation_root, existing_database);
    }

    pub fn loadRoot(root_id: [:0]const u8) VaultError!Key {
        if (!validRoot(root_id)) return error.InvalidRoot;
        return native_backend.load(root_id);
    }

    pub fn loadOrCreateRoot(root_id: [:0]const u8, existing_database: bool) VaultError!Key {
        return loadOrCreateWith(native_backend, root_id, existing_database);
    }

    /// Explicit creation of a different versioned root. Existing root IDs
    /// return Conflict and remain unchanged; database re-encryption and its
    /// key-ID commit belong to the storage transaction, outside this API.
    pub fn createRoot(root_id: [:0]const u8) VaultError!Key {
        if (!validRoot(root_id)) return error.InvalidRoot;
        return native_backend.create(root_id);
    }
};

const FakeVault = struct {
    key: ?Key = null,
    load_error: ?VaultError = null,
    create_error: ?VaultError = null,
    concurrent_key: ?Key = null,
    load_calls: usize = 0,
    create_calls: usize = 0,

    fn backend(self: *FakeVault) Backend {
        return .{ .context = self, .load_fn = fakeLoad, .create_fn = fakeCreate };
    }

    fn fakeLoad(context: ?*anyopaque, _: [:0]const u8) VaultError!Key {
        const self: *FakeVault = @ptrCast(@alignCast(context.?));
        self.load_calls += 1;
        if (self.load_error) |failure| return failure;
        return self.key orelse error.Missing;
    }

    fn fakeCreate(context: ?*anyopaque, _: [:0]const u8) VaultError!Key {
        const self: *FakeVault = @ptrCast(@alignCast(context.?));
        self.create_calls += 1;
        if (self.concurrent_key) |key| {
            self.key = key;
            return error.Conflict;
        }
        if (self.create_error) |failure| return failure;
        if (self.key != null) return error.Conflict;
        const key: Key = @splat(0xa7);
        self.key = key;
        return key;
    }
};

test "missing key for existing database never creates a replacement" {
    var fake: FakeVault = .{};
    try std.testing.expectError(error.Missing, loadOrCreateWith(fake.backend(), installation_root, true));
    try std.testing.expectEqual(@as(usize, 0), fake.create_calls);
}

test "first initialization creates a fixed 32-byte root once" {
    var fake: FakeVault = .{};
    const first = try loadOrCreateWith(fake.backend(), installation_root, false);
    const second = try loadOrCreateWith(fake.backend(), installation_root, false);
    try std.testing.expectEqual(@as(usize, 32), first.len);
    try std.testing.expectEqualSlices(u8, &first, &second);
    try std.testing.expectEqual(@as(usize, 1), fake.create_calls);
}

test "vault custody failures propagate without key creation" {
    const failures = [_]VaultError{ error.Locked, error.Denied, error.Cancelled, error.Unavailable, error.InvalidKey, error.Conflict, error.BackendFailure, error.InvalidRoot };
    for ([_]bool{ false, true }) |existing_database| for (failures) |failure| {
        var fake: FakeVault = .{ .load_error = failure };
        try std.testing.expectError(failure, loadOrCreateWith(fake.backend(), installation_root, existing_database));
        try std.testing.expectEqual(@as(usize, 1), fake.load_calls);
        try std.testing.expectEqual(@as(usize, 0), fake.create_calls);
    };
}

test "creation failures propagate and concurrent creation reads the winner" {
    var failed: FakeVault = .{ .create_error = error.Denied };
    try std.testing.expectError(error.Denied, loadOrCreateWith(failed.backend(), installation_root, false));
    var racing: FakeVault = .{ .concurrent_key = @splat(0x42) };
    const key = try loadOrCreateWith(racing.backend(), installation_root, false);
    try std.testing.expectEqualSlices(u8, &(@as(Key, @splat(0x42))), &key);
    try std.testing.expectEqual(@as(usize, 2), racing.load_calls);
}

test "concurrent creation with missing readback never creates again" {
    // A conflicting create is not permission to regenerate a disappeared
    // winner. An interrupted backend or another writer may have removed it;
    // startup must return the failed read rather than minting another root.
    var fake: FakeVault = .{ .create_error = error.Conflict };
    try std.testing.expectError(error.Missing, loadOrCreateWith(fake.backend(), installation_root, false));
    try std.testing.expectEqual(@as(usize, 2), fake.load_calls);
    try std.testing.expectEqual(@as(usize, 1), fake.create_calls);
    try std.testing.expect(fake.key == null);
}

test "invalid root identity never reaches the vault" {
    var fake: FakeVault = .{};
    try std.testing.expectError(error.InvalidRoot, loadOrCreateWith(fake.backend(), "../replacement", false));
    try std.testing.expectError(error.InvalidRoot, loadOrCreateWith(fake.backend(), "", false));
    try std.testing.expectEqual(@as(usize, 0), fake.load_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.create_calls);
}

test "native bridge statuses are typed and unknown values fail closed" {
    try mapStatus(0);
    try std.testing.expectError(error.Locked, mapStatus(2));
    try std.testing.expectError(error.Cancelled, mapStatus(4));
    try std.testing.expectError(error.BackendFailure, mapStatus(4000));
}
