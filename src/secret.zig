const std = @import("std");
const types = @import("types.zig");
const paths = @import("paths.zig");
const log = @import("log.zig");
const age = @import("age.zig");
const env = @import("env.zig");
const builtin = @import("builtin");

pub const ReadError = error{
    NotFound,
    AccessDenied,
    DecryptFailed,
    CommandFailed,
    Timeout,
    OutOfMemory,
    IoError,
};

pub const WriteError = error{
    UnsupportedBackend,
    AccessDenied,
    IoError,
    OutOfMemory,
};

pub const WritebackPlan = struct {
    capability: types.SecretWriteCapability,
    automatic_refresh_admitted: bool,
    reason: []const u8,
};

// TIN-2058: the refresh-authority split. Login ownership (RepairOwner) and
// proactive-refresh authority are different axes: a provider whose login is
// upstream-CLI-owned can still grant oauth-mux the non-interactive refresh,
// but only when the provider definition declares the refresh grant AND the
// account's config carries explicit operator consent. Defaults keep today's
// refusal.
pub const RefreshAuthority = struct {
    provider_supports_refresh: bool = false,
    account_opted_in: bool = false,
};

pub fn read(backend: types.SecretBackend, allocator: std.mem.Allocator) ReadError![]const u8 {
    return switch (backend) {
        .keychain => |ref| readKeychain(ref, allocator),
        .env => |ref| readEnv(ref, allocator),
        .file => |ref| readFile(ref, allocator),
        .command => |ref| readCommand(ref, allocator),
        .sops => |ref| readSops(ref, allocator),
        .age => |ref| readAge(ref, allocator),
        .stdin => readStdin(allocator),
    };
}

pub fn writeCapability(backend: types.SecretBackend) types.SecretWriteCapability {
    return switch (backend) {
        .file => .replace_file,
        .command => .command_write,
        .keychain => .keychain_write,
        .sops => .sops_write,
        .env, .stdin => .readonly,
        .age => .unsupported,
    };
}

pub fn writebackPlan(backend: types.SecretBackend, owner: types.RepairOwner, authority: RefreshAuthority) WritebackPlan {
    const capability = writeCapability(backend);
    const authority_granted = switch (owner) {
        .oauth_mux_refresh => true,
        .upstream_cli_login => authority.provider_supports_refresh and authority.account_opted_in,
        // manual_only / external_secret_owner exclude mux writes outright;
        // account consent cannot override an operator/secret-owner boundary.
        .external_secret_owner, .manual_only => false,
    };
    if (!authority_granted) {
        return .{
            .capability = capability,
            .automatic_refresh_admitted = false,
            .reason = switch (owner) {
                .upstream_cli_login => if (authority.provider_supports_refresh)
                    "proactive_refresh_not_opted_in"
                else
                    "provider_repair_owned_by_upstream_cli",
                .external_secret_owner => "provider_repair_owned_by_external_secret",
                .manual_only => "provider_repair_is_manual_only",
                .oauth_mux_refresh => unreachable,
            },
        };
    }

    var plan: WritebackPlan = switch (capability) {
        .replace_file => .{
            .capability = capability,
            .automatic_refresh_admitted = true,
            .reason = "replace_file_writeback_available",
        },
        .readonly => .{
            .capability = capability,
            .automatic_refresh_admitted = false,
            .reason = "secret_backend_is_readonly",
        },
        .command_write => .{
            .capability = capability,
            .automatic_refresh_admitted = false,
            .reason = "command_write_contract_missing",
        },
        // TIN-2070: macOS keychain write is implemented (security
        // add-generic-password -U). Other platforms remain refused until a
        // write path is proven there (Linux secret-tool write is untested).
        .keychain_write => if (comptime builtin.os.tag == .macos) .{
            .capability = capability,
            .automatic_refresh_admitted = true,
            .reason = "keychain_writeback_available",
        } else .{
            .capability = capability,
            .automatic_refresh_admitted = false,
            .reason = "keychain_write_unproven_on_platform",
        },
        .sops_write => .{
            .capability = capability,
            .automatic_refresh_admitted = false,
            .reason = "sops_write_not_implemented",
        },
        .unsupported => .{
            .capability = capability,
            .automatic_refresh_admitted = false,
            .reason = "secret_backend_writeback_unsupported",
        },
    };
    // Consent-granted admission (vs mux-owned repair) is surfaced as its own
    // reason so the audit trail records WHY the write was allowed; the
    // capability field still names the mechanism.
    if (owner != .oauth_mux_refresh and plan.automatic_refresh_admitted) {
        plan.reason = "proactive_refresh_opted_in";
    }
    return plan;
}

pub fn writeReplace(backend: types.SecretBackend, bytes: []const u8, allocator: std.mem.Allocator) WriteError!void {
    return switch (backend) {
        .file => |ref| writeFileReplace(ref, bytes, allocator),
        .keychain => |ref| writeKeychain(ref, bytes, allocator),
        .sops, .age, .env, .command, .stdin => error.UnsupportedBackend,
    };
}

fn readEnv(ref: types.SecretBackend.EnvRef, allocator: std.mem.Allocator) ReadError![]const u8 {
    const val = env.get(allocator, ref.variable) catch return error.OutOfMemory;
    return val orelse {
        log.debug("env: {s} not set", .{ref.variable});
        return error.NotFound;
    };
}

fn readFile(ref: types.SecretBackend.FileRef, allocator: std.mem.Allocator) ReadError![]const u8 {
    const expanded = paths.expandTilde(allocator, ref.path) catch return error.OutOfMemory;
    defer allocator.free(expanded);

    const file = std.fs.openFileAbsolute(expanded, .{}) catch |e| {
        log.debug("file: open {s}: {s}", .{ ref.path, @errorName(e) });
        return switch (e) {
            error.FileNotFound => error.NotFound,
            error.AccessDenied => error.AccessDenied,
            else => error.IoError,
        };
    };
    defer file.close();

    return file.readToEndAlloc(allocator, 4 * 1024 * 1024) catch return error.IoError;
}

fn writeFileReplace(ref: types.SecretBackend.FileRef, bytes: []const u8, allocator: std.mem.Allocator) WriteError!void {
    const expanded = paths.expandTilde(allocator, ref.path) catch return error.OutOfMemory;
    defer allocator.free(expanded);

    if (std.fs.path.dirname(expanded)) |dir| {
        std.fs.cwd().makePath(dir) catch |e| switch (e) {
            error.AccessDenied => return error.AccessDenied,
            else => return error.IoError,
        };
    }

    const tmp_path = std.fmt.allocPrint(allocator, "{s}.tmp-{x}", .{ expanded, std.crypto.random.int(u64) }) catch return error.OutOfMemory;
    defer allocator.free(tmp_path);

    const file = std.fs.createFileAbsolute(tmp_path, .{ .exclusive = true, .mode = 0o600 }) catch |e| switch (e) {
        error.AccessDenied => return error.AccessDenied,
        else => return error.IoError,
    };
    errdefer std.fs.deleteFileAbsolute(tmp_path) catch {};

    {
        defer file.close();
        file.writeAll(bytes) catch return error.IoError;
        file.sync() catch return error.IoError;
    }

    std.fs.renameAbsolute(tmp_path, expanded) catch |e| switch (e) {
        error.AccessDenied => return error.AccessDenied,
        else => return error.IoError,
    };
    syncFileParent(expanded) catch return error.IoError;
}

fn syncFileParent(path: []const u8) !void {
    // std.posix.rename uses MOVEFILE_WRITE_THROUGH on Windows. POSIX needs an
    // explicit directory fsync so a successful credential replacement survives
    // a crash before an in-flight refresh quarantine is cleared.
    if (comptime builtin.os.tag == .windows) return;
    const parent = std.fs.path.dirname(path) orelse return error.InvalidPath;
    var dir = try std.fs.openDirAbsolute(parent, .{ .iterate = true });
    defer dir.close();
    try std.posix.fsync(dir.fd);
}

fn readKeychain(ref: types.SecretBackend.KeychainRef, allocator: std.mem.Allocator) ReadError![]const u8 {
    if (comptime builtin.os.tag == .macos) {
        return readKeychainMacOS(ref, allocator);
    } else if (comptime builtin.os.tag == .linux) {
        return readKeychainLinux(ref, allocator);
    } else {
        log.warn("keychain: not supported on this platform", .{});
        return error.NotFound;
    }
}

fn readKeychainMacOS(ref: types.SecretBackend.KeychainRef, allocator: std.mem.Allocator) ReadError![]const u8 {
    const result = runProcess(allocator, &.{
        "/usr/bin/security",
        "find-generic-password",
        "-s",
        ref.service,
        "-a",
        ref.account,
        "-w",
    }) catch return error.CommandFailed;
    defer if (result.stderr.len > 0) allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) {
            defer allocator.free(result.stdout);
            log.debug("keychain: security exited {d}", .{code});
            return error.NotFound;
        },
        else => {
            allocator.free(result.stdout);
            return error.CommandFailed;
        },
    }

    // Strip trailing newline
    const out = result.stdout;
    if (out.len > 0 and out[out.len - 1] == '\n') {
        const trimmed = allocator.dupe(u8, out[0 .. out.len - 1]) catch return error.OutOfMemory;
        allocator.free(out);
        return trimmed;
    }
    return out;
}

fn readKeychainLinux(ref: types.SecretBackend.KeychainRef, allocator: std.mem.Allocator) ReadError![]const u8 {
    const result = runProcess(allocator, &.{
        "secret-tool",
        "lookup",
        "service",
        ref.service,
        "account",
        ref.account,
    }) catch return error.CommandFailed;
    defer if (result.stderr.len > 0) allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) {
            defer allocator.free(result.stdout);
            return error.NotFound;
        },
        else => {
            allocator.free(result.stdout);
            return error.CommandFailed;
        },
    }
    return result.stdout;
}

// TIN-2070: keychain write for refresh writeback. -U updates the existing
// (service, account) item in place; the account must match the item's acct
// attribute (Claude Code sets the local username) or -U mints a divergent
// second item the CLI never reads. The secret travels as a direct argv
// element — no shell, no quoting, never logged. (It is briefly visible to
// same-user `ps`, the tradeoff TIN-2070 accepted over `security -i` stdin
// quoting fragility.) Known gap for the refresh hot path: runProcess has no
// deadline, so a locked keychain that prompts can wedge the caller — bounded
// waits belong to the TIN-2058/2059 refresh-authority hardening that admits
// this write path in the first place.
fn writeKeychain(ref: types.SecretBackend.KeychainRef, bytes: []const u8, allocator: std.mem.Allocator) WriteError!void {
    if (comptime builtin.os.tag != .macos) return error.UnsupportedBackend;

    const result = runProcess(allocator, &.{
        "/usr/bin/security",
        "add-generic-password",
        "-U",
        "-s",
        ref.service,
        "-a",
        ref.account,
        "-w",
        bytes,
    }) catch return error.IoError;
    defer allocator.free(result.stdout);
    defer if (result.stderr.len > 0) allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) {
            // Log only the exit code; stderr could name the service but the
            // payload never appears in security's output.
            log.debug("keychain: add-generic-password exited {d}", .{code});
            return error.AccessDenied;
        },
        else => return error.IoError,
    }
}

// Test/cleanup helper: best-effort removal of a (service, account) item.
fn deleteKeychainMacOS(ref: types.SecretBackend.KeychainRef, allocator: std.mem.Allocator) void {
    const result = runProcess(allocator, &.{
        "/usr/bin/security",
        "delete-generic-password",
        "-s",
        ref.service,
        "-a",
        ref.account,
    }) catch return;
    allocator.free(result.stdout);
    if (result.stderr.len > 0) allocator.free(result.stderr);
}

fn readCommand(ref: types.SecretBackend.CommandRef, allocator: std.mem.Allocator) ReadError![]const u8 {
    if (ref.argv.len == 0) return error.CommandFailed;

    const result = runProcess(allocator, ref.argv) catch return error.CommandFailed;
    defer if (result.stderr.len > 0) allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) {
            defer allocator.free(result.stdout);
            log.debug("command: exited {d}", .{code});
            return error.CommandFailed;
        },
        else => {
            allocator.free(result.stdout);
            return error.CommandFailed;
        },
    }

    // Strip trailing newline
    const out = result.stdout;
    if (out.len > 0 and out[out.len - 1] == '\n') {
        const trimmed = allocator.dupe(u8, out[0 .. out.len - 1]) catch return error.OutOfMemory;
        allocator.free(out);
        return trimmed;
    }
    return out;
}

fn readSops(ref: types.SecretBackend.SopsRef, allocator: std.mem.Allocator) ReadError![]const u8 {
    // SOPS files are JSON/YAML with encrypted values and a "sops" metadata key.
    // For age-based SOPS, each value is individually age-encrypted.
    // Simplification: shell out to `sops -d` if available, which handles all backends.
    const expanded = paths.expandTilde(allocator, ref.path) catch return error.OutOfMemory;
    defer allocator.free(expanded);

    const result = runProcess(allocator, &.{ "sops", "--decrypt", expanded }) catch {
        log.debug("sops: failed to run sops binary", .{});
        return error.DecryptFailed;
    };
    defer if (result.stderr.len > 0) allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) {
            defer allocator.free(result.stdout);
            log.debug("sops: decrypt exited {d}", .{code});
            return error.DecryptFailed;
        },
        else => {
            allocator.free(result.stdout);
            return error.DecryptFailed;
        },
    }

    // If key_path specified, extract that JSON key from the decrypted output
    if (ref.key_path) |key_path| {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{}) catch {
            return result.stdout; // return raw if not parseable
        };
        defer parsed.deinit();
        defer allocator.free(result.stdout);

        switch (parsed.value) {
            .object => |obj| {
                if (obj.get(key_path)) |val| {
                    switch (val) {
                        .string => |s| return allocator.dupe(u8, s) catch return error.OutOfMemory,
                        else => {},
                    }
                }
            },
            else => {},
        }
        return error.NotFound;
    }

    return result.stdout;
}

fn readAge(ref: types.SecretBackend.AgeRef, allocator: std.mem.Allocator) ReadError![]const u8 {
    const expanded_path = paths.expandTilde(allocator, ref.path) catch return error.OutOfMemory;
    defer allocator.free(expanded_path);

    const expanded_id = paths.expandTilde(allocator, ref.identity) catch return error.OutOfMemory;
    defer allocator.free(expanded_id);

    // Read the encrypted file
    const ciphertext = blk: {
        const file = std.fs.openFileAbsolute(expanded_path, .{}) catch return error.NotFound;
        defer file.close();
        break :blk file.readToEndAlloc(allocator, 4 * 1024 * 1024) catch return error.IoError;
    };
    defer allocator.free(ciphertext);

    // Read the identity (either a file path or inline key)
    const identity_key = if (std.mem.startsWith(u8, expanded_id, "AGE-SECRET-KEY-"))
        expanded_id
    else blk: {
        // Read from identity file, skip comment lines
        const id_file = std.fs.openFileAbsolute(expanded_id, .{}) catch return error.NotFound;
        defer id_file.close();
        const id_contents = id_file.readToEndAlloc(allocator, 4096) catch return error.IoError;
        defer allocator.free(id_contents);

        // Find the AGE-SECRET-KEY line
        var lines = std.mem.splitScalar(u8, id_contents, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (std.mem.startsWith(u8, trimmed, "AGE-SECRET-KEY-")) {
                break :blk allocator.dupe(u8, trimmed) catch return error.OutOfMemory;
            }
        }
        return error.NotFound;
    };

    return age.decryptFile(allocator, ciphertext, identity_key) catch |e| {
        log.debug("age: decrypt failed: {s}", .{@errorName(e)});
        return error.DecryptFailed;
    };
}

fn readStdin(allocator: std.mem.Allocator) ReadError![]const u8 {
    const stdin = std.io.getStdIn();
    return stdin.readToEndAlloc(allocator, 4 * 1024 * 1024) catch return error.IoError;
}

const ProcessResult = struct {
    stdout: []const u8,
    stderr: []const u8,
    term: std.process.Child.Term,
};

fn runProcess(allocator: std.mem.Allocator, argv: []const []const u8) !ProcessResult {
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();

    var stdout_buf = std.ArrayListUnmanaged(u8){};
    var stderr_buf = std.ArrayListUnmanaged(u8){};
    errdefer stdout_buf.deinit(allocator);
    errdefer stderr_buf.deinit(allocator);

    child.collectOutput(allocator, &stdout_buf, &stderr_buf, 1024 * 1024) catch {};
    const term = try child.wait();

    return .{
        .stdout = stdout_buf.toOwnedSlice(allocator) catch &.{},
        .stderr = stderr_buf.toOwnedSlice(allocator) catch &.{},
        .term = term,
    };
}

test "readEnv found" {
    // HOME is always set
    const result = try readEnv(.{ .variable = "HOME" }, std.testing.allocator);
    defer std.testing.allocator.free(result);
    try std.testing.expect(result.len > 0);
}

test "readEnv not found" {
    const result = readEnv(.{ .variable = "OMUX_TEST_NONEXISTENT_VAR_12345" }, std.testing.allocator);
    try std.testing.expectError(error.NotFound, result);
}

test "readFile not found" {
    const result = readFile(.{ .path = "/tmp/omux-test-nonexistent-file" }, std.testing.allocator);
    try std.testing.expectError(error.NotFound, result);
}

test "writeReplace atomically replaces file backend bytes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const target_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(target_path);
    const auth_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/auth.json", .{target_path});
    defer std.testing.allocator.free(auth_path);

    const backend = types.SecretBackend{ .file = .{ .path = auth_path } };
    try writeReplace(backend, "first", std.testing.allocator);
    {
        const read_back = try readFile(.{ .path = auth_path }, std.testing.allocator);
        defer std.testing.allocator.free(read_back);
        try std.testing.expectEqualStrings("first", read_back);
    }

    try writeReplace(backend, "second", std.testing.allocator);
    {
        const read_back = try readFile(.{ .path = auth_path }, std.testing.allocator);
        defer std.testing.allocator.free(read_back);
        try std.testing.expectEqualStrings("second", read_back);
    }
}

test "writeCapability classifies secret backend write surfaces" {
    try std.testing.expect(writeCapability(.{ .file = .{ .path = "/tmp/omux-auth.json" } }) == .replace_file);
    try std.testing.expect(writeCapability(.{ .env = .{ .variable = "OMUX_AUTH" } }) == .readonly);
    try std.testing.expect(writeCapability(.{ .command = .{ .argv = &.{"omux-secret"} } }) == .command_write);
    try std.testing.expect(writeCapability(.{ .keychain = .{ .service = "oauth-mux", .account = "work" } }) == .keychain_write);
    try std.testing.expect(writeCapability(.{ .sops = .{ .path = "/tmp/secrets.yaml" } }) == .sops_write);
    try std.testing.expect(writeCapability(.{ .age = .{ .path = "/tmp/secret.age", .identity = "/tmp/key.txt" } }) == .unsupported);
    try std.testing.expect(writeCapability(.stdin) == .readonly);
}

test "writebackPlan requires oauth-mux refresh ownership" {
    const file_backend = types.SecretBackend{ .file = .{ .path = "/tmp/omux-auth.json" } };
    const admitted = writebackPlan(file_backend, .oauth_mux_refresh, .{});
    try std.testing.expect(admitted.automatic_refresh_admitted);
    try std.testing.expect(admitted.capability == .replace_file);
    try std.testing.expectEqualStrings("replace_file_writeback_available", admitted.reason);

    const upstream_owned = writebackPlan(file_backend, .upstream_cli_login, .{});
    try std.testing.expect(!upstream_owned.automatic_refresh_admitted);
    try std.testing.expect(upstream_owned.capability == .replace_file);
    try std.testing.expectEqualStrings("provider_repair_owned_by_upstream_cli", upstream_owned.reason);

    const env_owned = writebackPlan(.{ .env = .{ .variable = "OMUX_AUTH" } }, .oauth_mux_refresh, .{});
    try std.testing.expect(!env_owned.automatic_refresh_admitted);
    try std.testing.expect(env_owned.capability == .readonly);
    try std.testing.expectEqualStrings("secret_backend_is_readonly", env_owned.reason);
}

test "writebackPlan keychain write is platform-gated" {
    const keychain_backend = types.SecretBackend{ .keychain = .{ .service = "oauth-mux-test", .account = "work" } };
    const plan = writebackPlan(keychain_backend, .oauth_mux_refresh, .{});
    try std.testing.expect(plan.capability == .keychain_write);
    if (comptime builtin.os.tag == .macos) {
        try std.testing.expect(plan.automatic_refresh_admitted);
        try std.testing.expectEqualStrings("keychain_writeback_available", plan.reason);
    } else {
        try std.testing.expect(!plan.automatic_refresh_admitted);
        try std.testing.expectEqualStrings("keychain_write_unproven_on_platform", plan.reason);
    }

    // Ownership still trumps capability: an upstream_cli_login provider
    // with no declared refresh grant (today's builtin claude/codex shape)
    // stays un-admitted even where write works, with the historical reason.
    const upstream = writebackPlan(keychain_backend, .upstream_cli_login, .{});
    try std.testing.expect(!upstream.automatic_refresh_admitted);
    try std.testing.expectEqualStrings("provider_repair_owned_by_upstream_cli", upstream.reason);
}

test "keychain write/read/overwrite/delete round-trip (macOS)" {
    if (comptime builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var nonce: [4]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    const service = try std.fmt.allocPrint(allocator, "oauth-mux-test-keychain-rt-{x}", .{std.fmt.fmtSliceHexLower(&nonce)});
    defer allocator.free(service);
    const ref = types.SecretBackend.KeychainRef{ .service = service, .account = "omux-test" };
    defer deleteKeychainMacOS(ref, allocator);

    const backend = types.SecretBackend{ .keychain = ref };
    // A locked login keychain (headless/SSH context) surfaces as
    // AccessDenied on the first write; that's environmental, not a
    // regression in our argv construction, so skip rather than fail. If the
    // test binary dies before cleanup, the stranded item is clearly named
    // oauth-mux-test-keychain-rt-* and holds only a fixture string.
    writeReplace(backend, "fixture-keychain-rt-v1", allocator) catch |e| switch (e) {
        error.AccessDenied => return error.SkipZigTest,
        else => return e,
    };
    {
        const got = try read(backend, allocator);
        defer allocator.free(got);
        try std.testing.expectEqualStrings("fixture-keychain-rt-v1", got);
    }

    // -U must update the existing item in place, not mint a second one.
    try writeReplace(backend, "fixture-keychain-rt-v2", allocator);
    {
        const got = try read(backend, allocator);
        defer allocator.free(got);
        try std.testing.expectEqualStrings("fixture-keychain-rt-v2", got);
    }

    deleteKeychainMacOS(ref, allocator);
    try std.testing.expectError(error.NotFound, read(backend, allocator));
}

test "writebackPlan refresh-authority split: consent admits refresh under upstream login ownership" {
    const file_backend = types.SecretBackend{ .file = .{ .path = "/tmp/omux-auth.json" } };

    // Opted-in account + provider-declared refresh grant: admitted, with the
    // consent basis in the audit reason; login ownership stays upstream.
    const opted = writebackPlan(file_backend, .upstream_cli_login, .{
        .provider_supports_refresh = true,
        .account_opted_in = true,
    });
    try std.testing.expect(opted.automatic_refresh_admitted);
    try std.testing.expect(opted.capability == .replace_file);
    try std.testing.expectEqualStrings("proactive_refresh_opted_in", opted.reason);

    // Provider supports refresh but the account has not consented: typed
    // refusal that names the missing knob.
    const not_opted = writebackPlan(file_backend, .upstream_cli_login, .{
        .provider_supports_refresh = true,
    });
    try std.testing.expect(!not_opted.automatic_refresh_admitted);
    try std.testing.expectEqualStrings("proactive_refresh_not_opted_in", not_opted.reason);

    // Provider declares no refresh grant: consent alone changes nothing and
    // the historical refusal reason is preserved.
    const unsupported = writebackPlan(file_backend, .upstream_cli_login, .{
        .account_opted_in = true,
    });
    try std.testing.expect(!unsupported.automatic_refresh_admitted);
    try std.testing.expectEqualStrings("provider_repair_owned_by_upstream_cli", unsupported.reason);

    // manual_only / external_secret_owner boundaries are not overridable by
    // account consent.
    const manual = writebackPlan(file_backend, .manual_only, .{
        .provider_supports_refresh = true,
        .account_opted_in = true,
    });
    try std.testing.expect(!manual.automatic_refresh_admitted);
    try std.testing.expectEqualStrings("provider_repair_is_manual_only", manual.reason);

    const external = writebackPlan(file_backend, .external_secret_owner, .{
        .provider_supports_refresh = true,
        .account_opted_in = true,
    });
    try std.testing.expect(!external.automatic_refresh_admitted);
    try std.testing.expectEqualStrings("provider_repair_owned_by_external_secret", external.reason);

    // Consent cannot bypass capability gating: a readonly backend stays
    // refused on capability grounds.
    const readonly = writebackPlan(.{ .env = .{ .variable = "OMUX_AUTH" } }, .upstream_cli_login, .{
        .provider_supports_refresh = true,
        .account_opted_in = true,
    });
    try std.testing.expect(!readonly.automatic_refresh_admitted);
    try std.testing.expectEqualStrings("secret_backend_is_readonly", readonly.reason);

    // TIN-2070 mechanism composes: consent admits the keychain write on
    // macOS and keeps the platform refusal elsewhere.
    const keychain = writebackPlan(.{ .keychain = .{ .service = "oauth-mux-test", .account = "work" } }, .upstream_cli_login, .{
        .provider_supports_refresh = true,
        .account_opted_in = true,
    });
    if (comptime builtin.os.tag == .macos) {
        try std.testing.expect(keychain.automatic_refresh_admitted);
        try std.testing.expectEqualStrings("proactive_refresh_opted_in", keychain.reason);
    } else {
        try std.testing.expect(!keychain.automatic_refresh_admitted);
        try std.testing.expectEqualStrings("keychain_write_unproven_on_platform", keychain.reason);
    }
}
