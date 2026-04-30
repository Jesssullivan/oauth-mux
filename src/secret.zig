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

pub fn writebackPlan(backend: types.SecretBackend, owner: types.RepairOwner) WritebackPlan {
    const capability = writeCapability(backend);
    if (owner != .oauth_mux_refresh) {
        return .{
            .capability = capability,
            .automatic_refresh_admitted = false,
            .reason = switch (owner) {
                .upstream_cli_login => "provider_repair_owned_by_upstream_cli",
                .external_secret_owner => "provider_repair_owned_by_external_secret",
                .manual_only => "provider_repair_is_manual_only",
                .oauth_mux_refresh => unreachable,
            },
        };
    }

    return switch (capability) {
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
        .keychain_write => .{
            .capability = capability,
            .automatic_refresh_admitted = false,
            .reason = "keychain_write_not_implemented",
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
}

pub fn writeReplace(backend: types.SecretBackend, bytes: []const u8, allocator: std.mem.Allocator) WriteError!void {
    return switch (backend) {
        .file => |ref| writeFileReplace(ref, bytes, allocator),
        .keychain, .sops, .age, .env, .command, .stdin => error.UnsupportedBackend,
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

    if (result.term.Exited != 0) {
        defer allocator.free(result.stdout);
        log.debug("keychain: security exited {d}", .{result.term.Exited});
        return error.NotFound;
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

    if (result.term.Exited != 0) {
        defer allocator.free(result.stdout);
        return error.NotFound;
    }
    return result.stdout;
}

fn readCommand(ref: types.SecretBackend.CommandRef, allocator: std.mem.Allocator) ReadError![]const u8 {
    if (ref.argv.len == 0) return error.CommandFailed;

    const result = runProcess(allocator, ref.argv) catch return error.CommandFailed;
    defer if (result.stderr.len > 0) allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        defer allocator.free(result.stdout);
        log.debug("command: exited {d}", .{result.term.Exited});
        return error.CommandFailed;
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

    if (result.term.Exited != 0) {
        defer allocator.free(result.stdout);
        log.debug("sops: decrypt exited {d}", .{result.term.Exited});
        return error.DecryptFailed;
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
    const admitted = writebackPlan(file_backend, .oauth_mux_refresh);
    try std.testing.expect(admitted.automatic_refresh_admitted);
    try std.testing.expect(admitted.capability == .replace_file);
    try std.testing.expectEqualStrings("replace_file_writeback_available", admitted.reason);

    const upstream_owned = writebackPlan(file_backend, .upstream_cli_login);
    try std.testing.expect(!upstream_owned.automatic_refresh_admitted);
    try std.testing.expect(upstream_owned.capability == .replace_file);
    try std.testing.expectEqualStrings("provider_repair_owned_by_upstream_cli", upstream_owned.reason);

    const env_owned = writebackPlan(.{ .env = .{ .variable = "OMUX_AUTH" } }, .oauth_mux_refresh);
    try std.testing.expect(!env_owned.automatic_refresh_admitted);
    try std.testing.expect(env_owned.capability == .readonly);
    try std.testing.expectEqualStrings("secret_backend_is_readonly", env_owned.reason);
}
