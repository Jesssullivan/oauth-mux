const std = @import("std");
const types = @import("types.zig");
const paths = @import("paths.zig");
const log = @import("log.zig");
const age = @import("age.zig");
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

fn readEnv(ref: types.SecretBackend.EnvRef, allocator: std.mem.Allocator) ReadError![]const u8 {
    const val = std.posix.getenv(ref.variable) orelse {
        log.debug("env: {s} not set", .{ref.variable});
        return error.NotFound;
    };
    return allocator.dupe(u8, val) catch return error.OutOfMemory;
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
