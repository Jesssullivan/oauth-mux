//! Static, no-libc Linux exec trampoline. The 256-byte ABI1 record is appended
//! by the archive assembler; the compiled template is trusted build input.
//! No cwd change, fork, native-session claim, PATH search or runtime fallback.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const std_options: std.Options = .{
    .signal_stack_size = null,
    .enable_segfault_handler = false,
};
pub const std_options_debug_threaded_io = null;
pub const panic = std.debug.FullPanic(panicRefused);

const Error = error{ Refused, InstanceMismatch };
const machine: u16 = switch (builtin.cpu.arch) {
    .x86_64 => 62,
    .aarch64 => 183,
    else => @compileError("portable launcher supports only declared Linux ELF64 targets"),
};
comptime {
    if (builtin.os.tag != .linux or builtin.link_libc or !builtin.single_threaded or
        builtin.link_mode != .static or builtin.position_independent_executable)
        @compileError("portable launcher must be static, no-libc, single-threaded Linux ET_EXEC");
}

const max_path = 4096;
const max_file = 32 * 1024 * 1024;
const max_entries = 1024 * 1024;
const max_text = 8 * 1024 * 1024;
const record_size = 256;
const magic = "OMUXLNXLAUNCHv1\x00";
const stat_mask: linux.STATX = .{ .TYPE = true, .INO = true, .SIZE = true, .NLINK = true };

fn panicRefused(_: []const u8, _: ?usize) noreturn {
    refused();
}

fn terminalFailure(status: i32) noreturn {
    const message = "Omux portable launcher refused\n";
    // A pipe with no reader must not turn a fixed refusal into SIGPIPE.
    // This mask change happens only on the terminal failure path. If the
    // syscall is denied, omit the diagnostic and still exit with the status.
    var mask = linux.sigemptyset();
    linux.sigaddset(&mask, .PIPE);
    if (linux.errno(linux.sigprocmask(linux.SIG.BLOCK, &mask, null)) == .SUCCESS)
        _ = linux.write(2, message.ptr, message.len);
    linux.exit_group(status);
}

fn refused() noreturn {
    terminalFailure(126);
}

fn checked(result: usize) Error!usize {
    if (linux.errno(result) != .SUCCESS) return error.Refused;
    return result;
}

fn preadExact(fd: linux.fd_t, buffer: []u8, offset: usize) Error!void {
    var used: usize = 0;
    while (used < buffer.len) {
        const result = linux.pread(fd, buffer[used..].ptr, buffer.len - used, @intCast(offset + used));
        if (linux.errno(result) == .INTR) continue;
        const count = try checked(result);
        if (count == 0 or count > buffer.len - used) return error.Refused;
        used += count;
    }
}

fn statFd(fd: linux.fd_t) Error!linux.Statx {
    var value: linux.Statx = undefined;
    _ = try checked(linux.statx(fd, "", linux.AT.EMPTY_PATH, stat_mask, &value));
    if (!value.mask.TYPE or !value.mask.INO or !value.mask.SIZE or !value.mask.NLINK or
        (value.mode & linux.S.IFMT) != linux.S.IFREG or value.nlink == 0)
        return error.Refused;
    return value;
}

fn sameFile(a: linux.Statx, b: linux.Statx) bool {
    return a.ino == b.ino and a.dev_major == b.dev_major and a.dev_minor == b.dev_minor and
        a.size == b.size and a.nlink == b.nlink;
}

// Linux x86_64 and aarch64 use this 120-byte kernel fstatfs ABI. The
// declared target set above excludes ABIs with different word sizes/layouts.
const KernelStatfs = extern struct {
    fs_type: i64,
    block_size: i64,
    blocks: u64,
    blocks_free: u64,
    blocks_available: u64,
    files: u64,
    files_free: u64,
    fsid: [2]i32,
    name_length: i64,
    fragment_size: i64,
    flags: i64,
    spare: [4]i64,
};
comptime {
    if (@sizeOf(KernelStatfs) != 120 or @offsetOf(KernelStatfs, "fs_type") != 0)
        @compileError("unexpected Linux fstatfs ABI");
}

fn procDirectory() Error!linux.fd_t {
    const fd: linux.fd_t = @intCast(try checked(linux.openat(linux.AT.FDCWD, "/proc/self", .{ .DIRECTORY = true, .CLOEXEC = true, .NONBLOCK = true }, 0)));
    errdefer _ = linux.close(fd);
    var filesystem: KernelStatfs = undefined;
    _ = try checked(linux.syscall2(.fstatfs, @intCast(fd), @intFromPtr(&filesystem)));
    if (filesystem.fs_type != 0x9fa0) return error.Refused; // PROC_SUPER_MAGIC
    return fd;
}

fn selfPath(proc_fd: linux.fd_t, buffer: []u8) Error![]const u8 {
    while (true) {
        const result = linux.readlinkat(proc_fd, "exe", buffer.ptr, buffer.len);
        if (linux.errno(result) == .INTR) continue;
        const count = try checked(result);
        if (count == 0 or count >= buffer.len) return error.Refused;
        const path = buffer[0..count];
        if (path[0] != '/' or std.mem.endsWith(u8, path, " (deleted)")) return error.Refused;
        var pieces = std.mem.splitScalar(u8, path[1..], '/');
        while (pieces.next()) |piece| {
            if (piece.len == 0 or std.mem.eql(u8, piece, ".") or std.mem.eql(u8, piece, ".."))
                return error.Refused;
        }
        return path;
    }
}

fn zero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn loaderName(bytes: []const u8) Error![]const u8 {
    const end = std.mem.indexOfScalar(u8, bytes, 0) orelse return error.Refused;
    if (end == 0 or end > 128 or !zero(bytes[end..])) return error.Refused;
    const name = bytes[0..end];
    const first = name[0];
    if (!((first >= 'a' and first <= 'z') or (first >= 'A' and first <= 'Z') or
        (first >= '0' and first <= '9') or first == '_')) return error.Refused;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.Refused;
    for (name) |byte| {
        if (!((byte >= 'a' and byte <= 'z') or (byte >= 'A' and byte <= 'Z') or
            (byte >= '0' and byte <= '9') or byte == '.' or byte == '_' or byte == '+' or byte == '-'))
            return error.Refused;
    }
    return name;
}

const Record = struct {
    role: u8,
    channel: u8,
    loader: []const u8,
};

fn parseRecord(bytes: *const [record_size]u8) Error!Record {
    if (!std.mem.eql(u8, bytes[0..16], magic) or bytes[16] != 1 or
        bytes[17] < 1 or bytes[17] > 3 or bytes[18] > 2 or bytes[19] != 0 or
        std.mem.readInt(u16, bytes[20..22], .little) != machine or
        !zero(bytes[22..32]) or !zero(bytes[161..256])) return error.Refused;
    return .{ .role = bytes[17], .channel = bytes[18], .loader = try loaderName(bytes[32..161]) };
}

fn rootPath(path: []const u8, role: u8) Error![]const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return error.Refused;
    const name = path[slash + 1 ..];
    const valid = switch (role) {
        1 => std.mem.eql(u8, name, "omux") or std.mem.eql(u8, name, "oauth-mux") or
            std.mem.eql(u8, name, "omux-native-host") or std.mem.eql(u8, name, "git-credential-omux"),
        2 => std.mem.eql(u8, name, "omuxd"),
        3 => std.mem.eql(u8, name, "omux-control"),
        else => return error.Refused,
    };
    if (!valid or slash < 5 or !std.mem.endsWith(u8, path[0..slash], "/bin"))
        return error.Refused;
    return path[0 .. slash - 4];
}

// Only generated strings need storage. Arguments and untouched environment
// strings remain the original kernel pointers, including empty strings.
const Strings = struct {
    buffer: [64 * 1024]u8 = undefined,
    used: usize = 0,

    fn make(self: *Strings, parts: []const []const u8) Error![:0]const u8 {
        const start = self.used;
        for (parts) |part| {
            if (part.len >= self.buffer.len - self.used) return error.Refused;
            @memcpy(self.buffer[self.used..][0..part.len], part);
            self.used += part.len;
        }
        if (self.used == self.buffer.len or self.used - start >= max_path + 64)
            return error.Refused;
        self.buffer[self.used] = 0;
        self.used += 1;
        return self.buffer[start .. self.used - 1 :0];
    }
};

fn keyValue(entry: []const u8, key: []const u8) ?[]const u8 {
    if (entry.len > key.len and entry[key.len] == '=' and std.mem.startsWith(u8, entry, key))
        return entry[key.len + 1 ..];
    return null;
}

fn launch(init: std.process.Init.Minimal) Error!void {
    const original = init.args.vector;
    const environment = init.environ.block.slice;
    if (original.len == 0 or original.len > max_entries or environment.len > max_entries)
        return error.Refused;
    var text_bytes: usize = 0;
    for (original) |arg| {
        const size = std.mem.span(arg).len + 1;
        if (size > max_text - text_bytes) return error.Refused;
        text_bytes += size;
    }
    for (environment) |entry| {
        const size = std.mem.span(entry orelse return error.Refused).len + 1;
        if (size > max_text - text_bytes) return error.Refused;
        text_bytes += size;
    }

    const proc_fd = try procDirectory();
    defer _ = linux.close(proc_fd);
    const self_fd: linux.fd_t = @intCast(try checked(linux.openat(proc_fd, "exe", .{ .CLOEXEC = true, .NONBLOCK = true }, 0)));
    defer _ = linux.close(self_fd);
    const self_stat = try statFd(self_fd);
    if (self_stat.size < 64 + record_size or self_stat.size > max_file + record_size)
        return error.Refused;
    var footer: [record_size]u8 = undefined;
    try preadExact(self_fd, &footer, @intCast(self_stat.size - record_size));
    const record = try parseRecord(&footer);
    var elf_header: [64]u8 = undefined;
    try preadExact(self_fd, &elf_header, 0);
    if (!std.mem.eql(u8, elf_header[0..7], "\x7fELF\x02\x01\x01") or
        std.mem.readInt(u16, elf_header[16..18], .little) != 2 or
        std.mem.readInt(u16, elf_header[18..20], .little) != machine)
        return error.Refused;

    var path_buffer: [max_path]u8 = undefined;
    const path = try selfPath(proc_fd, &path_buffer);
    const root = try rootPath(path, record.role);
    var strings: Strings = .{};
    const self_z = try strings.make(&.{path});
    const named_fd: linux.fd_t = @intCast(try checked(linux.openat(linux.AT.FDCWD, self_z.ptr, .{ .CLOEXEC = true, .NOFOLLOW = true, .NONBLOCK = true }, 0)));
    defer _ = linux.close(named_fd);
    if (!sameFile(self_stat, try statFd(named_fd))) return error.Refused;
    var again: [max_path]u8 = undefined;
    if (!std.mem.eql(u8, path, try selfPath(proc_fd, &again))) return error.Refused;

    const prefix_env = try strings.make(&.{ "OMUX_INSTALL_PREFIX=", root });
    const ca_env = try strings.make(&.{ "OMUX_CA_BUNDLE=", root, "/lib/omux/share/ca-bundle.crt" });
    const runtime = try strings.make(&.{ root, if (record.role == 3) "/lib/omux/qt" else "/lib/omux" });
    const library_path = try strings.make(&.{ runtime, "/lib" });
    const loader = try strings.make(&.{ library_path, "/", record.loader });
    const backend = try strings.make(&.{ runtime, "/libexec/", switch (record.role) {
        1 => "omux.bin",
        2 => "omuxd.bin",
        3 => "omux-control.bin",
        else => return error.Refused,
    } });
    const qt_plugins = try strings.make(&.{ "QT_PLUGIN_PATH=", runtime, "/plugins" });
    const qt_platforms = try strings.make(&.{ "QT_QPA_PLATFORM_PLUGIN_PATH=", runtime, "/plugins/platforms" });
    const instance: [:0]const u8 = if (record.channel == 1) "dev" else "default";
    const instance_env: [:0]const u8 = if (record.channel == 1) "OMUX_INSTANCE=dev" else "OMUX_INSTANCE=default";
    const managed_keys = [_][]const u8{
        "OMUX_INSTALL_PREFIX", "OMUX_CA_BUNDLE", "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "OMUX_INSTANCE",
    };
    const managed_values = [_][*:0]const u8{
        prefix_env.ptr, ca_env.ptr, qt_plugins.ptr, qt_platforms.ptr, instance_env.ptr,
    };

    // Kernel-sized input vectors are held in one bounded anonymous allocation.
    // CLOEXEC applies only to our three new file descriptors; inherited descriptors
    // and streams are never enumerated, closed, duplicated or reconfigured.
    const argc = original.len + 7;
    const env_capacity = environment.len + managed_keys.len + 1;
    const mapped_size = (argc + env_capacity) * @sizeOf(?[*:0]const u8);
    const address = try checked(linux.mmap(null, mapped_size, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0));
    const pointers: [*]?[*:0]const u8 = @ptrFromInt(address);
    const argv = pointers[0..argc];
    const envp = pointers[argc .. argc + env_capacity];
    argv[0] = loader.ptr;
    argv[1] = "--inhibit-cache";
    argv[2] = "--library-path";
    argv[3] = library_path.ptr;
    argv[4] = "--argv0";
    argv[5] = original[0];
    argv[6] = backend.ptr;
    for (original[1..], 7..) |arg, index| argv[index] = arg;
    argv[argc - 1] = null;

    var env_count: usize = 0;
    for (environment) |entry_optional| {
        const entry = entry_optional orelse return error.Refused;
        const value = std.mem.span(entry);
        if (keyValue(value, "LD_PRELOAD") != null or keyValue(value, "LD_AUDIT") != null or
            keyValue(value, "LD_LIBRARY_PATH") != null) continue;
        var handled = false;
        for (managed_keys, 0..) |key, index| {
            if ((index == 2 or index == 3) and record.role != 3) continue;
            if (index == 4 and record.channel == 0) continue;
            if (keyValue(value, key)) |old_value| {
                if (index == 4 and !std.mem.eql(u8, old_value, instance)) return error.InstanceMismatch;
                handled = true;
                break;
            }
        }
        if (!handled) {
            envp[env_count] = entry;
            env_count += 1;
        }
    }
    for (managed_keys, 0..) |_, index| {
        if ((index == 2 or index == 3) and record.role != 3) continue;
        if (index == 4 and record.channel == 0) continue;
        envp[env_count] = managed_values[index];
        env_count += 1;
    }
    envp[env_count] = null;
    // Check the name again after preparation. A later same-user rename can still
    // race path resolution; this is a same-user installation, not a privilege
    // boundary. Never substitute a host loader if the packaged path fails.
    if (!sameFile(self_stat, try statFd(named_fd)) or
        !std.mem.eql(u8, path, try selfPath(proc_fd, &again))) return error.Refused;
    _ = linux.execve(loader.ptr, @ptrCast(argv.ptr), @ptrCast(envp.ptr));
    return error.Refused;
}

pub fn main(init: std.process.Init.Minimal) u8 {
    launch(init) catch |err| switch (err) {
        error.Refused => refused(),
        error.InstanceMismatch => terminalFailure(64),
    };
    return 126;
}
