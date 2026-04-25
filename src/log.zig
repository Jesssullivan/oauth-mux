const std = @import("std");

pub const Level = enum {
    debug,
    info,
    warn,
    err,

    fn label(self: Level) []const u8 {
        return switch (self) {
            .debug => "DBG",
            .info => "INF",
            .warn => "WRN",
            .err => "ERR",
        };
    }

    fn color(self: Level) []const u8 {
        return switch (self) {
            .debug => "\x1b[36m",
            .info => "\x1b[32m",
            .warn => "\x1b[33m",
            .err => "\x1b[31m",
        };
    }
};

const reset = "\x1b[0m";

var min_level: Level = .info;
var use_color: bool = true;

pub fn setLevel(level: Level) void {
    min_level = level;
}

pub fn setColor(enabled: bool) void {
    use_color = enabled;
}

pub fn init() void {
    if (std.posix.getenv("OMUX_DEBUG")) |_| {
        min_level = .debug;
    }
    if (std.posix.getenv("NO_COLOR")) |_| {
        use_color = false;
    }
}

pub fn log(level: Level, comptime fmt: []const u8, args: anytype) void {
    if (@intFromEnum(level) < @intFromEnum(min_level)) return;
    const stderr = std.io.getStdErr().writer();
    if (use_color) {
        stderr.print("{s}[{s}]{s} " ++ fmt ++ "\n", .{level.color()} ++ .{level.label()} ++ .{reset} ++ args) catch {};
    } else {
        stderr.print("[{s}] " ++ fmt ++ "\n", .{level.label()} ++ args) catch {};
    }
}

pub fn debug(comptime fmt: []const u8, args: anytype) void {
    log(.debug, fmt, args);
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    log(.info, fmt, args);
}

pub fn warn(comptime fmt: []const u8, args: anytype) void {
    log(.warn, fmt, args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    log(.err, fmt, args);
}
