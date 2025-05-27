// src/logger.zig
// Simple logging for iteration 1

const std = @import("std");
const config = @import("config.zig");

pub const LogLevel = enum(u8) {
    debug = 0,
    info = 1,
    warn = 2,
    err = 3,

    pub fn fromString(s: []const u8) LogLevel {
        if (std.ascii.eqlIgnoreCase(s, "debug")) return .debug;
        if (std.ascii.eqlIgnoreCase(s, "info")) return .info;
        if (std.ascii.eqlIgnoreCase(s, "warn")) return .warn;
        if (std.ascii.eqlIgnoreCase(s, "err") or std.ascii.eqlIgnoreCase(s, "error")) return .err;
        return .info;
    }

    pub fn toString(self: LogLevel) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
        };
    }
};

pub const Logger = struct {
    level: LogLevel,
    format: config.LoggingConfig.LogFormat,
    writer: std.fs.File.Writer,

    pub fn init(logging_config: config.LoggingConfig) Logger {
        return Logger{
            .level = LogLevel.fromString(logging_config.level),
            .format = logging_config.format,
            .writer = std.io.getStdErr().writer(),
        };
    }

    fn shouldLog(self: *const Logger, level: LogLevel) bool {
        return @intFromEnum(level) >= @intFromEnum(self.level);
    }

    fn logMessage(self: *Logger, level: LogLevel, scope: []const u8, message: []const u8) void {
        if (!self.shouldLog(level)) return;

        const timestamp = std.time.milliTimestamp();

        switch (self.format) {
            .json => {
                self.writer.print("{{\"ts\":{},\"level\":\"{s}\",\"scope\":\"{s}\",\"message\":\"{s}\"}}\n", .{ timestamp, level.toString(), scope, message }) catch {};
            },
            .text => {
                self.writer.print("[{}] {s} [{s}] {s}\n", .{ timestamp, level.toString(), scope, message }) catch {};
            },
        }
    }

    pub fn debug(self: *Logger, scope: []const u8, message: []const u8) void {
        self.logMessage(.debug, scope, message);
    }

    pub fn info(self: *Logger, scope: []const u8, message: []const u8) void {
        self.logMessage(.info, scope, message);
    }

    pub fn warn(self: *Logger, scope: []const u8, message: []const u8) void {
        self.logMessage(.warn, scope, message);
    }

    pub fn err(self: *Logger, scope: []const u8, message: []const u8) void {
        self.logMessage(.err, scope, message);
    }

    pub fn debugf(self: *Logger, allocator: std.mem.Allocator, scope: []const u8, comptime fmt: []const u8, args: anytype) void {
        if (!self.shouldLog(.debug)) return;
        const message = std.fmt.allocPrint(allocator, fmt, args) catch return;
        defer allocator.free(message);
        self.debug(scope, message);
    }

    pub fn infof(self: *Logger, allocator: std.mem.Allocator, scope: []const u8, comptime fmt: []const u8, args: anytype) void {
        if (!self.shouldLog(.info)) return;
        const message = std.fmt.allocPrint(allocator, fmt, args) catch return;
        defer allocator.free(message);
        self.info(scope, message);
    }

    pub fn warnf(self: *Logger, allocator: std.mem.Allocator, scope: []const u8, comptime fmt: []const u8, args: anytype) void {
        if (!self.shouldLog(.warn)) return;
        const message = std.fmt.allocPrint(allocator, fmt, args) catch return;
        defer allocator.free(message);
        self.warn(scope, message);
    }

    pub fn errf(self: *Logger, allocator: std.mem.Allocator, scope: []const u8, comptime fmt: []const u8, args: anytype) void {
        if (!self.shouldLog(.err)) return;
        const message = std.fmt.allocPrint(allocator, fmt, args) catch return;
        defer allocator.free(message);
        self.err(scope, message);
    }
};

// Global logger instance
var global_logger: ?Logger = null;

pub fn init(logging_config: config.LoggingConfig) void {
    global_logger = Logger.init(logging_config);
}

// Global convenience functions
pub fn debug(scope: []const u8, message: []const u8) void {
    if (global_logger) |*logger| logger.debug(scope, message);
}

pub fn info(scope: []const u8, message: []const u8) void {
    if (global_logger) |*logger| logger.info(scope, message);
}

pub fn warn(scope: []const u8, message: []const u8) void {
    if (global_logger) |*logger| logger.warn(scope, message);
}

pub fn err(scope: []const u8, message: []const u8) void {
    if (global_logger) |*logger| logger.err(scope, message);
}

pub fn debugf(allocator: std.mem.Allocator, scope: []const u8, comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |*logger| logger.debugf(allocator, scope, fmt, args);
}

pub fn infof(allocator: std.mem.Allocator, scope: []const u8, comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |*logger| logger.infof(allocator, scope, fmt, args);
}

pub fn warnf(allocator: std.mem.Allocator, scope: []const u8, comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |*logger| logger.warnf(allocator, scope, fmt, args);
}

pub fn errf(allocator: std.mem.Allocator, scope: []const u8, comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |*logger| logger.errf(allocator, scope, fmt, args);
}
