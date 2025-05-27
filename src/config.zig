// src/config.zig
const std = @import("std");
const toml = @import("zig-toml");

pub const Config = struct {
    server: ServerConfig,
    tls: TlsConfig,
    upstream: UpstreamConfig,
    logging: LoggingConfig,
    health_check: HealthCheckConfig,
    allocator: std.mem.Allocator,

    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !Config {
        var parser = toml.Parser(RawConfig).init(allocator);
        defer parser.deinit();

        var result = try parser.parseFile(path);
        defer result.deinit();

        return try cloneConfig(allocator, result.value);
    }

    pub fn deinit(self: *const Config) void {
        self.server.deinit(self.allocator);
        self.tls.deinit(self.allocator);
        self.upstream.deinit(self.allocator);
        self.logging.deinit(self.allocator);
        self.health_check.deinit(self.allocator);
    }

    fn cloneConfig(allocator: std.mem.Allocator, raw: RawConfig) !Config {
        return Config{
            .server = try ServerConfig.clone(allocator, raw.server),
            .tls = try TlsConfig.clone(allocator, raw.tls),
            .upstream = try UpstreamConfig.clone(allocator, raw.upstream),
            .logging = try LoggingConfig.clone(allocator, raw.logging),
            .health_check = try HealthCheckConfig.clone(allocator, raw.health_check orelse RawHealthCheckConfig{}),
            .allocator = allocator,
        };
    }
};

const RawConfig = struct {
    server: RawServerConfig,
    tls: RawTlsConfig,
    upstream: RawUpstreamConfig,
    logging: RawLoggingConfig,
    health_check: ?RawHealthCheckConfig = null,
};

const RawServerConfig = struct {
    listen_addr: []const u8,
    health_addr: []const u8,
};

const RawTlsConfig = struct {
    chain_path: []const u8,
    key_path: []const u8,
    root_ca_path: []const u8,
};

const RawUpstreamConfig = struct {
    backends: [][]const u8,
};

const RawLoggingConfig = struct {
    level: []const u8,
    format: []const u8,
    log_response_body: ?bool = null,
    max_logged_body_size: ?usize = null,
    detailed_logging: ?bool = null,
};

const RawHealthCheckConfig = struct {
    interval_seconds: ?u32 = null,
    connection_timeout_ms: ?u32 = null,
};

pub const ServerConfig = struct {
    listen_addr: []const u8,
    health_addr: []const u8,

    fn clone(allocator: std.mem.Allocator, raw: RawServerConfig) !ServerConfig {
        return ServerConfig{
            .listen_addr = try allocator.dupe(u8, raw.listen_addr),
            .health_addr = try allocator.dupe(u8, raw.health_addr),
        };
    }

    fn deinit(self: *const ServerConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.listen_addr);
        allocator.free(self.health_addr);
    }
};

pub const TlsConfig = struct {
    chain_path: []const u8,
    key_path: []const u8,
    root_ca_path: []const u8,

    fn clone(allocator: std.mem.Allocator, raw: RawTlsConfig) !TlsConfig {
        return TlsConfig{
            .chain_path = try allocator.dupe(u8, raw.chain_path),
            .key_path = try allocator.dupe(u8, raw.key_path),
            .root_ca_path = try allocator.dupe(u8, raw.root_ca_path),
        };
    }

    fn deinit(self: *const TlsConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.chain_path);
        allocator.free(self.key_path);
        allocator.free(self.root_ca_path);
    }
};

pub const UpstreamConfig = struct {
    backends: [][]const u8,

    fn clone(allocator: std.mem.Allocator, raw: RawUpstreamConfig) !UpstreamConfig {
        var backends = try allocator.alloc([]const u8, raw.backends.len);
        for (raw.backends, 0..) |backend, i| {
            backends[i] = try allocator.dupe(u8, backend);
        }
        return UpstreamConfig{
            .backends = backends,
        };
    }

    fn deinit(self: *const UpstreamConfig, allocator: std.mem.Allocator) void {
        for (self.backends) |backend| {
            allocator.free(backend);
        }
        allocator.free(self.backends);
    }
};

pub const LoggingConfig = struct {
    level: []const u8,
    format: LogFormat,
    log_response_body: bool,
    max_logged_body_size: usize,
    detailed_logging: bool,

    const DEFAULT_LOG_RESPONSE_BODY = true;
    const DEFAULT_MAX_LOGGED_BODY_SIZE = 1024 * 1024;

    pub const LogFormat = enum {
        text,
        json,

        pub fn fromString(s: []const u8) LogFormat {
            if (std.ascii.eqlIgnoreCase(s, "json")) {
                return .json;
            } else {
                return .text;
            }
        }
    };

    fn clone(allocator: std.mem.Allocator, raw: RawLoggingConfig) !LoggingConfig {
        std.log.info("DEBUG: raw.format = {any}", .{raw.format});
        const format = LogFormat.fromString(raw.format);
        std.log.info("DEBUG: parsed format = {any}", .{format});
        return LoggingConfig{
            .level = try allocator.dupe(u8, raw.level),
            .format = format,
            .log_response_body = raw.log_response_body orelse DEFAULT_LOG_RESPONSE_BODY,
            .max_logged_body_size = raw.max_logged_body_size orelse DEFAULT_MAX_LOGGED_BODY_SIZE,
            .detailed_logging = raw.detailed_logging orelse false,
        };
    }

    fn deinit(self: *const LoggingConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.level);
    }
};

pub const HealthCheckConfig = struct {
    interval_seconds: u32,
    connection_timeout_ms: u32,

    const DEFAULT_INTERVAL_SECONDS = 10;
    const DEFAULT_CONNECTION_TIMEOUT_MS = 1000;

    const MIN_INTERVAL_SECONDS = 1;
    const MAX_INTERVAL_SECONDS = 300;

    fn clone(allocator: std.mem.Allocator, raw: RawHealthCheckConfig) !HealthCheckConfig {
        _ = allocator;

        const interval = raw.interval_seconds orelse DEFAULT_INTERVAL_SECONDS;
        const timeout = raw.connection_timeout_ms orelse DEFAULT_CONNECTION_TIMEOUT_MS;

        const safe_interval = std.math.clamp(interval, MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS);
        const safe_timeout = std.math.clamp(timeout, 100, 30000);

        return HealthCheckConfig{
            .interval_seconds = safe_interval,
            .connection_timeout_ms = safe_timeout,
        };
    }

    fn deinit(self: *const HealthCheckConfig, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
    }
};
