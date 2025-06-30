// src/proxy.zig - Main proxy server

const std = @import("std");
const logger = @import("logger.zig");
const core = @import("core/context.zig");
const connection = @import("connection.zig");
const config = @import("config.zig");
const uv = @import("utils/uv.zig");
const refcounted = @import("utils/refcounted.zig");
const connection_pool = @import("connection_pool.zig");
const buffer_pool = @import("utils/buffer_pool.zig");
const request_logger = @import("request_logger.zig");
const mtls = @import("mtls/tls.zig");
const ConnectionContext = connection.ConnectionContext;

pub const Proxy = struct {
    gpa: std.mem.Allocator,
    global: *core.GlobalContext,
    tls_server: mtls.TlsServer,

    loop: *uv.Loop,
    server: uv.Tcp,

    upstream_pool: connection_pool.ConnectionPool,
    pool_cleanup_timer: uv.Timer,

    async_logger: request_logger.AsyncRequestLogger,

    total_requests_processed: std.atomic.Value(u64),

    active_connections: std.atomic.Value(u32),
    active_requests: std.atomic.Value(u32), // NEW: track active requests
    accepts_paused: std.atomic.Value(bool),
    last_accept_pause_time: std.atomic.Value(i64),

    const MAX_ACTIVE_CONNECTIONS: u32 = 1000;
    const MAX_ACTIVE_REQUESTS: u32 = 500; // Pause if more than 500 requests
    const RESUME_ACTIVE_REQUESTS: u32 = 400; // Resume when below 400 (not 250!)
    const MIN_PAUSE_DURATION_MS: i64 = 1000; // Minimum pause duration before resuming accepts

    pub fn init(gpa: std.mem.Allocator, global: *core.GlobalContext, tls_config: config.TlsConfig, logging_config: config.LoggingConfig) !Proxy {
        const tls_server = try mtls.TlsServer.init(gpa, tls_config);

        const loop = try gpa.create(uv.Loop);
        loop.* = std.mem.zeroes(uv.Loop);
        try loop.init();

        logger.debug("proxy", "Loop initialized");

        try buffer_pool.initGlobalPool(gpa);

        const server = std.mem.zeroes(uv.Tcp);

        const upstream_pool = connection_pool.ConnectionPool.init(gpa, loop);

        const pool_cleanup_timer = std.mem.zeroes(uv.Timer);

        const async_logger = request_logger.AsyncRequestLogger.init(gpa, loop, logging_config.detailed_logging);

        return Proxy{
            .gpa = gpa,
            .global = global,
            .tls_server = tls_server,
            .loop = loop,
            .server = server,
            .upstream_pool = upstream_pool,
            .pool_cleanup_timer = pool_cleanup_timer,
            .async_logger = async_logger,
            .total_requests_processed = std.atomic.Value(u64).init(0),
            .active_connections = std.atomic.Value(u32).init(0),
            .active_requests = std.atomic.Value(u32).init(0),
            .accepts_paused = std.atomic.Value(bool).init(false),
            .last_accept_pause_time = std.atomic.Value(i64).init(0),
        };
    }

    pub fn deinit(self: *Proxy) void {
        self.tls_server.deinit();
        self.upstream_pool.deinit();
        self.server.safeClose(null);
        self.loop.close();
        self.gpa.destroy(self.loop);
    }

    pub fn run(self: *Proxy) !void {
        try self.server.init(self.loop);

        logger.infof(self.gpa, "proxy", "Refcounted Async TLS Proxy listening on {}", .{self.global.listen_addr});

        self.server.setData(self);

        const test_addr = std.net.Address.parseIp("127.0.0.1", 8443) catch unreachable;
        const bind_result = uv.uv_tcp_bind(@ptrCast(&self.server), &test_addr.any, 0);

        if (bind_result != 0) {
            const error_msg = uv.errorString(bind_result);
            logger.errf(self.gpa, "proxy", "Bind failed with error code {}: {s}", .{ bind_result, error_msg });
            return error.BindFailed;
        }

        const listen_result = uv.uv_listen(@ptrCast(&self.server), 1024, onNewConnection);

        if (listen_result != 0) {
            logger.errf(self.gpa, "proxy", "Listen failed with error: {s}", .{uv.errorString(listen_result)});
            return error.ListenFailed;
        }

        logger.debug("proxy", "Server listening for connections");

        var perf_timer = std.mem.zeroes(uv.Timer);
        try perf_timer.init(self.loop);
        perf_timer.setData(self);
        try perf_timer.start(performanceMonitorCallback, 10000, 10000);

        try self.upstream_pool.startIdleCleanup();

        try self.pool_cleanup_timer.init(self.loop);
        self.pool_cleanup_timer.setData(self);
        try self.pool_cleanup_timer.start(poolCleanupCallback, 60000, 60000);

        try self.server.setSimultaneousAccepts(true);
        var pressure_timer = std.mem.zeroes(uv.Timer);
        try pressure_timer.init(self.loop);
        pressure_timer.setData(self);
        try pressure_timer.start(pressureCheckCallback, 100, 100);

        const final_result = self.loop.run(uv.UV_RUN_DEFAULT);
        logger.debugf(self.gpa, "proxy", "Event loop exited with: {}", .{final_result});

        logger.info("proxy", "Refcounted proxy shutting down");
    }

    fn pressureCheckCallback(handle: *anyopaque) callconv(.C) void {
        const timer: *uv.Timer = @ptrCast(@alignCast(handle));
        const proxy = timer.getData(Proxy) orelse return;
        proxy.checkAcceptPressure();
    }

    fn performanceMonitorCallback(handle: *anyopaque) callconv(.C) void {
        const timer: *uv.Timer = @ptrCast(@alignCast(handle));
        const proxy = timer.getData(Proxy) orelse return;

        const processed = proxy.total_requests_processed.load(.monotonic);
        const active_conns = proxy.active_connections.load(.monotonic);
        const active_reqs = proxy.active_requests.load(.monotonic);
        const paused = proxy.accepts_paused.load(.monotonic);

        logger.infof(proxy.gpa, "proxy", "PERF: processed={}, active_conns={}, active_requests={}, accepts_paused={}", .{ processed, active_conns, active_reqs, paused });
    }

    fn onNewConnection(server_handle: *anyopaque, status: c_int) callconv(.C) void {
        if (status < 0) {
            logger.err("proxy", "Failed to accept connection");
            return;
        }

        const server: *uv.Tcp = @ptrCast(@alignCast(server_handle));
        const proxy = server.getData(Proxy) orelse {
            logger.err("proxy", "Server handle missing proxy data");
            return;
        };

        proxy.acceptConnection() catch |err| {
            logger.errf(proxy.gpa, "proxy", "Failed to accept connection: {}", .{err});
        };
    }

    pub fn checkAcceptPressure(self: *Proxy) void {
        const requests = self.active_requests.load(.monotonic);
        const currently_paused = self.accepts_paused.load(.monotonic);

        // Only pause if we have too many active requests
        const should_pause = requests >= MAX_ACTIVE_REQUESTS;

        // Resume if requests are low enough
        const should_resume = requests < RESUME_ACTIVE_REQUESTS;

        if (should_pause and !currently_paused) {
            self.pauseAccepts();
        } else if (should_resume and currently_paused) {
            // Check minimum pause duration to prevent flapping
            const now = std.time.milliTimestamp();
            const pause_duration = now - self.last_accept_pause_time.load(.monotonic);

            if (pause_duration >= MIN_PAUSE_DURATION_MS) {
                self.resumeAccepts();
            }
        }
    }

    fn pauseAccepts(self: *Proxy) void {
        self.server.setSimultaneousAccepts(false) catch |err| {
            logger.errf(self.gpa, "proxy", "Failed to pause accepts: {}", .{err});
            return;
        };

        self.accepts_paused.store(true, .monotonic);
        self.last_accept_pause_time.store(std.time.milliTimestamp(), .monotonic);

        logger.warnf(self.gpa, "proxy", "Paused accepting new connections (active_conns: {}, active_requests: {})", .{ self.active_connections.load(.monotonic), self.active_requests.load(.monotonic) });
    }

    fn resumeAccepts(self: *Proxy) void {
        self.server.setSimultaneousAccepts(true) catch |err| {
            logger.errf(self.gpa, "proxy", "Failed to resume accepts: {}", .{err});
            return;
        };

        self.accepts_paused.store(false, .monotonic);

        const pause_duration = std.time.milliTimestamp() - self.last_accept_pause_time.load(.monotonic);
        logger.infof(self.gpa, "proxy", "Resumed accepting connections after {}ms pause", .{pause_duration});
    }

    fn acceptConnection(self: *Proxy) !void {
        const connections = self.active_connections.load(.monotonic);
        if (connections >= MAX_ACTIVE_CONNECTIONS) {
            logger.warn("proxy", "Rejecting connection - at maximum capacity");
            return;
        }

        logger.debug("proxy", "Attempting to accept new refcounted connection");

        const ref_conn_ctx = try connection.ConnectionContext.init(self.gpa, self);
        errdefer ref_conn_ctx.release();

        try self.server.accept(&ref_conn_ctx.get().downstream_tcp);

        _ = self.active_connections.fetchAdd(1, .monotonic);

        logger.debug("proxy", "Connection accepted, starting TLS handshake");

        ref_conn_ctx.get().startTlsHandshake();

        ref_conn_ctx.release();

        self.checkAcceptPressure();
    }
};

fn poolCleanupCallback(handle: *anyopaque) callconv(.C) void {
    const timer: *uv.Timer = @ptrCast(@alignCast(handle));
    const proxy = timer.getData(Proxy) orelse return;

    proxy.upstream_pool.closeIdleConnections();
    logger.debug("proxy", "Cleaned up idle connections from pool");
}

pub const WriteContext = struct {
    write_req: uv.WriteReq,
    conn_ref: connection.ConnectionPtr,
    data: []u8,

    pub fn deinit(self: *WriteContext) void {
        if (self.conn_ref.get()) |ref_conn| {
            const conn = ref_conn.get();
            conn.gpa.free(self.data);
            conn.gpa.destroy(self);
        }
        self.conn_ref.deinit();
    }
};

pub fn writeCallback(req: *anyopaque, status: c_int) callconv(.C) void {
    const write_req: *uv.WriteReq = @ptrCast(@alignCast(req));

    if (write_req.getData(WriteContext)) |write_ctx| {
        defer write_ctx.deinit();

        if (write_ctx.conn_ref.get()) |ref_conn| {
            const conn = ref_conn.get();

            if (status < 0) {
                if (uv.isConnectionError(status)) {
                    logger.debugf(conn.gpa, "proxy", "Write failed - connection broken: {s}", .{uv.errorString(status)});
                } else {
                    logger.errf(conn.gpa, "proxy", "Write failed: {s}", .{uv.errorString(status)});
                }

                conn.close();
            }
        }
    }
}
