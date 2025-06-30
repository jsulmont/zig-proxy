// src/connection_pool.zig - HTTP connection pooling with async DNS resolution and reference counting
const std = @import("std");
const logger = @import("logger.zig");
const uv = @import("utils/uv.zig");
const http = @import("http.zig");
const types = @import("core/types.zig");
const refcounted = @import("utils/refcounted.zig");
const buffer_pool = @import("utils/buffer_pool.zig");

const POOL_MIN_SIZE_PER_HOST = 300;
const POOL_MAX_SIZE_PER_HOST = 3000;
const POOL_GROWTH_THRESHOLD = 0.8;
const CONNECTION_IDLE_TIMEOUT_MS = 5000;
const CONNECTION_MAX_REQUESTS = 10000;

// Reference counted types
pub const RefPooledConnection = refcounted.Ref(PooledConnection);
pub const PooledConnectionPtr = refcounted.RefPtr(RefPooledConnection);

pub const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    loop: *uv.Loop,
    pools: std.HashMap([]const u8, *HostPool, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    idle_cleanup_timer: uv.Timer,

    pub fn init(allocator: std.mem.Allocator, loop: *uv.Loop) ConnectionPool {
        return ConnectionPool{
            .allocator = allocator,
            .loop = loop,
            .pools = std.HashMap([]const u8, *HostPool, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .idle_cleanup_timer = std.mem.zeroes(uv.Timer),
        };
    }

    pub fn startIdleCleanup(self: *ConnectionPool) !void {
        try self.idle_cleanup_timer.init(self.loop);
        self.idle_cleanup_timer.setData(self);
        try self.idle_cleanup_timer.start(idleCleanupCallback, 5000, 5000);
        logger.debug("pool", "Idle connection cleanup timer started (5s interval)");
    }

    pub fn deinit(self: *ConnectionPool) void {
        self.idle_cleanup_timer.stop();
        self.idle_cleanup_timer.safeClose(null);

        var iterator = self.pools.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.pools.deinit();
    }

    /// REFCOUNTED: Get a reference counted pooled connection
    pub fn getConnection(self: *ConnectionPool, host: []const u8, port: u16) !*RefPooledConnection {
        const host_key = try std.fmt.allocPrint(self.allocator, "{s}:{}", .{ host, port });

        const host_pool = blk: {
            if (self.pools.get(host_key)) |pool| {
                self.allocator.free(host_key);
                break :blk pool;
            } else {
                const new_pool = try self.allocator.create(HostPool);
                new_pool.* = try HostPool.init(self.allocator, self.loop, host, port);
                try self.pools.put(host_key, new_pool);
                break :blk new_pool;
            }
        };

        return host_pool.borrowConnection();
    }

    /// REFCOUNTED: Return a connection to the pool (now takes reference)
    pub fn returnConnection(self: *ConnectionPool, ref_conn: *RefPooledConnection) void {
        _ = self;
        const conn = ref_conn.get();
        conn.host_pool.returnConnection(ref_conn);
    }

    pub fn closeIdleConnections(self: *ConnectionPool) void {
        var iterator = self.pools.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.closeIdleConnections();
        }
    }

    fn idleCleanupCallback(handle: *anyopaque) callconv(.C) void {
        const timer: *uv.Timer = @ptrCast(@alignCast(handle));
        const pool = timer.getData(ConnectionPool) orelse return;

        pool.closeIdleConnections();
        logger.debug("pool", "Idle connection cleanup completed");
    }
};

const HostPool = struct {
    allocator: std.mem.Allocator,
    loop: *uv.Loop,
    host: []const u8,
    port: u16,

    is_growing: bool = false,

    // REFCOUNTED: Store reference counted connections
    available: std.ArrayList(*RefPooledConnection),
    in_use: std.ArrayList(*RefPooledConnection),
    total_connections: u32,
    max_pool_size: u32,

    // DNS cache for this host
    resolved_addr: ?std.net.Address = null,
    dns_resolving: bool = false,
    dns_pending_requests: std.ArrayList(*RefPooledConnection),

    pub fn init(allocator: std.mem.Allocator, loop: *uv.Loop, host: []const u8, port: u16) !HostPool {
        return HostPool{
            .allocator = allocator,
            .loop = loop,
            .host = try allocator.dupe(u8, host),
            .port = port,
            .available = std.ArrayList(*RefPooledConnection).init(allocator),
            .in_use = std.ArrayList(*RefPooledConnection).init(allocator),
            .total_connections = 0,
            .max_pool_size = POOL_MIN_SIZE_PER_HOST,
            .dns_pending_requests = std.ArrayList(*RefPooledConnection).init(allocator),
        };
    }

    pub fn deinit(self: *HostPool) void {
        // REFCOUNTED: Release all connection references
        for (self.available.items) |ref_conn| {
            ref_conn.get().close();
            ref_conn.release();
        }
        for (self.in_use.items) |ref_conn| {
            ref_conn.get().close();
            ref_conn.release();
        }
        for (self.dns_pending_requests.items) |ref_conn| {
            ref_conn.get().handleDnsError("Pool shutting down");
            ref_conn.release();
        }

        self.available.deinit();
        self.in_use.deinit();
        self.dns_pending_requests.deinit();
        self.allocator.free(self.host);
    }

    /// REFCOUNTED: Borrow a connection, returns reference counted connection
    pub fn borrowConnection(self: *HostPool) !*RefPooledConnection {
        self.adjustPoolSize();

        // Try to reuse an available connection
        while (self.available.items.len > 0) {
            const ref_conn = self.available.orderedRemove(self.available.items.len - 1);
            const conn = ref_conn.get();

            if (conn.isHealthy() and conn.quickHealthCheck()) {
                try self.in_use.append(ref_conn);
                conn.last_used = std.time.milliTimestamp();
                logger.debugf(self.allocator, "pool", "Reusing validated refcounted connection to {s}:{} (available: {}, in_use: {}, max: {})", .{ self.host, self.port, self.available.items.len, self.in_use.items.len, self.max_pool_size });
                return ref_conn; // Return the reference (caller owns it now)
            } else {
                logger.debugf(self.allocator, "pool", "Discarding unhealthy refcounted connection to {s}:{}", .{ self.host, self.port });
                conn.close();
                ref_conn.release(); // Release our reference
                self.total_connections -= 1;
            }
        }

        // Create new connection if under limit
        if (self.total_connections < self.max_pool_size) {
            const ref_conn = try self.createConnection();
            try self.in_use.append(ref_conn.retain()); // Keep one reference for pool tracking
            self.total_connections += 1;
            logger.debugf(self.allocator, "pool", "Created new refcounted connection to {s}:{} (total: {}, max: {})", .{ self.host, self.port, self.total_connections, self.max_pool_size });
            return ref_conn; // Return reference to caller
        }

        // Pool exhausted - create temporary connection (not tracked in pool)
        const temp_conn = try self.createConnection();
        logger.debugf(self.allocator, "pool", "Pool exhausted - creating temporary connection to {s}:{}", .{ self.host, self.port });
        return temp_conn;
    }

    fn adjustPoolSize(self: *HostPool) void {
        const in_use_count = self.in_use.items.len;
        const usage_ratio = if (self.max_pool_size > 0)
            @as(f32, @floatFromInt(in_use_count)) / @as(f32, @floatFromInt(self.max_pool_size))
        else
            0.0;

        if (usage_ratio > POOL_GROWTH_THRESHOLD and self.max_pool_size < POOL_MAX_SIZE_PER_HOST and !self.is_growing) {
            const new_size = @min(self.max_pool_size * 2, POOL_MAX_SIZE_PER_HOST);
            if (new_size != self.max_pool_size) {
                self.is_growing = true;
                logger.debugf(self.allocator, "pool", "Growing pool for {s}:{} from {} to {} (usage: {:.1}%)", .{ self.host, self.port, self.max_pool_size, new_size, usage_ratio * 100.0 });
                self.max_pool_size = new_size;
                self.is_growing = false;
            }
        } else if (usage_ratio < 0.2 and self.max_pool_size > POOL_MIN_SIZE_PER_HOST) {
            const new_size = @max(self.max_pool_size / 2, POOL_MIN_SIZE_PER_HOST);
            if (new_size != self.max_pool_size) {
                logger.debugf(self.allocator, "pool", "Shrinking pool for {s}:{} from {} to {} (usage: {:.1}%)", .{ self.host, self.port, self.max_pool_size, new_size, usage_ratio * 100.0 });
                self.max_pool_size = new_size;
            }
        }
    }

    /// REFCOUNTED: Return a connection to the pool
    pub fn returnConnection(self: *HostPool, ref_conn: *RefPooledConnection) void {
        const conn = ref_conn.get();

        // Remove from in_use list
        for (self.in_use.items, 0..) |in_use_conn, i| {
            if (in_use_conn == ref_conn) {
                _ = self.in_use.orderedRemove(i);
                break;
            }
        }

        if (conn.request_count >= CONNECTION_MAX_REQUESTS) {
            logger.debugf(self.allocator, "pool", "Closing refcounted connection to {s}:{} - max requests reached ({})", .{ self.host, self.port, conn.request_count });
            conn.close();
            ref_conn.release(); // Release pool's reference
            self.total_connections -= 1;
            return;
        }

        if (conn.isHealthy() and conn.quickHealthCheck()) {
            self.available.append(ref_conn) catch {
                conn.close();
                ref_conn.release(); // Release pool's reference
                self.total_connections -= 1;
                return;
            };
            logger.debugf(self.allocator, "pool", "Returned refcounted connection to {s}:{} (available: {}, in_use: {})", .{ self.host, self.port, self.available.items.len, self.in_use.items.len });
        } else {
            conn.close();
            ref_conn.release(); // Release pool's reference
            self.total_connections -= 1;
            logger.debugf(self.allocator, "pool", "Closed unhealthy refcounted connection to {s}:{} (total: {})", .{ self.host, self.port, self.total_connections });
        }
    }

    pub fn closeIdleConnections(self: *HostPool) void {
        const now = std.time.milliTimestamp();
        var i: usize = 0;
        var closed_count: u32 = 0;

        while (i < self.available.items.len) {
            const ref_conn = self.available.items[i];
            const conn = ref_conn.get();

            // Safe integer arithmetic to prevent overflow
            const connection_age = if (now >= conn.last_used)
                now - conn.last_used
            else
                0; // Handle clock skew/wraparound

            if (connection_age > CONNECTION_IDLE_TIMEOUT_MS) {
                _ = self.available.orderedRemove(i);
                conn.close();
                ref_conn.release(); // Release pool's reference
                if (self.total_connections > 0) {
                    self.total_connections -= 1;
                }
                closed_count += 1;
            } else {
                i += 1;
            }
        }

        if (closed_count > 0) {
            logger.debugf(self.allocator, "pool", "Closed {} idle refcounted connections to {s}:{}", .{ closed_count, self.host, self.port });
        }
    }

    /// REFCOUNTED: Create a new reference counted connection
    fn createConnection(self: *HostPool) !*RefPooledConnection {
        return PooledConnection.init(self.allocator, self.loop, self);
    }

    // ASYNC DNS RESOLUTION METHODS
    pub fn resolveHost(self: *HostPool, ref_conn: *RefPooledConnection) !void {
        const conn = ref_conn.get();

        // Check if we already have the address cached
        if (self.resolved_addr) |addr| {
            conn.resolved_addr = addr;
            try conn.startConnectWithResolvedAddr();
            return;
        }

        // Check if DNS resolution is already in progress
        if (self.dns_resolving) {
            try self.dns_pending_requests.append(ref_conn.retain()); // Keep reference while pending
            logger.debugf(self.allocator, "pool", "Queuing refcounted connection for {s}:{} - DNS resolution in progress", .{ self.host, self.port });
            return;
        }

        // Start DNS resolution
        self.dns_resolving = true;
        try self.dns_pending_requests.append(ref_conn.retain()); // Keep reference while pending

        logger.debugf(self.allocator, "pool", "Starting async DNS resolution for {s}", .{self.host});

        // Try to parse as IP first (fast path)
        if (std.net.Address.parseIp(self.host, self.port)) |addr| {
            // It's already an IP address
            self.resolved_addr = addr;
            self.dns_resolving = false;
            self.processPendingDnsRequests(null);
            return;
        } else |_| {
            // It's a hostname, need async DNS lookup
            try self.startAsyncDnsLookup();
        }
    }

    fn startAsyncDnsLookup(self: *HostPool) !void {
        const dns_req = try self.allocator.create(uv.GetAddrInfoReq);
        dns_req.* = uv.GetAddrInfoReq.init();
        dns_req.setData(self);

        const hostname_z = try self.allocator.dupeZ(u8, self.host);
        defer self.allocator.free(hostname_z);

        const port_str = try std.fmt.allocPrintZ(self.allocator, "{}", .{self.port});
        defer self.allocator.free(port_str);

        const result = uv.uv_getaddrinfo(
            @ptrCast(self.loop),
            @ptrCast(dns_req),
            dnsResolveCallback,
            hostname_z.ptr,
            port_str.ptr,
            null, // hints
        );

        if (result != 0) {
            self.allocator.destroy(dns_req);
            self.dns_resolving = false;
            logger.errf(self.allocator, "pool", "Failed to start DNS lookup for {s}: {s}", .{ self.host, uv.errorString(result) });

            const error_msg = "DNS lookup failed";
            self.processPendingDnsRequests(error_msg);
            return error.DnsLookupFailed;
        }
    }

    fn dnsResolveCallback(req: *anyopaque, status: c_int, res: ?*uv.AddrInfo) callconv(.C) void {
        const dns_req: *uv.GetAddrInfoReq = @ptrCast(@alignCast(req));
        const self = dns_req.getData(HostPool) orelse return;

        defer {
            self.allocator.destroy(dns_req);
            self.dns_resolving = false;
        }

        if (status != 0) {
            logger.errf(self.allocator, "pool", "DNS resolution failed for {s}: {s}", .{ self.host, uv.errorString(status) });
            const error_msg = "DNS resolution failed";
            self.processPendingDnsRequests(error_msg);
            return;
        }

        const addr_info = res orelse {
            logger.errf(self.allocator, "pool", "DNS resolution returned no results for {s}", .{self.host});
            const error_msg = "No DNS results";
            self.processPendingDnsRequests(error_msg);
            return;
        };

        // Use the first address result
        if (addr_info.addr) |sockaddr| {
            // Convert sockaddr to std.net.Address
            self.resolved_addr = std.net.Address.initPosix(@alignCast(sockaddr));

            // Override port (getaddrinfo might not set it correctly)
            var addr = self.resolved_addr.?;
            addr.setPort(self.port);
            self.resolved_addr = addr;

            logger.debugf(self.allocator, "pool", "DNS resolved {s} -> {}", .{ self.host, self.resolved_addr.? });

            // Process all pending requests
            self.processPendingDnsRequests(null);
        } else {
            logger.errf(self.allocator, "pool", "DNS resolution returned invalid address for {s}", .{self.host});
            const error_msg = "Invalid DNS address";
            self.processPendingDnsRequests(error_msg);
        }

        // Free the address info
        if (res) |addr_res| {
            uv.uv_freeaddrinfo(addr_res);
        }
    }

    fn processPendingDnsRequests(self: *HostPool, error_message: ?[]const u8) void {
        while (self.dns_pending_requests.items.len > 0) {
            const ref_conn = self.dns_pending_requests.orderedRemove(0);
            const conn = ref_conn.get();

            if (error_message) |err_msg| {
                // DNS failed, notify the connection
                conn.handleDnsError(err_msg);
            } else if (self.resolved_addr) |addr| {
                // DNS succeeded, start connection
                conn.resolved_addr = addr;
                conn.startConnectWithResolvedAddr() catch |err| {
                    logger.errf(self.allocator, "pool", "Failed to start connection after DNS resolution: {}", .{err});
                    conn.handleError();
                };
            } else {
                // This shouldn't happen
                conn.handleDnsError("Internal DNS error");
            }

            ref_conn.release();
        }
    }
};

/// REFCOUNTED: Pooled connection with safe lifecycle management
pub const PooledConnection = struct {
    allocator: std.mem.Allocator,
    host_pool: *HostPool,

    tcp: *uv.Tcp,
    state: ConnectionState,
    last_used: i64,
    request_count: u32,
    connection_failed: bool = false,

    // DNS resolution
    resolved_addr: ?std.net.Address = null,

    // REFCOUNTED: Store request contexts with references
    pending_requests: std.ArrayList(PendingRequest),
    current_request: ?PendingRequest = null,

    const ConnectionState = enum {
        disconnected,
        resolving_dns,
        connecting,
        connected,
        failed,
    };

    /// REFCOUNTED: Request context that holds references to prevent use-after-free
    const PendingRequest = struct {
        request_data: []u8,
        callback: *const fn (*anyopaque, []const u8) void,
        context: *anyopaque,

        pub fn deinit(self: *PendingRequest, allocator: std.mem.Allocator) void {
            allocator.free(self.request_data);
        }
    };

    /// REFCOUNTED: Create a new reference counted pooled connection
    pub fn init(allocator: std.mem.Allocator, loop: *uv.Loop, host_pool: *HostPool) !*RefPooledConnection {
        const tcp = try allocator.create(uv.Tcp);
        tcp.* = std.mem.zeroes(uv.Tcp);
        try tcp.init(loop);

        tcp.keepAlive(true, 30) catch |err| {
            logger.warnf(allocator, "pool", "Failed to enable keep-alive: {}", .{err});
        };

        const conn = PooledConnection{
            .allocator = allocator,
            .host_pool = host_pool,
            .tcp = tcp,
            .state = .disconnected,
            .last_used = std.time.milliTimestamp(),
            .request_count = 0,
            .pending_requests = std.ArrayList(PendingRequest).init(allocator),
        };

        // Create reference counted wrapper
        const ref_conn = try RefPooledConnection.init(allocator, conn);

        // REFCOUNTED: Store reference in TCP handle
        tcp.setData(ref_conn.retain());

        return ref_conn;
    }

    /// REFCOUNTED: Safe cleanup when reference count reaches zero
    pub fn deinit(self: *PooledConnection) void {
        logger.debug("pool", "Cleaning up refcounted pooled connection");

        // Clean up all pending requests
        for (self.pending_requests.items) |*request| {
            request.deinit(self.allocator);
        }
        self.pending_requests.deinit();

        if (self.current_request) |*request| {
            request.deinit(self.allocator);
        }

        self.allocator.destroy(self.tcp);
    }

    /// REFCOUNTED: Execute request with safe context management
    pub fn executeRequest(self: *PooledConnection, request_data: []const u8, callback: *const fn (*anyopaque, []const u8) void, context: *anyopaque) !void {
        const pending_request = PendingRequest{
            .request_data = try self.allocator.dupe(u8, request_data),
            .callback = callback,
            .context = context,
        };

        switch (self.state) {
            .connected => {
                self.current_request = pending_request;
                try self.sendRequest();
            },
            .connecting => {
                try self.pending_requests.append(pending_request);
            },
            .disconnected, .failed => {
                try self.pending_requests.append(pending_request);
                try self.connect();
            },
            .resolving_dns => {
                try self.pending_requests.append(pending_request);
            },
        }
    }

    fn connect(self: *PooledConnection) !void {
        if (self.state == .connecting or self.state == .resolving_dns) return;

        // Get our reference from TCP handle for DNS resolution
        const our_ref = if (self.tcp.getData(RefPooledConnection)) |ref|
            ref
        else
            return error.NoConnectionReference;

        // Start with DNS resolution
        self.state = .resolving_dns;
        try self.host_pool.resolveHost(our_ref);
    }

    // Called after DNS resolution completes successfully
    pub fn startConnectWithResolvedAddr(self: *PooledConnection) !void {
        const addr = self.resolved_addr orelse return error.NoResolvedAddress;

        self.state = .connecting;
        logger.debugf(self.allocator, "pool", "Connecting refcounted connection to resolved address {}", .{addr});

        const connect_req = try self.allocator.create(uv.ConnectReq);
        connect_req.* = uv.ConnectReq.init();

        // Get our reference for the connect callback
        const our_ref = if (self.tcp.getData(RefPooledConnection)) |ref|
            ref.retain()
        else
            return error.NoConnectionReference;

        connect_req.setData(our_ref);

        try self.tcp.connect(connect_req, &addr.any, connectCallback);
    }

    // Called when DNS resolution fails
    pub fn handleDnsError(self: *PooledConnection, error_message: []const u8) void {
        logger.errf(self.allocator, "pool", "DNS error for {s}:{}: {s}", .{ self.host_pool.host, self.host_pool.port, error_message });
        self.state = .failed;
        self.connection_failed = true;
        self.flushPendingRequests(true);
    }

    /// REFCOUNTED: Safe libuv connect callback
    fn connectCallback(req: *anyopaque, status: c_int) callconv(.C) void {
        const connect_req: *uv.ConnectReq = @ptrCast(@alignCast(req));

        if (connect_req.getData(RefPooledConnection)) |ref_conn| {
            defer ref_conn.release(); // Release the reference we retained for this callback

            const self = ref_conn.get();
            self.allocator.destroy(connect_req);

            if (status < 0) {
                self.state = .failed;
                self.connection_failed = true;
                logger.errf(self.allocator, "pool", "Connect failed to {s}:{}: {s}", .{ self.host_pool.host, self.host_pool.port, uv.errorString(status) });
                self.flushPendingRequests(true);
                return;
            }

            self.state = .connected;
            logger.debugf(self.allocator, "pool", "Refcounted connection connected to {s}:{}", .{ self.host_pool.host, self.host_pool.port });

            self.flushPendingRequests(false);
        }
    }

    fn sendRequest(self: *PooledConnection) !void {
        const request = self.current_request.?;

        logger.debugf(self.allocator, "pool", "Sending refcounted request to {s}:{} ({} bytes)", .{ self.host_pool.host, self.host_pool.port, request.request_data.len });

        const write_ctx = try self.allocator.create(WriteContext);

        const our_ref = if (self.tcp.getData(RefPooledConnection)) |ref|
            ref.retain()
        else
            return error.NoConnectionReference;

        write_ctx.* = WriteContext{
            .write_req = uv.WriteReq.init(),
            .connection_ref = our_ref,
            .allocator = self.allocator,
        };
        write_ctx.write_req.setData(write_ctx);

        const buf = uv.Buffer.init(@constCast(request.request_data));
        try self.tcp.write(&write_ctx.write_req, &[_]uv.Buffer{buf}, writeCallback);
    }

    fn flushPendingRequests(self: *PooledConnection, send_error: bool) void {
        while (self.pending_requests.items.len > 0) {
            var request = self.pending_requests.orderedRemove(0); // Changed to mutable

            if (send_error) {
                const error_response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                request.callback(request.context, error_response);
                request.deinit(self.allocator); // Now mutable, so this works
            } else {
                if (self.current_request == null) {
                    self.current_request = request;
                    self.sendRequest() catch {
                        self.handleError();
                        return;
                    };
                } else {
                    self.pending_requests.insert(0, request) catch {
                        request.deinit(self.allocator); // Now mutable, so this works
                    };
                    break;
                }
            }
        }
    }

    /// REFCOUNTED: Safe write callback
    fn writeCallback(req: *anyopaque, status: c_int) callconv(.C) void {
        const write_req: *uv.WriteReq = @ptrCast(@alignCast(req));

        if (write_req.getData(WriteContext)) |write_ctx| {
            defer write_ctx.deinit();

            const self = write_ctx.connection_ref.get();

            if (status < 0) {
                // FIXED: status is already a libuv error code, use directly
                if (uv.isConnectionError(status)) {
                    logger.debugf(self.allocator, "pool", "Write to {s}:{} failed - connection broken: {s}", .{ self.host_pool.host, self.host_pool.port, uv.errorString(status) });
                } else {
                    logger.errf(self.allocator, "pool", "Write to {s}:{} failed: {s}", .{ self.host_pool.host, self.host_pool.port, uv.errorString(status) });
                }
                self.connection_failed = true;
                self.handleError();
                return;
            }

            logger.debugf(self.allocator, "pool", "Successfully wrote refcounted request to {s}:{} (state: {}, failed: {})", .{ self.host_pool.host, self.host_pool.port, self.state, self.connection_failed });

            // Stop any existing reading before starting new reading
            self.tcp.stopReading();

            // Try to start reading and capture the specific error
            if (self.tcp.startReading(allocCallback, readCallback)) {
                logger.debugf(self.allocator, "pool", "Started reading from {s}:{}", .{ self.host_pool.host, self.host_pool.port });
            } else |err| {
                logger.errf(self.allocator, "pool", "Failed to start reading from {s}:{} - specific error: {}", .{ self.host_pool.host, self.host_pool.port, err });

                // Check if the TCP handle is still valid by trying to get its file descriptor
                if (self.tcp.getFileDescriptor()) |fd| {
                    logger.debugf(self.allocator, "pool", "TCP handle fd={} appears valid", .{fd});
                } else |fd_err| {
                    logger.debugf(self.allocator, "pool", "TCP handle appears invalid: {}", .{fd_err});
                }

                self.connection_failed = true;
                self.handleError();
            }
        }
    }

    /// REFCOUNTED: Safe alloc callback
    fn allocCallback(handle: *anyopaque, suggested_size: usize, buf: *uv.Buffer) callconv(.C) void {
        _ = suggested_size;
        const tcp: *uv.Tcp = @ptrCast(@alignCast(handle));

        if (tcp.getData(RefPooledConnection)) |_| {
            const read_buffer = buffer_pool.getBuffer();
            if (read_buffer.len > 0) {
                buf.* = uv.Buffer.init(read_buffer);
            } else {
                buf.* = uv.Buffer.init(&[_]u8{});
            }
        } else {
            buf.* = uv.Buffer.init(&[_]u8{});
        }
    }

    /// REFCOUNTED: Safe read callback
    fn readCallback(stream: *anyopaque, nread: isize, buf: *const uv.Buffer) callconv(.C) void {
        const tcp: *uv.Tcp = @ptrCast(@alignCast(stream));

        if (tcp.getData(RefPooledConnection)) |ref_conn| {
            const self = ref_conn.get();

            // Always return buffer to pool when done
            defer if (buf.len > 0) buffer_pool.returnBuffer(buf.base[0..buf.len]);

            if (nread < 0) {
                // FIXED: nread is already a libuv error code, use directly
                const uv_err: c_int = @intCast(nread);

                if (uv_err == uv.UV_EOF) {
                    logger.debugf(self.allocator, "pool", "Connection to {s}:{} closed by peer (EOF)", .{ self.host_pool.host, self.host_pool.port });
                    self.finishRequest();
                } else if (uv.isConnectionError(uv_err)) {
                    logger.debugf(self.allocator, "pool", "Connection to {s}:{} broken: {s}", .{ self.host_pool.host, self.host_pool.port, uv.errorString(uv_err) });
                    self.connection_failed = true;
                    self.handleError();
                } else {
                    logger.errf(self.allocator, "pool", "Read error from {s}:{}: {s}", .{ self.host_pool.host, self.host_pool.port, uv.errorString(uv_err) });
                    self.connection_failed = true;
                    self.handleError();
                }
                return;
            }

            if (nread == 0) return;

            const bytes_read: usize = @intCast(nread);

            if (self.current_request) |*request| {
                // For now, just forward the response immediately
                // In a real implementation, you'd buffer until complete
                request.callback(request.context, buf.base[0..bytes_read]);
                self.finishRequest();
            }
        } else {
            // No valid connection reference - return buffer to pool
            if (buf.len > 0) {
                buffer_pool.returnBuffer(buf.base[0..buf.len]);
            }
        }
    }

    fn finishRequest(self: *PooledConnection) void {
        if (self.current_request) |*request| {
            request.deinit(self.allocator);
            self.current_request = null;
        }

        self.request_count += 1;
        self.last_used = std.time.milliTimestamp();

        if (self.pending_requests.items.len > 0) {
            const next_request = self.pending_requests.orderedRemove(0);
            self.current_request = next_request;
            self.sendRequest() catch {
                self.handleError();
                return;
            };
            return;
        }

        // Get our reference to return to pool
        if (self.tcp.getData(RefPooledConnection)) |ref_conn| {
            self.host_pool.returnConnection(ref_conn);
        }
    }

    fn handleError(self: *PooledConnection) void {
        if (self.current_request) |*request| {
            const error_response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            request.callback(request.context, error_response);
            request.deinit(self.allocator);
            self.current_request = null;
        }

        self.flushPendingRequests(true);

        self.connection_failed = true;
        self.state = .failed;

        self.close();
    }

    pub fn isHealthy(self: *PooledConnection) bool {
        const now = std.time.milliTimestamp();

        // Safe integer arithmetic to prevent overflow
        const age_ms = if (now >= self.last_used)
            now - self.last_used
        else
            0; // Handle clock skew/wraparound

        return !self.connection_failed and
            self.state == .connected and
            age_ms < CONNECTION_IDLE_TIMEOUT_MS and
            self.request_count < CONNECTION_MAX_REQUESTS;
    }

    pub fn quickHealthCheck(self: *PooledConnection) bool {
        if (self.state != .connected or self.connection_failed) {
            return false;
        }

        const now = std.time.milliTimestamp();

        // Safe integer arithmetic to prevent overflow
        const age_ms = if (now >= self.last_used)
            now - self.last_used
        else
            0; // Handle clock skew/wraparound

        const threshold = (CONNECTION_IDLE_TIMEOUT_MS * 8) / 10;
        if (age_ms > threshold) {
            logger.debugf(self.allocator, "pool", "Refcounted connection to {s}:{} is suspicious ({}ms old)", .{ self.host_pool.host, self.host_pool.port, age_ms });
            return false;
        }

        return true;
    }

    pub fn close(self: *PooledConnection) void {
        logger.debugf(self.allocator, "pool", "Closing refcounted connection to {s}:{}", .{ self.host_pool.host, self.host_pool.port });

        for (self.pending_requests.items) |*request| {
            const error_response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            request.callback(request.context, error_response);
            request.deinit(self.allocator);
        }
        self.pending_requests.clearRetainingCapacity();

        if (self.current_request) |*request| {
            const error_response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            request.callback(request.context, error_response);
            request.deinit(self.allocator);
            self.current_request = null;
        }

        self.tcp.safeClose(closeCallback);
    }

    /// REFCOUNTED: Safe close callback
    fn closeCallback(handle: *anyopaque) callconv(.C) void {
        const tcp: *uv.Tcp = @ptrCast(@alignCast(handle));

        if (tcp.getData(RefPooledConnection)) |ref_conn| {
            logger.debug("pool", "TCP handle closed, releasing refcounted connection reference");
            ref_conn.release(); // Release the reference stored in TCP handle
        }
    }
};

/// REFCOUNTED: Write context that holds connection reference
const WriteContext = struct {
    write_req: uv.WriteReq,
    connection_ref: *RefPooledConnection,
    allocator: std.mem.Allocator, // Store allocator directly to avoid issues

    pub fn deinit(self: *WriteContext) void {
        // Release the connection reference first
        self.connection_ref.release();

        // Then destroy the WriteContext using stored allocator
        self.allocator.destroy(self);
    }
};
