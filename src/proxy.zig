// File: src/proxy.zig

const std = @import("std");
const logger = @import("logger.zig");
const core = @import("core/context.zig");
const types = @import("core/types.zig");
const http = @import("http.zig");
const mtls = @import("mtls/tls.zig");
const config = @import("config.zig");
const uv = @import("utils/uv.zig");
const refcounted = @import("utils/refcounted.zig");
const upstream = @import("upstream.zig");
const connection_pool = @import("connection_pool.zig");
const buffer_pool = @import("utils/buffer_pool.zig");
const request_logger = @import("request_logger.zig");
const xml_parser = @import("xml_parser.zig");
const certificate = @import("mtls/certificate.zig");

const RefConnectionContext = refcounted.Ref(ConnectionContext);
const ConnectionPtr = refcounted.RefPtr(RefConnectionContext);

pub const Proxy = struct {
    gpa: std.mem.Allocator,
    global: *core.GlobalContext,
    tls_server: mtls.TlsServer,

    loop: *uv.Loop,
    server: uv.Tcp,

    upstream_pool: connection_pool.ConnectionPool,
    pool_cleanup_timer: uv.Timer,

    async_logger: request_logger.AsyncRequestLogger,

    queued_requests: std.atomic.Value(u32),
    total_requests_processed: std.atomic.Value(u64),
    total_requests_queued: std.atomic.Value(u64),

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
            .queued_requests = std.atomic.Value(u32).init(0),
            .total_requests_processed = std.atomic.Value(u64).init(0),
            .total_requests_queued = std.atomic.Value(u64).init(0),
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

        const final_result = self.loop.run(uv.UV_RUN_DEFAULT);
        logger.debugf(self.gpa, "proxy", "Event loop exited with: {}", .{final_result});

        logger.info("proxy", "Refcounted proxy shutting down");
    }

    fn performanceMonitorCallback(handle: *anyopaque) callconv(.C) void {
        const timer: *uv.Timer = @ptrCast(@alignCast(handle));
        const proxy = timer.getData(Proxy) orelse return;

        const queued = proxy.queued_requests.load(.monotonic);
        const processed = proxy.total_requests_processed.load(.monotonic);
        const queue_total = proxy.total_requests_queued.load(.monotonic);

        logger.infof(proxy.gpa, "proxy", "PERF: queued={}, processed={}, queue_total={}", .{ queued, processed, queue_total });
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

    fn acceptConnection(self: *Proxy) !void {
        logger.debug("proxy", "Attempting to accept new refcounted connection");

        const ref_conn_ctx = try ConnectionContext.init(self.gpa, self);
        errdefer ref_conn_ctx.release();

        try self.server.accept(&ref_conn_ctx.get().downstream_tcp);

        logger.debug("proxy", "Connection accepted, starting TLS handshake");

        ref_conn_ctx.get().startTlsHandshake();
    }
};

fn poolCleanupCallback(handle: *anyopaque) callconv(.C) void {
    const timer: *uv.Timer = @ptrCast(@alignCast(handle));
    const proxy = timer.getData(Proxy) orelse return;

    proxy.upstream_pool.closeIdleConnections();
    logger.debug("proxy", "Cleaned up idle connections from pool");
}

pub const ConnectionContext = struct {
    gpa: std.mem.Allocator,
    proxy: *Proxy,

    arena: *std.heap.ArenaAllocator,

    downstream_tcp: uv.Tcp,

    tls_conn: mtls.TlsConnection,
    handshake_state: HandshakeState,

    read_buffer: [16384]u8,
    read_pos: usize,
    request_ctx: ?*RequestContext,

    upstream_ref: upstream.UpstreamPtr,

    connection_start_time: i64,
    requests_processed: u32 = 0,

    lfdi: ?[]const u8 = null,
    sfdi: ?[]const u8 = null,

    const HandshakeState = enum {
        starting,
        in_progress,
        complete,
        failed,
    };

    pub fn init(gpa: std.mem.Allocator, proxy: *Proxy) !*RefConnectionContext {
        const arena = try gpa.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(gpa);

        const conn_ctx = ConnectionContext{
            .gpa = gpa,
            .proxy = proxy,
            .arena = arena,
            .read_buffer = std.mem.zeroes([16384]u8),
            .read_pos = 0,
            .request_ctx = null,
            .handshake_state = .starting,
            .connection_start_time = std.time.milliTimestamp(),
            .upstream_ref = upstream.UpstreamPtr.init(null),
            .downstream_tcp = std.mem.zeroes(uv.Tcp),
            .tls_conn = try proxy.tls_server.createConnection(),
        };

        const ref_conn = try RefConnectionContext.init(gpa, conn_ctx);

        try ref_conn.get().downstream_tcp.init(proxy.loop);

        ref_conn.get().downstream_tcp.setData(ref_conn.retain());

        return ref_conn;
    }

    pub fn deinit(self: *ConnectionContext) void {
        logger.debug("proxy", "Cleaning up refcounted connection context");

        if (self.lfdi) |lfdi| self.gpa.free(lfdi);
        if (self.sfdi) |sfdi| self.gpa.free(sfdi);

        self.upstream_ref.deinit();

        if (self.request_ctx) |req_ctx| {
            req_ctx.deinit();
        }

        self.tls_conn.deinit();

        const duration = std.time.milliTimestamp() - self.connection_start_time;
        if (self.requests_processed > 0) {
            logger.debugf(self.gpa, "proxy", "Refcounted connection closed after {}ms, processed {} requests", .{ duration, self.requests_processed });
        }

        const gpa = self.gpa;
        const arena = self.arena;

        arena.deinit();
        gpa.destroy(arena);
    }

    pub fn startTlsHandshake(self: *ConnectionContext) void {
        logger.debug("proxy", "Starting refcounted TLS handshake");
        self.handshake_state = .in_progress;

        self.downstream_tcp.startReading(allocCallback, readCallback) catch |err| {
            logger.errf(self.gpa, "proxy", "Failed to start reading: {}", .{err});
            self.close();
            return;
        };

        self.continueHandshake();
    }

    fn continueHandshake(self: *ConnectionContext) void {
        logger.debug("proxy", "Continuing TLS handshake");

        self.tls_conn.continueHandshake() catch |err| {
            switch (err) {
                error.WantRead => {
                    logger.debug("proxy", "TLS handshake wants read - draining output first");
                    self.drainTlsOutput();
                    return;
                },
                error.WantWrite => {
                    logger.debug("proxy", "TLS handshake wants write - draining output");
                    self.drainTlsOutput();
                    return;
                },
                else => {
                    logger.errf(self.gpa, "proxy", "TLS handshake failed: {}", .{err});
                    self.handshake_state = .failed;
                    self.close();
                    return;
                },
            }
        };

        if (self.tls_conn.isHandshakeDone()) {
            logger.debug("proxy", "Refcounted TLS handshake completed");
            self.handshake_state = .complete;
            self.extractCertificateInfo();
            self.drainTlsOutput();
            self.startHttpReading();
        } else {
            logger.debug("proxy", "TLS handshake step completed, but not done yet");
            self.drainTlsOutput();
        }
    }

    fn extractCertificateInfo(self: *ConnectionContext) void {
        if (self.tls_conn.getClientCertificate()) |cert| {
            const fingerprint = certificate.calculateCertificateFingerprint(self.gpa, cert) catch |err| {
                logger.warnf(self.gpa, "proxy", "Failed to calculate certificate fingerprint: {}", .{err});
                return;
            };
            defer self.gpa.free(fingerprint);

            self.lfdi = certificate.extractLfdiFromFingerprint(self.gpa, fingerprint) catch |err| {
                logger.warnf(self.gpa, "proxy", "Failed to extract LFDI: {}", .{err});
                return;
            };

            self.sfdi = certificate.extractSfdiFromFingerprint(self.gpa, fingerprint) catch |err| {
                logger.warnf(self.gpa, "proxy", "Failed to extract SFDI: {}", .{err});
                return;
            };

            logger.debugf(self.gpa, "proxy", "Extracted LFDI: {s}, SFDI: {s}", .{ self.lfdi orelse "null", self.sfdi orelse "null" });
        }
    }

    fn drainTlsOutput(self: *ConnectionContext) void {
        var output_buffer: [8192]u8 = undefined;

        const bytes_to_send = self.tls_conn.drainToSocket(output_buffer[0..]) catch |err| {
            logger.errf(self.gpa, "proxy", "Failed to drain TLS output: {}", .{err});
            self.close();
            return;
        };

        if (bytes_to_send > 0) {
            logger.debugf(self.gpa, "proxy", "Draining {} TLS bytes to send to downstream", .{bytes_to_send});
            self.writeToDownstream(output_buffer[0..bytes_to_send]);
        }
    }

    fn writeToDownstream(self: *ConnectionContext, data: []const u8) void {
        const write_ctx = self.gpa.create(WriteContext) catch |err| {
            logger.errf(self.gpa, "proxy", "Failed to create write context: {}", .{err});
            self.close();
            return;
        };

        const our_ref = if (self.downstream_tcp.getData(RefConnectionContext)) |ref|
            ref.retain()
        else {
            logger.err("proxy", "Could not find connection reference for write");
            self.gpa.destroy(write_ctx);
            self.close();
            return;
        };

        write_ctx.* = WriteContext{
            .write_req = uv.WriteReq.init(),
            .conn_ref = ConnectionPtr.init(our_ref),
            .data = self.gpa.dupe(u8, data) catch {
                our_ref.release();
                self.gpa.destroy(write_ctx);
                self.close();
                return;
            },
        };

        write_ctx.write_req.setData(write_ctx);

        const buf = uv.Buffer.init(@constCast(write_ctx.data));
        self.downstream_tcp.write(&write_ctx.write_req, &[_]uv.Buffer{buf}, writeCallback) catch |err| {
            logger.errf(self.gpa, "proxy", "Failed to write to downstream: {}", .{err});
            write_ctx.deinit();
            self.close();
        };
    }

    fn startHttpReading(self: *ConnectionContext) void {
        _ = self;
        logger.debug("proxy", "Switching to HTTP request reading mode");
    }

    fn processHttpData(self: *ConnectionContext) void {
        self.tls_conn.feedSocketData(self.read_buffer[0..self.read_pos]) catch |err| {
            logger.errf(self.gpa, "proxy", "Failed to feed HTTP data to TLS: {}", .{err});
            self.close();
            return;
        };

        self.read_pos = 0;

        var http_buffer: [16384]u8 = undefined;
        var http_total: usize = 0;

        while (http_total < http_buffer.len) {
            const bytes_read = self.tls_conn.read(http_buffer[http_total..]) catch |err| {
                switch (err) {
                    error.WantRead => break,
                    error.ConnectionClosed => {
                        logger.debug("proxy", "TLS connection closed by downstream");
                        self.close();
                        return;
                    },
                    else => {
                        logger.errf(self.gpa, "proxy", "TLS read error: {}", .{err});
                        self.close();
                        return;
                    },
                }
            };

            if (bytes_read == 0) break;
            http_total += bytes_read;

            if (http.isRequestComplete(http_buffer[0..http_total])) {
                logger.debug("proxy", "Complete HTTP request received");
                self.processHttpRequest(http_buffer[0..http_total]);
                return;
            }
        }

        self.drainTlsOutput();
    }

    fn processHttpRequest(self: *ConnectionContext, http_data: []const u8) void {
        logger.debugf(self.gpa, "proxy", "Processing HTTP request ({} bytes)", .{http_data.len});

        self.request_ctx = RequestContext.init(self.gpa, self) catch |err| {
            logger.errf(self.gpa, "proxy", "Failed to create request context: {}", .{err});
            self.close();
            return;
        };

        const request = http.parseRequest(self.request_ctx.?.arena.allocator(), http_data) catch |err| {
            logger.errf(self.gpa, "proxy", "Failed to parse HTTP request: {}", .{err});
            self.sendErrorResponse(400, "Bad Request");
            return;
        };

        self.request_ctx.?.setRequest(request);
        self.requests_processed += 1;
        _ = self.proxy.total_requests_processed.fetchAdd(1, .monotonic);

        logger.debugf(self.gpa, "proxy", "Request {s}: {} {s}", .{ self.request_ctx.?.request_id, request.method, request.path });

        self.parseRequestXml();
        self.startUpstreamRequest();
    }

    fn parseRequestXml(self: *ConnectionContext) void {
        const request = &self.request_ctx.?.request.?;

        if (request.body) |body| {
            if (self.isXmlContent(body)) {
                xml_parser.init();
                var processor = xml_parser.XmlProcessor.init(self.gpa);
                var result = processor.processXml(body, .inbound, null) catch {
                    logger.debug("proxy", "Failed to parse request XML");
                    return;
                };
                defer result.deinit(self.gpa);

                if (result.message_type) |msg_type| {
                    self.request_ctx.?.request_xml_message = self.gpa.dupe(u8, msg_type.toString()) catch null;
                    logger.debugf(self.gpa, "proxy", "Request contains XML: {s}", .{msg_type.toString()});
                }
            }
        }
    }

    fn isXmlContent(self: *ConnectionContext, data: []const u8) bool {
        _ = self;
        const trimmed = std.mem.trim(u8, data, " \t\n\r");
        return trimmed.len > 0 and trimmed[0] == '<';
    }

    fn startUpstreamRequest(self: *ConnectionContext) void {
        const upstream_url = self.proxy.global.getNextUpstream();
        if (upstream_url.len == 0) {
            logger.err("proxy", "No upstream available");
            self.sendErrorResponse(503, "Service Unavailable");
            return;
        }

        self.request_ctx.?.setUpstream(upstream_url) catch |err| {
            logger.errf(self.gpa, "proxy", "Failed to set upstream: {}", .{err});
            self.sendErrorResponse(502, "Bad Gateway");
            return;
        };

        logger.debugf(self.gpa, "proxy", "Starting refcounted upstream request to: {s}", .{upstream_url});

        const our_ref = if (self.downstream_tcp.getData(RefConnectionContext)) |ref|
            ref
        else {
            logger.err("proxy", "Could not find connection reference for upstream");
            self.sendErrorResponse(502, "Bad Gateway");
            return;
        };

        const upstream_result = upstream.createUpstreamContext(
            self.gpa,
            @ptrCast(our_ref),
            &self.proxy.upstream_pool,
            upstream_url,
            &self.request_ctx.?.request.?,
            @ptrCast(&upstreamResponseCallback),
        ) catch |err| {
            logger.errf(self.gpa, "proxy", "Failed to create upstream context: {}", .{err});
            self.sendErrorResponse(502, "Bad Gateway");
            return;
        };

        self.upstream_ref.reset(upstream_result.upstream);

        upstream.UpstreamContext.startConnection(upstream_result.upstream) catch |err| {
            logger.errf(self.gpa, "proxy", "Failed to start upstream connection: {}", .{err});
            self.sendErrorResponse(502, "Bad Gateway");
        };
    }

    fn upstreamResponseCallback(downstream_ref: *RefConnectionContext, response_data: []const u8) void {
        const self = downstream_ref.get();
        self.sendUpstreamResponse(response_data);
    }

    fn sendUpstreamResponse(self: *ConnectionContext, response_data: []const u8) void {
        logger.debugf(self.gpa, "proxy", "Sending upstream response ({} bytes) to downstream", .{response_data.len});

        const log_entry = self.createLogEntry(request_logger.ResponseSource.upstream, 200, response_data) catch {
            logger.err("proxy", "Failed to create log entry");
            self.sendTlsResponse(response_data);
            return;
        };

        self.proxy.async_logger.logRequest(log_entry) catch |err| {
            logger.errf(self.gpa, "proxy", "Failed to submit log entry: {}", .{err});
        };

        self.sendTlsResponse(response_data);
    }

    fn sendErrorResponse(self: *ConnectionContext, status_code: u16, message: []const u8) void {
        const response = std.fmt.allocPrint(self.arena.allocator(), "HTTP/1.1 {} {s}\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Content-Length: {}\r\n" ++
            "Connection: close\r\n" ++
            "\r\n" ++
            "{s}", .{ status_code, message, message.len, message }) catch {
            self.close();
            return;
        };

        const log_entry = self.createLogEntry(request_logger.ResponseSource.proxy, status_code, response) catch {
            logger.err("proxy", "Failed to create error log entry");
            self.sendTlsResponse(response);
            return;
        };

        self.proxy.async_logger.logRequest(log_entry) catch |err| {
            logger.errf(self.gpa, "proxy", "Failed to submit error log entry: {}", .{err});
        };

        self.sendTlsResponse(response);
    }
    fn createLogEntry(self: *ConnectionContext, response_source: request_logger.ResponseSource, status_code: u16, response_data: []const u8) !request_logger.RequestLogEntry {
        const req_ctx = self.request_ctx orelse return error.NoRequestContext;
        const request = &req_ctx.request.?;

        var response_xml_message: ?[]const u8 = null;
        var upstream_host: ?[]const u8 = null;
        var upstream_port: ?u16 = null;

        if (self.isXmlContent(response_data)) {
            xml_parser.init();
            var processor = xml_parser.XmlProcessor.init(self.gpa);
            var result = processor.processXml(response_data, .outbound, null) catch |err| blk: {
                logger.debugf(self.gpa, "proxy", "Failed to parse response XML: {}", .{err});
                break :blk xml_parser.XmlParseResult{
                    .is_well_formed = false,
                    .processing_time_ns = 0,
                };
            };
            defer result.deinit(self.gpa);

            if (result.message_type) |msg_type| {
                response_xml_message = try self.gpa.dupe(u8, msg_type.toString());
            }
        }

        if (response_source == .upstream and req_ctx.upstream_url.len > 0) {
            if (std.mem.lastIndexOf(u8, req_ctx.upstream_url, ":")) |pos| {
                upstream_host = try self.gpa.dupe(u8, req_ctx.upstream_url[0..pos]);
                const port_str = req_ctx.upstream_url[pos + 1 ..];
                upstream_port = std.fmt.parseInt(u16, port_str, 10) catch 80;
            } else {
                upstream_host = try self.gpa.dupe(u8, req_ctx.upstream_url);
                upstream_port = 80;
            }
        }

        return request_logger.RequestLogEntry{
            .timestamp = std.time.milliTimestamp(),
            .lfdi = if (self.lfdi) |lfdi| try self.gpa.dupe(u8, lfdi) else null,
            .sfdi = if (self.sfdi) |sfdi| try self.gpa.dupe(u8, sfdi) else null,
            .method = try self.gpa.dupe(u8, request.method.toString()),
            .path = try self.gpa.dupe(u8, request.path),
            .request_xml_message = if (req_ctx.request_xml_message) |msg| try self.gpa.dupe(u8, msg) else null,
            .response_source = response_source,
            .response_code = status_code,
            .response_xml_message = response_xml_message,
            .upstream_host = upstream_host,
            .upstream_port = upstream_port,
        };
    }

    fn sendTlsResponse(self: *ConnectionContext, response_data: []const u8) void {
        var sent: usize = 0;
        while (sent < response_data.len) {
            const bytes_written = self.tls_conn.write(response_data[sent..]) catch |err| {
                switch (err) {
                    error.WantWrite => {
                        self.drainTlsOutput();
                        continue;
                    },
                    else => {
                        logger.errf(self.gpa, "proxy", "TLS write error: {}", .{err});
                        self.close();
                        return;
                    },
                }
            };

            sent += bytes_written;
            self.drainTlsOutput();
        }

        self.drainTlsOutput();

        if (self.request_ctx) |req_ctx| {
            req_ctx.markComplete();
            logger.debugf(self.gpa, "proxy", "Request {s} completed in {:.2}ms", .{ req_ctx.request_id, req_ctx.getProcessingTimeMs() });
        }
    }

    pub fn close(self: *ConnectionContext) void {
        logger.debug("proxy", "Closing refcounted connection");
        self.downstream_tcp.safeClose(connectionCloseCallback);
    }

    fn allocCallback(handle: *anyopaque, suggested_size: usize, buf: *uv.Buffer) callconv(.C) void {
        _ = suggested_size;
        const tcp: *uv.Tcp = @ptrCast(@alignCast(handle));

        if (tcp.getData(RefConnectionContext)) |ref_conn| {
            const self = ref_conn.get();
            const available = self.read_buffer.len - self.read_pos;
            if (available > 0) {
                buf.* = uv.Buffer.init(self.read_buffer[self.read_pos..]);
            } else {
                const pooled_buf = buffer_pool.getBuffer();
                if (pooled_buf.len > 0) {
                    buf.* = uv.Buffer.init(pooled_buf);
                } else {
                    buf.* = uv.Buffer.init(self.read_buffer[0..1]);
                }
            }
        } else {
            buf.* = uv.Buffer.init(&[_]u8{});
        }
    }

    fn readCallback(stream: *anyopaque, nread: isize, buf: *const uv.Buffer) callconv(.C) void {
        _ = buf;
        const tcp: *uv.Tcp = @ptrCast(@alignCast(stream));

        if (tcp.getData(RefConnectionContext)) |ref_conn| {
            const self = ref_conn.get();

            if (nread < 0) {
                const uv_err: c_int = @intCast(nread);

                if (uv_err == uv.UV_EOF) {
                    logger.debug("proxy", "Downstream closed connection (EOF)");
                } else if (uv.isConnectionError(uv_err)) {
                    logger.debugf(self.gpa, "proxy", "Connection broken: {s}", .{uv.errorString(uv_err)});
                } else {
                    logger.errf(self.gpa, "proxy", "Read error: {s}", .{uv.errorString(uv_err)});
                }
                self.close();
                return;
            }

            if (nread == 0) return;

            const bytes_read: usize = @intCast(nread);
            self.read_pos += bytes_read;

            logger.debugf(self.gpa, "proxy", "Read {} bytes from downstream", .{bytes_read});

            switch (self.handshake_state) {
                .in_progress => {
                    self.tls_conn.feedSocketData(self.read_buffer[0..self.read_pos]) catch |err| {
                        logger.errf(self.gpa, "proxy", "Failed to feed TLS data: {}", .{err});
                        self.close();
                        return;
                    };

                    self.read_pos = 0;
                    self.continueHandshake();
                },
                .complete => {
                    self.processHttpData();
                },
                else => {
                    logger.warnf(self.gpa, "proxy", "Received data in unexpected handshake state: {}", .{self.handshake_state});
                    self.close();
                },
            }
        }
    }

    fn connectionCloseCallback(handle: *anyopaque) callconv(.C) void {
        const tcp: *uv.Tcp = @ptrCast(@alignCast(handle));

        if (tcp.getData(RefConnectionContext)) |ref_conn| {
            logger.debug("proxy", "Connection closed, releasing reference");
            ref_conn.release();
        }
    }
};

const WriteContext = struct {
    write_req: uv.WriteReq,
    conn_ref: ConnectionPtr,
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

const RequestContext = struct {
    arena: *std.heap.ArenaAllocator,
    gpa: std.mem.Allocator,
    conn_ctx: *ConnectionContext,
    request_id: []const u8,
    start_time: i128,
    request: ?types.HttpRequest = null,
    upstream_url: []const u8 = "",
    request_xml_message: ?[]const u8 = null,

    pub fn init(gpa: std.mem.Allocator, conn_ctx: *ConnectionContext) !*RequestContext {
        const arena = try gpa.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(gpa);
        const allocator = arena.allocator();

        const self = try allocator.create(RequestContext);
        self.arena = arena;
        self.gpa = gpa;
        self.conn_ctx = conn_ctx;
        self.start_time = std.time.nanoTimestamp();
        self.request_id = try generateRequestId(allocator);

        return self;
    }

    pub fn deinit(self: *RequestContext) void {
        if (self.request_xml_message) |msg| {
            self.gpa.free(msg);
        }
        const gpa = self.gpa;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }

    pub fn setRequest(self: *RequestContext, request: types.HttpRequest) void {
        self.request = request;
    }

    pub fn setUpstream(self: *RequestContext, url: []const u8) !void {
        self.upstream_url = try self.arena.allocator().dupe(u8, url);
    }

    pub fn markComplete(self: *RequestContext) void {
        _ = self;
    }

    pub fn getProcessingTimeMs(self: *RequestContext) f64 {
        const duration_ns = std.time.nanoTimestamp() - self.start_time;
        return @as(f64, @floatFromInt(duration_ns)) / 1_000_000.0;
    }

    fn generateRequestId(allocator: std.mem.Allocator) ![]const u8 {
        var buffer: [16]u8 = undefined;
        std.crypto.random.bytes(&buffer);
        return std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&buffer)});
    }
};

fn writeCallback(req: *anyopaque, status: c_int) callconv(.C) void {
    const write_req: *uv.WriteReq = @ptrCast(@alignCast(req));

    if (write_req.getData(WriteContext)) |write_ctx| {
        defer write_ctx.deinit();

        if (status < 0) {
            if (write_ctx.conn_ref.get()) |ref_conn| {
                const conn = ref_conn.get();

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
