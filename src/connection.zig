// src/connection.zig - Connection and request management
const std = @import("std");
const logger = @import("logger.zig");
const types = @import("core/types.zig");
const http = @import("http.zig");
const mtls = @import("mtls/tls.zig");
const uv = @import("utils/uv.zig");
const refcounted = @import("utils/refcounted.zig");
const upstream = @import("upstream.zig");
const buffer_pool = @import("utils/buffer_pool.zig");
const request_logger = @import("request_logger.zig");
const xml_parser = @import("xml_parser.zig");
const certificate = @import("mtls/certificate.zig");

const RefConnectionContext = refcounted.Ref(ConnectionContext);
pub const ConnectionPtr = refcounted.RefPtr(RefConnectionContext);

pub const ConnectionContext = struct {
    gpa: std.mem.Allocator,
    proxy: *anyopaque, // Avoid circular dependency

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

    pub fn init(gpa: std.mem.Allocator, proxy: *anyopaque) !*RefConnectionContext {
        const arena = try gpa.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(gpa);

        // Import proxy type to access tls_server
        const Proxy = @import("proxy.zig").Proxy;
        const proxy_typed: *Proxy = @ptrCast(@alignCast(proxy));

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
            .tls_conn = try proxy_typed.tls_server.createConnection(),
        };

        const ref_conn = try RefConnectionContext.init(gpa, conn_ctx);

        try ref_conn.get().downstream_tcp.init(proxy_typed.loop);
        ref_conn.get().downstream_tcp.setData(ref_conn.retain());

        return ref_conn;
    }

    pub fn deinit(self: *ConnectionContext) void {
        logger.debug("connection", "Cleaning up refcounted connection context");

        if (self.lfdi) |lfdi| self.gpa.free(lfdi);
        if (self.sfdi) |sfdi| self.gpa.free(sfdi);

        self.upstream_ref.deinit();

        if (self.request_ctx) |req_ctx| {
            req_ctx.deinit();
        }

        self.tls_conn.deinit();

        const duration = std.time.milliTimestamp() - self.connection_start_time;
        if (self.requests_processed > 0) {
            logger.debugf(self.gpa, "connection", "Connection closed after {}ms, processed {} requests", .{ duration, self.requests_processed });
        }

        const gpa = self.gpa;
        const arena = self.arena;

        arena.deinit();
        gpa.destroy(arena);
    }

    pub fn startTlsHandshake(self: *ConnectionContext) void {
        logger.debug("connection", "Starting refcounted TLS handshake");
        self.handshake_state = .in_progress;

        self.downstream_tcp.startReading(allocCallback, readCallback) catch |err| {
            logger.errf(self.gpa, "connection", "Failed to start reading: {}", .{err});
            self.close();
            return;
        };

        self.continueHandshake();
    }

    pub fn continueHandshake(self: *ConnectionContext) void {
        logger.debug("connection", "Continuing TLS handshake");

        self.tls_conn.continueHandshake() catch |err| {
            switch (err) {
                error.WantRead => {
                    logger.debug("connection", "TLS handshake wants read - draining output first");
                    self.drainTlsOutput();
                    return;
                },
                error.WantWrite => {
                    logger.debug("connection", "TLS handshake wants write - draining output");
                    self.drainTlsOutput();
                    return;
                },
                else => {
                    logger.errf(self.gpa, "connection", "TLS handshake failed: {}", .{err});
                    self.handshake_state = .failed;
                    self.close();
                    return;
                },
            }
        };

        if (self.tls_conn.isHandshakeDone()) {
            logger.debug("connection", "TLS handshake completed");
            self.handshake_state = .complete;
            self.extractCertificateInfo();
            self.drainTlsOutput();
            self.startHttpReading();
        } else {
            logger.debug("connection", "TLS handshake step completed, but not done yet");
            self.drainTlsOutput();
        }
    }

    pub fn processHttpData(self: *ConnectionContext) void {
        self.tls_conn.feedSocketData(self.read_buffer[0..self.read_pos]) catch |err| {
            logger.errf(self.gpa, "connection", "Failed to feed HTTP data to TLS: {}", .{err});
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
                        logger.debug("connection", "TLS connection closed by downstream");
                        self.close();
                        return;
                    },
                    else => {
                        logger.errf(self.gpa, "connection", "TLS read error: {}", .{err});
                        self.close();
                        return;
                    },
                }
            };

            if (bytes_read == 0) break;
            http_total += bytes_read;

            if (http.isRequestComplete(http_buffer[0..http_total])) {
                logger.debug("connection", "Complete HTTP request received");
                self.processHttpRequest(http_buffer[0..http_total]);
                return;
            }
        }

        self.drainTlsOutput();
    }

    pub fn processHttpRequest(self: *ConnectionContext, http_data: []const u8) void {
        logger.debugf(self.gpa, "connection", "Processing HTTP request ({} bytes)", .{http_data.len});

        self.request_ctx = RequestContext.init(self.gpa, self) catch |err| {
            logger.errf(self.gpa, "connection", "Failed to create request context: {}", .{err});
            self.close();
            return;
        };

        const request = http.parseRequest(self.request_ctx.?.arena.allocator(), http_data) catch |err| {
            logger.errf(self.gpa, "connection", "Failed to parse HTTP request: {}", .{err});
            self.sendErrorResponse(400, "Bad Request");
            return;
        };

        self.request_ctx.?.setRequest(request);
        self.requests_processed += 1;

        // Get proxy reference for stats
        const Proxy = @import("proxy.zig").Proxy;
        const proxy_typed: *Proxy = @ptrCast(@alignCast(self.proxy));
        _ = proxy_typed.total_requests_processed.fetchAdd(1, .monotonic);

        logger.debugf(self.gpa, "connection", "Request {s}: {} {s}", .{ self.request_ctx.?.request_id, request.method, request.path });

        self.parseRequestXml();
        self.startUpstreamRequest();
    }

    pub fn sendUpstreamResponse(self: *ConnectionContext, response_data: []const u8) void {
        logger.debugf(self.gpa, "connection", "Sending upstream response ({} bytes) to downstream", .{response_data.len});

        const log_entry = self.createLogEntry(request_logger.ResponseSource.upstream, 200, response_data) catch {
            logger.err("connection", "Failed to create log entry");
            self.sendTlsResponse(response_data);
            return;
        };

        // Get proxy reference for async logger
        const Proxy = @import("proxy.zig").Proxy;
        const proxy_typed: *Proxy = @ptrCast(@alignCast(self.proxy));

        proxy_typed.async_logger.logRequest(log_entry) catch |err| {
            logger.errf(self.gpa, "connection", "Failed to submit log entry: {}", .{err});
        };

        self.sendTlsResponse(response_data);
    }

    pub fn sendErrorResponse(self: *ConnectionContext, status_code: u16, message: []const u8) void {
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
            logger.err("connection", "Failed to create error log entry");
            self.sendTlsResponse(response);
            return;
        };

        // Get proxy reference for async logger
        const Proxy = @import("proxy.zig").Proxy;
        const proxy_typed: *Proxy = @ptrCast(@alignCast(self.proxy));

        proxy_typed.async_logger.logRequest(log_entry) catch |err| {
            logger.errf(self.gpa, "connection", "Failed to submit error log entry: {}", .{err});
        };

        self.sendTlsResponse(response);
    }

    pub fn close(self: *ConnectionContext) void {
        logger.debug("connection", "Closing refcounted connection");
        self.downstream_tcp.safeClose(connectionCloseCallback);
    }

    fn extractCertificateInfo(self: *ConnectionContext) void {
        if (self.tls_conn.getClientCertificate()) |cert| {
            const fingerprint = certificate.calculateCertificateFingerprint(self.gpa, cert) catch |err| {
                logger.warnf(self.gpa, "connection", "Failed to calculate certificate fingerprint: {}", .{err});
                return;
            };
            defer self.gpa.free(fingerprint);

            self.lfdi = certificate.extractLfdiFromFingerprint(self.gpa, fingerprint) catch |err| {
                logger.warnf(self.gpa, "connection", "Failed to extract LFDI: {}", .{err});
                return;
            };

            self.sfdi = certificate.extractSfdiFromFingerprint(self.gpa, fingerprint) catch |err| {
                logger.warnf(self.gpa, "connection", "Failed to extract SFDI: {}", .{err});
                return;
            };

            logger.debugf(self.gpa, "connection", "Extracted LFDI: {s}, SFDI: {s}", .{ self.lfdi orelse "null", self.sfdi orelse "null" });
        }
    }

    fn drainTlsOutput(self: *ConnectionContext) void {
        var output_buffer: [8192]u8 = undefined;

        const bytes_to_send = self.tls_conn.drainToSocket(output_buffer[0..]) catch |err| {
            logger.errf(self.gpa, "connection", "Failed to drain TLS output: {}", .{err});
            self.close();
            return;
        };

        if (bytes_to_send > 0) {
            logger.debugf(self.gpa, "connection", "Draining {} TLS bytes to send to downstream", .{bytes_to_send});
            self.writeToDownstream(output_buffer[0..bytes_to_send]);
        }
    }

    fn writeToDownstream(self: *ConnectionContext, data: []const u8) void {
        const WriteContext = @import("proxy.zig").WriteContext;

        const write_ctx = self.gpa.create(WriteContext) catch |err| {
            logger.errf(self.gpa, "connection", "Failed to create write context: {}", .{err});
            self.close();
            return;
        };

        const our_ref = if (self.downstream_tcp.getData(RefConnectionContext)) |ref|
            ref.retain()
        else {
            logger.err("connection", "Could not find connection reference for write");
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

        const writeCallback = @import("proxy.zig").writeCallback;
        const buf = uv.Buffer.init(@constCast(write_ctx.data));
        self.downstream_tcp.write(&write_ctx.write_req, &[_]uv.Buffer{buf}, writeCallback) catch |err| {
            logger.errf(self.gpa, "connection", "Failed to write to downstream: {}", .{err});
            write_ctx.deinit();
            self.close();
        };
    }

    fn startHttpReading(self: *ConnectionContext) void {
        _ = self;
        logger.debug("connection", "Switching to HTTP request reading mode");
    }

    fn parseRequestXml(self: *ConnectionContext) void {
        const request = &self.request_ctx.?.request.?;

        if (request.body) |body| {
            if (self.isXmlBody(body)) {
                xml_parser.init();
                var processor = xml_parser.XmlProcessor.init(self.gpa);
                var result = processor.processXml(body, .inbound, null) catch {
                    logger.debug("connection", "Failed to parse request XML");
                    return;
                };
                defer result.deinit(self.gpa);

                if (result.message_type) |msg_type| {
                    const req_allocator = self.request_ctx.?.arena.allocator();
                    self.request_ctx.?.request_xml_message = req_allocator.dupe(u8, msg_type.toString()) catch null;
                    logger.debugf(self.gpa, "connection", "Request contains XML: {s}", .{msg_type.toString()});
                }
            }
        }
    }

    fn isXmlBody(self: *ConnectionContext, data: []const u8) bool {
        _ = self;
        const trimmed = std.mem.trim(u8, data, " \t\n\r");
        return trimmed.len > 0 and trimmed[0] == '<';
    }

    fn hasXmlContentType(self: *ConnectionContext, http_data: []const u8) bool {
        _ = self;
        if (std.mem.indexOf(u8, http_data, "\r\n\r\n")) |header_end| {
            const headers = http_data[0..header_end];
            var line_it = std.mem.splitSequence(u8, headers, "\r\n");
            while (line_it.next()) |line| {
                if (std.ascii.startsWithIgnoreCase(line, "content-type:")) {
                    return std.ascii.indexOfIgnoreCase(line, "xml") != null;
                }
            }
        }
        return false;
    }

    fn startUpstreamRequest(self: *ConnectionContext) void {
        const Proxy = @import("proxy.zig").Proxy;
        const proxy_typed: *Proxy = @ptrCast(@alignCast(self.proxy));

        const upstream_url = proxy_typed.global.getNextUpstream();
        if (upstream_url.len == 0) {
            logger.err("connection", "No upstream available");
            self.sendErrorResponse(503, "Service Unavailable");
            return;
        }

        self.request_ctx.?.setUpstream(upstream_url) catch |err| {
            logger.errf(self.gpa, "connection", "Failed to set upstream: {}", .{err});
            self.sendErrorResponse(502, "Bad Gateway");
            return;
        };

        logger.debugf(self.gpa, "connection", "Starting refcounted upstream request to: {s}", .{upstream_url});

        const our_ref = if (self.downstream_tcp.getData(RefConnectionContext)) |ref|
            ref
        else {
            logger.err("connection", "Could not find connection reference for upstream");
            self.sendErrorResponse(502, "Bad Gateway");
            return;
        };

        const upstream_result = upstream.createUpstreamContext(
            self.gpa,
            @ptrCast(our_ref),
            &proxy_typed.upstream_pool,
            upstream_url,
            &self.request_ctx.?.request.?,
            @ptrCast(&upstreamResponseCallback),
        ) catch |err| {
            logger.errf(self.gpa, "connection", "Failed to create upstream context: {}", .{err});
            self.sendErrorResponse(502, "Bad Gateway");
            return;
        };

        self.upstream_ref.reset(upstream_result.upstream);

        upstream.UpstreamContext.startConnection(upstream_result.upstream) catch |err| {
            logger.errf(self.gpa, "connection", "Failed to start upstream connection: {}", .{err});
            self.sendErrorResponse(502, "Bad Gateway");
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
                        logger.errf(self.gpa, "connection", "TLS write error: {}", .{err});
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
            logger.debugf(self.gpa, "connection", "Request {s} completed in {:.2}ms", .{ req_ctx.request_id, req_ctx.getProcessingTimeMs() });
        }
    }

    fn createLogEntry(self: *ConnectionContext, response_source: request_logger.ResponseSource, status_code: u16, response_data: []const u8) !request_logger.RequestLogEntry {
        const req_ctx = self.request_ctx orelse return error.NoRequestContext;
        const request = &req_ctx.request.?;

        var response_xml_message: ?[]const u8 = null;
        var upstream_host: ?[]const u8 = null;
        var upstream_port: ?u16 = null;

        const response_body = if (std.mem.indexOf(u8, response_data, "\r\n\r\n")) |header_end|
            response_data[header_end + 4 ..]
        else
            response_data;

        if (response_body.len > 0 and self.hasXmlContentType(response_data)) {
            xml_parser.init();
            var processor = xml_parser.XmlProcessor.init(self.gpa);
            var result = processor.processXml(response_body, .outbound, null) catch |err| blk: {
                logger.errf(self.gpa, "connection", "Failed to parse response XML: {}", .{err});
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
            var url_after_scheme = req_ctx.upstream_url;
            if (std.mem.indexOf(u8, url_after_scheme, "://")) |scheme_end| {
                url_after_scheme = url_after_scheme[scheme_end + 3 ..];
            }

            if (std.mem.lastIndexOf(u8, url_after_scheme, ":")) |pos| {
                upstream_host = try self.gpa.dupe(u8, url_after_scheme[0..pos]);
                const port_str = url_after_scheme[pos + 1 ..];
                upstream_port = std.fmt.parseInt(u16, port_str, 10) catch 80;
            } else {
                upstream_host = try self.gpa.dupe(u8, url_after_scheme);
                upstream_port = 80;
            }
        }

        const timestamp = std.time.milliTimestamp();

        const lfdi_copy = if (self.lfdi) |lfdi|
            try self.gpa.dupe(u8, lfdi)
        else
            null;

        const sfdi_copy = if (self.sfdi) |sfdi|
            try self.gpa.dupe(u8, sfdi)
        else
            null;

        const method_copy = try self.gpa.dupe(u8, request.method.toString());
        const path_copy = try self.gpa.dupe(u8, request.path);

        const request_xml_copy = if (req_ctx.request_xml_message) |msg|
            try self.gpa.dupe(u8, msg)
        else
            null;

        return request_logger.RequestLogEntry{
            .timestamp = timestamp,
            .lfdi = lfdi_copy,
            .sfdi = sfdi_copy,
            .method = method_copy,
            .path = path_copy,
            .request_xml_message = request_xml_copy,
            .response_source = response_source,
            .response_code = status_code,
            .response_xml_message = response_xml_message,
            .upstream_host = upstream_host,
            .upstream_port = upstream_port,
        };
    }

    // Callbacks
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
                    logger.debug("connection", "Downstream closed connection (EOF)");
                } else if (uv.isConnectionError(uv_err)) {
                    logger.debugf(self.gpa, "connection", "Connection broken: {s}", .{uv.errorString(uv_err)});
                } else {
                    logger.errf(self.gpa, "connection", "Read error: {s}", .{uv.errorString(uv_err)});
                }
                self.close();
                return;
            }

            if (nread == 0) return;

            const bytes_read: usize = @intCast(nread);
            self.read_pos += bytes_read;

            logger.debugf(self.gpa, "connection", "Read {} bytes from downstream", .{bytes_read});

            switch (self.handshake_state) {
                .in_progress => {
                    self.tls_conn.feedSocketData(self.read_buffer[0..self.read_pos]) catch |err| {
                        logger.errf(self.gpa, "connection", "Failed to feed TLS data: {}", .{err});
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
                    logger.warnf(self.gpa, "connection", "Received data in unexpected handshake state: {}", .{self.handshake_state});
                    self.close();
                },
            }
        }
    }

    fn connectionCloseCallback(handle: *anyopaque) callconv(.C) void {
        const tcp: *uv.Tcp = @ptrCast(@alignCast(handle));

        if (tcp.getData(RefConnectionContext)) |ref_conn| {
            logger.debug("connection", "Connection closed, releasing reference");
            ref_conn.release();
        }
    }

    fn upstreamResponseCallback(downstream_ref: *RefConnectionContext, response_data: []const u8) void {
        const self = downstream_ref.get();
        self.sendUpstreamResponse(response_data);
    }
};

pub const RequestContext = struct {
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
        self.* = RequestContext{
            .arena = arena,
            .gpa = gpa,
            .conn_ctx = conn_ctx,
            .start_time = std.time.nanoTimestamp(),
            .request_id = try generateRequestId(allocator),
            .request = null,
            .upstream_url = "",
            .request_xml_message = null,
        };

        return self;
    }

    pub fn deinit(self: *RequestContext) void {
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
