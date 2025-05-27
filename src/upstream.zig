// src/upstream.zig - Upstream with connection pooling and reference counting
const std = @import("std");
const logger = @import("logger.zig");
const uv = @import("utils/uv.zig");
const http = @import("http.zig");
const types = @import("core/types.zig");
const xml_parser = @import("xml_parser.zig");
const connection_pool = @import("connection_pool.zig");
const refcounted = @import("utils/refcounted.zig");

// Forward declaration - will be properly imported at runtime
// We'll use *anyopaque and cast when needed to avoid circular imports
pub const RefConnectionContext = *anyopaque;

// Reference counted types for upstream
const RefUpstreamContext = refcounted.Ref(UpstreamContext);
pub const UpstreamPtr = refcounted.RefPtr(RefUpstreamContext);

// Reference to connection pool connection (defined in connection_pool.zig)
pub const PooledConnectionPtr = refcounted.RefPtr(connection_pool.RefPooledConnection);

/// Parsed upstream URL information
pub const UpstreamUrl = struct {
    scheme: Scheme,
    host: []const u8,
    port: u16,
    path: []const u8,

    const Scheme = enum {
        http,
        https,

        pub fn defaultPort(self: Scheme) u16 {
            return switch (self) {
                .http => 80,
                .https => 443,
            };
        }
    };

    pub fn parse(allocator: std.mem.Allocator, url: []const u8) !UpstreamUrl {
        var scheme: Scheme = undefined;
        var remaining: []const u8 = undefined;

        if (std.mem.startsWith(u8, url, "http://")) {
            scheme = .http;
            remaining = url[7..];
        } else if (std.mem.startsWith(u8, url, "https://")) {
            scheme = .https;
            remaining = url[8..];
        } else {
            return error.InvalidScheme;
        }

        const path_start = std.mem.indexOf(u8, remaining, "/");
        const host_port = if (path_start) |start| remaining[0..start] else remaining;
        const path = if (path_start) |start| remaining[start..] else "/";

        var host: []const u8 = undefined;
        var port: u16 = scheme.defaultPort();

        if (std.mem.lastIndexOf(u8, host_port, ":")) |colon_pos| {
            host = host_port[0..colon_pos];
            const port_str = host_port[colon_pos + 1 ..];
            port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidPort;
        } else {
            host = host_port;
        }

        return UpstreamUrl{
            .scheme = scheme,
            .host = try allocator.dupe(u8, host),
            .port = port,
            .path = try allocator.dupe(u8, path),
        };
    }

    pub fn deinit(self: *UpstreamUrl, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
        allocator.free(self.path);
    }
};

/// REFCOUNTED: Context for managing an upstream request using connection pooling
pub const UpstreamContext = struct {
    gpa: std.mem.Allocator,

    // REFCOUNTED: Reference to downstream connection (as opaque pointer)
    downstream_ref: RefConnectionContext,

    // Response callback that takes opaque connection reference
    response_callback: ?*const fn (RefConnectionContext, []const u8) void = null,

    upstream_url: UpstreamUrl,
    request: *types.HttpRequest,
    upstream_request_data: []u8,

    // Connection pool reference
    connection_pool_ref: *connection_pool.ConnectionPool,

    // REFCOUNTED: Reference to pooled connection
    pooled_conn_ref: PooledConnectionPtr,

    // XML processing
    xml_processor: ?xml_parser.XmlProcessor = null,

    // State tracking
    state: State,
    start_time: i64,

    const State = enum {
        sending_request,
        receiving_response,
        processing_xml,
        complete,
        error_state,
    };

    /// REFCOUNTED: Create upstream context with reference to downstream connection
    pub fn init(
        gpa: std.mem.Allocator,
        downstream_ref: RefConnectionContext,
        pool: *connection_pool.ConnectionPool,
        upstream_url_str: []const u8,
        request: *types.HttpRequest,
        response_callback: *const fn (RefConnectionContext, []const u8) void,
    ) !*RefUpstreamContext {
        var upstream_url = try UpstreamUrl.parse(gpa, upstream_url_str);
        errdefer upstream_url.deinit(gpa);

        const upstream_request_data = try http.buildUpstreamRequest(gpa, request, upstream_url.host);
        errdefer gpa.free(upstream_request_data);

        const upstream_ctx = UpstreamContext{
            .gpa = gpa,
            .downstream_ref = downstream_ref,
            .response_callback = response_callback,
            .upstream_url = upstream_url,
            .request = request,
            .upstream_request_data = upstream_request_data,
            .connection_pool_ref = pool,
            .pooled_conn_ref = PooledConnectionPtr.init(null),
            .state = .sending_request,
            .start_time = std.time.milliTimestamp(),
        };

        logger.debugf(gpa, "upstream", "Created refcounted upstream context for {s}://{s}:{}", .{ @tagName(upstream_url.scheme), upstream_url.host, upstream_url.port });

        return RefUpstreamContext.init(gpa, upstream_ctx);
    }

    /// REFCOUNTED: Safe cleanup when reference count reaches zero
    pub fn deinit(self: *UpstreamContext) void {
        logger.debug("upstream", "Cleaning up refcounted upstream context");

        self.upstream_url.deinit(self.gpa);
        self.gpa.free(self.upstream_request_data);

        // Clean up references
        // Note: downstream_ref is just an opaque pointer, no cleanup needed
        self.pooled_conn_ref.deinit();

        if (self.xml_processor) |*processor| {
            _ = processor;
        }

        const duration = std.time.milliTimestamp() - self.start_time;
        logger.debugf(self.gpa, "upstream", "Refcounted upstream request completed in {}ms", .{duration});
    }

    /// REFCOUNTED: Safe connection start with proper reference management
    pub fn startConnection(ref_upstream: *RefUpstreamContext) !void {
        const self = ref_upstream.get();
        logger.debugf(self.gpa, "upstream", "Starting refcounted request to {s}:{}", .{ self.upstream_url.host, self.upstream_url.port });

        // Get connection from pool
        const ref_pooled_conn = try self.connection_pool_ref.getConnection(self.upstream_url.host, self.upstream_url.port);

        // Store reference to pooled connection
        self.pooled_conn_ref.reset(ref_pooled_conn);

        // Create callback context that holds reference to upstream
        const callback_ctx = try self.gpa.create(UpstreamCallbackContext);
        callback_ctx.* = UpstreamCallbackContext{
            .upstream_ref = UpstreamPtr.init(ref_upstream), // This retains ref_upstream
            .gpa = self.gpa,
        };

        // Execute request using pooled connection
        try ref_pooled_conn.get().executeRequest(self.upstream_request_data, pooledResponseCallback, callback_ctx);
    }

    /// REFCOUNTED: Safe response processing
    fn processResponse(self: *UpstreamContext, response_data: []const u8) void {
        logger.debugf(self.gpa, "upstream", "Processing refcounted response ({} bytes)", .{response_data.len});

        if (response_data.len == 0) {
            self.notifyDownstreamError(502, "Bad Gateway - Empty response");
            return;
        }

        // Check if response contains XML content
        if (self.isXmlContent(response_data)) {
            self.processXmlResponse(response_data);
        } else {
            // Non-XML response - forward directly
            self.forwardResponse(response_data);
        }
    }

    fn isXmlContent(self: *UpstreamContext, response_data: []const u8) bool {
        _ = self;

        // Look for Content-Type: application/xml or text/xml
        if (std.mem.indexOf(u8, response_data, "\r\n\r\n")) |header_end| {
            const headers = response_data[0..header_end];

            if (std.ascii.indexOfIgnoreCase(headers, "content-type:")) |ct_start| {
                const ct_line_start = ct_start;
                const ct_line_end = std.mem.indexOfScalarPos(u8, headers, ct_start, '\r') orelse headers.len;
                const content_type = headers[ct_line_start..ct_line_end];

                return std.ascii.indexOfIgnoreCase(content_type, "xml") != null;
            }
        }

        // Fallback: check if body starts with XML
        if (std.mem.indexOf(u8, response_data, "\r\n\r\n")) |header_end| {
            const body_start = header_end + 4;
            if (body_start < response_data.len) {
                const body = std.mem.trim(u8, response_data[body_start..], " \t\n\r");
                return body.len > 0 and body[0] == '<';
            }
        }

        return false;
    }

    fn processXmlResponse(self: *UpstreamContext, response_data: []const u8) void {
        logger.debug("upstream", "Processing XML response via refcounted pool");

        // Initialize XML processor if needed
        if (self.xml_processor == null) {
            xml_parser.init(); // Global init
            self.xml_processor = xml_parser.XmlProcessor.init(self.gpa);
        }

        // Extract XML body from HTTP response
        const xml_body = if (std.mem.indexOf(u8, response_data, "\r\n\r\n")) |header_end|
            response_data[header_end + 4 ..]
        else
            response_data;

        // Process XML
        if (self.xml_processor) |*processor| {
            var xml_result = processor.processXml(xml_body, .inbound, self.upstream_url.host) catch {
                logger.warn("upstream", "XML processing failed");
                self.forwardResponse(response_data); // Forward as-is
                return;
            };
            defer xml_result.deinit(self.gpa);

            if (xml_result.is_well_formed) {
                if (xml_result.message_type) |msg_type| {
                    logger.debugf(self.gpa, "upstream", "Received valid {s} XML message via refcounted pool", .{@tagName(msg_type)});
                }
            } else {
                logger.warn("upstream", "Received malformed XML");
                if (xml_result.error_message) |err_msg| {
                    logger.warnf(self.gpa, "upstream", "XML error: {s}", .{err_msg});
                }
            }
        }

        // Forward the response (XML processing is for observability)
        self.forwardResponse(response_data);
    }

    fn forwardResponse(self: *UpstreamContext, response_data: []const u8) void {
        self.state = .complete;
        self.notifyDownstreamResponse(response_data);
    }

    fn notifyDownstreamError(self: *UpstreamContext, status_code: u16, message: []const u8) void {
        const error_response = std.fmt.allocPrint(self.gpa, "HTTP/1.1 {} {s}\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Content-Length: {}\r\n" ++
            "Connection: close\r\n" ++
            "\r\n" ++
            "{s}", .{ status_code, message, message.len, message }) catch {
            self.notifyDownstreamResponse("HTTP/1.1 500 Internal Server Error\r\n\r\n");
            return;
        };
        defer self.gpa.free(error_response);

        self.notifyDownstreamResponse(error_response);
    }

    /// REFCOUNTED: Safe notification to downstream connection
    fn notifyDownstreamResponse(self: *UpstreamContext, response_data: []const u8) void {
        if (self.response_callback) |callback| {
            logger.debug("upstream", "Notifying downstream with refcounted response");
            callback(self.downstream_ref, response_data);
        } else {
            logger.err("upstream", "No response callback set!");
        }
    }
};

/// REFCOUNTED: Callback context that holds references to prevent use-after-free
const UpstreamCallbackContext = struct {
    upstream_ref: UpstreamPtr,
    gpa: std.mem.Allocator,

    pub fn deinit(self: *UpstreamCallbackContext) void {
        self.upstream_ref.deinit();
        self.gpa.destroy(self);
    }
};

/// REFCOUNTED: Safe callback from pooled connection
fn pooledResponseCallback(context: *anyopaque, response_data: []const u8) void {
    const callback_ctx: *UpstreamCallbackContext = @ptrCast(@alignCast(context));
    defer callback_ctx.deinit(); // Clean up callback context when done

    // Check if upstream context is still valid
    if (callback_ctx.upstream_ref.get()) |ref_upstream| {
        const upstream = ref_upstream.get();
        logger.debug("upstream", "Received refcounted response from pool");
        upstream.processResponse(response_data);
    } else {
        logger.warn("upstream", "Upstream context no longer valid, dropping pooled response");
    }
}

/// REFCOUNTED: Convenience function that returns both the upstream context and a pointer to store
pub fn createUpstreamContext(
    gpa: std.mem.Allocator,
    downstream_ref: RefConnectionContext,
    pool: *connection_pool.ConnectionPool,
    upstream_url: []const u8,
    request: *types.HttpRequest,
    response_callback: *const fn (RefConnectionContext, []const u8) void,
) !struct { upstream: *RefUpstreamContext, ptr: UpstreamPtr } {
    const ref_upstream = try UpstreamContext.init(
        gpa,
        downstream_ref,
        pool,
        upstream_url,
        request,
        response_callback,
    );

    const upstream_ptr = UpstreamPtr.init(ref_upstream);

    return .{ .upstream = ref_upstream, .ptr = upstream_ptr };
}
