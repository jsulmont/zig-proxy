// src/mtls/tls.zig - High-performance TLS connection handling
const std = @import("std");
const openssl = @import("../utils/openssl.zig");
const config = @import("../config.zig");
const logger = @import("../logger.zig");
const session_manager = @import("session_manager.zig");
const session_cache = @import("session_cache.zig");
const validation = @import("validation.zig");
const certificate = @import("certificate.zig");

pub const TlsServer = struct {
    allocator: std.mem.Allocator,
    ssl_ctx: openssl.SslContext,
    session_mgr: session_manager.SessionManager,
    vendor_config: ?config.VendorConfig,
    validator: ?validation.CertificateValidator,

    pub fn init(allocator: std.mem.Allocator, tls_config: config.TlsConfig) !TlsServer {
        try openssl.init();

        var ssl_ctx = try openssl.SslContext.init();
        errdefer ssl_ctx.deinit();

        // OPTIMIZED: Initialize session management first
        try session_cache.initGlobalCache(allocator, 20000, 3600);

        // OPTIMIZED: Set session ID context (important for session reuse)
        const session_id_context = "zig-proxy-ieee2030.5-v2";
        ssl_ctx.setSessionIdContext(session_id_context.ptr, session_id_context.len);

        // OPTIMIZED: Enable high-performance session caching
        ssl_ctx.enableSessionCaching(3600); // 1 hour timeout

        var session_mgr = session_manager.SessionManager.init(allocator);
        session_mgr.enableSessionCache(&ssl_ctx);

        // Load certificates
        const cert_path = try allocator.dupeZ(u8, tls_config.chain_path);
        defer allocator.free(cert_path);
        try ssl_ctx.useCertificateChainFile(cert_path.ptr);

        const key_path = try allocator.dupeZ(u8, tls_config.key_path);
        defer allocator.free(key_path);
        try ssl_ctx.usePrivateKeyFile(key_path.ptr);

        try ssl_ctx.checkPrivateKey();

        const ca_path = try allocator.dupeZ(u8, tls_config.root_ca_path);
        defer allocator.free(ca_path);
        try ssl_ctx.loadVerifyLocations(ca_path.ptr);

        ssl_ctx.setVerifyMode(openssl.SSL_VERIFY_PEER | openssl.SSL_VERIFY_FAIL_IF_NO_PEER_CERT);

        logger.info("tls", "High-performance TLS server initialized");
        logger.debugf(allocator, "tls", "  Certificate: {s}", .{tls_config.chain_path});
        logger.debugf(allocator, "tls", "  Private key: {s}", .{tls_config.key_path});
        logger.debugf(allocator, "tls", "  CA file: {s}", .{tls_config.root_ca_path});
        logger.info("tls", "  Features: Session resumption, tickets, 20K cache, 1h timeout");

        return TlsServer{
            .allocator = allocator,
            .ssl_ctx = ssl_ctx,
            .session_mgr = session_mgr,
            .vendor_config = null,
            .validator = null,
        };
    }

    pub fn initWithVendorConfig(allocator: std.mem.Allocator, tls_config: config.TlsConfig, vendor_config: config.VendorConfig) !TlsServer {
        var server = try init(allocator, tls_config);

        // Store vendor config
        server.vendor_config = vendor_config;

        // Initialize validator with vendor config
        server.validator = try validation.CertificateValidator.initWithVendorConfig(allocator, false, // don't skip OID validation
            vendor_config);

        logger.infof(allocator, "tls", "Registered {} vendor OIDs for certificate validation", .{vendor_config.vendors.len});

        return server;
    }

    pub fn deinit(self: *TlsServer) void {
        if (self.validator) |*validator| {
            validator.deinit();
        }
        self.ssl_ctx.deinit();
        session_cache.deinitGlobalCache(self.allocator);
    }

    pub fn createConnection(self: *TlsServer) !TlsConnection {
        return TlsConnection.init(&self.ssl_ctx, self.allocator, self.validator);
    }
};

pub const TlsConnection = struct {
    ssl_conn: openssl.SslConnection,
    allocator: std.mem.Allocator,
    client_cert: ?openssl.Certificate = null,
    client_cert_info: ?certificate.CertificateInfo = null,
    handshake_done: bool = false,
    validator: ?validation.CertificateValidator,

    pub fn init(ssl_ctx: *openssl.SslContext, allocator: std.mem.Allocator, validator: ?validation.CertificateValidator) !TlsConnection {
        const ssl_conn = try openssl.SslConnection.init(ssl_ctx);

        return TlsConnection{
            .ssl_conn = ssl_conn,
            .allocator = allocator,
            .validator = validator,
        };
    }

    pub fn deinit(self: *TlsConnection) void {
        if (self.client_cert_info) |*cert_info| {
            cert_info.deinit(self.allocator);
        }
        if (self.client_cert) |*cert| {
            cert.deinit();
        }
        self.ssl_conn.deinit();
    }

    pub fn feedSocketData(self: *TlsConnection, data: []const u8) !void {
        if (data.len == 0) return;
        try self.ssl_conn.feedData(data);
    }

    pub fn drainToSocket(self: *TlsConnection, buffer: []u8) !usize {
        return self.ssl_conn.drainOutput(buffer);
    }

    pub fn continueHandshake(self: *TlsConnection) !void {
        self.ssl_conn.accept() catch |err| {
            switch (err) {
                error.WantRead, error.WantWrite => {
                    return err;
                },
                else => {
                    logger.errf(self.allocator, "tls", "TLS handshake error: {}", .{err});
                    const ssl_err = openssl.getErrorString();
                    logger.errf(self.allocator, "tls", "OpenSSL error: {s}", .{ssl_err});

                    // Clear error queue
                    while (openssl.ERR_get_error() != 0) {}

                    return err;
                },
            }
        };

        if (!self.handshake_done) {
            self.handshake_done = true;

            // Process client certificate
            if (openssl.Certificate.fromPeer(&self.ssl_conn)) |cert| {
                self.client_cert = cert;

                // Validate certificate if validator is available
                if (self.validator) |*validator| {
                    self.client_cert_info = validator.validateCertificate(&cert) catch |err| {
                        logger.errf(self.allocator, "tls", "Certificate validation failed: {}", .{err});
                        return err;
                    };

                    // Log certificate info
                    if (self.client_cert_info) |cert_info| {
                        logger.infof(self.allocator, "tls", "Client certificate validated - LFDI: {s}, SFDI: {s}", .{ cert_info.lfdi orelse "none", cert_info.sfdi orelse "none" });

                        if (cert_info.hardware_identity) |hw| {
                            logger.infof(self.allocator, "tls", "Device: {s} ({s})", .{ hw.device_type.toString(), hw.vendor_name orelse "Unknown Vendor" });
                        }
                    }
                } else {
                    // No validator, just extract basic info
                    const subject = cert.getSubjectName(self.allocator) catch |err| blk: {
                        logger.warnf(self.allocator, "tls", "Failed to get certificate subject: {}", .{err});
                        break :blk try self.allocator.dupe(u8, "unknown");
                    };
                    defer self.allocator.free(subject);

                    const issuer = cert.getIssuerName(self.allocator) catch |err| blk: {
                        logger.warnf(self.allocator, "tls", "Failed to get certificate issuer: {}", .{err});
                        break :blk try self.allocator.dupe(u8, "unknown");
                    };
                    defer self.allocator.free(issuer);

                    logger.infof(self.allocator, "tls", "Client certificate - Subject: {s}, Issuer: {s}", .{ subject, issuer });
                }
            } else {
                logger.warn("tls", "No client certificate available after handshake");
            }
        }
    }

    pub fn isHandshakeDone(self: *const TlsConnection) bool {
        return self.handshake_done;
    }

    pub fn read(self: *TlsConnection, buffer: []u8) !usize {
        return self.ssl_conn.read(buffer);
    }

    pub fn write(self: *TlsConnection, data: []const u8) !usize {
        return self.ssl_conn.write(data);
    }

    pub fn getClientCertificate(self: *TlsConnection) ?*const openssl.Certificate {
        return if (self.client_cert) |*cert| cert else null;
    }

    pub fn getClientCertificateInfo(self: *TlsConnection) ?*const certificate.CertificateInfo {
        return if (self.client_cert_info) |*info| info else null;
    }
};
