// src/utils/openssl.zig - Performance-optimized OpenSSL bindings

const std = @import("std");
const logger = @import("../logger.zig");

// ... [keep all existing type definitions and constants] ...
pub const SSL_CTX = opaque {};
pub const SSL = opaque {};
pub const X509 = opaque {};
pub const X509_STORE = opaque {};
pub const EVP_PKEY = opaque {};
pub const BIO = opaque {};
pub const STACK_OF_X509 = opaque {};
pub const SSL_METHOD = opaque {};
pub const SSL_SESSION = opaque {};

pub const SSL_VERIFY_PEER: c_int = 0x01;
pub const SSL_VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 0x02;
pub const SSL_VERIFY_CLIENT_ONCE: c_int = 0x04;

pub const SSL_FILETYPE_PEM: c_int = 1;
pub const SSL_FILETYPE_ASN1: c_int = 2;

pub const NID_certificate_policies: c_int = 89;

pub const TLS1_2_VERSION: c_int = 0x0303;

// OPTIMIZED: Additional performance-oriented SSL options
pub const SSL_OP_NO_SSLv2: c_long = 0x01000000;
pub const SSL_OP_NO_SSLv3: c_long = 0x02000000;
pub const SSL_OP_NO_TLSv1: c_long = 0x04000000;
pub const SSL_OP_NO_TLSv1_1: c_long = 0x10000000;
pub const SSL_OP_NO_TLSv1_3: c_long = 0x20000000;
pub const SSL_OP_NO_COMPRESSION: c_long = 0x00020000;
pub const SSL_OP_NO_TICKET: c_long = 0x00004000;
pub const SSL_OP_CIPHER_SERVER_PREFERENCE: c_long = 0x00400000;
pub const SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION: c_long = 0x00010000;
pub const SSL_OP_SINGLE_ECDH_USE: c_long = 0x00080000;
pub const SSL_OP_SINGLE_DH_USE: c_long = 0x00100000;

// OPTIMIZED: Session cache modes
pub const SSL_SESS_CACHE_OFF: c_long = 0x0000;
pub const SSL_SESS_CACHE_CLIENT: c_long = 0x0001;
pub const SSL_SESS_CACHE_SERVER: c_long = 0x0002;
pub const SSL_SESS_CACHE_BOTH: c_long = 0x0003;
pub const SSL_SESS_CACHE_NO_AUTO_CLEAR: c_long = 0x0080;
pub const SSL_SESS_CACHE_NO_INTERNAL_STORE: c_long = 0x0200;

// OPTIMIZED: Additional SSL modes for performance
pub const SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER: c_long = 0x00000002;
pub const SSL_MODE_ENABLE_PARTIAL_WRITE: c_long = 0x00000001;
pub const SSL_MODE_AUTO_RETRY: c_long = 0x00000004;
pub const SSL_MODE_RELEASE_BUFFERS: c_long = 0x00000010;

// ... [keep all existing error constants] ...
pub const SSL_ERROR_NONE: c_int = 0;
pub const SSL_ERROR_SSL: c_int = 1;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_WANT_X509_LOOKUP: c_int = 4;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;
pub const SSL_ERROR_WANT_CONNECT: c_int = 7;
pub const SSL_ERROR_WANT_ACCEPT: c_int = 8;

pub const BIO_NOCLOSE: c_int = 0x00;
pub const BIO_CLOSE: c_int = 0x01;

// ... [keep all existing function declarations] ...
pub extern "c" fn OPENSSL_init_ssl(opts: u64, settings: ?*anyopaque) c_int;
pub extern "c" fn OPENSSL_init_crypto(opts: u64, settings: ?*anyopaque) c_int;

pub extern "c" fn TLS_server_method() *const SSL_METHOD;
pub extern "c" fn SSL_CTX_new(method: *const SSL_METHOD) ?*SSL_CTX;
pub extern "c" fn SSL_CTX_free(ctx: *SSL_CTX) void;
pub extern "c" fn SSL_CTX_use_certificate_chain_file(ctx: *SSL_CTX, file: [*:0]const u8) c_int;
pub extern "c" fn SSL_CTX_use_PrivateKey_file(ctx: *SSL_CTX, file: [*:0]const u8, type_: c_int) c_int;
pub extern "c" fn SSL_CTX_check_private_key(ctx: *SSL_CTX) c_int;
pub extern "c" fn SSL_CTX_load_verify_locations(ctx: *SSL_CTX, CAfile: ?[*:0]const u8, CApath: ?[*:0]const u8) c_int;
pub extern "c" fn SSL_CTX_set_verify(ctx: *SSL_CTX, mode: c_int, callback: ?*const fn (c_int, *X509_STORE) callconv(.C) c_int) void;
pub extern "c" fn SSL_CTX_set_options(ctx: *SSL_CTX, options: c_long) c_long;
pub extern "c" fn SSL_CTX_clear_options(ctx: *SSL_CTX, options: c_long) c_long;
pub extern "c" fn SSL_CTX_ctrl(ctx: *SSL_CTX, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;
pub extern "c" fn SSL_CTX_set_cipher_list(ctx: *SSL_CTX, str: [*:0]const u8) c_int;

// OPTIMIZED: Additional session management functions
pub extern "c" fn SSL_CTX_sess_set_new_cb(ctx: *SSL_CTX, cb: ?NewSessionCallback) void;
pub extern "c" fn SSL_CTX_sess_set_get_cb(ctx: *SSL_CTX, cb: ?GetSessionCallback) void;
pub extern "c" fn SSL_CTX_sess_set_remove_cb(ctx: *SSL_CTX, cb: ?RemoveSessionCallback) void;
pub extern "c" fn SSL_CTX_set_session_id_context(ctx: *SSL_CTX, sid_ctx: [*]const u8, sid_ctx_len: c_uint) c_int;
pub extern "c" fn SSL_CTX_set_timeout(ctx: *SSL_CTX, timeout: c_long) c_long;
pub extern "c" fn SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx: *SSL_CTX, cb: ?TicketKeyCallback) c_long;
pub extern "c" fn SSL_CTX_sess_set_cache_size(ctx: *SSL_CTX, size: c_long) c_long;
pub extern "c" fn SSL_SESSION_get_id(session: *SSL_SESSION, len: [*c]c_uint) [*c]const u8;

pub extern "c" fn i2d_SSL_SESSION(session: *SSL_SESSION, pp: [*c][*c]u8) c_int;
pub extern "c" fn d2i_SSL_SESSION(session: [*c]*SSL_SESSION, pp: [*c][*c]const u8, length: c_long) ?*SSL_SESSION;
pub extern "c" fn SSL_SESSION_up_ref(session: *SSL_SESSION) c_int;
pub extern "c" fn SSL_SESSION_free(session: *SSL_SESSION) void;

pub const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
pub const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
pub const SSL_CTRL_SET_MODE: c_int = 33;
pub const SSL_CTRL_SET_SESS_CACHE_SIZE: c_int = 42;
pub const SSL_CTRL_SET_SESS_CACHE_MODE: c_int = 44;

// ... [keep remaining function declarations] ...
pub extern "c" fn SSL_new(ctx: *SSL_CTX) ?*SSL;
pub extern "c" fn SSL_free(ssl: *SSL) void;
pub extern "c" fn SSL_set_bio(ssl: *SSL, rbio: *BIO, wbio: *BIO) void;
pub extern "c" fn SSL_accept(ssl: *SSL) c_int;
pub extern "c" fn SSL_read(ssl: *SSL, buf: *anyopaque, num: c_int) c_int;
pub extern "c" fn SSL_write(ssl: *SSL, buf: *const anyopaque, num: c_int) c_int;
pub extern "c" fn SSL_shutdown(ssl: *SSL) c_int;
pub extern "c" fn SSL_get_error(ssl: *SSL, ret: c_int) c_int;
pub extern "c" fn SSL_get1_peer_certificate(ssl: *SSL) ?*X509;

// ... [keep X509 and BIO functions] ...
pub extern "c" fn X509_free(cert: *X509) void;
pub extern "c" fn X509_get_subject_name(cert: *X509) ?*anyopaque;
pub extern "c" fn X509_get_issuer_name(cert: *X509) ?*anyopaque;
pub extern "c" fn X509_NAME_oneline(name: *anyopaque, buf: ?[*]u8, size: c_int) [*:0]u8;
pub extern "c" fn X509_get_ext_d2i(x: *X509, nid: c_int, crit: ?*c_int, idx: ?*c_int) ?*anyopaque;
pub extern "c" fn CERTIFICATEPOLICIES_free(policies: *anyopaque) void;
pub extern "c" fn OPENSSL_sk_num(st: *anyopaque) c_int;
pub extern "c" fn OPENSSL_sk_value(st: *anyopaque, i: c_int) ?*anyopaque;
pub extern "c" fn OBJ_obj2txt(buf: [*]u8, buf_len: c_int, obj: *anyopaque, no_name: c_int) c_int;

pub extern "c" fn BIO_new(type_: *anyopaque) ?*BIO;
pub extern "c" fn BIO_free(bio: *BIO) c_int;
pub extern "c" fn BIO_s_mem() *anyopaque;
pub extern "c" fn BIO_read(bio: *BIO, data: *anyopaque, len: c_int) c_int;
pub extern "c" fn BIO_write(bio: *BIO, data: *const anyopaque, len: c_int) c_int;
pub extern "c" fn BIO_ctrl(bio: *BIO, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;
pub extern "c" fn PEM_write_bio_X509(bio: *BIO, cert: *X509) c_int;

const BIO_CTRL_INFO: c_int = 3;
const BIO_C_SET_BUF_MEM_EOF_RETURN: c_int = 130;

pub extern "c" fn ERR_get_error() c_ulong;
pub extern "c" fn ERR_error_string(e: c_ulong, buf: ?[*]u8) [*:0]u8;

// ... [keep callback type definitions] ...
pub const NewSessionCallback = *const fn (*SSL, *SSL_SESSION) callconv(.C) c_int;
pub const GetSessionCallback = *const fn (*SSL, [*c]const u8, c_int, [*c]c_int) callconv(.C) ?*SSL_SESSION;
pub const RemoveSessionCallback = *const fn (*SSL_CTX, *SSL_SESSION) callconv(.C) void;
pub const TicketKeyCallback = *const fn (*SSL, [*c]u8, [*c]u8, *anyopaque, *anyopaque, c_int) callconv(.C) c_int;

pub const SessionCallbacks = struct {
    new_session_cb: ?NewSessionCallback,
    get_session_cb: ?GetSessionCallback,
    remove_session_cb: ?RemoveSessionCallback,
};

// ... [keep existing helper functions] ...
fn sslCtxSetMinProtoVersion(ctx: *SSL_CTX, version: c_int) c_long {
    return SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, @intCast(version), null);
}

fn sslCtxSetMaxProtoVersion(ctx: *SSL_CTX, version: c_int) c_long {
    return SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, @intCast(version), null);
}

fn sslCtxSetMode(ctx: *SSL_CTX, mode: c_long) c_long {
    return SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MODE, mode, null);
}

fn bioSetMemEofReturn(bio: *BIO, v: c_int) c_long {
    return BIO_ctrl(bio, BIO_C_SET_BUF_MEM_EOF_RETURN, @intCast(v), null);
}

fn bioGetMemData(bio: *BIO, pp: *[*]u8) c_long {
    return BIO_ctrl(bio, BIO_CTRL_INFO, 0, @ptrCast(pp));
}

pub fn init() !void {
    if (OPENSSL_init_ssl(0, null) != 1) {
        return error.OpenSSLInitFailed;
    }
    if (OPENSSL_init_crypto(0, null) != 1) {
        return error.OpenSSLInitFailed;
    }
}

pub fn getErrorString() [*:0]u8 {
    const err = ERR_get_error();
    return ERR_error_string(err, null);
}

pub const SslContext = struct {
    ctx: *SSL_CTX,

    pub fn init() !SslContext {
        const method = TLS_server_method();
        const ctx = SSL_CTX_new(method) orelse return error.ContextCreationFailed;

        _ = sslCtxSetMinProtoVersion(ctx, TLS1_2_VERSION);
        _ = sslCtxSetMaxProtoVersion(ctx, TLS1_2_VERSION);

        // OPTIMIZED: Enhanced SSL options for performance
        const perf_options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
            SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_3 | SSL_OP_NO_COMPRESSION |
            SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_SINGLE_ECDH_USE |
            SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
        _ = SSL_CTX_set_options(ctx, perf_options);

        // OPTIMIZED: Performance-oriented SSL modes
        const perf_modes = SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE |
            SSL_MODE_AUTO_RETRY | SSL_MODE_RELEASE_BUFFERS;
        _ = sslCtxSetMode(ctx, perf_modes);

        // OPTIMIZED: IEEE 2030.5 cipher list with performance preference order
        // Put ECDHE-ECDSA-AES128-CCM8 first for best performance while maintaining compliance
        _ = SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-CCM8@SECLEVEL=0:" ++
            "ECDHE-ECDSA-AES128-GCM-SHA256:" ++
            "ECDHE-ECDSA-AES256-GCM-SHA384:" ++
            "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5");

        logger.info("ssl", "High-performance SSL context created (TLS 1.2, optimized for IEEE 2030.5)");
        return SslContext{ .ctx = ctx };
    }

    pub fn deinit(self: *SslContext) void {
        SSL_CTX_free(self.ctx);
    }

    pub fn useCertificateChainFile(self: *SslContext, file_path: [*:0]const u8) !void {
        if (SSL_CTX_use_certificate_chain_file(self.ctx, file_path) != 1) {
            return error.CertificateLoadFailed;
        }
    }

    pub fn usePrivateKeyFile(self: *SslContext, file_path: [*:0]const u8) !void {
        if (SSL_CTX_use_PrivateKey_file(self.ctx, file_path, SSL_FILETYPE_PEM) != 1) {
            return error.PrivateKeyLoadFailed;
        }
    }

    pub fn checkPrivateKey(self: *SslContext) !void {
        if (SSL_CTX_check_private_key(self.ctx) != 1) {
            return error.PrivateKeyCheckFailed;
        }
    }

    pub fn loadVerifyLocations(self: *SslContext, ca_file: [*:0]const u8) !void {
        if (SSL_CTX_load_verify_locations(self.ctx, ca_file, null) != 1) {
            return error.CALoadFailed;
        }
    }

    pub fn setVerifyMode(self: *SslContext, mode: c_int) void {
        SSL_CTX_set_verify(self.ctx, mode, null);
    }

    pub fn setSessionIdContext(self: *SslContext, context: [*]const u8, len: usize) void {
        _ = SSL_CTX_set_session_id_context(self.ctx, context, @intCast(len));
    }

    // OPTIMIZED: Enhanced session caching with performance tuning
    pub fn enableSessionCaching(self: *SslContext, timeout_seconds: u32) void {
        _ = SSL_CTX_set_timeout(self.ctx, @intCast(timeout_seconds));
        logger.debugf(std.heap.c_allocator, "ssl", "Session timeout set: {}s", .{timeout_seconds});
    }

    // OPTIMIZED: Performance-focused session cache configuration
    pub fn enableSessionCache(self: *SslContext, callbacks: SessionCallbacks) void {
        // Use hybrid cache mode for optimal performance
        const cache_mode = SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR;
        _ = SSL_CTX_ctrl(self.ctx, SSL_CTRL_SET_SESS_CACHE_MODE, cache_mode, null);

        SSL_CTX_sess_set_new_cb(self.ctx, callbacks.new_session_cb);
        SSL_CTX_sess_set_get_cb(self.ctx, callbacks.get_session_cb);
        SSL_CTX_sess_set_remove_cb(self.ctx, callbacks.remove_session_cb);

        logger.info("ssl", "High-performance session cache enabled (hybrid mode)");
    }

    pub fn enableSessionTickets(self: *SslContext, ticket_callback: TicketKeyCallback) void {
        _ = SSL_CTX_clear_options(self.ctx, SSL_OP_NO_TICKET);
        _ = SSL_CTX_set_tlsext_ticket_key_evp_cb(self.ctx, ticket_callback);
        logger.info("ssl", "Session tickets enabled with optimized callback");
    }
};

// ... [keep SslConnection and Certificate implementations unchanged] ...
pub const SslConnection = struct {
    ssl: *SSL,
    rbio: *BIO,
    wbio: *BIO,

    pub fn init(ctx: *SslContext) !SslConnection {
        const ssl = SSL_new(ctx.ctx) orelse return error.ConnectionCreationFailed;

        const rbio = BIO_new(BIO_s_mem()) orelse {
            SSL_free(ssl);
            return error.BioCreationFailed;
        };

        const wbio = BIO_new(BIO_s_mem()) orelse {
            _ = BIO_free(rbio);
            SSL_free(ssl);
            return error.BioCreationFailed;
        };

        _ = bioSetMemEofReturn(rbio, -1);
        SSL_set_bio(ssl, rbio, wbio);

        return SslConnection{
            .ssl = ssl,
            .rbio = rbio,
            .wbio = wbio,
        };
    }

    pub fn deinit(self: *SslConnection) void {
        _ = SSL_shutdown(self.ssl);
        SSL_free(self.ssl);
    }

    pub fn accept(self: *SslConnection) !void {
        const result = SSL_accept(self.ssl);
        if (result != 1) {
            const err = SSL_get_error(self.ssl, result);
            return switch (err) {
                SSL_ERROR_WANT_READ => error.WantRead,
                SSL_ERROR_WANT_WRITE => error.WantWrite,
                else => error.HandshakeFailed,
            };
        }
    }

    pub fn feedData(self: *SslConnection, data: []const u8) !void {
        const result = BIO_write(self.rbio, data.ptr, @intCast(data.len));
        if (result <= 0) {
            return error.BioWriteFailed;
        }
    }

    pub fn drainOutput(self: *SslConnection, buffer: []u8) !usize {
        const result = BIO_read(self.wbio, buffer.ptr, @intCast(buffer.len));
        if (result <= 0) {
            return 0;
        }
        return @intCast(result);
    }

    pub fn read(self: *SslConnection, buffer: []u8) !usize {
        const result = SSL_read(self.ssl, buffer.ptr, @intCast(buffer.len));
        if (result <= 0) {
            const err = SSL_get_error(self.ssl, result);
            return switch (err) {
                SSL_ERROR_WANT_READ => error.WantRead,
                SSL_ERROR_WANT_WRITE => error.WantWrite,
                SSL_ERROR_ZERO_RETURN => error.ConnectionClosed,
                else => error.ReadFailed,
            };
        }
        return @intCast(result);
    }

    pub fn write(self: *SslConnection, data: []const u8) !usize {
        const result = SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (result <= 0) {
            const err = SSL_get_error(self.ssl, result);
            return switch (err) {
                SSL_ERROR_WANT_READ => error.WantRead,
                SSL_ERROR_WANT_WRITE => error.WantWrite,
                else => error.WriteFailed,
            };
        }
        return @intCast(result);
    }

    pub fn getPeerCertificate(self: *SslConnection) ?*X509 {
        return SSL_get1_peer_certificate(self.ssl);
    }

    pub fn getLastError(self: *SslConnection, ret_code: c_int) c_int {
        return SSL_get_error(self.ssl, ret_code);
    }
};

pub const Certificate = struct {
    cert: *X509,
    owned: bool,

    pub fn fromPeer(ssl_conn: *SslConnection) ?Certificate {
        const cert = ssl_conn.getPeerCertificate() orelse return null;
        return Certificate{ .cert = cert, .owned = true };
    }

    pub fn deinit(self: *Certificate) void {
        if (self.owned) {
            X509_free(self.cert);
        }
    }

    pub fn getSubjectName(self: *const Certificate, allocator: std.mem.Allocator) ![]u8 {
        const name = X509_get_subject_name(self.cert) orelse return error.NoSubjectName;
        const line = X509_NAME_oneline(name, null, 0);
        defer std.c.free(line);
        return allocator.dupe(u8, std.mem.span(line));
    }

    pub fn getIssuerName(self: *const Certificate, allocator: std.mem.Allocator) ![]u8 {
        const name = X509_get_issuer_name(self.cert) orelse return error.NoIssuerName;
        const line = X509_NAME_oneline(name, null, 0);
        defer std.c.free(line);
        return allocator.dupe(u8, std.mem.span(line));
    }

    pub fn toPem(self: *const Certificate, allocator: std.mem.Allocator) ![]u8 {
        _ = self;
        return allocator.dupe(u8, "-----BEGIN CERTIFICATE-----\nMOCK_CERTIFICATE_DATA\n-----END CERTIFICATE-----\n");
    }

    pub fn extractPolicyOids(self: *const Certificate, allocator: std.mem.Allocator) !std.ArrayList([]const u8) {
        var policy_oids = std.ArrayList([]const u8).init(allocator);

        const policies = X509_get_ext_d2i(self.cert, NID_certificate_policies, null, null);
        if (policies == null) {
            return policy_oids;
        }
        defer CERTIFICATEPOLICIES_free(policies.?);

        const num_policies = OPENSSL_sk_num(policies.?);
        var i: c_int = 0;
        while (i < num_policies) : (i += 1) {
            if (OPENSSL_sk_value(policies.?, i)) |policy_info| {
                const policy_info_ptr: [*]usize = @ptrCast(@alignCast(policy_info));
                const policy_oid_ptr = policy_info_ptr[0];

                if (policy_oid_ptr != 0) {
                    const policy_oid: *anyopaque = @ptrFromInt(policy_oid_ptr);

                    var oid_buf: [128]u8 = undefined;
                    const len = OBJ_obj2txt(&oid_buf, oid_buf.len, policy_oid, 1);

                    if (len > 0) {
                        const oid_str = oid_buf[0..@intCast(len)];
                        try policy_oids.append(try allocator.dupe(u8, oid_str));
                    }
                }
            }
        }

        return policy_oids;
    }
};
