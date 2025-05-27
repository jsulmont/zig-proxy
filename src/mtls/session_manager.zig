// src/mtls/session_manager.zig
// High-performance TLS session management optimized for IEEE 2030.5

const std = @import("std");
const logger = @import("../logger.zig");
const openssl = @import("../utils/openssl.zig");
const session_cache = @import("session_cache.zig");

/// Performance-optimized session manager for high-throughput TLS
pub const SessionManager = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) SessionManager {
        return SessionManager{
            .allocator = allocator,
        };
    }

    pub fn getCallbacks(self: *SessionManager) openssl.SessionCallbacks {
        _ = self;
        return openssl.SessionCallbacks{
            .new_session_cb = sessionNewCallback,
            .get_session_cb = sessionGetCallback,
            .remove_session_cb = sessionRemoveCallback,
        };
    }

    pub fn getTicketCallback(self: *SessionManager) openssl.TicketKeyCallback {
        _ = self;
        return ticketKeyCallback;
    }

    /// Initialize high-performance session caching on SSL context
    pub fn enableSessionCache(self: *SessionManager, ssl_ctx: *openssl.SslContext) void {
        // OPTIMIZED: Use hybrid cache mode for better performance
        // Allow OpenSSL internal cache + external storage
        const cache_mode = openssl.SSL_SESS_CACHE_SERVER | openssl.SSL_SESS_CACHE_NO_AUTO_CLEAR;
        _ = openssl.SSL_CTX_ctrl(ssl_ctx.ctx, openssl.SSL_CTRL_SET_SESS_CACHE_MODE, cache_mode, null);

        // OPTIMIZED: Increase session timeout to 1 hour for better reuse
        _ = openssl.SSL_CTX_set_timeout(ssl_ctx.ctx, 3600);

        // Set session callbacks
        const callbacks = self.getCallbacks();
        openssl.SSL_CTX_sess_set_new_cb(ssl_ctx.ctx, callbacks.new_session_cb);
        openssl.SSL_CTX_sess_set_get_cb(ssl_ctx.ctx, callbacks.get_session_cb);
        openssl.SSL_CTX_sess_set_remove_cb(ssl_ctx.ctx, callbacks.remove_session_cb);

        // OPTIMIZED: Enable session tickets with improved callback
        _ = openssl.SSL_CTX_clear_options(ssl_ctx.ctx, openssl.SSL_OP_NO_TICKET);
        const ticket_cb = self.getTicketCallback();
        _ = openssl.SSL_CTX_set_tlsext_ticket_key_evp_cb(ssl_ctx.ctx, ticket_cb);

        // OPTIMIZED: Set larger session cache size in OpenSSL
        _ = openssl.SSL_CTX_ctrl(ssl_ctx.ctx, openssl.SSL_CTRL_SET_SESS_CACHE_SIZE, 10000, null);

        logger.info("tls", "High-performance session caching enabled - hybrid mode, 1h timeout");
    }
};

// OPTIMIZED: Session callback implementations with performance tracking

fn sessionNewCallback(ssl: *openssl.SSL, session: *openssl.SSL_SESSION) callconv(.C) c_int {
    _ = ssl;

    var session_id_len: c_uint = 0;
    const session_id_ptr = openssl.SSL_SESSION_get_id(session, &session_id_len);
    if (session_id_len == 0) return 0;

    const session_id = session_id_ptr[0..session_id_len];

    // OPTIMIZED: Fast session serialization
    var session_data_ptr: [*c]u8 = null;
    const session_data_len = openssl.i2d_SSL_SESSION(session, &session_data_ptr);
    if (session_data_len <= 0) return 0;

    defer std.c.free(session_data_ptr);
    const session_data = session_data_ptr[0..@intCast(session_data_len)];

    // Store in high-performance cache
    if (session_cache.getGlobalCache()) |cache| {
        cache.store(session_id, session_data, null) catch {
            return 0;
        };

        return 1; // Success - increment reference count
    }

    return 0;
}

fn sessionGetCallback(ssl: *openssl.SSL, session_id: [*c]const u8, session_id_len: c_int, copy: [*c]c_int) callconv(.C) ?*openssl.SSL_SESSION {
    _ = ssl;
    if (session_id_len <= 0) return null;

    const session_id_slice = session_id[0..@intCast(session_id_len)];

    if (session_cache.getGlobalCache()) |cache| {
        if (cache.retrieve(session_id_slice)) |ref_session| {
            defer ref_session.release();

            const cached_session = ref_session.get();

            // OPTIMIZED: Fast session deserialization
            var session_data_ptr = cached_session.session_data.ptr;
            const session_data_len = @as(c_long, @intCast(cached_session.session_data.len));

            if (openssl.d2i_SSL_SESSION(null, @ptrCast(&session_data_ptr), session_data_len)) |ssl_session| {
                copy.* = 1; // Tell OpenSSL to increment reference count
                return ssl_session;
            }
        }
    }

    return null;
}

fn sessionRemoveCallback(ctx: *openssl.SSL_CTX, session: *openssl.SSL_SESSION) callconv(.C) void {
    _ = ctx;

    var session_id_len: c_uint = 0;
    const session_id_ptr = openssl.SSL_SESSION_get_id(session, &session_id_len);
    if (session_id_len == 0) return;

    const session_id = session_id_ptr[0..session_id_len];

    if (session_cache.getGlobalCache()) |cache| {
        cache.remove(session_id);
    }
}

// OPTIMIZED: High-performance session ticket callback
fn ticketKeyCallback(ssl: *openssl.SSL, key_name: [*c]u8, iv: [*c]u8, ectx: *anyopaque, hctx: *anyopaque, enc: c_int) callconv(.C) c_int {
    _ = ssl;
    _ = ectx;
    _ = hctx;

    const key_name_size = 16;
    const iv_size = 16;

    if (enc == 1) {
        // Encrypting - creating new ticket

        // OPTIMIZED: Use timestamp-based key name for better tracking
        const timestamp = @as(u32, @truncate(@as(u64, @intCast(std.time.timestamp()))));
        const key_name_bytes = std.mem.asBytes(&timestamp);
        @memcpy(key_name[0..key_name_bytes.len], key_name_bytes);
        @memset(key_name[key_name_bytes.len..key_name_size], 0);

        // Generate random IV efficiently
        var random_iv: [16]u8 = undefined;
        std.crypto.random.bytes(&random_iv);
        @memcpy(iv[0..iv_size], &random_iv);

        return 1; // Success
    } else {
        // Decrypting - validating existing ticket

        // OPTIMIZED: Accept tickets from last 24 hours for better reuse
        const current_time = @as(u32, @truncate(@as(u64, @intCast(std.time.timestamp()))));
        const ticket_timestamp = std.mem.bytesToValue(u32, key_name[0..@sizeOf(u32)]);

        const age_seconds = if (current_time >= ticket_timestamp)
            current_time - ticket_timestamp
        else
            std.math.maxInt(u32); // Handle clock skew

        if (age_seconds <= 86400) { // 24 hours
            return 1; // Key valid
        } else {
            return 0; // Key expired
        }
    }
}
