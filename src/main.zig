// src/main.zig

const std = @import("std");
const config = @import("config.zig");
const logger = @import("logger.zig");
const core = @import("core/context.zig");
const jemalloc = @import("core/jemalloc.zig");
const proxy = @import("proxy.zig");
const buffer_pool = @import("utils/buffer_pool.zig");

pub fn main() !void {
    const gpa = jemalloc.allocator();

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    var config_path: []const u8 = "config/server.toml";

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "-c") and i + 1 < args.len) {
            config_path = args[i + 1];
            i += 1;
        }
    }

    std.log.info("Loading config from: {s}", .{config_path});

    const cfg = config.Config.loadFromFile(gpa, config_path) catch |err| {
        std.log.err("Failed to load config: {}", .{err});
        return;
    };
    defer cfg.deinit();
    std.log.info("DEBUG: Config format = {any}", .{cfg.logging.format});

    logger.init(cfg.logging);
    logger.info("main", "Initializing buffer pool for memory optimization");
    try buffer_pool.initGlobalPool(gpa);
    defer buffer_pool.deinitGlobalPool(gpa);

    logger.info("main", "Starting IEEE 2030.5 Proxy with mTLS support");
    logger.infof(gpa, "main", " Listen address: {s}", .{cfg.server.listen_addr});
    logger.infof(gpa, "main", " Backends: {any}", .{cfg.upstream.backends});
    logger.infof(gpa, "main", " TLS enabled: cert={s}, key={s}, ca={s}", .{
        cfg.tls.chain_path,
        cfg.tls.key_path,
        cfg.tls.root_ca_path,
    });
    logger.infof(gpa, "main", " Detailed logging: {}", .{cfg.logging.detailed_logging});

    const colon_pos = std.mem.lastIndexOf(u8, cfg.server.listen_addr, ":") orelse {
        logger.err("main", "Invalid listen address format");
        return;
    };

    const addr_str = cfg.server.listen_addr[0..colon_pos];
    const port_str = cfg.server.listen_addr[colon_pos + 1 ..];
    const port = std.fmt.parseInt(u16, port_str, 10) catch {
        logger.err("main", "Invalid port number");
        return;
    };

    const listen_addr = std.net.Address.parseIp(addr_str, port) catch {
        logger.err("main", "Failed to parse listen address");
        return;
    };

    const global = core.GlobalContext.init(gpa, listen_addr, cfg.upstream.backends) catch |err| {
        logger.errf(gpa, "main", "Failed to create global context: {}", .{err});
        return;
    };
    defer global.deinit();

    var http_proxy = proxy.Proxy.init(gpa, global, cfg.tls, cfg.logging) catch |err| {
        logger.errf(gpa, "main", "Failed to create TLS proxy: {}", .{err});
        return;
    };
    defer http_proxy.deinit();

    logger.info("main", " TLS Proxy ready");
    logger.info("main", " Features: HTTP parsing, mTLS, certificate validation, arena memory management, request logging");

    http_proxy.run() catch |err| {
        logger.errf(gpa, "main", "Proxy error: {}", .{err});
        return;
    };

    logger.info("main", " Proxy shutdown complete");
}
