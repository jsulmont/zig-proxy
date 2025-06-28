// src/core/context.zig ]
const std = @import("std");

pub const GlobalContext = struct {
    allocator: std.mem.Allocator,

    // Configuration
    listen_addr: std.net.Address,
    backends: [][]const u8,

    // State
    shutdown_requested: bool = false,

    pub fn init(allocator: std.mem.Allocator, listen_addr: std.net.Address, backend_urls: [][]const u8) !*GlobalContext {
        const self = try allocator.create(GlobalContext);
        self.* = GlobalContext{
            .allocator = allocator,
            .listen_addr = listen_addr,
            .backends = try allocator.dupe([]const u8, backend_urls),
        };
        return self;
    }

    pub fn deinit(self: *GlobalContext) void {
        self.allocator.free(self.backends);
        self.allocator.destroy(self);
    }

    pub fn requestShutdown(self: *GlobalContext) void {
        self.shutdown_requested = true;
    }

    pub fn shouldShutdown(self: *const GlobalContext) bool {
        return self.shutdown_requested;
    }

    pub fn getNextUpstream(self: *GlobalContext) []const u8 {
        if (self.backends.len == 0) return "";
        const index = @rem(std.time.milliTimestamp(), @as(i64, @intCast(self.backends.len)));
        return self.backends[@intCast(index)];
    }
};
