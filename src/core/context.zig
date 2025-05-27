// src/core/context.zig
// Context structures with proper arena lifetimes

const std = @import("std");
const arena = @import("arena.zig");
const types = @import("types.zig");

/// Global context with process lifetime
pub const GlobalContext = struct {
    arena: arena.ManagedArena,
    gpa: std.mem.Allocator,

    // Configuration
    listen_addr: std.net.Address,
    backends: [][]const u8,

    // State
    shutdown_requested: bool = false,

    pub fn init(gpa: std.mem.Allocator, listen_addr: std.net.Address, backend_urls: [][]const u8) !*GlobalContext {
        var global_arena = arena.ManagedArena.init(gpa);
        const allocator = global_arena.allocator();

        const self = try allocator.create(GlobalContext);
        self.* = GlobalContext{
            .arena = global_arena,
            .gpa = gpa,
            .listen_addr = listen_addr,
            .backends = try allocator.dupe([]const u8, backend_urls),
        };

        return self;
    }

    pub fn deinit(self: *GlobalContext) void {
        self.arena.deinit();
        // Note: Don't free self here - it was allocated from the arena
    }

    pub fn getAllocator(self: *GlobalContext) std.mem.Allocator {
        return self.arena.allocator();
    }

    pub fn requestShutdown(self: *GlobalContext) void {
        self.shutdown_requested = true;
    }

    pub fn shouldShutdown(self: *const GlobalContext) bool {
        return self.shutdown_requested;
    }

    pub fn getNextUpstream(self: *GlobalContext) []const u8 {
        if (self.backends.len == 0) return "";

        // Simple round-robin for now
        // TODO: Add atomic counter for thread safety in future iterations
        const index = @rem(std.time.milliTimestamp(), @as(i64, @intCast(self.backends.len)));
        return self.backends[@intCast(index)];
    }
};

/// Request context with independent arena lifetime
pub const RequestContext = struct {
    arena: arena.ManagedArena,
    gpa: std.mem.Allocator,

    // Request identification
    request_id: []const u8,
    start_time: i64,

    // Request data (arena allocated)
    request: ?types.HttpRequest = null,
    response: ?types.HttpResponse = null,

    // Processing state
    state: State = .parsing,
    backend_url: []const u8 = "",
    client_addr: []const u8 = "",

    const State = enum {
        parsing,
        upstream_connecting,
        upstream_sending,
        upstream_receiving,
        downstream_sending,
        complete,
        error_state,
    };

    pub fn init(gpa: std.mem.Allocator) !*RequestContext {
        // Allocate the RequestContext from GPA, not from arena
        const self = try gpa.create(RequestContext);

        // Initialize the arena
        var request_arena = arena.ManagedArena.init(gpa);
        const allocator = request_arena.allocator();

        self.* = RequestContext{
            .arena = request_arena,
            .gpa = gpa,
            .request_id = try arena.generateRequestId(allocator),
            .start_time = std.time.milliTimestamp(),
        };

        return self;
    }

    pub fn deinit(self: *RequestContext) void {
        // Clean up any remaining request/response data
        if (self.request) |*req| {
            req.deinit(self.arena.allocator());
        }
        if (self.response) |*resp| {
            resp.deinit(self.arena.allocator());
        }

        // Destroy arena (frees all request-scoped allocations)
        self.arena.deinit();

        // Now destroy the RequestContext itself using GPA
        self.gpa.destroy(self);
    }

    pub fn getAllocator(self: *RequestContext) std.mem.Allocator {
        return self.arena.allocator();
    }

    pub fn setRequest(self: *RequestContext, request: types.HttpRequest) void {
        self.request = request;
        self.state = .upstream_connecting;
    }

    pub fn setResponse(self: *RequestContext, response: types.HttpResponse) void {
        self.response = response;
        self.state = .downstream_sending;
    }

    pub fn markComplete(self: *RequestContext) void {
        self.state = .complete;
    }

    pub fn markError(self: *RequestContext) void {
        self.state = .error_state;
    }

    pub fn setBackend(self: *RequestContext, backend_url: []const u8) !void {
        self.backend_url = try self.arena.allocator().dupe(u8, backend_url);
    }

    pub fn setClientAddr(self: *RequestContext, addr: []const u8) !void {
        self.client_addr = try self.arena.allocator().dupe(u8, addr);
    }

    pub fn getProcessingTimeMs(self: *const RequestContext) f64 {
        const now = std.time.milliTimestamp();
        return @as(f64, @floatFromInt(now - self.start_time));
    }
};
