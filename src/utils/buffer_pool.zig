// src/utils/buffer_pool.zig
const std = @import("std");
const logger = @import("../logger.zig");

const BUFFER_SIZE = 8192;
const MAX_POOLED_BUFFERS = 1000; // Prevent unbounded growth

pub const BufferPool = struct {
    available: std.ArrayList([]u8),
    allocator: std.mem.Allocator,
    total_allocated: std.atomic.Value(u32),
    pool_hits: std.atomic.Value(u64),
    pool_misses: std.atomic.Value(u64),

    pub fn init(allocator: std.mem.Allocator) BufferPool {
        return BufferPool{
            .available = std.ArrayList([]u8).init(allocator),
            .allocator = allocator,
            .total_allocated = std.atomic.Value(u32).init(0),
            .pool_hits = std.atomic.Value(u64).init(0),
            .pool_misses = std.atomic.Value(u64).init(0),
        };
    }

    pub fn deinit(self: *BufferPool) void {
        // Free all pooled buffers
        for (self.available.items) |buf| {
            self.allocator.free(buf);
        }
        self.available.deinit();

        const total = self.total_allocated.load(.monotonic);
        const hits = self.pool_hits.load(.monotonic);
        const misses = self.pool_misses.load(.monotonic);

        logger.infof(self.allocator, "buffer_pool", "Pool stats - Total allocated: {}, Hits: {}, Misses: {}, Hit rate: {:.1}%", .{ total, hits, misses, if (hits + misses > 0) @as(f64, @floatFromInt(hits)) / @as(f64, @floatFromInt(hits + misses)) * 100.0 else 0.0 });
    }

    pub fn getBuffer(self: *BufferPool) []u8 {
        // Try to get from pool first
        if (self.available.items.len > 0) {
            const buf = self.available.orderedRemove(self.available.items.len - 1);
            _ = self.pool_hits.fetchAdd(1, .monotonic);
            return buf;
        }

        // Pool empty, allocate new
        const buf = self.allocator.alloc(u8, BUFFER_SIZE) catch {
            // Emergency fallback - should rarely happen
            logger.err("buffer_pool", "Failed to allocate buffer");
            return &[_]u8{};
        };

        _ = self.total_allocated.fetchAdd(1, .monotonic);
        _ = self.pool_misses.fetchAdd(1, .monotonic);

        return buf;
    }

    pub fn returnBuffer(self: *BufferPool, buf: []u8) void {
        // Validate buffer size
        if (buf.len != BUFFER_SIZE) {
            // Wrong size buffer, just free it
            if (buf.len > 0) {
                self.allocator.free(buf);
            }
            return;
        }

        // Don't let pool grow unbounded
        if (self.available.items.len >= MAX_POOLED_BUFFERS) {
            self.allocator.free(buf);
            return;
        }

        // Return to pool
        self.available.append(buf) catch {
            // Pool append failed, just free the buffer
            self.allocator.free(buf);
        };
    }

    // Pre-warm the pool with some buffers
    pub fn prewarm(self: *BufferPool, count: u32) void {
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            const buf = self.allocator.alloc(u8, BUFFER_SIZE) catch break;
            self.available.append(buf) catch {
                self.allocator.free(buf);
                break;
            };
            _ = self.total_allocated.fetchAdd(1, .monotonic);
        }

        logger.infof(self.allocator, "buffer_pool", "Pre-warmed pool with {} buffers", .{self.available.items.len});
    }

    pub fn getStats(self: *const BufferPool) PoolStats {
        return PoolStats{
            .available_buffers = @as(u32, @intCast(self.available.items.len)),
            .total_allocated = self.total_allocated.load(.monotonic),
            .pool_hits = self.pool_hits.load(.monotonic),
            .pool_misses = self.pool_misses.load(.monotonic),
        };
    }
};

pub const PoolStats = struct {
    available_buffers: u32,
    total_allocated: u32,
    pool_hits: u64,
    pool_misses: u64,

    pub fn hitRate(self: PoolStats) f64 {
        const total_requests = self.pool_hits + self.pool_misses;
        if (total_requests == 0) return 0.0;
        return @as(f64, @floatFromInt(self.pool_hits)) / @as(f64, @floatFromInt(total_requests)) * 100.0;
    }
};

// Global buffer pool
var global_buffer_pool: ?*BufferPool = null;

pub fn initGlobalPool(allocator: std.mem.Allocator) !void {
    const pool = try allocator.create(BufferPool);
    pool.* = BufferPool.init(allocator);

    // Pre-warm with some buffers for immediate use
    pool.prewarm(100);

    global_buffer_pool = pool;
    logger.info("buffer_pool", "Global buffer pool initialized");
}

pub fn deinitGlobalPool(allocator: std.mem.Allocator) void {
    if (global_buffer_pool) |pool| {
        pool.deinit();
        allocator.destroy(pool);
        global_buffer_pool = null;
        logger.info("buffer_pool", "Global buffer pool destroyed");
    }
}

pub fn getGlobalPool() ?*BufferPool {
    return global_buffer_pool;
}

// Convenience functions
pub fn getBuffer() []u8 {
    if (global_buffer_pool) |pool| {
        return pool.getBuffer();
    }
    // Fallback if no pool available
    return std.heap.c_allocator.alloc(u8, BUFFER_SIZE) catch &[_]u8{};
}

pub fn returnBuffer(buf: []u8) void {
    if (global_buffer_pool) |pool| {
        pool.returnBuffer(buf);
    } else if (buf.len > 0) {
        // No pool, just free
        std.heap.c_allocator.free(buf);
    }
}
