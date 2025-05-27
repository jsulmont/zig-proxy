// src/jemalloc.zig - Simple jemalloc integration
const std = @import("std");

// jemalloc stats functions (optional - for monitoring)
extern "c" fn je_malloc_stats_print(write_cb: ?*const fn (?*anyopaque, [*:0]const u8) callconv(.C) void, cbopaque: ?*anyopaque, opts: ?[*:0]const u8) void;
extern "c" fn je_mallctl(name: [*:0]const u8, oldp: ?*anyopaque, oldlenp: ?*usize, newp: ?*anyopaque, newlen: usize) c_int;

// Just use the system allocator - jemalloc will replace malloc/free automatically
pub fn allocator() std.mem.Allocator {
    return std.heap.c_allocator;
}

// Optional: jemalloc-specific utilities for monitoring
pub fn printStats() void {
    je_malloc_stats_print(null, null, null);
}

pub const MemStats = struct {
    allocated: usize,
    active: usize,
    metadata: usize,
    resident: usize,
};

pub fn getMemStats() MemStats {
    var allocated: usize = 0;
    var active: usize = 0;
    var metadata: usize = 0;
    var resident: usize = 0;

    var size: usize = @sizeOf(usize);

    _ = je_mallctl("stats.allocated", &allocated, &size, null, 0);
    _ = je_mallctl("stats.active", &active, &size, null, 0);
    _ = je_mallctl("stats.metadata", &metadata, &size, null, 0);
    _ = je_mallctl("stats.resident", &resident, &size, null, 0);

    return MemStats{
        .allocated = allocated,
        .active = active,
        .metadata = metadata,
        .resident = resident,
    };
}
