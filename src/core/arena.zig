// src/core/arena.zig
// Arena wrapper with lifetime tracking and safety checks

const std = @import("std");

/// Arena wrapper that tracks its own validity and provides safe access
pub const ManagedArena = struct {
    arena: std.heap.ArenaAllocator,
    gpa: std.mem.Allocator,
    is_valid: bool,

    pub fn init(gpa: std.mem.Allocator) ManagedArena {
        return ManagedArena{
            .arena = std.heap.ArenaAllocator.init(gpa),
            .gpa = gpa,
            .is_valid = true,
        };
    }

    pub fn allocator(self: *ManagedArena) std.mem.Allocator {
        std.debug.assert(self.is_valid);
        return self.arena.allocator();
    }

    pub fn deinit(self: *ManagedArena) void {
        if (self.is_valid) {
            self.is_valid = false;
            self.arena.deinit();
        }
    }

    pub fn isValid(self: *const ManagedArena) bool {
        return self.is_valid;
    }
};

/// Generate unique request ID for tracing
pub fn generateRequestId(allocator: std.mem.Allocator) ![]const u8 {
    var random_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);

    return std.fmt.allocPrint(allocator, "{x:0>8}-{x:0>4}-{x:0>4}-{x:0>4}-{x:0>12}", .{
        std.mem.readInt(u32, random_bytes[0..4], .big),
        std.mem.readInt(u16, random_bytes[4..6], .big),
        std.mem.readInt(u16, random_bytes[6..8], .big),
        std.mem.readInt(u16, random_bytes[8..10], .big),
        (@as(u64, std.mem.readInt(u32, random_bytes[10..14], .big)) << 16) | std.mem.readInt(u16, random_bytes[14..16], .big),
    }) catch {
        const timestamp = @as(u64, @intCast(std.time.milliTimestamp()));
        return std.fmt.allocPrint(allocator, "req-{x}", .{timestamp}) catch return "req-unknown";
    };
}
