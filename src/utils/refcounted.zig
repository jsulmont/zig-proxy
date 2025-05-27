// src/utils/refcounted.zig
// Thread-safe reference counting for async components

const std = @import("std");

/// Reference counted wrapper for safe shared ownership in async contexts
/// T must have a `deinit()` method that takes no parameters
pub fn RefCounted(comptime T: type, comptime use_atomic: bool) type {
    const CounterType = if (use_atomic) std.atomic.Value(u32) else u32;

    return struct {
        const Self = @This();

        data: *T, // Store pointer instead of direct embed for opaque types
        ref_count: CounterType,
        allocator: std.mem.Allocator,

        /// Create a new reference counted object
        /// Initial reference count is 1
        pub fn init(allocator: std.mem.Allocator, data: T) !*Self {
            const self = try allocator.create(Self);

            // Allocate space for the data
            const data_ptr = try allocator.create(T);
            data_ptr.* = data;

            self.* = Self{
                .data = data_ptr,
                .ref_count = if (use_atomic) CounterType.init(1) else 1,
                .allocator = allocator,
            };
            return self;
        }

        /// Increment reference count and return self
        /// Thread-safe
        pub fn retain(self: *Self) *Self {
            if (use_atomic) {
                _ = self.ref_count.fetchAdd(1, .monotonic);
            } else {
                self.ref_count += 1;
            }
            return self;
        }

        /// Decrement reference count and destroy if reaches zero
        /// Thread-safe
        pub fn release(self: *Self) void {
            const old_count = if (use_atomic)
                self.ref_count.fetchSub(1, .monotonic)
            else blk: {
                const old = self.ref_count;
                self.ref_count -= 1;
                break :blk old;
            };

            if (old_count == 1) {
                // Last reference, clean up
                self.data.deinit();
                const allocator = self.allocator;
                allocator.destroy(self.data);
                allocator.destroy(self);
            }
        }

        /// Get current reference count (for debugging)
        pub fn getRefCount(self: *const Self) u32 {
            return if (use_atomic)
                self.ref_count.load(.monotonic)
            else
                self.ref_count;
        }

        /// Access the wrapped data
        pub fn get(self: *Self) *T {
            return self.data;
        }

        /// Access the wrapped data (const)
        pub fn getConst(self: *const Self) *const T {
            return self.data;
        }
    };
}

/// Non-atomic version for single-threaded use (libuv event loop)
pub fn Ref(comptime T: type) type {
    return RefCounted(T, false);
}

/// Atomic version for multi-threaded use
pub fn AtomicRef(comptime T: type) type {
    return RefCounted(T, true);
}

/// Smart pointer that automatically manages reference counting
/// Similar to a weak reference - doesn't affect object lifetime
pub fn RefPtr(comptime RefCountedType: type) type {
    return struct {
        const Self = @This();

        ptr: ?*RefCountedType,

        pub fn init(ref_obj: ?*RefCountedType) Self {
            if (ref_obj) |obj| {
                _ = obj.retain();
            }
            return Self{ .ptr = ref_obj };
        }

        pub fn deinit(self: *Self) void {
            if (self.ptr) |obj| {
                obj.release();
                self.ptr = null;
            }
        }

        pub fn get(self: *const Self) ?*RefCountedType {
            return self.ptr;
        }

        pub fn isValid(self: *const Self) bool {
            return self.ptr != null;
        }

        /// Replace the held reference
        pub fn reset(self: *Self, new_ref: ?*RefCountedType) void {
            if (self.ptr) |old_obj| {
                old_obj.release();
            }

            self.ptr = new_ref;
            if (new_ref) |obj| {
                _ = obj.retain();
            }
        }

        /// Transfer ownership (doesn't increment ref count)
        pub fn transfer(self: *Self, new_ref: ?*RefCountedType) void {
            if (self.ptr) |old_obj| {
                old_obj.release();
            }
            self.ptr = new_ref;
        }
    };
}

// Test usage example
test "basic refcounting" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Mock object that tracks if deinit was called
    const TestObject = struct {
        value: i32,
        deinit_called: *bool,

        const TestSelf = @This();

        pub fn init(value: i32, deinit_called: *bool) TestSelf {
            return TestSelf{
                .value = value,
                .deinit_called = deinit_called,
            };
        }

        pub fn deinit(self: *TestSelf) void {
            self.deinit_called.* = true;
        }
    };

    var deinit_called = false;
    const test_obj = TestObject.init(42, &deinit_called);

    // Create reference counted wrapper
    const RefTestObject = Ref(TestObject);
    const ref_obj = try RefTestObject.init(allocator, test_obj);

    // Initial ref count should be 1
    try testing.expectEqual(@as(u32, 1), ref_obj.getRefCount());
    try testing.expectEqual(@as(i32, 42), ref_obj.get().value);

    // Add another reference
    const ref_obj2 = ref_obj.retain();
    try testing.expectEqual(@as(u32, 2), ref_obj.getRefCount());
    try testing.expectEqual(ref_obj, ref_obj2);

    // Release one reference
    ref_obj2.release();
    try testing.expectEqual(@as(u32, 1), ref_obj.getRefCount());
    try testing.expect(!deinit_called);

    // Release last reference - should trigger deinit
    ref_obj.release();
    try testing.expect(deinit_called);
}

test "RefPtr usage" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const TestObject = struct {
        value: i32,

        pub fn deinit(self: *@This()) void {
            _ = self;
        }
    };

    const RefTestObject = Ref(TestObject);
    const ref_obj = try RefTestObject.init(allocator, TestObject{ .value = 100 });

    // Create smart pointers
    var ptr1 = RefPtr(RefTestObject).init(ref_obj);
    defer ptr1.deinit();

    var ptr2 = RefPtr(RefTestObject).init(ref_obj);
    defer ptr2.deinit();

    // Should have 3 references: original + 2 pointers
    try testing.expectEqual(@as(u32, 3), ref_obj.getRefCount());

    // Access through pointer
    if (ptr1.get()) |obj| {
        try testing.expectEqual(@as(i32, 100), obj.get().value);
    }

    // Release original reference
    ref_obj.release();

    // Should still have 2 references from pointers
    if (ptr1.get()) |obj| {
        try testing.expectEqual(@as(u32, 2), obj.getRefCount());
    }

    // Pointers will automatically release in defer
}
