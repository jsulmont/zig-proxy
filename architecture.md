# Zig Reverse Proxy Foundation Blueprint

**Version:** 1.0  
**Date:** 2025-01-12  
**Purpose:** Foundation architecture for high-performance reverse proxy with libuv and arena-based memory management

---

## 1. Core Principles

### 1.1 Memory Management Philosophy

- **Arena-per-scope:** Each logical scope gets its own arena allocator
- **No nested arenas:** Arenas are independent, not hierarchical
- **Clear ownership:** Every object has exactly one owner
- **Fail-fast cleanup:** Arena destruction frees everything at once

### 1.2 Handle Ownership Rules

- **libuv handles never stored in arenas directly**
- **Handles paired with context structs that reference arenas**
- **Only the owner closes handles**
- **Every `uv_close()` has matching context cleanup**

---

## 2. Arena Architecture

### 2.1 Arena Scopes

| Arena Type | Lifetime | Purpose | Destroyed When |
|------------|----------|---------|----------------|
| **Global Arena** | Process lifetime | Config, loop, pools | Process exit |
| **Connection Arena** | Downstream connection | Connection state, parser | Connection close |
| **Request Arena** | HTTP request | Request/response data | Request complete |
| **Pool Arena** | Upstream pool | Pooled connections | Pool shutdown |

### 2.2 Arena Independence

```text
[Global Arena]     ←─ process lifetime
[Connection Arena] ←─ downstream connection lifetime  
[Request Arena]    ←─ HTTP request lifetime (independent!)
[Pool Arena]       ←─ upstream pool lifetime
```

**Key:** Request Arena is **not nested** under Connection Arena. A request can outlive its downstream connection.

---

## 3. Core Data Structures

### 3.1 Global Context

```zig
const GlobalContext = struct {
    arena: *std.heap.ArenaAllocator,
    loop: uv.Loop,
    upstream_pool: *UpstreamPool,
    config: *ProxyConfig,
    metrics: *Metrics,
    
    pub fn init(gpa: std.mem.Allocator) !*GlobalContext {
        const arena = try gpa.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(gpa);
        const allocator = arena.allocator();
        
        const self = try allocator.create(GlobalContext);
        self.arena = arena;
        // Initialize other fields...
        return self;
    }
    
    pub fn deinit(self: *GlobalContext, gpa: std.mem.Allocator) void {
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};
```

### 3.2 Downstream Connection Context

```zig
const DownstreamConn = struct {
    // libuv handle (system allocated)
    tcp: uv.Tcp,
    
    // Arena for this connection's lifetime
    arena: *std.heap.ArenaAllocator,
    gpa: std.mem.Allocator, // For arena cleanup
    
    // Connection state (arena allocated)
    parser: *HttpParser,
    state: ConnectionState,
    tls_ctx: ?*TlsContext,
    
    // Backref to global
    global: *GlobalContext,
    
    pub fn init(gpa: std.mem.Allocator, global: *GlobalContext) !*DownstreamConn {
        const arena = try gpa.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(gpa);
        const allocator = arena.allocator();
        
        const self = try allocator.create(DownstreamConn);
        self.arena = arena;
        self.gpa = gpa;
        self.global = global;
        
        // Initialize TCP handle
        try self.tcp.init(&global.loop);
        self.tcp.setData(self);
        
        // Initialize connection state
        self.parser = try allocator.create(HttpParser);
        self.parser.* = HttpParser.init(allocator);
        
        return self;
    }
    
    pub fn close(self: *DownstreamConn) void {
        // Close libuv handle (will trigger closeCallback)
        self.tcp.close(closeCallback);
    }
    
    fn closeCallback(handle: *anyopaque) callconv(.C) void {
        const tcp: *uv.Tcp = @ptrCast(@alignCast(handle));
        const self = tcp.getData(DownstreamConn) orelse return;
        
        // Destroy arena (frees all connection-scoped allocations)
        const gpa = self.gpa;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};
```

### 3.3 Request Context (Spans Downstream + Upstream)

```zig
const RequestContext = struct {
    // Arena for this request's lifetime
    arena: *std.heap.ArenaAllocator,
    gpa: std.mem.Allocator, // For arena cleanup
    
    // Request ID for tracing
    request_id: []const u8,
    start_time: i64,
    
    // Downstream request data (arena allocated)
    method: []const u8,
    path: []const u8,
    headers: []Header,
    body: ?[]const u8,
    
    // Upstream connection (borrowed from pool)
    upstream_conn: ?*UpstreamConn,
    
    // Upstream request/response data (arena allocated)
    upstream_request: ?*UpstreamRequest,
    upstream_response: ?*UpstreamResponse,
    
    // Associated connections
    downstream: *DownstreamConn,
    
    // Request state
    state: RequestState,
    timeout_timer: ?uv.Timer,
    
    const RequestState = enum {
        parsing,
        upstream_connecting,
        upstream_sending,
        upstream_receiving,
        downstream_sending,
        complete,
        error_state,
    };
    
    pub fn init(gpa: std.mem.Allocator, downstream: *DownstreamConn) !*RequestContext {
        const arena = try gpa.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(gpa);
        const allocator = arena.allocator();
        
        const self = try allocator.create(RequestContext);
        self.arena = arena;
        self.gpa = gpa;
        self.downstream = downstream;
        self.state = .parsing;
        
        // Generate request ID
        self.request_id = try generateRequestId(allocator);
        self.start_time = std.time.nanoTimestamp();
        
        return self;
    }
    
    pub fn complete(self: *RequestContext) void {
        // Stop any timers
        if (self.timeout_timer) |*timer| {
            timer.stop();
            timer.close(null);
        }
        
        // Return upstream connection to pool if borrowed
        if (self.upstream_conn) |conn| {
            self.downstream.global.upstream_pool.returnConnection(conn);
        }
        
        // Destroy arena (frees all request-scoped allocations)
        const gpa = self.gpa;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};
```

### 3.4 Upstream Connection (Pool-managed)

```zig
const UpstreamConn = struct {
    // libuv handle (system allocated)
    tcp: uv.Tcp,
    
    // Pool arena reference
    pool_arena: *std.heap.ArenaAllocator,
    
    // Connection state (pool arena allocated)
    backend_url: []const u8,
    state: UpstreamState,
    last_used: i64,
    request_count: u32,
    
    // Pool management
    parent_pool: *UpstreamPool,
    is_busy: bool,
    
    const UpstreamState = enum {
        connecting,
        idle,
        busy,
        closing,
        closed,
    };
    
    pub fn init(pool_arena: *std.heap.ArenaAllocator, pool: *UpstreamPool, backend_url: []const u8) !*UpstreamConn {
        const allocator = pool_arena.allocator();
        
        const self = try allocator.create(UpstreamConn);
        self.pool_arena = pool_arena;
        self.parent_pool = pool;
        self.backend_url = try allocator.dupe(u8, backend_url);
        self.state = .connecting;
        self.last_used = std.time.timestamp();
        self.request_count = 0;
        self.is_busy = false;
        
        // Initialize TCP handle
        try self.tcp.init(&pool.global.loop);
        self.tcp.setData(self);
        
        return self;
    }
    
    pub fn markBusy(self: *UpstreamConn) void {
        self.is_busy = true;
        self.state = .busy;
        self.last_used = std.time.timestamp();
    }
    
    pub fn markIdle(self: *UpstreamConn) void {
        self.is_busy = false;
        self.state = .idle;
        self.last_used = std.time.timestamp();
    }
    
    pub fn close(self: *UpstreamConn) void {
        self.state = .closing;
        self.tcp.close(upstreamCloseCallback);
    }
    
    fn upstreamCloseCallback(handle: *anyopaque) callconv(.C) void {
        const tcp: *uv.Tcp = @ptrCast(@alignCast(handle));
        const self = tcp.getData(UpstreamConn) orelse return;
        
        self.state = .closed;
        // Note: Don't free here - pool manages lifetime
        self.parent_pool.removeConnection(self);
    }
};
```

---

## 4. Arena Creation & Destruction Points

### 4.1 Arena Lifecycle Hooks

| Event | Arena Action | Responsible Component |
|-------|--------------|----------------------|
| **Process Start** | Create Global Arena | `main()` |
| **Downstream Accept** | Create Connection Arena | Connection manager |
| **HTTP Request Start** | Create Request Arena | Request parser |
| **Request Complete** | Destroy Request Arena | Request handler |
| **Downstream Close** | Destroy Connection Arena | Connection close callback |
| **Pool Shutdown** | Destroy Pool Arena | Pool manager |
| **Process Exit** | Destroy Global Arena | `main()` cleanup |

### 4.2 Request Flow with Arena Management

```
1. [Downstream Accept]
   → Create Connection Arena
   → Create DownstreamConn in Connection Arena
   
2. [HTTP Request Received]  
   → Create Request Arena
   → Create RequestContext in Request Arena
   → Parse request data into Request Arena
   
3. [Upstream Processing]
   → Borrow UpstreamConn from Pool Arena
   → Store upstream state in Request Arena
   
4. [Response Complete]
   → Return UpstreamConn to pool
   → Destroy Request Arena ←← ALL REQUEST DATA FREED
   
5. [Connection Close]
   → Destroy Connection Arena ←← ALL CONNECTION DATA FREED
```

---

## 5. libuv Handle Safety Patterns

### 5.1 Handle + Arena Safe Usage

**Problem:** libuv callbacks can fire after arena is destroyed

**Solution:** Always embed arena validity checks in handles

```zig
const WriteContext = struct {
    write_req: uv.WriteReq,
    request_ctx: *RequestContext, // Reference to arena owner
    buffer: []const u8,           // Points into arena
    
    pub fn init(request_ctx: *RequestContext, data: []const u8) !*WriteContext {
        // Allocate from system (not arena) - handle lifetime independent
        const self = try request_ctx.gpa.create(WriteContext);
        self.write_req = uv.WriteReq.init();
        self.request_ctx = request_ctx;
        self.buffer = data; // Points into request arena
        
        self.write_req.setData(self);
        return self;
    }
    
    fn writeCallback(req: *anyopaque, status: c_int) callconv(.C) void {
        const write_req: *uv.WriteReq = @ptrCast(@alignCast(req));
        const self = write_req.getData(WriteContext) orelse return;
        
        // Check if request is still valid (arena not destroyed)
        if (self.request_ctx.state == .complete) {
            // Request already completed, just cleanup write context
            self.request_ctx.gpa.destroy(self);
            return;
        }
        
        // Safe to access arena data
        // ... handle write completion ...
        
        // Cleanup write context
        self.request_ctx.gpa.destroy(self);
    }
};
```

### 5.2 Timer Safety Pattern

```zig
const TimeoutContext = struct {
    timer: uv.Timer,
    request_ctx: *RequestContext,
    
    fn timeoutCallback(timer: *anyopaque) callconv(.C) void {
        const timer_handle: *uv.Timer = @ptrCast(@alignCast(timer));
        const self = timer_handle.getData(TimeoutContext) orelse return;
        
        // Check arena validity
        if (self.request_ctx.state == .complete) {
            return; // Request already completed
        }
        
        // Trigger timeout handling
        self.request_ctx.handleTimeout();
    }
};
```

### 5.3 Connection Pooling Safety

```zig
const UpstreamPool = struct {
    arena: *std.heap.ArenaAllocator,
    connections: std.HashMap([]const u8, std.ArrayList(*UpstreamConn)),
    
    pub fn borrowConnection(self: *UpstreamPool, backend_url: []const u8) ?*UpstreamConn {
        const pool = self.connections.getPtr(backend_url) orelse return null;
        
        for (pool.items) |conn| {
            if (!conn.is_busy and conn.state == .idle) {
                conn.markBusy();
                return conn;
            }
        }
        return null;
    }
    
    pub fn returnConnection(self: *UpstreamPool, conn: *UpstreamConn) void {
        // Connection stays in Pool Arena - just mark as available
        conn.markIdle();
        
        // Optional: Check if connection should be closed due to age/errors
        if (conn.shouldClose()) {
            conn.close(); // Will trigger pool removal via callback
        }
    }
};
```

---

## 6. Error Handling & Cleanup Patterns

### 6.1 Request Cancellation

```zig
pub fn cancelRequest(request_ctx: *RequestContext, reason: CancelReason) void {
    // Mark as complete to prevent further callbacks
    request_ctx.state = .complete;
    
    // Cancel any pending upstream operations
    if (request_ctx.upstream_conn) |conn| {
        // Don't close connection, just return to pool
        request_ctx.upstream_conn = null;
        conn.parent_pool.returnConnection(conn);
    }
    
    // Stop timers
    if (request_ctx.timeout_timer) |*timer| {
        timer.stop();
        timer.close(null);
    }
    
    // Arena destruction handles all memory cleanup
    request_ctx.complete();
}
```

### 6.2 Connection Error Handling

```zig
pub fn handleConnectionError(downstream: *DownstreamConn, error_code: c_int) void {
    // Cancel all active requests on this connection
    // (Implementation would track active requests per connection)
    
    // Close connection (triggers arena cleanup)
    downstream.close();
}
```

---

## 7. Implementation Checklist

### 7.1 Foundation Implementation Order

1. **✅ Arena managers** - Create arena wrapper types
2. **✅ Core context structs** - GlobalContext, DownstreamConn, RequestContext, UpstreamConn  
3. **✅ Handle safety patterns** - WriteContext, TimeoutContext patterns
4. **✅ Basic request flow** - Accept → Parse → Forward → Respond
5. **✅ Connection pooling** - Pool management with proper lifetimes
6. **✅ Error handling** - Cancellation, timeouts, connection errors
7. **✅ Performance optimizations** - Reuse patterns, buffer management

### 7.2 Safety Guarantees to Validate

- [ ] **No use-after-free:** All callbacks check arena validity
- [ ] **No double-close:** Handle ownership clearly defined  
- [ ] **No memory leaks:** Every arena has clear destruction point
- [ ] **No callback-after-free:** Handle contexts outlive arenas when needed
- [ ] **Graceful cancellation:** Requests can be cancelled cleanly
- [ ] **Pool safety:** Connections properly returned/removed from pools

---
