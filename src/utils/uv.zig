// src/utils/uv.zig - Fixed libuv wrapper with proper error translation
const std = @import("std");

// TODO: Replace with actual libuv bindings
const LOOP_SIZE = 1072;
const HANDLE_SIZE = 264;
const REQ_SIZE = 256;

// Opaque libuv types
pub const uv_loop_t = opaque {};
pub const uv_handle_t = opaque {};
pub const uv_stream_t = opaque {};
pub const uv_tcp_t = opaque {};
pub const uv_timer_t = opaque {};
pub const uv_req_t = opaque {};
pub const uv_write_t = opaque {};
pub const uv_connect_t = opaque {};
pub const uv_getaddrinfo_t = opaque {};
pub const uv_work_t = opaque {};

// Work queue callback types
pub const uv_work_cb = *const fn (*uv_work_t) callconv(.C) void;
pub const uv_after_work_cb = *const fn (*uv_work_t, c_int) callconv(.C) void;

// Base handle type
pub const Handle = extern struct {
    data: [HANDLE_SIZE]u8 align(@alignOf(*anyopaque)),

    pub fn setData(self: *Handle, user_data: ?*anyopaque) void {
        uv_handle_set_data(@ptrCast(self), user_data);
    }

    pub fn getData(self: *const Handle, comptime T: type) ?*T {
        return @ptrCast(@alignCast(uv_handle_get_data(@ptrCast(self))));
    }

    pub fn close(self: *Handle, callback: ?CloseCb) void {
        uv_close(@ptrCast(self), callback);
    }

    pub fn safeClose(self: *Handle, callback: ?CloseCb) void {
        if (uv_is_closing(@ptrCast(self)) == 0) {
            uv_close(@ptrCast(self), callback);
        }
    }
};

pub const Loop = extern struct {
    data: [LOOP_SIZE]u8 align(@alignOf(*anyopaque)),

    pub fn init(self: *Loop) !void {
        if (uv_loop_init(@ptrCast(self)) != 0) {
            return error.LoopInitFailed;
        }
    }

    pub fn close(self: *Loop) void {
        _ = uv_loop_close(@ptrCast(self));
    }

    pub fn run(self: *Loop, mode: c_int) c_int {
        return uv_run(@ptrCast(self), mode);
    }

    pub fn stop(self: *Loop) void {
        uv_stop(@ptrCast(self));
    }
};

pub const Tcp = extern struct {
    data: [HANDLE_SIZE]u8 align(@alignOf(*anyopaque)),

    pub fn init(self: *Tcp, loop: *Loop) !void {
        if (uv_tcp_init(@ptrCast(loop), @ptrCast(self)) != 0) {
            return error.TcpInitFailed;
        }
    }

    pub fn bind(self: *Tcp, addr: *const std.posix.sockaddr, flags: c_uint) !void {
        if (uv_tcp_bind(@ptrCast(self), addr, flags) != 0) {
            return error.BindFailed;
        }
    }

    pub fn listen(self: *Tcp, backlog: c_int, callback: ConnectionCb) !void {
        if (uv_listen(@ptrCast(self), backlog, callback) != 0) {
            return error.ListenFailed;
        }
    }

    pub fn accept(self: *Tcp, client: *Tcp) !void {
        if (uv_accept(@ptrCast(self), @ptrCast(client)) != 0) {
            return error.AcceptFailed;
        }
    }

    pub fn connect(self: *Tcp, req: *ConnectReq, addr: *const std.posix.sockaddr, callback: ConnectCb) !void {
        if (uv_tcp_connect(@ptrCast(req), @ptrCast(self), addr, callback) != 0) {
            return error.ConnectFailed;
        }
    }

    pub fn startReading(self: *Tcp, alloc_cb: AllocCb, read_cb: ReadCb) !void {
        const result = uv_read_start(@ptrCast(self), alloc_cb, read_cb);
        if (result != 0) {
            return error.ReadStartFailed;
        }
    }

    pub fn stopReading(self: *Tcp) void {
        _ = uv_read_stop(@ptrCast(self));
    }

    pub fn write(self: *Tcp, req: *WriteReq, bufs: []const Buffer, callback: WriteCb) !void {
        if (uv_write(@ptrCast(req), @ptrCast(self), bufs.ptr, @intCast(bufs.len), callback) != 0) {
            return error.WriteFailed;
        }
    }

    pub fn close(self: *Tcp, callback: ?CloseCb) void {
        uv_close(@ptrCast(self), callback);
    }

    pub fn safeClose(self: *Tcp, callback: ?CloseCb) void {
        if (uv_is_closing(@ptrCast(self)) == 0) {
            uv_close(@ptrCast(self), callback);
        }
    }

    pub fn setData(self: *Tcp, user_data: ?*anyopaque) void {
        uv_handle_set_data(@ptrCast(self), user_data);
    }

    pub fn getData(self: *const Tcp, comptime T: type) ?*T {
        return @ptrCast(@alignCast(uv_handle_get_data(@ptrCast(self))));
    }

    pub fn getWriteQueueSize(self: *const Tcp) usize {
        return uv_stream_get_write_queue_size(@ptrCast(self));
    }

    pub fn keepAlive(self: *Tcp, enable: bool, delay: u32) !void {
        if (uv_tcp_keepalive(@ptrCast(self), if (enable) 1 else 0, delay) != 0) {
            return error.KeepAliveFailed;
        }
    }

    pub fn getFileDescriptor(self: *const Tcp) !c_int {
        var fd: c_int = undefined;
        if (uv_fileno(@ptrCast(@constCast(self)), &fd) != 0) {
            return error.GetFdFailed;
        }
        return fd;
    }
};

pub const Timer = extern struct {
    data: [HANDLE_SIZE]u8 align(@alignOf(*anyopaque)),

    pub fn init(self: *Timer, loop: *Loop) !void {
        if (uv_timer_init(@ptrCast(loop), @ptrCast(self)) != 0) {
            return error.TimerInitFailed;
        }
    }

    pub fn start(self: *Timer, callback: TimerCb, timeout: u64, repeat: u64) !void {
        if (uv_timer_start(@ptrCast(self), callback, timeout, repeat) != 0) {
            return error.TimerStartFailed;
        }
    }

    pub fn stop(self: *Timer) void {
        _ = uv_timer_stop(@ptrCast(self));
    }

    pub fn close(self: *Timer, callback: ?CloseCb) void {
        uv_close(@ptrCast(self), callback);
    }

    pub fn safeClose(self: *Timer, callback: ?CloseCb) void {
        if (uv_is_closing(@ptrCast(self)) == 0) {
            uv_close(@ptrCast(self), callback);
        }
    }

    pub fn setData(self: *Timer, user_data: ?*anyopaque) void {
        uv_handle_set_data(@ptrCast(self), user_data);
    }

    pub fn getData(self: *const Timer, comptime T: type) ?*T {
        return @ptrCast(@alignCast(uv_handle_get_data(@ptrCast(self))));
    }
};

const RequestBase = extern struct {
    data: ?*anyopaque,
    type: c_int,
    reserved: [6]?*anyopaque,
};

pub const WriteReq = extern struct {
    data: [REQ_SIZE]u8 align(@alignOf(*anyopaque)),

    pub fn init() WriteReq {
        return WriteReq{
            .data = std.mem.zeroes([REQ_SIZE]u8),
        };
    }

    pub fn setData(self: *WriteReq, user_data: ?*anyopaque) void {
        const req_ptr: *RequestBase = @ptrCast(self);
        req_ptr.data = user_data;
    }

    pub fn getData(self: *const WriteReq, comptime T: type) ?*T {
        const req_ptr: *const RequestBase = @ptrCast(self);
        return @ptrCast(@alignCast(req_ptr.data));
    }
};

pub const ConnectReq = extern struct {
    data: [REQ_SIZE]u8 align(@alignOf(*anyopaque)),

    pub fn init() ConnectReq {
        return ConnectReq{
            .data = std.mem.zeroes([REQ_SIZE]u8),
        };
    }

    pub fn setData(self: *ConnectReq, user_data: ?*anyopaque) void {
        const req_ptr: *RequestBase = @ptrCast(self);
        req_ptr.data = user_data;
    }

    pub fn getData(self: *const ConnectReq, comptime T: type) ?*T {
        const req_ptr: *const RequestBase = @ptrCast(self);
        return @ptrCast(@alignCast(req_ptr.data));
    }
};

pub const GetAddrInfoReq = extern struct {
    data: [REQ_SIZE]u8 align(@alignOf(*anyopaque)),

    pub fn init() GetAddrInfoReq {
        return GetAddrInfoReq{
            .data = std.mem.zeroes([REQ_SIZE]u8),
        };
    }

    pub fn setData(self: *GetAddrInfoReq, user_data: ?*anyopaque) void {
        const req_ptr: *RequestBase = @ptrCast(self);
        req_ptr.data = user_data;
    }

    pub fn getData(self: *const GetAddrInfoReq, comptime T: type) ?*T {
        const req_ptr: *const RequestBase = @ptrCast(self);
        return @ptrCast(@alignCast(req_ptr.data));
    }
};

pub const WorkReq = extern struct {
    data: [REQ_SIZE]u8 align(@alignOf(*anyopaque)),

    pub fn init() WorkReq {
        return WorkReq{
            .data = std.mem.zeroes([REQ_SIZE]u8),
        };
    }

    pub fn setData(self: *WorkReq, user_data: ?*anyopaque) void {
        const req_ptr: *RequestBase = @ptrCast(self);
        req_ptr.data = user_data;
    }

    pub fn getData(self: *const WorkReq, comptime T: type) ?*T {
        const req_ptr: *const RequestBase = @ptrCast(self);
        return @ptrCast(@alignCast(req_ptr.data));
    }

    pub fn queue(self: *WorkReq, loop: *Loop, work_cb: uv_work_cb, after_work_cb: uv_after_work_cb) !void {
        if (uv_queue_work(@ptrCast(loop), @ptrCast(self), work_cb, after_work_cb) != 0) {
            return error.QueueWorkFailed;
        }
    }
};

pub const AllocCb = *const fn (handle: *anyopaque, suggested_size: usize, buf: *Buffer) callconv(.C) void;
pub const ReadCb = *const fn (stream: *anyopaque, nread: isize, buf: *const Buffer) callconv(.C) void;
pub const WriteCb = *const fn (req: *anyopaque, status: c_int) callconv(.C) void;
pub const ConnectCb = *const fn (req: *anyopaque, status: c_int) callconv(.C) void;
pub const ConnectionCb = *const fn (server: *anyopaque, status: c_int) callconv(.C) void;
pub const CloseCb = *const fn (handle: *anyopaque) callconv(.C) void;
pub const GetAddrInfoCb = *const fn (req: *anyopaque, status: c_int, res: ?*AddrInfo) callconv(.C) void;
pub const TimerCb = *const fn (handle: *anyopaque) callconv(.C) void;

pub const Buffer = extern struct {
    base: [*]u8,
    len: usize,

    pub fn init(data: []u8) Buffer {
        return Buffer{
            .base = data.ptr,
            .len = data.len,
        };
    }
};

pub const AddrInfo = extern struct {
    flags: c_int,
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    addrlen: usize,
    addr: ?*std.posix.sockaddr,
    canonname: ?[*:0]u8,
    next: ?*AddrInfo,
};

pub const UV_RUN_DEFAULT: c_int = 0;
pub const UV_RUN_ONCE: c_int = 1;
pub const UV_RUN_NOWAIT: c_int = 2;

// FIXED: Correct libuv error codes (they are negative!)
pub const UV_EOF: c_int = -4095;
pub const UV_ECONNRESET: c_int = -4077;
pub const UV_EPIPE: c_int = -4047;
pub const UV_ECONNABORTED: c_int = -4079;
pub const UV_ENOTCONN: c_int = -4042;
pub const UV_ETIMEDOUT: c_int = -4039;
pub const UV_ECONNREFUSED: c_int = -4078;

pub extern "c" fn uv_loop_init(loop: *uv_loop_t) c_int;
pub extern "c" fn uv_loop_close(loop: *uv_loop_t) c_int;
pub extern "c" fn uv_run(loop: *uv_loop_t, mode: c_int) c_int;
pub extern "c" fn uv_stop(loop: *uv_loop_t) void;

pub extern "c" fn uv_tcp_init(loop: *uv_loop_t, handle: *uv_tcp_t) c_int;
pub extern "c" fn uv_tcp_bind(handle: *uv_tcp_t, addr: *const std.posix.sockaddr, flags: c_uint) c_int;
pub extern "c" fn uv_listen(stream: *uv_stream_t, backlog: c_int, cb: ConnectionCb) c_int;
pub extern "c" fn uv_accept(server: *uv_stream_t, client: *uv_stream_t) c_int;
pub extern "c" fn uv_read_start(stream: *uv_stream_t, alloc_cb: AllocCb, read_cb: ReadCb) c_int;
pub extern "c" fn uv_read_stop(stream: *uv_stream_t) c_int;
pub extern "c" fn uv_write(req: *uv_write_t, handle: *uv_stream_t, bufs: [*]const Buffer, nbufs: c_uint, cb: WriteCb) c_int;
pub extern "c" fn uv_tcp_connect(req: *uv_connect_t, handle: *uv_tcp_t, addr: *const std.posix.sockaddr, cb: ConnectCb) c_int;
pub extern "c" fn uv_close(handle: *uv_handle_t, close_cb: ?CloseCb) void;
pub extern "c" fn uv_is_closing(handle: *uv_handle_t) c_int;

pub extern "c" fn uv_timer_init(loop: *uv_loop_t, handle: *uv_timer_t) c_int;
pub extern "c" fn uv_timer_start(handle: *uv_timer_t, cb: TimerCb, timeout: u64, repeat: u64) c_int;
pub extern "c" fn uv_timer_stop(handle: *uv_timer_t) c_int;

pub extern "c" fn uv_getaddrinfo(loop: *uv_loop_t, req: *uv_getaddrinfo_t, cb: GetAddrInfoCb, hostname: [*:0]const u8, service: [*:0]const u8, hints: ?*const AddrInfo) c_int;
pub extern "c" fn uv_freeaddrinfo(ai: *AddrInfo) void;

pub extern "c" fn uv_queue_work(loop: *uv_loop_t, req: *uv_work_t, work_cb: uv_work_cb, after_work_cb: uv_after_work_cb) c_int;

pub extern "c" fn uv_strerror(err: c_int) [*:0]const u8;
pub extern "c" fn uv_handle_set_data(handle: *uv_handle_t, data: ?*anyopaque) void;
pub extern "c" fn uv_handle_get_data(handle: *const uv_handle_t) ?*anyopaque;
pub extern "c" fn uv_stream_get_write_queue_size(stream: *uv_stream_t) usize;

pub extern "c" fn uv_tcp_keepalive(handle: *uv_tcp_t, enable: c_int, delay: c_uint) c_int;
pub extern "c" fn uv_fileno(handle: *uv_handle_t, fd: *c_int) c_int;

pub extern "c" fn uv_loop_alive(loop: *uv_loop_t) c_int;
pub extern "c" fn uv_is_active(handle: *uv_handle_t) c_int;
pub extern "c" fn uv_handle_size(type: c_int) usize;
pub extern "c" fn uv_req_size(type: c_int) usize;

pub fn errorString(err: c_int) []const u8 {
    return std.mem.span(uv_strerror(err));
}

pub fn isConnectionError(err: c_int) bool {
    return err == UV_EOF or
        err == UV_ECONNRESET or
        err == UV_EPIPE or
        err == UV_ECONNABORTED or
        err == UV_ENOTCONN or
        err == UV_ETIMEDOUT or
        err == UV_ECONNREFUSED;
}

pub const handleSetData = Handle.setData;
pub fn handleGetData(handle: *const anyopaque, comptime T: type) ?*T {
    return @ptrCast(@alignCast(uv_handle_get_data(@ptrCast(handle))));
}
