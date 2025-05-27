// src/request_logger.zig
const std = @import("std");
const xml_parser = @import("xml_parser.zig");
const uv = @import("utils/uv.zig");
const logger = @import("logger.zig");

pub const ResponseSource = enum {
    proxy,
    upstream,
};

pub const RequestLogEntry = struct {
    timestamp: i64,
    lfdi: ?[]const u8,
    sfdi: ?[]const u8,
    method: []const u8,
    path: []const u8,
    request_xml_message: ?[]const u8,
    response_source: ResponseSource,
    response_code: u16,
    response_xml_message: ?[]const u8,
    upstream_host: ?[]const u8,
    upstream_port: ?u16,

    pub fn deinit(self: *RequestLogEntry, allocator: std.mem.Allocator) void {
        if (self.lfdi) |lfdi| allocator.free(lfdi);
        if (self.sfdi) |sfdi| allocator.free(sfdi);
        allocator.free(self.method);
        allocator.free(self.path);
        if (self.request_xml_message) |msg| allocator.free(msg);
        if (self.response_xml_message) |msg| allocator.free(msg);
        if (self.upstream_host) |host| allocator.free(host);
    }

    pub fn toJson(self: *const RequestLogEntry, allocator: std.mem.Allocator) ![]u8 {
        return std.json.stringifyAlloc(allocator, self, .{});
    }
};

const LogWork = struct {
    work_req: uv.WorkReq,
    log_entry: RequestLogEntry,
    allocator: std.mem.Allocator,
    json_data: ?[]u8,

    fn deinit(self: *LogWork) void {
        self.log_entry.deinit(self.allocator);
        if (self.json_data) |data| {
            self.allocator.free(data);
        }
        self.allocator.destroy(self);
    }
};

pub const AsyncRequestLogger = struct {
    allocator: std.mem.Allocator,
    loop: *uv.Loop,
    enabled: bool,

    pub fn init(allocator: std.mem.Allocator, loop: *uv.Loop, enabled: bool) AsyncRequestLogger {
        return AsyncRequestLogger{
            .allocator = allocator,
            .loop = loop,
            .enabled = enabled,
        };
    }

    pub fn logRequest(self: *AsyncRequestLogger, log_entry: RequestLogEntry) !void {
        if (!self.enabled) {
            var mut_entry = log_entry;
            mut_entry.deinit(self.allocator);
            return;
        }

        const work = try self.allocator.create(LogWork);
        work.* = LogWork{
            .work_req = uv.WorkReq.init(),
            .log_entry = log_entry,
            .allocator = self.allocator,
            .json_data = null,
        };

        work.work_req.setData(work);
        try work.work_req.queue(self.loop, workCallback, afterWorkCallback);
    }

    fn workCallback(req: *uv.uv_work_t) callconv(.C) void {
        const work_req: *uv.WorkReq = @ptrCast(@alignCast(req));
        const work = work_req.getData(LogWork) orelse return;

        work.json_data = work.log_entry.toJson(work.allocator) catch |err| {
            logger.errf(work.allocator, "request_logger", "Failed to serialize log entry: {}", .{err});
            return;
        };
    }

    fn afterWorkCallback(req: *uv.uv_work_t, status: c_int) callconv(.C) void {
        const work_req: *uv.WorkReq = @ptrCast(@alignCast(req));
        const work = work_req.getData(LogWork) orelse return;
        defer work.deinit();

        if (status != 0) {
            logger.errf(work.allocator, "request_logger", "Async log work failed: {}", .{status});
            return;
        }

        if (work.json_data) |json| {
            const stderr = std.io.getStdErr().writer();
            stderr.print("{s}\n", .{json}) catch {};
        }
    }
};
