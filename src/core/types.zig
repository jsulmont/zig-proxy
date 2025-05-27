// src/core/types.zig
// Common types used throughout the proxy

const std = @import("std");

/// HTTP method enumeration
pub const HttpMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,

    pub fn toString(self: HttpMethod) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .HEAD => "HEAD",
            .OPTIONS => "OPTIONS",
            .PATCH => "PATCH",
        };
    }

    pub fn fromString(s: []const u8) ?HttpMethod {
        if (std.mem.eql(u8, s, "GET")) return .GET;
        if (std.mem.eql(u8, s, "POST")) return .POST;
        if (std.mem.eql(u8, s, "PUT")) return .PUT;
        if (std.mem.eql(u8, s, "DELETE")) return .DELETE;
        if (std.mem.eql(u8, s, "HEAD")) return .HEAD;
        if (std.mem.eql(u8, s, "OPTIONS")) return .OPTIONS;
        if (std.mem.eql(u8, s, "PATCH")) return .PATCH;
        return null;
    }
};

/// HTTP header structure
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// HTTP request structure
pub const HttpRequest = struct {
    method: HttpMethod,
    path: []const u8,
    version: HttpVersion,
    headers: std.ArrayListUnmanaged(Header),
    body: ?[]const u8,
    raw_buffer: []const u8,

    pub const HttpVersion = enum {
        HTTP_1_0,
        HTTP_1_1,
    };

    pub fn deinit(self: *HttpRequest, allocator: std.mem.Allocator) void {
        self.headers.deinit(allocator);
        // Don't free raw_buffer - we don't own it anymore
    }
};

/// HTTP response structure
pub const HttpResponse = struct {
    status_code: u16,
    reason_phrase: []const u8,
    version: HttpRequest.HttpVersion,
    headers: std.ArrayListUnmanaged(Header),
    body: []const u8,

    pub fn deinit(self: *HttpResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.reason_phrase);
        for (self.headers.items) |header| {
            allocator.free(header.name);
            allocator.free(header.value);
        }
        self.headers.deinit(allocator);
        allocator.free(self.body);
    }

    pub fn toBytes(self: *const HttpResponse, allocator: std.mem.Allocator) ![]u8 {
        var response = std.ArrayList(u8).init(allocator);
        defer response.deinit();

        const writer = response.writer();

        // Status line
        try writer.print("HTTP/1.1 {} {s}\r\n", .{ self.status_code, self.reason_phrase });

        // Headers
        for (self.headers.items) |header| {
            try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
        }

        // Content-Length
        try writer.print("Content-Length: {}\r\n", .{self.body.len});
        try writer.writeAll("Connection: close\r\n");
        try writer.writeAll("\r\n");

        // Body
        try writer.writeAll(self.body);

        return response.toOwnedSlice();
    }
};
