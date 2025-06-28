// src/http.zig
// Wrapper around the fast HTTP parser

const std = @import("std");
const types = @import("core/types.zig");
const http_parser = @import("core/http_parser.zig");

pub const ParseError = error{
    InvalidMethod,
    InvalidVersion,
    HeadersOverflow,
    ParseFailed,
    Incomplete,
};

/// Parse HTTP request from raw bytes
pub fn parseRequest(allocator: std.mem.Allocator, data: []const u8) !types.HttpRequest {
    // NO COPY - parse directly from the input buffer 🐲
    var headers_buffer: [32]http_parser.Header = undefined;

    const parsed = http_parser.Request.parse(data, &headers_buffer) catch |err| {
        return switch (err) {
            http_parser.ParseError.Partial => ParseError.Incomplete,
            http_parser.ParseError.TooManyHeaders => ParseError.HeadersOverflow,
            http_parser.ParseError.Token => ParseError.ParseFailed,
            http_parser.ParseError.Version => ParseError.InvalidVersion,
            else => ParseError.ParseFailed,
        };
    };

    const method = types.HttpMethod.fromString(parsed.method) orelse {
        return ParseError.InvalidMethod;
    };

    const version: types.HttpRequest.HttpVersion = switch (parsed.minor_version) {
        0 => .HTTP_1_0,
        1 => .HTTP_1_1,
        else => return ParseError.InvalidVersion,
    };

    var headers = std.ArrayListUnmanaged(types.Header){};
    for (parsed.headers) |header| {
        try headers.append(allocator, types.Header{
            .name = header.name,
            .value = header.value,
        });
    }

    var body: ?[]const u8 = null;
    if (std.mem.indexOf(u8, data, "\r\n\r\n")) |header_end| {
        const body_start = header_end + 4;
        if (body_start < data.len) {
            const body_data = data[body_start..];
            if (body_data.len > 0) {
                body = body_data;
            }
        }
    }

    return types.HttpRequest{
        .method = method,
        .path = parsed.path,
        .version = version,
        .headers = headers,
        .body = body,
        .raw_buffer = data,
    };
}

pub fn buildUpstreamRequestDirect(allocator: std.mem.Allocator, method: []const u8, path: []const u8, headers: []const http_parser.Header, body: ?[]const u8, new_host: []const u8) ![]u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    const writer = buffer.writer();

    try writer.print("{s} {s} HTTP/1.1\r\n", .{ method, path });
    try writer.print("Host: {s}\r\n", .{new_host});

    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "host") or
            std.ascii.eqlIgnoreCase(header.name, "connection")) continue;

        try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    }

    try writer.writeAll("Connection: keep-alive\r\n");

    if (body) |b| {
        try writer.print("Content-Length: {}\r\n\r\n", .{b.len});
        try writer.writeAll(b);
    } else {
        try writer.writeAll("\r\n");
    }

    return buffer.toOwnedSlice();
}

/// Check if HTTP request is complete
pub fn isRequestComplete(data: []const u8) bool {
    const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse return false;

    const headers_section = data[0..header_end];
    var content_length: ?usize = null;

    var lines = std.mem.splitScalar(u8, headers_section, '\n');
    while (lines.next()) |line| {
        const clean_line = std.mem.trim(u8, line, "\r\n");
        if (std.ascii.startsWithIgnoreCase(clean_line, "content-length:")) {
            const colon_pos = std.mem.indexOf(u8, clean_line, ":") orelse continue;
            const value = std.mem.trim(u8, clean_line[colon_pos + 1 ..], " \t");
            content_length = std.fmt.parseInt(usize, value, 10) catch null;
            break;
        }
    }

    const headers_size = header_end + 4;

    if (content_length) |expected_body_size| {
        return data.len >= headers_size + expected_body_size;
    } else {
        return true; // No body expected
    }
}

/// Build HTTP request for upstream
pub fn buildUpstreamRequest(allocator: std.mem.Allocator, request: *const types.HttpRequest, host: []const u8) ![]u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    const writer = buffer.writer();

    try writer.print("{s} {s} HTTP/1.1\r\n", .{ request.method.toString(), request.path });

    try writer.print("Host: {s}\r\n", .{host});

    for (request.headers.items) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "host") or
            std.ascii.eqlIgnoreCase(header.name, "connection"))
        {
            continue;
        }
        try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    }

    try writer.writeAll("Connection: keep-alive\r\n");

    if (request.body) |body| {
        try writer.print("Content-Length: {}\r\n", .{body.len});
        try writer.writeAll("\r\n");
        try writer.writeAll(body);
    } else {
        try writer.writeAll("\r\n");
    }

    return buffer.toOwnedSlice();
}
