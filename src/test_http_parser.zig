const std = @import("std");
const testing = std.testing;
const http_parser = @import("core/http_parser.zig");

const Request = http_parser.Request;
const Response = http_parser.Response;
const Header = http_parser.Header;
const ParseError = http_parser.ParseError;

// Test helper to create a temporary header array
fn createHeaders(comptime size: usize) [size]Header {
    return [_]Header{.{ .name = "", .value = "" }} ** size;
}

// ============================================================================
// REQUEST PARSING TESTS
// ============================================================================

test "basic GET request" {
    const req_str = "GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var headers = createHeaders(10);

    const req = try Request.parse(req_str, &headers);

    try testing.expectEqualStrings("GET", req.method);
    try testing.expectEqualStrings("/hello", req.path);
    try testing.expectEqual(@as(usize, 1), req.minor_version);
    try testing.expectEqualStrings("Host", req.headers[0].name);
    try testing.expectEqualStrings("example.com", req.headers[0].value);
}

test "POST request with body" {
    const req_str = "POST /api/users HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n";
    var headers = createHeaders(10);

    const req = try Request.parse(req_str, &headers);

    try testing.expectEqualStrings("POST", req.method);
    try testing.expectEqualStrings("/api/users", req.path);
    try testing.expectEqual(@as(usize, 0), req.minor_version);
    try testing.expectEqualStrings("Content-Type", req.headers[0].name);
    try testing.expectEqualStrings("application/json", req.headers[0].value);
    try testing.expectEqualStrings("Content-Length", req.headers[1].name);
    try testing.expectEqualStrings("25", req.headers[1].value);
}

test "request with multiple headers" {
    const req_str = "PUT /data HTTP/1.1\r\n" ++
        "Host: api.example.com\r\n" ++
        "User-Agent: TestClient/1.0\r\n" ++
        "Accept: */*\r\n" ++
        "Authorization: Bearer token123\r\n" ++
        "\r\n";
    var headers = createHeaders(10);

    const req = try Request.parse(req_str, &headers);

    try testing.expectEqualStrings("PUT", req.method);
    try testing.expectEqualStrings("/data", req.path);
    try testing.expectEqual(@as(usize, 1), req.minor_version);

    // Check all headers
    try testing.expectEqualStrings("Host", req.headers[0].name);
    try testing.expectEqualStrings("api.example.com", req.headers[0].value);
    try testing.expectEqualStrings("User-Agent", req.headers[1].name);
    try testing.expectEqualStrings("TestClient/1.0", req.headers[1].value);
    try testing.expectEqualStrings("Accept", req.headers[2].name);
    try testing.expectEqualStrings("*/*", req.headers[2].value);
    try testing.expectEqualStrings("Authorization", req.headers[3].name);
    try testing.expectEqualStrings("Bearer token123", req.headers[3].value);
}

test "request with complex URI" {
    const req_str = "GET /path/to/resource?param1=value1&param2=value2#fragment HTTP/1.1\r\n\r\n";
    var headers = createHeaders(10);

    const req = try Request.parse(req_str, &headers);

    try testing.expectEqualStrings("GET", req.method);
    try testing.expectEqualStrings("/path/to/resource?param1=value1&param2=value2#fragment", req.path);
}

test "request with no headers" {
    const req_str = "GET / HTTP/1.1\r\n\r\n";
    var headers = createHeaders(10);

    const req = try Request.parse(req_str, &headers);

    try testing.expectEqualStrings("GET", req.method);
    try testing.expectEqualStrings("/", req.path);
    try testing.expectEqual(@as(usize, 1), req.minor_version);
}

test "request with header values containing spaces" {
    const req_str = "GET /test HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n";
    var headers = createHeaders(10);

    const req = try Request.parse(req_str, &headers);

    try testing.expectEqualStrings("User-Agent", req.headers[0].name);
    try testing.expectEqualStrings("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", req.headers[0].value);
}

test "request with LF only (no CR)" {
    const req_str = "GET /test HTTP/1.1\nHost: example.com\n\n";
    var headers = createHeaders(10);

    const req = try Request.parse(req_str, &headers);

    try testing.expectEqualStrings("GET", req.method);
    try testing.expectEqualStrings("/test", req.path);
    try testing.expectEqualStrings("Host", req.headers[0].name);
    try testing.expectEqualStrings("example.com", req.headers[0].value);
}

// ============================================================================
// RESPONSE PARSING TESTS
// ============================================================================

test "basic HTTP response" {
    const resp_str = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n";
    var headers = createHeaders(10);

    const resp = try Response.parse(resp_str, &headers);

    try testing.expectEqual(@as(usize, 1), resp.minor_version);
    try testing.expectEqual(@as(u16, 200), resp.code);
    try testing.expectEqualStrings("OK", resp.reason);
    try testing.expectEqualStrings("Content-Length", resp.headers[0].name);
    try testing.expectEqualStrings("13", resp.headers[0].value);
}

test "response with no reason phrase" {
    const resp_str = "HTTP/1.1 404\r\nContent-Type: text/plain\r\n\r\n";
    var headers = createHeaders(10);

    const resp = try Response.parse(resp_str, &headers);

    try testing.expectEqual(@as(u16, 404), resp.code);
    try testing.expectEqualStrings("", resp.reason);
}

test "response with reason phrase containing spaces" {
    const resp_str = "HTTP/1.0 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n";
    var headers = createHeaders(10);

    const resp = try Response.parse(resp_str, &headers);

    try testing.expectEqual(@as(usize, 0), resp.minor_version);
    try testing.expectEqual(@as(u16, 500), resp.code);
    try testing.expectEqualStrings("Internal Server Error", resp.reason);
}

test "response with multiple headers" {
    const resp_str = "HTTP/1.1 200 OK\r\n" ++
        "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache/2.2.14\r\n" ++
        "Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\n" ++
        "Content-Length: 88\r\n" ++
        "Content-Type: text/html\r\n" ++
        "\r\n";
    var headers = createHeaders(10);

    const resp = try Response.parse(resp_str, &headers);

    try testing.expectEqual(@as(u16, 200), resp.code);
    try testing.expectEqualStrings("Date", resp.headers[0].name);
    try testing.expectEqualStrings("Mon, 27 Jul 2009 12:28:53 GMT", resp.headers[0].value);
    try testing.expectEqualStrings("Server", resp.headers[1].name);
    try testing.expectEqualStrings("Apache/2.2.14", resp.headers[1].value);
}

test "response status codes" {
    const test_cases = [_]struct { str: []const u8, code: u16 }{
        .{ .str = "HTTP/1.1 100 Continue\r\n\r\n", .code = 100 },
        .{ .str = "HTTP/1.1 201 Created\r\n\r\n", .code = 201 },
        .{ .str = "HTTP/1.1 301 Moved Permanently\r\n\r\n", .code = 301 },
        .{ .str = "HTTP/1.1 400 Bad Request\r\n\r\n", .code = 400 },
        .{ .str = "HTTP/1.1 401 Unauthorized\r\n\r\n", .code = 401 },
        .{ .str = "HTTP/1.1 403 Forbidden\r\n\r\n", .code = 403 },
        .{ .str = "HTTP/1.1 500 Internal Server Error\r\n\r\n", .code = 500 },
        .{ .str = "HTTP/1.1 502 Bad Gateway\r\n\r\n", .code = 502 },
        .{ .str = "HTTP/1.1 999 Custom\r\n\r\n", .code = 999 },
    };

    for (test_cases) |case| {
        var headers = createHeaders(5);
        const resp = try Response.parse(case.str, &headers);
        try testing.expectEqual(case.code, resp.code);
    }
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

test "invalid HTTP version" {
    const test_cases = [_][]const u8{
        "GET / HTTP/2.0\r\n\r\n",
        "GET / HTTP/0.9\r\n\r\n",
        "GET / HTTPS/1.1\r\n\r\n",
        "GET / HTTP/1.2\r\n\r\n",
        "GET / HTTP/\r\n\r\n",
    };

    for (test_cases) |case| {
        var headers = createHeaders(10);
        try testing.expectError(ParseError.Version, Request.parse(case, &headers));
    }
}

test "invalid method" {
    const test_cases = [_][]const u8{
        "G@T / HTTP/1.1\r\n\r\n",
        "GET\x00 / HTTP/1.1\r\n\r\n",
        "GET\r / HTTP/1.1\r\n\r\n",
        "GET\n / HTTP/1.1\r\n\r\n",
    };

    for (test_cases) |case| {
        var headers = createHeaders(10);
        try testing.expectError(ParseError.Token, Request.parse(case, &headers));
    }
}

test "invalid URI" {
    const test_cases = [_][]const u8{
        "GET \x00 HTTP/1.1\r\n\r\n",
        "GET /path\x01 HTTP/1.1\r\n\r\n",
        "GET /path\r HTTP/1.1\r\n\r\n",
    };

    for (test_cases) |case| {
        var headers = createHeaders(10);
        try testing.expectError(ParseError.Token, Request.parse(case, &headers));
    }
}

test "invalid status code" {
    const test_cases = [_][]const u8{
        "HTTP/1.1 abc OK\r\n\r\n",
        "HTTP/1.1 20a OK\r\n\r\n",
        "HTTP/1.1 2000 OK\r\n\r\n",
        "HTTP/1.1 20 OK\r\n\r\n",
    };

    for (test_cases) |case| {
        var headers = createHeaders(10);
        try testing.expectError(ParseError.Status, Response.parse(case, &headers));
    }
}

test "invalid header names" {
    const test_cases = [_][]const u8{
        "GET / HTTP/1.1\r\nHost@: example.com\r\n\r\n",
        "GET / HTTP/1.1\r\nHost\x00: example.com\r\n\r\n",
        "GET / HTTP/1.1\r\nHost\r: example.com\r\n\r\n",
        "GET / HTTP/1.1\r\n: example.com\r\n\r\n",
    };

    for (test_cases) |case| {
        var headers = createHeaders(10);
        try testing.expectError(ParseError.HeaderName, Request.parse(case, &headers));
    }
}

test "too many headers" {
    // Build request with many headers using allocator
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var long_request = std.ArrayList(u8).init(allocator);
    defer long_request.deinit();

    try long_request.appendSlice("GET / HTTP/1.1\r\n");

    var i: usize = 0;
    while (i < 20) : (i += 1) {
        try long_request.writer().print("Header{}: value\r\n", .{i});
    }
    try long_request.appendSlice("\r\n");

    var headers = createHeaders(5); // Only space for 5 headers
    try testing.expectError(ParseError.TooManyHeaders, Request.parse(long_request.items, &headers));
}

test "partial requests" {
    const test_cases = [_][]const u8{
        "GET",
        "GET /",
        "GET / HTTP",
        "GET / HTTP/1.1",
        "GET / HTTP/1.1\r",
        "GET / HTTP/1.1\r\nHost",
        "GET / HTTP/1.1\r\nHost:",
        "GET / HTTP/1.1\r\nHost: example.com",
        "GET / HTTP/1.1\r\nHost: example.com\r",
    };

    for (test_cases) |case| {
        var headers = createHeaders(10);
        try testing.expectError(ParseError.Partial, Request.parse(case, &headers));
    }
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

test "header with whitespace around colon" {
    const req_str = "GET / HTTP/1.1\r\nHost   :   example.com\r\n\r\n";
    var headers = createHeaders(10);

    const req = try Request.parse(req_str, &headers);

    try testing.expectEqualStrings("Host", req.headers[0].name);
    try testing.expectEqualStrings("example.com", req.headers[0].value);
}

test "header with leading/trailing whitespace in value" {
    const req_str = "GET / HTTP/1.1\r\nHost:   example.com   \r\n\r\n";
    var headers = createHeaders(10);

    const req = try Request.parse(req_str, &headers);

    // The parser should trim leading whitespace but preserve trailing whitespace
    try testing.expectEqualStrings("example.com   ", req.headers[0].value);
}

test "empty header value" {
    const req_str = "GET / HTTP/1.1\r\nX-Empty:\r\n\r\n";
    var headers = createHeaders(10);

    const req = try Request.parse(req_str, &headers);

    try testing.expectEqualStrings("X-Empty", req.headers[0].name);
    try testing.expectEqualStrings("", req.headers[0].value);
}

test "header value with special characters" {
    const req_str = "GET / HTTP/1.1\r\nX-Special: !@#$%^&*()_+-={}[]|\\:;\"'<>?,./\r\n\r\n";
    var headers = createHeaders(10);

    const req = try Request.parse(req_str, &headers);

    try testing.expectEqualStrings("X-Special", req.headers[0].name);
    try testing.expectEqualStrings("!@#$%^&*()_+-={}[]|\\:;\"'<>?,./", req.headers[0].value);
}

test "very long header value" {
    const long_value = "a" ** 1000;
    const req_str = "GET / HTTP/1.1\r\nX-Long: " ++ long_value ++ "\r\n\r\n";
    var headers = createHeaders(10);

    const req = try Request.parse(req_str, &headers);

    try testing.expectEqualStrings("X-Long", req.headers[0].name);
    try testing.expectEqualStrings(long_value, req.headers[0].value);
}

test "case sensitivity in method" {
    const test_cases = [_]struct { input: []const u8, expected: []const u8 }{
        .{ .input = "get / HTTP/1.1\r\n\r\n", .expected = "get" },
        .{ .input = "Get / HTTP/1.1\r\n\r\n", .expected = "Get" },
        .{ .input = "POST / HTTP/1.1\r\n\r\n", .expected = "POST" },
        .{ .input = "post / HTTP/1.1\r\n\r\n", .expected = "post" },
        .{ .input = "OPTIONS / HTTP/1.1\r\n\r\n", .expected = "OPTIONS" },
    };

    for (test_cases) |case| {
        var headers = createHeaders(10);
        const req = try Request.parse(case.input, &headers);
        try testing.expectEqualStrings(case.expected, req.method);
    }
}

test "case sensitivity in header names" {
    const req_str = "GET / HTTP/1.1\r\nhost: example.com\r\nContent-TYPE: text/html\r\n\r\n";
    var headers = createHeaders(10);

    const req = try Request.parse(req_str, &headers);

    try testing.expectEqualStrings("host", req.headers[0].name);
    try testing.expectEqualStrings("Content-TYPE", req.headers[1].name);
}

// ============================================================================
// BYTES READ TRACKING TESTS
// ============================================================================

test "response bytes read tracking" {
    const resp_str = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
    var headers = createHeaders(10);

    const resp = try Response.parse(resp_str, &headers);

    // Should only read up to the end of headers
    const expected_bytes = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n".len;
    try testing.expectEqual(expected_bytes, resp.bytes_read);
}

// ============================================================================
// EXACTSIZEMATCHER TESTS
// ============================================================================

test "ExactSizeMatcher functionality" {
    const Matcher8 = http_parser.ExactSizeMatcher(8);

    // Test compile-time case generation
    const http11_case = Matcher8.case("HTTP/1.1");
    const http10_case = Matcher8.case("HTTP/1.0");

    // Test runtime matching
    try testing.expectEqual(http11_case, Matcher8.match("HTTP/1.1"));
    try testing.expectEqual(http10_case, Matcher8.match("HTTP/1.0"));

    // Test different strings produce different values
    try testing.expect(http11_case != http10_case);

    // Test shorter strings
    try testing.expect(Matcher8.match("HTTP") != http11_case);

    // Test longer strings return max value
    try testing.expectEqual(std.math.maxInt(u64), Matcher8.match("HTTP/1.1X"));
}

// ============================================================================
// PERFORMANCE/STRESS TESTS
// ============================================================================

test "large number of headers" {
    // Build request with many headers using allocator
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var large_request = std.ArrayList(u8).init(allocator);
    defer large_request.deinit();

    try large_request.appendSlice("GET / HTTP/1.1\r\n");

    var i: usize = 0;
    while (i < 100) : (i += 1) {
        try large_request.writer().print("Header{}: value{}\r\n", .{ i, i });
    }
    try large_request.appendSlice("\r\n");

    var headers = createHeaders(150);

    const req = try Request.parse(large_request.items, &headers);

    try testing.expectEqualStrings("GET", req.method);
    try testing.expectEqualStrings("/", req.path);
    try testing.expectEqualStrings("Header0", req.headers[0].name);
    try testing.expectEqualStrings("value0", req.headers[0].value);
    try testing.expectEqualStrings("Header99", req.headers[99].name);
    try testing.expectEqualStrings("value99", req.headers[99].value);
}

test "various HTTP methods" {
    const methods = [_][]const u8{ "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT" };

    for (methods) |method| {
        // Use allocator to build dynamic string
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        const req_str = try std.fmt.allocPrint(allocator, "{s} / HTTP/1.1\r\n\r\n", .{method});
        var headers = createHeaders(10);

        const req = try Request.parse(req_str, &headers);
        try testing.expectEqualStrings(method, req.method);
    }
}

// Test with binary data in header values (should fail gracefully)
test "binary data in header values" {
    const req_str = "GET / HTTP/1.1\r\nX-Binary: \x00\x01\x02\x03\r\n\r\n";
    var headers = createHeaders(10);

    // This should fail because binary data isn't valid in header values
    try testing.expectError(ParseError.HeaderValue, Request.parse(req_str, &headers));
}
