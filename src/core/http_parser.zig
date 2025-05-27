// src/core/http_parser.zig

pub const std = @import("std");
const builtin = @import("builtin");

const assert = std.debug.assert;
const Vector = std.meta.Vector;

pub const ParseError = error{
    Token,
    NewLine,
    Version,
    TooManyHeaders,
    HeaderName,
    HeaderValue,
    Partial,
    Status,
};

/// Cursed code I stole from bun (by Jarred Sumner).
/// Converts cases into an integer and does int comparisons on them
pub fn ExactSizeMatcher(comptime max_bytes: usize) type {
    switch (max_bytes) {
        1, 2, 4, 8, 12, 16 => {},
        else => @compileError("max_bytes must be 1, 2, 4, 8, 12, or 16."),
    }

    const T = std.meta.Int(.unsigned, max_bytes * 8);
    const native_endian = builtin.target.cpu.arch.endian();

    return struct {
        /// Run-time matcher
        pub fn match(str: anytype) T {
            return switch (str.len) {
                0 => 0,

                1...max_bytes - 1 => blk: {
                    var tmp = std.mem.zeroes([max_bytes]u8);
                    @memcpy(tmp[0..str.len], str);
                    break :blk std.mem.readInt(T, &tmp, native_endian);
                },

                max_bytes => blk: {
                    // copy slice into a fixed-size buffer
                    var buf: [max_bytes]u8 = undefined;
                    @memcpy(&buf, str);
                    break :blk std.mem.readInt(T, &buf, native_endian);
                },

                else => std.math.maxInt(T),
            };
        }

        /// Compile-time helper for string literals
        pub fn case(comptime str: []const u8) T {
            if (str.len < max_bytes) {
                var buf = std.mem.zeroes([max_bytes]u8);
                @memcpy(buf[0..str.len], str);
                return std.mem.readInt(T, &buf, native_endian);
            } else if (str.len == max_bytes) {
                var buf: [max_bytes]u8 = undefined;
                @memcpy(&buf, str);
                return std.mem.readInt(T, &buf, native_endian);
            } else {
                @compileError("str: \"" ++ str ++ "\" too long");
            }
        }
    };
}

/// ASCII codes to accept URI string
/// i.e. A-Z a-z 0-9 !#$%&'*+-._();:@=,/?[]~^
/// TODO: Make a stricter checking for URI string?
// zig fmt: off
const URI_MAP = [256]u1{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//  \0                            \n
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//  commands
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
//  \w !  "  #  $  %  &  '  (  )  *  +  ,  -  .  /
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
//  0  1  2  3  4  5  6  7  8  9  :  ;  <  =  >  ?
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
//  @  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
//  P  Q  R  S  T  U  V  W  X  Y  Z  [  \  ]  ^  _
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
//  `  a  b  c  d  e  f  g  h  i  j  k  l  m  n  o
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
//  p  q  r  s  t  u  v  w  x  y  z  {  |  }  ~  del
    //   ====== Extended ASCII (aka. obs-text) ======
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};
// zig fmt: on

fn isURIToken(b: u8) bool {
    return URI_MAP[b] == 1;
}

// HTTP token characters per RFC 7230
// token = 1*tchar
// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
const TOKEN_MAP = [256]u1{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0,
    //  \w !  "  #  $  %  &  '  (  )  *  +  ,  -  .  /
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    //  0  1  2  3  4  5  6  7  8  9  :  ;  <  =  >  ?
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    //  @  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
    //  P  Q  R  S  T  U  V  W  X  Y  Z  [  \  ]  ^  _
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    //  `  a  b  c  d  e  f  g  h  i  j  k  l  m  n  o
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0,
    //  p  q  r  s  t  u  v  w  x  y  z  {  |  }  ~  del
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

fn isToken(b: u8) bool {
    return TOKEN_MAP[b] == 1;
}

const HEADER_NAME_MAP = [256]u1{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

fn isHeaderNameToken(b: u8) bool {
    return HEADER_NAME_MAP[b] == 1;
}

const HEADER_VALUE_MAP = [256]u1{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};

const _HEADER_VALUE_V: Vector(256, u1) = HEADER_VALUE_MAP;
const HEADER_VALUE_VECTOR: Vector(256, bool) =
    _HEADER_VALUE_V == @as(Vector(256, u1), @splat(@as(u1, 1)));

fn isHeaderValueToken(b: u8) bool {
    return HEADER_VALUE_MAP[b] == 1;
}

// fn isHeaderValueTokenVectorized(b: anytype) Vector(@typeInfo(@TypeOf(b)).Vector.len, bool) {
//     return HEADER_VALUE_VECTOR[b];
// }

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Response = struct {
    minor_version: usize,
    code: u16,
    headers: []const Header,
    reason: []const u8,
    bytes_read: usize = 0,

    pub fn parse(buf: []const u8, headers: []Header) ParseError!Response {
        var parser = Parser.init(buf);
        // try parser.skipEmptyLines();

        const minor_version = try parser.parseVersion();

        // Expect a space after HTTP version
        if (!parser.expect(' ')) return error.Status;

        const code = try parser.parseCode();

        var reason: []const u8 = "";

        // RFC7230 says there must be 'SP' and then reason-phrase, but admits
        // its only for legacy reasons. With the reason-phrase completely
        // optional (and preferred to be omitted) in HTTP2, we'll just
        // handle any response that doesn't include a reason-phrase, because
        // it's more lenient, and we don't care anyways.
        //
        // So, a SP means parse a reason-phrase.
        // A newline means go to headers.
        // Anything else we'll say is a malformed status.
        switch (parser.next() orelse return error.Partial) {
            ' ' => {
                reason = try parser.parseReason();
            },
            '\r' => {
                if (!parser.expect('\n')) return error.Status;
            },
            '\n' => {},
            else => return error.Status,
        }

        const headers_len = try parser.parseHeaders(headers);

        return Response{
            .minor_version = minor_version,
            .code = code,
            .headers = headers[0..headers_len],
            .reason = reason,
            .bytes_read = parser.pos,
        };
    }
};

pub const Request = struct {
    method: []const u8,
    path: []const u8,
    headers: []const Header,
    minor_version: usize,

    pub fn parse(buf: []const u8, headers: []Header) ParseError!Request {
        var parser = Parser.init(buf);

        const method = try parser.parseToken();
        const path = try parser.parseURI();
        const minor_version = try parser.parseVersion();
        try parser.parseNewline();
        const headers_len = try parser.parseHeaders(headers);

        return Request{
            .method = method,
            .minor_version = minor_version,
            .path = path,
            .headers = headers[0..headers_len],
        };
    }
};

test "parse request" {
    const REQ = "GET /hello HTTP/1.1\r\n" ++
        "User-Agent: 1234\r\n\r\n";

    var headers: [32]Header = undefined;

    const req = try Request.parse(REQ, &headers);

    try std.testing.expectEqualStrings("GET", req.method);
    try std.testing.expectEqualStrings("/hello", req.path);
    try std.testing.expectEqual(@as(usize, 1), req.minor_version);

    try std.testing.expectEqualStrings("User-Agent", req.headers[0].name);
    try std.testing.expectEqualStrings("1234", req.headers[0].value);
}

const Parser = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Parser {
        return .{ .buf = buf };
    }

    inline fn expect(self: *Parser, ch: u8) bool {
        if (self.pos < self.buf.len and self.buf[self.pos] == ch) {
            self.pos += 1;
            return true;
        }
        return false;
    }

    inline fn expectNext(self: *Parser, ch: u8) bool {
        const b = self.peek() orelse return false;
        if (b == ch) {
            self.pos += 1;
            return true;
        }
        return false;
    }

    inline fn next(self: *Parser) ?u8 {
        if (self.pos < self.buf.len) {
            const ch = self.buf[self.pos];
            self.pos += 1;
            return ch;
        }
        return null;
    }

    inline fn peek(self: *Parser) ?u8 {
        if (self.pos < self.buf.len) {
            return self.buf[self.pos];
        }
        return null;
    }

    const Version = ExactSizeMatcher(8);

    /// Parse a version, like `HTTP/1.1`
    /// Returns the minor version, and errors if the major version isn't 1
    pub fn parseVersion(self: *Parser) ParseError!usize {
        // Check if we have enough bytes for a complete version string
        if (self.pos + 8 > self.buf.len) return error.Partial;

        switch (Version.match(self.buf[self.pos .. self.pos + 8])) {
            Version.case("HTTP/1.1") => {
                self.pos += 8;
                return 1;
            },
            Version.case("HTTP/1.0") => {
                self.pos += 8;
                return 0;
            },
            else => {
                // std.log.warn("{s}", .{self.buf[self.pos..]});
                return error.Version;
            },
        }
    }

    pub fn parseURI(self: *Parser) ParseError![]const u8 {
        const start = self.pos;
        while (self.pos < self.buf.len) {
            const ch = self.buf[self.pos];
            if (ch == ' ') {
                const result = self.buf[start..self.pos];
                self.pos += 1; // skip the space
                return result;
            } else if (!isURIToken(ch)) {
                return error.Token;
            }
            self.pos += 1;
        }
        return error.Partial;
    }

    pub fn parseToken(self: *Parser) ParseError![]const u8 {
        const start = self.pos;
        while (self.pos < self.buf.len) {
            const ch = self.buf[self.pos];
            if (ch == ' ') {
                const result = self.buf[start..self.pos];
                self.pos += 1; // skip the space
                return result;
            } else if (!isToken(ch)) {
                return error.Token;
            }
            self.pos += 1;
        }
        return error.Partial;
    }

    /// From [RFC 7230](https://tools.ietf.org/html/rfc7230):
    ///
    /// > ```notrust
    /// > reason-phrase  = *( HTAB / SP / VCHAR / obs-text )
    /// > HTAB           = %x09        ; horizontal tab
    /// > VCHAR          = %x21-7E     ; visible (printing) characters
    /// > obs-text       = %x80-FF
    /// > ```
    ///
    /// > A.2.  Changes from RFC 2616
    /// >
    /// > Non-US-ASCII content in header fields and the reason phrase > has been obsoleted and made opaque (the TEXT rule was removed).
    pub fn parseReason(self: *Parser) ParseError![]const u8 {
        const start = self.pos;
        var seen_obs_text = false;
        while (self.pos < self.buf.len) {
            const ch = self.buf[self.pos];
            if (ch == '\r') {
                if (self.pos + 1 >= self.buf.len) return error.Partial;
                if (self.buf[self.pos + 1] != '\n') return error.Status;

                const result = if (seen_obs_text) "" else self.buf[start..self.pos];
                self.pos += 2; // skip \r\n
                return result;
            } else if (ch == '\n') {
                const result = if (seen_obs_text) "" else self.buf[start..self.pos];
                self.pos += 1; // skip \n
                return result;
            } else if (!(ch == 0x09 or ch == ' ' or (ch >= 0x21 and ch <= 0x7E) or ch >= 0x80)) {
                return error.Status;
            } else if (ch >= 0x80) {
                seen_obs_text = true;
            }
            self.pos += 1;
        }
        return error.Partial;
    }

    pub fn parseCode(self: *Parser) ParseError!u16 {
        if (self.pos + 3 > self.buf.len) return error.Partial;

        const hundreds = self.buf[self.pos];
        const tens = self.buf[self.pos + 1];
        const ones = self.buf[self.pos + 2];

        if (!std.ascii.isDigit(hundreds) or !std.ascii.isDigit(tens) or !std.ascii.isDigit(ones)) {
            return error.Status;
        }

        self.pos += 3;
        return @as(u16, hundreds - '0') * 100 + @as(u16, tens - '0') * 10 + @as(u16, ones - '0');
    }

    /// Returns the number of headers
    pub fn parseHeaders(self: *Parser, headers: []Header) ParseError!usize {
        var header_index: usize = 0;

        while (self.pos < self.buf.len) {
            const ch = self.buf[self.pos];
            if (ch == '\r') {
                if (self.pos + 1 >= self.buf.len) return error.Partial;
                if (self.buf[self.pos + 1] == '\n') {
                    self.pos += 2; // skip \r\n
                    break;
                }
                return error.NewLine;
            } else if (ch == '\n') {
                self.pos += 1; // skip \n
                break;
            } else if (!isHeaderNameToken(ch)) {
                return error.HeaderName;
            }

            if (header_index >= headers.len) {
                return error.TooManyHeaders;
            }

            headers[header_index].name = try self.parseHeaderName();
            headers[header_index].value = try self.parseHeaderValue();

            header_index += 1;
        }

        return header_index;
    }

    inline fn parseHeaderName(self: *Parser) ParseError![]const u8 {
        const start = self.pos;
        while (self.pos < self.buf.len) {
            const ch = self.buf[self.pos];

            if (ch == ':') {
                const result = self.buf[start..self.pos];
                self.pos += 1; // skip ':'
                return result;
            } else if (!isHeaderNameToken(ch)) {
                const name = self.buf[start..self.pos];

                // eat white space between name and colon
                while (self.pos < self.buf.len) {
                    const b = self.buf[self.pos];
                    if (b == ' ' or b == '\t') {
                        self.pos += 1;
                        continue;
                    } else if (b == ':') {
                        self.pos += 1; // skip ':'
                        return name;
                    }
                    return error.HeaderName;
                }
                return error.Partial;
            }
            self.pos += 1;
        }
        return error.Partial;
    }

    inline fn parseHeaderValue(self: *Parser) ParseError![]const u8 {
        // Skip leading whitespace after colon
        while (self.pos < self.buf.len) {
            const ch = self.buf[self.pos];
            if (ch == ' ' or ch == '\t') {
                self.pos += 1;
                continue;
            }
            break;
        }

        if (self.pos >= self.buf.len) return error.Partial;

        // Check for immediate newline (empty header value)
        const ch = self.buf[self.pos];
        if (ch == '\r') {
            if (self.pos + 1 >= self.buf.len) return error.Partial;
            if (self.buf[self.pos + 1] == '\n') {
                self.pos += 2; // skip \r\n
                return "";
            }
            return error.HeaderValue;
        } else if (ch == '\n') {
            self.pos += 1; // skip \n
            return "";
        }

        const start = self.pos;

        // Parse value till EOL
        while (self.pos < self.buf.len) {
            const current = self.buf[self.pos];
            if (!isHeaderValueToken(current)) {
                if (current == '\r') {
                    if (self.pos + 1 >= self.buf.len) return error.Partial;
                    if (self.buf[self.pos + 1] == '\n') {
                        const result = self.buf[start..self.pos];
                        self.pos += 2; // skip \r\n
                        return result;
                    }
                    return error.HeaderValue;
                } else if (current == '\n') {
                    const result = self.buf[start..self.pos];
                    self.pos += 1; // skip \n
                    return result;
                }
                return error.HeaderValue;
            }
            self.pos += 1;
        }

        return error.Partial;
    }

    pub fn parseNewline(self: *Parser) ParseError!void {
        if (self.pos >= self.buf.len) return error.Partial;

        const ch = self.buf[self.pos];
        switch (ch) {
            '\r' => {
                if (self.pos + 1 >= self.buf.len) return error.Partial;
                if (self.buf[self.pos + 1] != '\n') return error.NewLine;
                self.pos += 2;
            },
            '\n' => {
                self.pos += 1;
            },
            else => return error.NewLine,
        }
    }

    pub fn skipEmptyLines(self: *Parser) ParseError!void {
        while (self.pos < self.buf.len) {
            const ch = self.buf[self.pos];

            switch (ch) {
                '\r' => {
                    if (self.pos + 1 >= self.buf.len) return error.Partial;
                    if (self.buf[self.pos + 1] != '\n') return error.NewLine;
                    self.pos += 2;
                },
                '\n' => {
                    self.pos += 1;
                },
                else => break,
            }
        }
    }
};

// pub export fn fhp_parseRequest(
//     buffer: [*c]u8,
//     buffer_len: usize,
//     method: [*c][*c]u8,
//     method_len: [*c]usize,
//     path: [*c][*c]u8,
//     path_len: [*c]usize,
//     minor_version: [*c]usize,
//     headers: [*c]fhp_Header,
//     num_headers: usize,
// ) c_int {
//     var buf =
// }
