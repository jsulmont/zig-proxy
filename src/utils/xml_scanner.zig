// src/utils/xml_scanner.zig - Zero-copy XML scanner for IEEE 2030.5
const std = @import("std");

/// Zero-copy XML scanner - returns slices into original data
pub const XmlScanner = struct {
    /// Scan result that points into the original buffer
    pub const ScanResult = struct {
        root_element: ?[]const u8, // Slice into original data
        is_complete: bool = false,

        /// Create an owned copy for thread-safe logging
        pub fn toOwned(self: ScanResult, allocator: std.mem.Allocator) !OwnedResult {
            return OwnedResult{
                .root_element = if (self.root_element) |elem|
                    try allocator.dupe(u8, elem)
                else
                    null,
                .is_complete = self.is_complete,
            };
        }
    };

    /// Owned result safe to pass between threads
    pub const OwnedResult = struct {
        root_element: ?[]const u8, // Owned by allocator
        is_complete: bool,

        pub fn deinit(self: *OwnedResult, allocator: std.mem.Allocator) void {
            if (self.root_element) |elem| {
                allocator.free(elem);
            }
        }
    };

    /// Scan XML data without any allocations
    pub fn scan(data: []const u8) ScanResult {
        var pos: usize = 0;

        // Skip BOM if present
        if (data.len >= 3 and data[0] == 0xEF and data[1] == 0xBB and data[2] == 0xBF) {
            pos = 3;
        }

        // Skip to root element
        pos = skipToRootElement(data, pos);
        if (pos >= data.len or data[pos] != '<') {
            return .{ .root_element = null };
        }

        pos += 1; // Skip '<'

        // Extract element name
        const elem_start = pos;
        while (pos < data.len) : (pos += 1) {
            switch (data[pos]) {
                ' ', '\t', '\n', '\r', '>', '/' => break,
                else => {},
            }
        }

        if (pos == elem_start) {
            return .{ .root_element = null };
        }

        const element_name = data[elem_start..pos];

        // Quick validation - just check if we can find the closing tag
        const is_complete = quickValidate(data, pos, element_name);

        return .{
            .root_element = element_name,
            .is_complete = is_complete,
        };
    }

    fn skipToRootElement(data: []const u8, start: usize) usize {
        var pos = start;

        while (pos < data.len) {
            // Skip whitespace
            while (pos < data.len and std.ascii.isWhitespace(data[pos])) : (pos += 1) {}

            if (pos >= data.len) break;

            // Check what we're looking at
            if (data[pos] != '<') {
                // Not XML
                return data.len;
            }

            if (pos + 1 >= data.len) break;

            switch (data[pos + 1]) {
                '?' => {
                    // XML declaration or processing instruction
                    pos = skipUntil(data, pos + 2, "?>") orelse data.len;
                    if (pos < data.len) pos += 2;
                },
                '!' => {
                    // Comment, CDATA, or DOCTYPE
                    if (pos + 3 < data.len and data[pos + 2] == '-' and data[pos + 3] == '-') {
                        // Comment
                        pos = skipUntil(data, pos + 4, "-->") orelse data.len;
                        if (pos < data.len) pos += 3;
                    } else if (pos + 8 < data.len and std.mem.eql(u8, data[pos + 2 .. pos + 8], "CDATA[")) {
                        // CDATA - this shouldn't be before root element, but handle it
                        pos = skipUntil(data, pos + 8, "]]>") orelse data.len;
                        if (pos < data.len) pos += 3;
                    } else {
                        // DOCTYPE or other
                        pos = skipUntil(data, pos + 2, ">") orelse data.len;
                        if (pos < data.len) pos += 1;
                    }
                },
                else => {
                    // This should be the root element
                    return pos;
                },
            }
        }

        return pos;
    }

    fn skipUntil(data: []const u8, start: usize, needle: []const u8) ?usize {
        return std.mem.indexOfPos(u8, data, start, needle);
    }

    fn quickValidate(data: []const u8, after_name: usize, element_name: []const u8) bool {
        var pos = after_name;

        // Skip to end of opening tag
        while (pos < data.len and data[pos] != '>') : (pos += 1) {
            if (data[pos] == '/' and pos + 1 < data.len and data[pos + 1] == '>') {
                // Self-closing tag
                return true;
            }
        }

        if (pos >= data.len) return false;
        pos += 1; // Skip '>'

        // Look for closing tag
        var search_pos = pos;
        while (search_pos < data.len) {
            const close_pos = std.mem.indexOfPos(u8, data, search_pos, "</") orelse return false;
            search_pos = close_pos + 2;

            // Check if this is our closing tag
            if (search_pos + element_name.len <= data.len and
                std.mem.eql(u8, data[search_pos .. search_pos + element_name.len], element_name))
            {
                // Verify it's followed by '>' or whitespace
                const after_elem = search_pos + element_name.len;
                if (after_elem < data.len) {
                    switch (data[after_elem]) {
                        '>', ' ', '\t', '\n', '\r' => return true,
                        else => {},
                    }
                }
            }
        }

        return false;
    }
};
