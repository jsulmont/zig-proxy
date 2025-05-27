// src/utils/libxml2.zig - Minimal libxml2 bindings for XML parsing and validation
const std = @import("std");
const logger = @import("../logger.zig");

// libxml2 types
pub const xmlChar = u8;
pub const xmlDoc = opaque {};
pub const xmlNode = opaque {};
pub const xmlParserCtxt = opaque {};
pub const xmlError = opaque {};

// Parser options
pub const XML_PARSE_NOERROR: c_int = 1 << 5;
pub const XML_PARSE_NOWARNING: c_int = 1 << 6;
pub const XML_PARSE_PEDANTIC: c_int = 1 << 7;
pub const XML_PARSE_NOBLANKS: c_int = 1 << 8;
pub const XML_PARSE_RECOVER: c_int = 1 << 9;

// Node types
pub const XML_ELEMENT_NODE: c_int = 1;
pub const XML_ATTRIBUTE_NODE: c_int = 2;
pub const XML_TEXT_NODE: c_int = 3;
pub const XML_DOCUMENT_NODE: c_int = 9;

// libxml2 function declarations
pub extern "c" fn xmlInitParser() void;
pub extern "c" fn xmlCleanupParser() void;

// Document parsing
pub extern "c" fn xmlParseMemory(buffer: [*c]const u8, size: c_int) ?*xmlDoc;
pub extern "c" fn xmlReadMemory(buffer: [*c]const u8, size: c_int, url: [*c]const u8, encoding: [*c]const u8, options: c_int) ?*xmlDoc;
pub extern "c" fn xmlFreeDoc(doc: *xmlDoc) void;

// Node access
pub extern "c" fn xmlDocGetRootElement(doc: *xmlDoc) ?*xmlNode;
pub extern "c" fn xmlNodeGetContent(node: *xmlNode) ?[*:0]u8;
pub extern "c" fn xmlGetProp(node: *xmlNode, name: [*c]const u8) ?[*:0]u8;

// Memory management
pub extern "c" fn xmlFree(ptr: ?*anyopaque) void;

// Error handling
pub extern "c" fn xmlGetLastError() ?*xmlError;
pub extern "c" fn xmlResetLastError() void;

// Node structure access (we need to define the layout)
pub const XmlNode = extern struct {
    _private: ?*anyopaque,
    type: c_int,
    name: ?[*:0]const u8,
    children: ?*XmlNode,
    last: ?*XmlNode,
    parent: ?*XmlNode,
    next: ?*XmlNode,
    prev: ?*XmlNode,
    doc: ?*xmlDoc,
    ns: ?*anyopaque, // xmlNs
    content: ?[*:0]u8,
    properties: ?*anyopaque, // xmlAttr
    nsDef: ?*anyopaque, // xmlNs
    psvi: ?*anyopaque,
    line: c_ushort,
    extra: c_ushort,
};

// High-level wrapper for safe XML operations
pub const XmlDocument = struct {
    doc: *xmlDoc,
    allocator: std.mem.Allocator,

    pub fn parseMemory(allocator: std.mem.Allocator, xml_data: []const u8) !XmlDocument {
        // Use xmlReadMemory for better error handling
        const doc = xmlReadMemory(xml_data.ptr, @intCast(xml_data.len), null, // URL
            null, // encoding (auto-detect)
            XML_PARSE_RECOVER | XML_PARSE_NOERROR | XML_PARSE_NOWARNING // Recover from errors, suppress error output
        ) orelse {
            return error.XmlParseError;
        };

        return XmlDocument{
            .doc = doc,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *XmlDocument) void {
        xmlFreeDoc(self.doc);
    }

    pub fn getRootElement(self: *XmlDocument) ?XmlElement {
        const root_node = xmlDocGetRootElement(self.doc) orelse return null;
        return XmlElement{
            .node = @ptrCast(root_node),
            .allocator = self.allocator,
        };
    }
};

pub const XmlElement = struct {
    node: *XmlNode,
    allocator: std.mem.Allocator,

    pub fn getName(self: *const XmlElement) ?[]const u8 {
        return if (self.node.name) |name| std.mem.span(name) else null;
    }

    pub fn getContent(self: *const XmlElement) !?[]u8 {
        const content_ptr = xmlNodeGetContent(@ptrCast(self.node)) orelse return null;
        defer xmlFree(content_ptr);

        const content_span = std.mem.span(content_ptr);
        return try self.allocator.dupe(u8, content_span);
    }

    pub fn getAttribute(self: *const XmlElement, attr_name: []const u8) !?[]u8 {
        const attr_name_z = try self.allocator.dupeZ(u8, attr_name);
        defer self.allocator.free(attr_name_z);

        const attr_value = xmlGetProp(@ptrCast(self.node), attr_name_z.ptr) orelse return null;
        defer xmlFree(attr_value);

        const value_span = std.mem.span(attr_value);
        return try self.allocator.dupe(u8, value_span);
    }

    pub fn getFirstChild(self: *const XmlElement) ?XmlElement {
        const child = self.node.children orelse return null;

        // Skip text nodes to find first element
        var current = child;
        while (current.type != XML_ELEMENT_NODE) {
            current = current.next orelse return null;
        }

        return XmlElement{
            .node = current,
            .allocator = self.allocator,
        };
    }

    pub fn getNextSibling(self: *const XmlElement) ?XmlElement {
        var current = self.node.next;

        // Skip non-element nodes
        while (current) |node| {
            if (node.type == XML_ELEMENT_NODE) {
                return XmlElement{
                    .node = node,
                    .allocator = self.allocator,
                };
            }
            current = node.next;
        }

        return null;
    }

    /// Simple XPath-like element finder - finds first element with given name
    pub fn findElement(self: *const XmlElement, element_name: []const u8) ?XmlElement {
        // Check current element
        if (self.getName()) |name| {
            if (std.mem.eql(u8, name, element_name)) {
                return self.*;
            }
        }

        // Check children recursively
        var child = self.getFirstChild();
        while (child) |c| {
            if (c.findElement(element_name)) |found| {
                return found;
            }
            child = c.getNextSibling();
        }

        return null;
    }
};

// Global initialization
var xml_initialized = false;

pub fn init() void {
    if (!xml_initialized) {
        xmlInitParser();
        xml_initialized = true;
        logger.debug("xml", "libxml2 initialized");
    }
}

pub fn deinit() void {
    if (xml_initialized) {
        xmlCleanupParser();
        xml_initialized = false;
        logger.debug("xml", "libxml2 cleanup complete");
    }
}

// Quick validation function - just checks if XML is well-formed
pub fn isWellFormed(xml_data: []const u8) bool {
    if (xml_data.len == 0) return false;

    const doc = xmlReadMemory(xml_data.ptr, @intCast(xml_data.len), null, null, XML_PARSE_NOERROR | XML_PARSE_NOWARNING);

    if (doc) |d| {
        xmlFreeDoc(d);
        return true;
    }

    return false;
}

// Extract just the root element name without full parsing (fast path)
pub fn extractRootElementName(allocator: std.mem.Allocator, xml_data: []const u8) !?[]u8 {
    if (xml_data.len == 0) return null;

    // Look for first opening tag
    const start = std.mem.indexOf(u8, xml_data, "<") orelse return null;
    var pos = start + 1;

    // Skip XML declaration and processing instructions
    while (pos < xml_data.len and (xml_data[pos] == '?' or xml_data[pos] == '!')) {
        // Find end of this tag
        const tag_end = std.mem.indexOfScalarPos(u8, xml_data, pos, '>') orelse return null;
        pos = tag_end + 1;

        // Find next opening tag
        const next_start = std.mem.indexOfScalarPos(u8, xml_data, pos, '<') orelse return null;
        pos = next_start + 1;
    }

    if (pos >= xml_data.len) return null;

    // Extract element name
    var end = pos;
    while (end < xml_data.len) {
        const c = xml_data[end];
        if (c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == '>' or c == '/') {
            break;
        }
        end += 1;
    }

    if (end == pos) return null;

    return try allocator.dupe(u8, xml_data[pos..end]);
}
