// src/xml_parser.zig - XML parsing and validation for IEEE 2030.5 compliance
const std = @import("std");
const observability = @import("observability.zig");
const logger = @import("logger.zig");

/// Zero-copy XML scanner - returns slices into original data
pub const XmlScanner = struct {
    /// Scan result that points into the original buffer
    pub const ScanResult = struct {
        root_element: ?[]const u8, // Slice into original data
        is_complete: bool = false,
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

/// XML processing result with validation info
pub const XmlParseResult = struct {
    is_well_formed: bool,
    root_element: ?[]const u8 = null, // Owned by allocator
    message_type: ?MessageType = null,
    processing_time_ns: u64,
    error_message: ?[]const u8 = null, // Owned by allocator

    pub fn deinit(self: *XmlParseResult, allocator: std.mem.Allocator) void {
        if (self.root_element) |elem| allocator.free(elem);
        if (self.error_message) |msg| allocator.free(msg);
    }
};

/// Common IEEE 2030.5 message types for quick identification
pub const MessageType = enum {
    // DER (Distributed Energy Resource) messages
    der_capability,
    der_control,
    der_status,
    der_availability,
    der_settings,

    // Device and Function Set messages
    device_capability,
    device_information,
    device_status,
    function_set_assignments,

    // End Device messages
    end_device,
    end_device_list,

    // Metering messages
    mirror_usage_point,
    mirror_meter_reading,
    usage_point,
    meter_reading,
    reading,
    reading_set,

    // Time and control messages
    time,
    demand_response_program,
    demand_response_program_list,
    load_shed_availability,
    end_device_control,
    end_device_control_list,

    // Pricing messages
    tariff_profile,
    tariff_profile_list,
    time_tariff_interval,
    rate_component,

    // Log and event messages
    log_event,
    log_event_list,

    // File and firmware messages
    file,
    file_list,
    file_status,

    // Subscription and notification
    subscription,
    subscription_list,
    notification,

    // Generic/unknown
    unknown,

    pub fn fromRootElement(root_element: []const u8) MessageType {
        // Map IEEE 2030.5 XML root elements to message types
        const type_map = std.StaticStringMap(MessageType).initComptime(.{
            // DER messages
            .{ "DERCapability", .der_capability },
            .{ "DERControl", .der_control },
            .{ "DERControlList", .der_control },
            .{ "DERStatus", .der_status },
            .{ "DERAvailability", .der_availability },
            .{ "DERSettings", .der_settings },

            // Device messages
            .{ "DeviceCapability", .device_capability },
            .{ "DeviceInformation", .device_information },
            .{ "DeviceStatus", .device_status },
            .{ "FunctionSetAssignments", .function_set_assignments },

            // End Device messages
            .{ "EndDevice", .end_device },
            .{ "EndDeviceList", .end_device_list },

            // Metering messages
            .{ "MirrorUsagePoint", .mirror_usage_point },
            .{ "MirrorMeterReading", .mirror_meter_reading },
            .{ "UsagePoint", .usage_point },
            .{ "UsagePointList", .usage_point },
            .{ "MeterReading", .meter_reading },
            .{ "MeterReadingList", .meter_reading },
            .{ "Reading", .reading },
            .{ "ReadingList", .reading },
            .{ "ReadingSet", .reading_set },
            .{ "ReadingSetList", .reading_set },

            // Time messages
            .{ "Time", .time },

            // Demand Response messages
            .{ "DemandResponseProgram", .demand_response_program },
            .{ "DemandResponseProgramList", .demand_response_program_list },
            .{ "LoadShedAvailability", .load_shed_availability },
            .{ "EndDeviceControl", .end_device_control },
            .{ "EndDeviceControlList", .end_device_control_list },

            // Pricing messages
            .{ "TariffProfile", .tariff_profile },
            .{ "TariffProfileList", .tariff_profile_list },
            .{ "TimeTariffInterval", .time_tariff_interval },
            .{ "RateComponent", .rate_component },
            .{ "RateComponentList", .rate_component },

            // Log messages
            .{ "LogEvent", .log_event },
            .{ "LogEventList", .log_event_list },

            // File messages
            .{ "File", .file },
            .{ "FileList", .file_list },
            .{ "FileStatus", .file_status },
            .{ "FileStatusList", .file_status },

            // Subscription messages
            .{ "Subscription", .subscription },
            .{ "SubscriptionList", .subscription_list },
            .{ "Notification", .notification },
        });

        return type_map.get(root_element) orelse .unknown;
    }

    pub fn toString(self: MessageType) []const u8 {
        return switch (self) {
            .der_capability => "DERCapability",
            .der_control => "DERControl",
            .der_status => "DERStatus",
            .der_availability => "DERAvailability",
            .der_settings => "DERSettings",
            .device_capability => "DeviceCapability",
            .device_information => "DeviceInformation",
            .device_status => "DeviceStatus",
            .function_set_assignments => "FunctionSetAssignments",
            .end_device => "EndDevice",
            .end_device_list => "EndDeviceList",
            .mirror_usage_point => "MirrorUsagePoint",
            .mirror_meter_reading => "MirrorMeterReading",
            .usage_point => "UsagePoint",
            .meter_reading => "MeterReading",
            .reading => "Reading",
            .reading_set => "ReadingSet",
            .time => "Time",
            .demand_response_program => "DemandResponseProgram",
            .demand_response_program_list => "DemandResponseProgramList",
            .load_shed_availability => "LoadShedAvailability",
            .end_device_control => "EndDeviceControl",
            .end_device_control_list => "EndDeviceControlList",
            .tariff_profile => "TariffProfile",
            .tariff_profile_list => "TariffProfileList",
            .time_tariff_interval => "TimeTariffInterval",
            .rate_component => "RateComponent",
            .log_event => "LogEvent",
            .log_event_list => "LogEventList",
            .file => "File",
            .file_list => "FileList",
            .file_status => "FileStatus",
            .subscription => "Subscription",
            .subscription_list => "SubscriptionList",
            .notification => "Notification",
            .unknown => "Unknown",
        };
    }
};

/// Main XML parser for IEEE 2030.5 content
pub const XmlProcessor = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) XmlProcessor {
        return XmlProcessor{
            .allocator = allocator,
        };
    }

    /// Process XML content and return validation result
    /// This is the main entry point for all XML processing
    pub fn processXml(self: *XmlProcessor, xml_data: []const u8, direction: observability.Direction, backend_url: ?[]const u8) !XmlParseResult {
        var timer = observability.XmlTimer.start();

        var result = XmlParseResult{
            .is_well_formed = false,
            .processing_time_ns = 0,
        };

        // Handle empty or obviously non-XML content
        if (xml_data.len == 0) {
            result.processing_time_ns = timer.elapsedNs();
            result.error_message = try self.allocator.dupe(u8, "Empty content");
            observability.recordError(.malformed_xml, null);
            return result;
        }

        // Quick check: does it start with '<'?
        const trimmed = std.mem.trim(u8, xml_data, " \t\n\r");
        if (trimmed.len == 0 or trimmed[0] != '<') {
            result.processing_time_ns = timer.elapsedNs();
            result.error_message = try self.allocator.dupe(u8, "Not XML content");
            observability.recordError(.malformed_xml, null);
            return result;
        }

        // Zero-copy scan
        const scan_result = XmlScanner.scan(trimmed);

        if (scan_result.root_element) |elem| {
            // Create owned copy for thread-safe logging
            result.root_element = try self.allocator.dupe(u8, elem);
            result.message_type = MessageType.fromRootElement(elem);
            result.is_well_formed = scan_result.is_complete;

            if (result.is_well_formed) {
                result.processing_time_ns = timer.elapsedNs();
                observability.recordMessage(result.message_type.?, direction, backend_url, result.processing_time_ns);

                logger.debugf(self.allocator, "xml", "Processed {s} XML message ({s}) in {:.2}ms", .{ elem, @tagName(direction), timer.elapsedMs() });

                return result;
            } else {
                result.error_message = try self.allocator.dupe(u8, "XML appears incomplete or malformed");
                observability.recordError(.malformed_xml, result.message_type);
            }
        } else {
            result.error_message = try self.allocator.dupe(u8, "Could not find root element");
            observability.recordError(.parse_error, null);
        }

        result.processing_time_ns = timer.elapsedNs();
        return result;
    }
};

// Global initialization
var xml_processor_initialized = false;

pub fn init() void {
    if (!xml_processor_initialized) {
        xml_processor_initialized = true;
        logger.info("xml", "XML processor initialized (zero-copy mode)");
    }
}

pub fn deinit() void {
    if (xml_processor_initialized) {
        xml_processor_initialized = false;
        logger.info("xml", "XML processor deinitialized");
    }
}

/// Convenience function for quick XML validation
pub fn validateXml(allocator: std.mem.Allocator, xml_data: []const u8) !bool {
    var processor = XmlProcessor.init(allocator);
    var result = try processor.processXml(xml_data, .inbound, null);
    defer result.deinit(allocator);

    return result.is_well_formed;
}

/// Convenience function to get message type from XML
pub fn getMessageType(allocator: std.mem.Allocator, xml_data: []const u8) !?MessageType {
    var processor = XmlProcessor.init(allocator);
    var result = try processor.processXml(xml_data, .inbound, null);
    defer result.deinit(allocator);

    return result.message_type;
}
