// src/xml_parser.zig - XML parsing and validation for IEEE 2030.5 compliance
const std = @import("std");
const libxml2 = @import("utils/libxml2.zig");
const observability = @import("observability.zig");
const logger = @import("logger.zig");

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

        // Try fast root element extraction first
        const root_element = libxml2.extractRootElementName(self.allocator, trimmed) catch |err| {
            result.processing_time_ns = timer.elapsedNs();
            result.error_message = try std.fmt.allocPrint(self.allocator, "Root element extraction failed: {}", .{err});
            observability.recordError(.parse_error, null);
            return result;
        };

        if (root_element) |elem| {
            result.root_element = elem;
            result.message_type = MessageType.fromRootElement(elem);

            // Now do full XML validation
            result.is_well_formed = libxml2.isWellFormed(trimmed);

            if (!result.is_well_formed) {
                result.error_message = try self.allocator.dupe(u8, "XML is not well-formed");
                observability.recordError(.malformed_xml, result.message_type);
            } else {
                // Success! Record statistics
                result.processing_time_ns = timer.elapsedNs();
                observability.recordMessage(result.message_type.?, direction, backend_url, result.processing_time_ns);

                logger.debugf(self.allocator, "xml", "Processed {s} XML message ({s}) in {:.2}ms", .{ elem, @tagName(direction), timer.elapsedMs() });

                return result;
            }
        } else {
            result.error_message = try self.allocator.dupe(u8, "Could not extract root element");
            observability.recordError(.parse_error, null);
        }

        result.processing_time_ns = timer.elapsedNs();
        return result;
    }

    /// Detailed XML parsing with element access (for future validation)
    /// This provides access to the parsed XML tree for content validation
    pub fn parseWithAccess(self: *XmlProcessor, xml_data: []const u8) !?ParsedXml {
        if (xml_data.len == 0) return null;

        const trimmed = std.mem.trim(u8, xml_data, " \t\n\r");
        if (trimmed.len == 0 or trimmed[0] != '<') return null;

        const doc = libxml2.XmlDocument.parseMemory(self.allocator, trimmed) catch |err| {
            logger.debugf("xml", "Failed to parse XML document: {}", .{err});
            return null;
        };

        return ParsedXml{
            .document = doc,
            .allocator = self.allocator,
        };
    }
};

/// Wrapper for parsed XML document with helper methods
pub const ParsedXml = struct {
    document: libxml2.XmlDocument,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ParsedXml) void {
        self.document.deinit();
    }

    pub fn getRootElement(self: *ParsedXml) ?libxml2.XmlElement {
        return self.document.getRootElement();
    }

    /// Find element by name (simple XPath-like search)
    pub fn findElement(self: *ParsedXml, element_name: []const u8) ?libxml2.XmlElement {
        const root = self.getRootElement() orelse return null;
        return root.findElement(element_name);
    }

    /// Get text content of an element
    pub fn getElementText(self: *ParsedXml, element_name: []const u8) !?[]u8 {
        const element = self.findElement(element_name) orelse return null;
        return element.getContent();
    }

    /// Get attribute value from an element
    pub fn getElementAttribute(self: *ParsedXml, element_name: []const u8, attr_name: []const u8) !?[]u8 {
        const element = self.findElement(element_name) orelse return null;
        return element.getAttribute(attr_name);
    }

    /// IEEE 2030.5 specific: extract common fields for validation
    pub fn extractCommonFields(self: *ParsedXml) !CommonFields {
        var fields = CommonFields{};

        // Extract href (common in IEEE 2030.5)
        if (self.getRootElement()) |root| {
            fields.href = root.getAttribute("href") catch null;
        }

        // Extract mRID (meter reading ID)
        fields.mrid = self.getElementText("mRID") catch null;

        // Extract description
        fields.description = self.getElementText("description") catch null;

        // Extract version
        fields.version = self.getElementText("version") catch null;

        // Extract time-related fields
        fields.creation_time = self.getElementText("creationTime") catch null;
        fields.effective_time = self.getElementText("effectiveTime") catch null;

        return fields;
    }
};

/// Common IEEE 2030.5 fields for validation
pub const CommonFields = struct {
    href: ?[]u8 = null,
    mrid: ?[]u8 = null,
    description: ?[]u8 = null,
    version: ?[]u8 = null,
    creation_time: ?[]u8 = null,
    effective_time: ?[]u8 = null,

    pub fn deinit(self: *CommonFields, allocator: std.mem.Allocator) void {
        if (self.href) |h| allocator.free(h);
        if (self.mrid) |m| allocator.free(m);
        if (self.description) |d| allocator.free(d);
        if (self.version) |v| allocator.free(v);
        if (self.creation_time) |ct| allocator.free(ct);
        if (self.effective_time) |et| allocator.free(et);
    }
};

// Global initialization
var xml_processor_initialized = false;

pub fn init() void {
    if (!xml_processor_initialized) {
        libxml2.init();
        xml_processor_initialized = true;
        logger.info("xml", "XML processor initialized");
    }
}

pub fn deinit() void {
    if (xml_processor_initialized) {
        libxml2.deinit();
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
