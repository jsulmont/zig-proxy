// src/observability.zig
// Lock-free XML message statistics and timing
const std = @import("std");
const logger = @import("logger.zig");
const xml_parser = @import("xml_parser.zig");

pub const MessageType = xml_parser.MessageType;

const MAX_BACKENDS = 16; // TODO: make configurable

const BackendAtomicStat = struct {
    url_hash: std.atomic.Value(u64), // Hash of the URL (0 means unused slot)
    count: std.atomic.Value(u64),

    const EMPTY_HASH: u64 = 0;

    fn init() BackendAtomicStat {
        return BackendAtomicStat{
            .url_hash = std.atomic.Value(u64).init(EMPTY_HASH),
            .count = std.atomic.Value(u64).init(0),
        };
    }

    fn isEmpty(self: *const BackendAtomicStat) bool {
        return self.url_hash.load(.monotonic) == EMPTY_HASH;
    }

    fn matchesUrl(self: *const BackendAtomicStat, url: []const u8) bool {
        const url_hash = hashString(url);
        return self.url_hash.load(.monotonic) == url_hash;
    }

    fn tryClaimForUrl(self: *BackendAtomicStat, url: []const u8) bool {
        const url_hash = hashString(url);
        const expected = EMPTY_HASH;
        return self.url_hash.cmpxchgStrong(expected, url_hash, .acq_rel, .monotonic) == null;
    }
};

fn hashString(s: []const u8) u64 {
    // TODO: find a better hash function (std?)
    var hash: u64 = 5381;
    for (s) |c| {
        hash = ((hash << 5) +% hash) +% c;
    }
    return if (hash == 0) 1 else hash;
}

/// We use std.atomics here, which is overkill as
/// by design we're single threaded.
pub const XmlStats = struct {
    // Direction counters
    inbound_total: std.atomic.Value(u64), // client -> server
    outbound_total: std.atomic.Value(u64), // server -> client

    // Processing time tracking (nanoseconds)
    total_parse_time_ns: std.atomic.Value(u64),
    total_messages_parsed: std.atomic.Value(u64),

    // Error counters
    malformed_xml_count: std.atomic.Value(u64),
    parse_error_count: std.atomic.Value(u64),
    validation_error_count: std.atomic.Value(u64),

    // IEEE 2030.5 message type counters (static set - no dynamic allocation needed!)
    der_capability_count: std.atomic.Value(u64),
    der_control_count: std.atomic.Value(u64),
    der_status_count: std.atomic.Value(u64),
    der_availability_count: std.atomic.Value(u64),
    der_settings_count: std.atomic.Value(u64),
    device_capability_count: std.atomic.Value(u64),
    device_information_count: std.atomic.Value(u64),
    device_status_count: std.atomic.Value(u64),
    function_set_assignments_count: std.atomic.Value(u64),
    end_device_count: std.atomic.Value(u64),
    end_device_list_count: std.atomic.Value(u64),
    mirror_usage_point_count: std.atomic.Value(u64),
    mirror_meter_reading_count: std.atomic.Value(u64),
    usage_point_count: std.atomic.Value(u64),
    meter_reading_count: std.atomic.Value(u64),
    reading_count: std.atomic.Value(u64),
    reading_set_count: std.atomic.Value(u64),
    time_count: std.atomic.Value(u64),
    demand_response_program_count: std.atomic.Value(u64),
    demand_response_program_list_count: std.atomic.Value(u64),
    load_shed_availability_count: std.atomic.Value(u64),
    end_device_control_count: std.atomic.Value(u64),
    end_device_control_list_count: std.atomic.Value(u64),
    tariff_profile_count: std.atomic.Value(u64),
    tariff_profile_list_count: std.atomic.Value(u64),
    time_tariff_interval_count: std.atomic.Value(u64),
    rate_component_count: std.atomic.Value(u64),
    log_event_count: std.atomic.Value(u64),
    log_event_list_count: std.atomic.Value(u64),
    file_count: std.atomic.Value(u64),
    file_list_count: std.atomic.Value(u64),
    file_status_count: std.atomic.Value(u64),
    subscription_count: std.atomic.Value(u64),
    subscription_list_count: std.atomic.Value(u64),
    notification_count: std.atomic.Value(u64),
    unknown_count: std.atomic.Value(u64),

    // Backend counters
    backend_stats: [MAX_BACKENDS]BackendAtomicStat,
    backend_count: std.atomic.Value(usize),

    pub fn init() XmlStats {
        var backend_stats: [MAX_BACKENDS]BackendAtomicStat = undefined;
        for (&backend_stats) |*stat| {
            stat.* = BackendAtomicStat.init();
        }

        return XmlStats{
            .inbound_total = std.atomic.Value(u64).init(0),
            .outbound_total = std.atomic.Value(u64).init(0),
            .total_parse_time_ns = std.atomic.Value(u64).init(0),
            .total_messages_parsed = std.atomic.Value(u64).init(0),
            .malformed_xml_count = std.atomic.Value(u64).init(0),
            .parse_error_count = std.atomic.Value(u64).init(0),
            .validation_error_count = std.atomic.Value(u64).init(0),
            .der_capability_count = std.atomic.Value(u64).init(0),
            .der_control_count = std.atomic.Value(u64).init(0),
            .der_status_count = std.atomic.Value(u64).init(0),
            .der_availability_count = std.atomic.Value(u64).init(0),
            .der_settings_count = std.atomic.Value(u64).init(0),
            .device_capability_count = std.atomic.Value(u64).init(0),
            .device_information_count = std.atomic.Value(u64).init(0),
            .device_status_count = std.atomic.Value(u64).init(0),
            .function_set_assignments_count = std.atomic.Value(u64).init(0),
            .end_device_count = std.atomic.Value(u64).init(0),
            .end_device_list_count = std.atomic.Value(u64).init(0),
            .mirror_usage_point_count = std.atomic.Value(u64).init(0),
            .mirror_meter_reading_count = std.atomic.Value(u64).init(0),
            .usage_point_count = std.atomic.Value(u64).init(0),
            .meter_reading_count = std.atomic.Value(u64).init(0),
            .reading_count = std.atomic.Value(u64).init(0),
            .reading_set_count = std.atomic.Value(u64).init(0),
            .time_count = std.atomic.Value(u64).init(0),
            .demand_response_program_count = std.atomic.Value(u64).init(0),
            .demand_response_program_list_count = std.atomic.Value(u64).init(0),
            .load_shed_availability_count = std.atomic.Value(u64).init(0),
            .end_device_control_count = std.atomic.Value(u64).init(0),
            .end_device_control_list_count = std.atomic.Value(u64).init(0),
            .tariff_profile_count = std.atomic.Value(u64).init(0),
            .tariff_profile_list_count = std.atomic.Value(u64).init(0),
            .time_tariff_interval_count = std.atomic.Value(u64).init(0),
            .rate_component_count = std.atomic.Value(u64).init(0),
            .log_event_count = std.atomic.Value(u64).init(0),
            .log_event_list_count = std.atomic.Value(u64).init(0),
            .file_count = std.atomic.Value(u64).init(0),
            .file_list_count = std.atomic.Value(u64).init(0),
            .file_status_count = std.atomic.Value(u64).init(0),
            .subscription_count = std.atomic.Value(u64).init(0),
            .subscription_list_count = std.atomic.Value(u64).init(0),
            .notification_count = std.atomic.Value(u64).init(0),
            .unknown_count = std.atomic.Value(u64).init(0),
            .backend_stats = backend_stats,
            .backend_count = std.atomic.Value(usize).init(0),
        };
    }

    pub fn deinit(self: *XmlStats) void {
        _ = self;
    }

    /// Record XML message processing with timing
    pub fn recordMessage(self: *XmlStats, message_type: MessageType, direction: Direction, backend_url: ?[]const u8, parse_time_ns: u64) void {
        switch (direction) {
            .inbound => _ = self.inbound_total.fetchAdd(1, .monotonic),
            .outbound => _ = self.outbound_total.fetchAdd(1, .monotonic),
        }

        _ = self.total_parse_time_ns.fetchAdd(parse_time_ns, .monotonic);
        _ = self.total_messages_parsed.fetchAdd(1, .monotonic);

        self.incrementMessageTypeCounter(message_type);

        if (backend_url) |url| {
            self.incrementBackendCounter(url);
        }

        logger.debugf(std.heap.c_allocator, "xml_stats", "Recorded {s} message ({s}) in {:.2}ms", .{ message_type.toString(), @tagName(direction), @as(f64, @floatFromInt(parse_time_ns)) / 1_000_000.0 });
    }

    pub fn recordError(self: *XmlStats, error_type: ErrorType, message_type: ?MessageType) void {
        switch (error_type) {
            .malformed_xml => _ = self.malformed_xml_count.fetchAdd(1, .monotonic),
            .parse_error => _ = self.parse_error_count.fetchAdd(1, .monotonic),
            .validation_error => _ = self.validation_error_count.fetchAdd(1, .monotonic),
        }

        logger.warnf(std.heap.c_allocator, "xml_stats", "Recorded {s} error for message type: {s}", .{ @tagName(error_type), if (message_type) |mt| mt.toString() else "unknown" });
    }

    fn incrementMessageTypeCounter(self: *XmlStats, message_type: MessageType) void {
        switch (message_type) {
            .der_capability => _ = self.der_capability_count.fetchAdd(1, .monotonic),
            .der_control => _ = self.der_control_count.fetchAdd(1, .monotonic),
            .der_status => _ = self.der_status_count.fetchAdd(1, .monotonic),
            .der_availability => _ = self.der_availability_count.fetchAdd(1, .monotonic),
            .der_settings => _ = self.der_settings_count.fetchAdd(1, .monotonic),
            .device_capability => _ = self.device_capability_count.fetchAdd(1, .monotonic),
            .device_information => _ = self.device_information_count.fetchAdd(1, .monotonic),
            .device_status => _ = self.device_status_count.fetchAdd(1, .monotonic),
            .function_set_assignments => _ = self.function_set_assignments_count.fetchAdd(1, .monotonic),
            .end_device => _ = self.end_device_count.fetchAdd(1, .monotonic),
            .end_device_list => _ = self.end_device_list_count.fetchAdd(1, .monotonic),
            .mirror_usage_point => _ = self.mirror_usage_point_count.fetchAdd(1, .monotonic),
            .mirror_meter_reading => _ = self.mirror_meter_reading_count.fetchAdd(1, .monotonic),
            .usage_point => _ = self.usage_point_count.fetchAdd(1, .monotonic),
            .meter_reading => _ = self.meter_reading_count.fetchAdd(1, .monotonic),
            .reading => _ = self.reading_count.fetchAdd(1, .monotonic),
            .reading_set => _ = self.reading_set_count.fetchAdd(1, .monotonic),
            .time => _ = self.time_count.fetchAdd(1, .monotonic),
            .demand_response_program => _ = self.demand_response_program_count.fetchAdd(1, .monotonic),
            .demand_response_program_list => _ = self.demand_response_program_list_count.fetchAdd(1, .monotonic),
            .load_shed_availability => _ = self.load_shed_availability_count.fetchAdd(1, .monotonic),
            .end_device_control => _ = self.end_device_control_count.fetchAdd(1, .monotonic),
            .end_device_control_list => _ = self.end_device_control_list_count.fetchAdd(1, .monotonic),
            .tariff_profile => _ = self.tariff_profile_count.fetchAdd(1, .monotonic),
            .tariff_profile_list => _ = self.tariff_profile_list_count.fetchAdd(1, .monotonic),
            .time_tariff_interval => _ = self.time_tariff_interval_count.fetchAdd(1, .monotonic),
            .rate_component => _ = self.rate_component_count.fetchAdd(1, .monotonic),
            .log_event => _ = self.log_event_count.fetchAdd(1, .monotonic),
            .log_event_list => _ = self.log_event_list_count.fetchAdd(1, .monotonic),
            .file => _ = self.file_count.fetchAdd(1, .monotonic),
            .file_list => _ = self.file_list_count.fetchAdd(1, .monotonic),
            .file_status => _ = self.file_status_count.fetchAdd(1, .monotonic),
            .subscription => _ = self.subscription_count.fetchAdd(1, .monotonic),
            .subscription_list => _ = self.subscription_list_count.fetchAdd(1, .monotonic),
            .notification => _ = self.notification_count.fetchAdd(1, .monotonic),
            .unknown => _ = self.unknown_count.fetchAdd(1, .monotonic),
        }
    }

    fn incrementBackendCounter(self: *XmlStats, backend_url: []const u8) void {
        const url_hash = hashString(backend_url);

        for (&self.backend_stats) |*stat| {
            if (stat.url_hash.load(.monotonic) == url_hash) {
                _ = stat.count.fetchAdd(1, .monotonic);
                return;
            }
        }

        for (&self.backend_stats) |*stat| {
            if (stat.tryClaimForUrl(backend_url)) {
                _ = stat.count.fetchAdd(1, .monotonic);
                _ = self.backend_count.fetchAdd(1, .monotonic);
                return;
            }
        }

        logger.warnf(std.heap.c_allocator, "xml_stats", "Backend stats array full, cannot track: {s}", .{backend_url});
    }

    pub fn getSnapshot(self: *XmlStats, allocator: std.mem.Allocator) !StatsSnapshot {
        var message_types = std.ArrayList(MessageTypeStat).init(allocator);

        const addIfNonZero = struct {
            fn add(list: *std.ArrayList(MessageTypeStat), alloc: std.mem.Allocator, name: []const u8, counter: *const std.atomic.Value(u64)) !void {
                const count = counter.load(.monotonic);
                if (count > 0) {
                    try list.append(MessageTypeStat{
                        .name = try alloc.dupe(u8, name),
                        .count = count,
                    });
                }
            }
        }.add;

        try addIfNonZero(&message_types, allocator, "DERCapability", &self.der_capability_count);
        try addIfNonZero(&message_types, allocator, "DERControl", &self.der_control_count);
        try addIfNonZero(&message_types, allocator, "DERStatus", &self.der_status_count);
        try addIfNonZero(&message_types, allocator, "DERAvailability", &self.der_availability_count);
        try addIfNonZero(&message_types, allocator, "DERSettings", &self.der_settings_count);
        try addIfNonZero(&message_types, allocator, "DeviceCapability", &self.device_capability_count);
        try addIfNonZero(&message_types, allocator, "DeviceInformation", &self.device_information_count);
        try addIfNonZero(&message_types, allocator, "DeviceStatus", &self.device_status_count);
        try addIfNonZero(&message_types, allocator, "FunctionSetAssignments", &self.function_set_assignments_count);
        try addIfNonZero(&message_types, allocator, "EndDevice", &self.end_device_count);
        try addIfNonZero(&message_types, allocator, "EndDeviceList", &self.end_device_list_count);
        try addIfNonZero(&message_types, allocator, "MirrorUsagePoint", &self.mirror_usage_point_count);
        try addIfNonZero(&message_types, allocator, "MirrorMeterReading", &self.mirror_meter_reading_count);
        try addIfNonZero(&message_types, allocator, "UsagePoint", &self.usage_point_count);
        try addIfNonZero(&message_types, allocator, "MeterReading", &self.meter_reading_count);
        try addIfNonZero(&message_types, allocator, "Reading", &self.reading_count);
        try addIfNonZero(&message_types, allocator, "ReadingSet", &self.reading_set_count);
        try addIfNonZero(&message_types, allocator, "Time", &self.time_count);
        try addIfNonZero(&message_types, allocator, "DemandResponseProgram", &self.demand_response_program_count);
        try addIfNonZero(&message_types, allocator, "DemandResponseProgramList", &self.demand_response_program_list_count);
        try addIfNonZero(&message_types, allocator, "LoadShedAvailability", &self.load_shed_availability_count);
        try addIfNonZero(&message_types, allocator, "EndDeviceControl", &self.end_device_control_count);
        try addIfNonZero(&message_types, allocator, "EndDeviceControlList", &self.end_device_control_list_count);
        try addIfNonZero(&message_types, allocator, "TariffProfile", &self.tariff_profile_count);
        try addIfNonZero(&message_types, allocator, "TariffProfileList", &self.tariff_profile_list_count);
        try addIfNonZero(&message_types, allocator, "TimeTariffInterval", &self.time_tariff_interval_count);
        try addIfNonZero(&message_types, allocator, "RateComponent", &self.rate_component_count);
        try addIfNonZero(&message_types, allocator, "LogEvent", &self.log_event_count);
        try addIfNonZero(&message_types, allocator, "LogEventList", &self.log_event_list_count);
        try addIfNonZero(&message_types, allocator, "File", &self.file_count);
        try addIfNonZero(&message_types, allocator, "FileList", &self.file_list_count);
        try addIfNonZero(&message_types, allocator, "FileStatus", &self.file_status_count);
        try addIfNonZero(&message_types, allocator, "Subscription", &self.subscription_count);
        try addIfNonZero(&message_types, allocator, "SubscriptionList", &self.subscription_list_count);
        try addIfNonZero(&message_types, allocator, "Notification", &self.notification_count);
        try addIfNonZero(&message_types, allocator, "Unknown", &self.unknown_count);

        var backends = std.ArrayList(BackendStat).init(allocator);
        for (&self.backend_stats, 0..) |*stat, i| {
            const count = stat.count.load(.monotonic);
            if (count > 0) {
                const backend_name = try std.fmt.allocPrint(allocator, "backend-{}", .{i});
                try backends.append(BackendStat{
                    .url = backend_name,
                    .count = count,
                });
            }
        }

        const total_messages = self.total_messages_parsed.load(.monotonic);
        const total_time = self.total_parse_time_ns.load(.monotonic);

        return StatsSnapshot{
            .inbound_count = self.inbound_total.load(.monotonic),
            .outbound_count = self.outbound_total.load(.monotonic),
            .total_messages = total_messages,
            .average_parse_time_ms = if (total_messages > 0)
                @as(f64, @floatFromInt(total_time)) / @as(f64, @floatFromInt(total_messages)) / 1_000_000.0
            else
                0.0,
            .malformed_xml_count = self.malformed_xml_count.load(.monotonic),
            .parse_error_count = self.parse_error_count.load(.monotonic),
            .validation_error_count = self.validation_error_count.load(.monotonic),
            .message_types = message_types,
            .backends = backends,
        };
    }

    /// Get statistics as JSON string
    pub fn toJson(self: *XmlStats, allocator: std.mem.Allocator) ![]u8 {
        const snapshot = try self.getSnapshot(allocator);
        defer snapshot.deinit(allocator);

        const SerializableSnapshot = struct {
            inbound_count: u64,
            outbound_count: u64,
            total_messages: u64,
            average_parse_time_ms: f64,
            malformed_xml_count: u64,
            parse_error_count: u64,
            validation_error_count: u64,
            message_types: []const MessageTypeStat,
            backends: []const BackendStat,
        };

        const serializable = SerializableSnapshot{
            .inbound_count = snapshot.inbound_count,
            .outbound_count = snapshot.outbound_count,
            .total_messages = snapshot.total_messages,
            .average_parse_time_ms = snapshot.average_parse_time_ms,
            .malformed_xml_count = snapshot.malformed_xml_count,
            .parse_error_count = snapshot.parse_error_count,
            .validation_error_count = snapshot.validation_error_count,
            .message_types = snapshot.message_types.items,
            .backends = snapshot.backends.items,
        };

        return try std.json.stringifyAlloc(allocator, serializable, .{
            .whitespace = .indent_2,
        });
    }
};

pub const Direction = enum {
    inbound,
    outbound,
};

pub const ErrorType = enum {
    malformed_xml,
    parse_error,
    validation_error,
};

pub const MessageTypeStat = struct {
    name: []const u8,
    count: u64,

    pub fn deinit(self: *MessageTypeStat, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }
};

pub const BackendStat = struct {
    url: []const u8,
    count: u64,

    pub fn deinit(self: *BackendStat, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
    }
};

pub const StatsSnapshot = struct {
    inbound_count: u64,
    outbound_count: u64,
    total_messages: u64,
    average_parse_time_ms: f64,
    malformed_xml_count: u64,
    parse_error_count: u64,
    validation_error_count: u64,
    message_types: std.ArrayList(MessageTypeStat),
    backends: std.ArrayList(BackendStat),

    pub fn deinit(self: *const StatsSnapshot, allocator: std.mem.Allocator) void {
        for (self.message_types.items) |*stat| {
            allocator.free(stat.name);
        }
        self.message_types.deinit();

        for (self.backends.items) |*stat| {
            allocator.free(stat.url);
        }
        self.backends.deinit();
    }
};

/// Timer for measuring XML processing time
pub const XmlTimer = struct {
    start_time: i128,

    pub fn start() XmlTimer {
        return XmlTimer{
            .start_time = std.time.nanoTimestamp(),
        };
    }

    pub fn elapsedNs(self: *const XmlTimer) u64 {
        const now = std.time.nanoTimestamp();
        const elapsed = now - self.start_time;
        return @intCast(@max(0, elapsed));
    }

    pub fn elapsedMs(self: *const XmlTimer) f64 {
        return @as(f64, @floatFromInt(self.elapsedNs())) / 1_000_000.0;
    }
};

// Global XML stats instance
var global_xml_stats: ?*XmlStats = null;

pub fn initGlobalStats(allocator: std.mem.Allocator) !void {
    const stats = try allocator.create(XmlStats);
    stats.* = XmlStats.init();
    global_xml_stats = stats;
    logger.info("xml_stats", "Global XML statistics initialized (lock-free)");
}

pub fn deinitGlobalStats(allocator: std.mem.Allocator) void {
    if (global_xml_stats) |stats| {
        stats.deinit();
        allocator.destroy(stats);
        global_xml_stats = null;
        logger.info("xml_stats", "Global XML statistics deinitialized");
    }
}

pub fn getGlobalStats() ?*XmlStats {
    return global_xml_stats;
}

/// Convenience function to record a message with global stats
pub fn recordMessage(message_type: MessageType, direction: Direction, backend_url: ?[]const u8, parse_time_ns: u64) void {
    if (global_xml_stats) |stats| {
        stats.recordMessage(message_type, direction, backend_url, parse_time_ns); // No error possible!
    }
}

/// Convenience function to record an error with global stats
pub fn recordError(error_type: ErrorType, message_type: ?MessageType) void {
    if (global_xml_stats) |stats| {
        stats.recordError(error_type, message_type);
    }
}
