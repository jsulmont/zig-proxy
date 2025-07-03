// src/mtls/certificate.zig
const std = @import("std");
const openssl = @import("../utils/openssl.zig");
const logger = @import("../logger.zig");

pub const CertificateInfo = struct {
    lfdi: ?[]const u8 = null,
    sfdi: ?[]const u8 = null,
    hardware_identity: ?HardwareIdentity = null,
    subject: ?[]const u8 = null,
    issuer: ?[]const u8 = null,
    fingerprint: ?[]const u8 = null,

    pub fn deinit(self: *CertificateInfo, allocator: std.mem.Allocator) void {
        if (self.lfdi) |lfdi| allocator.free(lfdi);
        if (self.sfdi) |sfdi| allocator.free(sfdi);
        if (self.hardware_identity) |*hw| hw.deinit(allocator);
        if (self.subject) |subject| allocator.free(subject);
        if (self.issuer) |issuer| allocator.free(issuer);
        if (self.fingerprint) |fp| allocator.free(fp);
    }
};

pub const DeviceType = enum {
    der_device,
    meter,
    gateway,
    aggregator,
    ev_charger,
    thermostat,
    custom,
    unknown,

    pub fn toString(self: DeviceType) []const u8 {
        return switch (self) {
            .der_device => "DER Device",
            .meter => "Smart Meter",
            .gateway => "Gateway",
            .aggregator => "Aggregator",
            .ev_charger => "EV Charger",
            .thermostat => "Smart Thermostat",
            .custom => "Custom Device",
            .unknown => "Unknown Device",
        };
    }

    pub fn fromString(s: []const u8) DeviceType {
        if (std.ascii.eqlIgnoreCase(s, "der_device")) return .der_device;
        if (std.ascii.eqlIgnoreCase(s, "meter")) return .meter;
        if (std.ascii.eqlIgnoreCase(s, "gateway")) return .gateway;
        if (std.ascii.eqlIgnoreCase(s, "aggregator")) return .aggregator;
        if (std.ascii.eqlIgnoreCase(s, "ev_charger")) return .ev_charger;
        if (std.ascii.eqlIgnoreCase(s, "thermostat")) return .thermostat;
        if (std.ascii.eqlIgnoreCase(s, "custom")) return .custom;
        return .unknown;
    }
};

pub const HardwareIdentity = struct {
    hw_type: []const u8,
    hw_serial: []const u8,
    raw_serial: []const u8,
    device_type: DeviceType,
    vendor_name: ?[]const u8,

    pub fn deinit(self: *HardwareIdentity, allocator: std.mem.Allocator) void {
        allocator.free(self.hw_type);
        allocator.free(self.hw_serial);
        allocator.free(self.raw_serial);
        if (self.vendor_name) |name| allocator.free(name);
    }
};

// Vendor OID configuration
pub const VendorOidConfig = struct {
    name: []const u8,
    oid: []const u8,
    device_type: DeviceType,
};

// Global vendor OID registry - can be populated from config
var vendor_oid_registry: ?std.StringHashMap(VendorOidConfig) = null;

pub fn initVendorRegistry(allocator: std.mem.Allocator) !void {
    if (vendor_oid_registry == null) {
        vendor_oid_registry = std.StringHashMap(VendorOidConfig).init(allocator);
    }
}

pub fn deinitVendorRegistry() void {
    if (vendor_oid_registry) |*registry| {
        registry.deinit();
        vendor_oid_registry = null;
    }
}

pub fn registerVendorOid(oid: []const u8, config: VendorOidConfig) !void {
    if (vendor_oid_registry) |*registry| {
        try registry.put(oid, config);
        logger.infof(std.heap.c_allocator, "certificate", "Registered vendor OID {s} for {s} ({s})", .{ oid, config.name, config.device_type.toString() });
    }
}

// IEEE 2030.5 specific OIDs
const IEEE_2030_5_HARDWARE_MODULE_NAME_OID = "1.3.6.1.5.5.7.8.4"; // Hardware Module Name extension
const IEEE_2030_5_DEVICE_IDENTITY_OID = "1.3.6.1.4.1.40732.2"; // IEEE 2030.5 device identity arc

pub fn calculateCertificateFingerprint(allocator: std.mem.Allocator, cert: *const openssl.Certificate) ![]u8 {
    const pem_data = try cert.toPem(allocator);
    defer allocator.free(pem_data);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(pem_data);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);

    var fingerprint = try allocator.alloc(u8, 64 + 15);
    var fp_idx: usize = 0;
    for (hash, 0..) |byte, i| {
        if (i > 0 and i % 2 == 0) {
            fingerprint[fp_idx] = '-';
            fp_idx += 1;
        }
        const hex_chars = "0123456789ABCDEF";
        fingerprint[fp_idx] = hex_chars[byte >> 4];
        fingerprint[fp_idx + 1] = hex_chars[byte & 0x0F];
        fp_idx += 2;
    }

    return fingerprint[0..fp_idx];
}

pub fn extractLfdiFromFingerprint(allocator: std.mem.Allocator, fingerprint: []const u8) ![]u8 {
    const clean_fp = try allocator.alloc(u8, 40);
    var clean_idx: usize = 0;
    var hex_count: usize = 0;

    for (fingerprint) |char| {
        if (char != '-') {
            if (hex_count >= 40) break;
            clean_fp[clean_idx] = char;
            clean_idx += 1;
            hex_count += 1;
        }
    }

    return clean_fp[0..40];
}

pub fn extractSfdiFromFingerprint(allocator: std.mem.Allocator, fingerprint: []const u8) ![]u8 {
    var clean_hex: [9]u8 = undefined;
    var hex_idx: usize = 0;

    for (fingerprint) |char| {
        if (char != '-' and hex_idx < 9) {
            clean_hex[hex_idx] = char;
            hex_idx += 1;
        }
    }

    const truncated = std.fmt.parseInt(u64, clean_hex[0..9], 16) catch return error.InvalidFingerprint;

    const decimal_str = try std.fmt.allocPrint(allocator, "{:011}", .{truncated});
    if (decimal_str.len != 11) {
        allocator.free(decimal_str);
        return error.InvalidSfdiLength;
    }

    var sum: u32 = 0;
    for (decimal_str) |digit| {
        sum += digit - '0';
    }
    const checksum = (10 - (sum % 10)) % 10;

    const sfdi = try std.fmt.allocPrint(allocator, "{s}{}", .{ decimal_str, checksum });
    allocator.free(decimal_str);

    return sfdi;
}

pub fn extractHardwareIdentity(allocator: std.mem.Allocator, cert: *const openssl.Certificate) !HardwareIdentity {
    // Try to extract hardware module name extension (OID 1.3.6.1.5.5.7.8.4)
    // This is commonly used for hardware device identification

    // First, try to get all extensions
    var extensions = std.ArrayList(CertExtension).init(allocator);
    defer extensions.deinit();

    try extractAllExtensions(allocator, cert, &extensions);

    // Look for hardware module name extension
    for (extensions.items) |ext| {
        defer ext.deinit(allocator);

        if (std.mem.eql(u8, ext.oid, IEEE_2030_5_HARDWARE_MODULE_NAME_OID)) {
            // Parse hardware module name structure
            return parseHardwareModuleName(allocator, ext.value);
        }
    }

    // Fallback: Look for vendor-specific OIDs in certificate policies
    var policy_oids = try cert.extractPolicyOids(allocator);
    defer {
        for (policy_oids.items) |oid| {
            allocator.free(oid);
        }
        policy_oids.deinit();
    }

    for (policy_oids.items) |policy_oid| {
        if (vendor_oid_registry) |*registry| {
            if (registry.get(policy_oid)) |vendor_config| {
                // Found a registered vendor OID
                logger.debugf(allocator, "certificate", "Found vendor OID {s} for {s}", .{ policy_oid, vendor_config.name });

                // Extract serial number from subject DN
                const subject = try cert.getSubjectName(allocator);
                defer allocator.free(subject);

                const serial = extractSerialFromDN(subject) orelse "UNKNOWN";

                return HardwareIdentity{
                    .hw_type = try allocator.dupe(u8, policy_oid),
                    .hw_serial = try allocator.dupe(u8, serial),
                    .raw_serial = try allocator.dupe(u8, serial),
                    .device_type = vendor_config.device_type,
                    .vendor_name = try allocator.dupe(u8, vendor_config.name),
                };
            }
        }
    }

    // Last fallback: Try to extract from subject DN
    const subject = try cert.getSubjectName(allocator);
    defer allocator.free(subject);

    if (extractSerialFromDN(subject)) |serial| {
        logger.debugf(allocator, "certificate", "Using serial from DN: {s}", .{serial});

        return HardwareIdentity{
            .hw_type = try allocator.dupe(u8, "DN-SERIAL"),
            .hw_serial = try allocator.dupe(u8, serial),
            .raw_serial = try allocator.dupe(u8, serial),
            .device_type = .unknown,
            .vendor_name = null,
        };
    }

    return error.HardwareIdentityNotFound;
}

const CertExtension = struct {
    oid: []const u8,
    critical: bool,
    value: []const u8,

    pub fn deinit(self: *const CertExtension, allocator: std.mem.Allocator) void {
        allocator.free(self.oid);
        allocator.free(self.value);
    }
};

fn extractAllExtensions(allocator: std.mem.Allocator, cert: *const openssl.Certificate, extensions: *std.ArrayList(CertExtension)) !void {
    // This is a simplified version - in reality, you'd need to iterate through
    // all certificate extensions using OpenSSL APIs
    // For now, we'll just handle the extensions we can get

    // Get certificate policies (we already have this implemented)
    var policy_oids = try cert.extractPolicyOids(allocator);
    defer {
        for (policy_oids.items) |oid| {
            allocator.free(oid);
        }
        policy_oids.deinit();
    }

    // Add policy OIDs as extensions
    for (policy_oids.items) |policy_oid| {
        try extensions.append(CertExtension{
            .oid = try allocator.dupe(u8, "2.5.29.32"), // Certificate Policies OID
            .critical = false,
            .value = try allocator.dupe(u8, policy_oid),
        });
    }

    // TODO: Add more extension parsing here
    // Need to add OpenSSL bindings for:
    // - X509_get_ext_count()
    // - X509_get_ext()
    // - X509_EXTENSION_get_object()
    // - X509_EXTENSION_get_data()
}

fn parseHardwareModuleName(allocator: std.mem.Allocator, data: []const u8) !HardwareIdentity {
    // Hardware Module Name is typically encoded as:
    // SEQUENCE {
    //   hwType OBJECT IDENTIFIER,
    //   hwSerialNum OCTET STRING
    // }

    // This is a simplified parser - in production you'd use proper ASN.1 parsing
    // For now, we'll just extract what we can

    // TODO: Implement proper ASN.1 parsing
    logger.debug("certificate", "Hardware module name parsing not fully implemented");

    return HardwareIdentity{
        .hw_type = try allocator.dupe(u8, "HW-MODULE"),
        .hw_serial = try allocator.dupe(u8, "PENDING"),
        .raw_serial = try allocator.dupe(u8, data),
        .device_type = .unknown,
        .vendor_name = null,
    };
}

fn extractSerialFromDN(dn: []const u8) ?[]const u8 {
    // Look for serial number in DN
    // Common patterns: "CN=device-12345", "serialNumber=12345", "UID=12345"

    const patterns = [_][]const u8{
        "serialNumber=",
        "SERIALNUMBER=",
        "UID=",
        "uid=",
        "CN=device-",
        "CN=meter-",
        "CN=der-",
    };

    for (patterns) |pattern| {
        if (std.mem.indexOf(u8, dn, pattern)) |idx| {
            const start = idx + pattern.len;
            var end = start;

            // Find end of value (comma, slash, or end of string)
            while (end < dn.len and dn[end] != ',' and dn[end] != '/') : (end += 1) {}

            if (end > start) {
                return dn[start..end];
            }
        }
    }

    return null;
}

// Helper function to identify device type from certificate attributes
pub fn identifyDeviceType(cert_info: *const CertificateInfo) DeviceType {
    if (cert_info.hardware_identity) |hw| {
        // If we have vendor info, use that
        if (hw.device_type != .unknown) {
            return hw.device_type;
        }

        // Try to guess from serial number patterns
        if (std.mem.indexOf(u8, hw.hw_serial, "DER") != null) return .der_device;
        if (std.mem.indexOf(u8, hw.hw_serial, "MTR") != null) return .meter;
        if (std.mem.indexOf(u8, hw.hw_serial, "GW") != null) return .gateway;
        if (std.mem.indexOf(u8, hw.hw_serial, "AGG") != null) return .aggregator;
        if (std.mem.indexOf(u8, hw.hw_serial, "EVSE") != null) return .ev_charger;
        if (std.mem.indexOf(u8, hw.hw_serial, "TSTAT") != null) return .thermostat;
    }

    // Try subject DN patterns
    if (cert_info.subject) |subject| {
        const lower = std.ascii.lowerString(subject, subject);
        defer std.heap.c_allocator.free(lower);

        if (std.mem.indexOf(u8, lower, "meter") != null) return .meter;
        if (std.mem.indexOf(u8, lower, "gateway") != null) return .gateway;
        if (std.mem.indexOf(u8, lower, "aggregator") != null) return .aggregator;
        if (std.mem.indexOf(u8, lower, "charger") != null) return .ev_charger;
        if (std.mem.indexOf(u8, lower, "evse") != null) return .ev_charger;
        if (std.mem.indexOf(u8, lower, "thermostat") != null) return .thermostat;
        if (std.mem.indexOf(u8, lower, "der") != null) return .der_device;
    }

    return .unknown;
}
