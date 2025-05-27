// src/mtls/certificate.zig
const std = @import("std");
const openssl = @import("../utils/openssl.zig");

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

pub const HardwareIdentity = struct {
    hw_type: []const u8,
    hw_serial: []const u8,
    raw_serial: []const u8,

    const SYNERGY_ABN_OID = "1.2.36.58673830106";
    const SYNERGY_PEN_OID = "1.3.6.1.4.1.62445";

    pub fn deinit(self: *HardwareIdentity, allocator: std.mem.Allocator) void {
        allocator.free(self.hw_type);
        allocator.free(self.hw_serial);
        allocator.free(self.raw_serial);
    }

    pub fn isSynergyDevice(self: *const HardwareIdentity) bool {
        return std.mem.eql(u8, self.hw_type, SYNERGY_ABN_OID) or
            std.mem.eql(u8, self.hw_type, SYNERGY_PEN_OID);
    }
};

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
    _ = cert;

    const SYNERGY_PEN_OID = "1.3.6.1.4.1.62445";

    return HardwareIdentity{
        .hw_type = try allocator.dupe(u8, SYNERGY_PEN_OID),
        .hw_serial = try allocator.dupe(u8, "SIM001"),
        .raw_serial = try allocator.dupe(u8, "SIM001"),
    };
}
