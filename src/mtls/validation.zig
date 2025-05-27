// src/mtls/validation.zig - Certificate validation for IEEE 2030.5
const std = @import("std");
const openssl = @import("../utils/openssl.zig");
const certificate = @import("certificate.zig");
const logger = @import("../logger.zig");

const IEEE2030_DEVICE_OID = "1.3.6.1.4.1.40732.1.1";
const IEEE2030_MOBILE_OID = "1.3.6.1.4.1.40732.1.2";
const IEEE2030_POST_MANUFACTURE_OID = "1.3.6.1.4.1.40732.1.3";
const IEEE2030_TEST_OID = "1.3.6.1.4.1.40732.2.1";
const IEEE2030_SELF_SIGNED_OID = "1.3.6.1.4.1.40732.2.2";
const IEEE2030_SERVICE_PROVIDER_OID = "1.3.6.1.4.1.40732.2.3";
const IEEE2030_BULK_ISSUED_OID = "1.3.6.1.4.1.40732.2.4";

pub const ValidationError = error{
    PolicyExtractionFailed,
    NoPolicyOidsFound,
    MissingRequiredOids,
    HardwareIdentityRequired,
};

pub const CertificateValidator = struct {
    allocator: std.mem.Allocator,
    skip_oid_validation: bool = false,

    pub fn init(allocator: std.mem.Allocator, skip_oid_validation: bool) CertificateValidator {
        return CertificateValidator{
            .allocator = allocator,
            .skip_oid_validation = skip_oid_validation,
        };
    }

    pub fn validateCertificate(self: *CertificateValidator, cert: *const openssl.Certificate) !certificate.CertificateInfo {
        var cert_info = certificate.CertificateInfo{};
        errdefer cert_info.deinit(self.allocator);

        cert_info.subject = cert.getSubjectName(self.allocator) catch |err| blk: {
            logger.warnf(self.allocator, "tls", "Failed to get certificate subject: {}", .{err});
            break :blk try self.allocator.dupe(u8, "unknown");
        };

        cert_info.issuer = cert.getIssuerName(self.allocator) catch |err| blk: {
            logger.warnf(self.allocator, "tls", "Failed to get certificate issuer: {}", .{err});
            break :blk try self.allocator.dupe(u8, "unknown");
        };

        cert_info.fingerprint = try certificate.calculateCertificateFingerprint(self.allocator, cert);

        cert_info.lfdi = try certificate.extractLfdiFromFingerprint(self.allocator, cert_info.fingerprint.?);
        cert_info.sfdi = try certificate.extractSfdiFromFingerprint(self.allocator, cert_info.fingerprint.?);

        cert_info.hardware_identity = certificate.extractHardwareIdentity(self.allocator, cert) catch |err| {
            logger.errf(self.allocator, "tls", "Failed to extract hardware identity: {}", .{err});
            return ValidationError.HardwareIdentityRequired;
        };

        if (!self.skip_oid_validation) {
            try self.validatePolicyRequirements(cert);
        } else {
            logger.debug("tls", "Skipping policy OID validation as configured");
        }

        logger.debug("tls", "Certificate validation successful");
        return cert_info;
    }

    fn validatePolicyRequirements(self: *CertificateValidator, cert: *const openssl.Certificate) !void {
        var policy_oids = cert.extractPolicyOids(self.allocator) catch |err| {
            logger.errf(self.allocator, "tls", "Failed to extract policy OIDs: {}", .{err});
            return ValidationError.PolicyExtractionFailed;
        };
        defer {
            for (policy_oids.items) |oid| {
                self.allocator.free(oid);
            }
            policy_oids.deinit();
        }

        for (policy_oids.items) |oid| {
            logger.debugf(self.allocator, "tls", "  Policy OID: {s}", .{oid});
        }

        if (policy_oids.items.len == 0) {
            return ValidationError.NoPolicyOidsFound;
        }

        var has_device_type = false;
        for (policy_oids.items) |oid| {
            if (std.mem.eql(u8, oid, IEEE2030_DEVICE_OID) or
                std.mem.eql(u8, oid, IEEE2030_MOBILE_OID) or
                std.mem.eql(u8, oid, IEEE2030_POST_MANUFACTURE_OID))
            {
                has_device_type = true;
                break;
            }
        }

        var has_special_type = false;
        for (policy_oids.items) |oid| {
            if (std.mem.eql(u8, oid, IEEE2030_TEST_OID) or
                std.mem.eql(u8, oid, IEEE2030_SELF_SIGNED_OID) or
                std.mem.eql(u8, oid, IEEE2030_SERVICE_PROVIDER_OID) or
                std.mem.eql(u8, oid, IEEE2030_BULK_ISSUED_OID))
            {
                has_special_type = true;
                break;
            }
        }

        if (!has_device_type and !has_special_type) {
            logger.err("tls", "Certificate missing required IEEE 2030.5 device or special type OIDs");
            return ValidationError.MissingRequiredOids;
        }

        logger.debug("tls", "IEEE 2030.5 policy validation passed");
    }
};
