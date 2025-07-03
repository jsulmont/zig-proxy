// build.zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const toml_dep = b.dependency("toml", .{
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "zig-proxy",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("zig-toml", toml_dep.module("zig-toml"));

    exe.linkLibC();
    exe.linkSystemLibrary("ssl");
    exe.linkSystemLibrary("crypto");
    exe.linkSystemLibrary("xml2");
    exe.linkSystemLibrary("uv");

    if (target.result.os.tag == .macos) {
        // Add homebrew paths
        exe.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
        exe.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });

        // Add libxml2 include path
        exe.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include/libxml2" });

        // Try to find OpenSSL dynamically instead of hardcoding version
        // First try the generic path
        const generic_ssl_include = "/opt/homebrew/opt/openssl/include";
        const generic_ssl_lib = "/opt/homebrew/opt/openssl/lib";

        // Check if generic path exists, otherwise fall back to versioned paths
        if (std.fs.accessAbsolute(generic_ssl_include, .{})) {
            exe.addIncludePath(.{ .cwd_relative = generic_ssl_include });
            exe.addLibraryPath(.{ .cwd_relative = generic_ssl_lib });
        } else |_| {
            // Try common OpenSSL 3.x paths
            const possible_paths = [_][]const u8{
                "/opt/homebrew/opt/openssl@3/include",
                "/opt/homebrew/opt/openssl@3.0/include",
                "/opt/homebrew/opt/openssl@3.1/include",
                "/opt/homebrew/opt/openssl@3.2/include",
                "/opt/homebrew/opt/openssl@3.3/include",
            };

            for (possible_paths) |include_path| {
                if (std.fs.accessAbsolute(include_path, .{})) {
                    exe.addIncludePath(.{ .cwd_relative = include_path });
                    // Derive lib path from include path
                    const lib_path = std.mem.concat(b.allocator, u8, &[_][]const u8{
                        include_path[0 .. include_path.len - 7], // Remove "include"
                        "lib",
                    }) catch continue;
                    defer b.allocator.free(lib_path);
                    exe.addLibraryPath(.{ .cwd_relative = lib_path });
                    break;
                } else |_| {
                    continue;
                }
            }
        }

        // exe.linkSystemLibrary("jemalloc");
    } else if (target.result.os.tag == .linux) {
        exe.addIncludePath(.{ .cwd_relative = "/usr/include/openssl" });
        exe.addIncludePath(.{ .cwd_relative = "/usr/include/libxml2" });
        exe.addLibraryPath(.{ .cwd_relative = "/usr/lib/x86_64-linux-gnu" });

        exe.linkSystemLibrary("jemalloc");
    }

    if (optimize == .ReleaseFast or optimize == .ReleaseSafe) {
        exe.root_module.addCMacro("OPENSSL_NO_DEPRECATED", "1");
        exe.root_module.addCMacro("OPENSSL_API_COMPAT", "0x30000000L");
    }

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the proxy");
    run_step.dependOn(&run_cmd.step);
}
