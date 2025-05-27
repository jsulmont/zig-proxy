// build.zig - add libuv
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
        exe.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
        exe.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        exe.addIncludePath(.{ .cwd_relative = "/opt/homebrew/Cellar/openssl@3/3.5.0/include" });
        exe.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/Cellar/openssl@3/3.5.0/lib" });
        exe.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include/libxml2" });

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
