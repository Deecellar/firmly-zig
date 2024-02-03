const std = @import("std");

pub fn build(b: *std.Build) void {
    const build_examples: bool = b.option(bool, "build_examples", "Build the examples of the library") orelse true;
    const mod = b.addModule("firmly-zig", .{
        .root_source_file = .{ .path = "firmly-zig.zig" },
    });
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    const lib = b.addStaticLibrary(.{ .name = "firmly-zig", .root_source_file = .{ .path = "firmly-zig.zig" }, .optimize = mode, .target = target });
    lib.linkLibC();
    lib.linkSystemLibrary("firm");
    b.installArtifact(lib);

    if (build_examples) {
        const examples = b.addExecutable(.{ .name = "firmly-zig-brainfuck", .root_source_file = .{ .path = "example/bf_example.zig" }, .optimize = mode, .target = target });
        examples.root_module.addImport("firmly-zig", mod);
        examples.linkLibrary(lib);
        b.installArtifact(examples);
        b.installBinFile("example/test.bf", "test.bf");
        b.installBinFile("example/bf_runtime.zig", "bf_runtime.zig");
    }

    var main_tests = b.addTest(.{ .name = "firmly-zig-tests", .root_source_file = .{ .path = "firmly-zig.zig" }, .optimize = mode, .target = target });

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
