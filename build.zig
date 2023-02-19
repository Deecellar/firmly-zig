const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const build_examples : bool = b.option(bool,"build_examples", "Build the examples of the library") orelse true;
    b.addModule(.{
        .name = "firmly-zig",
        .source_file = .{ .path = "firmly-zig.zig" },
        .dependencies = &.{},
    });
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});
    
    const lib = b.addStaticLibrary(std.build.StaticLibraryOptions{.name = "firmly-zig", .root_source_file = .{.path = "firmly-zig.zig"}, .optimize = mode, .target = target });
    lib.linkLibC();
    lib.linkSystemLibrary("firm");  
    lib.install();

    if(build_examples) {
        const examples = b.addExecutable(std.build.ExecutableOptions{.name = "firmly-zig-brainfuck", .root_source_file = .{.path = "example/bf_example.zig"}, .optimize = mode, .target = target });
        const firmly_zig_module = std.build.CreateModuleOptions{.source_file = .{.path = "firmly-zig.zig"}};
        examples.addAnonymousModule("firmly-zig", firmly_zig_module );
        examples.linkLibrary(lib);
        examples.install();
        b.installBinFile("example/test.bf", "test.bf");
        b.installBinFile("example/bf_runtime.zig", "bf_runtime.zig");
    }

        var main_tests = b.addTest(std.build.TestOptions{.name = "firmly-zig-tests", .root_source_file = .{.path = "firmly-zig.zig"}, .optimize = mode, .target = target });

        const test_step = b.step("test", "Run library tests");
        test_step.dependOn(&main_tests.step);
}
