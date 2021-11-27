const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const build_examples : bool = b.option(bool,"build_examples", "Build the examples of the library") orelse true;

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("firmly-zig", "firmly-zig.zig");
    lib.setBuildMode(mode);
    lib.linkLibC();
    lib.linkSystemLibrary("firm");
    lib.install();

    if(build_examples) {
        const examples = b.addExecutable("firmly-zig-brainfuck-low-level", "example/bf_example.zig");
        examples.setBuildMode(mode);
        examples.addPackagePath("firmly-zig", "firmly-zig.zig");
        examples.linkLibrary(lib);
        examples.install();
        const examples_codegen = b.addExecutable("firmly-zig-brainfuck-codegen", "example/bf_codegen_example.zig");
        examples_codegen.setBuildMode(mode);
        examples_codegen.addPackagePath("firmly-zig", "firmly-zig.zig");
        examples.linkLibrary(lib);
        examples_codegen.install();
    }

    var main_tests = b.addTest("src/main.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
