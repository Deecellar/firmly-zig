pub const low_level = @import("src/firm-abi.zig");
pub const codegen = @import("src/codegen.zig").codegen;

test {
    @import("std").testing.refAllDecls(@This());
}