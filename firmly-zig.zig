pub const low_level = @import("src/firm-abi.zig");

test {
    @import("std").testing.refAllDecls(@This());
}