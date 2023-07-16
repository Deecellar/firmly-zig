const std = @import("std");

export fn putchar(c: u8) callconv(.C) void {
    std.io.getStdOut().writer().writeByte(c) catch unreachable;
    return;
}

export fn getchar() callconv(.C) u8 {
    return std.io.getStdIn().reader().readByte() catch return 0;
}

extern fn bf_main() callconv(.C) u8;

pub fn main() !void {
    _ = bf_main();
}
