const std = @import("std");
const builtin = @import("builtin");

var global_io: std.Io = undefined;
var stdout_buffer: [8192]u8 = undefined;
var stdout_writer: std.Io.File.Writer = undefined;

export fn putchar(c: u8) void {
    stdout_writer.interface.writeByte(c) catch unreachable;
    if (c == '\n') {
        stdout_writer.interface.flush() catch unreachable;
    }
}

export fn getchar() u8 {
    const stdin = std.Io.File.stdin();
    var buf: [1]u8 = undefined;
    var r = stdin.reader(global_io, &buf);
    return r.interface.takeByte() catch return 0;
}

export fn bf_scan_forward(ptr: [*]u8) [*]u8 {
    if (builtin.cpu.arch == .x86_64) {
        return asm volatile (
            \\cld
            \\repne scasb
            \\dec %%rdi
            : [res] "={rdi}" (-> [*]u8),
            : [ptr] "{rdi}" (ptr),
              [zero] "{al}" (@as(u8, 0)),
              [count] "{rcx}" (@as(usize, 0xFFFFFFFFFFFFFFFF)),
            : .{ .rcx = true, .memory = true, .cc = true }
        );
    } else {
        var p = ptr;
        while (p[0] != 0) : (p += 1) {}
        return p;
    }
}

export fn bf_scan_backward(ptr: [*]u8) [*]u8 {
    if (builtin.cpu.arch == .x86_64) {
        return asm volatile (
            \\std
            \\repne scasb
            \\inc %%rdi
            \\cld
            : [res] "={rdi}" (-> [*]u8),
            : [ptr] "{rdi}" (ptr),
              [zero] "{al}" (@as(u8, 0)),
              [count] "{rcx}" (@as(usize, 0xFFFFFFFFFFFFFFFF)),
            : .{ .rcx = true, .memory = true, .cc = true }
        );
    } else {
        var p = ptr;
        while (p[0] != 0) : (p -= 1) {}
        return p;
    }
}

extern fn bf_main() i32;

pub fn main(init: std.process.Init) !void {
    global_io = init.io;
    stdout_writer = std.Io.File.stdout().writer(global_io, &stdout_buffer);
    
    _ = bf_main();
    
    stdout_writer.interface.flush() catch unreachable;
}
