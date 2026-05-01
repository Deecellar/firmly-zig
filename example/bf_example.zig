const std = @import("std");
const firm = @import("firmly-zig").low_level;
const mainLocalVars = 1; // main function has 1 local variable
const dataSize = 1000000; // A 1MB of storage for brainfuck
const variablePointer = 0; // The pointer to the current position in the data
var typeBu: ?*firm.ir_type = null;
var putchar: ?*firm.ir_node = null;
var getchar: ?*firm.ir_node = null;
var putcharEntity: ?*firm.ir_entity = null;
var getcharEntity: ?*firm.ir_entity = null;
var scanForwardEntity: ?*firm.ir_entity = null;
var scanBackwardEntity: ?*firm.ir_entity = null;

fn initializeFirm() void {
    firm.irInit();
}

fn createGraph() ?*firm.ir_graph {
    const methodType: ?*firm.ir_type = firm.newTypeMethod(0, 1, false, .{ .calling_convention_special = firm.calling_convention_enum.calling_helpers.decl_set }, firm.mtp_additional_properties.no_property);
    const intType: ?*firm.ir_type = firm.newTypePrimitive(firm.getMode(.Is));
    firm.setMethodResType(methodType, 0, intType);

    const id = firm.irPlatformMangleGlobal("bf_main");
    const globalType = firm.getGlobType();
    const entity = firm.newEntity(globalType, id, methodType);

    const irGraph = firm.newIrGraph(entity, mainLocalVars);

    firm.setEntityIdent(entity, id);
    return irGraph;
}

fn createField() ?*firm.ir_entity {
    const byteType = firm.newTypePrimitive(firm.getMode(.Bu));

    const arrayType = firm.newTypeArray(byteType, dataSize);

    const id = firm.irPlatformMangleGlobal("data");
    const globalType = firm.getGlobType();
    const entity = firm.newEntity(globalType, id, arrayType);

    const nullInitializer = firm.getInitializerNull();
    firm.setEntityInitializer(entity, nullInitializer);

    firm.setEntityVisibility(entity, firm.ir_visibility.private);
    return entity;
}

fn createPutCharEntity() ?*firm.ir_entity {
    const typeInt = firm.newTypePrimitive(firm.getMode(.Is));

    const methodType = firm.newTypeMethod(1, 1, false, .{ .calling_convention_special = firm.calling_convention_enum.calling_helpers.decl_set }, firm.mtp_additional_properties.no_property);

    firm.setMethodResType(methodType, 0, typeInt);
    firm.setMethodParamType(methodType, 0, typeInt);

    const id = firm.irPlatformMangleGlobal("putchar");
    const globalType = firm.getGlobType();
    const entity = firm.newEntity(globalType, id, methodType);
    firm.setEntityIdent(entity, id);

    return entity;
}

fn createGetCharEntity() ?*firm.ir_entity {
    const typeInt = firm.newTypePrimitive(firm.getMode(.Is));

    const methodType = firm.newTypeMethod(0, 1, false, .{ .calling_convention_special = firm.calling_convention_enum.calling_helpers.decl_set }, firm.mtp_additional_properties.no_property);

    firm.setMethodResType(methodType, 0, typeInt);

    const id = firm.irPlatformMangleGlobal("getchar");
    const globalType = firm.getGlobType();
    const entity = firm.newEntity(globalType, id, methodType);
    firm.setEntityIdent(entity, id);

    return entity;
}

fn getScanForwardEntity() ?*firm.ir_entity {
    if (scanForwardEntity == null) {
        const typePtr = firm.newTypePrimitive(firm.getMode(.P));
        const methodType = firm.newTypeMethod(1, 1, false, .{ .calling_convention_special = firm.calling_convention_enum.calling_helpers.decl_set }, firm.mtp_additional_properties.no_property);
        firm.setMethodParamType(methodType, 0, typePtr);
        firm.setMethodResType(methodType, 0, typePtr);

        const id = firm.irPlatformMangleGlobal("bf_scan_forward");
        scanForwardEntity = firm.newEntity(firm.getGlobType(), id, methodType);
    }
    return scanForwardEntity;
}

fn getScanBackwardEntity() ?*firm.ir_entity {
    if (scanBackwardEntity == null) {
        const typePtr = firm.newTypePrimitive(firm.getMode(.P));
        const methodType = firm.newTypeMethod(1, 1, false, .{ .calling_convention_special = firm.calling_convention_enum.calling_helpers.decl_set }, firm.mtp_additional_properties.no_property);
        firm.setMethodParamType(methodType, 0, typePtr);
        firm.setMethodResType(methodType, 0, typePtr);

        const id = firm.irPlatformMangleGlobal("bf_scan_backward");
        scanBackwardEntity = firm.newEntity(firm.getGlobType(), id, methodType);
    }
    return scanBackwardEntity;
}

fn modifyPointer(amount: i32) void {
    if (amount == 0) return;
    const pointerValue = firm.getValue(variablePointer, firm.getMode(.P));
    const offsetMode = firm.getReferenceOffsetMode(firm.getMode(.P));
    const tarval = firm.newTarvalFromLong(@intCast(@abs(amount)), offsetMode);
    const amountNode = firm.newConst(tarval);

    const newNode = if (amount > 0)
        firm.newAdd(pointerValue, amountNode)
    else
        firm.newSub(pointerValue, amountNode);

    firm.setValue(variablePointer, newNode);
}

fn getEffectiveAddress(offset: i32) ?*firm.ir_node {
    const pointerValue = firm.getValue(variablePointer, firm.getMode(.P));
    if (offset == 0) return pointerValue;

    const offsetMode = firm.getReferenceOffsetMode(firm.getMode(.P));
    const tarval = firm.newTarvalFromLong(@intCast(@abs(offset)), offsetMode);
    const offsetNode = firm.newConst(tarval);

    return if (offset > 0)
        firm.newAdd(pointerValue, offsetNode)
    else
        firm.newSub(pointerValue, offsetNode);
}

fn modifyByte(amount: i32, offset: i32) void {
    if (amount == 0) return;
    const address = getEffectiveAddress(offset);
    const mem = firm.getStore();
    const load = firm.newLoad(mem, address, firm.getMode(.Bu), typeBu, firm.ir_cons_flags.cons_none);

    const loadResult = firm.newProj(load, firm.getMode(.Bu), @intFromEnum(firm.projection_input_Load.res));
    const loadMem = firm.newProj(load, firm.getMode(.M), @intFromEnum(firm.projection_input_Load.M));

    const tarval = firm.newTarvalFromLong(@intCast(@abs(amount)), firm.getMode(.Bu));
    const amountNode = firm.newConst(tarval);

    const newNode = if (amount > 0)
        firm.newAdd(loadResult, amountNode)
    else
        firm.newSub(loadResult, amountNode);

    const store = firm.newStore(loadMem, address, newNode, typeBu, firm.ir_cons_flags.cons_none);
    const storeMem = firm.newProj(store, firm.getMode(.M), @intFromEnum(firm.projection_input_Store.M));

    firm.setStore(storeMem);
}

fn setByte(value: u8, offset: i32) void {
    const address = getEffectiveAddress(offset);
    const mem = firm.getStore();
    const tarval = firm.newTarvalFromLong(value, firm.getMode(.Bu));
    const valueNode = firm.newConst(tarval);

    const store = firm.newStore(mem, address, valueNode, typeBu, firm.ir_cons_flags.cons_none);
    const storeMem = firm.newProj(store, firm.getMode(.M), @intFromEnum(firm.projection_input_Store.M));

    firm.setStore(storeMem);
}

fn outputByte(offset: i32) void {
    if (putchar == null) {
        putcharEntity = createPutCharEntity();
        putchar = firm.newAddress(putcharEntity);
    }

    const address = getEffectiveAddress(offset);
    const mem = firm.getStore();

    const load = firm.newLoad(mem, address, firm.getMode(.Bu), typeBu, firm.ir_cons_flags.cons_none);
    const loadResult = firm.newProj(load, firm.getMode(.Bu), @intFromEnum(firm.projection_input_Load.res));

    const convert = firm.newConv(loadResult, firm.getMode(.Is));
    const in: [1]?*firm.ir_node = .{convert};
    const cType = firm.getEntityType(putcharEntity);
    const call = firm.newCall(mem, putchar, 1, &in, cType);

    const callMem = firm.newProj(call, firm.getMode(.M), @intFromEnum(firm.projection_input_Call.M));

    firm.setStore(callMem);
}

fn inputByte(offset: i32) void {
    if (getchar == null) {
        getcharEntity = createGetCharEntity();
        getchar = firm.newAddress(getcharEntity);
    }

    const mem = firm.getStore();

    const ctype = firm.getEntityType(getcharEntity);
    const call = firm.newCall(mem, getchar, 0, null, ctype);

    const callMem = firm.newProj(call, firm.getMode(.M), @intFromEnum(firm.projection_input_Call.M));

    const callResults = firm.newProj(call, firm.getMode(.T), @intFromEnum(firm.projection_input_Call.T_result));
    const callResult = firm.newProj(callResults, firm.getMode(.Is), 0);

    const address = getEffectiveAddress(offset);
    const convert = firm.newConv(callResult, firm.getMode(.Bu));

    const store = firm.newStore(callMem, address, convert, typeBu, firm.ir_cons_flags.cons_none);
    const storeMem = firm.newProj(store, firm.getMode(.M), @intFromEnum(firm.projection_input_Store.M));

    firm.setStore(storeMem);
}

fn multiplyAdd(src_offset: i32, dest_offset: i32, multiplier: i32) void {
    if (multiplier == 0) return;
    const src_address = getEffectiveAddress(src_offset);
    const dest_address = getEffectiveAddress(dest_offset);
    const mem = firm.getStore();

    const load_src = firm.newLoad(mem, src_address, firm.getMode(.Bu), typeBu, firm.ir_cons_flags.cons_none);
    const src_val = firm.newProj(load_src, firm.getMode(.Bu), @intFromEnum(firm.projection_input_Load.res));
    const src_mem = firm.newProj(load_src, firm.getMode(.M), @intFromEnum(firm.projection_input_Load.M));

    const load_dest = firm.newLoad(src_mem, dest_address, firm.getMode(.Bu), typeBu, firm.ir_cons_flags.cons_none);
    const dest_val = firm.newProj(load_dest, firm.getMode(.Bu), @intFromEnum(firm.projection_input_Load.res));
    const dest_mem = firm.newProj(load_dest, firm.getMode(.M), @intFromEnum(firm.projection_input_Load.M));

    const mult_tarval = firm.newTarvalFromLong(@intCast(@abs(multiplier)), firm.getMode(.Bu));
    const mult_node = firm.newConst(mult_tarval);

    const prod = firm.newMul(src_val, mult_node);
    const result = if (multiplier > 0)
        firm.newAdd(dest_val, prod)
    else
        firm.newSub(dest_val, prod);

    const store = firm.newStore(dest_mem, dest_address, result, typeBu, firm.ir_cons_flags.cons_none);
    const store_mem = firm.newProj(store, firm.getMode(.M), @intFromEnum(firm.projection_input_Store.M));

    firm.setStore(store_mem);
}

fn scanLoop(step: i32, offset: i32) void {
    modifyPointer(offset);
    const pointerValue = firm.getValue(variablePointer, firm.getMode(.P));
    const mem = firm.getStore();

    const entity = if (step > 0) getScanForwardEntity() else getScanBackwardEntity();
    const func_addr = firm.newAddress(entity);
    const cType = firm.getEntityType(entity);
    
    const in: [1]?*firm.ir_node = .{pointerValue};
    const call = firm.newCall(mem, func_addr, 1, &in, cType);
    
    const callMem = firm.newProj(call, firm.getMode(.M), @intFromEnum(firm.projection_input_Call.M));
    const callResults = firm.newProj(call, firm.getMode(.T), @intFromEnum(firm.projection_input_Call.T_result));
    const callResult = firm.newProj(callResults, firm.getMode(.P), 0);

    firm.setStore(callMem);
    firm.setValue(variablePointer, callResult);
}

fn createReturn() void {
    const mem = firm.getStore();
    var zero = firm.newConst(firm.newTarvalFromLong(0, firm.getMode(.Is)));
    const returnNode = firm.newReturn(mem, 1, &zero);

    const endBlock = firm.getIrgEndBlock(firm.current_ir_graph);
    firm.addImmblockPred(endBlock, returnNode);

    firm.matureImmblock(firm.getCurBlock());

    firm.setCurBlock(null);
}

const LoopFrame = struct {
    jmp: ?*firm.ir_node,
    loopHeaderBlock: ?*firm.ir_node,
    trueProj: ?*firm.ir_node,
};

fn parseLoopProlog() LoopFrame {
    const jmp = firm.newJmp();
    firm.matureImmblock(firm.getCurBlock());
    const loopHeaderBlock = firm.newImmblock();
    firm.addImmblockPred(loopHeaderBlock, jmp);
    firm.setCurBlock(loopHeaderBlock);

    const pointerValue = firm.getValue(variablePointer, firm.getMode(.P));
    const mem = firm.getStore();
    const load = firm.newLoad(mem, pointerValue, firm.getMode(.Bu), typeBu, firm.ir_cons_flags.cons_none);
    const loadResult = firm.newProj(load, firm.getMode(.Bu), @intFromEnum(firm.projection_input_Load.res));
    const loadMem = firm.newProj(load, firm.getMode(.M), @intFromEnum(firm.projection_input_Load.M));

    firm.setStore(loadMem);

    const zero = firm.newConst(firm.newTarvalFromLong(0, firm.getMode(.Bu)));

    const equal = firm.newCmp(loadResult, zero, firm.ir_relation.equal);
    const cond = firm.newCond(equal);
    const trueProj = firm.newProj(cond, firm.getMode(.X), @intFromEnum(firm.projection_input_Cond.True));
    const falseProj = firm.newProj(cond, firm.getMode(.X), @intFromEnum(firm.projection_input_Cond.False));

    const loopBodyBlock = firm.newImmblock();
    firm.addImmblockPred(loopBodyBlock, falseProj);
    firm.setCurBlock(loopBodyBlock);

    return LoopFrame{ .jmp = jmp, .loopHeaderBlock = loopHeaderBlock, .trueProj = trueProj };
}

fn parseLoopEpilogue(frame: *LoopFrame) void {
    const jmp = firm.newJmp();
    firm.addImmblockPred(frame.loopHeaderBlock, jmp);
    firm.matureImmblock(frame.loopHeaderBlock);
    firm.matureImmblock(firm.getCurBlock());

    const afterLoop = firm.newImmblock();
    firm.addImmblockPred(afterLoop, frame.trueProj);
    firm.setCurBlock(afterLoop);
}

const Parser = struct {
    buffer: []const u8,
    pos: usize = 0,
    offset: i32 = 0,
    io: std.Io,
    allocator: std.mem.Allocator,
    has_mutated: bool = false,
    pending_changes: std.AutoArrayHashMapUnmanaged(i32, i32) = .{},

    fn peek(self: *const Parser) ?u8 {
        if (self.pos >= self.buffer.len) return null;
        return self.buffer[self.pos];
    }

    fn peekAt(self: *const Parser, delta: usize) ?u8 {
        if (self.pos + delta >= self.buffer.len) return null;
        return self.buffer[self.pos + delta];
    }

    fn advance(self: *Parser) void {
        self.pos += 1;
    }

    fn flushChanges(self: *Parser) !void {
        var it = self.pending_changes.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* != 0) {
                modifyByte(entry.value_ptr.*, entry.key_ptr.*);
            }
        }
        self.pending_changes.clearRetainingCapacity();
    }

    fn commitOffset(self: *Parser) void {
        if (self.offset != 0) {
            modifyPointer(self.offset);
            self.offset = 0;
        }
    }

    fn parseBlock(self: *Parser) !void {
        while (self.peek()) |c| {
            switch (c) {
                '>', '<' => {
                    var delta: i32 = 0;
                    while (self.peek()) |cc| {
                        if (cc == '>') delta += 1
                        else if (cc == '<') delta -= 1
                        else if (cc == '+' or cc == '-' or cc == '.' or cc == ',' or cc == '[' or cc == ']') break;
                        self.advance();
                    }
                    self.offset += delta;
                },
                '+', '-' => {
                    self.has_mutated = true;
                    var delta: i32 = 0;
                    while (self.peek()) |cc| {
                        if (cc == '+') delta += 1
                        else if (cc == '-') delta -= 1
                        else if (cc == '>' or cc == '<' or cc == '.' or cc == ',' or cc == '[' or cc == ']') break;
                        self.advance();
                    }
                    const entry = try self.pending_changes.getOrPut(self.allocator, self.offset);
                    if (!entry.found_existing) entry.value_ptr.* = 0;
                    entry.value_ptr.* += delta;
                },
                '.' => {
                    try self.flushChanges();
                    outputByte(self.offset);
                    self.advance();
                },
                ',' => {
                    self.has_mutated = true;
                    try self.flushChanges();
                    inputByte(self.offset);
                    self.advance();
                },
                '[' => {
                    // Leading dead code elimination
                    if (!self.has_mutated) {
                        var depth: usize = 1;
                        self.advance();
                        while (depth > 0) {
                            const cc = self.peek() orelse break;
                            if (cc == '[') depth += 1
                            else if (cc == ']') depth -= 1;
                            self.advance();
                        }
                        continue;
                    }

                    // Try to match scan loop: [>] or [<]
                    if ((self.peekAt(1) == '>' or self.peekAt(1) == '<') and self.peekAt(2) == ']') {
                        try self.flushChanges();
                        const step: i32 = if (self.peekAt(1) == '>') 1 else -1;
                        scanLoop(step, self.offset);
                        self.pos += 3;
                        continue;
                    }

                    // Try to match move/add loop
                    {
                        var i: usize = 1;
                        var valid = true;
                        var balanced_move: i32 = 0;
                        var changes = std.AutoArrayHashMapUnmanaged(i32, i32){};
                        defer changes.deinit(self.allocator);

                        while (self.peekAt(i)) |cc| {
                            if (cc == ']') break;
                            if (cc == '>') balanced_move += 1
                            else if (cc == '<') balanced_move -= 1
                            else if (cc == '+') {
                                const entry = try changes.getOrPut(self.allocator, balanced_move);
                                if (!entry.found_existing) entry.value_ptr.* = 0;
                                entry.value_ptr.* += 1;
                            } else if (cc == '-') {
                                const entry = try changes.getOrPut(self.allocator, balanced_move);
                                if (!entry.found_existing) entry.value_ptr.* = 0;
                                entry.value_ptr.* -= 1;
                            } else if (cc == '.' or cc == ',' or cc == '[') {
                                valid = false;
                                break;
                            }
                            i += 1;
                        }
                        
                        const net_origin_change = if (changes.getPtr(0)) |ptr| ptr.* else 0;
                        
                        if (valid and balanced_move == 0 and net_origin_change == -1 and self.peekAt(i) == ']') {
                            try self.flushChanges();
                            var it = changes.iterator();
                            while (it.next()) |entry| {
                                if (entry.key_ptr.* == 0) continue;
                                multiplyAdd(self.offset, self.offset + entry.key_ptr.*, entry.value_ptr.*);
                            }
                            setByte(0, self.offset);
                            self.pos = self.pos + i + 1;
                            continue;
                        }
                    }

                    // Try to match clear loop: [-] or [+]
                    if ((self.peekAt(1) == '-' or self.peekAt(1) == '+') and self.peekAt(2) == ']') {
                        try self.flushChanges();
                        setByte(0, self.offset);
                        self.pos += 3;
                        continue;
                    }

                    // Standard loop
                    try self.flushChanges();
                    self.commitOffset();
                    var frame = parseLoopProlog();
                    self.advance();
                    try self.parseBlock();
                    if (self.peek() != ']') {
                        std.log.err("parse error: unmatched '[' at pos {d}", .{self.pos});
                        return error.UnmatchedBracket;
                    }
                    try self.flushChanges();
                    self.commitOffset();
                    parseLoopEpilogue(&frame);
                    self.advance();
                },
                ']' => {
                    try self.flushChanges();
                    return;
                },
                else => {
                    // Ignore comments
                    self.advance();
                }
            }
        }
    }
};

fn parse(io: std.Io, allocator: std.mem.Allocator, content: []const u8) !void {
    var p = Parser{
        .buffer = content,
        .io = io,
        .allocator = allocator,
    };
    defer p.pending_changes.deinit(allocator);
    try p.parseBlock();
    try p.flushChanges();
    p.commitOffset();
    if (p.pos < p.buffer.len) {
        std.log.err("parse error: unexpected ']' at pos {d}", .{p.pos});
        return error.UnexpectedClosingBracket;
    }
}

/// This is a port of https://github.com/libfirm/firm-bf/blob/master/main.c using firmly-zig low level API / I have modified some of it to further some opt.

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) {
        std.log.err("usage: {s} <source.bf> [output.s]", .{args[0]});
        std.process.exit(1);
    }
    const source_path = args[1];
    const output_path = if (args.len > 2) args[2] else "test.s";

    initializeFirm();
    const graph = createGraph();
    firm.setCurrentIrGraph(graph);

    typeBu = firm.getTypeForMode(firm.getMode(.Bu));

    const field = createField();
    const fieldStart = firm.newAddress(field);
    firm.setValue(variablePointer, fieldStart);
    
    var file = try std.Io.Dir.cwd().openFile(io, source_path, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    var r = file.reader(io, &.{ });
    const content = try r.interface.allocRemaining(arena, .unlimited);
    _ = stat;

    defer arena.free(content);

    try parse(io, arena, content);
    createReturn();


firm.irgFinalizeCons(graph);
firm.irgAssertVerify(graph);
firm.doLoopInversion(graph);

var j: usize = 0;
while (j < 10) : (j += 1) {
    firm.optimizeGraphDf(graph);
    firm.optimizeReassociation(graph);
    firm.scalarReplacementOpt(graph);
    firm.optimizeLoadStore(graph);
    firm.convOpt(graph);
    firm.combo(graph);
    firm.optJumpthreading(graph);

    firm.placeCode(graph);

    firm.constructConfirms(graph);
    firm.optimizeGraphDf(graph);
    firm.removeConfirms(graph);
    firm.optimizeCf(graph);

    firm.removeUnreachableCode(graph);
    firm.deadNodeElimination(graph);
}

firm.constructCfBackedges(graph);
firm.assureLoopinfo(graph);

firm.unrollLoops(graph, 16, 256); 

firm.optimizeGraphDf(graph);
firm.combo(graph);
firm.optimizeCf(graph);
firm.removeUnreachableCode(graph);

firm.placeCode(graph);
    const out_path_z = try arena.dupeZ(u8, output_path);
    defer arena.free(out_path_z);

    const out = std.c.fopen(out_path_z, "w");
    if (out == null) {
        std.log.err("could not open output file: {s}\n", .{output_path});
        return;
    }
    if (out) |o| {
        firm.beMain(o, "");
        _ = std.c.fclose(o);
    }
}
