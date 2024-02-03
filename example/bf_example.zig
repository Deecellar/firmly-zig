const std = @import("std");
const firm = @import("firmly-zig").low_level;
const mainLocalVars = 1; // main function has 1 local variable
const dataSize = 30000; // A 30000 byte of storage for brainfuck
const variablePointer = 0; // The pointer to the current position in the data
var typeBu: ?*firm.ir_type = null;
var putchar: ?*firm.ir_node = null;
var getchar: ?*firm.ir_node = null;
var putcharEntity: ?*firm.ir_entity = null;
var getcharEntity: ?*firm.ir_entity = null;

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

fn increasePointer() void {
    const pointerValue = firm.getValue(variablePointer, firm.getMode(.P));

    const offsetMode = firm.getReferenceOffsetMode(firm.getMode(.P));
    const tarval = firm.newTarvalFromLong(1, offsetMode);
    const one = firm.newConst(tarval);

    const add = firm.newAdd(pointerValue, one);

    firm.setValue(variablePointer, add);
}

fn decreasePointer() void {
    const pointerValue = firm.getValue(variablePointer, firm.getMode(.P));

    const offsetMode = firm.getReferenceOffsetMode(firm.getMode(.P));
    const tarval = firm.newTarvalFromLong(1, offsetMode);
    const one = firm.newConst(tarval);

    const sub = firm.newSub(pointerValue, one);
    firm.setValue(variablePointer, sub);
}

fn incrementByte() void {
    const pointerValue = firm.getValue(variablePointer, firm.getMode(.P));

    const mem = firm.getStore();
    const load = firm.newLoad(mem, pointerValue, firm.getMode(.Bu), typeBu, firm.ir_cons_flags.cons_none);

    const loadResult = firm.newProj(load, firm.getMode(.Bu), @intFromEnum(firm.projection_input_Load.res));
    const loadMem = firm.newProj(load, firm.getMode(.M), @intFromEnum(firm.projection_input_Load.M));

    const tarval = firm.newTarvalFromLong(1, firm.getMode(.Bu));
    const one = firm.newConst(tarval);

    const add = firm.newAdd(loadResult, one);

    const store = firm.newStore(loadMem, pointerValue, add, typeBu, firm.ir_cons_flags.cons_none);
    const storeMem = firm.newProj(store, firm.getMode(.M), @intFromEnum(firm.projection_input_Store.M));

    firm.setStore(storeMem);
}

fn decrementByte() void {
    const pointerValue = firm.getValue(variablePointer, firm.getMode(.P));

    const mem = firm.getStore();
    const load = firm.newLoad(mem, pointerValue, firm.getMode(.Bu), typeBu, firm.ir_cons_flags.cons_none);

    const loadResult = firm.newProj(load, firm.getMode(.Bu), @intFromEnum(firm.projection_input_Load.res));
    const loadMem = firm.newProj(load, firm.getMode(.M), @intFromEnum(firm.projection_input_Load.M));

    const tarval = firm.newTarvalFromLong(1, firm.getMode(.Bu));
    const one = firm.newConst(tarval);

    const sub = firm.newSub(loadResult, one);

    const store = firm.newStore(loadMem, pointerValue, sub, typeBu, firm.ir_cons_flags.cons_none);
    const storeMem = firm.newProj(store, firm.getMode(.M), @intFromEnum(firm.projection_input_Store.M));

    firm.setStore(storeMem);
}

fn outputByte() void {
    if (putchar == null) {
        putcharEntity = createPutCharEntity();
        putchar = firm.newAddress(putcharEntity);
    }

    const pointerValue = firm.getValue(variablePointer, firm.getMode(.P));
    const mem = firm.getStore();

    const load = firm.newLoad(mem, pointerValue, firm.getMode(.Bu), typeBu, firm.ir_cons_flags.cons_none);
    const loadResult = firm.newProj(load, firm.getMode(.Bu), @intFromEnum(firm.projection_input_Load.res));

    const convert = firm.newConv(loadResult, firm.getMode(.Is));
    const in: [1]?*firm.ir_node = .{convert};
    const cType = firm.getEntityType(putcharEntity);
    const call = firm.newCall(mem, putchar, 1, &in, cType);

    const callMem = firm.newProj(call, firm.getMode(.M), @intFromEnum(firm.projection_input_Call.M));

    firm.setStore(callMem);
}

fn inputByte() void {
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

    const pointerValue = firm.getValue(variablePointer, firm.getMode(.P));
    const convert = firm.newConv(callResult, firm.getMode(.Is));

    const store = firm.newStore(callMem, pointerValue, convert, typeBu, firm.ir_cons_flags.cons_none);
    const storeMem = firm.newProj(store, firm.getMode(.M), @intFromEnum(firm.projection_input_Store.M));

    firm.setStore(storeMem);
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

fn parse(file: std.fs.File) !void {
    var buffer: [128 * 1024]u8 = undefined;
    var frameBuffers: [256]LoopFrame = undefined;
    var reader = file.reader();
    var size: usize = 1;
    var loop: usize = 0;

    while (size != 0) {
        size = try reader.read(&buffer);
        if (size > 0) {
            for (buffer[0..size]) |v| {
                // We interpret brainfuck as a sequence of commands.
                switch (v) {
                    '>' => increasePointer(),
                    '<' => decreasePointer(),
                    '+' => incrementByte(),
                    '-' => decrementByte(),
                    '.' => outputByte(),
                    ',' => inputByte(),
                    '[' => {
                        loop += 1;
                        frameBuffers[loop - 1] = parseLoopProlog();
                    },
                    ']' => {
                        var current_frame = frameBuffers[loop - 1];
                        parseLoopEpilogue(&current_frame);
                        if (blk: {
                            const res = @subWithOverflow(
                                loop,
                                1,
                            );
                            loop = res[0];
                            break :blk res[1] == 1;
                        }) {
                            std.log.err("parse error: unexpected '['\n", .{});
                            return;
                        }
                    },
                    else => {},
                }
            }
        }
    }
    if (loop > 0) {
        std.log.err("parse error: unmatched '['\n", .{});
    }
}

/// This is a port of https://github.com/libfirm/firm-bf/blob/master/main.c using firmly-zig low level API
pub fn main() !void {
    initializeFirm();
    const graph = createGraph();
    firm.setCurrentIrGraph(graph);

    typeBu = firm.getTypeForMode(firm.getMode(.Bu));

    const field = createField();
    const fieldStart = firm.newAddress(field);
    firm.setValue(variablePointer, fieldStart);
    var file: std.fs.File = try std.fs.cwd().openFile("test.bf", std.fs.File.OpenFlags{});
    try parse(file);
    file.close();
    createReturn();

    firm.irgFinalizeCons(graph);
    firm.irgAssertVerify(graph);

    firm.doLoopInversion(graph);
    firm.optimizeReassociation(graph);
    firm.optimizeLoadStore(graph);
    firm.optimizeGraphDf(graph);
    firm.combo(graph);
    firm.scalarReplacementOpt(graph);
    firm.placeCode(graph);
    firm.optimizeReassociation(graph);
    firm.optimizeGraphDf(graph);
    firm.optJumpthreading(graph);
    firm.optimizeGraphDf(graph);
    firm.constructConfirms(graph);
    firm.optimizeGraphDf(graph);
    firm.removeConfirms(graph);
    firm.optimizeCf(graph);
    firm.optimizeLoadStore(graph);
    firm.optimizeGraphDf(graph);
    firm.combo(graph);
    firm.placeCode(graph);
    firm.optimizeCf(graph);

    const out = std.c.fopen("test.s", "w");
    if (out == null) {
        std.log.err("could not open output file\n", .{});
        return;
    }
    if (out) |o| {
        firm.beMain(o, "");
        _ = std.c.fclose(o);
    }
}
