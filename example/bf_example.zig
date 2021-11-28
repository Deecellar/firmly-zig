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
    var methodType : ?*firm.ir_type = firm.newTypeMethod(0, 1, false, .{.calling_convention_special = firm.calling_convention_enum.calling_helpers.decl_set}, firm.mtp_additional_properties.no_property);
    var intType : ?*firm.ir_type= firm.newTypePrimitive(firm.mode_Is);
    firm.setMethodResType(methodType, 0, intType);

    var id = firm.irPlatformMangleGlobal("bf_main");
    var globalType = firm.getGlobType();
    var entity = firm.newEntity(globalType, id, methodType);

    var irGraph = firm.newIrGraph(entity, mainLocalVars);

    firm.setEntityIdent(entity, id);
    return irGraph;
}

fn createField() ?*firm.ir_entity {
    var byteType = firm.newTypePrimitive(firm.mode_Bu);

    var arrayType = firm.newTypeArray(byteType, dataSize);

    var id = firm.irPlatformMangleGlobal("data");
    var globalType = firm.getGlobType();
    var entity = firm.newEntity(globalType, id, arrayType);

    var nullInitializer = firm.getInitializerNull();
    firm.setEntityInitializer(entity, nullInitializer);

    firm.setEntityVisibility(entity, firm.ir_visibility.private);
    return entity;
}

fn createPutCharEntity() ?*firm.ir_entity {
    var typeInt = firm.newTypePrimitive(firm.mode_Is);

    var methodType = firm.newTypeMethod(1, 1, false, .{.calling_convention_special = firm.calling_convention_enum.calling_helpers.decl_set}, firm.mtp_additional_properties.no_property);

    firm.setMethodResType(methodType, 0, typeInt);
    firm.setMethodParamType(methodType, 0, typeInt);

    var id = firm.irPlatformMangleGlobal("putchar");
    var globalType = firm.getGlobType();
    var entity = firm.newEntity(globalType, id, methodType);
    firm.setEntityIdent(entity, id);

    return entity;
}

fn createGetCharEntity() ?*firm.ir_entity {
    var typeInt = firm.newTypePrimitive(firm.mode_Is);

    var methodType = firm.newTypeMethod(0, 1, false, .{.calling_convention_special = firm.calling_convention_enum.calling_helpers.decl_set}, firm.mtp_additional_properties.no_property);

    firm.setMethodResType(methodType, 0, typeInt);

    var id = firm.irPlatformMangleGlobal("getchar");
    var globalType = firm.getGlobType();
    var entity = firm.newEntity(globalType, id, methodType);
    firm.setEntityIdent(entity, id);

    return entity;
}

fn increasePointer() void {
    var pointerValue = firm.getValue(variablePointer, firm.mode_P);

    var offsetMode = firm.getReferenceOffsetMode(firm.mode_P);
    var tarval = firm.newTarvalFromLong(1, offsetMode);
    var one = firm.newConst(tarval);

    var add = firm.newAdd(pointerValue, one);

    firm.setValue(variablePointer, add);
}

fn decreasePointer() void {
    var pointerValue = firm.getValue(variablePointer, firm.mode_P);

    var offsetMode = firm.getReferenceOffsetMode(firm.mode_P);
    var tarval = firm.newTarvalFromLong(1, offsetMode);
    var one = firm.newConst(tarval);

    var sub = firm.newSub(pointerValue, one);
    firm.setValue(variablePointer, sub);
}

fn incrementByte() void {
    var pointerValue = firm.getValue(variablePointer, firm.mode_P);

    var mem = firm.getStore();
    var load = firm.newLoad(mem, pointerValue, firm.mode_Bu, typeBu, firm.ir_cons_flags.cons_none);

    var loadResult = firm.newProj(load, firm.mode_Bu, @enumToInt(firm.projection_input_Load.res));
    var loadMem = firm.newProj(load, firm.mode_M, @enumToInt(firm.projection_input_Load.M));

    var tarval = firm.newTarvalFromLong(1, firm.mode_Bu);
    var one = firm.newConst(tarval);

    var add = firm.newAdd(loadResult, one);

    var store = firm.newStore(loadMem, pointerValue, add, typeBu, firm.ir_cons_flags.cons_none);
    var storeMem = firm.newProj(store, firm.mode_M, @enumToInt(firm.projection_input_Store.M));

    firm.setStore(storeMem);
}

fn decrementByte() void {
    var pointerValue = firm.getValue(variablePointer, firm.mode_P);

    var mem = firm.getStore();
    var load = firm.newLoad(mem, pointerValue, firm.mode_Bu, typeBu, firm.ir_cons_flags.cons_none);

    var loadResult = firm.newProj(load, firm.mode_Bu, @enumToInt(firm.projection_input_Load.res));
    var loadMem = firm.newProj(load, firm.mode_M, @enumToInt(firm.projection_input_Load.M));

    var tarval = firm.newTarvalFromLong(1, firm.mode_Bu);
    var one = firm.newConst(tarval);

    var sub = firm.newSub(loadResult, one);

    var store = firm.newStore(loadMem, pointerValue, sub, typeBu, firm.ir_cons_flags.cons_none);
    var storeMem = firm.newProj(store, firm.mode_M, @enumToInt(firm.projection_input_Store.M));

    firm.setStore(storeMem);
}

fn outputByte() void {
    if (putchar == null) {
        putcharEntity = createPutCharEntity();
        putchar = firm.newAddress(putcharEntity);
    }

    var pointerValue = firm.getValue(variablePointer, firm.mode_P);
    var mem = firm.getStore();

    var load = firm.newLoad(mem, pointerValue, firm.mode_Bu, typeBu, firm.ir_cons_flags.cons_none);
    var loadResult = firm.newProj(load, firm.mode_Bu, @enumToInt(firm.projection_input_Load.res));

    var convert = firm.newConv(loadResult, firm.mode_Is);
    var in: [1]?*firm.ir_node = .{convert};
    var cType = firm.getEntityType(putcharEntity);
    var call = firm.newCall(mem, putchar, 1, &in, cType);

    var callMem = firm.newProj(call, firm.mode_M, @enumToInt(firm.projection_input_Call.M));

    firm.setStore(callMem);
}

fn inputByte() void {
    if (getchar == null) {
        getcharEntity = createGetCharEntity();
        getchar = firm.newAddress(getcharEntity);
    }

    var mem = firm.getStore();

    var ctype = firm.getEntityType(getcharEntity);
    var call = firm.newCall(mem, getchar, 0, null, ctype);

    var callMem = firm.newProj(call, firm.mode_M, @enumToInt(firm.projection_input_Call.M));

    var callResults = firm.newProj(call, firm.mode_T, @enumToInt(firm.projection_input_Call.T_result));
    var callResult = firm.newProj(callResults, firm.mode_Is, 0);

    var pointerValue = firm.getValue(variablePointer, firm.mode_P);
    var convert = firm.newConv(callResult, firm.mode_Is);

    var store = firm.newStore(callMem, pointerValue, convert, typeBu, firm.ir_cons_flags.cons_none);
    var storeMem = firm.newProj(store, firm.mode_M, @enumToInt(firm.projection_input_Store.M));

    firm.setStore(storeMem);
}

fn createReturn() void {
    var mem = firm.getStore();
    var zero = firm.newConst(firm.newTarvalFromLong(0, firm.mode_Is));
    var returnNode = firm.newReturn(mem, 1, &zero);

    var endBlock = firm.getIrgEndBlock(firm.current_ir_graph);
    firm.addImmblockPred(endBlock, returnNode);

    firm.matureImmblock(firm.getCurBlock());

    firm.setCurBlock(null);
}

fn parseLoop() void {
    var jmp = firm.newJmp();
    firm.matureImmblock(firm.getCurBlock());
    var loopHeaderBlock = firm.newImmblock();
    firm.addImmblockPred(loopHeaderBlock, jmp);
    firm.setCurBlock(loopHeaderBlock);

    var pointerValue = firm.getValue(variablePointer, firm.mode_P);
    var mem = firm.getStore();
    var load = firm.newLoad(mem, pointerValue, firm.mode_Bu, typeBu, firm.ir_cons_flags.cons_none);
    var loadResult = firm.newProj(load, firm.mode_Bu, @enumToInt(firm.projection_input_Load.res));
    var loadMem = firm.newProj(load, firm.mode_M, @enumToInt(firm.projection_input_Load.M));

    firm.setStore(loadMem);

    var zero = firm.newConst(firm.newTarvalFromLong(0, firm.mode_Bu));

    var equal = firm.newCmp(loadResult, zero, firm.ir_relation.equal);
    var cond = firm.newCond(equal);
    var trueProj = firm.newProj(cond, firm.mode_X, @enumToInt(firm.projection_input_Cond.True));
    var falseProj = firm.newProj(cond, firm.mode_X, @enumToInt(firm.projection_input_Cond.False));

    var loopBodyBlock = firm.newImmblock();
    firm.addImmblockPred(loopBodyBlock, falseProj);
    firm.setCurBlock(loopBodyBlock);

    suspend {}

    var jmp2 = firm.newJmp();
    firm.addImmblockPred(loopHeaderBlock, jmp2);
    firm.matureImmblock(loopHeaderBlock);
    firm.matureImmblock(firm.getCurBlock());

    var afterLoop = firm.newImmblock();
    firm.addImmblockPred(afterLoop, trueProj);
    firm.setCurBlock(afterLoop);
}

fn parse(file: std.fs.File) !void {
    var buffer: [128 * 1024]u8 = undefined;
    var frameBuffers: [256]@Frame(parseLoop) = undefined;
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
                        frameBuffers[loop - 1] = async parseLoop();
                    },
                    ']' => {
                        resume frameBuffers[loop-1];
                        if (@subWithOverflow(usize, loop, 1, &loop)) {
                            std.log.err("parse error: unexpected '['\n", .{});
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
    var graph = createGraph();
    firm.setCurrentIrGraph(graph);

    typeBu = firm.getTypeForMode(firm.mode_Bu);

    var field = createField();
    var fieldStart = firm.newAddress(field);
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

    var out = std.c.fopen("test.s", "w");
    if (out == null) {
        std.log.err("could not open output file\n", .{});
        return;
    }
    if (out) |o| {
        firm.beMain(o, "");
        _ = std.c.fclose(o);
    }
}
