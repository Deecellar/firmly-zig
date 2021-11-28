// This file is in the making, just a bunch of friendly codes

const std = @import("std");
const firm_abi = @import("firm-abi.zig");
/// Codegen helpers for a program
pub const Codegen = struct {
    /// Enum with all the binary opcodes
    pub const BinaryOperations = enum {
        And,
        Or,
        Eor,
        Add,
        Sub,
        Mul,
        Mulh,
        Mod,
        Div,
        Cmp_Less,
        Cmp_Less_Equal,
        Cmp_Greater,
        Cmp_Greater_Equal,
        Cmp_Equal,
        Cmp_Not_Equal,
        Cmp_Less_Greater,
        Cmp_Not_Equal_Float,
        Cmp_Unordered,
        Cmp_Unordered_Less,
        Cmp_Unordered_Less_Equal,
        Cmp_Unordered_Greater,
        Cmp_Unordered_Greater_Equal,
        Cmp_False,
        Cmp_True,
        Error,
    };
    // Handles the binary operations
    pub fn binaryOperation(op: BinaryOperations, lhs: *firm_abi.ir_node, rhs: *firm_abi.ir_node) *firm_abi.ir_node {
        var node_op : *firm_abi.ir_node = switch(op) {
            BinaryOperations.And => firm_abi.newAdd(lhs, rhs),
            BinaryOperations.Or => firm_abi.newOr(lhs, rhs),
            BinaryOperations.Eor => firm_abi.newEor(lhs, rhs),
            BinaryOperations.Add => firm_abi.newAdd(lhs, rhs),
            BinaryOperations.Sub => firm_abi.newSub(lhs, rhs),
            BinaryOperations.Mul => firm_abi.newMul(lhs, rhs),
            BinaryOperations.Mulh => firm_abi.newMulh(lhs, rhs),
            BinaryOperations.Mod => firm_abi.newMod(lhs, rhs),
            BinaryOperations.Div => firm_abi.newDiv(lhs, rhs),
            BinaryOperations.Cmp_Less => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.less),
            BinaryOperations.Cmp_Less_Equal => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.less_equal),
            BinaryOperations.Cmp_Greater => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.greater),
            BinaryOperations.Cmp_Greater_Equal => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.greater_equal),
            BinaryOperations.Cmp_Equal => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.equal),
            BinaryOperations.Cmp_Not_Equal => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.less_equal_greater),
            BinaryOperations.Cmp_Less_Greater => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.less_greater),
            BinaryOperations.Cmp_Not_Equal_Float => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.unordered_less_greater),
            BinaryOperations.Cmp_Unordered => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.unordered),
            BinaryOperations.Cmp_Unordered_Less => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.unordered_less),
            BinaryOperations.Cmp_Unordered_Less_Equal => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.unordered_less_equal),
            BinaryOperations.Cmp_Unordered_Greater => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.unordered_greater),
            BinaryOperations.Cmp_Unordered_Greater_Equal => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.unordered_greater_equal),
            BinaryOperations.Cmp_False => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.false),
            BinaryOperations.Cmp_True => firm_abi.newCmp(lhs, rhs, firm_abi.ir_relation.true),
            else => firm_abi.newBad(firm_abi.mode_ANY),
        } orelse firm_abi.newBad(firm_abi.mode_ANY);

        return node_op;
    }
    /// Enum with all the unary opcodes
    pub const UnaryOperations = enum {
        Not,
        Error,
    };

    // Handles the unary operations
    pub fn unaryOperation(op: UnaryOperations, lhs: *firm_abi.ir_node) *firm_abi.ir_node {
        var node_op : *firm_abi.ir_node = switch(op) {
            UnaryOperations.Not => firm_abi.newNot(lhs),
        } orelse firm_abi.newBad(firm_abi.mode_ANY);
        return node_op;
    }

    // Get Number Tarval from a value
    pub fn getNumberTarval(comptime intType : type, value: intType) *firm_abi.ir_tarval {
        var typeInfo : std.builtin.TypeInfo = @typeInfo(intType);
        if(typeInfo == .Int) {
            if(typeInfo.Int.bits <= 32){
                if(typeInfo.Int.Signedness == .signed) {
                    return firm_abi.newTarvalFromLong(value, firm_abi.mode_I);
                }
                
            }
        }
        return firm_abi.newTarvalFromLong(value, firm_abi.mode_I);
    }
    // Create a function on the ir_graph with the given name and type signature, and appends the given graph to the main graph
};

/// Program struct represents the main ir_graph 
pub const program = struct {
    /// The main ir_graph
    ir_graph: firm_abi.ir_graph,
    /// init the program
    pub fn init() void {
        firm_abi.irInit();
        
    }
};
