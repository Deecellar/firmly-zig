const std = @import("std");
pub const ir_visited_t = u64;
pub const ir_label_t = u64;
pub const dbg_info = opaque {};
pub const type_dbg_info = opaque {};
pub const ir_node = opaque {};
pub const ir_op = opaque {};
pub const ir_mode = opaque {};
pub const ir_edge_t = opaque {};
pub const ir_heights_t = opaque {};
pub const ir_tarval = opaque {};
pub const ir_type = opaque {};
pub const ir_graph = opaque {};
pub const ir_prog = opaque {};
pub const ir_loop = opaque {};
pub const ir_entity = opaque {};
pub const ir_cdep = opaque {};
pub const ir_initializer_t = opaque {};
pub const ir_machine_triple_t = opaque {};
pub const ir_switch_table = opaque {};
pub const ir_relation = enum(u32) {
    False,
    equal,
    less,
    less_equal,
    greater,
    greater_equal,
    less_greater,
    less_equal_greater,
    unordered,
    unordered_equal,
    unordered_less,
    unordered_less_equal,
    unordered_greater,
    unordered_greater_equal,
    unordered_less_greater,
    True,
};
pub const ir_cons_flags = enum(u32) { cons_none = 0, cons_volatile = 1, cons_unaligned = 2, cons_floats = 4, cons_throws_exceptions = 8 };
pub const op_pin_state = enum(u32) {
    floats,
    pinned,
    exc_pinned,
};
pub const cond_jmp_predicate = enum(u32) {
    none,
    True,
    False,
};
pub const mtp_additional_properties = enum(u32) {
    no_property = 0,
    pure = 1,
    no_write = 2,
    no_return = 4,
    terminates = 8,
    no_throw = 16,
    naked = 32,
    malloc = 64,
    returns_twice = 128,
    private = 256,
    always_inline = 512,
    no_inline = 1024,
    inline_recommended = 2048,
    temporary = 4096,
    is_constructor = 8192,
};
pub const ir_asm_constraint = extern struct {
    in_pos: i32,
    out_pos: i32,
    constraint: [*]const u8,
    mode: ?*ir_mode,
};
pub const ir_builtin_kind = enum(u32) {
    trap,
    debug_break,
    return_address,
    frame_address,
    prefetch,
    ffs,
    clz,
    ctz,
    popcount,
    parity,
    bswap,
    inport,
    outport,
    saturating_increment,
    compare_swap,
    may_alias,
    va_start,
    va_arg,
};
pub const ir_volatility = enum(u32) {
    non_volatile,
    is_volatile,
};
pub const ir_align = enum(u32) {
    is_aligned,
    non_aligned,
};
pub const float_int_conversion_overflow_style_t = enum(u32) {
    indefinite,
    min_max,
};
pub const hook_entry_t = opaque {};
pub const ir_visibility = enum(u32) { external, external_private, external_protected, local, private };
pub const ir_linkage = enum(u32) {
    default,
    constant,
    weak,
    garbage_collect,
    merge,
    hidden_user,
    no_codegen,
    no_identity,
};
pub const ir_entity_usage = enum(u32) {
    none = 0,
    address_taken = 1,
    write = 2,
    read = 4,
    reinterpret_cast = 8,
    unknown = 15,
};
pub const ir_initializer_kind_t = enum(u32) { CONST, TARVAL, NULL, COMPOUND };
pub const ptr_access_kind = enum(u32) { none = 0, read = 1, write = 2, rw = 3, store = 4, all = 7 };
pub const tp_opcode = enum(u32) { uninitalized, Struct, Union, class, segment, method, array, pointer, primitive, code, unknown };
pub const inh_transitive_closure_state = enum(u32) { none, valid, invalid, max };
pub const ir_type_state = enum(u32) { Undefined, fixed };

pub const calling_convention_enum = enum(u32) {
    reg_param = 0x01000000,
    last_on_top = 0x02000000,
    callee_clear_stk = 0x04000000,
    this_call = 0x08000000,
    compound_ret = 0x10000000,
    frame_on_caller_stk = 0x20000000,
    fpreg_param = 0x40000000,
    pub const calling_helpers = enum(u32) {
        decl_set = 0,
        stdcall_set = @enumToInt(calling_convention_enum.callee_clear_stk),
        fastcall_set = @enumToInt(calling_convention_enum.callee_clear_stk) | @enumToInt(calling_convention_enum.reg_param),
    };
    pub const cc_bits: u32 = (0xFF << 24);
    pub fn isCallType(mask: u32, calling_help: calling_helpers) bool {
        switch (calling_help) {
            .decl_set => return (mask & cc_bits) == @enumToInt(calling_helpers.decl_set),
            .stdcall_set => return (mask & cc_bits) == @enumToInt(calling_helpers.stdcall_set),
            .fastcall_set => return (mask & cc_bits) == @enumToInt(calling_helpers.fastcall_set),
            else => unreachable,
        }
    }
    pub fn setCdecl(mask: u32, calling_help: calling_helpers) u32 {
        return (((mask & ~cc_bits)) | @enumToInt(calling_help));
    }
};
const convention = enum {
    calling_convention,
    calling_convention_special,
    value,
};
pub const calling_convention = union(convention) { calling_convention: calling_convention_enum, calling_convention_special: calling_convention_enum.calling_helpers, value: u32 };
pub const ir_mode_arithmetic = enum(u32) {
    none = 1,
    twos_complement = 2,
    ieee754 = 256,
    x86_extended_float = 257,
};
pub const asm_constraint_flags_t = enum(u32) {
    none = 0,
    supports_register = 1,
    supports_memop = 2,
    Immediate = 4,
    supports_any = 7,
    no_support = 8,
    modifier_write = 16,
    modifier_read = 32,
    modifier_early_clobber = 64,
    modifier_commutative = 128,
    invalid = 256,
};
pub const osr_flags = enum(u32) { none, lftr_with_ov_check, ignore_x86_shift, keep_reg_pressure = 4 };
pub const dwarf_source_language = enum(u32) { C89 = 1, C = 2, Ada83 = 3, C_plus_plus = 4, Cobol74 = 5, Cobol85 = 6, Fortran77 = 7, Fortran90 = 8, Pascal83 = 9, Modula2 = 10, Java = 11, C99 = 12, Ada95 = 13, Fortan95 = 14, PLI = 15, ObjC = 16, ObjC_plus_plus = 17, UPC = 18, D = 19, Python = 20, Go = 22 };
pub const dbg_action = enum(u32) {
    err,
    opt_ssa,
    opt_auxnode,
    const_eval,
    opt_cse,
    straightening,
    if_simplifcation,
    algebraic_simplification,
    write_after_write,
    write_after_read,
    read_after_write,
    read_after_read,
    read_a_constant,
    dead_code,
    opt_confirm,
    gvn_pre,
    combo,
    jumpthreading,
    backend,
    max,
};
pub const src_loc_t = extern struct {
    file: [*]const u8,
    line: i32,
    column: i32,
};
pub const firm_kind = enum(u32) {
    bad,
    entity,
    firm_type,
    ir_graph,
    ir_mode,
    ir_tarval,
    ir_loop,
    ir_max,
};
pub const irp_callgraph_state = enum(u32) { none, consistent, inconsistent, and_calltree_consistent };
pub const loop_nesting_depth_state = enum(u32) { none, consistent, inconsistent };
pub const range_types = enum(u32) {
    Undefined,
    range,
    antirange,
    varying,
};

pub const op_arity = enum(u32) {
    invalid,
    binary,
    dynamic,
    any,
};
pub const irop_flags = enum(u32) {
    none = 0,
    commutative = 1,
    cfopcode = 2,
    fragile = 4,
    forking = 8,
    constlike = 32,
    keep = 64,
    start_block = 128,
    uses_memory = 256,
    dump_noblock = 512,
    unknown_jump = 2048,
    const_memory = 4096,
};

pub const dumb_node = enum(u32) {
    opcode_txt,
    mode_txt,
    nodeattr_txt,
    info_txt,
};

pub const ir_opcode = enum(u32) {
    Asm,
    Add,
    Address,
    Align,
    Alloc,
    Anchor,
    And,
    Bad,
    Bitcast,
    Block,
    Builtin,
    Call,
    Cmp,
    Cond,
    Confirm,
    Const,
    Conv,
    CopyB,
    Deleted,
    Div,
    Dummy,
    End,
    Eor,
    Free,
    IJmp,
    Id,
    Jmp,
    Load,
    Member,
    Minus,
    Mod,
    Mul,
    Mulh,
    Mux,
    NoMem,
    Not,
    Offset,
    Or,
    Phi,
    Pin,
    Proj,
    Raise,
    Return,
    Sel,
    Shl,
    Shr,
    Shrs,
    Size,
    Start,
    Store,
    Sub,
    Switch,
    Sync,
    Tuple,
    Unknown,
};

pub const ir_verbosity = enum(u32) {
    onlynames = 1,
    fields = 2,
    methods = 4,
    nostatic = 64,
    typeattrs = 8,
    entattrs = 16,
    entconsts = 32,
    accessStats = 256,
    max = 1341132734,
};

pub const input_number_ASM = enum(u32) {
    mem,
};

pub const projection_input_ASM = enum(u32) {
    M,
    regular,
    first_out,
};

pub const input_number_Add = enum(u32) {
    left,
    right,
};

pub const projection_input_Alloc = enum(u32) {
    M,
    res,
};

pub const input_number_Anchor = enum(u32) {
    end_block,
    start_block,
    end,
    start,
    frame,
    initial_mem,
    args,
    no_mem,
};

pub const projection_input_Bitcast = enum(u32) {
    op,
};

pub const input_number_Builtin = enum(u32) {
    mem,
};

pub const projection_input_Builtin = enum(u32) {
    M,
};

pub const input_number_Call = enum(u32) {
    mem,
    ptr,
};

pub const projection_input_Call = enum(u32) {
    M,
    T_result,
    X_regular,
    X_except,
};

pub const inptu_number_Cmp = enum(u32) {
    left,
    right,
};

pub const input_number_Cond = enum(u32) {
    selector,
};

pub const projection_input_Cond = enum(u32) {
    False,
    True,
};

pub const input_number_Confirm = enum(u32) {
    value,
    bound,
};

pub const input_number_Conv = enum(u32) {
    op,
};

pub const input_number_CopyB = enum(u32) {
    mem,
    dst,
    src,
};

pub const input_number_Div = enum(u32) {
    mem,
    left,
    right,
};

pub const projection_input_Div = enum(u32) {
    M,
    res,
    X_regular,
    X_except,
};

pub const input_number_Eor = enum(u32) {
    left,
    right,
};

pub const input_number_Free = enum(u32) {
    mem,
    ptr,
};

pub const input_number_IJmp = enum(u32) {
    target,
};

pub const input_number_Id = enum(u32) {
    pred,
};

pub const input_number_Load = enum(u32) {
    mem,
    ptr,
};

pub const projection_input_Load = enum(u32) {
    M,
    res,
    X_regular,
    X_except,
};

pub const input_number_Member = enum(u32) {
    ptr,
};

pub const input_number_Minus = enum(u32) {
    op,
};

pub const input_number_Mod = enum(u32) {
    mem,
    left,
    right,
};

pub const projection_input_Mod = enum(u32) {
    M,
    res,
    X_regular,
    X_except,
};

pub const input_number_Mul = enum(u32) {
    left,
    right,
};

pub const input_number_Mulh = enum(u32) {
    left,
    right,
};

pub const input_number_Mux = enum(u32) {
    sel,
    False,
    True,
};

pub const input_number_Not = enum(u32) {
    op,
};

pub const input_number_Or = enum(u32) {
    left,
    right,
};

pub const input_number_Pin = enum(u32) {
    op,
};

pub const input_number_Proj = enum(u32) {
    pred,
};

pub const input_number_Raise = enum(u32) {
    mem,
    exo_ptr,
};

pub const projection_input_Raise = enum(u32) {
    M,
    X,
};

pub const input_number_Return = enum(u32) {
    mem,
};

pub const input_number_Sel = enum(u32) {
    ptr,
    index,
};

pub const input_number_Shl = enum(u32) {
    left,
    right,
};

pub const input_number_Shr = enum(u32) {
    left,
    right,
};

pub const input_number_Shrs = enum(u32) {
    left,
    right,
};

pub const projection_input_Start = enum(u32) {
    M,
    P_frame_base,
    T_args,
};

pub const input_number_Store = enum(u32) {
    mem,
    ptr,
    value,
};

pub const projection_input_Store = enum(u32) {
    M,
    X_regular,
    X_except,
};

pub const input_number_Sub = enum(u32) {
    left,
    right,
};

pub const input_number_Switch = enum(u32) {
    selector,
};

pub const ir_dump_flags_t = enum(u32) {
    blocks_as_subgraphs = 1,
    with_typegraph = 2,
    disable_edge_labels = 4,
    consts_local = 8,
    idx_label = 16,
    number_label = 32,
    keepalive_edges = 64,
    out_edges = 128,
    dominance = 256,
    loops = 512,
    back_edges = 1024,
    iredges = 2048,
    all_anchors = 4096,
    show_marks = 8192,
    no_entity_values = 16384,
    ld_names = 32768,
    entities_in_hierarchy = 65536,
};

pub const ir_edge_kind_t = enum(u32) {
    Normal = 0,
    Block = 1,
};

pub const ir_resources_t = enum(u32) {
    none = 0,
    block_visited = 1,
    block_mark = 2,
    irn_visited = 4,
    irn_link = 8,
    loop_link = 16,
    phi_list = 32,
};

pub const ir_graph_constraints_t = enum(u32) {
    ARCH_DEP = 1,
    MODEB_LOWERED = 2,
    NORMALISATION2 = 4,
    OPTIMIZE_UNREACHABLE_CODE = 8,
    CONSTRUCTION = 16,
    TARGET_LOWERED = 32,
    BACKEND = 64,
};

pub const ir_graph_properties_t = enum(u32) {
    none = 0,
    no_critical_edges = 1,
    no_bads = 2,
    no_tuples = 4,
    no_unreachable_code = 8,
    one_return = 16,
    consistent_dominance = 32,
    consistent_postdominance = 64,
    consistent_dominance_frontiers = 128,
    consistent_out_edges = 256,
    consistent_outs = 512,
    consistent_loopinfo = 1024,
    consistent_entity_usage = 2048,
    many_returns = 4096,
    control_flow = 1273,
    all = 8191,
};

pub const ir_alias_relation = enum(u32) { no_alias, may_alias, sure_alias };
pub const ir_entity_usage_computed_state = enum(u32) {
    not_computed,
    computed,
};
pub const ir_disambiguator_options = enum(u32) {
    none = 0,
    always_alias = 1,
    type_based = 2,
    byte_type_may_alias = 4,
    no_alias = 8,
    inherited = 16,
};

pub const ir_segment_t = enum(u32) {
    global,
    thread_local,
    constructors,
    destructors,
    jrc,
};

pub const irp_resources_t = enum(u32) {
    none = 0,
    irg_link = 1,
    entity_link = 2,
    type_visited = 4,
    link = 8,
};

pub const ikind = enum(u32) {
    intrinsic_call,
    intrinsic_instruction,
};

pub const ir_platform_type_t = enum(u32) {
    bool,
    char,
    short,
    int,
    long,
    long_long,
    float,
    double,
    long_double,
};

pub const vrp_attr = extern struct {
    bits_set: ?*ir_tarval,
    bits_not_set: ?*ir_tarval,
    range_type: range_types,
    range_bottom: ?*ir_tarval,
    range_top: ?*ir_tarval,
};

pub const i_call_record = extern struct {
    kind: ikind,
    i_ent: ?*ir_entity,
    i_mapper: ?i_mapper_func,
};
pub const i_instr_record = extern struct {
    kind: ikind,
    op: ?*ir_op,
    i_mapper: ?i_mapper_func,
};
pub const i_record = extern union {
    kind: ikind,
    i_call: i_call_record,
    i_instr: i_instr_record,
};

pub const ir_dump_verbosity_t = enum(u32) {
    dump_verbosity_onlynames = 0x00000001,
    dump_verbosity_fields = 0x00000002,
    dump_verbosity_methods = 0x00000004,
    dump_verbosity_nostatic = 0x00000040,
    dump_verbosity_typeattrs = 0x00000008,
    dump_verbosity_entattrs = 0x00000010,
    dump_verbosity_entconsts = 0x00000020,
    dump_verbosity_accessStats = 0x00000100,
    dump_verbosity_max = 0x4FF00FBE,
};

pub const dump_reason_t = enum(u32) { dump_node_opcode_txt, dump_node_mode_txt, dump_node_nodeattr_txt, dump_node_info_txt };

pub extern var mode_M: ?*ir_mode;
pub extern var mode_F: ?*ir_mode;
pub extern var mode_D: ?*ir_mode;
pub extern var mode_Bs: ?*ir_mode;
pub extern var mode_Bu: ?*ir_mode;
pub extern var mode_Hs: ?*ir_mode;
pub extern var mode_Hu: ?*ir_mode;
pub extern var mode_Is: ?*ir_mode;
pub extern var mode_Iu: ?*ir_mode;
pub extern var mode_Ls: ?*ir_mode;
pub extern var mode_Lu: ?*ir_mode;
pub extern var mode_P: ?*ir_mode;
pub extern var mode_b: ?*ir_mode;
pub extern var mode_X: ?*ir_mode;
pub extern var mode_BB: ?*ir_mode;
pub extern var mode_T: ?*ir_mode;
pub extern var mode_ANY: ?*ir_mode;
pub extern var mode_BAD: ?*ir_mode;

pub extern var op_ASM: ?*ir_op;

pub extern var op_Add: ?*ir_op;
pub extern var op_Address: ?*ir_op;
pub extern var op_Align: ?*ir_op;
pub extern var op_Alloc: ?*ir_op;
pub extern var op_Anchor: ?*ir_op;

pub extern var op_And: ?*ir_op;
pub extern var op_Bad: ?*ir_op;

pub extern var op_Bitcast: ?*ir_op;
pub extern var op_Block: ?*ir_op;

pub extern var op_Builtin: ?*ir_op;

pub extern var op_Call: ?*ir_op;

pub extern var op_Cmp: ?*ir_op;

pub extern var op_Cond: ?*ir_op;

pub extern var op_Confirm: ?*ir_op;
pub extern var op_Const: ?*ir_op;

pub extern var op_Conv: ?*ir_op;

pub extern var op_CopyB: ?*ir_op;
pub extern var op_Deleted: ?*ir_op;

pub extern var op_Div: ?*ir_op;
pub extern var op_Dummy: ?*ir_op;
pub extern var op_End: ?*ir_op;

pub extern var Lop_Eor: ?*ir_op;

pub extern var op_Free: ?*ir_op;

pub extern var op_IJmp: ?*ir_op;

pub extern var op_Id: ?*ir_op;
pub extern var op_Jmp: ?*ir_op;

pub extern var op_Load: ?*ir_op;

pub extern var op_Member: ?*ir_op;

pub extern var op_Minus: ?*ir_op;

pub extern var op_Mod: ?*ir_op;

pub extern var op_Mul: ?*ir_op;

pub extern var op_Mulh: ?*ir_op;

pub extern var op_Mux: ?*ir_op;
pub extern var op_NoMem: ?*ir_op;

pub extern var op_Not: ?*ir_op;
pub extern var op_Offset: ?*ir_op;

pub extern var op_Or: ?*ir_op;
pub extern var op_Phi: ?*ir_op;

pub extern var op_Pin: ?*ir_op;

pub extern var op_Proj: ?*ir_op;

pub extern var op_Raise: ?*ir_op;

pub extern var op_Return: ?*ir_op;

pub extern var op_Sel: ?*ir_op;

pub extern var op_Shl: ?*ir_op;

pub const obstack = opaque {};

pub extern var op_Shr: ?*ir_op;

pub extern var op_Shrs: ?*ir_op;
pub extern var op_Size: ?*ir_op;

pub extern var op_Start: ?*ir_op;

pub extern var op_Store: ?*ir_op;

pub extern var op_Sub: ?*ir_op;

pub extern var op_Switch: ?*ir_op;
pub extern var op_Sync: ?*ir_op;
pub extern var op_Tuple: ?*ir_op;
pub extern var op_Unknown: ?*ir_op;
pub extern var current_ir_graph: ?*ir_graph;

pub const IrMode = enum {
    M,
    Is,
    Iu,
    F,
    D,
    P,
    Hs,
    Hu,
    Ls,
    Lu,
    Bs,
    Bu,
    T,
    BB,
    X,
    ANY,
    BAD,
};
pub fn getMode(mode: IrMode) ?*ir_mode {
    switch (mode) {
        .M => return mode_M,
        .Is => return mode_Is,
        .Iu => return mode_Iu,
        .F => return mode_F,
        .D => return mode_D,
        .P => return mode_P,
        .Hs => return mode_Hs,
        .Hu => return mode_Hu,
        .Ls => return mode_Ls,
        .Lu => return mode_Lu,
        .Bs => return mode_Bs,
        .Bu => return mode_Bu,
        .T => return mode_T,
        .BB => return mode_BB,
        .X => return mode_X,
        .ANY => return mode_ANY,
        .BAD => return mode_BAD,
    }
}

pub const optimization_state_t = u32;
pub const irg_callee_info_none: i32 = 0;
pub const irg_callee_info_consistent: i32 = 1;
pub const irg_callee_info_inconsistent: i32 = 2;
pub const irg_callee_info_state = u32;
pub const loop_element = extern union {
    kind: [*]firm_kind,
    node: ?*ir_node,
    son: ?*ir_loop,
    irg: ?*ir_graph,
};

pub extern var irp: ?*ir_prog;

pub const ir_intrinsics_map = opaque {};

pub const ir_platform_define_t = opaque {};
pub const ir_timer_t = opaque {};
pub extern const tarval_bad: ?*ir_tarval;
pub extern const tarval_unknown: ?*ir_tarval;
pub const check_alloc_entity_func = ?fn (?*ir_entity) callconv(.C) i32;

pub extern var tarval_b_false: ?*ir_tarval;
pub extern var tarval_b_true: ?*ir_tarval;

pub const arch_allow_ifconv_func = ?fn (?*const ir_node, ?*const ir_node, ?*const ir_node) callconv(.C) i32;
pub const opt_ptr = ?fn (?*ir_graph) callconv(.C) void;
pub const after_transform_func = ?fn (?*ir_graph, [*]const u8) callconv(.C) void;
pub const retrieve_dbg_func = ?fn (?*const dbg_info) callconv(.C) src_loc_t;
pub const retrieve_type_dbg_func = ?fn ([*]u8, usize, ?*const type_dbg_info) callconv(.C) void;
pub const op_func = ?fn () callconv(.C) void;
pub const hash_func = ?fn (?*const ir_node) callconv(.C) u32;
pub const computed_value_func = ?fn (?*const ir_node) callconv(.C) ?*ir_tarval;
pub const equivalent_node_func = ?fn (?*ir_node) callconv(.C) ?*ir_node;
pub const transform_node_func = ?fn (?*ir_node) callconv(.C) ?*ir_node;
pub const node_attrs_equal_func = ?fn (?*const ir_node, ?*const ir_node) callconv(.C) i32;
pub const reassociate_func = ?fn ([*]?*ir_node) callconv(.C) i32;
pub const copy_attr_func = ?fn (?*ir_graph, ?*const ir_node, ?*ir_node) callconv(.C) void;
pub const get_type_attr_func = ?fn (?*const ir_node) callconv(.C) ?*ir_type;
pub const get_entity_attr_func = ?fn (?*const ir_node) callconv(.C) ?*ir_entity;
pub const verify_node_func = ?fn (?*const ir_node) callconv(.C) i32;
pub const verify_proj_node_func = ?fn (?*const ir_node) callconv(.C) i32;
pub const dump_node_func = ?fn (*std.c.FILE, ?*const ir_node, dump_reason_t) callconv(.C) void;
pub const ir_prog_dump_func = ?fn (*std.c.FILE) callconv(.C) void;
pub const ir_graph_dump_func = ?fn (*std.c.FILE, ?*ir_graph) callconv(.C) void;
pub const dump_node_vcgattr_func = ?fn (*std.c.FILE, ?*const ir_node, ?*const ir_node) callconv(.C) i32;
pub const dump_edge_vcgattr_func = ?fn (*std.c.FILE, ?*const ir_node, i32) callconv(.C) i32;
pub const dump_node_edge_func = ?fn (*std.c.FILE, ?*const ir_node) callconv(.C) void;
pub const irg_walk_func = fn (?*ir_node, ?*anyopaque) callconv(.C) void;
pub const uninitialized_local_variable_func_t = fn (?*ir_graph, ?*ir_mode, i32) callconv(.C) ?*ir_node;
pub const compare_types_func_t = fn (?*const anyopaque, ?*const anyopaque) callconv(.C) i32;
pub const type_walk_func = fn (?*ir_type, ?*ir_entity, ?*anyopaque) callconv(.C) void;
pub const class_walk_func = fn (?*ir_type, ?*anyopaque) callconv(.C) void;
pub const entity_walk_func = fn (?*ir_entity, ?*anyopaque) callconv(.C) void;
pub const callgraph_walk_func = fn (?*ir_graph, ?*anyopaque) callconv(.C) void;
pub const merge_pair_func = fn (?*ir_node, ?*ir_node, dbg_action) callconv(.C) void;
pub const merge_sets_func = fn ([*]const ?*ir_node, i32, [*]const ?*ir_node, i32, dbg_action) callconv(.C) void;
pub const dump_node_info_cb_t = fn (?*anyopaque, *std.c.FILE, ?*const ir_node) callconv(.C) void;
pub const lower_mux_callback = fn (?*ir_node) callconv(.C) i32;
pub const i_mapper_func = fn (?*ir_node) callconv(.C) i32;

pub const low_level = struct {
    pub extern fn get_entity_visibility(entity: ?*const ir_entity) ir_visibility;
    pub extern fn set_entity_visibility(entity: ?*ir_entity, visibility: ir_visibility) void;
    pub extern fn entity_is_externally_visible(entity: ?*const ir_entity) i32;
    pub extern fn entity_has_definition(entity: ?*const ir_entity) i32;
    pub extern fn new_entity(owner: ?*ir_type, name: [*]const u8, tp: ?*ir_type) ?*ir_entity;
    pub extern fn new_global_entity(segment: ?*ir_type, ld_name: [*]const u8, @"type": ?*ir_type, visibility: ir_visibility, linkage: ir_linkage) ?*ir_entity;
    pub extern fn new_parameter_entity(owner: ?*ir_type, pos: usize, @"type": ?*ir_type) ?*ir_entity;
    pub extern fn new_alias_entity(owner: ?*ir_type, name: [*]const u8, alias: ?*ir_entity, @"type": ?*ir_type, visibility: ir_visibility) ?*ir_entity;
    pub extern fn set_entity_alias(alias: ?*ir_entity, aliased: ?*ir_entity) void;
    pub extern fn get_entity_alias(alias: ?*const ir_entity) ?*ir_entity;
    pub extern fn check_entity(ent: ?*const ir_entity) i32;
    pub extern fn clone_entity(old: ?*const ir_entity, name: [*]const u8, owner: ?*ir_type) ?*ir_entity;
    pub extern fn free_entity(ent: ?*ir_entity) void;
    pub extern fn get_entity_name(ent: ?*const ir_entity) [*]const u8;
    pub extern fn get_entity_ident(ent: ?*const ir_entity) [*]const u8;
    pub extern fn set_entity_ident(ent: ?*ir_entity, id: [*]const u8) void;
    pub extern fn get_entity_ld_ident(ent: ?*const ir_entity) [*]const u8;
    pub extern fn set_entity_ld_ident(ent: ?*ir_entity, ld_ident: [*]const u8) void;
    pub extern fn get_entity_ld_name(ent: ?*const ir_entity) [*]const u8;
    pub extern fn entity_has_ld_ident(entity: ?*const ir_entity) i32;
    pub extern fn get_entity_owner(ent: ?*const ir_entity) ?*ir_type;
    pub extern fn set_entity_owner(ent: ?*ir_entity, owner: ?*ir_type) void;
    pub extern fn get_entity_type(ent: ?*const ir_entity) ?*ir_type;
    pub extern fn set_entity_type(ent: ?*ir_entity, tp: ?*ir_type) void;
    pub extern fn get_entity_linkage(entity: ?*const ir_entity) ir_linkage;
    pub extern fn set_entity_linkage(entity: ?*ir_entity, linkage: ir_linkage) void;
    pub extern fn add_entity_linkage(entity: ?*ir_entity, linkage: ir_linkage) void;
    pub extern fn remove_entity_linkage(entity: ?*ir_entity, linkage: ir_linkage) void;
    pub extern fn get_entity_volatility(ent: ?*const ir_entity) ir_volatility;
    pub extern fn set_entity_volatility(ent: ?*ir_entity, vol: ir_volatility) void;
    pub extern fn get_volatility_name(@"var": ir_volatility) [*]const u8;
    pub extern fn get_entity_alignment(entity: ?*const ir_entity) u32;
    pub extern fn set_entity_alignment(entity: ?*ir_entity, alignment: u32) void;
    pub extern fn get_entity_aligned(ent: ?*const ir_entity) ir_align;
    pub extern fn set_entity_aligned(ent: ?*ir_entity, a: ir_align) void;
    pub extern fn get_align_name(a: ir_align) [*]const u8;
    pub extern fn get_entity_offset(entity: ?*const ir_entity) i32;
    pub extern fn set_entity_offset(entity: ?*ir_entity, offset: i32) void;
    pub extern fn get_entity_bitfield_offset(entity: ?*const ir_entity) u32;
    pub extern fn set_entity_bitfield_offset(entity: ?*ir_entity, offset: u32) void;
    pub extern fn set_entity_bitfield_size(entity: ?*ir_entity, size: u32) void;
    pub extern fn get_entity_bitfield_size(entity: ?*const ir_entity) u32;
    pub extern fn get_entity_link(ent: ?*const ir_entity) ?*anyopaque;
    pub extern fn set_entity_link(ent: ?*ir_entity, l: ?*anyopaque) void;
    pub extern fn get_entity_irg(ent: ?*const ir_entity) ?*ir_graph;
    pub extern fn get_entity_linktime_irg(ent: ?*const ir_entity) ?*ir_graph;
    pub extern fn get_entity_vtable_number(ent: ?*const ir_entity) u32;
    pub extern fn set_entity_vtable_number(ent: ?*ir_entity, vtable_number: u32) void;
    pub extern fn set_entity_label(ent: ?*ir_entity, label: ir_label_t) void;
    pub extern fn get_entity_label(ent: ?*const ir_entity) ir_label_t;
    pub extern fn get_entity_usage(ent: ?*const ir_entity) ir_entity_usage;
    pub extern fn set_entity_usage(ent: ?*ir_entity, flag: ir_entity_usage) void;
    pub extern fn get_entity_dbg_info(ent: ?*const ir_entity) ?*dbg_info;
    pub extern fn set_entity_dbg_info(ent: ?*ir_entity, db: ?*dbg_info) void;
    pub extern fn is_parameter_entity(entity: ?*const ir_entity) i32;
    pub extern fn get_entity_parameter_number(entity: ?*const ir_entity) usize;
    pub extern fn set_entity_parameter_number(entity: ?*ir_entity, n: usize) void;
    pub extern fn get_initializer_kind(initializer: ?*const ir_initializer_t) ir_initializer_kind_t;
    pub extern fn get_initializer_kind_name(ini: ir_initializer_kind_t) [*]const u8;
    pub extern fn get_initializer_null() ?*ir_initializer_t;
    pub extern fn create_initializer_const(value: ?*ir_node) ?*ir_initializer_t;
    pub extern fn create_initializer_tarval(tv: ?*ir_tarval) ?*ir_initializer_t;
    pub extern fn get_initializer_const_value(initializer: ?*const ir_initializer_t) ?*ir_node;
    pub extern fn get_initializer_tarval_value(initialzier: ?*const ir_initializer_t) ?*ir_tarval;
    pub extern fn create_initializer_compound(n_entries: usize) ?*ir_initializer_t;
    pub extern fn get_initializer_compound_n_entries(initializer: ?*const ir_initializer_t) usize;
    pub extern fn set_initializer_compound_value(initializer: ?*ir_initializer_t, index: usize, value: ?*ir_initializer_t) void;
    pub extern fn get_initializer_compound_value(initializer: ?*const ir_initializer_t, index: usize) ?*ir_initializer_t;
    pub extern fn set_entity_initializer(entity: ?*ir_entity, initializer: ?*ir_initializer_t) void;
    pub extern fn get_entity_initializer(entity: ?*const ir_entity) ?*ir_initializer_t;
    pub extern fn add_entity_overwrites(ent: ?*ir_entity, overwritten: ?*ir_entity) void;
    pub extern fn get_entity_n_overwrites(ent: ?*const ir_entity) usize;
    pub extern fn get_entity_overwrites_index(ent: ?*const ir_entity, overwritten: ?*ir_entity) usize;
    pub extern fn get_entity_overwrites(ent: ?*const ir_entity, pos: usize) ?*ir_entity;
    pub extern fn set_entity_overwrites(ent: ?*ir_entity, pos: usize, overwritten: ?*ir_entity) void;
    pub extern fn remove_entity_overwrites(ent: ?*ir_entity, overwritten: ?*ir_entity) void;
    pub extern fn get_entity_n_overwrittenby(ent: ?*const ir_entity) usize;
    pub extern fn get_entity_overwrittenby_index(ent: ?*const ir_entity, overwrites: ?*ir_entity) usize;
    pub extern fn get_entity_overwrittenby(ent: ?*const ir_entity, pos: usize) ?*ir_entity;
    pub extern fn set_entity_overwrittenby(ent: ?*ir_entity, pos: usize, overwrites: ?*ir_entity) void;
    pub extern fn remove_entity_overwrittenby(ent: ?*ir_entity, overwrites: ?*ir_entity) void;
    pub extern fn is_compound_entity(ent: ?*const ir_entity) i32;
    pub extern fn is_method_entity(ent: ?*const ir_entity) i32;
    pub extern fn is_alias_entity(ent: ?*const ir_entity) i32;
    pub extern fn get_entity_nr(ent: ?*const ir_entity) i64;
    pub extern fn get_entity_visited(ent: ?*const ir_entity) ir_visited_t;
    pub extern fn set_entity_visited(ent: ?*ir_entity, num: ir_visited_t) void;
    pub extern fn mark_entity_visited(ent: ?*ir_entity) void;
    pub extern fn entity_visited(ent: ?*const ir_entity) i32;
    pub extern fn entity_not_visited(ent: ?*const ir_entity) i32;
    pub extern fn entity_has_additional_properties(entity: ?*const ir_entity) i32;
    pub extern fn get_entity_additional_properties(ent: ?*const ir_entity) mtp_additional_properties;
    pub extern fn set_entity_additional_properties(ent: ?*ir_entity, prop: mtp_additional_properties) void;
    pub extern fn add_entity_additional_properties(ent: ?*ir_entity, flag: mtp_additional_properties) void;
    pub extern fn get_unknown_entity() ?*ir_entity;
    pub extern fn is_unknown_entity(entity: ?*const ir_entity) i32;
    pub extern fn get_type_opcode_name(opcode: tp_opcode) [*]const u8;
    pub extern fn is_SubClass_of(low: ?*const ir_type, high: ?*const ir_type) i32;
    pub extern fn is_SubClass_ptr_of(low: ?*ir_type, high: ?*ir_type) i32;
    pub extern fn is_overwritten_by(high: ?*ir_entity, low: ?*ir_entity) i32;
    pub extern fn resolve_ent_polymorphy(dynamic_class: ?*ir_type, static_ent: ?*ir_entity) ?*ir_entity;
    pub extern fn set_irp_inh_transitive_closure_state(s: inh_transitive_closure_state) void;
    pub extern fn invalidate_irp_inh_transitive_closure_state() void;
    pub extern fn get_irp_inh_transitive_closure_state() inh_transitive_closure_state;
    pub extern fn compute_inh_transitive_closure() void;
    pub extern fn free_inh_transitive_closure() void;
    pub extern fn get_class_trans_subtype_first(tp: ?*const ir_type) ?*ir_type;
    pub extern fn get_class_trans_subtype_next(tp: ?*const ir_type) ?*ir_type;
    pub extern fn is_class_trans_subtype(tp: ?*const ir_type, subtp: ?*const ir_type) i32;
    pub extern fn get_class_trans_supertype_first(tp: ?*const ir_type) ?*ir_type;
    pub extern fn get_class_trans_supertype_next(tp: ?*const ir_type) ?*ir_type;
    pub extern fn get_entity_trans_overwrittenby_first(ent: ?*const ir_entity) ?*ir_entity;
    pub extern fn get_entity_trans_overwrittenby_next(ent: ?*const ir_entity) ?*ir_entity;
    pub extern fn get_entity_trans_overwrites_first(ent: ?*const ir_entity) ?*ir_entity;
    pub extern fn get_entity_trans_overwrites_next(ent: ?*const ir_entity) ?*ir_entity;
    pub extern fn check_type(tp: ?*const ir_type) i32;
    pub extern fn tr_verify() i32;
    pub extern fn free_type(tp: ?*ir_type) void;
    pub extern fn get_type_opcode(@"type": ?*const ir_type) tp_opcode;
    pub extern fn ir_print_type(buffer: [*]u8, buffer_size: usize, tp: ?*const ir_type) void;
    pub extern fn get_type_state_name(s: ir_type_state) [*]const u8;
    pub extern fn get_type_state(tp: ?*const ir_type) ir_type_state;
    pub extern fn set_type_state(tp: ?*ir_type, state: ir_type_state) void;
    pub extern fn get_type_mode(tp: ?*const ir_type) ?*ir_mode;
    pub extern fn get_type_size(tp: ?*const ir_type) u32;
    pub extern fn set_type_size(tp: ?*ir_type, size: u32) void;
    pub extern fn get_type_alignment(tp: ?*const ir_type) u32;
    pub extern fn set_type_alignment(tp: ?*ir_type, @"align": u32) void;
    pub extern fn get_type_visited(tp: ?*const ir_type) ir_visited_t;
    pub extern fn set_type_visited(tp: ?*ir_type, num: ir_visited_t) void;
    pub extern fn mark_type_visited(tp: ?*ir_type) void;
    pub extern fn type_visited(tp: ?*const ir_type) i32;
    pub extern fn get_type_link(tp: ?*const ir_type) ?*anyopaque;
    pub extern fn set_type_link(tp: ?*ir_type, l: ?*anyopaque) void;
    pub extern fn inc_master_type_visited() void;
    pub extern fn set_master_type_visited(val: ir_visited_t) void;
    pub extern fn get_master_type_visited() ir_visited_t;
    pub extern fn set_type_dbg_info(tp: ?*ir_type, db: ?*type_dbg_info) void;
    pub extern fn get_type_dbg_info(tp: ?*const ir_type) ?*type_dbg_info;
    pub extern fn get_type_nr(tp: ?*const ir_type) i64;
    pub extern fn new_type_class(name: [*]const u8) ?*ir_type;
    pub extern fn get_class_n_members(clss: ?*const ir_type) usize;
    pub extern fn get_class_member(clss: ?*const ir_type, pos: usize) ?*ir_entity;
    pub extern fn get_class_member_index(clss: ?*const ir_type, mem: ?*const ir_entity) usize;
    pub extern fn add_class_subtype(clss: ?*ir_type, subtype: ?*ir_type) void;
    pub extern fn get_class_n_subtypes(clss: ?*const ir_type) usize;
    pub extern fn get_class_subtype(clss: ?*const ir_type, pos: usize) ?*ir_type;
    pub extern fn get_class_subtype_index(clss: ?*const ir_type, subclass: ?*const ir_type) usize;
    pub extern fn set_class_subtype(clss: ?*ir_type, subtype: ?*ir_type, pos: usize) void;
    pub extern fn remove_class_subtype(clss: ?*ir_type, subtype: ?*ir_type) void;
    pub extern fn add_class_supertype(clss: ?*ir_type, supertype: ?*ir_type) void;
    pub extern fn get_class_n_supertypes(clss: ?*const ir_type) usize;
    pub extern fn get_class_supertype_index(clss: ?*const ir_type, super_clss: ?*const ir_type) usize;
    pub extern fn get_class_supertype(clss: ?*const ir_type, pos: usize) ?*ir_type;
    pub extern fn set_class_supertype(clss: ?*ir_type, supertype: ?*ir_type, pos: usize) void;
    pub extern fn remove_class_supertype(clss: ?*ir_type, supertype: ?*ir_type) void;
    pub extern fn is_Class_type(clss: ?*const ir_type) i32;
    pub extern fn new_type_struct(name: [*]const u8) ?*ir_type;
    pub extern fn get_struct_n_members(strct: ?*const ir_type) usize;
    pub extern fn get_struct_member(strct: ?*const ir_type, pos: usize) ?*ir_entity;
    pub extern fn get_struct_member_index(strct: ?*const ir_type, member: ?*const ir_entity) usize;
    pub extern fn is_Struct_type(strct: ?*const ir_type) i32;
    pub extern fn new_type_union(name: [*]const u8) ?*ir_type;
    pub extern fn get_union_n_members(uni: ?*const ir_type) usize;
    pub extern fn get_union_member(uni: ?*const ir_type, pos: usize) ?*ir_entity;
    pub extern fn get_union_member_index(uni: ?*const ir_type, member: ?*const ir_entity) usize;
    pub extern fn is_Union_type(uni: ?*const ir_type) i32;
    pub extern fn new_type_method(n_param: usize, n_res: usize, is_variadic: i32, cc_mask: u32, property_mask: mtp_additional_properties) ?*ir_type;
    pub extern fn get_method_n_params(method: ?*const ir_type) usize;
    pub extern fn get_method_param_type(method: ?*const ir_type, pos: usize) ?*ir_type;
    pub extern fn set_method_param_type(method: ?*ir_type, pos: usize, tp: ?*ir_type) void;
    pub extern fn get_method_n_ress(method: ?*const ir_type) usize;
    pub extern fn get_method_res_type(method: ?*const ir_type, pos: usize) ?*ir_type;
    pub extern fn set_method_res_type(method: ?*ir_type, pos: usize, tp: ?*ir_type) void;
    pub extern fn is_method_variadic(method: ?*const ir_type) i32;
    pub extern fn get_method_additional_properties(method: ?*const ir_type) mtp_additional_properties;
    pub extern fn get_method_calling_convention(method: ?*const ir_type) u32;
    pub extern fn get_method_n_regparams(method: ?*ir_type) u32;
    pub extern fn is_Method_type(method: ?*const ir_type) i32;
    pub extern fn new_type_array(element_type: ?*ir_type, n_elements: u32) ?*ir_type;
    pub extern fn get_array_size(array: ?*const ir_type) u32;
    pub extern fn get_array_element_type(array: ?*const ir_type) ?*ir_type;
    pub extern fn is_Array_type(array: ?*const ir_type) i32;
    pub extern fn new_type_pointer(points_to: ?*ir_type) ?*ir_type;
    pub extern fn set_pointer_points_to_type(pointer: ?*ir_type, tp: ?*ir_type) void;
    pub extern fn get_pointer_points_to_type(pointer: ?*const ir_type) ?*ir_type;
    pub extern fn is_Pointer_type(pointer: ?*const ir_type) i32;
    pub extern fn new_type_primitive(mode: ?*ir_mode) ?*ir_type;
    pub extern fn is_Primitive_type(primitive: ?*const ir_type) i32;
    pub extern fn get_code_type() ?*ir_type;
    pub extern fn is_code_type(tp: ?*const ir_type) i32;
    pub extern fn get_unknown_type() ?*ir_type;
    pub extern fn is_unknown_type(@"type": ?*const ir_type) i32;
    pub extern fn is_atomic_type(tp: ?*const ir_type) i32;
    pub extern fn get_compound_ident(tp: ?*const ir_type) [*]const u8;
    pub extern fn get_compound_name(tp: ?*const ir_type) [*]const u8;
    pub extern fn get_compound_n_members(tp: ?*const ir_type) usize;
    pub extern fn get_compound_member(tp: ?*const ir_type, pos: usize) ?*ir_entity;
    pub extern fn get_compound_member_index(tp: ?*const ir_type, member: ?*const ir_entity) usize;
    pub extern fn remove_compound_member(compound: ?*ir_type, entity: ?*ir_entity) void;
    pub extern fn default_layout_compound_type(tp: ?*ir_type) void;
    pub extern fn is_compound_type(tp: ?*const ir_type) i32;
    pub extern fn new_type_frame() ?*ir_type;
    pub extern fn is_frame_type(tp: ?*const ir_type) i32;
    pub extern fn clone_frame_type(@"type": ?*ir_type) ?*ir_type;
    pub extern fn is_segment_type(tp: ?*const ir_type) i32;
    pub extern fn type_walk(pre: ?type_walk_func, post: ?type_walk_func, env: ?*anyopaque) void;
    pub extern fn type_walk_irg(irg: ?*ir_graph, pre: ?type_walk_func, post: ?type_walk_func, env: ?*anyopaque) void;
    pub extern fn type_walk_super2sub(pre: ?type_walk_func, post: ?type_walk_func, env: ?*anyopaque) void;
    pub extern fn type_walk_super(pre: ?type_walk_func, post: ?type_walk_func, env: ?*anyopaque) void;
    pub extern fn class_walk_super2sub(pre: ?class_walk_func, post: ?class_walk_func, env: ?*anyopaque) void;
    pub extern fn walk_types_entities(tp: ?*ir_type, doit: ?entity_walk_func, env: ?*anyopaque) void;
    pub extern fn get_method_param_access(ent: ?*ir_entity, pos: usize) ptr_access_kind;
    pub extern fn analyze_irg_args(irg: ?*ir_graph) void;
    pub extern fn get_method_param_weight(ent: ?*ir_entity, pos: usize) u32;
    pub extern fn analyze_irg_args_weight(irg: ?*ir_graph) void;
    pub extern fn new_int_mode(name: [*]const u8, bit_size: u32, sign: i32, modulo_shift: u32) ?*ir_mode;
    pub extern fn new_reference_mode(name: [*]const u8, bit_size: u32, modulo_shift: u32) ?*ir_mode;
    pub extern fn new_float_mode(name: [*]const u8, arithmetic: ir_mode_arithmetic, exponent_size: u32, mantissa_size: u32, int_conv_overflow: float_int_conversion_overflow_style_t) ?*ir_mode;
    pub extern fn new_non_arithmetic_mode(name: [*]const u8, bit_size: u32) ?*ir_mode;
    pub extern fn get_mode_ident(mode: ?*const ir_mode) [*]const u8;
    pub extern fn get_mode_name(mode: ?*const ir_mode) [*]const u8;
    pub extern fn get_mode_size_bits(mode: ?*const ir_mode) u32;
    pub extern fn get_mode_size_bytes(mode: ?*const ir_mode) u32;
    pub extern fn get_mode_arithmetic(mode: ?*const ir_mode) ir_mode_arithmetic;
    pub extern fn get_mode_modulo_shift(mode: ?*const ir_mode) u32;
    pub extern fn get_mode_min(mode: ?*const ir_mode) ?*ir_tarval;
    pub extern fn get_mode_max(mode: ?*const ir_mode) ?*ir_tarval;
    pub extern fn get_mode_null(mode: ?*const ir_mode) ?*ir_tarval;
    pub extern fn get_mode_one(mode: ?*const ir_mode) ?*ir_tarval;
    pub extern fn get_mode_all_one(mode: ?*const ir_mode) ?*ir_tarval;
    pub extern fn get_mode_infinite(mode: ?*const ir_mode) ?*ir_tarval;
    pub extern fn get_modeF() ?*ir_mode;
    pub extern fn get_modeD() ?*ir_mode;
    pub extern fn get_modeBs() ?*ir_mode;
    pub extern fn get_modeBu() ?*ir_mode;
    pub extern fn get_modeHs() ?*ir_mode;
    pub extern fn get_modeHu() ?*ir_mode;
    pub extern fn get_modeIs() ?*ir_mode;
    pub extern fn get_modeIu() ?*ir_mode;
    pub extern fn get_modeLs() ?*ir_mode;
    pub extern fn get_modeLu() ?*ir_mode;
    pub extern fn get_modeP() ?*ir_mode;
    pub extern fn get_modeb() ?*ir_mode;
    pub extern fn get_modeX() ?*ir_mode;
    pub extern fn get_modeBB() ?*ir_mode;
    pub extern fn get_modeM() ?*ir_mode;
    pub extern fn get_modeT() ?*ir_mode;
    pub extern fn get_modeANY() ?*ir_mode;
    pub extern fn get_modeBAD() ?*ir_mode;
    pub extern fn set_modeP(p: ?*ir_mode) void;
    pub extern fn mode_is_signed(mode: ?*const ir_mode) i32;
    pub extern fn mode_is_float(mode: ?*const ir_mode) i32;
    pub extern fn mode_is_int(mode: ?*const ir_mode) i32;
    pub extern fn mode_is_reference(mode: ?*const ir_mode) i32;
    pub extern fn mode_is_num(mode: ?*const ir_mode) i32;
    pub extern fn mode_is_data(mode: ?*const ir_mode) i32;
    pub extern fn smaller_mode(sm: ?*const ir_mode, lm: ?*const ir_mode) i32;
    pub extern fn values_in_mode(sm: ?*const ir_mode, lm: ?*const ir_mode) i32;
    pub extern fn find_unsigned_mode(mode: ?*const ir_mode) ?*ir_mode;
    pub extern fn find_signed_mode(mode: ?*const ir_mode) ?*ir_mode;
    pub extern fn find_double_bits_int_mode(mode: ?*const ir_mode) ?*ir_mode;
    pub extern fn mode_has_signed_zero(mode: ?*const ir_mode) i32;
    pub extern fn mode_overflow_on_unary_Minus(mode: ?*const ir_mode) i32;
    pub extern fn mode_wrap_around(mode: ?*const ir_mode) i32;
    pub extern fn get_reference_offset_mode(mode: ?*const ir_mode) ?*ir_mode;
    pub extern fn set_reference_offset_mode(ref_mode: ?*ir_mode, int_mode: ?*ir_mode) void;
    pub extern fn get_mode_mantissa_size(mode: ?*const ir_mode) u32;
    pub extern fn get_mode_exponent_size(mode: ?*const ir_mode) u32;
    pub extern fn get_mode_float_int_overflow(mode: ?*const ir_mode) float_int_conversion_overflow_style_t;
    pub extern fn is_reinterpret_cast(src: ?*const ir_mode, dst: ?*const ir_mode) i32;
    pub extern fn get_type_for_mode(mode: ?*const ir_mode) ?*ir_type;
    pub extern fn ir_get_n_modes() usize;
    pub extern fn ir_get_mode(num: usize) ?*ir_mode;
    pub extern fn optimize_cf(irg: ?*ir_graph) void;
    pub extern fn opt_jumpthreading(irg: ?*ir_graph) void;
    pub extern fn opt_bool(irg: ?*ir_graph) void;
    pub extern fn conv_opt(irg: ?*ir_graph) void;
    pub extern fn optimize_funccalls() void;
    pub extern fn do_gvn_pre(irg: ?*ir_graph) void;
    pub extern fn opt_if_conv(irg: ?*ir_graph) void;
    pub extern fn opt_if_conv_cb(irg: ?*ir_graph, callback: arch_allow_ifconv_func) void;
    pub extern fn opt_parallelize_mem(irg: ?*ir_graph) void;
    pub extern fn can_replace_load_by_const(load: ?*const ir_node, c: ?*ir_node) ?*ir_node;
    pub extern fn optimize_load_store(irg: ?*ir_graph) void;
    pub extern fn combine_memops(irg: ?*ir_graph) void;
    pub extern fn opt_ldst(irg: ?*ir_graph) void;
    pub extern fn opt_frame_irg(irg: ?*ir_graph) void;
    pub extern fn opt_osr(irg: ?*ir_graph, flags: u32) void;
    pub extern fn remove_phi_cycles(irg: ?*ir_graph) void;
    pub extern fn proc_cloning(threshold: f32) void;
    pub extern fn optimize_reassociation(irg: ?*ir_graph) void;
    pub extern fn normalize_one_return(irg: ?*ir_graph) void;
    pub extern fn normalize_n_returns(irg: ?*ir_graph) void;
    pub extern fn scalar_replacement_opt(irg: ?*ir_graph) void;
    pub extern fn opt_tail_rec_irg(irg: ?*ir_graph) void;
    pub extern fn combo(irg: ?*ir_graph) void;
    pub extern fn inline_functions(maxsize: u32, inline_threshold: i32, after_inline_opt: opt_ptr) void;
    pub extern fn shape_blocks(irg: ?*ir_graph) void;
    pub extern fn do_loop_inversion(irg: ?*ir_graph) void;
    pub extern fn do_loop_unrolling(irg: ?*ir_graph) void;
    pub extern fn unroll_loops(irg: ?*ir_graph, factor: u32, maxsize: u32) void;
    pub extern fn do_loop_peeling(irg: ?*ir_graph) void;
    pub extern fn garbage_collect_entities() void;
    pub extern fn dead_node_elimination(irg: ?*ir_graph) void;
    pub extern fn place_code(irg: ?*ir_graph) void;
    pub extern fn occult_consts(irg: ?*ir_graph) void;
    pub extern fn value_not_null(n: ?*const ir_node, confirm: [*]?*const ir_node) i32;
    pub extern fn computed_value_Cmp_Confirm(left: ?*ir_node, right: ?*ir_node, relation: ir_relation) ?*ir_tarval;
    pub extern fn create_compilerlib_entity(name: [*]const u8, mt: ?*ir_type) ?*ir_entity;
    pub extern fn be_lower_for_target() void;
    pub extern fn be_set_after_transform_func(func: after_transform_func) void;
    pub extern fn be_main(output: *std.c.FILE, compilation_unit_name: [*]const u8) void;
    pub extern fn be_parse_asm_constraints(constraints: [*]const u8) asm_constraint_flags_t;
    pub extern fn be_is_valid_clobber(clobber: [*]const u8) i32;
    pub extern fn be_dwarf_set_source_language(language: dwarf_source_language) void;
    pub extern fn be_dwarf_set_compilation_directory(directory: [*]const u8) void;
    pub extern fn get_irp_callgraph_state() irp_callgraph_state;
    pub extern fn set_irp_callgraph_state(s: irp_callgraph_state) void;
    pub extern fn get_irg_n_callers(irg: ?*const ir_graph) usize;
    pub extern fn get_irg_caller(irg: ?*const ir_graph, pos: usize) ?*ir_graph;
    pub extern fn is_irg_caller_backedge(irg: ?*const ir_graph, pos: usize) i32;
    pub extern fn has_irg_caller_backedge(irg: ?*const ir_graph) i32;
    pub extern fn get_irg_caller_loop_depth(irg: ?*const ir_graph, pos: usize) usize;
    pub extern fn get_irg_n_callees(irg: ?*const ir_graph) usize;
    pub extern fn get_irg_callee(irg: ?*const ir_graph, pos: usize) ?*ir_graph;
    pub extern fn is_irg_callee_backedge(irg: ?*const ir_graph, pos: usize) i32;
    pub extern fn has_irg_callee_backedge(irg: ?*const ir_graph) i32;
    pub extern fn get_irg_callee_loop_depth(irg: ?*const ir_graph, pos: usize) usize;
    pub extern fn get_irg_method_execution_frequency(irg: ?*const ir_graph) f64;
    pub extern fn compute_callgraph() void;
    pub extern fn free_callgraph() void;
    pub extern fn callgraph_walk(pre: ?callgraph_walk_func, post: ?callgraph_walk_func, env: ?*anyopaque) void;
    pub extern fn find_callgraph_recursions() void;
    pub extern fn analyse_loop_nesting_depth() void;
    pub extern fn get_irp_loop_nesting_depth_state() loop_nesting_depth_state;
    pub extern fn set_irp_loop_nesting_depth_state(s: loop_nesting_depth_state) void;
    pub extern fn set_irp_loop_nesting_depth_state_inconsistent() void;
    pub extern fn compute_cdep(irg: ?*ir_graph) void;
    pub extern fn free_cdep(irg: ?*ir_graph) void;
    pub extern fn get_cdep_node(cdep: ?*const ir_cdep) ?*ir_node;
    pub extern fn get_cdep_next(cdep: ?*const ir_cdep) ?*ir_cdep;
    pub extern fn find_cdep(block: ?*const ir_node) ?*ir_cdep;
    pub extern fn exchange_cdep(old: ?*ir_node, nw: ?*const ir_node) void;
    pub extern fn is_cdep_on(dependee: ?*const ir_node, candidate: ?*const ir_node) i32;
    pub extern fn get_unique_cdep(block: ?*const ir_node) ?*ir_node;
    pub extern fn has_multiple_cdep(block: ?*const ir_node) i32;
    pub extern fn cgana(free_methods: [*][*]?*ir_entity) usize;
    pub extern fn free_callee_info(irg: ?*ir_graph) void;
    pub extern fn free_irp_callee_info() void;
    pub extern fn opt_call_addrs() void;
    pub extern fn cg_call_has_callees(node: ?*const ir_node) i32;
    pub extern fn cg_get_call_n_callees(node: ?*const ir_node) usize;
    pub extern fn cg_get_call_callee(node: ?*const ir_node, pos: usize) ?*ir_entity;
    pub extern fn cg_set_call_callee_arr(node: ?*ir_node, n: usize, arr: [*]?*ir_entity) void;
    pub extern fn cg_remove_call_callee_arr(node: ?*ir_node) void;
    pub extern fn dbg_action_2_str(a: dbg_action) [*]const u8;
    pub extern fn dbg_init(dbg_info_merge_pair: ?merge_pair_func, dbg_info_merge_sets: ?merge_sets_func) void;
    pub extern fn ir_set_debug_retrieve(func: retrieve_dbg_func) void;
    pub extern fn ir_set_type_debug_retrieve(func: retrieve_type_dbg_func) void;
    pub extern fn ir_retrieve_dbg_info(dbg: ?*const dbg_info) src_loc_t;
    pub extern fn ir_retrieve_type_dbg_info(buffer: [*]u8, buffer_size: usize, tdbgi: ?*const type_dbg_info) void;
    pub extern fn ir_estimate_execfreq(irg: ?*ir_graph) void;
    pub extern fn get_block_execfreq(block: ?*const ir_node) f64;
    pub extern fn ir_init() void;
    pub extern fn ir_init_library() void;
    pub extern fn ir_finish() void;
    pub extern fn ir_get_version_major() u32;
    pub extern fn ir_get_version_minor() u32;
    pub extern fn ir_get_version_micro() u32;
    pub extern fn ir_get_version_revision() [*]const u8;
    pub extern fn ir_get_version_build() [*]const u8;
    pub extern fn get_kind(firm_thing: ?*const anyopaque) firm_kind;
    pub extern fn get_irn_height(h: ?*const ir_heights_t, irn: ?*const ir_node) u32;
    pub extern fn heights_reachable_in_block(h: ?*ir_heights_t, src: ?*const ir_node, tgt: ?*const ir_node) i32;
    pub extern fn heights_recompute_block(h: ?*ir_heights_t, block: ?*ir_node) u32;
    pub extern fn heights_new(irg: ?*ir_graph) ?*ir_heights_t;
    pub extern fn heights_free(h: ?*ir_heights_t) void;
    pub extern fn new_id_from_str(str: [*]const u8) [*]const u8;
    pub extern fn new_id_from_chars(str: [*]const u8, len: usize) [*]const u8;
    pub extern fn new_id_fmt(fmt: [*]const u8, ...) [*]const u8;
    pub extern fn get_id_str(id: [*]const u8) [*]const u8;
    pub extern fn id_unique(tag: [*]const u8) [*]const u8;
    pub extern fn gc_irgs(n_keep: usize, keep_arr: [*]?*ir_entity) void;
    pub extern fn get_op_name(op: ?*const ir_op) [*]const u8;
    pub extern fn get_op_code(op: ?*const ir_op) u32;
    pub extern fn get_op_pin_state_name(s: op_pin_state) [*]const u8;
    pub extern fn get_op_pinned(op: ?*const ir_op) op_pin_state;
    pub extern fn get_next_ir_opcode() u32;
    pub extern fn get_next_ir_opcodes(num: u32) u32;
    pub extern fn get_generic_function_ptr(op: ?*const ir_op) op_func;
    pub extern fn set_generic_function_ptr(op: ?*ir_op, func: op_func) void;
    pub extern fn get_op_flags(op: ?*const ir_op) irop_flags;
    pub extern fn set_op_hash(op: ?*ir_op, func: hash_func) void;
    pub extern fn set_op_computed_value(op: ?*ir_op, func: computed_value_func) void;
    pub extern fn set_op_computed_value_proj(op: ?*ir_op, func: computed_value_func) void;
    pub extern fn set_op_equivalent_node(op: ?*ir_op, func: equivalent_node_func) void;
    pub extern fn set_op_equivalent_node_proj(op: ?*ir_op, func: equivalent_node_func) void;
    pub extern fn set_op_transform_node(op: ?*ir_op, func: transform_node_func) void;
    pub extern fn set_op_transform_node_proj(op: ?*ir_op, func: transform_node_func) void;
    pub extern fn set_op_attrs_equal(op: ?*ir_op, func: node_attrs_equal_func) void;
    pub extern fn set_op_reassociate(op: ?*ir_op, func: reassociate_func) void;
    pub extern fn set_op_copy_attr(op: ?*ir_op, func: copy_attr_func) void;
    pub extern fn set_op_get_type_attr(op: ?*ir_op, func: get_type_attr_func) void;
    pub extern fn set_op_get_entity_attr(op: ?*ir_op, func: get_entity_attr_func) void;
    pub extern fn set_op_verify(op: ?*ir_op, func: verify_node_func) void;
    pub extern fn set_op_verify_proj(op: ?*ir_op, func: verify_proj_node_func) void;
    pub extern fn set_op_dump(op: ?*ir_op, func: dump_node_func) void;
    pub extern fn new_ir_op(code: u32, name: [*]const u8, p: op_pin_state, flags: irop_flags, opar: op_arity, op_index: i32, attr_size: usize) ?*ir_op;
    pub extern fn free_ir_op(code: ?*ir_op) void;
    pub extern fn ir_get_n_opcodes() u32;
    pub extern fn ir_get_opcode(code: u32) ?*ir_op;
    pub extern fn ir_clear_opcodes_generic_func() void;
    pub extern fn ir_op_set_memory_index(op: ?*ir_op, memory_index: i32) void;
    pub extern fn ir_op_set_fragile_indices(op: ?*ir_op, pn_x_regular: u32, pn_x_except: u32) void;
    pub extern fn new_rd_ASM(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, text: [*]const u8, n_constraints: usize, constraints: [*]ir_asm_constraint, n_clobbers: usize, clobbers: [*][*]const u8, flags: ir_cons_flags) ?*ir_node;
    pub extern fn new_r_ASM(block: ?*ir_node, irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, text: [*]const u8, n_constraints: usize, constraints: [*]ir_asm_constraint, n_clobbers: usize, clobbers: [*][*]const u8, flags: ir_cons_flags) ?*ir_node;
    pub extern fn new_d_ASM(dbgi: ?*dbg_info, irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, text: [*]const u8, n_constraints: usize, constraints: [*]ir_asm_constraint, n_clobbers: usize, clobbers: [*][*]const u8, flags: ir_cons_flags) ?*ir_node;
    pub extern fn new_ASM(irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, text: [*]const u8, n_constraints: usize, constraints: [*]ir_asm_constraint, n_clobbers: usize, clobbers: [*][*]const u8, flags: ir_cons_flags) ?*ir_node;
    pub extern fn is_ASM(node: ?*const ir_node) i32;
    pub extern fn get_ASM_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_ASM_mem(node: ?*ir_node, mem: ?*ir_node) void;
    pub extern fn get_ASM_n_inputs(node: ?*const ir_node) i32;
    pub extern fn get_ASM_input(node: ?*const ir_node, pos: i32) ?*ir_node;
    pub extern fn set_ASM_input(node: ?*ir_node, pos: i32, input: ?*ir_node) void;
    pub extern fn get_ASM_input_arr(node: ?*ir_node) [*]?*ir_node;
    pub extern fn get_ASM_constraints(node: ?*const ir_node) [*]ir_asm_constraint;
    pub extern fn set_ASM_constraints(node: ?*ir_node, constraints: [*]ir_asm_constraint) void;
    pub extern fn get_ASM_clobbers(node: ?*const ir_node) [*][*]const u8;
    pub extern fn set_ASM_clobbers(node: ?*ir_node, clobbers: [*][*]const u8) void;
    pub extern fn get_ASM_text(node: ?*const ir_node) [*]const u8;
    pub extern fn set_ASM_text(node: ?*ir_node, text: [*]const u8) void;
    pub extern fn get_op_ASM() ?*ir_op;
    pub extern fn new_rd_Add(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Add(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Add(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_Add(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn is_Add(node: ?*const ir_node) i32;
    pub extern fn get_Add_left(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Add_left(node: ?*ir_node, left: ?*ir_node) void;
    pub extern fn get_Add_right(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Add_right(node: ?*ir_node, right: ?*ir_node) void;
    pub extern fn get_op_Add() ?*ir_op;
    pub extern fn new_rd_Address(dbgi: ?*dbg_info, irg: ?*ir_graph, entity: ?*ir_entity) ?*ir_node;
    pub extern fn new_r_Address(irg: ?*ir_graph, entity: ?*ir_entity) ?*ir_node;
    pub extern fn new_d_Address(dbgi: ?*dbg_info, entity: ?*ir_entity) ?*ir_node;
    pub extern fn new_Address(entity: ?*ir_entity) ?*ir_node;
    pub extern fn is_Address(node: ?*const ir_node) i32;
    pub extern fn get_Address_entity(node: ?*const ir_node) ?*ir_entity;
    pub extern fn set_Address_entity(node: ?*ir_node, entity: ?*ir_entity) void;
    pub extern fn get_op_Address() ?*ir_op;
    pub extern fn new_rd_Align(dbgi: ?*dbg_info, irg: ?*ir_graph, mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_r_Align(irg: ?*ir_graph, mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_d_Align(dbgi: ?*dbg_info, mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_Align(mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node;
    pub extern fn is_Align(node: ?*const ir_node) i32;
    pub extern fn get_Align_type(node: ?*const ir_node) ?*ir_type;
    pub extern fn set_Align_type(node: ?*ir_node, @"type": ?*ir_type) void;
    pub extern fn get_op_Align() ?*ir_op;
    pub extern fn new_rd_Alloc(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_size: ?*ir_node, alignment: u32) ?*ir_node;
    pub extern fn new_r_Alloc(block: ?*ir_node, irn_mem: ?*ir_node, irn_size: ?*ir_node, alignment: u32) ?*ir_node;
    pub extern fn new_d_Alloc(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_size: ?*ir_node, alignment: u32) ?*ir_node;
    pub extern fn new_Alloc(irn_mem: ?*ir_node, irn_size: ?*ir_node, alignment: u32) ?*ir_node;
    pub extern fn is_Alloc(node: ?*const ir_node) i32;
    pub extern fn get_Alloc_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Alloc_mem(node: ?*ir_node, mem: ?*ir_node) void;
    pub extern fn get_Alloc_size(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Alloc_size(node: ?*ir_node, size: ?*ir_node) void;
    pub extern fn get_Alloc_alignment(node: ?*const ir_node) u32;
    pub extern fn set_Alloc_alignment(node: ?*ir_node, alignment: u32) void;
    pub extern fn get_op_Alloc() ?*ir_op;
    pub extern fn is_Anchor(node: ?*const ir_node) i32;
    pub extern fn get_Anchor_end_block(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Anchor_end_block(node: ?*ir_node, end_block: ?*ir_node) void;
    pub extern fn get_Anchor_start_block(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Anchor_start_block(node: ?*ir_node, start_block: ?*ir_node) void;
    pub extern fn get_Anchor_end(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Anchor_end(node: ?*ir_node, end: ?*ir_node) void;
    pub extern fn get_Anchor_start(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Anchor_start(node: ?*ir_node, start: ?*ir_node) void;
    pub extern fn get_Anchor_frame(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Anchor_frame(node: ?*ir_node, frame: ?*ir_node) void;
    pub extern fn get_Anchor_initial_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Anchor_initial_mem(node: ?*ir_node, initial_mem: ?*ir_node) void;
    pub extern fn get_Anchor_args(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Anchor_args(node: ?*ir_node, args: ?*ir_node) void;
    pub extern fn get_Anchor_no_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Anchor_no_mem(node: ?*ir_node, no_mem: ?*ir_node) void;
    pub extern fn get_op_Anchor() ?*ir_op;
    pub extern fn new_rd_And(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_r_And(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_d_And(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_And(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn is_And(node: ?*const ir_node) i32;
    pub extern fn get_And_left(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_And_left(node: ?*ir_node, left: ?*ir_node) void;
    pub extern fn get_And_right(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_And_right(node: ?*ir_node, right: ?*ir_node) void;
    pub extern fn get_op_And() ?*ir_op;
    pub extern fn new_rd_Bad(dbgi: ?*dbg_info, irg: ?*ir_graph, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_r_Bad(irg: ?*ir_graph, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_d_Bad(dbgi: ?*dbg_info, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_Bad(mode: ?*ir_mode) ?*ir_node;
    pub extern fn is_Bad(node: ?*const ir_node) i32;
    pub extern fn get_op_Bad() ?*ir_op;
    pub extern fn new_rd_Bitcast(dbgi: ?*dbg_info, block: ?*ir_node, irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_r_Bitcast(block: ?*ir_node, irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_d_Bitcast(dbgi: ?*dbg_info, irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_Bitcast(irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node;
    pub extern fn is_Bitcast(node: ?*const ir_node) i32;
    pub extern fn get_Bitcast_op(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Bitcast_op(node: ?*ir_node, op: ?*ir_node) void;
    pub extern fn get_op_Bitcast() ?*ir_op;
    pub extern fn new_rd_Block(dbgi: ?*dbg_info, irg: ?*ir_graph, arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn new_r_Block(irg: ?*ir_graph, arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn new_d_Block(dbgi: ?*dbg_info, arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn new_Block(arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn is_Block(node: ?*const ir_node) i32;
    pub extern fn get_Block_n_cfgpreds(node: ?*const ir_node) i32;
    pub extern fn get_Block_cfgpred(node: ?*const ir_node, pos: i32) ?*ir_node;
    pub extern fn set_Block_cfgpred(node: ?*ir_node, pos: i32, cfgpred: ?*ir_node) void;
    pub extern fn get_Block_cfgpred_arr(node: ?*ir_node) [*]?*ir_node;
    pub extern fn get_Block_entity(node: ?*const ir_node) ?*ir_entity;
    pub extern fn set_Block_entity(node: ?*ir_node, entity: ?*ir_entity) void;
    pub extern fn get_op_Block() ?*ir_op;
    pub extern fn new_rd_Builtin(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, kind: ir_builtin_kind, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_r_Builtin(block: ?*ir_node, irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, kind: ir_builtin_kind, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_d_Builtin(dbgi: ?*dbg_info, irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, kind: ir_builtin_kind, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_Builtin(irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, kind: ir_builtin_kind, @"type": ?*ir_type) ?*ir_node;
    pub extern fn is_Builtin(node: ?*const ir_node) i32;
    pub extern fn get_Builtin_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Builtin_mem(node: ?*ir_node, mem: ?*ir_node) void;
    pub extern fn get_Builtin_n_params(node: ?*const ir_node) i32;
    pub extern fn get_Builtin_param(node: ?*const ir_node, pos: i32) ?*ir_node;
    pub extern fn set_Builtin_param(node: ?*ir_node, pos: i32, param: ?*ir_node) void;
    pub extern fn get_Builtin_param_arr(node: ?*ir_node) [*]?*ir_node;
    pub extern fn get_Builtin_kind(node: ?*const ir_node) ir_builtin_kind;
    pub extern fn set_Builtin_kind(node: ?*ir_node, kind: ir_builtin_kind) void;
    pub extern fn get_Builtin_type(node: ?*const ir_node) ?*ir_type;
    pub extern fn set_Builtin_type(node: ?*ir_node, @"type": ?*ir_type) void;
    pub extern fn get_op_Builtin() ?*ir_op;
    pub extern fn new_rd_Call(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, arity: i32, in: ?[*]const ?*ir_node, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_r_Call(block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, arity: i32, in: ?[*]const ?*ir_node, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_d_Call(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, arity: i32, in: ?[*]const ?*ir_node, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_Call(irn_mem: ?*ir_node, irn_ptr: ?*ir_node, arity: i32, in: ?[*]const ?*ir_node, @"type": ?*ir_type) ?*ir_node;
    pub extern fn is_Call(node: ?*const ir_node) i32;
    pub extern fn get_Call_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Call_mem(node: ?*ir_node, mem: ?*ir_node) void;
    pub extern fn get_Call_ptr(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Call_ptr(node: ?*ir_node, ptr: ?*ir_node) void;
    pub extern fn get_Call_n_params(node: ?*const ir_node) i32;
    pub extern fn get_Call_param(node: ?*const ir_node, pos: i32) ?*ir_node;
    pub extern fn set_Call_param(node: ?*ir_node, pos: i32, param: ?*ir_node) void;
    pub extern fn get_Call_param_arr(node: ?*ir_node) [*]?*ir_node;
    pub extern fn get_Call_type(node: ?*const ir_node) ?*ir_type;
    pub extern fn set_Call_type(node: ?*ir_node, @"type": ?*ir_type) void;
    pub extern fn get_op_Call() ?*ir_op;
    pub extern fn new_rd_Cmp(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, relation: ir_relation) ?*ir_node;
    pub extern fn new_r_Cmp(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, relation: ir_relation) ?*ir_node;
    pub extern fn new_d_Cmp(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node, relation: ir_relation) ?*ir_node;
    pub extern fn new_Cmp(irn_left: ?*ir_node, irn_right: ?*ir_node, relation: ir_relation) ?*ir_node;
    pub extern fn is_Cmp(node: ?*const ir_node) i32;
    pub extern fn get_Cmp_left(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Cmp_left(node: ?*ir_node, left: ?*ir_node) void;
    pub extern fn get_Cmp_right(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Cmp_right(node: ?*ir_node, right: ?*ir_node) void;
    pub extern fn get_Cmp_relation(node: ?*const ir_node) ir_relation;
    pub extern fn set_Cmp_relation(node: ?*ir_node, relation: ir_relation) void;
    pub extern fn get_op_Cmp() ?*ir_op;
    pub extern fn new_rd_Cond(dbgi: ?*dbg_info, block: ?*ir_node, irn_selector: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Cond(block: ?*ir_node, irn_selector: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Cond(dbgi: ?*dbg_info, irn_selector: ?*ir_node) ?*ir_node;
    pub extern fn new_Cond(irn_selector: ?*ir_node) ?*ir_node;
    pub extern fn is_Cond(node: ?*const ir_node) i32;
    pub extern fn get_Cond_selector(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Cond_selector(node: ?*ir_node, selector: ?*ir_node) void;
    pub extern fn get_Cond_jmp_pred(node: ?*const ir_node) cond_jmp_predicate;
    pub extern fn set_Cond_jmp_pred(node: ?*ir_node, jmp_pred: cond_jmp_predicate) void;
    pub extern fn get_op_Cond() ?*ir_op;
    pub extern fn new_rd_Confirm(dbgi: ?*dbg_info, block: ?*ir_node, irn_value: ?*ir_node, irn_bound: ?*ir_node, relation: ir_relation) ?*ir_node;
    pub extern fn new_r_Confirm(block: ?*ir_node, irn_value: ?*ir_node, irn_bound: ?*ir_node, relation: ir_relation) ?*ir_node;
    pub extern fn new_d_Confirm(dbgi: ?*dbg_info, irn_value: ?*ir_node, irn_bound: ?*ir_node, relation: ir_relation) ?*ir_node;
    pub extern fn new_Confirm(irn_value: ?*ir_node, irn_bound: ?*ir_node, relation: ir_relation) ?*ir_node;
    pub extern fn is_Confirm(node: ?*const ir_node) i32;
    pub extern fn get_Confirm_value(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Confirm_value(node: ?*ir_node, value: ?*ir_node) void;
    pub extern fn get_Confirm_bound(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Confirm_bound(node: ?*ir_node, bound: ?*ir_node) void;
    pub extern fn get_Confirm_relation(node: ?*const ir_node) ir_relation;
    pub extern fn set_Confirm_relation(node: ?*ir_node, relation: ir_relation) void;
    pub extern fn get_op_Confirm() ?*ir_op;
    pub extern fn new_rd_Const(dbgi: ?*dbg_info, irg: ?*ir_graph, tarval: ?*ir_tarval) ?*ir_node;
    pub extern fn new_r_Const(irg: ?*ir_graph, tarval: ?*ir_tarval) ?*ir_node;
    pub extern fn new_d_Const(dbgi: ?*dbg_info, tarval: ?*ir_tarval) ?*ir_node;
    pub extern fn new_Const(tarval: ?*ir_tarval) ?*ir_node;
    pub extern fn is_Const(node: ?*const ir_node) i32;
    pub extern fn get_Const_tarval(node: ?*const ir_node) ?*ir_tarval;
    pub extern fn set_Const_tarval(node: ?*ir_node, tarval: ?*ir_tarval) void;
    pub extern fn get_op_Const() ?*ir_op;
    pub extern fn new_rd_Conv(dbgi: ?*dbg_info, block: ?*ir_node, irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_r_Conv(block: ?*ir_node, irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_d_Conv(dbgi: ?*dbg_info, irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_Conv(irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node;
    pub extern fn is_Conv(node: ?*const ir_node) i32;
    pub extern fn get_Conv_op(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Conv_op(node: ?*ir_node, op: ?*ir_node) void;
    pub extern fn get_op_Conv() ?*ir_op;
    pub extern fn new_rd_CopyB(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_dst: ?*ir_node, irn_src: ?*ir_node, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node;
    pub extern fn new_r_CopyB(block: ?*ir_node, irn_mem: ?*ir_node, irn_dst: ?*ir_node, irn_src: ?*ir_node, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node;
    pub extern fn new_d_CopyB(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_dst: ?*ir_node, irn_src: ?*ir_node, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node;
    pub extern fn new_CopyB(irn_mem: ?*ir_node, irn_dst: ?*ir_node, irn_src: ?*ir_node, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node;
    pub extern fn is_CopyB(node: ?*const ir_node) i32;
    pub extern fn get_CopyB_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_CopyB_mem(node: ?*ir_node, mem: ?*ir_node) void;
    pub extern fn get_CopyB_dst(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_CopyB_dst(node: ?*ir_node, dst: ?*ir_node) void;
    pub extern fn get_CopyB_src(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_CopyB_src(node: ?*ir_node, src: ?*ir_node) void;
    pub extern fn get_CopyB_type(node: ?*const ir_node) ?*ir_type;
    pub extern fn set_CopyB_type(node: ?*ir_node, @"type": ?*ir_type) void;
    pub extern fn get_CopyB_volatility(node: ?*const ir_node) ir_volatility;
    pub extern fn set_CopyB_volatility(node: ?*ir_node, volatility: ir_volatility) void;
    pub extern fn get_op_CopyB() ?*ir_op;
    pub extern fn is_Deleted(node: ?*const ir_node) i32;
    pub extern fn get_op_Deleted() ?*ir_op;
    pub extern fn new_rd_Div(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node;
    pub extern fn new_r_Div(block: ?*ir_node, irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node;
    pub extern fn new_d_Div(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node;
    pub extern fn new_Div(irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node;
    pub extern fn is_Div(node: ?*const ir_node) i32;
    pub extern fn get_Div_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Div_mem(node: ?*ir_node, mem: ?*ir_node) void;
    pub extern fn get_Div_left(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Div_left(node: ?*ir_node, left: ?*ir_node) void;
    pub extern fn get_Div_right(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Div_right(node: ?*ir_node, right: ?*ir_node) void;
    pub extern fn get_Div_resmode(node: ?*const ir_node) ?*ir_mode;
    pub extern fn set_Div_resmode(node: ?*ir_node, resmode: ?*ir_mode) void;
    pub extern fn get_Div_no_remainder(node: ?*const ir_node) i32;
    pub extern fn set_Div_no_remainder(node: ?*ir_node, no_remainder: i32) void;
    pub extern fn get_op_Div() ?*ir_op;
    pub extern fn new_rd_Dummy(dbgi: ?*dbg_info, irg: ?*ir_graph, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_r_Dummy(irg: ?*ir_graph, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_d_Dummy(dbgi: ?*dbg_info, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_Dummy(mode: ?*ir_mode) ?*ir_node;
    pub extern fn is_Dummy(node: ?*const ir_node) i32;
    pub extern fn get_op_Dummy() ?*ir_op;
    pub extern fn new_rd_End(dbgi: ?*dbg_info, irg: ?*ir_graph, arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn new_r_End(irg: ?*ir_graph, arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn new_d_End(dbgi: ?*dbg_info, arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn new_End(arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn is_End(node: ?*const ir_node) i32;
    pub extern fn get_End_n_keepalives(node: ?*const ir_node) i32;
    pub extern fn get_End_keepalive(node: ?*const ir_node, pos: i32) ?*ir_node;
    pub extern fn set_End_keepalive(node: ?*ir_node, pos: i32, keepalive: ?*ir_node) void;
    pub extern fn get_End_keepalive_arr(node: ?*ir_node) [*]?*ir_node;
    pub extern fn get_op_End() ?*ir_op;
    pub extern fn new_rd_Eor(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Eor(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Eor(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_Eor(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn is_Eor(node: ?*const ir_node) i32;
    pub extern fn get_Eor_left(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Eor_left(node: ?*ir_node, left: ?*ir_node) void;
    pub extern fn get_Eor_right(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Eor_right(node: ?*ir_node, right: ?*ir_node) void;
    pub extern fn get_op_Eor() ?*ir_op;
    pub extern fn new_rd_Free(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Free(block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Free(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_ptr: ?*ir_node) ?*ir_node;
    pub extern fn new_Free(irn_mem: ?*ir_node, irn_ptr: ?*ir_node) ?*ir_node;
    pub extern fn is_Free(node: ?*const ir_node) i32;
    pub extern fn get_Free_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Free_mem(node: ?*ir_node, mem: ?*ir_node) void;
    pub extern fn get_Free_ptr(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Free_ptr(node: ?*ir_node, ptr: ?*ir_node) void;
    pub extern fn get_op_Free() ?*ir_op;
    pub extern fn new_rd_IJmp(dbgi: ?*dbg_info, block: ?*ir_node, irn_target: ?*ir_node) ?*ir_node;
    pub extern fn new_r_IJmp(block: ?*ir_node, irn_target: ?*ir_node) ?*ir_node;
    pub extern fn new_d_IJmp(dbgi: ?*dbg_info, irn_target: ?*ir_node) ?*ir_node;
    pub extern fn new_IJmp(irn_target: ?*ir_node) ?*ir_node;
    pub extern fn is_IJmp(node: ?*const ir_node) i32;
    pub extern fn get_IJmp_target(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_IJmp_target(node: ?*ir_node, target: ?*ir_node) void;
    pub extern fn get_op_IJmp() ?*ir_op;
    pub extern fn is_Id(node: ?*const ir_node) i32;
    pub extern fn get_Id_pred(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Id_pred(node: ?*ir_node, pred: ?*ir_node) void;
    pub extern fn get_op_Id() ?*ir_op;
    pub extern fn new_rd_Jmp(dbgi: ?*dbg_info, block: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Jmp(block: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Jmp(dbgi: ?*dbg_info) ?*ir_node;
    pub extern fn new_Jmp() ?*ir_node;
    pub extern fn is_Jmp(node: ?*const ir_node) i32;
    pub extern fn get_op_Jmp() ?*ir_op;
    pub extern fn new_rd_Load(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, mode: ?*ir_mode, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node;
    pub extern fn new_r_Load(block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, mode: ?*ir_mode, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node;
    pub extern fn new_d_Load(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, mode: ?*ir_mode, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node;
    pub extern fn new_Load(irn_mem: ?*ir_node, irn_ptr: ?*ir_node, mode: ?*ir_mode, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node;
    pub extern fn is_Load(node: ?*const ir_node) i32;
    pub extern fn get_Load_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Load_mem(node: ?*ir_node, mem: ?*ir_node) void;
    pub extern fn get_Load_ptr(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Load_ptr(node: ?*ir_node, ptr: ?*ir_node) void;
    pub extern fn get_Load_mode(node: ?*const ir_node) ?*ir_mode;
    pub extern fn set_Load_mode(node: ?*ir_node, mode: ?*ir_mode) void;
    pub extern fn get_Load_type(node: ?*const ir_node) ?*ir_type;
    pub extern fn set_Load_type(node: ?*ir_node, @"type": ?*ir_type) void;
    pub extern fn get_Load_volatility(node: ?*const ir_node) ir_volatility;
    pub extern fn set_Load_volatility(node: ?*ir_node, volatility: ir_volatility) void;
    pub extern fn get_Load_unaligned(node: ?*const ir_node) ir_align;
    pub extern fn set_Load_unaligned(node: ?*ir_node, unaligned: ir_align) void;
    pub extern fn get_op_Load() ?*ir_op;
    pub extern fn new_rd_Member(dbgi: ?*dbg_info, block: ?*ir_node, irn_ptr: ?*ir_node, entity: ?*ir_entity) ?*ir_node;
    pub extern fn new_r_Member(block: ?*ir_node, irn_ptr: ?*ir_node, entity: ?*ir_entity) ?*ir_node;
    pub extern fn new_d_Member(dbgi: ?*dbg_info, irn_ptr: ?*ir_node, entity: ?*ir_entity) ?*ir_node;
    pub extern fn new_Member(irn_ptr: ?*ir_node, entity: ?*ir_entity) ?*ir_node;
    pub extern fn is_Member(node: ?*const ir_node) i32;
    pub extern fn get_Member_ptr(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Member_ptr(node: ?*ir_node, ptr: ?*ir_node) void;
    pub extern fn get_Member_entity(node: ?*const ir_node) ?*ir_entity;
    pub extern fn set_Member_entity(node: ?*ir_node, entity: ?*ir_entity) void;
    pub extern fn get_op_Member() ?*ir_op;
    pub extern fn new_rd_Minus(dbgi: ?*dbg_info, block: ?*ir_node, irn_op: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Minus(block: ?*ir_node, irn_op: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Minus(dbgi: ?*dbg_info, irn_op: ?*ir_node) ?*ir_node;
    pub extern fn new_Minus(irn_op: ?*ir_node) ?*ir_node;
    pub extern fn is_Minus(node: ?*const ir_node) i32;
    pub extern fn get_Minus_op(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Minus_op(node: ?*ir_node, op: ?*ir_node) void;
    pub extern fn get_op_Minus() ?*ir_op;
    pub extern fn new_rd_Mod(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node;
    pub extern fn new_r_Mod(block: ?*ir_node, irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node;
    pub extern fn new_d_Mod(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node;
    pub extern fn new_Mod(irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node;
    pub extern fn is_Mod(node: ?*const ir_node) i32;
    pub extern fn get_Mod_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Mod_mem(node: ?*ir_node, mem: ?*ir_node) void;
    pub extern fn get_Mod_left(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Mod_left(node: ?*ir_node, left: ?*ir_node) void;
    pub extern fn get_Mod_right(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Mod_right(node: ?*ir_node, right: ?*ir_node) void;
    pub extern fn get_Mod_resmode(node: ?*const ir_node) ?*ir_mode;
    pub extern fn set_Mod_resmode(node: ?*ir_node, resmode: ?*ir_mode) void;
    pub extern fn get_op_Mod() ?*ir_op;
    pub extern fn new_rd_Mul(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Mul(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Mul(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_Mul(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn is_Mul(node: ?*const ir_node) i32;
    pub extern fn get_Mul_left(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Mul_left(node: ?*ir_node, left: ?*ir_node) void;
    pub extern fn get_Mul_right(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Mul_right(node: ?*ir_node, right: ?*ir_node) void;
    pub extern fn get_op_Mul() ?*ir_op;
    pub extern fn new_rd_Mulh(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Mulh(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Mulh(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_Mulh(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn is_Mulh(node: ?*const ir_node) i32;
    pub extern fn get_Mulh_left(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Mulh_left(node: ?*ir_node, left: ?*ir_node) void;
    pub extern fn get_Mulh_right(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Mulh_right(node: ?*ir_node, right: ?*ir_node) void;
    pub extern fn get_op_Mulh() ?*ir_op;
    pub extern fn new_rd_Mux(dbgi: ?*dbg_info, block: ?*ir_node, irn_sel: ?*ir_node, irn_false: ?*ir_node, irn_true: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Mux(block: ?*ir_node, irn_sel: ?*ir_node, irn_false: ?*ir_node, irn_true: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Mux(dbgi: ?*dbg_info, irn_sel: ?*ir_node, irn_false: ?*ir_node, irn_true: ?*ir_node) ?*ir_node;
    pub extern fn new_Mux(irn_sel: ?*ir_node, irn_false: ?*ir_node, irn_true: ?*ir_node) ?*ir_node;
    pub extern fn is_Mux(node: ?*const ir_node) i32;
    pub extern fn get_Mux_sel(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Mux_sel(node: ?*ir_node, sel: ?*ir_node) void;
    pub extern fn get_Mux_false(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Mux_false(node: ?*ir_node, false_: ?*ir_node) void;
    pub extern fn get_Mux_true(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Mux_true(node: ?*ir_node, true_: ?*ir_node) void;
    pub extern fn get_op_Mux() ?*ir_op;
    pub extern fn new_rd_NoMem(dbgi: ?*dbg_info, irg: ?*ir_graph) ?*ir_node;
    pub extern fn new_r_NoMem(irg: ?*ir_graph) ?*ir_node;
    pub extern fn new_d_NoMem(dbgi: ?*dbg_info) ?*ir_node;
    pub extern fn new_NoMem() ?*ir_node;
    pub extern fn is_NoMem(node: ?*const ir_node) i32;
    pub extern fn get_op_NoMem() ?*ir_op;
    pub extern fn new_rd_Not(dbgi: ?*dbg_info, block: ?*ir_node, irn_op: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Not(block: ?*ir_node, irn_op: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Not(dbgi: ?*dbg_info, irn_op: ?*ir_node) ?*ir_node;
    pub extern fn new_Not(irn_op: ?*ir_node) ?*ir_node;
    pub extern fn is_Not(node: ?*const ir_node) i32;
    pub extern fn get_Not_op(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Not_op(node: ?*ir_node, op: ?*ir_node) void;
    pub extern fn get_op_Not() ?*ir_op;
    pub extern fn new_rd_Offset(dbgi: ?*dbg_info, irg: ?*ir_graph, mode: ?*ir_mode, entity: ?*ir_entity) ?*ir_node;
    pub extern fn new_r_Offset(irg: ?*ir_graph, mode: ?*ir_mode, entity: ?*ir_entity) ?*ir_node;
    pub extern fn new_d_Offset(dbgi: ?*dbg_info, mode: ?*ir_mode, entity: ?*ir_entity) ?*ir_node;
    pub extern fn new_Offset(mode: ?*ir_mode, entity: ?*ir_entity) ?*ir_node;
    pub extern fn is_Offset(node: ?*const ir_node) i32;
    pub extern fn get_Offset_entity(node: ?*const ir_node) ?*ir_entity;
    pub extern fn set_Offset_entity(node: ?*ir_node, entity: ?*ir_entity) void;
    pub extern fn get_op_Offset() ?*ir_op;
    pub extern fn new_rd_Or(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Or(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Or(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_Or(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn is_Or(node: ?*const ir_node) i32;
    pub extern fn get_Or_left(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Or_left(node: ?*ir_node, left: ?*ir_node) void;
    pub extern fn get_Or_right(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Or_right(node: ?*ir_node, right: ?*ir_node) void;
    pub extern fn get_op_Or() ?*ir_op;
    pub extern fn new_rd_Phi(dbgi: ?*dbg_info, block: ?*ir_node, arity: i32, in: [*]const ?*ir_node, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_r_Phi(block: ?*ir_node, arity: i32, in: [*]const ?*ir_node, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_d_Phi(dbgi: ?*dbg_info, arity: i32, in: [*]const ?*ir_node, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_Phi(arity: i32, in: [*]const ?*ir_node, mode: ?*ir_mode) ?*ir_node;
    pub extern fn is_Phi(node: ?*const ir_node) i32;
    pub extern fn get_Phi_n_preds(node: ?*const ir_node) i32;
    pub extern fn get_Phi_pred(node: ?*const ir_node, pos: i32) ?*ir_node;
    pub extern fn set_Phi_pred(node: ?*ir_node, pos: i32, pred: ?*ir_node) void;
    pub extern fn get_Phi_pred_arr(node: ?*ir_node) [*]?*ir_node;
    pub extern fn get_Phi_loop(node: ?*const ir_node) i32;
    pub extern fn set_Phi_loop(node: ?*ir_node, loop: i32) void;
    pub extern fn get_op_Phi() ?*ir_op;
    pub extern fn new_rd_Pin(dbgi: ?*dbg_info, block: ?*ir_node, irn_op: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Pin(block: ?*ir_node, irn_op: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Pin(dbgi: ?*dbg_info, irn_op: ?*ir_node) ?*ir_node;
    pub extern fn new_Pin(irn_op: ?*ir_node) ?*ir_node;
    pub extern fn is_Pin(node: ?*const ir_node) i32;
    pub extern fn get_Pin_op(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Pin_op(node: ?*ir_node, op: ?*ir_node) void;
    pub extern fn get_op_Pin() ?*ir_op;
    pub extern fn new_rd_Proj(dbgi: ?*dbg_info, irn_pred: ?*ir_node, mode: ?*ir_mode, num: u32) ?*ir_node;
    pub extern fn new_r_Proj(irn_pred: ?*ir_node, mode: ?*ir_mode, num: u32) ?*ir_node;
    pub extern fn new_d_Proj(dbgi: ?*dbg_info, irn_pred: ?*ir_node, mode: ?*ir_mode, num: u32) ?*ir_node;
    pub extern fn new_Proj(irn_pred: ?*ir_node, mode: ?*ir_mode, num: u32) ?*ir_node;
    pub extern fn is_Proj(node: ?*const ir_node) i32;
    pub extern fn get_Proj_pred(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Proj_pred(node: ?*ir_node, pred: ?*ir_node) void;
    pub extern fn get_Proj_num(node: ?*const ir_node) u32;
    pub extern fn set_Proj_num(node: ?*ir_node, num: u32) void;
    pub extern fn get_op_Proj() ?*ir_op;
    pub extern fn new_rd_Raise(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_exo_ptr: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Raise(block: ?*ir_node, irn_mem: ?*ir_node, irn_exo_ptr: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Raise(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_exo_ptr: ?*ir_node) ?*ir_node;
    pub extern fn new_Raise(irn_mem: ?*ir_node, irn_exo_ptr: ?*ir_node) ?*ir_node;
    pub extern fn is_Raise(node: ?*const ir_node) i32;
    pub extern fn get_Raise_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Raise_mem(node: ?*ir_node, mem: ?*ir_node) void;
    pub extern fn get_Raise_exo_ptr(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Raise_exo_ptr(node: ?*ir_node, exo_ptr: ?*ir_node) void;
    pub extern fn get_op_Raise() ?*ir_op;
    pub extern fn new_rd_Return(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, arity: i32, in: *?*ir_node) ?*ir_node;
    pub extern fn new_r_Return(block: ?*ir_node, irn_mem: ?*ir_node, arity: i32, in: *?*ir_node) ?*ir_node;
    pub extern fn new_d_Return(dbgi: ?*dbg_info, irn_mem: ?*ir_node, arity: i32, in: *?*ir_node) ?*ir_node;
    pub extern fn new_Return(irn_mem: ?*ir_node, arity: i32, in: *?*ir_node) ?*ir_node;
    pub extern fn is_Return(node: ?*const ir_node) i32;
    pub extern fn get_Return_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Return_mem(node: ?*ir_node, mem: ?*ir_node) void;
    pub extern fn get_Return_n_ress(node: ?*const ir_node) i32;
    pub extern fn get_Return_res(node: ?*const ir_node, pos: i32) ?*ir_node;
    pub extern fn set_Return_res(node: ?*ir_node, pos: i32, res: ?*ir_node) void;
    pub extern fn get_Return_res_arr(node: ?*ir_node) [*]?*ir_node;
    pub extern fn get_op_Return() ?*ir_op;
    pub extern fn new_rd_Sel(dbgi: ?*dbg_info, block: ?*ir_node, irn_ptr: ?*ir_node, irn_index: ?*ir_node, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_r_Sel(block: ?*ir_node, irn_ptr: ?*ir_node, irn_index: ?*ir_node, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_d_Sel(dbgi: ?*dbg_info, irn_ptr: ?*ir_node, irn_index: ?*ir_node, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_Sel(irn_ptr: ?*ir_node, irn_index: ?*ir_node, @"type": ?*ir_type) ?*ir_node;
    pub extern fn is_Sel(node: ?*const ir_node) i32;
    pub extern fn get_Sel_ptr(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Sel_ptr(node: ?*ir_node, ptr: ?*ir_node) void;
    pub extern fn get_Sel_index(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Sel_index(node: ?*ir_node, index: ?*ir_node) void;
    pub extern fn get_Sel_type(node: ?*const ir_node) ?*ir_type;
    pub extern fn set_Sel_type(node: ?*ir_node, @"type": ?*ir_type) void;
    pub extern fn get_op_Sel() ?*ir_op;
    pub extern fn new_rd_Shl(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Shl(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Shl(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_Shl(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn is_Shl(node: ?*const ir_node) i32;
    pub extern fn get_Shl_left(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Shl_left(node: ?*ir_node, left: ?*ir_node) void;
    pub extern fn get_Shl_right(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Shl_right(node: ?*ir_node, right: ?*ir_node) void;
    pub extern fn get_op_Shl() ?*ir_op;
    pub extern fn ir_printf(fmt: [*]const u8, ...) i32;
    pub extern fn ir_fprintf(f: *std.c.FILE, fmt: [*]const u8, ...) i32;
    pub extern fn ir_snprintf(buf: [*]u8, n: usize, fmt: [*]const u8, ...) i32;
    pub extern fn ir_vprintf(fmt: [*]const u8, ...) i32;
    pub extern fn ir_vfprintf(f: *std.c.FILE, fmt: [*]const u8, ...) i32;
    pub extern fn ir_vsnprintf(buf: [*]u8, len: usize, fmt: [*]const u8, ...) i32;
    pub extern fn ir_obst_vprintf(obst: ?*obstack, fmt: [*]const u8, ...) i32;
    pub extern fn tarval_snprintf(buf: [*]u8, buflen: usize, tv: ?*const ir_tarval) i32;
    pub extern fn new_rd_Shr(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Shr(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Shr(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_Shr(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn is_Shr(node: ?*const ir_node) i32;
    pub extern fn get_Shr_left(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Shr_left(node: ?*ir_node, left: ?*ir_node) void;
    pub extern fn get_Shr_right(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Shr_right(node: ?*ir_node, right: ?*ir_node) void;
    pub extern fn get_op_Shr() ?*ir_op;
    pub extern fn new_rd_Shrs(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Shrs(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Shrs(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_Shrs(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn is_Shrs(node: ?*const ir_node) i32;
    pub extern fn get_Shrs_left(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Shrs_left(node: ?*ir_node, left: ?*ir_node) void;
    pub extern fn get_Shrs_right(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Shrs_right(node: ?*ir_node, right: ?*ir_node) void;
    pub extern fn get_op_Shrs() ?*ir_op;
    pub extern fn new_rd_Size(dbgi: ?*dbg_info, irg: ?*ir_graph, mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_r_Size(irg: ?*ir_graph, mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_d_Size(dbgi: ?*dbg_info, mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node;
    pub extern fn new_Size(mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node;
    pub extern fn is_Size(node: ?*const ir_node) i32;
    pub extern fn get_Size_type(node: ?*const ir_node) ?*ir_type;
    pub extern fn set_Size_type(node: ?*ir_node, @"type": ?*ir_type) void;
    pub extern fn get_op_Size() ?*ir_op;
    pub extern fn new_rd_Start(dbgi: ?*dbg_info, irg: ?*ir_graph) ?*ir_node;
    pub extern fn new_r_Start(irg: ?*ir_graph) ?*ir_node;
    pub extern fn new_d_Start(dbgi: ?*dbg_info) ?*ir_node;
    pub extern fn new_Start() ?*ir_node;
    pub extern fn is_Start(node: ?*const ir_node) i32;
    pub extern fn get_op_Start() ?*ir_op;
    pub extern fn new_rd_Store(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, irn_value: ?*ir_node, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node;
    pub extern fn new_r_Store(block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, irn_value: ?*ir_node, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node;
    pub extern fn new_d_Store(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, irn_value: ?*ir_node, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node;
    pub extern fn new_Store(irn_mem: ?*ir_node, irn_ptr: ?*ir_node, irn_value: ?*ir_node, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node;
    pub extern fn is_Store(node: ?*const ir_node) i32;
    pub extern fn get_Store_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Store_mem(node: ?*ir_node, mem: ?*ir_node) void;
    pub extern fn get_Store_ptr(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Store_ptr(node: ?*ir_node, ptr: ?*ir_node) void;
    pub extern fn get_Store_value(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Store_value(node: ?*ir_node, value: ?*ir_node) void;
    pub extern fn get_Store_type(node: ?*const ir_node) ?*ir_type;
    pub extern fn set_Store_type(node: ?*ir_node, @"type": ?*ir_type) void;
    pub extern fn get_Store_volatility(node: ?*const ir_node) ir_volatility;
    pub extern fn set_Store_volatility(node: ?*ir_node, volatility: ir_volatility) void;
    pub extern fn get_Store_unaligned(node: ?*const ir_node) ir_align;
    pub extern fn set_Store_unaligned(node: ?*ir_node, unaligned: ir_align) void;
    pub extern fn get_op_Store() ?*ir_op;
    pub extern fn new_rd_Sub(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_r_Sub(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_d_Sub(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn new_Sub(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node;
    pub extern fn is_Sub(node: ?*const ir_node) i32;
    pub extern fn get_Sub_left(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Sub_left(node: ?*ir_node, left: ?*ir_node) void;
    pub extern fn get_Sub_right(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Sub_right(node: ?*ir_node, right: ?*ir_node) void;
    pub extern fn get_op_Sub() ?*ir_op;
    pub extern fn new_rd_Switch(dbgi: ?*dbg_info, block: ?*ir_node, irn_selector: ?*ir_node, n_outs: u32, table: ?*ir_switch_table) ?*ir_node;
    pub extern fn new_r_Switch(block: ?*ir_node, irn_selector: ?*ir_node, n_outs: u32, table: ?*ir_switch_table) ?*ir_node;
    pub extern fn new_d_Switch(dbgi: ?*dbg_info, irn_selector: ?*ir_node, n_outs: u32, table: ?*ir_switch_table) ?*ir_node;
    pub extern fn new_Switch(irn_selector: ?*ir_node, n_outs: u32, table: ?*ir_switch_table) ?*ir_node;
    pub extern fn is_Switch(node: ?*const ir_node) i32;
    pub extern fn get_Switch_selector(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_Switch_selector(node: ?*ir_node, selector: ?*ir_node) void;
    pub extern fn get_Switch_n_outs(node: ?*const ir_node) u32;
    pub extern fn set_Switch_n_outs(node: ?*ir_node, n_outs: u32) void;
    pub extern fn get_Switch_table(node: ?*const ir_node) ?*ir_switch_table;
    pub extern fn set_Switch_table(node: ?*ir_node, table: ?*ir_switch_table) void;
    pub extern fn get_op_Switch() ?*ir_op;
    pub extern fn new_rd_Sync(dbgi: ?*dbg_info, block: ?*ir_node, arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn new_r_Sync(block: ?*ir_node, arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn new_d_Sync(dbgi: ?*dbg_info, arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn new_Sync(arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn is_Sync(node: ?*const ir_node) i32;
    pub extern fn get_Sync_n_preds(node: ?*const ir_node) i32;
    pub extern fn get_Sync_pred(node: ?*const ir_node, pos: i32) ?*ir_node;
    pub extern fn set_Sync_pred(node: ?*ir_node, pos: i32, pred: ?*ir_node) void;
    pub extern fn get_Sync_pred_arr(node: ?*ir_node) [*]?*ir_node;
    pub extern fn get_op_Sync() ?*ir_op;
    pub extern fn new_rd_Tuple(dbgi: ?*dbg_info, block: ?*ir_node, arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn new_r_Tuple(block: ?*ir_node, arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn new_d_Tuple(dbgi: ?*dbg_info, arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn new_Tuple(arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn is_Tuple(node: ?*const ir_node) i32;
    pub extern fn get_Tuple_n_preds(node: ?*const ir_node) i32;
    pub extern fn get_Tuple_pred(node: ?*const ir_node, pos: i32) ?*ir_node;
    pub extern fn set_Tuple_pred(node: ?*ir_node, pos: i32, pred: ?*ir_node) void;
    pub extern fn get_Tuple_pred_arr(node: ?*ir_node) [*]?*ir_node;
    pub extern fn get_op_Tuple() ?*ir_op;
    pub extern fn new_rd_Unknown(dbgi: ?*dbg_info, irg: ?*ir_graph, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_r_Unknown(irg: ?*ir_graph, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_d_Unknown(dbgi: ?*dbg_info, mode: ?*ir_mode) ?*ir_node;
    pub extern fn new_Unknown(mode: ?*ir_mode) ?*ir_node;
    pub extern fn is_Unknown(node: ?*const ir_node) i32;
    pub extern fn get_op_Unknown() ?*ir_op;
    pub extern fn is_binop(node: ?*const ir_node) i32;
    pub extern fn is_entconst(node: ?*const ir_node) i32;
    pub extern fn get_entconst_entity(node: ?*const ir_node) ?*ir_entity;
    pub extern fn set_entconst_entity(node: ?*ir_node, entity: ?*ir_entity) void;
    pub extern fn is_typeconst(node: ?*const ir_node) i32;
    pub extern fn get_typeconst_type(node: ?*const ir_node) ?*ir_type;
    pub extern fn set_typeconst_type(node: ?*ir_node, @"type": ?*ir_type) void;
    pub extern fn get_irn_arity(node: ?*const ir_node) i32;
    pub extern fn get_irn_n(node: ?*const ir_node, n: i32) ?*ir_node;
    pub extern fn set_irn_in(node: ?*ir_node, arity: i32, in: [*]const ?*ir_node) void;
    pub extern fn set_irn_n(node: ?*ir_node, n: i32, in: ?*ir_node) void;
    pub extern fn add_irn_n(node: ?*ir_node, in: ?*ir_node) i32;
    pub extern fn set_irn_mode(node: ?*ir_node, mode: ?*ir_mode) void;
    pub extern fn get_irn_mode(node: ?*const ir_node) ?*ir_mode;
    pub extern fn get_irn_op(node: ?*const ir_node) ?*ir_op;
    pub extern fn get_irn_opcode(node: ?*const ir_node) u32;
    pub extern fn get_irn_opname(node: ?*const ir_node) [*]const u8;
    pub extern fn get_irn_opident(node: ?*const ir_node) [*]const u8;
    pub extern fn get_irn_visited(node: ?*const ir_node) ir_visited_t;
    pub extern fn set_irn_visited(node: ?*ir_node, visited: ir_visited_t) void;
    pub extern fn mark_irn_visited(node: ?*ir_node) void;
    pub extern fn irn_visited(node: ?*const ir_node) i32;
    pub extern fn irn_visited_else_mark(node: ?*ir_node) i32;
    pub extern fn set_irn_link(node: ?*ir_node, link: ?*anyopaque) void;
    pub extern fn get_irn_link(node: ?*const ir_node) ?*anyopaque;
    pub extern fn get_irn_irg(node: ?*const ir_node) ?*ir_graph;
    pub extern fn get_irn_node_nr(node: ?*const ir_node) i64;
    pub extern fn get_irn_pinned(node: ?*const ir_node) i32;
    pub extern fn set_irn_pinned(node: ?*ir_node, pinned: i32) void;
    pub extern fn new_ir_node(db: ?*dbg_info, irg: ?*ir_graph, block: ?*ir_node, op: ?*ir_op, mode: ?*ir_mode, arity: i32, in: [*]const ?*ir_node) ?*ir_node;
    pub extern fn exact_copy(node: ?*const ir_node) ?*ir_node;
    pub extern fn irn_copy_into_irg(node: ?*const ir_node, irg: ?*ir_graph) ?*ir_node;
    pub extern fn get_nodes_block(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_nodes_block(node: ?*ir_node, block: ?*ir_node) void;
    pub extern fn get_Block_cfgpred_block(node: ?*const ir_node, pos: i32) ?*ir_node;
    pub extern fn get_Block_matured(block: ?*const ir_node) i32;
    pub extern fn set_Block_matured(block: ?*ir_node, matured: i32) void;
    pub extern fn get_Block_block_visited(block: ?*const ir_node) ir_visited_t;
    pub extern fn set_Block_block_visited(block: ?*ir_node, visit: ir_visited_t) void;
    pub extern fn mark_Block_block_visited(node: ?*ir_node) void;
    pub extern fn Block_block_visited(node: ?*const ir_node) i32;
    pub extern fn create_Block_entity(block: ?*ir_node) ?*ir_entity;
    pub extern fn get_Block_phis(block: ?*const ir_node) ?*ir_node;
    pub extern fn set_Block_phis(block: ?*ir_node, phi: ?*ir_node) void;
    pub extern fn add_Block_phi(block: ?*ir_node, phi: ?*ir_node) void;
    pub extern fn get_Block_mark(block: ?*const ir_node) u32;
    pub extern fn set_Block_mark(block: ?*ir_node, mark: u32) void;
    pub extern fn add_End_keepalive(end: ?*ir_node, ka: ?*ir_node) void;
    pub extern fn set_End_keepalives(end: ?*ir_node, n: i32, in: [*]?*ir_node) void;
    pub extern fn remove_End_keepalive(end: ?*ir_node, irn: ?*const ir_node) void;
    pub extern fn remove_End_n(end: ?*ir_node, idx: i32) void;
    pub extern fn remove_End_Bads_and_doublets(end: ?*ir_node) void;
    pub extern fn free_End(end: ?*ir_node) void;
    pub extern fn is_Const_null(node: ?*const ir_node) i32;
    pub extern fn is_Const_one(node: ?*const ir_node) i32;
    pub extern fn is_Const_all_one(node: ?*const ir_node) i32;
    pub extern fn get_Call_callee(call: ?*const ir_node) ?*ir_entity;
    pub extern fn get_builtin_kind_name(kind: ir_builtin_kind) [*]const u8;
    pub extern fn get_binop_left(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_binop_left(node: ?*ir_node, left: ?*ir_node) void;
    pub extern fn get_binop_right(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_binop_right(node: ?*ir_node, right: ?*ir_node) void;
    pub extern fn is_x_except_Proj(node: ?*const ir_node) i32;
    pub extern fn is_x_regular_Proj(node: ?*const ir_node) i32;
    pub extern fn ir_set_throws_exception(node: ?*ir_node, throws_exception: i32) void;
    pub extern fn ir_throws_exception(node: ?*const ir_node) i32;
    pub extern fn get_relation_string(relation: ir_relation) [*]const u8;
    pub extern fn get_negated_relation(relation: ir_relation) ir_relation;
    pub extern fn get_inversed_relation(relation: ir_relation) ir_relation;
    pub extern fn get_Phi_next(phi: ?*const ir_node) ?*ir_node;
    pub extern fn set_Phi_next(phi: ?*ir_node, next: ?*ir_node) void;
    pub extern fn is_memop(node: ?*const ir_node) i32;
    pub extern fn get_memop_mem(node: ?*const ir_node) ?*ir_node;
    pub extern fn set_memop_mem(node: ?*ir_node, mem: ?*ir_node) void;
    pub extern fn add_Sync_pred(node: ?*ir_node, pred: ?*ir_node) void;
    pub extern fn remove_Sync_n(n: ?*ir_node, i: i32) void;
    pub extern fn get_ASM_n_constraints(node: ?*const ir_node) usize;
    pub extern fn get_ASM_n_clobbers(node: ?*const ir_node) usize;
    pub extern fn skip_Proj(node: ?*ir_node) ?*ir_node;
    pub extern fn skip_Proj_const(node: ?*const ir_node) ?*const ir_node;
    pub extern fn skip_Id(node: ?*ir_node) ?*ir_node;
    pub extern fn skip_Tuple(node: ?*ir_node) ?*ir_node;
    pub extern fn skip_Pin(node: ?*ir_node) ?*ir_node;
    pub extern fn skip_Confirm(node: ?*ir_node) ?*ir_node;
    pub extern fn is_cfop(node: ?*const ir_node) i32;
    pub extern fn is_unknown_jump(node: ?*const ir_node) i32;
    pub extern fn is_fragile_op(node: ?*const ir_node) i32;
    pub extern fn is_irn_forking(node: ?*const ir_node) i32;
    pub extern fn is_irn_const_memory(node: ?*const ir_node) i32;
    pub extern fn copy_node_attr(irg: ?*ir_graph, old_node: ?*const ir_node, new_node: ?*ir_node) void;
    pub extern fn get_irn_type_attr(n: ?*ir_node) ?*ir_type;
    pub extern fn get_irn_entity_attr(n: ?*ir_node) ?*ir_entity;
    pub extern fn is_irn_constlike(node: ?*const ir_node) i32;
    pub extern fn is_irn_keep(node: ?*const ir_node) i32;
    pub extern fn is_irn_start_block_placed(node: ?*const ir_node) i32;
    pub extern fn get_cond_jmp_predicate_name(pred: cond_jmp_predicate) [*]const u8;
    pub extern fn get_irn_generic_attr(node: ?*ir_node) ?*anyopaque;
    pub extern fn get_irn_generic_attr_const(node: ?*const ir_node) ?*const anyopaque;
    pub extern fn get_irn_idx(node: ?*const ir_node) u32;
    pub extern fn set_irn_dbg_info(n: ?*ir_node, db: ?*dbg_info) void;
    pub extern fn get_irn_dbg_info(n: ?*const ir_node) ?*dbg_info;
    pub extern fn gdb_node_helper(firm_object: ?*const anyopaque) [*]const u8;
    pub extern fn ir_new_switch_table(irg: ?*ir_graph, n_entries: usize) ?*ir_switch_table;
    pub extern fn ir_switch_table_get_n_entries(table: ?*const ir_switch_table) usize;
    pub extern fn ir_switch_table_set(table: ?*ir_switch_table, entry: usize, min: ?*ir_tarval, max: ?*ir_tarval, pn: u32) void;
    pub extern fn ir_switch_table_get_max(table: ?*const ir_switch_table, entry: usize) ?*ir_tarval;
    pub extern fn ir_switch_table_get_min(table: ?*const ir_switch_table, entry: usize) ?*ir_tarval;
    pub extern fn ir_switch_table_get_pn(table: ?*const ir_switch_table, entry: usize) u32;
    pub extern fn ir_switch_table_duplicate(irg: ?*ir_graph, table: ?*const ir_switch_table) ?*ir_switch_table;
    pub extern fn new_rd_Const_long(db: ?*dbg_info, irg: ?*ir_graph, mode: ?*ir_mode, value: i64) ?*ir_node;
    pub extern fn new_r_Const_long(irg: ?*ir_graph, mode: ?*ir_mode, value: i64) ?*ir_node;
    pub extern fn new_d_Const_long(db: ?*dbg_info, mode: ?*ir_mode, value: i64) ?*ir_node;
    pub extern fn new_Const_long(mode: ?*ir_mode, value: i64) ?*ir_node;
    pub extern fn new_rd_Phi_loop(db: ?*dbg_info, block: ?*ir_node, arity: i32, in: [*]?*ir_node) ?*ir_node;
    pub extern fn new_r_Phi_loop(block: ?*ir_node, arity: i32, in: [*]?*ir_node) ?*ir_node;
    pub extern fn new_d_Phi_loop(db: ?*dbg_info, arity: i32, in: [*]?*ir_node) ?*ir_node;
    pub extern fn new_Phi_loop(arity: i32, in: [*]?*ir_node) ?*ir_node;
    pub extern fn new_rd_DivRL(db: ?*dbg_info, block: ?*ir_node, memop: ?*ir_node, op1: ?*ir_node, op2: ?*ir_node, pinned: i32) ?*ir_node;
    pub extern fn new_r_DivRL(block: ?*ir_node, memop: ?*ir_node, op1: ?*ir_node, op2: ?*ir_node, pinned: i32) ?*ir_node;
    pub extern fn new_d_DivRL(db: ?*dbg_info, memop: ?*ir_node, op1: ?*ir_node, op2: ?*ir_node, pinned: i32) ?*ir_node;
    pub extern fn new_DivRL(memop: ?*ir_node, op1: ?*ir_node, op2: ?*ir_node, pinned: i32) ?*ir_node;
    pub extern fn get_current_ir_graph() ?*ir_graph;
    pub extern fn set_current_ir_graph(graph: ?*ir_graph) void;
    pub extern fn new_d_immBlock(db: ?*dbg_info) ?*ir_node;
    pub extern fn new_immBlock() ?*ir_node;
    pub extern fn new_r_immBlock(irg: ?*ir_graph) ?*ir_node;
    pub extern fn new_rd_immBlock(db: ?*dbg_info, irg: ?*ir_graph) ?*ir_node;
    pub extern fn add_immBlock_pred(immblock: ?*ir_node, jmp: ?*ir_node) void;
    pub extern fn mature_immBlock(block: ?*ir_node) void;
    pub extern fn set_cur_block(target: ?*ir_node) void;
    pub extern fn set_r_cur_block(irg: ?*ir_graph, target: ?*ir_node) void;
    pub extern fn get_cur_block() ?*ir_node;
    pub extern fn get_r_cur_block(irg: ?*ir_graph) ?*ir_node;
    pub extern fn get_value(pos: i32, mode: ?*ir_mode) ?*ir_node;
    pub extern fn get_r_value(irg: ?*ir_graph, pos: i32, mode: ?*ir_mode) ?*ir_node;
    pub extern fn ir_guess_mode(pos: i32) ?*ir_mode;
    pub extern fn ir_r_guess_mode(irg: ?*ir_graph, pos: i32) ?*ir_mode;
    pub extern fn set_value(pos: i32, value: ?*ir_node) void;
    pub extern fn set_r_value(irg: ?*ir_graph, pos: i32, value: ?*ir_node) void;
    pub extern fn get_store() ?*ir_node;
    pub extern fn get_r_store(irg: ?*ir_graph) ?*ir_node;
    pub extern fn set_store(store: ?*ir_node) void;
    pub extern fn set_r_store(irg: ?*ir_graph, store: ?*ir_node) void;
    pub extern fn keep_alive(ka: ?*ir_node) void;
    pub extern fn irg_finalize_cons(irg: ?*ir_graph) void;
    pub extern fn verify_new_node(node: ?*ir_node) void;
    pub extern fn ir_set_uninitialized_local_variable_func(func: ?uninitialized_local_variable_func_t) void;
    pub extern fn construct_confirms(irg: ?*ir_graph) void;
    pub extern fn construct_confirms_only(irg: ?*ir_graph) void;
    pub extern fn remove_confirms(irg: ?*ir_graph) void;
    pub extern fn get_Block_idom(block: ?*const ir_node) ?*ir_node;
    pub extern fn get_Block_ipostdom(block: ?*const ir_node) ?*ir_node;
    pub extern fn get_Block_dom_depth(bl: ?*const ir_node) i32;
    pub extern fn get_Block_postdom_depth(bl: ?*const ir_node) i32;
    pub extern fn block_dominates(a: ?*const ir_node, b: ?*const ir_node) i32;
    pub extern fn block_postdominates(a: ?*const ir_node, b: ?*const ir_node) i32;
    pub extern fn block_strictly_postdominates(a: ?*const ir_node, b: ?*const ir_node) i32;
    pub extern fn get_Block_dominated_first(block: ?*const ir_node) ?*ir_node;
    pub extern fn get_Block_postdominated_first(bl: ?*const ir_node) ?*ir_node;
    pub extern fn get_Block_dominated_next(node: ?*const ir_node) ?*ir_node;
    pub extern fn get_Block_postdominated_next(node: ?*const ir_node) ?*ir_node;
    pub extern fn ir_deepest_common_dominator(block0: ?*ir_node, block1: ?*ir_node) ?*ir_node;
    pub extern fn dom_tree_walk(n: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn postdom_tree_walk(n: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn dom_tree_walk_irg(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn postdom_tree_walk_irg(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn compute_doms(irg: ?*ir_graph) void;
    pub extern fn compute_postdoms(irg: ?*ir_graph) void;
    pub extern fn ir_compute_dominance_frontiers(irg: ?*ir_graph) void;
    pub extern fn ir_get_dominance_frontier(block: ?*const ir_node) [*]?*ir_node;
    pub extern fn dump_ir_graph(graph: ?*ir_graph, suffix: [*]const u8) void;
    pub extern fn dump_ir_prog_ext(func: ir_prog_dump_func, suffix: [*]const u8) void;
    pub extern fn dump_ir_graph_ext(func: ir_graph_dump_func, graph: ?*ir_graph, suffix: [*]const u8) void;
    pub extern fn dump_all_ir_graphs(suffix: [*]const u8) void;
    pub extern fn ir_set_dump_path(path: [*]const u8) void;
    pub extern fn ir_set_dump_filter(name: [*]const u8) void;
    pub extern fn ir_get_dump_filter() [*]const u8;
    pub extern fn dump_ir_graph_file(out: *std.c.FILE, graph: ?*ir_graph) void;
    pub extern fn dump_cfg(out: *std.c.FILE, graph: ?*ir_graph) void;
    pub extern fn dump_callgraph(out: *std.c.FILE) void;
    pub extern fn dump_typegraph(out: *std.c.FILE) void;
    pub extern fn dump_class_hierarchy(out: *std.c.FILE) void;
    pub extern fn dump_loop_tree(out: *std.c.FILE, graph: ?*ir_graph) void;
    pub extern fn dump_callgraph_loop_tree(out: *std.c.FILE) void;
    pub extern fn dump_types_as_text(out: *std.c.FILE) void;
    pub extern fn dump_globals_as_text(out: *std.c.FILE) void;
    pub extern fn dump_loop(out: *std.c.FILE, loop: ?*ir_loop) void;
    pub extern fn dump_graph_as_text(out: *std.c.FILE, graph: ?*const ir_graph) void;
    pub extern fn dump_entity_to_file(out: *std.c.FILE, entity: ?*const ir_entity) void;
    pub extern fn dump_type_to_file(out: *std.c.FILE, @"type": ?*const ir_type) void;
    pub extern fn ir_set_dump_verbosity(verbosity: ir_dump_verbosity_t) void;
    pub extern fn ir_get_dump_verbosity() ir_dump_verbosity_t;
    pub extern fn ir_set_dump_flags(flags: ir_dump_flags_t) void;
    pub extern fn ir_add_dump_flags(flags: ir_dump_flags_t) void;
    pub extern fn ir_remove_dump_flags(flags: ir_dump_flags_t) void;
    pub extern fn ir_get_dump_flags() ir_dump_flags_t;
    pub extern fn set_dump_node_vcgattr_hook(hook: dump_node_vcgattr_func) void;
    pub extern fn set_dump_edge_vcgattr_hook(hook: dump_edge_vcgattr_func) void;
    pub extern fn set_dump_node_edge_hook(func: dump_node_edge_func) void;
    pub extern fn get_dump_node_edge_hook() dump_node_edge_func;
    pub extern fn set_dump_block_edge_hook(func: dump_node_edge_func) void;
    pub extern fn get_dump_block_edge_hook() dump_node_edge_func;
    pub extern fn dump_add_node_info_callback(cb: ?dump_node_info_cb_t, data: ?*anyopaque) ?*hook_entry_t;
    pub extern fn dump_remove_node_info_callback(handle: ?*hook_entry_t) void;
    pub extern fn dump_vcg_header(out: *std.c.FILE, name: [*]const u8, layout: [*]const u8, orientation: [*]const u8) void;
    pub extern fn dump_vcg_footer(out: *std.c.FILE) void;
    pub extern fn dump_node(out: *std.c.FILE, node: ?*const ir_node) void;
    pub extern fn dump_ir_data_edges(out: *std.c.FILE, node: ?*const ir_node) void;
    pub extern fn print_nodeid(out: *std.c.FILE, node: ?*const ir_node) void;
    pub extern fn dump_begin_block_subgraph(out: *std.c.FILE, block: ?*const ir_node) void;
    pub extern fn dump_end_block_subgraph(out: *std.c.FILE, block: ?*const ir_node) void;
    pub extern fn dump_block_edges(out: *std.c.FILE, block: ?*const ir_node) void;
    pub extern fn dump_blocks_as_subgraphs(out: *std.c.FILE, irg: ?*ir_graph) void;
    pub extern fn get_irn_out_edge_first_kind(irn: ?*const ir_node, kind: ir_edge_kind_t) ?*const ir_edge_t;
    pub extern fn get_irn_out_edge_first(irn: ?*const ir_node) ?*const ir_edge_t;
    pub extern fn get_block_succ_first(block: ?*const ir_node) ?*const ir_edge_t;
    pub extern fn get_irn_out_edge_next(irn: ?*const ir_node, last: ?*const ir_edge_t, kind: ir_edge_kind_t) ?*const ir_edge_t;
    pub extern fn get_edge_src_irn(edge: ?*const ir_edge_t) ?*ir_node;
    pub extern fn get_edge_src_pos(edge: ?*const ir_edge_t) i32;
    pub extern fn get_irn_n_edges_kind(irn: ?*const ir_node, kind: ir_edge_kind_t) i32;
    pub extern fn get_irn_n_edges(irn: ?*const ir_node) i32;
    pub extern fn edges_activated_kind(irg: ?*const ir_graph, kind: ir_edge_kind_t) i32;
    pub extern fn edges_activated(irg: ?*const ir_graph) i32;
    pub extern fn edges_activate_kind(irg: ?*ir_graph, kind: ir_edge_kind_t) void;
    pub extern fn edges_deactivate_kind(irg: ?*ir_graph, kind: ir_edge_kind_t) void;
    pub extern fn edges_reroute_kind(old: ?*ir_node, nw: ?*ir_node, kind: ir_edge_kind_t) void;
    pub extern fn edges_reroute(old: ?*ir_node, nw: ?*ir_node) void;
    pub extern fn edges_reroute_except(old: ?*ir_node, nw: ?*ir_node, exception: ?*ir_node) void;
    pub extern fn edges_verify(irg: ?*ir_graph) i32;
    pub extern fn edges_verify_kind(irg: ?*ir_graph, kind: ir_edge_kind_t) i32;
    pub extern fn edges_init_dbg(do_dbg: i32) void;
    pub extern fn edges_activate(irg: ?*ir_graph) void;
    pub extern fn edges_deactivate(irg: ?*ir_graph) void;
    pub extern fn assure_edges(irg: ?*ir_graph) void;
    pub extern fn assure_edges_kind(irg: ?*ir_graph, kind: ir_edge_kind_t) void;
    pub extern fn irg_block_edges_walk(block: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn irg_walk_edges(start: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn set_optimize(value: i32) void;
    pub extern fn get_optimize() i32;
    pub extern fn set_opt_constant_folding(value: i32) void;
    pub extern fn get_opt_constant_folding() i32;
    pub extern fn set_opt_algebraic_simplification(value: i32) void;
    pub extern fn get_opt_algebraic_simplification() i32;
    pub extern fn set_opt_cse(value: i32) void;
    pub extern fn get_opt_cse() i32;
    pub extern fn set_opt_global_cse(value: i32) void;
    pub extern fn get_opt_global_cse() i32;
    pub extern fn set_opt_global_null_ptr_elimination(value: i32) void;
    pub extern fn get_opt_global_null_ptr_elimination() i32;
    pub extern fn save_optimization_state(state: [*]optimization_state_t) void;
    pub extern fn restore_optimization_state(state: [*]const optimization_state_t) void;
    pub extern fn all_optimizations_off() void;
    pub extern fn exchange(old: ?*ir_node, nw: ?*ir_node) void;
    pub extern fn turn_into_tuple(node: ?*ir_node, arity: i32, in: [*]const ?*ir_node) void;
    pub extern fn collect_phiprojs_and_start_block_nodes(irg: ?*ir_graph) void;
    pub extern fn collect_new_start_block_node(node: ?*ir_node) void;
    pub extern fn collect_new_phi_node(node: ?*ir_node) void;
    pub extern fn part_block(node: ?*ir_node) void;
    pub extern fn part_block_edges(node: ?*ir_node) ?*ir_node;
    pub extern fn kill_node(node: ?*ir_node) void;
    pub extern fn duplicate_subgraph(dbg: ?*dbg_info, n: ?*ir_node, to_block: ?*ir_node) ?*ir_node;
    pub extern fn local_optimize_node(n: ?*ir_node) void;
    pub extern fn optimize_node(n: ?*ir_node) ?*ir_node;
    pub extern fn local_optimize_graph(irg: ?*ir_graph) void;
    pub extern fn optimize_graph_df(irg: ?*ir_graph) void;
    pub extern fn local_opts_const_code() void;
    pub extern fn remove_unreachable_code(irg: ?*ir_graph) void;
    pub extern fn remove_bads(irg: ?*ir_graph) void;
    pub extern fn remove_tuples(irg: ?*ir_graph) void;
    pub extern fn remove_critical_cf_edges(irg: ?*ir_graph) void;
    pub extern fn remove_critical_cf_edges_ex(irg: ?*ir_graph, ignore_exception_edges: i32) void;
    pub extern fn new_ir_graph(ent: ?*ir_entity, n_loc: i32) ?*ir_graph;
    pub extern fn free_ir_graph(irg: ?*ir_graph) void;
    pub extern fn get_irg_entity(irg: ?*const ir_graph) ?*ir_entity;
    pub extern fn set_irg_entity(irg: ?*ir_graph, ent: ?*ir_entity) void;
    pub extern fn get_irg_frame_type(irg: ?*ir_graph) ?*ir_type;
    pub extern fn set_irg_frame_type(irg: ?*ir_graph, ftp: ?*ir_type) void;
    pub extern fn get_irg_start_block(irg: ?*const ir_graph) ?*ir_node;
    pub extern fn set_irg_start_block(irg: ?*ir_graph, node: ?*ir_node) void;
    pub extern fn get_irg_start(irg: ?*const ir_graph) ?*ir_node;
    pub extern fn set_irg_start(irg: ?*ir_graph, node: ?*ir_node) void;
    pub extern fn get_irg_end_block(irg: ?*const ir_graph) ?*ir_node;
    pub extern fn set_irg_end_block(irg: ?*ir_graph, node: ?*ir_node) void;
    pub extern fn get_irg_end(irg: ?*const ir_graph) ?*ir_node;
    pub extern fn set_irg_end(irg: ?*ir_graph, node: ?*ir_node) void;
    pub extern fn get_irg_frame(irg: ?*const ir_graph) ?*ir_node;
    pub extern fn set_irg_frame(irg: ?*ir_graph, node: ?*ir_node) void;
    pub extern fn get_irg_initial_mem(irg: ?*const ir_graph) ?*ir_node;
    pub extern fn set_irg_initial_mem(irg: ?*ir_graph, node: ?*ir_node) void;
    pub extern fn get_irg_args(irg: ?*const ir_graph) ?*ir_node;
    pub extern fn set_irg_args(irg: ?*ir_graph, node: ?*ir_node) void;
    pub extern fn get_irg_no_mem(irg: ?*const ir_graph) ?*ir_node;
    pub extern fn set_irg_no_mem(irg: ?*ir_graph, node: ?*ir_node) void;
    pub extern fn get_irg_n_locs(irg: ?*ir_graph) i32;
    pub extern fn get_irg_graph_nr(irg: ?*const ir_graph) i64;
    pub extern fn get_irg_idx(irg: ?*const ir_graph) usize;
    pub extern fn get_idx_irn(irg: ?*const ir_graph, idx: u32) ?*ir_node;
    pub extern fn get_irg_pinned(irg: ?*const ir_graph) op_pin_state;
    pub extern fn get_irg_callee_info_state(irg: ?*const ir_graph) irg_callee_info_state;
    pub extern fn set_irg_callee_info_state(irg: ?*ir_graph, s: irg_callee_info_state) void;
    pub extern fn set_irg_link(irg: ?*ir_graph, thing: ?*anyopaque) void;
    pub extern fn get_irg_link(irg: ?*const ir_graph) ?*anyopaque;
    pub extern fn inc_irg_visited(irg: ?*ir_graph) void;
    pub extern fn get_irg_visited(irg: ?*const ir_graph) ir_visited_t;
    pub extern fn set_irg_visited(irg: ?*ir_graph, i: ir_visited_t) void;
    pub extern fn get_max_irg_visited() ir_visited_t;
    pub extern fn set_max_irg_visited(val: i32) void;
    pub extern fn inc_max_irg_visited() ir_visited_t;
    pub extern fn inc_irg_block_visited(irg: ?*ir_graph) void;
    pub extern fn get_irg_block_visited(irg: ?*const ir_graph) ir_visited_t;
    pub extern fn set_irg_block_visited(irg: ?*ir_graph, i: ir_visited_t) void;
    pub extern fn ir_reserve_resources(irg: ?*ir_graph, resources: ir_resources_t) void;
    pub extern fn ir_free_resources(irg: ?*ir_graph, resources: ir_resources_t) void;
    pub extern fn ir_resources_reserved(irg: ?*const ir_graph) ir_resources_t;
    pub extern fn add_irg_constraints(irg: ?*ir_graph, constraints: ir_graph_constraints_t) void;
    pub extern fn clear_irg_constraints(irg: ?*ir_graph, constraints: ir_graph_constraints_t) void;
    pub extern fn irg_is_constrained(irg: ?*const ir_graph, constraints: ir_graph_constraints_t) i32;
    pub extern fn add_irg_properties(irg: ?*ir_graph, props: ir_graph_properties_t) void;
    pub extern fn clear_irg_properties(irg: ?*ir_graph, props: ir_graph_properties_t) void;
    pub extern fn irg_has_properties(irg: ?*const ir_graph, props: ir_graph_properties_t) i32;
    pub extern fn assure_irg_properties(irg: ?*ir_graph, props: ir_graph_properties_t) void;
    pub extern fn confirm_irg_properties(irg: ?*ir_graph, props: ir_graph_properties_t) void;
    pub extern fn set_irg_loc_description(irg: ?*ir_graph, n: i32, description: ?*anyopaque) void;
    pub extern fn get_irg_loc_description(irg: ?*ir_graph, n: i32) ?*anyopaque;
    pub extern fn get_irg_last_idx(irg: ?*const ir_graph) u32;
    pub extern fn irg_walk(node: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn irg_walk_core(node: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn irg_walk_graph(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn irg_walk_in_or_dep(node: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn irg_walk_in_or_dep_graph(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn irg_walk_topological(irg: ?*ir_graph, walker: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn all_irg_walk(pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn irg_block_walk(node: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn irg_block_walk_graph(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn walk_const_code(pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn irg_walk_blkwise_graph(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn irg_walk_blkwise_dom_top_down(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn irg_walk_anchors(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn irg_walk_2(node: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn ir_export(filename: [*]const u8) i32;
    pub extern fn ir_export_file(output: *std.c.FILE) void;
    pub extern fn ir_import(filename: [*]const u8) i32;
    pub extern fn ir_import_file(input: *std.c.FILE, inputname: [*]const u8) i32;
    pub extern fn is_backedge(n: ?*const ir_node, pos: i32) i32;
    pub extern fn set_backedge(n: ?*ir_node, pos: i32) void;
    pub extern fn has_backedges(n: ?*const ir_node) i32;
    pub extern fn clear_backedges(n: ?*ir_node) void;
    pub extern fn set_irg_loop(irg: ?*ir_graph, l: ?*ir_loop) void;
    pub extern fn get_irg_loop(irg: ?*const ir_graph) ?*ir_loop;
    pub extern fn get_irn_loop(n: ?*const ir_node) ?*ir_loop;
    pub extern fn get_loop_outer_loop(loop: ?*const ir_loop) ?*ir_loop;
    pub extern fn get_loop_depth(loop: ?*const ir_loop) u32;
    pub extern fn get_loop_n_elements(loop: ?*const ir_loop) usize;
    pub extern fn get_loop_element(loop: ?*const ir_loop, pos: usize) loop_element;
    pub extern fn get_loop_loop_nr(loop: ?*const ir_loop) i64;
    pub extern fn set_loop_link(loop: ?*ir_loop, link: ?*anyopaque) void;
    pub extern fn get_loop_link(loop: ?*const ir_loop) ?*anyopaque;
    pub extern fn construct_cf_backedges(irg: ?*ir_graph) void;
    pub extern fn assure_loopinfo(irg: ?*ir_graph) void;
    pub extern fn free_loop_information(irg: ?*ir_graph) void;
    pub extern fn is_loop_invariant(n: ?*const ir_node, block: ?*const ir_node) i32;
    pub extern fn get_ir_alias_relation_name(rel: ir_alias_relation) [*]const u8;
    pub extern fn get_alias_relation(addr1: ?*const ir_node, type1: ?*const ir_type, size1: u32, addr2: ?*const ir_node, type2: ?*const ir_type, size2: u32) ir_alias_relation;
    pub extern fn assure_irg_entity_usage_computed(irg: ?*ir_graph) void;
    pub extern fn get_irp_globals_entity_usage_state() ir_entity_usage_computed_state;
    pub extern fn set_irp_globals_entity_usage_state(state: ir_entity_usage_computed_state) void;
    pub extern fn assure_irp_globals_entity_usage_computed() void;
    pub extern fn get_irg_memory_disambiguator_options(irg: ?*const ir_graph) ir_disambiguator_options;
    pub extern fn set_irg_memory_disambiguator_options(irg: ?*ir_graph, options: ir_disambiguator_options) void;
    pub extern fn set_irp_memory_disambiguator_options(options: ir_disambiguator_options) void;
    pub extern fn mark_private_methods() void;
    pub extern fn computed_value(n: ?*const ir_node) ?*ir_tarval;
    pub extern fn optimize_in_place(n: ?*ir_node) ?*ir_node;
    pub extern fn ir_is_negated_value(a: ?*const ir_node, b: ?*const ir_node) i32;
    pub extern fn ir_get_possible_cmp_relations(left: ?*const ir_node, right: ?*const ir_node) ir_relation;
    pub extern fn ir_allow_imprecise_float_transforms(enable: i32) void;
    pub extern fn ir_imprecise_float_transforms_allowed() i32;
    pub extern fn get_irn_n_outs(node: ?*const ir_node) u32;
    pub extern fn get_irn_out(def: ?*const ir_node, pos: u32) ?*ir_node;
    pub extern fn get_irn_out_ex(def: ?*const ir_node, pos: u32, in_pos: [*]i32) ?*ir_node;
    pub extern fn get_Block_n_cfg_outs(node: ?*const ir_node) u32;
    pub extern fn get_Block_n_cfg_outs_ka(node: ?*const ir_node) u32;
    pub extern fn get_Block_cfg_out(node: ?*const ir_node, pos: u32) ?*ir_node;
    pub extern fn get_Block_cfg_out_ex(node: ?*const ir_node, pos: u32, in_pos: [*]i32) ?*ir_node;
    pub extern fn get_Block_cfg_out_ka(node: ?*const ir_node, pos: u32) ?*ir_node;
    pub extern fn irg_out_walk(node: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn irg_out_block_walk(node: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void;
    pub extern fn compute_irg_outs(irg: ?*ir_graph) void;
    pub extern fn assure_irg_outs(irg: ?*ir_graph) void;
    pub extern fn free_irg_outs(irg: ?*ir_graph) void;
    pub extern fn irp_reserve_resources(irp: ?*ir_prog, resources: irp_resources_t) void;
    pub extern fn irp_free_resources(irp: ?*ir_prog, resources: irp_resources_t) void;
    pub extern fn irp_resources_reserved(irp: ?*const ir_prog) irp_resources_t;
    pub extern fn get_irp() ?*ir_prog;
    pub extern fn set_irp(irp: ?*ir_prog) void;
    pub extern fn new_ir_prog(name: [*]const u8) ?*ir_prog;
    pub extern fn free_ir_prog() void;
    pub extern fn set_irp_prog_name(name: [*]const u8) void;
    pub extern fn irp_prog_name_is_set() i32;
    pub extern fn get_irp_ident() [*]const u8;
    pub extern fn get_irp_name() [*]const u8;
    pub extern fn get_irp_main_irg() ?*ir_graph;
    pub extern fn set_irp_main_irg(main_irg: ?*ir_graph) void;
    pub extern fn get_irp_last_idx() usize;
    pub extern fn get_irp_n_irgs() usize;
    pub extern fn get_irp_irg(pos: usize) ?*ir_graph;
    pub extern fn set_irp_irg(pos: usize, irg: ?*ir_graph) void;
    pub extern fn get_segment_type(segment: ir_segment_t) ?*ir_type;
    pub extern fn set_segment_type(segment: ir_segment_t, new_type: ?*ir_type) void;
    pub extern fn get_glob_type() ?*ir_type;
    pub extern fn get_tls_type() ?*ir_type;
    pub extern fn ir_get_global(name: [*]const u8) ?*ir_entity;
    pub extern fn get_irp_n_types() usize;
    pub extern fn get_irp_type(pos: usize) ?*ir_type;
    pub extern fn set_irp_type(pos: usize, typ: ?*ir_type) void;
    pub extern fn get_const_code_irg() ?*ir_graph;
    pub extern fn get_irp_callee_info_state() irg_callee_info_state;
    pub extern fn set_irp_callee_info_state(s: irg_callee_info_state) void;
    pub extern fn get_irp_next_label_nr() ir_label_t;
    pub extern fn add_irp_asm(asm_string: [*]const u8) void;
    pub extern fn get_irp_n_asms() usize;
    pub extern fn get_irp_asm(pos: usize) [*]const u8;
    pub extern fn irn_verify(node: ?*const ir_node) i32;
    pub extern fn irg_verify(irg: ?*ir_graph) i32;
    pub extern fn irg_assert_verify(irg: ?*ir_graph) void;
    pub extern fn lower_CopyB(irg: ?*ir_graph, max_small_size: u32, min_large_size: u32, allow_misalignments: i32) void;
    pub extern fn lower_switch(irg: ?*ir_graph, small_switch: u32, spare_size: u32, selector_mode: ?*ir_mode) void;
    pub extern fn lower_highlevel_graph(irg: ?*ir_graph) void;
    pub extern fn lower_highlevel() void;
    pub extern fn lower_const_code() void;
    pub extern fn lower_mux(irg: ?*ir_graph, cb_func: ?lower_mux_callback) void;
    pub extern fn ir_create_intrinsics_map(list: [*]i_record, length: usize, part_block_used: i32) ?*ir_intrinsics_map;
    pub extern fn ir_free_intrinsics_map(map: ?*ir_intrinsics_map) void;
    pub extern fn ir_lower_intrinsics(irg: ?*ir_graph, map: ?*ir_intrinsics_map) void;
    pub extern fn i_mapper_abs(call: ?*ir_node) i32;
    pub extern fn i_mapper_sqrt(call: ?*ir_node) i32;
    pub extern fn i_mapper_cbrt(call: ?*ir_node) i32;
    pub extern fn i_mapper_pow(call: ?*ir_node) i32;
    pub extern fn i_mapper_exp(call: ?*ir_node) i32;
    pub extern fn i_mapper_exp2(call: ?*ir_node) i32;
    pub extern fn i_mapper_exp10(call: ?*ir_node) i32;
    pub extern fn i_mapper_log(call: ?*ir_node) i32;
    pub extern fn i_mapper_log2(call: ?*ir_node) i32;
    pub extern fn i_mapper_log10(call: ?*ir_node) i32;
    pub extern fn i_mapper_sin(call: ?*ir_node) i32;
    pub extern fn i_mapper_cos(call: ?*ir_node) i32;
    pub extern fn i_mapper_tan(call: ?*ir_node) i32;
    pub extern fn i_mapper_asin(call: ?*ir_node) i32;
    pub extern fn i_mapper_acos(call: ?*ir_node) i32;
    pub extern fn i_mapper_atan(call: ?*ir_node) i32;
    pub extern fn i_mapper_sinh(call: ?*ir_node) i32;
    pub extern fn i_mapper_cosh(call: ?*ir_node) i32;
    pub extern fn i_mapper_tanh(call: ?*ir_node) i32;
    pub extern fn i_mapper_strcmp(call: ?*ir_node) i32;
    pub extern fn i_mapper_strncmp(call: ?*ir_node) i32;
    pub extern fn i_mapper_strcpy(call: ?*ir_node) i32;
    pub extern fn i_mapper_strlen(call: ?*ir_node) i32;
    pub extern fn i_mapper_memcpy(call: ?*ir_node) i32;
    pub extern fn i_mapper_memmove(call: ?*ir_node) i32;
    pub extern fn i_mapper_memset(call: ?*ir_node) i32;
    pub extern fn i_mapper_memcmp(call: ?*ir_node) i32;
    pub extern fn ir_target_set(target_triple: [*]const u8) i32;
    pub extern fn ir_target_set_triple(machine: ?*const ir_machine_triple_t) i32;
    pub extern fn ir_target_option(option: [*]const u8) i32;
    pub extern fn ir_target_init() void;
    pub extern fn ir_target_experimental() [*]const u8;
    pub extern fn ir_target_big_endian() i32;
    pub extern fn ir_target_biggest_alignment() u32;
    pub extern fn ir_target_pointer_size() u32;
    pub extern fn ir_target_supports_pic() i32;
    pub extern fn ir_target_fast_unaligned_memaccess() i32;
    pub extern fn ir_target_float_arithmetic_mode() ?*ir_mode;
    pub extern fn ir_target_float_int_overflow_style() float_int_conversion_overflow_style_t;
    pub extern fn ir_platform_long_long_and_double_struct_align_override() u32;
    pub extern fn ir_platform_pic_is_default() i32;
    pub extern fn ir_platform_supports_thread_local_storage() i32;
    pub extern fn ir_platform_define_value(define: ?*const ir_platform_define_t) [*]const u8;
    pub extern fn ir_platform_wchar_type() ir_platform_type_t;
    pub extern fn ir_platform_wchar_is_signed() i32;
    pub extern fn ir_platform_intptr_type() ir_platform_type_t;
    pub extern fn ir_platform_type_size(@"type": ir_platform_type_t) u32;
    pub extern fn ir_platform_type_align(@"type": ir_platform_type_t) u32;
    pub extern fn ir_platform_type_mode(@"type": ir_platform_type_t, is_signed: i32) ?*ir_mode;
    pub extern fn ir_platform_va_list_type() ?*ir_type;
    pub extern fn ir_platform_user_label_prefix() u8;
    pub extern fn ir_platform_default_exe_name() [*]const u8;
    pub extern fn ir_platform_mangle_global(name: [*]const u8) [*]const u8;
    pub extern fn ir_platform_define_first() ?*const ir_platform_define_t;
    pub extern fn ir_platform_define_next(define: ?*const ir_platform_define_t) ?*const ir_platform_define_t;
    pub extern fn ir_platform_define_name(define: ?*const ir_platform_define_t) [*]const u8;
    pub extern fn ir_parse_machine_triple(triple_string: [*]const u8) ?*ir_machine_triple_t;
    pub extern fn ir_get_host_machine_triple() ?*ir_machine_triple_t;
    pub extern fn ir_triple_get_cpu_type(triple: ?*const ir_machine_triple_t) [*]const u8;
    pub extern fn ir_triple_get_manufacturer(triple: ?*const ir_machine_triple_t) [*]const u8;
    pub extern fn ir_triple_get_operating_system(triple: ?*const ir_machine_triple_t) [*]const u8;
    pub extern fn ir_triple_set_cpu_type(triple: ?*ir_machine_triple_t, cpu_type: [*]const u8) void;
    pub extern fn ir_free_machine_triple(triple: ?*ir_machine_triple_t) void;
    pub extern fn ir_timer_enter_high_priority() i32;
    pub extern fn ir_timer_leave_high_priority() i32;
    pub extern fn ir_timer_new() ?*ir_timer_t;
    pub extern fn ir_timer_free(timer: ?*ir_timer_t) void;
    pub extern fn ir_timer_start(timer: ?*ir_timer_t) void;
    pub extern fn ir_timer_reset_and_start(timer: ?*ir_timer_t) void;
    pub extern fn ir_timer_reset(timer: ?*ir_timer_t) void;
    pub extern fn ir_timer_stop(timer: ?*ir_timer_t) void;
    pub extern fn ir_timer_init_parent(timer: ?*ir_timer_t) void;
    pub extern fn ir_timer_push(timer: ?*ir_timer_t) void;
    pub extern fn ir_timer_pop(timer: ?*ir_timer_t) void;
    pub extern fn ir_timer_elapsed_msec(timer: ?*const ir_timer_t) u64;
    pub extern fn ir_timer_elapsed_usec(timer: ?*const ir_timer_t) u64;
    pub extern fn ir_timer_elapsed_sec(timer: ?*const ir_timer_t) f64;
    pub extern fn new_tarval_from_str(str: [*]const u8, len: usize, mode: ?*ir_mode) ?*ir_tarval;
    pub extern fn new_integer_tarval_from_str(str: [*]const u8, len: usize, negative: i32, base: u8, mode: ?*ir_mode) ?*ir_tarval;
    pub extern fn new_tarval_from_long(l: i64, mode: ?*ir_mode) ?*ir_tarval;
    pub extern fn new_tarval_from_bytes(buf: [*]const u8, mode: ?*ir_mode) ?*ir_tarval;
    pub extern fn new_tarval_nan(mode: ?*ir_mode, signaling: i32, payload: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_to_bytes(buffer: [*]u8, tv: ?*const ir_tarval) void;
    pub extern fn get_tarval_long(tv: ?*const ir_tarval) i64;
    pub extern fn tarval_is_long(tv: ?*const ir_tarval) i32;
    pub extern fn new_tarval_from_double(d: f64, mode: ?*ir_mode) ?*ir_tarval;
    pub extern fn new_tarval_from_long_double(d: f64, mode: ?*ir_mode) ?*ir_tarval;
    pub extern fn get_tarval_double(tv: ?*const ir_tarval) f64;
    pub extern fn get_tarval_long_double(tv: ?*const ir_tarval) f64;
    pub extern fn tarval_is_double(tv: ?*const ir_tarval) i32;
    pub extern fn get_tarval_mode(tv: ?*const ir_tarval) ?*ir_mode;
    pub extern fn tarval_is_negative(tv: ?*const ir_tarval) i32;
    pub extern fn tarval_is_null(tv: ?*const ir_tarval) i32;
    pub extern fn tarval_is_one(tv: ?*const ir_tarval) i32;
    pub extern fn tarval_is_all_one(tv: ?*const ir_tarval) i32;
    pub extern fn tarval_is_constant(tv: ?*const ir_tarval) i32;
    pub extern fn get_tarval_bad() ?*ir_tarval;
    pub extern fn get_tarval_unknown() ?*ir_tarval;
    pub extern fn get_tarval_b_false() ?*ir_tarval;
    pub extern fn get_tarval_b_true() ?*ir_tarval;
    pub extern fn tarval_set_wrap_on_overflow(wrap_on_overflow: i32) void;
    pub extern fn tarval_get_wrap_on_overflow() i32;
    pub extern fn tarval_cmp(a: ?*const ir_tarval, b: ?*const ir_tarval) ir_relation;
    pub extern fn tarval_convert_to(src: ?*const ir_tarval, mode: ?*ir_mode) ?*ir_tarval;
    pub extern fn tarval_bitcast(src: ?*const ir_tarval, mode: ?*ir_mode) ?*ir_tarval;
    pub extern fn tarval_not(a: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_neg(a: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_add(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_sub(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_mul(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_div(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_mod(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_divmod(a: ?*const ir_tarval, b: ?*const ir_tarval, mod_res: [*]?*ir_tarval) ?*ir_tarval;
    pub extern fn tarval_abs(a: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_and(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_andnot(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_or(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_ornot(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_eor(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_shl(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_shl_unsigned(a: ?*const ir_tarval, b: u32) ?*ir_tarval;
    pub extern fn tarval_shr(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_shr_unsigned(a: ?*const ir_tarval, b: u32) ?*ir_tarval;
    pub extern fn tarval_shrs(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval;
    pub extern fn tarval_shrs_unsigned(a: ?*const ir_tarval, b: u32) ?*ir_tarval;
    pub extern fn get_tarval_sub_bits(tv: ?*const ir_tarval, byte_ofs: u32) u8;
    pub extern fn get_tarval_popcount(tv: ?*const ir_tarval) i32;
    pub extern fn get_tarval_lowest_bit(tv: ?*const ir_tarval) i32;
    pub extern fn get_tarval_highest_bit(tv: ?*const ir_tarval) i32;
    pub extern fn tarval_zero_mantissa(tv: ?*const ir_tarval) i32;
    pub extern fn tarval_get_exponent(tv: ?*const ir_tarval) i32;
    pub extern fn tarval_ieee754_can_conv_lossless(tv: ?*const ir_tarval, mode: ?*const ir_mode) i32;
    pub extern fn tarval_ieee754_get_exact() u32;
    pub extern fn tarval_is_nan(tv: ?*const ir_tarval) i32;
    pub extern fn tarval_is_quiet_nan(tv: ?*const ir_tarval) i32;
    pub extern fn tarval_is_signaling_nan(tv: ?*const ir_tarval) i32;
    pub extern fn tarval_is_finite(tv: ?*const ir_tarval) i32;
    pub extern fn set_vrp_data(irg: ?*ir_graph) void;
    pub extern fn free_vrp_data(irg: ?*ir_graph) void;
    pub extern fn vrp_cmp(left: ?*const ir_node, right: ?*const ir_node) ir_relation;
    pub extern fn vrp_get_info(n: ?*const ir_node) [*]vrp_attr;
};

pub fn getEntityVisibility(entity: ?*const ir_entity) ir_visibility {
    return @intToEnum(ir_visibility, low_level.get_entity_visibility(entity));
}
pub fn setEntityVisibility(entity: ?*ir_entity, visibility: ir_visibility) void {
    return low_level.set_entity_visibility(entity, visibility);
}
pub fn entityIsExternallyVisible(entity: ?*const ir_entity) i32 {
    return low_level.entity_is_externally_visible(entity);
}
pub fn entityHasDefinition(entity: ?*const ir_entity) i32 {
    return low_level.entity_has_definition(entity);
}
pub fn newEntity(owner: ?*ir_type, name: [*]const u8, tp: ?*ir_type) ?*ir_entity {
    return low_level.new_entity(owner, name, tp);
}
pub fn newGlobalEntity(segment: ?*ir_type, ld_name: [*]const u8, @"type": ?*ir_type, visibility: ir_visibility, linkage: u32) ?*ir_entity {
    return low_level.new_global_entity(segment, ld_name, @"type", @enumToInt(visibility), linkage);
}
pub fn newParameterEntity(owner: ?*ir_type, pos: usize, @"type": ?*ir_type) ?*ir_entity {
    return low_level.new_parameter_entity(owner, pos, @"type");
}
pub fn newAliasEntity(owner: ?*ir_type, name: [*]const u8, alias: ?*ir_entity, @"type": ?*ir_type, visibility: ir_visibility) ?*ir_entity {
    return low_level.new_alias_entity(owner, name, alias, @"type", @enumToInt(visibility));
}
pub fn setEntityAlias(alias: ?*ir_entity, aliased: ?*ir_entity) void {
    return low_level.set_entity_alias(alias, aliased);
}
pub fn getEntityAlias(alias: ?*const ir_entity) ?*ir_entity {
    return low_level.get_entity_alias(alias);
}
pub fn checkEntity(ent: ?*const ir_entity) i32 {
    return low_level.check_entity(ent);
}
pub fn cloneEntity(old: ?*const ir_entity, name: [*]const u8, owner: ?*ir_type) ?*ir_entity {
    return low_level.clone_entity(old, name, owner);
}
pub fn freeEntity(ent: ?*ir_entity) void {
    return low_level.free_entity(ent);
}
pub fn getEntityName(ent: ?*const ir_entity) [*]const u8 {
    return low_level.get_entity_name(ent);
}
pub fn getEntityIdent(ent: ?*const ir_entity) [*]const u8 {
    return low_level.get_entity_ident(ent);
}
pub fn setEntityIdent(ent: ?*ir_entity, id: [*]const u8) void {
    return low_level.set_entity_ident(ent, id);
}
pub fn getEntityLdIdent(ent: ?*const ir_entity) [*]const u8 {
    return low_level.get_entity_ld_ident(ent);
}
pub fn setEntityLdIdent(ent: ?*ir_entity, ld_ident: [*]const u8) void {
    return low_level.set_entity_ld_ident(ent, ld_ident);
}
pub fn getEntityLdName(ent: ?*const ir_entity) [*]const u8 {
    return low_level.get_entity_ld_name(ent);
}
pub fn entityHasLdIdent(entity: ?*const ir_entity) i32 {
    return low_level.entity_has_ld_ident(entity);
}
pub fn getEntityOwner(ent: ?*const ir_entity) ?*ir_type {
    return low_level.get_entity_owner(ent);
}
pub fn setEntityOwner(ent: ?*ir_entity, owner: ?*ir_type) void {
    return low_level.set_entity_owner(ent, owner);
}
pub fn getEntityType(ent: ?*const ir_entity) ?*ir_type {
    return low_level.get_entity_type(ent);
}
pub fn setEntityType(ent: ?*ir_entity, tp: ?*ir_type) void {
    return low_level.set_entity_type(ent, tp);
}
pub fn getEntityLinkage(entity: ?*const ir_entity) ir_linkage {
    return @intToEnum(ir_linkage, low_level.get_entity_linkage(entity));
}
pub fn setEntityLinkage(entity: ?*ir_entity, linkage: u32) void {
    return low_level.set_entity_linkage(entity, linkage);
}
pub fn addEntityLinkage(entity: ?*ir_entity, linkage: u32) void {
    return low_level.add_entity_linkage(entity, linkage);
}
pub fn removeEntityLinkage(entity: ?*ir_entity, linkage: u32) void {
    return low_level.remove_entity_linkage(entity, linkage);
}
pub fn getEntityVolatility(ent: ?*const ir_entity) ir_volatility {
    return @intToEnum(ir_volatility, low_level.get_entity_volatility(ent));
}
pub fn setEntityVolatility(ent: ?*ir_entity, vol: u32) void {
    return low_level.set_entity_volatility(ent, vol);
}
pub fn getVolatilityName(@"var": u32) [*]const u8 {
    return low_level.get_volatility_name(@"var");
}
pub fn getEntityAlignment(entity: ?*const ir_entity) u32 {
    return low_level.get_entity_alignment(entity);
}
pub fn setEntityAlignment(entity: ?*ir_entity, alignment: u32) void {
    return low_level.set_entity_alignment(entity, alignment);
}
pub fn getEntityAligned(ent: ?*const ir_entity) ir_align {
    return @intToEnum(ir_align, low_level.get_entity_aligned(ent));
}
pub fn setEntityAligned(ent: ?*ir_entity, a: u32) void {
    return low_level.set_entity_aligned(ent, a);
}
pub fn getAlignName(a: u32) [*]const u8 {
    return low_level.get_align_name(a);
}
pub fn getEntityOffset(entity: ?*const ir_entity) i32 {
    return low_level.get_entity_offset(entity);
}
pub fn setEntityOffset(entity: ?*ir_entity, offset: i32) void {
    return low_level.set_entity_offset(entity, offset);
}
pub fn getEntityBitfieldOffset(entity: ?*const ir_entity) u32 {
    return low_level.get_entity_bitfield_offset(entity);
}
pub fn setEntityBitfieldOffset(entity: ?*ir_entity, offset: u32) void {
    return low_level.set_entity_bitfield_offset(entity, offset);
}
pub fn setEntityBitfieldSize(entity: ?*ir_entity, size: u32) void {
    return low_level.set_entity_bitfield_size(entity, size);
}
pub fn getEntityBitfieldSize(entity: ?*const ir_entity) u32 {
    return low_level.get_entity_bitfield_size(entity);
}
pub fn getEntityLink(ent: ?*const ir_entity) ?*anyopaque {
    return low_level.get_entity_link(ent);
}
pub fn setEntityLink(ent: ?*ir_entity, l: ?*anyopaque) void {
    return low_level.set_entity_link(ent, l);
}
pub fn getEntityIrg(ent: ?*const ir_entity) ?*ir_graph {
    return low_level.get_entity_irg(ent);
}
pub fn getEntityLinktimeIrg(ent: ?*const ir_entity) ?*ir_graph {
    return low_level.get_entity_linktime_irg(ent);
}
pub fn getEntityVtableNumber(ent: ?*const ir_entity) u32 {
    return low_level.get_entity_vtable_number(ent);
}
pub fn setEntityVtableNumber(ent: ?*ir_entity, vtable_number: u32) void {
    return low_level.set_entity_vtable_number(ent, vtable_number);
}
pub fn setEntityLabel(ent: ?*ir_entity, label: ir_label_t) void {
    return low_level.set_entity_label(ent, label);
}
pub fn getEntityLabel(ent: ?*const ir_entity) ir_label_t {
    return low_level.get_entity_label(ent);
}
pub fn getEntityUsage(ent: ?*const ir_entity) ir_entity_usage {
    return @intToEnum(ir_entity_usage, low_level.get_entity_usage(ent));
}
pub fn setEntityUsage(ent: ?*ir_entity, flag: u32) void {
    return low_level.set_entity_usage(ent, flag);
}
pub fn getEntityDbgInfo(ent: ?*const ir_entity) ?*dbg_info {
    return low_level.get_entity_dbg_info(ent);
}
pub fn setEntityDbgInfo(ent: ?*ir_entity, db: ?*dbg_info) void {
    return low_level.set_entity_dbg_info(ent, db);
}
pub fn isParameterEntity(entity: ?*const ir_entity) bool {
    return low_level.is_parameter_entity(entity) == 1;
}
pub fn getEntityParameterNumber(entity: ?*const ir_entity) usize {
    return low_level.get_entity_parameter_number(entity);
}
pub fn setEntityParameterNumber(entity: ?*ir_entity, n: usize) void {
    return low_level.set_entity_parameter_number(entity, n);
}
pub fn getInitializerKind(initializer: ?*const ir_initializer_t) ir_initializer_kind_t {
    return @intToEnum(ir_initializer_kind_t, low_level.get_initializer_kind(initializer));
}
pub fn getInitializerKindName(ini: u32) [*]const u8 {
    return low_level.get_initializer_kind_name(ini);
}
pub fn getInitializerNull() ?*ir_initializer_t {
    return low_level.get_initializer_null();
}
pub fn createInitializerConst(value: ?*ir_node) ?*ir_initializer_t {
    return low_level.create_initializer_const(value);
}
pub fn createInitializerTarval(tv: ?*ir_tarval) ?*ir_initializer_t {
    return low_level.create_initializer_tarval(tv);
}
pub fn getInitializerConstValue(initializer: ?*const ir_initializer_t) ?*ir_node {
    return low_level.get_initializer_const_value(initializer);
}
pub fn getInitializerTarvalValue(initialzier: ?*const ir_initializer_t) ?*ir_tarval {
    return low_level.get_initializer_tarval_value(initialzier);
}
pub fn createInitializerCompound(n_entries: usize) ?*ir_initializer_t {
    return low_level.create_initializer_compound(n_entries);
}
pub fn getInitializerCompoundNEntries(initializer: ?*const ir_initializer_t) usize {
    return low_level.get_initializer_compound_n_entries(initializer);
}
pub fn setInitializerCompoundValue(initializer: ?*ir_initializer_t, index: usize, value: ?*ir_initializer_t) void {
    return low_level.set_initializer_compound_value(initializer, index, value);
}
pub fn getInitializerCompoundValue(initializer: ?*const ir_initializer_t, index: usize) ?*ir_initializer_t {
    return low_level.get_initializer_compound_value(initializer, index);
}
pub fn setEntityInitializer(entity: ?*ir_entity, initializer: ?*ir_initializer_t) void {
    return low_level.set_entity_initializer(entity, initializer);
}
pub fn getEntityInitializer(entity: ?*const ir_entity) ?*ir_initializer_t {
    return low_level.get_entity_initializer(entity);
}
pub fn addEntityOverwrites(ent: ?*ir_entity, overwritten: ?*ir_entity) void {
    return low_level.add_entity_overwrites(ent, overwritten);
}
pub fn getEntityNOverwrites(ent: ?*const ir_entity) usize {
    return low_level.get_entity_n_overwrites(ent);
}
pub fn getEntityOverwritesIndex(ent: ?*const ir_entity, overwritten: ?*ir_entity) usize {
    return low_level.get_entity_overwrites_index(ent, overwritten);
}
pub fn getEntityOverwrites(ent: ?*const ir_entity, pos: usize) ?*ir_entity {
    return low_level.get_entity_overwrites(ent, pos);
}
pub fn setEntityOverwrites(ent: ?*ir_entity, pos: usize, overwritten: ?*ir_entity) void {
    return low_level.set_entity_overwrites(ent, pos, overwritten);
}
pub fn removeEntityOverwrites(ent: ?*ir_entity, overwritten: ?*ir_entity) void {
    return low_level.remove_entity_overwrites(ent, overwritten);
}
pub fn getEntityNOverwrittenby(ent: ?*const ir_entity) usize {
    return low_level.get_entity_n_overwrittenby(ent);
}
pub fn getEntityOverwrittenbyIndex(ent: ?*const ir_entity, overwrites: ?*ir_entity) usize {
    return low_level.get_entity_overwrittenby_index(ent, overwrites);
}
pub fn getEntityOverwrittenby(ent: ?*const ir_entity, pos: usize) ?*ir_entity {
    return low_level.get_entity_overwrittenby(ent, pos);
}
pub fn setEntityOverwrittenby(ent: ?*ir_entity, pos: usize, overwrites: ?*ir_entity) void {
    return low_level.set_entity_overwrittenby(ent, pos, overwrites);
}
pub fn removeEntityOverwrittenby(ent: ?*ir_entity, overwrites: ?*ir_entity) void {
    return low_level.remove_entity_overwrittenby(ent, overwrites);
}
pub fn isCompoundEntity(ent: ?*const ir_entity) bool {
    return low_level.is_compound_entity(ent) == 1;
}
pub fn isMethodEntity(ent: ?*const ir_entity) bool {
    return low_level.is_method_entity(ent) == 1;
}
pub fn isAliasEntity(ent: ?*const ir_entity) bool {
    return low_level.is_alias_entity(ent) == 1;
}
pub fn getEntityNr(ent: ?*const ir_entity) i64 {
    return low_level.get_entity_nr(ent);
}
pub fn getEntityVisited(ent: ?*const ir_entity) ir_visited_t {
    return low_level.get_entity_visited(ent);
}
pub fn setEntityVisited(ent: ?*ir_entity, num: ir_visited_t) void {
    return low_level.set_entity_visited(ent, num);
}
pub fn markEntityVisited(ent: ?*ir_entity) void {
    return low_level.mark_entity_visited(ent);
}
pub fn entityVisited(ent: ?*const ir_entity) i32 {
    return low_level.entity_visited(ent);
}
pub fn entityNotVisited(ent: ?*const ir_entity) i32 {
    return low_level.entity_not_visited(ent);
}
pub fn entityHasAdditionalProperties(entity: ?*const ir_entity) i32 {
    return low_level.entity_has_additional_properties(entity);
}
pub fn getEntityAdditionalProperties(ent: ?*const ir_entity) mtp_additional_properties {
    return @intToEnum(mtp_additional_properties, low_level.get_entity_additional_properties(ent));
}
pub fn setEntityAdditionalProperties(ent: ?*ir_entity, prop: u32) void {
    return low_level.set_entity_additional_properties(ent, prop);
}
pub fn addEntityAdditionalProperties(ent: ?*ir_entity, flag: u32) void {
    return low_level.add_entity_additional_properties(ent, flag);
}
pub fn getUnknownEntity() ?*ir_entity {
    return low_level.get_unknown_entity();
}
pub fn isUnknownEntity(entity: ?*const ir_entity) bool {
    return low_level.is_unknown_entity(entity) == 1;
}
pub fn getTypeOpcodeName(opcode: u32) [*]const u8 {
    return low_level.get_type_opcode_name(opcode);
}
pub fn isSubclassOf(low: ?*const ir_type, high: ?*const ir_type) bool {
    return low_level.is_SubClass_of(low, high) == 1;
}
pub fn isSubclassPtrOf(low: ?*ir_type, high: ?*ir_type) bool {
    return low_level.is_SubClass_ptr_of(low, high) == 1;
}
pub fn isOverwrittenBy(high: ?*ir_entity, low: ?*ir_entity) bool {
    return low_level.is_overwritten_by(high, low) == 1;
}
pub fn resolveEntPolymorphy(dynamic_class: ?*ir_type, static_ent: ?*ir_entity) ?*ir_entity {
    return low_level.resolve_ent_polymorphy(dynamic_class, static_ent);
}
pub fn setIrpInhTransitiveClosureState(s: u32) void {
    return low_level.set_irp_inh_transitive_closure_state(s);
}
pub fn invalidateIrpInhTransitiveClosureState() void {
    return low_level.invalidate_irp_inh_transitive_closure_state();
}
pub fn getIrpInhTransitiveClosureState() inh_transitive_closure_state {
    return @intToEnum(inh_transitive_closure_state, low_level.get_irp_inh_transitive_closure_state());
}
pub fn computeInhTransitiveClosure() void {
    return low_level.compute_inh_transitive_closure();
}
pub fn freeInhTransitiveClosure() void {
    return low_level.free_inh_transitive_closure();
}
pub fn getClassTransSubtypeFirst(tp: ?*const ir_type) ?*ir_type {
    return low_level.get_class_trans_subtype_first(tp);
}
pub fn getClassTransSubtypeNext(tp: ?*const ir_type) ?*ir_type {
    return low_level.get_class_trans_subtype_next(tp);
}
pub fn isClassTransSubtype(tp: ?*const ir_type, subtp: ?*const ir_type) bool {
    return low_level.is_class_trans_subtype(tp, subtp) == 1;
}
pub fn getClassTransSupertypeFirst(tp: ?*const ir_type) ?*ir_type {
    return low_level.get_class_trans_supertype_first(tp);
}
pub fn getClassTransSupertypeNext(tp: ?*const ir_type) ?*ir_type {
    return low_level.get_class_trans_supertype_next(tp);
}
pub fn getEntityTransOverwrittenbyFirst(ent: ?*const ir_entity) ?*ir_entity {
    return low_level.get_entity_trans_overwrittenby_first(ent);
}
pub fn getEntityTransOverwrittenbyNext(ent: ?*const ir_entity) ?*ir_entity {
    return low_level.get_entity_trans_overwrittenby_next(ent);
}
pub fn getEntityTransOverwritesFirst(ent: ?*const ir_entity) ?*ir_entity {
    return low_level.get_entity_trans_overwrites_first(ent);
}
pub fn getEntityTransOverwritesNext(ent: ?*const ir_entity) ?*ir_entity {
    return low_level.get_entity_trans_overwrites_next(ent);
}
pub fn checkType(tp: ?*const ir_type) i32 {
    return low_level.check_type(tp);
}
pub fn trVerify() i32 {
    return low_level.tr_verify();
}
pub fn freeType(tp: ?*ir_type) void {
    return low_level.free_type(tp);
}
pub fn getTypeOpcode(@"type": ?*const ir_type) tp_opcode {
    return @intToEnum(tp_opcode, low_level.get_type_opcode(@"type"));
}
pub fn irPrintType(buffer: [*]u8, buffer_size: usize, tp: ?*const ir_type) void {
    return low_level.ir_print_type(buffer, buffer_size, tp);
}
pub fn getTypeStateName(s: u32) [*]const u8 {
    return low_level.get_type_state_name(s);
}
pub fn getTypeState(tp: ?*const ir_type) ir_type_state {
    return @intToEnum(ir_type_state, low_level.get_type_state(tp));
}
pub fn setTypeState(tp: ?*ir_type, state: u32) void {
    return low_level.set_type_state(tp, state);
}
pub fn getTypeMode(tp: ?*const ir_type) ?*ir_mode {
    return low_level.get_type_mode(tp);
}
pub fn getTypeSize(tp: ?*const ir_type) u32 {
    return low_level.get_type_size(tp);
}
pub fn setTypeSize(tp: ?*ir_type, size: u32) void {
    return low_level.set_type_size(tp, size);
}
pub fn getTypeAlignment(tp: ?*const ir_type) u32 {
    return low_level.get_type_alignment(tp);
}
pub fn setTypeAlignment(tp: ?*ir_type, @"align": u32) void {
    return low_level.set_type_alignment(tp, @"align");
}
pub fn getTypeVisited(tp: ?*const ir_type) ir_visited_t {
    return low_level.get_type_visited(tp);
}
pub fn setTypeVisited(tp: ?*ir_type, num: ir_visited_t) void {
    return low_level.set_type_visited(tp, num);
}
pub fn markTypeVisited(tp: ?*ir_type) void {
    return low_level.mark_type_visited(tp);
}
pub fn typeVisited(tp: ?*const ir_type) i32 {
    return low_level.type_visited(tp);
}
pub fn getTypeLink(tp: ?*const ir_type) ?*anyopaque {
    return low_level.get_type_link(tp);
}
pub fn setTypeLink(tp: ?*ir_type, l: ?*anyopaque) void {
    return low_level.set_type_link(tp, l);
}
pub fn incMasterTypeVisited() void {
    return low_level.inc_master_type_visited();
}
pub fn setMasterTypeVisited(val: ir_visited_t) void {
    return low_level.set_master_type_visited(val);
}
pub fn getMasterTypeVisited() ir_visited_t {
    return low_level.get_master_type_visited();
}
pub fn setTypeDbgInfo(tp: ?*ir_type, db: ?*type_dbg_info) void {
    return low_level.set_type_dbg_info(tp, db);
}
pub fn getTypeDbgInfo(tp: ?*const ir_type) ?*type_dbg_info {
    return low_level.get_type_dbg_info(tp);
}
pub fn getTypeNr(tp: ?*const ir_type) i64 {
    return low_level.get_type_nr(tp);
}
pub fn newTypeClass(name: [*]const u8) ?*ir_type {
    return low_level.new_type_class(name);
}
pub fn getClassNMembers(clss: ?*const ir_type) usize {
    return low_level.get_class_n_members(clss);
}
pub fn getClassMember(clss: ?*const ir_type, pos: usize) ?*ir_entity {
    return low_level.get_class_member(clss, pos);
}
pub fn getClassMemberIndex(clss: ?*const ir_type, mem: ?*const ir_entity) usize {
    return low_level.get_class_member_index(clss, mem);
}
pub fn addClassSubtype(clss: ?*ir_type, subtype: ?*ir_type) void {
    return low_level.add_class_subtype(clss, subtype);
}
pub fn getClassNSubtypes(clss: ?*const ir_type) usize {
    return low_level.get_class_n_subtypes(clss);
}
pub fn getClassSubtype(clss: ?*const ir_type, pos: usize) ?*ir_type {
    return low_level.get_class_subtype(clss, pos);
}
pub fn getClassSubtypeIndex(clss: ?*const ir_type, subclass: ?*const ir_type) usize {
    return low_level.get_class_subtype_index(clss, subclass);
}
pub fn setClassSubtype(clss: ?*ir_type, subtype: ?*ir_type, pos: usize) void {
    return low_level.set_class_subtype(clss, subtype, pos);
}
pub fn removeClassSubtype(clss: ?*ir_type, subtype: ?*ir_type) void {
    return low_level.remove_class_subtype(clss, subtype);
}
pub fn addClassSupertype(clss: ?*ir_type, supertype: ?*ir_type) void {
    return low_level.add_class_supertype(clss, supertype);
}
pub fn getClassNSupertypes(clss: ?*const ir_type) usize {
    return low_level.get_class_n_supertypes(clss);
}
pub fn getClassSupertypeIndex(clss: ?*const ir_type, super_clss: ?*const ir_type) usize {
    return low_level.get_class_supertype_index(clss, super_clss);
}
pub fn getClassSupertype(clss: ?*const ir_type, pos: usize) ?*ir_type {
    return low_level.get_class_supertype(clss, pos);
}
pub fn setClassSupertype(clss: ?*ir_type, supertype: ?*ir_type, pos: usize) void {
    return low_level.set_class_supertype(clss, supertype, pos);
}
pub fn removeClassSupertype(clss: ?*ir_type, supertype: ?*ir_type) void {
    return low_level.remove_class_supertype(clss, supertype);
}
pub fn isClassType(clss: ?*const ir_type) bool {
    return low_level.is_Class_type(clss) == 1;
}
pub fn newTypeStruct(name: [*]const u8) ?*ir_type {
    return low_level.new_type_struct(name);
}
pub fn getStructNMembers(strct: ?*const ir_type) usize {
    return low_level.get_struct_n_members(strct);
}
pub fn getStructMember(strct: ?*const ir_type, pos: usize) ?*ir_entity {
    return low_level.get_struct_member(strct, pos);
}
pub fn getStructMemberIndex(strct: ?*const ir_type, member: ?*const ir_entity) usize {
    return low_level.get_struct_member_index(strct, member);
}
pub fn isStructType(strct: ?*const ir_type) bool {
    return low_level.is_Struct_type(strct) == 1;
}
pub fn newTypeUnion(name: [*]const u8) ?*ir_type {
    return low_level.new_type_union(name);
}
pub fn getUnionNMembers(uni: ?*const ir_type) usize {
    return low_level.get_union_n_members(uni);
}
pub fn getUnionMember(uni: ?*const ir_type, pos: usize) ?*ir_entity {
    return low_level.get_union_member(uni, pos);
}
pub fn getUnionMemberIndex(uni: ?*const ir_type, member: ?*const ir_entity) usize {
    return low_level.get_union_member_index(uni, member);
}
pub fn isUnionType(uni: ?*const ir_type) bool {
    return low_level.is_Union_type(uni) == 1;
}
pub fn newTypeMethod(n_param: usize, n_res: usize, is_variadic: bool, cc_mask: calling_convention, property_mask: mtp_additional_properties) ?*ir_type {
    switch (cc_mask) {
        .calling_convention => return low_level.new_type_method(n_param, n_res, @boolToInt(is_variadic), @enumToInt(cc_mask.calling_convention), property_mask),
        .calling_convention_special => return low_level.new_type_method(n_param, n_res, @boolToInt(is_variadic), @enumToInt(cc_mask.calling_convention_special), property_mask),
        .value => return low_level.new_type_method(n_param, n_res, @boolToInt(is_variadic), cc_mask.value, property_mask),
    }
}
pub fn getMethodNParams(method: ?*const ir_type) usize {
    return low_level.get_method_n_params(method);
}
pub fn getMethodParamType(method: ?*const ir_type, pos: usize) ?*ir_type {
    return low_level.get_method_param_type(method, pos);
}
pub fn setMethodParamType(method: ?*ir_type, pos: usize, tp: ?*ir_type) void {
    return low_level.set_method_param_type(method, pos, tp);
}
pub fn getMethodNRess(method: ?*const ir_type) usize {
    return low_level.get_method_n_ress(method);
}
pub fn getMethodResType(method: ?*const ir_type, pos: usize) ?*ir_type {
    return low_level.get_method_res_type(method, pos);
}
pub fn setMethodResType(method: ?*ir_type, pos: usize, tp: ?*ir_type) void {
    return low_level.set_method_res_type(method, pos, tp);
}
pub fn isMethodVariadic(method: ?*const ir_type) bool {
    return low_level.is_method_variadic(method) == 1;
}
pub fn getMethodAdditionalProperties(method: ?*const ir_type) mtp_additional_properties {
    return @intToEnum(mtp_additional_properties, low_level.get_method_additional_properties(method));
}
pub fn getMethodCallingConvention(method: ?*const ir_type) calling_convention {
    return @intToEnum(calling_convention, low_level.get_method_calling_convention(method));
}
pub fn getMethodNRegparams(method: ?*ir_type) u32 {
    return low_level.get_method_n_regparams(method);
}
pub fn isMethodType(method: ?*const ir_type) bool {
    return low_level.is_Method_type(method) == 1;
}
pub fn newTypeArray(element_type: ?*ir_type, n_elements: u32) ?*ir_type {
    return low_level.new_type_array(element_type, n_elements);
}
pub fn getArraySize(array: ?*const ir_type) u32 {
    return low_level.get_array_size(array);
}
pub fn getArrayElementType(array: ?*const ir_type) ?*ir_type {
    return low_level.get_array_element_type(array);
}
pub fn isArrayType(array: ?*const ir_type) bool {
    return low_level.is_Array_type(array) == 1;
}
pub fn newTypePointer(points_to: ?*ir_type) ?*ir_type {
    return low_level.new_type_pointer(points_to);
}
pub fn setPointerPointsToType(pointer: ?*ir_type, tp: ?*ir_type) void {
    return low_level.set_pointer_points_to_type(pointer, tp);
}
pub fn getPointerPointsToType(pointer: ?*const ir_type) ?*ir_type {
    return low_level.get_pointer_points_to_type(pointer);
}
pub fn isPointerType(pointer: ?*const ir_type) bool {
    return low_level.is_Pointer_type(pointer) == 1;
}
pub fn newTypePrimitive(mode: ?*ir_mode) ?*ir_type {
    return low_level.new_type_primitive(mode);
}
pub fn isPrimitiveType(primitive: ?*const ir_type) bool {
    return low_level.is_Primitive_type(primitive) == 1;
}
pub fn getCodeType() ?*ir_type {
    return low_level.get_code_type();
}
pub fn isCodeType(tp: ?*const ir_type) bool {
    return low_level.is_code_type(tp) == 1;
}
pub fn getUnknownType() ?*ir_type {
    return low_level.get_unknown_type();
}
pub fn isUnknownType(@"type": ?*const ir_type) bool {
    return low_level.is_unknown_type(@"type") == 1;
}
pub fn isAtomicType(tp: ?*const ir_type) bool {
    return low_level.is_atomic_type(tp) == 1;
}
pub fn getCompoundIdent(tp: ?*const ir_type) [*]const u8 {
    return low_level.get_compound_ident(tp);
}
pub fn getCompoundName(tp: ?*const ir_type) [*]const u8 {
    return low_level.get_compound_name(tp);
}
pub fn getCompoundNMembers(tp: ?*const ir_type) usize {
    return low_level.get_compound_n_members(tp);
}
pub fn getCompoundMember(tp: ?*const ir_type, pos: usize) ?*ir_entity {
    return low_level.get_compound_member(tp, pos);
}
pub fn getCompoundMemberIndex(tp: ?*const ir_type, member: ?*const ir_entity) usize {
    return low_level.get_compound_member_index(tp, member);
}
pub fn removeCompoundMember(compound: ?*ir_type, entity: ?*ir_entity) void {
    return low_level.remove_compound_member(compound, entity);
}
pub fn defaultLayoutCompoundType(tp: ?*ir_type) void {
    return low_level.default_layout_compound_type(tp);
}
pub fn isCompoundType(tp: ?*const ir_type) bool {
    return low_level.is_compound_type(tp) == 1;
}
pub fn newTypeFrame() ?*ir_type {
    return low_level.new_type_frame();
}
pub fn isFrameType(tp: ?*const ir_type) bool {
    return low_level.is_frame_type(tp) == 1;
}
pub fn cloneFrameType(@"type": ?*ir_type) ?*ir_type {
    return low_level.clone_frame_type(@"type");
}
pub fn isSegmentType(tp: ?*const ir_type) bool {
    return low_level.is_segment_type(tp) == 1;
}
pub fn typeWalk(pre: ?type_walk_func, post: ?type_walk_func, env: ?*anyopaque) void {
    return low_level.type_walk(pre, post, env);
}
pub fn typeWalkIrg(irg: ?*ir_graph, pre: ?type_walk_func, post: ?type_walk_func, env: ?*anyopaque) void {
    return low_level.type_walk_irg(irg, pre, post, env);
}
pub fn typeWalkSuper2sub(pre: ?type_walk_func, post: ?type_walk_func, env: ?*anyopaque) void {
    return low_level.type_walk_super2sub(pre, post, env);
}
pub fn typeWalkSuper(pre: ?type_walk_func, post: ?type_walk_func, env: ?*anyopaque) void {
    return low_level.type_walk_super(pre, post, env);
}
pub fn classWalkSuper2sub(pre: ?class_walk_func, post: ?class_walk_func, env: ?*anyopaque) void {
    return low_level.class_walk_super2sub(pre, post, env);
}
pub fn walkTypesEntities(tp: ?*ir_type, doit: ?entity_walk_func, env: ?*anyopaque) void {
    return low_level.walk_types_entities(tp, doit, env);
}
pub fn getMethodParamAccess(ent: ?*ir_entity, pos: usize) ptr_access_kind {
    return @intToEnum(ptr_access_kind, low_level.get_method_param_access(ent, pos));
}
pub fn analyzeIrgArgs(irg: ?*ir_graph) void {
    return low_level.analyze_irg_args(irg);
}
pub fn getMethodParamWeight(ent: ?*ir_entity, pos: usize) u32 {
    return low_level.get_method_param_weight(ent, pos);
}
pub fn analyzeIrgArgsWeight(irg: ?*ir_graph) void {
    return low_level.analyze_irg_args_weight(irg);
}
pub fn newIntMode(name: [*]const u8, bit_size: u32, sign: i32, modulo_shift: u32) ?*ir_mode {
    return low_level.new_int_mode(name, bit_size, sign, modulo_shift);
}
pub fn newReferenceMode(name: [*]const u8, bit_size: u32, modulo_shift: u32) ?*ir_mode {
    return low_level.new_reference_mode(name, bit_size, modulo_shift);
}
pub fn newFloatMode(name: [*]const u8, arithmetic: u32, exponent_size: u32, mantissa_size: u32, int_conv_overflow: u32) ?*ir_mode {
    return low_level.new_float_mode(name, arithmetic, exponent_size, mantissa_size, int_conv_overflow);
}
pub fn newNonArithmeticMode(name: [*]const u8, bit_size: u32) ?*ir_mode {
    return low_level.new_non_arithmetic_mode(name, bit_size);
}
pub fn getModeIdent(mode: ?*const ir_mode) [*]const u8 {
    return low_level.get_mode_ident(mode);
}
pub fn getModeName(mode: ?*const ir_mode) [*]const u8 {
    return low_level.get_mode_name(mode);
}
pub fn getModeSizeBits(mode: ?*const ir_mode) u32 {
    return low_level.get_mode_size_bits(mode);
}
pub fn getModeSizeBytes(mode: ?*const ir_mode) u32 {
    return low_level.get_mode_size_bytes(mode);
}
pub fn getModeArithmetic(mode: ?*const ir_mode) ir_mode_arithmetic {
    return @intToEnum(ir_mode_arithmetic, low_level.get_mode_arithmetic(mode));
}
pub fn getModeModuloShift(mode: ?*const ir_mode) u32 {
    return low_level.get_mode_modulo_shift(mode);
}
pub fn getModeMin(mode: ?*const ir_mode) ?*ir_tarval {
    return low_level.get_mode_min(mode);
}
pub fn getModeMax(mode: ?*const ir_mode) ?*ir_tarval {
    return low_level.get_mode_max(mode);
}
pub fn getModeNull(mode: ?*const ir_mode) ?*ir_tarval {
    return low_level.get_mode_null(mode);
}
pub fn getModeOne(mode: ?*const ir_mode) ?*ir_tarval {
    return low_level.get_mode_one(mode);
}
pub fn getModeAllOne(mode: ?*const ir_mode) ?*ir_tarval {
    return low_level.get_mode_all_one(mode);
}
pub fn getModeInfinite(mode: ?*const ir_mode) ?*ir_tarval {
    return low_level.get_mode_infinite(mode);
}
pub fn getModef() ?*ir_mode {
    return low_level.get_modeF();
}
pub fn getModed() ?*ir_mode {
    return low_level.get_modeD();
}
pub fn getModebs() ?*ir_mode {
    return low_level.get_modeBs();
}
pub fn getModebu() ?*ir_mode {
    return low_level.get_modeBu();
}
pub fn getModehs() ?*ir_mode {
    return low_level.get_modeHs();
}
pub fn getModehu() ?*ir_mode {
    return low_level.get_modeHu();
}
pub fn getModeis() ?*ir_mode {
    return low_level.get_modeIs();
}
pub fn getModeiu() ?*ir_mode {
    return low_level.get_modeIu();
}
pub fn getModels() ?*ir_mode {
    return low_level.get_modeLs();
}
pub fn getModelu() ?*ir_mode {
    return low_level.get_modeLu();
}
pub fn getModep() ?*ir_mode {
    return low_level.get_modeP();
}
pub fn getModeb() ?*ir_mode {
    return low_level.get_modeb();
}
pub fn getModex() ?*ir_mode {
    return low_level.get_modeX();
}
pub fn getModebb() ?*ir_mode {
    return low_level.get_modeBB();
}
pub fn getModem() ?*ir_mode {
    return low_level.get_modeM();
}
pub fn getModet() ?*ir_mode {
    return low_level.get_modeT();
}
pub fn getModeany() ?*ir_mode {
    return low_level.get_modeANY();
}
pub fn getModebad() ?*ir_mode {
    return low_level.get_modeBAD();
}
pub fn setModep(p: ?*ir_mode) void {
    return low_level.set_modeP(p);
}
pub fn modeIsSigned(mode: ?*const ir_mode) i32 {
    return low_level.mode_is_signed(mode);
}
pub fn modeIsFloat(mode: ?*const ir_mode) i32 {
    return low_level.mode_is_float(mode);
}
pub fn modeIsInt(mode: ?*const ir_mode) i32 {
    return low_level.mode_is_int(mode);
}
pub fn modeIsReference(mode: ?*const ir_mode) i32 {
    return low_level.mode_is_reference(mode);
}
pub fn modeIsNum(mode: ?*const ir_mode) i32 {
    return low_level.mode_is_num(mode);
}
pub fn modeIsData(mode: ?*const ir_mode) i32 {
    return low_level.mode_is_data(mode);
}
pub fn smallerMode(sm: ?*const ir_mode, lm: ?*const ir_mode) i32 {
    return low_level.smaller_mode(sm, lm);
}
pub fn valuesInMode(sm: ?*const ir_mode, lm: ?*const ir_mode) i32 {
    return low_level.values_in_mode(sm, lm);
}
pub fn findUnsignedMode(mode: ?*const ir_mode) ?*ir_mode {
    return low_level.find_unsigned_mode(mode);
}
pub fn findSignedMode(mode: ?*const ir_mode) ?*ir_mode {
    return low_level.find_signed_mode(mode);
}
pub fn findDoubleBitsIntMode(mode: ?*const ir_mode) ?*ir_mode {
    return low_level.find_double_bits_int_mode(mode);
}
pub fn modeHasSignedZero(mode: ?*const ir_mode) i32 {
    return low_level.mode_has_signed_zero(mode);
}
pub fn modeOverflowOnUnaryMinus(mode: ?*const ir_mode) i32 {
    return low_level.mode_overflow_on_unary_Minus(mode);
}
pub fn modeWrapAround(mode: ?*const ir_mode) i32 {
    return low_level.mode_wrap_around(mode);
}
pub fn getReferenceOffsetMode(mode: ?*const ir_mode) ?*ir_mode {
    return low_level.get_reference_offset_mode(mode);
}
pub fn setReferenceOffsetMode(ref_mode: ?*ir_mode, int_mode: ?*ir_mode) void {
    return low_level.set_reference_offset_mode(ref_mode, int_mode);
}
pub fn getModeMantissaSize(mode: ?*const ir_mode) u32 {
    return low_level.get_mode_mantissa_size(mode);
}
pub fn getModeExponentSize(mode: ?*const ir_mode) u32 {
    return low_level.get_mode_exponent_size(mode);
}
pub fn getModeFloatIntOverflow(mode: ?*const ir_mode) float_int_conversion_overflow_style_t {
    return @intToEnum(float_int_conversion_overflow_style_t, low_level.get_mode_float_int_overflow(mode));
}
pub fn isReinterpretCast(src: ?*const ir_mode, dst: ?*const ir_mode) bool {
    return low_level.is_reinterpret_cast(src, dst) == 1;
}
pub fn getTypeForMode(mode: ?*const ir_mode) ?*ir_type {
    return low_level.get_type_for_mode(mode);
}
pub fn irGetNModes() usize {
    return low_level.ir_get_n_modes();
}
pub fn irGetMode(num: usize) ?*ir_mode {
    return low_level.ir_get_mode(num);
}
pub fn optimizeCf(irg: ?*ir_graph) void {
    return low_level.optimize_cf(irg);
}
pub fn optJumpthreading(irg: ?*ir_graph) void {
    return low_level.opt_jumpthreading(irg);
}
pub fn optBool(irg: ?*ir_graph) void {
    return low_level.opt_bool(irg);
}
pub fn convOpt(irg: ?*ir_graph) void {
    return low_level.conv_opt(irg);
}
pub fn optimizeFunccalls() void {
    return low_level.optimize_funccalls();
}
pub fn doGvnPre(irg: ?*ir_graph) void {
    return low_level.do_gvn_pre(irg);
}
pub fn optIfConv(irg: ?*ir_graph) void {
    return low_level.opt_if_conv(irg);
}
pub fn optIfConvCb(irg: ?*ir_graph, callback: arch_allow_ifconv_func) void {
    return low_level.opt_if_conv_cb(irg, callback);
}
pub fn optParallelizeMem(irg: ?*ir_graph) void {
    return low_level.opt_parallelize_mem(irg);
}
pub fn canReplaceLoadByConst(load: ?*const ir_node, c: ?*ir_node) ?*ir_node {
    return low_level.can_replace_load_by_const(load, c);
}
pub fn optimizeLoadStore(irg: ?*ir_graph) void {
    return low_level.optimize_load_store(irg);
}
pub fn combineMemops(irg: ?*ir_graph) void {
    return low_level.combine_memops(irg);
}
pub fn optLdst(irg: ?*ir_graph) void {
    return low_level.opt_ldst(irg);
}
pub fn optFrameIrg(irg: ?*ir_graph) void {
    return low_level.opt_frame_irg(irg);
}
pub fn optOsr(irg: ?*ir_graph, flags: u32) void {
    return low_level.opt_osr(irg, flags);
}
pub fn removePhiCycles(irg: ?*ir_graph) void {
    return low_level.remove_phi_cycles(irg);
}
pub fn procCloning(threshold: f32) void {
    return low_level.proc_cloning(threshold);
}
pub fn optimizeReassociation(irg: ?*ir_graph) void {
    return low_level.optimize_reassociation(irg);
}
pub fn normalizeOneReturn(irg: ?*ir_graph) void {
    return low_level.normalize_one_return(irg);
}
pub fn normalizeNReturns(irg: ?*ir_graph) void {
    return low_level.normalize_n_returns(irg);
}
pub fn scalarReplacementOpt(irg: ?*ir_graph) void {
    return low_level.scalar_replacement_opt(irg);
}
pub fn optTailRecIrg(irg: ?*ir_graph) void {
    return low_level.opt_tail_rec_irg(irg);
}
pub fn combo(irg: ?*ir_graph) void {
    return low_level.combo(irg);
}
pub fn inlineFunctions(maxsize: u32, inline_threshold: i32, after_inline_opt: opt_ptr) void {
    return low_level.inline_functions(maxsize, inline_threshold, after_inline_opt);
}
pub fn shapeBlocks(irg: ?*ir_graph) void {
    return low_level.shape_blocks(irg);
}
pub fn doLoopInversion(irg: ?*ir_graph) void {
    return low_level.do_loop_inversion(irg);
}
pub fn doLoopUnrolling(irg: ?*ir_graph) void {
    return low_level.do_loop_unrolling(irg);
}
pub fn unrollLoops(irg: ?*ir_graph, factor: u32, maxsize: u32) void {
    return low_level.unroll_loops(irg, factor, maxsize);
}
pub fn doLoopPeeling(irg: ?*ir_graph) void {
    return low_level.do_loop_peeling(irg);
}
pub fn garbageCollectEntities() void {
    return low_level.garbage_collect_entities();
}
pub fn deadNodeElimination(irg: ?*ir_graph) void {
    return low_level.dead_node_elimination(irg);
}
pub fn placeCode(irg: ?*ir_graph) void {
    return low_level.place_code(irg);
}
pub fn occultConsts(irg: ?*ir_graph) void {
    return low_level.occult_consts(irg);
}
pub fn valueNotNull(n: ?*const ir_node, confirm: [*]?*const ir_node) i32 {
    return low_level.value_not_null(n, confirm);
}
pub fn computedValueCmpConfirm(left: ?*ir_node, right: ?*ir_node, relation: ir_relation) ?*ir_tarval {
    return low_level.computed_value_Cmp_Confirm(left, right, @enumToInt(relation));
}
pub fn createCompilerlibEntity(name: [*]const u8, mt: ?*ir_type) ?*ir_entity {
    return low_level.create_compilerlib_entity(name, mt);
}
pub fn beLowerForTarget() void {
    return low_level.be_lower_for_target();
}
pub fn beSetAfterTransformFunc(func: after_transform_func) void {
    return low_level.be_set_after_transform_func(func);
}
pub fn beMain(output: *std.c.FILE, compilation_unit_name: [*]const u8) void {
    return low_level.be_main(output, compilation_unit_name);
}
pub fn beParseAsmConstraints(constraints: [*]const u8) asm_constraint_flags_t {
    return @intToEnum(asm_constraint_flags_t, low_level.be_parse_asm_constraints(constraints));
}
pub fn beIsValidClobber(clobber: [*]const u8) i32 {
    return low_level.be_is_valid_clobber(clobber);
}
pub fn beDwarfSetSourceLanguage(language: u32) void {
    return low_level.be_dwarf_set_source_language(language);
}
pub fn beDwarfSetCompilationDirectory(directory: [*]const u8) void {
    return low_level.be_dwarf_set_compilation_directory(directory);
}
pub fn getIrpCallgraphState() irp_callgraph_state {
    return @intToEnum(irp_callgraph_state, low_level.get_irp_callgraph_state());
}
pub fn setIrpCallgraphState(s: u32) void {
    return low_level.set_irp_callgraph_state(s);
}
pub fn getIrgNCallers(irg: ?*const ir_graph) usize {
    return low_level.get_irg_n_callers(irg);
}
pub fn getIrgCaller(irg: ?*const ir_graph, pos: usize) ?*ir_graph {
    return low_level.get_irg_caller(irg, pos);
}
pub fn isIrgCallerBackedge(irg: ?*const ir_graph, pos: usize) bool {
    return low_level.is_irg_caller_backedge(irg, pos) == 1;
}
pub fn hasIrgCallerBackedge(irg: ?*const ir_graph) i32 {
    return low_level.has_irg_caller_backedge(irg);
}
pub fn getIrgCallerLoopDepth(irg: ?*const ir_graph, pos: usize) usize {
    return low_level.get_irg_caller_loop_depth(irg, pos);
}
pub fn getIrgNCallees(irg: ?*const ir_graph) usize {
    return low_level.get_irg_n_callees(irg);
}
pub fn getIrgCallee(irg: ?*const ir_graph, pos: usize) ?*ir_graph {
    return low_level.get_irg_callee(irg, pos);
}
pub fn isIrgCalleeBackedge(irg: ?*const ir_graph, pos: usize) bool {
    return low_level.is_irg_callee_backedge(irg, pos) == 1;
}
pub fn hasIrgCalleeBackedge(irg: ?*const ir_graph) i32 {
    return low_level.has_irg_callee_backedge(irg);
}
pub fn getIrgCalleeLoopDepth(irg: ?*const ir_graph, pos: usize) usize {
    return low_level.get_irg_callee_loop_depth(irg, pos);
}
pub fn getIrgMethodExecutionFrequency(irg: ?*const ir_graph) f64 {
    return low_level.get_irg_method_execution_frequency(irg);
}
pub fn computeCallgraph() void {
    return low_level.compute_callgraph();
}
pub fn freeCallgraph() void {
    return low_level.free_callgraph();
}
pub fn callgraphWalk(pre: ?callgraph_walk_func, post: ?callgraph_walk_func, env: ?*anyopaque) void {
    return low_level.callgraph_walk(pre, post, env);
}
pub fn findCallgraphRecursions() void {
    return low_level.find_callgraph_recursions();
}
pub fn analyseLoopNestingDepth() void {
    return low_level.analyse_loop_nesting_depth();
}
pub fn getIrpLoopNestingDepthState() loop_nesting_depth_state {
    return @intToEnum(loop_nesting_depth_state, low_level.get_irp_loop_nesting_depth_state());
}
pub fn setIrpLoopNestingDepthState(s: u32) void {
    return low_level.set_irp_loop_nesting_depth_state(s);
}
pub fn setIrpLoopNestingDepthStateInconsistent() void {
    return low_level.set_irp_loop_nesting_depth_state_inconsistent();
}
pub fn computeCdep(irg: ?*ir_graph) void {
    return low_level.compute_cdep(irg);
}
pub fn freeCdep(irg: ?*ir_graph) void {
    return low_level.free_cdep(irg);
}
pub fn getCdepNode(cdep: ?*const ir_cdep) ?*ir_node {
    return low_level.get_cdep_node(cdep);
}
pub fn getCdepNext(cdep: ?*const ir_cdep) ?*ir_cdep {
    return low_level.get_cdep_next(cdep);
}
pub fn findCdep(block: ?*const ir_node) ?*ir_cdep {
    return low_level.find_cdep(block);
}
pub fn exchangeCdep(old: ?*ir_node, nw: ?*const ir_node) void {
    return low_level.exchange_cdep(old, nw);
}
pub fn isCdepOn(dependee: ?*const ir_node, candidate: ?*const ir_node) bool {
    return low_level.is_cdep_on(dependee, candidate) == 1;
}
pub fn getUniqueCdep(block: ?*const ir_node) ?*ir_node {
    return low_level.get_unique_cdep(block);
}
pub fn hasMultipleCdep(block: ?*const ir_node) i32 {
    return low_level.has_multiple_cdep(block);
}
pub fn cgana(free_methods: [*][*]?*ir_entity) usize {
    return low_level.cgana(free_methods);
}
pub fn freeCalleeInfo(irg: ?*ir_graph) void {
    return low_level.free_callee_info(irg);
}
pub fn freeIrpCalleeInfo() void {
    return low_level.free_irp_callee_info();
}
pub fn optCallAddrs() void {
    return low_level.opt_call_addrs();
}
pub fn cgCallHasCallees(node: ?*const ir_node) i32 {
    return low_level.cg_call_has_callees(node);
}
pub fn cgGetCallNCallees(node: ?*const ir_node) usize {
    return low_level.cg_get_call_n_callees(node);
}
pub fn cgGetCallCallee(node: ?*const ir_node, pos: usize) ?*ir_entity {
    return low_level.cg_get_call_callee(node, pos);
}
pub fn cgSetCallCalleeArr(node: ?*ir_node, n: usize, arr: [*]?*ir_entity) void {
    return low_level.cg_set_call_callee_arr(node, n, arr);
}
pub fn cgRemoveCallCalleeArr(node: ?*ir_node) void {
    return low_level.cg_remove_call_callee_arr(node);
}
pub fn dbgAction2Str(a: u32) [*]const u8 {
    return low_level.dbg_action_2_str(a);
}
pub fn dbgInit(dbg_info_merge_pair: ?merge_pair_func, dbg_info_merge_sets: ?merge_sets_func) void {
    return low_level.dbg_init(dbg_info_merge_pair, dbg_info_merge_sets);
}
pub fn irSetDebugRetrieve(func: retrieve_dbg_func) void {
    return low_level.ir_set_debug_retrieve(func);
}
pub fn irSetTypeDebugRetrieve(func: retrieve_type_dbg_func) void {
    return low_level.ir_set_type_debug_retrieve(func);
}
pub fn irRetrieveDbgInfo(dbg: ?*const dbg_info) src_loc_t {
    return low_level.ir_retrieve_dbg_info(dbg);
}
pub fn irRetrieveTypeDbgInfo(buffer: [*]u8, buffer_size: usize, tdbgi: ?*const type_dbg_info) void {
    return low_level.ir_retrieve_type_dbg_info(buffer, buffer_size, tdbgi);
}
pub fn irEstimateExecfreq(irg: ?*ir_graph) void {
    return low_level.ir_estimate_execfreq(irg);
}
pub fn getBlockExecfreq(block: ?*const ir_node) f64 {
    return low_level.get_block_execfreq(block);
}
pub fn irInit() void {
    return low_level.ir_init();
}
pub fn irInitLibrary() void {
    return low_level.ir_init_library();
}
pub fn irFinish() void {
    return low_level.ir_finish();
}
pub fn irGetVersionMajor() u32 {
    return low_level.ir_get_version_major();
}
pub fn irGetVersionMinor() u32 {
    return low_level.ir_get_version_minor();
}
pub fn irGetVersionMicro() u32 {
    return low_level.ir_get_version_micro();
}
pub fn irGetVersionRevision() [*]const u8 {
    return low_level.ir_get_version_revision();
}
pub fn irGetVersionBuild() [*]const u8 {
    return low_level.ir_get_version_build();
}
pub fn getKind(firm_thing: ?*const anyopaque) firm_kind {
    return @intToEnum(firm_kind, low_level.get_kind(firm_thing));
}
pub fn getIrnHeight(h: ?*const ir_heights_t, irn: ?*const ir_node) u32 {
    return low_level.get_irn_height(h, irn);
}
pub fn heightsReachableInBlock(h: ?*ir_heights_t, src: ?*const ir_node, tgt: ?*const ir_node) i32 {
    return low_level.heights_reachable_in_block(h, src, tgt);
}
pub fn heightsRecomputeBlock(h: ?*ir_heights_t, block: ?*ir_node) u32 {
    return low_level.heights_recompute_block(h, block);
}
pub fn heightsNew(irg: ?*ir_graph) ?*ir_heights_t {
    return low_level.heights_new(irg);
}
pub fn heightsFree(h: ?*ir_heights_t) void {
    return low_level.heights_free(h);
}
pub fn newIdFromStr(str: [*]const u8) [*]const u8 {
    return low_level.new_id_from_str(str);
}
pub fn newIdFromChars(str: [*]const u8, len: usize) [*]const u8 {
    return low_level.new_id_from_chars(str, len);
}
pub fn newIdFmt(fmt: [*]const u8, variadic: anytype) [*]const u8 {
    return low_level.new_id_fmt(fmt, variadic);
}
pub fn getIdStr(id: [*]const u8) [*]const u8 {
    return low_level.get_id_str(id);
}
pub fn idUnique(tag: [*]const u8) [*]const u8 {
    return low_level.id_unique(tag);
}
pub fn gcIrgs(n_keep: usize, keep_arr: [*]?*ir_entity) void {
    return low_level.gc_irgs(n_keep, keep_arr);
}
pub fn getOpName(op: ?*const ir_op) [*]const u8 {
    return low_level.get_op_name(op);
}
pub fn getOpCode(op: ?*const ir_op) u32 {
    return low_level.get_op_code(op);
}
pub fn getOpPinStateName(s: u32) [*]const u8 {
    return low_level.get_op_pin_state_name(s);
}
pub fn getOpPinned(op: ?*const ir_op) op_pin_state {
    return @intToEnum(op_pin_state, low_level.get_op_pinned(op));
}
pub fn getNextIrOpcode() u32 {
    return low_level.get_next_ir_opcode();
}
pub fn getNextIrOpcodes(num: u32) u32 {
    return low_level.get_next_ir_opcodes(num);
}
pub fn getGenericFunctionPtr(op: ?*const ir_op) op_func {
    return low_level.get_generic_function_ptr(op);
}
pub fn setGenericFunctionPtr(op: ?*ir_op, func: op_func) void {
    return low_level.set_generic_function_ptr(op, func);
}
pub fn getOpFlags(op: ?*const ir_op) irop_flags {
    return @intToEnum(irop_flags, low_level.get_op_flags(op));
}
pub fn setOpHash(op: ?*ir_op, func: hash_func) void {
    return low_level.set_op_hash(op, func);
}
pub fn setOpComputedValue(op: ?*ir_op, func: computed_value_func) void {
    return low_level.set_op_computed_value(op, func);
}
pub fn setOpComputedValueProj(op: ?*ir_op, func: computed_value_func) void {
    return low_level.set_op_computed_value_proj(op, func);
}
pub fn setOpEquivalentNode(op: ?*ir_op, func: equivalent_node_func) void {
    return low_level.set_op_equivalent_node(op, func);
}
pub fn setOpEquivalentNodeProj(op: ?*ir_op, func: equivalent_node_func) void {
    return low_level.set_op_equivalent_node_proj(op, func);
}
pub fn setOpTransformNode(op: ?*ir_op, func: transform_node_func) void {
    return low_level.set_op_transform_node(op, func);
}
pub fn setOpTransformNodeProj(op: ?*ir_op, func: transform_node_func) void {
    return low_level.set_op_transform_node_proj(op, func);
}
pub fn setOpAttrsEqual(op: ?*ir_op, func: node_attrs_equal_func) void {
    return low_level.set_op_attrs_equal(op, func);
}
pub fn setOpReassociate(op: ?*ir_op, func: reassociate_func) void {
    return low_level.set_op_reassociate(op, func);
}
pub fn setOpCopyAttr(op: ?*ir_op, func: copy_attr_func) void {
    return low_level.set_op_copy_attr(op, func);
}
pub fn setOpGetTypeAttr(op: ?*ir_op, func: get_type_attr_func) void {
    return low_level.set_op_get_type_attr(op, func);
}
pub fn setOpGetEntityAttr(op: ?*ir_op, func: get_entity_attr_func) void {
    return low_level.set_op_get_entity_attr(op, func);
}
pub fn setOpVerify(op: ?*ir_op, func: verify_node_func) void {
    return low_level.set_op_verify(op, func);
}
pub fn setOpVerifyProj(op: ?*ir_op, func: verify_proj_node_func) void {
    return low_level.set_op_verify_proj(op, func);
}
pub fn setOpDump(op: ?*ir_op, func: dump_node_func) void {
    return low_level.set_op_dump(op, func);
}
pub fn newIrOp(code: u32, name: [*]const u8, p: u32, flags: u32, opar: u32, op_index: i32, attr_size: usize) ?*ir_op {
    return low_level.new_ir_op(code, name, p, flags, opar, op_index, attr_size);
}
pub fn freeIrOp(code: ?*ir_op) void {
    return low_level.free_ir_op(code);
}
pub fn irGetNOpcodes() u32 {
    return low_level.ir_get_n_opcodes();
}
pub fn irGetOpcode(code: u32) ?*ir_op {
    return low_level.ir_get_opcode(code);
}
pub fn irClearOpcodesGenericFunc() void {
    return low_level.ir_clear_opcodes_generic_func();
}
pub fn irOpSetMemoryIndex(op: ?*ir_op, memory_index: i32) void {
    return low_level.ir_op_set_memory_index(op, memory_index);
}
pub fn irOpSetFragileIndices(op: ?*ir_op, pn_x_regular: u32, pn_x_except: u32) void {
    return low_level.ir_op_set_fragile_indices(op, pn_x_regular, pn_x_except);
}
pub fn newRdAsm(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, text: [*]const u8, n_constraints: usize, constraints: [*]ir_asm_constraint, n_clobbers: usize, clobbers: [*][*]const u8, flags: u32) ?*ir_node {
    return low_level.new_rd_ASM(dbgi, block, irn_mem, arity, in, text, n_constraints, constraints, n_clobbers, clobbers, flags);
}
pub fn newRAsm(block: ?*ir_node, irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, text: [*]const u8, n_constraints: usize, constraints: [*]ir_asm_constraint, n_clobbers: usize, clobbers: [*][*]const u8, flags: u32) ?*ir_node {
    return low_level.new_r_ASM(block, irn_mem, arity, in, text, n_constraints, constraints, n_clobbers, clobbers, flags);
}
pub fn newDAsm(dbgi: ?*dbg_info, irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, text: [*]const u8, n_constraints: usize, constraints: [*]ir_asm_constraint, n_clobbers: usize, clobbers: [*][*]const u8, flags: u32) ?*ir_node {
    return low_level.new_d_ASM(dbgi, irn_mem, arity, in, text, n_constraints, constraints, n_clobbers, clobbers, flags);
}
pub fn newAsm(irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, text: [*]const u8, n_constraints: usize, constraints: [*]ir_asm_constraint, n_clobbers: usize, clobbers: [*][*]const u8, flags: u32) ?*ir_node {
    return low_level.new_ASM(irn_mem, arity, in, text, n_constraints, constraints, n_clobbers, clobbers, flags);
}
pub fn isAsm(node: ?*const ir_node) bool {
    return low_level.is_ASM(node) == 1;
}
pub fn getAsmMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_ASM_mem(node);
}
pub fn setAsmMem(node: ?*ir_node, mem: ?*ir_node) void {
    return low_level.set_ASM_mem(node, mem);
}
pub fn getAsmNInputs(node: ?*const ir_node) i32 {
    return low_level.get_ASM_n_inputs(node);
}
pub fn getAsmInput(node: ?*const ir_node, pos: i32) ?*ir_node {
    return low_level.get_ASM_input(node, pos);
}
pub fn setAsmInput(node: ?*ir_node, pos: i32, input: ?*ir_node) void {
    return low_level.set_ASM_input(node, pos, input);
}
pub fn getAsmInputArr(node: ?*ir_node) [*]?*ir_node {
    return low_level.get_ASM_input_arr(node);
}
pub fn getAsmConstraints(node: ?*const ir_node) [*]ir_asm_constraint {
    return low_level.get_ASM_constraints(node);
}
pub fn setAsmConstraints(node: ?*ir_node, constraints: [*]ir_asm_constraint) void {
    return low_level.set_ASM_constraints(node, constraints);
}
pub fn getAsmClobbers(node: ?*const ir_node) [*]const u8 {
    return low_level.get_ASM_clobbers(node);
}
pub fn setAsmClobbers(node: ?*ir_node, clobbers: [*][*]const u8) void {
    return low_level.set_ASM_clobbers(node, clobbers);
}
pub fn getAsmText(node: ?*const ir_node) [*]const u8 {
    return low_level.get_ASM_text(node);
}
pub fn setAsmText(node: ?*ir_node, text: [*]const u8) void {
    return low_level.set_ASM_text(node, text);
}
pub fn getOpAsm() ?*ir_op {
    return low_level.get_op_ASM();
}
pub fn newRdAdd(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Add(dbgi, block, irn_left, irn_right);
}
pub fn newRAdd(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_r_Add(block, irn_left, irn_right);
}
pub fn newDAdd(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_d_Add(dbgi, irn_left, irn_right);
}
pub fn newAdd(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_Add(irn_left, irn_right);
}
pub fn isAdd(node: ?*const ir_node) bool {
    return low_level.is_Add(node) == 1;
}
pub fn getAddLeft(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Add_left(node);
}
pub fn setAddLeft(node: ?*ir_node, left: ?*ir_node) void {
    return low_level.set_Add_left(node, left);
}
pub fn getAddRight(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Add_right(node);
}
pub fn setAddRight(node: ?*ir_node, right: ?*ir_node) void {
    return low_level.set_Add_right(node, right);
}
pub fn getOpAdd() ?*ir_op {
    return low_level.get_op_Add();
}
pub fn newRdAddress(dbgi: ?*dbg_info, irg: ?*ir_graph, entity: ?*ir_entity) ?*ir_node {
    return low_level.new_rd_Address(dbgi, irg, entity);
}
pub fn newRAddress(irg: ?*ir_graph, entity: ?*ir_entity) ?*ir_node {
    return low_level.new_r_Address(irg, entity);
}
pub fn newDAddress(dbgi: ?*dbg_info, entity: ?*ir_entity) ?*ir_node {
    return low_level.new_d_Address(dbgi, entity);
}
pub fn newAddress(entity: ?*ir_entity) ?*ir_node {
    return low_level.new_Address(entity);
}
pub fn isAddress(node: ?*const ir_node) bool {
    return low_level.is_Address(node) == 1;
}
pub fn getAddressEntity(node: ?*const ir_node) ?*ir_entity {
    return low_level.get_Address_entity(node);
}
pub fn setAddressEntity(node: ?*ir_node, entity: ?*ir_entity) void {
    return low_level.set_Address_entity(node, entity);
}
pub fn getOpAddress() ?*ir_op {
    return low_level.get_op_Address();
}
pub fn newRdAlign(dbgi: ?*dbg_info, irg: ?*ir_graph, mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_rd_Align(dbgi, irg, mode, @"type");
}
pub fn newRAlign(irg: ?*ir_graph, mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_r_Align(irg, mode, @"type");
}
pub fn newDAlign(dbgi: ?*dbg_info, mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_d_Align(dbgi, mode, @"type");
}
pub fn newAlign(mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_Align(mode, @"type");
}
pub fn isAlign(node: ?*const ir_node) bool {
    return low_level.is_Align(node) == 1;
}
pub fn getAlignType(node: ?*const ir_node) ?*ir_type {
    return low_level.get_Align_type(node);
}
pub fn setAlignType(node: ?*ir_node, @"type": ?*ir_type) void {
    return low_level.set_Align_type(node, @"type");
}
pub fn getOpAlign() ?*ir_op {
    return low_level.get_op_Align();
}
pub fn newRdAlloc(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_size: ?*ir_node, alignment: u32) ?*ir_node {
    return low_level.new_rd_Alloc(dbgi, block, irn_mem, irn_size, alignment);
}
pub fn newRAlloc(block: ?*ir_node, irn_mem: ?*ir_node, irn_size: ?*ir_node, alignment: u32) ?*ir_node {
    return low_level.new_r_Alloc(block, irn_mem, irn_size, alignment);
}
pub fn newDAlloc(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_size: ?*ir_node, alignment: u32) ?*ir_node {
    return low_level.new_d_Alloc(dbgi, irn_mem, irn_size, alignment);
}
pub fn newAlloc(irn_mem: ?*ir_node, irn_size: ?*ir_node, alignment: u32) ?*ir_node {
    return low_level.new_Alloc(irn_mem, irn_size, alignment);
}
pub fn isAlloc(node: ?*const ir_node) bool {
    return low_level.is_Alloc(node) == 1;
}
pub fn getAllocMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Alloc_mem(node);
}
pub fn setAllocMem(node: ?*ir_node, mem: ?*ir_node) void {
    return low_level.set_Alloc_mem(node, mem);
}
pub fn getAllocSize(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Alloc_size(node);
}
pub fn setAllocSize(node: ?*ir_node, size: ?*ir_node) void {
    return low_level.set_Alloc_size(node, size);
}
pub fn getAllocAlignment(node: ?*const ir_node) u32 {
    return low_level.get_Alloc_alignment(node);
}
pub fn setAllocAlignment(node: ?*ir_node, alignment: u32) void {
    return low_level.set_Alloc_alignment(node, alignment);
}
pub fn getOpAlloc() ?*ir_op {
    return low_level.get_op_Alloc();
}
pub fn isAnchor(node: ?*const ir_node) bool {
    return low_level.is_Anchor(node) == 1;
}
pub fn getAnchorEndBlock(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Anchor_end_block(node);
}
pub fn setAnchorEndBlock(node: ?*ir_node, end_block: ?*ir_node) void {
    return low_level.set_Anchor_end_block(node, end_block);
}
pub fn getAnchorStartBlock(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Anchor_start_block(node);
}
pub fn setAnchorStartBlock(node: ?*ir_node, start_block: ?*ir_node) void {
    return low_level.set_Anchor_start_block(node, start_block);
}
pub fn getAnchorEnd(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Anchor_end(node);
}
pub fn setAnchorEnd(node: ?*ir_node, end: ?*ir_node) void {
    return low_level.set_Anchor_end(node, end);
}
pub fn getAnchorStart(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Anchor_start(node);
}
pub fn setAnchorStart(node: ?*ir_node, start: ?*ir_node) void {
    return low_level.set_Anchor_start(node, start);
}
pub fn getAnchorFrame(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Anchor_frame(node);
}
pub fn setAnchorFrame(node: ?*ir_node, frame: ?*ir_node) void {
    return low_level.set_Anchor_frame(node, frame);
}
pub fn getAnchorInitialMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Anchor_initial_mem(node);
}
pub fn setAnchorInitialMem(node: ?*ir_node, initial_mem: ?*ir_node) void {
    return low_level.set_Anchor_initial_mem(node, initial_mem);
}
pub fn getAnchorArgs(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Anchor_args(node);
}
pub fn setAnchorArgs(node: ?*ir_node, args: ?*ir_node) void {
    return low_level.set_Anchor_args(node, args);
}
pub fn getAnchorNoMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Anchor_no_mem(node);
}
pub fn setAnchorNoMem(node: ?*ir_node, no_mem: ?*ir_node) void {
    return low_level.set_Anchor_no_mem(node, no_mem);
}
pub fn getOpAnchor() ?*ir_op {
    return low_level.get_op_Anchor();
}
pub fn newRdAnd(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_rd_And(dbgi, block, irn_left, irn_right);
}
pub fn newRAnd(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_r_And(block, irn_left, irn_right);
}
pub fn newDAnd(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_d_And(dbgi, irn_left, irn_right);
}
pub fn newAnd(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_And(irn_left, irn_right);
}
pub fn isAnd(node: ?*const ir_node) bool {
    return low_level.is_And(node) == 1;
}
pub fn getAndLeft(node: ?*const ir_node) ?*ir_node {
    return low_level.get_And_left(node);
}
pub fn setAndLeft(node: ?*ir_node, left: ?*ir_node) void {
    return low_level.set_And_left(node, left);
}
pub fn getAndRight(node: ?*const ir_node) ?*ir_node {
    return low_level.get_And_right(node);
}
pub fn setAndRight(node: ?*ir_node, right: ?*ir_node) void {
    return low_level.set_And_right(node, right);
}
pub fn getOpAnd() ?*ir_op {
    return low_level.get_op_And();
}
pub fn newRdBad(dbgi: ?*dbg_info, irg: ?*ir_graph, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_rd_Bad(dbgi, irg, mode);
}
pub fn newRBad(irg: ?*ir_graph, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_r_Bad(irg, mode);
}
pub fn newDBad(dbgi: ?*dbg_info, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_d_Bad(dbgi, mode);
}
pub fn newBad(mode: ?*ir_mode) ?*ir_node {
    return low_level.new_Bad(mode);
}
pub fn isBad(node: ?*const ir_node) bool {
    return low_level.is_Bad(node) == 1;
}
pub fn getOpBad() ?*ir_op {
    return low_level.get_op_Bad();
}
pub fn newRdBitcast(dbgi: ?*dbg_info, block: ?*ir_node, irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_rd_Bitcast(dbgi, block, irn_op, mode);
}
pub fn newRBitcast(block: ?*ir_node, irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_r_Bitcast(block, irn_op, mode);
}
pub fn newDBitcast(dbgi: ?*dbg_info, irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_d_Bitcast(dbgi, irn_op, mode);
}
pub fn newBitcast(irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_Bitcast(irn_op, mode);
}
pub fn isBitcast(node: ?*const ir_node) bool {
    return low_level.is_Bitcast(node) == 1;
}
pub fn getBitcastOp(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Bitcast_op(node);
}
pub fn setBitcastOp(node: ?*ir_node, op: ?*ir_node) void {
    return low_level.set_Bitcast_op(node, op);
}
pub fn getOpBitcast() ?*ir_op {
    return low_level.get_op_Bitcast();
}
pub fn newRdBlock(dbgi: ?*dbg_info, irg: ?*ir_graph, arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_rd_Block(dbgi, irg, arity, in);
}
pub fn newRBlock(irg: ?*ir_graph, arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_r_Block(irg, arity, in);
}
pub fn newDBlock(dbgi: ?*dbg_info, arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_d_Block(dbgi, arity, in);
}
pub fn newBlock(arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_Block(arity, in);
}
pub fn isBlock(node: ?*const ir_node) bool {
    return low_level.is_Block(node) == 1;
}
pub fn getBlockNCfgpreds(node: ?*const ir_node) i32 {
    return low_level.get_Block_n_cfgpreds(node);
}
pub fn getBlockCfgpred(node: ?*const ir_node, pos: i32) ?*ir_node {
    return low_level.get_Block_cfgpred(node, pos);
}
pub fn setBlockCfgpred(node: ?*ir_node, pos: i32, cfgpred: ?*ir_node) void {
    return low_level.set_Block_cfgpred(node, pos, cfgpred);
}
pub fn getBlockCfgpredArr(node: ?*ir_node) [*]?*ir_node {
    return low_level.get_Block_cfgpred_arr(node);
}
pub fn getBlockEntity(node: ?*const ir_node) ?*ir_entity {
    return low_level.get_Block_entity(node);
}
pub fn setBlockEntity(node: ?*ir_node, entity: ?*ir_entity) void {
    return low_level.set_Block_entity(node, entity);
}
pub fn getOpBlock() ?*ir_op {
    return low_level.get_op_Block();
}
pub fn newRdBuiltin(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, kind: u32, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_rd_Builtin(dbgi, block, irn_mem, arity, in, kind, @"type");
}
pub fn newRBuiltin(block: ?*ir_node, irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, kind: u32, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_r_Builtin(block, irn_mem, arity, in, kind, @"type");
}
pub fn newDBuiltin(dbgi: ?*dbg_info, irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, kind: u32, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_d_Builtin(dbgi, irn_mem, arity, in, kind, @"type");
}
pub fn newBuiltin(irn_mem: ?*ir_node, arity: i32, in: [*]const ?*ir_node, kind: u32, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_Builtin(irn_mem, arity, in, kind, @"type");
}
pub fn isBuiltin(node: ?*const ir_node) bool {
    return low_level.is_Builtin(node) == 1;
}
pub fn getBuiltinMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Builtin_mem(node);
}
pub fn setBuiltinMem(node: ?*ir_node, mem: ?*ir_node) void {
    return low_level.set_Builtin_mem(node, mem);
}
pub fn getBuiltinNParams(node: ?*const ir_node) i32 {
    return low_level.get_Builtin_n_params(node);
}
pub fn getBuiltinParam(node: ?*const ir_node, pos: i32) ?*ir_node {
    return low_level.get_Builtin_param(node, pos);
}
pub fn setBuiltinParam(node: ?*ir_node, pos: i32, param: ?*ir_node) void {
    return low_level.set_Builtin_param(node, pos, param);
}
pub fn getBuiltinParamArr(node: ?*ir_node) [*]?*ir_node {
    return low_level.get_Builtin_param_arr(node);
}
pub fn getBuiltinKind(node: ?*const ir_node) ir_builtin_kind {
    return @intToEnum(ir_builtin_kind, low_level.get_Builtin_kind(node));
}
pub fn setBuiltinKind(node: ?*ir_node, kind: u32) void {
    return low_level.set_Builtin_kind(node, kind);
}
pub fn getBuiltinType(node: ?*const ir_node) ?*ir_type {
    return low_level.get_Builtin_type(node);
}
pub fn setBuiltinType(node: ?*ir_node, @"type": ?*ir_type) void {
    return low_level.set_Builtin_type(node, @"type");
}
pub fn getOpBuiltin() ?*ir_op {
    return low_level.get_op_Builtin();
}
pub fn newRdCall(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, arity: i32, in: ?[*]const ?*ir_node, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_rd_Call(dbgi, block, irn_mem, irn_ptr, arity, in, @"type");
}
pub fn newRCall(block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, arity: i32, in: ?[*]const ?*ir_node, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_r_Call(block, irn_mem, irn_ptr, arity, in, @"type");
}
pub fn newDCall(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, arity: i32, in: ?[*]const ?*ir_node, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_d_Call(dbgi, irn_mem, irn_ptr, arity, in, @"type");
}
pub fn newCall(irn_mem: ?*ir_node, irn_ptr: ?*ir_node, arity: i32, in: ?[*]const ?*ir_node, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_Call(irn_mem, irn_ptr, arity, in, @"type");
}
pub fn isCall(node: ?*const ir_node) bool {
    return low_level.is_Call(node) == 1;
}
pub fn getCallMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Call_mem(node);
}
pub fn setCallMem(node: ?*ir_node, mem: ?*ir_node) void {
    return low_level.set_Call_mem(node, mem);
}
pub fn getCallPtr(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Call_ptr(node);
}
pub fn setCallPtr(node: ?*ir_node, ptr: ?*ir_node) void {
    return low_level.set_Call_ptr(node, ptr);
}
pub fn getCallNParams(node: ?*const ir_node) i32 {
    return low_level.get_Call_n_params(node);
}
pub fn getCallParam(node: ?*const ir_node, pos: i32) ?*ir_node {
    return low_level.get_Call_param(node, pos);
}
pub fn setCallParam(node: ?*ir_node, pos: i32, param: ?*ir_node) void {
    return low_level.set_Call_param(node, pos, param);
}
pub fn getCallParamArr(node: ?*ir_node) [*]?*ir_node {
    return low_level.get_Call_param_arr(node);
}
pub fn getCallType(node: ?*const ir_node) ?*ir_type {
    return low_level.get_Call_type(node);
}
pub fn setCallType(node: ?*ir_node, @"type": ?*ir_type) void {
    return low_level.set_Call_type(node, @"type");
}
pub fn getOpCall() ?*ir_op {
    return low_level.get_op_Call();
}
pub fn newRdCmp(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, relation: ir_relation) ?*ir_node {
    return low_level.new_rd_Cmp(dbgi, block, irn_left, irn_right, relation);
}
pub fn newRCmp(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, relation: ir_relation) ?*ir_node {
    return low_level.new_r_Cmp(block, irn_left, irn_right, relation);
}
pub fn newDCmp(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node, relation: ir_relation) ?*ir_node {
    return low_level.new_d_Cmp(dbgi, irn_left, irn_right, relation);
}
pub fn newCmp(irn_left: ?*ir_node, irn_right: ?*ir_node, relation: ir_relation) ?*ir_node {
    return low_level.new_Cmp(irn_left, irn_right, relation);
}
pub fn isCmp(node: ?*const ir_node) bool {
    return low_level.is_Cmp(node) == 1;
}
pub fn getCmpLeft(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Cmp_left(node);
}
pub fn setCmpLeft(node: ?*ir_node, left: ?*ir_node) void {
    return low_level.set_Cmp_left(node, left);
}
pub fn getCmpRight(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Cmp_right(node);
}
pub fn setCmpRight(node: ?*ir_node, right: ?*ir_node) void {
    return low_level.set_Cmp_right(node, right);
}
pub fn getCmpRelation(node: ?*const ir_node) ir_relation {
    return @intToEnum(ir_relation, low_level.get_Cmp_relation(node));
}
pub fn setCmpRelation(node: ?*ir_node, relation: ir_relation) void {
    return low_level.set_Cmp_relation(node, relation);
}
pub fn getOpCmp() ?*ir_op {
    return low_level.get_op_Cmp();
}
pub fn newRdCond(dbgi: ?*dbg_info, block: ?*ir_node, irn_selector: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Cond(dbgi, block, irn_selector);
}
pub fn newRCond(block: ?*ir_node, irn_selector: ?*ir_node) ?*ir_node {
    return low_level.new_r_Cond(block, irn_selector);
}
pub fn newDCond(dbgi: ?*dbg_info, irn_selector: ?*ir_node) ?*ir_node {
    return low_level.new_d_Cond(dbgi, irn_selector);
}
pub fn newCond(irn_selector: ?*ir_node) ?*ir_node {
    return low_level.new_Cond(irn_selector);
}
pub fn isCond(node: ?*const ir_node) bool {
    return low_level.is_Cond(node) == 1;
}
pub fn getCondSelector(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Cond_selector(node);
}
pub fn setCondSelector(node: ?*ir_node, selector: ?*ir_node) void {
    return low_level.set_Cond_selector(node, selector);
}
pub fn getCondJmpPred(node: ?*const ir_node) cond_jmp_predicate {
    return @intToEnum(cond_jmp_predicate, low_level.get_Cond_jmp_pred(node));
}
pub fn setCondJmpPred(node: ?*ir_node, jmp_pred: u32) void {
    return low_level.set_Cond_jmp_pred(node, jmp_pred);
}
pub fn getOpCond() ?*ir_op {
    return low_level.get_op_Cond();
}
pub fn newRdConfirm(dbgi: ?*dbg_info, block: ?*ir_node, irn_value: ?*ir_node, irn_bound: ?*ir_node, relation: ir_relation) ?*ir_node {
    return low_level.new_rd_Confirm(dbgi, block, irn_value, irn_bound, relation);
}
pub fn newRConfirm(block: ?*ir_node, irn_value: ?*ir_node, irn_bound: ?*ir_node, relation: ir_relation) ?*ir_node {
    return low_level.new_r_Confirm(block, irn_value, irn_bound, relation);
}
pub fn newDConfirm(dbgi: ?*dbg_info, irn_value: ?*ir_node, irn_bound: ?*ir_node, relation: ir_relation) ?*ir_node {
    return low_level.new_d_Confirm(dbgi, irn_value, irn_bound, relation);
}
pub fn newConfirm(irn_value: ?*ir_node, irn_bound: ?*ir_node, relation: ir_relation) ?*ir_node {
    return low_level.new_Confirm(irn_value, irn_bound, relation);
}
pub fn isConfirm(node: ?*const ir_node) bool {
    return low_level.is_Confirm(node) == 1;
}
pub fn getConfirmValue(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Confirm_value(node);
}
pub fn setConfirmValue(node: ?*ir_node, value: ?*ir_node) void {
    return low_level.set_Confirm_value(node, value);
}
pub fn getConfirmBound(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Confirm_bound(node);
}
pub fn setConfirmBound(node: ?*ir_node, bound: ?*ir_node) void {
    return low_level.set_Confirm_bound(node, bound);
}
pub fn getConfirmRelation(node: ?*const ir_node) ir_relation {
    return @intToEnum(ir_relation, low_level.get_Confirm_relation(node));
}
pub fn setConfirmRelation(node: ?*ir_node, relation: ir_relation) void {
    return low_level.set_Confirm_relation(node, relation);
}
pub fn getOpConfirm() ?*ir_op {
    return low_level.get_op_Confirm();
}
pub fn newRdConst(dbgi: ?*dbg_info, irg: ?*ir_graph, tarval: ?*ir_tarval) ?*ir_node {
    return low_level.new_rd_Const(dbgi, irg, tarval);
}
pub fn newRConst(irg: ?*ir_graph, tarval: ?*ir_tarval) ?*ir_node {
    return low_level.new_r_Const(irg, tarval);
}
pub fn newDConst(dbgi: ?*dbg_info, tarval: ?*ir_tarval) ?*ir_node {
    return low_level.new_d_Const(dbgi, tarval);
}
pub fn newConst(tarval: ?*ir_tarval) ?*ir_node {
    return low_level.new_Const(tarval);
}
pub fn isConst(node: ?*const ir_node) bool {
    return low_level.is_Const(node) == 1;
}
pub fn getConstTarval(node: ?*const ir_node) ?*ir_tarval {
    return low_level.get_Const_tarval(node);
}
pub fn setConstTarval(node: ?*ir_node, tarval: ?*ir_tarval) void {
    return low_level.set_Const_tarval(node, tarval);
}
pub fn getOpConst() ?*ir_op {
    return low_level.get_op_Const();
}
pub fn newRdConv(dbgi: ?*dbg_info, block: ?*ir_node, irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_rd_Conv(dbgi, block, irn_op, mode);
}
pub fn newRConv(block: ?*ir_node, irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_r_Conv(block, irn_op, mode);
}
pub fn newDConv(dbgi: ?*dbg_info, irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_d_Conv(dbgi, irn_op, mode);
}
pub fn newConv(irn_op: ?*ir_node, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_Conv(irn_op, mode);
}
pub fn isConv(node: ?*const ir_node) bool {
    return low_level.is_Conv(node) == 1;
}
pub fn getConvOp(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Conv_op(node);
}
pub fn setConvOp(node: ?*ir_node, op: ?*ir_node) void {
    return low_level.set_Conv_op(node, op);
}
pub fn getOpConv() ?*ir_op {
    return low_level.get_op_Conv();
}
pub fn newRdCopyb(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_dst: ?*ir_node, irn_src: ?*ir_node, @"type": ?*ir_type, flags: u32) ?*ir_node {
    return low_level.new_rd_CopyB(dbgi, block, irn_mem, irn_dst, irn_src, @"type", flags);
}
pub fn newRCopyb(block: ?*ir_node, irn_mem: ?*ir_node, irn_dst: ?*ir_node, irn_src: ?*ir_node, @"type": ?*ir_type, flags: u32) ?*ir_node {
    return low_level.new_r_CopyB(block, irn_mem, irn_dst, irn_src, @"type", flags);
}
pub fn newDCopyb(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_dst: ?*ir_node, irn_src: ?*ir_node, @"type": ?*ir_type, flags: u32) ?*ir_node {
    return low_level.new_d_CopyB(dbgi, irn_mem, irn_dst, irn_src, @"type", flags);
}
pub fn newCopyb(irn_mem: ?*ir_node, irn_dst: ?*ir_node, irn_src: ?*ir_node, @"type": ?*ir_type, flags: u32) ?*ir_node {
    return low_level.new_CopyB(irn_mem, irn_dst, irn_src, @"type", flags);
}
pub fn isCopyb(node: ?*const ir_node) bool {
    return low_level.is_CopyB(node) == 1;
}
pub fn getCopybMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_CopyB_mem(node);
}
pub fn setCopybMem(node: ?*ir_node, mem: ?*ir_node) void {
    return low_level.set_CopyB_mem(node, mem);
}
pub fn getCopybDst(node: ?*const ir_node) ?*ir_node {
    return low_level.get_CopyB_dst(node);
}
pub fn setCopybDst(node: ?*ir_node, dst: ?*ir_node) void {
    return low_level.set_CopyB_dst(node, dst);
}
pub fn getCopybSrc(node: ?*const ir_node) ?*ir_node {
    return low_level.get_CopyB_src(node);
}
pub fn setCopybSrc(node: ?*ir_node, src: ?*ir_node) void {
    return low_level.set_CopyB_src(node, src);
}
pub fn getCopybType(node: ?*const ir_node) ?*ir_type {
    return low_level.get_CopyB_type(node);
}
pub fn setCopybType(node: ?*ir_node, @"type": ?*ir_type) void {
    return low_level.set_CopyB_type(node, @"type");
}
pub fn getCopybVolatility(node: ?*const ir_node) ir_volatility {
    return @intToEnum(ir_volatility, low_level.get_CopyB_volatility(node));
}
pub fn setCopybVolatility(node: ?*ir_node, volatility: u32) void {
    return low_level.set_CopyB_volatility(node, volatility);
}
pub fn getOpCopyb() ?*ir_op {
    return low_level.get_op_CopyB();
}
pub fn isDeleted(node: ?*const ir_node) bool {
    return low_level.is_Deleted(node) == 1;
}
pub fn getOpDeleted() ?*ir_op {
    return low_level.get_op_Deleted();
}
pub fn newRdDiv(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node {
    return low_level.new_rd_Div(dbgi, block, irn_mem, irn_left, irn_right, pinned);
}
pub fn newRDiv(block: ?*ir_node, irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node {
    return low_level.new_r_Div(block, irn_mem, irn_left, irn_right, pinned);
}
pub fn newDDiv(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node {
    return low_level.new_d_Div(dbgi, irn_mem, irn_left, irn_right, pinned);
}
pub fn newDiv(irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node {
    return low_level.new_Div(irn_mem, irn_left, irn_right, pinned);
}
pub fn isDiv(node: ?*const ir_node) bool {
    return low_level.is_Div(node) == 1;
}
pub fn getDivMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Div_mem(node);
}
pub fn setDivMem(node: ?*ir_node, mem: ?*ir_node) void {
    return low_level.set_Div_mem(node, mem);
}
pub fn getDivLeft(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Div_left(node);
}
pub fn setDivLeft(node: ?*ir_node, left: ?*ir_node) void {
    return low_level.set_Div_left(node, left);
}
pub fn getDivRight(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Div_right(node);
}
pub fn setDivRight(node: ?*ir_node, right: ?*ir_node) void {
    return low_level.set_Div_right(node, right);
}
pub fn getDivResmode(node: ?*const ir_node) ?*ir_mode {
    return low_level.get_Div_resmode(node);
}
pub fn setDivResmode(node: ?*ir_node, resmode: ?*ir_mode) void {
    return low_level.set_Div_resmode(node, resmode);
}
pub fn getDivNoRemainder(node: ?*const ir_node) i32 {
    return low_level.get_Div_no_remainder(node);
}
pub fn setDivNoRemainder(node: ?*ir_node, no_remainder: i32) void {
    return low_level.set_Div_no_remainder(node, no_remainder);
}
pub fn getOpDiv() ?*ir_op {
    return low_level.get_op_Div();
}
pub fn newRdDummy(dbgi: ?*dbg_info, irg: ?*ir_graph, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_rd_Dummy(dbgi, irg, mode);
}
pub fn newRDummy(irg: ?*ir_graph, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_r_Dummy(irg, mode);
}
pub fn newDDummy(dbgi: ?*dbg_info, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_d_Dummy(dbgi, mode);
}
pub fn newDummy(mode: ?*ir_mode) ?*ir_node {
    return low_level.new_Dummy(mode);
}
pub fn isDummy(node: ?*const ir_node) bool {
    return low_level.is_Dummy(node) == 1;
}
pub fn getOpDummy() ?*ir_op {
    return low_level.get_op_Dummy();
}
pub fn newRdEnd(dbgi: ?*dbg_info, irg: ?*ir_graph, arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_rd_End(dbgi, irg, arity, in);
}
pub fn newREnd(irg: ?*ir_graph, arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_r_End(irg, arity, in);
}
pub fn newDEnd(dbgi: ?*dbg_info, arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_d_End(dbgi, arity, in);
}
pub fn newEnd(arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_End(arity, in);
}
pub fn isEnd(node: ?*const ir_node) bool {
    return low_level.is_End(node) == 1;
}
pub fn getEndNKeepalives(node: ?*const ir_node) i32 {
    return low_level.get_End_n_keepalives(node);
}
pub fn getEndKeepalive(node: ?*const ir_node, pos: i32) ?*ir_node {
    return low_level.get_End_keepalive(node, pos);
}
pub fn setEndKeepalive(node: ?*ir_node, pos: i32, keepalive: ?*ir_node) void {
    return low_level.set_End_keepalive(node, pos, keepalive);
}
pub fn getEndKeepaliveArr(node: ?*ir_node) [*]?*ir_node {
    return low_level.get_End_keepalive_arr(node);
}
pub fn getOpEnd() ?*ir_op {
    return low_level.get_op_End();
}
pub fn newRdEor(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Eor(dbgi, block, irn_left, irn_right);
}
pub fn newREor(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_r_Eor(block, irn_left, irn_right);
}
pub fn newDEor(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_d_Eor(dbgi, irn_left, irn_right);
}
pub fn newEor(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_Eor(irn_left, irn_right);
}
pub fn isEor(node: ?*const ir_node) bool {
    return low_level.is_Eor(node) == 1;
}
pub fn getEorLeft(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Eor_left(node);
}
pub fn setEorLeft(node: ?*ir_node, left: ?*ir_node) void {
    return low_level.set_Eor_left(node, left);
}
pub fn getEorRight(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Eor_right(node);
}
pub fn setEorRight(node: ?*ir_node, right: ?*ir_node) void {
    return low_level.set_Eor_right(node, right);
}
pub fn getOpEor() ?*ir_op {
    return low_level.get_op_Eor();
}
pub fn newRdFree(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Free(dbgi, block, irn_mem, irn_ptr);
}
pub fn newRFree(block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node) ?*ir_node {
    return low_level.new_r_Free(block, irn_mem, irn_ptr);
}
pub fn newDFree(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_ptr: ?*ir_node) ?*ir_node {
    return low_level.new_d_Free(dbgi, irn_mem, irn_ptr);
}
pub fn newFree(irn_mem: ?*ir_node, irn_ptr: ?*ir_node) ?*ir_node {
    return low_level.new_Free(irn_mem, irn_ptr);
}
pub fn isFree(node: ?*const ir_node) bool {
    return low_level.is_Free(node) == 1;
}
pub fn getFreeMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Free_mem(node);
}
pub fn setFreeMem(node: ?*ir_node, mem: ?*ir_node) void {
    return low_level.set_Free_mem(node, mem);
}
pub fn getFreePtr(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Free_ptr(node);
}
pub fn setFreePtr(node: ?*ir_node, ptr: ?*ir_node) void {
    return low_level.set_Free_ptr(node, ptr);
}
pub fn getOpFree() ?*ir_op {
    return low_level.get_op_Free();
}
pub fn newRdIjmp(dbgi: ?*dbg_info, block: ?*ir_node, irn_target: ?*ir_node) ?*ir_node {
    return low_level.new_rd_IJmp(dbgi, block, irn_target);
}
pub fn newRIjmp(block: ?*ir_node, irn_target: ?*ir_node) ?*ir_node {
    return low_level.new_r_IJmp(block, irn_target);
}
pub fn newDIjmp(dbgi: ?*dbg_info, irn_target: ?*ir_node) ?*ir_node {
    return low_level.new_d_IJmp(dbgi, irn_target);
}
pub fn newIjmp(irn_target: ?*ir_node) ?*ir_node {
    return low_level.new_IJmp(irn_target);
}
pub fn isIjmp(node: ?*const ir_node) bool {
    return low_level.is_IJmp(node) == 1;
}
pub fn getIjmpTarget(node: ?*const ir_node) ?*ir_node {
    return low_level.get_IJmp_target(node);
}
pub fn setIjmpTarget(node: ?*ir_node, target: ?*ir_node) void {
    return low_level.set_IJmp_target(node, target);
}
pub fn getOpIjmp() ?*ir_op {
    return low_level.get_op_IJmp();
}
pub fn isId(node: ?*const ir_node) bool {
    return low_level.is_Id(node) == 1;
}
pub fn getIdPred(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Id_pred(node);
}
pub fn setIdPred(node: ?*ir_node, pred: ?*ir_node) void {
    return low_level.set_Id_pred(node, pred);
}
pub fn getOpId() ?*ir_op {
    return low_level.get_op_Id();
}
pub fn newRdJmp(dbgi: ?*dbg_info, block: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Jmp(dbgi, block);
}
pub fn newRJmp(block: ?*ir_node) ?*ir_node {
    return low_level.new_r_Jmp(block);
}
pub fn newDJmp(dbgi: ?*dbg_info) ?*ir_node {
    return low_level.new_d_Jmp(dbgi);
}
pub fn newJmp() ?*ir_node {
    return low_level.new_Jmp();
}
pub fn isJmp(node: ?*const ir_node) bool {
    return low_level.is_Jmp(node) == 1;
}
pub fn getOpJmp() ?*ir_op {
    return low_level.get_op_Jmp();
}
pub fn newRdLoad(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, mode: ?*ir_mode, @"type": ?*ir_type, flags: u32) ?*ir_node {
    return low_level.new_rd_Load(dbgi, block, irn_mem, irn_ptr, mode, @"type", flags);
}
pub fn newRLoad(block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, mode: ?*ir_mode, @"type": ?*ir_type, flags: u32) ?*ir_node {
    return low_level.new_r_Load(block, irn_mem, irn_ptr, mode, @"type", flags);
}
pub fn newDLoad(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, mode: ?*ir_mode, @"type": ?*ir_type, flags: u32) ?*ir_node {
    return low_level.new_d_Load(dbgi, irn_mem, irn_ptr, mode, @"type", flags);
}
pub fn newLoad(irn_mem: ?*ir_node, irn_ptr: ?*ir_node, mode: ?*ir_mode, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node {
    return low_level.new_Load(irn_mem, irn_ptr, mode, @"type", flags);
}
pub fn isLoad(node: ?*const ir_node) bool {
    return low_level.is_Load(node) == 1;
}
pub fn getLoadMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Load_mem(node);
}
pub fn setLoadMem(node: ?*ir_node, mem: ?*ir_node) void {
    return low_level.set_Load_mem(node, mem);
}
pub fn getLoadPtr(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Load_ptr(node);
}
pub fn setLoadPtr(node: ?*ir_node, ptr: ?*ir_node) void {
    return low_level.set_Load_ptr(node, ptr);
}
pub fn getLoadMode(node: ?*const ir_node) ?*ir_mode {
    return low_level.get_Load_mode(node);
}
pub fn setLoadMode(node: ?*ir_node, mode: ?*ir_mode) void {
    return low_level.set_Load_mode(node, mode);
}
pub fn getLoadType(node: ?*const ir_node) ?*ir_type {
    return low_level.get_Load_type(node);
}
pub fn setLoadType(node: ?*ir_node, @"type": ?*ir_type) void {
    return low_level.set_Load_type(node, @"type");
}
pub fn getLoadVolatility(node: ?*const ir_node) ir_volatility {
    return @intToEnum(ir_volatility, low_level.get_Load_volatility(node));
}
pub fn setLoadVolatility(node: ?*ir_node, volatility: u32) void {
    return low_level.set_Load_volatility(node, volatility);
}
pub fn getLoadUnaligned(node: ?*const ir_node) ir_align {
    return @intToEnum(ir_align, low_level.get_Load_unaligned(node));
}
pub fn setLoadUnaligned(node: ?*ir_node, unaligned: u32) void {
    return low_level.set_Load_unaligned(node, unaligned);
}
pub fn getOpLoad() ?*ir_op {
    return low_level.get_op_Load();
}
pub fn newRdMember(dbgi: ?*dbg_info, block: ?*ir_node, irn_ptr: ?*ir_node, entity: ?*ir_entity) ?*ir_node {
    return low_level.new_rd_Member(dbgi, block, irn_ptr, entity);
}
pub fn newRMember(block: ?*ir_node, irn_ptr: ?*ir_node, entity: ?*ir_entity) ?*ir_node {
    return low_level.new_r_Member(block, irn_ptr, entity);
}
pub fn newDMember(dbgi: ?*dbg_info, irn_ptr: ?*ir_node, entity: ?*ir_entity) ?*ir_node {
    return low_level.new_d_Member(dbgi, irn_ptr, entity);
}
pub fn newMember(irn_ptr: ?*ir_node, entity: ?*ir_entity) ?*ir_node {
    return low_level.new_Member(irn_ptr, entity);
}
pub fn isMember(node: ?*const ir_node) bool {
    return low_level.is_Member(node) == 1;
}
pub fn getMemberPtr(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Member_ptr(node);
}
pub fn setMemberPtr(node: ?*ir_node, ptr: ?*ir_node) void {
    return low_level.set_Member_ptr(node, ptr);
}
pub fn getMemberEntity(node: ?*const ir_node) ?*ir_entity {
    return low_level.get_Member_entity(node);
}
pub fn setMemberEntity(node: ?*ir_node, entity: ?*ir_entity) void {
    return low_level.set_Member_entity(node, entity);
}
pub fn getOpMember() ?*ir_op {
    return low_level.get_op_Member();
}
pub fn newRdMinus(dbgi: ?*dbg_info, block: ?*ir_node, irn_op: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Minus(dbgi, block, irn_op);
}
pub fn newRMinus(block: ?*ir_node, irn_op: ?*ir_node) ?*ir_node {
    return low_level.new_r_Minus(block, irn_op);
}
pub fn newDMinus(dbgi: ?*dbg_info, irn_op: ?*ir_node) ?*ir_node {
    return low_level.new_d_Minus(dbgi, irn_op);
}
pub fn newMinus(irn_op: ?*ir_node) ?*ir_node {
    return low_level.new_Minus(irn_op);
}
pub fn isMinus(node: ?*const ir_node) bool {
    return low_level.is_Minus(node) == 1;
}
pub fn getMinusOp(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Minus_op(node);
}
pub fn setMinusOp(node: ?*ir_node, op: ?*ir_node) void {
    return low_level.set_Minus_op(node, op);
}
pub fn getOpMinus() ?*ir_op {
    return low_level.get_op_Minus();
}
pub fn newRdMod(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node {
    return low_level.new_rd_Mod(dbgi, block, irn_mem, irn_left, irn_right, pinned);
}
pub fn newRMod(block: ?*ir_node, irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node {
    return low_level.new_r_Mod(block, irn_mem, irn_left, irn_right, pinned);
}
pub fn newDMod(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node {
    return low_level.new_d_Mod(dbgi, irn_mem, irn_left, irn_right, pinned);
}
pub fn newMod(irn_mem: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node, pinned: i32) ?*ir_node {
    return low_level.new_Mod(irn_mem, irn_left, irn_right, pinned);
}
pub fn isMod(node: ?*const ir_node) bool {
    return low_level.is_Mod(node) == 1;
}
pub fn getModMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Mod_mem(node);
}
pub fn setModMem(node: ?*ir_node, mem: ?*ir_node) void {
    return low_level.set_Mod_mem(node, mem);
}
pub fn getModLeft(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Mod_left(node);
}
pub fn setModLeft(node: ?*ir_node, left: ?*ir_node) void {
    return low_level.set_Mod_left(node, left);
}
pub fn getModRight(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Mod_right(node);
}
pub fn setModRight(node: ?*ir_node, right: ?*ir_node) void {
    return low_level.set_Mod_right(node, right);
}
pub fn getModResmode(node: ?*const ir_node) ?*ir_mode {
    return low_level.get_Mod_resmode(node);
}
pub fn setModResmode(node: ?*ir_node, resmode: ?*ir_mode) void {
    return low_level.set_Mod_resmode(node, resmode);
}
pub fn getOpMod() ?*ir_op {
    return low_level.get_op_Mod();
}
pub fn newRdMul(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Mul(dbgi, block, irn_left, irn_right);
}
pub fn newRMul(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_r_Mul(block, irn_left, irn_right);
}
pub fn newDMul(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_d_Mul(dbgi, irn_left, irn_right);
}
pub fn newMul(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_Mul(irn_left, irn_right);
}
pub fn isMul(node: ?*const ir_node) bool {
    return low_level.is_Mul(node) == 1;
}
pub fn getMulLeft(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Mul_left(node);
}
pub fn setMulLeft(node: ?*ir_node, left: ?*ir_node) void {
    return low_level.set_Mul_left(node, left);
}
pub fn getMulRight(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Mul_right(node);
}
pub fn setMulRight(node: ?*ir_node, right: ?*ir_node) void {
    return low_level.set_Mul_right(node, right);
}
pub fn getOpMul() ?*ir_op {
    return low_level.get_op_Mul();
}
pub fn newRdMulh(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Mulh(dbgi, block, irn_left, irn_right);
}
pub fn newRMulh(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_r_Mulh(block, irn_left, irn_right);
}
pub fn newDMulh(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_d_Mulh(dbgi, irn_left, irn_right);
}
pub fn newMulh(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_Mulh(irn_left, irn_right);
}
pub fn isMulh(node: ?*const ir_node) bool {
    return low_level.is_Mulh(node) == 1;
}
pub fn getMulhLeft(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Mulh_left(node);
}
pub fn setMulhLeft(node: ?*ir_node, left: ?*ir_node) void {
    return low_level.set_Mulh_left(node, left);
}
pub fn getMulhRight(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Mulh_right(node);
}
pub fn setMulhRight(node: ?*ir_node, right: ?*ir_node) void {
    return low_level.set_Mulh_right(node, right);
}
pub fn getOpMulh() ?*ir_op {
    return low_level.get_op_Mulh();
}
pub fn newRdMux(dbgi: ?*dbg_info, block: ?*ir_node, irn_sel: ?*ir_node, irn_false: ?*ir_node, irn_true: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Mux(dbgi, block, irn_sel, irn_false, irn_true);
}
pub fn newRMux(block: ?*ir_node, irn_sel: ?*ir_node, irn_false: ?*ir_node, irn_true: ?*ir_node) ?*ir_node {
    return low_level.new_r_Mux(block, irn_sel, irn_false, irn_true);
}
pub fn newDMux(dbgi: ?*dbg_info, irn_sel: ?*ir_node, irn_false: ?*ir_node, irn_true: ?*ir_node) ?*ir_node {
    return low_level.new_d_Mux(dbgi, irn_sel, irn_false, irn_true);
}
pub fn newMux(irn_sel: ?*ir_node, irn_false: ?*ir_node, irn_true: ?*ir_node) ?*ir_node {
    return low_level.new_Mux(irn_sel, irn_false, irn_true);
}
pub fn isMux(node: ?*const ir_node) bool {
    return low_level.is_Mux(node) == 1;
}
pub fn getMuxSel(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Mux_sel(node);
}
pub fn setMuxSel(node: ?*ir_node, sel: ?*ir_node) void {
    return low_level.set_Mux_sel(node, sel);
}
pub fn getMuxFalse(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Mux_false(node);
}
pub fn setMuxFalse(node: ?*ir_node, false_: ?*ir_node) void {
    return low_level.set_Mux_false(node, false_);
}
pub fn getMuxTrue(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Mux_true(node);
}
pub fn setMuxTrue(node: ?*ir_node, true_: ?*ir_node) void {
    return low_level.set_Mux_true(node, true_);
}
pub fn getOpMux() ?*ir_op {
    return low_level.get_op_Mux();
}
pub fn newRdNomem(dbgi: ?*dbg_info, irg: ?*ir_graph) ?*ir_node {
    return low_level.new_rd_NoMem(dbgi, irg);
}
pub fn newRNomem(irg: ?*ir_graph) ?*ir_node {
    return low_level.new_r_NoMem(irg);
}
pub fn newDNomem(dbgi: ?*dbg_info) ?*ir_node {
    return low_level.new_d_NoMem(dbgi);
}
pub fn newNomem() ?*ir_node {
    return low_level.new_NoMem();
}
pub fn isNomem(node: ?*const ir_node) bool {
    return low_level.is_NoMem(node) == 1;
}
pub fn getOpNomem() ?*ir_op {
    return low_level.get_op_NoMem();
}
pub fn newRdNot(dbgi: ?*dbg_info, block: ?*ir_node, irn_op: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Not(dbgi, block, irn_op);
}
pub fn newRNot(block: ?*ir_node, irn_op: ?*ir_node) ?*ir_node {
    return low_level.new_r_Not(block, irn_op);
}
pub fn newDNot(dbgi: ?*dbg_info, irn_op: ?*ir_node) ?*ir_node {
    return low_level.new_d_Not(dbgi, irn_op);
}
pub fn newNot(irn_op: ?*ir_node) ?*ir_node {
    return low_level.new_Not(irn_op);
}
pub fn isNot(node: ?*const ir_node) bool {
    return low_level.is_Not(node) == 1;
}
pub fn getNotOp(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Not_op(node);
}
pub fn setNotOp(node: ?*ir_node, op: ?*ir_node) void {
    return low_level.set_Not_op(node, op);
}
pub fn getOpNot() ?*ir_op {
    return low_level.get_op_Not();
}
pub fn newRdOffset(dbgi: ?*dbg_info, irg: ?*ir_graph, mode: ?*ir_mode, entity: ?*ir_entity) ?*ir_node {
    return low_level.new_rd_Offset(dbgi, irg, mode, entity);
}
pub fn newROffset(irg: ?*ir_graph, mode: ?*ir_mode, entity: ?*ir_entity) ?*ir_node {
    return low_level.new_r_Offset(irg, mode, entity);
}
pub fn newDOffset(dbgi: ?*dbg_info, mode: ?*ir_mode, entity: ?*ir_entity) ?*ir_node {
    return low_level.new_d_Offset(dbgi, mode, entity);
}
pub fn newOffset(mode: ?*ir_mode, entity: ?*ir_entity) ?*ir_node {
    return low_level.new_Offset(mode, entity);
}
pub fn isOffset(node: ?*const ir_node) bool {
    return low_level.is_Offset(node) == 1;
}
pub fn getOffsetEntity(node: ?*const ir_node) ?*ir_entity {
    return low_level.get_Offset_entity(node);
}
pub fn setOffsetEntity(node: ?*ir_node, entity: ?*ir_entity) void {
    return low_level.set_Offset_entity(node, entity);
}
pub fn getOpOffset() ?*ir_op {
    return low_level.get_op_Offset();
}
pub fn newRdOr(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Or(dbgi, block, irn_left, irn_right);
}
pub fn newROr(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_r_Or(block, irn_left, irn_right);
}
pub fn newDOr(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_d_Or(dbgi, irn_left, irn_right);
}
pub fn newOr(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_Or(irn_left, irn_right);
}
pub fn isOr(node: ?*const ir_node) bool {
    return low_level.is_Or(node) == 1;
}
pub fn getOrLeft(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Or_left(node);
}
pub fn setOrLeft(node: ?*ir_node, left: ?*ir_node) void {
    return low_level.set_Or_left(node, left);
}
pub fn getOrRight(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Or_right(node);
}
pub fn setOrRight(node: ?*ir_node, right: ?*ir_node) void {
    return low_level.set_Or_right(node, right);
}
pub fn getOpOr() ?*ir_op {
    return low_level.get_op_Or();
}
pub fn newRdPhi(dbgi: ?*dbg_info, block: ?*ir_node, arity: i32, in: [*]const ?*ir_node, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_rd_Phi(dbgi, block, arity, in, mode);
}
pub fn newRPhi(block: ?*ir_node, arity: i32, in: [*]const ?*ir_node, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_r_Phi(block, arity, in, mode);
}
pub fn newDPhi(dbgi: ?*dbg_info, arity: i32, in: [*]const ?*ir_node, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_d_Phi(dbgi, arity, in, mode);
}
pub fn newPhi(arity: i32, in: [*]const ?*ir_node, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_Phi(arity, in, mode);
}
pub fn isPhi(node: ?*const ir_node) bool {
    return low_level.is_Phi(node) == 1;
}
pub fn getPhiNPreds(node: ?*const ir_node) i32 {
    return low_level.get_Phi_n_preds(node);
}
pub fn getPhiPred(node: ?*const ir_node, pos: i32) ?*ir_node {
    return low_level.get_Phi_pred(node, pos);
}
pub fn setPhiPred(node: ?*ir_node, pos: i32, pred: ?*ir_node) void {
    return low_level.set_Phi_pred(node, pos, pred);
}
pub fn getPhiPredArr(node: ?*ir_node) [*]?*ir_node {
    return low_level.get_Phi_pred_arr(node);
}
pub fn getPhiLoop(node: ?*const ir_node) i32 {
    return low_level.get_Phi_loop(node);
}
pub fn setPhiLoop(node: ?*ir_node, loop: i32) void {
    return low_level.set_Phi_loop(node, loop);
}
pub fn getOpPhi() ?*ir_op {
    return low_level.get_op_Phi();
}
pub fn newRdPin(dbgi: ?*dbg_info, block: ?*ir_node, irn_op: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Pin(dbgi, block, irn_op);
}
pub fn newRPin(block: ?*ir_node, irn_op: ?*ir_node) ?*ir_node {
    return low_level.new_r_Pin(block, irn_op);
}
pub fn newDPin(dbgi: ?*dbg_info, irn_op: ?*ir_node) ?*ir_node {
    return low_level.new_d_Pin(dbgi, irn_op);
}
pub fn newPin(irn_op: ?*ir_node) ?*ir_node {
    return low_level.new_Pin(irn_op);
}
pub fn isPin(node: ?*const ir_node) bool {
    return low_level.is_Pin(node) == 1;
}
pub fn getPinOp(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Pin_op(node);
}
pub fn setPinOp(node: ?*ir_node, op: ?*ir_node) void {
    return low_level.set_Pin_op(node, op);
}
pub fn getOpPin() ?*ir_op {
    return low_level.get_op_Pin();
}
pub fn newRdProj(dbgi: ?*dbg_info, irn_pred: ?*ir_node, mode: ?*ir_mode, num: u32) ?*ir_node {
    return low_level.new_rd_Proj(dbgi, irn_pred, mode, num);
}
pub fn newRProj(irn_pred: ?*ir_node, mode: ?*ir_mode, num: u32) ?*ir_node {
    return low_level.new_r_Proj(irn_pred, mode, num);
}
pub fn newDProj(dbgi: ?*dbg_info, irn_pred: ?*ir_node, mode: ?*ir_mode, num: u32) ?*ir_node {
    return low_level.new_d_Proj(dbgi, irn_pred, mode, num);
}
pub fn newProj(irn_pred: ?*ir_node, mode: ?*ir_mode, num: u32) ?*ir_node {
    return low_level.new_Proj(irn_pred, mode, num);
}
pub fn isProj(node: ?*const ir_node) bool {
    return low_level.is_Proj(node) == 1;
}
pub fn getProjPred(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Proj_pred(node);
}
pub fn setProjPred(node: ?*ir_node, pred: ?*ir_node) void {
    return low_level.set_Proj_pred(node, pred);
}
pub fn getProjNum(node: ?*const ir_node) u32 {
    return low_level.get_Proj_num(node);
}
pub fn setProjNum(node: ?*ir_node, num: u32) void {
    return low_level.set_Proj_num(node, num);
}
pub fn getOpProj() ?*ir_op {
    return low_level.get_op_Proj();
}
pub fn newRdRaise(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_exo_ptr: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Raise(dbgi, block, irn_mem, irn_exo_ptr);
}
pub fn newRRaise(block: ?*ir_node, irn_mem: ?*ir_node, irn_exo_ptr: ?*ir_node) ?*ir_node {
    return low_level.new_r_Raise(block, irn_mem, irn_exo_ptr);
}
pub fn newDRaise(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_exo_ptr: ?*ir_node) ?*ir_node {
    return low_level.new_d_Raise(dbgi, irn_mem, irn_exo_ptr);
}
pub fn newRaise(irn_mem: ?*ir_node, irn_exo_ptr: ?*ir_node) ?*ir_node {
    return low_level.new_Raise(irn_mem, irn_exo_ptr);
}
pub fn isRaise(node: ?*const ir_node) bool {
    return low_level.is_Raise(node) == 1;
}
pub fn getRaiseMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Raise_mem(node);
}
pub fn setRaiseMem(node: ?*ir_node, mem: ?*ir_node) void {
    return low_level.set_Raise_mem(node, mem);
}
pub fn getRaiseExoPtr(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Raise_exo_ptr(node);
}
pub fn setRaiseExoPtr(node: ?*ir_node, exo_ptr: ?*ir_node) void {
    return low_level.set_Raise_exo_ptr(node, exo_ptr);
}
pub fn getOpRaise() ?*ir_op {
    return low_level.get_op_Raise();
}
pub fn newRdReturn(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, arity: i32, in: *?*ir_node) ?*ir_node {
    return low_level.new_rd_Return(dbgi, block, irn_mem, arity, in);
}
pub fn newRReturn(block: ?*ir_node, irn_mem: ?*ir_node, arity: i32, in: *?*ir_node) ?*ir_node {
    return low_level.new_r_Return(block, irn_mem, arity, in);
}
pub fn newDReturn(dbgi: ?*dbg_info, irn_mem: ?*ir_node, arity: i32, in: *?*ir_node) ?*ir_node {
    return low_level.new_d_Return(dbgi, irn_mem, arity, in);
}
pub fn newReturn(irn_mem: ?*ir_node, arity: i32, in: *?*ir_node) ?*ir_node {
    return low_level.new_Return(irn_mem, arity, in);
}
pub fn isReturn(node: ?*const ir_node) bool {
    return low_level.is_Return(node) == 1;
}
pub fn getReturnMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Return_mem(node);
}
pub fn setReturnMem(node: ?*ir_node, mem: ?*ir_node) void {
    return low_level.set_Return_mem(node, mem);
}
pub fn getReturnNRess(node: ?*const ir_node) i32 {
    return low_level.get_Return_n_ress(node);
}
pub fn getReturnRes(node: ?*const ir_node, pos: i32) ?*ir_node {
    return low_level.get_Return_res(node, pos);
}
pub fn setReturnRes(node: ?*ir_node, pos: i32, res: ?*ir_node) void {
    return low_level.set_Return_res(node, pos, res);
}
pub fn getReturnResArr(node: ?*ir_node) [*]?*ir_node {
    return low_level.get_Return_res_arr(node);
}
pub fn getOpReturn() ?*ir_op {
    return low_level.get_op_Return();
}
pub fn newRdSel(dbgi: ?*dbg_info, block: ?*ir_node, irn_ptr: ?*ir_node, irn_index: ?*ir_node, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_rd_Sel(dbgi, block, irn_ptr, irn_index, @"type");
}
pub fn newRSel(block: ?*ir_node, irn_ptr: ?*ir_node, irn_index: ?*ir_node, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_r_Sel(block, irn_ptr, irn_index, @"type");
}
pub fn newDSel(dbgi: ?*dbg_info, irn_ptr: ?*ir_node, irn_index: ?*ir_node, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_d_Sel(dbgi, irn_ptr, irn_index, @"type");
}
pub fn newSel(irn_ptr: ?*ir_node, irn_index: ?*ir_node, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_Sel(irn_ptr, irn_index, @"type");
}
pub fn isSel(node: ?*const ir_node) bool {
    return low_level.is_Sel(node) == 1;
}
pub fn getSelPtr(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Sel_ptr(node);
}
pub fn setSelPtr(node: ?*ir_node, ptr: ?*ir_node) void {
    return low_level.set_Sel_ptr(node, ptr);
}
pub fn getSelIndex(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Sel_index(node);
}
pub fn setSelIndex(node: ?*ir_node, index: ?*ir_node) void {
    return low_level.set_Sel_index(node, index);
}
pub fn getSelType(node: ?*const ir_node) ?*ir_type {
    return low_level.get_Sel_type(node);
}
pub fn setSelType(node: ?*ir_node, @"type": ?*ir_type) void {
    return low_level.set_Sel_type(node, @"type");
}
pub fn getOpSel() ?*ir_op {
    return low_level.get_op_Sel();
}
pub fn newRdShl(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Shl(dbgi, block, irn_left, irn_right);
}
pub fn newRShl(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_r_Shl(block, irn_left, irn_right);
}
pub fn newDShl(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_d_Shl(dbgi, irn_left, irn_right);
}
pub fn newShl(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_Shl(irn_left, irn_right);
}
pub fn isShl(node: ?*const ir_node) bool {
    return low_level.is_Shl(node) == 1;
}
pub fn getShlLeft(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Shl_left(node);
}
pub fn setShlLeft(node: ?*ir_node, left: ?*ir_node) void {
    return low_level.set_Shl_left(node, left);
}
pub fn getShlRight(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Shl_right(node);
}
pub fn setShlRight(node: ?*ir_node, right: ?*ir_node) void {
    return low_level.set_Shl_right(node, right);
}
pub fn getOpShl() ?*ir_op {
    return low_level.get_op_Shl();
}
pub fn irPrintf(fmt: [*]const u8, variadic: anytype) i32 {
    return low_level.ir_printf(fmt, variadic);
}
pub fn irFprintf(f: *std.c.FILE, fmt: [*]const u8, variadic: anytype) i32 {
    return low_level.ir_fprintf(f, fmt, variadic);
}
pub fn irSnprintf(buf: [*]u8, n: usize, fmt: [*]const u8, variadic: anytype) i32 {
    return low_level.ir_snprintf(buf, n, fmt, variadic);
}
pub fn irVprintf(fmt: [*]const u8, variadic: anytype) i32 {
    return low_level.ir_vprintf(fmt, variadic);
}
pub fn irVfprintf(f: *std.c.FILE, fmt: [*]const u8, variadic: anytype) i32 {
    return low_level.ir_vfprintf(f, fmt, variadic);
}
pub fn irVsnprintf(buf: [*]u8, len: usize, fmt: [*]const u8, variadic: anytype) i32 {
    return low_level.ir_vsnprintf(buf, len, fmt, variadic);
}
pub fn irObstVprintf(obst: ?*obstack, fmt: [*]const u8, variadic: anytype) i32 {
    return low_level.ir_obst_vprintf(obst, fmt, variadic);
}
pub fn tarvalSnprintf(buf: [*]u8, buflen: usize, tv: ?*const ir_tarval) i32 {
    return low_level.tarval_snprintf(buf, buflen, tv);
}
pub fn newRdShr(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Shr(dbgi, block, irn_left, irn_right);
}
pub fn newRShr(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_r_Shr(block, irn_left, irn_right);
}
pub fn newDShr(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_d_Shr(dbgi, irn_left, irn_right);
}
pub fn newShr(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_Shr(irn_left, irn_right);
}
pub fn isShr(node: ?*const ir_node) bool {
    return low_level.is_Shr(node) == 1;
}
pub fn getShrLeft(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Shr_left(node);
}
pub fn setShrLeft(node: ?*ir_node, left: ?*ir_node) void {
    return low_level.set_Shr_left(node, left);
}
pub fn getShrRight(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Shr_right(node);
}
pub fn setShrRight(node: ?*ir_node, right: ?*ir_node) void {
    return low_level.set_Shr_right(node, right);
}
pub fn getOpShr() ?*ir_op {
    return low_level.get_op_Shr();
}
pub fn newRdShrs(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Shrs(dbgi, block, irn_left, irn_right);
}
pub fn newRShrs(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_r_Shrs(block, irn_left, irn_right);
}
pub fn newDShrs(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_d_Shrs(dbgi, irn_left, irn_right);
}
pub fn newShrs(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_Shrs(irn_left, irn_right);
}
pub fn isShrs(node: ?*const ir_node) bool {
    return low_level.is_Shrs(node) == 1;
}
pub fn getShrsLeft(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Shrs_left(node);
}
pub fn setShrsLeft(node: ?*ir_node, left: ?*ir_node) void {
    return low_level.set_Shrs_left(node, left);
}
pub fn getShrsRight(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Shrs_right(node);
}
pub fn setShrsRight(node: ?*ir_node, right: ?*ir_node) void {
    return low_level.set_Shrs_right(node, right);
}
pub fn getOpShrs() ?*ir_op {
    return low_level.get_op_Shrs();
}
pub fn newRdSize(dbgi: ?*dbg_info, irg: ?*ir_graph, mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_rd_Size(dbgi, irg, mode, @"type");
}
pub fn newRSize(irg: ?*ir_graph, mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_r_Size(irg, mode, @"type");
}
pub fn newDSize(dbgi: ?*dbg_info, mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_d_Size(dbgi, mode, @"type");
}
pub fn newSize(mode: ?*ir_mode, @"type": ?*ir_type) ?*ir_node {
    return low_level.new_Size(mode, @"type");
}
pub fn isSize(node: ?*const ir_node) bool {
    return low_level.is_Size(node) == 1;
}
pub fn getSizeType(node: ?*const ir_node) ?*ir_type {
    return low_level.get_Size_type(node);
}
pub fn setSizeType(node: ?*ir_node, @"type": ?*ir_type) void {
    return low_level.set_Size_type(node, @"type");
}
pub fn getOpSize() ?*ir_op {
    return low_level.get_op_Size();
}
pub fn newRdStart(dbgi: ?*dbg_info, irg: ?*ir_graph) ?*ir_node {
    return low_level.new_rd_Start(dbgi, irg);
}
pub fn newRStart(irg: ?*ir_graph) ?*ir_node {
    return low_level.new_r_Start(irg);
}
pub fn newDStart(dbgi: ?*dbg_info) ?*ir_node {
    return low_level.new_d_Start(dbgi);
}
pub fn newStart() ?*ir_node {
    return low_level.new_Start();
}
pub fn isStart(node: ?*const ir_node) bool {
    return low_level.is_Start(node) == 1;
}
pub fn getOpStart() ?*ir_op {
    return low_level.get_op_Start();
}
pub fn newRdStore(dbgi: ?*dbg_info, block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, irn_value: ?*ir_node, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node {
    return low_level.new_rd_Store(dbgi, block, irn_mem, irn_ptr, irn_value, @"type", flags);
}
pub fn newRStore(block: ?*ir_node, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, irn_value: ?*ir_node, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node {
    return low_level.new_r_Store(block, irn_mem, irn_ptr, irn_value, @"type", flags);
}
pub fn newDStore(dbgi: ?*dbg_info, irn_mem: ?*ir_node, irn_ptr: ?*ir_node, irn_value: ?*ir_node, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node {
    return low_level.new_d_Store(dbgi, irn_mem, irn_ptr, irn_value, @"type", flags);
}
pub fn newStore(irn_mem: ?*ir_node, irn_ptr: ?*ir_node, irn_value: ?*ir_node, @"type": ?*ir_type, flags: ir_cons_flags) ?*ir_node {
    return low_level.new_Store(irn_mem, irn_ptr, irn_value, @"type", flags);
}
pub fn isStore(node: ?*const ir_node) bool {
    return low_level.is_Store(node) == 1;
}
pub fn getStoreMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Store_mem(node);
}
pub fn setStoreMem(node: ?*ir_node, mem: ?*ir_node) void {
    return low_level.set_Store_mem(node, mem);
}
pub fn getStorePtr(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Store_ptr(node);
}
pub fn setStorePtr(node: ?*ir_node, ptr: ?*ir_node) void {
    return low_level.set_Store_ptr(node, ptr);
}
pub fn getStoreValue(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Store_value(node);
}
pub fn setStoreValue(node: ?*ir_node, value: ?*ir_node) void {
    return low_level.set_Store_value(node, value);
}
pub fn getStoreType(node: ?*const ir_node) ?*ir_type {
    return low_level.get_Store_type(node);
}
pub fn setStoreType(node: ?*ir_node, @"type": ?*ir_type) void {
    return low_level.set_Store_type(node, @"type");
}
pub fn getStoreVolatility(node: ?*const ir_node) ir_volatility {
    return @intToEnum(ir_volatility, low_level.get_Store_volatility(node));
}
pub fn setStoreVolatility(node: ?*ir_node, volatility: u32) void {
    return low_level.set_Store_volatility(node, volatility);
}
pub fn getStoreUnaligned(node: ?*const ir_node) ir_align {
    return @intToEnum(ir_align, low_level.get_Store_unaligned(node));
}
pub fn setStoreUnaligned(node: ?*ir_node, unaligned: u32) void {
    return low_level.set_Store_unaligned(node, unaligned);
}
pub fn getOpStore() ?*ir_op {
    return low_level.get_op_Store();
}
pub fn newRdSub(dbgi: ?*dbg_info, block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_rd_Sub(dbgi, block, irn_left, irn_right);
}
pub fn newRSub(block: ?*ir_node, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_r_Sub(block, irn_left, irn_right);
}
pub fn newDSub(dbgi: ?*dbg_info, irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_d_Sub(dbgi, irn_left, irn_right);
}
pub fn newSub(irn_left: ?*ir_node, irn_right: ?*ir_node) ?*ir_node {
    return low_level.new_Sub(irn_left, irn_right);
}
pub fn isSub(node: ?*const ir_node) bool {
    return low_level.is_Sub(node) == 1;
}
pub fn getSubLeft(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Sub_left(node);
}
pub fn setSubLeft(node: ?*ir_node, left: ?*ir_node) void {
    return low_level.set_Sub_left(node, left);
}
pub fn getSubRight(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Sub_right(node);
}
pub fn setSubRight(node: ?*ir_node, right: ?*ir_node) void {
    return low_level.set_Sub_right(node, right);
}
pub fn getOpSub() ?*ir_op {
    return low_level.get_op_Sub();
}
pub fn newRdSwitch(dbgi: ?*dbg_info, block: ?*ir_node, irn_selector: ?*ir_node, n_outs: u32, table: ?*ir_switch_table) ?*ir_node {
    return low_level.new_rd_Switch(dbgi, block, irn_selector, n_outs, table);
}
pub fn newRSwitch(block: ?*ir_node, irn_selector: ?*ir_node, n_outs: u32, table: ?*ir_switch_table) ?*ir_node {
    return low_level.new_r_Switch(block, irn_selector, n_outs, table);
}
pub fn newDSwitch(dbgi: ?*dbg_info, irn_selector: ?*ir_node, n_outs: u32, table: ?*ir_switch_table) ?*ir_node {
    return low_level.new_d_Switch(dbgi, irn_selector, n_outs, table);
}
pub fn newSwitch(irn_selector: ?*ir_node, n_outs: u32, table: ?*ir_switch_table) ?*ir_node {
    return low_level.new_Switch(irn_selector, n_outs, table);
}
pub fn isSwitch(node: ?*const ir_node) bool {
    return low_level.is_Switch(node) == 1;
}
pub fn getSwitchSelector(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Switch_selector(node);
}
pub fn setSwitchSelector(node: ?*ir_node, selector: ?*ir_node) void {
    return low_level.set_Switch_selector(node, selector);
}
pub fn getSwitchNOuts(node: ?*const ir_node) u32 {
    return low_level.get_Switch_n_outs(node);
}
pub fn setSwitchNOuts(node: ?*ir_node, n_outs: u32) void {
    return low_level.set_Switch_n_outs(node, n_outs);
}
pub fn getSwitchTable(node: ?*const ir_node) ?*ir_switch_table {
    return low_level.get_Switch_table(node);
}
pub fn setSwitchTable(node: ?*ir_node, table: ?*ir_switch_table) void {
    return low_level.set_Switch_table(node, table);
}
pub fn getOpSwitch() ?*ir_op {
    return low_level.get_op_Switch();
}
pub fn newRdSync(dbgi: ?*dbg_info, block: ?*ir_node, arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_rd_Sync(dbgi, block, arity, in);
}
pub fn newRSync(block: ?*ir_node, arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_r_Sync(block, arity, in);
}
pub fn newDSync(dbgi: ?*dbg_info, arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_d_Sync(dbgi, arity, in);
}
pub fn newSync(arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_Sync(arity, in);
}
pub fn isSync(node: ?*const ir_node) bool {
    return low_level.is_Sync(node) == 1;
}
pub fn getSyncNPreds(node: ?*const ir_node) i32 {
    return low_level.get_Sync_n_preds(node);
}
pub fn getSyncPred(node: ?*const ir_node, pos: i32) ?*ir_node {
    return low_level.get_Sync_pred(node, pos);
}
pub fn setSyncPred(node: ?*ir_node, pos: i32, pred: ?*ir_node) void {
    return low_level.set_Sync_pred(node, pos, pred);
}
pub fn getSyncPredArr(node: ?*ir_node) [*]?*ir_node {
    return low_level.get_Sync_pred_arr(node);
}
pub fn getOpSync() ?*ir_op {
    return low_level.get_op_Sync();
}
pub fn newRdTuple(dbgi: ?*dbg_info, block: ?*ir_node, arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_rd_Tuple(dbgi, block, arity, in);
}
pub fn newRTuple(block: ?*ir_node, arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_r_Tuple(block, arity, in);
}
pub fn newDTuple(dbgi: ?*dbg_info, arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_d_Tuple(dbgi, arity, in);
}
pub fn newTuple(arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_Tuple(arity, in);
}
pub fn isTuple(node: ?*const ir_node) bool {
    return low_level.is_Tuple(node) == 1;
}
pub fn getTupleNPreds(node: ?*const ir_node) i32 {
    return low_level.get_Tuple_n_preds(node);
}
pub fn getTuplePred(node: ?*const ir_node, pos: i32) ?*ir_node {
    return low_level.get_Tuple_pred(node, pos);
}
pub fn setTuplePred(node: ?*ir_node, pos: i32, pred: ?*ir_node) void {
    return low_level.set_Tuple_pred(node, pos, pred);
}
pub fn getTuplePredArr(node: ?*ir_node) [*]?*ir_node {
    return low_level.get_Tuple_pred_arr(node);
}
pub fn getOpTuple() ?*ir_op {
    return low_level.get_op_Tuple();
}
pub fn newRdUnknown(dbgi: ?*dbg_info, irg: ?*ir_graph, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_rd_Unknown(dbgi, irg, mode);
}
pub fn newRUnknown(irg: ?*ir_graph, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_r_Unknown(irg, mode);
}
pub fn newDUnknown(dbgi: ?*dbg_info, mode: ?*ir_mode) ?*ir_node {
    return low_level.new_d_Unknown(dbgi, mode);
}
pub fn newUnknown(mode: ?*ir_mode) ?*ir_node {
    return low_level.new_Unknown(mode);
}
pub fn isUnknown(node: ?*const ir_node) bool {
    return low_level.is_Unknown(node) == 1;
}
pub fn getOpUnknown() ?*ir_op {
    return low_level.get_op_Unknown();
}
pub fn isBinop(node: ?*const ir_node) bool {
    return low_level.is_binop(node) == 1;
}
pub fn isEntconst(node: ?*const ir_node) bool {
    return low_level.is_entconst(node) == 1;
}
pub fn getEntconstEntity(node: ?*const ir_node) ?*ir_entity {
    return low_level.get_entconst_entity(node);
}
pub fn setEntconstEntity(node: ?*ir_node, entity: ?*ir_entity) void {
    return low_level.set_entconst_entity(node, entity);
}
pub fn isTypeconst(node: ?*const ir_node) bool {
    return low_level.is_typeconst(node) == 1;
}
pub fn getTypeconstType(node: ?*const ir_node) ?*ir_type {
    return low_level.get_typeconst_type(node);
}
pub fn setTypeconstType(node: ?*ir_node, @"type": ?*ir_type) void {
    return low_level.set_typeconst_type(node, @"type");
}
pub fn getIrnArity(node: ?*const ir_node) i32 {
    return low_level.get_irn_arity(node);
}
pub fn getIrnN(node: ?*const ir_node, n: i32) ?*ir_node {
    return low_level.get_irn_n(node, n);
}
pub fn setIrnIn(node: ?*ir_node, arity: i32, in: [*]const ?*ir_node) void {
    return low_level.set_irn_in(node, arity, in);
}
pub fn setIrnN(node: ?*ir_node, n: i32, in: ?*ir_node) void {
    return low_level.set_irn_n(node, n, in);
}
pub fn addIrnN(node: ?*ir_node, in: ?*ir_node) i32 {
    return low_level.add_irn_n(node, in);
}
pub fn setIrnMode(node: ?*ir_node, mode: ?*ir_mode) void {
    return low_level.set_irn_mode(node, mode);
}
pub fn getIrnMode(node: ?*const ir_node) ?*ir_mode {
    return low_level.get_irn_mode(node);
}
pub fn getIrnOp(node: ?*const ir_node) ?*ir_op {
    return low_level.get_irn_op(node);
}
pub fn getIrnOpcode(node: ?*const ir_node) u32 {
    return low_level.get_irn_opcode(node);
}
pub fn getIrnOpname(node: ?*const ir_node) [*]const u8 {
    return low_level.get_irn_opname(node);
}
pub fn getIrnOpident(node: ?*const ir_node) [*]const u8 {
    return low_level.get_irn_opident(node);
}
pub fn getIrnVisited(node: ?*const ir_node) ir_visited_t {
    return low_level.get_irn_visited(node);
}
pub fn setIrnVisited(node: ?*ir_node, visited: ir_visited_t) void {
    return low_level.set_irn_visited(node, visited);
}
pub fn markIrnVisited(node: ?*ir_node) void {
    return low_level.mark_irn_visited(node);
}
pub fn irnVisited(node: ?*const ir_node) i32 {
    return low_level.irn_visited(node);
}
pub fn irnVisitedElseMark(node: ?*ir_node) i32 {
    return low_level.irn_visited_else_mark(node);
}
pub fn setIrnLink(node: ?*ir_node, link: ?*anyopaque) void {
    return low_level.set_irn_link(node, link);
}
pub fn getIrnLink(node: ?*const ir_node) ?*anyopaque {
    return low_level.get_irn_link(node);
}
pub fn getIrnIrg(node: ?*const ir_node) ?*ir_graph {
    return low_level.get_irn_irg(node);
}
pub fn getIrnNodeNr(node: ?*const ir_node) i64 {
    return low_level.get_irn_node_nr(node);
}
pub fn getIrnPinned(node: ?*const ir_node) i32 {
    return low_level.get_irn_pinned(node);
}
pub fn setIrnPinned(node: ?*ir_node, pinned: i32) void {
    return low_level.set_irn_pinned(node, pinned);
}
pub fn newIrNode(db: ?*dbg_info, irg: ?*ir_graph, block: ?*ir_node, op: ?*ir_op, mode: ?*ir_mode, arity: i32, in: [*]const ?*ir_node) ?*ir_node {
    return low_level.new_ir_node(db, irg, block, op, mode, arity, in);
}
pub fn exactCopy(node: ?*const ir_node) ?*ir_node {
    return low_level.exact_copy(node);
}
pub fn irnCopyIntoIrg(node: ?*const ir_node, irg: ?*ir_graph) ?*ir_node {
    return low_level.irn_copy_into_irg(node, irg);
}
pub fn getNodesBlock(node: ?*const ir_node) ?*ir_node {
    return low_level.get_nodes_block(node);
}
pub fn setNodesBlock(node: ?*ir_node, block: ?*ir_node) void {
    return low_level.set_nodes_block(node, block);
}
pub fn getBlockCfgpredBlock(node: ?*const ir_node, pos: i32) ?*ir_node {
    return low_level.get_Block_cfgpred_block(node, pos);
}
pub fn getBlockMatured(block: ?*const ir_node) i32 {
    return low_level.get_Block_matured(block);
}
pub fn setBlockMatured(block: ?*ir_node, matured: i32) void {
    return low_level.set_Block_matured(block, matured);
}
pub fn getBlockBlockVisited(block: ?*const ir_node) ir_visited_t {
    return low_level.get_Block_block_visited(block);
}
pub fn setBlockBlockVisited(block: ?*ir_node, visit: ir_visited_t) void {
    return low_level.set_Block_block_visited(block, visit);
}
pub fn markBlockBlockVisited(node: ?*ir_node) void {
    return low_level.mark_Block_block_visited(node);
}
pub fn blockBlockVisited(node: ?*const ir_node) i32 {
    return low_level.Block_block_visited(node);
}
pub fn createBlockEntity(block: ?*ir_node) ?*ir_entity {
    return low_level.create_Block_entity(block);
}
pub fn getBlockPhis(block: ?*const ir_node) ?*ir_node {
    return low_level.get_Block_phis(block);
}
pub fn setBlockPhis(block: ?*ir_node, phi: ?*ir_node) void {
    return low_level.set_Block_phis(block, phi);
}
pub fn addBlockPhi(block: ?*ir_node, phi: ?*ir_node) void {
    return low_level.add_Block_phi(block, phi);
}
pub fn getBlockMark(block: ?*const ir_node) u32 {
    return low_level.get_Block_mark(block);
}
pub fn setBlockMark(block: ?*ir_node, mark: u32) void {
    return low_level.set_Block_mark(block, mark);
}
pub fn addEndKeepalive(end: ?*ir_node, ka: ?*ir_node) void {
    return low_level.add_End_keepalive(end, ka);
}
pub fn setEndKeepalives(end: ?*ir_node, n: i32, in: [*]?*ir_node) void {
    return low_level.set_End_keepalives(end, n, in);
}
pub fn removeEndKeepalive(end: ?*ir_node, irn: ?*const ir_node) void {
    return low_level.remove_End_keepalive(end, irn);
}
pub fn removeEndN(end: ?*ir_node, idx: i32) void {
    return low_level.remove_End_n(end, idx);
}
pub fn removeEndBadsAndDoublets(end: ?*ir_node) void {
    return low_level.remove_End_Bads_and_doublets(end);
}
pub fn freeEnd(end: ?*ir_node) void {
    return low_level.free_End(end);
}
pub fn isConstNull(node: ?*const ir_node) bool {
    return low_level.is_Const_null(node) == 1;
}
pub fn isConstOne(node: ?*const ir_node) bool {
    return low_level.is_Const_one(node) == 1;
}
pub fn isConstAllOne(node: ?*const ir_node) bool {
    return low_level.is_Const_all_one(node) == 1;
}
pub fn getCallCallee(call: ?*const ir_node) ?*ir_entity {
    return low_level.get_Call_callee(call);
}
pub fn getBuiltinKindName(kind: u32) [*]const u8 {
    return low_level.get_builtin_kind_name(kind);
}
pub fn getBinopLeft(node: ?*const ir_node) ?*ir_node {
    return low_level.get_binop_left(node);
}
pub fn setBinopLeft(node: ?*ir_node, left: ?*ir_node) void {
    return low_level.set_binop_left(node, left);
}
pub fn getBinopRight(node: ?*const ir_node) ?*ir_node {
    return low_level.get_binop_right(node);
}
pub fn setBinopRight(node: ?*ir_node, right: ?*ir_node) void {
    return low_level.set_binop_right(node, right);
}
pub fn isXExceptProj(node: ?*const ir_node) bool {
    return low_level.is_x_except_Proj(node) == 1;
}
pub fn isXRegularProj(node: ?*const ir_node) bool {
    return low_level.is_x_regular_Proj(node) == 1;
}
pub fn irSetThrowsException(node: ?*ir_node, throws_exception: i32) void {
    return low_level.ir_set_throws_exception(node, throws_exception);
}
pub fn irThrowsException(node: ?*const ir_node) i32 {
    return low_level.ir_throws_exception(node);
}
pub fn getRelationString(relation: ir_relation) [*]const u8 {
    return low_level.get_relation_string(relation);
}
pub fn getNegatedRelation(relation: ir_relation) ir_relation {
    return @intToEnum(ir_relation, low_level.get_negated_relation(relation));
}
pub fn getInversedRelation(relation: ir_relation) ir_relation {
    return @intToEnum(ir_relation, low_level.get_inversed_relation(relation));
}
pub fn getPhiNext(phi: ?*const ir_node) ?*ir_node {
    return low_level.get_Phi_next(phi);
}
pub fn setPhiNext(phi: ?*ir_node, next: ?*ir_node) void {
    return low_level.set_Phi_next(phi, next);
}
pub fn isMemop(node: ?*const ir_node) bool {
    return low_level.is_memop(node) == 1;
}
pub fn getMemopMem(node: ?*const ir_node) ?*ir_node {
    return low_level.get_memop_mem(node);
}
pub fn setMemopMem(node: ?*ir_node, mem: ?*ir_node) void {
    return low_level.set_memop_mem(node, mem);
}
pub fn addSyncPred(node: ?*ir_node, pred: ?*ir_node) void {
    return low_level.add_Sync_pred(node, pred);
}
pub fn removeSyncN(n: ?*ir_node, i: i32) void {
    return low_level.remove_Sync_n(n, i);
}
pub fn getAsmNConstraints(node: ?*const ir_node) usize {
    return low_level.get_ASM_n_constraints(node);
}
pub fn getAsmNClobbers(node: ?*const ir_node) usize {
    return low_level.get_ASM_n_clobbers(node);
}
pub fn skipProj(node: ?*ir_node) ?*ir_node {
    return low_level.skip_Proj(node);
}
pub fn skipProjConst(node: ?*const ir_node) ir_node {
    return low_level.skip_Proj_const(node);
}
pub fn skipId(node: ?*ir_node) ?*ir_node {
    return low_level.skip_Id(node);
}
pub fn skipTuple(node: ?*ir_node) ?*ir_node {
    return low_level.skip_Tuple(node);
}
pub fn skipPin(node: ?*ir_node) ?*ir_node {
    return low_level.skip_Pin(node);
}
pub fn skipConfirm(node: ?*ir_node) ?*ir_node {
    return low_level.skip_Confirm(node);
}
pub fn isCfop(node: ?*const ir_node) bool {
    return low_level.is_cfop(node) == 1;
}
pub fn isUnknownJump(node: ?*const ir_node) bool {
    return low_level.is_unknown_jump(node) == 1;
}
pub fn isFragileOp(node: ?*const ir_node) bool {
    return low_level.is_fragile_op(node) == 1;
}
pub fn isIrnForking(node: ?*const ir_node) bool {
    return low_level.is_irn_forking(node) == 1;
}
pub fn isIrnConstMemory(node: ?*const ir_node) bool {
    return low_level.is_irn_const_memory(node) == 1;
}
pub fn copyNodeAttr(irg: ?*ir_graph, old_node: ?*const ir_node, new_node: ?*ir_node) void {
    return low_level.copy_node_attr(irg, old_node, new_node);
}
pub fn getIrnTypeAttr(n: ?*ir_node) ?*ir_type {
    return low_level.get_irn_type_attr(n);
}
pub fn getIrnEntityAttr(n: ?*ir_node) ?*ir_entity {
    return low_level.get_irn_entity_attr(n);
}
pub fn isIrnConstlike(node: ?*const ir_node) bool {
    return low_level.is_irn_constlike(node) == 1;
}
pub fn isIrnKeep(node: ?*const ir_node) bool {
    return low_level.is_irn_keep(node) == 1;
}
pub fn isIrnStartBlockPlaced(node: ?*const ir_node) bool {
    return low_level.is_irn_start_block_placed(node) == 1;
}
pub fn getCondJmpPredicateName(pred: u32) [*]const u8 {
    return low_level.get_cond_jmp_predicate_name(pred);
}
pub fn getIrnGenericAttr(node: ?*ir_node) ?*anyopaque {
    return low_level.get_irn_generic_attr(node);
}
pub fn getIrnGenericAttrConst(node: ?*const ir_node) anyopaque {
    return low_level.get_irn_generic_attr_const(node);
}
pub fn getIrnIdx(node: ?*const ir_node) u32 {
    return low_level.get_irn_idx(node);
}
pub fn setIrnDbgInfo(n: ?*ir_node, db: ?*dbg_info) void {
    return low_level.set_irn_dbg_info(n, db);
}
pub fn getIrnDbgInfo(n: ?*const ir_node) ?*dbg_info {
    return low_level.get_irn_dbg_info(n);
}
pub fn gdbNodeHelper(firm_object: ?*const anyopaque) [*]const u8 {
    return low_level.gdb_node_helper(firm_object);
}
pub fn irNewSwitchTable(irg: ?*ir_graph, n_entries: usize) ?*ir_switch_table {
    return low_level.ir_new_switch_table(irg, n_entries);
}
pub fn irSwitchTableGetNEntries(table: ?*const ir_switch_table) usize {
    return low_level.ir_switch_table_get_n_entries(table);
}
pub fn irSwitchTableSet(table: ?*ir_switch_table, entry: usize, min: ?*ir_tarval, max: ?*ir_tarval, pn: u32) void {
    return low_level.ir_switch_table_set(table, entry, min, max, pn);
}
pub fn irSwitchTableGetMax(table: ?*const ir_switch_table, entry: usize) ?*ir_tarval {
    return low_level.ir_switch_table_get_max(table, entry);
}
pub fn irSwitchTableGetMin(table: ?*const ir_switch_table, entry: usize) ?*ir_tarval {
    return low_level.ir_switch_table_get_min(table, entry);
}
pub fn irSwitchTableGetPn(table: ?*const ir_switch_table, entry: usize) u32 {
    return low_level.ir_switch_table_get_pn(table, entry);
}
pub fn irSwitchTableDuplicate(irg: ?*ir_graph, table: ?*const ir_switch_table) ?*ir_switch_table {
    return low_level.ir_switch_table_duplicate(irg, table);
}
pub fn newRdConstLong(db: ?*dbg_info, irg: ?*ir_graph, mode: ?*ir_mode, value: i64) ?*ir_node {
    return low_level.new_rd_Const_long(db, irg, mode, value);
}
pub fn newRConstLong(irg: ?*ir_graph, mode: ?*ir_mode, value: i64) ?*ir_node {
    return low_level.new_r_Const_long(irg, mode, value);
}
pub fn newDConstLong(db: ?*dbg_info, mode: ?*ir_mode, value: i64) ?*ir_node {
    return low_level.new_d_Const_long(db, mode, value);
}
pub fn newConstLong(mode: ?*ir_mode, value: i64) ?*ir_node {
    return low_level.new_Const_long(mode, value);
}
pub fn newRdPhiLoop(db: ?*dbg_info, block: ?*ir_node, arity: i32, in: [*]?*ir_node) ?*ir_node {
    return low_level.new_rd_Phi_loop(db, block, arity, in);
}
pub fn newRPhiLoop(block: ?*ir_node, arity: i32, in: [*]?*ir_node) ?*ir_node {
    return low_level.new_r_Phi_loop(block, arity, in);
}
pub fn newDPhiLoop(db: ?*dbg_info, arity: i32, in: [*]?*ir_node) ?*ir_node {
    return low_level.new_d_Phi_loop(db, arity, in);
}
pub fn newPhiLoop(arity: i32, in: [*]?*ir_node) ?*ir_node {
    return low_level.new_Phi_loop(arity, in);
}
pub fn newRdDivrl(db: ?*dbg_info, block: ?*ir_node, memop: ?*ir_node, op1: ?*ir_node, op2: ?*ir_node, pinned: i32) ?*ir_node {
    return low_level.new_rd_DivRL(db, block, memop, op1, op2, pinned);
}
pub fn newRDivrl(block: ?*ir_node, memop: ?*ir_node, op1: ?*ir_node, op2: ?*ir_node, pinned: i32) ?*ir_node {
    return low_level.new_r_DivRL(block, memop, op1, op2, pinned);
}
pub fn newDDivrl(db: ?*dbg_info, memop: ?*ir_node, op1: ?*ir_node, op2: ?*ir_node, pinned: i32) ?*ir_node {
    return low_level.new_d_DivRL(db, memop, op1, op2, pinned);
}
pub fn newDivrl(memop: ?*ir_node, op1: ?*ir_node, op2: ?*ir_node, pinned: i32) ?*ir_node {
    return low_level.new_DivRL(memop, op1, op2, pinned);
}
pub fn getCurrentIrGraph() ?*ir_graph {
    return low_level.get_current_ir_graph();
}
pub fn setCurrentIrGraph(graph: ?*ir_graph) void {
    return low_level.set_current_ir_graph(graph);
}
pub fn newDImmblock(db: ?*dbg_info) ?*ir_node {
    return low_level.new_d_immBlock(db);
}
pub fn newImmblock() ?*ir_node {
    return low_level.new_immBlock();
}
pub fn newRImmblock(irg: ?*ir_graph) ?*ir_node {
    return low_level.new_r_immBlock(irg);
}
pub fn newRdImmblock(db: ?*dbg_info, irg: ?*ir_graph) ?*ir_node {
    return low_level.new_rd_immBlock(db, irg);
}
pub fn addImmblockPred(immblock: ?*ir_node, jmp: ?*ir_node) void {
    return low_level.add_immBlock_pred(immblock, jmp);
}
pub fn matureImmblock(block: ?*ir_node) void {
    return low_level.mature_immBlock(block);
}
pub fn setCurBlock(target: ?*ir_node) void {
    return low_level.set_cur_block(target);
}
pub fn setRCurBlock(irg: ?*ir_graph, target: ?*ir_node) void {
    return low_level.set_r_cur_block(irg, target);
}
pub fn getCurBlock() ?*ir_node {
    return low_level.get_cur_block();
}
pub fn getRCurBlock(irg: ?*ir_graph) ?*ir_node {
    return low_level.get_r_cur_block(irg);
}
pub fn getValue(pos: i32, mode: ?*ir_mode) ?*ir_node {
    return low_level.get_value(pos, mode);
}
pub fn getRValue(irg: ?*ir_graph, pos: i32, mode: ?*ir_mode) ?*ir_node {
    return low_level.get_r_value(irg, pos, mode);
}
pub fn irGuessMode(pos: i32) ?*ir_mode {
    return low_level.ir_guess_mode(pos);
}
pub fn irRGuessMode(irg: ?*ir_graph, pos: i32) ?*ir_mode {
    return low_level.ir_r_guess_mode(irg, pos);
}
pub fn setValue(pos: i32, value: ?*ir_node) void {
    return low_level.set_value(pos, value);
}
pub fn setRValue(irg: ?*ir_graph, pos: i32, value: ?*ir_node) void {
    return low_level.set_r_value(irg, pos, value);
}
pub fn getStore() ?*ir_node {
    return low_level.get_store();
}
pub fn getRStore(irg: ?*ir_graph) ?*ir_node {
    return low_level.get_r_store(irg);
}
pub fn setStore(store: ?*ir_node) void {
    return low_level.set_store(store);
}
pub fn setRStore(irg: ?*ir_graph, store: ?*ir_node) void {
    return low_level.set_r_store(irg, store);
}
pub fn keepAlive(ka: ?*ir_node) void {
    return low_level.keep_alive(ka);
}
pub fn irgFinalizeCons(irg: ?*ir_graph) void {
    return low_level.irg_finalize_cons(irg);
}
pub fn verifyNewNode(node: ?*ir_node) void {
    return low_level.verify_new_node(node);
}
pub fn irSetUninitializedLocalVariableFunc(func: ?uninitialized_local_variable_func_t) void {
    return low_level.ir_set_uninitialized_local_variable_func(func);
}
pub fn constructConfirms(irg: ?*ir_graph) void {
    return low_level.construct_confirms(irg);
}
pub fn constructConfirmsOnly(irg: ?*ir_graph) void {
    return low_level.construct_confirms_only(irg);
}
pub fn removeConfirms(irg: ?*ir_graph) void {
    return low_level.remove_confirms(irg);
}
pub fn getBlockIdom(block: ?*const ir_node) ?*ir_node {
    return low_level.get_Block_idom(block);
}
pub fn getBlockIpostdom(block: ?*const ir_node) ?*ir_node {
    return low_level.get_Block_ipostdom(block);
}
pub fn getBlockDomDepth(bl: ?*const ir_node) i32 {
    return low_level.get_Block_dom_depth(bl);
}
pub fn getBlockPostdomDepth(bl: ?*const ir_node) i32 {
    return low_level.get_Block_postdom_depth(bl);
}
pub fn blockDominates(a: ?*const ir_node, b: ?*const ir_node) i32 {
    return low_level.block_dominates(a, b);
}
pub fn blockPostdominates(a: ?*const ir_node, b: ?*const ir_node) i32 {
    return low_level.block_postdominates(a, b);
}
pub fn blockStrictlyPostdominates(a: ?*const ir_node, b: ?*const ir_node) i32 {
    return low_level.block_strictly_postdominates(a, b);
}
pub fn getBlockDominatedFirst(block: ?*const ir_node) ?*ir_node {
    return low_level.get_Block_dominated_first(block);
}
pub fn getBlockPostdominatedFirst(bl: ?*const ir_node) ?*ir_node {
    return low_level.get_Block_postdominated_first(bl);
}
pub fn getBlockDominatedNext(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Block_dominated_next(node);
}
pub fn getBlockPostdominatedNext(node: ?*const ir_node) ?*ir_node {
    return low_level.get_Block_postdominated_next(node);
}
pub fn irDeepestCommonDominator(block0: ?*ir_node, block1: ?*ir_node) ?*ir_node {
    return low_level.ir_deepest_common_dominator(block0, block1);
}
pub fn domTreeWalk(n: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.dom_tree_walk(n, pre, post, env);
}
pub fn postdomTreeWalk(n: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.postdom_tree_walk(n, pre, post, env);
}
pub fn domTreeWalkIrg(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.dom_tree_walk_irg(irg, pre, post, env);
}
pub fn postdomTreeWalkIrg(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.postdom_tree_walk_irg(irg, pre, post, env);
}
pub fn computeDoms(irg: ?*ir_graph) void {
    return low_level.compute_doms(irg);
}
pub fn computePostdoms(irg: ?*ir_graph) void {
    return low_level.compute_postdoms(irg);
}
pub fn irComputeDominanceFrontiers(irg: ?*ir_graph) void {
    return low_level.ir_compute_dominance_frontiers(irg);
}
pub fn irGetDominanceFrontier(block: ?*const ir_node) [*]?*ir_node {
    return low_level.ir_get_dominance_frontier(block);
}
pub fn dumpIrGraph(graph: ?*ir_graph, suffix: [*]const u8) void {
    return low_level.dump_ir_graph(graph, suffix);
}
pub fn dumpIrProgExt(func: ir_prog_dump_func, suffix: [*]const u8) void {
    return low_level.dump_ir_prog_ext(func, suffix);
}
pub fn dumpIrGraphExt(func: ir_graph_dump_func, graph: ?*ir_graph, suffix: [*]const u8) void {
    return low_level.dump_ir_graph_ext(func, graph, suffix);
}
pub fn dumpAllIrGraphs(suffix: [*]const u8) void {
    return low_level.dump_all_ir_graphs(suffix);
}
pub fn irSetDumpPath(path: [*]const u8) void {
    return low_level.ir_set_dump_path(path);
}
pub fn irSetDumpFilter(name: [*]const u8) void {
    return low_level.ir_set_dump_filter(name);
}
pub fn irGetDumpFilter() [*]const u8 {
    return low_level.ir_get_dump_filter();
}
pub fn dumpIrGraphFile(out: *std.c.FILE, graph: ?*ir_graph) void {
    return low_level.dump_ir_graph_file(out, graph);
}
pub fn dumpCfg(out: *std.c.FILE, graph: ?*ir_graph) void {
    return low_level.dump_cfg(out, graph);
}
pub fn dumpCallgraph(out: *std.c.FILE) void {
    return low_level.dump_callgraph(out);
}
pub fn dumpTypegraph(out: *std.c.FILE) void {
    return low_level.dump_typegraph(out);
}
pub fn dumpClassHierarchy(out: *std.c.FILE) void {
    return low_level.dump_class_hierarchy(out);
}
pub fn dumpLoopTree(out: *std.c.FILE, graph: ?*ir_graph) void {
    return low_level.dump_loop_tree(out, graph);
}
pub fn dumpCallgraphLoopTree(out: *std.c.FILE) void {
    return low_level.dump_callgraph_loop_tree(out);
}
pub fn dumpTypesAsText(out: *std.c.FILE) void {
    return low_level.dump_types_as_text(out);
}
pub fn dumpGlobalsAsText(out: *std.c.FILE) void {
    return low_level.dump_globals_as_text(out);
}
pub fn dumpLoop(out: *std.c.FILE, loop: ?*ir_loop) void {
    return low_level.dump_loop(out, loop);
}
pub fn dumpGraphAsText(out: *std.c.FILE, graph: ?*const ir_graph) void {
    return low_level.dump_graph_as_text(out, graph);
}
pub fn dumpEntityToFile(out: *std.c.FILE, entity: ?*const ir_entity) void {
    return low_level.dump_entity_to_file(out, entity);
}
pub fn dumpTypeToFile(out: *std.c.FILE, @"type": ?*const ir_type) void {
    return low_level.dump_type_to_file(out, @"type");
}
pub fn irSetDumpVerbosity(verbosity: u32) void {
    return low_level.ir_set_dump_verbosity(verbosity);
}
pub fn irGetDumpVerbosity() ir_dump_verbosity_t {
    return @intToEnum(ir_dump_verbosity_t, low_level.ir_get_dump_verbosity());
}
pub fn irSetDumpFlags(flags: u32) void {
    return low_level.ir_set_dump_flags(flags);
}
pub fn irAddDumpFlags(flags: u32) void {
    return low_level.ir_add_dump_flags(flags);
}
pub fn irRemoveDumpFlags(flags: u32) void {
    return low_level.ir_remove_dump_flags(flags);
}
pub fn irGetDumpFlags() ir_dump_flags_t {
    return @intToEnum(ir_dump_flags_t, low_level.ir_get_dump_flags());
}
pub fn setDumpNodeVcgattrHook(hook: dump_node_vcgattr_func) void {
    return low_level.set_dump_node_vcgattr_hook(hook);
}
pub fn setDumpEdgeVcgattrHook(hook: dump_edge_vcgattr_func) void {
    return low_level.set_dump_edge_vcgattr_hook(hook);
}
pub fn setDumpNodeEdgeHook(func: dump_node_edge_func) void {
    return low_level.set_dump_node_edge_hook(func);
}
pub fn getDumpNodeEdgeHook() dump_node_edge_func {
    return low_level.get_dump_node_edge_hook();
}
pub fn setDumpBlockEdgeHook(func: dump_node_edge_func) void {
    return low_level.set_dump_block_edge_hook(func);
}
pub fn getDumpBlockEdgeHook() dump_node_edge_func {
    return low_level.get_dump_block_edge_hook();
}
pub fn dumpAddNodeInfoCallback(cb: ?dump_node_info_cb_t, data: ?*anyopaque) ?*hook_entry_t {
    return low_level.dump_add_node_info_callback(cb, data);
}
pub fn dumpRemoveNodeInfoCallback(handle: ?*hook_entry_t) void {
    return low_level.dump_remove_node_info_callback(handle);
}
pub fn dumpVcgHeader(out: *std.c.FILE, name: [*]const u8, layout: [*]const u8, orientation: [*]const u8) void {
    return low_level.dump_vcg_header(out, name, layout, orientation);
}
pub fn dumpVcgFooter(out: *std.c.FILE) void {
    return low_level.dump_vcg_footer(out);
}
pub fn dumpNode(out: *std.c.FILE, node: ?*const ir_node) void {
    return low_level.dump_node(out, node);
}
pub fn dumpIrDataEdges(out: *std.c.FILE, node: ?*const ir_node) void {
    return low_level.dump_ir_data_edges(out, node);
}
pub fn printNodeid(out: *std.c.FILE, node: ?*const ir_node) void {
    return low_level.print_nodeid(out, node);
}
pub fn dumpBeginBlockSubgraph(out: *std.c.FILE, block: ?*const ir_node) void {
    return low_level.dump_begin_block_subgraph(out, block);
}
pub fn dumpEndBlockSubgraph(out: *std.c.FILE, block: ?*const ir_node) void {
    return low_level.dump_end_block_subgraph(out, block);
}
pub fn dumpBlockEdges(out: *std.c.FILE, block: ?*const ir_node) void {
    return low_level.dump_block_edges(out, block);
}
pub fn dumpBlocksAsSubgraphs(out: *std.c.FILE, irg: ?*ir_graph) void {
    return low_level.dump_blocks_as_subgraphs(out, irg);
}
pub fn getIrnOutEdgeFirstKind(irn: ?*const ir_node, kind: u32) ir_edge_t {
    return low_level.get_irn_out_edge_first_kind(irn, kind);
}
pub fn getIrnOutEdgeFirst(irn: ?*const ir_node) ir_edge_t {
    return low_level.get_irn_out_edge_first(irn);
}
pub fn getBlockSuccFirst(block: ?*const ir_node) ir_edge_t {
    return low_level.get_block_succ_first(block);
}
pub fn getIrnOutEdgeNext(irn: ?*const ir_node, last: ?*const ir_edge_t, kind: u32) ir_edge_t {
    return low_level.get_irn_out_edge_next(irn, last, kind);
}
pub fn getEdgeSrcIrn(edge: ?*const ir_edge_t) ?*ir_node {
    return low_level.get_edge_src_irn(edge);
}
pub fn getEdgeSrcPos(edge: ?*const ir_edge_t) i32 {
    return low_level.get_edge_src_pos(edge);
}
pub fn getIrnNEdgesKind(irn: ?*const ir_node, kind: u32) i32 {
    return low_level.get_irn_n_edges_kind(irn, kind);
}
pub fn getIrnNEdges(irn: ?*const ir_node) i32 {
    return low_level.get_irn_n_edges(irn);
}
pub fn edgesActivatedKind(irg: ?*const ir_graph, kind: u32) i32 {
    return low_level.edges_activated_kind(irg, kind);
}
pub fn edgesActivated(irg: ?*const ir_graph) i32 {
    return low_level.edges_activated(irg);
}
pub fn edgesActivateKind(irg: ?*ir_graph, kind: u32) void {
    return low_level.edges_activate_kind(irg, kind);
}
pub fn edgesDeactivateKind(irg: ?*ir_graph, kind: u32) void {
    return low_level.edges_deactivate_kind(irg, kind);
}
pub fn edgesRerouteKind(old: ?*ir_node, nw: ?*ir_node, kind: u32) void {
    return low_level.edges_reroute_kind(old, nw, kind);
}
pub fn edgesReroute(old: ?*ir_node, nw: ?*ir_node) void {
    return low_level.edges_reroute(old, nw);
}
pub fn edgesRerouteExcept(old: ?*ir_node, nw: ?*ir_node, exception: ?*ir_node) void {
    return low_level.edges_reroute_except(old, nw, exception);
}
pub fn edgesVerify(irg: ?*ir_graph) i32 {
    return low_level.edges_verify(irg);
}
pub fn edgesVerifyKind(irg: ?*ir_graph, kind: u32) i32 {
    return low_level.edges_verify_kind(irg, kind);
}
pub fn edgesInitDbg(do_dbg: i32) void {
    return low_level.edges_init_dbg(do_dbg);
}
pub fn edgesActivate(irg: ?*ir_graph) void {
    return low_level.edges_activate(irg);
}
pub fn edgesDeactivate(irg: ?*ir_graph) void {
    return low_level.edges_deactivate(irg);
}
pub fn assureEdges(irg: ?*ir_graph) void {
    return low_level.assure_edges(irg);
}
pub fn assureEdgesKind(irg: ?*ir_graph, kind: u32) void {
    return low_level.assure_edges_kind(irg, kind);
}
pub fn irgBlockEdgesWalk(block: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_block_edges_walk(block, pre, post, env);
}
pub fn irgWalkEdges(start: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_walk_edges(start, pre, post, env);
}
pub fn setOptimize(value: i32) void {
    return low_level.set_optimize(value);
}
pub fn getOptimize() i32 {
    return low_level.get_optimize();
}
pub fn setOptConstantFolding(value: i32) void {
    return low_level.set_opt_constant_folding(value);
}
pub fn getOptConstantFolding() i32 {
    return low_level.get_opt_constant_folding();
}
pub fn setOptAlgebraicSimplification(value: i32) void {
    return low_level.set_opt_algebraic_simplification(value);
}
pub fn getOptAlgebraicSimplification() i32 {
    return low_level.get_opt_algebraic_simplification();
}
pub fn setOptCse(value: i32) void {
    return low_level.set_opt_cse(value);
}
pub fn getOptCse() i32 {
    return low_level.get_opt_cse();
}
pub fn setOptGlobalCse(value: i32) void {
    return low_level.set_opt_global_cse(value);
}
pub fn getOptGlobalCse() i32 {
    return low_level.get_opt_global_cse();
}
pub fn setOptGlobalNullPtrElimination(value: i32) void {
    return low_level.set_opt_global_null_ptr_elimination(value);
}
pub fn getOptGlobalNullPtrElimination() i32 {
    return low_level.get_opt_global_null_ptr_elimination();
}
pub fn saveOptimizationState(state: [*]optimization_state_t) void {
    return low_level.save_optimization_state(state);
}
pub fn restoreOptimizationState(state: [*]const optimization_state_t) void {
    return low_level.restore_optimization_state(state);
}
pub fn allOptimizationsOff() void {
    return low_level.all_optimizations_off();
}
pub fn exchange(old: ?*ir_node, nw: ?*ir_node) void {
    return low_level.exchange(old, nw);
}
pub fn turnIntoTuple(node: ?*ir_node, arity: i32, in: [*]const ?*ir_node) void {
    return low_level.turn_into_tuple(node, arity, in);
}
pub fn collectPhiprojsAndStartBlockNodes(irg: ?*ir_graph) void {
    return low_level.collect_phiprojs_and_start_block_nodes(irg);
}
pub fn collectNewStartBlockNode(node: ?*ir_node) void {
    return low_level.collect_new_start_block_node(node);
}
pub fn collectNewPhiNode(node: ?*ir_node) void {
    return low_level.collect_new_phi_node(node);
}
pub fn partBlock(node: ?*ir_node) void {
    return low_level.part_block(node);
}
pub fn partBlockEdges(node: ?*ir_node) ?*ir_node {
    return low_level.part_block_edges(node);
}
pub fn killNode(node: ?*ir_node) void {
    return low_level.kill_node(node);
}
pub fn duplicateSubgraph(dbg: ?*dbg_info, n: ?*ir_node, to_block: ?*ir_node) ?*ir_node {
    return low_level.duplicate_subgraph(dbg, n, to_block);
}
pub fn localOptimizeNode(n: ?*ir_node) void {
    return low_level.local_optimize_node(n);
}
pub fn optimizeNode(n: ?*ir_node) ?*ir_node {
    return low_level.optimize_node(n);
}
pub fn localOptimizeGraph(irg: ?*ir_graph) void {
    return low_level.local_optimize_graph(irg);
}
pub fn optimizeGraphDf(irg: ?*ir_graph) void {
    return low_level.optimize_graph_df(irg);
}
pub fn localOptsConstCode() void {
    return low_level.local_opts_const_code();
}
pub fn removeUnreachableCode(irg: ?*ir_graph) void {
    return low_level.remove_unreachable_code(irg);
}
pub fn removeBads(irg: ?*ir_graph) void {
    return low_level.remove_bads(irg);
}
pub fn removeTuples(irg: ?*ir_graph) void {
    return low_level.remove_tuples(irg);
}
pub fn removeCriticalCfEdges(irg: ?*ir_graph) void {
    return low_level.remove_critical_cf_edges(irg);
}
pub fn removeCriticalCfEdgesEx(irg: ?*ir_graph, ignore_exception_edges: i32) void {
    return low_level.remove_critical_cf_edges_ex(irg, ignore_exception_edges);
}
pub fn newIrGraph(ent: ?*ir_entity, n_loc: i32) ?*ir_graph {
    return low_level.new_ir_graph(ent, n_loc);
}
pub fn freeIrGraph(irg: ?*ir_graph) void {
    return low_level.free_ir_graph(irg);
}
pub fn getIrgEntity(irg: ?*const ir_graph) ?*ir_entity {
    return low_level.get_irg_entity(irg);
}
pub fn setIrgEntity(irg: ?*ir_graph, ent: ?*ir_entity) void {
    return low_level.set_irg_entity(irg, ent);
}
pub fn getIrgFrameType(irg: ?*ir_graph) ?*ir_type {
    return low_level.get_irg_frame_type(irg);
}
pub fn setIrgFrameType(irg: ?*ir_graph, ftp: ?*ir_type) void {
    return low_level.set_irg_frame_type(irg, ftp);
}
pub fn getIrgStartBlock(irg: ?*const ir_graph) ?*ir_node {
    return low_level.get_irg_start_block(irg);
}
pub fn setIrgStartBlock(irg: ?*ir_graph, node: ?*ir_node) void {
    return low_level.set_irg_start_block(irg, node);
}
pub fn getIrgStart(irg: ?*const ir_graph) ?*ir_node {
    return low_level.get_irg_start(irg);
}
pub fn setIrgStart(irg: ?*ir_graph, node: ?*ir_node) void {
    return low_level.set_irg_start(irg, node);
}
pub fn getIrgEndBlock(irg: ?*const ir_graph) ?*ir_node {
    return low_level.get_irg_end_block(irg);
}
pub fn setIrgEndBlock(irg: ?*ir_graph, node: ?*ir_node) void {
    return low_level.set_irg_end_block(irg, node);
}
pub fn getIrgEnd(irg: ?*const ir_graph) ?*ir_node {
    return low_level.get_irg_end(irg);
}
pub fn setIrgEnd(irg: ?*ir_graph, node: ?*ir_node) void {
    return low_level.set_irg_end(irg, node);
}
pub fn getIrgFrame(irg: ?*const ir_graph) ?*ir_node {
    return low_level.get_irg_frame(irg);
}
pub fn setIrgFrame(irg: ?*ir_graph, node: ?*ir_node) void {
    return low_level.set_irg_frame(irg, node);
}
pub fn getIrgInitialMem(irg: ?*const ir_graph) ?*ir_node {
    return low_level.get_irg_initial_mem(irg);
}
pub fn setIrgInitialMem(irg: ?*ir_graph, node: ?*ir_node) void {
    return low_level.set_irg_initial_mem(irg, node);
}
pub fn getIrgArgs(irg: ?*const ir_graph) ?*ir_node {
    return low_level.get_irg_args(irg);
}
pub fn setIrgArgs(irg: ?*ir_graph, node: ?*ir_node) void {
    return low_level.set_irg_args(irg, node);
}
pub fn getIrgNoMem(irg: ?*const ir_graph) ?*ir_node {
    return low_level.get_irg_no_mem(irg);
}
pub fn setIrgNoMem(irg: ?*ir_graph, node: ?*ir_node) void {
    return low_level.set_irg_no_mem(irg, node);
}
pub fn getIrgNLocs(irg: ?*ir_graph) i32 {
    return low_level.get_irg_n_locs(irg);
}
pub fn getIrgGraphNr(irg: ?*const ir_graph) i64 {
    return low_level.get_irg_graph_nr(irg);
}
pub fn getIrgIdx(irg: ?*const ir_graph) usize {
    return low_level.get_irg_idx(irg);
}
pub fn getIdxIrn(irg: ?*const ir_graph, idx: u32) ?*ir_node {
    return low_level.get_idx_irn(irg, idx);
}
pub fn getIrgPinned(irg: ?*const ir_graph) op_pin_state {
    return @intToEnum(op_pin_state, low_level.get_irg_pinned(irg));
}
pub fn getIrgCalleeInfoState(irg: ?*const ir_graph) irg_callee_info_state {
    return low_level.get_irg_callee_info_state(irg);
}
pub fn setIrgCalleeInfoState(irg: ?*ir_graph, s: irg_callee_info_state) void {
    return low_level.set_irg_callee_info_state(irg, s);
}
pub fn setIrgLink(irg: ?*ir_graph, thing: ?*anyopaque) void {
    return low_level.set_irg_link(irg, thing);
}
pub fn getIrgLink(irg: ?*const ir_graph) ?*anyopaque {
    return low_level.get_irg_link(irg);
}
pub fn incIrgVisited(irg: ?*ir_graph) void {
    return low_level.inc_irg_visited(irg);
}
pub fn getIrgVisited(irg: ?*const ir_graph) ir_visited_t {
    return low_level.get_irg_visited(irg);
}
pub fn setIrgVisited(irg: ?*ir_graph, i: ir_visited_t) void {
    return low_level.set_irg_visited(irg, i);
}
pub fn getMaxIrgVisited() ir_visited_t {
    return low_level.get_max_irg_visited();
}
pub fn setMaxIrgVisited(val: i32) void {
    return low_level.set_max_irg_visited(val);
}
pub fn incMaxIrgVisited() ir_visited_t {
    return low_level.inc_max_irg_visited();
}
pub fn incIrgBlockVisited(irg: ?*ir_graph) void {
    return low_level.inc_irg_block_visited(irg);
}
pub fn getIrgBlockVisited(irg: ?*const ir_graph) ir_visited_t {
    return low_level.get_irg_block_visited(irg);
}
pub fn setIrgBlockVisited(irg: ?*ir_graph, i: ir_visited_t) void {
    return low_level.set_irg_block_visited(irg, i);
}
pub fn irReserveResources(irg: ?*ir_graph, resources: u32) void {
    return low_level.ir_reserve_resources(irg, resources);
}
pub fn irFreeResources(irg: ?*ir_graph, resources: u32) void {
    return low_level.ir_free_resources(irg, resources);
}
pub fn irResourcesReserved(irg: ?*const ir_graph) ir_resources_t {
    return @intToEnum(ir_resources_t, low_level.ir_resources_reserved(irg));
}
pub fn addIrgConstraints(irg: ?*ir_graph, constraints: u32) void {
    return low_level.add_irg_constraints(irg, constraints);
}
pub fn clearIrgConstraints(irg: ?*ir_graph, constraints: u32) void {
    return low_level.clear_irg_constraints(irg, constraints);
}
pub fn irgIsConstrained(irg: ?*const ir_graph, constraints: u32) i32 {
    return low_level.irg_is_constrained(irg, constraints);
}
pub fn addIrgProperties(irg: ?*ir_graph, props: u32) void {
    return low_level.add_irg_properties(irg, props);
}
pub fn clearIrgProperties(irg: ?*ir_graph, props: u32) void {
    return low_level.clear_irg_properties(irg, props);
}
pub fn irgHasProperties(irg: ?*const ir_graph, props: u32) i32 {
    return low_level.irg_has_properties(irg, props);
}
pub fn assureIrgProperties(irg: ?*ir_graph, props: u32) void {
    return low_level.assure_irg_properties(irg, props);
}
pub fn confirmIrgProperties(irg: ?*ir_graph, props: u32) void {
    return low_level.confirm_irg_properties(irg, props);
}
pub fn setIrgLocDescription(irg: ?*ir_graph, n: i32, description: ?*anyopaque) void {
    return low_level.set_irg_loc_description(irg, n, description);
}
pub fn getIrgLocDescription(irg: ?*ir_graph, n: i32) ?*anyopaque {
    return low_level.get_irg_loc_description(irg, n);
}
pub fn getIrgLastIdx(irg: ?*const ir_graph) u32 {
    return low_level.get_irg_last_idx(irg);
}
pub fn irgWalk(node: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_walk(node, pre, post, env);
}
pub fn irgWalkCore(node: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_walk_core(node, pre, post, env);
}
pub fn irgWalkGraph(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_walk_graph(irg, pre, post, env);
}
pub fn irgWalkInOrDep(node: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_walk_in_or_dep(node, pre, post, env);
}
pub fn irgWalkInOrDepGraph(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_walk_in_or_dep_graph(irg, pre, post, env);
}
pub fn irgWalkTopological(irg: ?*ir_graph, walker: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_walk_topological(irg, walker, env);
}
pub fn allIrgWalk(pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.all_irg_walk(pre, post, env);
}
pub fn irgBlockWalk(node: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_block_walk(node, pre, post, env);
}
pub fn irgBlockWalkGraph(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_block_walk_graph(irg, pre, post, env);
}
pub fn walkConstCode(pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.walk_const_code(pre, post, env);
}
pub fn irgWalkBlkwiseGraph(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_walk_blkwise_graph(irg, pre, post, env);
}
pub fn irgWalkBlkwiseDomTopDown(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_walk_blkwise_dom_top_down(irg, pre, post, env);
}
pub fn irgWalkAnchors(irg: ?*ir_graph, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_walk_anchors(irg, pre, post, env);
}
pub fn irgWalk2(node: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_walk_2(node, pre, post, env);
}
pub fn irExport(filename: [*]const u8) i32 {
    return low_level.ir_export(filename);
}
pub fn irExportFile(output: *std.c.FILE) void {
    return low_level.ir_export_file(output);
}
pub fn irImport(filename: [*]const u8) i32 {
    return low_level.ir_import(filename);
}
pub fn irImportFile(input: *std.c.FILE, inputname: [*]const u8) i32 {
    return low_level.ir_import_file(input, inputname);
}
pub fn isBackedge(n: ?*const ir_node, pos: bool) bool {
    return low_level.is_backedge(n, pos) == 1;
}
pub fn setBackedge(n: ?*ir_node, pos: i32) void {
    return low_level.set_backedge(n, pos);
}
pub fn hasBackedges(n: ?*const ir_node) i32 {
    return low_level.has_backedges(n);
}
pub fn clearBackedges(n: ?*ir_node) void {
    return low_level.clear_backedges(n);
}
pub fn setIrgLoop(irg: ?*ir_graph, l: ?*ir_loop) void {
    return low_level.set_irg_loop(irg, l);
}
pub fn getIrgLoop(irg: ?*const ir_graph) ?*ir_loop {
    return low_level.get_irg_loop(irg);
}
pub fn getIrnLoop(n: ?*const ir_node) ?*ir_loop {
    return low_level.get_irn_loop(n);
}
pub fn getLoopOuterLoop(loop: ?*const ir_loop) ?*ir_loop {
    return low_level.get_loop_outer_loop(loop);
}
pub fn getLoopDepth(loop: ?*const ir_loop) u32 {
    return low_level.get_loop_depth(loop);
}
pub fn getLoopNElements(loop: ?*const ir_loop) usize {
    return low_level.get_loop_n_elements(loop);
}
pub fn getLoopElement(loop: ?*const ir_loop, pos: usize) loop_element {
    return low_level.get_loop_element(loop, pos);
}
pub fn getLoopLoopNr(loop: ?*const ir_loop) i64 {
    return low_level.get_loop_loop_nr(loop);
}
pub fn setLoopLink(loop: ?*ir_loop, link: ?*anyopaque) void {
    return low_level.set_loop_link(loop, link);
}
pub fn getLoopLink(loop: ?*const ir_loop) ?*anyopaque {
    return low_level.get_loop_link(loop);
}
pub fn constructCfBackedges(irg: ?*ir_graph) void {
    return low_level.construct_cf_backedges(irg);
}
pub fn assureLoopinfo(irg: ?*ir_graph) void {
    return low_level.assure_loopinfo(irg);
}
pub fn freeLoopInformation(irg: ?*ir_graph) void {
    return low_level.free_loop_information(irg);
}
pub fn isLoopInvariant(n: ?*const ir_node, block: ?*const ir_node) bool {
    return low_level.is_loop_invariant(n, block) == 1;
}
pub fn getIrAliasRelationName(rel: u32) [*]const u8 {
    return low_level.get_ir_alias_relation_name(rel);
}
pub fn getAliasRelation(addr1: ?*const ir_node, type1: ?*const ir_type, size1: u32, addr2: ?*const ir_node, type2: ?*const ir_type, size2: u32) ir_alias_relation {
    return @intToEnum(ir_alias_relation, low_level.get_alias_relation(addr1, type1, size1, addr2, type2, size2));
}
pub fn assureIrgEntityUsageComputed(irg: ?*ir_graph) void {
    return low_level.assure_irg_entity_usage_computed(irg);
}
pub fn getIrpGlobalsEntityUsageState() ir_entity_usage_computed_state {
    return @intToEnum(ir_entity_usage_computed_state, low_level.get_irp_globals_entity_usage_state());
}
pub fn setIrpGlobalsEntityUsageState(state: u32) void {
    return low_level.set_irp_globals_entity_usage_state(state);
}
pub fn assureIrpGlobalsEntityUsageComputed() void {
    return low_level.assure_irp_globals_entity_usage_computed();
}
pub fn getIrgMemoryDisambiguatorOptions(irg: ?*const ir_graph) ir_disambiguator_options {
    return @intToEnum(ir_disambiguator_options, low_level.get_irg_memory_disambiguator_options(irg));
}
pub fn setIrgMemoryDisambiguatorOptions(irg: ?*ir_graph, options: u32) void {
    return low_level.set_irg_memory_disambiguator_options(irg, options);
}
pub fn setIrpMemoryDisambiguatorOptions(options: u32) void {
    return low_level.set_irp_memory_disambiguator_options(options);
}
pub fn markPrivateMethods() void {
    return low_level.mark_private_methods();
}
pub fn computedValue(n: ?*const ir_node) ?*ir_tarval {
    return low_level.computed_value(n);
}
pub fn optimizeInPlace(n: ?*ir_node) ?*ir_node {
    return low_level.optimize_in_place(n);
}
pub fn irIsNegatedValue(a: ?*const ir_node, b: ?*const ir_node) i32 {
    return low_level.ir_is_negated_value(a, b);
}
pub fn irGetPossibleCmpRelations(left: ?*const ir_node, right: ?*const ir_node) ir_relation {
    return @intToEnum(ir_relation, low_level.ir_get_possible_cmp_relations(left, right));
}
pub fn irAllowImpreciseFloatTransforms(enable: i32) void {
    return low_level.ir_allow_imprecise_float_transforms(enable);
}
pub fn irImpreciseFloatTransformsAllowed() i32 {
    return low_level.ir_imprecise_float_transforms_allowed();
}
pub fn getIrnNOuts(node: ?*const ir_node) u32 {
    return low_level.get_irn_n_outs(node);
}
pub fn getIrnOut(def: ?*const ir_node, pos: u32) ?*ir_node {
    return low_level.get_irn_out(def, pos);
}
pub fn getIrnOutEx(def: ?*const ir_node, pos: u32, in_pos: [*]i32) ?*ir_node {
    return low_level.get_irn_out_ex(def, pos, in_pos);
}
pub fn getBlockNCfgOuts(node: ?*const ir_node) u32 {
    return low_level.get_Block_n_cfg_outs(node);
}
pub fn getBlockNCfgOutsKa(node: ?*const ir_node) u32 {
    return low_level.get_Block_n_cfg_outs_ka(node);
}
pub fn getBlockCfgOut(node: ?*const ir_node, pos: u32) ?*ir_node {
    return low_level.get_Block_cfg_out(node, pos);
}
pub fn getBlockCfgOutEx(node: ?*const ir_node, pos: u32, in_pos: [*]i32) ?*ir_node {
    return low_level.get_Block_cfg_out_ex(node, pos, in_pos);
}
pub fn getBlockCfgOutKa(node: ?*const ir_node, pos: u32) ?*ir_node {
    return low_level.get_Block_cfg_out_ka(node, pos);
}
pub fn irgOutWalk(node: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_out_walk(node, pre, post, env);
}
pub fn irgOutBlockWalk(node: ?*ir_node, pre: ?irg_walk_func, post: ?irg_walk_func, env: ?*anyopaque) void {
    return low_level.irg_out_block_walk(node, pre, post, env);
}
pub fn computeIrgOuts(irg: ?*ir_graph) void {
    return low_level.compute_irg_outs(irg);
}
pub fn assureIrgOuts(irg: ?*ir_graph) void {
    return low_level.assure_irg_outs(irg);
}
pub fn freeIrgOuts(irg: ?*ir_graph) void {
    return low_level.free_irg_outs(irg);
}
pub fn irpReserveResources(irp1: ?*ir_prog, resources: u32) void {
    return low_level.irp_reserve_resources(irp1, resources);
}
pub fn irpFreeResources(irp2: ?*ir_prog, resources: u32) void {
    return low_level.irp_free_resources(irp2, resources);
}
pub fn irpResourcesReserved(irp3: ?*const ir_prog) irp_resources_t {
    return @intToEnum(irp_resources_t, low_level.irp_resources_reserved(irp3));
}
pub fn getIrp() ?*ir_prog {
    return low_level.get_irp();
}
pub fn setIrp(irp4: ?*ir_prog) void {
    return low_level.set_irp(irp4);
}
pub fn newIrProg(name: [*]const u8) ?*ir_prog {
    return low_level.new_ir_prog(name);
}
pub fn freeIrProg() void {
    return low_level.free_ir_prog();
}
pub fn setIrpProgName(name: [*]const u8) void {
    return low_level.set_irp_prog_name(name);
}
pub fn irpProgNameIsSet() i32 {
    return low_level.irp_prog_name_is_set();
}
pub fn getIrpIdent() [*]const u8 {
    return low_level.get_irp_ident();
}
pub fn getIrpName() [*]const u8 {
    return low_level.get_irp_name();
}
pub fn getIrpMainIrg() ?*ir_graph {
    return low_level.get_irp_main_irg();
}
pub fn setIrpMainIrg(main_irg: ?*ir_graph) void {
    return low_level.set_irp_main_irg(main_irg);
}
pub fn getIrpLastIdx() usize {
    return low_level.get_irp_last_idx();
}
pub fn getIrpNIrgs() usize {
    return low_level.get_irp_n_irgs();
}
pub fn getIrpIrg(pos: usize) ?*ir_graph {
    return low_level.get_irp_irg(pos);
}
pub fn setIrpIrg(pos: usize, irg: ?*ir_graph) void {
    return low_level.set_irp_irg(pos, irg);
}
pub fn getSegmentType(segment: u32) ?*ir_type {
    return low_level.get_segment_type(segment);
}
pub fn setSegmentType(segment: u32, new_type: ?*ir_type) void {
    return low_level.set_segment_type(segment, new_type);
}
pub fn getGlobType() ?*ir_type {
    return low_level.get_glob_type();
}
pub fn getTlsType() ?*ir_type {
    return low_level.get_tls_type();
}
pub fn irGetGlobal(name: [*]const u8) ?*ir_entity {
    return low_level.ir_get_global(name);
}
pub fn getIrpNTypes() usize {
    return low_level.get_irp_n_types();
}
pub fn getIrpType(pos: usize) ?*ir_type {
    return low_level.get_irp_type(pos);
}
pub fn setIrpType(pos: usize, typ: ?*ir_type) void {
    return low_level.set_irp_type(pos, typ);
}
pub fn getConstCodeIrg() ?*ir_graph {
    return low_level.get_const_code_irg();
}
pub fn getIrpCalleeInfoState() irg_callee_info_state {
    return low_level.get_irp_callee_info_state();
}
pub fn setIrpCalleeInfoState(s: irg_callee_info_state) void {
    return low_level.set_irp_callee_info_state(s);
}
pub fn getIrpNextLabelNr() ir_label_t {
    return low_level.get_irp_next_label_nr();
}
pub fn addIrpAsm(asm_string: [*]const u8) void {
    return low_level.add_irp_asm(asm_string);
}
pub fn getIrpNAsms() usize {
    return low_level.get_irp_n_asms();
}
pub fn getIrpAsm(pos: usize) [*]const u8 {
    return low_level.get_irp_asm(pos);
}
pub fn irnVerify(node: ?*const ir_node) i32 {
    return low_level.irn_verify(node);
}
pub fn irgVerify(irg: ?*ir_graph) i32 {
    return low_level.irg_verify(irg);
}
pub fn irgAssertVerify(irg: ?*ir_graph) void {
    return low_level.irg_assert_verify(irg);
}
pub fn lowerCopyb(irg: ?*ir_graph, max_small_size: u32, min_large_size: u32, allow_misalignments: i32) void {
    return low_level.lower_CopyB(irg, max_small_size, min_large_size, allow_misalignments);
}
pub fn lowerSwitch(irg: ?*ir_graph, small_switch: u32, spare_size: u32, selector_mode: ?*ir_mode) void {
    return low_level.lower_switch(irg, small_switch, spare_size, selector_mode);
}
pub fn lowerHighlevelGraph(irg: ?*ir_graph) void {
    return low_level.lower_highlevel_graph(irg);
}
pub fn lowerHighlevel() void {
    return low_level.lower_highlevel();
}
pub fn lowerConstCode() void {
    return low_level.lower_const_code();
}
pub fn lowerMux(irg: ?*ir_graph, cb_func: ?lower_mux_callback) void {
    return low_level.lower_mux(irg, cb_func);
}
pub fn irCreateIntrinsicsMap(list: [*]i_record, length: usize, part_block_used: i32) ?*ir_intrinsics_map {
    return low_level.ir_create_intrinsics_map(list, length, part_block_used);
}
pub fn irFreeIntrinsicsMap(map: ?*ir_intrinsics_map) void {
    return low_level.ir_free_intrinsics_map(map);
}
pub fn irLowerIntrinsics(irg: ?*ir_graph, map: ?*ir_intrinsics_map) void {
    return low_level.ir_lower_intrinsics(irg, map);
}
pub fn iMapperAbs(call: ?*ir_node) i32 {
    return low_level.i_mapper_abs(call);
}
pub fn iMapperSqrt(call: ?*ir_node) i32 {
    return low_level.i_mapper_sqrt(call);
}
pub fn iMapperCbrt(call: ?*ir_node) i32 {
    return low_level.i_mapper_cbrt(call);
}
pub fn iMapperPow(call: ?*ir_node) i32 {
    return low_level.i_mapper_pow(call);
}
pub fn iMapperExp(call: ?*ir_node) i32 {
    return low_level.i_mapper_exp(call);
}
pub fn iMapperExp2(call: ?*ir_node) i32 {
    return low_level.i_mapper_exp2(call);
}
pub fn iMapperExp10(call: ?*ir_node) i32 {
    return low_level.i_mapper_exp10(call);
}
pub fn iMapperLog(call: ?*ir_node) i32 {
    return low_level.i_mapper_log(call);
}
pub fn iMapperLog2(call: ?*ir_node) i32 {
    return low_level.i_mapper_log2(call);
}
pub fn iMapperLog10(call: ?*ir_node) i32 {
    return low_level.i_mapper_log10(call);
}
pub fn iMapperSin(call: ?*ir_node) i32 {
    return low_level.i_mapper_sin(call);
}
pub fn iMapperCos(call: ?*ir_node) i32 {
    return low_level.i_mapper_cos(call);
}
pub fn iMapperTan(call: ?*ir_node) i32 {
    return low_level.i_mapper_tan(call);
}
pub fn iMapperAsin(call: ?*ir_node) i32 {
    return low_level.i_mapper_asin(call);
}
pub fn iMapperAcos(call: ?*ir_node) i32 {
    return low_level.i_mapper_acos(call);
}
pub fn iMapperAtan(call: ?*ir_node) i32 {
    return low_level.i_mapper_atan(call);
}
pub fn iMapperSinh(call: ?*ir_node) i32 {
    return low_level.i_mapper_sinh(call);
}
pub fn iMapperCosh(call: ?*ir_node) i32 {
    return low_level.i_mapper_cosh(call);
}
pub fn iMapperTanh(call: ?*ir_node) i32 {
    return low_level.i_mapper_tanh(call);
}
pub fn iMapperStrcmp(call: ?*ir_node) i32 {
    return low_level.i_mapper_strcmp(call);
}
pub fn iMapperStrncmp(call: ?*ir_node) i32 {
    return low_level.i_mapper_strncmp(call);
}
pub fn iMapperStrcpy(call: ?*ir_node) i32 {
    return low_level.i_mapper_strcpy(call);
}
pub fn iMapperStrlen(call: ?*ir_node) i32 {
    return low_level.i_mapper_strlen(call);
}
pub fn iMapperMemcpy(call: ?*ir_node) i32 {
    return low_level.i_mapper_memcpy(call);
}
pub fn iMapperMemmove(call: ?*ir_node) i32 {
    return low_level.i_mapper_memmove(call);
}
pub fn iMapperMemset(call: ?*ir_node) i32 {
    return low_level.i_mapper_memset(call);
}
pub fn iMapperMemcmp(call: ?*ir_node) i32 {
    return low_level.i_mapper_memcmp(call);
}
pub fn irTargetSet(target_triple: [*]const u8) i32 {
    return low_level.ir_target_set(target_triple);
}
pub fn irTargetSetTriple(machine: ?*const ir_machine_triple_t) i32 {
    return low_level.ir_target_set_triple(machine);
}
pub fn irTargetOption(option: [*]const u8) i32 {
    return low_level.ir_target_option(option);
}
pub fn irTargetInit() void {
    return low_level.ir_target_init();
}
pub fn irTargetExperimental() [*]const u8 {
    return low_level.ir_target_experimental();
}
pub fn irTargetBigEndian() i32 {
    return low_level.ir_target_big_endian();
}
pub fn irTargetBiggestAlignment() u32 {
    return low_level.ir_target_biggest_alignment();
}
pub fn irTargetPointerSize() u32 {
    return low_level.ir_target_pointer_size();
}
pub fn irTargetSupportsPic() i32 {
    return low_level.ir_target_supports_pic();
}
pub fn irTargetFastUnalignedMemaccess() i32 {
    return low_level.ir_target_fast_unaligned_memaccess();
}
pub fn irTargetFloatArithmeticMode() ?*ir_mode {
    return low_level.ir_target_float_arithmetic_mode();
}
pub fn irTargetFloatIntOverflowStyle() float_int_conversion_overflow_style_t {
    return @intToEnum(float_int_conversion_overflow_style_t, low_level.ir_target_float_int_overflow_style());
}
pub fn irPlatformLongLongAndDoubleStructAlignOverride() u32 {
    return low_level.ir_platform_long_long_and_double_struct_align_override();
}
pub fn irPlatformPicIsDefault() i32 {
    return low_level.ir_platform_pic_is_default();
}
pub fn irPlatformSupportsThreadLocalStorage() i32 {
    return low_level.ir_platform_supports_thread_local_storage();
}
pub fn irPlatformDefineValue(define: ?*const ir_platform_define_t) [*]const u8 {
    return low_level.ir_platform_define_value(define);
}
pub fn irPlatformWcharType() ir_platform_type_t {
    return @intToEnum(ir_platform_type_t, low_level.ir_platform_wchar_type());
}
pub fn irPlatformWcharIsSigned() i32 {
    return low_level.ir_platform_wchar_is_signed();
}
pub fn irPlatformIntptrType() ir_platform_type_t {
    return @intToEnum(ir_platform_type_t, low_level.ir_platform_intptr_type());
}
pub fn irPlatformTypeSize(@"type": u32) u32 {
    return low_level.ir_platform_type_size(@"type");
}
pub fn irPlatformTypeAlign(@"type": u32) u32 {
    return low_level.ir_platform_type_align(@"type");
}
pub fn irPlatformTypeMode(@"type": u32, is_signed: i32) ?*ir_mode {
    return low_level.ir_platform_type_mode(@"type", is_signed);
}
pub fn irPlatformVaListType() ?*ir_type {
    return low_level.ir_platform_va_list_type();
}
pub fn irPlatformUserLabelPrefix() [*]const u8 {
    return low_level.ir_platform_user_label_prefix();
}
pub fn irPlatformDefaultExeName() [*]const u8 {
    return low_level.ir_platform_default_exe_name();
}
pub fn irPlatformMangleGlobal(name: [*]const u8) [*]const u8 {
    return low_level.ir_platform_mangle_global(name);
}
pub fn irPlatformDefineFirst() ir_platform_define_t {
    return low_level.ir_platform_define_first();
}
pub fn irPlatformDefineNext(define: ?*const ir_platform_define_t) ir_platform_define_t {
    return low_level.ir_platform_define_next(define);
}
pub fn irPlatformDefineName(define: ?*const ir_platform_define_t) [*]const u8 {
    return low_level.ir_platform_define_name(define);
}
pub fn irParseMachineTriple(triple_string: [*]const u8) ?*ir_machine_triple_t {
    return low_level.ir_parse_machine_triple(triple_string);
}
pub fn irGetHostMachineTriple() ?*ir_machine_triple_t {
    return low_level.ir_get_host_machine_triple();
}
pub fn irTripleGetCpuType(triple: ?*const ir_machine_triple_t) [*]const u8 {
    return low_level.ir_triple_get_cpu_type(triple);
}
pub fn irTripleGetManufacturer(triple: ?*const ir_machine_triple_t) [*]const u8 {
    return low_level.ir_triple_get_manufacturer(triple);
}
pub fn irTripleGetOperatingSystem(triple: ?*const ir_machine_triple_t) [*]const u8 {
    return low_level.ir_triple_get_operating_system(triple);
}
pub fn irTripleSetCpuType(triple: ?*ir_machine_triple_t, cpu_type: [*]const u8) void {
    return low_level.ir_triple_set_cpu_type(triple, cpu_type);
}
pub fn irFreeMachineTriple(triple: ?*ir_machine_triple_t) void {
    return low_level.ir_free_machine_triple(triple);
}
pub fn irTimerEnterHighPriority() i32 {
    return low_level.ir_timer_enter_high_priority();
}
pub fn irTimerLeaveHighPriority() i32 {
    return low_level.ir_timer_leave_high_priority();
}
pub fn irTimerNew() ?*ir_timer_t {
    return low_level.ir_timer_new();
}
pub fn irTimerFree(timer: ?*ir_timer_t) void {
    return low_level.ir_timer_free(timer);
}
pub fn irTimerStart(timer: ?*ir_timer_t) void {
    return low_level.ir_timer_start(timer);
}
pub fn irTimerResetAndStart(timer: ?*ir_timer_t) void {
    return low_level.ir_timer_reset_and_start(timer);
}
pub fn irTimerReset(timer: ?*ir_timer_t) void {
    return low_level.ir_timer_reset(timer);
}
pub fn irTimerStop(timer: ?*ir_timer_t) void {
    return low_level.ir_timer_stop(timer);
}
pub fn irTimerInitParent(timer: ?*ir_timer_t) void {
    return low_level.ir_timer_init_parent(timer);
}
pub fn irTimerPush(timer: ?*ir_timer_t) void {
    return low_level.ir_timer_push(timer);
}
pub fn irTimerPop(timer: ?*ir_timer_t) void {
    return low_level.ir_timer_pop(timer);
}
pub fn irTimerElapsedMsec(timer: ?*const ir_timer_t) u64 {
    return low_level.ir_timer_elapsed_msec(timer);
}
pub fn irTimerElapsedUsec(timer: ?*const ir_timer_t) u64 {
    return low_level.ir_timer_elapsed_usec(timer);
}
pub fn irTimerElapsedSec(timer: ?*const ir_timer_t) f64 {
    return low_level.ir_timer_elapsed_sec(timer);
}
pub fn newTarvalFromStr(str: [*]const u8, len: usize, mode: ?*ir_mode) ?*ir_tarval {
    return low_level.new_tarval_from_str(str, len, mode);
}
pub fn newIntegerTarvalFromStr(str: [*]const u8, len: usize, negative: i32, base: u8, mode: ?*ir_mode) ?*ir_tarval {
    return low_level.new_integer_tarval_from_str(str, len, negative, base, mode);
}
pub fn newTarvalFromLong(l: i64, mode: ?*ir_mode) ?*ir_tarval {
    return low_level.new_tarval_from_long(l, mode);
}
pub fn newTarvalFromBytes(buf: [*]const u8, mode: ?*ir_mode) ?*ir_tarval {
    return low_level.new_tarval_from_bytes(buf, mode);
}
pub fn newTarvalNan(mode: ?*ir_mode, signaling: i32, payload: ?*const ir_tarval) ?*ir_tarval {
    return low_level.new_tarval_nan(mode, signaling, payload);
}
pub fn tarvalToBytes(buffer: [*]u8, tv: ?*const ir_tarval) void {
    return low_level.tarval_to_bytes(buffer, tv);
}
pub fn getTarvalLong(tv: ?*const ir_tarval) i64 {
    return low_level.get_tarval_long(tv);
}
pub fn tarvalIsLong(tv: ?*const ir_tarval) i32 {
    return low_level.tarval_is_long(tv);
}
pub fn newTarvalFromDouble(d: f64, mode: ?*ir_mode) ?*ir_tarval {
    return low_level.new_tarval_from_double(d, mode);
}
pub fn newTarvalFromLongDouble(d: f64, mode: ?*ir_mode) ?*ir_tarval {
    return low_level.new_tarval_from_long_double(d, mode);
}
pub fn getTarvalDouble(tv: ?*const ir_tarval) f64 {
    return low_level.get_tarval_double(tv);
}
pub fn getTarvalLongDouble(tv: ?*const ir_tarval) f64 {
    return low_level.get_tarval_long_double(tv);
}
pub fn tarvalIsDouble(tv: ?*const ir_tarval) i32 {
    return low_level.tarval_is_double(tv);
}
pub fn getTarvalMode(tv: ?*const ir_tarval) ?*ir_mode {
    return low_level.get_tarval_mode(tv);
}
pub fn tarvalIsNegative(tv: ?*const ir_tarval) i32 {
    return low_level.tarval_is_negative(tv);
}
pub fn tarvalIsNull(tv: ?*const ir_tarval) i32 {
    return low_level.tarval_is_null(tv);
}
pub fn tarvalIsOne(tv: ?*const ir_tarval) i32 {
    return low_level.tarval_is_one(tv);
}
pub fn tarvalIsAllOne(tv: ?*const ir_tarval) i32 {
    return low_level.tarval_is_all_one(tv);
}
pub fn tarvalIsConstant(tv: ?*const ir_tarval) i32 {
    return low_level.tarval_is_constant(tv);
}
pub fn getTarvalBad() ?*ir_tarval {
    return low_level.get_tarval_bad();
}
pub fn getTarvalUnknown() ?*ir_tarval {
    return low_level.get_tarval_unknown();
}
pub fn getTarvalBFalse() ?*ir_tarval {
    return low_level.get_tarval_b_false();
}
pub fn getTarvalBTrue() ?*ir_tarval {
    return low_level.get_tarval_b_true();
}
pub fn tarvalSetWrapOnOverflow(wrap_on_overflow: i32) void {
    return low_level.tarval_set_wrap_on_overflow(wrap_on_overflow);
}
pub fn tarvalGetWrapOnOverflow() i32 {
    return low_level.tarval_get_wrap_on_overflow();
}
pub fn tarvalCmp(a: ?*const ir_tarval, b: ?*const ir_tarval) ir_relation {
    return @intToEnum(ir_relation, low_level.tarval_cmp(a, b));
}
pub fn tarvalConvertTo(src: ?*const ir_tarval, mode: ?*ir_mode) ?*ir_tarval {
    return low_level.tarval_convert_to(src, mode);
}
pub fn tarvalBitcast(src: ?*const ir_tarval, mode: ?*ir_mode) ?*ir_tarval {
    return low_level.tarval_bitcast(src, mode);
}
pub fn tarvalNot(a: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_not(a);
}
pub fn tarvalNeg(a: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_neg(a);
}
pub fn tarvalAdd(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_add(a, b);
}
pub fn tarvalSub(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_sub(a, b);
}
pub fn tarvalMul(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_mul(a, b);
}
pub fn tarvalDiv(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_div(a, b);
}
pub fn tarvalMod(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_mod(a, b);
}
pub fn tarvalDivmod(a: ?*const ir_tarval, b: ?*const ir_tarval, mod_res: [*]?*ir_tarval) ?*ir_tarval {
    return low_level.tarval_divmod(a, b, mod_res);
}
pub fn tarvalAbs(a: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_abs(a);
}
pub fn tarvalAnd(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_and(a, b);
}
pub fn tarvalAndnot(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_andnot(a, b);
}
pub fn tarvalOr(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_or(a, b);
}
pub fn tarvalOrnot(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_ornot(a, b);
}
pub fn tarvalEor(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_eor(a, b);
}
pub fn tarvalShl(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_shl(a, b);
}
pub fn tarvalShlUnsigned(a: ?*const ir_tarval, b: u32) ?*ir_tarval {
    return low_level.tarval_shl_unsigned(a, b);
}
pub fn tarvalShr(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_shr(a, b);
}
pub fn tarvalShrUnsigned(a: ?*const ir_tarval, b: u32) ?*ir_tarval {
    return low_level.tarval_shr_unsigned(a, b);
}
pub fn tarvalShrs(a: ?*const ir_tarval, b: ?*const ir_tarval) ?*ir_tarval {
    return low_level.tarval_shrs(a, b);
}
pub fn tarvalShrsUnsigned(a: ?*const ir_tarval, b: u32) ?*ir_tarval {
    return low_level.tarval_shrs_unsigned(a, b);
}
pub fn getTarvalSubBits(tv: ?*const ir_tarval, byte_ofs: u32) [*]const u8 {
    return low_level.get_tarval_sub_bits(tv, byte_ofs);
}
pub fn getTarvalPopcount(tv: ?*const ir_tarval) i32 {
    return low_level.get_tarval_popcount(tv);
}
pub fn getTarvalLowestBit(tv: ?*const ir_tarval) i32 {
    return low_level.get_tarval_lowest_bit(tv);
}
pub fn getTarvalHighestBit(tv: ?*const ir_tarval) i32 {
    return low_level.get_tarval_highest_bit(tv);
}
pub fn tarvalZeroMantissa(tv: ?*const ir_tarval) i32 {
    return low_level.tarval_zero_mantissa(tv);
}
pub fn tarvalGetExponent(tv: ?*const ir_tarval) i32 {
    return low_level.tarval_get_exponent(tv);
}
pub fn tarvalIeee754CanConvLossless(tv: ?*const ir_tarval, mode: ?*const ir_mode) i32 {
    return low_level.tarval_ieee754_can_conv_lossless(tv, mode);
}
pub fn tarvalIeee754GetExact() u32 {
    return low_level.tarval_ieee754_get_exact();
}
pub fn tarvalIsNan(tv: ?*const ir_tarval) i32 {
    return low_level.tarval_is_nan(tv);
}
pub fn tarvalIsQuietNan(tv: ?*const ir_tarval) i32 {
    return low_level.tarval_is_quiet_nan(tv);
}
pub fn tarvalIsSignalingNan(tv: ?*const ir_tarval) i32 {
    return low_level.tarval_is_signaling_nan(tv);
}
pub fn tarvalIsFinite(tv: ?*const ir_tarval) i32 {
    return low_level.tarval_is_finite(tv);
}
pub fn setVrpData(irg: ?*ir_graph) void {
    return low_level.set_vrp_data(irg);
}
pub fn freeVrpData(irg: ?*ir_graph) void {
    return low_level.free_vrp_data(irg);
}
pub fn vrpCmp(left: ?*const ir_node, right: ?*const ir_node) ir_relation {
    return @intToEnum(ir_relation, low_level.vrp_cmp(left, right));
}
pub fn vrpGetInfo(n: ?*const ir_node) [*]vrp_attr {
    return low_level.vrp_get_info(n);
}
