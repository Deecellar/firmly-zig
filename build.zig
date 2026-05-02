const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const build_examples = b.option(bool, "build_examples", "Build the examples") orelse true;

    const libfirm_dep = b.dependency("libfirm", .{});
    const libfirm_path = libfirm_dep.path("");

    const libfirm_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .sanitize_c = .off,
    });

    const libfirm = b.addLibrary(.{
        .name = "firm",
        .root_module = libfirm_mod,
    });

    if (target.result.os.tag == .windows) {
        libfirm_mod.linkSystemLibrary("regex", .{});
        libfirm_mod.linkSystemLibrary("winmm", .{});
    }

    libfirm_mod.addCMacro("FIRM_BUILD", "1");
    libfirm_mod.addCMacro("FIRM_DLL", "1");

    const gen_step = b.addWriteFiles();
    const gen_dir = gen_step.getDirectory();

    const gen_ir_py = libfirm_dep.path("scripts/gen_ir.py");
    const ir_spec_py = libfirm_dep.path("scripts/ir_spec.py");
    const templates_dir = libfirm_dep.path("scripts/templates");

    const files_to_gen = .{
        .{ "include/libfirm/nodes.h", "nodes.h" },
        .{ "ir/ir/gen_irnode.h", "gen_irnode.h" },
        .{ "ir/ir/gen_proj_names.h", "gen_proj_names.h" },
        .{ "ir/ir/gen_irio.c", "gen_irio.c" },
        .{ "ir/ir/gen_irnode.c", "gen_irnode.c" },
    };

    inline for (files_to_gen) |file| {
        const run = b.addSystemCommand(&.{"python3"});
        run.addFileArg(gen_ir_py);
        run.addFileArg(ir_spec_py);
        run.addFileArg(templates_dir.path(b, file[1]));
        const out = run.captureStdOut(.{ .basename = file[1] });
        _ = gen_step.addCopyFile(out, file[0]);
    }

    libfirm_mod.addIncludePath(libfirm_dep.path("include"));
    libfirm_mod.addIncludePath(libfirm_dep.path("include/libfirm"));
    libfirm_mod.addIncludePath(libfirm_dep.path("include/libfirm/adt"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/adt"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/ana"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/be"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/common"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/ident"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/ir"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/kaps"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/libcore"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/lower"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/lpp"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/obstack"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/opt"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/stat"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/tr"));
    libfirm_mod.addIncludePath(libfirm_dep.path("ir/tv"));

    libfirm_mod.addIncludePath(gen_dir.path(b, "include"));
    libfirm_mod.addIncludePath(gen_dir.path(b, "include/libfirm"));
    libfirm_mod.addIncludePath(gen_dir.path(b, "ir/ir"));

    const common_sources = &.{
        "ir/adt/array.c",
        "ir/adt/bipartite.c",
        "ir/adt/bitset.c",
        "ir/adt/cpset.c",
        "ir/adt/deq.c",
        "ir/adt/gaussjordan.c",
        "ir/adt/gaussseidel.c",
        "ir/adt/hungarian.c",
        "ir/adt/pmap.c",
        "ir/adt/pqueue.c",
        "ir/adt/pset.c",
        "ir/adt/pset_new.c",
        "ir/adt/set.c",
        "ir/adt/xmalloc.c",
        "ir/ana/analyze_irg_args.c",
        "ir/ana/callgraph.c",
        "ir/ana/cdep.c",
        "ir/ana/cgana.c",
        "ir/ana/constbits.c",
        "ir/ana/dca.c",
        "ir/ana/dfs.c",
        "ir/ana/domfront.c",
        "ir/ana/execfreq.c",
        "ir/ana/heights.c",
        "ir/ana/irbackedge.c",
        "ir/ana/ircfscc.c",
        "ir/ana/irconsconfirm.c",
        "ir/ana/irdom.c",
        "ir/ana/irlivechk.c",
        "ir/ana/irloop.c",
        "ir/ana/irmemory.c",
        "ir/ana/irouts.c",
        "ir/ana/vrp.c",
        "ir/be/be2addr.c",
        "ir/be/bearch.c",
        "ir/be/beasm.c",
        "ir/be/beblocksched.c",
        "ir/be/bechordal.c",
        "ir/be/bechordal_common.c",
        "ir/be/bechordal_main.c",
        "ir/be/becopyheur4.c",
        "ir/be/becopyilp.c",
        "ir/be/becopyilp2.c",
        "ir/be/becopyopt.c",
        "ir/be/bediagnostic.c",
        "ir/be/bedump.c",
        "ir/be/bedwarf.c",
        "ir/be/beemithlp.c",
        "ir/be/beemitter.c",
        "ir/be/beflags.c",
        "ir/be/begnuas.c",
        "ir/be/beifg.c",
        "ir/be/beinfo.c",
        "ir/be/beinsn.c",
        "ir/be/beirg.c",
        "ir/be/bejit.c",
        "ir/be/belistsched.c",
        "ir/be/belive.c",
        "ir/be/beloopana.c",
        "ir/be/belower.c",
        "ir/be/bemain.c",
        "ir/be/bemodule.c",
        "ir/be/benode.c",
        "ir/be/bepbqpcoloring.c",
        "ir/be/bepeephole.c",
        "ir/be/beprefalloc.c",
        "ir/be/bera.c",
        "ir/be/besched.c",
        "ir/be/beschednormal.c",
        "ir/be/beschedrand.c",
        "ir/be/beschedtrivial.c",
        "ir/be/bespill.c",
        "ir/be/bespillbelady.c",
        "ir/be/bespilldaemel.c",
        "ir/be/bespillslots.c",
        "ir/be/bespillutil.c",
        "ir/be/bessaconstr.c",
        "ir/be/bessadestr.c",
        "ir/be/bestack.c",
        "ir/be/bestat.c",
        "ir/be/bestate.c",
        "ir/be/betranshlp.c",
        "ir/be/beuses.c",
        "ir/be/beutil.c",
        "ir/be/bevarargs.c",
        "ir/be/beverify.c",
        "ir/be/target.c",
        "ir/be/machine_triple.c",
        "ir/be/platform.c",
        "ir/common/debug.c",
        "ir/common/debugger.c",
        "ir/common/firm.c",
        "ir/common/firm_common.c",
        "ir/common/panic.c",
        "ir/common/timing.c",
        "ir/ident/ident.c",
        "ir/ir/dbginfo.c",
        "ir/ir/irarch.c",
        "ir/ir/irargs.c",
        "ir/ir/ircons.c",
        "ir/ir/irdump.c",
        "ir/ir/irdumptxt.c",
        "ir/ir/iredges.c",
        "ir/ir/irflag.c",
        "ir/ir/irgmod.c",
        "ir/ir/irgraph.c",
        "ir/ir/irgwalk.c",
        "ir/ir/irgwalk_blk.c",
        "ir/ir/irhooks.c",
        "ir/ir/irio.c",
        "ir/ir/irmode.c",
        "ir/ir/irnode.c",
        "ir/ir/irnodehashmap.c",
        "ir/ir/irnodeset.c",
        "ir/ir/irop.c",
        "ir/ir/irprintf.c",
        "ir/ir/irprofile.c",
        "ir/ir/irprog.c",
        "ir/ir/irssacons.c",
        "ir/ir/irtools.c",
        "ir/ir/irverify.c",
        "ir/ir/valueset.c",
        "ir/kaps/brute_force.c",
        "ir/kaps/bucket.c",
        "ir/kaps/heuristical.c",
        "ir/kaps/heuristical_co.c",
        "ir/kaps/heuristical_co_ld.c",
        "ir/kaps/html_dumper.c",
        "ir/kaps/kaps.c",
        "ir/kaps/matrix.c",
        "ir/kaps/optimal.c",
        "ir/kaps/pbqp_edge.c",
        "ir/kaps/pbqp_node.c",
        "ir/kaps/vector.c",
        "ir/libcore/lc_appendable.c",
        "ir/libcore/lc_opts.c",
        "ir/libcore/lc_opts_enum.c",
        "ir/libcore/lc_printf.c",
        "ir/lower/lower_alloc.c",
        "ir/lower/lower_builtins.c",
        "ir/lower/lower_calls.c",
        "ir/lower/lower_copyb.c",
        "ir/lower/lower_dw.c",
        "ir/lower/lower_hl.c",
        "ir/lower/lower_intrinsics.c",
        "ir/lower/lower_mode_b.c",
        "ir/lower/lower_mux.c",
        "ir/lower/lower_softfloat.c",
        "ir/lower/lower_switch.c",
        "ir/lpp/lpp.c",
        "ir/lpp/lpp_cplex.c",
        "ir/lpp/lpp_gurobi.c",
        "ir/lpp/lpp_solvers.c",
        "ir/lpp/mps.c",
        "ir/lpp/sp_matrix.c",
        "ir/obstack/obstack.c",
        "ir/obstack/obstack_printf.c",
        "ir/opt/boolopt.c",
        "ir/opt/cfopt.c",
        "ir/opt/code_placement.c",
        "ir/opt/combo.c",
        "ir/opt/convopt.c",
        "ir/opt/critical_edges.c",
        "ir/opt/dead_code_elimination.c",
        "ir/opt/funccall.c",
        "ir/opt/garbage_collect.c",
        "ir/opt/gvn_pre.c",
        "ir/opt/ifconv.c",
        "ir/opt/instrument.c",
        "ir/opt/ircgopt.c",
        "ir/opt/ircomplib.c",
        "ir/opt/irgopt.c",
        "ir/opt/iropt.c",
        "ir/opt/jumpthreading.c",
        "ir/opt/ldstopt.c",
        "ir/opt/loop.c",
        "ir/opt/lcssa.c",
        "ir/opt/loop_unrolling.c",
        "ir/opt/occult_const.c",
        "ir/opt/opt_blocks.c",
        "ir/opt/opt_confirms.c",
        "ir/opt/opt_frame.c",
        "ir/opt/opt_inline.c",
        "ir/opt/opt_ldst.c",
        "ir/opt/opt_osr.c",
        "ir/opt/parallelize_mem.c",
        "ir/opt/proc_cloning.c",
        "ir/opt/reassoc.c",
        "ir/opt/return.c",
        "ir/opt/rm_bads.c",
        "ir/opt/rm_tuples.c",
        "ir/opt/scalar_replace.c",
        "ir/opt/tailrec.c",
        "ir/opt/unreachable.c",
        "ir/stat/stat_timing.c",
        "ir/stat/statev.c",
        "ir/tr/entity.c",
        "ir/tr/tr_inheritance.c",
        "ir/tr/trverify.c",
        "ir/tr/type.c",
        "ir/tr/typewalk.c",
        "ir/tv/fltcalc.c",
        "ir/tv/strcalc.c",
        "ir/tv/tv.c",
    };

    libfirm_mod.addCSourceFiles(.{
        .root = libfirm_path,
        .files = common_sources,
        .flags = &.{"-std=c99"},
    });

    libfirm_mod.addCSourceFiles(.{
        .root = gen_dir,
        .files = &.{
            "ir/ir/gen_irio.c",
            "ir/ir/gen_irnode.c",
        },
        .flags = &.{"-std=c99"},
    });

    const backends = &[_][]const u8{ "ia32", "arm", "sparc", "amd64", "mips", "riscv", "TEMPLATE" };
    for (backends) |be| {
        addBackend(b, libfirm_mod, libfirm_dep, be);
    }

    const firmly_zig_mod = b.addModule("firmly-zig", .{
        .root_source_file = b.path("firmly-zig.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    firmly_zig_mod.linkLibrary(libfirm);

    const lib = b.addLibrary(.{
        .name = "firmly-zig",
        .root_module = firmly_zig_mod,
    });
    b.installArtifact(lib);

    if (build_examples) {
        const bf_example = b.addExecutable(.{
            .name = "firmly-zig-brainfuck",
            .root_module = b.createModule(.{
                .root_source_file = b.path("example/bf_example.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        bf_example.root_module.addImport("firmly-zig", firmly_zig_mod);
        b.installArtifact(bf_example);

        const bf_gen = b.addRunArtifact(bf_example);
        bf_gen.addFileArg(b.path("example/test.bf"));
        const bf_s = bf_gen.addOutputFileArg("test.s");

        const bf_runtime = b.addExecutable(.{
            .name = "hello-bf",
            .root_module = b.createModule(.{
                .root_source_file = b.path("example/bf_runtime.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        bf_runtime.root_module.addObjectFile(bf_s);
        b.installArtifact(bf_runtime);

        const run_bf = b.addRunArtifact(bf_runtime);
        const run_step = b.step("run-bf", "Run the brainfuck hello world example");
        run_step.dependOn(&run_bf.step);
    }

    const main_tests = b.addTest(.{
        .name = "firmly-zig-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("firmly-zig.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    main_tests.root_module.linkLibrary(libfirm);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}

fn addBackend(b: *std.Build, libfirm_mod: *std.Build.Module, libfirm_dep: *std.Build.Dependency, name: []const u8) void {
    const libfirm_path = libfirm_dep.path("");

    const backend_dir = b.fmt("ir/be/{s}", .{name});
    libfirm_mod.addIncludePath(libfirm_dep.path(backend_dir));

    if (std.mem.eql(u8, name, "amd64") or std.mem.eql(u8, name, "ia32")) {
        libfirm_mod.addIncludePath(libfirm_dep.path("ir/be/ia32"));
    }

    const be_scripts = libfirm_dep.path("ir/be/scripts");
    const spec = libfirm_dep.path(b.fmt("ir/be/{s}/{s}_spec.pl", .{ name, name }));

    const generators = &[_][]const u8{
        "generate_emitter.pl",
        "generate_regalloc_if.pl",
        "generate_new_opcodes.pl",
    };

    for (generators) |gen_script| {
        const run = b.addSystemCommand(&.{"perl"});
        run.addFileArg(be_scripts.path(b, gen_script));
        run.addFileArg(spec);
        const out_dir = run.addOutputDirectoryArg("be_gen");
        libfirm_mod.addIncludePath(out_dir);

        const gen_c_name = if (std.mem.eql(u8, gen_script, "generate_emitter.pl"))
            b.fmt("gen_{s}_emitter.c", .{name})
        else if (std.mem.eql(u8, gen_script, "generate_regalloc_if.pl"))
            b.fmt("gen_{s}_regalloc_if.c", .{name})
        else
            b.fmt("gen_{s}_new_nodes.c", .{name});

        libfirm_mod.addCSourceFiles(.{
            .root = out_dir,
            .files = &.{gen_c_name},
            .flags = &.{"-std=c99"},
        });
    }

    if (std.mem.eql(u8, name, "ia32")) {
        libfirm_mod.addCSourceFiles(.{
            .root = libfirm_path,
            .files = &.{
                "ir/be/ia32/ia32_architecture.c",
                "ir/be/ia32/ia32_bearch.c",
                "ir/be/ia32/ia32_cconv.c",
                "ir/be/ia32/ia32_emitter.c",
                "ir/be/ia32/ia32_encode.c",
                "ir/be/ia32/ia32_finish.c",
                "ir/be/ia32/ia32_fpu.c",
                "ir/be/ia32/ia32_intrinsics.c",
                "ir/be/ia32/ia32_new_nodes.c",
                "ir/be/ia32/ia32_optimize.c",
                "ir/be/ia32/ia32_pic.c",
                "ir/be/ia32/ia32_transform.c",
                "ir/be/ia32/x86_address_mode.c",
                "ir/be/ia32/x86_architecture.c",
                "ir/be/ia32/x86_asm.c",
                "ir/be/ia32/x86_cconv.c",
                "ir/be/ia32/x86_node.c",
                "ir/be/ia32/x86_x87.c",
            },
            .flags = &.{"-std=c99"},
        });
    } else if (std.mem.eql(u8, name, "arm")) {
        libfirm_mod.addCSourceFiles(.{
            .root = libfirm_path,
            .files = &.{
                "ir/be/arm/arm_bearch.c",
                "ir/be/arm/arm_cconv.c",
                "ir/be/arm/arm_emitter.c",
                "ir/be/arm/arm_finish.c",
                "ir/be/arm/arm_lower64.c",
                "ir/be/arm/arm_new_nodes.c",
                "ir/be/arm/arm_optimize.c",
                "ir/be/arm/arm_transform.c",
            },
            .flags = &.{"-std=c99"},
        });
    } else if (std.mem.eql(u8, name, "sparc")) {
        libfirm_mod.addCSourceFiles(.{
            .root = libfirm_path,
            .files = &.{
                "ir/be/sparc/sparc_bearch.c",
                "ir/be/sparc/sparc_cconv.c",
                "ir/be/sparc/sparc_emitter.c",
                "ir/be/sparc/sparc_finish.c",
                "ir/be/sparc/sparc_lower64.c",
                "ir/be/sparc/sparc_new_nodes.c",
                "ir/be/sparc/sparc_stackframe.c",
                "ir/be/sparc/sparc_transform.c",
            },
            .flags = &.{"-std=c99"},
        });
    } else if (std.mem.eql(u8, name, "amd64")) {
        libfirm_mod.addCSourceFiles(.{
            .root = libfirm_path,
            .files = &.{
                "ir/be/amd64/amd64_architecture.c",
                "ir/be/amd64/amd64_bearch.c",
                "ir/be/amd64/amd64_cconv.c",
                "ir/be/amd64/amd64_emitter.c",
                "ir/be/amd64/amd64_finish.c",
                "ir/be/amd64/amd64_new_nodes.c",
                "ir/be/amd64/amd64_optimize.c",
                "ir/be/amd64/amd64_pic.c",
                "ir/be/amd64/amd64_transform.c",
                "ir/be/amd64/amd64_varargs.c",
                "ir/be/amd64/amd64_x87.c",
                "ir/be/amd64/amd64_abi.c",
            },
            .flags = &.{"-std=c99"},
        });
    } else if (std.mem.eql(u8, name, "mips")) {
        libfirm_mod.addCSourceFiles(.{
            .root = libfirm_path,
            .files = &.{
                "ir/be/mips/mips_bearch.c",
                "ir/be/mips/mips_cconv.c",
                "ir/be/mips/mips_emitter.c",
                "ir/be/mips/mips_lower64.c",
                "ir/be/mips/mips_new_nodes.c",
                "ir/be/mips/mips_nodes_attr.c",
                "ir/be/mips/mips_transform.c",
            },
            .flags = &.{"-std=c99"},
        });
    } else if (std.mem.eql(u8, name, "riscv")) {
        libfirm_mod.addCSourceFiles(.{
            .root = libfirm_path,
            .files = &.{
                "ir/be/riscv/riscv_abi.c",
                "ir/be/riscv/riscv_bearch.c",
                "ir/be/riscv/riscv_cconv.c",
                "ir/be/riscv/riscv_emitter.c",
                "ir/be/riscv/riscv_finish.c",
                "ir/be/riscv/riscv_lower64.c",
                "ir/be/riscv/riscv_new_nodes.c",
                "ir/be/riscv/riscv_nodes_attr.c",
                "ir/be/riscv/riscv_transform.c",
            },
            .flags = &.{"-std=c99"},
        });
    } else if (std.mem.eql(u8, name, "TEMPLATE")) {
        libfirm_mod.addCSourceFiles(.{
            .root = libfirm_path,
            .files = &.{
                "ir/be/TEMPLATE/TEMPLATE_bearch.c",
                "ir/be/TEMPLATE/TEMPLATE_emitter.c",
                "ir/be/TEMPLATE/TEMPLATE_new_nodes.c",
                "ir/be/TEMPLATE/TEMPLATE_transform.c",
            },
            .flags = &.{"-std=c99"},
        });
    }
}
