const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .strip = true,
    });

    mod.addCSourceFile(.{
        .file = b.path("hydrogen.c"),
    });

    const lib = b.addLibrary(.{
        .name = "hydrogen",
        .linkage = .static,
        .root_module = mod,
    });

    b.installArtifact(lib);

    _ = b.addModule("libhydrogen", .{
        .root_source_file = b.path("hydrogen.c"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const test_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addCSourceFile(.{
        .file = b.path("tests/tests.c"),
    });
    test_mod.addIncludePath(b.path("."));
    test_mod.linkLibrary(lib);

    const test_exe = b.addExecutable(.{
        .name = "hydrogen-tests",
        .root_module = test_mod,
    });

    const run_tests = b.addRunArtifact(test_exe);
    const test_step = b.step("test", "Run the test suite");
    test_step.dependOn(&run_tests.step);
}
