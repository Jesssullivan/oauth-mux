"""Give the freshly compiled runtime a distinct regular executable basename.

Both public entry points use src/main.zig. Omuxd dispatch depends on argv[0],
so an alias to a File still named omux is insufficient. No program is launched
by this action: the declared Python tool copies the target-platform image bytes.
"""

def _impl(ctx):
    output = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.run(
        executable = ctx.executable._python,
        arguments = ["-I", "-B", "-c",
            "import os,shutil,sys; shutil.copyfile(sys.argv[1],sys.argv[2]); os.chmod(sys.argv[2],0o755)",
            ctx.file.binary.path, output.path],
        inputs = depset([ctx.file.binary]),
        tools = [ctx.attr._python[DefaultInfo].files_to_run] + ctx.attr._all_tools[DefaultInfo].files.to_list(),
        outputs = [output],
        mnemonic = "OmuxRuntimeImageCopy",
        progress_message = "Naming the shared compiled runtime %s" % ctx.label,
        use_default_shell_env = False,
        env = {"PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    runfiles = ctx.runfiles(files = [output]).merge(ctx.attr.binary[DefaultInfo].default_runfiles)
    return [DefaultInfo(files = depset([output]), executable = output, runfiles = runfiles)]

runtime_image_copy = rule(
    implementation = _impl,
    executable = True,
    attrs = {
        # This is an artifact input, never a build-execution-platform program.
        "binary": attr.label(allow_single_file = True, executable = True, cfg = "target", mandatory = True),
        "_python": attr.label(default = "@omux_nix//:python", executable = True, cfg = "exec"),
        "_all_tools": attr.label(default = "@omux_nix//:python_tools", cfg = "exec"),
    },
)
