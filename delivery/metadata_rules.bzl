"""Explicit provenance for extension artifacts; never infer clean source."""

def _extension_metadata(ctx):
    # A metadata request is an explicit provenance assertion by its operator.
    # Keep unstamped normal builds usable without manufacturing a commit.
    commit = ctx.var.get("OMUX_SOURCE_COMMIT", "")
    dirty = ctx.var.get("OMUX_SOURCE_DIRTY", "")
    if not commit or dirty not in ["true", "false"]:
        fail("Extension metadata requires --define=OMUX_SOURCE_COMMIT=<full commit> and --define=OMUX_SOURCE_DIRTY=true|false")
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    args = ctx.actions.args()
    args.add(ctx.file._script)
    args.add("--archive", ctx.file.archive)
    args.add("--channel", ctx.attr.channel)
    args.add("--source-commit", commit)
    args.add("--source-dirty", dirty)
    args.add("--out", output)
    ctx.actions.run(
        executable = ctx.executable._python,
        arguments = [args],
        inputs = depset([ctx.file.archive, ctx.file._script]),
        tools = [ctx.attr._python[DefaultInfo].files_to_run] + ctx.attr._all_tools[DefaultInfo].files.to_list(),
        outputs = [output],
        mnemonic = "OmuxExtensionMetadata",
        use_default_shell_env = False,
        env = {"PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return [DefaultInfo(files = depset([output]))]

extension_metadata = rule(
    implementation = _extension_metadata,
    attrs = {
        "archive": attr.label(allow_single_file = True, mandatory = True),
        "channel": attr.string(values = ["release", "development"], mandatory = True),
        "_script": attr.label(default = "//delivery:extension_metadata.py", allow_single_file = True),
        "_python": attr.label(default = "@omux_nix//:python", executable = True, cfg = "exec"),
        "_all_tools": attr.label(default = "@omux_nix//:all_tools", cfg = "exec"),
    },
)
