"""Join retained public qualification receipts with declared runtime inputs."""

def _implementation(ctx):
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    args = ctx.actions.args()
    args.add_all(["-I", "-B"])
    args.add(ctx.file._script)
    args.add("--inventory", ctx.file.inventory)
    args.add("--mapping", ctx.file.mapping)
    args.add("--mapping-sha256", ctx.attr.mapping_sha256)
    args.add("--nar", ctx.file.nar)
    args.add("--nar-sha256", ctx.attr.nar_sha256)
    args.add("--exclusions", ctx.file.exclusions)
    args.add("--declared-exclusions")
    args.add("--out", output)
    ctx.actions.run(
        executable = ctx.executable._python,
        arguments = [args],
        inputs = [ctx.file._script, ctx.file.inventory, ctx.file.mapping, ctx.file.nar, ctx.file.exclusions],
        tools = [ctx.attr._python[DefaultInfo].files_to_run] + ctx.attr._all_tools[DefaultInfo].files.to_list(),
        outputs = [output],
        mnemonic = "OmuxBrowserRuntimeAuthority",
        use_default_shell_env = False,
        env = {"PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return [DefaultInfo(files = depset([output]))]

browser_runtime_authority = rule(
    implementation = _implementation,
    attrs = {
        "inventory": attr.label(allow_single_file = True, mandatory = True),
        "mapping": attr.label(allow_single_file = True, mandatory = True),
        "mapping_sha256": attr.string(mandatory = True),
        "nar": attr.label(allow_single_file = True, mandatory = True),
        "nar_sha256": attr.string(mandatory = True),
        "exclusions": attr.label(allow_single_file = True, mandatory = True),
        "_script": attr.label(default = "//delivery:browser_runtime_authority.py", allow_single_file = True),
        "_python": attr.label(default = "@omux_nix//:python", executable = True, cfg = "exec"),
        "_all_tools": attr.label(default = "@omux_nix//:all_tools", cfg = "exec"),
    },
)
