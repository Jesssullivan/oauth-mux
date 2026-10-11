"""Channel archives use only declared identity, source and pinned tool inputs."""

load("//tools:native_tool_info.bzl", "OmuxNixToolInfo")

def _channel_archive(ctx):
    if ctx.attr.browser == "chromium" and not ctx.file.public_key:
        fail("Chromium channel archives require a public identity key")
    if ctx.attr.browser == "firefox" and (ctx.file.public_key or ctx.attr.output_suffix != ".xpi"):
        fail("Firefox channel archives require .xpi output and no Chromium identity key")
    output = ctx.actions.declare_file(ctx.label.name + ctx.attr.output_suffix)
    args = ctx.actions.args()
    args.add(ctx.file._script)
    args.add("--manifest", ctx.file.browser_manifest)
    args.add("--browser", ctx.attr.browser)
    if ctx.file.public_key:
        args.add("--public-key", ctx.file.public_key)
    args.add("--channel", ctx.attr.channel)
    args.add("--out", output)
    for source in ctx.files.srcs:
        args.add("--source", source)
    ctx.actions.run(
        executable = ctx.executable._python,
        arguments = [args],
        inputs = depset(ctx.files.srcs + [ctx.file.browser_manifest, ctx.file._script] + ([ctx.file.public_key] if ctx.file.public_key else [])),
        tools = [ctx.attr._python[DefaultInfo].files_to_run] + ctx.attr._all_tools[DefaultInfo].files.to_list(),
        outputs = [output],
        mnemonic = "OmuxChannelArchive",
        use_default_shell_env = False,
        env = {"PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return [DefaultInfo(files = depset([output]))]

channel_archive = rule(
    implementation = _channel_archive,
    attrs = {
        "browser_manifest": attr.label(allow_single_file = True, mandatory = True),
        "public_key": attr.label(allow_single_file = True),
        "browser": attr.string(default = "chromium", values = ["chromium", "firefox"]),
        "output_suffix": attr.string(default = ".zip", values = [".zip", ".xpi"]),
        "srcs": attr.label_list(allow_files = True),
        "channel": attr.string(values = ["release", "development"], mandatory = True),
        "_script": attr.label(default = "//extensions:channel.py", allow_single_file = True),
        "_python": attr.label(default = "@omux_nix//:python", executable = True, cfg = "exec"),
        "_all_tools": attr.label(default = "@omux_nix//:all_tools", cfg = "exec"),
    },
)

def _development_identity(ctx):
    output = ctx.actions.declare_file(ctx.label.name + ".public-key")
    args = ctx.actions.args()
    args.add(ctx.file._script)
    args.add("--openssl", ctx.attr._openssl[OmuxNixToolInfo].executable_path)
    args.add("--out", output)
    ctx.actions.run(
        executable = ctx.executable._python,
        arguments = [args],
        inputs = depset(
            [ctx.file._script],
            transitive = [ctx.attr._openssl[OmuxNixToolInfo].closure_files],
        ),
        tools = [ctx.attr._python[DefaultInfo].files_to_run] + ctx.attr._all_tools[DefaultInfo].files.to_list(),
        outputs = [output],
        mnemonic = "OmuxDevelopmentPublicIdentity",
        progress_message = "Generate public-only Omux development identity for explicit pinning",
        use_default_shell_env = False,
        env = {"PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"},
        execution_requirements = {
            "no-cache": "1",
            "no-remote": "1",
            "no-remote-cache": "1",
            "no-remote-exec": "1",
        },
    )
    return [DefaultInfo(files = depset([output]))]

development_identity = rule(
    implementation = _development_identity,
    attrs = {
        "_script": attr.label(default = "//extensions:development_identity.py", allow_single_file = True),
        "_python": attr.label(default = "@omux_nix//:python", executable = True, cfg = "exec"),
        "_openssl": attr.label(default = "@omux_nix//:openssl_tool", providers = [OmuxNixToolInfo], cfg = "exec"),
        "_all_tools": attr.label(default = "@omux_nix//:all_tools", cfg = "exec"),
    },
)
