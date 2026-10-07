"""Archive actions with declared binaries, channel and pinned interpreter."""

def _native_resolution(ctx):
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    args = ctx.actions.args()
    args.add(ctx.file._audit)
    args.add(ctx.file.control)
    args.add(ctx.file.plugin)
    args.add("--output", output)
    for candidate in ctx.files.runtime_files:
        if candidate.basename == "libsystemd.so.0":
            args.add("--variant", candidate)
    ctx.actions.run(
        executable = ctx.executable._python,
        arguments = [args],
        inputs = depset([ctx.file._audit, ctx.file._portable, ctx.file.control, ctx.file.plugin] +
                        ctx.files.runtime_files + ctx.files.plugin_files),
        tools = [ctx.attr._python[DefaultInfo].files_to_run, ctx.attr.control[DefaultInfo].files_to_run] +
                ctx.attr._all_tools[DefaultInfo].files.to_list(),
        outputs = [output],
        mnemonic = "OmuxNativeQtResolution",
        progress_message = "Auditing pinned native Qt startup library resolution",
        use_default_shell_env = False,
        env = {"PATH": "", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return [DefaultInfo(files = depset([output]))]

native_resolution = rule(
    implementation = _native_resolution,
    attrs = {
        "control": attr.label(allow_single_file = True, mandatory = True),
        "plugin": attr.label(allow_single_file = True, default = "@omux_nix//:qt_offscreen_plugin"),
        "runtime_files": attr.label(default = "@omux_nix//:qt_runtime_libraries"),
        "plugin_files": attr.label(default = "@omux_nix//:qt_platform_plugins"),
        "_audit": attr.label(default = "//delivery:runtime_audit.py", allow_single_file = True),
        "_portable": attr.label(default = "//delivery:portable.py", allow_single_file = True),
        "_python": attr.label(default = "@omux_nix//:python", executable = True, cfg = "exec"),
        "_all_tools": attr.label(default = "@omux_nix//:all_tools", cfg = "exec"),
    },
)

def _release_archive(ctx):
    development_revision = ctx.attr.development_source_revision
    if development_revision:
        if ctx.attr.channel != "development":
            fail("development_source_revision is exclusive to dirty development archives")
        if len(development_revision) not in [40, 64] or any([char not in "0123456789abcdef" for char in development_revision.elems()]):
            fail("development_source_revision must be a full lowercase commit digest")
    output = ctx.actions.declare_file(ctx.label.name + ".tar.gz")
    args = ctx.actions.args()
    args.add(ctx.file._pack)
    for name in ["binary", "daemon", "reference", "systemd_template", "launchd_template"]:
        args.add("--" + name.replace("_", "-"))
        args.add(getattr(ctx.file, name))
    args.add("--target", ctx.attr.target)
    args.add("--channel", ctx.attr.channel)
    args.add("--output", output)
    args.add("--epoch", "0")
    if development_revision:
        args.add("--source-revision", development_revision)
        args.add("--source-dirty", "true")
    if ctx.attr.target.endswith("-linux"):
        args.add("--patchelf", ctx.executable._patchelf)
        args.add("--ca-bundle", ctx.file._ca_bundle)
        for file in ctx.files.runtime_files:
            args.add("--runtime-file", file)
        for file in ctx.files.qt_runtime_files:
            args.add("--qt-runtime-file", file)
        if ctx.file.control:
            args.add("--control", ctx.file.control)
            for file in ctx.files.qt_plugin_files:
                args.add("--qt-plugin", file)
            if ctx.file.resolution_witness:
                args.add("--resolution-witness", ctx.file.resolution_witness)
    # A declared development revision names the caller's base commit; dirty
    # source and exact artifact evidence remain independent qualifications.
    # This non-stamped action is explicitly a dirty development artifact.
    # Publishable provenance is supplied only by an explicit local bundle run.
    ctx.actions.run(
        executable = ctx.executable._python,
        arguments = [args],
        inputs = depset([ctx.file._pack, ctx.file._portable, ctx.file.binary, ctx.file.daemon, ctx.file.reference,
                         ctx.file.systemd_template, ctx.file.launchd_template, ctx.file._ca_bundle] + ctx.files.runtime_files +
                        ctx.files.qt_runtime_files + ctx.files.qt_plugin_files + ([ctx.file.control] if ctx.file.control else []) +
                        ([ctx.file.resolution_witness] if ctx.file.resolution_witness else [])),
        tools = [ctx.attr._python[DefaultInfo].files_to_run, ctx.attr._patchelf[DefaultInfo].files_to_run] + ctx.attr._all_tools[DefaultInfo].files.to_list(),
        outputs = [output],
        mnemonic = "OmuxDevelopmentBundle",
        progress_message = "Packaging verified Omux development archive",
        use_default_shell_env = False,
        env = {"PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return [DefaultInfo(files = depset([output]))]

release_archive = rule(
    implementation = _release_archive,
    attrs = {
        "binary": attr.label(allow_single_file = True, mandatory = True),
        "daemon": attr.label(allow_single_file = True, mandatory = True),
        "reference": attr.label(allow_single_file = True, mandatory = True),
        "systemd_template": attr.label(allow_single_file = True, mandatory = True),
        "launchd_template": attr.label(allow_single_file = True, mandatory = True),
        "target": attr.string(mandatory = True),
        "channel": attr.string(values = ["development", "release"], mandatory = True),
        "development_source_revision": attr.string(default = "", doc = "Optional caller-declared full base commit for a dirty development archive only; empty preserves existing provenance."),
        "runtime_files": attr.label(default = "@omux_nix//:runtime_libraries"),
        "control": attr.label(allow_single_file = True),
        "qt_runtime_files": attr.label_list(),
        "qt_plugin_files": attr.label_list(),
        "resolution_witness": attr.label(allow_single_file = True),
        "_pack": attr.label(default = "//delivery:pack.py", allow_single_file = True),
        "_portable": attr.label(default = "//delivery:portable.py", allow_single_file = True),
        "_ca_bundle": attr.label(default = "@omux_nix//:ca_bundle", allow_single_file = True),
        "_patchelf": attr.label(default = "@omux_nix//:patchelf", executable = True, cfg = "exec"),
        "_python": attr.label(default = "@omux_nix//:python", executable = True, cfg = "exec"),
        "_all_tools": attr.label(default = "@omux_nix//:python_tools", cfg = "exec"),
    },
)

def channel_archives(name, **kwargs):
    """Declare two isolated custody channels from identical product inputs.

    Channel selection does not change experimental, unstamped release status.
    """
    release_archive(name = name, channel = "development", **kwargs)
    native.alias(name = "development_instance_archive", actual = ":" + name)
    release_archive(name = "default_instance_archive", channel = "release", **kwargs)
