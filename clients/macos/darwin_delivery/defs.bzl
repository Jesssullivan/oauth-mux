"""Experimental aarch64 Darwin delivery, isolated from exported Linux delivery."""
load("//tools:swift_rules.bzl", "OmuxAppleInfo")
load("@rules_cc//cc:cc_binary.bzl", "cc_binary")

SelectorInfo = provider(fields = ["value"])
def _selector_impl(ctx):
    return [SelectorInfo(value = ctx.build_setting_value)]
revision_selector = rule(implementation = _selector_impl, build_setting = config.string(flag = True))
dirty_selector = rule(implementation = _selector_impl, build_setting = config.bool(flag = True))

def _selected(ctx):
    revision = ctx.attr._revision[SelectorInfo].value
    if len(revision) != 40 or any([c not in "0123456789abcdef" for c in revision.elems()]):
        fail("An explicit exact source revision selector is required; no ambient Git inspection.")
    dirty = ctx.attr._dirty[SelectorInfo].value
    if ctx.attr.channel == "release" and dirty:
        fail("Release artifact provenance must be independently qualified clean before selecting this graph.")
    return revision, dirty

def _bundle_impl(ctx):
    apple = ctx.attr._apple[OmuxAppleInfo]
    if not apple.available or apple.system != "aarch64-darwin" or not ctx.target_platform_has_constraint(ctx.attr._arm64[platform_common.ConstraintValueInfo]):
        fail("The experimental channel bundle requires its exact aarch64 Darwin SDK/tool closure.")
    revision, dirty = _selected(ctx)
    output = ctx.actions.declare_directory(ctx.label.name + ".artifact")
    receipt = ctx.actions.declare_file(ctx.label.name + ".artifact-receipt.json")
    inputs = [ctx.file._adapter, ctx.file._artifact, ctx.file._macho, ctx.file._bundle,
              ctx.file.info, ctx.file.helper, ctx.file.product, ctx.file.launcher_source, apple.custody]
    args = ctx.actions.args()
    args.add(ctx.file._adapter)
    args.add_all(["--output", output.path, "--receipt", receipt.path, "--channel", ctx.attr.channel,
                  "--revision", revision, "--dirty", "true" if dirty else "false",
                  "--artifact-module", ctx.file._artifact.path, "--macho-module", ctx.file._macho.path,
                  "--bundle-module", ctx.file._bundle.path, "--info", ctx.file.info.path,
                  "--helper", ctx.file.helper.path, "--product", ctx.file.product.path,
                  "--custody", apple.custody.path, "--launcher-source", ctx.file.launcher_source.path])
    for name in ["control_launcher", "cli_launcher", "daemon_launcher", "host_launcher", "control", "cli", "daemon"]:
        target = getattr(ctx.attr, name)
        binary = target[DefaultInfo].files_to_run.executable
        args.add_all(["--" + name.replace("_", "-"), binary.path])
        inputs.append(binary)
    ctx.actions.run(
        executable = ctx.executable._python,
        arguments = [args],
        inputs = depset(inputs, transitive = [apple.inputs]),
        tools = [ctx.attr._python[DefaultInfo].files_to_run] + ctx.attr._all_tools[DefaultInfo].files.to_list(),
        outputs = [output, receipt],
        mnemonic = "OmuxExperimentalDarwinArtifact",
        progress_message = "Assembling bound channel launchers and final ad-hoc Darwin inventory",
        use_default_shell_env = False,
        env = {"PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"},
        execution_requirements = {"requires-darwin": "1"},
    )
    return [DefaultInfo(files = depset([output, receipt]))]

_attrs = {
    "channel": attr.string(values = ["development", "release"], mandatory = True),
    "info": attr.label(default = "//clients/macos:Info.plist", allow_single_file = True),
    "helper": attr.label(default = "//clients/macos:ai.xoxd.omux.daemon.plist", allow_single_file = True),
    "product": attr.label(default = "//:src/product.zig", allow_single_file = True),
    "launcher_source": attr.label(default = ":channel_launcher.c", allow_single_file = True),
    "_revision": attr.label(default = ":source_revision"),
    "_dirty": attr.label(default = ":source_dirty"),
    "_apple": attr.label(default = "@omux_apple//:config", providers = [OmuxAppleInfo], cfg = "exec"),
    "_python": attr.label(default = "@omux_nix//:python", executable = True, cfg = "exec"),
    "_all_tools": attr.label(default = "@omux_nix//:all_tools", cfg = "exec"),
    "_adapter": attr.label(default = "//tools/darwin_artifact:bundle.py", allow_single_file = True),
    "_artifact": attr.label(default = "//tools/darwin_artifact:artifact.py", allow_single_file = True),
    "_bundle": attr.label(default = "//tools:macos_bundle.py", allow_single_file = True),
    "_macho": attr.label(default = "//tools:macho.py", allow_single_file = True),
    "_arm64": attr.label(default = "@platforms//cpu:aarch64"),
}
_attrs.update({name: attr.label(executable = True, cfg = "target", mandatory = True)
               for name in ["control_launcher", "cli_launcher", "daemon_launcher", "host_launcher", "control", "cli", "daemon"]})
experimental_darwin_artifact = rule(implementation = _bundle_impl, attrs = _attrs)

def experimental_channel_targets():
    roles = {"Omux": "OmuxControls", "omux": "omux-runtime",
             "omuxd": "omux-daemon-runtime", "omux-native-host": "omux-runtime"}
    for channel, instance in [("development", "dev"), ("release", "default")]:
        for role, backend in roles.items():
            cc_binary(
                name = channel + "_" + role,
                srcs = ["channel_launcher.c"],
                defines = ["_DARWIN_C_SOURCE=1", "OMUX_BIND_INSTANCE=\"" + instance + "\"",
                           "OMUX_BIND_ROLE=\"" + role + "\"", "OMUX_BIND_BACKEND=\"" + backend + "\""],
                copts = ["-std=c11", "-mmacosx-version-min=14.0"],
                linkopts = ["-mmacosx-version-min=14.0", "-Wl,-headerpad_max_install_names"],
                target_compatible_with = ["@platforms//os:macos", "@platforms//cpu:aarch64"],
                exec_compatible_with = ["@platforms//os:macos"],
                tags = ["manual"],
            )
        experimental_darwin_artifact(
            name = channel + "_artifact", channel = channel,
            control_launcher = ":" + channel + "_Omux", cli_launcher = ":" + channel + "_omux",
            daemon_launcher = ":" + channel + "_omuxd", host_launcher = ":" + channel + "_omux-native-host",
            control = "//clients/macos:control", cli = "//:omux", daemon = "//:omuxd",
            target_compatible_with = ["@platforms//os:macos", "@platforms//cpu:aarch64"],
            exec_compatible_with = ["@platforms//os:macos"],
            tags = ["manual"],
        )
