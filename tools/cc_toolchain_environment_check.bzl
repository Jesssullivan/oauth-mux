"""Consume the selected C++ configuration and build a real toolchain smoke fixture."""

load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@omux_nix//:tool_paths.bzl", "NIX_COREUTILS_BIN")

def _check_impl(ctx):
    toolchain = find_cc_toolchain(ctx)
    configuration = cc_common.configure_features(
        ctx = ctx,
        cc_toolchain = toolchain,
        requested_features = ctx.features,
        unsupported_features = ctx.disabled_features,
    )
    actions = [
        ACTION_NAMES.c_compile,
        ACTION_NAMES.cpp_compile,
        ACTION_NAMES.assemble,
        ACTION_NAMES.preprocess_assemble,
        ACTION_NAMES.linkstamp_compile,
        ACTION_NAMES.cpp_link_executable,
        ACTION_NAMES.cpp_link_dynamic_library,
        ACTION_NAMES.cpp_link_nodeps_dynamic_library,
        ACTION_NAMES.cpp_link_static_library,
        ACTION_NAMES.strip,
    ]
    for action in actions:
        environment = cc_common.get_environment_variables(
            feature_configuration = configuration,
            action_name = action,
            variables = cc_common.empty_variables(),
        )
        if not NIX_COREUTILS_BIN or environment.get("PATH") != NIX_COREUTILS_BIN:
            fail("configured C/C++ action must override coordinator executable search: " + action)
        executable = cc_common.get_tool_for_action(feature_configuration = configuration, action_name = action)
        if "/tool_wrappers/" not in executable and not executable.startswith("tool_wrappers/"):
            fail("configured C/C++ action must use a declared Nix wrapper: " + action)

    c_source = ctx.actions.declare_file(ctx.label.name + ".c")
    cpp_source = ctx.actions.declare_file(ctx.label.name + ".cpp")
    ctx.actions.write(c_source, "int omux_toolchain_c(void) { return 17; }\n")
    ctx.actions.write(cpp_source, 'extern "C" int omux_toolchain_c(void);\nint main() { return omux_toolchain_c() == 17 ? 0 : 1; }\n')
    _, outputs = cc_common.compile(
        actions = ctx.actions,
        feature_configuration = configuration,
        cc_toolchain = toolchain,
        name = ctx.label.name,
        srcs = [c_source, cpp_source],
    )
    executable = cc_common.link(
        actions = ctx.actions,
        feature_configuration = configuration,
        cc_toolchain = toolchain,
        name = ctx.label.name,
        compilation_outputs = outputs,
        output_type = "executable",
    ).executable
    _, archive_outputs = cc_common.create_linking_context_from_compilation_outputs(
        actions = ctx.actions,
        feature_configuration = configuration,
        cc_toolchain = toolchain,
        name = ctx.label.name + "_archive",
        compilation_outputs = outputs,
        disallow_dynamic_library = True,
    )
    archive = archive_outputs.library_to_link.static_library or archive_outputs.library_to_link.pic_static_library
    if not archive:
        fail("configured toolchain did not declare a static archive smoke output")
    stripped = ctx.actions.declare_file(ctx.label.name + ".stripped")
    strip_variables = cc_common.create_compile_variables(
        cc_toolchain = toolchain,
        feature_configuration = configuration,
        output_file = stripped.path,
        variables_extension = {"input_file": executable.path},
    )
    ctx.actions.run(
        executable = cc_common.get_tool_for_action(feature_configuration = configuration, action_name = ACTION_NAMES.strip),
        arguments = cc_common.get_memory_inefficient_command_line(
            feature_configuration = configuration,
            action_name = ACTION_NAMES.strip,
            variables = strip_variables,
        ),
        env = cc_common.get_environment_variables(
            feature_configuration = configuration,
            action_name = ACTION_NAMES.strip,
            variables = strip_variables,
        ),
        use_default_shell_env = True,
        inputs = depset([executable], transitive = [toolchain.all_files]),
        outputs = [stripped],
        mnemonic = "OmuxToolchainStripSmoke",
        toolchain = "@bazel_tools//tools/cpp:toolchain_type",
    )
    return [DefaultInfo(files = depset([executable, archive, stripped]))]

cc_toolchain_environment_check = rule(
    implementation = _check_impl,
    fragments = ["cpp"],
    toolchains = use_cc_toolchain(),
)
