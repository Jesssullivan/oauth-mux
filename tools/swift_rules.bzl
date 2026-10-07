"""Declared SwiftUI executable and ad-hoc signed development application bundle.

The locked Nix closure supplies every compiler, interpreter and SDK input.
There is no xcrun, xcode-select, ambient swiftc, signing identity, or host SDK
discovery. A Darwin executor is mandatory for the macOS-constrained targets.
"""

OmuxAppleInfo = provider(fields = ["available", "system", "sdk", "developer_dir", "swiftc", "clang", "path", "custody", "inputs"])

def _apple_config_impl(ctx):
    inputs = depset([ctx.file.swiftc, ctx.file.custody], transitive = [ctx.attr.closure[DefaultInfo].files])
    return [
        OmuxAppleInfo(
            available = ctx.attr.available,
            system = ctx.attr.system,
            sdk = ctx.attr.sdk,
            developer_dir = ctx.attr.developer_dir,
            swiftc = ctx.file.swiftc,
            clang = ctx.attr.clang,
            path = ctx.attr.path,
            custody = ctx.file.custody,
            inputs = inputs,
        ),
        DefaultInfo(files = inputs),
    ]

omux_apple_config = rule(
    implementation = _apple_config_impl,
    attrs = {
        "available": attr.bool(mandatory = True),
        "system": attr.string(mandatory = True),
        "sdk": attr.string(),
        "developer_dir": attr.string(),
        "swiftc": attr.label(allow_single_file = True, mandatory = True),
        "clang": attr.string(),
        "path": attr.string(),
        "custody": attr.label(allow_single_file = True, mandatory = True),
        "closure": attr.label(mandatory = True),
    },
)

def _swift_program_impl(ctx):
    apple = ctx.attr._apple[OmuxAppleInfo]
    if not apple.available:
        fail("SwiftUI requires a Darwin execution platform with the locked flake's declared Swift compiler and Apple SDK. Ambient Xcode/xcrun and Linux cross-compilation are unsupported.")
    if ctx.target_platform_has_constraint(ctx.attr._arm64[platform_common.ConstraintValueInfo]):
        architecture = "arm64"
    elif ctx.target_platform_has_constraint(ctx.attr._x86_64[platform_common.ConstraintValueInfo]):
        architecture = "x86_64"
    else:
        fail("The SwiftUI client supports only arm64 and x86_64 macOS targets.")
    output = ctx.actions.declare_file(ctx.attr.executable_name)
    # Modules and compiler caches are unique to this action. They are produced
    # inside the sandbox and never use a user's shared module cache.
    module_cache = ctx.actions.declare_directory(ctx.label.name + ".modules")
    args = ctx.actions.args()
    args.add_all([
        "-parse-as-library",
        "-swift-version", "5",
        "-strict-concurrency=complete",
        "-module-name", ctx.attr.module_name,
        "-target", architecture + "-apple-macosx" + ctx.attr.minimum_os_version,
        "-sdk", apple.sdk,
        "-module-cache-path", module_cache.path,
        "-O",
        "-no-toolchain-stdlib-rpath",
        "-Xlinker", "-headerpad_max_install_names",
    ])
    for framework in ctx.attr.frameworks:
        args.add_all(["-framework", framework])
    args.add_all(ctx.files.srcs)
    args.add_all(["-o", output])
    ctx.actions.run(
        executable = apple.swiftc,
        arguments = [args],
        inputs = depset(ctx.files.srcs, transitive = [apple.inputs]),
        tools = apple.inputs,
        outputs = [output, module_cache],
        mnemonic = "OmuxSwiftUI",
        progress_message = "Compiling SwiftUI controls with the declared Nix Swift/Apple SDK",
        use_default_shell_env = False,
        env = {
            "PATH": apple.path,
            "DEVELOPER_DIR": apple.developer_dir,
            "SDKROOT": apple.sdk,
            "MACOSX_DEPLOYMENT_TARGET": ctx.attr.minimum_os_version,
            # The Swift driver normally looks for clang through xcrun. Its
            # explicit override selects the declared Nix compiler instead.
            "SWIFT_DRIVER_CLANG_EXEC": apple.clang,
            "ZERO_AR_DATE": "1",
        },
        execution_requirements = {"requires-darwin": "1"},
    )
    return [DefaultInfo(executable = output, files = depset([output]), runfiles = ctx.runfiles(files = [output]))]

omux_swift_program = rule(
    implementation = _swift_program_impl,
    executable = True,
    attrs = {
        "srcs": attr.label_list(allow_files = [".swift"], mandatory = True),
        "executable_name": attr.string(default = "Omux"),
        "module_name": attr.string(default = "OmuxControls"),
        "frameworks": attr.string_list(default = ["SwiftUI", "AppKit", "Combine", "Foundation", "ServiceManagement"]),
        "minimum_os_version": attr.string(default = "14.0"),
        "_arm64": attr.label(default = "@platforms//cpu:aarch64"),
        "_x86_64": attr.label(default = "@platforms//cpu:x86_64"),
        "_apple": attr.label(default = "@omux_apple//:config", providers = [OmuxAppleInfo], cfg = "exec"),
    },
)

def _macos_application_impl(ctx):
    apple = ctx.attr._apple[OmuxAppleInfo]
    if not apple.available:
        fail("The macOS app bundle requires declared Apple SDK custody on a Darwin executor.")
    output = ctx.actions.declare_directory(ctx.label.name + ".app")
    arguments = ctx.actions.args()
    arguments.add(ctx.file._bundle)
    arguments.add_all([output, ctx.executable.binary, ctx.executable.cli, ctx.executable.daemon, ctx.file.info_plist, ctx.file.agent_plist, ctx.file.product, apple.custody], expand_directories = False)
    if ctx.target_platform_has_constraint(ctx.attr._arm64[platform_common.ConstraintValueInfo]):
        arguments.add("arm64")
    elif ctx.target_platform_has_constraint(ctx.attr._x86_64[platform_common.ConstraintValueInfo]):
        arguments.add("x86_64")
    else:
        fail("The macOS bundle supports only arm64 and x86_64 targets.")
    ctx.actions.run(
        executable = ctx.executable._python,
        arguments = [arguments],
        inputs = [ctx.file._bundle, ctx.file._macho, ctx.executable.binary, ctx.executable.cli, ctx.executable.daemon, ctx.file.info_plist, ctx.file.agent_plist, ctx.file.product, apple.custody],
        tools = [ctx.attr._python[DefaultInfo].files_to_run] + ctx.attr._all_tools[DefaultInfo].files.to_list(),
        outputs = [output],
        mnemonic = "OmuxMacOSBundle",
        progress_message = "Relocating and ad-hoc signing %s.app with declared Darwin tools" % ctx.label.name,
        use_default_shell_env = False,
        env = {"PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"},
        execution_requirements = {"requires-darwin": "1"},
    )
    return [DefaultInfo(files = depset([output]))]

omux_macos_application = rule(
    implementation = _macos_application_impl,
    attrs = {
        "binary": attr.label(executable = True, cfg = "target", mandatory = True),
        "cli": attr.label(executable = True, cfg = "target", mandatory = True),
        "daemon": attr.label(executable = True, cfg = "target", mandatory = True),
        "info_plist": attr.label(allow_single_file = [".plist"], mandatory = True),
        "agent_plist": attr.label(allow_single_file = [".plist"], mandatory = True),
        "product": attr.label(allow_single_file = [".zig"], mandatory = True),
        "_apple": attr.label(default = "@omux_apple//:config", providers = [OmuxAppleInfo], cfg = "exec"),
        "_python": attr.label(default = "@omux_nix//:python", executable = True, cfg = "exec"),
        "_all_tools": attr.label(default = "@omux_nix//:all_tools", cfg = "exec"),
        "_bundle": attr.label(default = "//tools:macos_bundle.py", allow_single_file = True),
        "_macho": attr.label(default = "//tools:macho.py", allow_single_file = True),
        "_arm64": attr.label(default = "@platforms//cpu:aarch64"),
        "_x86_64": attr.label(default = "@platforms//cpu:x86_64"),
    },
)

def _macos_archive_impl(ctx):
    if ctx.target_platform_has_constraint(ctx.attr._arm64[platform_common.ConstraintValueInfo]):
        architecture = "arm64"
    elif ctx.target_platform_has_constraint(ctx.attr._x86_64[platform_common.ConstraintValueInfo]):
        architecture = "x86_64"
    else:
        fail("The macOS archive supports only arm64 and x86_64 targets.")
    output = ctx.actions.declare_file("Omux-macos-" + architecture + ".zip")
    arguments = ctx.actions.args()
    arguments.add_all([ctx.file._bundle, "--archive", ctx.file.app, output], expand_directories = False)
    ctx.actions.run(
        executable = ctx.executable._python,
        arguments = [arguments],
        inputs = [ctx.file.app, ctx.file._bundle, ctx.file._macho],
        tools = [ctx.attr._python[DefaultInfo].files_to_run] + ctx.attr._all_tools[DefaultInfo].files.to_list(),
        outputs = [output],
        mnemonic = "OmuxMacOSArchive",
        progress_message = "Archiving the relocated, resource-sealed macOS application",
        use_default_shell_env = False,
        env = {"PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return [DefaultInfo(files = depset([output]))]

omux_macos_archive = rule(
    implementation = _macos_archive_impl,
    attrs = {
        "app": attr.label(allow_single_file = True, mandatory = True),
        "_bundle": attr.label(default = "//tools:macos_bundle.py", allow_single_file = True),
        "_macho": attr.label(default = "//tools:macho.py", allow_single_file = True),
        "_python": attr.label(default = "@omux_nix//:python", executable = True, cfg = "exec"),
        "_all_tools": attr.label(default = "@omux_nix//:all_tools", cfg = "exec"),
        "_arm64": attr.label(default = "@platforms//cpu:aarch64"),
        "_x86_64": attr.label(default = "@platforms//cpu:x86_64"),
    },
)
