"""A declared C/C++ toolchain backed by the flake's immutable Nix closure.

Compiler wrappers and their transitive store inputs are supplied by
``omux_nix_repository``. No host compiler or /usr/include fallback is used.
Remote workers must mount the manifest's identical /nix/store closure; Nix
wrappers and Mach-O install names retain those content-addressed paths.
"""

load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/toolchains:cc_toolchain_config_info.bzl", "CcToolchainConfigInfo")
load("@rules_cc//cc:cc_toolchain_config_lib.bzl", "action_config", "env_entry", "env_set", "feature", "flag_group", "flag_set", "tool", "tool_path", "variable_with_value")
load("@//tools:native_tool_info.bzl", "OmuxNixToolInfo")

_COMPILE = [
    ACTION_NAMES.c_compile,
    ACTION_NAMES.cpp_compile,
    ACTION_NAMES.assemble,
    ACTION_NAMES.preprocess_assemble,
    ACTION_NAMES.linkstamp_compile,
]
_LINK = [
    ACTION_NAMES.cpp_link_executable,
    ACTION_NAMES.cpp_link_dynamic_library,
    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
]
_DYNAMIC_LINK = [
    ACTION_NAMES.cpp_link_dynamic_library,
    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
]

def _flags(name, actions, flags, enabled = True):
    return feature(
        name = name,
        enabled = enabled,
        flag_sets = [flag_set(actions = actions, flag_groups = [flag_group(flags = flags)])],
    )

def _config_impl(ctx):
    search_parts = ctx.attr.executable_search_path.split("/")
    if len(search_parts) != 5 or search_parts[:3] != ["", "nix", "store"] or search_parts[-1] != "bin":
        fail("C/C++ executable search must name one immutable store root's bin directory")
    search_root = search_parts[3]
    if len(search_root) < 34 or search_root[32] != "-" or any([character not in "0123456789abcdfghijklmnpqrsvwxyz" for character in search_root[:32].elems()]) or any([character in ctx.attr.executable_search_path for character in [":", " ", "\t", "\n", "\r"]]):
        fail("C/C++ executable search must name the selected manifest's immutable coreutils bin directory")
    darwin = ctx.attr.system.endswith("-darwin")
    compiler = "tool_wrappers/cc"
    linker = "tool_wrappers/cxx"
    cpp_include_paths = [path for path in ctx.attr.builtin_include_directories if "/include/c++/" in path]
    gcc_include_paths = [path for path in ctx.attr.builtin_include_directories if "/lib/gcc/" in path]
    framework_include_paths = [path for path in ctx.attr.builtin_include_directories if darwin and path.endswith("/System/Library/Frameworks")]
    libc_include_paths = [path for path in ctx.attr.builtin_include_directories if path not in cpp_include_paths and path not in gcc_include_paths and path not in framework_include_paths]
    # GCC's C++ forwarding headers use include_next: libc must follow them.
    builtin_include_paths = cpp_include_paths + gcc_include_paths + libc_include_paths + framework_include_paths
    static_library_flags = [
        flag_group(flags = ["-Wl,-force_load,%{libraries_to_link.name}"], expand_if_true = "libraries_to_link.is_whole_archive"),
        flag_group(flags = ["%{libraries_to_link.name}"], expand_if_false = "libraries_to_link.is_whole_archive"),
    ] if darwin else [
        flag_group(flags = ["-Wl,--whole-archive"], expand_if_true = "libraries_to_link.is_whole_archive"),
        flag_group(flags = ["%{libraries_to_link.name}"]),
        flag_group(flags = ["-Wl,--no-whole-archive"], expand_if_true = "libraries_to_link.is_whole_archive"),
    ]
    features = [
        # Bazel's default PATH belongs to the coordinator, including the tools
        # embedded by Nixpkgs' strict_action_env patch. Feature environments
        # override that default for compile, link and archive actions. The
        # repository supplies only its manifest's declared coreutils directory;
        # Nix wrappers prepend their own declared assembler/linker directory.
        feature(
            name = "declared_tool_environment",
            enabled = True,
            env_sets = [env_set(
                actions = _COMPILE + _LINK + [ACTION_NAMES.cpp_link_static_library, ACTION_NAMES.strip],
                env_entries = [env_entry(key = "PATH", value = ctx.attr.executable_search_path)],
            )],
        ),
        feature(name = "supports_pic", enabled = True),
        feature(name = "supports_dynamic_linker", enabled = True),
        feature(name = "no_legacy_features", enabled = True),
        feature(
            name = "compiler_input_flags",
            enabled = True,
            flag_sets = [flag_set(actions = _COMPILE, flag_groups = [flag_group(flags = ["-c", "%{source_file}"], expand_if_available = "source_file")])],
        ),
        feature(
            name = "compiler_output_flags",
            enabled = True,
            flag_sets = [flag_set(actions = _COMPILE, flag_groups = [flag_group(flags = ["-o", "%{output_file}"], expand_if_available = "output_file")])],
        ),
        feature(
            name = "dependency_file",
            enabled = True,
            flag_sets = [flag_set(actions = _COMPILE, flag_groups = [flag_group(flags = ["-MD", "-MF", "%{dependency_file}"], expand_if_available = "dependency_file")])],
        ),
        feature(
            name = "preprocessor_defines",
            enabled = True,
            flag_sets = [flag_set(actions = _COMPILE, flag_groups = [flag_group(flags = ["-D%{preprocessor_defines}"], iterate_over = "preprocessor_defines")])],
        ),
        feature(
            name = "include_paths",
            enabled = True,
            flag_sets = [flag_set(actions = _COMPILE, flag_groups = [
                flag_group(flags = ["-iquote", "%{quote_include_paths}"], iterate_over = "quote_include_paths"),
                flag_group(flags = ["-I%{include_paths}"], iterate_over = "include_paths"),
                flag_group(flags = ["-isystem", "%{system_include_paths}"], iterate_over = "system_include_paths"),
            ])],
        ),
        feature(
            name = "declared_builtin_include_paths",
            enabled = True,
            flag_sets = [
                flag_set(actions = [ACTION_NAMES.cpp_compile, ACTION_NAMES.linkstamp_compile], flag_groups = [flag_group(flags = [item for path in cpp_include_paths + gcc_include_paths + libc_include_paths for item in ["-isystem", path]])]),
                flag_set(actions = [ACTION_NAMES.c_compile, ACTION_NAMES.assemble, ACTION_NAMES.preprocess_assemble], flag_groups = [flag_group(flags = [item for path in gcc_include_paths + libc_include_paths for item in ["-isystem", path]])]),
            ],
        ),
        feature(
            name = "pic",
            flag_sets = [flag_set(actions = _COMPILE, flag_groups = [flag_group(flags = ["-fPIC"], expand_if_available = "pic")])],
        ),
        _flags("default_cpp_standard", [ACTION_NAMES.cpp_compile], ["-std=c++17"]),
        feature(
            name = "user_compile_flags",
            enabled = True,
            flag_sets = [flag_set(actions = _COMPILE, flag_groups = [flag_group(flags = ["%{user_compile_flags}"], iterate_over = "user_compile_flags", expand_if_available = "user_compile_flags")])],
        ),
        _flags("dbg", _COMPILE, ["-g", "-O0"], False),
        _flags("opt", _COMPILE, ["-O2", "-DNDEBUG"], False),
        _flags("fastbuild", _COMPILE, ["-O0"], False),
        feature(
            name = "output_execpath_flags",
            enabled = True,
            flag_sets = [flag_set(actions = _LINK, flag_groups = [flag_group(flags = ["-o", "%{output_execpath}"])])],
        ),
        _flags("dynamic_library_linker_flags", _DYNAMIC_LINK, ["-dynamiclib" if darwin else "-shared"]),
        feature(
            name = "library_search_directories",
            enabled = True,
            flag_sets = [flag_set(actions = _LINK, flag_groups = [flag_group(flags = ["-L%{library_search_directories}"], iterate_over = "library_search_directories")])],
        ),
        feature(
            name = "runtime_library_search_directories",
            enabled = True,
            flag_sets = [flag_set(actions = _LINK, flag_groups = [flag_group(
                flags = ["-Wl,-rpath," + ("@loader_path/" if darwin else "$ORIGIN/") + "%{runtime_library_search_directories}"],
                iterate_over = "runtime_library_search_directories",
                expand_if_available = "runtime_library_search_directories",
            )])],
        ),
        feature(
            name = "libraries_to_link",
            enabled = True,
            flag_sets = [flag_set(actions = _LINK, flag_groups = [flag_group(iterate_over = "libraries_to_link", flag_groups = [
                flag_group(flags = ["%{libraries_to_link.name}"], expand_if_equal = variable_with_value(name = "libraries_to_link.type", value = "object_file")),
                flag_group(flags = ["%{libraries_to_link.object_files}"], iterate_over = "libraries_to_link.object_files", expand_if_equal = variable_with_value(name = "libraries_to_link.type", value = "object_file_group")),
                flag_group(flags = ["%{libraries_to_link.name}"], expand_if_equal = variable_with_value(name = "libraries_to_link.type", value = "interface_library")),
                flag_group(flags = ["-l%{libraries_to_link.name}"], expand_if_equal = variable_with_value(name = "libraries_to_link.type", value = "dynamic_library")),
                flag_group(flags = ["%{libraries_to_link.name}" if darwin else "-l:%{libraries_to_link.name}"], expand_if_equal = variable_with_value(name = "libraries_to_link.type", value = "versioned_dynamic_library")),
                flag_group(flag_groups = static_library_flags, expand_if_equal = variable_with_value(name = "libraries_to_link.type", value = "static_library")),
            ])])],
        ),
        feature(
            name = "user_link_flags",
            enabled = True,
            flag_sets = [flag_set(actions = _LINK, flag_groups = [flag_group(flags = ["%{user_link_flags}"], iterate_over = "user_link_flags", expand_if_available = "user_link_flags")])],
        ),
        feature(
            name = "linker_param_file",
            enabled = True,
            flag_sets = [flag_set(actions = _LINK, flag_groups = [flag_group(flags = ["@%{linker_param_file}"], expand_if_available = "linker_param_file")])],
        ),
        feature(
            name = "archiver_flags",
            enabled = True,
            flag_sets = [flag_set(actions = [ACTION_NAMES.cpp_link_static_library], flag_groups = [
                flag_group(flags = ["rcs", "%{output_execpath}"]),
                flag_group(iterate_over = "libraries_to_link", expand_if_available = "libraries_to_link", flag_groups = [
                    flag_group(flags = ["%{libraries_to_link.name}"], expand_if_equal = variable_with_value(name = "libraries_to_link.type", value = "object_file")),
                    flag_group(flags = ["%{libraries_to_link.object_files}"], iterate_over = "libraries_to_link.object_files", expand_if_equal = variable_with_value(name = "libraries_to_link.type", value = "object_file_group")),
                ]),
            ])],
        ),
        feature(
            name = "strip_flags",
            enabled = True,
            flag_sets = [flag_set(actions = [ACTION_NAMES.strip], flag_groups = [
                flag_group(flags = ["-S", "-o", "%{output_file}", "%{input_file}"]),
                flag_group(flags = ["%{stripopts}"], iterate_over = "stripopts", expand_if_available = "stripopts"),
            ])],
        ),
    ]
    # Framework headers have their own Clang lookup protocol and live outside
    # SDK/usr/include. The manifest names only the locked public SDK subtree.
    # Keep Linux features and ordinary include ordering unchanged.
    if framework_include_paths:
        features.append(_flags("declared_builtin_framework_paths", _COMPILE, [item for path in framework_include_paths for item in ["-iframework", path]]))
    configs = [action_config(action_name = name, enabled = True, tools = [tool(path = linker if name in [ACTION_NAMES.cpp_compile, ACTION_NAMES.linkstamp_compile] else compiler)]) for name in _COMPILE]
    configs += [action_config(action_name = name, enabled = True, tools = [tool(path = linker)]) for name in _LINK]
    configs.append(action_config(action_name = ACTION_NAMES.cpp_link_static_library, enabled = True, tools = [tool(path = "tool_wrappers/ar")]))
    configs.append(action_config(action_name = ACTION_NAMES.strip, enabled = True, tools = [tool(path = "tool_wrappers/strip")]))
    return [cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        features = features,
        action_configs = configs,
        cxx_builtin_include_directories = builtin_include_paths,
        toolchain_identifier = "omux-nix-" + ctx.attr.system,
        host_system_name = ctx.attr.system,
        target_system_name = ctx.attr.system,
        target_cpu = "aarch64" if ctx.attr.system.startswith("aarch64-") else "k8",
        target_libc = "darwin" if darwin else "glibc",
        compiler = "clang" if darwin else "gcc",
        abi_version = "local",
        abi_libc_version = "local",
        tool_paths = [tool_path(name = name, path = "tool_wrappers/" + path) for name, path in [
            ("gcc", "cc"), ("g++", "cxx"), ("ar", "ar"), ("ld", "linker"),
            ("nm", "nm"), ("strip", "strip"), ("objcopy", "objcopy"),
            ("objdump", "objdump"), ("gcov", "gcov"), ("cpp", "cc"), ("dwp", "dwp"),
        ]],
    )]

omux_cc_toolchain_config = rule(
    implementation = _config_impl,
    attrs = {
        "system": attr.string(mandatory = True),
        "builtin_include_directories": attr.string_list(mandatory = True),
        "executable_search_path": attr.string(mandatory = True),
    },
    provides = [CcToolchainConfigInfo],
)

def _nix_tool_impl(ctx):
    if not ctx.attr.executable_path.startswith("/nix/store/"):
        fail("Nix tool executable_path must name its immutable /nix/store executable")
    closure_files = ctx.attr.closure[DefaultInfo].files
    output = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(output = output, target_file = ctx.file.script, is_executable = True)
    return [OmuxNixToolInfo(
        executable_path = ctx.attr.executable_path,
        closure_files = closure_files,
    ), DefaultInfo(
        executable = output,
        files = depset([output]),
        runfiles = ctx.runfiles(transitive_files = closure_files),
    )]

omux_nix_tool = rule(
    implementation = _nix_tool_impl,
    executable = True,
    attrs = {
        "script": attr.label(allow_single_file = True, mandatory = True),
        "executable_path": attr.string(mandatory = True),
        "closure": attr.label(mandatory = True),
    },
)
