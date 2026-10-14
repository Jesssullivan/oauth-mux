"""Import declared flake outputs into Bazel without probing ambient tools.

The flake supplies OMUX_BAZEL_CLOSURE/native.json. All paths in that manifest
are immutable /nix/store inputs, exposed as repository files and included in
the C/C++ toolchain's all_files. Remote workers require the same Nix closure
mounted at its recorded paths (Nix tool wrappers retain absolute references).
"""

_PACKAGES = {
    "libc": struct(libraries = ["c"], headers = [], includes = ["include"], deps = []),
    "sqlite": struct(libraries = ["sqlite3"], headers = ["sqlite3.h"], includes = ["include"], deps = []),
    "openssl": struct(libraries = ["ssl", "crypto"], headers = [], includes = ["include"], deps = []),
    "nghttp2": struct(libraries = ["nghttp2"], headers = ["nghttp2/nghttp2.h"], includes = ["include"], deps = []),
    "curl": struct(libraries = ["curl"], headers = ["curl/curl.h", "curl/multi.h"], includes = ["include"], deps = ["openssl", "nghttp2"]),
    "glib": struct(libraries = ["glib-2.0", "gobject-2.0", "gio-2.0", "gmodule-2.0"], headers = ["glib-2.0/glib.h", "glib-2.0/glib-object.h", "glib-2.0/gio/gio.h"], includes = ["include/glib-2.0", "lib/glib-2.0/include"], deps = []),
    "libsecret": struct(libraries = ["secret-1"], headers = ["libsecret-1/libsecret/secret.h"], includes = ["include/libsecret-1"], deps = ["glib"]),
    "qt": struct(libraries = ["Qt6Core", "Qt6Gui", "Qt6Widgets", "Qt6Network"], headers = [], includes = ["include", "include/QtCore", "include/QtGui", "include/QtWidgets", "include/QtNetwork"], deps = []),
}

def _quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"

def _store_path(value, description):
    if type(value) != "string" or not value.startswith("/nix/store/") or "/../" in value or "\n" in value or "\r" in value:
        fail("{} must be an absolute immutable /nix/store path".format(description))
    return value

def _first_existing(ctx, candidates):
    for candidate in candidates:
        if ctx.path(candidate).exists:
            return candidate
    return None

def _package_outputs(pkg):
    return [pkg[key] for key in ["dev", "lib", "out"] if key in pkg]

def _bootstrap_python(ctx, execution_root):
    root = ctx.attr.bootstrap_closure or ctx.os.environ.get("OMUX_BAZEL_BOOTSTRAP_CLOSURE") or execution_root
    root = _store_path(root, "repository bootstrap closure")
    manifest = ctx.path(root + "/native.json")
    ctx.watch(manifest)
    bootstrap = json.decode(ctx.read(manifest))
    host_os = {"linux": "linux", "mac os x": "darwin"}.get(ctx.os.name.lower())
    host_cpu = {"amd64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(ctx.os.arch.lower())
    if not host_os or not host_cpu or bootstrap.get("system") != host_cpu + "-" + host_os:
        fail("repository bootstrap closure must match the Bazel client OS and CPU")
    paths = ctx.path(root + "/store-paths")
    registration = ctx.path(root + "/registration")
    if not paths.exists or not registration.exists:
        fail("repository bootstrap closure must export store-paths and registration")
    ctx.watch(paths)
    ctx.watch(registration)
    roots = {}
    for entry in ctx.read(paths).split("\n"):
        if entry:
            entry = _store_path(entry, "bootstrap store-paths entry")
            if len(entry.split("/")) != 4 or not ctx.path(entry).exists:
                fail("bootstrap closure store root is unavailable or invalid: " + entry)
            roots[entry] = True
    python_output = _store_path(bootstrap.get("packages", {}).get("python", {}).get("out"), "bootstrap Python output")
    python = python_output + "/bin/python3"
    if "/".join(python_output.split("/")[:4]) not in roots or not ctx.path(python).exists:
        fail("bootstrap Python must belong to the declared transitive bootstrap closure")
    return python

def _library(ctx, pkg, name):
    outputs = _package_outputs(pkg)
    # Match the ELF SONAME alias, so Bazel's solib/runfiles tree contains the
    # filename recorded in DT_NEEDED rather than only the development .so link.
    for output in outputs:
        libdir = ctx.path(output + "/lib")
        if not libdir.exists:
            continue
        prefix = "lib" + name + ".so."
        sonames = []
        for candidate in libdir.readdir():
            basename = candidate.basename
            if basename.startswith(prefix):
                suffix = basename[len(prefix):]
                if suffix and len([char for char in suffix.elems() if char in "0123456789"]) == len(suffix):
                    sonames.append(str(candidate))
        if sonames:
            return struct(source = sorted(sonames)[0], attribute = "shared_library")
    for suffix, attribute in [(".so", "shared_library"), (".dylib", "shared_library"), (".a", "static_library")]:
        for output in outputs:
            path = ctx.path(output + "/lib/lib" + name + suffix)
            if path.exists:
                return struct(source = str(path), attribute = attribute)
    fail("native closure package lacks lib{} (.so, .dylib, or .a)".format(name))

def _runtime_closure(ctx, native, key, directory, manifest_name):
    roots = []
    manifest = native.get(key)
    if manifest:
        manifest = _store_path(manifest, key + " manifest")
        for path in ctx.read(manifest).split("\n"):
            if path:
                path = _store_path(path, key + " entry")
                if not ctx.path(path).exists:
                    fail("native runtime closure input is unavailable: " + path)
                roots.append(path)
                ctx.symlink(path, directory + "/" + path.split("/")[3])
    ctx.file(manifest_name, "\n".join(roots) + "\n")

def _qt_platform_plugins(ctx, packages):
    plugins = []
    if "qt" not in packages:
        return plugins
    for output in _package_outputs(packages["qt"]):
        for suffix in ["/lib/qt-6/plugins/platforms", "/lib/qt6/plugins/platforms", "/plugins/platforms"]:
            directory = ctx.path(output + suffix)
            if not directory.exists:
                continue
            for candidate in directory.readdir():
                name = candidate.basename
                if name in ["libqxcb.so", "libqoffscreen.so"] or (name.startswith("libqwayland") and name.endswith(".so")):
                    destination = "qt_platform_plugins/platforms/" + name
                    if destination not in plugins:
                        ctx.symlink(candidate, destination)
                        plugins.append(destination)
    return sorted(plugins)

def _nix_repo_impl(ctx):
    root = ctx.attr.closure or ctx.os.environ.get("OMUX_BAZEL_CLOSURE", "")
    if not root:
        fail("OMUX_BAZEL_CLOSURE is absent. Run Bazel inside `nix develop`; the flake supplies the pinned native closure.")
    _store_path(root, "native closure root")
    manifest_path = ctx.path(root + "/native.json")
    if not manifest_path.exists:
        fail("native closure manifest is missing: " + str(manifest_path))
    native = json.decode(ctx.read(manifest_path))
    for key in ["cc", "cxx", "ar", "linker"]:
        if not native.get(key):
            fail("native closure manifest must declare " + key)
    system = native.get("system", "")
    if system not in ["x86_64-linux", "aarch64-linux", "x86_64-darwin", "aarch64-darwin"]:
        fail("unsupported native closure system: " + system)
    if system.endswith("-linux") and native.get("libc_abi") != "2.42":
        fail("the Linux Zig target requires the locked native libc ABI 2.42; update its target toolchains together with the Nix closure")
    ctx.file("native.json", json.encode_indent(native, indent = "  ") + "\n")
    ctx.symlink(ctx.attr.toolchain_rule, "nix_cc_toolchain.bzl")

    packages = native.get("packages", {})
    zig_rootopts = []
    zig_linkopts = []
    zig_framework_prefix = None
    zig_sdk_library_prefix = None
    dynamic_linker_files = []
    if system.endswith("-linux"):
        if "libc" not in packages or not native.get("dynamic_linker"):
            fail("Linux native closure must declare packages.libc and dynamic_linker; host runtime selection is forbidden")
        dynamic_linker = _store_path(native["dynamic_linker"], "dynamic linker")
        if not ctx.path(dynamic_linker).exists:
            fail("declared dynamic linker is unavailable: " + dynamic_linker)
        dynamic_linker_file = "runtime_loader/" + dynamic_linker.split("/")[-1]
        ctx.symlink(dynamic_linker, dynamic_linker_file)
        dynamic_linker_files.append(dynamic_linker_file)
        zig_rootopts = ["--dynamic-linker", dynamic_linker]
        zig_linkopts = ["-rpath", _store_path(packages["libc"]["out"], "libc.out") + "/lib"]
    else:
        apple = native.get("apple")
        if not apple or not apple.get("sdk"):
            fail("Darwin native closure must declare its locked Apple SDK")
        sdk = _store_path(apple["sdk"], "Darwin SDK")
        sdk_output = _store_path(packages.get("apple_sdk", {}).get("out", ""), "Darwin SDK package output")
        if not sdk.startswith(sdk_output + "/"):
            fail("Darwin SDK must belong to the declared Apple SDK package")
        frameworks = sdk + "/System/Library/Frameworks"
        if frameworks not in native.get("builtin_include_directories", []):
            fail("Darwin SDK public framework root must be declared for native header validation")
        if not ctx.path(frameworks).exists:
            fail("declared Darwin SDK public frameworks are unavailable")
        sdk_libraries = sdk + "/usr/lib"
        if not ctx.path(sdk_libraries + "/libobjc.A.tbd").exists:
            fail("declared Darwin SDK Objective-C dependency stub is unavailable")
        # Framework and library searches belong to the root module before -M.
        zig_rootopts = ["-F", frameworks, "-L", sdk_libraries]
        # The link option is emitted last, after rules_zig's declared
        # dynamic dependencies request LLD. Zig's Mach-O linker is native;
        # its ELF LLD selection cannot link Darwin binaries.
        zig_linkopts = ["-fno-lld"]
        zig_framework_prefix = "packages/apple_sdk/out" + frameworks[len(sdk_output):] + "/"
        zig_sdk_library_prefix = "packages/apple_sdk/out" + sdk_libraries[len(sdk_output):] + "/"
    store_inputs = {}
    for name, pkg in packages.items():
        for output_name, output in pkg.items():
            if output_name in ["out", "dev", "lib", "bin"]:
                path = _store_path(output, name + "." + output_name)
                if not ctx.path(path).exists:
                    fail("native closure output is unavailable: " + path)
                ctx.symlink(path, "packages/{}/{}".format(name, output_name))
                store_inputs[path] = True
    for path in native.get("closure", []):
        store_inputs[_store_path(path, "closure entry")] = True
    closure_paths = ctx.path(root + "/store-paths")
    if closure_paths.exists:
        for path in ctx.read(closure_paths).split("\n"):
            if path:
                store_inputs[_store_path(path, "store-paths entry")] = True
    else:
        if not native.get("closure", []):
            fail("native closure must provide store-paths or a closure array; transitive Nix inputs cannot be implicit")
    for key in ["cc", "cxx", "ar", "linker", "nm", "strip", "objcopy", "objdump", "gcov", "dwp"]:
        if key in native:
            path = _store_path(native[key], key)
            # A compiler's store root and support files must be declared too.
            store_inputs["/".join(path.split("/")[:4])] = True
    for name, path in native.get("tools", {}).items():
        path = _store_path(path, name + " tool")
        store_inputs["/".join(path.split("/")[:4])] = True
    for path in sorted(store_inputs.keys()):
        if not ctx.path(path).exists:
            fail("native closure input is unavailable: " + path)
        ctx.symlink(path, "closure/" + path.split("/")[3])
    ctx.file("store-paths", "\n".join(sorted(store_inputs.keys())) + "\n")
    registration_path = ctx.path(root + "/registration")
    if not registration_path.exists:
        fail("native closure must export Nix registration metadata for worker provisioning")
    ctx.file("registration", ctx.read(registration_path))
    _runtime_closure(ctx, native, "runtime_store_paths", "runtime_closure", "runtime-store-paths")
    _runtime_closure(ctx, native, "qt_runtime_store_paths", "qt_runtime_closure", "qt-runtime-store-paths")
    qt_platform_plugins = _qt_platform_plugins(ctx, packages)
    # Darwin SDK/framework directory aliases can point back into an ancestor.
    # Enumerate finite file paths with the declared Python tool instead of
    # Bazel recursive globbing, which errors before toolchain analysis.
    ctx.watch(ctx.path(ctx.attr.file_inventory))
    inventory = ctx.execute([_bootstrap_python(ctx, root), "-I", "-S", ctx.path(ctx.attr.file_inventory), str(ctx.path(".")), "closure", "packages", "runtime_closure", "qt_runtime_closure"], timeout = 1800)
    if inventory.return_code:
        fail("declared Nix file inventory failed: " + inventory.stderr)
    inventory_report = json.decode(inventory.stdout)
    inventory_files = inventory_report["files"]
    ctx.file("file-inventory.json", json.encode_indent(inventory_report, indent = "  ") + "\n")
    shell = _store_path(packages["bash"]["out"] + "/bin/bash", "bash executable")
    capability_names = ["dbus_run_session", "dbus_daemon", "gnome_keyring_daemon", "patchelf", "openssl_tool", "systemctl", "moc", "rcc", "uic", "secret_tool"]
    executable_candidates = {
        "python": [packages["python"]["out"] + "/bin/python3"] if "python" in packages else [],
        "node": [packages["node"]["out"] + "/bin/node"] if "node" in packages else [],
        "bash": [shell],
        "patchelf": [packages["patchelf"]["out"] + "/bin/patchelf"] if "patchelf" in packages else [],
        "systemctl": [],
        "ssh": [],
        "dbus_daemon": [],
        "dbus_run_session": [],
        "gnome_keyring_daemon": [],
        "secret_tool": [],
        "openssl_tool": [packages["openssl"]["bin"] + "/bin/openssl"] if "bin" in packages.get("openssl", {}) else [],
        "moc": [output + suffix for output in _package_outputs(packages.get("qt", {})) for suffix in ["/libexec/moc", "/bin/moc"]],
        "rcc": [output + suffix for output in _package_outputs(packages.get("qt", {})) for suffix in ["/libexec/rcc", "/bin/rcc"]],
        "uic": [output + suffix for output in _package_outputs(packages.get("qt", {})) for suffix in ["/libexec/uic", "/bin/uic"]],
    }
    resolved_tools = {}
    for name, candidates in executable_candidates.items():
        executable = native.get("tools", {}).get(name) or _first_existing(ctx, candidates)
        if not executable:
            continue
        executable = _store_path(executable, name + " executable")
        if not ctx.path(executable).exists:
            fail("declared native executable is unavailable: " + executable)
        resolved_tools[name] = executable
    ctx.file("resolved-tools.json", json.encode({name: resolved_tools[name] for name in capability_names if name in resolved_tools}) + "\n")
    # Select interpreter+Bash dependencies from the existing registration graph;
    # no Nix query/evaluation or new realization occurs during selection.
    ctx.watch(ctx.path(ctx.attr.interpreter_closure))
    selection = ctx.execute([
        _bootstrap_python(ctx, root), "-I", "-S", ctx.path(ctx.attr.interpreter_closure),
        "--native", ctx.path("native.json"),
        "--store-paths", ctx.path("store-paths"),
        "--registration", ctx.path("registration"),
        "--inventory", ctx.path("file-inventory.json"),
        "--resolved-tools", ctx.path("resolved-tools.json"),
    ], timeout = 120)
    if selection.return_code:
        fail("declared interpreter closure selection failed: " + selection.stdout)
    selection_report = json.decode(selection.stdout)
    interpreter_groups = selection_report["groups"]
    declared_inventory_files = {path: True for path in inventory_files}
    for name, group in interpreter_groups.items():
        if name == "codex_metadata_query":
            if "query_tools" not in selection_report or selection_report["query_tools"].get("roots") != group["roots"]:
                fail("metadata query closure binding absent")
        elif name not in ["python", "node", "bash"] + capability_names or name not in resolved_tools:
            fail("undeclared capability closure group: " + name)
        if any([path not in store_inputs for path in group["roots"]]) or any([path not in declared_inventory_files for path in group["files"]]):
            fail("capability closure contains undeclared inputs: " + name)
    interpreter_summary = {}
    for name, group in interpreter_groups.items():
        ctx.file(name + "-store-paths", "\n".join(group["roots"]) + "\n")
        ctx.file(name + "-registration", group["registration"])
        interpreter_summary[name] = {"roots": group["roots"], "file_count": len(group["files"])}
    ctx.file("interpreter-closures.json", json.encode_indent({"schemaVersion": 1, "groups": interpreter_summary}, indent = "  ") + "\n")
    if "codex_metadata_query" in interpreter_groups:
        ctx.file("codex-metadata-query-tools.json", json.encode(selection_report["query_tools"]) + "\n")
    closure_files = [path for path in inventory_files if path.startswith("closure/") or path.startswith("packages/")]
    zig_framework_files = [path for path in closure_files if zig_framework_prefix and path.startswith(zig_framework_prefix)]
    if zig_framework_prefix and not zig_framework_files:
        fail("declared Darwin public framework search root has no inventoried files")
    zig_sdk_library_files = [path for path in closure_files if zig_sdk_library_prefix and path.startswith(zig_sdk_library_prefix) and path.endswith(".tbd")]
    if zig_sdk_library_prefix and zig_sdk_library_prefix + "libobjc.A.tbd" not in zig_sdk_library_files:
        fail("declared Darwin Objective-C dependency stub is not an inventoried action input")
    runtime_files = [path for path in closure_files if path.endswith(".dylib") or path.endswith(".so") or ".so." in path]
    runtime_library_files = [path for path in inventory_files if path.startswith("runtime_closure/") and (path.endswith(".dylib") or path.endswith(".so") or ".so." in path)]
    qt_runtime_files = [path for path in inventory_files if path.startswith("qt_runtime_closure/") and ("/lib/" in path or "/lib64/" in path) and "/plugins/" not in path and (path.endswith(".dylib") or path.endswith(".so") or ".so." in path)]

    shell = _store_path(packages["bash"]["out"] + "/bin/bash", "bash executable")
    for name in ["cc", "cxx", "ar", "linker", "nm", "strip", "objcopy", "objdump", "gcov", "dwp"]:
        path = native.get(name)
        if not path and name in ["objdump", "dwp"]:
            path = _first_existing(ctx, ["/".join(native["ar"].split("/")[:-1]) + "/" + name])
        if path:
            path = _store_path(path, name + " executable")
            if not ctx.path(path).exists:
                fail("declared compiler tool is unavailable: " + path)
            if name in ["cc", "cxx"]:
                body = "#!{}\nset -eu\nomux_action_root=\"$(pwd -P)\"\nexec {} \"-ffile-prefix-map=$omux_action_root=.\" \"-fdebug-prefix-map=$omux_action_root=.\" \"$@\"\n".format(shell, _quote(path))
            else:
                body = "#!{}\nset -eu\nexec {} \"$@\"\n".format(shell, _quote(path))
        else:
            # Missing optional tools fail explicitly instead of finding a host binary.
            body = "#!{}\nprintf '%s\\n' 'native closure does not declare {}' >&2\nexit 127\n".format(shell, name)
        ctx.file("tool_wrappers/" + name, body, executable = True)

    includes = native.get("builtin_include_directories", [])
    if not includes:
        for key in ["libc_headers", "gcc_headers"]:
            paths = native.get(key, [])
            if type(paths) == "string":
                paths = [paths]
            includes.extend(paths)
    if not includes:
        fail("native manifest must declare builtin_include_directories (or libc_headers/gcc_headers); host headers are forbidden")
    for path in includes:
        _store_path(path, "builtin include directory")
        if not ctx.path(path).exists:
            fail("declared builtin include directory is unavailable: " + path)

    systemctl = native.get("tools", {}).get("systemctl")
    tool_defines = []
    header = "#pragma once\n"
    if systemctl:
        systemctl = _store_path(systemctl, "systemctl executable")
        # rules_cc tokenizes defines before constructing compiler argv. Preserve
        # the C string's quotes through that tokenizer rather than losing them.
        tool_defines.append("OMUX_SYSTEMCTL_PATH=" + json.encode(systemctl).replace("\\", "\\\\").replace('"', '\\"'))
        header += "#define OMUX_SYSTEMCTL_PATH " + json.encode(systemctl) + "\n"
    ctx.file("runtime_tool_paths.h", header)

    build = [
        'load("@rules_cc//cc:cc_import.bzl", "cc_import")',
        'load("@rules_cc//cc:cc_library.bzl", "cc_library")',
        'load("@rules_cc//cc/toolchains:cc_toolchain.bzl", "cc_toolchain")',
        'load(":nix_cc_toolchain.bzl", "omux_cc_toolchain_config", "omux_nix_tool")',
        'package(default_visibility = ["//visibility:public"])',
        # Nix closures include example systemd filenames with literal backslashes,
        # which Bazel cannot represent as labels. They are not compiler inputs.
        'CLOSURE_FILES = {} + glob(["tool_wrappers/*"], allow_empty = True)'.format(repr(closure_files)),
        'exports_files(["native.json", "file-inventory.json", "store-paths", "registration", "runtime-store-paths", "qt-runtime-store-paths", "tool_paths.bzl", "runtime_tool_paths.h", "interpreter-closures.json"] + {} + glob(["tool_wrappers/*"], allow_empty = True))'.format(repr([name + suffix for name in interpreter_groups for suffix in ["-store-paths", "-registration"]])),
        'filegroup(name = "closure_metadata", srcs = ["native.json", "file-inventory.json", "store-paths", "registration", "runtime-store-paths", "qt-runtime-store-paths"])',
        'filegroup(name = "all_tools", srcs = CLOSURE_FILES + ["native.json", "file-inventory.json", "store-paths", "registration"])',
        'filegroup(name = "zig_framework_inputs", srcs = {})'.format(repr(zig_framework_files)),
        'filegroup(name = "zig_sdk_library_inputs", srcs = {})'.format(repr(zig_sdk_library_files)),
        'filegroup(name = "all_headers", srcs = {})'.format(repr([path for path in closure_files if path.endswith(".h") or path.endswith(".hpp") or path.endswith(".inc")])),
        'filegroup(name = "runtime", srcs = {})'.format(repr(runtime_files)),
        'filegroup(name = "runtime_libraries", srcs = {})'.format(repr(runtime_library_files)),
        'filegroup(name = "qt_runtime_libraries", srcs = {})'.format(repr(qt_runtime_files)),
        'filegroup(name = "qt_platform_plugins", srcs = {})'.format(repr(qt_platform_plugins)),
        'filegroup(name = "qt_offscreen_plugin", srcs = {})'.format(repr([path for path in qt_platform_plugins if path.endswith("/libqoffscreen.so")])),
        'filegroup(name = "dynamic_linker", srcs = {})'.format(repr(dynamic_linker_files)),
        'filegroup(name = "ca_bundle", srcs = ["packages/cacert/out/etc/ssl/certs/ca-bundle.crt"])',
        'cc_library(name = "runtime_tool_paths", hdrs = ["runtime_tool_paths.h"], includes = ["."], defines = {})'.format(repr(tool_defines)),
        'omux_cc_toolchain_config(name = "config", system = {}, builtin_include_directories = {}, executable_search_path = {})'.format(repr(system), repr(includes), repr(_store_path(packages["coreutils"]["out"], "coreutils.out") + "/bin")),
        'cc_toolchain(name = "cc_toolchain", toolchain_identifier = {}, toolchain_config = ":config", all_files = ":all_tools", ar_files = ":all_tools", as_files = ":all_tools", compiler_files = ":all_tools", dwp_files = ":all_tools", linker_files = ":all_tools", objcopy_files = ":all_tools", strip_files = ":all_tools", supports_param_files = 1)'.format(repr("omux-nix-" + system)),
        'toolchain(name = "toolchain", toolchain_type = "@bazel_tools//tools/cpp:toolchain_type", toolchain = ":cc_toolchain", exec_compatible_with = {constraints}, target_compatible_with = {constraints})'.format(constraints = repr([
            "@platforms//cpu:" + ("aarch64" if system.startswith("aarch64-") else "x86_64"),
            "@platforms//os:" + ("macos" if system.endswith("-darwin") else "linux"),
        ])),
        'platform(name = "execution_platform", constraint_values = {constraints}, exec_properties = {properties})'.format(
            constraints = repr([
                "@platforms//cpu:" + ("aarch64" if system.startswith("aarch64-") else "x86_64"),
                "@platforms//os:" + ("macos" if system.endswith("-darwin") else "linux"),
            ]),
            properties = repr({"nix_closure": root.split("/")[-1]}),
        ),
    ]
    for name, group in interpreter_groups.items():
        wrappers = (["codex-metadata-query-tools.json"] if name == "codex_metadata_query" else
                    ["tool_wrappers/bash"] if name == "bash" else ["tool_wrappers/" + name, "tool_wrappers/bash"])
        build.append('filegroup(name = {}, srcs = {})'.format(
            repr(name + "_tools"),
            repr(group["files"] + wrappers + ["native.json", "interpreter-closures.json", name + "-store-paths", name + "-registration"]),
        ))
    if "codex_metadata_query" in interpreter_groups:
        build.append('exports_files(["codex-metadata-query-tools.json"])')
    for name, spec in _PACKAGES.items():
        if name not in packages:
            continue
        pkg = packages[name]
        library_deps = []
        for library in spec.libraries:
            found = _library(ctx, pkg, library)
            imported_path = "libraries/" + name + "/" + found.source.split("/")[-1]
            ctx.symlink(found.source, imported_path)
            label = "_" + name + "_" + library.replace("-", "_").replace(".", "_")
            build.append('cc_import(name = {}, {} = {})'.format(repr(label), found.attribute, repr(imported_path)))
            library_deps.append(":" + label)
        public_headers = []
        include_dirs = []
        header_roots = []
        for output_name in ["dev", "lib", "out"]:
            if output_name not in pkg:
                continue
            relative = "packages/{}/{}".format(name, output_name)
            for directory in spec.includes:
                if ctx.path(pkg[output_name] + "/" + directory).exists:
                    include_dirs.append(relative + "/" + directory)
                    header_roots.append(relative + "/" + directory + "/**")
            for header in spec.headers:
                if ctx.path(pkg[output_name] + "/include/" + header).exists:
                    public_headers.append(relative + "/include/" + header)
        library_deps += [":" + dependency for dependency in spec.deps if dependency in packages]
        if name == "qt":
            library_deps.append(":runtime_tool_paths")
        build.append('cc_library(name = {}, hdrs = {}, textual_hdrs = {}, includes = {}, deps = {}, data = [":runtime"])'.format(
            repr(name), repr(public_headers), repr([path for path in closure_files if any([path.startswith(directory + "/") for directory in include_dirs])]), repr(include_dirs), repr(library_deps),
        ))

    for name, executable in resolved_tools.items():
        ctx.file("tool_wrappers/" + name, "#!{}\nset -eu\nexec {} \"$@\"\n".format(shell, _quote(executable)), executable = True)
        tool_closure = ":" + name + "_tools" if name in interpreter_groups else ":all_tools"
        build.append('omux_nix_tool(name = {}, script = {}, executable_path = {}, closure = {})'.format(repr(name), repr("tool_wrappers/" + name), repr(executable), repr(tool_closure)))
        if name == "patchelf":
            # The capability selector already requires this exact executable to
            # be registered and inventoried. FD-bound callers need its raw ELF.
            build.append('filegroup(name = "patchelf_native", srcs = {})'.format(repr(["closure/" + executable[len("/nix/store/"):]])))
    if "bash" not in resolved_tools or "bash" not in interpreter_groups:
        fail("minimal interpreted launchers require the declared Bash tool and closure")
    build.append('omux_nix_tool(name = "interpreter_bash", script = "tool_wrappers/bash", executable_path = {}, closure = ":bash_tools")'.format(repr(resolved_tools["bash"])))
    ctx.file("tool_paths.bzl", "\n".join([
        '"""Immutable tool paths exported by the declared flake closure."""',
        "NIX_BASH = " + repr(shell),
        "NIX_PYTHON = " + repr(resolved_tools.get("python")),
        "NIX_NODE = " + repr(resolved_tools.get("node")),
        "NIX_PATCHELF = " + repr(resolved_tools.get("patchelf")),
        "NIX_SYSTEMCTL = " + repr(resolved_tools.get("systemctl")),
        "NIX_SSH = " + repr(resolved_tools.get("ssh")),
        "NIX_DBUS_DAEMON = " + repr(resolved_tools.get("dbus_daemon")),
        "NIX_DBUS_RUN_SESSION = " + repr(resolved_tools.get("dbus_run_session")),
        "NIX_GNOME_KEYRING_DAEMON = " + repr(resolved_tools.get("gnome_keyring_daemon")),
        "NIX_SECRET_TOOL = " + repr(resolved_tools.get("secret_tool")),
        "NIX_COREUTILS_BIN = " + repr(packages["coreutils"]["out"] + "/bin" if "coreutils" in packages else None),
        "NIX_CLOSURE = " + repr(root),
        "NIX_ZIG_ROOTOPTS = " + repr(zig_rootopts),
        "NIX_ZIG_LINKOPTS = " + repr(zig_linkopts),
        "NIX_ZIG_SDK_INPUTS = " + repr(["@omux_nix//:zig_framework_inputs", "@omux_nix//:zig_sdk_library_inputs"] if zig_framework_prefix else []),
    ]) + "\n")
    ctx.file("BUILD.bazel", "\n\n".join(build) + "\n")

omux_nix_repository = repository_rule(
    implementation = _nix_repo_impl,
    attrs = {
        "closure": attr.string(doc = "Explicit flake closure output; otherwise OMUX_BAZEL_CLOSURE."),
        "bootstrap_closure": attr.string(doc = "Host-compatible inventory bootstrap closure; otherwise OMUX_BAZEL_BOOTSTRAP_CLOSURE or the execution closure."),
        "toolchain_rule": attr.label(default = Label("//tools:nix_cc_toolchain.bzl"), allow_single_file = True),
        "file_inventory": attr.label(default = Label("//tools:nix_file_inventory.py"), allow_single_file = True),
        "interpreter_closure": attr.label(default = Label("//tools:nix_interpreter_closure.py"), allow_single_file = True),
    },
    environ = ["OMUX_BAZEL_CLOSURE", "OMUX_BAZEL_BOOTSTRAP_CLOSURE"],
    local = True,
)
