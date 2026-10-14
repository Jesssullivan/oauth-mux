"""Declared coordinator tools; never part of the application runtime closure."""

_HOST_TOOLS = {"python": "/bin/python3", "bash": "/bin/bash", "nix": "/bin/nix", "nix_store": "/bin/nix-store", "ssh": "/bin/ssh", "git": "/bin/git"}

def _immutable(value, description):
    if type(value) != "string" or not value.startswith("/nix/store/") or "/../" in value or "\n" in value or "\r" in value:
        fail(description + " must be an immutable absolute Nix store path")
    return value

def _quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"

def _host_tools_impl(ctx):
    requested = ctx.attr.requested_tools
    if not requested or len({name: True for name in requested}) != len(requested):
        fail("requested host tools must be a nonempty distinct capability list")
    unknown = [name for name in requested if name not in _HOST_TOOLS]
    if unknown:
        fail("unknown host tool capabilities: " + ", ".join(unknown))
    if "nix_store" in requested and "nix" not in requested:
        fail("nix_store requires the same explicit Nix package capability")
    if "python" not in requested or "bash" not in requested:
        fail("host inventory and wrappers require explicit python and bash capabilities")
    root = _immutable(ctx.attr.closure or ctx.os.environ.get("OMUX_BAZEL_BOOTSTRAP_CLOSURE"), "host bootstrap closure")
    manifest = ctx.path(root + "/native.json")
    paths = ctx.path(root + "/store-paths")
    registration = ctx.path(root + "/registration")
    for path in [manifest, paths, registration]:
        if not path.exists:
            fail("host bootstrap metadata is unavailable: " + str(path))
        ctx.watch(path)
    native = json.decode(ctx.read(manifest))
    os = {"linux": "linux", "mac os x": "darwin"}.get(ctx.os.name.lower())
    cpu = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(ctx.os.arch.lower())
    if not os or not cpu or native.get("system") != cpu + "-" + os:
        fail("host bootstrap closure must match the coordinator OS and CPU")
    roots = {}
    for entry in ctx.read(paths).split("\n"):
        if not entry:
            continue
        entry = _immutable(entry, "host closure entry")
        if len(entry.split("/")) != 4 or not ctx.path(entry).exists:
            fail("host closure root is invalid or unavailable: " + entry)
        roots[entry] = True
        ctx.symlink(entry, "closure/" + entry.split("/")[3])
    if not roots:
        fail("host bootstrap closure must declare its transitive store inputs")
    packages = native.get("packages", {})
    declared = native.get("tools", {})
    tools = {}
    for name in requested:
        suffix = _HOST_TOOLS[name]
        package = "openssh" if name == "ssh" else ("nix" if name == "nix_store" else name)
        output = packages.get(package, {}).get("out")
        candidate = declared.get(name) or (output + suffix if output else None)
        candidate = _immutable(candidate, "host " + name)
        if "/".join(candidate.split("/")[:4]) not in roots or not ctx.path(candidate).exists:
            fail("host " + name + " must belong to the complete bootstrap closure")
        tools[name] = candidate
    exports = ["native.json", "store-paths", "registration", "file-inventory.json"]
    for name, executable in tools.items():
        raw = "executables/" + name
        ctx.symlink(executable, raw)
        exports.append(raw)
    if ctx.attr.require_ca:
        ca_output = _immutable(packages.get("cacert", {}).get("out"), "host certificate output")
        ca_bundle = ca_output + "/etc/ssl/certs/ca-bundle.crt"
        if ca_output not in roots or not ctx.path(ca_bundle).exists:
            fail("host CA bundle must belong to the complete bootstrap closure")
        ctx.symlink(ca_bundle, "ca-bundle.crt")
        exports.append("ca-bundle.crt")
    ctx.file("native.json", ctx.read(manifest))
    ctx.file("store-paths", "\n".join(sorted(roots.keys())) + "\n")
    ctx.file("registration", ctx.read(registration))
    ctx.watch(ctx.path(ctx.attr.file_inventory))
    inventory = ctx.execute([tools["python"], "-I", "-S", ctx.path(ctx.attr.file_inventory), str(ctx.path(".")), "closure"], timeout = 600)
    if inventory.return_code:
        fail("declared host closure inventory failed: " + inventory.stderr)
    report = json.decode(inventory.stdout)
    ctx.file("file-inventory.json", json.encode_indent(report, indent = "  ") + "\n")
    seed_files = []
    if "nix_store" in requested:
        # Explicit local-build capability only. Read NAR node metadata with
        # pinned Python; never consult the shared Nix DB or invoke Nix here.
        for path in [ctx.attr.seed_descriptor, ctx.attr.nar_descriptor, ctx.attr.registration_parser]:
            ctx.watch(ctx.path(path))
        bootstrap = "import importlib.util,sys,runpy; " + \
            "paths=sys.argv[1:4]; sys.argv=sys.argv[3:]; " + \
            "spec=importlib.util.spec_from_file_location('nar_descriptor',paths[0]); " + \
            "module=importlib.util.module_from_spec(spec); sys.modules['nar_descriptor']=module; spec.loader.exec_module(module); " + \
            "spec=importlib.util.spec_from_file_location('nix_interpreter_closure',paths[1]); " + \
            "module=importlib.util.module_from_spec(spec); sys.modules['nix_interpreter_closure']=module; spec.loader.exec_module(module); " + \
            "runpy.run_path(paths[2],run_name='__main__')"
        described = ctx.execute([tools["python"], "-I", "-S", "-c", bootstrap,
            ctx.path(ctx.attr.nar_descriptor), ctx.path(ctx.attr.registration_parser),
            ctx.path(ctx.attr.seed_descriptor), ctx.path("native.json"),
            ctx.path("store-paths"), ctx.path("registration")], timeout = 600)
        if described.return_code:
            fail("declared private-store seed metadata refused")
        seed = json.decode(described.stdout)
        if seed.get("kind") != "omux-nix-private-store-seed-v1":
            fail("private-store seed schema")
        if seed["tools"] != {name: tools[name] for name in ["bash", "nix", "nix_store"]}:
            fail("private-store tools must match their exact selected bootstrap package")
        for row in seed["files"]:
            source = ctx.path(row["source"])
            if not source.exists or source.is_dir or str(source.realpath) != row["source"]:
                fail("private-store regular source redirects or is absent")
            ctx.watch(source)
            ctx.symlink(source, row["alias"])
            seed_files.append(row["alias"])
        ctx.file("private-store-seed.json", described.stdout)
        exports.append("private-store-seed.json")
    build = [
        'load("@//tools:nix_cc_toolchain.bzl", "omux_nix_tool")',
        'package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(repr(exports)),
        'filegroup(name = "all_tools", srcs = {} + ["native.json", "store-paths", "registration", "file-inventory.json"] + glob(["wrappers/*"]))'.format(repr(report["files"])),
    ]
    if seed_files:
        build.append('filegroup(name = "private_store_seed", srcs = {} + ["private-store-seed.json", "native.json", "store-paths", "registration", "file-inventory.json"])'.format(repr(seed_files)))
    for name, executable in tools.items():
        wrapper = "wrappers/" + name
        ctx.file(wrapper, "#!{}\nset -eu\nexec {} \"$@\"\n".format(tools["bash"], _quote(executable)), executable = True)
        build.append('omux_nix_tool(name = {}, script = {}, executable_path = {}, closure = ":all_tools")'.format(repr(name), repr(wrapper), repr(executable)))
    ctx.file("BUILD.bazel", "\n\n".join(build) + "\n")

omux_host_tools_repository = repository_rule(
    implementation = _host_tools_impl,
    attrs = {
        "closure": attr.string(doc = "Host bootstrap closure; otherwise OMUX_BAZEL_BOOTSTRAP_CLOSURE."),
        "file_inventory": attr.label(default = Label("//tools:nix_file_inventory.py"), allow_single_file = True),
        "requested_tools": attr.string_list(default = ["python", "bash", "nix", "ssh", "git"], doc = "Explicit coordinator capabilities; python/bash are required for declared inventory/wrappers."),
        "seed_descriptor": attr.label(default = Label("//tools:nix_private_store_seed.py"), allow_single_file = True),
        "nar_descriptor": attr.label(default = Label("//tools:nar_descriptor.py"), allow_single_file = True),
        "registration_parser": attr.label(default = Label("//tools:nix_interpreter_closure.py"), allow_single_file = True),
        "require_ca": attr.bool(default = True, doc = "Require the declared CA bundle; false is reserved for local-only capability-scoped evaluation."),
    },
    environ = ["OMUX_BAZEL_BOOTSTRAP_CLOSURE"],
    local = True,
)
