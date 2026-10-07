"""Declared coordinator tools; never part of the application runtime closure."""

_HOST_TOOLS = {"python": "/bin/python3", "bash": "/bin/bash", "nix": "/bin/nix", "ssh": "/bin/ssh", "git": "/bin/git"}

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
        package = "openssh" if name == "ssh" else name
        output = packages.get(package, {}).get("out")
        candidate = declared.get(name) or (output + suffix if output else None)
        candidate = _immutable(candidate, "host " + name)
        if "/".join(candidate.split("/")[:4]) not in roots or not ctx.path(candidate).exists:
            fail("host " + name + " must belong to the complete bootstrap closure")
        tools[name] = candidate
    exports = ["native.json", "store-paths"]
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
    build = [
        'load("@//tools:nix_cc_toolchain.bzl", "omux_nix_tool")',
        'package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(repr(exports)),
        'filegroup(name = "all_tools", srcs = {} + ["native.json", "store-paths", "registration", "file-inventory.json"] + glob(["wrappers/*"]))'.format(repr(report["files"])),
    ]
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
        "require_ca": attr.bool(default = True, doc = "Require the declared CA bundle; false is reserved for local-only capability-scoped evaluation."),
    },
    environ = ["OMUX_BAZEL_BOOTSTRAP_CLOSURE"],
    local = True,
)
