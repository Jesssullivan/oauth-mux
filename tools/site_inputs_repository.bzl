"""Read-only operator-selected public sibling inputs; never invokes a tool.

The copied bytes become declared Bazel inputs. The operator must separately bind
the chosen inventory/lock SHA256 digests when requesting inventory evidence.
"""

_INPUTS = {
    "flake.lock": "flake.lock",
    "flake.nix": "flake.nix",
    "offline-site-roots.json": "tools/offline-site-roots.json",
    "tool-selection.nix": "tools/tool-selection.nix",
}

def _implementation(ctx):
    root = ctx.os.environ.get("OMUX_SITE_SOURCE", "")
    if not root.startswith("/") or root == "/" or "\\" in root or "\n" in root or "\r" in root:
        fail("OMUX_SITE_SOURCE must name an explicit absolute sibling checkout")
    components = root.split("/")[1:]
    if any([part in ["", ".", ".."] for part in components]):
        fail("OMUX_SITE_SOURCE must have no traversal or empty components")
    for output, relative in _INPUTS.items():
        source = ctx.path(root + "/" + relative)
        # Explicit watch is limited to these public inputs. The checkout
        # directory, credentials and arbitrary application sources are not read.
        ctx.watch(source)
        if not source.exists:
            fail("Declared public site input is absent: " + relative)
        content = ctx.read(source, watch = "no")
        if len(content) > 1048576:
            fail("Declared public site input exceeds 1 MiB: " + relative)
        ctx.file(output, content, executable = False)
    ctx.file("BUILD.bazel", """package(default_visibility = ["//visibility:public"])
exports_files(["flake.lock", "flake.nix", "offline-site-roots.json", "tool-selection.nix"])
filegroup(name = "site_lock", srcs = ["flake.lock"])
filegroup(name = "site_flake", srcs = ["flake.nix"])
filegroup(name = "site_roots", srcs = ["offline-site-roots.json"])
filegroup(name = "site_selection", srcs = ["tool-selection.nix"])
""", executable = False)

site_inputs_repository = repository_rule(
    implementation = _implementation,
    environ = ["OMUX_SITE_SOURCE"],
    local = True,
)
