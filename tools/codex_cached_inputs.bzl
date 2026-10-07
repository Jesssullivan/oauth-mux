"""Declare exactly three operator-selected public Codex Git pack inputs.

This rule never executes Git, hashes payloads, fetches data, walks a mirror or
mutates operator state. The declared pristine producer verifies fixed digests.
"""

_PACK_STEM = "pack-c4c9ce7cd275c2c4f91c442087b9738342ae193a"

def _implementation(ctx):
    root = ctx.os.environ.get("OMUX_CODEX_PACK_DIRECTORY", "")
    if not root.startswith("/") or root == "/" or any([char in root for char in ["\\", "\n", "\r"]]):
        fail("OMUX_CODEX_PACK_DIRECTORY must name an explicit absolute pack directory")
    if any([part in ["", ".", ".."] for part in root.split("/")[1:]]):
        fail("OMUX_CODEX_PACK_DIRECTORY must have no traversal or empty components")
    names = []
    for extension in ["pack", "idx", "rev"]:
        name = _PACK_STEM + "." + extension
        source = ctx.path(root + "/" + name)
        ctx.watch(source)
        if not source.exists:
            fail("Declared Codex pack input is absent: " + name)
        ctx.symlink(source, name)
        names.append(name)
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(repr(names)),
        'filegroup(name = "pack", srcs = ["' + names[0] + '"])',
        'filegroup(name = "idx", srcs = ["' + names[1] + '"])',
        'filegroup(name = "rev", srcs = ["' + names[2] + '"])',
        'filegroup(name = "pack_files", srcs = {})'.format(repr(names)),
        "",
    ]), executable = False)

codex_cached_inputs = repository_rule(
    implementation = _implementation,
    environ = ["OMUX_CODEX_PACK_DIRECTORY"],
    local = True,
)
