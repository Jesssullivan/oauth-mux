"""Inert explicitly guarded retained runtime009 file declaration.

No execution, download, payload hash, directory scan or operator mutation.
Guard performs no-follow custody/hash admission; declared consumers keep pins.
"""
VARIABLE = "OMUX_CODEX_OWNER_RUNTIME_DIRECTORY"
DIGEST = "0094334d7fd27b81f613ebe734305412bd13f95f1f3396ba2f0396168e5223ad"
_NUL = json.decode('"\\u0000"')

def _implementation(ctx):
    root = ctx.os.environ.get(VARIABLE, "")
    if not root.startswith("/") or root.endswith("/") or any([part in ["", ".", ".."] for part in root.split("/")[1:]]) or any([char in root for char in ["\\", "\n", "\r", _NUL]]) or root.rsplit("/", 1)[-1] != DIGEST:
        fail("explicit guarded digest-named retained runtime directory required")
    selected = ctx.path(root)
    if not selected.exists or not selected.is_dir or str(selected.realpath) != root:
        fail("retained runtime physical directory absent or linked")
    archive = ctx.path(root + "/codex-owner-runtime.tar.gz")
    if not archive.exists or archive.is_dir or str(archive.realpath) != str(archive):
        fail("retained runtime regular input absent or linked")
    ctx.watch(selected)
    ctx.watch(archive)
    ctx.symlink(archive, "codex-owner-runtime.tar.gz")
    ctx.file("BUILD.bazel", 'package(default_visibility = ["//visibility:public"])\nexports_files(["codex-owner-runtime.tar.gz"])\n', executable = False)

codex_owner_runtime_repository = repository_rule(
    implementation = _implementation,
    environ = [VARIABLE],
    local = True,
)
