"""Declare four explicit retained public Codex source artifacts without execution.

The guard must admit canonical, owned regular files at the exact recorded sizes
before repository evaluation. Starlark has no no-follow regular-file stat API;
ctx.read below reads only the two bounded, pre-admitted receipt files. Payload
hashes and all fixed SHA256 values are verified by the fresh-source action.
This repository does not discover paths, enumerate directories or mutate caches.
"""

_PRISTINE = "OMUX_CODEX_PRISTINE_DIRECTORY"
_RECOVERY = "OMUX_CODEX_RECOVERY_DELTA_DIRECTORY"
_FILES = {
    _PRISTINE: ["pristine.tar.gz", "pristine-receipt.json"],
    _RECOVERY: ["recovery-delta.patch", "recovery-delta-receipt.json"],
}
_RECEIPT_BYTES = {
    "pristine-receipt.json": 1574870,
    "recovery-delta-receipt.json": 24651,
}
_COMMIT = "00c972ed5d6ff6499317fd41b7f23605b8e6850d"

def _directory(ctx, variable):
    root = ctx.os.environ.get(variable, "")
    if not root.startswith("/") or root == "/" or any([character in root for character in ["\\", "\n", "\r"]]):
        fail(variable + " must name an explicit absolute retained artifact directory")
    if any([component in ["", ".", ".."] for component in root.split("/")[1:]]):
        fail(variable + " must be canonical without traversal or empty components")
    path = ctx.path(root)
    if not path.exists or not path.is_dir or str(path.realpath) != root:
        fail(variable + " must name an existing canonical real directory")
    return root

def _implementation(ctx):
    for variable, names in _FILES.items():
        root = _directory(ctx, variable)
        for name in names:
            source = ctx.path(root + "/" + name)
            if not source.exists or source.is_dir or str(source.realpath) != str(source):
                fail("Retained source artifact must exist without links: " + name)
            ctx.watch(source)
            if name in _RECEIPT_BYTES:
                content = ctx.read(source, watch = "no")
                if len(content) != _RECEIPT_BYTES[name]:
                    fail("Retained source receipt size changed: " + name)
                receipt = json.decode(content)
                if receipt.get("commit") != _COMMIT or receipt.get("native_support") != False:
                    fail("Retained source receipt scope changed: " + name)
                if name == "pristine-receipt.json":
                    if receipt.get("status") != "verified-pristine-source" or receipt.get("archive_sha256") != "dbe1a1ec6ce7c6a981b5adf2410be4ae68f8bc906b1dec6b5e65a78efbc3292d":
                        fail("Retained pristine source receipt changed")
                elif receipt.get("status") != "scoped-source-delta-awaiting-review" or receipt.get("patch_sha256") != "aa4bc7f3cdd281a34096260ff60dd17dfdc892c55e59e282989110383e701cf5":
                    fail("Retained recovery delta receipt changed")
            ctx.symlink(source, name)
    ctx.file("BUILD.bazel", """package(default_visibility = ["//visibility:public"])
exports_files(["pristine.tar.gz", "pristine-receipt.json", "recovery-delta.patch", "recovery-delta-receipt.json"])
filegroup(name = "inputs", srcs = ["pristine.tar.gz", "pristine-receipt.json", "recovery-delta.patch", "recovery-delta-receipt.json"])
""", executable = False)

codex_source_artifacts_repository = repository_rule(
    implementation = _implementation,
    environ = [_PRISTINE, _RECOVERY],
    local = True,
)
