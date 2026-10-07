"""Read-only declaration of the frozen candidate's finite Rust/C input set."""

def _implementation(ctx):
    root = ctx.os.environ.get("OMUX_CODEX_RECOVERY_SOURCE", "")
    if not root.startswith("/") or root == "/" or any([char in root for char in ["\\", "\n", "\r"]]):
        fail("OMUX_CODEX_RECOVERY_SOURCE must select an explicit absolute SDK source directory")
    if any([part in ["", ".", ".."] for part in root.split("/")[1:]]):
        fail("recovery source directory must have no traversal or empty components")
    manifest = json.decode(ctx.read(ctx.attr.manifest))
    if manifest.get("upstream_commit") != "00c972ed5d6ff6499317fd41b7f23605b8e6850d" or manifest.get("patch_sha256") != "2e5542c5f6a44e3a8dd38b4a4093d1735ff19771721b05fc51f55b475b1a8d46":
        fail("recovery source selection requires the exact frozen owner candidate")
    names = sorted([name for name in manifest["files"] if name.endswith(".rs") or name.endswith(".c") or name.endswith(".h")])
    if not names or len(names) > 128:
        fail("recovery source code allowlist exceeds bound")
    for name in names:
        if not name.startswith("codex-rs/") or any([char in name for char in ["\\", "\n", "\r", "\t"]]) or any([part in ["", ".", ".."] for part in name.split("/")]):
            fail("recovery source path is outside the code boundary")
        source = ctx.path(root + "/" + name)
        ctx.watch(source)
        if not source.exists:
            fail("declared recovery code input is absent: " + name)
        ctx.symlink(source, name)
    ctx.file("source-input-anchor.txt", "Declared manifest-owned Rust/C recovery inputs only.\n", executable = False)
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files(["source-input-anchor.txt"])',
        'filegroup(name = "code_inputs", srcs = {})'.format(repr(names)),
        "",
    ]), executable = False)

codex_recovery_inputs = repository_rule(
    implementation = _implementation,
    attrs = {"manifest": attr.label(default = Label("//integrations/codex-owner-candidate:manifest.json"), allow_single_file = True)},
    environ = ["OMUX_CODEX_RECOVERY_SOURCE"],
    local = True,
)
