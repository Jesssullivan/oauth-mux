"""Declare one finite pinned public C11 source and reviewed dependency patch."""
_PARENT = "/home/jess/.local/state/omux-execution-20261005/cache-v2-4689a690587ec00080acae0eb6ba13df894a284b47e0ce7a6ee828bed0cb8d9d/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_live_source_producer/test.outputs/codex-live-source"
_PATCH = "/srv/fast-local/jess/git/oauth-mux/docs/agent-notes/2026-10-07-native-protocol-history-edge-formatted.UNAPPLIED.native.patch"

def _implementation(ctx):
    parent_receipt = ctx.path(_PARENT + "/source-receipt.json")
    if not parent_receipt.exists or parent_receipt.is_dir or str(parent_receipt.realpath) != str(parent_receipt):
        fail("protocol-history parent receipt redirected or absent")
    raw = ctx.read(parent_receipt)
    report = json.decode(raw)
    if len(raw) != 1589582 or report.get("status") != "verified-fresh-native-candidate" or report.get("commit") != "00c972ed5d6ff6499317fd41b7f23605b8e6850d" or report.get("inventory_sha256") != "5e7628d20807b41c795d08d2ed6f0e6107d394b718f25dd22e9705206c38cc69":
        fail("fixed protocol-history parent source metadata differs")
    files = report.get("source_inventory", {})
    if len(files) != 8549 or report.get("tracked_files") != 8549:
        fail("fixed protocol-history parent source count differs")
    source_root = ctx.path(_PARENT + "/source")
    if not source_root.exists or not source_root.is_dir or str(source_root.realpath) != str(source_root):
        fail("protocol-history source root redirected or absent")
    names = []
    for index, name in enumerate(sorted(files)):
        if name.startswith("/") or any([part in ["", ".", ".."] for part in name.split("/")]) or any([character in name for character in ["\\", "\n", "\r", "\t"]]):
            fail("protocol-history source input path is noncanonical")
        if files[name].get("mode") not in ["100644", "100755", "120000"]:
            fail("protocol-history source input mode differs")
        target = ctx.path(_PARENT + "/source/" + name)
        if not target.exists or target.is_dir:
            fail("protocol-history source input absent or nonfile")
        resolved = str(target.realpath)
        if files[name].get("mode") == "120000":
            prefix = str(source_root) + "/"
            if not resolved.startswith(prefix):
                fail("protocol-history source link leaves selected root")
            member = resolved[len(prefix):]
            if member not in files or files[member].get("mode") not in ["100644", "100755"]:
                fail("protocol-history source link target is not selected regular member")
        elif resolved != str(target):
            fail("protocol-history regular input or ancestor redirected")
        ctx.watch(target)
        alias = "source-inputs/" + str(index)
        ctx.symlink(target, alias)
        names.append(alias)
    ctx.watch(parent_receipt)
    ctx.symlink(parent_receipt, "parent-source-receipt.json")
    names.append("parent-source-receipt.json")
    patch = ctx.path(_PATCH)
    if not patch.exists or patch.is_dir or str(patch.realpath) != str(patch):
        fail("protocol-history reviewed patch absent or redirected")
    ctx.watch(patch)
    ctx.symlink(patch, "protocol-history.patch")
    names.append("protocol-history.patch")
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(repr(names)),
        'filegroup(name = "inputs", srcs = {})'.format(repr(names)),
        "",
    ]), executable = False)

codex_protocol_history_source_inputs = repository_rule(implementation = _implementation, local = True)
