"""Declare only actual N3 source for a distinct metadata/SDK input binding."""
_ROOT = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/95f10057-c0be-4a94-98f8-291dedec0d48/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_owner_status_persistence_source_producer/test.outputs/owner-status-persistence-source"

def _implementation(ctx):
    root = ctx.path(_ROOT)
    receipt = ctx.path(_ROOT + "/source-receipt.json")
    if not root.exists or not root.is_dir or str(root.realpath) != str(root) or not receipt.exists or receipt.is_dir or str(receipt.realpath) != str(receipt):
        fail("N3 binding physical source absent or redirected")
    raw = ctx.read(receipt)
    report = json.decode(raw)
    files = report.get("source_inventory", {})
    if len(raw) != 1592382 or report.get("kind") != "omux-owner-status-persistence-source-v1" or report.get("status") != "verified-owner-status-persistence-source-pending-sdk-and-schema" or report.get("inventory_sha256") != "252599e5faafa05e2ff688e57e58d1890aea57ead0f35ce0633588754cae5030" or len(files) != 8549:
        fail("N3 binding source metadata differs")
    names = []
    for index, name in enumerate(sorted(files)):
        if name.startswith("/") or any([part in ["", ".", ".."] for part in name.split("/")]) or any([c in name for c in ["\\", "\n", "\r", "\t"]]):
            fail("N3 binding source path is noncanonical")
        row = files[name]
        path = ctx.path(_ROOT + "/source/" + name)
        if row.get("mode") not in ["100644", "100755", "120000"] or not path.exists or path.is_dir:
            fail("N3 binding source member differs")
        if row["mode"] == "120000":
            resolved = str(path.realpath)
            prefix = _ROOT + "/source/"
            if not resolved.startswith(prefix) or resolved[len(prefix):] not in files or files[resolved[len(prefix):]].get("mode") not in ["100644", "100755"]:
                fail("N3 binding source link leaves declared regular members")
        elif str(path.realpath) != str(path):
            fail("N3 binding regular source redirected")
        ctx.watch(path)
        alias = "source-inputs/" + str(index)
        ctx.symlink(path, alias)
        names.append(alias)
    ctx.watch(receipt)
    ctx.symlink(receipt, "source-receipt.json")
    names.append("source-receipt.json")
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(repr(names)),
        'filegroup(name = "inputs", srcs = {})'.format(repr(names)),
        "",
    ]), executable = False)

codex_owner_status_persistence_binding_inputs = repository_rule(implementation = _implementation, local = True)
