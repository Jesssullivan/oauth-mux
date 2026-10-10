"""Declare actual seventh source only after its genuine receipt is pinned."""
def _implementation(ctx):
    manifest = ctx.path(ctx.attr.manifest)
    config = json.decode(ctx.read(manifest))
    ctx.watch(manifest)
    ctx.symlink(manifest, "seventh-input.json")
    names = ["seventh-input.json"]
    if config.get("status") == "awaiting-actual-seventh-receipt":
        if any([config.get(key) != None for key in ["root", "receipt_sha256", "receipt_bytes", "inventory_sha256", "source_members", "source_bytes"]]):
            fail("unconfigured seventh input contains invented qualification")
    elif config.get("status") == "actual-seventh-source-pinned":
        root = config.get("root")
        if type(root) != "string" or not root.startswith("/") or any([part in ["", ".", ".."] for part in root[1:].split("/")]):
            fail("seventh input root is not canonical")
        origin = ctx.path(root)
        receipt = ctx.path(root + "/source-receipt.json")
        if not origin.exists or not origin.is_dir or str(origin.realpath) != str(origin) or not receipt.exists or receipt.is_dir or str(receipt.realpath) != str(receipt):
            fail("seventh input absent or redirected")
        raw = ctx.read(receipt)
        report = json.decode(raw)
        files = report.get("source_inventory", {})
        if len(raw) != config.get("receipt_bytes") or report.get("kind") != "omux-native-source-context-source-v1" or report.get("inventory_sha256") != config.get("inventory_sha256") or len(files) != config.get("source_members"):
            fail("seventh input declaration differs")
        for index, name in enumerate(sorted(files)):
            if name.startswith("/") or any([part in ["", ".", ".."] for part in name.split("/")]) or any([c in name for c in ["\\", "\n", "\r", "\t"]]):
                fail("seventh input member is not canonical")
            row = files[name]
            path = ctx.path(root + "/source/" + name)
            if row.get("mode") not in ["100644", "100755", "120000"] or not path.exists or path.is_dir:
                fail("seventh input member differs")
            if row["mode"] == "120000":
                resolved = str(path.realpath)
                prefix = root + "/source/"
                if not resolved.startswith(prefix) or resolved[len(prefix):] not in files or files[resolved[len(prefix):]].get("mode") not in ["100644", "100755"]:
                    fail("seventh source link leaves declared regular members")
            elif str(path.realpath) != str(path):
                fail("seventh regular member redirected")
            ctx.watch(path)
            alias = "source-inputs/" + str(index)
            ctx.symlink(path, alias)
            names.append(alias)
        ctx.watch(receipt)
        ctx.symlink(receipt, "source-receipt.json")
        names.append("source-receipt.json")
    else:
        fail("seventh input qualification state unsupported")
    ctx.file("BUILD.bazel", "\n".join(['package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(repr(names)), 'filegroup(name = "inputs", srcs = {})'.format(repr(names)), ""]), executable = False)

codex_native_source_context_refresh_inputs = repository_rule(
    implementation = _implementation, local = True,
    attrs = {"manifest": attr.label(mandatory = True, allow_single_file = True)},
)
