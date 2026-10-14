"""Declare selected N10 content and original public proof leaves only.

The new action independently authenticates every byte and current custody.
Historical ancestor repositories are absent from this declaration. Path/JSON
shape here is not regular-type, digest, execution or source qualification.
"""

def _need(value):
    if not value:
        fail("selected N10 content declaration refused")

def _sha(value):
    return type(value) == "string" and len(value) == 64 and all([c in "0123456789abcdef" for c in value.elems()])

def _name(value):
    _need(type(value) == "string" and len(value) > 0 and len(value) <= 4096 and not value.startswith("/") and len(value.split("/")) <= 64 and all([part not in ["", ".", ".."] for part in value.split("/")]) and all([c not in value for c in ["\\", "\n", "\r", "\t", "\000"]]))

def _physical(ctx, value, directory = False):
    _need(type(value) == "string" and value.startswith("/") and all([part not in ["", ".", ".."] for part in value[1:].split("/")]))
    path = ctx.path(value)
    _need(path.exists and path.is_dir == directory and str(path.realpath) == value)
    return path

def _implementation(ctx):
    raw = ctx.read(ctx.path(ctx.attr.selection))
    _need(len(raw) <= 16384)
    config = json.decode(raw)
    _need(type(config) == "dict" and sorted(config.keys()) == ["kind", "parent", "schema_version", "status"] and type(config["schema_version"]) == "int" and config["schema_version"] == 1 and config["kind"] == "omux-native-n10-content-input-v1" and config["status"] == "selected-N10-content-uncompiled")
    ctx.watch(ctx.path(ctx.attr.selection))
    selected = config["parent"]
    _need(type(selected) == "dict" and sorted(selected.keys()) == ["inventory_sha256", "producer", "receipt_bytes", "receipt_sha256", "root"] and _sha(selected["inventory_sha256"]) and _sha(selected["receipt_sha256"]) and type(selected["receipt_bytes"]) == "int" and selected["receipt_bytes"] > 0 and selected["receipt_bytes"] <= 8 * 1024 * 1024)
    _physical(ctx, selected["root"], True)
    _physical(ctx, selected["root"] + "/source", True)
    receipt = _physical(ctx, selected["root"] + "/source-receipt.json")
    report_raw = ctx.read(receipt)
    _need(len(report_raw) == selected["receipt_bytes"])
    report = json.decode(report_raw)
    inventory = report.get("source_inventory")
    _need(report.get("kind") == "omux-native-source-file-writer-boundary-v1" and report.get("status") == "verified-tenth-file-writer-source-uncompiled" and report.get("inventory_sha256") == selected["inventory_sha256"] and type(inventory) == "dict" and len(inventory) == 8553 and len(report.get("patch_sha256", [])) == 10)
    producer = selected["producer"]
    _need(type(producer) == "dict" and sorted(producer.keys()) == ["graph_sha256", "receipt", "sha256", "source_commit"] and _sha(producer["sha256"]) and _sha(producer["graph_sha256"]))
    outer = _physical(ctx, producer["receipt"])
    outer_raw = ctx.read(outer)
    _need(len(outer_raw) <= 16 * 1024 * 1024)
    authority = json.decode(outer_raw)
    targets = ["//tools:codex_native_source_file_writer_test", "//tools:codex_native_source_file_writer_producer", "//tools:codex_native_source_file_writer_metadata_producer"]
    _need(authority.get("profile") == "native-file-writer-source-reserved" and authority.get("targets") == targets and authority.get("exit") == 0 and authority.get("workload_exit") == 0 and authority.get("source_commit") == producer["source_commit"] and authority.get("graph_sha256") == producer["graph_sha256"])
    epoch = str(outer.dirname)
    evidence_path = _physical(ctx, epoch + "/test-evidence.json")
    evidence_raw = ctx.read(evidence_path)
    _need(len(evidence_raw) <= 16 * 1024 * 1024)
    evidence = json.decode(evidence_raw)
    _need(evidence.get("targets") == targets and type(evidence.get("results")) == "list" and [row.get("target") for row in evidence["results"]] == targets)
    paths = [str(receipt), str(outer), str(evidence_path)]
    for result in evidence["results"]:
        _need(result.get("state") == "observed")
        for source in ["test.log", "test.xml"]:
            entries = [row for row in result.get("files", []) if row.get("source") == source]
            _need(len(entries) == 1 and entries[0].get("state") == "copied")
            name = entries[0].get("file")
            _need(type(name) == "string" and len(name) == 73 and name.endswith(".evidence") and _sha(name[:-9]) and _sha(entries[0].get("sha256")))
            paths.append(str(_physical(ctx, epoch + "/test-evidence/" + name)))
    for name, pin in sorted(inventory.items()):
        _name(name)
        _need(type(pin) == "dict" and sorted(pin.keys()) == ["mode", "sha256"] and pin["mode"] in ["100644", "100755", "120000"] and _sha(pin["sha256"]))
        file = ctx.path(selected["root"] + "/source/" + name)
        _need(file.exists and not file.is_dir)
        if pin["mode"] == "120000":
            prefix = selected["root"] + "/source/"
            target = str(file.realpath)
            _need(target.startswith(prefix) and target[len(prefix):] in inventory and inventory[target[len(prefix):]]["mode"] in ["100644", "100755"])
        else:
            _physical(ctx, str(file))
        paths.append(str(file))
    _need(len(paths) == 8562 and len({path: True for path in paths}) == len(paths))
    rows = []
    aliases = []
    for index, path in enumerate(paths):
        alias = "input/" + str(index)
        ctx.watch(ctx.path(path))
        ctx.symlink(ctx.path(path), alias)
        rows.append({"path": path, "alias": alias})
        aliases.append(alias)
    ctx.file("source-inputs.json", json.encode({"kind": config["kind"], "selection": selected, "inputs": rows}) + "\n", executable = False)
    aliases.append("source-inputs.json")
    ctx.file("BUILD.bazel", "\n".join(["package(default_visibility = [\"//visibility:public\"])", "exports_files({})".format(repr(aliases)), "filegroup(name = \"inputs\", srcs = {})".format(repr(aliases)), ""]), executable = False)

codex_native_n10_content_inputs = repository_rule(implementation = _implementation, local = True, attrs = {
    "selection": attr.label(mandatory = True, allow_single_file = True),
})
