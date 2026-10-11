"""Closed carrier metadata/SDK projection declaration, never legacy SDK leaves.

Raw transport remains in the separately selected carrier repository. This rule
only declares genuine metadata/SDK reports, generated HUB/graph and five proof
roles each. Runtime readers independently authenticate all declared bytes.
"""
_TARGETS = {"metadata": "//tools:codex_native_carrier_metadata_producer", "sdk": "//tools:codex_native_carrier_sdk_export_producer"}
_PROFILES = {"metadata": "native-sdk-carrier-metadata-reserved", "sdk": "native-sdk-carrier-sdk-export-reserved"}
_ROOTS = ["/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/", "/home/jess/.local/state/omux-execution-20261005/"]


def _need(value, stage):
    if not value:
        fail("native carrier material declaration refused: " + stage)


def _hex(value, length):
    return type(value) == "string" and len(value) == length and all([c in "0123456789abcdef" for c in value.elems()])


def _name(value):
    _need(type(value) == "string" and len(value) <= 4096 and all([part not in ["", ".", ".."] for part in value.split("/")]) and not any([c in value for c in ["\\", "\n", "\r", "\t", "\000"]]), "relative-name")
    return value


def _physical(ctx, value):
    _need(type(value) == "string" and value.startswith("/"), "absolute-name")
    _name(value[1:])
    path = ctx.path(value)
    _need(path.exists and not path.is_dir and str(path.realpath) == value, "physical-nofollow-leaf")
    return path


def _read(ctx, value, maximum):
    path = _physical(ctx, value)
    ctx.watch(path)
    raw = ctx.read(path, watch = "no")
    _need(0 < len(raw) and len(raw) <= maximum, "bounded-json")
    document = json.decode(raw)
    _need(type(document) == "dict", "json-object")
    return document, raw


def _add(ctx, files, role, path, digest, size):
    _name(role)
    _need(role not in files and _hex(digest, 64) and type(size) == "int" and 0 <= size and size <= 67108864, "closed-leaf-row")
    physical = _physical(ctx, path)
    alias = "inputs/" + role
    ctx.watch(physical)
    ctx.symlink(physical, alias)
    files[role] = {"path": path, "sha256": digest, "bytes": size, "alias": alias}
    _physical(ctx, path)


def _producer(ctx, files, role, selected):
    _need(type(selected) == "dict" and sorted(selected.keys()) == ["producer", "program"], "selected-program")
    producer, program = selected["producer"], selected["program"]
    _need(type(producer) == "dict" and sorted(producer.keys()) == ["graph_sha256", "receipt", "sha256", "source_commit"] and _hex(producer["sha256"], 64) and _hex(producer["graph_sha256"], 64) and _hex(producer["source_commit"], 40), "selected-outer-pins")
    _need(type(program) == "dict" and sorted(program.keys()) == ["bytes", "path", "sha256"] and _hex(program["sha256"], 64) and type(program["bytes"]) == "int" and 0 < program["bytes"] and program["bytes"] <= 16777216, "selected-program-row")
    prefixes = [prefix for prefix in _ROOTS if producer["receipt"].startswith(prefix)]
    _need(len(prefixes) == 1, "outer-namespace")
    parts = producer["receipt"][len(prefixes[0]):].split("/")
    _need(len(parts) == 2 and parts[1] == "receipt.json" and len(parts[0]) == 36 and [parts[0][i] for i in [8, 13, 18, 23]] == ["-", "-", "-", "-"] and _hex(parts[0].replace("-", ""), 32), "outer-epoch")
    epoch = producer["receipt"][:-len("/receipt.json")]
    outer, raw = _read(ctx, producer["receipt"], 4194304)
    target = _TARGETS[role]
    _need(outer.get("profile") == _PROFILES[role] and outer.get("targets") == [target] and outer.get("verb") == "test" and type(outer.get("exit")) == "int" and outer["exit"] == 0 and type(outer.get("workload_exit")) == "int" and outer["workload_exit"] == 0 and outer.get("source_dirty") == "false" and outer.get("controller_failure") == None and outer.get("descendants_empty") == True and outer.get("cleanup", {}).get("state") == "empty" and outer.get("source_commit") == producer["source_commit"] and outer.get("graph_sha256") == producer["graph_sha256"] and outer.get("output_base") == epoch + "/output-base", "actual-successful-producer")
    prefix = epoch + "/output-base/execroot/_main/bazel-out/"
    suffix = "/testlogs/tools/" + target.split(":")[1] + "/test.outputs/" + ("native-sdk-carrier-metadata/metadata-receipt.json" if role == "metadata" else "native-carrier-sdk-export/sdk-receipt.json")
    _need(program["path"].startswith(prefix) and program["path"].endswith(suffix), "actual-program-namespace")
    configuration = program["path"][len(prefix):-len(suffix)]
    _need(len(configuration) > 0 and len(configuration) <= 128 and all([c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-" for c in configuration.elems()]), "output-configuration")
    _add(ctx, files, role + "/outer-receipt.json", producer["receipt"], producer["sha256"], len(raw))
    retained = outer.get("test_evidence")
    _need(type(retained) == "dict" and retained.get("state") == "preserved" and _hex(retained.get("sha256"), 64), "retained-evidence")
    index, index_raw = _read(ctx, epoch + "/test-evidence.json", 4194304)
    _need(index.get("targets") == [target] and type(index.get("bazel_exit")) == "int" and index["bazel_exit"] == 0 and type(index.get("schema")) == "int" and index["schema"] == 1 and index.get("epoch_start_ns") == outer.get("epoch_start_ns") and type(index.get("results")) == "list" and len(index["results"]) == 1 and index["results"][0].get("target") == target and index["results"][0].get("state") == "observed", "actual-test-index")
    _add(ctx, files, role + "/test-evidence.json", epoch + "/test-evidence.json", retained["sha256"], len(index_raw))
    for source, leaf in [("test.log", "test-log.evidence"), ("test.xml", "test-xml.evidence")]:
        rows = [row for row in index["results"][0].get("files", []) if row.get("source") == source]
        _need(len(rows) == 1 and rows[0].get("state") == "copied" and _hex(rows[0].get("sha256"), 64) and type(rows[0].get("bytes")) == "int" and 0 < rows[0]["bytes"] and rows[0]["bytes"] <= 67108864 and type(rows[0].get("file")) == "string" and rows[0]["file"].endswith(".evidence") and _hex(rows[0]["file"][:-len(".evidence")], 64), "copied-proof-member")
        _add(ctx, files, role + "/" + leaf, epoch + "/test-evidence/" + rows[0]["file"], rows[0]["sha256"], rows[0]["bytes"])
    report, report_raw = _read(ctx, program["path"], 16777216)
    _need(len(report_raw) == program["bytes"], "program-byte-count")
    _add(ctx, files, role + "/program-report.json", program["path"], program["sha256"], program["bytes"])
    return report


def _implementation(ctx):
    selector = ctx.path(ctx.attr.selection)
    ctx.watch(selector)
    raw = ctx.read(selector, watch = "no")
    _need(0 < len(raw) and len(raw) <= 65536, "bounded-selector")
    document = json.decode(raw)
    _need(type(document) == "dict" and sorted(document.keys()) == ["compile", "kind", "metadata", "schema_version", "selection", "status"] and type(document["schema_version"]) == "int" and document["schema_version"] == 2 and document["kind"] == "omux-native-carrier-material-config-v2", "typed-config")
    _need(document["status"] == "actual-qualified-carrier-route-selected" and document["metadata"] != None, "cold-selection")
    files = {}
    metadata = _producer(ctx, files, "metadata", document["metadata"])
    _need(metadata.get("kind") == "omux-native-sdk-carrier-metadata-v2" and type(metadata.get("generated_hub")) == "list" and 0 < len(metadata["generated_hub"]) and len(metadata["generated_hub"]) <= 16, "actual-hub-report")
    metadata_root = document["metadata"]["program"]["path"][:-len("/metadata-receipt.json")]
    for row in metadata["generated_hub"]:
        _need(type(row) == "dict" and sorted(row.keys()) == ["path", "sha256"] and "/" not in row["path"] and _hex(row["sha256"], 64), "hub-member")
        name = metadata_root + "/hub/source/" + _name(row["path"])
        contents = ctx.read(_physical(ctx, name), watch = "no")
        _need(len(contents) <= 16777216, "hub-bound")
        _add(ctx, files, "metadata/hub/" + row["path"], name, row["sha256"], len(contents))
    if ctx.attr.stage == "material":
        selected = document["selection"]
        _need(type(selected) == "dict" and selected.get("schema_version") == 2 and selected.get("kind") == "omux-native-carrier-native-selection-v2", "selected-material-v2")
        sdk = selected["sdk"]
        program_path = sdk["root"] + "/sdk-receipt.json"
        report, report_raw = _read(ctx, program_path, 16777216)
        selected_sdk = {"producer": sdk["producer"], "program": {"path": program_path, "sha256": sdk["receipt_sha256"], "bytes": len(report_raw)}}
        report = _producer(ctx, files, "sdk", selected_sdk)
        _need(report.get("kind") == "omux-native-carrier-sdk-projection-v2" and report.get("authority_sha256") == sdk["inventory_sha256"], "sdk-projection-pin")
        authority, authority_raw = _read(ctx, sdk["root"] + "/authority.json", 16777216)
        _need(authority.get("kind") == "omux-native-carrier-sdk-authority-core-v2", "sdk-authority-core")
        _add(ctx, files, "sdk/authority.json", sdk["root"] + "/authority.json", sdk["inventory_sha256"], len(authority_raw))
        for role in ["hub", "graph"]:
            members = report.get(role + "_files")
            _need(type(members) == "dict" and 0 < len(members) and len(members) <= 4096, "projection-map")
            for name, row in sorted(members.items()):
                _name(name)
                _need(type(row) == "dict" and sorted(row.keys()) == ["bytes", "mode", "sha256"] and row["mode"] in ["100644", "100755"], "projection-member")
                _add(ctx, files, "sdk/" + role + "/" + name, sdk["root"] + "/" + role + "/" + name, row["sha256"], row["bytes"])
    _need(len(files) <= 4096, "declared-input-count")
    for row in files.values():
        _physical(ctx, row["path"])
    ctx.file("inputs.json", json.encode({"kind": "omux-native-carrier-declared-inputs-v2", "stage": ctx.attr.stage, "files": files}), executable = False)
    if ctx.attr.stage == "material":
        ctx.file("selected-material.json", json.encode(document["selection"]), executable = False)
    names = [row["alias"] for row in files.values()] + ["inputs.json"] + (["selected-material.json"] if ctx.attr.stage == "material" else [])
    ctx.file("BUILD.bazel", "\n".join(['package(default_visibility = ["//visibility:public"])', 'exports_files({})'.format(repr(names)), 'filegroup(name = "inputs", srcs = {})'.format(repr(names)), ""]), executable = False)

codex_native_carrier_material_inputs = repository_rule(implementation = _implementation, local = True, attrs = {
    "selection": attr.label(mandatory = True, allow_single_file = True),
    "stage": attr.string(mandatory = True, values = ["metadata", "material"]),
})
