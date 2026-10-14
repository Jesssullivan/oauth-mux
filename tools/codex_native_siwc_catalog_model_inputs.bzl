"""Declare exact qualified N10 source/proofs; action independently authenticates all bytes."""

def _need(value):
    if not value:
        fail("file-writer model source declaration refused")

def _sha(value):
    return type(value) == "string" and len(value) == 64 and all([c in "0123456789abcdef" for c in value.elems()])

def _name(value):
    _need(type(value) == "string" and len(value) > 0 and len(value) <= 4096 and not value.startswith("/") and len(value.split("/")) <= 64 and all([part not in ["", ".", ".."] for part in value.split("/")]) and all([c not in value for c in ["\\", "\n", "\r", "\t", "\000"]]))

def _physical(ctx, value, directory = False):
    _need(type(value) == "string" and value.startswith("/") and all([part not in ["", ".", ".."] for part in value[1:].split("/")]))
    path = ctx.path(value)
    _need(path.exists and path.is_dir == directory and str(path.realpath) == value)
    return path

def _retained(ctx, config):
    # Separate content-only family. These repository reads derive declarations;
    # the action independently authenticates every selected raw SHA and witness.
    history = config['kind'] == 'omux-native-siwc-catalog-owned-history-retained-selection-v3'
    if history:
        _need(config['schema_version'] == 1 and config['status'] == 'qualified-retained-catalog-owned-history-source-hub-uncompiled' and config['catalog_controls_sha256'] == '9ae90d61ffab78afe467fcc1e9def2c0ada704ab1b458322e4257a1d0b2f9fbd')
    else:
        _need(config["schema_version"] == 1 and config["status"] == "qualified-retained-catalog-content-source-hub-uncompiled" and _sha(config["catalog_controls_sha256"]))
    selected = config["source"]
    _need(type(selected) == "dict" and sorted(selected.keys()) == ["inventory_sha256", "producer", "receipt_bytes", "receipt_sha256", "root", "source_phase_receipt", "transport_receipt"] and _sha(selected["inventory_sha256"]) and _sha(selected["receipt_sha256"]) and type(selected["receipt_bytes"]) == "int" and 0 < selected["receipt_bytes"] and selected["receipt_bytes"] <= 8 * 1024 * 1024)
    producer = selected["producer"]
    _need(type(producer) == "dict" and sorted(producer.keys()) == ["graph_sha256", "receipt", "sha256", "source_commit"] and _sha(producer["sha256"]) and _sha(producer["graph_sha256"]) and type(producer["source_commit"]) == "string" and len(producer["source_commit"]) == 40 and all([c in "0123456789abcdef" for c in producer["source_commit"].elems()]))
    outer_path = _physical(ctx, producer["receipt"])
    epoch = str(outer_path.dirname)
    identifier = outer_path.dirname.basename
    _need(outer_path.basename == "receipt.json" and len(identifier) == 36 and [identifier[i] for i in [8, 13, 18, 23]] == ["-", "-", "-", "-"] and all([c in "0123456789abcdef" for c in identifier.replace("-", "").elems()]) and str(outer_path.dirname.dirname) in ["/home/jess/.local/state/omux-execution-20261005", "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005"]))
    _need(selected["root"] == epoch + "/native-content-retained/native-siwc-catalog-content-source")
    for name in ["transport_receipt", "source_phase_receipt"]:
        pin = selected[name]
        _need(type(pin) == "dict" and sorted(pin.keys()) == ["bytes", "sha256"] and _sha(pin["sha256"]) and type(pin["bytes"]) == "int" and 0 < pin["bytes"] and pin["bytes"] <= 8 * 1024 * 1024)
    _physical(ctx, selected["root"], True)
    _physical(ctx, selected["root"] + "/source", True)
    receipt_path = _physical(ctx, selected["root"] + "/source-receipt.json")
    raw = ctx.read(receipt_path)
    _need(len(raw) == selected["receipt_bytes"])
    report = json.decode(raw)
    inventory = report.get("source_inventory")
    if history:
        _need(report.get('kind') == 'omux-native-siwc-catalog-owned-history-source-v3' and report.get('status') == 'verified-siwc-catalog-owned-history-source-uncompiled' and report.get('inventory_sha256') == selected['inventory_sha256'] and report.get('native_controls_sha256') == report.get('native_owned_history_controls_sha256') == config['catalog_controls_sha256'] and report.get('native_owned_history_manifest_sha256') == 'd1b7bfc9bc81ccbc8672165e301f3000bc42b56a848758ab348f4e97d810b588' and type(inventory) == 'dict' and len(inventory) == 8557 and len(report.get('patch_sha256', [])) == 13 and report['patch_sha256'][-1] == '030630425f378832d182333d46d95f8ba183f2de3a04ea34195fb2e9b4c98eb1')
    else:
        _need(report.get("kind") == "omux-native-siwc-catalog-content-source-v1" and report.get("status") == "verified-siwc-catalog-content-source-uncompiled" and report.get("inventory_sha256") == selected["inventory_sha256"] and report.get("native_controls_sha256") == config["catalog_controls_sha256"] and type(inventory) == "dict" and len(inventory) == 8557 and len(report.get("patch_sha256", [])) == 12)
    outer_raw = ctx.read(outer_path)
    _need(len(outer_raw) <= 16 * 1024 * 1024)
    outer = json.decode(outer_raw)
    targets = ["//tools:codex_native_siwc_catalog_content_source_test", "//tools:codex_native_siwc_catalog_content_source_producer"]
    _need(outer.get("id") == identifier and outer.get("profile") == "native-siwc-catalog-content-source-reserved" and outer.get("targets") == targets and outer.get("exit") == 0 and outer.get("workload_exit") == 0 and outer.get("source_commit") == producer["source_commit"] and outer.get("graph_sha256") == producer["graph_sha256"])
    phase_path = _physical(ctx, epoch + "/source-phase-receipt.json")
    phase_raw = ctx.read(phase_path)
    _need(len(phase_raw) == selected["source_phase_receipt"]["bytes"])
    phase = json.decode(phase_raw)
    _need(phase.get("kind") == "omux-native-siwc-content-source-phase-v1" and phase.get("id") == identifier and phase.get("targets") == targets and phase.get("exit") == 0 and phase.get("workload_exit") == 0 and outer.get("source_phase_receipt") == {"path": "source-phase-receipt.json", "sha256": selected["source_phase_receipt"]["sha256"], "bytes": selected["source_phase_receipt"]["bytes"]})
    publication_path = _physical(ctx, epoch + "/native-content-retained/publication-receipt.json")
    publication_raw = ctx.read(publication_path)
    _need(len(publication_raw) == selected["transport_receipt"]["bytes"])
    publication = json.decode(publication_raw)
    _need(publication.get("kind") == "omux-native-siwc-content-retained-publication-v1" and publication.get("source_phase_receipt_sha256") == selected["source_phase_receipt"]["sha256"] and publication.get("publication", {}).get("root") == selected["root"] and publication.get("original_action_sdk_custody_inherited") == False)
    descriptor = outer.get("native_siwc_content_publication")
    _need(type(descriptor) == "dict" and descriptor.get("root") == selected["root"] and descriptor.get("transport_receipt") == {"path": str(publication_path), "sha256": selected["transport_receipt"]["sha256"], "bytes": selected["transport_receipt"]["bytes"]} and descriptor.get("source_phase_receipt_sha256") == selected["source_phase_receipt"]["sha256"] and descriptor.get("original_action_sdk_custody_inherited") == False)
    delivery = outer.get("native_siwc_content_delivery")
    _need(type(delivery) == "dict" and delivery.get("started") == True and delivery.get("phase") == "complete" and delivery.get("exit") == 0 and delivery.get("workload_exit") == 0 and delivery.get("cleanup", {}).get("state") == "empty" and delivery.get("cleanup", {}).get("ownership") == "verified" and delivery.get("cleanup", {}).get("readback_attempts", 0) >= 2)
    index_path = _physical(ctx, epoch + "/test-evidence.json")
    index_raw = ctx.read(index_path)
    _need(len(index_raw) <= 16 * 1024 * 1024)
    index = json.decode(index_raw)
    _need(index.get("targets") == targets and type(index.get("results")) == "list" and [row.get("target") for row in index["results"]] == targets)
    paths = [str(receipt_path), str(outer_path), str(index_path), str(phase_path), str(publication_path)]
    for result in index["results"]:
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
    hub = report.get("generated_hub")
    _need(type(hub) == "dict" and 0 < len(hub) and len(hub) <= 16 and all([name in hub for name in ["BUILD.bazel", "defs.bzl", "data.bzl"]]))
    for name, pin in sorted(hub.items()):
        _need(type(name) == "string" and "/" not in name and name not in ["", ".", ".."] and _sha(pin.get("sha256")) and type(pin.get("bytes")) == "int" and 0 < pin["bytes"] and pin["bytes"] <= 8 * 1024 * 1024)
        paths.append(str(_physical(ctx, selected["root"] + "/hub/source/" + name)))
    _need(len(paths) == 8566 + len(hub) and len({path: True for path in paths}) == len(paths))
    rows = []
    aliases = []
    for index, path in enumerate(paths):
        alias = "input/" + str(index)
        ctx.watch(ctx.path(path))
        ctx.symlink(ctx.path(path), alias)
        rows.append({"path": path, "alias": alias})
        aliases.append(alias)
    ctx.file("source-inputs.json", json.encode({"kind": ('omux-native-siwc-catalog-owned-history-retained-input-v3' if history else "omux-native-siwc-catalog-retained-delivery-input-v1"), "selection": selected, "inputs": rows}) + "\n", executable = False)
    aliases.append("source-inputs.json")
    ctx.file("BUILD.bazel", "\n".join(["package(default_visibility = [\"//visibility:public\"])", "exports_files({})".format(repr(aliases)), "filegroup(name = \"inputs\", srcs = {})".format(repr(aliases)), ""]), executable = False)

def _implementation(ctx):
    raw = ctx.read(ctx.path(ctx.attr.selection))
    _need(len(raw) <= 16384)
    config = json.decode(raw)
    _need(type(config) == "dict" and sorted(config.keys()) == ["catalog_controls_sha256", "kind", "schema_version", "source", "status"])
    if config["kind"] in ("omux-native-siwc-catalog-retained-delivery-selection-v1", "omux-native-siwc-catalog-owned-history-retained-selection-v3"):
        ctx.watch(ctx.path(ctx.attr.selection))
        _retained(ctx, config)
        return
    _need(config["schema_version"] == 1 and config["kind"] == "omux-native-siwc-catalog-model-selection-v1" )
    ctx.watch(ctx.path(ctx.attr.selection))
    if config["status"] == "PENDING-GENUINE-SOURCE-QUALIFICATION":
        _need(config["source"] == None and _sha(config["catalog_controls_sha256"]))
        ctx.file("source-inputs.json", json.encode({"kind": "omux-native-siwc-catalog-model-input-v1", "selection": None, "inputs": []}) + "\n", executable = False)
        ctx.file("BUILD.bazel", 'package(default_visibility = ["//visibility:public"])\nfilegroup(name = "inputs", srcs = ["source-inputs.json"])\n', executable = False)
        return
    _need(config["status"] in ["qualified-catalog-source-hub-uncompiled", "qualified-catalog-content-source-hub-uncompiled"])
    content = config["status"] == "qualified-catalog-content-source-hub-uncompiled"
    report_kind = "omux-native-siwc-catalog-content-source-v1" if content else "omux-native-siwc-catalog-source-v1"
    report_status = "verified-siwc-catalog-content-source-uncompiled" if content else "verified-siwc-catalog-source-uncompiled"
    profile = "native-siwc-catalog-content-source-reserved" if content else "native-siwc-catalog-source-reserved"
    prefix = "codex_native_siwc_catalog_content_source" if content else "codex_native_siwc_catalog_source"
    selected = config["source"]
    _need(type(selected) == "dict" and sorted(selected.keys()) == ["inventory_sha256", "producer", "receipt_bytes", "receipt_sha256", "root"] and _sha(selected["inventory_sha256"]) and _sha(selected["receipt_sha256"]) and type(selected["receipt_bytes"]) == "int" and selected["receipt_bytes"] > 0 and selected["receipt_bytes"] <= 8 * 1024 * 1024)
    _physical(ctx, selected["root"], True)
    _physical(ctx, selected["root"] + "/source", True)
    receipt = _physical(ctx, selected["root"] + "/source-receipt.json")
    report_raw = ctx.read(receipt)
    _need(len(report_raw) == selected["receipt_bytes"])
    report = json.decode(report_raw)
    inventory = report.get("source_inventory")
    _need(report.get("kind") == report_kind and report.get("status") == report_status and report.get("inventory_sha256") == selected["inventory_sha256"] and type(inventory) == "dict" and len(inventory) == 8557 and len(report.get("patch_sha256", [])) == 12 and report.get("native_controls_sha256") == config["catalog_controls_sha256"])
    producer = selected["producer"]
    _need(type(producer) == "dict" and sorted(producer.keys()) == ["graph_sha256", "receipt", "sha256", "source_commit"] and _sha(producer["sha256"]) and _sha(producer["graph_sha256"]))
    outer = _physical(ctx, producer["receipt"])
    outer_raw = ctx.read(outer)
    _need(len(outer_raw) <= 16 * 1024 * 1024)
    authority = json.decode(outer_raw)
    targets = ["//tools:" + prefix + "_test", "//tools:" + prefix + "_producer"]
    _need(authority.get("profile") == profile and authority.get("targets") == targets and authority.get("exit") == 0 and authority.get("workload_exit") == 0 and authority.get("source_commit") == producer["source_commit"] and authority.get("graph_sha256") == producer["graph_sha256"])
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
    hub = report.get("generated_hub")
    _need(type(hub) == "dict" and len(hub) > 0 and len(hub) <= 16 and all([name in hub for name in ["BUILD.bazel", "defs.bzl", "data.bzl"]]))
    for name, pin in sorted(hub.items()):
        _need(type(name) == "string" and "/" not in name and name not in ["", ".", ".."] and _sha(pin.get("sha256")) and type(pin.get("bytes")) == "int" and pin["bytes"] > 0 and pin["bytes"] <= 8 * 1024 * 1024)
        paths.append(str(_physical(ctx, selected["root"] + "/hub/source/" + name)))
    _need(len(paths) == 8564 + len(hub) and len({path: True for path in paths}) == len(paths))
    rows = []
    aliases = []
    for index, path in enumerate(paths):
        alias = "input/" + str(index)
        ctx.watch(ctx.path(path))
        ctx.symlink(ctx.path(path), alias)
        rows.append({"path": path, "alias": alias})
        aliases.append(alias)
    ctx.file("source-inputs.json", json.encode({"kind": "omux-native-siwc-catalog-model-input-v1", "selection": selected, "inputs": rows}) + "\n", executable = False)
    aliases.append("source-inputs.json")
    ctx.file("BUILD.bazel", "\n".join(["package(default_visibility = [\"//visibility:public\"])", "exports_files({})".format(repr(aliases)), "filegroup(name = \"inputs\", srcs = {})".format(repr(aliases)), ""]), executable = False)

codex_native_siwc_catalog_model_inputs = repository_rule(implementation = _implementation, local = True, attrs = {
    "selection": attr.label(mandatory = True, allow_single_file = True),
})
