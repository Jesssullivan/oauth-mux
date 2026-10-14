"""Exact retained producer proof inputs; no acquisition repository dependency.

Declaration discovers only the selected successful epoch's five bounded proof
leaves. It does not authenticate hashes or qualify execution: the consuming
action independently joins every alias, selected pin, byte and guarded receipt.
"""

_TARGET = "//tools:codex_native_sdk_carrier_seal_producer"
_PROFILE = "native-sdk-carrier-seal-reserved"
_ROLES = ["outer_receipt", "test_evidence", "test_log", "test_xml", "program_report"]
_ALIASES = ["proof/outer-receipt.json", "proof/test-evidence.json", "proof/test-log.evidence", "proof/test-xml.evidence", "proof/program-report.json"]
_PREFIXES = ["/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/", "/home/jess/.local/state/omux-execution-20261005/"]

def _need(value, stage):
    if not value:
        fail("native SDK carrier proof declaration refused: " + stage)

def _hex(value, size):
    return type(value) == "string" and len(value) == size and all([c in "0123456789abcdef" for c in value.elems()])

def _absolute(value):
    _need(type(value) == "string" and value.startswith("/") and len(value) <= 4096 and all([part not in ["", ".", ".."] for part in value.split("/")[1:]]) and not any([c in value for c in ["\\", " ", "\n", "\r", "\t", "\000"]]), "canonical-path")
    return value

def _epoch(receipt):
    _absolute(receipt)
    prefixes = [prefix for prefix in _PREFIXES if receipt.startswith(prefix)]
    _need(len(prefixes) == 1, "selected-coordinator-namespace")
    relative = receipt[len(prefixes[0]):].split("/")
    _need(len(relative) == 2 and relative[1] == "receipt.json", "selected-outer-receipt")
    name = relative[0]
    _need(len(name) == 36 and [name[i] for i in [8, 13, 18, 23]] == ["-", "-", "-", "-"] and _hex(name.replace("-", ""), 32), "selected-epoch")
    return receipt[:-len("/receipt.json")]

def _physical(ctx, name):
    path = ctx.path(_absolute(name))
    _need(path.exists and not path.is_dir and str(path.realpath) == name, "selected-physical-proof-leaf")
    return path

def _read(ctx, path, limit):
    ctx.watch(path)
    raw = ctx.read(path, watch = "no")
    _need(len(raw) > 0 and len(raw) <= limit, "bounded-control")
    value = json.decode(raw)
    _need(type(value) == "dict", "control-object")
    return value

def _implementation(ctx):
    # NULL is intentionally cold. No future evidence path/pin is manufactured.
    selector = _read(ctx, ctx.path(ctx.attr.selection), 16384)
    _need(sorted(selector.keys()) == ["kind", "schema_version", "selection", "status"] and type(selector["schema_version"]) == "int" and selector["schema_version"] == 2 and selector["kind"] == "omux-native-sdk-carrier-metadata-input-v2" and selector["status"] == "selected-qualified-carrier-for-metadata", "selected-v2-control")
    selected = selector["selection"]
    _need(type(selected) == "dict" and sorted(selected.keys()) == ["carrier", "original_selection", "qualification"], "closed-selection")
    qualified = selected["qualification"]
    _need(type(qualified) == "dict" and sorted(qualified.keys()) == ["producer", "report"], "closed-qualification")
    producer, report = qualified["producer"], qualified["report"]
    _need(type(producer) == "dict" and sorted(producer.keys()) == ["graph_sha256", "receipt", "sha256", "source_commit"] and _hex(producer["sha256"], 64) and _hex(producer["graph_sha256"], 64) and _hex(producer["source_commit"], 40), "selected-producer-pins")
    _need(type(report) == "dict" and sorted(report.keys()) == ["path", "sha256"] and _hex(report["sha256"], 64), "selected-report-pin")
    epoch = _epoch(producer["receipt"])
    report_path = _absolute(report["path"])
    report_prefix = epoch + "/output-base/execroot/_main/bazel-out/"
    report_suffix = "/testlogs/tools/codex_native_sdk_carrier_seal_producer/test.outputs/sdk-private/native-sdk-carrier-producer.json"
    _need(report_path.startswith(report_prefix) and report_path.endswith(report_suffix), "selected-program-namespace")
    configuration = report_path[len(report_prefix):-len(report_suffix)]
    _need(len(configuration) > 0 and len(configuration) <= 128 and all([c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-" for c in configuration.elems()]), "selected-output-configuration")
    receipt_path = _physical(ctx, producer["receipt"])
    receipt = _read(ctx, receipt_path, 4194304)
    _need(receipt.get("id") == epoch.split("/")[-1] and receipt.get("profile") == _PROFILE and receipt.get("verb") == "test" and receipt.get("targets") == [_TARGET] and type(receipt.get("exit")) == "int" and receipt["exit"] == 0 and type(receipt.get("workload_exit")) == "int" and receipt["workload_exit"] == 0 and receipt.get("controller_failure") == None and receipt.get("descendants_empty") == True and receipt.get("cleanup", {}).get("state") == "empty" and receipt.get("source_dirty") == "false" and receipt.get("source_commit") == producer["source_commit"] and receipt.get("graph_sha256") == producer["graph_sha256"] and receipt.get("output_base") == epoch + "/output-base", "actual-terminal-producer")
    retained = receipt.get("test_evidence")
    _need(type(retained) == "dict" and retained.get("state") == "preserved" and _hex(retained.get("sha256"), 64), "preserved-evidence-pin")
    evidence_name = epoch + "/test-evidence.json"
    evidence = _read(ctx, _physical(ctx, evidence_name), 4194304)
    _need(type(evidence.get("schema")) == "int" and evidence["schema"] == 1 and type(evidence.get("bazel_exit")) == "int" and evidence["bazel_exit"] == 0 and evidence.get("epoch_start_ns") == receipt.get("epoch_start_ns") and evidence.get("targets") == [_TARGET] and type(evidence.get("results")) == "list" and len(evidence["results"]) == 1, "actual-observed-test")
    result = evidence["results"][0]
    _need(type(result) == "dict" and result.get("target") == _TARGET and result.get("state") == "observed" and type(result.get("files")) == "list" and len(result["files"]) <= 64, "single-observed-target")
    proofs = {
        "outer_receipt": {"path": producer["receipt"], "sha256": producer["sha256"], "alias": _ALIASES[0]},
        "test_evidence": {"path": evidence_name, "sha256": retained["sha256"], "alias": _ALIASES[1]},
        "program_report": {"path": report_path, "sha256": report["sha256"], "alias": _ALIASES[4]},
    }
    for source, role, alias in [("test.log", "test_log", _ALIASES[2]), ("test.xml", "test_xml", _ALIASES[3])]:
        entries = [entry for entry in result["files"] if type(entry) == "dict" and entry.get("source") == source]
        _need(len(entries) == 1, "unique-copied-test-member")
        entry = entries[0]
        filename = entry.get("file")
        _need(entry.get("state") == "copied" and type(filename) == "string" and filename.endswith(".evidence") and _hex(filename[:-len(".evidence")], 64) and _hex(entry.get("sha256"), 64) and type(entry.get("bytes")) == "int" and entry["bytes"] > 0 and entry["bytes"] <= 67108864, "copied-test-member-pin")
        proofs[role] = {"path": epoch + "/test-evidence/" + filename, "sha256": entry["sha256"], "alias": alias}
    _need(len({proofs[role]["path"]: True for role in _ROLES}) == 5, "distinct-proof-leaves")
    # Register the exact five source dependencies. No host SDK/source tree,
    # acquisition rule, or unselected epoch is an action input here.
    for role in _ROLES:
        physical = _physical(ctx, proofs[role]["path"])
        ctx.watch(physical)
        ctx.symlink(physical, proofs[role]["alias"])
    for role in _ROLES:
        _physical(ctx, proofs[role]["path"])
    ctx.file("proof-inputs.json", json.encode({"kind": "omux-native-sdk-carrier-proof-inputs-v1", "proofs": proofs}), executable = False)
    files = _ALIASES + ["proof-inputs.json"]
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(repr(files)),
        'filegroup(name = "inputs", srcs = {})'.format(repr(files)),
        "",
    ]), executable = False)

codex_native_sdk_carrier_proof_inputs = repository_rule(
    implementation = _implementation,
    attrs = {"selection": attr.label(mandatory = True, allow_single_file = True)},
    local = True,
)
