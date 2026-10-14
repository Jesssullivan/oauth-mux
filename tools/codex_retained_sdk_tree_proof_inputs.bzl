"""Declare selected immutable creator proofs; SDK tree is a direct artifact.

Structural repository declaration is not byte/clock/execution authentication.
The production consumer holds and independently authenticates every role.
"""
_TARGET = "//tools:codex_native_retained_sdk_tree_producer"
_PROFILE = "native-sdk-tree-producer-reserved"
_ROOTS = ["/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/", "/home/jess/.local/state/omux-execution-20261005/"]
_FIELDS = ["MODE", "ENTRY_NS", "DEADLINE_NS", "EPOCH", "SOURCE_COMMIT", "GRAPH_SHA256"]
_ROLES = ["outer_receipt", "test_evidence", "test_log", "test_xml", "program_receipt", "selected_inventory", "selected_recipe", "selected_creator_context", "qualification_confirmation"]
_ALIASES = ["proof/outer-receipt.json", "proof/test-evidence.json", "proof/test-log.evidence", "proof/test-xml.evidence", "proof/program-receipt.json", "proof/selected-inventory.json", "proof/selected-recipe.json", "proof/selected-creator-context.json", "proof/qualification-confirmation.json"]

def _need(value, reason):
    if not value:
        fail("retained SDK proof declaration refused: " + reason)

def _hex(value, size = 64):
    return type(value) == "string" and len(value) == size and all([c in "0123456789abcdef" for c in value.elems()])

def _path(value):
    _need(type(value) == "string" and value.startswith("/") and len(value) <= 4096 and all([part not in ["", ".", ".."] for part in value.split("/")[1:]]) and not any([c in value for c in ["\\", " ", "\n", "\r", "\t", "\000"]]), "canonical-path")
    return value

def _physical(ctx, name):
    path = ctx.path(_path(name))
    _need(path.exists and not path.is_dir and str(path.realpath) == name, "physical-metadata-leaf")
    return path

def _read(ctx, path, limit):
    ctx.watch(path)
    raw = ctx.read(path, watch = "no")
    _need(0 < len(raw) and len(raw) <= limit, "bounded-metadata")
    value = json.decode(raw)
    _need(type(value) == "dict", "metadata-object")
    return value

def _row(row, limit):
    _need(type(row) == "dict" and sorted(row.keys()) == ["bytes", "path", "sha256"] and _hex(row["sha256"]) and type(row["bytes"]) == "int" and 0 < row["bytes"] and row["bytes"] <= limit, "closed-pin-row")
    _path(row["path"])

def _context(value):
    _need(type(value) == "dict" and sorted(value.keys()) == sorted(_FIELDS) and all([type(value[name]) == "string" for name in _FIELDS]) and value["MODE"] == _PROFILE, "creator-context-fields")
    _need(all([len(value[name]) > 0 and len(value[name]) <= 20 and all([c in "0123456789" for c in value[name].elems()]) for name in ["ENTRY_NS", "DEADLINE_NS"]]), "creator-integers")
    _need(int(value["ENTRY_NS"]) > 0 and int(value["DEADLINE_NS"]) - int(value["ENTRY_NS"]) == 1200 * 1000000000 and _hex(value["SOURCE_COMMIT"], 40) and _hex(value["GRAPH_SHA256"]), "original-creator-envelope")
    epoch = _path(value["EPOCH"])
    prefixes = [prefix for prefix in _ROOTS if epoch.startswith(prefix)]
    _need(len(prefixes) == 1, "creator-state-root")
    name = epoch[len(prefixes[0]):]
    _need(len(name) == 36 and [name[i] for i in [8, 13, 18, 23]] == ["-", "-", "-", "-"] and _hex(name.replace("-", ""), 32), "creator-uuid")
    return epoch

def _implementation(ctx):
    config_path = ctx.path(ctx.attr.selection)
    config = _read(ctx, config_path, 65536)
    _need(sorted(config.keys()) == ["kind", "schema_version", "selection", "status"] and type(config["schema_version"]) == "int" and config["schema_version"] == 1 and config["kind"] == "omux-retained-public-sdk-tree-selection-v1", "selector-shape")
    if config["status"] == "UNSELECTED":
        _need(config["selection"] == None, "null-selection")
        ctx.file("selection.bzl", "SDK_TREE_CREATOR_CONTEXT = None\n", executable = False)
        ctx.file("sdk-tree-proof-inputs.json", json.encode({"kind": "omux-retained-public-sdk-tree-proof-inputs-v1", "proofs": None}) + "\n", executable = False)
        ctx.file("BUILD.bazel", 'package(default_visibility=["//visibility:public"])\nexports_files(["selection.bzl","sdk-tree-proof-inputs.json"])\nfilegroup(name="inputs",srcs=["sdk-tree-proof-inputs.json"])\n', executable = False)
        return
    _need(config["status"] == "SELECTED-SUCCESSFUL-CREATOR-CONTENT-ONLY", "selected-content-status")
    selected = config["selection"]
    _need(type(selected) == "dict" and sorted(selected.keys()) == ["confirmation", "creator_context", "inventory", "materialization", "producer", "receipt"], "selection-fields")
    creator = selected["creator_context"]
    epoch = _context(creator)
    producer = selected["producer"]
    _need(type(producer) == "dict" and sorted(producer.keys()) == ["graph_sha256", "receipt", "sha256", "source_commit"] and producer["receipt"] == epoch + "/receipt.json" and _hex(producer["sha256"]) and producer["source_commit"] == creator["SOURCE_COMMIT"] and producer["graph_sha256"] == creator["GRAPH_SHA256"], "producer-pins")
    _row(selected["receipt"], 65536)
    _row(selected["inventory"], 268435456)
    _row(selected["confirmation"], 65536)
    _need(selected["confirmation"]["path"] == epoch + "/sdk-tree-qualified.json", "fixed-qualification-confirmation")
    _need(selected["receipt"]["path"] == epoch + "/sdk-tree-created/receipt.json" and selected["inventory"]["path"] == epoch + "/sdk-tree-created/inventory.json", "immutable-selected-members")
    material = selected["materialization"]
    _need(type(material) == "dict" and sorted(material.keys()) == ["action_inputs_sha256", "recipe_sha256"] and all([_hex(value) for value in material.values()]), "logical-materialization-pins")
    outer = _read(ctx, _physical(ctx, producer["receipt"]), 1048576)
    publication = {
        "schema_version": 1,
        "kind": "omux-retained-sdk-tree-terminal-publication-v1",
        "state": "committed-at-canonical-rename",
        "method": "qualified-input-drain-before-owned-atomic-rename-v1",
        "original_entry_monotonic_ns": int(creator["ENTRY_NS"]),
        "original_deadline_monotonic_ns": int(creator["DEADLINE_NS"]),
        "publication_cutoff_monotonic_ns": int(creator["DEADLINE_NS"]) - 30 * 1000000000,
        "writer_exclusive_through_commit": True,
        "qualification_input_closes_verified_before_commit": True,
        "post_commit_writer_release_is_receipt_authority": False,
        "current_parent_lock_claim": False,
        "sdk_execution_qualified": False,
        "source_qualified": False,
        "runtime_qualified": False,
    }
    _need(outer.get("native_sdk_tree_terminal_publication") == publication, "owned-terminal-commit-record")
    confirmation = _read(ctx, _physical(ctx, selected["confirmation"]["path"]), 65536)
    _need(sorted(confirmation.keys()) == sorted(["schema_version", "kind", "epoch", "profile", "source_commit", "graph_sha256", "receipt", "original_entry_monotonic_ns", "original_deadline_monotonic_ns", "observed_qualified_monotonic_ns", "canonical_receipt_creator_witness", "qualification", "sdk_execution_qualified", "source_qualified", "runtime_qualified"]), "closed-qualification-confirmation")
    _need(confirmation["schema_version"] == 1 and confirmation["kind"] == "omux-retained-sdk-tree-qualification-confirmation-v1" and confirmation["epoch"] == epoch and confirmation["profile"] == _PROFILE and confirmation["source_commit"] == creator["SOURCE_COMMIT"] and confirmation["graph_sha256"] == creator["GRAPH_SHA256"] and confirmation["receipt"] == {"sha256": producer["sha256"], "bytes": len(ctx.read(_physical(ctx, producer["receipt"]), watch = "no"))}, "qualified-canonical-receipt-context")
    _need(confirmation["original_entry_monotonic_ns"] == int(creator["ENTRY_NS"]) and confirmation["original_deadline_monotonic_ns"] == int(creator["DEADLINE_NS"]) and type(confirmation["observed_qualified_monotonic_ns"]) == "int" and int(creator["ENTRY_NS"]) <= confirmation["observed_qualified_monotonic_ns"] and confirmation["observed_qualified_monotonic_ns"] < int(creator["DEADLINE_NS"]) - 30 * 1000000000, "observed-timely-qualification")
    _need(confirmation["qualification"] == {"scope": "same-owned-canonical-receipt-postcommit-full-proof-v1", "canonical_held_named_join": True, "current_graph_join": True, "qualification_input_closes_verified": True, "original_cutoff_join": True, "writer_exclusive": True, "current_parent_lock_claim": False} and confirmation["sdk_execution_qualified"] == False and confirmation["source_qualified"] == False and confirmation["runtime_qualified"] == False, "qualification-provenance-only")
    _need(type(confirmation["canonical_receipt_creator_witness"]) == "list" and len(confirmation["canonical_receipt_creator_witness"]) == 9 and all([type(value) == "int" for value in confirmation["canonical_receipt_creator_witness"]]) and confirmation["canonical_receipt_creator_witness"][6] == confirmation["receipt"]["bytes"], "canonical-creator-witness-shape")
    _need(outer.get("id") == epoch.split("/")[-1] and outer.get("profile") == _PROFILE and outer.get("verb") == "test" and outer.get("targets") == [_TARGET] and type(outer.get("exit")) == "int" and outer["exit"] == 0 and type(outer.get("workload_exit")) == "int" and outer["workload_exit"] == 0 and outer.get("controller_failure") == None and outer.get("descendants_empty") == True and outer.get("cleanup", {}).get("state") == "empty" and outer.get("cleanup", {}).get("ownership") == "verified" and outer.get("cleanup", {}).get("readback_attempts", 0) >= 2 and outer.get("source_dirty") == "false" and outer.get("source_commit") == producer["source_commit"] and outer.get("graph_sha256") == producer["graph_sha256"], "successful-fixed-creator")
    retained = outer.get("test_evidence")
    _need(type(retained) == "dict" and retained.get("state") == "preserved" and _hex(retained.get("sha256")), "evidence-pin")
    evidence_path = epoch + "/test-evidence.json"
    evidence = _read(ctx, _physical(ctx, evidence_path), 4194304)
    _need(evidence.get("schema") == 1 and type(evidence.get("bazel_exit")) == "int" and evidence["bazel_exit"] == 0 and evidence.get("targets") == [_TARGET] and evidence.get("epoch_start_ns") == outer.get("epoch_start_ns") and type(evidence.get("results")) == "list" and len(evidence["results"]) == 1, "single-observed-creator")
    result = evidence["results"][0]
    _need(type(result) == "dict" and result.get("target") == _TARGET and result.get("state") == "observed" and type(result.get("files")) == "list" and len(result["files"]) <= 64, "creator-test-result")
    origin = outer.get("native_sdk_tree_artifact_origin")
    _need(type(origin) == "dict" and origin.get("creator_context") == creator and origin.get("materialization") == material and type(origin.get("created_metadata")) == "list" and len(origin["created_metadata"]) == 4, "creator-copy-ledger")
    names = ["creator-context.json", "inventory.json", "receipt.json", "recipe.json"]
    copied = {}
    for index in range(4):
        row = origin["created_metadata"][index]
        _need(type(row) == "dict" and sorted(row.keys()) == ["bytes", "name", "path", "sha256"] and row["name"] == names[index], "ordered-copy-ledger")
        pin = {key: row[key] for key in ["path", "sha256", "bytes"]}
        _row(pin, 268435456 if row["name"] in ["inventory.json", "recipe.json"] else 65536)
        _need(row["path"] == epoch + "/sdk-tree-created/" + row["name"], "fixed-copy-path")
        copied[row["name"]] = pin
    _need(copied["receipt.json"] == selected["receipt"] and copied["inventory.json"] == selected["inventory"] and copied["recipe.json"]["sha256"] == material["recipe_sha256"], "selected-copy-commitments")
    proofs = {
        "outer_receipt": {"path": producer["receipt"], "sha256": producer["sha256"], "bytes": len(ctx.read(_physical(ctx, producer["receipt"]), watch = "no")), "alias": _ALIASES[0]},
        "test_evidence": {"path": evidence_path, "sha256": retained["sha256"], "bytes": len(ctx.read(_physical(ctx, evidence_path), watch = "no")), "alias": _ALIASES[1]},
        "program_receipt": dict(copied["receipt.json"], alias = _ALIASES[4]),
        "selected_inventory": dict(copied["inventory.json"], alias = _ALIASES[5]),
        "selected_recipe": dict(copied["recipe.json"], alias = _ALIASES[6]),
        "selected_creator_context": dict(copied["creator-context.json"], alias = _ALIASES[7]),
        "qualification_confirmation": dict(selected["confirmation"], alias = _ALIASES[8]),
    }
    for source, role, alias in [("test.log", "test_log", _ALIASES[2]), ("test.xml", "test_xml", _ALIASES[3])]:
        entries = [entry for entry in result["files"] if type(entry) == "dict" and entry.get("source") == source]
        _need(len(entries) == 1, "unique-observed-test-member")
        entry = entries[0]
        name = entry.get("file")
        _need(entry.get("state") == "copied" and type(name) == "string" and name.endswith(".evidence") and _hex(name[:-len(".evidence")]) and _hex(entry.get("sha256")) and type(entry.get("bytes")) == "int" and 0 < entry["bytes"] and entry["bytes"] <= 67108864, "copied-test-member")
        proofs[role] = {"path": epoch + "/test-evidence/" + name, "sha256": entry["sha256"], "bytes": entry["bytes"], "alias": alias}
    _need(len({proofs[role]["path"]: True for role in _ROLES}) == 9, "distinct-current-proof-roles")
    for role in _ROLES:
        physical = _physical(ctx, proofs[role]["path"])
        ctx.watch(physical)
        ctx.symlink(physical, proofs[role]["alias"])
    for role in _ROLES:
        _physical(ctx, proofs[role]["path"])
    ctx.file("selection.bzl", "SDK_TREE_CREATOR_CONTEXT = " + repr(creator) + "\n", executable = False)
    ctx.file("sdk-tree-proof-inputs.json", json.encode({"kind": "omux-retained-public-sdk-tree-proof-inputs-v1", "proofs": proofs}) + "\n", executable = False)
    files = _ALIASES + ["sdk-tree-proof-inputs.json"]
    ctx.file("BUILD.bazel", 'package(default_visibility=["//visibility:public"])\nexports_files(' + repr(files + ["selection.bzl"]) + ')\nfilegroup(name="inputs",srcs=' + repr(files) + ')\n', executable = False)

codex_retained_sdk_tree_proof_inputs = repository_rule(
    implementation = _implementation,
    attrs = {"selection": attr.label(mandatory = True, allow_single_file = True)},
    local = True,
)
