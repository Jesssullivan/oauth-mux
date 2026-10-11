"""Exact public PACKAGE data only; all authority is validated in the TEST."""
_ROOTS = ["/home/jess/.local/state/omux-execution-20261005/", "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/"]
_OUTPUTS = ["fresh-native-runtime.tar.gz", "runtime-manifest.json", "runtime-receipt.json", "registration-receipt.json", "package-selection.json", "package-outputs.json"]

def _path(value):
    return type(value) == "string" and value.startswith("/") and not any([p in ["", ".", ".."] for p in value.split("/")[1:]]) and not any([c in value for c in ["\\", "\n", "\r", "\t", " ", ":"]])

def _sha(value):
    return type(value) == "string" and len(value) == 64 and all([c in "0123456789abcdef" for c in value.elems()])

def _physical(ctx, name):
    if not _path(name) or not any([name.startswith(root) for root in _ROOTS] + [name.startswith("/srv/fast-local/jess/git/oauth-mux/docs/agent-notes/2026-10-10-native-acquisition-input-lift.UNAPPLIED/ledger-snapshots/")]):
        fail("ordinary direct input leaves finite public proof roots")
    result = ctx.path(name)
    if not result.exists or result.is_dir or str(result.realpath) != name:
        fail("ordinary direct input requires physical file ancestry")
    ctx.watch(result)
    return result

def _read(ctx, name, maximum):
    raw = ctx.read(_physical(ctx, name))
    if not 0 < len(raw) <= maximum:
        fail("ordinary direct metadata bound")
    return raw

def _impl(ctx):
    config = json.decode(ctx.read(ctx.attr.manifest))
    if sorted(config.keys()) != ["kind", "schema_version", "selection"] or config["schema_version"] != 1 or config["kind"] != "omux-direct-native-tui-input-configuration-v1":
        fail("ordinary direct configuration differs")
    names = ["input-pin.json", "input-pin.sha256"] + _OUTPUTS
    if config["selection"] == None:
        ctx.file("input-pin.json", "{\"kind\":\"unconfigured-direct-native-tui\"}\n")
        ctx.file("input-pin.sha256", "unconfigured\n")
        for name in _OUTPUTS:
            ctx.file(name, "unconfigured\n")
        ctx.file("BUILD.bazel", "exports_files(" + repr(names) + ")\nfilegroup(name='inputs',srcs=" + repr(names) + ",visibility=['//visibility:public'])\n")
        return
    selected = config["selection"]
    if type(selected) != "dict" or sorted(selected.keys()) != ["path", "sha256"] or not _sha(selected["sha256"]):
        fail("ordinary direct selected pin differs")
    raw = _read(ctx, selected["path"], 65536)
    pin = json.decode(raw)
    if sorted(pin.keys()) != ["kind", "package", "schema_version"] or pin["schema_version"] != 1 or pin["kind"] != "omux-direct-native-tui-package-pin-v1" or sorted(pin["package"].keys()) != ["producer", "root"]:
        fail("ordinary direct versioned package pin differs")
    root = pin["package"]["root"]
    if not _path(root) or not any([root.startswith(p) for p in _ROOTS]) or not root.endswith("/testlogs/tools/codex_native_acquisition_runtime_package/test.outputs/fresh-native-runtime"):
        fail("ordinary direct package must name original TEST output namespace")
    for name in _OUTPUTS:
        ctx.symlink(_physical(ctx, root + "/" + name), name)
    rows = json.decode(_read(ctx, root + "/package-selection.json", 16 * 1024 * 1024))
    if rows.get("kind") != "omux-native-source-acquisition-native-package-selection-v1" or rows.get("purpose") != "evaluation-only":
        fail("ordinary direct package must retain complete modern selection")
    entries = dict(rows["files"])
    for group, prefix in [("protocol_schema_files", "schema/"), ("native_acquisition_artifact_files", "evidence/")]:
        for key, row in rows[group].items():
            entries[prefix + key] = row
    for action, group in rows["authority_receipts"].items():
        entries["authority/" + action + "/outer"] = group["outer"]
        entries["authority/" + action + "/evidence"] = group["evidence"]
        for name, row in group["members"].items():
            entries["authority/" + action + "/" + name] = row
    if len(entries) > 4096:
        fail("ordinary direct input count bound")
    total = 0
    for index, role in enumerate(sorted(entries)):
        row = entries[role]
        if sorted(row.keys()) != ["bytes", "path", "sha256"] or not _sha(row["sha256"]) or type(row["bytes"]) != "int" or not 0 < row["bytes"] <= (512 * 1024 * 1024 if role == "codex" else 16 * 1024 * 1024):
            fail("ordinary direct input row bound")
        total += row["bytes"]
        if total > 512 * 1024 * 1024:
            fail("ordinary direct selected aggregate bound")
        alias = "selected-" + str(index)
        ctx.symlink(_physical(ctx, row["path"]), alias)
        names.append(alias)
    producer = pin["package"]["producer"]
    if sorted(producer.keys()) != ["graph_sha256", "receipt", "sha256", "source_commit"] or not _sha(producer["sha256"]) or not _sha(producer["graph_sha256"]) or len(producer["source_commit"]) != 40:
        fail("ordinary direct package guardian pin differs")
    parent = producer["receipt"].rsplit("/", 1)[0]
    outer = "package-guardian.json"
    ctx.symlink(_physical(ctx, producer["receipt"]), outer)
    evidence_raw = _read(ctx, parent + "/test-evidence.json", 16 * 1024 * 1024)
    ctx.symlink(_physical(ctx, parent + "/test-evidence.json"), "package-evidence.json")
    names += [outer, "package-evidence.json"]
    evidence = json.decode(evidence_raw)
    if len(evidence.get("results", [])) != 1:
        fail("ordinary direct package requires singleton guardian evidence")
    members = evidence["results"][0]["files"]
    if len(members) != 2:
        fail("ordinary direct package evidence member bound")
    for index, member in enumerate(members):
        leaf = member["file"]
        if member["state"] != "copied" or not leaf.endswith(".evidence") or not _sha(leaf[:-9]):
            fail("ordinary direct package evidence leaf differs")
        alias = "package-evidence-" + str(index)
        ctx.symlink(_physical(ctx, parent + "/test-evidence/" + leaf), alias)
        names.append(alias)
    ctx.file("input-pin.json", raw)
    ctx.file("input-pin.sha256", selected["sha256"] + "\n")
    ctx.file("BUILD.bazel", "exports_files(" + repr(names) + ")\nfilegroup(name='inputs',srcs=" + repr(names) + ",visibility=['//visibility:public'])\n")

ordinary_direct_native_inputs = repository_rule(implementation=_impl, attrs={"manifest":attr.label(mandatory=True, allow_single_file=True)}, local=True)
