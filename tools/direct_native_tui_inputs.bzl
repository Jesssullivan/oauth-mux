"""Exact public PACKAGE data only; all authority is validated in the TEST."""
_ROOTS = ["/home/jess/.local/state/omux-execution-20261005/", "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/"]
_ENV = ["OMUX_NATIVE_ORDINARY_MODE", "OMUX_NATIVE_ORDINARY_ENTRY_NS", "OMUX_NATIVE_ORDINARY_DEADLINE_NS"]
_OUTPUTS = ["fresh-native-runtime.tar.gz", "runtime-manifest.json", "runtime-receipt.json", "registration-receipt.json", "package-selection.json", "package-outputs.json"]

def _path(value):
    return type(value) == "string" and value.startswith("/") and not any([p in ["", ".", ".."] for p in value.split("/")[1:]]) and not any([c in value for c in ["\\", "\n", "\r", "\t", " ", ":", "\000"]])

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
    if not (0 < len(raw) and len(raw) <= maximum):
        fail("ordinary direct metadata bound")
    return raw

def _store_root(value):
    if not _path(value) or len(value) > 4096 or not value.startswith("/nix/store/") or len(value.split("/")) != 4:
        return False
    name = value.split("/")[3]
    return len(name) > 33 and name[32] == "-" and all([name[index] in "0123456789abcdfghijklmnpqrsvwxyz" for index in range(32)])

def _runtime_mapping(raw, entry, deadline):
    if not (0 < len(raw) and len(raw) <= 16 * 1024 * 1024):
        fail("ordinary captured runtime map bound")
    mapping = json.decode(raw)
    if type(mapping) != "dict" or sorted(mapping.keys()) != ["kind", "members", "original_deadline_monotonic_ns", "original_entry_monotonic_ns", "roots", "schema_version"] or type(mapping["schema_version"]) != "int" or mapping["schema_version"] != 1 or mapping["kind"] != "omux-direct-carrier-runtime-closure-inputs-v1" or type(mapping["original_entry_monotonic_ns"]) != "int" or mapping["original_entry_monotonic_ns"] != entry or type(mapping["original_deadline_monotonic_ns"]) != "int" or mapping["original_deadline_monotonic_ns"] != deadline:
        fail("ordinary captured runtime context differs")
    roots = mapping["roots"]
    members = mapping["members"]
    if type(roots) != "list" or not (0 < len(roots) and len(roots) <= 32) or len(roots) != len({name:True for name in roots}) or any([not _store_root(name) for name in roots]) or type(members) != "list" or len(members) > 100000:
        fail("ordinary captured runtime role bounds differ")
    paths = {}
    aliases = {}
    for row in members:
        if type(row) != "dict" or sorted(row.keys()) != ["alias", "path"] or not _path(row["path"]) or len(row["path"]) > 4096 or type(row["alias"]) != "string" or len(row["alias"]) > 4096:
            fail("ordinary captured runtime member shape differs")
        root = "/".join(row["path"].split("/")[:4])
        if root not in roots or row["path"] == root:
            fail("ordinary captured runtime member root differs")
        relative = row["path"][len(root) + 1:]
        if len(relative.split("/")) > 128 or row["alias"] != "runtime-closure/root-" + str(roots.index(root)) + "/" + relative or row["path"] in paths or row["alias"] in aliases:
            fail("ordinary captured runtime alias/depth differs")
        paths[row["path"]] = True
        aliases[row["alias"]] = True
    return mapping

def _publish_runtime(ctx, raw, entry, deadline):
    # All map admission happens before any file, symlink or BUILD mutation.
    mapping = _runtime_mapping(raw, entry, deadline)
    ctx.file("runtime-closure-inputs.json", raw, executable = False)
    for number, name in enumerate(mapping["roots"]):
        ctx.symlink(ctx.path(name), "runtime-closure/root-" + str(number))
    return [row["alias"] for row in mapping["members"]]

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
    carrier = root.endswith("/testlogs/tools/codex_native_carrier_runtime_package/test.outputs/fresh-native-runtime")
    if not _path(root) or not any([root.startswith(p) for p in _ROOTS]) or not (carrier or root.endswith("/testlogs/tools/codex_native_acquisition_runtime_package/test.outputs/fresh-native-runtime")):
        fail("ordinary direct package must name original TEST output namespace")
    for name in _OUTPUTS:
        ctx.symlink(_physical(ctx, root + "/" + name), name)
    rows = json.decode(_read(ctx, root + "/package-selection.json", 16 * 1024 * 1024))
    expected_kind = "omux-native-carrier-native-package-selection-v2" if carrier else "omux-native-source-acquisition-native-package-selection-v1"
    if rows.get("kind") != expected_kind or rows.get("schema_version") != (2 if carrier else 1) or rows.get("purpose") != "evaluation-only":
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
    if carrier:
        retained = rows["carrier_materials"]
        if sorted(retained["receipts"].keys()) != ["authority_document", "carrier_receipt", "metadata_program", "seal_program"] or sorted(retained["authorities"].keys()) != ["metadata", "seal"]:
            fail("ordinary carrier compact role set differs")
        for name, row in retained["receipts"].items():
            entries["carrier/" + name] = row
        for action, group in retained["authorities"].items():
            if sorted(group.keys()) != ["evidence", "members", "outer"] or len(group["members"]) != 2:
                fail("ordinary carrier compact proof group differs")
            prefix = "carrier-authority/" + action + "/"
            entries[prefix + "outer"] = group["outer"]
            entries[prefix + "evidence"] = group["evidence"]
            for name, row in group["members"].items():
                entries[prefix + name] = row
    if len(entries) > 4096:
        fail("ordinary direct input count bound")
    total = 0
    for index, role in enumerate(sorted(entries)):
        row = entries[role]
        if sorted(row.keys()) != ["bytes", "path", "sha256"] or not _sha(row["sha256"]) or type(row["bytes"]) != "int" or not (0 < row["bytes"] and row["bytes"] <= (512 * 1024 * 1024 if role == "codex" else 16 * 1024 * 1024)):
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
    if carrier:
        sources = [row["source"] for row in members]
        allowed = ["test.log", "test.xml", "test.outputs_manifest/MANIFEST", "test.outputs_manifest/ANNOTATIONS"]
        if not (2 <= len(members) and len(members) <= 4) or len(sources) != len({name:True for name in sources}) or any([name not in allowed for name in sources]):
            fail("ordinary carrier collector diagnostics differ")
        members = [row for row in members if row["source"] in ["test.log", "test.xml"]]
        if sorted([row["source"] for row in members]) != ["test.log", "test.xml"]:
            fail("ordinary carrier required proof leaves differ")
    elif len(members) != 2:
        fail("ordinary direct package evidence member bound")
    for index, member in enumerate(members):
        leaf = member["file"]
        if member["state"] != "copied" or not leaf.endswith(".evidence") or not _sha(leaf[:-9]):
            fail("ordinary direct package evidence leaf differs")
        alias = "package-evidence-" + str(index)
        ctx.symlink(_physical(ctx, parent + "/test-evidence/" + leaf), alias)
        names.append(alias)
    closure_files = []
    if carrier:
        environment = {key:ctx.os.environ.get(key, "") for key in _ENV}
        if environment["OMUX_NATIVE_ORDINARY_MODE"] != "native-acquisition-ordinary-tui-reserved":
            fail("ordinary runtime declaration needs original repository clock")
        for key in _ENV[1:]:
            value = environment[key]
            if not (0 < len(value) and len(value) <= 19) or value[0] == "0" or any([c not in "0123456789" for c in value.elems()]):
                fail("ordinary runtime declaration clock differs")
        entry = int(environment[_ENV[1]])
        deadline = int(environment[_ENV[2]])
        if entry <= 0 or deadline - entry != 1200 * 1000000000 or deadline >= 9223372036854775808:
            fail("ordinary runtime declaration original envelope differs")
        python = ctx.path(ctx.attr._python)
        scanner = ctx.path(ctx.attr._scanner)
        ctx.watch(python)
        ctx.watch(scanner)
        made = ctx.execute([str(python), "-I", "-S", str(scanner),
            "--registration", str(_physical(ctx, root + "/registration-receipt.json"))],
            timeout = 1170, environment = environment)
        if made.return_code != 0 or not (0 < len(made.stdout) and len(made.stdout) <= 16 * 1024 * 1024):
            fail("ordinary bounded runtime declaration refused")
        closure_files = _publish_runtime(ctx, made.stdout, entry, deadline)
        names.append("runtime-closure-inputs.json")
    ctx.file("input-pin.json", raw)
    ctx.file("input-pin.sha256", selected["sha256"] + "\n")
    ctx.file("BUILD.bazel", "exports_files(" + repr(names) + ")\nfilegroup(name='inputs',srcs=" + repr(names) + ("+" + repr(closure_files) if carrier else "") + ",visibility=['//visibility:public'])\n")

ordinary_direct_native_inputs = repository_rule(implementation=_impl, attrs={
    "manifest":attr.label(mandatory=True, allow_single_file=True),
    "_scanner":attr.label(default=Label("//tools:direct_native_runtime_closure_inputs.py"), allow_single_file=True),
    "_python":attr.label(default=Label("@omux_nix//:tool_wrappers/python"), allow_single_file=True),
}, environ=_ENV, local=True)
