"""Finite selected evaluation package inputs; no execution or fallback family."""
_ROLES = ["source", "sdk", "sdk_metadata", "plan", "query", "compiler_selection", "compiler_ledger", "compiler_ledger_snapshot", "compiler", "compiler_outer", "codex", "config_schema"]
_ROOTS = ["/home/jess/.local/state/omux-execution-20261005/", "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/", "/srv/fast-local/jess/state/codex/omux-native-candidate-20261007/"]

def _path(value):
    return type(value) == "string" and value.startswith("/") and not any([p in ["", ".", ".."] for p in value.split("/")[1:]]) and not any([c in value for c in ["\\", "\n", "\r", "\t", " ", ":"]])

def _sha(value):
    return type(value) == "string" and len(value) == 64 and all([c in "0123456789abcdef" for c in value.elems()])

def package_member_path_valid(role, path, sha256):
    """The compiler's one fixed public ledger snapshot is not a generic root."""
    if not _path(path) or not _sha(sha256):
        return False
    if role == "compiler_ledger_snapshot":
        # Matches compilation.PUBLIC_ROOT / GOAL_SNAPSHOT_PREFIX exactly.
        return path == "/srv/fast-local/jess/git/oauth-mux/docs/agent-notes/2026-10-10-native-acquisition-input-lift.UNAPPLIED/ledger-snapshots/" + sha256 + ".json"
    return any([path.startswith(root) for root in _ROOTS])

def package_configuration_valid(value):
    """Declaration only: actual package action must prove every selected authority."""
    if type(value) != "dict" or sorted(value.keys()) != ["kind", "schema_version", "selection", "status"] or type(value["schema_version"]) != "int" or value["schema_version"] != 1 or value["kind"] != "omux-native-acquisition-package-input-configuration-v1":
        return False
    if value["status"] == "awaiting-qualified-material":
        return value["selection"] == None
    row = value["selection"]
    return value["status"] == "selected-material" and type(row) == "dict" and sorted(row.keys()) == ["path", "sha256"] and _path(row["path"]) and len(row["path"]) <= 4096 and "\000" not in row["path"] and _sha(row["sha256"]) and any([row["path"].startswith(root) for root in _ROOTS])

def carrier_package_shape_valid(value):
    """Closed compact declaration; action independently authenticates contents."""
    if type(value) != "dict" or sorted(value.keys()) != ["authority_receipts", "carrier_materials", "compilation", "files", "kind", "material", "native_acquisition_artifact_files", "protocol_schema_files", "purpose", "schema_version"] or type(value["schema_version"]) != "int" or value["schema_version"] != 2 or value["kind"] != "omux-native-carrier-native-package-selection-v2" or value["purpose"] != "evaluation-only":
        return False
    retained = value["carrier_materials"]
    if type(retained) != "dict" or sorted(retained.keys()) != ["authorities", "authority_sha256", "carrier_files", "kind", "projection", "receipts", "schema_version"] or type(retained["schema_version"]) != "int" or retained["schema_version"] != 2 or retained["kind"] != "omux-native-carrier-retained-authority-v2" or not _sha(retained["authority_sha256"]):
        return False
    if type(retained["receipts"]) != "dict" or sorted(retained["receipts"].keys()) != ["authority_document", "carrier_receipt", "metadata_program", "seal_program"] or type(retained["authorities"]) != "dict" or sorted(retained["authorities"].keys()) != ["metadata", "seal"]:
        return False
    if not all([type(row) == "dict" for row in retained["receipts"].values()]):
        return False
    projection = retained["projection"]
    if type(projection) != "dict" or sorted(projection.keys()) != ["graph_inventory_sha256", "hub_inventory_sha256", "inventory_sha256", "receipt_sha256"] or not all([_sha(pin) for pin in projection.values()]):
        return False
    transport = retained["carrier_files"]
    if type(transport) != "list" or len(transport) != 4:
        return False
    for index, name in enumerate(["manifest.json", "origin-receipt.json", "payload.bin", "receipt.json"]):
        row = transport[index]
        if type(row) != "dict" or sorted(row.keys()) != ["bytes", "name", "sha256"] or row["name"] != name or not _sha(row["sha256"]) or type(row["bytes"]) != "int" or row["bytes"] <= 0:
            return False
    for group in retained["authorities"].values():
        if type(group) != "dict" or sorted(group.keys()) != ["evidence", "members", "outer"] or type(group["members"]) != "dict" or len(group["members"]) != 2 or not all([type(name) == "string" and name.endswith(".evidence") and _sha(name[:-9]) for name in group["members"]]):
            return False
    return type(value["files"]) == "dict" and sorted(value["files"].keys()) == sorted(_ROLES) and all([type(row) == "dict" for row in value["files"].values()]) and retained["receipts"]["metadata_program"] == value["files"]["sdk_metadata"] and retained["receipts"]["authority_document"].get("sha256") == retained["authority_sha256"] and projection["inventory_sha256"] == retained["authority_sha256"] and projection["receipt_sha256"] == value["files"]["sdk"].get("sha256")

def carrier_package_entries(value):
    result = {"carrier/" + role: row for role, row in value["carrier_materials"]["receipts"].items()}
    for action, group in value["carrier_materials"]["authorities"].items():
        result["carrier-authority/" + action + "/outer"] = group["outer"]
        result["carrier-authority/" + action + "/evidence"] = group["evidence"]
        for name, row in group["members"].items():
            result["carrier-authority/" + action + "/" + name] = row
    return result

def _impl(ctx):
    manifest = ctx.path(ctx.attr.manifest)
    configuration_raw = ctx.read(manifest)
    if len(configuration_raw) > 16384:
        fail("package configuration exceeds bound")
    configuration = json.decode(configuration_raw)
    if not package_configuration_valid(configuration):
        fail("package configuration must be closed pending or explicitly selected material")
    ctx.watch(manifest)
    row = configuration["selection"]
    # Pending configuration remains an executable refusal, before selected host
    # paths are consulted. It never claims an actual source/compiler tuple.
    if row == None:
        ctx.file("package-selection.json", json.encode({"kind":"unconfigured-native-acquisition-package", "configured":False}) + "\n")
        ctx.file("package-selection.sha256", "unconfigured\n")
        ctx.file("input-aliases.json", "{}\n")
        ctx.file("BUILD.bazel", "exports_files(['package-selection.json','package-selection.sha256','input-aliases.json'])\nfilegroup(name='inputs',srcs=glob(['*.json','*.sha256']),visibility=['//visibility:public'])\n")
        return
    selected = ctx.path(row["path"])
    if not selected.exists or selected.is_dir or str(selected.realpath) != row["path"]:
        fail("package selection must have physical ancestry")
    ctx.watch(selected)
    raw = ctx.read(selected)
    if len(raw) > 16 * 1024 * 1024:
        fail("package selection exceeds metadata bound")
    value = json.decode(raw)
    carrier = value.get("kind") == "omux-native-carrier-native-package-selection-v2"
    if (carrier and not carrier_package_shape_valid(value)) or (not carrier and (value.get("kind") != "omux-native-source-acquisition-native-package-selection-v1" or value.get("purpose") != "evaluation-only" or sorted(value.get("files", {}).keys()) != sorted(_ROLES))):
        fail("package requires distinct modern evaluation material")
    if not carrier and (type(value.get("schema_version")) != "int" or value["schema_version"] != 1 or "carrier_materials" in value):
        fail("package mixed schema/material family")
    entries = dict(value["files"])
    for family, prefix in [("protocol_schema_files", "schema/"), ("native_acquisition_artifact_files", "evidence/")]:
        pins = value.get(family)
        if type(pins) != "dict" or not pins or len(pins) > 4096:
            fail("package map bounds differ")
        for name, pin in pins.items():
            if type(name) != "string" or name.startswith("/") or any([p in ["", ".", ".."] for p in name.split("/")]):
                fail("package logical member name is unsafe")
            entries[prefix + name] = pin
    groups = value.get("authority_receipts", {})
    if sorted(groups.keys()) != ["compiler", "plan", "query", "sdk", "source"]:
        fail("package requires full five authority groups")
    for action, group in groups.items():
        if sorted(group.keys()) != ["evidence", "members", "outer"] or len(group["members"]) != (6 if action == "source" else 2):
            fail("package authority shape differs")
        entries["authority/" + action + "/outer"] = group["outer"]
        entries["authority/" + action + "/evidence"] = group["evidence"]
        for name, pin in group["members"].items():
            if not name.endswith(".evidence") or not _sha(name[:-9]):
                fail("package authority member name differs")
            entries["authority/" + action + "/" + name] = pin
    if len(entries) > 4096:
        fail("package total input count bound")
    if carrier:
        entries.update(carrier_package_entries(value))
        if len(entries) + 3 > 4096:
            fail("carrier package count includes declaration controls")
        projected_aliases = {role: ctx.name + "/input-" + str(index) for index, role in enumerate(sorted(entries))}
        retained_bytes = len(raw) + 65 + len(json.encode(projected_aliases) + "\n")
        for role, pin in entries.items():
            if type(pin) != "dict" or sorted(pin.keys()) != ["bytes", "path", "sha256"] or not _path(pin["path"]) or not _sha(pin["sha256"]) or type(pin["bytes"]) != "int" or not (0 < pin["bytes"] and pin["bytes"] <= (512 * 1024 * 1024 if role == "codex" else 16 * 1024 * 1024)) or not package_member_path_valid(role, pin["path"], pin["sha256"]):
                fail("carrier bounded compact declaration row")
            retained_bytes += pin["bytes"]
        if retained_bytes > 512 * 1024 * 1024:
            fail("carrier aggregate includes aliases and declaration before retention")
    aliases, names, total = {}, [], 0
    for index, role in enumerate(sorted(entries)):
        pin = entries[role]
        if type(pin) != "dict" or sorted(pin.keys()) != ["bytes", "path", "sha256"] or not _path(pin["path"]) or not _sha(pin["sha256"]) or type(pin["bytes"]) != "int" or not (0 < pin["bytes"] and pin["bytes"] <= (512 * 1024 * 1024 if role == "codex" else 16 * 1024 * 1024)):
            fail("package bounded literal row differs")
        if not package_member_path_valid(role, pin["path"], pin["sha256"]):
            fail("package input leaves finite owned public roots")
        total += pin["bytes"]
        if total > 512 * 1024 * 1024:
            fail("package aggregate selected bytes bound")
        source = ctx.path(pin["path"])
        if not source.exists or source.is_dir or str(source.realpath) != pin["path"]:
            fail("package selected input must have physical ancestry")
        ctx.watch(source)
        alias = "input-" + str(index)
        ctx.symlink(source, alias)
        names.append(alias)
        aliases[role] = ctx.name + "/" + alias
    # Cryptographic and full action/readback validation occurs in the declared
    # producer, before any package transformation, against these pinned rows.
    ctx.file("package-selection.json", raw)
    ctx.file("package-selection.sha256", row["sha256"] + "\n")
    ctx.file("input-aliases.json", json.encode(aliases) + "\n")
    names += ["package-selection.json", "package-selection.sha256", "input-aliases.json"]
    ctx.file("BUILD.bazel", "exports_files(" + repr(names) + ")\nfilegroup(name='inputs',srcs=" + repr(names) + ",visibility=['//visibility:public'])\n")

codex_native_acquisition_package_inputs = repository_rule(implementation=_impl, attrs={"manifest":attr.label(mandatory=True, allow_single_file=True)}, local=True)

def _extension(ctx):
    tags = [tag for module in ctx.modules for tag in module.tags.configuration]
    if len(tags) != 1 or not any([module.is_root and len(module.tags.configuration) == 1 for module in ctx.modules]):
        fail("package inputs require one explicit root configuration")
    codex_native_acquisition_package_inputs(name="omux_native_acquisition_package_data", manifest=tags[0].manifest)

native_acquisition_package_inputs = module_extension(implementation=_extension, tag_classes={"configuration":tag_class(attrs={"manifest":attr.label(mandatory=True)})})
