"""Finite selected evaluation package inputs; no execution or fallback family."""
_ROLES = ["source", "sdk", "sdk_metadata", "plan", "query", "compiler_selection", "compiler_ledger", "compiler_ledger_snapshot", "compiler", "compiler_outer", "codex", "config_schema"]
_ROOTS = ["/home/jess/.local/state/omux-execution-20261005/", "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/", "/srv/fast-local/jess/state/codex/omux-native-candidate-20261007/"]

def _path(value):
    return type(value) == "string" and value.startswith("/") and not any([p in ["", ".", ".."] for p in value.split("/")[1:]]) and not any([c in value for c in ["\\", "\n", "\r", "\t", " ", ":"]])

def _sha(value):
    return type(value) == "string" and len(value) == 64 and all([c in "0123456789abcdef" for c in value.elems()])

def _impl(ctx):
    # Pending configuration remains an executable refusal, before selected host
    # paths are consulted. It never claims an actual source/compiler tuple.
    if not ctx.attr.selection and not ctx.attr.sha256:
        ctx.file("package-selection.json", json.encode({"kind":"unconfigured-native-acquisition-package", "configured":False}) + "\n")
        ctx.file("package-selection.sha256", "unconfigured\n")
        ctx.file("input-aliases.json", "{}\n")
        ctx.file("BUILD.bazel", "exports_files(['package-selection.json','package-selection.sha256','input-aliases.json'])\nfilegroup(name='inputs',srcs=glob(['*.json','*.sha256']),visibility=['//visibility:public'])\n")
        return
    if not _path(ctx.attr.selection) or not _sha(ctx.attr.sha256) or not any([ctx.attr.selection.startswith(root) for root in _ROOTS]):
        fail("package selection must be an exact pinned owned public file")
    selected = ctx.path(ctx.attr.selection)
    if not selected.exists or selected.is_dir or str(selected.realpath) != ctx.attr.selection:
        fail("package selection must have physical ancestry")
    ctx.watch(selected)
    raw = ctx.read(selected)
    if len(raw) > 16 * 1024 * 1024:
        fail("package selection exceeds metadata bound")
    value = json.decode(raw)
    if value.get("kind") != "omux-native-source-acquisition-native-package-selection-v1" or value.get("purpose") != "evaluation-only" or sorted(value.get("files", {}).keys()) != sorted(_ROLES):
        fail("package requires distinct modern evaluation material")
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
    aliases, names, total = {}, [], 0
    for index, role in enumerate(sorted(entries)):
        pin = entries[role]
        if type(pin) != "dict" or sorted(pin.keys()) != ["bytes", "path", "sha256"] or not _path(pin["path"]) or not _sha(pin["sha256"]) or type(pin["bytes"]) != "int" or not 0 < pin["bytes"] <= (512 * 1024 * 1024 if role == "codex" else 16 * 1024 * 1024):
            fail("package bounded literal row differs")
        if not any([pin["path"].startswith(root) for root in _ROOTS]):
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
    ctx.file("package-selection.sha256", ctx.attr.sha256 + "\n")
    ctx.file("input-aliases.json", json.encode(aliases) + "\n")
    names += ["package-selection.json", "package-selection.sha256", "input-aliases.json"]
    ctx.file("BUILD.bazel", "exports_files(" + repr(names) + ")\nfilegroup(name='inputs',srcs=" + repr(names) + ",visibility=['//visibility:public'])\n")

codex_native_acquisition_package_inputs = repository_rule(implementation=_impl, attrs={"selection":attr.string(), "sha256":attr.string()}, local=True)

def _extension(ctx):
    codex_native_acquisition_package_inputs(name="omux_native_acquisition_package_data")

native_acquisition_package_inputs = module_extension(implementation=_extension)
