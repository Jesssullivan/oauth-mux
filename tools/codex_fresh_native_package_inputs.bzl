"""Finite independently pinned fresh-native package inputs; no tool execution."""
_ROLES = ["source","export","compile","qualification_run","qualification","qualification_xml","schema_run","config_schema","codex"]
_HOME = "/home/jess/.local/state/omux-execution-20261005/"
_NATIVE = "/srv/fast-local/jess/state/codex/omux-native-candidate-20261007/"

def _hash(value):
    return len(value) == 64 and all([c in "0123456789abcdef" for c in value.elems()])

def _path(value):
    return value.startswith("/") and "//" not in value and ".." not in value.split("/") and not any([c in value for c in ["\\","\n","\r","\t",":"," "]])

def _selected_impl(ctx):
    path = ctx.attr.selection
    if not _path(path) or not path.endswith("/package-selection.json") or not _hash(ctx.attr.sha256):
        fail("fresh package selection requires exact canonical public path and literal SHA")
    if not (path.startswith(_HOME) or path.startswith(_NATIVE)):
        fail("fresh package selection must remain in the owned public operator state")
    selected = ctx.path(path)
    if str(selected.realpath) != path:
        fail("fresh package selection may not have symlink components")
    raw = ctx.read(selected)
    if len(raw) > 16 * 1024 * 1024:
        fail("fresh package selection exceeds finite metadata bound")
    value = json.decode(raw)
    if value.get("kind") != "omux-fresh-native-package-selection-v1" or sorted(value.get("files", {}).keys()) != sorted(_ROLES):
        fail("fresh package exact input role schema differs")
    if sorted(value.get("protocol_schema_roots", {}).keys()) != ["experimental","stable"]:
        fail("fresh package requires both generated JSON schema roots")
    pins = value.get("protocol_schema_files", {})
    if not pins or len(pins) > 4096:
        fail("fresh package protocol JSON inventory bound")
    entries = dict(value["files"])
    for name,pin in pins.items():
        if not (name.startswith("stable/json/") or name.startswith("experimental/json/")) or not name.endswith(".json") or ".." in name.split("/"):
            fail("fresh package protocol JSON member name differs")
        entries["protocol/"+name] = pin
    names, aliases = [], {}
    for index,role in enumerate(sorted(entries)):
        pin = entries[role]
        source = pin.get("path","")
        if sorted(pin.keys()) != ["bytes","path","sha256"] or not _path(source) or not _hash(pin["sha256"]) or type(pin["bytes"]) != "int" or pin["bytes"] < 0 or pin["bytes"] > 1073741824:
            fail("fresh package selected file pin differs")
        if role in ["source","export"]:
            suffix = "/tools/codex_live_source_producer/test.outputs/codex-live-source/source-receipt.json" if role == "source" else "/tools/codex_retained_sdk_export_producer/test.outputs/sdk-private/sdk-export/receipt.json"
            if not source.startswith(_HOME) or "/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs" not in source or not source.endswith(suffix):
                fail("fresh package source/export leaves exact declared producer outputs")
        elif role in ["compile","qualification_run","schema_run"]:
            if not source.startswith(_NATIVE) or not source.endswith("/receipt.json") or len(source[len(_NATIVE):].split("/")) != 2:
                fail("fresh package guard receipt leaves exact owned native invocation")
        elif role in ["qualification","qualification_xml"]:
            suffix = "/native-qualification.json" if role=="qualification" else "/native-qualification.xml"
            if not source.startswith(_NATIVE) or not source.endswith(suffix) or len(source[len(_NATIVE):].split("/")) != 2:
                fail("fresh package grouped output leaves owned native invocation")
        else:
            if not source.startswith(_NATIVE+"cache-v2-") or "/output-base/execroot/_main/bazel-out/" not in source or "/bin/" not in source:
                fail("fresh package artifact leaves owned declared native output base")
            if role == "codex" and not source.endswith("/bin/codex-rs/cli/codex"):
                fail("fresh package requires exact freshly built CLI label output")
            if role == "config_schema" and not source.endswith("/bin/bazel/schema/native-config.schema.json"):
                fail("fresh package requires declared generated config schema")
            if role.startswith("protocol/") and "/bin/bazel/schema/public-schema-bundle." not in source:
                fail("fresh package protocol JSON leaves generating action")
        source_path = ctx.path(source)
        if str(source_path.realpath) != source:
            fail("fresh package selected input must have canonical non-symlink ancestry")
        alias = "input-"+str(index)
        ctx.symlink(source_path,alias)
        names.append(alias)
        aliases[role] = ctx.name+"/"+alias
    # Enumerate finite selected JSON roots before Bazel admits their bytes.
    observed = []
    pending = []
    for mode in ["stable","experimental"]:
        root = value["protocol_schema_roots"][mode]
        if not _path(root) or not root.startswith(_NATIVE+"cache-v2-") or not root.endswith("/bin/bazel/schema/public-schema-bundle."+mode+"/json"):
            fail("fresh package protocol root leaves declared JSON output")
        root_path = ctx.path(root)
        if str(root_path.realpath) != root:
            fail("fresh package protocol root ancestry may not be linked")
        pending.append((root_path,mode+"/json/"))
    for unused in range(4097):
        if not pending:
            break
        parent,prefix = pending.pop()
        for member in parent.readdir():
            name = str(member).split("/")[-1]
            if str(member.realpath) != str(member):
                fail("fresh package protocol JSON member may not be linked")
            if member.is_dir:
                pending.append((member,prefix+name+"/"))
            else:
                if not name.endswith(".json"):
                    fail("fresh package protocol JSON subtree has foreign file")
                observed.append(prefix+name)
            if len(observed)+len(pending) > 4096:
                fail("fresh package protocol JSON subtree bound")
    if pending or sorted(observed) != sorted(pins.keys()):
        fail("fresh package protocol JSON inventory must be complete")
    ctx.file("package-selection.json",raw,executable=False)
    ctx.file("package-selection.sha256",ctx.attr.sha256+"\n",executable=False)
    ctx.file("input-aliases.json",json.encode(aliases)+"\n",executable=False)
    names += ["package-selection.json","package-selection.sha256","input-aliases.json"]
    ctx.file("BUILD.bazel","exports_files("+repr(names)+")\nfilegroup(name='inputs',srcs="+repr(names)+")\n")
    
codex_fresh_native_package_inputs = repository_rule(
    implementation=_selected_impl,
    attrs={"selection":attr.string(mandatory=True),"sha256":attr.string(mandatory=True)},
    local=True,
)
