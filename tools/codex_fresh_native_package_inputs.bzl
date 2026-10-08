"""Finite independently pinned fresh-native package inputs; no tool execution."""
_ROLES = ["source","export","compile","qualification_run","qualification","qualification_xml","schema_run","config_schema","codex"]
_STAGED_ROLES = _ROLES + ["library_run","library_artifacts","compile_artifacts","qualification_artifacts","schema_artifacts"]
_HOME = "/home/jess/.local/state/omux-execution-20261005/"
_NATIVE = "/srv/fast-local/jess/state/codex/omux-native-candidate-20261007/"

def _hash(value):
    return len(value) == 64 and all([c in "0123456789abcdef" for c in value.elems()])

def _path(value):
    return value.startswith("/") and "//" not in value and ".." not in value.split("/") and not any([c in value for c in ["\\","\n","\r","\t",":"," "]])

def _receipt_uuid(value):
    pieces = value.split("-")
    return len(pieces) == 5 and [len(p) for p in pieces] == [8, 4, 4, 4, 12] and all([
        c in "0123456789abcdef" for p in pieces for c in p.elems()
    ])

def receipt_producer(role, path):
    """Return the exact public producer label, or None; no filesystem access."""
    if role not in ["source", "export"] or type(path) != "string" or not _path(path):
        return None
    fast = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/"
    roots = [_HOME] if role == "source" else [_HOME, fast]
    selected = [root for root in roots if path.startswith(root)]
    if len(selected) != 1:
        return None
    root = selected[0]
    parts = path[len(root):].split("/")
    if not parts or not parts[0]:
        return None
    uuid = _receipt_uuid(parts[0])
    if role == "export" and root == fast and uuid and parts[1:] == ["sdk-private", "sdk-export", "receipt.json"]:
        return "//tools:codex_retained_sdk_export_run"
    source_cache = role == "source" and parts[0].startswith("cache-v2-") and _hash(parts[0][len("cache-v2-"):])
    if not (uuid or source_cache):
        return None
    suffix = ["codex_live_source_producer", "test.outputs", "codex-live-source", "source-receipt.json"] if role == "source" else [
        "codex_retained_sdk_export_producer", "test.outputs", "sdk-private", "sdk-export", "receipt.json",
    ]
    expected = ["output-base", "execroot", "_main", "bazel-out", "k8-fastbuild", "testlogs", "tools"] + suffix
    if parts[1:] != expected:
        return None
    return "//tools:" + suffix[0]


_PROTOCOL_ROLES = _ROLES + ["protocol_run","protocol_artifacts","schema_artifacts","cli_artifacts"]
_FAST = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/"

def _protocol_producer(role, source):
    roots = [root for root in [_HOME, _FAST] if source.startswith(root)]
    if len(roots) != 1:
        return False
    parts = source[len(roots[0]):].split("/")
    if not parts or not (_receipt_uuid(parts[0]) or (parts[0].startswith("cache-v2-") and _hash(parts[0][9:]))):
        return False
    prefix = ["output-base","execroot","_main","bazel-out"]
    target = "codex_protocol_history_source_producer" if role == "source" else "codex_protocol_history_sdk_export_producer"
    output = ["protocol-history-source","source-receipt.json"] if role == "source" else ["protocol-history-sdk-export","receipt.json"]
    return len(parts) == 12 and parts[1:5] == prefix and parts[5] and all([c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for c in parts[5].elems()]) and parts[6:] == ["testlogs","tools",target,"test.outputs"] + output

def _protocol_output(source, prefix, tail):
    if not source.startswith(_NATIVE):
        return False
    parts = source[len(_NATIVE):].split("/")
    return len(parts) >= 8 and parts[0].startswith(prefix) and _hash(parts[0][len(prefix):]) and parts[1:5] == ["output-base","execroot","_main","bazel-out"] and parts[5].endswith("-opt") and all([c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-" for c in parts[5].elems()]) and parts[6] == "bin" and "/".join(parts[7:]) == tail

def _protocol_run(source, leaf):
    if not source.startswith(_NATIVE):
        return False
    parts = source[len(_NATIVE):].split("/")
    return len(parts) == 2 and _receipt_uuid(parts[0]) and parts[1] == leaf

def _protocol_selected(ctx, raw, value):
    if sorted(value.keys()) != sorted(["kind","source_root","export_root","patch_sha256","files","protocol_schema_files","protocol_schema_roots","native_cli_selection","protocol_history_artifact_files"]) or sorted(value.get("files",{}).keys()) != sorted(_PROTOCOL_ROLES):
        fail("protocol-history package requires exact thirteen-role document")
    if value["files"]["source"].get("path") != value["source_root"]+"/source-receipt.json" or value["files"]["export"].get("path") != value["export_root"]+"/receipt.json":
        fail("protocol-history source SDK roots differ")
    if type(value["patch_sha256"]) != "list" or len(value["patch_sha256"]) != 4 or not all([type(pin) == "string" and _hash(pin) for pin in value["patch_sha256"]]):
        fail("protocol-history package requires four pinned transformations")
    extra = value["protocol_history_artifact_files"]
    pins = value["protocol_schema_files"]
    roots = value["protocol_schema_roots"]
    if type(extra) != "dict" or len(extra) != 7 or type(pins) != "dict" or not pins or len(pins) > 4096 or sorted(roots.keys()) != ["experimental","stable"]:
        fail("protocol-history exact evidence and complete schema bounds differ")
    entries = dict(value["files"])
    for path,pin in extra.items():
        if path != pin.get("path"):
            fail("protocol-history explicit evidence map key differs")
        entries["protocol-history/"+path] = pin
    for name,pin in pins.items():
        parts = name.split("/")
        if len(parts) < 3 or parts[0] not in ["stable","experimental"] or parts[1] != "json" or any([part in ["",".",".."] for part in parts]) or not name.endswith(".json"):
            fail("protocol-history schema name differs")
        entries["protocol/"+name] = pin
    checked = {}
    total_schema_bytes = 0
    for role,pin in entries.items():
        mode = role.startswith("protocol-history/")
        keys = ["bytes","mode","path","sha256"] if mode else ["bytes","path","sha256"]
        if type(pin) != "dict" or sorted(pin.keys()) != keys or type(pin["path"]) != "string" or not _path(pin["path"]) or type(pin["sha256"]) != "string" or not _hash(pin["sha256"]) or type(pin["bytes"]) != "int" or pin["bytes"] <= 0 or pin["bytes"] > (536870912 if role == "codex" else (268435456 if role in ["source","export"] else 8388608)):
            fail("protocol-history bounded literal input pin differs")
        source = pin["path"]
        if role in ["source","export"]:
            if not _protocol_producer(role,source):
                fail("protocol-history receipt leaves exact declared producer")
        elif role in ["protocol_run","compile","qualification_run","schema_run"]:
            if not _protocol_run(source,"receipt.json"):
                fail("protocol-history receipt leaves actual guard epoch")
        elif role in ["protocol_artifacts","schema_artifacts","cli_artifacts"]:
            if not _protocol_run(source,"protocol-history-cli-artifacts.json" if role == "cli_artifacts" else "protocol-history-native-artifacts.json"):
                fail("protocol-history artifact envelope leaves actual epoch")
        elif role in ["qualification","qualification_xml"]:
            if not _protocol_run(source,"native-qualification.json" if role == "qualification" else "native-qualification.xml"):
                fail("protocol-history qualification leaves actual CLI epoch")
        elif mode:
            if type(pin["mode"]) != "int" or pin["mode"] not in [256,288,292,384,416,420] or not source.startswith(_NATIVE):
                fail("protocol-history copied evidence custody differs")
            parts = source[len(_NATIVE):].split("/")
            if not ((len(parts) == 2 and _receipt_uuid(parts[0]) and parts[1] == "test-evidence.json") or (len(parts) == 3 and _receipt_uuid(parts[0]) and parts[1] == "test-evidence" and parts[2].endswith(".evidence") and _hash(parts[2][:-9]))):
                fail("protocol-history evidence leaves finite actual copied logs")
        elif role == "codex":
            if not _protocol_output(source,"protocol-history-cli-","codex-rs/cli/codex"):
                fail("protocol-history CLI leaves selected new one-shot output")
        elif role == "config_schema":
            if not _protocol_output(source,"protocol-history-checks-","bazel/schema/native-config.schema.json"):
                fail("protocol-history config leaves selected successful schema action")
        elif role.startswith("protocol/"):
            parts = role[len("protocol/"):].split("/")
            if not _protocol_output(source,"protocol-history-checks-","bazel/schema/public-schema-bundle."+parts[0]+"/"+"/".join(parts[1:])):
                fail("protocol-history JSON leaves selected successful schema action")
            total_schema_bytes += pin["bytes"]
        leaf = ctx.path(source)
        if not leaf.exists or leaf.is_dir or str(leaf.realpath) != source:
            fail("protocol-history selected input must be physical regular public leaf")
        checked[role] = leaf
    if total_schema_bytes > 67108864:
        fail("protocol-history total JSON bytes bound")
    # Qualify all selected trees before admitting any input aliases into Bazel.
    pending, observed = [], []
    for mode in ["stable","experimental"]:
        root = roots[mode]
        if type(root) != "string" or not _path(root) or not _protocol_output(root,"protocol-history-checks-","bazel/schema/public-schema-bundle."+mode+"/json"):
            fail("protocol-history schema root scope differs")
        node = ctx.path(root)
        if not node.exists or not node.is_dir or str(node.realpath) != root:
            fail("protocol-history schema root may not redirect")
        pending.append((node,mode+"/json/"))
    for unused in range(4097):
        if not pending:
            break
        parent,prefix = pending.pop()
        for member in parent.readdir():
            name = str(member).split("/")[-1]
            if str(member.realpath) != str(member):
                fail("protocol-history schema member may not redirect")
            if member.is_dir:
                pending.append((member,prefix+name+"/"))
            else:
                key = prefix+name
                if not name.endswith(".json") or key not in pins or pins[key]["path"] != str(member):
                    fail("protocol-history schema member differs from finite pin")
                observed.append(key)
            if len(observed)+len(pending) > 4096:
                fail("protocol-history schema count bound")
    if pending or sorted(observed) != sorted(pins.keys()):
        fail("protocol-history JSON inventory must be complete")
    names, aliases = [], {}
    for index,role in enumerate(sorted(checked)):
        alias = "input-"+str(index)
        ctx.watch(checked[role])
        ctx.symlink(checked[role],alias)
        names.append(alias)
        aliases[role] = ctx.name+"/"+alias
    ctx.file("package-selection.json",raw,executable=False)
    ctx.file("package-selection.sha256",ctx.attr.sha256+"\n",executable=False)
    ctx.file("input-aliases.json",json.encode(aliases)+"\n",executable=False)
    names += ["package-selection.json","package-selection.sha256","input-aliases.json"]
    ctx.file("BUILD.bazel","exports_files("+repr(names)+")\nfilegroup(name='inputs',srcs="+repr(names)+",visibility=['//visibility:public'])\n")

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
    if value.get("kind") == "omux-protocol-history-native-package-selection-v1":
        _protocol_selected(ctx, raw, value)
        return
    staged = value.get("kind") == "omux-staged-native-package-selection-v1"
    roles = _STAGED_ROLES if staged else _ROLES
    if (not staged and value.get("kind") != "omux-fresh-native-package-selection-v1") or sorted(value.get("files", {}).keys()) != sorted(roles):
        fail("fresh package exact input role schema differs")
    if sorted(value.get("protocol_schema_roots", {}).keys()) != ["experimental","stable"]:
        fail("fresh package requires both generated JSON schema roots")
    pins = value.get("protocol_schema_files", {})
    if not pins or len(pins) > 4096:
        fail("fresh package protocol JSON inventory bound")
    entries = dict(value["files"])
    if staged:
        extra = value.get("staged_artifact_files", {})
        if type(extra) != "dict" or len(extra) != 7:
            fail("staged package requires exact three libraries and four actual C evidence files")
        for path,pin in extra.items():
            if path != pin.get("path"):
                fail("staged package explicit output map key differs")
            entries["staged/"+path] = pin
    for name,pin in pins.items():
        if not (name.startswith("stable/json/") or name.startswith("experimental/json/")) or not name.endswith(".json") or ".." in name.split("/"):
            fail("fresh package protocol JSON member name differs")
        entries["protocol/"+name] = pin
    names, aliases = [], {}
    for index,role in enumerate(sorted(entries)):
        pin = entries[role]
        source = pin.get("path","")
        expected_keys = ["bytes","mode","path","sha256"] if role.startswith("staged/") else ["bytes","path","sha256"]
        if sorted(pin.keys()) != expected_keys or not _path(source) or not _hash(pin["sha256"]) or type(pin["bytes"]) != "int" or pin["bytes"] < 0 or pin["bytes"] > 1073741824:
            fail("fresh package selected file pin differs")
        if role.startswith("staged/"):
            if type(pin["mode"]) != "int" or pin["mode"] not in [256, 288, 292, 384, 416, 420] or pin["bytes"] <= 0:
                fail("staged file mode/custody/positive size differs")
            if not source.startswith(_NATIVE):
                fail("staged extra output leaves exact public native state")
            parts = source[len(_NATIVE):].split("/")
            library = False
            if len(parts) == 10 and parts[0].startswith("cache-v2-") and _hash(parts[0][len("cache-v2-"):]) and parts[1:5] == ["output-base","execroot","_main","bazel-out"] and parts[5].endswith("-opt") and parts[6:8] == ["bin","codex-rs"]:
                crates = {"config":"codex_config", "login":"codex_login", "app-server-protocol":"codex_app_server_protocol"}
                if parts[8] in crates:
                    prefix = "lib"+crates[parts[8]]+"-"
                    leaf = parts[9]
                    decimal = leaf[len(prefix):-len(".rlib")] if leaf.startswith(prefix) and leaf.endswith(".rlib") else ""
                    library = 0 < len(decimal) and len(decimal) <= 20 and all([c in "0123456789" for c in decimal.elems()])
            qualified = value["files"]["qualification_run"]["path"]
            root = qualified[:-len("receipt.json")] if qualified.endswith("/receipt.json") else ""
            evidence = (source == root+"test-evidence.json") or (source.startswith(root+"test-evidence/") and len(parts) == 3 and all([c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-" for c in parts[2].elems()]))
            if not (library or evidence) or pin["bytes"] > (268435456 if library else 8388608):
                fail("staged extra output leaves recorded library or actual copied qualification scope")
        if role in ["source","export"]:
            if receipt_producer(role, source) == None:
                fail("fresh package source/export leaves exact declared producer outputs")
        elif role in ["compile","qualification_run","schema_run","library_run"]:
            if not source.startswith(_NATIVE) or not source.endswith("/receipt.json") or len(source[len(_NATIVE):].split("/")) != 2:
                fail("fresh package guard receipt leaves exact owned native invocation")
        elif role in ["library_artifacts","compile_artifacts","qualification_artifacts","schema_artifacts"]:
            if not source.startswith(_NATIVE) or not source.endswith("/native-staged-artifacts.json") or len(source[len(_NATIVE):].split("/")) != 2:
                fail("staged artifact envelope leaves exact actual native invocation")
        elif role.startswith("staged/"):
            pass  # Exact finite public library/evidence scopes checked above.
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
    ctx.file("BUILD.bazel","exports_files("+repr(names)+")\nfilegroup(name='inputs',srcs="+repr(names)+",visibility=['//visibility:public'])\n")
    
codex_fresh_native_package_inputs = repository_rule(
    implementation=_selected_impl,
    attrs={"selection":attr.string(mandatory=True),"sha256":attr.string(mandatory=True)},
    local=True,
)
