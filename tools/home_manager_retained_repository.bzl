"""Declare one independently selected readonly pair and development artifact.

No executable, walk, fetch, link-target resolution, producer or cache mutation.
The fresh action verifies fixed receipt SHA256/NAR/custody before and after use.
Source link metadata stays in the inventory, never Bazel link-target inputs.
"""

PAIR_RECEIPT_SHA256 = "9e9c04f6768b4ba7ac4023f54c5ae98c5a585da1642a3fca9c0c153d8a1c30eb"
ARTIFACT_RECEIPT_SHA256 = "aa9c9f0c5808da597294b04d59f1e7111567145e1c3f2790fff07c5e670e2ae8"
ARTIFACT_ROOT = "/home/jess/.local/state/omux-execution-20261005/cache-v2-0263cddbc2fe72e072e344a70bf61fdc0e90702986c9738e791ef64375ac8aee/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/home_manager_artifact_producer/test.outputs/home-manager-artifact/artifact"
PAIR_ROOT = "/home/jess/.local/state/omux-home-manager-prefetch-20261006/e3b9e0bc-f473-49f5-be46-4f23e2776a1f/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/home_manager_acquisition_producer/test.outputs/home-manager-pair"
_NAMES = ["home-manager", "nixpkgs"]
_NUL = json.decode('"\\u0000"')
_PINS = {
    "home-manager": ["65258d5c65a250189fde2e35f490d15e064c4c62", "sha256-Sxu1NLTD/Ern6hFGLlZmtKCSct3YQXZI/lls8RE1XeM="],
    "nixpkgs": ["a9e6d84f9c2f9012f5fe7d964a7851352300e61a", "sha256-WncT27+3BOkgTaJZLnCsf3LcYf9RXMuR9ONSN4rzQ7s="],
}

def _absolute(value):
    if not value.startswith("/") or any([part in ["", ".", ".."] for part in value.split("/")[1:]]) or any([c in value for c in ["\\", "\n", "\r", _NUL]]):
        fail("frozen physical retained root required")
    return value

def _relative(value, root = False):
    if type(value) != "string" or len(value) > 4096 or (not root and not value) or any([c in value for c in ["\\", "\n", "\r", _NUL]]):
        fail("invalid retained inventory name")
    if value and any([part in ["", ".", ".."] for part in value.split("/")]):
        fail("invalid retained inventory traversal")
    return value

def _fields(value, expected):
    if type(value) != "dict" or sorted(value.keys()) != sorted(expected):
        fail("retained metadata fields changed")

def _regular(ctx, source, destination):
    path = ctx.path(source)
    if not path.exists or path.is_dir or str(path.realpath) != source:
        fail("retained regular declaration absent or linked")
    ctx.watch(path)
    ctx.symlink(path, destination)
    return destination

def _metadata(ctx, path, maximum):
    candidate = ctx.path(path)
    if not candidate.exists or candidate.is_dir or str(candidate.realpath) != path:
        fail("retained metadata absent or linked")
    ctx.watch(candidate)
    content = ctx.read(candidate, watch = "no")
    if not content or len(content) > maximum:
        fail("retained metadata byte bound")
    return json.decode(content)

def _inert_link(node):
    target = node["target"]
    if type(target) != "string" or not target or len(target) > 4096 or target.startswith("/") or any([c in target for c in ["\n", "\r", _NUL, "\\"]]):
        fail("source link requires separate external-input qualification")
    # Lexical containment only: never stat, read or resolve the target.
    parts = node["path"].split("/")[:-1]
    for part in target.split("/"):
        if part in ["", "."]:
            continue
        if part == "..":
            if not parts:
                fail("source link escapes declared source root")
            parts.pop()
        else:
            parts.append(part)

def _implementation(ctx):
    pair = _absolute(PAIR_ROOT)
    artifact = _absolute(ARTIFACT_ROOT)
    for root in [pair, artifact]:
        path = ctx.path(root)
        if not path.exists or not path.is_dir or str(path.realpath) != root:
            fail("frozen retained physical tree unavailable")
    receipt = _metadata(ctx, pair + "/receipt.json", 65536)
    _fields(receipt, ["schemaVersion", "kind", "lockSha256", "inventorySha256", "sources"])
    if receipt["schemaVersion"] != 1 or receipt["kind"] != "omux-home-manager-acquired-pair":
        fail("retained pair receipt scope changed")
    _fields(receipt["sources"], _NAMES)
    inventory = _metadata(ctx, pair + "/inventory.json", 64 * 1024 * 1024)
    _fields(inventory, ["schemaVersion", "sources"])
    _fields(inventory["sources"], _NAMES)
    if inventory["schemaVersion"] != 1:
        fail("retained inventory version changed")
    files = [_regular(ctx, pair + "/receipt.json", "pair/receipt.json"),
             _regular(ctx, pair + "/inventory.json", "pair/inventory.json")]
    for name in _NAMES:
        source = receipt["sources"][name]
        if source["revision"] != _PINS[name][0] or source["narHash"] != _PINS[name][1]:
            fail("retained source pin changed")
        _fields(inventory["sources"][name], ["nodes"])
        nodes = inventory["sources"][name]["nodes"]
        if type(nodes) != "list" or not nodes or len(nodes) > 200000:
            fail("retained source inventory bound")
        by_path = {}
        total = 0
        for node in nodes:
            path = _relative(node["path"], root = True)
            if path in by_path:
                fail("duplicate retained source node")
            kind = node["type"]
            if kind == "regular":
                _fields(node, ["path", "type", "size", "executable"])
                if type(node["size"]) != "int" or node["size"] < 0 or node["size"] > 512 * 1024 * 1024 or type(node["executable"]) != "bool" or not path:
                    fail("retained regular file bound")
                total += node["size"]
                if total > 2 * 1024 * 1024 * 1024:
                    fail("retained source byte bound")
                files.append(_regular(ctx, pair + "/" + name + "/" + path, "pair/" + name + "/" + path))
            elif kind == "directory":
                _fields(node, ["path", "type"])
            elif kind == "symlink":
                _fields(node, ["path", "type", "target"])
                if not path:
                    fail("retained source root must be directory")
                _inert_link(node)
            else:
                fail("retained special file refused")
            by_path[path] = kind
        if by_path.get("") != "directory":
            fail("retained source root missing")
        for path in by_path:
            if path and by_path.get("/".join(path.split("/")[:-1])) != "directory":
                fail("retained inventory parent is not directory")
    manifest = _metadata(ctx, artifact + "/release-manifest.json", 65536)
    artifacts = manifest.get("artifacts", [])
    if type(artifacts) != "list" or not artifacts or len(artifacts) > 254:
        fail("retained artifact inventory bound")
    names = {"release-manifest.json": True, "SHA256SUMS": True}
    for item in artifacts:
        path = _relative(item["path"])
        if path in names:
            fail("duplicate retained artifact file")
        names[path] = True
    for path in sorted(names):
        files.append(_regular(ctx, artifact + "/" + path, "artifact/" + path))
    files.append(_regular(ctx, artifact.rsplit("/", 1)[0] + "/receipt.json", "artifact-receipt.json"))
    ctx.file("layout.json", json.encode({
        "schemaVersion": 1, "pairReceipt": "pair/receipt.json", "pairInventory": "pair/inventory.json",
        "pairReceiptSha256": PAIR_RECEIPT_SHA256,
        "artifactReceipt": "artifact-receipt.json", "artifactManifest": "artifact/release-manifest.json",
        "artifactReceiptSha256": ARTIFACT_RECEIPT_SHA256,
        "artifactFiles": sorted(names),
        "sourceWrapper": {"epoch": "e3b9e0bc-f473-49f5-be46-4f23e2776a1f", "controllerExit": 3,
                          "workloadExit": 3, "descendantsEmpty": True, "producerSeconds": "__OMUX_SOURCE_SECONDS__",
                          "controllerReceiptSha256": "3356a5660fd73954d33253ec929957c4c47212036280de6c2a4de2ce6eb566f0"},
    }).replace('"__OMUX_SOURCE_SECONDS__"', "617.128") + "\n", executable = False)
    files.append("layout.json")
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files(["artifact-receipt.json", "layout.json"])',
        'filegroup(name = "retained_inputs", srcs = {})'.format(repr(files)),
    ]) + "\n", executable = False)

home_manager_retained_repository = repository_rule(implementation = _implementation, local = True)
