"""New local digest-verified SDK acquisition; not legacy watch equivalence.

Only the independently authenticated carrier leaves enter consuming actions.
Origin byte authority is the fixed complete receipt, not mutable tree watches.
Each genuine qualification requires a fresh owned output base and original
guardian envelope. This repository is never itself SDK/runtime qualification.
"""

_ORIGIN = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/e5b17d7e-d19d-4cb2-be22-41a86b98af7b/sdk-private/sdk-export"
_ORIGIN_SHA = "1aa4c87d689f464e576a5c6a51b4c6350a8f0346f6b94299856d01db5147d4f0"
_FILES = ["payload.bin", "manifest.json", "origin-receipt.json", "receipt.json"]
_HELPERS = ["codex_native_sdk_carrier_producer.py", "codex_native_sdk_carrier.py", "codex_retained_sdk_export.py", "nar_descriptor.py"]
_ENV = ["OMUX_SDK_CARRIER_MODE", "OMUX_SDK_CARRIER_ENTRY_NS", "OMUX_SDK_CARRIER_DEADLINE_NS", "OMUX_SDK_CARRIER_EPOCH", "OMUX_SDK_CARRIER_SOURCE_COMMIT", "OMUX_SDK_CARRIER_GRAPH_SHA256"]

def _need(value, stage):
    if not value:
        fail("native SDK carrier declaration refused: " + stage)

def _sha(value):
    return type(value) == "string" and len(value) == 64 and all([c in "0123456789abcdef" for c in value.elems()])

def _absolute(value):
    _need(type(value) == "string" and value.startswith("/") and len(value) <= 4096 and all([part not in ["", ".", ".."] for part in value.split("/")[1:]]) and not any([c in value for c in ["\\", " ", "\n", "\r", "\t", "\000"]]), "canonical-path")
    return value

def _integer(value):
    _need(type(value) == "string" and 0 < len(value) and len(value) <= 20 and all([c in "0123456789" for c in value.elems()]), "integer-envelope")
    return int(value)

def _uuid(value):
    return len(value) == 36 and [value[i] for i in [8, 13, 18, 23]] == ["-", "-", "-", "-"] and all([c in "0123456789abcdef" for c in value.replace("-", "").elems()])

def _bootstrap_file(ctx, bootstrap, role):
    selected = ctx.path(bootstrap + "/" + role)
    physical = _absolute(str(selected.realpath))
    parts = physical.split("/")
    _need(selected.exists and not selected.is_dir and len(parts) in [4, 5] and parts[:3] == ["", "nix", "store"], "bootstrap-metadata")
    name = parts[3]
    _need(len(name) >= 34 and name[32] == "-" and all([name[i] in "0123456789abcdfghijklmnpqrsvwxyz" for i in range(32)]) and (len(parts) == 4 or role == "store-paths" and name[33:] == "closure-info" and parts[4] == "store-paths"), "bootstrap-object")
    ctx.watch(selected)
    ctx.watch(ctx.path(physical))
    return ctx.path(physical)

def _python(ctx):
    bootstrap = _absolute(ctx.attr.bootstrap_closure or ctx.os.environ.get("OMUX_BAZEL_BOOTSTRAP_CLOSURE", ""))
    _need(bootstrap.startswith("/nix/store/") and len(bootstrap.split("/")) == 4, "locked-bootstrap")
    native = _bootstrap_file(ctx, bootstrap, "native.json")
    paths = _bootstrap_file(ctx, bootstrap, "store-paths")
    manifest = json.decode(ctx.read(native, watch = "no"))
    os_name = {"linux": "linux"}.get(ctx.os.name.lower())
    cpu = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(ctx.os.arch.lower())
    _need(os_name == "linux" and cpu and manifest.get("system") == cpu + "-linux", "fixed-publication-host")
    python = _absolute(manifest["packages"]["python"]["out"])
    _need(python.startswith("/nix/store/") and len(python.split("/")) == 4 and python in ctx.read(paths, watch = "no").split("\n") and ctx.path(python + "/bin/python3").exists, "locked-python")
    return python + "/bin/python3"

def _implementation(ctx):
    _need(ctx.attr.origin_root == _ORIGIN and ctx.attr.origin_receipt_sha256 == _ORIGIN_SHA, "fixed-genuine-origin")
    environment = {key: ctx.os.environ.get(key, "") for key in _ENV}
    _need(environment["OMUX_SDK_CARRIER_MODE"] == "native-sdk-carrier-seal-reserved", "fresh-guarded-acquisition-mode")
    entry = _integer(environment["OMUX_SDK_CARRIER_ENTRY_NS"])
    deadline = _integer(environment["OMUX_SDK_CARRIER_DEADLINE_NS"])
    _need(entry > 0 and deadline - entry == 1200 * 1000000000, "original-envelope")
    python = _python(ctx)
    names = []
    for label in [ctx.attr._producer] + ctx.attr._sources:
        path = ctx.path(label)
        _need(path.basename in _HELPERS and path.basename not in names, "declared-helper-name")
        names.append(path.basename)
        ctx.watch(path)
        ctx.file(path.basename, ctx.read(path, watch = "no"), executable = False)
    _need(sorted(names) == sorted(_HELPERS), "complete-helper-closure")
    wrapper = "import runpy,sys; directory=sys.argv.pop(1); script=sys.argv.pop(1); sys.path.insert(0,directory); sys.argv[0]=script; runpy.run_path(script,run_name='__main__')"
    ctx.report_progress("native SDK carrier: authenticating and sealing origin")
    made = ctx.execute([python, "-I", "-S", "-c", wrapper, str(ctx.path(".")), str(ctx.path("codex_native_sdk_carrier_producer.py")), "--phase", "acquire", "--directory", str(ctx.path("."))], timeout = 1170, environment = environment)
    _need(made.return_code == 0, "full-origin-seal")
    report = json.decode(made.stdout)
    _need(type(report) == "dict" and sorted(report.keys()) == ["carrier_receipt_sha256", "deadline_monotonic_ns", "entry_monotonic_ns", "files", "kind", "origin_receipt_sha256"] and report["kind"] == "omux-native-sdk-carrier-declaration-result-v1" and report["entry_monotonic_ns"] == entry and report["deadline_monotonic_ns"] == deadline and report["origin_receipt_sha256"] == _ORIGIN_SHA and _sha(report["carrier_receipt_sha256"]), "closed-seal-report")
    _need(type(report["files"]) == "list" and len(report["files"]) == 4, "four-regular-carrier-leaves")
    names = []
    for row in report["files"]:
        _need(type(row) == "dict" and sorted(row.keys()) == ["name", "sha256", "size"] and row["name"] in _FILES and row["name"] not in names and _sha(row["sha256"]) and type(row["size"]) == "int" and row["size"] >= 0 and row["size"] <= 17179869184, "closed-carrier-leaf")
        names.append(row["name"])
        leaf = ctx.path("carrier-private/carrier/" + row["name"])
        _need(leaf.exists and not leaf.is_dir and str(leaf.realpath) == str(leaf), "physical-carrier-leaf")
        if row["name"] == "receipt.json":
            _need(row["sha256"] == report["carrier_receipt_sha256"], "actual-carrier-receipt-pin")
    # Genuine origin/held-parent/content authentication is done by the declared
    # helper. Repository path predicates are bounded publication readback only.
    # No origin watch_tree or ambient host dependency enters a consumer action.
    files = ["carrier-private/carrier/" + name for name in _FILES]
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(repr(files)),
        'filegroup(name = "inputs", srcs = {})'.format(repr(files)),
        "",
    ]), executable = False)

codex_native_sdk_carrier_inputs = repository_rule(
    implementation = _implementation,
    attrs = {
        "origin_root": attr.string(mandatory = True),
        "origin_receipt_sha256": attr.string(mandatory = True),
        "bootstrap_closure": attr.string(),
        "_producer": attr.label(default = Label("//tools:codex_native_sdk_carrier_producer.py"), allow_single_file = True),
        "_sources": attr.label_list(default = [Label("//tools:codex_native_sdk_carrier.py"), Label("//tools:codex_retained_sdk_export.py"), Label("//tools:nar_descriptor.py")], allow_files = True),
    },
    environ = ["OMUX_BAZEL_BOOTSTRAP_CLOSURE"] + _ENV,
    local = True,
)

def _selected(ctx):
    # Cold until root selects the actual retained successful producer artifact.
    # Exact SHA values are independently selected attributes, never inferred.
    selected = _absolute(ctx.attr.carrier_root)
    prefixes = ["/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/", "/home/jess/.local/state/omux-execution-20261005/"]
    matching = [prefix for prefix in prefixes if selected.startswith(prefix)]
    _need(len(matching) == 1, "retained-coordinator-namespace")
    relative = selected[len(matching[0]):].split("/")
    _need(len(relative) == 12 and _uuid(relative[0]) and relative[1:] == ["output-base", "execroot", "_main", "bazel-out", "k8-fastbuild", "testlogs", "tools", "codex_native_sdk_carrier_seal_producer", "test.outputs", "sdk-private", "sdk-carrier"], "retained-qualified-artifact-namespace")
    _need(type(ctx.attr.digests) == "dict" and sorted(ctx.attr.digests.keys()) == sorted(_FILES) and all([_sha(ctx.attr.digests[name]) for name in _FILES]), "independently-selected-four-digests")
    for name in _FILES:
        physical = ctx.path(selected + "/" + name)
        _need(physical.exists and not physical.is_dir and str(physical.realpath) == str(physical), "selected-physical-carrier-leaf")
        ctx.watch(physical)
        # Four source aliases only. The consuming action authenticates every
        # carrier byte/NAR and all selected hashes before fresh extraction.
        ctx.symlink(physical, "carrier/" + name)
    ctx.file("selection.json", json.encode({"carrier_root": selected, "digests": ctx.attr.digests}), executable = False)
    files = ["carrier/" + name for name in _FILES] + ["selection.json"]
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(repr(files)),
        'filegroup(name = "inputs", srcs = {})'.format(repr(files)),
        "",
    ]), executable = False)

codex_native_sdk_carrier_selected_inputs = repository_rule(
    implementation = _selected,
    attrs = {"carrier_root": attr.string(mandatory = True), "digests": attr.string_dict(mandatory = True)},
    local = True,
)
