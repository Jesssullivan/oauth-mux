"""Fixed source+sealed SDK declaration with unchanged individual watch paths.

Both helper phases run only through repository_ctx.execute with locked Python.
They perform structural declaration; full byte/NAR authentication stays in TEST.
"""
_CONTROL = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/32da88ee-f894-4453-8371-3cc4719c8ade/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_owner_status_persistence_metadata_binding_producer/test.outputs/owner-status-persistence-metadata-binding.json"
_CONTROL_SHA = "19903dbf0c939fe88522f3ee45dfb9049739abc12ad68bdb890b04867d2b08fe"
_SOURCE = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/95f10057-c0be-4a94-98f8-291dedec0d48/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_owner_status_persistence_source_producer/test.outputs/owner-status-persistence-source"
_EXPORT = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/e5b17d7e-d19d-4cb2-be22-41a86b98af7b/sdk-private/sdk-export"
_EXPORT_SHA = "1aa4c87d689f464e576a5c6a51b4c6350a8f0346f6b94299856d01db5147d4f0"
_JDK = "/nix/store/siln89j8b6k5wdzw4asl69bma0k96nns-openjdk-headless-21.0.10+7"
_KIND = "omux-owner-status-persistence-declaration-plan-v1"

def _need(value, stage):
    if not value:
        fail("protocol-history metadata input refused: " + stage)

def _sha(value):
    return type(value) == "string" and len(value) == 64 and all([c in "0123456789abcdef" for c in value.elems()])

def _absolute(value):
    _need(type(value) == "string" and value.startswith("/") and all([part not in ["", ".", ".."] for part in value.split("/")[1:]]) and not any([c in value for c in ["\n", "\r", "\t", "\000"]]), "canonical-path")
    return value

def _declared_role(value):
    # A returned mapping never grants access to another root. The fixed helper
    # additionally reconstructs the exact role inventory in both phases.
    value = _absolute(value)
    _need(value in [_CONTROL, _SOURCE + "/source-receipt.json", _EXPORT + "/receipt.json"] or any([
        value.startswith(root + "/") for root in [_SOURCE + "/source", _EXPORT + "/repositories", _EXPORT + "/graph", _EXPORT + "/registry-cache", _JDK]
    ]), "closed-declaration-role")
    return value

def _bootstrap_metadata(ctx, bootstrap, role):
    selected = ctx.path(bootstrap + "/" + role)
    physical = str(selected.realpath)
    parts = physical.split("/")
    _need(selected.exists and not selected.is_dir and len(parts) in [4, 5] and parts[:3] == ["", "nix", "store"], "bootstrap-metadata")
    name = parts[3]
    _need(len(name) >= 34 and name[32] == "-" and all([name[i] in "0123456789abcdfghijklmnpqrsvwxyz" for i in range(32)]) and (len(parts) == 4 or role == "store-paths" and name[33:] == "closure-info" and parts[4] == "store-paths"), "bootstrap-metadata-object")
    path = ctx.path(_absolute(physical))
    _need(path.exists and not path.is_dir and str(path.realpath) == physical, "physical-bootstrap-metadata")
    ctx.watch(selected)
    ctx.watch(path)
    return path

def _python(ctx):
    bootstrap = _absolute(ctx.attr.bootstrap_closure or ctx.os.environ.get("OMUX_BAZEL_BOOTSTRAP_CLOSURE", ""))
    _need(bootstrap.startswith("/nix/store/") and len(bootstrap.split("/")) == 4, "locked-bootstrap")
    native = _bootstrap_metadata(ctx, bootstrap, "native.json")
    paths = _bootstrap_metadata(ctx, bootstrap, "store-paths")
    manifest = json.decode(ctx.read(native, watch = "no"))
    os = {"linux": "linux", "mac os x": "darwin"}.get(ctx.os.name.lower())
    cpu = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(ctx.os.arch.lower())
    _need(os == "linux" and cpu and manifest.get("system") == cpu + "-" + os, "fixed-linux-publication-host")
    python = _absolute(manifest["packages"]["python"]["out"])
    _need(python.startswith("/nix/store/") and len(python.split("/")) == 4 and python in ctx.read(paths, watch = "no").split("\n") and ctx.path(python + "/bin/python3").exists, "declared-bootstrap-python")
    return python + "/bin/python3"

def _build(count):
    aliases = ["input-files/" + str(index) for index in range(count)]
    files = aliases + ["metadata-input.json", "metadata-input.sha256"]
    return "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(repr(files)),
        'filegroup(name = "inputs", srcs = {})'.format(repr(files)),
        "",
    ])

def _implementation(ctx):
    _need(ctx.attr.selection == _CONTROL and ctx.attr.sha256 == _CONTROL_SHA, "actual-n4-selection")
    python = _python(ctx)
    helper = ctx.path(ctx.attr._declaration_helper)
    ctx.watch(helper)
    ctx.file(".metadata-declaration.py", ctx.read(helper, watch = "no"), executable = False)
    directory = str(ctx.path("."))
    command = [python, "-I", "-S", str(ctx.path(".metadata-declaration.py"))]
    planned = ctx.execute(command + ["--phase", "plan", "--directory", directory], timeout = 600)
    _need(planned.return_code == 0, "structural-plan-refused")
    plan = json.decode(planned.stdout)
    _need(type(plan) == "dict" and sorted(plan.keys()) == ["control_raw", "kind", "plan_sha256", "regularInputs", "selection_sha256", "watchInputs"] and plan["kind"] == _KIND and _sha(plan["plan_sha256"]) and plan["selection_sha256"] == _CONTROL_SHA and type(plan["control_raw"]) == "string" and len(plan["control_raw"]) == 2896, "closed-plan-report")
    regular = plan["regularInputs"]
    watches = plan["watchInputs"]
    _need(type(regular) == "list" and 0 < len(regular) <= 500000 and type(watches) == "list" and len(regular) <= len(watches) <= 1000000 and regular[:2] == [_CONTROL, _SOURCE + "/source-receipt.json"], "finite-plan-mapping")
    for path in regular:
        _declared_role(path)
    # Preserve every original individual watch, including duplicates and order.
    # Absent targets and skipped JDK symbolic leaves gain no implicit watch.
    for path in watches:
        ctx.watch(ctx.path(_declared_role(path)))
    made = ctx.execute(command + ["--phase", "materialize", "--directory", directory, "--plan-sha256", plan["plan_sha256"]], timeout = 600)
    _need(made.return_code == 0, "revalidated-publication-refused")
    report = json.decode(made.stdout)
    _need(type(report) == "dict" and sorted(report.keys()) == ["build_sha256", "input_count", "materialized", "plan_sha256", "selection_sha256"] and report["materialized"] == True and report["input_count"] == len(regular) and report["plan_sha256"] == plan["plan_sha256"] and report["selection_sha256"] == _CONTROL_SHA and _sha(report["build_sha256"]), "closed-publication-report")
    # BUILD was published last by the helper. These bounded root reads reject an
    # incomplete/mismatched report without granting any new source authority.
    _need(ctx.read("metadata-input.json", watch = "no") == plan["control_raw"] and ctx.read("metadata-input.sha256", watch = "no") == _CONTROL_SHA + "\n" and ctx.read("BUILD.bazel", watch = "no") == _build(len(regular)), "final-root-publication")

codex_owner_status_persistence_metadata_inputs = repository_rule(
    implementation = _implementation,
    attrs = {
        "selection": attr.string(mandatory = True),
        "sha256": attr.string(mandatory = True),
        "bootstrap_closure": attr.string(),
        "_declaration_helper": attr.label(default = Label("//tools:codex_owner_status_persistence_metadata_declaration.py"), allow_single_file = True),
    },
    environ = ["OMUX_BAZEL_BOOTSTRAP_CLOSURE"],
    local = True,
)
