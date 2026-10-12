"""Complete ORIGINAL SDK/JDK regular inputs, never a sparse SDK certificate.

PRIVATE DRAFT: guard/MODULE/BUILD integration and genuine input gates unrun.
Large input/watch graph is retained; this contract removes fresh SDK copying.
"""

_ORIGIN = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/e5b17d7e-d19d-4cb2-be22-41a86b98af7b/sdk-private/sdk-export"
_PIN = "1aa4c87d689f464e576a5c6a51b4c6350a8f0346f6b94299856d01db5147d4f0"
_JDK = "/nix/store/siln89j8b6k5wdzw4asl69bma0k96nns-openjdk-headless-21.0.10+7"
_KIND = "omux-declared-original-sdk-content-v1"
_MODE = "native-file-writer-models-reserved"
_ENV = ["OMUX_NATIVE_FILE_WRITER_MODELS_" + field for field in ["MODE", "ENTRY_NS", "DEADLINE_NS", "EPOCH", "SOURCE_COMMIT", "GRAPH_SHA256"]]
_HELPERS = ["codex_original_sdk_declaration.py", "codex_original_sdk_inputs.py", "codex_native_sdk_carrier.py", "codex_retained_sdk_export.py", "nar_descriptor.py"]

def _need(value, stage):
    if not value:
        fail("original SDK declaration refused: " + stage)

def _sha(value):
    return type(value) == "string" and len(value) == 64 and all([c in "0123456789abcdef" for c in value.elems()])

def _absolute(value):
    _need(type(value) == "string" and value.startswith("/") and len(value) <= 4096 and all([part not in ["", ".", ".."] for part in value.split("/")[1:]]) and not any([c in value for c in ["\n", "\r", "\t", "\000"]]), "canonical-path")
    return value

def _role(value):
    value = _absolute(value)
    _need(value == _ORIGIN + "/receipt.json" or any([value.startswith(prefix + "/") for prefix in [_ORIGIN + "/repositories", _ORIGIN + "/graph", _ORIGIN + "/registry-cache", _JDK]]), "fixed-regular-role")
    return value

def _fresh_epoch_action_mode(ctx, environment, directory):
    if not ctx.attr.fresh_epoch_action_inputs:
        return False
    # This explicit mode uses the existing guarded fresh output-base contract.
    # No cached catalogue or copied origin proof becomes consumer authority.
    epoch = _absolute(environment.get("OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH", ""))
    _need(environment.get("OMUX_NATIVE_FILE_WRITER_MODELS_MODE") == _MODE and
          _absolute(directory) == epoch + "/output-base/external/+codex_original_sdk_inputs+omux_original_native_sdk_inputs",
          "fresh-epoch-owned-output-base")
    return True

def _regular_watch_path(path, fresh):
    selected = _role(path)
    if not fresh:
        return selected
    # Metadata still invalidates repository generation. All regular bytes stay
    # exact declared action inputs and receive fresh full reader SHA/NAR proof.
    metadata = selected == _ORIGIN + "/receipt.json" or any([
        selected.startswith(prefix + "/") for prefix in [_ORIGIN + "/graph", _ORIGIN + "/registry-cache"]
    ]) or any([selected.endswith("/" + name) for name in
               ["MODULE.bazel", "BUILD.bazel", "BUILD", "WORKSPACE", "WORKSPACE.bazel", "REPO.bazel"]])
    return selected if metadata else None

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
    cpu = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(ctx.os.arch.lower())
    _need(ctx.os.name.lower() == "linux" and cpu and manifest.get("system") == cpu + "-linux", "fixed-publication-host")
    python = _absolute(manifest["packages"]["python"]["out"])
    _need(python.startswith("/nix/store/") and len(python.split("/")) == 4 and python in ctx.read(paths, watch = "no").split("\n") and ctx.path(python + "/bin/python3").exists, "locked-python")
    return python + "/bin/python3"

def _implementation(ctx):
    _need(ctx.attr.origin_root == _ORIGIN and ctx.attr.origin_receipt_sha256 == _PIN, "fixed-original-content")
    environment = {key: ctx.os.environ.get(key, "") for key in _ENV}
    _need(environment["OMUX_NATIVE_FILE_WRITER_MODELS_MODE"] == _MODE, "guarded-original-model-mode")
    python = _python(ctx)
    names = []
    for label in [ctx.attr._declaration] + ctx.attr._sources:
        path = ctx.path(label)
        _need(path.basename in _HELPERS and path.basename not in names, "declared-helper-name")
        names.append(path.basename)
        ctx.watch(path)
        ctx.file(".sdk-tool/" + path.basename, ctx.read(path, watch = "no"), executable = False)
    _need(sorted(names) == sorted(_HELPERS), "complete-helper-closure")
    command = [python, "-I", "-S", str(ctx.path(".sdk-tool/codex_original_sdk_declaration.py"))]
    directory = str(ctx.path("."))
    fresh = _fresh_epoch_action_mode(ctx, environment, directory)
    ctx.report_progress("original SDK declaration: complete structural plan")
    planned = ctx.execute(command + ["--phase", "plan", "--directory", directory], timeout = 600, environment = environment)
    _need(planned.return_code == 0, "structural-plan")
    plan = json.decode(planned.stdout)
    _need(type(plan) == "dict" and sorted(plan.keys()) == ["kind", "plan_sha256", "regular_inputs"] and plan["kind"] == _KIND and _sha(plan["plan_sha256"]) and type(plan["regular_inputs"]) == "list" and 0 < len(plan["regular_inputs"]) and len(plan["regular_inputs"]) <= 500000, "closed-plan")
    # Exact whole regular-input membership/order is reconstructed independently
    # in the helper and consuming reader. No tree/dangling/external link watch.
    # These content watches do not claim inode, link or absence invalidation.
    if fresh:
        print("original SDK fresh epoch: accepted complete structural plan")
    for path in plan["regular_inputs"]:
        watched = _regular_watch_path(path, fresh)
        if watched != None:
            ctx.watch(ctx.path(watched))
    if fresh:
        print("original SDK fresh epoch: registered metadata watches")
    ctx.report_progress("original SDK declaration: revalidated publication")
    made = ctx.execute(command + ["--phase", "materialize", "--directory", directory, "--plan-sha256", plan["plan_sha256"]], timeout = 600, environment = environment)
    _need(made.return_code == 0, "publication")
    report = json.decode(made.stdout)
    _need(type(report) == "dict" and sorted(report.keys()) == ["kind", "plan_sha256", "published", "regular_count"] and report["kind"] == _KIND and report["plan_sha256"] == plan["plan_sha256"] and report["published"] == True and report["regular_count"] == len(plan["regular_inputs"]), "closed-publication")
    _need(ctx.path("sdk-inputs.json").exists and not ctx.path("sdk-inputs.json").is_dir and ctx.path("BUILD.bazel").exists and not ctx.path("BUILD.bazel").is_dir, "published-target-boundary")
    if fresh:
        print("original SDK fresh epoch: published complete catalogue")

codex_original_sdk_inputs = repository_rule(
    implementation = _implementation,
    attrs = {
        "origin_root": attr.string(mandatory = True),
        "origin_receipt_sha256": attr.string(mandatory = True),
        "bootstrap_closure": attr.string(),
        "fresh_epoch_action_inputs": attr.bool(default = False),
        "_declaration": attr.label(default = Label("//tools:codex_original_sdk_declaration.py"), allow_single_file = True),
        "_sources": attr.label_list(default = [Label("//tools:codex_original_sdk_inputs.py"), Label("//tools:codex_native_sdk_carrier.py"), Label("//tools:codex_retained_sdk_export.py"), Label("//tools:nar_descriptor.py")], allow_files = True),
    },
    environ = ["OMUX_BAZEL_BOOTSTRAP_CLOSURE"] + _ENV,
    local = True,
)
