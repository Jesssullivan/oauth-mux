"""Lazy selected successful obligations data for one fixed main-repo TEST.

The selected instance declares public recorded inputs only. Native admission
and realization require independent consumer qualification.
"""

def _absolute(value):
    if type(value) != "string" or not value.startswith("/") or len(value) > 4096 or any([part in ["", ".", ".."] for part in value.split("/")[1:]]) or any([c in value for c in ["\\", "\n", "\r", "\000", " ", "\t"]]):
        fail("explicit canonical public input required")
    return value

def _digest(value):
    if type(value) != "string" or len(value) != 64 or any([c not in "0123456789abcdef" for c in value.elems()]):
        fail("independently selected SHA256 required")
    return value

def _uuid(value):
    if len(value) != 36 or [value[i] for i in [8, 13, 18, 23]] != ["-", "-", "-", "-"]:
        return False
    return all([c in "0123456789abcdef" for c in value.replace("-", "").elems()])

def _impl(ctx):
    selected = _absolute(ctx.attr.selection_path)
    digest = _digest(ctx.attr.selection_sha256)
    coordinators = ["/home/jess/.local/state/omux-execution-20261005", "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005"]
    matching = [root for root in coordinators if selected.startswith(root + "/")]
    if len(matching) != 1:
        fail("selected public coordination namespace required")
    relative = selected[len(matching[0]) + 1:].split("/")
    if len(relative) != 2 or not _uuid(relative[0]) or relative[1] != "native-flake-seed-plan-selection.json":
        fail("exact selected plan input leaf required")
    leaf = ctx.path(selected)
    if not leaf.exists or leaf.is_dir or str(leaf.realpath) != selected:
        fail("canonical selected metadata unavailable")
    ctx.watch(leaf)
    raw = ctx.read(leaf, watch = "no")
    if len(raw) > 65536:
        fail("selected plan metadata exceeds bound")
    ctx.file("selection.json", raw, executable = False)
    bootstrap = _absolute(ctx.attr.bootstrap_closure or ctx.os.environ.get("OMUX_BAZEL_BOOTSTRAP_CLOSURE", ""))
    if not bootstrap.startswith("/nix/store/") or len(bootstrap.split("/")) != 4:
        fail("locked immutable bootstrap closure required")
    native = ctx.path(bootstrap + "/native.json")
    paths = ctx.path(bootstrap + "/store-paths")
    ctx.watch(native)
    ctx.watch(paths)
    manifest = json.decode(ctx.read(native))
    python = _absolute(manifest["packages"]["python"]["out"])
    if not python.startswith("/nix/store/") or len(python.split("/")) != 4 or python not in ctx.read(paths).split("\n") or not ctx.path(python + "/bin/python3").exists:
        fail("already-declared locked Python unavailable")
    for helper in [ctx.attr.generator] + ctx.attr.generator_sources:
        path = ctx.path(helper)
        ctx.watch(path)
        ctx.file(path.basename, ctx.read(path), executable = False)
    project = {"flake.nix": str(ctx.path(ctx.attr.flake).realpath),
               "flake.lock": str(ctx.path(ctx.attr.lock).realpath),
               "tools/zig-index.json": str(ctx.path(ctx.attr.zig_index).realpath),
               "tools/codex_upstream_archives.json": str(ctx.path(ctx.attr.archives).realpath)}
    ctx.file("project-sources.json", json.encode(project), executable = False)
    wrapper = "import runpy,sys; directory=sys.argv.pop(1); script=sys.argv.pop(1); sys.path.insert(0,directory); sys.argv[0]=script; runpy.run_path(script,run_name='__main__')"
    generated = ctx.execute([python + "/bin/python3", "-I", "-S", "-c", wrapper,
        str(ctx.path(".")), str(ctx.path("native_flake_seed_plan_inputs.py")),
        "--selection", str(ctx.path("selection.json")), "--sha256", digest,
        "--seed", str(ctx.path(ctx.attr.seed)), "--descriptors", str(ctx.path(ctx.attr.descriptors)),
        "--project", str(ctx.path("project-sources.json")), "--directory", str(ctx.path(".")),
        "--materialize"], timeout = 600)
    if generated.return_code:
        fail("selected plan declaration refused; no discovery or fallback")
    report = json.decode(generated.stdout)
    if report.get("regularMaterialized") != True:
        fail("closed selected alias materialization required")
    mapping_digest = _digest(report["mapping_sha256"])
    if len(report["regularInputs"]) > 1000000:
        fail("selected regular input count exceeds bound")
    labels = []
    for index, item in enumerate(report["regularInputs"]):
        expected = "regular/" + ("00000000" + str(index))[-8:]
        if sorted(item.keys()) != ["alias", "source"] or item["alias"] != expected:
            fail("closed contiguous declared leaf mapping required")
        source = _absolute(item["source"])
        labels.append(expected)
    watches = report.get("watchInputs")
    if type(watches) != "list" or len(watches) > 1000000:
        fail("closed selected watch mapping required")
    seen_watches = {}
    for item in watches:
        if sorted(item.keys()) != ["kind", "path"] or item["kind"] not in ["file", "tree"]:
            fail("closed selected watch kind required")
        source = _absolute(item["path"])
        key = item["kind"] + ":" + source
        if key in seen_watches:
            continue
        seen_watches[key] = True
        path = ctx.path(source)
        if item["kind"] == "tree":
            # Only freshly proven root-owned read-only Nix subtrees without
            # symlinks are grouped. Mutable retained/project inputs stay leaves.
            ctx.watch(path)
            ctx.watch_tree(path)
        else:
            ctx.watch(path)
    metadata = report["metadata"]
    if len(metadata) not in [5, 7] or metadata != ["metadata/" + ("00000000" + str(i))[-8:] for i in range(len(metadata))]:
        fail("closed metadata alias sequence required")
    if len(report["metadataInputs"]) != len(metadata):
        fail("closed selected metadata watch set required")
    for source in report["metadataInputs"]:
        ctx.watch(ctx.path(_absolute(source)))
    ctx.file("selection.sha256", digest + "\n", executable = False)
    ctx.file("inputs.sha256", mapping_digest + "\n", executable = False)
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files(["selection.json", "selection.sha256", "inputs.json", "inputs.sha256"])',
        'filegroup(name = "inputs", srcs = ' + repr(labels + metadata + ["selection.json", "selection.sha256", "inputs.json", "inputs.sha256"]) + ')',
    ]) + "\n", executable = False)

native_flake_seed_plan_repository = repository_rule(
    implementation = _impl,
    attrs = {
        "selection_path": attr.string(),
        "selection_sha256": attr.string(),
        "bootstrap_closure": attr.string(),
        "generator": attr.label(default = Label("//tools:native_flake_seed_plan_inputs.py"), allow_single_file = True),
        "generator_sources": attr.label_list(default = [
            Label("//tools:native_flake_seed_plan.py"), Label("//tools:native_flake_schedule.py"),
            Label("//tools:native_flake_sources.py"), Label("//tools:nar_descriptor.py"),
            Label("//tools:nix_source_probe.py"), Label("//tools:verify_declared_nars.py"),
            Label("//tools:verify_cached_nars.py"), Label("//tools:nix_private_store_seed.py"),
            Label("//tools:nix_private_store_qualification.py"), Label("//tools:nix_interpreter_closure.py"),
            Label("//tools:native_flake_missing_plan.py"),
        ], allow_files = True),
        "seed": attr.label(default = Label("@omux_private_store_host//:private-store-seed.json"), allow_single_file = True),
        "descriptors": attr.label(default = Label("@omux_native_flake_sources//:source-descriptors.json"), allow_single_file = True),
        "flake": attr.label(default = Label("//:flake.nix"), allow_single_file = True),
        "lock": attr.label(default = Label("//:flake.lock"), allow_single_file = True),
        "zig_index": attr.label(default = Label("//tools:zig-index.json"), allow_single_file = True),
        "archives": attr.label(default = Label("//tools:codex_upstream_archives.json"), allow_single_file = True),
    },
    environ = ["OMUX_BAZEL_BOOTSTRAP_CLOSURE"],
    local = True,
)
