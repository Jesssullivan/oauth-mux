"""Lazy finite ready-query tool data. No Nix query/build or ambient fallback."""

def _absolute(value):
    if type(value) != "string" or not value.startswith("/") or len(value) > 4096 or any([part in ["", ".", ".."] for part in value.split("/")[1:]]) or any([c in value for c in ["\\", "\n", "\r", "\000", " ", "\t"]]):
        fail("canonical selected public metadata required")
    return value

def _digest(value):
    if type(value) != "string" or len(value) != 64 or any([c not in "0123456789abcdef" for c in value.elems()]):
        fail("independent query selection digest required")
    return value

def _leaf(ctx, value):
    path = ctx.path(_absolute(value))
    if not path.exists or path.is_dir or str(path.realpath) != value:
        fail("selected query metadata or regular leaf redirected/unavailable")
    return path

def _bootstrap_metadata(ctx, value):
    # Locked bootstrap linkFarm metadata may redirect only to an immutable
    # physical Nix-store regular object. Selected operator leaves never do.
    path = ctx.path(value)
    real = str(path.realpath)
    if not path.exists or path.is_dir or not real.startswith("/nix/store/") or len(real.split("/")) != 4:
        fail("immutable bootstrap metadata object required")
    physical = _leaf(ctx, real)
    ctx.watch(path)
    ctx.watch(physical)
    return physical

def _impl(ctx):
    if not ctx.attr.selection_path and not ctx.attr.selection_sha256:
        ctx.file("query-tools-unconfigured.json", '{"configured":false}\n')
        ctx.file("BUILD.bazel", 'package(default_visibility=["//visibility:public"])\nfilegroup(name="inputs",srcs=["query-tools-unconfigured.json"])\n')
        return
    selected = _absolute(ctx.attr.selection_path)
    digest = _digest(ctx.attr.selection_sha256)
    coordinators = ["/home/jess/.local/state/omux-execution-20261005", "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005"]
    matches = [root for root in coordinators if selected.startswith(root + "/")]
    if len(matches) != 1:
        fail("selected public coordinator namespace required")
    parts = selected[len(matches[0]) + 1:].split("/")
    if len(parts) != 2 or parts[1] != "protocol-history-query-tools-selection.json" or len(parts[0]) != 36 or [parts[0][i] for i in [8, 13, 18, 23]] != ["-", "-", "-", "-"] or any([c not in "0123456789abcdef" for c in parts[0].replace("-", "").elems()]):
        fail("fixed public query selection leaf required")
    leaf = _leaf(ctx, selected)
    ctx.watch(leaf)
    content = ctx.read(leaf, watch = "no")
    if len(content) > 65536:
        fail("selected query metadata bound")
    ctx.file("selection.json", content, executable = False)
    bootstrap = _absolute(ctx.attr.bootstrap_closure or ctx.os.environ.get("OMUX_BAZEL_BOOTSTRAP_CLOSURE", ""))
    if not bootstrap.startswith("/nix/store/") or len(bootstrap.split("/")) != 4:
        fail("immutable registered bootstrap closure required")
    native, paths = _bootstrap_metadata(ctx, bootstrap + "/native.json"), _bootstrap_metadata(ctx, bootstrap + "/store-paths")
    ctx.watch(native)
    ctx.watch(paths)
    manifest = json.decode(ctx.read(native))
    python = _absolute(manifest["packages"]["python"]["out"])
    if not python.startswith("/nix/store/") or len(python.split("/")) != 4 or python not in ctx.read(paths).split("\n") or not ctx.path(python + "/bin/python3").exists:
        fail("declared bootstrap Python unavailable")
    for helper in [ctx.attr.generator] + ctx.attr.generator_sources:
        path = ctx.path(helper)
        ctx.watch(path)
        ctx.file(path.basename, ctx.read(path), executable = False)
    for name, label in {"seed.json": ctx.attr.seed, "source-descriptors.json": ctx.attr.descriptors, "wrapper.nix": ctx.attr.wrapper}.items():
        path = ctx.path(label)
        ctx.watch(path)
        ctx.file(name, ctx.read(path), executable = False)
    project = {"flake.nix": ctx.attr.flake, "flake.lock": ctx.attr.lock, "tools/zig-index.json": ctx.attr.zig_index, "tools/codex_upstream_archives.json": ctx.attr.archives}
    project_sources = {}
    for name, label in project.items():
        path = ctx.path(label)
        ctx.watch(path)
        ctx.file("project/" + name, ctx.read(path), executable = False)
        project_sources[name] = str(ctx.path("project/" + name))
    ctx.file("project-sources.json", json.encode(project_sources), executable = False)
    wrapper = "import runpy,sys; directory=sys.argv.pop(1); script=sys.argv.pop(1); sys.path.insert(0,directory); sys.argv[0]=script; runpy.run_path(script,run_name='__main__')"
    result = ctx.execute([python + "/bin/python3", "-I", "-S", "-c", wrapper,
        str(ctx.path(".")), str(ctx.path("codex_protocol_history_query_tools.py")),
        "--selection", str(ctx.path("selection.json")), "--sha256", digest,
        "--seed", str(ctx.path("seed.json")), "--descriptors", str(ctx.path("source-descriptors.json")),
        "--project", str(ctx.path("project-sources.json")), "--wrapper", str(ctx.path("wrapper.nix")),
        "--directory", str(ctx.path("."))], timeout = 600)
    if result.return_code:
        fail("finite query tool declaration refused; no lookup or acquisition fallback")
    report = json.decode(result.stdout)
    mapping_digest = _digest(report["mapping_sha256"])
    if len(report["regularInputs"]) > 200000:
        fail("query regular-input bound")
    labels = []
    for index, row in enumerate(report["regularInputs"]):
        expected = "regular/" + ("00000000" + str(index))[-8:]
        if sorted(row.keys()) != ["alias", "source"] or row["alias"] != expected:
            fail("contiguous closed query leaf mapping required")
        source = _leaf(ctx, row["source"])
        ctx.watch(source)
        ctx.symlink(source, expected)
        labels.append(expected)
    for source in report["metadataInputs"]:
        ctx.watch(_leaf(ctx, source))
    if report["metadata"] != ["metadata/" + ("00000000" + str(index))[-8:] for index in range(len(report["metadata"]))]:
        fail("closed query metadata sequence required")
    ctx.file("selection.sha256", digest + "\n", executable = False)
    ctx.file("inputs.sha256", mapping_digest + "\n", executable = False)
    extras = ["selection.json", "selection.sha256", "query-inputs.json", "inputs.sha256", "codex-metadata-query-tools.json",
        "seed.json", "source-descriptors.json", "wrapper.nix"] + ["project/" + name for name in project] + [ctx.path(label).basename for label in ctx.attr.generator_sources]
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility=["//visibility:public"])',
        'exports_files(' + repr(extras) + ')',
        'filegroup(name="inputs",srcs=' + repr(labels + report["metadata"] + extras) + ')',
    ]) + "\n", executable = False)

protocol_history_query_tools_repository = repository_rule(
    implementation = _impl,
    attrs = {
        "selection_path": attr.string(),
        "selection_sha256": attr.string(),
        "bootstrap_closure": attr.string(),
        "generator": attr.label(default = Label("//tools:codex_protocol_history_query_tools.py"), allow_single_file = True),
        "generator_sources": attr.label_list(default = [
            Label("//tools:codex_query_registration.py"),
            Label("//tools:native_flake_seed_plan_inputs.py"), Label("//tools:native_flake_seed_plan.py"),
            Label("//tools:native_flake_schedule.py"), Label("//tools:native_flake_sources.py"),
            Label("//tools:nar_descriptor.py"), Label("//tools:verify_declared_nars.py"),
            Label("//tools:verify_cached_nars.py"), Label("//tools:nix_source_probe.py"),
            Label("//tools:nix_private_store_seed.py"), Label("//tools:nix_private_store_qualification.py"),
            Label("//tools:nix_interpreter_closure.py"), Label("//tools:native_flake_missing_plan.py"),
            Label("//tools:guard_native_seed_plan_reserved.py"), Label("//tools:guard_resident_observation.py"),
        ], allow_files = True),
        "seed": attr.label(default = Label("@omux_private_store_host//:private-store-seed.json"), allow_single_file = True),
        "descriptors": attr.label(default = Label("@omux_native_flake_sources//:source-descriptors.json"), allow_single_file = True),
        "wrapper": attr.label(default = Label("//tools:native_flake_schedule.nix"), allow_single_file = True),
        "flake": attr.label(default = Label("//:flake.nix"), allow_single_file = True),
        "lock": attr.label(default = Label("//:flake.lock"), allow_single_file = True),
        "zig_index": attr.label(default = Label("//tools:zig-index.json"), allow_single_file = True),
        "archives": attr.label(default = Label("//tools:codex_upstream_archives.json"), allow_single_file = True),
    },
    environ = ["OMUX_BAZEL_BOOTSTRAP_CLOSURE"],
    local = True,
)
