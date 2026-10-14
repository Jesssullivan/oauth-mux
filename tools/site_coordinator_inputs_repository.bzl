"""Copy explicitly selected public site prerequisite bytes; no execution or qualification."""

def _absolute(value):
    if type(value) != "string" or not value.startswith("/") or any([part in ["", ".", ".."] for part in value.split("/")[1:]]) or any([c in value for c in ["\\", "\n", "\r", " "]]):
        fail("explicit canonical public input path required")
    return value

def _location(value, suffix):
    value = _absolute(value)
    roots = ["/home/jess/.local/state/omux-execution-20261005/", "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/"]
    matching = [root for root in roots if value.startswith(root)]
    if len(matching) != 1:
        fail("selected receipt outside closed owned execution roots")
    parts = value[len(matching[0]):].split("/")
    epoch = parts[0].split("-")
    if [len(part) for part in epoch] != [8, 4, 4, 4, 12] or any([c not in "0123456789abcdef" for part in epoch for c in part.elems()]) or "/".join(parts[1:]) != suffix:
        fail("only exact current epoch producer paths accepted")
    return value

def _copy(ctx, source, output, maximum):
    source = _absolute(source)
    path = ctx.path(source)
    if not path.exists or path.is_dir or str(path.realpath) != source:
        fail("selected public receipt missing or aliased")
    ctx.watch(path)
    content = ctx.read(path, watch = "no")
    if len(content) > maximum:
        fail("selected public receipt exceeds bound")
    ctx.file(output, content, executable = False)
    return content

def _implementation(ctx):
    selected = ctx.os.environ.get("OMUX_SITE_COORDINATOR_INPUTS", "")
    digest = ctx.os.environ.get("OMUX_SITE_COORDINATOR_INPUTS_SHA256", "")
    if len(digest) != 64 or any([c not in "0123456789abcdef" for c in digest.elems()]):
        fail("explicit descriptor SHA256 required")
    raw = _copy(ctx, _location(selected, "site-coordinator-inputs.json"), "selection.json", 16384)
    value = json.decode(raw)
    if type(value) != "dict" or sorted(value.keys()) != ["candidate", "schema_version", "version"] or value["schema_version"] != 1:
        fail("closed site prerequisite selection required")
    for role in ["candidate", "version"]:
        row = value[role]
        if role == "version" and row == None:
            continue
        if type(row) != "dict" or sorted(row.keys()) != ["path", "sha256"]:
            fail("closed selected receipt required")
        if type(row["sha256"]) != "string" or len(row["sha256"]) != 64 or any([c not in "0123456789abcdef" for c in row["sha256"].elems()]):
            fail("selected producer SHA256 required")
        suffix = {"candidate": "site_coordinator_settings_producer/test.outputs/site-coordinator-settings/site-coordinator-settings.json",
                  "version": "site_coordinator_binary_qualification/test.outputs/site-coordinator-qualification/site-coordinator-qualification.json"}[role]
        _copy(ctx, _location(row["path"], "output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/" + suffix), role + ".json", 65536)
    ctx.file("selection.sha256", digest + "\n", executable = False)
    ctx.file("BUILD.bazel", 'package(default_visibility = ["//visibility:public"])\nexports_files(["selection.json", "selection.sha256", "candidate.json", "version.json"])\n', executable = False)

site_coordinator_inputs_repository = repository_rule(
    implementation = _implementation,
    environ = ["OMUX_SITE_COORDINATOR_INPUTS", "OMUX_SITE_COORDINATOR_INPUTS_SHA256"],
    local = True,
)
