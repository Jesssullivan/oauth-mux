"""Cold read-only generated-object declaration, never a generation producer.

Only exact selected regular body inputs are action aliases. Named directory and
link topology is independently observed; watchers do not assert inode/alias
invalidation or genuine evaluator/Apple/activation qualification.
"""

_KIND = "omux-darwin-home-manager-generated-inputs-v1"

def _fields(value, names):
    if type(value) != "dict" or sorted(value.keys()) != sorted(names):
        fail("Darwin generated selection fields changed")

def _pin(value):
    if type(value) != "string" or len(value) != 64 or any([c not in "0123456789abcdef" for c in value.elems()]):
        fail("Darwin generated selection digest invalid")

def _path(value):
    if type(value) != "string" or len(value) > 4096 or not value.startswith("/") or value == "/" or any([part in ["", ".", ".."] for part in value.split("/")[1:]]) or any([c in value for c in ["\n", "\r", "\t", json.decode('"\\u0000"')]]):
        fail("Darwin generated selection requires an exact physical absolute path")

def _regular(ctx, path, alias):
    _path(path)
    value = ctx.path(path)
    if not value.exists or value.is_dir or str(value.realpath) != path:
        fail("Darwin selected regular input absent or linked")
    ctx.watch(value)
    ctx.symlink(value, alias)

def _implementation(ctx):
    raw = ctx.read(ctx.attr.selection)
    if not raw or len(raw) > 65536:
        fail("Darwin generated selection exceeds its control bound")
    value = json.decode(raw)
    _fields(value, ["schemaVersion", "kind", "selection"])
    if type(value["schemaVersion"]) != "int" or value["schemaVersion"] != 1 or value["kind"] != _KIND:
        fail("Darwin generated selection family changed")
    files = ["layout.json"]
    choice = value["selection"]
    if choice != None:
        _fields(choice, ["spec", "sources"])
        _fields(choice["spec"], ["path", "sha256"])
        _pin(choice["spec"]["sha256"])
        if type(choice["sources"]) != "dict" or not choice["sources"] or len(choice["sources"]) > 32:
            fail("Darwin generated source count exceeds its bound")
        spec = dict(choice["spec"])
        spec["alias"] = "spec.json"
        _regular(ctx, spec["path"], spec["alias"])
        files.append(spec["alias"])
        sources = {}
        for number, path in enumerate(sorted(choice["sources"].keys())):
            row = choice["sources"][path]
            _fields(row, ["sha256"])
            _pin(row["sha256"])
            alias = "source/" + str(number)
            _regular(ctx, path, alias)
            sources[path] = {"sha256": row["sha256"], "alias": alias}
            files.append(alias)
        value = {"schemaVersion": 1, "kind": _KIND, "selection": {"spec": spec, "sources": sources}}
    ctx.file("layout.json", json.encode(value) + "\n", executable = False)
    # Publication last; initial null emits only a cold layout, no host reads.
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility=["//visibility:public"])',
        'exports_files(["layout.json"])',
        'filegroup(name="inputs",srcs=' + repr(files) + ')',
    ]) + "\n", executable = False)

darwin_generated_inputs = repository_rule(
    implementation = _implementation,
    attrs = {"selection": attr.label(allow_single_file = True, mandatory = True)},
    local = True,
)
