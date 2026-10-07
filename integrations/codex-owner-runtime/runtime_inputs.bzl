"""Finite declared runtime inputs in one runfiles-addressed response file."""

def _runfile_key(ctx, file):
    if file.short_path.startswith("../"):
        return file.short_path[3:]
    return ctx.workspace_name + "/" + file.short_path

def _runtime_inputs_manifest(ctx):
    files = ctx.files.srcs
    if not files or len(files) > 4096:
        fail("declared runtime file selection exceeds its finite bound")
    keys = sorted([_runfile_key(ctx, file) for file in files])
    if len({key: True for key in keys}) != len(keys):
        fail("declared runtime file selection repeats a runfile key")
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(output, json.encode({"schema_version": 1, "runfiles": keys}) + "\n")
    return [DefaultInfo(files = depset([output]), runfiles = ctx.runfiles(files = files + [output]))]

runtime_inputs_manifest = rule(
    implementation = _runtime_inputs_manifest,
    attrs = {"srcs": attr.label(mandatory = True)},
)
