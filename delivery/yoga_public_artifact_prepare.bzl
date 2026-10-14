"""Derive a closed public toolbar runfiles declaration; never execute its runner."""

def _key(ctx, file):
    return file.short_path[3:] if file.short_path.startswith("../") else ctx.workspace_name + "/" + file.short_path

def _impl(ctx):
    if ctx.attr.runner.label != Label("//delivery:yoga_toolbar_consent_proof"):
        fail("only the declared current toolbar runner is admitted")
    target = ctx.attr.runner[DefaultInfo]
    # Custom symlink maps are unsupported: every alias must come from a File's
    # canonical Bazel key, and each actual alias is authenticated by the action.
    if target.default_runfiles.symlinks.to_list() or target.default_runfiles.root_symlinks.to_list():
        fail("toolbar custom runfiles symlink maps unsupported")
    original = target.default_runfiles.files.to_list()
    manifest = target.files_to_run.runfiles_manifest
    repo_mapping = target.files_to_run.repo_mapping_manifest
    if manifest == None:
        fail("toolbar canonical runfiles manifest unavailable")
    launcher = target.files_to_run.executable
    if launcher == None:
        fail("toolbar executable unavailable")
    runner_keys = {_key(ctx, file): True for file in original}
    # Executable DefaultInfo adds its executable to actual runtime runfiles,
    # including when the rule's explicitly constructed runfiles omit it.
    runner_keys[_key(ctx, launcher)] = True
    support = [manifest] + ([repo_mapping] if repo_mapping != None else [])
    files = depset(original + target.files.to_list() + ctx.files.metadata + support).to_list()
    if len(files) < 16 or len(files) > 200000:
        fail("toolbar declaration file bound")
    rows = {}
    for file in files:
        key = _key(ctx, file)
        if key in rows and rows[key]["executionPath"] != file.path:
            fail("toolbar duplicate logical binding")
        rows[key] = {"key": key, "executionPath": file.path, "inRunner": key in runner_keys}
    revision = ctx.var.get("OMUX_SOURCE_COMMIT", "")
    dirty = ctx.var.get("OMUX_SOURCE_DIRTY", "")
    if len(revision) != 40 or any([char not in "0123456789abcdef" for char in revision.elems()]) or dirty != "false":
        fail("toolbar preparation needs explicit current clean coordinator source")
    roles = {}
    for label, role in ctx.attr.roles.items():
        candidates = label[DefaultInfo].files.to_list()
        if len(candidates) != 1:
            fail("toolbar role must be one declared File")
        key = _key(ctx, candidates[0])
        if key not in rows:
            fail("toolbar role missing from actual runner/metadata declaration")
        roles[role] = key
    if _key(ctx, launcher) not in rows:
        fail("toolbar executable/runfiles incomplete")
    roles["launcher"] = _key(ctx, launcher)
    roles["runner_manifest"] = _key(ctx, manifest)
    value = {"schemaVersion": 2, "scope": "yoga-current-toolbar-declaration-v2",
        "runnerLabel": "//delivery:yoga_toolbar_consent_proof", "preparationSource": revision,
        "preparationSourceDirty": False, "roles": roles,
        "repoMappingKey": _key(ctx, repo_mapping) if repo_mapping != None else None,
        "files": [rows[key] for key in sorted(rows)]}
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(output, json.encode(value) + "\n")
    # The exact owned BUILD-only warm vector selects this group explicitly.
    # Default files stay one declaration for the genuine producer's location
    # argument; building that JSON alone does not establish compilation warmth.
    return [DefaultInfo(files = depset([output]), runfiles = ctx.runfiles(files = files)),
        OutputGroupInfo(toolbar_public_build_inputs = depset(files))]

yoga_public_artifact_declaration = rule(implementation = _impl, attrs = {
    "runner": attr.label(mandatory = True, executable = True, cfg = "target"),
    "metadata": attr.label_list(allow_files = True),
    "roles": attr.label_keyed_string_dict(allow_files = True),
})
