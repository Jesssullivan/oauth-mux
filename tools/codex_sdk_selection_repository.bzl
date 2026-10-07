"""Finite local retained SDK qualification selection; no tool/network execution."""

def _selected_sdk_impl(ctx):
    selected = ctx.attr.selection
    if not selected.startswith("/") or ".." in selected.split("/") or "//" in selected or not selected.endswith("/sdk-selection.json"):
        fail("SDK selection requires the exact absolute qualification metadata path")
    digest = ctx.attr.sha256
    if len(digest) != 64 or any([c not in "0123456789abcdef" for c in digest.elems()]):
        fail("SDK selection requires root-selected SHA256")
    selected_path = ctx.path(selected)
    if str(selected_path.realpath) != selected:
        fail("SDK selection metadata path must have no symlink components")
    data = ctx.read(selected_path)
    if len(data) > 256 * 1024 * 1024:
        fail("SDK selected metadata exceeds 256MiB")
    selection = json.decode(data)
    if selection.get("schema") != "omux-retained-native-sdk-export-v1" or not selection.get("qualification_only"):
        fail("SDK selection requires a qualification receipt")
    # Exporter hashes these exact copied bytes against root-selected digest;
    # Starlark does not invent a hash or treat this structural read as proof.
    ctx.file("sdk-selection.json", data, executable = False)
    ctx.file("sdk-selection.sha256", digest + "\n", executable = False)
    ctx.file("selection-provenance.json", json.encode({"source": selected, "sha256": digest}), executable = False)
    ctx.file("BUILD.bazel", "exports_files([\"sdk-selection.json\", \"sdk-selection.sha256\", \"selection-provenance.json\"])\n")

codex_sdk_selection_repository = repository_rule(
    implementation = _selected_sdk_impl,
    attrs = {
        "selection": attr.string(mandatory = True),
        "sha256": attr.string(mandatory = True),
    },
    local = True,
)

# Root inserts the following use_repo_rule invocation in its owned MODULE only
# after qualification, replacing both attributes with actual selected facts:
# sdk_selection = use_repo_rule("//tools:codex_sdk_selection_repository.bzl", "codex_sdk_selection_repository")
# sdk_selection(name = "omux_sdk_selection", selection = "<actual absolute qualifier output>/sdk-selection.json", sha256 = "<actual root-selected SHA256>")
# No default path, cache search, provider access, or SHA inference is available.
