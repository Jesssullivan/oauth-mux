"""Actual query closure declaration; requires the newly qualified flake output."""

def _impl(ctx):
    files = ctx.attr.query_tools[DefaultInfo].files.to_list()
    paths = {file.short_path: True for file in files}
    names = {file.basename: True for file in files}
    required = ["codex-metadata-query-tools.json", "codex_metadata_query-store-paths",
                "codex_metadata_query-registration", "native.json", "interpreter-closures.json"]
    valid = len(files) == len(paths) and len(files) > len(required) and all([name in names for name in required])
    # These are actual imported closure files, not a guessed package filename
    # allowlist. Python models independently prove complete registration reachability.
    valid = valid and any(["/closure/" in "/" + path for path in paths])
    return [AnalysisTestResultInfo(success = valid,
        message = "actual metadata query closure declaration incomplete")]

codex_metadata_query_tools_declaration_test = rule(
    implementation = _impl,
    attrs = {"query_tools": attr.label(default = Label("@omux_nix//:codex_metadata_query_tools"))},
    analysis_test = True,
)
