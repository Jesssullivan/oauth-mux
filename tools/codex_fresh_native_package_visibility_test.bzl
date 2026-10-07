"""Actual selected repository cross-package admission; no selected input IO."""

def _impl(ctx):
    # Bazel checks the real external filegroup's visibility before this rule
    # executes. This target deliberately needs the genuine root-pinned package
    # input repository, and does not manufacture a model producer receipt.
    files = ctx.attr.inputs[DefaultInfo].files.to_list()
    names = [file.basename for file in files]
    valid = 12 <= len(names) and len(names) <= 4120 and len({name: True for name in names}) == len(names)
    if valid:
        expected = ["package-selection.json", "package-selection.sha256", "input-aliases.json"]
        expected += ["input-" + str(index) for index in range(len(names) - 3)]
        valid = sorted(names) == sorted(expected)
    return [AnalysisTestResultInfo(success = valid,
        message = "actual fresh package cross-repository inputs membership differs")]

codex_fresh_native_package_visibility_test = rule(
    implementation = _impl,
    attrs = {"inputs": attr.label(mandatory = True)},
    analysis_test = True,
)
