"""Capture the source catalog with optional explicit operator provenance.

Unselected builds retain unknown/null and dirty=true. Supplied assertions become
original renderer argv and action inputs; this rule never rewrites emitted JSON.
"""

def _reference_bundle_impl(ctx):
    has_commit = "OMUX_SOURCE_COMMIT" in ctx.var
    has_dirty = "OMUX_SOURCE_DIRTY" in ctx.var
    provenance = []
    if has_commit or has_dirty:
        commit = ctx.var.get("OMUX_SOURCE_COMMIT", "")
        dirty = ctx.var.get("OMUX_SOURCE_DIRTY", "")
        if (not has_commit or not has_dirty or len(commit) != 40 or
            any([byte not in "0123456789abcdef" for byte in commit.elems()]) or
            dirty not in ["true", "false"]):
            fail("Reference provenance requires paired --define=OMUX_SOURCE_COMMIT=<40 lowercase hex> and --define=OMUX_SOURCE_DIRTY=true|false")
        provenance = ["--source-commit", commit, "--source-dirty", dirty]
    arguments = [
        "-c",
        "set -euo pipefail\nomux_output=$1\nshift\nexec \"$@\" > \"$omux_output\"\n",
        "omux-reference-bundle",
        ctx.outputs.out.path,
        ctx.executable.executable.path,
        "reference",
    ] + provenance
    ctx.actions.run(
        executable = ctx.executable._bash,
        arguments = arguments,
        tools = [
            ctx.attr._bash[DefaultInfo].files_to_run,
            ctx.attr.executable[DefaultInfo].files_to_run,
        ] + ctx.attr._all_tools[DefaultInfo].files.to_list(),
        outputs = [ctx.outputs.out],
        mnemonic = "OmuxReferenceBundle",
        progress_message = "Generating %s" % ctx.label,
        use_default_shell_env = False,
        env = {"PATH": ""},
    )
    return [DefaultInfo(files = depset([ctx.outputs.out]))]

reference_bundle = rule(
    implementation = _reference_bundle_impl,
    attrs = {
        "executable": attr.label(mandatory = True, executable = True, cfg = "exec"),
        "out": attr.output(mandatory = True),
        "_bash": attr.label(default = "@omux_nix//:bash", executable = True, cfg = "exec"),
        "_all_tools": attr.label(default = "@omux_nix//:all_tools", cfg = "exec"),
    },
)
