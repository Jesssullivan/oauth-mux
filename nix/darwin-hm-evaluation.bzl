"""Parameterised genuine evaluation action; no selected fixture or platform claim.

Instantiate only with three declared regular archives, never host locators.
Archives preserve real pinned source symlinks; TreeArtifacts cannot substitute.
The cold observer repository does not instantiate this rule or these producers.
"""
load("//tools:native_tool_info.bzl", "OmuxNixToolInfo")

def _implementation(ctx):
    if len(ctx.attr.source_revision) != 40 or any([c not in "0123456789abcdef" for c in ctx.attr.source_revision.elems()]):
        fail("Darwin artifact source revision must be exact")
    if len(ctx.attr.extension_id) != 32 or any([c not in "abcdefghijklmnop" for c in ctx.attr.extension_id.elems()]):
        fail("Darwin Chromium origin requires one exact extension ID")
    roots = [ctx.file.nixpkgs_archive, ctx.file.home_manager_archive, ctx.file.artifact_archive]
    output = ctx.actions.declare_file(ctx.label.name + ".generation-definition.json")
    args = ctx.actions.args()
    args.add_all(["-I", "-B", "-X", "utf8", "-c",
        "import os,runpy,sys; script=sys.argv.pop(1); sys.path.insert(0,os.path.dirname(script)); sys.argv[0]=script; runpy.run_path(script,run_name='__main__')",
        ctx.file._runner.path])
    for key, value in [
        ("nix", ctx.attr._nix[OmuxNixToolInfo].executable_path),
        ("expression", ctx.file._expression.path),
        ("nixpkgs-archive", roots[0].path), ("home-manager-archive", roots[1].path),
        ("artifact-archive", roots[2].path), ("artifact-nar", ctx.attr.artifact_nar),
        ("source-revision", ctx.attr.source_revision), ("channel", ctx.attr.channel),
        ("extension-id", ctx.attr.extension_id), ("out", output.path),
    ]:
        args.add("--" + key, value)
    ctx.actions.run(
        executable = ctx.executable._python,
        arguments = [args],
        inputs = depset(roots + ctx.files._sources + [ctx.file._runner, ctx.file._expression]),
        tools = [ctx.attr._python[DefaultInfo].files_to_run] + ctx.attr._tools[DefaultInfo].files.to_list(),
        outputs = [output],
        # Only original action_env integer authority is consumed by the runner;
        # the evaluator receives a separately closed, empty configuration env.
        use_default_shell_env = True,
        execution_requirements = {"no-remote": "1", "no-cache": "1"},
        mnemonic = "OmuxDarwinHomeManagerEvaluation",
        progress_message = "Evaluating isolated pinned Darwin Home Manager definition",
    )
    return [DefaultInfo(files = depset([output]))]

darwin_home_manager_evaluation = rule(
    implementation = _implementation,
    attrs = {
        "nixpkgs_archive": attr.label(mandatory = True, allow_single_file = True),
        "home_manager_archive": attr.label(mandatory = True, allow_single_file = True),
        "artifact_archive": attr.label(mandatory = True, allow_single_file = True),
        "artifact_nar": attr.string(mandatory = True),
        "source_revision": attr.string(mandatory = True),
        "channel": attr.string(default = "development", values = ["development", "release"]),
        "extension_id": attr.string(mandatory = True),
        "_runner": attr.label(default = "//:nix/home_manager_darwin_evaluation.py", allow_single_file = True),
        "_expression": attr.label(default = "//:nix/home-manager-darwin-candidate-evaluation.nix", allow_single_file = True),
        "_sources": attr.label(default = "//:darwin_home_manager_candidate_sources"),
        "_python": attr.label(default = "@omux_eval_host//:python", executable = True, cfg = "exec"),
        "_nix": attr.label(default = "@omux_eval_host//:nix", providers = [OmuxNixToolInfo], cfg = "exec"),
        "_tools": attr.label(default = "@omux_eval_host//:all_tools", cfg = "exec"),
    },
)
