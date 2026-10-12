"""Byte-only post-operator-signing reseal. No signing tools or host operations."""

def _seal_impl(ctx):
    revision = ctx.attr.source_revision
    if len(revision) != 40 or any([c not in "0123456789abcdef" for c in revision.elems()]):
        fail("An exact independently selected source revision is required.")
    if ctx.attr.channel == "release" and ctx.attr.source_dirty:
        fail("Release source cleanliness requires its own qualification receipt.")
    if len(ctx.attr.operator_receipt_sha256) != 64 or any([c not in "0123456789abcdef" for c in ctx.attr.operator_receipt_sha256.elems()]):
        fail("The operator metadata receipt requires an independent exact digest.")
    if not ctx.file.final_app.is_directory:
        fail("The final app must be an explicit declared TreeArtifact, not a filesystem selector.")
    output = ctx.actions.declare_directory(ctx.label.name + ".artifact")
    receipt = ctx.actions.declare_file(ctx.label.name + ".artifact-receipt.json")
    args = ctx.actions.args()
    args.add(ctx.file._seal)
    args.add_all(["--app", ctx.file.final_app.path, "--output", output.path, "--receipt", receipt.path,
                  "--source-revision", revision, "--source-dirty", "true" if ctx.attr.source_dirty else "false",
                  "--channel", ctx.attr.channel, "--version", ctx.attr.product_version,
                  "--operator-receipt", ctx.file.operator_receipt.path,
                  "--operator-receipt-sha256", ctx.attr.operator_receipt_sha256,
                  "--artifact-module", ctx.file._artifact.path, "--macho-module", ctx.file._macho.path])
    ctx.actions.run(
        executable = ctx.executable._python, arguments = [args],
        inputs = [ctx.file.final_app, ctx.file.operator_receipt, ctx.file._seal, ctx.file._bundle,
                  ctx.file._artifact, ctx.file._macho],
        tools = [ctx.attr._python[DefaultInfo].files_to_run], outputs = [output, receipt],
        mnemonic = "OmuxDarwinFinalInventory", use_default_shell_env = False,
        env = {"PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return [DefaultInfo(files = depset([output, receipt]))]

omux_darwin_final_inventory = rule(implementation = _seal_impl, attrs = {
    "final_app": attr.label(allow_single_file = True, mandatory = True),
    "operator_receipt": attr.label(allow_single_file = True, mandatory = True),
    "operator_receipt_sha256": attr.string(mandatory = True),
    "source_revision": attr.string(mandatory = True),
    "source_dirty": attr.bool(mandatory = True),
    "channel": attr.string(values = ["development", "release"], mandatory = True),
    "product_version": attr.string(mandatory = True),
    "_python": attr.label(default = "@omux_nix//:python", executable = True, cfg = "exec"),
    "_seal": attr.label(default = ":seal.py", allow_single_file = True),
    "_bundle": attr.label(default = ":bundle.py", allow_single_file = True),
    "_artifact": attr.label(default = ":artifact.py", allow_single_file = True),
    "_macho": attr.label(default = "//tools:macho.py", allow_single_file = True),
})
