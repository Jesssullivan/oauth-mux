"""Formatting uses the same resolved Zig compiler as application actions."""
load(":native_tool_info.bzl", "OmuxNixToolInfo")

def _key(ctx, f):
    return f.short_path[3:] if f.short_path.startswith("../") else ctx.workspace_name + "/" + f.short_path

def _zig_format_impl(ctx):
    sdk = ctx.toolchains["@rules_zig//zig:toolchain_type"].zigtoolchaininfo
    compiler = sdk.zig_exe.file
    if compiler == None:
        fail("Zig formatting requires a declared SDK executable, not an ambient compiler path")
    bash = ctx.attr._bash[OmuxNixToolInfo]
    output = ctx.actions.declare_file(ctx.label.name)
    keys = " ".join(["'" + _key(ctx, f) + "'" for f in ctx.files.srcs])
    script = """#!@OMUX_BASH@
set -eu
if [ -n "${RUNFILES_DIR:-}" ]; then omux_runfiles="$RUNFILES_DIR"; else omux_runfiles="$0.runfiles"; fi
omux_compiler="$omux_runfiles/@OMUX_COMPILER@"
if [ @OMUX_CHECK@ = true ]; then
  for omux_path in @OMUX_FILES@; do "$omux_compiler" fmt --check "$omux_runfiles/$omux_path"; done
else
  if [ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]; then printf '%s\n' 'format must run through bazel run' >&2; exit 2; fi
  cd "$BUILD_WORKSPACE_DIRECTORY"
  exec "$omux_compiler" fmt "$@"
fi
""".replace("@OMUX_BASH@", bash.executable_path).replace("@OMUX_COMPILER@", _key(ctx, compiler)).replace("@OMUX_CHECK@", "true" if ctx.attr.check else "false").replace("@OMUX_FILES@", keys)
    ctx.actions.write(output, script, is_executable=True)
    sdk_files = [compiler] + ctx.files.srcs
    if sdk.zig_lib.file != None:
        sdk_files.append(sdk.zig_lib.file)
    runfiles = ctx.runfiles(files = sdk_files, transitive_files = bash.closure_files)
    runfiles = runfiles.merge(ctx.attr._bash[DefaultInfo].default_runfiles)
    return [DefaultInfo(executable = output, runfiles = runfiles)]

def _format_attrs(check = False):
    return {
        "srcs": attr.label_list(allow_files = [".zig"]),
        "check": attr.bool(default = check),
        "_bash": attr.label(default = Label("@omux_nix//:bash"), executable = True, cfg = "exec", providers = [OmuxNixToolInfo]),
    }

zig_format = rule(implementation = _zig_format_impl, executable = True, attrs = _format_attrs(), toolchains = ["@rules_zig//zig:toolchain_type"])
zig_format_test = rule(implementation = _zig_format_impl, test = True, attrs = _format_attrs(check = True), toolchains = ["@rules_zig//zig:toolchain_type"])
