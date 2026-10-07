"""Small declared-tool rules for browser tests and distributable archives.

All interpreters come from the locked Nix repository. The generated launchers
use its declared Bash to locate runfiles, then exec the declared interpreter.
"""

load("@omux_nix//:tool_paths.bzl", "NIX_BASH")
load(":native_tool_info.bzl", "OmuxNixToolInfo")

def _runfile_key(ctx, file):
    if file.short_path.startswith("../"):
        return file.short_path[3:]
    return ctx.workspace_name + "/" + file.short_path

def _quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"

def _interpreted_impl(ctx):
    interpreter = ctx.executable._interpreter
    file_targets = {str(target.label): target for target in ctx.attr.file_args}
    selected_files = []
    appended_arguments = []
    for label in sorted(file_targets):
        target = file_targets[label]
        flag = ctx.attr.file_args[target]
        if not flag.startswith("--") or len(flag) < 3 or len(flag) > 64 or flag[2] not in "abcdefghijklmnopqrstuvwxyz":
            fail("file_args requires a simple --option name")
        for character in flag[2:].elems():
            if character not in "abcdefghijklmnopqrstuvwxyz0123456789-":
                fail("file_args requires a simple --option name")
        by_path = {file.short_path: file for file in target[DefaultInfo].files.to_list()}
        for short_path in sorted(by_path):
            file = by_path[short_path]
            selected_files.append(file)
            if len(selected_files) > 4096:
                fail("file_args exceeds 4096 declared inputs")
            appended_arguments.append("set -- \"$@\" %s \"${RUNFILES_ROOT}/\"%s" % (_quote(flag), _quote(_runfile_key(ctx, file))))
    files = {file.path: file for file in ctx.files.srcs + ctx.files.data + selected_files + [ctx.file.main]}.values()
    targets = {str(target.label): target for target in ctx.attr.data + ctx.attr.srcs + file_targets.values() + [ctx.attr.main]}.values()
    mappings = []
    for arg in ctx.attr.args:
        expanded = ctx.expand_location(arg, targets = targets)
        rendered = _quote(expanded)
        run_alias = expanded
        source_alias = expanded
        # Physical absolute operator selectors are literal argv, even when a
        # declared source's execution path happens to be their suffix. Bazel
        # location expansion yields relative execution paths; only these need
        # their runfile equivalents, including executable outputs as data.
        if not expanded.startswith("/"):
            for file in files:
                if file.path in expanded:
                    path = "./" + file.path if "./" + file.path in expanded else file.path
                    rendered = rendered.replace(path, "'\"${RUNFILES_ROOT}/%s\"'" % _runfile_key(ctx, file))
                    run_alias = run_alias.replace(path, file.short_path)
                    source_alias = source_alias.replace(path, "./" + file.short_path)
        # Bazel run supplies runfiles paths while TestRunner uses execution
        # paths; Bazel 9 also prefixes root-package source locations with ./.
        cases = "|".join([_quote(value) for value in {value: True for value in [arg, expanded, run_alias, source_alias]}])
        mappings.append("    %s) argument=%s ;;" % (cases, rendered))

    launcher = ctx.actions.declare_file(ctx.label.name + ".sh")
    if ctx.attr._language == "python":
        # Python otherwise resolves a symlinked main's parent back into the
        # source tree. Run it with only its declared runfiles directory on the
        # import path, plus the pinned interpreter's standard library.
        bootstrap = "import os, runpy, sys; script = sys.argv.pop(1); sys.path.insert(0, os.path.dirname(script)); sys.argv[0] = script; runpy.run_path(script, run_name='__main__')"
        options = "-I -B -c " + _quote(bootstrap) + " "
    else:
        options = "--preserve-symlinks --preserve-symlinks-main "
    ctx.actions.write(
        launcher,
        """#!%s
set -eu
if [ -n "${TEST_SRCDIR:-}" ]; then
  RUNFILES_ROOT="$TEST_SRCDIR"
elif [ -n "${RUNFILES_DIR:-}" ]; then
  RUNFILES_ROOT="$RUNFILES_DIR"
elif [ -d "$0.runfiles" ]; then
  RUNFILES_ROOT="$0.runfiles"
else
  printf '%%s\\n' 'Omux executable requires Bazel directory runfiles.' >&2
  exit 1
fi
export PYTHONNOUSERSITE=1 PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1
unset NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONHOME
remaining=$#
while [ "$remaining" -gt 0 ]; do
  argument=$1
  shift
  case "$argument" in
%s
    *) ;;
  esac
  set -- "$@" "$argument"
  remaining=$((remaining - 1))
done
%s
exec "$RUNFILES_ROOT/%s" %s"$RUNFILES_ROOT/%s" "$@"
""" % (
            ctx.attr._launcher_bash[OmuxNixToolInfo].executable_path,
            "\n".join(mappings),
            "\n".join(appended_arguments),
            _runfile_key(ctx, interpreter),
            options,
            _runfile_key(ctx, ctx.file.main),
        ),
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = files + [interpreter])
    for target in ctx.attr.data + file_targets.values() + [ctx.attr._interpreter, ctx.attr._all_tools]:
        runfiles = runfiles.merge(target[DefaultInfo].default_runfiles)
        runfiles = runfiles.merge(ctx.runfiles(files = target[DefaultInfo].files.to_list()))
    return [
        DefaultInfo(executable = launcher, runfiles = runfiles),
        testing.TestEnvironment(environment = {}, inherited_environment = ctx.attr.env_inherit),
    ]

def _interpreter_attrs(interpreter, language, tools = None, bash = None):
    if tools == None:
        tools = "@omux_nix//:" + language + "_tools"
    if bash == None:
        bash = "@omux_nix//:interpreter_bash"
    return {
        "main": attr.label(allow_single_file = True, mandatory = True),
        "srcs": attr.label_list(allow_files = True),
        "data": attr.label_list(allow_files = True),
        "file_args": attr.label_keyed_string_dict(allow_files = True, doc = "Append one flag and exact runfile path per declared file; at most 4096 files."),
        "env_inherit": attr.string_list(doc = "Explicit runtime environment inputs for platform proof only."),
        "_interpreter": attr.label(default = interpreter, executable = True, cfg = "exec"),
        "_all_tools": attr.label(default = tools, cfg = "exec"),
        "_launcher_bash": attr.label(default = bash, providers = [OmuxNixToolInfo], cfg = "exec"),
        "_language": attr.string(default = language),
    }

node_test = rule(
    implementation = _interpreted_impl,
    attrs = _interpreter_attrs("@omux_nix//:node", "node"),
    test = True,
)

python_test = rule(
    implementation = _interpreted_impl,
    attrs = _interpreter_attrs("@omux_nix//:python", "python"),
    test = True,
)

python_binary = rule(
    implementation = _interpreted_impl,
    attrs = _interpreter_attrs("@omux_nix//:python", "python"),
    executable = True,
)

# Manual coordinator tools stay executable before selecting a Darwin closure.
host_python_binary = rule(
    implementation = _interpreted_impl,
    attrs = _interpreter_attrs("@omux_host//:python", "python", "@omux_host//:all_tools", "@omux_host//:bash"),
    executable = True,
)

def _stdout_capture_impl(ctx):
    targets = {str(target.label): target for target in [ctx.attr.executable] + ctx.attr.data}.values()
    arguments = [
        "-c",
        "set -euo pipefail\nomux_output=$1\nshift\nexec \"$@\" > \"$omux_output\"\n",
        "omux-stdout-capture",
        ctx.outputs.out.path,
        ctx.executable.executable.path,
    ] + [ctx.expand_location(arg, targets = targets) for arg in ctx.attr.args]
    ctx.actions.run(
        executable = ctx.executable._bash,
        arguments = arguments,
        inputs = depset(ctx.files.data),
        tools = [
            ctx.attr._bash[DefaultInfo].files_to_run,
            ctx.attr.executable[DefaultInfo].files_to_run,
        ] + ctx.attr._all_tools[DefaultInfo].files.to_list(),
        outputs = [ctx.outputs.out],
        mnemonic = "OmuxStdoutCapture",
        progress_message = "Generating %s" % ctx.label,
        use_default_shell_env = False,
        env = {"PATH": ""},
    )
    return [DefaultInfo(files = depset([ctx.outputs.out]))]

stdout_capture = rule(
    implementation = _stdout_capture_impl,
    attrs = {
        "executable": attr.label(mandatory = True, executable = True, cfg = "exec"),
        "args": attr.string_list(),
        "data": attr.label_list(allow_files = True),
        "out": attr.output(mandatory = True),
        "_bash": attr.label(default = "@omux_nix//:bash", executable = True, cfg = "exec"),
        "_all_tools": attr.label(default = "@omux_nix//:all_tools", cfg = "exec"),
    },
)

def _archive_impl(ctx):
    extension = ctx.attr._kind == "extension"
    suffix = ctx.attr.output_suffix if extension else ".tar.gz"
    output = ctx.actions.declare_file(ctx.label.name + suffix)
    arguments = ctx.actions.args()
    arguments.add(ctx.file._archive)
    arguments.add("--format", "zip" if extension else "tar.gz")
    arguments.add("--output", output)
    if ctx.attr.prefix:
        arguments.add("--prefix", ctx.attr.prefix)
    inputs = list(ctx.files.srcs)
    if extension:
        inputs.append(ctx.file.browser_manifest)
        arguments.add("--file", "manifest.json=" + ctx.file.browser_manifest.path)
    for file in ctx.files.srcs:
        destination = file.short_path
        if extension:
            if not destination.startswith("extensions/shared/"):
                fail("Extension archive inputs must be under extensions/shared/: " + destination)
            destination = destination[len("extensions/"):]
        if destination.startswith("../"):
            fail("Archive source inputs must belong to the main repository: " + destination)
        arguments.add("--file", destination + "=" + file.path)
    ctx.actions.run(
        executable = ctx.executable._python,
        arguments = [arguments],
        inputs = depset(inputs + [ctx.file._archive]),
        tools = [ctx.attr._python[DefaultInfo].files_to_run] + ctx.attr._all_tools[DefaultInfo].files.to_list(),
        outputs = [output],
        mnemonic = "OmuxArchive",
        progress_message = "Packaging %s" % ctx.label,
        use_default_shell_env = False,
        env = {"PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return [DefaultInfo(files = depset([output]))]

def _archive_attrs(kind):
    attrs = {
        "srcs": attr.label_list(allow_files = True, mandatory = True),
        "prefix": attr.string(),
        "_kind": attr.string(default = kind),
        "_python": attr.label(default = "@omux_nix//:python", executable = True, cfg = "exec"),
        "_all_tools": attr.label(default = "@omux_nix//:all_tools", cfg = "exec"),
        "_archive": attr.label(default = "//tools:archive.py", allow_single_file = True),
    }
    if kind == "extension":
        attrs["browser_manifest"] = attr.label(allow_single_file = True, mandatory = True)
        attrs["output_suffix"] = attr.string(default = ".zip", values = [".zip", ".xpi"])
    return attrs

source_archive = rule(implementation = _archive_impl, attrs = _archive_attrs("source"))
extension_archive = rule(implementation = _archive_impl, attrs = _archive_attrs("extension"))
