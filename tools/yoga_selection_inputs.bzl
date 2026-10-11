"""Inert data for one retained c106 selector; no caller attrs/env/executable."""

_BASE = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/cache-v2-39f2eb3574f1f88de5326867c7d8ef4bc518faba8cb6b2048f84613edac8947d/output-base"
_BIN = _BASE + "/execroot/_main/bazel-out/k8-fastbuild/bin"
_OLD_SOURCE = "/srv/fast-local/jess/git/oauth-mux-browser-inputs-20261008"

def _sources():
    # All paths below are explicitly selected PUBLIC source/artifact inputs.
    # Contents/pins/alias custody are verified by the declared assembly action.
    sources = {
        "build-receipt.json": "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/464e0a75-e0fe-414f-90a6-0909b814da12/receipt.json",
        "launcher.sh": _BIN + "/delivery/yoga_toolbar_consent_proof.sh",
        "runfiles.MANIFEST": _BIN + "/delivery/yoga_toolbar_consent_proof.sh.runfiles_manifest",
        "native.json": _BASE + "/external/+omux_nix_repository+omux_nix/native.json",
        "interpreter-closures.json": _BASE + "/external/+omux_nix_repository+omux_nix/interpreter-closures.json",
        "bundle.tar.gz": _BIN + "/delivery/release_archive.tar.gz",
        "extension.zip": _BIN + "/extensions/chromium_dev_package.zip",
        "browser-runtime.json": _BIN + "/delivery/qualified_browser_runtime.json",
        "portable_launcher_template.py": _BIN + "/delivery/portable_launcher_template.py",
    }
    for name in [
        "browser_runtime_authority.py", "yoga_toolbar_consent.py", "yoga_toolbar_contract.py",
        "test_installed_chromium.py", "test_installed_custody.py", "install.py", "pack.py", "portable.py",
        "yoga_wrapper_authority.py", "yoga_wrapper_custody.py", "chromium_native_recorder.py",
        "yoga_toolbar_native_recorder.py", "yoga_toolbar_observer.mjs",
    ]:
        sources["old-source/" + name] = _OLD_SOURCE + "/delivery/" + name
    for name in ["dbus_daemon", "dbus_run_session", "gnome_keyring_daemon", "python"]:
        for suffix in ["-registration", "-store-paths"]:
            sources[name + suffix] = _BASE + "/external/+omux_nix_repository+omux_nix/" + name + suffix
        sources["wrapper/" + name] = _BASE + "/external/+omux_nix_repository+omux_nix/tool_wrappers/" + name
    sources["wrapper/bash"] = _BASE + "/external/+omux_nix_repository+omux_nix/tool_wrappers/bash"
    return sources


def declared_physical(name, selected, physical):
    # Exact role, literal path and physical equality; redirects never become
    # declared data even if their destination is another allowed public role.
    return _sources().get(name) == selected and selected == physical


def _impl(ctx):
    sources = _sources()
    for name, path in sources.items():
        selected = ctx.path(path)
        # All35 literal paths were observed physical. Refuse ANY redirect
        # before declaring data; no generic source-prefix or Nix fallback.
        # Starlark realpath may inspect redirect metadata while refusing it.
        # It does not open contents. Held every-hop action checks remain.
        physical = selected.realpath
        if not declared_physical(name, path, str(physical)):
            fail("retained public selector declaration redirected")
        ctx.watch(selected)
        if not selected.exists:
            fail("retained public selector input unavailable")
        ctx.symlink(selected, name)
    ctx.file("BUILD.bazel", 'package(default_visibility = ["//visibility:public"])\nexports_files(' + repr(sorted(sources.keys())) + ')\nfilegroup(name = "old_public_inputs", srcs = ' + repr(sorted(sources.keys())) + ')\n')

yoga_selection_inputs = repository_rule(implementation = _impl, local = True)

def _declaration_test(ctx):
    failures = []
    sources = _sources()
    if len(sources) != 35:
        failures.append("fixed-input-count")
    for name, path in sources.items():
        if not declared_physical(name, path, path):
            failures.append("literal-role")
        for changed in ["/home/private/input", "/nix/store/" + "a" * 32 + "-unselected/input", path + ".changed"]:
            if declared_physical(name, path, changed):
                failures.append("redirect")
        if declared_physical("unknown-role", path, path):
            failures.append("unknown-role")
    if declared_physical("native.json", sources["native.json"], sources["build-receipt.json"]):
        failures.append("other-public-role")
    return [AnalysisTestResultInfo(success = not failures, message = ",".join(failures))]


yoga_selection_declaration_test = rule(implementation = _declaration_test, analysis_test = True)
