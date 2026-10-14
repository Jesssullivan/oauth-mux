"""Dedicated tree/history13 CLI package; old targets and graphs untouched."""
load(":rules.bzl","python_test")

def codex_owned_history_cli_targets(model_sources,model_data,guard_sources):
    package_code = ["codex_native_owned_history_cli.py","guard_native_owned_history_cli_reserved.py","guard_test_evidence.py",
        "//delivery:owned_history_runtime.py","//delivery:owned_history_native_tui_runtime.py",
        "//delivery:portable.py","//integrations/codex-owner-runtime:runtime_package.py",
        "//integrations/codex-upstream:patch_io.py","//integrations/codex-upstream:restore_source.py"]
    sources = depset(model_sources+guard_sources+package_code).to_list()
    controls = ["//integrations/codex-upstream/siwc-native:expected-tests.json",
        "//integrations/codex-upstream/siwc-native-catalog:expected-tests.json",
        "//integrations/codex-upstream/native-owned-history:expected-tests.json"]
    python_test(
        name="codex_native_owned_history_cli_producer",main="codex_native_owned_history_cli.py",srcs=sources,
        data=depset(model_data+controls+["//delivery:portable_launcher_template",":fresh_native_runtime_files",
            "@omux_nix//:runtime_libraries","@omux_nix//:tool_wrappers/strip","@omux_nix//:patchelf","@omux_nix//:ca_bundle"]).to_list(),
        args=["--strip","$(location @omux_nix//:tool_wrappers/strip)",
            "--patchelf","$(location @omux_nix//:patchelf)","--ca-bundle","$(location @omux_nix//:ca_bundle)",
            "--runtime-files-manifest","$(location :fresh_native_runtime_files)"],
        env_inherit=["OMUX_NATIVE_FILE_WRITER_MODELS_"+name for name in ["MODE","ENTRY_NS","DEADLINE_NS","EPOCH","SOURCE_COMMIT","GRAPH_SHA256"]]+["OMUX_NATIVE_SDK_TREE_CURRENT_BOOT_ID"],
        tags=["manual","no-remote","no-cache"],timeout="long",
        target_compatible_with=["@platforms//os:linux","@platforms//cpu:x86_64"],
    )
    python_test(name="codex_native_owned_history_cli_test",main="codex_native_owned_history_cli_test.py",srcs=sources,
        data=controls+["codex_owned_history_cli_targets.bzl","codex_owned_history_runtime_inputs.bzl",
            "//integrations/codex-upstream/native-owned-history:runtime-selection.json"],
        tags=["manual","no-remote","no-cache"],timeout="long")
    native.filegroup(name="owned_history_runtime_reader_support",srcs=depset(guard_sources+[
        "guard_native_owned_history_cli_reserved.py","guard_native_owned_history_ordinary_reserved.py","guard_test_evidence.py"]).to_list(),
        visibility=["//delivery:__pkg__"])
    exports = ["codex_owned_history_runtime_inputs.bzl","codex_owned_history_cli_targets.bzl"]
    native.exports_files(exports)
