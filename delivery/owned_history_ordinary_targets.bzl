"""Exact history13 ordinary-first setup/peer/SQL/rollout proof; no old image alias."""
load("//tools:rules.bzl","python_test")

def owned_history_ordinary_targets():
    sources = ["test_installed_native_tui.py","test_installed_codex_live_continuity.py",
        "test_installed_native_interop.py","test_installed_custody.py","native_resumed_checkpoint.py",
        "owned_history_runtime.py","owned_history_native_tui_runtime.py",
        "pack.py","install.py","portable.py",
        "//integrations/codex-owner-runtime:runtime_package.py",
        "//integrations/codex-upstream:patch_io.py","//integrations/codex-upstream:restore_source.py",
        "//tools:owned_history_runtime_reader_support"]
    controls = ["//integrations/codex-upstream/siwc-native:expected-tests.json",
        "//integrations/codex-upstream/siwc-native-catalog:expected-tests.json",
        "//integrations/codex-upstream/native-owned-history:expected-tests.json"]
    python_test(name="installed_owned_history_native_tui_test",main="test_installed_owned_history_native_tui.py",srcs=sources,
        data=controls+[":default_instance_archive","@omux_owned_history_ordinary_runtime//:inputs",
            "@omux_nix//:dbus_run_session","@omux_nix//:dbus_daemon","@omux_nix//:gnome_keyring_daemon"],
        args=["--history-pin=$(location @omux_owned_history_ordinary_runtime//:runtime-selection.json)",
            "--history-pin-sha=$(location @omux_owned_history_ordinary_runtime//:runtime-selection.sha256)",
            "--history-aliases=$(location @omux_owned_history_ordinary_runtime//:input-aliases.json)",
            "$(location :default_instance_archive)","$(location @omux_owned_history_ordinary_runtime//:runtime_archive)",
            "$(location @omux_owned_history_ordinary_runtime//:runtime_receipt)",
            "$(location @omux_nix//:dbus_run_session)","$(location @omux_nix//:dbus_daemon)",
            "$(location @omux_nix//:gnome_keyring_daemon)"],
        env_inherit=["OMUX_NATIVE_ORDINARY_MODE","OMUX_NATIVE_ORDINARY_ENTRY_NS","OMUX_NATIVE_ORDINARY_DEADLINE_NS"],
        tags=["manual","no-remote","no-cache"],timeout="long",
        target_compatible_with=["@platforms//os:linux","@platforms//cpu:x86_64"])
    python_test(name="owned_history_ordinary_contract_test",main="test_owned_history_ordinary_contract.py",
        srcs=sources+["test_installed_owned_history_native_tui.py"],
        data=controls+["owned_history_ordinary_targets.bzl","//tools:codex_owned_history_runtime_inputs.bzl","//tools:BUILD.bazel"],
        tags=["manual","no-remote","no-cache"])
    native.exports_files(["owned_history_runtime.py","owned_history_native_tui_runtime.py","owned_history_ordinary_targets.bzl"])
