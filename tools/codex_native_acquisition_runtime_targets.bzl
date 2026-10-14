"""Distinct evaluation-only package TEST; exact guard admission is separate."""
load("//tools:rules.bzl", "python_test")

def native_acquisition_runtime_targets(source_sources, sdk_sources, parent_data, sdk_data, tool_path):
    modern = ["codex_native_acquisition_binding.py", "codex_native_acquisition_metadata.py",
        "codex_native_acquisition_sdk_export.py", "codex_native_acquisition_material.py",
        "codex_native_acquisition_compilation.py", "codex_native_acquisition_preflight.py",
        "guard_resident_native_source_acquisition_source_reserved.py",
        "guard_native_acquisition_inputs_reserved.py"]
    python_test(
        name="codex_native_acquisition_runtime_package", main="codex_fresh_native_runtime.py",
        srcs=depset(["codex_fresh_native_runtime.py", "guard_cache.py",
            "//delivery:portable.py", "//delivery:nix_codex_runtime.py",
            "//integrations/codex-owner-runtime:runtime_package.py", "nix_interpreter_closure.py"] + modern + source_sources + sdk_sources).to_list(),
        data=depset(parent_data + sdk_data + [
            "//integrations/codex-upstream:native_source_context_patch",
            "@omux_native_acquisition_package_data//:inputs",
            "//integrations/codex-upstream:native_acquisition_input_configuration",
            "//integrations/codex-upstream:native_acquisition_n9_binding",
            "@omux_native_acquisition_metadata_inputs//:inputs",
            "@omux_protocol_history_query_tools//:inputs",
            "//tools:fresh_native_runtime_files", "@omux_nix//:ca_bundle",
            "@omux_nix//:tool_wrappers/strip", "@omux_nix//:patchelf",
            "@omux_private_store_host//:registration", "@omux_private_store_host//:store-paths"]).to_list(),
        args=["--selection", "$(location @omux_native_acquisition_package_data//:package-selection.json)",
            "--selection-sha-file", "$(location @omux_native_acquisition_package_data//:package-selection.sha256)",
            "--input-aliases", "$(location @omux_native_acquisition_package_data//:input-aliases.json)",
            "--strip", "$(location @omux_nix//:tool_wrappers/strip)",
            "--patchelf", "$(location @omux_nix//:patchelf)",
            "--ca-bundle", "$(location @omux_nix//:ca_bundle)",
            "--runtime-files-manifest", "$(location //tools:fresh_native_runtime_files)",
            "--tool-path", tool_path, "--launch-profile", "linux_nix_direct_main_v1",
            "--nix-registration", "$(location @omux_private_store_host//:registration)",
            "--nix-roots", "$(location @omux_private_store_host//:store-paths)"],
        tags=["manual", "no-remote", "no-cache"], timeout="long",
        target_compatible_with=["@platforms//os:linux", "@platforms//cpu:x86_64"],
    )

    # Ordinary direct-package evaluation shares source proof code, never BRIDGE
    # app-server qualification or a compiled-native acquisition authority flag.
    native.filegroup(name="codex_direct_native_tui_support",srcs=depset([
        "codex_fresh_native_runtime.py", "guard_cache.py", "codex_native_acquisition_process.py", "nar_descriptor.py",
        "//delivery:nix_codex_runtime.py", "//delivery:nix_codex_deployment.py", "//delivery:portable.py",
        "//integrations/codex-owner-runtime:runtime_package.py", "nix_interpreter_closure.py"
    ] + modern + source_sources + sdk_sources).to_list(),visibility=["//visibility:public"])
    native.filegroup(name="codex_direct_native_tui_support_data",srcs=depset(parent_data + sdk_data + [
        "//integrations/codex-upstream:native_source_context_patch",
        "//integrations/codex-upstream:native_acquisition_input_configuration",
        "//integrations/codex-upstream:native_acquisition_n9_binding",
        "@omux_native_acquisition_metadata_inputs//:inputs", "@omux_protocol_history_query_tools//:inputs"
    ]).to_list(),visibility=["//visibility:public"])
