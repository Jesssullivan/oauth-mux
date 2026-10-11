"""Separate ninth metadata/SDK targets; legacy source families remain unchanged."""
load(":rules.bzl", "python_test")

def native_acquisition_input_targets(source_sources, sdk_sources, guard_sources, parent_data, sdk_data):
    sources = depset(source_sources + sdk_sources + [
        "codex_native_acquisition_binding.py", "codex_native_acquisition_metadata.py",
        "codex_native_acquisition_sdk_export.py", "codex_native_acquisition_material.py",
        "guard_native_acquisition_inputs_reserved.py", "guard_resident_native_source_acquisition_source_reserved.py",
        "codex_native_acquisition_compilation.py", "codex_native_acquisition_preflight.py",
        "codex_native_acquisition_runtime_qualification.py", "guard_cache.py",
        "codex_native_acquisition_peer.py",
        "codex_native_acquisition_peer_test.py",
        "codex_native_acquisition_process.py", "codex_native_acquisition_process_test.py",
        "nar_descriptor.py",
        "codex_native_acquisition_bridge_material.py", "nix_interpreter_closure.py",
        "//delivery:portable.py",
    ]).to_list()
    data = depset(parent_data + sdk_data + [
        "//integrations/codex-upstream:native_source_context_patch",
        "//integrations/codex-upstream:native_acquisition_input_configuration",
        "//integrations/codex-upstream:native_acquisition_n9_binding",
        "@omux_native_acquisition_metadata_inputs//:inputs",
        "@omux_protocol_history_query_tools//:inputs",
    ]).to_list()
    # The real binder reconstructs the source lineage and checks N9 evidence.
    # SDK acquisition and its query tools remain on the other producer targets.
    binding_data = depset(parent_data + [
        "//integrations/codex-upstream:native_source_context_patch",
        "//integrations/codex-upstream:native_acquisition_input_configuration",
        "//integrations/codex-upstream:native_acquisition_n9_binding",
        "@omux_native_acquisition_metadata_inputs//:inputs",
    ]).to_list()
    # These exact unit models create their own fixtures or replace selected-input
    # seams. Keep all Python imports, without analyzing producer SDK/tool data.
    model_targets = (
        "codex_native_acquisition_metadata_sdk_test",
        "codex_native_acquisition_compilation_test",
        "codex_native_acquisition_preflight_test",
        "codex_native_acquisition_material_test",
        "codex_native_acquisition_runtime_qualification_test",
        "codex_native_acquisition_peer_test",
    )
    for name, main in [
        ("codex_native_acquisition_binding_producer", "codex_native_acquisition_binding.py"),
        ("codex_native_acquisition_metadata_producer", "codex_native_acquisition_metadata.py"),
        ("codex_native_acquisition_sdk_export_producer", "codex_native_acquisition_sdk_export.py"),
        ("codex_native_acquisition_metadata_sdk_test", "codex_native_acquisition_metadata_sdk_test.py"),
        ("codex_native_acquisition_compilation_producer", "codex_native_acquisition_compilation.py"),
        ("codex_native_acquisition_compilation_test", "codex_native_acquisition_compilation_test.py"),
        ("codex_native_acquisition_preflight_test", "codex_native_acquisition_preflight_test.py"),
        ("codex_native_acquisition_material_test", "codex_native_acquisition_material_test.py"),
        ("codex_native_acquisition_plan_producer", "codex_native_acquisition_plan_producer.py"),
        ("codex_native_acquisition_query_producer", "codex_native_acquisition_query_producer.py"),
        ("codex_native_acquisition_runtime_qualification_test", "codex_native_acquisition_runtime_qualification_test.py"),
        ("codex_native_acquisition_runtime_qualification_producer", "codex_native_acquisition_runtime_qualification.py"),
        ("codex_native_acquisition_peer_test", "codex_native_acquisition_peer_test.py"),
    ]:
        target_data = data
        if name in model_targets:
            target_data = []
        elif name == "codex_native_acquisition_binding_producer":
            target_data = binding_data
        if name in ("codex_native_acquisition_peer_test",
                    "codex_native_acquisition_runtime_qualification_test",
                    "codex_native_acquisition_runtime_qualification_producer"):
            target_data = target_data + ["//:native_peer_runtime_bridge.so"]
        if name == "codex_native_acquisition_runtime_qualification_producer":
            target_data = target_data + ["//integrations/codex-upstream:native_acquisition_runtime_configuration"]
        model_sources = ["codex_protocol_history_metadata_test.py", "codex_live_source_test.py"] if name == "codex_native_acquisition_metadata_sdk_test" else []
        python_test(name = name, main = main, srcs = depset(sources + [main] + model_sources).to_list(),
            data = target_data,
            timeout = "long", tags = ["manual", "no-remote", "no-cache"])
    python_test(name = "guard_native_acquisition_inputs_reserved_test",
        main = "guard_native_acquisition_inputs_reserved_test.py",
        srcs = depset(guard_sources + ["guard_native_acquisition_inputs_reserved.py"]).to_list())
    python_test(name = "codex_native_acquisition_bridge_material_test",
        main = "codex_native_acquisition_bridge_material_test.py",
        srcs = depset(sources + guard_sources).to_list(),
        tags = ["manual", "no-remote", "no-cache"])
    python_test(name = "codex_native_acquisition_bridge_material_producer",
        main = "codex_native_acquisition_bridge_material.py",
        srcs = depset(sources + guard_sources).to_list(),
        data = ["//:native_peer_runtime_bridge.so", "//:src/platform/native_peer_runtime_bridge.c",
            "//:src/platform/native_peer.c", "//:src/platform/native_peer.h",
            "@omux_nix//:all_tools", "@omux_nix//:native.json", "@omux_nix//:store-paths",
            "@omux_nix//:registration", "@omux_nix//:file-inventory.json"],
        args = ["--bridge", "$(location //:native_peer_runtime_bridge.so)",
            "--native", "$(location @omux_nix//:native.json)",
            "--paths", "$(location @omux_nix//:store-paths)",
            "--registration", "$(location @omux_nix//:registration)",
            "--inventory", "$(location @omux_nix//:file-inventory.json)",
            "--source", "$(location //:src/platform/native_peer_runtime_bridge.c)",
            "--source", "$(location //:src/platform/native_peer.c)",
            "--source", "$(location //:src/platform/native_peer.h)"],
        timeout = "long", tags = ["manual", "no-remote", "no-cache"])
