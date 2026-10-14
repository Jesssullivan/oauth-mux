"""Explicit N10 content DATA; no historical physical ancestor repository edge."""
load(":rules.bzl", "python_test")
load(":codex_native_acquisition_targets.bzl", "native_acquisition_source_closure")

# Code imports retain historical definitions; DATA names current physical inputs.
# This list is closed and independent of every historical parent_data argument.
def catalog_content_controls():
    return [
        "//integrations/codex-upstream:native-n10-content-input.json",
        "//integrations/codex-upstream/file-writer-models:inputs",
        "//integrations/codex-upstream/file-writer-models:qualified-parent.json",
        "//integrations/codex-upstream:native_file_writer_source_configuration",
        "//integrations/codex-upstream:native_file_writer_storage_patch",
        "//integrations/codex-upstream:native_file_writer_storage_manifest",
        "//integrations/codex-upstream/siwc-native:inputs",
        "//integrations/codex-upstream/siwc-native-catalog:inputs",
        "//integrations/codex-upstream/native-owned-history:inputs",
        # These are bounded recorded SDK/source provenance documents only.
        # They grant no current physical SOURCE9 or ancestor-custody authority.
        "//integrations/codex-upstream:native_acquisition_input_configuration",
        "//integrations/codex-upstream:native_acquisition_n9_binding",
        "//integrations/codex-upstream:native-sdk-carrier-metadata-inputs.json",
    ]

def catalog_content_source_data():
    return catalog_content_controls() + [
        "@omux_native_n10_content_inputs//:inputs",
        # Complete SDK/JDK packed bytes and original producer proof; the new
        # runtime owns fresh content custody, never original host inode proof.
        "@omux_native_sdk_carrier_inputs//:inputs",
        "@omux_native_sdk_carrier_proof_inputs//:inputs",
        "@omux_protocol_history_query_tools//:inputs",
    ]

def catalog_content_sources(source_sources, sdk_sources):
    return depset([
        src for src in native_acquisition_source_closure(source_sources, sdk_sources)
        if str(src) not in ("//delivery:portable.py", "codex_native_acquisition_bridge_material.py")
    ] + [
        "codex_native_source_file_writer.py", "guard_native_file_writer_source_reserved.py",
        "codex_native_file_writer_model_source.py", "codex_native_siwc_source.py",
        "codex_native_siwc_catalog_source.py", "codex_native_n10_source_intake.py",
        "codex_native_siwc_catalog_content_source.py", "codex_native_owned_history_source.py", "codex_transported_sdk_inputs.py",
        "codex_original_sdk_inputs.py",  # Semantic code only, no physical SDK DATA.
        "guard_native_siwc_catalog_content_source_reserved.py",
    ]).to_list()

def codex_native_siwc_catalog_content_source_targets(source_sources, sdk_sources, original_sdk_sources):
    sources = catalog_content_sources(source_sources, sdk_sources)
    python_test(
        name = "codex_native_siwc_catalog_content_source_producer",
        main = "codex_native_siwc_catalog_content_source.py",
        srcs = depset(sources + original_sdk_sources).to_list(),
        data = catalog_content_source_data(),
        env_inherit = ["OMUX_NATIVE_FILE_WRITER_MODELS_MODE", "OMUX_NATIVE_FILE_WRITER_MODELS_ENTRY_NS", "OMUX_NATIVE_FILE_WRITER_MODELS_DEADLINE_NS", "OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH", "OMUX_NATIVE_FILE_WRITER_MODELS_SOURCE_COMMIT", "OMUX_NATIVE_FILE_WRITER_MODELS_GRAPH_SHA256"],
        tags = ["manual", "no-remote", "no-cache"],
        timeout = "long",
        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
    )
    python_test(
        name = "codex_native_siwc_catalog_content_source_test",
        main = "codex_native_siwc_catalog_content_source_test.py",
        srcs = depset(sources + original_sdk_sources + ["codex_native_n10_source_intake_test.py", "codex_native_siwc_catalog_source_test.py",
            "codex_transported_sdk_inputs_test.py", "codex_native_sdk_carrier_test.py", "codex_native_owned_history_source_test.py"]).to_list(),
        data = catalog_content_controls() + [
            "//integrations/codex-upstream/native-owned-history:native_preimages",
            "//integrations/codex-upstream/siwc-native:native_preimages",
            "//integrations/codex-upstream/siwc-native-catalog:native_preimages",
            "//integrations/codex-upstream/siwc-native:BUILD.bazel",
            "//integrations/codex-upstream/siwc-native-catalog:BUILD.bazel",
            "codex_native_siwc_catalog_source_targets.bzl", "codex_native_siwc_source_BUILD.snippet",
            "codex_native_siwc_catalog_model_inputs.bzl",
        ],
        tags = ["manual", "no-remote", "no-cache"],
        timeout = "long",
        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
    )
