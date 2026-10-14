"""Additive complete-tree dependency and SOURCE declarations; defaults intact."""
load(":rules.bzl", "python_binary", "python_test")
load(":codex_retained_sdk_tree_rules.bzl", "retained_sdk_tree", "retained_sdk_materializer_closure_test", "retained_sdk_clock_domain_analysis_test")
load(":codex_native_siwc_catalog_content_source_targets.bzl", "catalog_content_controls")

_CREATOR_ENV = ["OMUX_NATIVE_SDK_TREE_" + name for name in ["MODE", "ENTRY_NS", "DEADLINE_NS", "EPOCH", "SOURCE_COMMIT", "GRAPH_SHA256", "BOOT_ID", "CURRENT_BOOT_ID"]]
_SOURCE_ENV = ["OMUX_NATIVE_FILE_WRITER_MODELS_" + name for name in ["MODE", "ENTRY_NS", "DEADLINE_NS", "EPOCH", "SOURCE_COMMIT", "GRAPH_SHA256"]]

def retained_sdk_tree_targets(carrier_sources, source_sources, guard_sources):
    creator_proofs = ["@omux_native_sdk_carrier_proof_inputs//:inputs",
        "//integrations/codex-upstream:native-sdk-carrier-metadata-inputs.json",
        "//integrations/codex-upstream:native_acquisition_input_configuration",
        "//integrations/codex-upstream:native_acquisition_n9_binding"]
    creator_carrier = ["@omux_native_sdk_carrier_inputs//:inputs"]
    # The existing native source library includes two model test helpers. They
    # are unnecessary for the shipping creator/SOURCE operation graph.
    production_sources = [source for source in source_sources if not str(source).endswith("_test.py")]
    # SDK creation/qualification uses these actual kernel/provenance parser
    # modules, not resident installation or native runtime packaging. Carrying
    # broad guard_sources would add portable.py and its source-stamped compiled
    # launcher even though neither materialize nor qualify uses that path.
    materializer_guard_sources = ["guard_cache.py", "guard_native_seed_plan_reserved.py",
        "guard_resident_observation.py", "guard_native_siwc_catalog_content_source_reserved.py",
        "guard_native_acquisition_inputs_reserved.py", "yoga_delivery_settings.py",
        "guard_yoga_delivery_profile.py", "yoga_executable_qualification.py"]
    materializer_sources = depset(carrier_sources + [
        "codex_retained_sdk_tree.py", "codex_native_retained_sdk_tree_producer.py",
        "codex_retained_sdk_tree_inputs.py", "guard_native_sdk_tree_reserved.py",
        "codex_original_sdk_inputs.py", "codex_native_file_writer_model_source.py",
    ] + materializer_guard_sources + production_sources).to_list()
    python_binary(
        name = "codex_native_retained_sdk_tree_materializer",
        main = "codex_native_retained_sdk_tree_producer.py",
        srcs = materializer_sources,
        data = creator_carrier + creator_proofs,
        tags = ["manual", "no-remote"],
    )
    retained_sdk_materializer_closure_test(
        name = "codex_retained_sdk_tree_materializer_closure_test",
        materializer = ":codex_native_retained_sdk_tree_materializer",
        tags = ["manual", "no-remote"],
    )
    retained_sdk_clock_domain_analysis_test(name = "codex_retained_sdk_tree_clock_domain_analysis_test",
        tags = ["manual", "no-remote"])
    retained_sdk_tree(
        name = "codex_native_retained_sdk_tree_materialized",
        materializer = ":codex_native_retained_sdk_tree_materializer",
        code = materializer_sources,
        carrier = creator_carrier,
        proofs = creator_proofs,
        tags = ["manual", "no-remote"],
    )
    native.filegroup(name = "codex_native_retained_sdk_tree_input_descriptor",
        srcs = [":codex_native_retained_sdk_tree_materialized"], output_group = "input_descriptor")
    native.filegroup(name = "codex_native_retained_sdk_tree_layout",
        srcs = [":codex_native_retained_sdk_tree_materialized"], output_group = "layout")
    native.filegroup(name = "codex_native_retained_sdk_tree_clock_domain",
        srcs = [":codex_native_retained_sdk_tree_materialized"], output_group = "clock_domain")
    native.filegroup(name = "codex_native_retained_sdk_tree_qualification_inputs",
        srcs = [":codex_native_retained_sdk_tree_materialized"], output_group = "qualification_inputs")
    python_test(
        name = "codex_native_retained_sdk_tree_producer",
        main = "codex_native_retained_sdk_tree_producer.py",
        srcs = materializer_sources,
        data = [":codex_native_retained_sdk_tree_materialized",
                ":codex_native_retained_sdk_tree_qualification_inputs"] + creator_proofs,
        args = ["--phase", "qualify"],
        file_args = {":codex_native_retained_sdk_tree_layout": "--data",
                     ":codex_native_retained_sdk_tree_input_descriptor": "--input-descriptor",
                     ":codex_native_retained_sdk_tree_clock_domain": "--clock-domain"},
        env_inherit = _CREATOR_ENV,
        tags = ["manual", "no-remote", "no-cache"],
        timeout = "long",
        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
    )
    tree_source_sources = depset(materializer_sources + production_sources + [
        "codex_retained_sdk_tree_reader.py", "codex_native_siwc_catalog_tree_source.py",
    ]).to_list()
    model_sources = depset(tree_source_sources + source_sources + [
        "codex_retained_sdk_tree_test.py", "codex_retained_sdk_tree_inputs_test.py",
        "codex_native_sdk_carrier_test.py", "codex_native_siwc_catalog_tree_source_test.py",
        "codex_retained_sdk_tree_fixture.py", "codex_retained_sdk_tree_admission_fixture.py",
        "guard_native_sdk_tree_reserved_test.py", "guard_test_evidence.py",
    ]).to_list()
    model_data = ["codex_retained_sdk_tree_rules.bzl", "codex_retained_sdk_tree_proof_inputs.bzl",
        "codex_retained_sdk_tree_targets.bzl", "//integrations/codex-upstream:native-retained-sdk-tree-inputs.json"]
    for name, main in [("codex_native_retained_sdk_tree_test", "codex_retained_sdk_tree_test.py"),
                       ("codex_retained_sdk_tree_inputs_test", "codex_retained_sdk_tree_inputs_test.py")]:
        python_test(name = name, main = main, srcs = model_sources, data = model_data,
            tags = ["manual", "no-remote", "no-cache"], timeout = "long")
    python_test(name = "guard_native_sdk_tree_reserved_test", main = "guard_native_sdk_tree_reserved_test.py",
        srcs = depset(guard_sources + ["guard_cache.py", "guard_native_sdk_tree_reserved.py", "guard_native_sdk_tree_reserved_test.py",
            "guard_yoga_delivery_profile.py", "yoga_executable_qualification.py"]).to_list(),
        data = model_data, tags = ["manual", "no-remote", "no-cache"])
    source_data = catalog_content_controls() + [
        "@omux_native_n10_content_inputs//:inputs", "@omux_protocol_history_query_tools//:inputs",
        "@omux_retained_public_sdk_tree_proof_inputs//:inputs",
        ":codex_native_retained_sdk_tree_materialized",
        "//integrations/codex-upstream:native-retained-sdk-tree-inputs.json",
    ]
    python_test(name = "codex_native_siwc_catalog_tree_source_test",
        main = "codex_native_siwc_catalog_tree_source_test.py", srcs = model_sources,
        data = catalog_content_controls() + model_data,
        tags = ["manual", "no-remote", "no-cache"], timeout = "long")
    python_test(name = "codex_native_siwc_catalog_tree_source_producer",
        main = "codex_native_siwc_catalog_tree_source.py", srcs = tree_source_sources,
        data = source_data, env_inherit = _SOURCE_ENV,
        tags = ["manual", "no-remote", "no-cache"], timeout = "long",
        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"])
