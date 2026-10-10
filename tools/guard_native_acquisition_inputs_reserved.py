"""Finite offline metadata/SDK admissions; genuine input proofs remain mandatory."""
import re
import guard_native_seed_plan_reserved as kernel

MODEL = "native-acquisition-inputs-models-reserved"
BINDING = "native-acquisition-binding-reserved"
METADATA = "native-acquisition-metadata-reserved"
SDK = "native-acquisition-sdk-reserved"
PLAN = "native-acquisition-plan-reserved"
QUERY = "native-acquisition-query-reserved"
COMPILE = "native-acquisition-compilation-reserved"
RUNTIME = "native-acquisition-runtime-qualification-reserved"
PACKAGE = "native-acquisition-package-reserved"
PACKAGE_MODELS = "native-acquisition-package-models-reserved"
BRIDGE = "native-acquisition-bridge-material-reserved"
BRIDGE_MODELS = "native-acquisition-bridge-models-reserved"
COHORTS = {
    PACKAGE_MODELS: ("//tools:guard_native_acquisition_inputs_reserved_test",
        "//tools:codex_fresh_native_receipt_scope_test", "//:docs_check"),
    BRIDGE: ("//tools:codex_native_acquisition_bridge_material_producer",),
    BRIDGE_MODELS: ("//tools:guard_native_acquisition_inputs_reserved_test",
        "//tools:codex_native_acquisition_bridge_material_test",
        "//tools:codex_native_acquisition_runtime_qualification_test", "//:docs_check"),
    MODEL: ("//tools:guard_native_acquisition_inputs_reserved_test",
            "//tools:codex_native_acquisition_metadata_sdk_test",
            "//tools:codex_native_acquisition_compilation_test",
            "//tools:codex_native_acquisition_preflight_test",
            "//tools:codex_native_acquisition_material_test",
            "//tools:codex_native_acquisition_runtime_qualification_test",
            "//tools:codex_protocol_history_query_tools_test",
            "//tools:codex_query_registration_test", "//:docs_check"),
    BINDING: ("//tools:codex_native_acquisition_binding_producer",),
    METADATA: ("//tools:codex_native_acquisition_metadata_producer",),
    SDK: ("//tools:codex_native_acquisition_sdk_export_producer",),
    PLAN: ("//tools:codex_native_acquisition_plan_producer",),
    QUERY: ("//tools:codex_native_acquisition_query_producer",),
    COMPILE: ("//tools:codex_native_acquisition_compilation_producer",),
    RUNTIME: ("//tools:codex_native_acquisition_runtime_qualification_producer",),
    PACKAGE: ("//tools:codex_native_acquisition_runtime_package",),
}
PROFILES = tuple(COHORTS)
MEMORY, TASKS, CPU = kernel.MEMORY, kernel.TASKS, kernel.CPU
Witness = kernel.Witness
WorkloadWitness = kernel.WorkloadWitness
monitor = kernel.monitor
cleanup_retained = kernel.cleanup_retained
release_worker = kernel.release_worker
properties = kernel.properties
remaining = kernel.remaining


def require(value):
    if value is not True:
        raise ValueError("native-acquisition-inputs-reservation-refused")


def selected(profile, arguments):
    require(profile in COHORTS and arguments == ["test", *COHORTS[profile]])
    return {"PrivateNetwork": "yes"}


def request(args, arguments):
    if args.profile not in PROFILES:
        return False
    selected(args.profile, arguments)
    allowed = {"profile", "manager", "arguments", "python", "systemd_run", "systemctl", "bazel",
        "closure", "bootstrap_closure", "zig_sdk", "java_home", "source_commit", "source_dirty",
        "state_dir", "initialize_state_dir", "coordination_dir", "become_file",
        "reuse_owned_cache", "repository_cache", "nixpkgs_source"}
    require(args.manager == "system" and args.reuse_owned_cache is False
        and not any(value for name, value in vars(args).items() if name not in allowed)
        and type(args.source_commit) is str and re.fullmatch(r"[0-9a-f]{40}", args.source_commit) is not None
        and args.source_dirty == "false")
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(args.repository_cache, args.nixpkgs_source)
    return True


def command(builder, bazel, run, arguments, profile, entry, deadline, **kwargs):
    selected(profile, arguments)
    remaining(entry, deadline)
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(kwargs.get("repository_cache"), kwargs.get("nixpkgs_source"))
    require(kwargs.get("output_base") is None)
    result = builder(bazel, run, arguments, profile="standard", **kwargs)
    index = result.index("test") + 1
    result[index:index] = ["--repository_disable_download", "--repo_contents_cache="]
    if profile == PACKAGE:
        result[index:index] = ["--test_env=OMUX_NATIVE_PACKAGE_MODE=" + PACKAGE,
            "--test_env=OMUX_NATIVE_PACKAGE_ENTRY_NS=" + str(entry),
            "--test_env=OMUX_NATIVE_PACKAGE_DEADLINE_NS=" + str(deadline)]
    if profile == RUNTIME:
        result[index:index] = ["--test_env=OMUX_NATIVE_RUNTIME_MODE=" + RUNTIME,
            "--test_env=OMUX_NATIVE_RUNTIME_ENTRY_NS=" + str(entry),
            "--test_env=OMUX_NATIVE_RUNTIME_DEADLINE_NS=" + str(deadline)]
    if profile == BRIDGE:
        from execution_guard import graph_digest
        from pathlib import Path
        result[index:index] = ["--test_env=OMUX_NATIVE_BRIDGE_MODE=" + BRIDGE,
            "--test_env=OMUX_NATIVE_BRIDGE_ENTRY_NS=" + str(entry),
            "--test_env=OMUX_NATIVE_BRIDGE_DEADLINE_NS=" + str(deadline),
            "--test_env=OMUX_NATIVE_BRIDGE_SOURCE_COMMIT=" + kwargs["source_commit"],
            "--test_env=OMUX_NATIVE_BRIDGE_GRAPH_SHA256=" + graph_digest(Path.cwd())[0]]
    return result


def projection(profile, entry, deadline, verified, resident):
    require(profile in PROFILES and (verified is None or type(verified) is bool))
    kernel.envelope(entry, deadline)
    return {"scope": "fixed-" + profile + "-v1", "profile": profile,
        "original_entry_monotonic_ns": entry, "original_deadline_monotonic_ns": deadline,
        "verified_after_cleanup": verified, "resident": resident,
        "input_predicates_required": True, "query_tools_qualified": False,
        "metadata_qualified": False, "sdk_qualified": False,
        "schema_qualified": False, "compiler_qualified": False,
        "native_runtime_qualified": False, "continuity_qualified": False,
        "custody_qualified": False, "health_qualified": False,
        "credential_acquisition": False, "native_source_finalized": False,
        "native_support": False, "provider_identity_proved": False,
        "live_handoff_proven": False, "context_rotation": False,
        "daemon_context_acquisition": False}
