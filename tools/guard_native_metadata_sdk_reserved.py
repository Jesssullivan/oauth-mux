"""Finite offline metadata/SDK admissions; genuine input proofs remain mandatory."""
import re
import guard_native_seed_plan_reserved as kernel

MODEL = "native-metadata-sdk-models-reserved"
DESCRIPTOR = "native-query-descriptor-reserved"
METADATA = "native-persistence-metadata-reserved"
SDK = "native-persistence-sdk-reserved"
PACKAGE_MODEL = "native-persistence-package-models-reserved"
COHORTS = {
    PACKAGE_MODEL: ("//tools:guard_native_metadata_sdk_reserved_test",
        "//tools:codex_persistence_package_family_test",
        "//tools:codex_protocol_history_package_consumer_test",
        "//tools:codex_protocol_history_completed_inputs_test",
        "//tools:codex_protocol_history_native_test",
        "//tools:codex_protocol_history_cli_test", "//:docs_check"),
    MODEL: ("//tools:guard_native_metadata_sdk_reserved_test",
            "//tools:codex_owner_status_persistence_metadata_sdk_test",
            "//tools:codex_protocol_history_query_tools_test",
            "//tools:codex_query_registration_test", "//:docs_check"),
    DESCRIPTOR: ("//tools:codex_metadata_query_tools_descriptor_test",),
    METADATA: ("//tools:codex_owner_status_persistence_metadata_producer",),
    SDK: ("//tools:codex_owner_status_persistence_sdk_export_producer",),
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
        raise ValueError("native-metadata-sdk-reservation-refused")


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
        "custody_qualified": False, "health_qualified": False}
