"""Finite custody runtime unit cohorts; no normal-vault or daemon effects."""
import re
import guard_native_seed_plan_reserved as kernel

PROFILE = "resident-custody-runtime-reserved"
MODEL_PROFILE = "resident-custody-runtime-models-reserved"
LINUX_PROFILE = "resident-custody-runtime-linux-reserved"
FORMAT_PROFILE = "resident-custody-runtime-format-reserved"
INSTALLED_MODEL_PROFILE = "resident-installed-custody-models-reserved"
DEFAULT_MODEL_PROFILE = "resident-default-source-models-reserved"
ACQUISITION_UNIT_PROFILE = "resident-native-acquisition-units-reserved"
DEPLOYMENT_WIRING_PROFILE = "resident-native-deployment-wiring-units-reserved"
LIFECYCLE_MODEL_PROFILE = "resident-lifecycle-accounting-models-reserved"
PROFILES = (MODEL_PROFILE, PROFILE, LINUX_PROFILE, FORMAT_PROFILE, INSTALLED_MODEL_PROFILE, DEFAULT_MODEL_PROFILE, ACQUISITION_UNIT_PROFILE, DEPLOYMENT_WIRING_PROFILE, LIFECYCLE_MODEL_PROFILE)
COHORTS = {
    LIFECYCLE_MODEL_PROFILE: ["test", "//tools:guard_resident_custody_runtime_reserved_test",
        "//:reliability_lifecycle_test", "//:reliability_lifecycle_witness_test",
        "//:reliability_lifecycle_source_actor_test", "//:setup_verification_test",
        "//:engine_test", "//:unit_tests", "//:docs_check"],
    DEPLOYMENT_WIRING_PROFILE: ["test", "//:daemon_test", "//:nix_module_evaluation_test", "//:docs_check"],
    ACQUISITION_UNIT_PROFILE: ["test", "//tools:guard_resident_custody_runtime_reserved_test",
        "//:native_source_acquisition_test", "//:native_source_consent_test",
        "//:qualified_runtime_delivery_test", "//:native_deployment_arguments_test",
        "//:runtime_selection_producer_test", "//:engine_test",
        "//delivery:nix_codex_runtime_test", "//delivery:nix_codex_deployment_test", "//:docs_check"],
    DEFAULT_MODEL_PROFILE: ["test", "//tools:guard_resident_custody_runtime_reserved_test",
        "//delivery:resident_default_enrollment_contract_test", "//delivery:resident_existing_enrollment_contract_test",
        "//delivery:resident_custody_reopen_contract_test", "//:docs_check"],
    INSTALLED_MODEL_PROFILE: ["test", "//tools:guard_resident_custody_runtime_reserved_test",
        "//delivery:resident_custody_reopen_contract_test", "//delivery:resident_owned_lifecycle_contract_test",
        "//:format_test", "//:docs_check"],
    FORMAT_PROFILE: ["run", "//:format", "--", "src/engine.zig", "src/vault.zig", "src/control.zig"],
    MODEL_PROFILE: ["test", "//tools:guard_resident_custody_runtime_reserved_test",
        "//tools:guard_resident_namespace_profile_test", "//tools:guard_resident_owned_update_test",
        "//:format_test", "//:docs_check"],
    PROFILE: ["test", "//:engine_test", "//:vault_test", "//:control_test", "//:reference_test"],
    LINUX_PROFILE: ["test", "//clients/linux:transport_test", "//clients/linux:setup_ui_test"],
}
ARGUMENTS = COHORTS[PROFILE]
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
        raise ValueError("resident-custody-runtime-reservation-refused")


def selected(profile, arguments):
    require(profile in PROFILES and arguments == COHORTS[profile])
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
        and type(args.source_commit) is str
        and re.fullmatch(r"[0-9a-f]{40}", args.source_commit) is not None
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
    # Construct locked BUILD options, then select this one independently admitted
    # formatter RUN. The generic standard formatter allowlist stays unchanged.
    if profile == FORMAT_PROFILE:
        result = builder(bazel, run, ["build", "//:format"], profile="standard", **kwargs)
        index = result.index("build")
        result[index] = "run"
        result.extend(arguments[2:])
    else:
        result = builder(bazel, run, arguments, profile="standard", **kwargs)
        index = result.index(arguments[0])
    index += 1
    result[index:index] = ["--repository_disable_download", "--repo_contents_cache="]
    return result


def projection(entry, deadline, verified, resident, profile=PROFILE):
    require(profile in PROFILES)
    kernel.envelope(entry, deadline)
    require(verified is None or type(verified) is bool)
    return {"scope": "fixed-resident-custody-runtime-reserved-v1", "mode": "isolated-lifecycle-runtime-units" if profile == LIFECYCLE_MODEL_PROFILE else "isolated-deployment-wiring-units" if profile == DEPLOYMENT_WIRING_PROFILE else "isolated-production-acquisition-units" if profile == ACQUISITION_UNIT_PROFILE else "bounded-source-formatting" if profile == FORMAT_PROFILE else "isolated-installed-custody-models" if profile == INSTALLED_MODEL_PROFILE else "isolated-default-source-models" if profile == DEFAULT_MODEL_PROFILE else "isolated-runtime-units",
        "original_entry_monotonic_ns": entry, "original_deadline_monotonic_ns": deadline,
        "verified_after_cleanup": verified, "resident": resident,
        "isolated_unit_scope": profile != FORMAT_PROFILE,
        "source_mutation_requested": profile == FORMAT_PROFILE,
        "normal_vault_observed": False, "daemon_transition_performed": False,
        "native_runtime_qualified": False, "sdk_qualified": False,
        "compiler_qualified": False, "schema_qualified": False,
        "final_source_qualified": False, "custody_qualified": False,
        "health_qualified": False,
        "continuity_qualified": False}
