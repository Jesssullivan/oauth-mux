"""Exact compact reconstruction/evaluation cohorts using original reservation."""
import re
import guard_native_seed_plan_reserved as kernel

RECONSTRUCTION = "home-manager-reconstruction-reserved"
EVALUATION = "home-manager-evaluation-reserved"
MODELS = "home-manager-bundle-models-reserved"
PROFILES = (RECONSTRUCTION, EVALUATION, MODELS)
COHORTS = {
    RECONSTRUCTION: ["test", "//tools:home_manager_retained_reconstruction_producer"],
    EVALUATION: ["test", "//tools:home_manager_acquired_evaluation"],
    MODELS: ["test", "//tools:guard_home_manager_bundle_reserved_test", "//tools:home_manager_bundle_selection_test", "//tools:home_manager_bundle_test"],
}
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
        raise ValueError("home-manager-bundle-reservation-refused")

def selected(profile, arguments):
    require(profile in PROFILES and arguments == COHORTS[profile])
    return {"PrivateNetwork": "yes"}

def request(args, arguments):
    if args.profile not in PROFILES:
        return False
    selected(args.profile, arguments)
    allowed = {"profile", "manager", "arguments", "python", "systemd_run", "systemctl", "bazel", "closure", "bootstrap_closure", "zig_sdk", "java_home", "source_commit", "source_dirty", "state_dir", "initialize_state_dir", "coordination_dir", "become_file", "reuse_owned_cache", "repository_cache", "nixpkgs_source"}
    require(args.manager == "system" and args.reuse_owned_cache is False and not any(value for name, value in vars(args).items() if name not in allowed) and type(args.source_commit) is str and re.fullmatch(r"[0-9a-f]{40}", args.source_commit) is not None and args.source_dirty == "false")
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
    options = ["--repository_disable_download", "--repo_contents_cache="]
    if profile != MODELS:
        options += ["--test_env=OMUX_HM_ROOT_ENTRY_NS=" + str(entry), "--test_env=OMUX_HM_ROOT_DEADLINE_NS=" + str(deadline), "--test_env=OMUX_HM_RESERVED_PROFILE=" + profile]
    index = result.index("test") + 1
    result[index:index] = options
    return result

def projection(profile, entry, deadline, verified, resident):
    require(profile in PROFILES and (verified is None or type(verified) is bool))
    kernel.envelope(entry, deadline)
    return {"scope": "home-manager-compact-reserved-v1", "mode": profile, "original_entry_monotonic_ns": entry, "original_deadline_monotonic_ns": deadline, "verified_after_cleanup": verified, "resident": resident, "activation_qualified": False, "current_artifact_qualified": False, "browser_consent_qualified": False, "continuity_qualified": False}
