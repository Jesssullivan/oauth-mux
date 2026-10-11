"""Exact fresh Linux archive BUILD with a sampled default-resident reservation."""
import re
import guard_native_seed_plan_reserved as kernel

PROFILE = "default-archive-reserved"
PROFILES = (PROFILE,)
LABEL = "//delivery:default_instance_archive"
ARGUMENTS = ["build", LABEL]
SCOPE = "default-linux-archive-reserved-v1"
MEMORY, TASKS, CPU = kernel.MEMORY, kernel.TASKS, kernel.CPU
Witness = kernel.Witness
WorkloadWitness = kernel.WorkloadWitness
monitor = kernel.monitor
cleanup_retained = kernel.cleanup_retained
release_worker = kernel.release_worker
properties = kernel.properties
remaining = kernel.remaining
def require(value):
    if not value:
        raise ValueError("default-archive-reservation-refused")

def selected(profile, arguments):
    require(profile == PROFILE and arguments == ARGUMENTS)
    return {"PrivateNetwork": "yes"}

def request(args, arguments):
    if args.profile != PROFILE:
        return False
    selected(args.profile, arguments)
    allowed = {"profile", "manager", "arguments", "python", "systemd_run", "systemctl", "bazel",
        "closure", "bootstrap_closure", "zig_sdk", "java_home", "source_commit", "source_dirty",
        "state_dir", "initialize_state_dir", "coordination_dir", "become_file",
        "reuse_owned_cache", "repository_cache", "nixpkgs_source"}
    require(args.manager == "system" and args.reuse_owned_cache is False
        and not any(value for name, value in vars(args).items() if name not in allowed)
        and type(args.source_commit) is str and re.fullmatch(r"[0-9a-f]{40}", args.source_commit)
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
    result[result.index("build")+1:result.index("build")+1] = [
        "--repository_disable_download", "--repo_contents_cache="]
    return result

def projection(entry, deadline, verified, resident):
    kernel.envelope(entry, deadline)
    require(verified is None or type(verified) is bool)
    return {"scope": SCOPE, "mode": "build",
        "original_entry_monotonic_ns": entry, "original_deadline_monotonic_ns": deadline,
        "verified_after_cleanup": verified, "resident": resident,
        "archive_installed": False, "enrollment_proven": False, "native_runtime_qualified": False}

def validate_qualification(receipt):
    """Additional public receipt predicate; archive/source/digest IO stays with its owner."""
    require(type(receipt) is dict and receipt.get("profile") == PROFILE
        and receipt.get("manager") == "system" and receipt.get("verb") == "build"
        and receipt.get("targets") == [LABEL]
        and type(receipt.get("exit")) is int and receipt["exit"] == 0
        and type(receipt.get("workload_exit")) is int and receipt["workload_exit"] == 0
        and receipt.get("descendants_empty") is True
        and type(receipt.get("cleanup")) is dict and receipt["cleanup"].get("state") == "empty"
        and receipt.get("controller_failure") is None
        and receipt.get("cache_reuse_requested") is False
        and receipt.get("cache_policy") is None and receipt.get("cache_key") is None)
    value = receipt.get("default_archive_reservation")
    require(type(value) is dict and set(value) == {"scope", "mode", "original_entry_monotonic_ns",
        "original_deadline_monotonic_ns", "verified_after_cleanup", "resident",
        "archive_installed", "enrollment_proven", "native_runtime_qualified"}
        and value["scope"] == SCOPE and value["mode"] == "build"
        and value["verified_after_cleanup"] is True
        and all(value[name] is False for name in
            ("archive_installed", "enrollment_proven", "native_runtime_qualified")))
    kernel.envelope(value["original_entry_monotonic_ns"], value["original_deadline_monotonic_ns"])
    observed = value["resident"]
    require(type(observed) is dict and set(observed) == {"scope", "kernel_bounds", "observations",
        "initial_direct_processes_retained", "initial_direct_process_count", "outer_pid_namespace_matched",
        "hierarchical_caps", "descendant_process_inventory", "installation_qualified", "health_observed",
        "custody_observed", "resident_signalled", "whole_host_reservation"}
        and observed["scope"] == "sampled-fixed-default-cgroup-kernel-reservation-v1"
        and type(observed["observations"]) is int and 0 < observed["observations"] <= 65535
        and type(observed["initial_direct_process_count"]) is int
        and 0 < observed["initial_direct_process_count"] <= 32
        and all(observed[name] is True for name in
            ("initial_direct_processes_retained", "outer_pid_namespace_matched", "hierarchical_caps"))
        and all(observed[name] is False for name in ("descendant_process_inventory",
            "installation_qualified", "health_observed", "custody_observed", "resident_signalled",
            "whole_host_reservation")))
    kernel.kernel_bounds(observed["kernel_bounds"])
    require(observed["initial_direct_process_count"] <= int(observed["kernel_bounds"]["pids.max"]))
    for name in ("limits", "observed_properties"):
        caps = receipt.get(name)
        require(type(caps) is dict and caps.get("MemoryMax") == str(MEMORY)
            and caps.get("TasksMax") == str(TASKS) and caps.get("MemorySwapMax") == "0")
        if name == "limits":
            require(caps.get("CPUQuotaPerSecUSec") == "1.9s")
        else:
            from guard_resident_dispatch import verify_cpu
            verify_cpu(caps.get("CPUQuotaPerSecUSec"))
    require(type(receipt.get("isolation")) is dict and receipt["isolation"].get("PrivateNetwork") == "yes")
    return True

