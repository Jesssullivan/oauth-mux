"""Exact offline registration TEST; complementary kernel reservation only."""
from decimal import Decimal
import math
import re
import guard_native_seed_plan_reserved as kernel

PROFILE = "query-registration-reserved"
PROFILES = (PROFILE,)
LABEL = "//tools:codex_query_registration_reserved_producer"
ARGUMENTS = ["test", LABEL]
SCOPE = "fixed-query-registration-reserved-v1"
ENTRY = "OMUX_QUERY_REGISTRATION_ROOT_ENTRY_NS"
DEADLINE = "OMUX_QUERY_REGISTRATION_ROOT_DEADLINE_NS"
MODE = "OMUX_QUERY_REGISTRATION_RESERVED_PROFILE"
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
        raise ValueError("query-registration-reservation-refused")


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
    result = builder(bazel, run, arguments, profile="standard", **kwargs)
    index = result.index("test") + 1
    result[index:index] = ["--repository_disable_download", "--repo_contents_cache=",
        "--test_env=" + MODE + "=" + PROFILE,
        "--test_env=" + ENTRY + "=" + str(entry),
        "--test_env=" + DEADLINE + "=" + str(deadline)]
    return result


def collector_deadline(environment, now_ns):
    """A collector's 30 seconds is also bounded by the original work cutoff."""
    require(environment.get(MODE) == PROFILE and type(now_ns) is int and now_ns > 0)
    values = []
    for name in (ENTRY, DEADLINE):
        raw = environment.get(name)
        require(type(raw) is str and re.fullmatch(r"[1-9][0-9]{0,19}", raw) is not None)
        values.append(int(raw))
    entry, deadline = values
    work = kernel.envelope(entry, deadline)
    require(entry <= now_ns < work)
    bound = min(work, now_ns + 30 * 10**9)
    # Never round a supplied integer work cutoff into a later float deadline.
    result = math.nextafter(float(bound / 10**9), -math.inf)
    require(math.isfinite(result) and result > now_ns / 10**9)
    return result


def projection(entry, deadline, verified, resident):
    kernel.envelope(entry, deadline)
    require(verified is None or type(verified) is bool)
    return {"scope": SCOPE, "mode": "metadata-test",
        "original_entry_monotonic_ns": entry, "original_deadline_monotonic_ns": deadline,
        "verified_after_cleanup": verified, "resident": resident,
        "collector_max_seconds": 30, "metadata_only": True,
        "nar_bytes_qualified": False, "complete_build_seed_qualified": False,
        "native_runtime_qualified": False, "sdk_qualified": False}


def microseconds(value):
    require(type(value) is str and 0<len(value)<=64)
    parts=value.split(" ");require(1<=len(parts)<=4)
    units={"min":(3,60000000),"s":(2,1000000),"ms":(1,1000),"us":(0,1)}
    previous=4;total=Decimal(0)
    for index,part in enumerate(parts):
        matched=re.fullmatch(r"((?:0|[1-9][0-9]{0,9})(?:[.][0-9]{1,6})?)(min|ms|us|s)",part)
        require(matched is not None)
        rank,scale=units[matched[2]];amount=Decimal(matched[1])
        require(rank<previous and amount>0)
        require(index==len(parts)-1 or amount==amount.to_integral_value())
        if len(parts)>1 and previous!=4:
            require(amount<(60 if matched[2]=="s" else 1000))
        total+=amount*scale;previous=rank
    # Parsing alone never admits more than the existing outer1200s ceiling.
    require(0<total<=1200*1000000)
    return total


def validate_qualification(receipt):
    """Only additional reservation predicates; supplied evidence stays caller-owned."""
    require(type(receipt) is dict and receipt.get("profile") == PROFILE
        and receipt.get("manager") == "system" and receipt.get("verb") == "test"
        and receipt.get("targets") == [LABEL]
        and type(receipt.get("exit")) is int and receipt["exit"] == 0
        and type(receipt.get("workload_exit")) is int and receipt["workload_exit"] == 0
        and receipt.get("descendants_empty") is True
        and type(receipt.get("cleanup")) is dict and receipt["cleanup"].get("state") == "empty"
        and receipt.get("controller_failure") is None
        and receipt.get("cache_reuse_requested") is False
        and receipt.get("cache_policy") is None and receipt.get("cache_key") is None)
    value = receipt.get("query_registration_reservation")
    require(type(value) is dict and set(value) == {"scope", "mode", "original_entry_monotonic_ns",
        "original_deadline_monotonic_ns", "verified_after_cleanup", "resident", "collector_max_seconds",
        "metadata_only", "nar_bytes_qualified", "complete_build_seed_qualified", "native_runtime_qualified",
        "sdk_qualified"} and value["scope"] == SCOPE and value["mode"] == "metadata-test"
        and value["verified_after_cleanup"] is True
        and type(value["collector_max_seconds"]) is int and value["collector_max_seconds"] == 30
        and value["metadata_only"] is True
        and all(value[name] is False for name in ("nar_bytes_qualified", "complete_build_seed_qualified",
            "native_runtime_qualified", "sdk_qualified")))
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
        and all(observed[name] is False for name in ("descendant_process_inventory", "installation_qualified",
            "health_observed", "custody_observed", "resident_signalled", "whole_host_reservation")))
    kernel.kernel_bounds(observed["kernel_bounds"])
    require(observed["initial_direct_process_count"] <= int(observed["kernel_bounds"]["pids.max"]))
    expected = {"MemoryMax": str(MEMORY), "MemorySwapMax": "0", "TasksMax": str(TASKS),
        "KillMode": "control-group", "SendSIGKILL": "yes", "OOMPolicy": "kill", "RemainAfterExit": "yes"}
    for name in ("limits", "observed_properties"):
        caps = receipt.get(name)
        require(type(caps) is dict and all(caps.get(key) == expected_value for key, expected_value in expected.items())
            and microseconds(caps.get("CPUQuotaPerSecUSec")) == 1900000)
        duration = microseconds(caps.get("RuntimeMaxUSec"))
        require(0 < duration <= (1170 if name == "observed_properties" else 1200) * 1000000)
    caps = receipt["observed_properties"]
    require(caps.get("NoNewPrivileges") == "yes" and caps.get("CapabilityBoundingSet") == ""
        and caps.get("AmbientCapabilities") == "" and caps.get("PrivateNetwork") == "yes")
    require(type(receipt.get("isolation")) is dict and receipt["isolation"].get("PrivateNetwork") == "yes")
    return True
