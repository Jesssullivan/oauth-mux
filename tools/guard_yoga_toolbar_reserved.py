"""One attended installed toolbar reservation; no host/browser invocation here."""
from decimal import Decimal
from pathlib import Path
import re
import guard_native_seed_plan_reserved as kernel

PROFILE = 'yoga-toolbar-reserved'
MODEL_PROFILE = 'yoga-toolbar-reserved-models'
PROFILES = (PROFILE, MODEL_PROFILE)
LABEL = '//delivery:yoga_toolbar_consent_proof'
MODEL_ARGUMENTS = ['test', '//tools:guard_yoga_toolbar_reserved_test',
    '//tools:yoga_reserved_session_qualification_test', '//tools:yoga_operator_coordinator_test',
    '//tools:yoga_operator_launch_test', '//tools:yoga_session_qualification_test',
    '//tools:guard_yoga_profile_test', '//delivery:yoga_installed_workspace_test',
    '//tools:yoga_installed_workspace_test', '//tools:guard_native_seed_plan_reserved_test',
    '//tools:execution_guard_test', '//:docs_check', '//tools:runtime_source_receipt']
SELECTION_SCOPE = 'yoga-local-installed-reserved-session-selection-v1'
QUALIFICATION_SCOPE = 'yoga-local-installed-reserved-guard-qualification-v1'
PLAN_SCOPE = 'yoga-guard-reserved-worker-plan-v1'
READY_SCOPE = 'yoga-guard-reserved-worker-ready-v1'
CLOCK = 'originalEntryMonotonicNs'
MEMORY, TASKS, CPU = kernel.MEMORY, kernel.TASKS, kernel.CPU
Witness, WorkloadWitness = kernel.Witness, kernel.WorkloadWitness
remaining, properties = kernel.remaining, kernel.properties
monitor, cleanup_retained, release_worker = kernel.monitor, kernel.cleanup_retained, kernel.release_worker


def require(value):
    if value is not True:
        raise ValueError('reserved-yoga-toolbar-refused')


def finite(manager, arguments):
    require(manager == 'system' and arguments == ['run', LABEL])


def request(args, arguments):
    if args.profile not in PROFILES:
        return False
    if args.profile == MODEL_PROFILE:
        selected(args.profile, arguments)
        allowed = {'profile', 'manager', 'arguments', 'python', 'systemd_run', 'systemctl',
            'bazel', 'closure', 'bootstrap_closure', 'zig_sdk', 'java_home', 'state_dir',
            'initialize_state_dir', 'coordination_dir', 'become_file', 'reuse_owned_cache',
            'source_commit', 'source_dirty', 'repository_cache', 'nixpkgs_source'}
        require(args.manager == 'system' and args.reuse_owned_cache is False
            and not any(value for name, value in vars(args).items() if name not in allowed)
            and type(args.source_commit) is str and re.fullmatch(r'[0-9a-f]{40}', args.source_commit) is not None
            and args.source_dirty == 'false')
        from guard_resident_enrollment_profile import repository_inputs
        repository_inputs(args.repository_cache, args.nixpkgs_source)
        return True
    finite(args.manager, arguments)
    allowed = {'profile', 'manager', 'arguments', 'python', 'systemd_run', 'systemctl',
        'bazel', 'closure', 'bootstrap_closure', 'zig_sdk', 'java_home', 'state_dir',
        'initialize_state_dir', 'coordination_dir', 'become_file', 'reuse_owned_cache',
        'yoga_qualification', 'yoga_qualification_sha256', 'yoga_deadline_monotonic_ns'}
    require(not any(value for name, value in vars(args).items() if name not in allowed)
        and args.reuse_owned_cache is False and isinstance(args.yoga_qualification, Path)
        and type(args.yoga_qualification_sha256) is str
        and re.fullmatch(r'[0-9a-f]{64}', args.yoga_qualification_sha256) is not None
        and type(args.yoga_deadline_monotonic_ns) is int)
    return True


def selected(profile, arguments):
    require(profile == MODEL_PROFILE and arguments == MODEL_ARGUMENTS)
    return {'PrivateNetwork': 'yes'}


def command(builder, bazel, run, arguments, profile, entry, deadline, **options):
    selected(profile, arguments)
    remaining(entry, deadline)
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(options.get('repository_cache'), options.get('nixpkgs_source'))
    require(options.get('output_base') is None)
    result = builder(bazel, run, arguments, profile='standard', **options)
    result[result.index('test')+1:result.index('test')+1] = ['--repository_disable_download', '--repo_contents_cache=']
    return result


def clock(value, deadline=None, *, cleanup=False):
    require(type(value) is dict and type(value.get(CLOCK)) is int
        and type(value.get('deadlineMonotonicNs')) is int)
    entry, selected = value[CLOCK], value['deadlineMonotonicNs']
    require(deadline is None or deadline == selected)
    remaining(entry, selected, cleanup=cleanup)
    return entry, selected


def selection(value, deadline, uid, home):
    import yoga_session_qualification as qualification
    require(type(value) is dict and value.get('scope') == SELECTION_SCOPE
        and set(value) == qualification.INSTALLED_FIELDS | {CLOCK})
    clock(value, deadline)
    view = dict(value); view.pop(CLOCK); view['scope'] = qualification.INSTALLED_SCOPE
    qualification.validate_selection(view, deadline, uid, home)
    return value


def schema(value, deadline, source_root, tools, graph_sha256, uid, *, cleanup=False):
    import guard_yoga_profile as guard
    require(type(value) is dict and value.get('scope') == QUALIFICATION_SCOPE
        and set(value) == guard.INSTALLED_FIELDS | {CLOCK})
    clock(value, deadline, cleanup=cleanup)
    view = dict(value); view.pop(CLOCK); view['scope'] = guard.INSTALLED_SCOPE
    guard.schema(view, deadline, source_root, tools, graph_sha256, uid)
    return value


def capture(admission, *, cleanup=False):
    import guard_yoga_installed_workspace as installed
    require(type(admission) is dict and installed.verified(admission) is True)
    held = admission['installedCapture']
    require(type(held) is installed.Capture and held.record['schemaVersion'] == 2
        and {'guard_yoga_toolbar_reserved.py', 'yoga_reserved_session_qualification.py'}
            .issubset(held.record['controllerPackageSha256'])
        and 'yoga_reserved_session_qualification.sh' in held.record['workspaceFiles'])
    clock(admission['receipt'], cleanup=cleanup)
    return held


def preallocate(*arguments, **options):
    import guard_yoga_profile as guard
    admitted = guard._preallocate(*arguments, reserved=True, **options)
    try:
        capture(admitted)
        admitted['reservedToolbar'] = True
        return admitted
    except BaseException:
        if 'installedCapture' in admitted:
            admitted['installedCapture'].close()
        admitted['pin'].close()
        raise


def runtime(entry, deadline):
    seconds = int(remaining(entry, deadline))
    require(seconds >= 1)
    return seconds


def policy(entry, deadline, seconds):
    kernel.envelope(entry, deadline)
    require(type(seconds) is int and 1 <= seconds <= 1170)
    return {'scope': 'fixed-yoga-toolbar-worker-reservation-v1', CLOCK: entry,
        'deadlineMonotonicNs': deadline, 'runtimeSeconds': seconds,
        'memoryBytes': MEMORY, 'tasks': TASKS, 'cpuPercent': CPU}


def plan(value):
    require(type(value) is dict and value.get('scope') == PLAN_SCOPE
        and type(value.get('reservation')) is dict)
    selected = value['reservation']
    entry, deadline = clock(selected, value.get('deadlineNs'))
    require(selected == policy(entry, deadline, selected.get('runtimeSeconds')))
    return selected


def verify_runtime(value, seconds):
    require(type(value) is str and len(value) <= 64 and type(seconds) is int and 1 <= seconds <= 1170)
    token = r'[0-9]{1,10}(?:\.[0-9]{1,6})?(?:min|ms|us|s)'
    require(re.fullmatch(token + r'(?:\s*' + token + r')*', value) is not None)
    weights = {'min': 60000000, 's': 1000000, 'ms': 1000, 'us': 1}
    total = sum(Decimal(amount) * weights[unit] for amount, unit in
        re.findall(r'([0-9]{1,10}(?:\.[0-9]{1,6})?)(min|ms|us|s)', value))
    require(total == seconds * 1000000)


def verify_properties(actual, base, entry, deadline, seconds):
    remaining(entry, deadline)
    policy(entry, deadline, seconds)
    selected = properties(base)
    selected.pop('RuntimeMaxUSec', None)
    require(all(actual.get(name) == value for name, value in selected.items()
                if name != 'CPUQuotaPerSecUSec'))
    # systemd normalizes 190% as 1.900s on some versions.
    require(type(actual.get('CPUQuotaPerSecUSec')) is str
        and re.fullmatch(r'1\.9(?:0{0,4})s', actual['CPUQuotaPerSecUSec']) is not None)
    verify_runtime(actual.get('RuntimeMaxUSec'), seconds)


def verify_cgroup(actual):
    require(type(actual) is dict and actual.get('memory.max') == str(MEMORY)
        and actual.get('memory.swap.max') == '0' and actual.get('pids.max') == str(TASKS)
        and actual.get('memory.oom.group') == '1')
    fields = actual.get('cpu.max', '').split()
    require(len(fields) == 2 and all(re.fullmatch(r'[1-9][0-9]{0,8}', part) for part in fields)
        and int(fields[0]) * 10 == 19 * int(fields[1]))


def projection(entry, deadline, verified, resident, yoga, final_status):
    kernel.envelope(entry, deadline)
    require(type(verified) is bool and type(final_status) is int and type(yoga) is dict)
    proved = (final_status == 0 and verified is True and yoga.get('executionPassed') is True
        and yoga.get('toolbarConsentProved') is True and yoga.get('machineObservationsJoined') is True
        and yoga.get('humanGestureProvenance') == 'operator-attested')
    return {'scope': 'yoga-toolbar-reserved-proof-v1', CLOCK: entry,
        'deadlineMonotonicNs': deadline, 'memoryBytes': MEMORY, 'tasks': TASKS,
        'cpuPercent': CPU, 'resident': resident, 'verified_after_cleanup': verified,
        'toolbarConsentProved': proved, 'providerAuthorityProved': False,
        'normalVaultCustodyProved': False, 'nativeContinuityProved': False}


def model_projection(entry, deadline, verified, resident):
    kernel.envelope(entry, deadline)
    require(verified is None or type(verified) is bool)
    return {'scope': 'yoga-toolbar-reserved-models-v1', CLOCK: entry,
        'deadlineMonotonicNs': deadline, 'verified_after_cleanup': verified, 'resident': resident,
        'browserInvoked': False, 'seatQualified': False, 'toolbarConsentProved': False,
        'providerAuthorityProved': False, 'normalVaultCustodyProved': False, 'nativeContinuityProved': False}


def finalize(receipt, entry, deadline, verified, resident):
    """Publish one consent verdict only after all original-clock outer checks."""
    require(type(receipt) is dict and receipt.get('profile') == PROFILE
        and type(receipt.get('exit')) is int and type(receipt.get('yoga')) is dict
        and type(receipt['yoga'].get('summary')) is dict and type(verified) is bool)
    try:
        remaining(entry, deadline, cleanup=True)
    except ValueError:
        verified = False
        receipt['exit'] = 125
    summary = receipt['yoga']['summary']
    value = projection(entry, deadline, verified, resident, summary, receipt['exit'])
    if value['toolbarConsentProved'] is not True and receipt['exit'] == 0:
        receipt['exit'] = 125
    receipt['yoga']['toolbarConsentProved'] = value['toolbarConsentProved']
    summary['toolbarConsentProved'] = value['toolbarConsentProved']
    receipt['yoga_toolbar_reservation'] = value
    return receipt
