"""Three exact Yoga administrative vectors; sampled resident reservation only."""
import re
import guard_native_seed_plan_reserved as kernel

SELECTION_PROFILE = 'yoga-installed-selection-reserved'
WORKSPACE_PROFILE = 'yoga-installed-workspace-reserved'
MODEL_PROFILE = 'yoga-installed-models-reserved'
PROFILES = (SELECTION_PROFILE, WORKSPACE_PROFILE, MODEL_PROFILE)
SELECTION_LABEL = '//delivery:yoga_installed_selection'
WORKSPACE_LABEL = '//delivery:yoga_installed_workspace'
MODEL_ARGUMENTS = ['test',
    '//tools:guard_yoga_installed_reserved_test',
    '//tools:yoga_installed_controller_support_test',
    '//delivery:yoga_installed_selection_test',
    '//tools:yoga_selection_declaration_test',
    '//delivery:yoga_installed_workspace_test',
    '//tools:yoga_installed_workspace_test',
    '//tools:guard_yoga_installed_producer_test',
    '//tools:guard_native_seed_plan_reserved_test',
    '//tools:guard_yoga_profile_test',
    '//tools:yoga_session_qualification_test',
    '//tools:yoga_operator_launch_test',
    '//tools:execution_guard_test', '//:docs_check', '//tools:runtime_source_receipt']
VECTORS = {SELECTION_PROFILE: ['test', SELECTION_LABEL],
           WORKSPACE_PROFILE: ['run', WORKSPACE_LABEL], MODEL_PROFILE: MODEL_ARGUMENTS}
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
        raise ValueError('yoga-installed-reservation-refused')


def selected(profile, arguments):
    require(profile in PROFILES and arguments == VECTORS[profile])
    return {'PrivateNetwork': 'yes'}


def request(args, arguments):
    if args.profile not in PROFILES:
        return False
    selected(args.profile, arguments)
    allowed = {'profile', 'manager', 'arguments', 'python', 'systemd_run', 'systemctl',
        'bazel', 'closure', 'bootstrap_closure', 'zig_sdk', 'java_home', 'source_commit',
        'source_dirty', 'state_dir', 'initialize_state_dir', 'coordination_dir',
        'become_file', 'reuse_owned_cache', 'repository_cache', 'nixpkgs_source'}
    digest = getattr(args, 'yoga_installed_producer_selection_sha256', None)
    if args.profile == WORKSPACE_PROFILE:
        allowed.add('yoga_installed_producer_selection_sha256')
        require(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest) is not None)
    else:
        require(digest is None)
    require(args.manager == 'system' and args.reuse_owned_cache is False
        and not any(value for name, value in vars(args).items() if name not in allowed)
        and type(args.source_commit) is str
        and re.fullmatch(r'[0-9a-f]{40}', args.source_commit) is not None
        and args.source_dirty == 'false')
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(args.repository_cache, args.nixpkgs_source)
    return True


def admit(digest, source_root, deadline):
    import guard_yoga_installed_producer as producer
    # Required v2 is checked before producer creates its exclusive outputs dir.
    return producer.Admission(digest, source_root, deadline, required_schema=2)


def command(builder, bazel, run, arguments, profile, entry, deadline, *, admission=None, **kwargs):
    selected(profile, arguments)
    remaining(entry, deadline)
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(kwargs.get('repository_cache'), kwargs.get('nixpkgs_source'))
    require(kwargs.get('output_base') is None)
    if profile == WORKSPACE_PROFILE:
        import guard_yoga_installed_producer as producer
        require(type(admission) is producer.Admission and admission.selection_schema == 2)
        result = producer.command(bazel, run, arguments, admission, builder,
                                  profile='standard', **kwargs)
        index = result.index('run') + 1
    else:
        require(admission is None)
        result = builder(bazel, run, arguments, profile='standard', **kwargs)
        index = result.index('test') + 1
    # Disabled for every route, including without a selected repository cache.
    result[index:index] = ['--repository_disable_download', '--repo_contents_cache=']
    if profile == SELECTION_PROFILE:
        result[index:index] = ['--test_env=OMUX_INSTALLED_SELECTION_DEADLINE_NS=' + str(deadline)]
    return result


def projection(profile, entry, deadline, verified, resident):
    require(profile in PROFILES and (verified is None or type(verified) is bool))
    kernel.envelope(entry, deadline)
    return {'scope': 'fixed-yoga-installed-reservation-v1',
        'mode': {SELECTION_PROFILE: 'selection', WORKSPACE_PROFILE: 'workspace', MODEL_PROFILE: 'models'}[profile],
        'original_entry_monotonic_ns': entry, 'original_deadline_monotonic_ns': deadline,
        'verified_after_cleanup': verified, 'resident': resident,
        'browser_invoked': False, 'provider_invoked': False, 'normal_vault_observed': False,
        'destination_installation_qualified': False, 'seat_qualified': False,
        'toolbar_consent_proved': False, 'native_runtime_qualified': False,
        'continuity_qualified': False}
