"""Finite current Omux/HM artifact action; existing resident reservation only."""
import re
import guard_native_seed_plan_reserved as kernel

PROFILE = 'current-home-manager-artifact-reserved'
MODELS = 'current-home-manager-artifact-models-reserved'
EVALUATE = 'current-home-manager-evaluation-reserved'
PROFILES = (PROFILE, MODELS, EVALUATE)
VECTORS = {EVALUATE: ['test','//tools:home_manager_current_evaluation'], PROFILE: ['test', '//delivery:current_home_manager_artifact'], MODELS: ['test',
    '//tools:guard_current_home_manager_artifact_reserved_test',
    '//delivery:current_home_manager_artifact_test', '//tools:home_manager_current_artifact_test',
    '//tools:home_manager_bundle_test', '//delivery:home_manager_service_test', '//:docs_check']}
MEMORY, TASKS, CPU = kernel.MEMORY, kernel.TASKS, kernel.CPU
Witness, WorkloadWitness = kernel.Witness, kernel.WorkloadWitness
monitor, cleanup_retained = kernel.monitor, kernel.cleanup_retained
release_worker, properties, remaining = kernel.release_worker, kernel.properties, kernel.remaining


def require(value):
    if value is not True:
        raise ValueError('current-home-manager-artifact-reservation-refused')


def selected(profile, arguments):
    require(profile in PROFILES and arguments == VECTORS[profile])
    return {'PrivateNetwork': 'yes'}


def request(args, arguments):
    if args.profile not in PROFILES:
        return False
    selected(args.profile, arguments)
    allowed = {'profile','manager','arguments','python','systemd_run','systemctl','bazel','closure',
        'bootstrap_closure','zig_sdk','java_home','source_commit','source_dirty','state_dir',
        'initialize_state_dir','coordination_dir','become_file','reuse_owned_cache','repository_cache','nixpkgs_source'}
    require(args.manager == 'system' and args.reuse_owned_cache is False
        and not any(value for name,value in vars(args).items() if name not in allowed)
        and isinstance(args.source_commit,str) and re.fullmatch('[0-9a-f]{40}',args.source_commit) is not None
        and args.source_dirty in ('true','false'))
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(args.repository_cache,args.nixpkgs_source)
    return True


def command(builder,bazel,run,arguments,profile,entry,deadline,**kwargs):
    selected(profile,arguments)
    remaining(entry,deadline)
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(kwargs.get('repository_cache'),kwargs.get('nixpkgs_source'))
    require(kwargs.get('output_base') is None)
    result = builder(bazel,run,arguments,profile='standard',**kwargs)
    index = result.index('test') + 1
    result[index:index] = ['--repository_disable_download','--repo_contents_cache=']
    if profile in (PROFILE,EVALUATE):
        from execution_guard import graph_digest
        from pathlib import Path
        values = {'MODE': profile, 'SOURCE_COMMIT': kwargs['source_commit'],
            'SOURCE_DIRTY':kwargs['source_dirty'],'GRAPH_SHA256':graph_digest(Path.cwd())[0],
            'ENTRY_NS':str(entry),'DEADLINE_NS':str(deadline)}
        result[index:index] = ['--test_env=OMUX_CURRENT_HM_' + key + '=' + value for key,value in values.items()]
    return result


def projection(profile,entry,deadline,verified,resident):
    require(profile in PROFILES and (verified is None or type(verified) is bool))
    kernel.envelope(entry,deadline)
    return {'scope':'fixed-' + profile + '-v1','profile':profile,
        'original_entry_monotonic_ns':entry,'original_deadline_monotonic_ns':deadline,
        'verified_after_cleanup':verified,'resident':resident,'shipped':False,
        'artifact_qualified':False,'activation_qualified':False,'browser_qualified':False,
        'custody_qualified':False,'health_qualified':False,'continuity_qualified':False,'live_qualified':False}
