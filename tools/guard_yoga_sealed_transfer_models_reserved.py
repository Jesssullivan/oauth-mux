"""One exact provider-free TEST vector, qualified shared kernel by reference."""
import re
import guard_native_seed_plan_reserved as kernel

PROFILE='yoga-sealed-workspace-models-reserved'
PROFILES=(PROFILE,)
MEMORY,TASKS,CPU=kernel.MEMORY,kernel.TASKS,kernel.CPU
MODELS=['test','//tools:guard_yoga_sealed_transfer_models_reserved_test','//tools:guard_yoga_controller_qualify_reserved_test','//tools:yoga_sealed_transfer_test','//tools:yoga_install_inputs_stage_test',
    '//tools:execution_guard_test','//delivery:yoga_installed_workspace_test',
    '//tools:yoga_installed_workspace_test','//tools:guard_yoga_installed_reserved_test',
    '//tools:yoga_installed_controller_support_test','//tools:yoga_local_console_scope_test','//:docs_check','//tools:runtime_source_receipt']

def selected(profile,arguments):
    kernel.require(profile==PROFILE and arguments==MODELS)
    return {'PrivateNetwork':'yes'}

def request(args,arguments):
    if args.profile!=PROFILE: return False
    selected(args.profile,arguments)
    allowed={'profile','manager','arguments','python','systemd_run','systemctl','bazel','closure',
        'bootstrap_closure','zig_sdk','java_home','source_commit','source_dirty','state_dir',
        'coordination_dir','become_file','repository_cache','nixpkgs_source'}
    kernel.require(args.manager=='system' and not any(value for name,value in vars(args).items() if name not in allowed)
        and type(args.source_commit) is str and re.fullmatch('[a-f0-9]{40}',args.source_commit) is not None
        and args.source_dirty=='false')
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(args.repository_cache,args.nixpkgs_source)
    return True

def command(builder,bazel,run,arguments,profile,entry,deadline,**kwargs):
    selected(profile,arguments); kernel.remaining(entry,deadline)
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(kwargs.get('repository_cache'),kwargs.get('nixpkgs_source'))
    result=builder(bazel,run,arguments,profile='standard',**kwargs)
    index=result.index('test')+1
    result[index:index]=['--repository_disable_download','--repo_contents_cache=']
    return result

def projection(entry,deadline,verified,resident):
    kernel.envelope(entry,deadline)
    kernel.require(verified is None or type(verified) is bool)
    return {'scope':'fixed-yoga-sealed-transfer-model-reservation-v1',
        'original_entry_monotonic_ns':entry,'original_deadline_monotonic_ns':deadline,
        'verified_after_cleanup':verified,'resident':resident,'provider_invoked':False,
        'browser_invoked':False,'ssh_invoked':False,'workspace_transferred':False,
        'destination_registration_qualified':False,'seat_qualified':False,'toolbar_consent_proved':False}

def verify_runtime(actual,seconds):
    from guard_yoga_sealed_transfer_profile import effective_runtime
    effective_runtime(actual,seconds)

properties=kernel.properties
Witness=kernel.Witness
WorkloadWitness=kernel.WorkloadWitness
monitor=kernel.monitor
cleanup_retained=kernel.cleanup_retained
release_worker=kernel.release_worker
remaining=kernel.remaining
