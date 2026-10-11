"""Exact sealed transfer RUN; separate from historical two-file staging."""
import hashlib
import os
from pathlib import Path
import time
import yoga_delivery_settings as readonly
import guard_yoga_install_inputs_profile as prior
import yoga_install_inputs_receiver as wire
import yoga_sealed_transfer_schema as schema
import guard_native_seed_plan_reserved as kernel
import guard_resident_owned_update as owned

PROFILE='yoga-sealed-workspace-stage'
LABEL='//tools:yoga_sealed_transfer_stage'
STATE=prior.STATE
COORDINATION=prior.COORDINATION
PROOF_MEMORY,PROOF_TASKS,PROOF_CPU_PERCENT=prior.PROOF_MEMORY,prior.PROOF_TASKS,prior.PROOF_CPU_PERCENT
CLEANUP_RESERVE_NS=30*10**9
AGENT=INPUT=WITNESS=None
VALUE=INPUT_DIGEST=None

def request(args,arguments,deadline):
    names={'profile','manager','arguments','python','systemd_run','systemctl','bazel','closure',
        'bootstrap_closure','zig_sdk','java_home','source_commit','source_dirty','state_dir',
        'coordination_dir','become_file','repository_cache','nixpkgs_source','yoga_delivery_epoch',
        'yoga_sealed_transfer_input','yoga_sealed_transfer_input_sha256'}
    schema.require(args.profile==PROFILE and args.manager=='system'
        and type(args.source_commit) is str and schema.REV.fullmatch(args.source_commit) is not None
        and args.source_dirty=='false' and not any(value for name,value in vars(args).items() if name not in names))
    selected(arguments)
    try:
        select_input(args.yoga_sealed_transfer_input,args.yoga_sealed_transfer_input_sha256,deadline)
        schema.require(VALUE['producerSourceCommit']==args.source_commit)
    except BaseException:
        close(); raise

def selected(arguments,*,site=False,pack=False,recovery=False):
    schema.require(arguments==['run',LABEL] and not any((site,pack,recovery)))
    return {'PrivateNetwork':'no'}

def select_input(path,digest,deadline):
    global INPUT,VALUE,INPUT_DIGEST
    schema.require(type(path) is str and str(Path(path))==path
        and any(path.startswith(root+'/') for root in schema.PUBLIC))
    INPUT=owned.PublicFile(path,deadline-CLEANUP_RESERVE_NS,schema.MAX_METADATA,owned=True)
    try:
        VALUE=schema.manifest(INPUT.raw,digest); INPUT_DIGEST=digest
    except BaseException:
        INPUT.close(); INPUT=None; raise

def coordination(root,state,arguments):
    selected(arguments)
    schema.require(Path(root)==COORDINATION and Path(state)==STATE)
    return COORDINATION

def finite(arguments,manager,epoch,unrelated):
    selected(arguments)
    schema.require(manager=='system' and type(epoch) is str and readonly.UUID.fullmatch(epoch) is not None
        and not any(unrelated) and INPUT is not None)

def envelope(deadline,arguments,prior_digest):
    selected(arguments); observe(deadline)
    schema.require(type(prior_digest) is str and schema.SHA.fullmatch(prior_digest) is not None)
    return {'OMUX_YOGA_DELIVERY_MODE':'stage-sealed-workspace',
        'OMUX_YOGA_DELIVERY_DEADLINE_NS':str(deadline),
        'OMUX_YOGA_SEALED_TRANSFER_ENTRY_NS':str(deadline-wire.MAX_NS),
        'OMUX_YOGA_DELIVERY_AUTHORITY_SHA256':prior_digest,
        'OMUX_YOGA_SEALED_TRANSFER_INPUT':str(INPUT.path),
        'OMUX_YOGA_SEALED_TRANSFER_INPUT_SHA256':INPUT_DIGEST}

def run_options(values):
    schema.require(set(values)=={'OMUX_YOGA_DELIVERY_MODE','OMUX_YOGA_DELIVERY_DEADLINE_NS',
        'OMUX_YOGA_SEALED_TRANSFER_ENTRY_NS','OMUX_YOGA_DELIVERY_AUTHORITY_SHA256',
        'OMUX_YOGA_SEALED_TRANSFER_INPUT','OMUX_YOGA_SEALED_TRANSFER_INPUT_SHA256'})
    return ['--run_env='+key+'='+values[key] for key in sorted(values)]

def proof_properties(base): return prior.proof_properties(base)
def runtime_seconds(deadline): return prior.runtime_seconds(deadline)

def admit(deadline):
    global AGENT,WITNESS
    schema.require(INPUT is not None and AGENT is None and WITNESS is None)
    WITNESS=kernel.Witness(deadline-wire.MAX_NS,deadline)
    try: AGENT=prior.Agent(deadline-CLEANUP_RESERVE_NS); observe(deadline)
    except BaseException:
        close(); raise

def observe(deadline,*,cleanup=False):
    schema.require(INPUT is not None and WITNESS is not None and AGENT is not None)
    cutoff=deadline if cleanup else deadline-CLEANUP_RESERVE_NS
    INPUT.deadline=cutoff; INPUT.recheck()
    schema.require(hashlib.sha256(INPUT.raw).hexdigest()==INPUT_DIGEST)
    AGENT.deadline=cutoff; AGENT.directory.deadline=cutoff; AGENT.source_parent.deadline=cutoff
    AGENT.check(); WITNESS.observe(cleanup=cleanup)

def close():
    global AGENT,INPUT,WITNESS
    held=(AGENT,INPUT,WITNESS); AGENT=INPUT=WITNESS=None
    failed=False
    for value in held:
        if value is not None:
            try: value.close()
            except BaseException: failed=True
    schema.require(not failed)

def finish(run,arguments,status,empty,source_verified,deadline,lock):
    selected(arguments); observe(deadline,cleanup=True)
    record={'mode':'stage-sealed-workspace','source_verified_after_cleanup':source_verified,
        'qualification':None,'copy_performed':False,'remote_owned_containment_verified':False,
        'remote_cleanup':'unproved','coordination_lock_witness':lock,'input_sha256':INPUT_DIGEST,
        'normal_resident_observed':True,'installation':False,'seat_qualified':False,'toolbar_consent_proved':False}
    if type(status) is int and status==0 and empty is True and source_verified is True:
        directory=readonly.trusted_directory(run,deadline)
        try:
            raw=readonly.read_owned(directory,'workload.log',8*1024**2,deadline)
            candidates=[schema.decode(row) for row in raw.splitlines() if row.startswith(b'{')]
            import yoga_sealed_transfer_receiver as receiver
            receiver.INPUT_SHA256=INPUT_DIGEST
            expected=dict(receiver.result(VALUE,'complete'),token=VALUE['transferId'],receiverCleanupVerified=True,
                destinationRegistrationVerified=True,producerSourceCommit=VALUE['producerSourceCommit'],
                producerGraphSha256=VALUE['producerGraphSha256'],destinationWorkspace=VALUE['destination']['workspace'])
            schema.require(len(candidates)==1)
            schema.exact_result(candidates[0],expected)
            observe(deadline,cleanup=True)
            published=readonly.publish(run,schema.canonical(expected),deadline)
            record.update(qualification=published,copy_performed=True,remote_owned_containment_verified=True,remote_cleanup='empty')
        finally: readonly.close_directory(directory)
    return record

budget=readonly.budget
tools=readonly.tools
lock_witness=readonly.lock_witness
def select_prior(epoch,graph,limits,deadline,lock):
    return readonly.select_prior(epoch,graph,limits,deadline,lock,reserved=True,source_commit=VALUE['producerSourceCommit'])
def recheck(prior,graph,limits,deadline,lock):
    return readonly.recheck(prior,graph,limits,deadline,lock,reserved=True,source_commit=VALUE['producerSourceCommit'])
def effective_runtime(actual,seconds):
    schema.require(type(seconds) is int and 0<seconds<=1200 and wire.duration(actual)==seconds*1000000)
