
"""One exact two-file staging action, separate from readonly Yoga delivery."""
from pathlib import Path
import math
import os
import time
import yoga_delivery_settings as readonly
import guard_yoga_delivery_profile as old_profile
import yoga_install_inputs_receiver as receiver

PROFILE='yoga-install-inputs'
LABEL='//tools:yoga_install_inputs_stage'
STATE=Path('/home/jess/.local/state/omux-yoga-install-inputs-20261008')
COORDINATION=old_profile.COORDINATION
PROOF_MEMORY=4026531840
PROOF_TASKS=480
PROOF_CPU_PERCENT=190
CLEANUP_RESERVE_NS=30*10**9
LOCAL_DISPOSITION=None
AGENT=None
ALIAS='/omux-yoga-install-inputs/ssh-agent'

def selected(arguments,*,site=False,pack=False,recovery=False):
    receiver.require(arguments==['run',LABEL] and not any((site,pack,recovery)),
                     'exact-two-file-staging-label')
    return {'PrivateNetwork':'no'}

def coordination(root,state,arguments):
    selected(arguments)
    receiver.require(root is not None and Path(root)==COORDINATION and Path(state)==STATE,
                     'fixed-staging-coordination')
    return COORDINATION

def finite(arguments,manager,epoch,unrelated):
    selected(arguments)
    receiver.require(manager=='system' and type(epoch) is str and readonly.UUID.fullmatch(epoch)
                     and not any(unrelated),'fresh-qualify-epoch-without-other-authority')

def envelope(deadline,arguments,prior):
    selected(arguments)
    receiver.tick(deadline-CLEANUP_RESERVE_NS)
    receiver.require(type(prior) is str and receiver.re.fullmatch('[a-f0-9]{64}',prior),
                     'guard-selected-prior-qualification')
    return {'OMUX_YOGA_DELIVERY_MODE':'stage-install-inputs',
            'OMUX_YOGA_DELIVERY_DEADLINE_NS':str(deadline),
            'OMUX_YOGA_INSTALL_INPUTS_ENTRY_NS':str(deadline-receiver.MAX_NS),
            'OMUX_YOGA_DELIVERY_AUTHORITY_SHA256':prior}

def run_options(values):
    receiver.require(set(values)=={'OMUX_YOGA_DELIVERY_MODE','OMUX_YOGA_DELIVERY_DEADLINE_NS',
        'OMUX_YOGA_INSTALL_INPUTS_ENTRY_NS','OMUX_YOGA_DELIVERY_AUTHORITY_SHA256'},
        'closed-staging-run-environment')
    return ['--run_env='+key+'='+values[key] for key in sorted(values)]

def proof_properties(base):
    return dict(base,MemoryMax=str(PROOF_MEMORY),TasksMax=str(PROOF_TASKS),CPUQuotaPerSecUSec='1.9s')

def runtime_seconds(deadline):
    remaining=math.floor(receiver.tick(deadline-CLEANUP_RESERVE_NS))
    receiver.require(remaining>0,'stage-runtime-exhausted')
    return remaining

def admit(deadline):
    global LOCAL_DISPOSITION, AGENT
    receiver.tick(deadline-CLEANUP_RESERVE_NS)
    peer=receiver.session_peer(deadline-CLEANUP_RESERVE_NS)
    value=receiver.default_disposition(deadline-CLEANUP_RESERVE_NS)
    LOCAL_DISPOSITION=(peer,value)
    AGENT=Agent(deadline-CLEANUP_RESERVE_NS)
    return value

def observe(deadline,*,cleanup=False):
    selected_deadline=deadline if cleanup else deadline-CLEANUP_RESERVE_NS
    if AGENT is not None:
        AGENT.deadline=selected_deadline
        AGENT.directory.deadline=selected_deadline
        AGENT.source_parent.deadline=selected_deadline
        AGENT.check()
    receiver.require(LOCAL_DISPOSITION is not None and
        (receiver.session_peer(selected_deadline),receiver.default_disposition(selected_deadline,
            cleanup_deadline=deadline))
        ==LOCAL_DISPOSITION,'local-default-disposition-changed')
    return LOCAL_DISPOSITION[1]

budget=readonly.budget
tools=readonly.tools
lock_witness=readonly.lock_witness
select_prior=readonly.select_prior
recheck=readonly.recheck
effective_runtime=readonly.effective_runtime

def finish(run,arguments,status,empty,source_verified,deadline,lock):
    selected(arguments)
    observe(deadline,cleanup=True)
    record={'mode':'stage-install-inputs','source_verified_after_cleanup':source_verified,
            'qualification':None,'copy_performed':False,'remote_owned_containment_verified':False,
            'remote_cleanup':'unproved','coordination_lock_witness':lock,
            'local_default_named_unit_inactive_or_missing':True}
    if type(status) is int and status==0 and empty is True and source_verified is True:
        directory=readonly.trusted_directory(run,deadline)
        try:
            raw=readonly.read_owned(directory,'workload.log',8*1024**2,deadline)
            candidates=[]
            for row in raw.splitlines():
                budget(deadline)
                if row.startswith(b'{'):
                    value=receiver.decode(row)
                    if type(value) is dict and value.get('scope')==receiver.SCOPE:
                        candidates.append(value)
            from yoga_install_inputs_stage import RESULT
            receiver.require(len(candidates)==1 and set(candidates[0])==set(RESULT)
                and candidates[0]==RESULT and type(candidates[0]['files']) is
                type(candidates[0]['bytes']) is int and all(type(candidates[0][key]) is bool for key in
                ('receiver_cleanup_verified','destination_rehashed','installation','ready')),
                'one-closed-successful-stage-projection')
            observe(deadline,cleanup=True)
            output=readonly.publish(run,receiver.canonical(candidates[0]),deadline)
            record.update(qualification=output,copy_performed=True,
                remote_owned_containment_verified=True,remote_cleanup='empty')
        finally:
            readonly.close_directory(directory)
    return record

class Agent:
    """Only the public Lab runtime GPG SSH selector, never auth contents."""
    def __init__(self,deadline):
        import socket
        import struct
        self.deadline,self.directory,self.placeholder,self.stream=None,None,None,None
        self.source='/run/user/'+str(os.getuid())+'/gnupg/S.gpg-agent.ssh'
        self.namespace=STATE/'inputs'
        self.deadline=deadline
        try:
            self.directory=receiver.Directory(self.namespace,deadline,leaf_private=True)
            receiver.require(set(os.listdir(self.directory.fd))=={'ssh-agent'},'fixed-agent-placeholder-members')
            self.placeholder=os.open('ssh-agent',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,
                                     dir_fd=self.directory.fd)
            info=os.fstat(self.placeholder)
            receiver.require(receiver.stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid()
                and info.st_gid==os.getgid() and info.st_nlink==1 and info.st_size==0
                and receiver.stat.S_IMODE(info.st_mode)==0o600,'fixed-regular-agent-placeholder')
            self.placeholder_pin=receiver.file_identity(info)
            self.source_parent=receiver.Directory(str(Path(self.source).parent),deadline,leaf_private=True)
            info=os.stat(Path(self.source).name,dir_fd=self.source_parent.fd,follow_symlinks=False)
            receiver.require(receiver.stat.S_ISSOCK(info.st_mode) and info.st_uid==os.getuid()
                and info.st_gid==os.getgid() and receiver.stat.S_IMODE(info.st_mode)==0o700,
                'fixed-agent-source-custody')
            self.source_pin=receiver.file_identity(info)
            self.stream=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            self.stream.settimeout(min(2,receiver.tick(deadline)))
            self.stream.connect(self.source)
            pid,uid,gid=struct.unpack('3i',self.stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            receiver.require(pid>1 and uid==os.getuid(),'fixed-agent-peer-user')
            self.peer=receiver.process(pid)
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        receiver.tick(self.deadline)
        self.directory.check();self.source_parent.check()
        receiver.require(self.placeholder_pin==receiver.file_identity(os.fstat(self.placeholder))
            ==receiver.file_identity(os.stat('ssh-agent',dir_fd=self.directory.fd,follow_symlinks=False))
            and set(os.listdir(self.directory.fd))=={'ssh-agent'},'agent-placeholder-rebound')
        receiver.require(self.source_pin==receiver.file_identity(os.stat(Path(self.source).name,
            dir_fd=self.source_parent.fd,follow_symlinks=False))
            and receiver.process(self.peer[0])==self.peer,'agent-source-rebound')

    def bindings(self):
        self.check()
        return [str(self.namespace)+':/omux-yoga-install-inputs:rbind',
                self.source+':'+ALIAS+':norbind']

    def verify_bindings(self,actual):
        entries=actual.get('BindReadOnlyPaths','').split()
        expected={str(self.namespace)+':/omux-yoga-install-inputs:rbind',self.source+':'+ALIAS}
        receiver.require(len(entries)==2 and set(entries)==expected and not actual.get('BindPaths',''),
                         'exact-agent-bind-readback')
        self.check()
        return True

    def close(self):
        failed=False
        for key in ('stream','placeholder','source_parent','directory'):
            value=getattr(self,key,None)
            setattr(self,key,None)
            if value is not None:
                try:
                    os.close(value) if key=='placeholder' else value.close()
                except BaseException:
                    failed=True
        receiver.require(not failed,'agent-custody-release')
