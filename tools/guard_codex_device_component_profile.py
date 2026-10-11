"""Exact provider-free package TEST/installer RUN. Never account acquisition."""
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import time
sys.path.insert(0,str(Path(__file__).parent.parent/'delivery'))
import codex_device_acquisition_component as component
import guard_native_acquisition_dispatch as acquisition

PROFILE='codex-device-component'
RESERVED_PROFILE='codex-device-component-reserved'
PROFILES=(PROFILE,RESERVED_PROFILE)
RESERVED_MEMORY,RESERVED_TASKS,RESERVED_CPU_PERCENT=4026531840,480,190
FIELDS=('codex_component_manifest','codex_component_manifest_sha256')
MANIFEST_BASE=Path('/srv/fast-local/jess/state/codex/omux-codex-component-inputs-20261008')
PROOF_MEMORY,PROOF_TASKS,PROOF_CPU_PERCENT=4294967296,512,200

class Settings:
    # Reuse only the existing full-budget original-clock lifecycle branch.
    acquisition_profile=True
    component_profile=True
    PROOF_MEMORY,PROOF_TASKS,PROOF_CPU_PERCENT=PROOF_MEMORY,PROOF_TASKS,PROOF_CPU_PERCENT
    def __init__(self,manifest,profile=PROFILE):
        component.require(profile in PROFILES)
        self.manifest,self.PROFILE=manifest,profile
        if profile==RESERVED_PROFILE:
            self.PROOF_MEMORY,self.PROOF_TASKS,self.PROOF_CPU_PERCENT=RESERVED_MEMORY,RESERVED_TASKS,RESERVED_CPU_PERCENT
    def finite(self,arguments,manager,manifest,reuse,unrelated=()):
        component.require(arguments in (['test',component.PRODUCER],['run',component.INSTALLER])
            and manager=='system' and manifest==self.manifest and reuse is False and not any(unrelated))
        return {'PrivateNetwork':'yes'}
    def projection(self,actual,verified=False):
        result=dict(actual)
        for key in ('BindPaths','BindReadOnlyPaths'):
            result[key]='verified-component-bindings' if verified else 'private-bind-redacted'
        return result
    def rejection(self,error):return 'codex-device-component-refused'

def select(args,arguments):
    values=tuple(getattr(args,name,None) for name in FIELDS)
    if args.profile not in PROFILES:
        component.require(all(value is None for value in values));return None
    component.require(all(value is not None for value in values))
    allowed=set(FIELDS)|{'profile','manager','arguments','python','systemd_run','systemctl','bazel',
        'closure','bootstrap_closure','zig_sdk','java_home','source_commit','source_dirty','state_dir',
        'initialize_state_dir','coordination_dir','become_file','reuse_owned_cache','repository_cache','nixpkgs_source'}
    settings=Settings(args.codex_component_manifest,args.profile)
    settings.finite(arguments,args.manager,args.codex_component_manifest,args.reuse_owned_cache,
        tuple(value for key,value in vars(args).items() if key not in allowed))
    component.require(type(args.source_commit) is str and re.fullmatch(r'[0-9a-f]{40}',args.source_commit)
        and args.source_dirty=='false' and type(args.codex_component_manifest_sha256) is str
        and component.HEX.fullmatch(args.codex_component_manifest_sha256))
    path=component.canonical(str(args.codex_component_manifest))
    component.require(path.name=='input.json' and path.parent.parent==MANIFEST_BASE
        and re.fullmatch(r'[0-9a-f]{32}',path.parent.name))
    acquisition.repositories(args.repository_cache,args.nixpkgs_source)
    return settings

def proof_properties(properties,profile):
    component.require(profile in PROFILES)
    if profile==RESERVED_PROFILE:
        return dict(properties,MemoryMax=str(RESERVED_MEMORY),TasksMax=str(RESERVED_TASKS),
            CPUQuotaPerSecUSec='1.9s')
    return dict(properties)

def normalized(value,readback=False):
    rows=[]
    for token in value.split():
        parts=token.split(':')
        component.require(len(parts) in (2,3))
        source,destination=map(component.canonical,parts[:2])
        # All component bindings are directories; actual systemctl emits rbind.
        component.require(parts[2:]==['rbind'] if readback else parts[2:] in ([],['rbind']))
        rows.append((str(source),str(destination)))
    component.require(len(rows)==len(set(rows)))
    return sorted(rows)

class Admission:
    acquisition_profile=True
    component_profile=True
    def __init__(self,settings,args,source,deadline):
        self.namespace=self.manifest_file=self.qualified=self.run=None
        self.outputs=[];self.collecting=False
        self.settings,self.manifest,self.original_deadline=settings,settings.manifest,deadline
        self.work_deadline=deadline-30*10**9
        self.repository_cache,self.nixpkgs_source=args.repository_cache,args.nixpkgs_source
        self.manifest_sha256=args.codex_component_manifest_sha256
        try:
            self.tick()
            self.namespace=component.Directory(self.manifest.parent,0o700)
            component.require(self.namespace.names()=={'input.json'})
            self.manifest_file=component.File(self.manifest,self.work_deadline,
                mode=0o600,limit=65536)
            component.require(self.manifest_file.row['sha256']==self.manifest_sha256)
            home=Path(pwd.getpwuid(os.getuid()).pw_dir)
            self.value=component.schema(component.parsed(self.manifest_file.raw()),home)
            arguments=args.arguments[1:] if args.arguments[:1]==['--'] else args.arguments
            component.require(arguments==(['test',component.PRODUCER] if self.value['action']=='produce'
                else ['run',component.INSTALLER]))
            self.qualified=component.Qualified(self.value,self.work_deadline)
            if self.value['action']!='produce':
                for name in ('data_home','state_home'):
                    held=component.Directory(Path(self.value[name])/'omux-acquisition/codex',0o700)
                    self.outputs.append(held)
                # Guard does not take installer's exclusive flock on another description.
                # Worker must obtain its own nonblocking lease before any write.
                component.require(self.outputs[0].names()<={'.lock','current.json',component.BACKEND}
                    and self.outputs[1].names()<={'install.json','producer.json'})
                if self.value['action']=='remove' or self.outputs[0].names()-{'.lock'} or self.outputs[1].names():
                    files=self.qualified.component['files']|{'component.json':self.qualified.descriptor.row}
                    tree,held=component.installed(*self.outputs,component.record(self.value,self.qualified,files),self.work_deadline)
                    try:tree.recheck()
                    finally:
                        tree.close()
                        for item in held:item.close()
            self.facts={'scope':'provider-free-codex-device-component','action':self.value['action'],
                'manifest_sha256':self.manifest_sha256,'provider_request_performed':False,
                'native_execution_performed':False,'resident_effects_authorized':False,
                'continuity_qualified':False,'credential_contents_read':False}
            self.recheck()
        except BaseException:self.close();raise
    def tick(self):component.tick(self.original_deadline if self.collecting else self.work_deadline)
    def recheck(self):
        self.tick();self.namespace.recheck();self.manifest_file.recheck();self.qualified.recheck()
        component.require(self.namespace.names()=={'input.json'})
        for directory in self.outputs:directory.recheck()
        if self.run is not None:self.run_held.recheck()
        self.tick();return self.facts
    def bind_run(self,run):
        component.require(self.run is None)
        self.run_held=component.Directory(run,0o700);self.run=run
    def bindings(self):
        source=(Path(self.value['runtime_directory']) if self.value['action']=='produce'
            else Path(self.value['component_directory']))
        return [str(self.namespace.path)+':'+str(Path(component.DESTINATION).parent),
            str(source)+':'+str(source),str(self.qualified.receipt.parent.path)+':'+str(self.qualified.receipt.parent.path)]
    def writable_bindings(self,run):
        component.require(run==self.run)
        return [str(directory.path)+':'+str(directory.path) for directory in self.outputs]+[str(run)+':'+str(run)]
    def verify_bindings(self,actual,run,cache):
        component.require(cache==self.repository_cache and run==self.run)
        wanted=self.bindings()+([str(cache)+':'+str(cache)] if cache is not None else [])
        component.require(normalized(actual.get('BindReadOnlyPaths',''),True)==normalized(' '.join(wanted))
            and normalized(actual.get('BindPaths',''),True)==normalized(' '.join(self.writable_bindings(run))))
    def environment(self):
        self.tick();info=os.fstat(self.namespace.fd)
        return {component.VARIABLE:component.DESTINATION,
            component.NSID:str(info.st_dev)+':'+str(info.st_ino),component.DEADLINE:str(self.original_deadline),
            component.EPOCH:str(self.run)}
    def runtime_seconds(self):
        self.tick();seconds=(self.work_deadline-time.monotonic_ns())//10**9
        component.require(1<=seconds<=1200);return seconds
    def completed(self,status,cleaned,epoch,producer_sha256,graph_sha256):
        component.require(type(status) is int and status==0 and cleaned is True and self.run is not None
            and self.run.name==epoch and type(graph_sha256) is str and component.HEX.fullmatch(graph_sha256))
        self.collecting=True
        for item in (self.manifest_file,self.qualified.receipt,self.qualified.report,self.qualified.descriptor):
            if item is not None:item.deadline=self.original_deadline
        self.qualified.deadline=self.original_deadline
        for file in self.qualified.tree.files.values():file.deadline=self.original_deadline
        self.recheck()
        if self.value['action']!='produce':
            if self.value['action']=='install':
                files=self.qualified.component['files']|{'component.json':self.qualified.descriptor.row}
                tree,held=component.installed(*self.outputs,component.record(self.value,self.qualified,files),self.original_deadline)
                try:tree.recheck()
                finally:
                    tree.close()
                    for item in held:item.close()
            else:component.require(self.outputs[0].names()=={'.lock'} and not self.outputs[1].names())
        # TEST outputs are read by the later independent successful-outer admission.
        # This guard receipt does not invent a package output hash or installer authority.
        self.recheck()
        return {'action_epoch':epoch,'controller_graph_sha256':graph_sha256,
            'manifest_sha256':self.manifest_sha256,'action':self.value['action'],
            'provider_request_performed':False,'resident_enrollment_completed':False,'continuity_qualified':False}
    def close(self):
        items=(self.qualified,self.manifest_file,self.namespace,getattr(self,'run_held',None),*self.outputs)
        self.outputs=[];self.qualified=self.manifest_file=self.namespace=None
        component.close_all(items)

def admit(settings,args,source,deadline):
    component.require(type(settings) is Settings);return Admission(settings,args,source,deadline)

def command(builder,bazel,run,arguments,admission,**kwargs):
    component.require(type(admission) is Admission)
    admission.settings.finite(arguments,'system',admission.manifest,False)
    acquisition.repositories(kwargs.get('repository_cache'),kwargs.get('nixpkgs_source'))
    component.require((kwargs.get('repository_cache'),kwargs.get('nixpkgs_source'))
        ==(admission.repository_cache,admission.nixpkgs_source))
    producing=admission.value['action']=='produce'
    component.require(arguments==(['test',component.PRODUCER] if producing else ['run',component.INSTALLER]))
    result=builder(bazel,run,arguments if producing else ['build',component.INSTALLER],**kwargs)
    if not producing:result[result.index('build')]='run'
    result[result.index('--spawn_strategy=sandboxed')]='--spawn_strategy=linux-sandbox'
    # Bazel9's canonical repository download veto; PrivateNetwork remains mandatory.
    additions=['--repository_disable_download',
        '--repo_env=OMUX_CODEX_COMPONENT_MANIFEST='+str(admission.manifest),
        '--repo_env=OMUX_CODEX_COMPONENT_MANIFEST_SHA256='+admission.manifest_sha256,
        '--repo_env=OMUX_NATIVE_ENROLLMENT_DIRECTORY=',
        '--repo_env=OMUX_YOGA_DELIVERY_QUALIFICATION=']
    if admission.repository_cache is not None:additions.append('--repo_contents_cache=')
    additions += [('--test_env=' if producing else '--run_env=')+key+'='+value for key,value in admission.environment().items()]
    position=result.index(arguments[1]);result[position:position]=additions
    return result
