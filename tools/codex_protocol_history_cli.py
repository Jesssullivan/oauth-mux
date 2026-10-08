"""One fresh selected-SDK CLI/14-gate position after immutable completed gates.

No stage of the earlier two-dispatch chain is reopened. This owner reserves a
separate singleton before launch, uses an empty output base, and closes on every
terminal outcome. No historical or predecessor output cache is adopted.
"""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import codex_protocol_history_native as protocol
import codex_protocol_history_completed_inputs as completed
import codex_native_profile as native
from codex_native_candidate_cache import controller_inventory
from codex_fresh_source import trusted_parent
from codex_sdk_profile import require,hash_regular,verify_inventory,EXPORT_MODE_POLICY

KIND='omux-protocol-history-cli-qualification-v1'
STATE=protocol.STATE
SELECTOR=STATE/'protocol-history-cli-selection.json'
CHAIN=STATE/'protocol-history-cli-chain.json'
JOURNAL='protocol-history-cli-journal.json'
ARTIFACTS='protocol-history-cli-artifacts.json'
STAGES={1:native.COMBINED_MODE}
MODES={native.COMBINED_MODE:native.MODES[native.COMBINED_MODE]}
GATES=native.QUALIFICATION_GATES
BAZEL=native.BAZEL
COMBINED_MODE=native.COMBINED_MODE
UUID=protocol.UUID
canonical=protocol.canonical
sha=protocol.sha
pin=protocol.pin
read_json=protocol.read_json
witness=protocol.witness
tick=protocol.tick
boot_host=protocol.boot_host
sealed_io=protocol.sealed_io
source_io=native.source_io
runtime=native.runtime
validate_source=protocol.validate_source


def selected(args):
    pair=(getattr(args,'native_protocol_cli',None),getattr(args,'native_protocol_cli_sha256',None))
    if not any(value is not None for value in pair):return False
    require(all(value is not None for value in pair) and args.profile=='codex-native'
        and args.manager=='system' and args.state_dir==STATE and Path(pair[0])==SELECTOR
        and str(pair[0])==str(SELECTOR) and args.native_mode==COMBINED_MODE
        and args.native_owned_candidate_cache is False and args.reuse_owned_cache is False
        and all(getattr(args,name,None) is None for name in (
            'native_cache_attempt','native_cache_transition','native_cache_transition_sha256',
            'native_cache_phase2','native_cache_phase2_sha256','native_fresh_completion',
            'native_fresh_completion_sha256','native_global_attempt','native_staged_compilation',
            'native_staged_compilation_sha256','native_stage','native_protocol_history',
            'native_protocol_history_sha256','native_protocol_stage')),
        'exclusive single selected CLI qualification required')
    pin(pair[1]);return True


def verify_inputs(args):
    require(selected(args), 'selected CLI source/SDK required')
    selection=completed.validate_selection(read_json(SELECTOR,args.native_protocol_cli_sha256,args.native_deadline))
    document=selection['inputs']
    require(document['source']['root']==str(args.native_source_root)
        and document['source']['receipt_sha256']==args.native_source_sha256
        and document['sdk']['root']==str(args.native_export_root)
        and document['sdk']['receipt_sha256']==args.native_export_sha256
        and document['controller_source_commit']==args.source_commit and args.source_dirty=='false',
        'CLI selected source/SDK/controller mismatch')
    return completed.load_completed_inputs(selection,args.native_patch_sha256,args.native_deadline)[0]


def completion_deadline(args,original_entry_ns,candidate=None):
    require(type(candidate) is Admission and candidate.verified_before_launch is True
        and selected(args) and type(original_entry_ns) is int
        and original_entry_ns==candidate.action_entry_ns
        and type(args.native_aggregate_seconds) is int and args.native_aggregate_seconds==3600,
        'CLI original one-shot clock requires actual new owner')
    tick(candidate.original_deadline_ns/10**9)
    return candidate.original_deadline_ns/10**9


def command(args,run,locked_path,bash,candidate=None):
    require(type(candidate) is Admission and candidate.authorize_native_mode(args) is True,
        'CLI command requires actual singleton owner')
    return native.command_from_verified_inputs(args,run,locked_path,bash,candidate,
        verify_inputs(args),MODES,GATES)


CLI=native.CLI
CLI_CONTEXT_FIELDS=native.CLI_CONTEXT_FIELDS
MAX_CLI_BYTES=native.MAX_CLI_BYTES
QUALIFICATION_GATES=GATES
qualification_log=native.qualification_log

def combined_cli_artifact(context):
    """Read actual explicit CLI output only after successful verified cleanup."""
    require(isinstance(context, dict) and set(context) == CLI_CONTEXT_FIELDS,
        'combined CLI exact cleanup context required')
    require(context['workload_exit'] == 0 and type(context['workload_exit']) is int
        and context['descendants_empty'] is True
        and context['source_and_export_verified_after_cleanup'] is True
        and context['bazel'] == BAZEL
        and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            context['invocation_id']),
        'combined CLI successful cleanup/tool context required')
    for name in CLI_CONTEXT_FIELDS - {'invocation_id', 'output_base', 'bazel',
            'workload_exit', 'descendants_empty', 'source_and_export_verified_after_cleanup'}:
        require(isinstance(context[name], str) and re.fullmatch(r'[0-9a-f]{64}', context[name]),
            'combined CLI exact provenance digest required')
    output = STATE / ('protocol-history-cli-' + context['candidate_cache_key']) / 'output-base'
    require(context['output_base'] == str(output), 'combined CLI exact output base required')
    root = output / 'execroot/_main/bazel-out'
    parent = trusted_parent(root)
    configurations = []
    try:
        names = os.listdir(parent)
        require(len(names) <= 64, 'combined CLI configuration inventory bound')
        for name in names:
            if not re.fullmatch(r'[A-Za-z0-9_.-]+-opt', name):
                continue
            directory = root / name / 'bin/codex-rs/cli'
            try:
                held = trusted_parent(directory)
            except FileNotFoundError:
                continue
            try:
                try:
                    info = os.stat('codex', dir_fd=held, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                require(stat.S_ISREG(info.st_mode), 'combined CLI output must be regular')
                configurations.append((name, directory))
            finally:
                os.close(held)
        require(len(configurations) == 1, 'combined CLI requires one actual declared output')
    finally:
        os.close(parent)
    configuration, directory = configurations[0]
    parent = trusted_parent(directory)
    child = None
    try:
        child = os.open('codex', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(child)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_nlink == 1 and not before.st_mode & 0o022
            and before.st_mode & 0o111 and 4 <= before.st_size <= MAX_CLI_BYTES,
            'combined CLI output custody/size refused')
        require(os.pread(child, 4, 0) == b'\x7fELF', 'combined CLI actual ELF required')
        sha, count = hashlib.sha256(), 0
        while True:
            tick(source_io.DEADLINE)
            value = os.read(child, 1024 * 1024)
            if not value:
                break
            count += len(value)
            require(count <= MAX_CLI_BYTES, 'combined CLI output bound')
            sha.update(value)
        witness = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(count == before.st_size and witness(before) == witness(os.fstat(child))
            == witness(os.stat('codex', dir_fd=parent, follow_symlinks=False)),
            'combined CLI output changed during actual hash')
        return {'kind': 'actual-explicit-cli-target-v1', 'target': CLI,
            'configuration': configuration, 'path': str(directory / 'codex'),
            'sha256': sha.hexdigest(), 'bytes': count}
    finally:
        if child is not None:
            os.close(child)
        os.close(parent)

def qualification_evidence(run, manifest, context=None):
    cli = None
    if context is not None:
        require(isinstance(context, dict) and set(context) == CLI_CONTEXT_FIELDS,
            'combined CLI exact cleanup context required')
        require(context['invocation_id'] == run.name, 'combined CLI invocation differs')
        require(set(manifest['targets']) == set(MODES[COMBINED_MODE][1])
            and len(manifest['targets']) == 4 and len(manifest['results']) == 4
            and {row['target'] for row in manifest['results']} == set(MODES[COMBINED_MODE][1]),
            'combined qualification exact four requested targets differ')
        cli_rows = [row for row in manifest['results'] if row['target'] == CLI]
        require(len(cli_rows) == 1 and cli_rows[0]['state'] == 'missing-test-directory'
            and cli_rows[0]['files'] == [], 'combined CLI must remain an explicit non-test target')
        manifest = dict(manifest, results=[row for row in manifest['results'] if row['target'] != CLI])
        cli = combined_cli_artifact(context)
    require({row['target'] for row in manifest['results']} == set(QUALIFICATION_GATES)
        and len(manifest['results']) == len(QUALIFICATION_GATES),
        'qualification exact target set differs')
    fd = trusted_parent(run / 'test-evidence')
    rows = {}
    try:
        for row in manifest['results']:
            entries = [e for e in row['files'] if e['source'] == 'test.log' and e['state'] == 'copied']
            require(len(entries) == 1, 'qualification requires one copied log per target')
            entry = entries[0]
            digest, _, value = hash_regular(fd, entry['file'], 64 * 1024 * 1024, True)
            require(digest == entry['sha256'], 'qualification log changed')
            rows[row['target']] = {'log_sha256': digest,
                'tests': qualification_log(value, row['target'])}
    finally:
        os.close(fd)
    count = sum(len(row['tests']) for row in rows.values())
    xml = ET.Element('testsuites', tests=str(count), failures='0', errors='0', skipped='0')
    for target, row in sorted(rows.items()):
        suite = ET.SubElement(xml, 'testsuite', name=target, tests=str(len(row['tests'])),
            failures='0', errors='0', skipped='0')
        props = ET.SubElement(suite, 'properties')
        ET.SubElement(props, 'property', name='actual_test_log_sha256', value=row['log_sha256'])
        for name in row['tests']:
            ET.SubElement(suite, 'testcase', classname=target, name=name)
    raw = ET.tostring(xml, encoding='utf-8', xml_declaration=True) + b'\n'
    receipt = {'schema': 'omux-native-grouped-qualification-v1',
        'evidence': 'exact stable libtest names and counts from SHA256-verified actual logs',
        'targets': rows, 'passed': count, 'failed': 0, 'ignored': 0,
        'xml_sha256': hashlib.sha256(raw).hexdigest(),
        'native_support': False, 'provider_evaluation': False}
    if cli is not None:
        require(count == 14, 'combined qualification requires all fourteen named gates')
        receipt.update(cli_artifact=cli, cli_context=dict(context))
    parent = trusted_parent(run)
    try:
        for name, value in (('native-qualification.xml', raw),
                ('native-qualification.json', (json.dumps(receipt, sort_keys=True) + '\n').encode())):
            child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(child, 'wb') as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)
    return receipt

def meaningful_tests(run,manifest,mode,context=None):
    require(mode==COMBINED_MODE and context is not None,
        'single CLI mode needs actual cleanup context')
    return qualification_evidence(run,manifest,context)



class Admission:
    def __init__(self,args,run,tools,graph,locked_path,manager,verify_previous,original_entry_ns):
        self.args,self.run,self.tools,self.graph=args,Path(run),dict(tools),graph
        self.locked_path,self.manager,self.verify_previous=locked_path,manager,verify_previous
        self.action_entry_ns=original_entry_ns
        self.stage=1
        self.verified_before_launch=False;self.verified_after_cleanup=None
        self.root_fd=self.lock_fd=self.output_fd=self.chain_fd=self.input_fd=self.source_fd=None
        self.artifacts_sha=None;self.history=[];self.journal_sha=None;self.input_holds=[]
        try:
            require(selected(args) and self.run==STATE/self.run.name and UUID.fullmatch(self.run.name)
                and type(original_entry_ns) is int and original_entry_ns>=0
                and type(args.native_aggregate_seconds) is int and args.native_aggregate_seconds==3600,
                'selected owner finite new epoch required')
            self.original_entry_ns=original_entry_ns
            self.original_deadline_ns=original_entry_ns+3600*10**9
            args.native_deadline=self.original_deadline_ns/10**9;tick(args.native_deadline)
            self.selection=completed.validate_selection(read_json(SELECTOR,args.native_protocol_cli_sha256,args.native_deadline))
            self.document=self.selection['inputs']
            # Outer pinned receipts bind role paths to their actual output_base
            # BEFORE opening any selected source/SDK role directory.
            for role,target,output in (('source','//tools:codex_protocol_history_source_producer','protocol-history-source'),
                ('sdk','//tools:codex_protocol_history_sdk_export_producer','protocol-history-sdk-export')):
                protocol.producer_success(self.document[role],target,output,args.native_deadline)
            for root in (Path(self.document['source']['root']),Path(self.document['sdk']['root']),protocol.inputs.EXPORT_ROOT):
                self.input_holds.append((root,protocol.inputs.hold_root(root)))
            qualified=verify_inputs(args)
            self.completed=completed.load_completed_inputs(self.selection,args.native_patch_sha256,
                args.native_deadline,verify_previous)[1]
            inventory=controller_inventory(Path.cwd(),graph,args.native_deadline)
            require(self.document['controller_graph_sha256']==graph[0]
                and manager=='system' and args.source_dirty=='false'
                and type(tools) is dict and set(tools)=={'bazel','python','systemd_run','systemctl',
                    'bootstrap','closure','java','bash'}
                and all(type(value) is str and value.startswith('/nix/store/')
                    and '..' not in Path(value).parts and not any(c.isspace() for c in value)
                    for value in tools.values()), 'selected actual controller/tools required')
            self.bindings={'kind':KIND,'selection':copy.deepcopy(self.document),
                'cli_selection':copy.deepcopy(self.selection),
                'controller_inventory':inventory,'controller_graph':graph,'tools':dict(tools),
                'source_sdk_custody':{str(root):{'device':os.fstat(held[0]).st_dev,
                    'inode':os.fstat(held[0]).st_ino,'uid':os.fstat(held[0]).st_uid,
                    'gid':os.fstat(held[0]).st_gid,'mode':stat.S_IMODE(os.fstat(held[0]).st_mode)}
                    for root,held in self.input_holds},
                'locked_path':locked_path,'boot_host':boot_host(),'stages':STAGES,'gates':GATES,
                'limits':{'memory':4294967296,'swap':0,'tasks':512,'cpu_percent':200,
                    'jobs':1,'heap_mib':768,'processors':1,'chain_seconds':3600,'reserve_seconds':120},
                'network':'private','batch':True,'repository_download':False,
                'remote':False,'ambient_caches':False,'core_codegen':native.core_codegen_policy()}
            self.bindings=json.loads(canonical(self.bindings))
            previous=read_json(STATE/self.selection['predecessors']['1']['id']/'receipt.json',
                self.selection['predecessors']['1']['sha256'],args.native_deadline)['native_protocol_history']['bindings']
            require(canonical({name:self.bindings[name] for name in (
                'controller_inventory','controller_graph','tools','locked_path','boot_host','source_sdk_custody')})
                ==canonical({name:previous[name] for name in (
                    'controller_inventory','controller_graph','tools','locked_path','boot_host','source_sdk_custody')}),
                'CLI must preserve exact original qualified controller/tools/custody before reservation')
            self.key=sha(canonical(self.bindings))
            self.root=STATE/('protocol-history-cli-'+self.key)
            self.source=self.root/'native-input/source'
            self.lease=SimpleNamespace(output_base=self.root/'output-base')
            self.reserve_chain()
            parent=trusted_parent(STATE)
            try:
                if self.stage==1:os.mkdir(self.root.name,0o700,dir_fd=parent);os.fsync(parent)
                self.root_fd=os.open(self.root.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            finally:os.close(parent)
            if self.stage==1:
                require(not os.listdir(self.root_fd), 'selected first root must be empty')
                self.lock_fd=os.open('lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.root_fd)
            else:self.lock_fd=os.open('lock',os.O_RDWR|os.O_NOFOLLOW,dir_fd=self.root_fd)
            fcntl.flock(self.lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if self.stage==1:
                os.mkdir('output-base',0o700,dir_fd=self.root_fd)
                source_io.DEADLINE=args.native_deadline
                self.source=native.copy_source(args.native_source_root,qualified[0],self.root)
            self.output_fd=os.open('output-base',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.root_fd)
            self.input_fd=os.open('native-input',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.root_fd)
            self.source_fd=os.open('source',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.input_fd)
            self.custody=self.capture_custody()
            if self.stage==1:
                require(not os.listdir(self.output_fd), 'selected output base must be new and empty')

            self.write_journal('pending',self.history,first=True)
            self.check_directories();self.recheck_inputs(qualified);self.verify_history()
            self.args_snapshot=self.snapshot(args)
            self.verified_before_launch=True
        except BaseException:
            self.close();raise

    def validate_clock(self,document):
        require(type(document) is dict and set(document)=={'schema_version','kind','key','selector_sha256',
            'source_commit','boot_host','original_entry_monotonic_ns','original_deadline_monotonic_ns'}
            and type(document['schema_version']) is int and document['schema_version']==1
            and document['kind']==KIND and document['boot_host']==boot_host()
            and type(document['original_entry_monotonic_ns']) is int
            and document['original_entry_monotonic_ns']>=0
            and type(document['original_deadline_monotonic_ns']) is int
            and document['original_deadline_monotonic_ns']==document['original_entry_monotonic_ns']+3600*10**9
            and self.action_entry_ns>=document['original_entry_monotonic_ns']
            and document['selector_sha256']==self.args.native_protocol_cli_sha256
            and document['source_commit']==self.args.source_commit,
            'selected original boot/chain clock differs')
        pin(document['key']);pin(document['selector_sha256'])
        tick(document['original_deadline_monotonic_ns']/10**9)

    def reserve_chain(self):
        self.chain={'schema_version':1,'kind':KIND,'key':self.key,
            'selector_sha256':self.args.native_protocol_cli_sha256,'source_commit':self.args.source_commit,
            'boot_host':self.bindings['boot_host'],'original_entry_monotonic_ns':self.original_entry_ns,
            'original_deadline_monotonic_ns':self.original_deadline_ns}
        self.validate_clock(self.chain)
        raw=canonical(self.chain)+b'\n';self.chain_sha=sha(raw)
        parent=trusted_parent(CHAIN.parent)
        try:
            if self.stage==1:self.write_file(parent,CHAIN.name,raw,0o400)
            self.chain_fd=os.open(CHAIN.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            self.chain_witness=witness(os.fstat(self.chain_fd))
            self.check_chain()
        finally:os.close(parent)

    def write_file(self,fd,name,raw,mode):
        output=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        try:
            view=memoryview(raw)
            while view:
                tick(self.args.native_deadline)
                count=os.write(output,view);require(count>0,'selected durable short write');view=view[count:]
            os.fchmod(output,mode);os.fsync(output)
        finally:os.close(output)
        os.fsync(fd)

    def check_chain(self):
        parent=trusted_parent(CHAIN.parent)
        try:
            held=os.fstat(self.chain_fd);named=os.stat(CHAIN.name,dir_fd=parent,follow_symlinks=False)
            require(stat.S_ISREG(held.st_mode) and held.st_uid==os.getuid() and held.st_gid==os.getgid()
                and held.st_nlink==1 and stat.S_IMODE(held.st_mode)==0o400
                and witness(held)==witness(named)==self.chain_witness, 'selected chain custody changed')
            raw=b'';offset=0
            while offset<=8192:
                tick(self.args.native_deadline);chunk=os.pread(self.chain_fd,8193-offset,offset)
                if not chunk:break
                raw+=chunk;offset+=len(chunk)
            require(len(raw)<=8192 and sha(raw)==self.chain_sha
                and witness(os.fstat(self.chain_fd))==self.chain_witness, 'selected chain content changed')
            self.validate_clock(json.loads(raw,object_pairs_hook=protocol.source.unique))
        finally:os.close(parent)

    def capture_custody(self):
        result={}
        for name,fd,mode in (('chain',self.chain_fd,0o400),('root',self.root_fd,0o700),
            ('lock',self.lock_fd,0o600),('output',self.output_fd,0o700),
            ('input',self.input_fd,0o555),('source',self.source_fd,0o555)):
            info=os.fstat(fd)
            require((stat.S_ISREG(info.st_mode) and info.st_nlink==1 if name in ('chain','lock')
                else stat.S_ISDIR(info.st_mode)) and info.st_uid==os.getuid() and info.st_gid==os.getgid()
                and stat.S_IMODE(info.st_mode)==mode, 'selected held directory/lock mode refused')
            result[name]={'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,
                'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)}
        return result

    def check_directories(self):
        self.check_chain()
        require(self.capture_custody()==self.custody and set(os.listdir(self.root_fd))=={
            'lock','output-base','native-input',JOURNAL}, 'selected held root shape changed')
        for name,file in (('root',self.root),('lock',self.root/'lock'),('output',self.lease.output_base),
            ('input',self.root/'native-input'),('source',self.source)):
            parent=trusted_parent(file.parent)
            try:info=os.stat(file.name,dir_fd=parent,follow_symlinks=False)
            finally:os.close(parent)
            row=self.custody[name]
            require({'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,'gid':info.st_gid,
                'mode':stat.S_IMODE(info.st_mode)}==row, 'selected canonical root/source/lock replaced')
        sealed_io.read_small(self.root_fd,JOURNAL,self.args.native_deadline,self.journal_sha)

    def snapshot(self,args):
        return canonical({'selector':str(args.native_protocol_cli),'pin':args.native_protocol_cli_sha256,
            'stage':1,'mode':args.native_mode,'source':str(args.native_source_root),
            'source_pin':args.native_source_sha256,'export':str(args.native_export_root),
            'export_pin':args.native_export_sha256,'patches':args.native_patch_sha256,
            'commit':args.source_commit,'dirty':args.source_dirty,'profile':args.profile,
            'manager':args.manager,'state':str(args.state_dir),'aggregate':args.native_aggregate_seconds})

    def recheck_inputs(self,qualified=None):
        tick(self.args.native_deadline)
        require(read_json(SELECTOR,self.args.native_protocol_cli_sha256,self.args.native_deadline)==self.selection
            and controller_inventory(Path.cwd(),self.graph,self.args.native_deadline)==self.bindings['controller_inventory']
            and boot_host()==self.bindings['boot_host'], 'selected declaration/controller/boot changed')
        qualified=verify_inputs(self.args) if qualified is None else qualified
        verify_inventory(self.source_fd,qualified[0]['source_inventory'],EXPORT_MODE_POLICY,
            on_read=lambda count:tick(self.args.native_deadline))
        for role,target,output in (('source','//tools:codex_protocol_history_source_producer','protocol-history-source'),
            ('sdk','//tools:codex_protocol_history_sdk_export_producer','protocol-history-sdk-export')):
            prior=protocol.producer_success(self.document[role],target,output,self.args.native_deadline)
            require(self.verify_previous(prior) is True, 'selected producer owned unit/cgroup no longer empty')
        for root,held in self.input_holds:protocol.inputs.recheck_root(root,held)

    def authorize_native_mode(self,args):
        require(type(self) is Admission and args is self.args and selected(args)
            and self.verified_before_launch is True and self.snapshot(args)==self.args_snapshot
            and args.native_deadline==self.original_deadline_ns/10**9,
            'selected exact admitted command required')
        self.check_directories();self.recheck_inputs();self.verify_history();return True

    def journal(self,status,history):
        return {'schema_version':1,'kind':KIND,'key':self.key,'stage':self.stage,'epoch':self.run.name,
            'status':status,'history':copy.deepcopy(history),'custody':copy.deepcopy(self.custody),
            'chain_sha256':self.chain_sha}

    def write_journal(self,status,history,first=False):
        require(status in ('pending','qualified-stage','closed'), 'selected journal status invalid')
        if not first:sealed_io.read_small(self.root_fd,JOURNAL,self.args.native_deadline,self.journal_sha)
        raw=canonical(self.journal(status,history))+b'\n'
        name=JOURNAL if first else 'journal-next-'+self.run.name
        self.write_file(self.root_fd,name,raw,0o600)
        if not first:os.replace(name,JOURNAL,src_dir_fd=self.root_fd,dst_dir_fd=self.root_fd);os.fsync(self.root_fd)
        self.journal_sha=sha(raw)

    def facts(self):
        return {'kind':KIND,'key':self.key,'bindings':copy.deepcopy(self.bindings),'stage':self.stage,
            'max_dispatches':1,'provenance_sha256':self.key,'selector_sha256':self.args.native_protocol_cli_sha256,'workspace':str(self.source),'output_base':str(self.lease.output_base),
            'chain_sha256':self.chain_sha,'custody':copy.deepcopy(self.custody),'history':copy.deepcopy(self.history),
            'original_entry_monotonic_ns':self.original_entry_ns,
            'original_deadline_monotonic_ns':self.original_deadline_ns,'action_entry_monotonic_ns':self.action_entry_ns,
            'verified_before_launch':self.verified_before_launch,'verified_after_cleanup':self.verified_after_cleanup,
            'artifacts_sha256':self.artifacts_sha,'native_support':False,'provider_evaluation':False}

    def verify_history(self):
        require(self.history==[], 'one-shot CLI cannot adopt predecessor caches')
        _,actual=completed.load_completed_inputs(self.selection,self.args.native_patch_sha256,
            self.args.native_deadline,self.verify_previous)
        require(canonical(actual)==canonical(self.completed), 'completed predecessor evidence changed')
        old=read_json(STATE/self.selection['predecessors']['1']['id']/'receipt.json',
            self.selection['predecessors']['1']['sha256'],self.args.native_deadline)['native_protocol_history']['bindings']
        require(canonical({name:self.bindings[name] for name in (
            'controller_inventory','controller_graph','tools','locked_path','boot_host','source_sdk_custody')})
            ==canonical({name:old[name] for name in (
                'controller_inventory','controller_graph','tools','locked_path','boot_host','source_sdk_custody')}),
            'CLI must use the same actual qualified controller/tools/source custody')

    def verify_after_cleanup(self,qualified):
        self.check_directories();self.recheck_inputs(qualified);self.verify_history()
        self.verified_after_cleanup=True

    def close(self):
        for _,(fd,_) in self.input_holds:os.close(fd)
        self.input_holds=[]
        for name in ('source_fd','input_fd','output_fd','lock_fd','root_fd','chain_fd'):
            fd=getattr(self,name,None)
            if fd is not None:os.close(fd);setattr(self,name,None)

def validate_completed_success(receipt,selection,qualified,deadline):
    """Validate recorded execution; current IO uses only the caller's clock."""
    completed.validate_selection(selection)
    document=selection['inputs'];stage=1;exported=qualified[1]
    tick(deadline)
    sealed_io.verify_caps(receipt)
    facts=receipt['native_protocol_history_cli'];sdk_receipt=receipt['native_sdk'];plan=sdk_receipt['plan']
    require(type(facts) is dict and set(facts)=={'kind','key','bindings','stage','max_dispatches',
        'workspace','output_base','provenance_sha256','selector_sha256','chain_sha256','custody','history','original_entry_monotonic_ns',
        'original_deadline_monotonic_ns','action_entry_monotonic_ns','verified_before_launch',
        'verified_after_cleanup','artifacts_sha256','native_support','provider_evaluation'},
        'selected closed success facts required')
    pin(facts['selector_sha256'])
    bindings=facts['bindings']
    completed.validate_controller(bindings,document)
    require(type(bindings) is dict and set(bindings)=={'kind','selection','controller_inventory',
        'controller_graph','tools','source_sdk_custody','cli_selection','locked_path','boot_host','stages','gates',
        'limits','network','batch','repository_download','remote','ambient_caches','core_codegen'}
        and bindings['kind']==KIND and bindings['stages']=={'1':STAGES[1]} and bindings['cli_selection']==selection
        and canonical(bindings['gates'])==canonical(GATES)
        and canonical(bindings['limits'])==canonical({'memory':4294967296,'swap':0,'tasks':512,'cpu_percent':200,
            'jobs':1,'heap_mib':768,'processors':1,'chain_seconds':3600,'reserve_seconds':120})
        and bindings['boot_host']==boot_host() and bindings['network']=='private'
        and bindings['batch'] is True and all(bindings[name] is False for name in (
            'repository_download','remote','ambient_caches')),
        'selected fixed whole-chain bindings differ')
    modes={'chain':0o400,'root':0o700,'lock':0o600,'output':0o700,'input':0o555,'source':0o555}
    require(type(facts['custody']) is dict and set(facts['custody'])==set(modes)
        and all(type(row) is dict and set(row)=={'device','inode','uid','gid','mode'}
            and all(type(value) is int for value in row.values()) and row['device']>=0 and row['inode']>0
            and row['uid']==os.getuid() and row['gid']==os.getgid() and row['mode']==modes[name]
            for name,row in facts['custody'].items()), 'selected strict held custody differs')
    require(receipt['profile']=='codex-native' and receipt['manager']=='system'
        and type(receipt['exit']) is int and receipt['exit']==0
        and type(receipt['workload_exit']) is int and receipt['workload_exit']==0
        and receipt['controller_failure'] is None and receipt['descendants_empty'] is True
        and receipt['cleanup']['state']=='empty'
        and all(receipt[name] is None for name in ('native_candidate_cache','native_fresh_completion','native_staged_compilation','native_protocol_history'))
        and receipt['source_dirty']=='false' and receipt['source_commit']==document['controller_source_commit']
        and receipt['graph_sha256']==document['controller_graph_sha256']
        and facts['kind']==KIND and type(facts['stage']) is int and facts['stage']==stage
        and type(facts['max_dispatches']) is int and facts['max_dispatches']==1
        and facts['verified_before_launch'] is True and facts['verified_after_cleanup'] is True
        and facts['native_support'] is False and facts['provider_evaluation'] is False
        and type(receipt['id']) is str and UUID.fullmatch(receipt['id'])
        and receipt['unit']=='omux-execution-'+receipt['id']+'.service'
        and facts['key']==facts['provenance_sha256']==sha(canonical(facts['bindings'])) and facts['history']==[]
        and facts['bindings']['selection']==document
        and facts['workspace']==str(STATE/('protocol-history-cli-'+facts['key'])/'native-input/source')
        and receipt['output_base']==facts['output_base']==str(STATE/('protocol-history-cli-'+facts['key'])/'output-base')
        and sdk_receipt['mode']==STAGES[stage] and receipt['verb']==MODES[STAGES[stage]][0]
        and receipt['targets']==list(MODES[STAGES[stage]][1])
        and sdk_receipt['source_receipt_sha256']==document['source']['receipt_sha256']
        and sdk_receipt['export_receipt_sha256']==document['sdk']['receipt_sha256']
        and sdk_receipt['source_and_export_verified_after_cleanup'] is True
        and type(sdk_receipt['aggregate_seconds']) is int and sdk_receipt['aggregate_seconds']==3600
        and type(sdk_receipt['original_entry_monotonic_ns']) is int
        and type(sdk_receipt['original_deadline_monotonic_ns']) is int
        and sdk_receipt['original_entry_monotonic_ns']==facts['original_entry_monotonic_ns']
        and sdk_receipt['original_deadline_monotonic_ns']==facts['original_deadline_monotonic_ns']
        and type(facts['original_entry_monotonic_ns']) is int and facts['original_entry_monotonic_ns']>=0
        and type(facts['original_deadline_monotonic_ns']) is int
        and facts['original_deadline_monotonic_ns']==facts['original_entry_monotonic_ns']+3600*10**9
        and type(facts['action_entry_monotonic_ns']) is int
        and facts['action_entry_monotonic_ns']==facts['original_entry_monotonic_ns']
        and facts['original_entry_monotonic_ns']<=facts['action_entry_monotonic_ns']<facts['original_deadline_monotonic_ns']
        and plan['source_inventory_sha256']==document['source']['inventory_sha256']
        and plan['export_inventory_sha256']==document['sdk']['inventory_sha256']
        and plan['cwd']==facts['workspace'] and plan['candidate_output_base']==facts['output_base'],
        'selected actual successful outer native receipt required')
    # Compare the whole command with the fixed builder result, not presence of
    # flags (which permits duplicate later override flags).
    original=Path(plan['environment']['HOME']).parent
    require(original==STATE/receipt['id'], 'selected private action HOME is not its actual epoch')
    maximum=(facts['original_deadline_monotonic_ns']-facts['action_entry_monotonic_ns'])//10**9-120
    native.phase2_effective_runtime(receipt['observed_properties']['RuntimeMaxUSec'],maximum)
    export_root=Path(document['sdk']['root'])
    fake_args=SimpleNamespace(native_mode=STAGES[stage],native_deadline=deadline,
        native_source_root=Path(document['source']['root']),native_export_root=export_root)
    candidate=SimpleNamespace(source=Path(facts['workspace']),root=Path(facts['workspace']).parent.parent,
        lease=SimpleNamespace(output_base=Path(facts['output_base'])))
    expected=native.command_from_verified_inputs(fake_args,original,facts['bindings']['locked_path'],
        facts['bindings']['tools']['bash'],candidate,
        ({'inventory_sha256':document['source']['inventory_sha256']},exported),MODES,
        GATES if stage==1 else None,prepare=False)
    require(canonical(plan)==canonical(expected), 'selected whole fixed command/environment changed')
    argv=plan['argv']
    require(argv[0]==BAZEL and '--jobs=1' in argv and '--host_jvm_args=-Xmx768m' in argv
        and '--host_jvm_args=-XX:ActiveProcessorCount=1' in argv
        and '--lockfile_mode=error' in argv and '--repository_disable_download' in argv
        and all(argv.count(flag)==1 for flag in ('--batch','--repository_disable_download',
            '--ignore_all_rc_files','--incompatible_strict_action_env'))
        and plan['core_codegen']==native.core_codegen_policy()
        and plan['environment']['USE_BAZEL_VERSION']==native.BAZEL_VERSION,
        'selected immutable offline native plan differs')
    # Closed families reject additions or duplicates before acceptance.
    fixed={'--jobs=':['--jobs=1'],'--host_jvm_args=':['--host_jvm_args=-Xmx768m',
        '--host_jvm_args=-XX:ActiveProcessorCount=1'],'--lockfile_mode=':['--lockfile_mode=error'],
        '--compilation_mode=':['--compilation_mode=opt'],'--disk_cache=':['--disk_cache='],
        '--remote_executor=':['--remote_executor='],'--remote_cache=':['--remote_cache='],
        '--repo_contents_cache=':['--repo_contents_cache='],'--bes_backend=':['--bes_backend='],
        '--experimental_remote_downloader=':['--experimental_remote_downloader='],
        '--sandbox_default_allow_network=':['--sandbox_default_allow_network=false']}
    for prefix,expected in fixed.items():
        require([value for value in argv if value.startswith(prefix)]==expected,'selected duplicate/mutated native flag')
    if stage==1:
        expected=['--test_arg=--exact','--test_arg=--format=pretty','--test_arg=--color=never']
        expected+=['--test_arg='+name for names in GATES.values() for name in names]
        require([value for value in argv if value.startswith('--test_arg=')]==expected
            and not any(value.startswith('--test_filter=') for value in argv)
            and '--nocache_test_results' in argv and '--test_sharding_strategy=disabled' in argv,
            'selected exact tests plan differs')




def collect_artifacts(run,receipt,deadline):
    source_io.DEADLINE=deadline
    facts=receipt['native_protocol_history_cli']
    require(receipt['test_evidence']['state']=='preserved', 'CLI actual tests must be preserved')
    manifest=read_json(Path(run)/'test-evidence.json',receipt['test_evidence']['sha256'],deadline)
    require(type(manifest['bazel_exit']) is int and manifest['bazel_exit']==0
        and manifest['epoch_start_ns']==receipt['epoch_start_ns']
        and manifest['targets']==list(MODES[COMBINED_MODE][1])
        and len(manifest['results'])==4
        and {row['target'] for row in manifest['results']}==set(MODES[COMBINED_MODE][1]),
        'CLI actual four-target evidence differs')
    logs={}
    for row in manifest['results']:
        if row['target']==native.CLI:
            require(row['state']=='missing-test-directory' and row['files']==[],
                'explicit CLI must not masquerade as a test')
            continue
        entries=[entry for entry in row['files'] if entry['source']=='test.log']
        require(row['state']=='observed' and len(entries)==1 and entries[0]['state']=='copied',
            'CLI native test log missing')
        entry=entries[0]
        require(re.fullmatch(r'[0-9a-f]{64}\.evidence',entry['file']), 'CLI native log pathname refused')
        fd=trusted_parent(Path(run)/'test-evidence')
        try:
            digest,count,raw=hash_regular(fd,entry['file'],64*1024*1024,True,
                on_read=lambda count:tick(deadline))
            require(digest==entry['sha256'] and type(entry['bytes']) is int
                and count==entry['bytes'] and count>0, 'CLI actual log bytes differ')
            native.qualification_log(raw,row['target'])
        finally:os.close(fd)
        logs[row['target']]=sealed_io.artifact_file(Path(run)/'test-evidence'/entry['file'],deadline,64*1024*1024)
    context={'invocation_id':receipt['id'],'output_base':receipt['output_base'],
        'source_receipt_sha256':receipt['native_sdk']['source_receipt_sha256'],
        'export_receipt_sha256':receipt['native_sdk']['export_receipt_sha256'],
        'source_inventory_sha256':receipt['native_sdk']['plan']['source_inventory_sha256'],
        'export_inventory_sha256':receipt['native_sdk']['plan']['export_inventory_sha256'],
        'candidate_cache_key':facts['key'],'candidate_provenance_sha256':facts['provenance_sha256'],
        'controller_graph_sha256':receipt['graph_sha256'],'bazel':BAZEL,
        'workload_exit':receipt['workload_exit'],'descendants_empty':receipt['descendants_empty'],
        'source_and_export_verified_after_cleanup':receipt['native_sdk']['source_and_export_verified_after_cleanup']}
    group_pin=sealed_io.artifact_file(Path(run)/'native-qualification.json',deadline,8*1024*1024,json_object=True)
    xml_pin=sealed_io.artifact_file(Path(run)/'native-qualification.xml',deadline,8*1024*1024)
    group=read_json(Path(group_pin['path']),group_pin['sha256'],deadline)
    actual_cli=combined_cli_artifact(context)
    require(group['schema']=='omux-native-grouped-qualification-v1'
        and type(group['passed']) is int and group['passed']==14
        and type(group['failed']) is int and group['failed']==0
        and type(group['ignored']) is int and group['ignored']==0
        and group['native_support'] is False and group['provider_evaluation'] is False
        and group['xml_sha256']==xml_pin['sha256']
        and set(group['targets'])==set(GATES)
        and group['cli_artifact']==actual_cli and group['cli_context']==context,
        'CLI exact grouped qualification or actual ELF differs')
    expected_targets={target:{'log_sha256':row['sha256'],'tests':sorted(GATES[target])}
        for target,row in logs.items()}
    require(group['targets']==expected_targets,
        'CLI qualification logs are not its copied actual named tests')
    xml=ET.Element('testsuites',tests='14',failures='0',errors='0',skipped='0')
    for target,row in sorted(expected_targets.items()):
        suite=ET.SubElement(xml,'testsuite',name=target,tests=str(len(row['tests'])),failures='0',errors='0',skipped='0')
        props=ET.SubElement(suite,'properties')
        ET.SubElement(props,'property',name='actual_test_log_sha256',value=row['log_sha256'])
        for name in row['tests']:ET.SubElement(suite,'testcase',classname=target,name=name)
    require(sha(ET.tostring(xml,encoding='utf-8',xml_declaration=True)+b'\n')==xml_pin['sha256'],
        'CLI qualification XML differs from actual fourteen names/log pins')
    return {'schema_version':1,'kind':KIND,'stage':1,'id':receipt['id'],
        'source_receipt_sha256':context['source_receipt_sha256'],
        'sdk_receipt_sha256':context['export_receipt_sha256'],
        'controller_graph_sha256':receipt['graph_sha256'],
        'artifacts':{'cli':actual_cli,'cli_context':context,'qualification':{
            'manifest':sealed_io.artifact_file(Path(run)/'test-evidence.json',deadline,8*1024*1024,json_object=True),
            'group':group_pin,'xml':xml_pin,'logs':logs}}}


def terminal_receipt(admission,receipt):
    try:
        if type(receipt['exit']) is int and receipt['exit']!=0:
            admission.write_journal('closed',[])
        else:
            require(type(receipt['exit']) is int and receipt['exit']==0, 'CLI terminal literal exit required')
            receipt['native_protocol_history_cli']=admission.facts()
            validate_completed_success(receipt,admission.selection,verify_inputs(admission.args),
                admission.args.native_deadline)
            admission.check_directories();admission.verify_history()
            artifacts=collect_artifacts(admission.run,receipt,admission.args.native_deadline)
            raw=canonical(artifacts)+b'\n';fd=trusted_parent(admission.run)
            try:admission.write_file(fd,ARTIFACTS,raw,0o600)
            finally:os.close(fd)
            admission.artifacts_sha=sha(raw)
            require(read_json(admission.run/ARTIFACTS,admission.artifacts_sha,admission.args.native_deadline)==artifacts
                and collect_artifacts(admission.run,receipt,admission.args.native_deadline)==artifacts,
                'CLI accepted artifacts changed after cleanup')
            receipt['native_protocol_history_cli']=admission.facts()
            raw=json.dumps(receipt,sort_keys=True)+'\n'
            admission.write_journal('closed',[{'stage':1,'id':admission.run.name,
                'sha256':sha(raw.encode()),'artifacts_sha256':admission.artifacts_sha}])
    except (OSError,ValueError,KeyError,TypeError,ET.ParseError):
        receipt['exit']=125
        try:admission.write_journal('closed',[])
        except (OSError,ValueError,KeyError,TypeError):pass
    receipt['native_protocol_history_cli']=admission.facts()
    return json.dumps(receipt,sort_keys=True)+'\n'


def readonly_paths(args,plan):
    selection=completed.validate_selection(read_json(SELECTOR,args.native_protocol_cli_sha256,args.native_deadline))
    first=read_json(STATE/selection['predecessors']['1']['id']/'receipt.json',
        selection['predecessors']['1']['sha256'],args.native_deadline)
    paths=set(native.readonly_paths(args,plan))
    paths.update((str(SELECTOR),str(CHAIN),str(protocol.SELECTOR),str(protocol.CHAIN),
        str(STATE/('protocol-history-checks-'+first['native_protocol_history']['key']))))
    paths.update(str(STATE/row['id']) for row in selection['predecessors'].values())
    require(all(Path(file).is_absolute() and not any(c.isspace() or c in ':\\\\' for c in file)
        for file in paths), 'CLI completed readonly mount pathname refused')
    return sorted(paths)


def verify_readonly(actual, args, plan):
    expected = set(readonly_paths(args, plan))
    observed = set()
    for entry in actual.get('BindReadOnlyPaths', '').split():
        parts = entry.split(':')
        require(1 <= len(parts) <= 3 and parts[0] in expected, 'unexpected native readonly mount')
        require(len(parts) == 1 or parts[1] == parts[0], 'native mount target changed')
        require(len(parts) < 3 or parts[2] in ('', 'rbind'), 'native mount option changed')
        observed.add(parts[0])
    require(observed == expected, 'native readonly mounts unproved')
    writable = actual.get('BindPaths', '').split()
    if plan.get('candidate_output_base') is None:
        require(not writable, 'unexpected writable native mount')
    else:
        require(len(writable) == 1, 'candidate cache requires one writable output base')
        parts = writable[0].split(':')
        require(1 <= len(parts) <= 3 and parts[0] == plan['candidate_output_base']
            and (len(parts) == 1 or parts[1] == parts[0])
            and (len(parts) < 3 or parts[2] in ('', 'rbind')), 'candidate writable mount mismatch')


def recheck_closed_custody(receipt,selection,deadline):
    completed.validate_selection(selection);facts=receipt['native_protocol_history_cli']
    root=STATE/('protocol-history-cli-'+facts['key'])
    files={'chain':CHAIN,'root':root,'lock':root/'lock','output':root/'output-base',
        'input':root/'native-input','source':root/'native-input/source'}
    for name,file in files.items():
        completed.same_custody(file,facts['custody'][name],deadline,directory=name not in ('chain','lock'))
    chain=read_json(CHAIN,facts['chain_sha256'],deadline,8192)
    expected_chain={'schema_version':1,'kind':KIND,'key':facts['key'],
        'selector_sha256':facts['selector_sha256'],'source_commit':selection['inputs']['controller_source_commit'],
        'boot_host':facts['bindings']['boot_host'],
        'original_entry_monotonic_ns':facts['original_entry_monotonic_ns'],
        'original_deadline_monotonic_ns':facts['original_deadline_monotonic_ns']}
    require(canonical(chain)==canonical(expected_chain), 'CLI closed immutable reservation content differs')
    fd=trusted_parent(root)
    try:
        require(set(os.listdir(fd))=={'lock','output-base','native-input',JOURNAL}, 'CLI closed root shape differs')
        journal,_=sealed_io.read_json(fd,JOURNAL,deadline)
    finally:os.close(fd)
    row={'stage':1,'id':receipt['id'],'sha256':sha((json.dumps(receipt,sort_keys=True)+'\n').encode()),
        'artifacts_sha256':facts['artifacts_sha256']}
    require(type(journal) is dict and set(journal)=={
        'schema_version','kind','key','stage','epoch','status','history','custody','chain_sha256'}
        and type(journal['schema_version']) is int and journal['schema_version']==1
        and type(journal['stage']) is int and journal['stage']==1
        and journal['kind']==KIND and journal['key']==facts['key'] and journal['epoch']==receipt['id']
        and journal['status']=='closed' and canonical(journal['history'])==canonical([row])
        and journal['custody']==facts['custody'] and journal['chain_sha256']==facts['chain_sha256'],
        'CLI closed journal needs exactly its actual successful position')
    return True
