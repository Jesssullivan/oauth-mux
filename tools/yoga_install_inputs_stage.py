"""One fixed public archive+receipt transfer; ordinary Yoga modes stay readonly."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shlex
import subprocess
import sys
import time
import uuid
import yoga_install_inputs_receiver as receiver
import yoga_controller_delivery as delivery
import yoga_executable_qualification as qualification
from ssh_policy import operator_config
import guard_resident_owned_update as owned

LABEL = '//tools:yoga_install_inputs_stage'
SOURCE = '7f01be9d8285642cd567644ce4f3ec26bb351a8c'
GRAPH = 'cd89266718df27fd73f352f13aeaa2dd904eb219db3e4c7911b4e448e2c87ef6'
MANIFEST = '15764acc5019ad9b3d1211cf09cf4e416e29c2194c856a43ac6f610e4dfaa75c'
ROOT = Path(receiver.PARENT) / receiver.EPOCH
RESULT = {'scope': receiver.SCOPE, 'phase': 'complete', 'files': 2,
          'bytes': sum(row[1] for row in receiver.FILES), 'receiver_cleanup_verified': True,
          'destination_rehashed': True, 'installation': False, 'ready': False}

def closure(rows):
    """Exact tool roots and complete pinned transitive refs, never any-Nix fallback."""
    by_path = {row['path']: row for row in rows}
    pending = {str(Path(*Path(path).parts[:4])) for path in receiver.TOOLS}
    selected = set()
    while pending:
        path = pending.pop()
        receiver.require(path in by_path and len(selected) <= 472, 'declared-tool-closure-missing')
        if path not in selected:
            selected.add(path)
            pending.update(set(by_path[path]['references']) - selected)
    return [by_path[path] for path in sorted(selected)]

class Source:
    def __init__(self, deadline):
        self.deadline, self.files = deadline, []
        try:
            # Fixed public namespaces are established before PublicFile opens.
            receipt = owned.PublicFile(ROOT / 'receipt.json', deadline, 1024*1024)
            self.files.append(receipt)
            receiver.require(len(receipt.raw) == receiver.FILES[1][1]
                and hashlib.sha256(receipt.raw).hexdigest() == receiver.FILES[1][2], 'original-receipt-pin')
            q = {'path': str(ROOT/'receipt.json'), 'bytes': receiver.FILES[1][1],
                 'sha256': receiver.FILES[1][2], 'source_commit': SOURCE, 'graph_sha256': GRAPH}
            actual = owned.qualification_output(receiver.decode(receipt.raw), q)
            receiver.require(actual == ROOT/'output-base', 'original-output-pointer')
            archive = owned.PublicFile(ROOT/receiver.ARCHIVE, deadline, owned.pack.MAX_BYTES)
            self.files.append(archive)
            receiver.require(len(archive.raw) == receiver.FILES[0][1]
                and hashlib.sha256(archive.raw).hexdigest() == receiver.FILES[0][2], 'original-archive-pin')
            files, _ = owned.pack.archive_contents(archive.raw)
            receiver.require(hashlib.sha256(files['release-manifest.json']).hexdigest() == MANIFEST,
                             'original-manifest-pin')
            manifest = receiver.decode(files['release-manifest.json'])
            receiver.require(manifest['target'] == 'x86_64-linux' and manifest['channel'] == 'release'
                and manifest['distribution'] == 'portable-linux'
                and manifest['provenance'] == {'sourceRevision': None, 'sourceDirty': True},
                'actual-unstamped-manifest')
            self.ordered = [archive.raw, receipt.raw]
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        receiver.tick(self.deadline)
        for value in self.files:
            value.recheck()

    def close(self):
        held, self.files = self.files, []
        failed = False
        for value in reversed(held):
            try:
                value.close()
            except BaseException:
                failed = True
        receiver.require(not failed, 'source-release-incomplete')

class ImmutableTool:
    def __init__(self, path, deadline):
        self.path,self.deadline,self.directory,self.fd=Path(path),deadline,None,None
        try:
            self.directory=receiver.Directory(str(self.path.parent),deadline,immutable_tool=True)
            self.fd=os.open(self.path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,
                            dir_fd=self.directory.fd)
            info=os.fstat(self.fd)
            receiver.require(receiver.stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_mode&0o111 and not info.st_mode&0o222
                    and info.st_nlink>=1 and 0<info.st_size<=64*1024**2,'immutable-tool-custody')
            self.pin=receiver.file_identity(info)
            chunks,total=[],0
            while True:
                receiver.tick(deadline)
                chunk=os.read(self.fd,65536)
                if not chunk:
                    break
                total+=len(chunk)
                receiver.require(total<=info.st_size,'immutable-tool-bound')
                chunks.append(chunk)
            self.raw=b''.join(chunks)
            receiver.require(total==info.st_size,'immutable-tool-size')
            self.recheck()
        except BaseException:
            self.close()
            raise

    def recheck(self):
        self.directory.check()
        receiver.require(self.pin==receiver.file_identity(os.fstat(self.fd))
             ==receiver.file_identity(os.stat(self.path.name,dir_fd=self.directory.fd,
                                              follow_symlinks=False)),'immutable-tool-changed')

    def close(self):
        fd,directory,self.fd,self.directory=self.fd,self.directory,None,None
        failed=False
        if fd is not None:
            try:
                os.close(fd)
            except BaseException:
                failed=True
        if directory is not None:
            try:
                directory.close()
            except BaseException:
                failed=True
        receiver.require(not failed,'immutable-tool-release')

def tool_pins(deadline):
    values = {}
    held = []
    try:
        for path in receiver.TOOLS:
            value = ImmutableTool(path, deadline)
            held.append(value)
            info = os.fstat(value.fd)
            receiver.require(info.st_uid == 0 and info.st_mode & 0o111 and not info.st_mode & 0o222,
                             'declared-tool-executable')
            values[path] = {'sha256': hashlib.sha256(value.raw).hexdigest(), 'bytes': len(value.raw)}
        for value in held:
            value.recheck()
        return values
    finally:
        failed = False
        for value in reversed(held):
            try:
                value.close()
            except BaseException:
                failed = True
        receiver.require(not failed, 'tool-pin-release')

def original_clock():
    entry = int(os.environ['OMUX_YOGA_INSTALL_INPUTS_ENTRY_NS'])
    deadline = int(os.environ['OMUX_YOGA_DELIVERY_DEADLINE_NS'])
    receiver.require(entry > 0 and deadline-entry == receiver.MAX_NS
            and entry <= time.monotonic_ns() < deadline-receiver.RESERVE_NS,
            'original-guard-clock-required')
    receiver.require(os.environ.get('OMUX_YOGA_DELIVERY_MODE') == 'stage-install-inputs',
                     'exact-stage-envelope-required')
    return entry, deadline

def program(source, expected, pins):
    # Fixed authenticated OS bootstrap. It captures the timestamp before Root's
    # reply and checks the genuine OS tuple again. No mutable work precedes the
    # translated-clock and service GO barriers.
    return source + '\n' + '''
def bootstrap():
    initial_seconds=int(sys.argv[1])
    require(5 < initial_seconds <= 1200, 'bootstrap-budget')
    initial_deadline=time.monotonic_ns()+initial_seconds*10**9
    expected=decode(sys.argv[2])
    pins=decode(sys.argv[3])
    qualifier=decode(sys.argv[4])
    observed=subprocess.run(['/usr/bin/python3','-I','-S','-c',qualifier,
         str(min(75,initial_seconds)),canonical(expected).decode(),'null'],
         stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
         timeout=tick(initial_deadline),env={'PATH':'','LANG':'C','LC_ALL':'C',
              'HOME':__import__('pwd').getpwuid(os.getuid()).pw_dir})
    require(observed.returncode == 0 and not observed.stderr and len(observed.stdout)<=8192
            and decode(observed.stdout)==expected, 'authenticated-host-changed')
    remote_timestamp=time.monotonic_ns()
    os.set_blocking(0,False); os.set_blocking(1,False)
    emit(1,{'scope':SCOPE,'phase':'clock','timestamp':remote_timestamp,
            'host':expected},initial_deadline)
    request=line(0,initial_deadline)
    require(type(request) is dict and set(request)=={'token','work_deadline'}, 'clock-frame')
    validate_remote_clock(remote_timestamp,request['work_deadline'])
    coordinator(request['token'],remote_timestamp,request['work_deadline'],
                SOURCE_TEXT,pins)
try:
    bootstrap()
except BaseException:
    sys.exit(125)
''' .replace('SOURCE_TEXT', repr(source))

def transfer(backend, source, receiver_source, pins, entry, deadline):
    receiver.require(type(backend) is delivery.Backend, 'concrete-qualified-transport')
    token = str(uuid.uuid4())
    before = time.monotonic_ns()
    seconds = (deadline-before-receiver.RESERVE_NS)//10**9
    receiver.require(5 < seconds <= 1170, 'original-transfer-budget')
    remote = program(receiver_source, backend.authority['remote'], pins)
    command = 'exec /usr/bin/python3 -I -S -c ' + shlex.quote(remote) + ' ' + str(seconds) + ' ' + \
        shlex.quote(receiver.canonical(backend.authority['remote']).decode()) + ' ' + \
        shlex.quote(receiver.canonical(pins).decode()) + ' ' + shlex.quote(receiver.canonical(qualification.REMOTE_CODE).decode())
    child = None
    failed = False
    try:
        backend.known_hosts.check()
        child = subprocess.Popen([backend.ssh, *backend.known_hosts.options(), *delivery.SSH_OPTIONS,
                                  *backend.options, delivery.HOST, command],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=backend.env)
        for stream in (child.stdin, child.stdout, child.stderr):
            os.set_blocking(stream.fileno(), False)
        work = deadline-receiver.RESERVE_NS
        clock = receiver.line(child.stdout.fileno(), work)
        after = time.monotonic_ns()
        receiver.require(type(clock) is dict and set(clock)=={'scope','phase','timestamp','host'}
                         and clock['scope']==receiver.SCOPE and clock['phase']=='clock'
                         and clock['host']==backend.authority['remote'], 'authenticated-clock-frame')
        cutoff = receiver.freeze_clock(clock['timestamp'], entry, deadline, before, after)
        receiver.emit(child.stdin.fileno(), {'token':token,'work_deadline':cutoff}, work)
        gate = receiver.line(child.stdout.fileno(), work)
        receiver.require(type(gate) is dict and set(gate)=={'scope','phase','token','pid','start','uid',
                            'caps_verified','physical_parent_verified'}
                         and gate['scope']==receiver.SCOPE and gate['phase']=='go-ready' and gate['token']==token
                         and all(type(gate[key]) is int and gate[key]>1 for key in ('pid','start'))
                         and type(gate['uid']) is int and gate['uid']==backend.authority['remote']['uid']
                         and gate['caps_verified'] is True and gate['physical_parent_verified'] is True,
                         'receiver-predata-gate')
        source.check()
        backend.known_hosts.check()
        receiver.emit(child.stdin.fileno(), {'go':token,'scope':receiver.SCOPE}, work)
        for row, raw in zip(receiver.FILES, source.ordered):
            role, count, digest = row
            receiver.emit(child.stdin.fileno(), {'role':role,'bytes':count,'sha256':digest}, work)
            for index in range(0,len(raw),receiver.FRAME):
                receiver.write_all(child.stdin.fileno(), raw[index:index+receiver.FRAME], work)
        receiver.emit(child.stdin.fileno(), {'end':receiver.SCOPE}, work)
        child.stdin.close()
        readback = receiver.line(child.stdout.fileno(), deadline)
        worker_expected = {'scope':receiver.SCOPE,'phase':'worker-readback','files':2,
                          'bytes':sum(row[1] for row in receiver.FILES),'destination_rehashed':True,
                          'installation':False,'ready':False}
        receiver.require(type(readback) is dict and set(readback)==set(worker_expected)
                and readback==worker_expected and type(readback['files']) is type(readback['bytes']) is int
                and all(type(readback[key]) is bool for key in ('destination_rehashed','installation','ready')),
                'closed-workload-readback')
        result = receiver.line(child.stdout.fileno(), deadline)
        expected = dict(RESULT,token=token)
        receiver.require(type(result) is dict and set(result)==set(expected) and result==expected
                and type(result['files']) is type(result['bytes']) is int
                and all(type(result[key]) is bool for key in
                    ('receiver_cleanup_verified','destination_rehashed','installation','ready')),
                'independently-observed-stage-result')
        receiver.require(child.wait(timeout=receiver.tick(deadline))==0
                         and not os.read(child.stderr.fileno(),4096), 'staging-transport-refused')
        source.check()
        receiver.require(backend.qualify()==backend.authority['remote'], 'post-staging-host-changed')
        backend.known_hosts.check()
        return {key:value for key,value in result.items() if key != 'token'}
    finally:
        if child is not None:
            try:
                if child.poll() is None:
                    child.kill()
            except BaseException:
                failed = True
            try:
                child.wait(timeout=receiver.tick(deadline))
            except BaseException:
                failed = True
            for stream in (child.stdin, child.stdout, child.stderr):
                try:
                    stream.close()
                except BaseException:
                    failed = True
        receiver.require(not failed, 'owned-transport-cleanup-incomplete')

def main(argv=None):
    parser=argparse.ArgumentParser()
    for key in ('inventory','receipt','bootstrap-manifest','known-hosts','authority','receiver-source'):
        parser.add_argument('--'+key,required=True)
    args=parser.parse_args(argv)
    entry,deadline=original_clock()
    floating=deadline/10**9
    rows=delivery.selected(delivery.read_public(args.inventory,8*1024**2,floating),
                           delivery.read_public(args.receipt,1024**2,floating))
    bootstrap=delivery.read_public(args.bootstrap_manifest,2*1024**2,floating)
    local=qualification.local_authority(bootstrap,rows,deadline)
    authority=delivery.strict_json(delivery.read_public(args.authority,16384,floating))
    receiver.require(hashlib.sha256(receiver.canonical(authority)).hexdigest()
            == os.environ['OMUX_YOGA_DELIVERY_AUTHORITY_SHA256'], 'guard-qualified-host-authority')
    import yoga_delivery_settings
    yoga_delivery_settings.qualification(authority)
    receiver_source=delivery.read_public(args.receiver_source,256*1024,floating).decode('utf8')
    source=None
    try:
        source=Source(deadline-receiver.RESERVE_NS)
        pins=tool_pins(deadline-receiver.RESERVE_NS)
        with delivery.KnownHostAuthority(args.known_hosts,floating) as known, operator_config(include_user=False) as options:
            # operator_config public fixed policy must supply explicit Yoga user/
            # address; no personal config or agent forwarding is imported.
            options=list(options)+['-oHostname=100.104.152.110','-oUser=jsullivan2',
                                  '-oProxyCommand=none','-oProxyJump=none']
            backend=delivery.Backend(qualification.SSH,options,floating,
                    dict(local,remote=authority['remote']),known)
            backend.env={'HOME':os.environ['HOME'],'SSH_AUTH_SOCK':'/omux-yoga-install-inputs/ssh-agent'}
            receiver.require(backend.qualify()==authority['remote'], 'qualified-host-changed')
            backend.verify(closure(rows))
            result=transfer(backend,source,receiver_source,pins,entry,deadline)
        print(receiver.canonical(result).decode('ascii'))
        return 0
    finally:
        if source is not None:
            source.deadline=deadline
            for value in source.files:
                value.deadline=deadline
            source.close()

if __name__=='__main__':
    try:
        sys.exit(main())
    except BaseException:
        print('yoga-public-input-staging-refused',file=sys.stderr)
        sys.exit(125)
