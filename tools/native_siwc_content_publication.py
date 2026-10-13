"""Fresh epoch SOURCE/HUB delivery; never an extension of action SDK proof.

Only the exact live content dependency lease admits capture after owned terminal
cleanup and uncached successful evidence. Action qualification ends at original
600; this separately named transport observes new bytes/inodes before the same
original outer work cutoff1170. No downstream SDK custody survives extraction.
"""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import sys
import time
import xml.etree.ElementTree as ET
import guard_resident_observation as resident

KIND = 'omux-native-siwc-content-retained-publication-v1'
DIRECTORY = 'native-content-retained'
LEAF = 'native-siwc-catalog-content-source'
RECEIPT = 'publication-receipt.json'
PROFILE = 'native-siwc-catalog-content-source-reserved'
TARGETS = ('//tools:codex_native_siwc_catalog_content_source_test',
    '//tools:codex_native_siwc_catalog_content_source_producer')
FIELDS = ('MODE', 'ENTRY_NS', 'DEADLINE_NS', 'EPOCH', 'SOURCE_COMMIT', 'GRAPH_SHA256')
MAX_METADATA = 8 * 1024 * 1024
MAX_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 8557 + 16 + 1
MAX_FDS = 16384
BLOCK = 65536


def need(value):
    if value is not True: raise ValueError('native content delivery refused')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'


def unique(rows):
    result = {}
    for key, value in rows:
        need(key not in result); result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def digest(value):
    need(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None)
    return value


def witness(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def name(value):
    need(type(value) is str and 0 < len(value.encode()) <= 4096
        and not value.startswith('/') and '\\' not in value
        and all(32 <= ord(char) != 127 for char in value)
        and len(value.split('/')) <= 64
        and all(part not in ('', '.', '..') for part in value.split('/')))
    return value


class Descriptors:
    """Enroll before inspection; detach before every close and drain failures."""
    def __init__(self): self.fds = []; self.closed = False

    def enroll(self, fd):
        try:
            need(not self.closed and len(self.fds) < MAX_FDS)
            self.fds.append(fd)
        except BaseException as error:
            # Interruption may occur after append; detach every occurrence
            # before close so later drain cannot retry an already retired FD.
            if isinstance(self.fds,list):
                while list.__contains__(self.fds,fd):list.remove(self.fds,fd)
            try: os.close(fd)
            except BaseException as cleanup: raise error from cleanup
            raise
        return fd

    def open(self, path, flags, mode=0o777, *, parent=None):
        need(not self.closed and len(self.fds) < MAX_FDS)
        return self.enroll(os.open(path, flags | os.O_CLOEXEC, mode, dir_fd=parent))

    def retire(self, fd):
        self.fds.remove(fd)
        os.close(fd)

    def close(self):
        self.closed = True
        owned, self.fds = self.fds, []
        first = None
        for fd in reversed(owned):
            try: os.close(fd)
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first


class OwnedStream:
    def __init__(self, owner, fd): self.owner,self.fd=owner,fd
    def __enter__(self): return self.fd
    def __exit__(self,kind,error,trace):
        try:self.owner.fds.retire(self.fd)
        except BaseException as cleanup:
            if error is not None:raise BaseException.with_traceback(error,trace) from cleanup
            raise
        return False


class Tree:
    """Retain every parent directory; source regular FDs stream and retire."""
    def __init__(self, owner, path, *, writable=False):
        need(isinstance(path, Path) and path.is_absolute() and str(path) == os.path.normpath(str(path)))
        self.owner, self.path, self.writable = owner, path, writable
        self.chain, self.directories, self.members = [], {}, {}
        fd = owner.fds.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.chain.append(('/', fd, witness(os.fstat(fd))))
        current = Path('/')
        for part in path.parts[1:]:
            owner.tick()
            before = os.stat(part, dir_fd=fd, follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode) and before.st_uid in (0, os.getuid())
                and not stat.S_IMODE(before.st_mode) & 0o022)
            child = owner.fds.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, parent=fd)
            anchor = witness(before)
            need(witness(os.fstat(child)) == anchor == witness(os.stat(part, dir_fd=fd, follow_symlinks=False)))
            current /= part; self.chain.append((str(current), child, anchor)); fd = child
        self.fd = fd
        need(os.fstat(fd).st_uid == os.getuid()
            and stat.S_IMODE(os.fstat(fd).st_mode) == (0o700 if writable else 0o555))
        self.directories[''] = (fd, None if writable else witness(os.fstat(fd)))

    def parent(self, path):
        prefix, _, leaf = path.rpartition('/')
        return self.directories[prefix][0], leaf

    def discover(self, expected):
        need(type(expected) is dict and 0 < len(expected) <= MAX_MEMBERS)
        children = {'': set()}
        for path in expected:
            name(path); pieces = path.split('/')
            for index, piece in enumerate(pieces):
                prefix = '/'.join(pieces[:index])
                if prefix not in children:need(len(children)<MAX_FDS);children[prefix]=set()
                children[prefix].add(piece)
                if index < len(pieces)-1:
                    child='/'.join(pieces[:index+1])
                    if child not in children:need(len(children)<MAX_FDS);children[child]=set()
        for path in sorted(children, key=lambda value:(value.count('/'), value)):
            self.owner.tick()
            if path:
                parent, leaf = self.parent(path)
                before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                need(stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid()
                    and stat.S_IMODE(before.st_mode) == 0o555)
                anchor = witness(before)
                if path in self.directories:
                    fd,original_anchor=self.directories[path]
                    need(original_anchor==anchor and witness(os.fstat(fd))==anchor)
                else:fd = self.owner.fds.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, parent=parent)
                need(witness(os.fstat(fd)) == anchor == witness(os.stat(leaf, dir_fd=parent, follow_symlinks=False)))
                self.directories[path] = (fd, anchor)
            fd = self.directories[path][0]
            need(_names(self.owner,fd,children[path]) == children[path])
        for path, row in expected.items():
            self.owner.tick(); parent, leaf = self.parent(path)
            before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            need(before.st_uid == os.getuid() and before.st_nlink == 1)
            literal = None
            if row['mode'] == '120000':
                need(stat.S_ISLNK(before.st_mode)); literal = os.readlink(leaf, dir_fd=parent)
                need(hashlib.sha256(literal.encode()).hexdigest() == row['sha256'])
                target = posixpath.normpath(posixpath.join(path.rpartition('/')[0], literal))
                need(not literal.startswith('/') and target in expected and expected[target]['mode'] != '120000')
            else:
                need(row['mode'] in ('100644','100755') and stat.S_ISREG(before.st_mode)
                    and stat.S_IMODE(before.st_mode) in ((0o444,0o555) if path=='source-receipt.json'
                        and row['mode']=='100644' else (0o555,))
                    and before.st_size <= MAX_BYTES)
            need(witness(before) == witness(os.stat(leaf, dir_fd=parent, follow_symlinks=False)))
            observed=(witness(before),literal)
            if path in self.members:need(self.members[path]==observed)
            self.members[path] = observed
        self.fence()

    def fence(self):
        self.owner.tick()
        for path, (anchor, literal) in self.members.items():
            parent, leaf = self.parent(path)
            need(witness(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == anchor)
            if literal is not None:
                need(os.readlink(leaf, dir_fd=parent) == literal
                    and witness(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == anchor)
        for path, (fd, anchor) in self.directories.items():
            if anchor is None: continue
            parent, leaf = (self.chain[-2][1], self.path.name) if not path else self.parent(path)
            need(witness(os.fstat(fd)) == anchor == witness(os.stat(leaf, dir_fd=parent, follow_symlinks=False)))
        # Ancestor directory namespace changes from unrelated siblings are not
        # member authority. Keep exact stable inode/owner/mode anchors instead.
        for index, (path, fd, anchor) in enumerate(self.chain):
            now = witness(os.fstat(fd)); need(now[:5] == anchor[:5])
            if index:
                parent = self.chain[index-1][1]
                need(witness(os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False))[:5] == anchor[:5])
        self.owner.tick()

    def read(self, path, row, *, keep=False):
        self.owner.tick(); parent, leaf = self.parent(path); anchor, literal = self.members[path]
        need(literal is None)
        fd = self.owner.fds.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, parent=parent)
        with OwnedStream(self.owner,fd):
            need(witness(os.fstat(fd)) == anchor == witness(os.stat(leaf, dir_fd=parent, follow_symlinks=False)))
            result, total, digestor = [], 0, hashlib.sha256()
            while True:
                self.owner.tick(); block = os.read(fd, BLOCK)
                if not block: break
                total += len(block); need(total <= anchor[6] <= MAX_BYTES)
                digestor.update(block)
                if keep: need(total <= MAX_METADATA); result.append(block)
            need(total == anchor[6] and digestor.hexdigest() == row['sha256']
                and witness(os.fstat(fd)) == anchor == witness(os.stat(leaf, dir_fd=parent, follow_symlinks=False)))
            return b''.join(result) if keep else total

    def full(self, expected):
        total = 0
        for path, row in expected.items():
            total += len(self.members[path][1].encode()) if row['mode'] == '120000' else self.read(path, row)
            need(total <= MAX_BYTES + MAX_METADATA)
        self.fence()


def _names(owner,fd,expected):
    # One library-owned scandir FD is reserved in the same aggregate limit;
    # close its iterator on every refusal. Never allocate an unbounded list.
    owner.tick();need(len(owner.fds.fds)+1<=MAX_FDS)
    result=set()
    with os.scandir(fd) as entries:
        for entry in entries:
            owner.tick();need(len(result)<len(expected) and entry.name in expected and entry.name not in result)
            result.add(entry.name)
    owner.tick();return result


class CapturedPublication:
    """Worker-owned delivery only; copied reports never transfer SDK authority."""
    def __init__(self, context):
        need(type(context) is dict and set(context) == set(FIELDS)
            and all(type(value) is str for value in context.values())
            and context['MODE'] == 'native-file-writer-models-reserved')
        need(all(re.fullmatch(r'[1-9][0-9]{0,18}',context[field]) is not None for field in ('ENTRY_NS','DEADLINE_NS')))
        self.context = dict(context); self.entry = int(context['ENTRY_NS']); self.until = int(context['DEADLINE_NS'])
        self.run = Path(context['EPOCH'])
        need(self.entry > 0 and self.until-self.entry == 1200*10**9
            and self.run.parent in resident.PUBLIC_ROOTS
            and str(self.run) == os.path.normpath(str(self.run))
            and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',self.run.name) is not None
            and re.fullmatch(r'[0-9a-f]{40}', context['SOURCE_COMMIT']) is not None)
        digest(context['GRAPH_SHA256'])
        self.cutoff = self.until-30*10**9
        self.fds, self.trees, self.metadata = Descriptors(), [], []
        self.pid, self.finished, self._record = os.getpid(), False, None
        self.tick()

    def tick(self):
        need(os.getpid() == self.pid and self.entry <= time.monotonic_ns() < self.cutoff)

    def read_metadata(self, path, maximum, pin=None, *, modes=(0o600,)):
        self.tick(); parent = Tree(self,path.parent,writable=stat.S_IMODE(os.stat(path.parent,follow_symlinks=False).st_mode)==0o700)
        parent.directories['']=(parent.fd,witness(os.fstat(parent.fd)))
        fd = self.fds.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,parent=parent.fd)
        before = witness(os.fstat(fd))
        need(stat.S_ISREG(before[4]) and before[2]==os.getuid() and before[5]==1
            and stat.S_IMODE(before[4]) in modes and 0 < before[6] <= maximum
            and witness(os.stat(path.name,dir_fd=parent.fd,follow_symlinks=False))==before)
        chunks=[];count=0
        while True:
            self.tick();block=os.read(fd,min(BLOCK,maximum+1-count))
            if not block: break
            count+=len(block);need(count<=maximum);chunks.append(block)
        raw=b''.join(chunks)
        need(count==before[6] and witness(os.fstat(fd))==before==witness(os.stat(path.name,dir_fd=parent.fd,follow_symlinks=False)))
        if pin is not None: need(hashlib.sha256(raw).hexdigest()==digest(pin))
        self.metadata.append((parent,path.name,fd,before));return raw

    def fence(self):
        self.tick()
        for parent,leaf,fd,anchor in self.metadata:
            parent.fence();need(witness(os.fstat(fd))==anchor==witness(os.stat(leaf,dir_fd=parent.fd,follow_symlinks=False)))
        if hasattr(self,'lease_namespace'):
            self.lease_namespace.fence()
            need(self.marker_raw==self._reread(self.marker_fd,self.marker_anchor))
            need(witness(os.fstat(self.base_fd))==self.base_anchor==witness(os.stat(
                'output-base',dir_fd=self.lease_namespace.fd,follow_symlinks=False)))
            _locked(self.lock_fd)
        # Rejoin every metadata leaf after the last marker read too. These
        # checks perform no additional bulk IO or renewed observation clock.
        for parent,leaf,fd,anchor in self.metadata:
            parent.fence();need(witness(os.fstat(fd))==anchor==witness(os.stat(leaf,dir_fd=parent.fd,follow_symlinks=False)))
        if hasattr(self, 'receipt_fd'):
            need(witness(os.fstat(self.receipt_writer))==self.receipt_anchor
                ==witness(os.fstat(self.receipt_fd)) == witness(os.stat(
                    RECEIPT, dir_fd=self.container.fd, follow_symlinks=False)))
        # Every remaining metadata/marker byte read is complete. The last
        # flat member/parent/root FULL9/literal joins cover all owned trees.
        for tree in self.trees:tree.fence()
        self.tick()

    def _reread(self,fd,anchor):
        need(0<=anchor[6]<=MAX_METADATA and witness(os.fstat(fd))==anchor);parts=[];offset=0
        while offset<anchor[6]:
            self.tick();part=os.pread(fd,min(BLOCK,anchor[6]-offset),offset);need(bool(part));parts.append(part);offset+=len(part)
        need(witness(os.fstat(fd))==anchor);return b''.join(parts)

    def record(self):
        need(self.finished and self._record is not None); self.fence()
        return decode(encoded(self._record))

    def close(self):
        self.finished = False; self._record = None
        self.fds.close()

    def __enter__(self): self.fence(); return self

    def __exit__(self, kind, error, trace):
        try:
            if kind is None: self.fence()
        except BaseException as failure:
            try: self.close()
            except BaseException as cleanup: raise failure from cleanup
            raise
        try: self.close()
        except BaseException as cleanup:
            if error is not None: raise BaseException.with_traceback(error, trace) from cleanup
            raise
        if error is None:self.tick()
        return False


def _members(report, raw):
    need(type(report) is dict and report['kind'] == 'omux-native-siwc-catalog-content-source-v1'
        and report['status'] == 'verified-siwc-catalog-content-source-uncompiled'
        and type(report['source_bytes']) is int and 0<report['source_bytes']<=MAX_BYTES
        and report['tracked_files'] == 8557 and len(report['patch_sha256']) == 12
        and report['historical_ancestor_reexecution'] is False and report['native_runtime_qualified'] is False
        and report['physical_mode_policy']=='bazel-retained-export-all-regular-and-directories-0555-v1')
    inventory, hub = report['source_inventory'], report['generated_hub']
    need(type(inventory) is dict and len(inventory) == 8557
        and type(hub) is dict and 0 < len(hub) <= 16 and {'BUILD.bazel', 'defs.bzl', 'data.bzl'} <= set(hub))
    # Exact source.canonical uses sorted keys with default json separators.
    need(hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest() == report['inventory_sha256'])
    expected = {}
    for path, row in inventory.items():
        name(path); need(type(row) is dict and set(row) == {'mode', 'sha256'}
            and row['mode'] in ('100644', '100755', '120000')); digest(row['sha256'])
        expected['source/'+path] = dict(row)
    for path, row in hub.items():
        name(path); need('/' not in path and type(row) is dict and set(row) == {'sha256', 'bytes'}
            and type(row['bytes']) is int and 0 < row['bytes'] <= MAX_METADATA); digest(row['sha256'])
        expected['hub/source/'+path] = {'mode':'100644', 'sha256':row['sha256']}
    expected['source-receipt.json'] = {'mode':'100644', 'sha256':hashlib.sha256(raw).hexdigest()}
    return expected


def _source_phase(owner, request):
    phase_raw=owner.read_metadata(owner.run/'source-phase-receipt.json',MAX_METADATA,request['source_phase_receipt_sha256'],modes=(0o400,0o600))
    phase=decode(phase_raw)
    need(type(phase) is dict and set(phase)=={'schema_version','kind','id','profile','targets',
        'source_commit','graph_sha256','context','clocks','exit','workload_exit','epoch_start_ns',
        'output_base','cache_reuse_requested','cache_policy','cache_key','dependency_lease','command',
        'limits','worker','cleanup','descendants_empty','test_evidence',
        'native_siwc_catalog_content_source_reservation'}
        and type(phase['epoch_start_ns']) is int and phase['epoch_start_ns']>0
        and type(phase['schema_version']) is int and phase['schema_version']==1 and phase['kind']=='omux-native-siwc-content-source-phase-v1'
        and phase['id']==owner.run.name and phase['profile']==PROFILE and phase['targets']==list(TARGETS)
        and phase['context']==owner.context and phase['clocks']==request['clocks']
        and type(phase['exit']) is int and type(phase['workload_exit']) is int
        and phase['exit']==phase['workload_exit']==0 and phase['source_commit']==owner.context['SOURCE_COMMIT']
        and phase['graph_sha256']==owner.context['GRAPH_SHA256'] and phase['descendants_empty'] is True
        and phase['cleanup']['state']=='empty' and phase['cleanup']['ownership']=='verified'
        and type(phase['cleanup']['readback_attempts']) is int and 2<=phase['cleanup']['readback_attempts']<=8
        and phase['cache_reuse_requested'] is True
        and phase['cache_policy']==2 and phase['cache_key']==request['dependency_lease']['key']
        and phase['dependency_lease']==request['dependency_lease'] and phase['output_base']==request['dependency_lease']['output_base'])
    proof=phase['native_siwc_catalog_content_source_reservation']
    need(proof['scope']=='fixed-native-siwc-catalog-content-source-reserved-v1'
        and proof['verified_after_cleanup'] is True and proof['original_entry_monotonic_ns']==owner.entry
        and proof['original_deadline_monotonic_ns']==owner.until and proof['action_cap_seconds']==840)
    # Kernel/process facts in phase1 are historical coordinator observations.
    # Delivery gets its own actual bounded worker and separately checked cleanup.
    need(type(phase['worker']) is dict and set(phase['worker'])=={'unit','invocation','pid','start_ticks','cgroup','kernel_bounds'})
    return phase,phase_raw


def _evidence(owner, request, phase):
    need(phase['test_evidence']['state']=='preserved' and phase['test_evidence']['manifest']=='test-evidence.json'
        and phase['test_evidence']['sha256']==request['test_evidence_sha256'])
    raw=owner.read_metadata(owner.run/'test-evidence.json',MAX_METADATA,request['test_evidence_sha256'])
    value=decode(raw)
    need(type(value['schema']) is int and value['schema']==1 and type(value['bazel_exit']) is int and value['bazel_exit']==0 and value['targets']==list(TARGETS)
        and value['epoch_start_ns']==phase['epoch_start_ns'] and type(value['results']) is list
        and [row['target'] for row in value['results']]==list(TARGETS)
        and all(row['state']=='observed' and row['configuration']==request['configuration'] for row in value['results']))
    for result in value['results']:
        for kind in ('test.log','test.xml'):
            entries=[row for row in result['files'] if row['source']==kind]
            need(len(entries)==1 and entries[0]['state']=='copied')
            row=entries[0];need(row['file']==hashlib.sha256((result['target']+'\0'+request['configuration']+'\0'+kind).encode()).hexdigest()+'.evidence')
            copied=owner.read_metadata(owner.run/'test-evidence'/row['file'],MAX_METADATA,row['sha256'])
            need(len(copied)==row['bytes'] and bool(copied))
            if kind=='test.xml':
                _xml_success(copied)
    return value


def _xml_success(raw):
    need(type(raw) is bytes and 0<len(raw)<=1024*1024)
    xml=ET.fromstring(raw)
    need(xml.tag in ('testsuite','testsuites'))
    nodes=0;suites=[]
    for node in xml.iter():
        nodes+=1;need(nodes<=4096 and node.tag not in ('failure','error','skipped'))
        if node.tag in ('testsuites','testsuite'):
            for field in ('errors','failures','skipped','disabled'):
                value=node.get(field,'0');need(re.fullmatch(r'[0-9]{1,9}',value) is not None and int(value)==0)
        if node.tag=='testsuite':
            value=node.get('tests','0');need(re.fullmatch(r'[0-9]{1,9}',value) is not None and int(value)>0);suites.append(node)
    need(bool(suites))


def _lease_view(owner, facts):
    required={'kind','key','namespace','output_base','run_id','checkout','source_commit','graph_sha256','entry_monotonic_ns','deadline_monotonic_ns'}
    need(type(facts) is dict and set(facts)==required and facts['kind']=='omux-native-siwc-content-dependency-lease-v1'
        and facts['run_id']==owner.run.name and facts['source_commit']==owner.context['SOURCE_COMMIT']
        and facts['graph_sha256']==owner.context['GRAPH_SHA256'] and facts['entry_monotonic_ns']==owner.entry
        and facts['deadline_monotonic_ns']==owner.until)
    key=digest(facts['key']);namespace=owner.run.parent/('cache-v2-'+key)
    need(facts['namespace']==namespace.name and facts['output_base']==str(namespace/'output-base'))
    owner.lease_namespace=Tree(owner,namespace,writable=True)
    marker=owner.read_metadata(namespace/'owner.json',4096,modes=(0o600,))
    row=decode(marker)
    need(row=={'schema':2,'key':key,'clean':False,'last_run':owner.run.name,'cleanup_receipt_sha256':None})
    unused,unused,owner.marker_fd,owner.marker_anchor=owner.metadata[-1];owner.marker_raw=marker
    lock=owner.fds.open('cache.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,parent=owner.lease_namespace.fd)
    lock_anchor=witness(os.fstat(lock))
    need(stat.S_ISREG(lock_anchor[4]) and lock_anchor[2]==os.getuid() and lock_anchor[5]==1
        and stat.S_IMODE(lock_anchor[4])==0o600 and lock_anchor[6]==0
        and lock_anchor==witness(os.stat('cache.lock',dir_fd=owner.lease_namespace.fd,follow_symlinks=False)))
    owner.metadata.append((owner.lease_namespace,'cache.lock',lock,lock_anchor))
    owner.lock_fd=lock
    owner.base_fd=owner.fds.open('output-base',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,parent=owner.lease_namespace.fd)
    owner.base_anchor=witness(os.fstat(owner.base_fd))
    need(owner.base_anchor[2]==os.getuid() and not stat.S_IMODE(owner.base_anchor[4])&0o022
        and owner.base_anchor==witness(os.stat('output-base',dir_fd=owner.lease_namespace.fd,follow_symlinks=False)))
    # Parent retains the actual exclusive lease throughout this worker. Lock
    # absence cannot be replaced by a dirty-marker dictionary. This proves
    # exclusion is live, not the identity of its holder; parent ownership is
    # separately observed by the actual coordinator/final outer authority.
    _locked(lock)
    return Path(facts['output_base'])


def _locked(lock):
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:pass
    else:
        fcntl.flock(lock,fcntl.LOCK_UN)
        need(False)


def _copy(owner, original, destination, expected):
    paths={''}
    for path in expected:
        pieces=path.split('/')
        for index in range(1,len(pieces)):
            path_prefix='/'.join(pieces[:index])
            if path_prefix not in paths:need(len(paths)<MAX_FDS);paths.add(path_prefix)
    for path in sorted(paths,key=lambda value:(value.count('/'),value)):
        if not path:continue
        owner.tick();parent,leaf=destination.parent(path)
        os.mkdir(leaf,0o700,dir_fd=parent)
        fd=owner.fds.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,parent=parent)
        need(witness(os.fstat(fd))==witness(os.stat(leaf,dir_fd=parent,follow_symlinks=False)))
        destination.directories[path]=(fd,None)
    total=0;created={}
    for path,row in expected.items():
        owner.tick();anchor,literal=original.members[path]
        parent,leaf=original.parent(path);outparent,outleaf=destination.parent(path)
        if literal is not None:
            need(witness(os.stat(leaf,dir_fd=parent,follow_symlinks=False))==anchor
                and os.readlink(leaf,dir_fd=parent)==literal)
            os.symlink(literal,outleaf,dir_fd=outparent)
            selected=witness(os.stat(outleaf,dir_fd=outparent,follow_symlinks=False))
            need(os.readlink(outleaf,dir_fd=outparent)==literal
                and selected==witness(os.stat(outleaf,dir_fd=outparent,follow_symlinks=False)))
            created[path]=(selected,literal);total+=len(literal.encode());continue
        source=owner.fds.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,parent=parent)
        target=owner.fds.open(outleaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,parent=outparent)
        error=None;trace=None
        try:
            need(witness(os.fstat(source))==anchor==witness(os.stat(leaf,dir_fd=parent,follow_symlinks=False)))
            count=0;h=hashlib.sha256()
            while True:
                owner.tick();block=os.read(source,BLOCK)
                if not block:break
                count+=len(block);total+=len(block);need(count<=anchor[6] and total<=MAX_BYTES+MAX_METADATA);h.update(block)
                view=memoryview(block)
                while view:
                    owner.tick();written=os.write(target,view);need(written>0);view=view[written:]
            need(count==anchor[6] and h.hexdigest()==row['sha256']
                and witness(os.fstat(source))==anchor==witness(os.stat(leaf,dir_fd=parent,follow_symlinks=False)))
            os.fchmod(target,stat.S_IMODE(anchor[4]));os.fsync(target)
            selected=witness(os.fstat(target))
            need(selected==witness(os.stat(outleaf,dir_fd=outparent,follow_symlinks=False)))
            created[path]=(selected,None)
        except BaseException as failure:error=failure;trace=BaseException.__traceback__.__get__(failure)
        first=None
        for fd in (target,source):
            try:owner.fds.retire(fd)
            except BaseException as failure:
                if first is None:first=failure
        if error is not None:
            if first is not None:raise BaseException.with_traceback(error,trace) from first
            raise BaseException.with_traceback(error,trace)
        if first is not None:raise first
    for path,(fd,unused) in sorted(destination.directories.items(),key=lambda row:row[0].count('/'),reverse=True):
        owner.tick();before=witness(os.fstat(fd))
        parent,leaf=(destination.chain[-2][1],destination.path.name) if not path else destination.parent(path)
        need(before==witness(os.stat(leaf,dir_fd=parent,follow_symlinks=False)))
        os.fchmod(fd,0o555);os.fsync(fd);after=witness(os.fstat(fd))
        need(after[:4]==before[:4] and after[5:8]==before[5:8]
            and stat.S_IMODE(after[4])==0o555
            and after==witness(os.stat(leaf,dir_fd=parent,follow_symlinks=False)))
        destination.directories[path]=(fd,after)
    path,fd,unused=destination.chain[-1];destination.chain[-1]=(path,fd,witness(os.fstat(fd)))
    destination.members=dict(created)
    destination.discover(expected)
    need(destination.members==created)
    original.full(expected);destination.full(expected);original.fence();destination.fence()


def capture(request_path, request_pin, context):
    owner=CapturedPublication(context)
    try:
        need(request_path==owner.run/'native-content-delivery-request.json')
        request_raw=owner.read_metadata(request_path,MAX_METADATA,digest(request_pin),modes=(0o400,))
        request=decode(request_raw)
        need(type(request) is dict and set(request)=={'schema_version','kind','context','clocks','dependency_lease',
            'source_phase_receipt_sha256','test_evidence_sha256','configuration'}
            and type(request['schema_version']) is int and request['schema_version']==1 and request['kind']=='omux-native-siwc-content-delivery-request-v1'
            and request['context']==owner.context and request['clocks']=={'source_until_ns':owner.entry+600*10**9,
                'work_until_ns':owner.cutoff,'outer_until_ns':owner.until}
            and type(request['configuration']) is str and re.fullmatch(r'[A-Za-z0-9_.-]+',request['configuration']) is not None)
        phase,phase_raw=_source_phase(owner,request);evidence=_evidence(owner,request,phase)
        base=_lease_view(owner,request['dependency_lease'])
        source_root=base/'execroot/_main/bazel-out'/request['configuration']/'testlogs/tools'/TARGETS[1].split(':')[1]/'test.outputs'/LEAF
        original=Tree(owner,source_root);owner.trees.append(original)
        fd=owner.fds.open('source-receipt.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,parent=original.fd)
        with OwnedStream(owner,fd):
            anchor=witness(os.fstat(fd));need(stat.S_ISREG(anchor[4]) and anchor[2]==os.getuid() and anchor[5]==1
                and stat.S_IMODE(anchor[4]) in (0o444,0o555) and 0<anchor[6]<=MAX_METADATA
                and anchor[7]>=phase['epoch_start_ns'])
            raw=owner._reread(fd,anchor)
            need(witness(os.stat('source-receipt.json',dir_fd=original.fd,follow_symlinks=False))==anchor)
        report=decode(raw);expected=_members(report,raw)
        need(report['producer_context']=={'mode':owner.context['MODE'],'epoch':str(owner.run),
            'source_commit':owner.context['SOURCE_COMMIT'],'graph_sha256':owner.context['GRAPH_SHA256'],
            'entry_monotonic_ns':owner.entry,'deadline_monotonic_ns':owner.until})
        original.discover(expected)
        source_count=sum(anchor[6] for path,(anchor,literal) in original.members.items() if path.startswith('source/'))
        need(source_count==report['source_bytes'])
        for path,row in report['generated_hub'].items():need(original.members['hub/source/'+path][0][6]==row['bytes'])
        original.full(expected)
        parent=Tree(owner,owner.run,writable=True)
        # Coordinator preallocated this single empty private container before
        # checkpoint handoff. Creating it now would change the held request's
        # parent namespace; no parent-witness exception is permitted.
        owner.container=Tree(owner,owner.run/DIRECTORY,writable=True)
        need(not _names(owner,owner.container.fd,set()) and os.fstat(owner.container.fd).st_nlink==2)
        os.mkdir(LEAF,0o700,dir_fd=owner.container.fd)
        fresh=Tree(owner,owner.run/DIRECTORY/LEAF,writable=True);owner.trees.append(fresh)
        _copy(owner,original,fresh,expected)
        members={path:{**row,'bytes':fresh.members[path][0][6],
            'physical_mode':stat.S_IMODE(fresh.members[path][0][4]),
            **({'literal':fresh.members[path][1]} if row['mode']=='120000' else {})} for path,row in expected.items()}
        receipt={'schema_version':1,'kind':KIND,'scope':'operational-fresh-source-hub-delivery-only',
            'context':owner.context,'clocks':request['clocks'],'dependency_lease':request['dependency_lease'],
            'source_phase_receipt_sha256':request['source_phase_receipt_sha256'],
            'test_evidence_sha256':request['test_evidence_sha256'],
            'original_action':{'root':str(source_root),'source_receipt_sha256':hashlib.sha256(raw).hexdigest(),
                'source_receipt_bytes':len(raw),'inventory_sha256':report['inventory_sha256']},
            'publication':{'root':str(fresh.path),'members':members,'source_bytes':report['source_bytes'],
                'fresh_witnesses_sha256':hashlib.sha256(encoded({path:list(row[0]) for path,row in fresh.members.items()})).hexdigest()},
            'original_action_sdk_custody_inherited':False,'source_qualification_extended':False,
            'sdk_execution_qualified':False,'compiler_qualified':False,'native_runtime_qualified':False,
            'ordinary_launch_qualified':False,'continuity_qualified':False}
        receipt_raw=encoded(receipt);need(len(receipt_raw)<=MAX_METADATA)
        _publish_receipt(owner,receipt_raw)
        _seal_container(owner,fresh)
        os.fsync(parent.fd)
        owner.trees.append(owner.container)
        original.full(expected);fresh.full(expected);owner.fence()
        owner._record={'kind':KIND,'root':str(fresh.path),'transport_receipt':{
            'path':str(owner.run/DIRECTORY/RECEIPT),'sha256':hashlib.sha256(receipt_raw).hexdigest(),'bytes':len(receipt_raw)},
            'source_receipt':{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'inventory_sha256':report['inventory_sha256']},
            'context':owner.context,'source_phase_receipt_sha256':request['source_phase_receipt_sha256'],
            'test_evidence_sha256':request['test_evidence_sha256'],'original_action_sdk_custody_inherited':False}
        owner.finished=True;return owner
    except BaseException as error:
        try:owner.close()
        except BaseException as cleanup:raise error from cleanup
        raise



def _seal_container(owner,fresh):
    # Only this worker-created publication namespace has an authenticated
    # writable-to-readonly transition. Rejoin the exact two names and the
    # held creator before sealing, then update its known descendant anchor.
    container=owner.container
    need(container.path==owner.run/DIRECTORY and fresh.path==container.path/LEAF)
    before=witness(os.fstat(container.fd))
    need(stat.S_IMODE(before[4])==0o700 and before[2]==os.getuid()
        and before==witness(os.stat(DIRECTORY,dir_fd=container.chain[-2][1],follow_symlinks=False))
        and _names(owner,container.fd,{LEAF,RECEIPT})=={LEAF,RECEIPT})
    old_path,old_fd,old_anchor=fresh.chain[-2]
    need(old_path==str(container.path) and witness(os.fstat(old_fd))==before
        and old_anchor[:5]==before[:5])
    os.fchmod(container.fd,0o555);os.fsync(container.fd)
    after=witness(os.fstat(container.fd))
    need(after[:4]==before[:4] and after[5:8]==before[5:8]
        and stat.S_IMODE(after[4])==0o555
        and after==witness(os.stat(DIRECTORY,dir_fd=container.chain[-2][1],follow_symlinks=False))
        and _names(owner,container.fd,{LEAF,RECEIPT})=={LEAF,RECEIPT})
    container.directories['']=(container.fd,after)
    path,fd,unused=container.chain[-1];container.chain[-1]=(path,fd,after)
    fresh.chain[-2]=(old_path,old_fd,after)
    fresh.fence();container.fence();owner.tick()


def _publish_receipt(owner,receipt_raw):
    need(type(receipt_raw) is bytes and 0<len(receipt_raw)<=MAX_METADATA
        and owner.container.path==owner.run/DIRECTORY)
    writer=owner.fds.open(RECEIPT,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,parent=owner.container.fd)
    remaining=memoryview(receipt_raw)
    while remaining:
        owner.tick();written=os.write(writer,remaining);need(written>0);remaining=remaining[written:]
    os.fchmod(writer,0o444);os.fsync(writer)
    owner.receipt_writer=writer;owner.receipt_anchor=witness(os.fstat(writer))
    need(stat.S_ISREG(owner.receipt_anchor[4]) and owner.receipt_anchor[2]==os.getuid()
        and owner.receipt_anchor[5]==1 and stat.S_IMODE(owner.receipt_anchor[4])==0o444
        and owner.receipt_anchor[6]==len(receipt_raw)<=MAX_METADATA
        and owner.receipt_anchor==witness(os.stat(RECEIPT,dir_fd=owner.container.fd,follow_symlinks=False)))
    owner.receipt_fd=owner.fds.open(RECEIPT,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,parent=owner.container.fd)
    need(witness(os.fstat(owner.receipt_fd))==owner.receipt_anchor
        ==witness(os.stat(RECEIPT,dir_fd=owner.container.fd,follow_symlinks=False)))
    need(owner._reread(owner.receipt_fd,owner.receipt_anchor)==receipt_raw)

def main():
    need(sys.argv==[sys.argv[0]] and os.environ.get('TEST_TIMEOUT')
        and 1<=int(os.environ['TEST_TIMEOUT'])<=840)
    context={field:os.environ.get('OMUX_NATIVE_FILE_WRITER_MODELS_'+field) for field in FIELDS}
    request=Path(os.environ['OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST'])
    with capture(request,os.environ['OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST_SHA256'],context) as owner:
        owner.record();owner.fence()
    owner.tick()
    print('native content delivery: complete fresh epoch SOURCE/HUB custody; action SDK authority not inherited',flush=True)
    owner.tick()


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError,UnicodeError,IndexError,MemoryError,ET.ParseError):
        print('native content delivery refused',file=sys.stderr);raise SystemExit(1) from None
