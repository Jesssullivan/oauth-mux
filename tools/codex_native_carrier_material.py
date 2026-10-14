"""Carrier-v2 selected authority and one workload-local fully verified extraction.

Original SOURCE proofs remain original. SDK projection digests are distinct from
historical physical SDK inventories. Installed retained proof is not extraction.
"""
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
import copy
import json
import os
from pathlib import Path
import re
import stat
import time

import codex_native_sdk_carrier as carrier
import codex_native_carrier_metadata as metadata
import codex_native_acquisition_binding as binding
import codex_native_acquisition_material as legacy
import codex_protocol_history_native as protocol
import codex_protocol_history_query_tools as query_tools
import codex_retained_sdk_export as sdk

source = binding.source
require = legacy.require
KIND = 'omux-native-carrier-native-selection-v2'
PACKAGE_KIND = 'omux-native-carrier-native-package-selection-v2'
SDK_KIND = 'omux-native-carrier-sdk-projection-v2'
CORE_KIND = 'omux-native-carrier-sdk-authority-core-v2'
CONFIG_KIND = 'omux-native-carrier-material-config-v2'
CONFIG = 'integrations/codex-upstream/native-carrier-material-inputs.json'
REPOSITORY = 'omux_native_carrier_material_inputs'
METADATA_REPOSITORY = 'omux_native_carrier_metadata_inputs'
DECLARED_KIND = 'omux-native-carrier-declared-inputs-v2'
SDK_TARGET = '//tools:codex_native_carrier_sdk_export_producer'
METADATA_TARGET = '//tools:codex_native_carrier_metadata_producer'
SDK_PROFILE = 'native-sdk-carrier-sdk-export-reserved'
FAMILY = 'native-carrier-acquisition-evaluation-v2'
CORE_KEYS = {'schema_version','kind','source','original_selection','carrier_files','seal','metadata',
             'hub_inventory_sha256','graph_inventory_sha256'}
FALSE_FLAGS = ('compiler_qualified','native_compile_passed','runtime_qualified',
    'installed_package_primary_qualified','schema_producer_qualified','native_support',
    'provider_evaluation','credential_acquisition_qualified','live_handoff_proven','source_witnesses_replaced')
SDK_KEYS = CORE_KEYS - {'kind'} | {'kind','status','authority_sha256','inventory_sha256','hub_files',
    'graph_files','mapping_sha256','patch_sha256','sdk_export_qualified','source_and_carrier_rechecked', *FALSE_FLAGS}
_SCOPE = legacy.CARRIER_SESSION
MAX_DOCUMENT = 16 * 1024 * 1024


def tick(deadline):
    require(type(deadline) is float and time.monotonic() < deadline)


def member(row, maximum=MAX_DOCUMENT):
    require(type(row) is dict and set(row) == {'path','sha256','bytes'})
    protocol.path(row['path']); protocol.pin(row['sha256'])
    require(type(row['bytes']) is int and 0 < row['bytes'] <= maximum)
    return row


def source_row(row):
    require(type(row) is dict and set(row) == {'root','receipt_sha256','inventory_sha256','producer'})
    legacy.role_root('source',row['root'])
    protocol.pin(row['receipt_sha256']); protocol.pin(row['inventory_sha256'])
    protocol.producer_pin(row['producer'])


def program(row):
    require(type(row) is dict and set(row) == {'producer','program'})
    protocol.producer_pin(row['producer']); member(row['program'])


def file_tuple(rows):
    require(type(rows) is list and len(rows) == len(carrier.FILES))
    for name,row in zip(carrier.FILES,rows):
        require(type(row) is dict and set(row) == {'name','sha256','bytes'} and row['name'] == name
            and type(row['bytes']) is int and 0 < row['bytes'] <= carrier.MAX_BYTES)
        protocol.pin(row['sha256'])
    return rows


def member_map(rows):
    require(type(rows) is dict and 0 < len(rows) <= 4096)
    for name,row in rows.items():
        carrier.relative(name)
        require(type(row) is dict and set(row) == {'sha256','bytes','mode'}
            and type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_DOCUMENT
            and row['mode'] in ('100644','100755'))
        protocol.pin(row['sha256'])
    return rows


def core(value):
    require(type(value) is dict and set(value) == CORE_KEYS and type(value['schema_version']) is int
        and value['schema_version'] == 2 and value['kind'] == CORE_KIND)
    source_row(value['source']); file_tuple(value['carrier_files'])
    require(value['original_selection'] == binding.selected_document()
        and value['source'] == binding.config()['source'])
    for role in ('seal','metadata'): program(value[role])
    for role in ('hub_inventory_sha256','graph_inventory_sha256'): protocol.pin(value[role])
    return value


def report_shape(value, authority_raw):
    require(type(value) is dict and set(value) == SDK_KEYS and type(value['schema_version']) is int
        and value['schema_version'] == 2 and value['kind'] == SDK_KIND
        and value['status'] == 'verified-carrier-sdk-projection-with-fresh-custody'
        and value['sdk_export_qualified'] is True and value['source_and_carrier_rechecked'] is True
        and all(value[key] is False for key in FALSE_FLAGS))
    require(type(authority_raw) is bytes and 0 < len(authority_raw) <= MAX_DOCUMENT)
    authority = core(json.loads(authority_raw,object_pairs_hook=source.unique))
    require(carrier.encoded(authority) == authority_raw
        and value['authority_sha256'] == value['inventory_sha256'] == source.sha(authority_raw))
    for key in CORE_KEYS - {'kind'}: require(value[key] == authority[key])
    for name in ('hub','graph'):
        rows = member_map(value[name + '_files'])
        require(source.sha(carrier.encoded(rows)) == value[name + '_inventory_sha256'])
    require(set(value['graph_files']) == set(sdk.GRAPH)
        and value['mapping_sha256'] == value['graph_files']['MODULE.bazel.lock']['sha256']
        and type(value['patch_sha256']) is list and len(value['patch_sha256']) == 9)
    for pin in value['patch_sha256']: protocol.pin(pin)
    return authority


def validate_selection(value):
    require(type(value) is dict and set(value) == {'schema_version','kind','source','sdk',
        'controller_source_commit','controller_graph_sha256'} and type(value['schema_version']) is int
        and value['schema_version'] == 2 and value['kind'] == KIND)
    source_row(value['source'])
    row = value['sdk']
    require(type(row) is dict and set(row) == {'root','receipt_sha256','inventory_sha256','producer'})
    protocol.path(row['root']); protocol.pin(row['receipt_sha256']); protocol.pin(row['inventory_sha256'])
    protocol.producer_pin(row['producer'])
    require(value['controller_source_commit'] == row['producer']['source_commit']
        and value['controller_graph_sha256'] == row['producer']['graph_sha256'])
    return value


def config(raw=None):
    raw = binding.ninth.parent.declared(CONFIG,65536) if raw is None else raw
    require(type(raw) is bytes and 0 < len(raw) <= 65536)
    value = json.loads(raw,object_pairs_hook=source.unique)
    require(type(value) is dict and set(value) == {'schema_version','kind','status','metadata','selection','compile'}
        and type(value['schema_version']) is int and value['schema_version'] == 2 and value['kind'] == CONFIG_KIND
        and value['status'] in ('awaiting-qualified-carrier-route','actual-qualified-carrier-route-selected'))
    if value['status'] == 'awaiting-qualified-carrier-route':
        require(value['metadata'] is None and value['selection'] is None and value['compile'] is None)
    else:
        program(value['metadata'])
        if value['selection'] is not None: validate_selection(value['selection'])
        if value['compile'] is not None:
            row = value['compile']
            require(type(row) is dict and set(row) == {'selection','result'})
            member(row['selection'],1024*1024)
            if row['result'] is not None:
                require(type(row['result']) is dict and set(row['result']) == {'path','sha256','bytes','producer'})
                member({name:row['result'][name] for name in ('path','sha256','bytes')})
                protocol.producer_pin(row['result']['producer'])
    return copy.deepcopy(value),source.sha(raw)


class DeclaredRoot(carrier.Root):
    """Generated repository controls can have0755 parents, unlike sealed SDK roots.

    This independent role retains the same full nofollow ancestry/name/FD joins.
    It does not loosen carrier.Root or admit group/other-writable directories.
    """
    def __init__(self,path,clock):
        self.path,self.clock,self.chain = carrier.absolute(path),clock,[]
        self.named,self.leaves,self.owned,self.origin_jdk = {},{},False,False
        try:
            fd = os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.chain.append((None,fd,carrier.identity(os.fstat(fd),True)))
            for part in self.path.parts[1:]:
                clock.tick(); before = os.stat(part,dir_fd=fd,follow_symlinks=False)
                require(stat.S_ISDIR(before.st_mode))
                child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                try:
                    held = os.fstat(child)
                    require(carrier.identity(before,True) == carrier.identity(held,True) == carrier.identity(
                        os.stat(part,dir_fd=fd,follow_symlinks=False),True)
                        and held.st_uid in (0,os.getuid())
                        and (not held.st_mode & 0o022 or bool(held.st_mode & stat.S_ISVTX)))
                except BaseException:
                    os.close(child); raise
                self.chain.append((part,child,carrier.identity(held,True))); fd = child
            require(os.fstat(fd).st_uid == os.getuid()
                and stat.S_IMODE(os.fstat(fd).st_mode) in (0o555,0o700,0o755))
            self.check()
        except BaseException:
            self.close(); raise


class SelectorReadback:
    """Caller-owned selector FDs can outlive the workload's extraction Session.

    The two raw authorities and absolute proof cutoff are captured by the
    admitted Session. This capability never creates another proof phase.
    """
    def __init__(self,raws,deadline,until_ns):
        require(type(raws) is tuple and len(raws) == 2 and type(until_ns) is int
            and deadline == float(until_ns / 10**9))
        self.clock = carrier.Clock(deadline); self.stack = ExitStack(); self.closed = False
        self.clock.until_ns = until_ns
        self.rows = []; self.parents = {}
        try:
            for name,raw,maximum in zip((CONFIG,metadata.CONFIG),raws,(65536,16384)):
                self.clock.tick()
                require(type(raw) is bytes and 0 < len(raw) <= maximum)
                alias = binding.ninth.parent.ROOT / name
                path = alias.resolve(strict=True)
                if path.parent not in self.parents:
                    self.parents[path.parent] = self.stack.enter_context(DeclaredRoot(path.parent,self.clock))
                root = self.parents[path.parent]
                fd,witness = root.open(path.name)
                self.stack.callback(os.close,fd)
                require(stat.S_IMODE(witness[4]) in (0o444,0o555,0o644))
                self.rows.append((alias,path,root,fd,witness,raw,maximum))
            self.check()
        except BaseException:
            self.close(); raise

    def check(self):
        require(not self.closed); self.clock.tick()
        for alias,path,root,fd,witness,raw,maximum in self.rows:
            self.clock.tick()
            require(alias.resolve(strict=True) == path and carrier.identity(os.fstat(fd)) == witness)
            require(carrier.read(root,path.name,maximum,source.sha(raw)) == raw)
        for alias,path,root,fd,witness,_,_ in self.rows:
            self.clock.tick(); root.check()
            require(alias.resolve(strict=True) == path and carrier.identity(os.fstat(fd)) == witness
                == carrier.identity(os.stat(path.name,dir_fd=root.fd,follow_symlinks=False)))
        self.clock.tick()

    def close(self):
        if not self.closed:
            self.closed = True; self.stack.close()
    def __enter__(self):
        require(not self.closed); return self
    def __exit__(self,*_): self.close()


class DeclaredInputs:
    """Exact declared aliases, held physical parents, and per-read pinned custody."""
    def __init__(self,runfiles,rows,deadline,*,stage):
        tick(deadline)
        require(stage in ('metadata','material'))
        repository = METADATA_REPOSITORY if stage == 'metadata' else REPOSITORY
        selected = [row[2] for row in rows if len(row) == 3 and row[0] in ('','_main') and row[1] == repository]
        require(len(selected) == 1 and re.fullmatch('[A-Za-z0-9_+.-]{1,256}',selected[0]) is not None
            and (selected[0] == repository or selected[0].endswith('+' + repository)))
        self.clock = carrier.Clock(deadline); self.stack = ExitStack(); self.parents = {}; self.aliases = []
        try:
            self.mapping_alias = runfiles / selected[0] / 'inputs.json'
            self.mapping_path = self.mapping_alias.resolve(strict=True)
            require(self.mapping_path.name == 'inputs.json' and self.mapping_path.parent.name == selected[0]
                and self.mapping_path.parent.parent.name == 'external')
            self.mapping_root = self.stack.enter_context(DeclaredRoot(self.mapping_path.parent,self.clock))
            self.mapping_raw = carrier.read(self.mapping_root,'inputs.json',MAX_DOCUMENT)
            self.document = json.loads(self.mapping_raw,object_pairs_hook=source.unique)
            require(type(self.document) is dict and set(self.document) == {'kind','stage','files'}
                and self.document['kind'] == DECLARED_KIND and self.document['stage'] == stage
                and type(self.document['files']) is dict and 0 < len(self.document['files']) <= 4096)
            self.files = self.document['files']; self.by_path = {}
            self.selection_raw = None
            if stage == 'material':
                self.selection_alias = runfiles / selected[0] / 'selected-material.json'
                self.selection_path = self.selection_alias.resolve(strict=True)
                require(self.selection_path == self.mapping_path.parent / 'selected-material.json')
                self.selection_raw = carrier.read(self.mapping_root,'selected-material.json',65536)
                self.selection = validate_selection(json.loads(self.selection_raw,object_pairs_hook=source.unique))
            for role,row in self.files.items():
                self.clock.tick(); carrier.relative(role)
                require(type(row) is dict and set(row) == {'path','sha256','bytes','alias'}
                    and row['alias'] == 'inputs/' + role)
                protocol.path(row['path']); protocol.pin(row['sha256'])
                maximum = 1024*1024*1024 if role == 'compiler/artifacts/native-cli' else 64*1024*1024
                require(type(row['bytes']) is int and 0 <= row['bytes'] <= maximum)
                path = protocol.path(row['path']); alias = runfiles / selected[0] / row['alias']
                require(alias.resolve(strict=True) == path)
                self.aliases.append((alias,path))
                if str(path) in self.by_path: require(self.by_path[str(path)]['sha256'] == row['sha256'])
                self.by_path[str(path)] = row
                if path.parent not in self.parents:
                    self.parents[path.parent] = self.stack.enter_context(DeclaredRoot(path.parent,self.clock))
            self.recheck()
        except BaseException:
            self.stack.close(); raise

    def recheck(self):
        self.clock.tick()
        require(self.mapping_alias.resolve(strict=True) == self.mapping_path)
        require(carrier.read(self.mapping_root,'inputs.json',MAX_DOCUMENT) == self.mapping_raw)
        if self.selection_raw is not None:
            require(self.selection_alias.resolve(strict=True) == self.selection_path
                and carrier.read(self.mapping_root,'selected-material.json',65536) == self.selection_raw)
        metadata.recheck_aliases(self.aliases,self.clock.deadline)
        for root in self.parents.values(): root.check()

    def read(self,path,pin,deadline,maximum=MAX_DOCUMENT):
        # Only an already-installed immutable runtime phase may join1170 to600.
        require(deadline == self.clock.deadline or query_tools.verification_deadline(deadline) == self.clock.deadline)
        self.recheck(); row = self.by_path.get(str(path))
        require(row is not None and row['sha256'] == pin and row['bytes'] <= maximum)
        raw = carrier.read(self.parents[Path(path).parent],Path(path).name,maximum,pin)
        require(len(raw) == row['bytes'])
        self.recheck(); return raw

    def read_json(self,path,pin,deadline,maximum=MAX_DOCUMENT):
        return json.loads(self.read(path,pin,deadline,maximum),object_pairs_hook=source.unique)

    def role(self,role):
        require(role in self.files); row = self.files[role]
        return self.read(row['path'],row['sha256'],self.clock.deadline,max(MAX_DOCUMENT,row['bytes']))

    def close(self): self.stack.close()
    def __enter__(self): return self
    def __exit__(self,*_): self.close()


class ProjectionRoot(carrier.Root):
    """Hold all projected regulars, including nested names, across each phase."""
    def __init__(self,*args,**kwargs):
        self.projection_leaves = {}
        self.writer_witnesses = None
        super().__init__(*args,**kwargs)

    def open(self,name):
        fd,witness = super().open(name)
        try:
            if self.writer_witnesses is not None:
                require(name in self.writer_witnesses and self.writer_witnesses[name] == witness)
            if name in self.projection_leaves:
                require(self.projection_leaves[name][2] == witness)
            else:
                require(len(self.projection_leaves) < 4096)
                parent,leaf = super().parent(name)
                retained = None
                try:
                    require(carrier.identity(os.stat(leaf,dir_fd=parent,follow_symlinks=False)) == witness)
                    retained = os.dup(fd)
                    self.projection_leaves[name] = (parent,retained,witness)
                except BaseException:
                    os.close(parent)
                    if retained is not None: os.close(retained)
                    raise
            self.check()
            return fd,witness
        except BaseException:
            os.close(fd); raise

    def check(self):
        super().check()
        for name,(parent,leaf_fd,witness) in self.projection_leaves.items():
            self.clock.tick()
            parts = carrier.relative(name)
            current = os.dup(self.fd)
            try:
                for index,part in enumerate(parts[:-1]):
                    self.clock.tick()
                    key = '/'.join(parts[:index+1])
                    selected = self.named[key]
                    require(carrier.identity(os.stat(part,dir_fd=current,follow_symlinks=False),True) == selected)
                    following = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=current)
                    try:
                        require(carrier.identity(os.fstat(following),True) == selected
                            == carrier.identity(os.stat(part,dir_fd=current,follow_symlinks=False),True))
                    except BaseException:
                        os.close(following); raise
                    os.close(current); current = following
                require(carrier.identity(os.fstat(current),True) == carrier.identity(os.fstat(parent),True)
                    and carrier.identity(os.fstat(leaf_fd)) == witness
                    == carrier.identity(os.stat(parts[-1],dir_fd=parent,follow_symlinks=False))
                    == carrier.identity(os.stat(parts[-1],dir_fd=current,follow_symlinks=False)))
            finally: os.close(current)

    def close(self):
        failure = None
        for parent,leaf,_ in self.projection_leaves.values():
            for fd in (leaf,parent):
                try: os.close(fd)
                except OSError as error:
                    if failure is None: failure = error
        self.projection_leaves = {}
        try: super().close()
        finally:
            if failure is not None: raise failure

def private_child(path,clock,*,root_class=carrier.Root):
    """Join exclusive created identity to a held, possibly0755 Bazel parent."""
    path = carrier.absolute(path)
    with DeclaredRoot(path.parent,clock) as parent:
        parent.check(); os.mkdir(path.name,0o700,dir_fd=parent.fd)
        created = os.stat(path.name,dir_fd=parent.fd,follow_symlinks=False)
        require(stat.S_ISDIR(created.st_mode) and created.st_uid == os.getuid()
            and stat.S_IMODE(created.st_mode) == 0o700)
        root = root_class(path,clock,sealed=False,expected_identity=carrier.identity(created,True),owned=True)
        try:
            parent.check()
            require(root.chain[-2][2] == carrier.identity(os.fstat(parent.fd),True)
                and carrier.identity(os.stat(path.name,dir_fd=parent.fd,follow_symlinks=False),True)
                == carrier.identity(created,True))
            root.check(); os.fsync(parent.fd)
            return root
        except BaseException:
            root.close(); raise


class ProjectionOutput(carrier.Output):
    """Only compact projection output; original carrier.Output stays exact."""
    def __init__(self,path,clock):
        self.path,self.clock,self.materialized = carrier.absolute(path),clock,{}
        self.root = private_child(self.path,clock,root_class=ProjectionRoot)
        self.root.writer_witnesses = self.materialized


def output_marker(raw,prefix,pin):
    protocol.pin(pin)
    require(type(raw) is bytes and len(raw) <= 64*1024*1024)
    lines = [line for line in raw.splitlines() if line.startswith(prefix.encode())]
    require(lines == [(prefix + pin).encode()])


def seal_marker(proofs,report,deadline):
    row = proofs.document['proofs']['test_log']
    proofs.join('test_log',Path(row['path']),row['sha256'],deadline)
    with DeclaredRoot(Path(row['path']).parent,carrier.Clock(deadline)) as root:
        raw = carrier.read(root,Path(row['path']).name,64*1024*1024,row['sha256'])
        root.check()
    expected = carrier.encoded(report)
    lines = []
    for line in raw.splitlines():
        tick(deadline)
        if line.startswith(b'{'):
            try: value = json.loads(line,object_pairs_hook=source.unique)
            except (ValueError,UnicodeDecodeError): continue
            if type(value) is dict and value.get('kind') == metadata.PRODUCER_KIND: lines.append(line)
    require(lines == [expected])
    proofs.recheck(deadline)


def projection_leaf_mode(root,witness,logical_mode='100644'):
    """Keep fresh writer modes exact; admit read-only retained nonexecutables."""
    require(logical_mode in ('100644','100755'))
    expected = 0o555 if logical_mode == '100755' else 0o444
    modes = (expected,) if root.owned or logical_mode == '100755' else (0o444,0o555)
    require(stat.S_IMODE(witness[4]) in modes)


def projection_read(root,report,clock,*,complete=True):
    expected_root = {'hub','graph','authority.json'} | ({'sdk-receipt.json'} if complete else set())
    carrier.names(root.fd,expected_root,clock)
    for name in (('authority.json','sdk-receipt.json') if complete else ('authority.json',)):
        fd,witness = root.open(name)
        try: projection_leaf_mode(root,witness)
        finally: os.close(fd)
    values = {}
    for role in ('hub','graph'):
        values[role] = {}
        children = {role:set()}
        for name in report[role + '_files']:
            parts = (role + '/' + name).split('/')
            for index in range(1,len(parts)):
                children.setdefault('/'.join(parts[:index]),set()).add(parts[index])
        for parent,names in children.items():
            fd,_ = root.parent(parent + '/selected-entry')
            try:
                require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o555)
                carrier.names(fd,names,clock)
            finally: os.close(fd)
        for name,row in report[role + '_files'].items():
            clock.tick(); fd,witness = root.open(role + '/' + name)
            try:
                projection_leaf_mode(root,witness,row['mode'])
            finally: os.close(fd)
            raw = carrier.read(root,role + '/' + name,MAX_DOCUMENT,row['sha256'])
            require(len(raw) == row['bytes']); values[role][name] = raw
    root.check(); return values


class FreshCustody:
    """Join full physical inventory after long proof work; never a content proof."""
    def __init__(self,carrier_root,carrier_report,extraction,roots,clock):
        self.roots,self.clock,self.receipt = roots,clock,copy.deepcopy(extraction)
        self.output = DeclaredRoot(Path(extraction['fresh_custody']['sdk']['root']).parent,clock)
        try:
            self.receipt_raw = carrier.encoded(extraction)
            require(carrier.read(self.output,'extraction-receipt.json',65536,
                source.sha(self.receipt_raw)) == self.receipt_raw)
            raw = carrier.read(carrier_root,'manifest.json',carrier.MAX_METADATA,carrier_report['manifest_sha256'])
            manifest = json.loads(raw,object_pairs_hook=source.unique)
            require(type(manifest) is dict and manifest['kind'] == carrier.MANIFEST
                and manifest['payload_sha256'] == extraction['payload_sha256']
                and manifest['origin_receipt_sha256'] == extraction['origin_receipt_sha256']
                and source.sha(raw) == extraction['manifest_sha256'])
            entries = manifest['entries']
            require(type(entries) is list and 0 < len(entries) <= carrier.MAX_ENTRIES)
            self.expected,self.children = {},{}
            for entry in entries:
                clock.tick()
                require(type(entry) is dict and entry.get('role') in ('sdk','jdk')
                    and entry.get('kind') in ('directory','file','symlink'))
                role,path = entry['role'],entry['path']; parts = carrier.relative(path,empty=True)
                key = (role,path);require(key not in self.expected)
                keys = {'role','path','kind','mode'} if entry['kind'] == 'directory' else (
                    {'role','path','kind','target'} if entry['kind'] == 'symlink' else
                    {'role','path','kind','mode','sha256','size','offset'})
                require(set(entry) == keys)
                self.expected[key] = entry
                if path:self.children.setdefault((role,'/'.join(parts[:-1])),set()).add(parts[-1])
            for (role,path),entry in self.expected.items():
                clock.tick()
                require((role,'') in self.expected and self.expected[(role,'')]['kind'] == 'directory')
                if path:require(self.expected[(role,'/'.join(carrier.relative(path)[:-1]))]['kind'] == 'directory')
            self.check()
        except BaseException:
            self.output.close();raise

    def check(self):
        self.clock.tick(); witnesses = {}
        carrier.names(self.output.fd,{'sdk','jdk','extraction-receipt.json'},self.clock)
        def visit(role,fd,path,depth):
            self.clock.tick();require(depth <= carrier.MAX_DEPTH)
            key = (role,path);selected = self.expected[key]
            before = os.fstat(fd)
            require(selected['kind'] == 'directory' and stat.S_ISDIR(before.st_mode)
                and stat.S_IMODE(before.st_mode) == selected['mode'] == 0o555
                and before.st_uid in (0,os.getuid()))
            witnesses[key] = carrier.identity(before)
            for name in carrier.names(fd,self.children.get(key,set()),self.clock):
                self.clock.tick();child = path+'/'+name if path else name
                row = self.expected[(role,child)]
                info = os.stat(name,dir_fd=fd,follow_symlinks=False)
                if row['kind'] == 'directory':
                    require(stat.S_ISDIR(info.st_mode))
                    opened = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                    try:
                        require(carrier.identity(info) == carrier.identity(os.fstat(opened)))
                        visit(role,opened,child,depth+1)
                    finally:os.close(opened)
                elif row['kind'] == 'symlink':
                    require(stat.S_ISLNK(info.st_mode) and os.readlink(name,dir_fd=fd) == row['target'])
                    witnesses[(role,child)] = carrier.identity(info)
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and info.st_uid in (0,os.getuid()) and stat.S_IMODE(info.st_mode) == row['mode']
                        and info.st_size == row['size'])
                    opened = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
                    try:require(carrier.identity(info) == carrier.identity(os.fstat(opened)))
                    finally:os.close(opened)
                    witnesses[(role,child)] = carrier.identity(info)
                require(carrier.identity(info) == carrier.identity(os.stat(name,dir_fd=fd,follow_symlinks=False)))
            require(carrier.identity(before) == carrier.identity(os.fstat(fd)))
        for role,root in self.roots.items():
            self.clock.tick();root.check();visit(role,root.fd,'',0)
            selected = self.receipt['fresh_custody'][role]
            require(selected['root'] == str(root.path) and selected['root_identity'] == root.chain[-1][2]
                and selected['members_sha256'] == source.sha(carrier.encoded(
                    [[name,value] for (which,name),value in sorted(witnesses.items()) if which == role])))
            root.check()
        require(set(witnesses) == set(self.expected)
            and carrier.read(self.output,'extraction-receipt.json',65536,source.sha(self.receipt_raw)) == self.receipt_raw)
        carrier.names(self.output.fd,{'sdk','jdk','extraction-receipt.json'},self.clock)
        self.output.check();self.clock.tick()

    def close(self):self.output.close()

class Session:
    """Keep one extraction through plan/query/compiler/package, never a reusable token."""
    def __init__(self,document,deadline,declared,carrier_root,carrier_aliases,carrier_declaration,seal_proofs,
                 temporary,selected_carrier,*,runfiles,rows):
        validate_selection(document); tick(deadline)
        self.caller_deadline = deadline
        deadline = query_tools.verification_deadline(deadline)
        self.document = copy.deepcopy(document); self.deadline = deadline; self.inputs = declared
        self.stack = ExitStack(); self.closed = False; self.carrier_root = Path(carrier_root)
        self.carrier_aliases = carrier_aliases; self.carrier_declaration = carrier_declaration
        self.seal_proofs = seal_proofs; self.selected_carrier = copy.deepcopy(selected_carrier)
        self.pin = selected_carrier['carrier']['receipt_sha256']; self.clock = carrier.Clock(deadline)
        try:
            self.stack.enter_context(declared)
            require(declared.selection_raw is not None and declared.selection == document)
            self.material_selection_sha256 = source.sha(declared.selection_raw)
            self.stack.enter_context(metadata.proof_scope(deadline))
            query_clock = metadata.legacy.DEADLINE
            try:
                metadata.legacy.DEADLINE = self.caller_deadline
                require(metadata.legacy.declared_query_tools(runfiles,rows) is True)
            finally: metadata.legacy.DEADLINE = query_clock
            self.carrier_hold = self.stack.enter_context(carrier.Root(self.carrier_root,self.clock))
            projection = document['sdk']; self.root = self.stack.enter_context(ProjectionRoot(projection['root'],self.clock))
            raw = declared.read(Path(projection['root'])/'sdk-receipt.json',projection['receipt_sha256'],deadline)
            self.report = json.loads(raw,object_pairs_hook=source.unique)
            self.authority_raw = declared.read(Path(projection['root'])/'authority.json',projection['inventory_sha256'],deadline)
            self.core = report_shape(self.report,self.authority_raw)
            require(self.report['source'] == document['source'] and self.report['inventory_sha256'] == projection['inventory_sha256'])
            self.projected = projection_read(self.root,self.report,self.clock)
            self.seal = metadata.qualify_producer(selected_carrier,deadline,seal_proofs)
            self.origin = carrier.validate_binding(self.carrier_root,self.pin,deadline); metadata.origin_join(self.origin)
            self.authenticated = self.authenticate()
            self.source_proof = self.stack.enter_context(binding.SourceProofSession(binding.config()))
            self.source_proof.initial_report()
            self.source_report = copy.deepcopy(self.source_proof.source_report)
            self.source_files = dict(self.source_proof.source_files); self.parent = copy.deepcopy(self.source_proof.baseline)
            require(self.report['patch_sha256'] == self.source_report['patch_sha256'])
            require(self.authenticated['source_inventory_sha256'] == self.source_report['inventory_sha256']
                and self.authenticated['source_graph'] == self.source_report['graph_files']
                and self.authenticated['patch_sha256'] == self.source_report['patch_sha256'])
            require({name:row['sha256'] for name,row in self.report['graph_files'].items()}
                == {name:row['sha256'] for name,row in self.source_report['graph_files'].items()})
            for name,raw in self.projected['graph'].items(): require(raw == self.source_files[name][1])
            self.extracted = Path(temporary) / 'extracted'
            self.temporary_hold = self.stack.enter_context(private_child(Path(temporary),self.clock))
            self.extraction = carrier.extract(self.carrier_root,self.pin,self.extracted,deadline)
            self.extraction_pin = carrier.sha(carrier.encoded(self.extraction))
            self.fresh = {role:self.stack.enter_context(carrier.Root(self.extracted/role,self.clock)) for role in ('sdk','jdk')}
            self.fresh_custody = FreshCustody(self.carrier_hold,self.origin,self.extraction,self.fresh,self.clock)
            self.stack.callback(self.fresh_custody.close)
            self.exported = sdk.validate_export(self.extracted/'sdk',metadata.legacy.EXPORT_SHA,
                source.BASE_INVENTORY,self.parent['baseline_graph_files'],on_read=lambda count:self.clock.tick())
            previous = metadata.legacy.read_hub(self.extracted/'sdk/repositories'/metadata.legacy.metadata.HUB)
            binding.verify_hub_delta(previous,self.projected['hub'])
            self.mappings = copy.deepcopy(self.exported)
            old_hub = self.mappings['repositories'][metadata.legacy.metadata.HUB]
            self.mappings['repositories'][metadata.legacy.metadata.HUB] = str(self.root.path/'hub')
            self.mappings['module_overrides'] = {name:(str(self.root.path/'hub') if path == old_hub else path)
                for name,path in self.mappings['module_overrides'].items()}
            self.mappings['inventory_sha256'] = self.report['inventory_sha256']
            self.mappings['mapping_sha256'] = self.report['mapping_sha256']
            self.recheck()
        except BaseException:
            self.close(); raise

    def authenticate(self):
        require(not self.closed)
        metadata.recheck_aliases(self.carrier_aliases,self.deadline)
        qualified = metadata.qualify_producer(self.selected_carrier,self.deadline,self.seal_proofs)
        seal_marker(self.seal_proofs,qualified['report'],self.deadline)
        metadata.recheck_declaration(self.carrier_declaration,qualified,self.carrier_root,self.pin,self.deadline)
        require(self.core['seal']['producer'] == self.selected_carrier['qualification']['producer']
            and self.core['seal']['program']['path'] == self.selected_carrier['qualification']['report']['path']
            and self.core['seal']['program']['sha256'] == self.selected_carrier['qualification']['report']['sha256'])
        actual_files = [{'name':row['name'],'sha256':row['sha256'],'bytes':row['size']} for row in qualified['report']['files']]
        require(actual_files == self.core['carrier_files'])
        meta = self.core['metadata']; program_row = meta['program']
        metadata_root = str(Path(program_row['path']).parent)
        outer = legacy.producer_success({'root':metadata_root,'producer':meta['producer']},METADATA_TARGET,
            'native-sdk-carrier-metadata',self.deadline,declared=self.inputs)
        raw = self.inputs.read(program_row['path'],program_row['sha256'],self.deadline)
        require(len(raw) == program_row['bytes'])
        report = json.loads(raw,object_pairs_hook=source.unique)
        require(type(report) is dict and set(report) == metadata.OUTPUT_FIELDS
            and report['schema_version'] == 2 and type(report['schema_version']) is int
            and report['kind'] == metadata.OUTPUT_KIND and report['original_selection'] == self.core['original_selection']
            and report['carrier']['receipt_sha256'] == self.pin and report['carrier']['origin'] == self.origin['origin']
            and report['carrier']['producer_context'] == self.origin['producer_context']
            and report['carrier']['qualification'] == qualified
            and report['query_exit'] == 0 and type(report['query_exit']) is int
            and report['query_tool_closure_independently_rechecked'] is True
            and report['source_and_extracted_carrier_rechecked'] is True
            and report['module_and_cargo_lock_unchanged'] is True
            and all(report[name] is False for name in metadata.FALSE_FLAGS))
        context = report['consumer_context']; reservation = outer['native_acquisition_inputs_reservation']
        require(context == {'mode':metadata.PROFILE,'epoch':str(Path(meta['producer']['receipt']).parent),
            'source_commit':meta['producer']['source_commit'],'graph_sha256':meta['producer']['graph_sha256'],
            'entry_monotonic_ns':reservation['original_entry_monotonic_ns'],
            'deadline_monotonic_ns':reservation['original_deadline_monotonic_ns']})
        log = self.inputs.role('metadata/test-log.evidence')
        output_marker(log,'omux-native-carrier-metadata-output-sha256=',program_row['sha256'])
        require(type(report['generated_hub']) is list and len(report['generated_hub']) == len(self.report['hub_files'])
            and 0 < len(report['generated_hub']) <= 16
            and all(type(row) is dict and set(row) == {'path','sha256'} for row in report['generated_hub'])
            and len({row['path'] for row in report['generated_hub']}) == len(report['generated_hub']))
        require({row['path']:row['sha256'] for row in report['generated_hub']}
            == {name:row['sha256'] for name,row in self.report['hub_files'].items()})
        legacy.producer_success(self.document['sdk'],SDK_TARGET,'native-carrier-sdk-export',self.deadline,declared=self.inputs)
        output_marker(self.inputs.role('sdk/test-log.evidence'),'omux-native-carrier-sdk-output-sha256=',
            self.document['sdk']['receipt_sha256'])
        return report

    def recheck(self):
        require(not self.closed); tick(self.deadline)
        require(self.authenticate() == self.authenticated)
        query = query_tools.verify_repository(metadata.legacy.QUERY_REPOSITORY,self.caller_deadline)
        require(query['status'] == 'declared-fixed-query-tools-byte-qualified' and query['inputs_rechecked'] is True)
        require(binding.load_verified_source(self.core['original_selection'])[0] == self.source_report)
        for name,held in self.source_proof.snapshots:
            held.recheck()
            if name == 'seventh': self.source_proof.join_n5(held)
            if name == 'ninth': self.source_proof.join_n9(held)
        require(sdk.validate_export(self.extracted/'sdk',metadata.legacy.EXPORT_SHA,source.BASE_INVENTORY,
            self.parent['baseline_graph_files'],on_read=lambda count:self.clock.tick()) == self.exported)
        require(projection_read(self.root,self.report,self.clock) == self.projected)
        require(carrier.validate_binding(self.carrier_root,self.pin,self.deadline) == self.origin)
        # Full fresh sweep occurs after final potentially long carrier validation.
        require(carrier.revalidate_extraction(self.carrier_root,self.pin,self.extracted,self.deadline,
            pinned_extraction_receipt_sha256=self.extraction_pin) == self.extraction)
        self.recheck_sources()
        self.inputs.recheck(); self.root.check(); self.carrier_hold.check()
        self.fresh_custody.check()
        self.temporary_hold.check()
        for root in self.fresh.values(): root.check()
        tick(self.deadline)

    def recheck_sources(self):
        for name,held in self.source_proof.snapshots:
            tick(self.deadline); held.recheck()
            if name == 'seventh': self.source_proof.join_n5(held)
            if name == 'ninth': self.source_proof.join_n9(held)

    def qualified(self,document,deadline):
        require(document == self.document and deadline == self.caller_deadline
            and query_tools.verification_deadline(deadline) == self.deadline); self.recheck()
        return self.source_report,self.source_files,self.parent,self.report,self.mappings

    def retain_selectors(self):
        require(not self.closed and _SCOPE.get() is self)
        phase = query_tools._CONSUMER_PHASE.get()
        require(isinstance(phase,query_tools._ConsumerPhase) and phase.query_deadline == self.deadline)
        return SelectorReadback(self.selector_bytes,self.deadline,phase.query_deadline_ns)

    def close(self):
        if not self.closed:
            self.closed = True; self.stack.close()


def current(document,deadline):
    session = _SCOPE.get()
    require(isinstance(session,Session) and not session.closed and session.document == document
        and session.caller_deadline == deadline and query_tools.verification_deadline(deadline) == session.deadline)
    return session


@contextmanager
def installed_session(session):
    require(isinstance(session,Session) and _SCOPE.get() is None and not session.closed)
    token = _SCOPE.set(session)
    try:
        yield session
        session.recheck()
        session.source_proof.finish()
        require(carrier.revalidate_extraction(session.carrier_root,session.pin,session.extracted,session.deadline,
            pinned_extraction_receipt_sha256=session.extraction_pin) == session.extraction)
        session.recheck_sources()
        session.inputs.recheck();session.root.check();session.carrier_hold.check()
        session.fresh_custody.check()
        session.temporary_hold.check()
        for root in session.fresh.values():root.check()
        tick(session.deadline)
    finally:
        _SCOPE.reset(token); session.close()


def qualify_selection(document,deadline):
    return current(document,deadline).qualified(document,deadline)


def stable_compact(source_report,sdk_report):
    session = _SCOPE.get()
    require(isinstance(session,Session) and not session.closed
        and source_report == session.source_report and sdk_report == session.report)
    return {'source_inventory_sha256':source_report['inventory_sha256'],
        'sdk_inventory_sha256':sdk_report['inventory_sha256'],
        'mapping_sha256':sdk_report['mapping_sha256'],'patch_sha256':source_report['patch_sha256'],
        'material_selection_sha256':session.material_selection_sha256}


@contextmanager
def session_scope(document,deadline,temporary,runfiles):
    """Admit declared source/transport/proofs once for one complete workload.

    Generated selected-material bytes have their own pin. They are joined to
    tracked configuration and the genuine SDK report, never self-authorizing.
    """
    tick(deadline); validate_selection(document)
    raw = binding.ninth.parent.declared(CONFIG,65536)
    configured,_ = config(raw)
    require(configured['selection'] == document)
    mapping = (runfiles / '_repo_mapping').read_bytes()
    require(0 < len(mapping) <= 1024*1024)
    rows = [line.split(',') for line in mapping.decode().splitlines()]
    selected_raw = binding.ninth.parent.declared(metadata.CONFIG,16384)
    selected = metadata.selection(selected_raw)
    packed,aliases,declaration = metadata.declared_carrier(runfiles,rows,selected,deadline)
    proofs = metadata.declared_proofs(runfiles,rows,selected,deadline)
    declared = DeclaredInputs(runfiles,rows,query_tools.verification_deadline(deadline),stage='material')
    try:
        session = Session(document,deadline,declared,packed,aliases,declaration,proofs,
            temporary,selected,runfiles=runfiles,rows=rows)
    except BaseException:
        declared.close(); raise
    session.selector_bytes = (raw,selected_raw)
    with installed_session(session):
        require(session.core['metadata'] == configured['metadata'])
        yield session
        require(binding.ninth.parent.declared(CONFIG,65536) == raw
            and binding.ninth.parent.declared(metadata.CONFIG,16384) == selected_raw)
    # Session close performs long SOURCE and fresh-custody work. Recheck the
    # independent tracked selectors afterward, using the same original cutoff.
    with metadata.proof_scope(query_tools.verification_deadline(deadline)):
        tick(query_tools.verification_deadline(deadline))
        require(binding.ninth.parent.declared(CONFIG,65536) == raw
            and binding.ninth.parent.declared(metadata.CONFIG,16384) == selected_raw)
        tick(query_tools.verification_deadline(deadline))


@contextmanager
def session_scope_for_package(selection,work_deadline,temporary,runfiles,*,entry_ns,original_deadline_ns):
    require(type(selection) is dict and selection.get('kind') == PACKAGE_KIND)
    with query_tools.consumer_phase(entry_ns,original_deadline_ns) as phase:
        require(work_deadline == phase.work_deadline)
        with session_scope(selection['material'],work_deadline,temporary,runfiles) as session:
            validate_package_paths(selection)
            configured,_ = config()
            require(configured['compile'] is not None
                and configured['compile']['selection']['path'] == selection['compilation']['selection']['path']
                and configured['compile']['selection']['sha256'] == selection['compilation']['selection']['sha256']
                and configured['compile']['result'] is not None
                and {key:configured['compile']['result'][key] for key in ('path','sha256','producer')}
                    == selection['compilation']['result'])
            yield session


def declared_read(path,pin,deadline,maximum=MAX_DOCUMENT):
    session = _SCOPE.get()
    require(isinstance(session,Session) and session.caller_deadline == deadline)
    require(query_tools.verification_deadline(deadline) == session.deadline)
    return session.inputs.read(path,pin,session.deadline,maximum)


def package_extra_rows(selection):
    value = selection['carrier_materials']
    rows = {'carrier/' + name:row for name,row in value['receipts'].items()}
    for action,group in value['authorities'].items():
        prefix = 'carrier-authority/' + action + '/'
        rows[prefix+'outer'] = group['outer']; rows[prefix+'evidence'] = group['evidence']
        for name,row in group['members'].items(): rows[prefix+name] = row
    require(len(rows) == 12)
    return rows


def validate_package_paths(selection):
    legacy._validate_paths_common(selection,schema=2,kind=PACKAGE_KIND)
    validate_selection(selection['material'])
    value = selection['carrier_materials']
    require(type(value) is dict and set(value) == {'schema_version','kind','authority_sha256',
        'carrier_files','projection','receipts','authorities'}
        and type(value['schema_version']) is int and value['schema_version'] == 2
        and value['kind'] == 'omux-native-carrier-retained-authority-v2')
    protocol.pin(value['authority_sha256']); file_tuple(value['carrier_files'])
    projection = value['projection']
    require(type(projection) is dict and set(projection) == {'receipt_sha256','inventory_sha256',
        'hub_inventory_sha256','graph_inventory_sha256'})
    for pin in projection.values(): protocol.pin(pin)
    require(projection['receipt_sha256'] == selection['files']['sdk']['sha256']
        == selection['material']['sdk']['receipt_sha256']
        and projection['inventory_sha256'] == value['authority_sha256']
        == selection['material']['sdk']['inventory_sha256'])
    receipts = value['receipts']
    require(type(receipts) is dict and set(receipts) == {'authority_document','carrier_receipt','seal_program','metadata_program'})
    for row in receipts.values(): member(row)
    require(receipts['authority_document']['sha256'] == value['authority_sha256']
        and receipts['metadata_program'] == selection['files']['sdk_metadata'])
    authorities = value['authorities']
    require(type(authorities) is dict and set(authorities) == {'seal','metadata'})
    for group in authorities.values():
        require(type(group) is dict and set(group) == {'outer','evidence','members'}
            and type(group['members']) is dict and len(group['members']) == 2)
        member(group['outer']); member(group['evidence'])
        for name,row in group['members'].items():
            require(type(name) is str and re.fullmatch('[0-9a-f]{64}\\.evidence',name) is not None)
            member(row,64*1024*1024)
    # Transport byte counts are tuple-only. The payload is never counted as
    # retained metadata and never smuggled into installed/deployed files.
    retained = [*selection['files'].values(),*selection['protocol_schema_files'].values(),
        *selection['native_acquisition_artifact_files'].values(),*package_extra_rows(selection).values()]
    for group in selection['authority_receipts'].values():
        retained += [group['outer'],group['evidence'],*group['members'].values()]
    require(len(retained) <= 4096 and sum(row['bytes'] for row in retained) <= 512*1024*1024)
    return selection


def _join_retained_authority(group,producer,staged,prefix):
    require(group['outer']['path'] == producer['receipt'] and group['outer']['sha256'] == producer['sha256'])
    outer = json.loads(staged[prefix+'outer'],object_pairs_hook=source.unique)
    index = json.loads(staged[prefix+'evidence'],object_pairs_hook=source.unique)
    parent = Path(producer['receipt']).parent
    require(group['evidence']['path'] == str(parent/'test-evidence.json')
        and group['evidence']['sha256'] == outer['test_evidence']['sha256'])
    require(type(index['results']) is list and 0 < len(index['results']) <= 3)
    entries = []
    for result in index['results']:
        require(type(result['files']) is list and 2 <= len(result['files']) <= 4)
        entries += [row for row in result['files'] if row['source'] in ('test.log','test.xml')]
    require(len(entries) == len(group['members'])
        and len({row['file'] for row in entries}) == len(entries)
        and {row['file'] for row in entries} == set(group['members']))
    for row in entries:
        require(row['state'] == 'copied' and type(row['bytes']) is int and row['bytes'] > 0
            and group['members'][row['file']] == {'path':str(parent/'test-evidence'/row['file']),
                'sha256':row['sha256'],'bytes':row['bytes']})
    return outer,index


def validate_package_chain(selection,values,protocol_values,staged_values,*,deadline):
    """Complete genuine PACKAGE verification, under one held extraction session."""
    import codex_native_acquisition_compilation as compiler
    validate_package_paths(selection); session = current(selection['material'],deadline)
    require(type(values) is dict and set(values) == legacy.ROLES
        and type(protocol_values) is dict and set(protocol_values) == set(selection['protocol_schema_files'])
        and type(staged_values) is dict)
    extra = dict(selection['native_acquisition_artifact_files'])
    for action,group in selection['authority_receipts'].items():
        prefix = 'authority/' + action + '/'
        extra[prefix+'outer'] = group['outer']; extra[prefix+'evidence'] = group['evidence']
        extra.update({prefix+name:row for name,row in group['members'].items()})
    extra.update(package_extra_rows(selection))
    require(set(staged_values) == set(extra))
    def join(rows,raws):
        for name,row in rows.items():
            tick(session.deadline); raw = raws[name]
            require(type(raw) is bytes and len(raw) == row['bytes'] and source.sha(raw) == row['sha256'])
    join(selection['files'],values); join(selection['protocol_schema_files'],protocol_values); join(extra,staged_values)
    parsed = {name:json.loads(values[name],object_pairs_hook=source.unique) for name in legacy.ROLES-{'codex'}}
    selected = selection['compilation']['selection']; result = selection['compilation']['result']
    document = compiler.selected_document(selected['path'],selected['sha256'],deadline)
    require(document == parsed['compiler_selection'] and document['material'] == selection['material'])
    verified = compiler.readback(document,result,deadline)
    require(parsed['source'] == session.source_report and parsed['sdk'] == session.report
        and parsed['sdk_metadata'] == session.authenticated)
    selected_sdk = selection['material']['sdk']
    require(selection['files']['source']['path'] == str(Path(selection['material']['source']['root'])/'source-receipt.json')
        and selection['files']['source']['sha256'] == selection['material']['source']['receipt_sha256'])
    require(selection['files']['sdk']['path'] == str(Path(selected_sdk['root'])/'sdk-receipt.json')
        and selection['files']['sdk']['sha256'] == selected_sdk['receipt_sha256'])
    value = selection['carrier_materials']; receipts = value['receipts']
    require(staged_values['carrier/authority_document'] == session.authority_raw
        and value['carrier_files'] == session.core['carrier_files']
        and value['projection'] == {'receipt_sha256':selected_sdk['receipt_sha256'],
            'inventory_sha256':session.report['inventory_sha256'],
            'hub_inventory_sha256':session.report['hub_inventory_sha256'],
            'graph_inventory_sha256':session.report['graph_inventory_sha256']})
    require(staged_values['carrier/carrier_receipt'] == carrier.encoded(session.origin)
        and receipts['carrier_receipt']['path'] == str(session.carrier_root/'receipt.json')
        and receipts['carrier_receipt']['sha256'] == session.pin)
    require(receipts['authority_document']['path'] == str(Path(selected_sdk['root'])/'authority.json'))
    for role in ('seal','metadata'):
        selected_program = session.core[role]
        require(receipts[role+'_program'] == selected_program['program'])
        program_raw = staged_values['carrier/'+role+'_program']
        expected = session.seal['report'] if role == 'seal' else session.authenticated
        require(json.loads(program_raw,object_pairs_hook=source.unique) == expected)
        _join_retained_authority(value['authorities'][role],selected_program['producer'],
            staged_values,'carrier-authority/'+role+'/')
    producers = {'source':selection['material']['source']['producer'],'sdk':selected_sdk['producer'],
        'plan':document['plan']['producer'],'query':document['query']['producer'],'compiler':result['producer']}
    for role,producer in producers.items():
        _join_retained_authority(selection['authority_receipts'][role],producer,staged_values,'authority/'+role+'/')
    joins = {'compiler_selection':selected,'compiler':result,'compiler_outer':result['producer'],
        'compiler_ledger':document['ledger'],'plan':document['plan'],'query':document['query'],
        'compiler_ledger_snapshot':parsed['compiler_ledger']['goal_snapshot']}
    for role,row in joins.items():
        require(selection['files'][role]['path'] == legacy.selected_role_path(role,row)
            and selection['files'][role]['sha256'] == row['sha256'])
    rows = parsed['compiler']['artifacts']; expected = {row['path']:row for row in rows}
    supplied = [selection['files']['codex'],selection['files']['config_schema'],
        *selection['protocol_schema_files'].values(),*selection['native_acquisition_artifact_files'].values()]
    require(len(supplied) == len(expected) and {row['path'] for row in supplied} == set(expected))
    for row in supplied:
        require(row['sha256'] == expected[row['path']]['sha256'] and row['bytes'] == expected[row['path']]['bytes'])
    require(expected[selection['files']['codex']['path']]['role'] == 'native-cli'
        and expected[selection['files']['config_schema']['path']]['role'] == 'config-schema')
    for name,row in selection['protocol_schema_files'].items():
        require(expected[row['path']]['role'] == name.split('/')[0]+'-schema')
    for name,row in selection['native_acquisition_artifact_files'].items():
        require(expected[row['path']]['role'] == ('test-xml' if name.endswith('.xml') else 'test-log'))
    join(selection['files'],values); join(selection['protocol_schema_files'],protocol_values); join(extra,staged_values)
    require(compiler.readback(document,result,deadline) == verified)
    session.recheck()
    return {'material_family':FAMILY,'compiler_qualified':True,'schema_qualified':True,
        'acquisitionContract':'unsupported','runtime_qualified':False,
        'provider_identity_proved':False,'live_handoff_proven':False}

def validate_mappings(document,mapping,deadline):
    session = current(document,deadline)
    require(mapping == session.mappings and mapping['registry_cache'] == str(session.extracted/'sdk/registry-cache')
        and set(mapping['repositories']) == set(session.exported['repositories']))
    for name,path in mapping['repositories'].items():
        expected = session.root.path/'hub' if name == metadata.legacy.metadata.HUB else session.extracted/'sdk/repositories'/name
        require(path == str(expected))
    return mapping
