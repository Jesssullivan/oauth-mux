"""Retain actual declared toolbar inputs in their ORIGINAL Bazel output root.

No runner or candidate executable is invoked. A future consumer must freshly
hold/revalidate this tuple and its source/Nix dependencies; this is neither a
relocatable launcher nor seat, registration, browser or consent authority.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time
import uuid
import zipfile
from io import BytesIO

import browser_runtime_authority as runtime
import pack

LABEL = '//delivery:yoga_public_artifact_prepare_producer'
RUNNER = '//delivery:yoga_toolbar_consent_proof'
SCOPE = 'yoga-current-public-toolbar-retained-v2'
VARIABLE = 'OMUX_YOGA_PUBLIC_PREP_'
MAX_FILES = 200000
MAX_BYTES = 8 * 1024**3
MAX_FILE = 512 * 1024**2
MAX_METADATA = 64 * 1024**2
MAX_HELD = 128
RULE_SHA = 'a7947d705d5bb9dc84c00138f07d36843bb9298cd0ab73af868b4d6c4ef73d95'
STORE = re.compile(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}')
ROLES = frozenset(('bundle', 'extension', 'chromium', 'node', 'observer', 'dbus_session',
    'dbus_daemon', 'keyring', 'runtime_authority', 'recorder', 'recorder_implementation',
    'launcher', 'native_manifest', 'native_store_paths', 'interpreter_closures',
    'python_wrapper', 'rules_source', 'runner_manifest'))
FLAGS = {'bundle':'--bundle', 'extension':'--extension', 'chromium':'--chromium',
    'node':'--node', 'observer':'--observer', 'dbus_session':'--dbus-session',
    'dbus_daemon':'--dbus-daemon', 'keyring':'--keyring',
    'runtime_authority':'--runtime-authority', 'recorder':'--recorder',
    'recorder_implementation':'--recorder-implementation', 'native_manifest':'--tool-manifest'}
FALSE = ('executionAuthority', 'seatQualified', 'toolbarConsentProved',
    'providerAccess', 'productionExport', 'normalVaultUnlocked',
    'destinationRegistrationVerified', 'relocatableRunfiles', 'embeddedProvenanceRewritten')
REQUIRED_RUNFILES = frozenset('_main/delivery/'+name for name in (
    'yoga_toolbar_consent.py','yoga_toolbar_contract.py','browser_runtime_authority.py',
    'test_installed_chromium.py','test_installed_custody.py','install.py','pack.py','portable.py',
    'portable_launcher_template.py','yoga_wrapper_authority.py','yoga_wrapper_custody.py'))


def require(value):
    if value is not True:
        raise ValueError('toolbar-public-preparation-refused')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def json_decode(raw):
    def unique(rows):
        result = {}
        for key, value in rows:
            require(key not in result); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-json')))


def decode(raw):
    value = json_decode(raw)
    if type(value) is dict and value.get('scope') == INVENTORY_WIRE_SCOPE:
        require(type(raw) is bytes and len(raw) <= MAX_METADATA)
        return inventory_expand(value)
    return value


def witness(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_custody(path, info):
    return info.st_uid in (0,os.getuid()) and (not info.st_mode & 0o022
        or path == Path('/nix/store') and stat.S_IMODE(info.st_mode) == 0o1775)


def relative(value):
    require(type(value) is str and 0 < len(value) <= 4096
        and not value.startswith('/') and str(PurePosixPath(value)) == value
        and not {'.', '..'}.intersection(value.split('/'))
        and all(32 <= ord(char) <= 126 and char != '\\' for char in value))
    return value


class Clock:
    def __init__(self, context, now=None):
        require(set(context) == {'epoch', 'entryNs', 'deadlineNs', 'sourceCommit', 'graphSha256', 'sourceRoot'})
        self.context, self.now = context, time.monotonic_ns if now is None else now
        require(type(context['entryNs']) is int and type(context['deadlineNs']) is int
            and context['deadlineNs'] - context['entryNs'] == 1200 * 10**9
            and type(context['sourceCommit']) is str and re.fullmatch('[0-9a-f]{40}', context['sourceCommit']) is not None
            and type(context['graphSha256']) is str and re.fullmatch('[0-9a-f]{64}', context['graphSha256']) is not None)
        epoch, source = Path(context['epoch']), Path(context['sourceRoot'])
        require(epoch.is_absolute() and str(uuid.UUID(epoch.name)) == epoch.name
            and source.is_absolute() and str(source) == os.path.normpath(str(source)))
        self.tick()

    def tick(self):
        require(self.context['entryNs'] <= self.now() < self.context['deadlineNs'] - 30 * 10**9)


class InputFdSlot:
    __slots__ = ('fd',)
    def __init__(self): self.fd = None


class Owned(list):
    def enroll(self, fd):
        try: self.append(fd)
        except BaseException as primary:
            if fd not in self:
                try: os.close(fd)
                except BaseException as cleanup: raise primary from cleanup
            raise
        return fd

    def empty_directory(self):
        # Registration and its possible allocation failure happen BEFORE open.
        slot = InputFdSlot(); self.append(slot)
        return slot

    def adopt(self, fd, prior):
        # Until insertion succeeds the prior registry remains the owner. A
        # post-insertion exception transfers that one owner, never closes it
        # in two different finally paths.
        selected = next(item for item in prior if
            (item.fd if type(item) is InputFdSlot else item) == fd)
        try: self.append(selected)
        except BaseException:
            if selected in self: prior.remove(selected)
            raise
        prior.remove(selected)

    def drain(self, primary=None):
        failure = None
        while self:
            selected = self.pop()
            if type(selected) is InputFdSlot:
                fd, selected.fd = selected.fd, None
                if fd is None: continue
            else: fd = selected
            try: os.close(fd)
            except BaseException as error:
                if failure is None: failure = error
        if failure is not None:
            if primary is not None: raise primary from failure
            raise failure


class Inputs:
    """Closed alias resolution, held mutable leaves, streamed immutable data.

    Nix roots come only from declared metadata/proof. Each symlink hop is
    captured and rechecked; arbitrary destinations, cycles and directories as
    file leaves refuse. No discovery or runtime registration query occurs.
    """
    def __init__(self, clock, output_base, source):
        self.clock = clock
        self.output_base, self.source = Path(output_base), Path(source)
        self.roots = {self.output_base:None, self.source:None}
        self.owned = Owned()
        self.rows, self.held, self.links = {}, {}, {}
        self.directory_slots = {}
        self.total = 0
        require(self.output_base.is_absolute() and self.source.is_absolute())
        try:
            for root in self.roots:
                require(root.resolve(strict=True) == root and stat.S_ISDIR(root.lstat().st_mode))
            self.root_facts = {str(root):witness(root.lstat())[:5] for root in self.roots}
            for root in self.roots: self.hold_directory(root)
        except BaseException as error:
            self.owned.drain(error)
            raise

    def hold_directory(self, path):
        path = Path(path); self.clock.tick()
        require(path.resolve(strict=True) == path and str(path) not in self.directory_slots
            and len(self.directory_slots) < 4)
        slot = self.owned.empty_directory()
        slot.fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        current = os.fstat(slot.fd)
        require(stat.S_ISDIR(current.st_mode) and directory_custody(path,current)
            and witness(current) == witness(path.lstat()))
        self.directory_slots[str(path)] = slot
        previous = self.root_facts.get(str(path))
        require(previous is None or witness(current)[:len(previous)] == previous)
        self.root_facts[str(path)] = witness(current)[:5]
        self.clock.tick()

    def directory_commitments(self):
        self.recheck()
        result = []
        for path,slot in sorted(self.directory_slots.items()):
            self.clock.tick(); current = witness(os.fstat(slot.fd))
            require(current == witness(Path(path).lstat()))
            self.root_facts[path] = current
            result.append({'path':path,'witness':list(current)})
        self.recheck()
        return result

    def allowed(self, path):
        # Probe the live authorized root map by lexical ancestry, never cache a
        # resolved path or positive decision. Cost depends on path depth rather
        # than the number of declared Nix roots; component boundaries stay exact.
        return path in self.roots or any(parent in self.roots for parent in path.parents)

    def resolve(self, path):
        path = Path(path)
        require(path.is_absolute())
        path = Path(os.path.normpath(str(path)))
        require(self.allowed(path))
        seen, count = set(), 0
        while True:
            self.clock.tick()
            selected = Path('/')
            changed = False
            for index, part in enumerate(path.parts[1:], 1):
                selected /= part
                info = selected.lstat()
                if stat.S_ISDIR(info.st_mode):
                    require(directory_custody(selected,info))
                if stat.S_ISLNK(info.st_mode):
                    count += 1; require(count <= 32 and str(selected) not in seen)
                    seen.add(str(selected)); target = os.readlink(selected)
                    require(type(target) is str and len(os.fsencode(target)) <= 4096
                        and '\n' not in target and '\r' not in target)
                    fact = (witness(info), target)
                    previous = self.links.get(str(selected)); require(previous is None or previous == fact)
                    self.links[str(selected)] = fact
                    destination = Path(target) if target.startswith('/') else selected.parent / target
                    path = Path(os.path.normpath(str(destination.joinpath(*path.parts[index+1:]))))
                    require(self.allowed(path)); changed = True; break
            if not changed: return path

    def add_nix_roots(self, values):
        require(type(values) is list and 0 < len(values) <= 4096 and len(values) == len(set(values)))
        for value in values:
            require(type(value) is str and STORE.fullmatch(value) is not None)
            if Path(value) not in self.roots:
                self.roots[Path(value)] = None
                information = Path(value).lstat()
                require(information.st_uid == 0 and (stat.S_ISLNK(information.st_mode)
                    or (stat.S_ISDIR(information.st_mode) or stat.S_ISREG(information.st_mode))
                        and not information.st_mode & 0o022))
                self.root_facts[value] = witness(information)

    def read(self, logical, actual, expected, *, aliases=(), content=False, maximum=MAX_FILE):
        self.clock.tick(); require(logical not in self.rows)
        require(type(aliases) is tuple and len(aliases) <= 1)
        # One bounded join per read, never a cross-file resolution cache. Equal
        # lexical names designate one input; every distinct alias still traverses
        # the unchanged resolver and retains its complete symlink witnesses.
        bindings = {}
        for candidate in (expected, actual) + aliases:
            path = Path(candidate)
            if path not in bindings: bindings[path] = self.resolve(path)
        physical = bindings[Path(actual)]
        require(all(selected == physical for selected in bindings.values()))
        parent = physical.parent
        require(parent.resolve(strict=True) == parent)
        owners = Owned(); primary = None
        try:
            directory_slot = owners.empty_directory()
            directory_slot.fd = os.open(parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            directory = directory_slot.fd
            parent_fact = witness(os.fstat(directory))
            require(parent_fact == witness(parent.lstat()))
            file_slot = owners.empty_directory()
            file_slot.fd = os.open(physical.name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC, dir_fd=directory)
            fd = file_slot.fd
            before = witness(os.fstat(fd))
            require(stat.S_ISREG(before[4]) and before[2] in (0, os.getuid())
                and not before[4] & 0o022 and before[5] >= 1 and 0 <= before[6] <= maximum
                and before == witness(physical.lstat()))
            self.total += before[6]; require(self.total <= MAX_BYTES)
            digest = hashlib.sha256(); count = 0; blocks = []
            while True:
                self.clock.tick(); block = os.read(fd, 1024*1024)
                if not block: break
                count += len(block); require(count <= before[6]); digest.update(block)
                if content: blocks.append(block)
            require(count == before[6] and before == witness(os.fstat(fd)) == witness(physical.lstat())
                and parent_fact == witness(os.fstat(directory)) == witness(parent.lstat()))
            row = {'key':logical, 'physical':str(physical), 'sha256':digest.hexdigest(),
                'bytes':count, 'witness':list(before)}
            self.rows[logical] = row
            # Hold mutable source/generated files through LAST tuple I/O. Nix
            # immutable leaves are individually fenced, then terminally joined.
            if physical.is_relative_to(self.output_base) or physical.is_relative_to(self.source):
                require(len(self.held) < MAX_HELD)
                self.owned.adopt(directory,owners)
                self.owned.adopt(fd,owners)
                self.held[logical] = (directory, fd, parent_fact)
            return b''.join(blocks) if content else row
        except BaseException as error: primary = error; raise
        finally:
            owners.drain(primary)
            if primary is None:
                require(before == witness(physical.lstat()) and parent_fact == witness(parent.lstat()))
                self.clock.tick()

    def recheck(self, *, held=True):
        self.clock.tick()
        for root, fact in self.root_facts.items():
            current = witness(Path(root).lstat())
            require(current[:len(fact)] == fact)
            if held and root in self.directory_slots:
                require(witness(os.fstat(self.directory_slots[root].fd))[:len(fact)] == fact)
            if not str(root).startswith('/nix/store/'):
                require(Path(root).resolve(strict=True) == Path(root))
        for path, (fact, target) in self.links.items():
            self.clock.tick(); require(witness(Path(path).lstat()) == fact and os.readlink(path) == target)
        for key, row in self.rows.items():
            self.clock.tick(); physical = Path(row['physical'])
            require(witness(physical.lstat()) == tuple(row['witness']))
            if key in self.held:
                directory, fd, parent_fact = self.held[key]
                require(parent_fact == witness(physical.parent.lstat()))
                if held: require(witness(os.fstat(fd)) == tuple(row['witness'])
                    and witness(os.fstat(directory)) == parent_fact)
        self.clock.tick()

    def close(self, primary=None):
        self.owned.drain(primary)
        if primary is None: self.recheck(held=False)


def acquire_declaration(inputs, action_path, retained_path):
    # Action aliases belong to this acquisition only. Keep their actual byte,
    # symlink and full-nine proof under the SAME original clock through close;
    # a separate retained read owns every fact published for future consumers.
    acquisition=Inputs(inputs.clock,inputs.output_base,inputs.source);primary=None
    try:
        action_raw=acquisition.read('action-declaration',action_path,retained_path,
            content=True,maximum=MAX_METADATA)
        retained_raw=inputs.read('declaration',retained_path,retained_path,
            content=True,maximum=MAX_METADATA)
        action_fact=acquisition.rows['action-declaration'];retained_fact=inputs.rows['declaration']
        require(action_raw==retained_raw and all(action_fact[field]==retained_fact[field]
            for field in ('physical','sha256','bytes','witness')))
        acquisition.recheck();inputs.recheck();inputs.clock.tick()
        return retained_raw
    except BaseException as error:primary=error;raise
    finally:
        acquisition.close(primary)
        if primary is None:inputs.recheck();inputs.clock.tick()


def declaration(raw, context):
    value = decode(raw)
    require(type(value) is dict and set(value) == {'schemaVersion','scope','runnerLabel',
        'preparationSource','preparationSourceDirty','roles','files','repoMappingKey'}
        and value['schemaVersion'] == 2 and value['scope'] == 'yoga-current-toolbar-declaration-v2'
        and value['runnerLabel'] == RUNNER and value['preparationSource'] == context['sourceCommit']
        and value['preparationSourceDirty'] is False
        and type(value['roles']) is dict and set(value['roles']) == ROLES
        and type(value['files']) is list and 16 <= len(value['files']) <= MAX_FILES)
    files = {}
    for row in value['files']:
        require(type(row) is dict and set(row) == {'key','executionPath','inRunner'}
            and type(row['inRunner']) is bool)
        key, path = relative(row['key']), relative(row['executionPath'])
        require(key not in files); files[key] = row
    require(list(files) == sorted(files) and set(value['roles'].values()).issubset(files)
        and len(set(value['roles'].values())) == len(ROLES)
        and REQUIRED_RUNFILES.issubset(files)
        and all(files[key]['inRunner'] is True for key in REQUIRED_RUNFILES))
    mapping_key=value['repoMappingKey']
    if mapping_key is not None:
        relative(mapping_key)
        require(mapping_key in files and files[mapping_key]['inRunner'] is False)
    return value, files


def extension(raw):
    require(len(raw) <= 4*1024**2)
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        rows = archive.infolist(); require(1 <= len(rows) <= 64)
        files = {}
        for row in rows:
            name = relative(row.filename)
            require(name not in files and not row.is_dir() and row.file_size <= 262144
                and row.compress_size <= 262144 and not stat.S_ISLNK(row.external_attr >> 16))
            files[name] = archive.read(row)
    manifest = decode(files['manifest.json']); key = base64.b64decode(manifest['key'], validate=True)
    identifier = ''.join(chr(97+int(char,16)) for char in hashlib.sha256(key).hexdigest()[:32])
    require(identifier == 'bggghdafplhajiailkafeihemlalagmm'
        and manifest['manifest_version'] == 3 and manifest['version'] == '0.2.0'
        and files['shared/channel.mjs'] == b'export const CHANNEL = "development";\nexport const INSTANCE = "dev";\nexport const NATIVE_HOST = "ai.xoxd.omux.dev";\n')
    return {'id':identifier, 'version':manifest['version'], 'channel':'development',
        'nativeHost':'ai.xoxd.omux.dev', 'published':False, 'signed':False}


def tuple_metadata(data, value):
    bundle, _ = pack.verify_bundle(data['bundle'])
    require(bundle['distribution'] == 'portable-linux' and bundle['target'] == 'x86_64-linux'
        and bundle.get('channel') == 'development')
    browser = runtime.validate_authority(data['runtime_authority'])
    native = decode(data['native_manifest']); groups = decode(data['interpreter_closures'])
    require(native['system'] == 'x86_64-linux' and groups['schemaVersion'] == 1
        and type(groups['groups']) is dict and 'python' in groups['groups'])
    require(hashlib.sha256(data['rules_source']).hexdigest() == RULE_SHA)
    shell = native['packages']['bash']['out'] + '/bin/bash'
    require(STORE.fullmatch(native['packages']['bash']['out']) is not None)
    roots = set(data['native_store_paths'].decode('ascii').splitlines())
    require(native['packages']['bash']['out'] in roots and native['packages']['python']['out'] in roots)
    backends = dict(native['tools'],python=native['packages']['python']['out']+'/bin/python3')
    for role, name in (('dbus_session','dbus_run_session'),('dbus_daemon','dbus_daemon'),
            ('keyring','gnome_keyring_daemon'),('python_wrapper','python')):
        backend = backends[name]
        require(type(backend) is str and re.fullmatch(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}/bin/[A-Za-z0-9._+-]{1,128}',backend) is not None
            and '/'.join(backend.split('/')[:4]) in roots)
        expected = ('#!'+shell+'\nset -eu\nexec \''+backend+'\' "$@"\n').encode('ascii')
        require(data[role] == expected)
    launcher = data['launcher'].decode('ascii')
    require(launcher.startswith('#!'+shell+'\nset -eu\n')
        and 'Omux executable requires Bazel directory runfiles.' in launcher
        and 'unset NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONHOME' in launcher
        and '"$RUNFILES_ROOT/'+value['roles']['python_wrapper']+'"' in launcher
        and '-I -B -X utf8 -c ' in launcher
        and '"$RUNFILES_ROOT/_main/delivery/yoga_toolbar_consent.py" "$@"' in launcher)
    for role, flag in FLAGS.items():
        require(flag in launcher and value['roles'][role] in launcher)
    return {'embeddedArchiveProvenance':bundle['provenance'],
        'archiveProduct':bundle['product'], 'extension':extension(data['extension']),
        'runtimeInventorySha256':browser['inventorySha256'],
        'wrapperBackends':{name:backends[name] for name in
            ('dbus_run_session','dbus_daemon','gnome_keyring_daemon','python')},
        'wrapperInterpreter':shell, 'interpreterDeclaration':groups,
        'runtimeAuthorityScope':browser['scope']}


INVENTORY_WIRE_SCOPE = 'yoga-original-toolbar-runfiles-byte-inventory-v2'
INVENTORY_FIELDS = frozenset(('schemaVersion','scope','context','originalOutputBase',
    'originalRunfilesRoot','originalControlRunfilesRoot','declarationSha256',
    'files','symlinks','roles','declaredFileCount','boundFileCount','totalBytes'))
MAX_INVENTORY_PATHS = MAX_METADATA // 2
MAX_INVENTORY_EXPANDED = 256 * 1024**2


def inventory_check(value, clock=None):
    """Validate scalar facts only; never grant filesystem or consumer authority."""
    require(type(value) is dict and set(value) == INVENTORY_FIELDS
        and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
        and value['scope'] == 'yoga-original-toolbar-runfiles-byte-inventory-v1'
        and type(value['files']) is list and 0 < len(value['files']) <= MAX_FILES+1
        and type(value['symlinks']) is list and len(value['symlinks']) <= MAX_METADATA//8
        and type(value['roles']) is dict and set(value['roles']) == ROLES)
    def integer(number): require(type(number) is int and 0 <= number < 2**128)
    def path(name, absolute):
        require(type(name) is str and 0 < len(os.fsencode(name)) <= 8192
            and name.startswith('/') is absolute and not name.startswith('//') and '\x00' not in name
            and str(PurePosixPath(name)) == name
            and not {'.','..'}.intersection(name.split('/'))
            and len(PurePosixPath(name).parts) <= 256
            and all(len(os.fsencode(part)) <= 4096 for part in PurePosixPath(name).parts))
    def fact(numbers):
        require(type(numbers) is list and len(numbers) == 9)
        for number in numbers[:7]: integer(number)
        for number in numbers[7:]:
            require(type(number) is int and -2**127 <= number < 2**127)
    def tick():
        if clock is not None:clock.tick()
    keys=[];total=0;expanded=0
    for row in value['files']:
        tick()
        require(type(row) is dict and set(row) == {'key','physical','sha256','bytes','witness'})
        relative(row['key']);path(row['key'],False);path(row['physical'],True)
        fact(row['witness']);integer(row['bytes'])
        require(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None
            and row['bytes'] == row['witness'][6] and stat.S_ISREG(row['witness'][4]))
        keys.append(row['key']);total+=row['bytes'];expanded+=len(canonical(row))
        require(expanded <= MAX_INVENTORY_EXPANDED)
    require(keys == sorted(set(keys)))
    links=[]
    for row in value['symlinks']:
        tick()
        require(type(row) is dict and set(row) == {'path','witness','target'})
        path(row['path'],True);fact(row['witness'])
        require(stat.S_ISLNK(row['witness'][4]))
        require(type(row['target']) is str and len(os.fsencode(row['target'])) <= 4096
            and '\n' not in row['target'] and '\r' not in row['target'] and '\x00' not in row['target'])
        links.append(row['path']);expanded+=len(canonical(row))
        require(expanded <= MAX_INVENTORY_EXPANDED)
    require(links == sorted(set(links)))
    for field in ('originalOutputBase','originalRunfilesRoot','originalControlRunfilesRoot'):
        path(value[field],True)
    require(type(value['declarationSha256']) is str
        and re.fullmatch('[0-9a-f]{64}',value['declarationSha256']) is not None)
    require(type(value['context']) is dict and set(value['context']) ==
        {'epoch','entryNs','deadlineNs','sourceCommit','graphSha256','sourceRoot'})
    for field in ('entryNs','deadlineNs'):integer(value['context'][field])
    require(value['context']['deadlineNs']-value['context']['entryNs'] == 1200*10**9)
    for field,length in (('sourceCommit',40),('graphSha256',64)):
        require(type(value['context'][field]) is str
            and re.fullmatch('[0-9a-f]{'+str(length)+'}',value['context'][field]) is not None)
    path(value['context']['epoch'],True);path(value['context']['sourceRoot'],True)
    require(str(uuid.UUID(Path(value['context']['epoch']).name)) == Path(value['context']['epoch']).name)
    require(all(type(key) is str for key in value['roles'].values())
        and len(set(value['roles'].values())) == len(ROLES))
    for name,key in value['roles'].items():require(type(key) is str and key in keys)
    for field in ('declaredFileCount','boundFileCount','totalBytes'):integer(value[field])
    require(16 <= value['declaredFileCount'] <= MAX_FILES
        and value['boundFileCount'] == len(keys)
        and value['declaredFileCount'] <= len(keys) <= value['declaredFileCount']+1
        and value['totalBytes'] == total and total <= MAX_BYTES)
    tick()
    return value


def inventory_compact(value, clock=None):
    """Lossless canonical path trie; literal symlink targets are separate atoms."""
    inventory_check(value,clock)
    atoms=[];atom_ids={};paths=[[-1,-1],[-1,-2]];path_ids={'':0,'/':1}
    targets=[[-1,-1]];target_ids={None:0}
    path_bytes=target_bytes=0
    def tick():
        if clock is not None:clock.tick()
    def atom(text):
        require(type(text) is str and len(os.fsencode(text)) <= 4096)
        if text not in atom_ids:
            require(len(atoms)<MAX_INVENTORY_PATHS)
            atom_ids[text]=len(atoms);atoms.append(text)
        return atom_ids[text]
    def path(text):
        nonlocal path_bytes
        current=1 if text.startswith('/') else 0;prefix='/' if current else ''
        for part in PurePosixPath(text).parts[1 if current else 0:]:
            tick();prefix=(prefix.rstrip('/')+'/'+part) if prefix else part
            if prefix not in path_ids:
                path_bytes+=len(os.fsencode(prefix))
                require(path_bytes <= MAX_INVENTORY_EXPANDED
                    and len(paths)<MAX_INVENTORY_PATHS)
                path_ids[prefix]=len(paths);paths.append([current,atom(part)])
            current=path_ids[prefix]
        return current
    def target(text):
        nonlocal target_bytes
        # Literal slash-separated tokens, including empty/dot/dotdot tokens.
        # Joining reproduces readlink bytes; this is never path normalization.
        current=0;prefix=None
        for part in text.split('/'):
            tick();prefix=part if prefix is None else prefix+'/'+part
            if prefix not in target_ids:
                target_bytes+=len(os.fsencode(prefix))
                require(target_bytes <= MAX_INVENTORY_EXPANDED
                    and len(targets)<MAX_INVENTORY_PATHS)
                target_ids[prefix]=len(targets);targets.append([current,atom(part)])
            current=target_ids[prefix]
        return current
    result={name:value[name] for name in INVENTORY_FIELDS-{'schemaVersion','scope','files','symlinks'}}
    result.update(schemaVersion=2,scope=INVENTORY_WIRE_SCOPE,strings=atoms,paths=paths,
        targets=targets,files=[],symlinks=[])
    for row in value['files']:
        tick();result['files'].append([path(row['key']),path(row['physical']),row['sha256'],row['bytes'],row['witness']])
    for row in value['symlinks']:
        tick();result['symlinks'].append([path(row['path']),row['witness'],target(row['target'])])
    require(len(canonical(result)) <= MAX_METADATA)
    tick()
    return result


def inventory_expand(value, clock=None):
    """Decode exact v2 wire to v1 semantic facts; raw wire SHA remains distinct."""
    require(type(value) is dict and set(value) == INVENTORY_FIELDS|{'strings','paths','targets'}
        and type(value['schemaVersion']) is int and value['schemaVersion'] == 2
        and value['scope'] == INVENTORY_WIRE_SCOPE
        and type(value['strings']) is list and len(value['strings']) <= MAX_INVENTORY_PATHS
        and type(value['paths']) is list and 2 <= len(value['paths']) <= MAX_INVENTORY_PATHS
        and value['paths'][:2] == [[-1,-1],[-1,-2]]
        and all(type(row) is list and len(row) == 2 and all(type(number) is int for number in row)
            for row in value['paths'][:2])
        and type(value['targets']) is list and 1 <= len(value['targets']) <= MAX_INVENTORY_PATHS
        and value['targets'][0] == [-1,-1]
        and all(type(number) is int for number in value['targets'][0])
        and type(value['files']) is list and 0 < len(value['files']) <= MAX_FILES+1
        and type(value['symlinks']) is list and len(value['symlinks']) <= MAX_METADATA//8)
    def tick():
        if clock is not None:clock.tick()
    require(len(canonical(value)) <= MAX_METADATA)
    atoms=value['strings'];seen=set()
    for atom in atoms:
        tick()
        require(type(atom) is str and len(os.fsencode(atom)) <= 4096 and atom not in seen)
        seen.add(atom)
    names=['','/'];depth=[0,0];pairs=set();expanded=0
    def ref(index,table):
        require(type(index) is int and 0 <= index < len(table));return table[index]
    for index,row in enumerate(value['paths'][2:],2):
        tick()
        require(type(row) is list and len(row) == 2)
        parent=ref(row[0],names);part=ref(row[1],atoms)
        require(type(row[0]) is int and row[0]<index and part not in ('','.','..')
            and '/' not in part and '\x00' not in part and tuple(row) not in pairs)
        pairs.add(tuple(row));name=parent.rstrip('/')+'/'+part if parent else part
        require(len(os.fsencode(name)) <= 8192 and depth[row[0]]<256)
        expanded+=len(os.fsencode(name));require(expanded <= MAX_INVENTORY_EXPANDED)
        names.append(name);depth.append(depth[row[0]]+1)
    literals=[None];literal_depth=[0];literal_pairs=set();literal_bytes=0
    for index,row in enumerate(value['targets'][1:],1):
        tick();require(type(row) is list and len(row) == 2)
        parent=ref(row[0],literals);part=ref(row[1],atoms)
        require(row[0]<index and '/' not in part and tuple(row) not in literal_pairs)
        literal_pairs.add(tuple(row));text=part if parent is None else parent+'/'+part
        require(len(os.fsencode(text)) <= 4096 and literal_depth[row[0]]<4097
            and '\n' not in text and '\r' not in text)
        literal_bytes+=len(os.fsencode(text));require(literal_bytes <= MAX_INVENTORY_EXPANDED)
        literals.append(text);literal_depth.append(literal_depth[row[0]]+1)
    result={name:value[name] for name in INVENTORY_FIELDS-{'schemaVersion','scope','files','symlinks'}}
    result.update(schemaVersion=1,scope='yoga-original-toolbar-runfiles-byte-inventory-v1',files=[],symlinks=[])
    for row in value['files']:
        tick()
        require(type(row) is list and len(row) == 5)
        result['files'].append({'key':ref(row[0],names),'physical':ref(row[1],names),
            'sha256':row[2],'bytes':row[3],'witness':row[4]})
    for row in value['symlinks']:
        tick()
        require(type(row) is list and len(row) == 3)
        result['symlinks'].append({'path':ref(row[0],names),'witness':row[1],'target':ref(row[2],literals)})
    inventory_check(result,clock)
    # Reject unused table atoms/nodes and all alternative encodings of the same
    # facts. Strict prior-parent construction also rules out cycles/forward refs.
    require(inventory_compact(result,clock) == value)
    tick()
    return result


def publish(product, values, clock):
    """Closed metadata outputs only; failure never becomes producer success."""
    clock.tick(); os.mkdir(product,mode=0o700)
    owners=Owned(); primary=None; rows=[]
    try:
        parent_slot=owners.empty_directory()
        parent_slot.fd=os.open(product,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        parent=parent_slot.fd
        for name, raw in values:
            clock.tick(); require(name in ('artifact.json','runfiles-inventory.json') and len(raw)<=MAX_METADATA)
            leaf_slot=owners.empty_directory()
            leaf_slot.fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
            fd=leaf_slot.fd
            position=0
            while position<len(raw):
                clock.tick(); written=os.write(fd,raw[position:]);require(written>0);position+=written
            os.fsync(fd); before=witness(os.fstat(fd))
            require(before[2]==os.getuid() and before[5]==1 and stat.S_IMODE(before[4])==0o600
                and before[6]==len(raw) and os.pread(fd,len(raw)+1,0)==raw)
            rows.append((name,fd,before))
        os.fsync(parent); anchor=witness(os.fstat(parent))
        require(anchor==witness(product.lstat()))
        for name,fd,before in rows:
            require(before==witness(os.fstat(fd))==witness(os.stat(name,dir_fd=parent,follow_symlinks=False)))
        clock.tick()
    except BaseException as error:primary=error;raise
    finally:
        owners.drain(primary)
        if primary is None:
            require(anchor==witness(product.lstat()))
            for name,fd,before in rows:require(before==witness((product/name).lstat()))
            require(anchor==witness(product.lstat()));clock.tick()


def manifest_unescape(value, *, key):
    """One pass over Bazel's field-specific escapes; never recursively decode."""
    decoded=[]; position=0
    escapes={'n':'\n', 'b':'\\'}
    if key: escapes['s']=' '
    while position < len(value):
        char=value[position]
        if char == '\\':
            require(position+1 < len(value) and value[position+1] in escapes)
            decoded.append(escapes[value[position+1]]); position+=2
        else:
            decoded.append(char); position+=1
    return ''.join(decoded)


def runfiles_manifest(raw, clock):
    """Canonical Bazel SOURCE_SYMLINKS records, joined to declared files later.

    Keys escape spaces/newlines/backslashes; targets escape only newlines and
    backslashes. Target spaces stay literal. No new path alphabet or root is
    authorized by decoding; each decoded field keeps the existing lexical fence.
    """
    require(type(raw) is bytes and 0 < len(raw) <= MAX_METADATA and raw.endswith(b'\n'))
    result={}; previous=None
    for line in raw.decode('ascii')[:-1].split('\n'):
        clock.tick(); require(0 < len(line) <= 16386)
        escaped=line.startswith(' ')
        key_wire,separator,target_wire=(line[1:] if escaped else line).partition(' ')
        require(separator == ' ' and key_wire != '' and target_wire != '')
        key=manifest_unescape(key_wire,key=True) if escaped else key_wire
        physical=manifest_unescape(target_wire,key=False) if escaped else target_wire
        relative(key)
        require(physical.startswith('/') and len(physical) <= 4096)
        relative(physical[1:])
        needs_escaping=' ' in key or '\n' in key or '\n' in physical
        if needs_escaping:
            canonical_key=key.replace('\\',r'\b').replace(' ',r'\s').replace('\n',r'\n')
            canonical_target=physical.replace('\\',r'\b').replace('\n',r'\n')
            canonical_line=' '+canonical_key+' '+canonical_target
        else:
            canonical_line=key+' '+physical
        require(line == canonical_line and key not in result
            and (previous is None or previous < key) and len(result) < MAX_FILES+1)
        result[key]=physical; previous=key
    clock.tick()
    return result


def prepare(declaration_path, environment):
    fields = {'EPOCH','ENTRY_NS','DEADLINE_NS','SOURCE_COMMIT','GRAPH_SHA256','SOURCE_ROOT'}
    require({key[len(VARIABLE):] for key in environment if key.startswith(VARIABLE)} == fields)
    context = {'epoch':environment[VARIABLE+'EPOCH'], 'entryNs':int(environment[VARIABLE+'ENTRY_NS']),
        'deadlineNs':int(environment[VARIABLE+'DEADLINE_NS']), 'sourceCommit':environment[VARIABLE+'SOURCE_COMMIT'],
        'graphSha256':environment[VARIABLE+'GRAPH_SHA256'], 'sourceRoot':environment[VARIABLE+'SOURCE_ROOT']}
    clock = Clock(context); epoch = Path(context['epoch']); base = epoch/'output-base'
    # No copied/relocated/ephemeral sandbox root can claim the original target.
    action_controls = Path(environment['TEST_SRCDIR']).resolve(strict=True)
    require(action_controls.is_relative_to(base))
    suffix = action_controls.relative_to(base).parts[-5:]
    require(len(suffix) == 5 and suffix[0] == 'bazel-out' and suffix[2:4] == ('bin','delivery')
        and suffix[4] == 'yoga_public_artifact_prepare_producer.sh.runfiles')
    # TestRunner may supply a processwrapper-sandbox tree. It is an input alias,
    # never the retained launcher root: qualify the actual original Bazel tree.
    controls = base/'execroot/_main'/Path(*suffix)
    require(controls.resolve(strict=True) == controls and stat.S_ISDIR(controls.lstat().st_mode))
    execroot = base/'execroot/_main'
    outputs = Path(environment['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True)
    require(outputs.is_relative_to(base) and outputs.name == 'test.outputs'
        and stat.S_ISDIR(outputs.lstat().st_mode) and outputs.lstat().st_uid == os.getuid())
    inputs = Inputs(clock, base, context['sourceRoot']); primary = None
    try:
        inputs.hold_directory(controls)
        path = Path(declaration_path)
        require(path.is_relative_to(action_controls))
        raw = acquire_declaration(inputs,path,controls/path.relative_to(action_controls))
        value, files = declaration(raw, context); data = {}
        # Bootstrap metadata must be generated under this original output base;
        # no Nix or foreign target is followed until its closed roots are known.
        for role in ('native_manifest','native_store_paths','runtime_authority'):
            key = value['roles'][role]
            data[role] = inputs.read(key, controls/key, execroot/files[key]['executionPath'], content=True, maximum=16*1024**2)
        browser = runtime.validate_authority(data['runtime_authority'])
        native_roots = data['native_store_paths'].decode('ascii').splitlines()
        require(native_roots == sorted(set(native_roots)))
        inputs.add_nix_roots(sorted(set(native_roots)|set(browser['storePaths'])))
        manifest_key = value['roles']['runner_manifest']
        data['runner_manifest'] = inputs.read(manifest_key,controls/manifest_key,
            execroot/files[manifest_key]['executionPath'],content=True,maximum=MAX_METADATA)
        manifest_path = Path(inputs.rows[manifest_key]['physical'])
        require(manifest_path.name == 'yoga_toolbar_consent_proof.sh.runfiles_manifest')
        runfiles = manifest_path.with_name('yoga_toolbar_consent_proof.sh.runfiles')
        require(runfiles.is_relative_to(base) and runfiles.resolve(strict=True) == runfiles
            and stat.S_ISDIR(runfiles.lstat().st_mode))
        inputs.hold_directory(runfiles)
        manifest = runfiles_manifest(data['runner_manifest'],clock)
        expected_keys = {key for key,row in files.items() if row['inRunner']}
        require(set(manifest) - {'_repo_mapping'} == expected_keys)
        mapping_key=value['repoMappingKey']
        require(('_repo_mapping' in manifest) == (mapping_key is not None))
        if mapping_key is not None:
            expected_mapping=execroot/files[mapping_key]['executionPath']
            require(expected_mapping.is_relative_to(base)
                and inputs.resolve(manifest['_repo_mapping']) == inputs.resolve(expected_mapping))
            inputs.read(mapping_key,controls/mapping_key,expected_mapping,maximum=MAX_METADATA)
            inputs.read('_repo_mapping',runfiles/'_repo_mapping',expected_mapping,maximum=MAX_METADATA)
        keys_to_roles = {key:role for role,key in value['roles'].items()}
        for key, row in files.items():
            clock.tick()
            if key in inputs.rows:
                if row['inRunner']:
                    require(inputs.resolve(runfiles/key) == Path(inputs.rows[key]['physical'])
                        and inputs.resolve(manifest[key]) == Path(inputs.rows[key]['physical']))
                continue
            role = keys_to_roles.get(key)
            executable_data = role in ('chromium','node')
            maximum = pack.MAX_BYTES if role == 'bundle' else 4*1024**2 if role == 'extension' else MAX_FILE if executable_data or role is None else 16*1024**2
            selected = (runfiles if row['inRunner'] else controls)/key
            expected = execroot/row['executionPath']
            aliases = (manifest[key],) if row['inRunner'] else ()
            raw = inputs.read(key,selected,expected,aliases=aliases,
                content=role is not None and not executable_data,maximum=maximum)
            if role is not None: data[role] = raw
        metadata = tuple_metadata(data, value)
        require(all(inputs.rows[key]['bytes']>0 for key in value['roles'].values()))
        for role in ('chromium','node','launcher','dbus_session','dbus_daemon','keyring','python_wrapper'):
            require(bool(inputs.rows[value['roles'][role]]['witness'][4] & 0o111))
        inputs.recheck()
        inventory = {'schemaVersion':1, 'scope':'yoga-original-toolbar-runfiles-byte-inventory-v1',
            'context':context, 'originalOutputBase':str(base), 'originalRunfilesRoot':str(runfiles),
            'originalControlRunfilesRoot':str(controls),
            'declarationSha256':inputs.rows['declaration']['sha256'],
            'files':[inputs.rows[key] for key in sorted(inputs.rows) if key != 'declaration'],
            'symlinks':[{'path':path,'witness':list(fact),'target':target}
                for path,(fact,target) in sorted(inputs.links.items())], 'roles':value['roles'],
            'declaredFileCount':len(files), 'boundFileCount':len(inputs.rows)-1,
            'totalBytes':sum(row['bytes'] for key,row in inputs.rows.items() if key != 'declaration')}
        encoded = canonical(inventory_compact(inventory,clock)); require(len(encoded) <= MAX_METADATA)
        clock.tick()
        directories = inputs.directory_commitments()
        descriptor = {'schemaVersion':2, 'scope':SCOPE, 'context':context,
            'directoryWitnesses':directories,
            'retentionMode':'original-output-base-and-declared-runfiles-only',
            'originalOutputBase':str(base), 'originalRunfilesRoot':str(runfiles),
            'originalControlRunfilesRoot':str(controls),
            'runnerLabel':RUNNER, 'roles':{role:inputs.rows[key] for role,key in value['roles'].items()},
            'declaration':inputs.rows['declaration'],
            'metadata':metadata, 'inventorySha256':hashlib.sha256(encoded).hexdigest(),
            'inventoryBytes':len(encoded), 'originalOuterReceiptJoinRequired':True,
            'freshConsumerQualificationRequired':True, **{flag:False for flag in FALSE}}
        publish(outputs/'yoga-public-toolbar',(('runfiles-inventory.json',encoded),('artifact.json',canonical(descriptor))),clock)
        inputs.recheck(); clock.tick()
        return descriptor
    except BaseException as error: primary = error; raise
    finally:
        inputs.close(primary)
        if primary is None: clock.tick()


REFUSAL_FILES = frozenset(('yoga_public_artifact_prepare.py', 'browser_runtime_authority.py',
    'pack.py', 'portable.py'))
REFUSAL_TYPES = frozenset(('ValueError', 'TypeError', 'KeyError', 'OSError', 'FileNotFoundError',
    'PermissionError', 'MemoryError', 'RuntimeRootError', 'UnicodeDecodeError', 'UnicodeEncodeError',
    'JSONDecodeError', 'BadZipFile', 'AssertionError', 'KeyboardInterrupt', 'SystemExit', 'BrokenPipeError'))


def refusal_diagnostic(error):
    """Bounded code coordinates only; no messages, locals, paths or env values."""
    name = type(error).__name__
    frames = []; selected = error.__traceback__; visited = 0
    while selected is not None and visited < 64:
        code = selected.tb_frame.f_code
        filename = code.co_filename.rsplit('/', 1)[-1]
        function = code.co_name; line = selected.tb_lineno
        if (filename in REFUSAL_FILES and type(function) is str
                and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,95}', function) is not None
                and type(line) is int and 1 <= line <= 100000):
            frames.append({'file':filename, 'function':function, 'line':line})
            if len(frames) > 12: del frames[0]
        visited += 1; selected = selected.tb_next
    return {'errorType':name if name in REFUSAL_TYPES else 'OtherError', 'ownedFrames':frames}


def emit_refusal_diagnostic(error):
    payload = json.dumps(refusal_diagnostic(error),sort_keys=True,separators=(',',':'),ensure_ascii=True)
    if len(payload.encode('ascii')) > 4096:
        return
    print('toolbar-public-preparation-diagnostic '+payload,file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--declaration',required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.declaration,os.environ)
        # The marker is provisional until stdout is actually flushed and the
        # SAME original cutoff is checked. No fresh aggregate clock is created.
        clock = Clock(result['context'])
        print('OMUX_YOGA_CURRENT_PUBLIC_TOOLBAR_PREPARED_NO_EXECUTION')
        sys.stdout.flush()
        clock.tick()
        return 0
    except BaseException as error:
        print('toolbar-public-preparation-refused',file=sys.stderr)
        try: emit_refusal_diagnostic(error)
        except BaseException: pass  # Diagnostics cannot turn refusal into acceptance.
        return 125


if __name__ == '__main__':
    sys.exit(main())
