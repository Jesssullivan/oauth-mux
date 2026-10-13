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
SCOPE = 'yoga-current-public-toolbar-retained-v1'
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


def decode(raw):
    def unique(rows):
        result = {}
        for key, value in rows:
            require(key not in result); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-json')))


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


class Owned(list):
    def enroll(self, fd):
        try: self.append(fd)
        except BaseException as primary:
            if fd not in self:
                try: os.close(fd)
                except BaseException as cleanup: raise primary from cleanup
            raise
        return fd

    def adopt(self, fd, prior):
        # Until insertion succeeds the prior registry remains the owner. A
        # post-insertion exception transfers that one owner, never closes it
        # in two different finally paths.
        try: self.append(fd)
        except BaseException:
            if fd in self: prior.remove(fd)
            raise
        prior.remove(fd)

    def drain(self, primary=None):
        failure = None
        while self:
            fd = self.pop()
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
        self.roots = [self.output_base, self.source]
        self.owned = Owned()
        self.rows, self.held, self.links = {}, {}, {}
        self.total = 0
        require(self.output_base.is_absolute() and self.source.is_absolute())
        for root in self.roots:
            require(root.resolve(strict=True) == root and stat.S_ISDIR(root.lstat().st_mode))
        self.root_facts = {str(root):witness(root.lstat())[:5] for root in self.roots}

    def allowed(self, path):
        return any(path == root or path.is_relative_to(root) for root in self.roots)

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
                self.roots.append(Path(value))
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
            directory = owners.enroll(os.open(parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC))
            parent_fact = witness(os.fstat(directory))
            require(parent_fact == witness(parent.lstat()))
            fd = owners.enroll(os.open(physical.name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC, dir_fd=directory))
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


def publish(product, values, clock):
    """Closed metadata outputs only; failure never becomes producer success."""
    clock.tick(); os.mkdir(product,mode=0o700)
    owners=Owned(); primary=None; rows=[]
    try:
        parent=owners.enroll(os.open(product,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC))
        for name, raw in values:
            clock.tick(); require(name in ('artifact.json','runfiles-inventory.json') and len(raw)<=MAX_METADATA)
            fd=owners.enroll(os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent))
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
        path = Path(declaration_path)
        require(path.is_relative_to(action_controls))
        raw = inputs.read('declaration', path, controls/path.relative_to(action_controls), content=True, maximum=MAX_METADATA)
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
        inputs.root_facts[str(runfiles)] = witness(runfiles.lstat())
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
        encoded = canonical(inventory); require(len(encoded) <= MAX_METADATA)
        descriptor = {'schemaVersion':1, 'scope':SCOPE, 'context':context,
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
