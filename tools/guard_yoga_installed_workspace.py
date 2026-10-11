"""Closed installed-toolbar inventory admission; never launches a process."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time
import yoga_installed_controller_support as support

SCOPE = 'yoga-installed-toolbar-workspace-v1'
SHA = re.compile(r'[0-9a-f]{64}')
MAX_RECEIPT = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
BUILD_SHA = '0a49b7fa86ca61863c75a312f8cb38d013df3fb832483373c43998e087f8847b'
BUILD_ID = '464e0a75-e0fe-414f-90a6-0909b814da12'
LAUNCHER_SHA = '9d046bf9e418b79a71e20d63f279f0b7bbde7b5bee5a7b3338dac70aebb4fca7'
MANIFEST_SHA = '118e3d5f9ca8b16eb280fad221bb10986d22075a774e73f05c842b2a6e0ed431'
ARTIFACTS = {'bundle': ('3bac456fe3b932dd45a6dddf41311e11728a1ac522b265e7f85348f97c3bf2e3', 59610247),
    'extension': ('0ec74f20b4d9831e760e0e133e4082298413677a1fca7c0f21c95619685dac01', 54966),
    'runtime_authority': ('6364ae0ab63d0c85d81c7cce06abd97e18adff053111272bbf1f4f0f64302700', 287401)}
ORIGIN_SOURCE_SHA = {
    'delivery/browser_runtime_authority.py':'82df5217b0772a8dfcc051cf90f4f8bc124873f9f7684876a91aa6f2c6de8752',
    'delivery/yoga_toolbar_consent.py':'0d8c4f416c24fcf8102aaec05d95072a5d534c4211c85c345c4c880246d85751',
    'delivery/yoga_toolbar_contract.py':'a574aefb6716d3b6a6cdec8ba15c46d87041210501da458896cc15f546e56770',
    'delivery/test_installed_chromium.py':'cce15578539bf72ffbdfc4e2cf84f937c185c7b5cc5bd6a4effc5fb0bdfa265a',
    'delivery/test_installed_custody.py':'af9abefadf9bb3a603faf76d54e8dd23d701d847b3f51c3a5a60bb8a6c40fed4',
    'delivery/install.py':'cdcb12de300a364f7c3b44f48b38da175b728bedb7c0abcbbdea69e20e4f2490',
    'delivery/pack.py':'46ab6d83d2878890838bfaf9948301af92b28ca8c8b6d975617d6acb51711964',
    'delivery/portable.py':'64a6478a8e41d93a71f4ecbdf9ca32e3a39c43c0baefe314b91cc5b93b9e446c',
    'delivery/yoga_wrapper_authority.py':'0f5a9286016f3258d93c0d5d53b18a466b475eb1ba91a4f1dac8bfc53e763c14',
    'delivery/yoga_wrapper_custody.py':'aed152c8974b6368f423df3a02b465bf468a4163c1c796589fc97def4efc9ff1',
    'delivery/chromium_native_recorder.py':'761e5a166199bbfd48e30d85f4005f683c07b3133069d315f360b6ed7e71a436',
    'delivery/yoga_toolbar_native_recorder.py':'a63aba133d72911f54868872dcdf0be1d106d6b2163033bee0c18733e1aba24d',
    'delivery/yoga_toolbar_observer.mjs':'3be025bf590488f2600627bcba1ae81aea2fc0509923485db44814270dd02f3c',
}
SOURCE_READER_SHA = {name:sha for name,sha in ORIGIN_SOURCE_SHA.items() if name not in (
    'delivery/chromium_native_recorder.py','delivery/yoga_toolbar_native_recorder.py','delivery/yoga_toolbar_observer.mjs')}
FIELDS = frozenset(('schemaVersion','scope','origin','buildReceiptSha256','launcherSha256',
    'runfilesManifestSha256','workspaceGraphSha256','sourceFilesSha256','inputSha256',
    'nativeManifestSha256','declaredStoreFiles','declaredRunfiles','controllerPackageSha256',
    'omittedRunfileKeys','workspaceFiles','executionAuthority','destinationRegistrationVerified',
    'seatQualified','toolbarConsentProved','embeddedArtifactProvenanceRewritten'))
ORIGIN_FIELDS = frozenset(('id','artifact_epoch','source_commit','source_dirty','graph_sha256',
    'profile','verb','targets','exit','workload_exit','descendants_empty','controller_failure',
    'output_base','cache_reuse_requested','cache_policy','cache_key','cleanup'))


def require(value):
    if not value:
        raise ValueError('installed-toolbar-inventory-refused')


def tick(deadline):
    require(type(deadline) is int and time.monotonic_ns() < deadline)


def decode(content):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value); value[key] = item
        return value
    return json.loads(content, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('installed-toolbar-inventory-refused')))


def identity(info):
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def relative(name):
    require(type(name) is str and name == str(PurePosixPath(name)) and not name.startswith('/')
            and not {'.','..'}.intersection(name.split('/')) and len(name.encode()) <= 4096
            and not any(ord(char) < 33 or char == '\\' for char in name))
    return name


def workspace_root(value):
    path=Path(value)
    require(str(path).startswith('/srv/') and str(path)==str(value)
            and not {'.','..'}.intersection(str(path).split('/')))
    return path


def shape(record):
    version2 = type(record) is dict and record.get('schemaVersion') == support.SCHEMA
    require(type(record) is dict and set(record) == (FIELDS | {'controllerDeliverySha256'} if version2 else FIELDS)
            and type(record['schemaVersion']) is int
            and record['schemaVersion'] == (support.SCHEMA if version2 else 1)
            and record['scope'] == (support.WORKSPACE_SCOPE if version2 else SCOPE))
    if version2:
        support.record_shape(record['controllerDeliverySha256'], record['workspaceFiles'])
        require('yoga_installed_controller_support.py' in record['controllerPackageSha256'])
    require(type(record['origin']) is dict and set(record['origin']) == ORIGIN_FIELDS)
    require(all(record[name] is False for name in ('executionAuthority','destinationRegistrationVerified',
        'seatQualified','toolbarConsentProved','embeddedArtifactProvenanceRewritten')))
    for name in ('buildReceiptSha256','launcherSha256','runfilesManifestSha256',
                 'workspaceGraphSha256','nativeManifestSha256'):
        require(type(record[name]) is str and SHA.fullmatch(record[name]))
    require(record['buildReceiptSha256'] == BUILD_SHA and record['launcherSha256'] == LAUNCHER_SHA
            and record['runfilesManifestSha256'] == MANIFEST_SHA)
    require(type(record['controllerPackageSha256']) is dict and 0 < len(record['controllerPackageSha256']) <= 512
            and {'execution_guard.py','guard_yoga_installed_workspace.py','guard_yoga_profile.py',
                 'yoga_operator_launch.py','yoga_operator_coordinator.py','yoga_session_qualification.py'}
                 .issubset(record['controllerPackageSha256']))
    require(type(record['workspaceFiles']) is dict and 0 < len(record['workspaceFiles']) <= 1024)
    total = 0
    for name, pin in record['workspaceFiles'].items():
        relative(name)
        require(name != 'installed-workspace.json' and type(pin) is dict and set(pin) == {'sha256','bytes','mode'}
                and type(pin['sha256']) is str and SHA.fullmatch(pin['sha256']) and type(pin['bytes']) is int
                and 0 <= pin['bytes'] <= MAX_TOTAL and type(pin['mode']) is int and pin['mode'] in (0o444,0o555))
        total += pin['bytes']; require(total <= MAX_TOTAL)
    for name, sha in record['controllerPackageSha256'].items():
        require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_-]+\.py',name)
                and type(sha) is str and SHA.fullmatch(sha)
                and record['workspaceFiles'].get('tools/'+name,{}).get('sha256') == sha)
    require({name[6:] for name in record['workspaceFiles'] if name.startswith('tools/') and name.endswith('.py')}
            == set(record['controllerPackageSha256']))
    require(record['sourceFilesSha256'] == SOURCE_READER_SHA)
    for name, sha in ORIGIN_SOURCE_SHA.items():
        require(record['workspaceFiles'].get(name,{}).get('sha256') == sha)
    for name, (sha,size) in ARTIFACTS.items():
        require(record['inputSha256'].get(name) == sha and any(pin['sha256'] == sha and pin['bytes'] == size
                for pin in record['workspaceFiles'].values()))
    require(record['omittedRunfileKeys'] == ['_repo_mapping','_main/delivery/yoga_toolbar_consent_proof.sh'])
    return record


class Capture:
    """Holds every leaf/ancestor until cleanup; receipt SHA is independently selected."""
    def __init__(self, root, selected, deadline, read_file):
        self.deadline, self.files, self.dirs, self.closed = deadline, [], [], False
        self.read_file, self.selected = read_file, selected
        self.root = workspace_root(root); self.record = None
        try:
            require(type(selected) is dict and set(selected) == {'path','sha256'}
                    and selected['path'] == str(self.root/'installed-workspace.json')
                    and type(selected['sha256']) is str and SHA.fullmatch(selected['sha256']))
            # Existing guardian reader proves physical ancestors before reading.
            raw = read_file(selected['path'], MAX_RECEIPT, deadline, expected=selected['sha256'])
            self.record = shape(decode(raw))
            expected = dict(self.record['workspaceFiles'])
            expected['installed-workspace.json'] = {'sha256':selected['sha256'],'bytes':len(raw),'mode':0o444}
            root_fd = os.open(self.root, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.dirs.append((self.root,root_fd,identity(os.fstat(root_fd))))
            self.expected = expected
            found, pending = set(), [('',root_fd)]
            while pending:
                prefix, directory = pending.pop(); tick(deadline)
                info = os.fstat(directory)
                require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
                for leaf in sorted(os.listdir(directory)):
                    tick(deadline); name = leaf if not prefix else prefix+'/'+leaf
                    info = os.stat(leaf,dir_fd=directory,follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        require(any(item.startswith(name+'/') for item in expected))
                        fd = os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
                        self.dirs.append((self.root/name,fd,identity(info)))
                        require(identity(info) == identity(os.fstat(fd)))
                        pending.append((name,fd)); continue
                    require(name in expected and name not in found)
                    pin = expected[name]
                    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                            and info.st_size == pin['bytes'] and stat.S_IMODE(info.st_mode) == pin['mode'])
                    fd = os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
                    self.files.append((self.root/name,fd,identity(info)))
                    require(identity(info) == identity(os.fstat(fd)))
                    digest, count = hashlib.sha256(), 0
                    while True:
                        tick(deadline); data = os.read(fd,65536)
                        if not data: break
                        count += len(data); require(count <= pin['bytes']); digest.update(data)
                    require(count == pin['bytes'] and digest.hexdigest() == pin['sha256']); found.add(name)
            require(found == set(expected)); self.recheck()
            require(self.bytes('origin-build-receipt.json',16*1024*1024) ==
                    read_file(self.root/'origin-build-receipt.json',16*1024*1024,deadline,expected=BUILD_SHA))
            origin = decode(self.bytes('origin-build-receipt.json',16*1024*1024))
            require(type(origin) is dict and all(origin.get(key) == value and type(origin.get(key)) is type(value)
                for key,value in self.record['origin'].items()))
            require(origin.get('id') == BUILD_ID and origin.get('artifact_epoch') == BUILD_ID
                    and origin.get('verb') == 'build' and origin.get('profile') == 'standard'
                    and origin.get('source_commit') == 'c106a52523d2161063a6a58d6d29a8f86039f827'
                    and origin.get('source_dirty') == 'false' and origin.get('exit') == 0
                    and type(origin.get('exit')) is int and origin.get('workload_exit') == 0
                    and type(origin.get('workload_exit')) is int and origin.get('descendants_empty') is True
                    and origin.get('controller_failure') is None
                    and origin.get('targets') == ['//delivery:yoga_toolbar_consent_proof'])
            require(hashlib.sha256(self.bytes('origin-runfiles.MANIFEST',MAX_RECEIPT)).hexdigest() == MANIFEST_SHA
                    and hashlib.sha256(self.bytes('installed-launcher.sh',1024*1024)).hexdigest() == LAUNCHER_SHA)
            reserved = {'guard_yoga_toolbar_reserved.py', 'yoga_reserved_session_qualification.py'}.issubset(
                self.record['controllerPackageSha256'])
            require(not reserved or self.record['schemaVersion'] == support.SCHEMA)
            console_files = {'yoga_local_console_scope.py','yoga_local_console_qualification.py'}
            present_console = console_files.intersection(self.record['controllerPackageSha256'])
            require(not present_console or present_console == console_files)
            console = bool(present_console)
            require(not console or reserved)
            prepare_files = {'yoga_installed_console_selection.py', 'yoga_installed_console_prepare.py',
                             'yoga_local_parent_envelope.py'}
            present_prepare = prepare_files.intersection(self.record['controllerPackageSha256'])
            require(not present_prepare or present_prepare == prepare_files)
            prepare = bool(present_prepare)
            require(not prepare or console)
            targets = ('execution_guard','yoga_session_qualification') + (('yoga_reserved_session_qualification',) if reserved else ()) + (('yoga_local_console_qualification',) if console else ()) + (('yoga_installed_console_prepare',) if prepare else ())
            for target in targets:
                launcher = self.bytes('installed-launcher.sh',1024*1024)
                require(launcher.count(b'_main/delivery/yoga_toolbar_consent.py') == 1
                        and self.bytes(target+'.sh',1024*1024) == launcher.replace(
                            b'_main/delivery/yoga_toolbar_consent.py',('_main/tools/'+target+'.py').encode()))
        except BaseException:
            self.close(); raise

    def bytes(self,name,maximum):
        tick(self.deadline); require(name in self.expected and self.expected[name]['bytes'] <= maximum)
        fd = next(fd for path,fd,_ in self.files if path == self.root/name)
        os.lseek(fd,0,os.SEEK_SET); chunks=[]; count=0
        while True:
            tick(self.deadline); data=os.read(fd,65536)
            if not data: break
            count+=len(data); require(count<=maximum); chunks.append(data)
        content=b''.join(chunks)
        require(count == self.expected[name]['bytes'] and hashlib.sha256(content).hexdigest()==self.expected[name]['sha256'])
        return content

    def recheck(self):
        tick(self.deadline); require(not self.closed)
        # Reprove no-follow physical ancestors before any named-path metadata;
        # a moved original tree behind a newly inserted parent alias refuses.
        require(self.read_file(self.selected['path'],MAX_RECEIPT,self.deadline,
            expected=self.selected['sha256']) == self.bytes('installed-workspace.json',MAX_RECEIPT))
        for path,fd,saved in self.dirs+self.files:
            tick(self.deadline)
            require(identity(os.fstat(fd)) == saved == identity(os.stat(path,follow_symlinks=False)))
        require({name for name in os.listdir(self.dirs[0][1])} ==
            {PurePosixPath(name).parts[0] for name in self.expected})
        for path,fd,_ in self.dirs:
            relative_dir=path.relative_to(self.root)
            expected={PurePosixPath(name).relative_to(relative_dir).parts[0] for name in self.expected
                      if PurePosixPath(name).is_relative_to(relative_dir)}
            require(set(os.listdir(fd)) == expected)

    def qualify(self,value,graph_sha256):
        require(self.record['workspaceGraphSha256'] == graph_sha256
                and value['sourceFilesSha256'] == self.record['sourceFilesSha256']
                and value['inputSha256'] == self.record['inputSha256']
                and value['vaultWrapperAuthority']['nativeManifest']['sha256'] == self.record['nativeManifestSha256'])
        # Each declared non-store workload input must be an actual inventory file;
        # immutable store executables retain runtime_qualification's exact roots.
        for name,path in value['inputPaths'].items():
            if str(path).startswith('/nix/store/'):
                require(name in ('chromium','node')); continue
            relative_path=str(Path(path).relative_to(self.root))
            require(relative_path in self.expected and self.expected[relative_path]['sha256'] == value['inputSha256'][name])
        manifest=Path(value['vaultWrapperAuthority']['nativeManifest']['path'])
        relative_manifest=str(manifest.relative_to(self.root))
        require(self.expected.get(relative_manifest,{}).get('sha256') == self.record['nativeManifestSha256'])
        # The actual modules loaded by guard/session/worker are the copied,
        # inventory-pinned siblings, rather than another mutable tools checkout.
        require(Path(__file__).resolve().parent == self.root/'tools')
        import sys
        if self.record['schemaVersion'] == support.SCHEMA:
            support.loaded_modules(self.root, self.record['controllerDeliverySha256'], tuple(sys.modules.values()))
        for module in tuple(sys.modules.values()):
            filename=getattr(module,'__file__',None)
            if not filename or not str(filename).endswith('.py'): continue
            path=Path(filename).resolve()
            if path.name in self.record['controllerPackageSha256']:
                require(path.parent == self.root/'tools')
        require(self.record['controllerPackageSha256']['guard_yoga_installed_workspace.py'] ==
                hashlib.sha256(self.bytes('tools/guard_yoga_installed_workspace.py',1024*1024)).hexdigest())
        self.recheck(); return True

    def close(self):
        if not self.closed:
            self.closed=True
            for _,fd,_ in reversed(self.files+self.dirs): os.close(fd)
            self.files,self.dirs=[],[]

    def projection(self,verified_after_cleanup):
        require(type(verified_after_cleanup) is bool)
        return {'scope':'yoga-installed-toolbar-inventory-v1',
            'workspace_receipt_sha256':self.selected['sha256'],
            'workspace_graph_sha256':self.record['workspaceGraphSha256'],
            'origin_build_receipt_sha256':BUILD_SHA,
            'origin_source_commit':self.record['origin']['source_commit'],
            'origin_graph_sha256':self.record['origin']['graph_sha256'],
            'whole_inventory_verified_after_cleanup':verified_after_cleanup,
            'controller_source_files':len(self.record['controllerPackageSha256']),
            'embedded_artifact_provenance_rewritten':False}


def verified(admission):
    capture=admission.get('installedCapture')
    require(type(capture) is Capture and capture.qualify(admission['receipt'],
            admission['receipt']['sourceGraphSha256']) is True)
    return True
