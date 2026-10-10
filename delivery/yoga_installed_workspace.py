"""One fixed installed-toolbar Bazel workspace; no compiler or host dispatch.

Proposal only. Intended declared producer: //delivery:yoga_installed_workspace.
Root selects the public prebuilt launcher/runfiles manifest and their hashes.
Its output still requires independent local guard/seat/runtime qualification.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

import yoga_payload as payload
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))
import yoga_installed_controller_support as support

LABEL = '//delivery:yoga_toolbar_consent_proof'
BUILD_ID = '464e0a75-e0fe-414f-90a6-0909b814da12'
BUILD_SHA = '0a49b7fa86ca61863c75a312f8cb38d013df3fb832483373c43998e087f8847b'
SOURCE_COMMIT = 'c106a52523d2161063a6a58d6d29a8f86039f827'
SOURCE_GRAPH = '69cf8d93377472dfd0eedad16a4d3d814585f0d486827a84a791e978ccbf6207'
OUTPUT_BASE = '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/cache-v2-39f2eb3574f1f88de5326867c7d8ef4bc518faba8cb6b2048f84613edac8947d/output-base'
SOURCE_ROOT = '/srv/fast-local/jess/git/oauth-mux-browser-inputs-20261008'
PUBLIC_STAGING = '/srv/fast-local/jess/state/codex/omux-installed-toolbar-public-20261008'
BUILD_RECEIPT = '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/' + BUILD_ID + '/receipt.json'
INVENTORY_SHA = {
    'browserInventory': '1c1d555f3124479d30972c05ce025f6d0f008dffb25698e085524421e16ac931',
    'controllerInventory': '2be4ecfe05837c67a7267aa216dbae683f2d44d07e96198d3475f3fbd124c7f8',
}
LAUNCHER_SHA = '9d046bf9e418b79a71e20d63f279f0b7bbde7b5bee5a7b3338dac70aebb4fca7'
MANIFEST_SHA = '118e3d5f9ca8b16eb280fad221bb10986d22075a774e73f05c842b2a6e0ed431'
LAUNCH_ARGS = ['--bundle', 'delivery/release_archive.tar.gz', '--extension', 'extensions/chromium_dev_package.zip',
    '--chromium', '../+cached_site_repository+omux_cached_site/packages/chromium/bin/chromium',
    '--node', '../+cached_site_repository+omux_cached_site/packages/node/bin/node',
    '--observer', 'delivery/yoga_toolbar_observer.mjs',
    '--dbus-session', '../+omux_nix_repository+omux_nix/dbus_run_session',
    '--dbus-daemon', '../+omux_nix_repository+omux_nix/dbus_daemon',
    '--keyring', '../+omux_nix_repository+omux_nix/gnome_keyring_daemon',
    '--runtime-authority', 'delivery/qualified_browser_runtime.json',
    '--recorder', 'delivery/yoga_toolbar_native_recorder.py',
    '--recorder-implementation', 'delivery/chromium_native_recorder.py',
    '--tool-manifest', '../+omux_nix_repository+omux_nix/native.json']
ORIGIN_FILES = frozenset('delivery/' + name for name in (
    'browser_runtime_authority.py', 'yoga_toolbar_consent.py', 'yoga_toolbar_contract.py',
    'test_installed_chromium.py', 'test_installed_custody.py', 'install.py', 'pack.py',
    'portable.py', 'yoga_wrapper_authority.py', 'yoga_wrapper_custody.py'))
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
ARTIFACTS = {
    'bundle': ('3bac456fe3b932dd45a6dddf41311e11728a1ac522b265e7f85348f97c3bf2e3', 59610247),
    'extension': ('0ec74f20b4d9831e760e0e133e4082298413677a1fca7c0f21c95619685dac01', 54966),
    'runtime_authority': ('6364ae0ab63d0c85d81c7cce06abd97e18adff053111272bbf1f4f0f64302700', 287401),
}
MAX_MANIFEST = 64 * 1024 * 1024
MAX_ENTRIES = 250000
MAX_COPIED = 256 * 1024 * 1024
SCOPE = 'yoga-installed-toolbar-workspace-v1'


def require(value):
    if not value:
        raise ValueError('installed-toolbar-workspace-refused')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def decode(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('installed-toolbar-workspace-refused')))


_MEASURED_PUBLIC_INPUT = object()
_ASSEMBLY_COORD = '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005'
_ASSEMBLY_COORDS = (Path(_ASSEMBLY_COORD), Path('/home/jess/.local/state/omux-execution-20261005'))
_ASSEMBLY_UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
_ASSEMBLY_REPOS = {'browserInventory': '+cached_site_repository+omux_cached_site',
                   'controllerInventory': '+cached_nar_repository+omux_yoga_controller_nars'}


def assembly_base(path, *, child=False):
    """Only a fresh epoch in one of the guard's two already-admitted roots."""
    require(type(child) is bool)
    path = source_path(str(path))
    matches = [root for root in _ASSEMBLY_COORDS if path.is_relative_to(root)]
    require(len(matches) == 1)
    parts = path.relative_to(matches[0]).parts
    require(len(parts) > 2 if child else len(parts) == 2)
    require(_ASSEMBLY_UUID.fullmatch(parts[0]) is not None and parts[1] == 'output-base')
    return matches[0] / parts[0] / 'output-base'


class AssemblyContext:
    """Hold private root/epoch and their exact no-follow output-base identity."""
    def __init__(self, base, until):
        self.base = assembly_base(base)
        self.until, self.directories = until, []
        try:
            for path, private in ((self.base.parent.parent, True), (self.base.parent, True), (self.base, False)):
                payload.budget(until)
                descriptor = payload.parent(path / 'placeholder')
                self.directories.append((path, descriptor, None, private))
                info = os.fstat(descriptor)
                self.owned(info, private)
                self.directories[-1] = (path, descriptor, self.identity(info), private)
            self.recheck()
        except BaseException:
            self.close(); raise

    @staticmethod
    def identity(info):
        return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode

    @staticmethod
    def owned(info, private):
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and (stat.S_IMODE(info.st_mode) == 0o700 if private else not info.st_mode & 0o022))

    def recheck(self):
        require(len(self.directories) == 3)
        require(assembly_base(self.base) == self.base
            and tuple(path for path, _, _, _ in self.directories)
                == (self.base.parent.parent, self.base.parent, self.base))
        for path, descriptor, saved, private in self.directories:
            payload.budget(self.until)
            current = payload.parent(path / 'placeholder')
            try:
                held, named = os.fstat(descriptor), os.fstat(current)
                self.owned(held, private); self.owned(named, private)
                require(saved == self.identity(held) == self.identity(named))
            finally:
                os.close(current)

    def close(self):
        directories, self.directories = self.directories, []
        for _, descriptor, _, _ in reversed(directories):
            os.close(descriptor)


class PhysicalCapture:
    """No alias resolution between authorization and the held no-follow open."""
    def __init__(self, path, expected, maximum, until, *, controller_root=None,
                 declared_inventory=None, store_roots=None, _assembly_context=None):
        self.path = source_path(str(path))
        require(_assembly_context is None or (declared_inventory is not None
            and type(_assembly_context) is AssemblyContext))
        self.assembly_context = _assembly_context
        if declared_inventory is not None:
            require(declared_inventory in _ASSEMBLY_REPOS and expected == INVENTORY_SHA[declared_inventory])
            if _assembly_context is None:
                # Preserve historical standard capture authorization unchanged.
                require(re.fullmatch(re.escape(_ASSEMBLY_COORD) + r'/(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|cache-v2-[0-9a-f]{64})/output-base/external/'
                    + re.escape(_ASSEMBLY_REPOS[declared_inventory]) + r'/inventory\.json', str(self.path)))
            else:
                require(self.path == _assembly_context.base / 'external' / _ASSEMBLY_REPOS[declared_inventory] / 'inventory.json')
                _assembly_context.recheck()
        elif store_roots is not None:
            require(type(store_roots) is frozenset and expected is not _MEASURED_PUBLIC_INPUT
                    and str(self.path).startswith('/nix/store/')
                    and str(Path(*self.path.parts[:4])) in store_roots)
        elif controller_root is None:
            public_capture_path(str(path))
        else:
            require(self.path.parent == controller_root and self.path.suffix == '.py')
        self.sha, self.until = (None if expected is _MEASURED_PUBLIC_INPUT else expected), until
        self.fd, self.parent = None, None
        try:
            require(expected is _MEASURED_PUBLIC_INPUT or (type(expected) is str and payload.SHA.fullmatch(expected)))
            payload.budget(until)
            self.parent = payload.parent(self.path)
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                              dir_fd=self.parent)
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid())
                    and not info.st_mode & 0o022 and (info.st_nlink >= 1 if store_roots is not None else info.st_nlink == 1)
                    and 0 <= info.st_size <= maximum)
            if store_roots is not None:
                require(info.st_uid == 0 and not info.st_mode & 0o222)
            self.identity, self.size = payload.identity(info), info.st_size
            self.bytes(maximum)
        except BaseException:
            self.close(); raise

    def check(self):
        payload.budget(self.until)
        if self.assembly_context is not None:
            self.assembly_context.recheck()
        named = payload.parent(self.path)
        try:
            require(payload.identity(os.fstat(self.fd)) == self.identity
                    and payload.identity(os.stat(self.path.name, dir_fd=named, follow_symlinks=False)) == self.identity)
            held_parent, named_parent = os.fstat(self.parent), os.fstat(named)
            require((held_parent.st_dev, held_parent.st_ino, held_parent.st_uid, held_parent.st_mode) ==
                    (named_parent.st_dev, named_parent.st_ino, named_parent.st_uid, named_parent.st_mode))
        finally:
            os.close(named)

    def bytes(self, maximum):
        require(self.size <= maximum)
        os.lseek(self.fd, 0, os.SEEK_SET)
        content = bytearray()
        while len(content) < self.size:
            payload.budget(self.until); block = os.read(self.fd, min(65536, self.size - len(content)))
            require(block); content.extend(block)
        self.check()
        observed = hashlib.sha256(content).hexdigest()
        if self.sha is None:
            self.sha = observed
        else:
            require(observed == self.sha)
        return bytes(content)

    @classmethod
    def measure(cls, path, maximum, until, *, controller_root=None):
        # Only the closed assembler uses this internal measurement token.
        # Normal pinned captures still reject None/malformed expected hashes.
        return cls(path, _MEASURED_PUBLIC_INPUT, maximum, until, controller_root=controller_root)

    def close(self):
        for name in ('fd', 'parent'):
            fd = getattr(self, name)
            if fd is not None:
                setattr(self, name, None); os.close(fd)


def source_path(value):
    require(type(value) is str and str(Path(value)) == value and value.startswith('/')
            and not {'.', '..'}.intersection(value.split('/'))
            and not any(ord(char) < 32 or char == '\\' for char in value)
            and len(os.fsencode(value)) <= 4096)
    return Path(value)


def public_capture_path(value):
    """Refuse personal/runtime metadata before even consulting a parent."""
    path = source_path(value)
    require(path == Path(BUILD_RECEIPT) or any(path.is_relative_to(root)
        and path != Path(root) for root in (PUBLIC_STAGING, OUTPUT_BASE, SOURCE_ROOT)))
    return path


def origin(receipt):
    expected = {'id': BUILD_ID, 'artifact_epoch': BUILD_ID, 'source_commit': SOURCE_COMMIT,
        'source_dirty': 'false', 'graph_sha256': SOURCE_GRAPH, 'profile': 'standard',
        'verb': 'build', 'targets': [LABEL], 'exit': 0, 'workload_exit': 0,
        'descendants_empty': True, 'controller_failure': None, 'output_base': OUTPUT_BASE,
        'cache_reuse_requested': True, 'cache_policy': 2,
        'cache_key': '39f2eb3574f1f88de5326867c7d8ef4bc518faba8cb6b2048f84613edac8947d'}
    require(type(receipt) is dict and all(receipt.get(key) == value
            and type(receipt.get(key)) is type(value) for key, value in expected.items()))
    require(receipt.get('cleanup') == {'ownership': 'unproved', 'readback_attempts': 0,
                                     'state': 'empty', 'stop': 'not-requested'})
    # Preserve the actual producer limitation rather than claiming owned cleanup.
    return dict(expected, cleanup=receipt['cleanup'])


def manifest_field(raw, *, logical):
    # Bazel 9.0.1 SourceManifestAction: logical fields escape space/newline/
    # backslash; physical fields escape only newline/backslash. Decode once,
    # then the existing canonical path restrictions still reject controls and
    # backslashes. Never interpret an escape introduced by this decoder.
    escapes = {"n": "\n", "b": "\\"}
    if logical:
        escapes["s"] = " "
    decoded, index = [], 0
    while index < len(raw):
        char = raw[index]
        if char == "\\":
            index += 1
            require(index < len(raw) and raw[index] in escapes)
            char = escapes[raw[index]]
        decoded.append(char)
        index += 1
    return "".join(decoded)


def manifest(data):
    require(type(data) is bytes and 0 < len(data) <= MAX_MANIFEST)
    result = {}
    for line in data.decode('utf-8', 'strict').splitlines():
        require(line)
        escaped = line.startswith(' ')
        record = line[1:] if escaped else line
        require(record and not record.startswith(' ') and ' ' in record)
        key, target = record.split(' ', 1)
        if escaped:
            require('\\' in key or '\\' in target)
            key = manifest_field(key, logical=True)
            target = manifest_field(target, logical=False)
        logical = PurePosixPath(key)
        if key == '_main/delivery/yoga_toolbar_consent_proof.sh':
            require(target == OUTPUT_BASE + '/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/yoga_toolbar_consent_proof.sh')
            continue  # Bazel supplies this new rule's executable at the same key.
        if key == '_repo_mapping':
            require(target == OUTPUT_BASE + '/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/yoga_toolbar_consent_proof.sh.repo_mapping')
            continue  # This fixed launcher uses literal runfile keys, never repository mapping.
        require(key == str(logical) and not logical.is_absolute()
                and not {'.', '..'}.intersection(logical.parts) and len(key.encode()) <= 4096
                and not any(ord(char) < 32 or char == '\\' for char in key)
                and key not in result and len(result) < MAX_ENTRIES)
        result[key] = str(source_path(target))
    require(all('_main/' + path in result for path in ORIGIN_FILES))
    return result


def selected(value):
    fields = {'schemaVersion', 'scope', 'buildReceipt', 'launcher', 'runfilesManifest',
              'inputPaths', 'inputSha256', 'nativeManifest', 'nativeManifestSha256',
              'browserInventory', 'controllerInventory', 'fileSha256', 'controllerPackage'}
    version2 = type(value) is dict and value.get('schemaVersion') == support.SCHEMA
    if version2:
        fields.add('controllerDelivery')
    require(type(value) is dict and set(value) == fields and type(value['schemaVersion']) is int
            and value['schemaVersion'] == (support.SCHEMA if version2 else 1)
            and value['scope'] == (support.SELECTION_SCOPE if version2 else 'yoga-installed-toolbar-selection-v1'))
    if version2:
        support.support(value['controllerDelivery'])
        support.controller(value['controllerPackage'], support.ROOT)
        require('yoga_installed_controller_support.py' in value['controllerPackage'].get('files', {}))
    for name in ('buildReceipt', 'launcher', 'runfilesManifest', 'browserInventory', 'controllerInventory'):
        pin = value[name]
        require(type(pin) is dict and set(pin) == {'path', 'sha256'} and payload.SHA.fullmatch(pin['sha256']))
        public_capture_path(pin['path'])
    require(value['buildReceipt']['sha256'] == BUILD_SHA
            and value['buildReceipt']['path'] == BUILD_RECEIPT)
    for name in INVENTORY_SHA:
        filename = 'browser-inventory.json' if name == 'browserInventory' else 'controller-inventory.json'
        require(value[name]['path'] == PUBLIC_STAGING + '/' + filename
                and value[name]['sha256'] == INVENTORY_SHA[name])
    launcher = Path(OUTPUT_BASE) / 'execroot/_main/bazel-out/k8-fastbuild/bin/delivery/yoga_toolbar_consent_proof.sh'
    require(value['launcher']['path'] == str(launcher)
            and value['launcher']['sha256'] == LAUNCHER_SHA
            and value['runfilesManifest']['sha256'] == MANIFEST_SHA
            and value['runfilesManifest']['path'] in (str(launcher) + '.runfiles_manifest',
                                                      str(launcher) + '.runfiles/MANIFEST'))
    require(type(value['inputPaths']) is dict and set(value['inputPaths']) == payload.INPUTS
            and type(value['inputSha256']) is dict and set(value['inputSha256']) == payload.INPUTS)
    for name in payload.INPUTS:
        source_path(value['inputPaths'][name])
        require(type(value['inputSha256'][name]) is str and payload.SHA.fullmatch(value['inputSha256'][name]))
    for name, (digest, _) in ARTIFACTS.items():
        require(value['inputSha256'][name] == digest
                and Path(value['inputPaths'][name]).is_relative_to(Path(OUTPUT_BASE) / 'execroot/_main/bazel-out'))
    require(type(value['nativeManifestSha256']) is str and payload.SHA.fullmatch(value['nativeManifestSha256']))
    source_path(value['nativeManifest'])
    require(Path(value['nativeManifest']).name == 'native.json'
            and Path(value['nativeManifest']).is_relative_to(OUTPUT_BASE))
    require(type(value['fileSha256']) is dict and 0 < len(value['fileSha256']) <= 256
            and all(type(key) is str and type(sha) is str and payload.SHA.fullmatch(sha)
                    for key, sha in value['fileSha256'].items()))
    package = value['controllerPackage']
    require(type(package) is dict and set(package) == {'root', 'files'}
            and type(package['root']) is str and re.fullmatch(
                r'/srv/fast-local/jess/git/oauth-mux(?:-[A-Za-z0-9_-]{1,100})?/tools', package['root']))
    source_path(package['root'])
    require(type(package['files']) is dict and 0 < len(package['files']) <= 512
            and all(type(name) is str and re.fullmatch(r'[A-Za-z0-9_-]+\.py', name)
                    and type(pin) is dict and set(pin) == {'sha256', 'bytes'}
                    and type(pin['sha256']) is str and payload.SHA.fullmatch(pin['sha256'])
                    and type(pin['bytes']) is int and 0 < pin['bytes'] <= 1024 * 1024
                    for name, pin in package['files'].items()))
    require({'execution_guard.py', 'guard_yoga_profile.py', 'guard_yoga_installed_workspace.py',
        'yoga_session_qualification.py', 'yoga_operator_coordinator.py', 'yoga_operator_launch.py',
        'yoga_proof_inputs.py', 'yoga_display_binding.py', 'guard_cache.py',
        'system_mask_policy.py'}.issubset(package['files']))
    return value


RULE = '''"""Fixed prebuilt executable/runfiles declaration; no executable action."""
def _impl(ctx):
    # Data paths and names are generated by the separately pinned producer.
    mapped = {key: ctx.attr.assets[int(index)].files.to_list()[0] for key, index in ctx.attr.entries.items()}
    launcher = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.symlink(output = launcher, target_file = ctx.file.launcher, is_executable = True)
    return [DefaultInfo(executable = launcher, runfiles = ctx.runfiles(root_symlinks = mapped))]
installed_toolbar = rule(implementation = _impl, executable = True, attrs = {
    "launcher": attr.label(allow_single_file = True, mandatory = True),
    "assets": attr.label_list(allow_files = True),
    "entries": attr.string_dict(mandatory = True),
})
'''


REPOSITORY = '''"""Exact selected store-file data aliases; no fetch or executable."""
def _impl(ctx):
    files = json.decode(ctx.read(ctx.path(ctx.attr.manifest)))
    for key, path in files.items():
        if not path.startswith("/nix/store/") or "/../" in path:
            fail("selected registered store file required")
        ctx.symlink(path, key)
    ctx.file("BUILD.bazel", 'package(default_visibility = ["//visibility:public"])\\nexports_files(' + repr(sorted(files.keys())) + ')\\n')
installed_store_files = repository_rule(implementation = _impl,
    attrs = {"manifest": attr.label(allow_single_file = True, mandatory = True)}, local = True)
'''


def build_files(mapping, copied, store, *, reserved=False):
    assets, entries, positions = [], {}, {}
    for index, key in enumerate(sorted(mapping)):
        alias = 'f%06d' % index
        name = copied.get(alias)
        label = ('@installed_store//:' + alias if alias in store else
                 '//delivery:' + name[len('delivery/'):] if name.startswith('delivery/') else
                 '//tools:' + name[len('tools/'):] if name.startswith('tools/') else '//:' + name)
        if label not in positions:
            positions[label] = len(assets); assets.append(label)
        entries[key] = str(positions[label])
    # Reuse the original generated launcher verbatim, including its fixed args.
    # sourceRoot remains this fixture; source generation identity is separate.
    module = 'module(name = "omux_installed_toolbar")\n'
    module += 'store = use_repo_rule("//tools:installed_store_files.bzl", "installed_store_files")\n'
    module += 'store(name = "installed_store", manifest = "//:installed-store-files.json")\n'
    root_paths = {name for name in copied.values() if not name.startswith(('delivery/', 'tools/'))}
    root = 'exports_files(' + repr(sorted(root_paths | {'installed-launcher.sh', 'installed-store-files.json',
        'yoga_session_qualification.sh', 'execution_guard.sh'} |
        ({'yoga_reserved_session_qualification.sh'} if reserved else set()))) + ')\n'
    delivery = 'load("//tools:installed_toolbar.bzl", "installed_toolbar")\n'
    delivery += 'exports_files(' + repr(sorted({name[len('delivery/'):] for name in copied.values()
                                               if name.startswith('delivery/')})) + ')\n'
    delivery += 'installed_toolbar(name = "yoga_toolbar_consent_proof", launcher = "//:installed-launcher.sh",\n'
    delivery += '    assets = ' + repr(assets) + ', entries = ' + repr(entries) + ', args = ' + repr(LAUNCH_ARGS) + ')\n'
    tools = 'load(":installed_toolbar.bzl", "installed_toolbar")\n'
    tools += 'exports_files(' + repr(sorted({'installed_toolbar.bzl','installed_store_files.bzl'} |
        {name[len('tools/'):] for name in copied.values() if name.startswith('tools/')})) + ')\n'
    targets = ('yoga_session_qualification', 'execution_guard') + (('yoga_reserved_session_qualification',) if reserved else ())
    for target in targets:
        tools += 'installed_toolbar(name = ' + repr(target) + ', launcher = "//:' + target + '.sh", assets = ' + repr(assets) + ', entries = ' + repr(entries) + ')\n'
    return {'MODULE.bazel': module.encode(), 'BUILD.bazel': root.encode(),
        'delivery/BUILD.bazel': delivery.encode(), 'tools/BUILD.bazel': tools.encode(),
        'tools/installed_toolbar.bzl': RULE.encode(), 'tools/installed_store_files.bzl': REPOSITORY.encode(),
        'installed-store-files.json': canonical(store)}


class _ResolverRoots(tuple):
    """Immutable lexical membership only; never a resolved-path/file cache."""
    __slots__ = ()

    def __new__(cls, roots):
        selected = frozenset(Path(root) for root in roots)
        ancestors = frozenset(parent for root in selected for parent in root.parents)
        return tuple.__new__(cls, (selected, ancestors))

    def contains(self, candidate, parents):
        return candidate in self[0] or any(parent in self[0] for parent in parents)

    def related(self, candidate, parents):
        return candidate in self[1] or self.contains(candidate, parents)


def resolver_roots(roots):
    return _ResolverRoots(roots)


def safe_resolve(target, roots, *, declared_paths=(), _trace=None):
    """Bound every symbolic hop to the selected public BUILD/source/store roots."""
    candidate_class, link_form, hops = 'unobserved', 'unobserved', 0
    def trace(operation):
        if _trace is not None:
            _trace(operation, candidate_class, link_form, hops)
    trace('path-shape')
    target = source_path(str(target))
    trace('declaration-type')
    require(type(declared_paths) is tuple)
    store = roots if type(roots) is _ResolverRoots else resolver_roots(roots)
    declared = {source_path(str(path)) for path in declared_paths}
    declared_index = resolver_roots(declared)
    historical = resolver_roots((Path(OUTPUT_BASE), Path(SOURCE_ROOT)))
    def classify(candidate, parents):
        if candidate in declared: return 'declared-leaf'
        if candidate in declared_index[1]: return 'declared-ancestor'
        if declared_index.contains(candidate, parents): return 'declared-descendant'
        for root, name in ((Path(OUTPUT_BASE), 'historical-output'), (Path(SOURCE_ROOT), 'historical-source')):
            if candidate == root or root in candidate.parents or candidate in root.parents: return name
        if store.related(candidate, parents): return 'store'
        return 'outside'
    pending, current, hops = list(Path(target).parts[1:]), Path('/'), 0
    while pending:
        part = pending.pop(0)
        if part == '.':
            continue
        if part == '..':
            current = current.parent; continue
        candidate = current / part
        parents = tuple(candidate.parents)
        if _trace is not None: candidate_class = classify(candidate, parents)
        trace('namespace-fence')
        require(historical.related(candidate, parents) or store.related(candidate, parents)
            or declared_index.related(candidate, parents))
        trace('lstat')
        info = os.lstat(candidate)
        if stat.S_ISLNK(info.st_mode):
            hops += 1
            if _trace is not None: link_form = 'unobserved'
            trace('symlink-limit')
            require(hops <= 64)
            trace('readlink')
            raw = os.readlink(candidate)
            if _trace is not None:
                link_form = 'absolute' if raw.startswith('/') else 'relative-parent' if '..' in raw.split('/') else 'relative'
            trace('symlink-text')
            require(not any(ord(char) < 32 for char in raw))
            absolute = raw if raw.startswith('/') else str(candidate.parent / raw)
            # Keep .. until after preceding directory symlinks have resolved.
            pending = absolute.split('/')[1:] + pending; current = Path('/')
        else:
            current = candidate
    parents = tuple(current.parents)
    if _trace is not None: candidate_class = classify(current, parents)
    trace('final-namespace-fence')
    require(historical.contains(current, parents) or store.contains(current, parents)
        or declared_index.contains(current, parents))
    return current


def graph(files):
    fixed = {'BUILD', 'BUILD.bazel', 'MODULE.bazel', 'MODULE.bazel.lock', 'WORKSPACE', 'WORKSPACE.bazel',
             'flake.nix', 'flake.lock', '.bazelrc', '.bazelversion'}
    hashed = hashlib.sha256()
    for name in sorted(files):
        path = PurePosixPath(name)
        if path.name in fixed or path.suffix in ('.bzl', '.nix') or (path.parts[0] == 'tools'
                and path.suffix in ('.py', '.json', '.patch', '.zig', '.h')):
            hashed.update(name.encode() + b'\0' + hashlib.sha256(files[name]).digest())
    return hashed.hexdigest()


def verify_output(root_fd, files, modes, until):
    """Reread this producer's exact no-follow output inventory before success."""
    expected_dirs = {str(parent) for name in files for parent in PurePosixPath(name).parents
                     if str(parent) != '.'}
    found, pending = set(), [('', os.dup(root_fd))]
    try:
        while pending:
            relative, directory = pending.pop()
            try:
                for leaf in sorted(os.listdir(directory)):
                    payload.budget(until)
                    name = leaf if not relative else relative + '/' + leaf
                    info = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        require(name in expected_dirs and info.st_uid == os.getuid()
                                and stat.S_IMODE(info.st_mode) == 0o700)
                        pending.append((name, os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                                      dir_fd=directory)))
                        continue
                    require(name in files and name not in found and stat.S_ISREG(info.st_mode)
                            and info.st_uid == os.getuid() and info.st_nlink == 1
                            and stat.S_IMODE(info.st_mode) == modes.get(name, 0o444)
                            and info.st_size == len(files[name]))
                    fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                    try:
                        require(payload.identity(os.fstat(fd)) == payload.identity(info))
                        hashed, size = hashlib.sha256(), 0
                        while True:
                            payload.budget(until); block = os.read(fd, 65536)
                            if not block:
                                break
                            size += len(block); require(size <= len(files[name])); hashed.update(block)
                        require(size == len(files[name]) and hashed.digest() == hashlib.sha256(files[name]).digest()
                                and payload.identity(os.fstat(fd)) == payload.identity(info)
                                and payload.identity(os.stat(leaf, dir_fd=directory, follow_symlinks=False)) == payload.identity(info))
                    finally:
                        os.close(fd)
                    found.add(name)
            finally:
                os.close(directory)
        require(found == set(files))
    finally:
        for _, directory in pending:
            os.close(directory)


def produce(selection_path, selection_sha256, output, deadline_ns):
    require(type(deadline_ns) is int and 30 * 10**9 < deadline_ns - time.monotonic_ns() <= 1200 * 10**9)
    until = (deadline_ns - 30 * 10**9) / 10**9
    root = source_path(output)
    require(root == Path(PUBLIC_STAGING) / 'outputs/workspace'
            and source_path(selection_path) == Path(PUBLIC_STAGING) / 'selection.json')
    # Public namespace refusal precedes held no-follow metadata/file reads.
    with ExitStack() as stack:
        def capture(path, digest, maximum, **options):
            held = PhysicalCapture(path, digest, maximum, until, **options)
            stack.callback(held.close)
            return held
        picked = capture(selection_path, selection_sha256, payload.MAX_METADATA)
        selection = selected(decode(picked.bytes(payload.MAX_METADATA)))
        receipt = capture(selection['buildReceipt']['path'], BUILD_SHA, payload.MAX_METADATA)
        origin_projection = origin(decode(receipt.bytes(payload.MAX_METADATA)))
        launch = capture(selection['launcher']['path'], selection['launcher']['sha256'], 1024 * 1024)
        captured_manifest = capture(selection['runfilesManifest']['path'], selection['runfilesManifest']['sha256'], MAX_MANIFEST)
        mapping = manifest(captured_manifest.bytes(MAX_MANIFEST))
        files = {'installed-launcher.sh': launch.bytes(1024 * 1024),
                 'origin-build-receipt.json': receipt.bytes(payload.MAX_METADATA),
                 'origin-runfiles.MANIFEST': captured_manifest.bytes(MAX_MANIFEST)}
        require(len(files['installed-launcher.sh']) == 5339
                and files['installed-launcher.sh'].startswith(
                    b'#!/nix/store/4bwbk4an4bx7cb8xwffghvjjyfyl7m2i-bash-interactive-5.3p9/bin/bash\n'))
        modes = {'installed-launcher.sh': 0o555}
        copied, store, captures, total = {}, {}, [picked, receipt, launch, captured_manifest], sum(map(len, files.values()))
        inventories = []
        for name in ('browserInventory', 'controllerInventory'):
            pin = selection[name]; held = capture(pin['path'], pin['sha256'], payload.MAX_METADATA)
            content = held.bytes(payload.MAX_METADATA); captures.append(held)
            value = decode(content)
            require(type(value) is dict and type(value.get('paths')) is list and 0 < len(value['paths']) <= 4096)
            inventories.extend(row['path'] for row in value['paths'])
            files['browser-inventory.json' if name == 'browserInventory' else 'controller-inventory.json'] = content
            total += len(content); require(total <= MAX_COPIED)
        roots = frozenset(inventories)
        require(all(re.fullmatch(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+', name) for name in roots))
        resolve_roots = resolver_roots(roots)
        # Never consult a manifest-selected personal path; only exact BUILD/source
        # namespaces and the selected immutable reference closures are admissible.
        aliases, used_pins = {}, set()
        for index, (key, target) in enumerate(sorted(mapping.items())):
            payload.budget(until)
            alias = 'f%06d' % index
            path = safe_resolve(target, resolve_roots)
            aliases[target] = str(path)
            if str(path).startswith('/nix/store/'):
                require(str(Path(*path.parts[:4])) in roots)
                store[alias] = str(path)
                continue
            require(path.is_relative_to(OUTPUT_BASE) or path.is_relative_to(SOURCE_ROOT))
            destination = (key[len('_main/'):] if key.startswith('_main/') else
                'runtime/' + str(path.relative_to(Path(OUTPUT_BASE) / 'external'))
                if path.is_relative_to(Path(OUTPUT_BASE) / 'external') else 'assets/' + alias)
            # Expected digest must come from the operator's independently captured
            # eleven inputs or their exact declared source filenames.
            require(key in selection['fileSha256']); used_pins.add(key)
            digest = selection['fileSha256'][key]
            if key.startswith('_main/') and key[len('_main/'):] in ORIGIN_SOURCE_SHA:
                require(digest == ORIGIN_SOURCE_SHA[key[len('_main/'):]])
            for name in payload.INPUTS:
                if safe_resolve(selection['inputPaths'][name], resolve_roots) == path:
                    require(digest == selection['inputSha256'][name])
            if target == selection['nativeManifest']:
                require(digest == selection['nativeManifestSha256'])
            held = capture(str(path), digest, payload.MAX_FILE)
            content = held.bytes(payload.MAX_FILE); captures.append(held)
            total += len(content); require(total <= MAX_COPIED)
            mode = 0o555 if os.fstat(held.fd).st_mode & 0o111 else 0o444
            require(destination not in files or (files[destination] == content and modes[destination] == mode))
            files[destination], copied[alias] = content, destination
            modes[destination] = mode
        require(used_pins == set(selection['fileSha256']))
        require(ORIGIN_FILES.issubset(files))
        require(all(name in files and hashlib.sha256(files[name]).hexdigest() == sha
                    for name,sha in ORIGIN_SOURCE_SHA.items()))
        for name, (digest, size) in ARTIFACTS.items():
            target = selection['inputPaths'][name]
            matches = [files[copied['f%06d' % index]] for index, (_, value) in enumerate(sorted(mapping.items()))
                       if value == target and 'f%06d' % index in copied]
            require(matches and all(len(content) == size and hashlib.sha256(content).hexdigest() == digest for content in matches))
        original_mapping = dict(mapping)
        package = selection['controllerPackage']; package_root = Path(package['root'])
        package_fd = payload.parent(package_root / 'placeholder')
        stack.callback(os.close, package_fd)
        package_identity = payload.identity(os.fstat(package_fd))
        def package_check():
            payload.budget(until)
            require({name for name in os.listdir(package_fd) if name.endswith('.py')} == set(package['files']))
            named = payload.parent(package_root / 'placeholder')
            try:
                require(package_identity == payload.identity(os.fstat(package_fd)) == payload.identity(os.fstat(named)))
            finally:
                os.close(named)
        package_check()
        # Qualified controller source is a distinct fixed public package; it is
        # not asserted to be part of the originating c106 toolbar BUILD.
        for name, pin in sorted(package['files'].items()):
            held = capture(package_root / name, pin['sha256'], 1024 * 1024, controller_root=package_root)
            content = held.bytes(1024 * 1024); captures.append(held)
            require(len(content) == pin['bytes'])
            destination, key = 'tools/' + name, '_main/tools/' + name
            require(key not in mapping and key > max(original_mapping))
            alias = 'f%06d' % len(mapping)
            mapping[key] = str(package_root / name); copied[alias] = destination
            files[destination], modes[destination] = content, 0o444
            total += len(content); require(total <= MAX_COPIED)
        support_hashes = {}
        if selection['schemaVersion'] == support.SCHEMA:
            # One exact successor-only eager import. Never rewrite c106 origin.
            extra = support.support(selection['controllerDelivery'])
            previous_copied, previous_store = dict(copied), dict(store)
            extra_targets = {}
            for name, pin in sorted(extra['files'].items()):
                held = capture(support.DELIVERY / name, pin['sha256'], 1024 * 1024,
                               controller_root=support.DELIVERY)
                content = held.bytes(1024 * 1024); captures.append(held)
                require(len(content) == pin['bytes'])
                destination, key = 'delivery/' + name, '_main/delivery/' + name
                require(destination not in files and key not in mapping and key not in original_mapping)
                mapping[key] = str(support.DELIVERY / name)
                extra_targets[key], files[destination], modes[destination] = destination, content, 0o444
                support_hashes[name] = pin['sha256']
                total += len(content); require(total <= MAX_COPIED)
            # The support key sorts before tools. Reindex all aliases; keeping
            # append-only fNNNNNN values would corrupt generated data mapping.
            copied, store = support.reindex(mapping, previous_copied, previous_store,
                                          extra_targets, until, payload.budget)
        # The original bootstrap is preserved; only the fixed Python main is
        # changed for the two declared controller entrypoints, never caller code.
        old_main = b'_main/delivery/yoga_toolbar_consent.py'
        require(files['installed-launcher.sh'].count(old_main) == 1)
        reserved = selection['schemaVersion'] == support.SCHEMA and {
            'guard_yoga_toolbar_reserved.py', 'yoga_reserved_session_qualification.py'}.issubset(package['files'])
        targets = ('yoga_session_qualification', 'execution_guard') + (('yoga_reserved_session_qualification',) if reserved else ())
        for target in targets:
            files[target + '.sh'] = files['installed-launcher.sh'].replace(old_main, ('_main/tools/' + target + '.py').encode())
            modes[target + '.sh'] = 0o555
        files.update(build_files(mapping, copied, store, reserved=reserved))
        fixed = {'BUILD', 'BUILD.bazel', 'MODULE.bazel', 'MODULE.bazel.lock', 'WORKSPACE', 'WORKSPACE.bazel',
                 'flake.nix', 'flake.lock', '.bazelrc', '.bazelversion'}
        graph_content = [content for name, content in files.items() if PurePosixPath(name).name in fixed
                         or PurePosixPath(name).suffix in ('.bzl', '.nix')
                         or (PurePosixPath(name).parts[0] == 'tools'
                             and PurePosixPath(name).suffix in ('.py', '.json', '.patch', '.zig', '.h'))]
        require(all(len(content) <= 16 * 1024 * 1024 for content in graph_content)
                and sum(map(len, graph_content)) <= 64 * 1024 * 1024)
        workspace_graph = graph(files)
        version2 = selection['schemaVersion'] == support.SCHEMA
        record = {'schemaVersion': support.SCHEMA if version2 else 1,
            'scope': support.WORKSPACE_SCOPE if version2 else SCOPE, 'origin': origin_projection,
            'buildReceiptSha256': BUILD_SHA, 'launcherSha256': selection['launcher']['sha256'],
            'runfilesManifestSha256': selection['runfilesManifest']['sha256'],
            'workspaceGraphSha256': workspace_graph,
            'sourceFilesSha256': {name: hashlib.sha256(files[name]).hexdigest() for name in sorted(ORIGIN_FILES)},
            'inputSha256': selection['inputSha256'], 'nativeManifestSha256': selection['nativeManifestSha256'],
            'declaredStoreFiles': store, 'declaredRunfiles': original_mapping,
            'controllerPackageSha256': {name: pin['sha256'] for name, pin in package['files'].items()},
            'omittedRunfileKeys': ['_repo_mapping', '_main/delivery/yoga_toolbar_consent_proof.sh'],
            'workspaceFiles': {name: {'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content),
                'mode': modes.get(name, 0o444)} for name, content in sorted(files.items())},
            'executionAuthority': False, 'destinationRegistrationVerified': False,
            'seatQualified': False, 'toolbarConsentProved': False,
            'embeddedArtifactProvenanceRewritten': False}
        if version2:
            record['controllerDeliverySha256'] = support_hashes
        files['installed-workspace.json'] = canonical(record)
        for held in captures:
            held.check()
        package_check()
        # Output must be absent and beneath an already owned/private physical
        # parent. There is no replace/adopt/delete path in this producer.
        parent = payload.parent(root)
        stack.callback(os.close, parent)
        info = os.fstat(parent)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        os.mkdir(root.name, mode=0o700, dir_fd=parent)
        owned = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        stack.callback(os.close, owned)
        identity = os.fstat(owned)
        # Partial failures retain this new marked public output for Root to inspect;
        # they never recursively remove an input or a substituted directory.
        for name, content in sorted(files.items(), key=lambda item: (item[0] == 'installed-workspace.json', item[0])):
            payload.budget(until)
            directory = os.dup(owned)
            try:
                parts = PurePosixPath(name).parts
                for part in parts[:-1]:
                    try:
                        os.mkdir(part, 0o700, dir_fd=directory)
                    except FileExistsError:
                        pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    os.close(directory); directory = child
                fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                try:
                    offset = 0
                    while offset < len(content):
                        payload.budget(until); written = os.write(fd, content[offset:offset + 65536])
                        require(written > 0); offset += written
                    os.fchmod(fd, modes.get(name, 0o444))
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(directory)
            finally:
                os.close(directory)
        for held in captures:
            held.check()
        package_check()
        for target, expected in aliases.items():
            payload.budget(until); require(str(safe_resolve(target, resolve_roots)) == expected)
        named = os.stat(root.name, dir_fd=parent, follow_symlinks=False)
        require((identity.st_dev, identity.st_ino, identity.st_uid, identity.st_mode) ==
                (named.st_dev, named.st_ino, named.st_uid, named.st_mode))
        verify_output(owned, files, modes, until)
        os.fsync(owned); os.fsync(parent)
        return {'scope': 'yoga-installed-toolbar-produced', 'workspaceGraphSha256': workspace_graph,
                'receiptSha256': hashlib.sha256(files['installed-workspace.json']).hexdigest(),
                'executionAuthority': False, 'toolbarConsentProved': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', required=True); parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--output', required=True); parser.add_argument('--deadline-monotonic-ns', type=int, required=True)
    args = parser.parse_args()
    try:
        result = produce(args.selection, args.selection_sha256, args.output, args.deadline_monotonic_ns)
        print(json.dumps(result, sort_keys=True)); return 0
    except Exception:
        print('{"scope":"yoga-installed-toolbar-refused","executionAuthority":false}'); return 125


if __name__ == '__main__':
    raise SystemExit(main())
