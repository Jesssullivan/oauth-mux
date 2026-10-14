"""Fixed c106 public selector assembly; Bazel TEST only, never writes staging."""
import argparse
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import re
import stat
import time

import yoga_installed_workspace as workspace
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))
import yoga_installed_controller_support as support

LABEL = '//delivery:yoga_installed_selection'
COORD = Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005')
CONTROLLER = support.TOOLS
_PHASES = frozenset({'request', 'deadline', 'assembly-context', 'origin-receipt', 'retained-launcher',
    'retained-manifest', 'browser-inventory', 'controller-inventory', 'inventory-roots',
    'native-manifest', 'retained-runfiles', 'independent-inputs', 'controller-package',
    'controller-files', 'controller-support', 'selection-schema', 'prepublication-recheck',
    'publication', 'postpublication-recheck'})
_PHASES |= frozenset(prefix + '-' + stage
    for prefix in ('browser-inventory', 'controller-inventory')
    for stage in ('alias-shape', 'alias-base', 'alias-role', 'alias-context-precheck',
                  'alias-resolution', 'alias-endpoint', 'alias-context-postcheck',
                  'capture', 'bytes', 'schema', 'roots'))
_OPERATIONS = frozenset({'stage', 'path-shape', 'declaration-type', 'namespace-fence',
    'lstat', 'symlink-limit', 'readlink', 'symlink-text', 'final-namespace-fence'})
_CANDIDATE_CLASSES = frozenset({'unobserved', 'declared-leaf', 'declared-ancestor',
    'declared-descendant', 'historical-output', 'historical-source', 'store', 'outside'})
_ALIAS_LAYOUTS = frozenset({'unobserved', 'historical', 'direct', 'canonical',
    'linux-sandbox', 'processwrapper-sandbox'})
_LINK_FORMS = frozenset({'unobserved', 'absolute', 'relative', 'relative-parent'})


class _AssemblyDiagnostic:
    """Closed non-authoritative phase only; never disclose an input or exception."""
    def __init__(self):
        self.phase = 'request'
        self.operation = 'stage'
        self.namespace = {'aliasLayout': 'unobserved', 'candidateClass': 'unobserved',
            'linkForm': 'unobserved', 'symbolicHops': 0}

    def enter(self, phase):
        workspace.require(type(phase) is str and phase in _PHASES)
        self.phase = phase
        self.operation = 'stage'
        if phase.endswith('-alias-shape'):
            self.namespace = {'aliasLayout': 'unobserved', 'candidateClass': 'unobserved',
                'linkForm': 'unobserved', 'symbolicHops': 0}

    def alias(self, layout):
        workspace.require(type(layout) is str and layout in _ALIAS_LAYOUTS)
        self.namespace['aliasLayout'] = layout

    def resolver(self, operation, candidate_class, link_form, hops):
        # Only closed categories from existing operations; no path/argv/env or
        # additional directory reads. This is the last entered operation.
        workspace.require(type(operation) is str and operation in _OPERATIONS
            and type(candidate_class) is str and candidate_class in _CANDIDATE_CLASSES
            and type(link_form) is str and link_form in _LINK_FORMS
            and type(hops) is int and 0 <= hops <= 65)
        self.operation = operation
        self.namespace.update(candidateClass=candidate_class, linkForm=link_form, symbolicHops=hops)

    def refusal(self):
        workspace.require(self.phase in _PHASES and self.operation in _OPERATIONS
            and self.namespace['aliasLayout'] in _ALIAS_LAYOUTS
            and self.namespace['candidateClass'] in _CANDIDATE_CLASSES
            and self.namespace['linkForm'] in _LINK_FORMS
            and type(self.namespace['symbolicHops']) is int and 0 <= self.namespace['symbolicHops'] <= 65)
        return workspace.canonical({'schemaVersion': 1,
            'scope': 'yoga-installed-selection-refusal-v1', 'phase': self.phase,
            'operation': self.operation, 'diagnosticMeaning': 'last-entered-operation',
            'declaredNamespace': dict(self.namespace),
            'executionAuthority': False, 'toolbarConsentProved': False,
            'browserInvoked': False, 'providerInvoked': False})


NATIVE_SHA = 'b24fb333d7cd58e57790cf02c69cf9a0c1eba3afc7359ab18318973d8b77d2c0'
INPUT_SHA = {
    'bundle': workspace.ARTIFACTS['bundle'][0],
    'extension': workspace.ARTIFACTS['extension'][0],
    'runtime_authority': workspace.ARTIFACTS['runtime_authority'][0],
    'chromium': 'e17d2b0d9b0218bb01bb208c8680d35431dc17208bbd00e69b5b88135f6e51f9',
    'node': 'ee614b3f5d9fb5aa59845aa18fb620e5b259a3cd907353b4fd43d904a76c5191',
    'observer': workspace.ORIGIN_SOURCE_SHA['delivery/yoga_toolbar_observer.mjs'],
    'recorder': workspace.ORIGIN_SOURCE_SHA['delivery/yoga_toolbar_native_recorder.py'],
    'recorder_implementation': workspace.ORIGIN_SOURCE_SHA['delivery/chromium_native_recorder.py'],
    'dbus_session': '0f1dc4d355e763b987340a2d984bcf058c0bb0ecca7c8ee4a513d8afd8bbabbf',
    'dbus_daemon': '352f2f64c60f465c3aa08079abfa9c75c67db58ff872fc4f72e1366f10be1bfe',
    'keyring': '6a5e31b15bb28687aa21078a224c6829e05e1bacf1ec83fc845d5f2254d88626',
}
INPUT_KEYS = {
    'bundle': '_main/delivery/release_archive.tar.gz',
    'extension': '_main/extensions/chromium_dev_package.zip',
    'runtime_authority': '_main/delivery/qualified_browser_runtime.json',
    'chromium': '+cached_site_repository+omux_cached_site/packages/chromium/bin/chromium',
    'node': '+cached_site_repository+omux_cached_site/packages/node/bin/node',
    'observer': '_main/delivery/yoga_toolbar_observer.mjs',
    'recorder': '_main/delivery/yoga_toolbar_native_recorder.py',
    'recorder_implementation': '_main/delivery/chromium_native_recorder.py',
    'dbus_session': '+omux_nix_repository+omux_nix/dbus_run_session',
    'dbus_daemon': '+omux_nix_repository+omux_nix/dbus_daemon',
    'keyring': '+omux_nix_repository+omux_nix/gnome_keyring_daemon',
}
BOOTSTRAP_SHA = {
    '_main/delivery/portable_launcher_template.py': 'ebf7b14f81b57290bdd395ed535e5b95cd74c50b94b544cc07020f1341c95bfc',
    '+omux_nix_repository+omux_nix/python': 'dcd0c375203a9608854148081e021d339a337e22f122bae6a1ae2a34440cf481',
    '+omux_nix_repository+omux_nix/tool_wrappers/python': 'dcd0c375203a9608854148081e021d339a337e22f122bae6a1ae2a34440cf481',
    '+omux_nix_repository+omux_nix/tool_wrappers/bash': '320ca17b474afcdcf8daac09dad94fdcb19dfef2945405b2f7e3bed1c760b02a',
}
BOOTSTRAP_PATH = {
    '_main/delivery/portable_launcher_template.py': workspace.OUTPUT_BASE + '/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/portable_launcher_template.py',
    '+omux_nix_repository+omux_nix/python': workspace.OUTPUT_BASE + '/external/+omux_nix_repository+omux_nix/tool_wrappers/python',
    '+omux_nix_repository+omux_nix/tool_wrappers/python': workspace.OUTPUT_BASE + '/external/+omux_nix_repository+omux_nix/tool_wrappers/python',
    '+omux_nix_repository+omux_nix/tool_wrappers/bash': workspace.OUTPUT_BASE + '/external/+omux_nix_repository+omux_nix/tool_wrappers/bash',
}


def historical_pin(key, physical, digest):
    if key in BOOTSTRAP_SHA:
        workspace.require(str(physical) == BOOTSTRAP_PATH[key] and digest == BOOTSTRAP_SHA[key])
    if key.startswith('_main/') and key[len('_main/'):] in workspace.ORIGIN_SOURCE_SHA:
        relative = key[len('_main/'):]
        workspace.require(str(physical) == workspace.SOURCE_ROOT + '/' + relative
                          and digest == workspace.ORIGIN_SOURCE_SHA[relative])
    if key == '+omux_nix_repository+omux_nix/native.json':
        workspace.require(str(physical) == workspace.OUTPUT_BASE + '/external/+omux_nix_repository+omux_nix/native.json'
                          and digest == NATIVE_SHA)
    for name, selected_key in INPUT_KEYS.items():
        if key == selected_key:
            workspace.require(digest == INPUT_SHA[name])
    for name in ('dbus_daemon', 'dbus_run_session', 'gnome_keyring_daemon'):
        if key == '+omux_nix_repository+omux_nix/tool_wrappers/' + name:
            selected = {'dbus_daemon': 'dbus_daemon', 'dbus_run_session': 'dbus_session', 'gnome_keyring_daemon': 'keyring'}[name]
            workspace.require(digest == INPUT_SHA[selected])


INVENTORY_REPOS = {'browserInventory': '+cached_site_repository+omux_cached_site',
                  'controllerInventory': '+cached_nar_repository+omux_yoga_controller_nars'}


def output_base(path, *, selected_base=None):
    path = workspace.source_path(str(path))
    if selected_base is not None:
        base = workspace.assembly_base(selected_base)
        workspace.require(path != base and path.is_relative_to(base))
        return base
    suffix = path.relative_to(COORD)
    parts = suffix.parts
    workspace.require(len(parts) > 2 and (re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', parts[0])
        or re.fullmatch(r'cache-v2-[0-9a-f]{64}', parts[0])) and parts[1] == 'output-base')
    return COORD / parts[0] / 'output-base'


def declared_alias_paths(alias, expected, role, *, selected_base, _assembly_context):
    """Exact same-target aliases, never a current base or repository tree."""
    alias, expected = workspace.source_path(str(alias)), workspace.source_path(str(expected))
    base = workspace.assembly_base(selected_base)
    inventory = role in {repository + '/inventory.json' for repository in INVENTORY_REPOS.values()}
    if inventory:
        workspace.require(expected == base / 'external' / role)
    elif re.fullmatch(r'_main/tools/[A-Za-z0-9_-]+\.py', role):
        workspace.require(expected == CONTROLLER / Path(role).name)
    else:
        workspace.require(role == '_main/delivery/codex_device_acquisition_component.py'
            and expected == support.DELIVERY / 'codex_device_acquisition_component.py')
    if alias == expected:
        paths = (alias, expected)
    else:
        output_base(alias, selected_base=base)
        relative = alias.relative_to(base).as_posix()
        suffix = 'execroot/_main/bazel-out/k8-fastbuild/bin/delivery/yoga_installed_selection.sh.runfiles/' + role
        workspace.require(re.fullmatch(r'(?:sandbox/(?:linux-sandbox|processwrapper-sandbox)/(?:0|[1-9][0-9]{0,8})/)?'
            + re.escape(suffix), relative) is not None)
        canonical = base / suffix
        paths = (alias, expected) if alias == canonical else (alias, canonical, expected)
        if inventory:
            # A sandbox input may target the artifact's exact execroot external
            # leaf; that repository alias redirects to the physical repository.
            # Declare only this inventory leaf, not external or the repo tree.
            execroot_inventory = base / 'execroot/_main/external' / role
            paths = paths[:-1] + (execroot_inventory, expected)
    workspace.require(type(_assembly_context) is workspace.AssemblyContext
        and _assembly_context.base == base)
    return paths


def declared_inventory(alias, name, *, selected_base=None, _assembly_context=None, _diagnostic=None):
    prefix = 'browser-inventory' if name == 'browserInventory' else 'controller-inventory'
    def phase(stage):
        if _diagnostic is not None:
            _diagnostic.enter(prefix + '-' + stage)
    phase('alias-shape')
    alias = workspace.source_path(str(alias))
    phase('alias-base')
    base = output_base(alias, selected_base=selected_base)
    repository = INVENTORY_REPOS[name]
    expected = base / 'external' / repository / 'inventory.json'
    phase('alias-role')
    workspace.require(alias == expected or str(alias).endswith('.runfiles/' + repository + '/inventory.json'))
    paths = ((alias, expected) if selected_base is None else declared_alias_paths(alias, expected,
        repository + '/inventory.json', selected_base=selected_base, _assembly_context=_assembly_context))
    if _diagnostic is not None:
        layout = ('historical' if selected_base is None else 'direct' if alias == expected else
            alias.relative_to(base).parts[1] if alias.relative_to(base).parts[0] == 'sandbox' else 'canonical')
        _diagnostic.alias(layout)
    if _assembly_context is not None:
        phase('alias-context-precheck')
        _assembly_context.recheck()
    phase('alias-resolution')
    options = {} if _diagnostic is None else {'_trace': _diagnostic.resolver}
    physical = workspace.safe_resolve(str(alias), frozenset(), declared_paths=paths, **options)
    phase('alias-endpoint')
    workspace.require(physical == expected)
    if _assembly_context is not None:
        phase('alias-context-postcheck')
        _assembly_context.recheck()
    return physical


def declared_controller(alias, name, *, selected_base=None, _assembly_context=None):
    alias = workspace.source_path(str(alias))
    expected = CONTROLLER / name
    workspace.require(alias == expected or (output_base(alias, selected_base=selected_base) and
        str(alias).endswith('.runfiles/_main/tools/' + name)))
    paths = ((alias, expected) if selected_base is None else declared_alias_paths(alias, expected,
        '_main/tools/' + name, selected_base=selected_base, _assembly_context=_assembly_context))
    if _assembly_context is not None:
        _assembly_context.recheck()
    physical = workspace.safe_resolve(str(alias), frozenset(), declared_paths=paths)
    workspace.require(physical == expected)
    if _assembly_context is not None:
        _assembly_context.recheck()
    return physical


def output_parent(path, *, selected_base=None):
    path = workspace.source_path(str(path))
    base = output_base(path, selected_base=selected_base)
    relative = path.relative_to(base).as_posix()
    # TestRunnerAction emits an execroot-relative output; test-setup.sh makes
    # it absolute before changing cwd. Both declared sandbox runners use their own execroot.
    workspace.require(re.fullmatch(
        r'(?:sandbox/(?:linux-sandbox|processwrapper-sandbox)/(?:0|[1-9][0-9]{0,8})/)?execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_installed_selection/test\.outputs',
        relative))
    return path


def directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def publish(parent_path, files, until, *, selected_base=None):
    workspace.require(set(files) == {'selection.json', 'browser-inventory.json', 'controller-inventory.json'})
    parent_path = output_parent(parent_path, selected_base=selected_base)
    root = parent_path / 'installed-toolbar-selection'
    with ExitStack() as stack:
        parent = workspace.payload.parent(root)
        stack.callback(os.close, parent)
        info = os.fstat(parent)
        workspace.require(info.st_uid == os.getuid() and not info.st_mode & 0o022)
        def parent_check():
            workspace.payload.budget(until)
            current = workspace.payload.parent(root)
            try:
                workspace.require(directory_identity(info) == directory_identity(os.fstat(parent))
                                  == directory_identity(os.fstat(current)))
                return os.stat(root.name, dir_fd=current, follow_symlinks=False)
            finally:
                os.close(current)
        # Reopen the canonical parent before creating any selected output.
        current = workspace.payload.parent(root)
        try:
            workspace.require(directory_identity(info) == directory_identity(os.fstat(current)))
        finally:
            os.close(current)
        os.mkdir(root.name, 0o700, dir_fd=parent)
        fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        stack.callback(os.close, fd)
        held = os.fstat(fd)
        for name, content in sorted(files.items()):
            workspace.payload.budget(until)
            leaf = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            try:
                offset = 0
                while offset < len(content):
                    workspace.payload.budget(until)
                    count = os.write(leaf, content[offset:offset + 65536])
                    workspace.require(count > 0); offset += count
                os.fsync(leaf)
            finally:
                os.close(leaf)
        # Shared finite no-extra output reader, exact content/0600 modes.
        workspace.verify_output(fd, files, {name: 0o600 for name in files}, until)
        named = parent_check()
        workspace.require(directory_identity(held) == directory_identity(os.fstat(fd)) == directory_identity(named))
        os.fsync(fd); os.fsync(parent)
        workspace.require(directory_identity(held) == directory_identity(parent_check()))
    return root


def assemble(browser_alias, controller_alias, controller_files, output, deadline_ns, *, controller_support,
             _diagnostic=None):
    def phase(name):
        if _diagnostic is not None:
            _diagnostic.enter(name)
    phase('deadline')
    workspace.require(type(deadline_ns) is int and 30 * 10**9 < deadline_ns - time.monotonic_ns() <= 1200 * 10**9)
    until = (deadline_ns - 30 * 10**9) / 10**9
    launch = workspace.OUTPUT_BASE + '/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/yoga_toolbar_consent_proof.sh'
    with ExitStack() as stack:
        phase('assembly-context')
        selected_base = workspace.assembly_base(output, child=True)
        output_parent(output, selected_base=selected_base)
        context = workspace.AssemblyContext(selected_base, until)
        stack.callback(context.close)
        captures, aliases = [], {}
        def capture(path, digest, maximum, **options):
            held = workspace.PhysicalCapture(path, digest, maximum, until, **options)
            stack.callback(held.close); captures.append(held)
            return held
        def measure(path, maximum=workspace.payload.MAX_FILE, **options):
            held = workspace.PhysicalCapture.measure(path, maximum, until, **options)
            stack.callback(held.close); captures.append(held)
            return held
        phase('origin-receipt')
        receipt = capture(workspace.BUILD_RECEIPT, workspace.BUILD_SHA, workspace.payload.MAX_METADATA)
        workspace.origin(workspace.decode(receipt.bytes(workspace.payload.MAX_METADATA)))
        phase('retained-launcher')
        launcher = capture(launch, workspace.LAUNCHER_SHA, 1024 * 1024)
        workspace.require(launcher.size == 5339)
        phase('retained-manifest')
        manifest = capture(launch + '.runfiles_manifest', workspace.MANIFEST_SHA, workspace.MAX_MANIFEST)
        mapping = workspace.manifest(manifest.bytes(workspace.MAX_MANIFEST))
        workspace.require(set(BOOTSTRAP_SHA).issubset(mapping))
        inventories, roots = {}, set()
        for name, alias in (('browserInventory', browser_alias), ('controllerInventory', controller_alias)):
            phase('browser-inventory' if name == 'browserInventory' else 'controller-inventory')
            physical = declared_inventory(alias, name, selected_base=selected_base,
                _assembly_context=context, _diagnostic=_diagnostic)
            phase('browser-inventory-capture' if name == 'browserInventory' else 'controller-inventory-capture')
            held = capture(physical, workspace.INVENTORY_SHA[name], workspace.payload.MAX_METADATA,
                           declared_inventory=name, _assembly_context=context)
            phase('browser-inventory-bytes' if name == 'browserInventory' else 'controller-inventory-bytes')
            content = held.bytes(workspace.payload.MAX_METADATA)
            phase('browser-inventory-schema' if name == 'browserInventory' else 'controller-inventory-schema')
            value = workspace.decode(content)
            workspace.require(type(value) is dict and type(value.get('paths')) is list and 0 < len(value['paths']) <= 4096)
            phase('browser-inventory-roots' if name == 'browserInventory' else 'controller-inventory-roots')
            roots.update(row['path'] for row in value['paths'])
            inventories['browser-inventory.json' if name == 'browserInventory' else 'controller-inventory.json'] = content
            aliases[str(alias)] = (physical, declared_alias_paths(alias, physical,
                INVENTORY_REPOS[name] + '/inventory.json', selected_base=selected_base, _assembly_context=context))
        phase('inventory-roots')
        workspace.require(all(re.fullmatch(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+', root) for root in roots))
        roots = frozenset(roots)
        resolve_roots = workspace.resolver_roots(roots)
        input_paths = {name: mapping[key] for name, key in INPUT_KEYS.items()}
        native = workspace.OUTPUT_BASE + '/external/+omux_nix_repository+omux_nix/native.json'
        phase('native-manifest')
        capture(native, NATIVE_SHA, workspace.payload.MAX_METADATA)
        pins = {}
        copied_bytes = receipt.size + launcher.size + manifest.size + sum(map(len, inventories.values()))
        workspace.require(copied_bytes <= workspace.MAX_COPIED)
        phase('retained-runfiles')
        for key, target in sorted(mapping.items()):
            workspace.payload.budget(until)
            physical = workspace.safe_resolve(target, resolve_roots)
            aliases[target] = (physical, ())
            if str(physical).startswith('/nix/store/'):
                workspace.require(key not in BOOTSTRAP_SHA and key != '+omux_nix_repository+omux_nix/native.json'
                    and not (key.startswith('_main/') and key[len('_main/'):] in workspace.ORIGIN_SOURCE_SHA)
                    and key not in {INPUT_KEYS[name] for name in INPUT_KEYS if name not in ('chromium', 'node')}
                    and not key.startswith('+omux_nix_repository+omux_nix/tool_wrappers/'))
                workspace.require(str(Path(*physical.parts[:4])) in roots)
                continue
            held = measure(physical, min(workspace.payload.MAX_FILE, workspace.MAX_COPIED - copied_bytes))
            copied_bytes += held.size
            pins[key] = held.sha
            workspace.require(len(pins) <= 256)
            historical_pin(key, physical, held.sha)
            if target == native:
                workspace.require(held.sha == NATIVE_SHA)
        # Independent eleven-input byte pins include actual Nix executables;
        # their public store bytes are read, never executed.
        phase('independent-inputs')
        for name, target in input_paths.items():
            physical = workspace.safe_resolve(target, resolve_roots)
            held = capture(physical, INPUT_SHA[name], workspace.payload.MAX_FILE,
                           store_roots=roots if str(physical).startswith('/nix/store/') else None)
            if name in workspace.ARTIFACTS:
                workspace.require(held.size == workspace.ARTIFACTS[name][1])
        phase('controller-package')
        names = [Path(path).name for path in controller_files]
        workspace.require(len(names) == len(set(names)) and 0 < len(names) <= 512
                          and all(re.fullmatch(r'[A-Za-z0-9_-]+\.py', name) for name in names))
        directory = workspace.payload.parent(CONTROLLER / 'placeholder')
        stack.callback(os.close, directory)
        saved_directory = os.fstat(directory)
        def package_check():
            workspace.payload.budget(until)
            workspace.require({name for name in os.listdir(directory) if name.endswith('.py')} == set(names))
            named = workspace.payload.parent(CONTROLLER / 'placeholder')
            try:
                held, current = os.fstat(directory), os.fstat(named)
                workspace.require((saved_directory.st_dev, saved_directory.st_ino, saved_directory.st_uid, saved_directory.st_mode)
                    == (held.st_dev, held.st_ino, held.st_uid, held.st_mode)
                    == (current.st_dev, current.st_ino, current.st_uid, current.st_mode))
            finally: os.close(named)
        package_check()
        package = {}
        phase('controller-files')
        for alias in controller_files:
            name = Path(alias).name
            physical = declared_controller(alias, name, selected_base=selected_base, _assembly_context=context)
            held = measure(physical, 1024 * 1024, controller_root=CONTROLLER)
            workspace.require(0 < held.size <= 1024 * 1024)
            copied_bytes += held.size
            workspace.require(copied_bytes <= workspace.MAX_COPIED)
            package[name] = {'sha256': held.sha, 'bytes': held.size}
            aliases[str(alias)] = (physical, declared_alias_paths(alias, physical,
                '_main/tools/' + name, selected_base=selected_base, _assembly_context=context))
        phase('controller-support')
        alias, expected = support.declared(controller_support,
            lambda path: output_base(path, selected_base=selected_base))
        support_paths = declared_alias_paths(alias, expected, '_main/delivery/codex_device_acquisition_component.py',
            selected_base=selected_base, _assembly_context=context)
        context.recheck()
        physical = workspace.safe_resolve(str(alias), frozenset(), declared_paths=support_paths)
        workspace.require(physical == expected)
        context.recheck()
        aliases[str(alias)] = (physical, support_paths)
        held_support = measure(physical, 1024 * 1024, controller_root=support.DELIVERY)
        copied_bytes += held_support.size
        workspace.require(copied_bytes <= workspace.MAX_COPIED)
        support_pin = {'root': str(support.DELIVERY), 'files': {
            expected.name: {'sha256': held_support.sha, 'bytes': held_support.size}}}
        support.support(support_pin)
        phase('selection-schema')
        selection = workspace.selected({'schemaVersion': support.SCHEMA, 'scope': support.SELECTION_SCOPE,
            'buildReceipt': {'path': workspace.BUILD_RECEIPT, 'sha256': workspace.BUILD_SHA},
            'launcher': {'path': launch, 'sha256': workspace.LAUNCHER_SHA},
            'runfilesManifest': {'path': launch + '.runfiles_manifest', 'sha256': workspace.MANIFEST_SHA},
            'inputPaths': input_paths, 'inputSha256': INPUT_SHA, 'nativeManifest': native,
            'nativeManifestSha256': NATIVE_SHA, 'fileSha256': pins,
            'browserInventory': {'path': workspace.PUBLIC_STAGING + '/browser-inventory.json', 'sha256': workspace.INVENTORY_SHA['browserInventory']},
            'controllerInventory': {'path': workspace.PUBLIC_STAGING + '/controller-inventory.json', 'sha256': workspace.INVENTORY_SHA['controllerInventory']},
            'controllerPackage': {'root': str(CONTROLLER), 'files': package},
            'controllerDelivery': support_pin})
        files = dict(inventories, **{'selection.json': workspace.canonical(selection) + b'\n'})
        def recheck():
            context.recheck()
            for held in captures: held.check()
            package_check()
            for target, (physical, declared) in aliases.items():
                workspace.require(workspace.safe_resolve(target, resolve_roots, declared_paths=declared) == physical)
        phase('prepublication-recheck')
        recheck()
        phase('publication')
        result = publish(output, files, until, selected_base=selected_base)
        phase('postpublication-recheck')
        recheck()
        return result, hashlib.sha256(files['selection.json']).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--browser-inventory', required=True)
    parser.add_argument('--controller-inventory', required=True)
    parser.add_argument('--controller-file', action='append', required=True)
    parser.add_argument('--controller-support-file', required=True)
    args = parser.parse_args()
    diagnostic = _AssemblyDiagnostic()
    try:
        raw = os.environ.get('OMUX_INSTALLED_SELECTION_DEADLINE_NS', '')
        workspace.require(re.fullmatch(r'[1-9][0-9]{1,19}', raw))
        _, digest = assemble(args.browser_inventory, args.controller_inventory, args.controller_file,
                             os.environ['TEST_UNDECLARED_OUTPUTS_DIR'], int(raw),
                             controller_support=args.controller_support_file, _diagnostic=diagnostic)
        print(workspace.canonical({'schemaVersion': 1, 'scope': 'yoga-installed-selection-assembly-v1',
            'selectionSha256': digest, 'executionAuthority': False, 'toolbarConsentProved': False}).decode())
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        parser.exit(125, 'installed-toolbar-selection-assembly-refused\n'
            + diagnostic.refusal().decode('ascii') + '\n')


if __name__ == '__main__': main()
