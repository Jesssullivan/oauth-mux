"""Complete original SDK input custody, distinct from an extracted SDK.

PRIVATE DRAFT: no producer/guard/admission is wired by this module.
The declared alias catalogue is structure, never independently trusted content.
Full selected carrier facts reconstruct it and authenticate all original bytes.
"""
from contextlib import ExitStack
from types import MappingProxyType
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time

import codex_native_sdk_carrier as carrier

sdk = carrier.sdk
KIND = 'omux-declared-original-sdk-content-v1'
REPOSITORY = 'omux_original_native_sdk_inputs'
ORIGIN = Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/e5b17d7e-d19d-4cb2-be22-41a86b98af7b/sdk-private/sdk-export')
ORIGIN_PIN = '1aa4c87d689f464e576a5c6a51b4c6350a8f0346f6b94299856d01db5147d4f0'
MANIFEST = 'sdk-inputs.json'
MODE = 'native-file-writer-models-reserved'
CONTEXT_FIELDS = ('MODE', 'ENTRY_NS', 'DEADLINE_NS', 'EPOCH', 'SOURCE_COMMIT', 'GRAPH_SHA256')


def need(value, reason):
    if value is not True:
        raise ValueError('original SDK input refused: ' + reason)


def validate_context(value):
    need(type(value) is dict and set(value) == set(CONTEXT_FIELDS)
         and all(type(item) is str for item in value.values()) and value['MODE'] == MODE,
         'actual-envelope-fields')
    for name in ('ENTRY_NS', 'DEADLINE_NS'):
        need(re.fullmatch(r'[1-9][0-9]{0,19}', value[name]) is not None, 'actual-envelope-integer')
    entry, until = int(value['ENTRY_NS']), int(value['DEADLINE_NS'])
    need(until - entry == 1200*10**9 and entry <= time.monotonic_ns(), 'actual-envelope-clock')
    need(re.fullmatch(r'(?:/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005|'
         r'/home/jess/\.local/state/omux-execution-20261005)/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',
         value['EPOCH']) is not None and re.fullmatch(r'[0-9a-f]{40}', value['SOURCE_COMMIT']) is not None,
         'actual-envelope-epoch-source')
    carrier.digest(value['GRAPH_SHA256'])
    return dict(value)


def declared_manifest(runfiles, rows):
    """Bind one mapped metadata leaf, not the materialized runfiles directory."""
    selected = [row[2] for row in rows if len(row) == 3 and
                row[0] in ('', '_main') and row[1] == REPOSITORY]
    need(len(selected) == 1 and re.fullmatch(r'[A-Za-z0-9_+.-]{1,256}', selected[0]) is not None,
         'single-repository-mapping')
    alias = Path(runfiles) / selected[0] / MANIFEST
    physical = alias.resolve(strict=True)
    need(physical.name == MANIFEST and physical.parent.name == selected[0]
         and physical.parent.parent.name == 'external', 'mapped-physical-manifest')
    return alias, physical


class Catalogue:
    """Hold manifest and alias-parent identity; no file-content proof is cached."""
    def __init__(self, physical, clock):
        self.clock, self.physical = clock, carrier.absolute(physical)
        self.anchor = carrier.Root(self.physical.parent / 'input-files', clock)
        self.fd = None
        self.aliases = {}
        try:
            self.alias_parent_witness = carrier.identity(os.fstat(self.anchor.fd))
            self.parent = self.anchor.chain[-2][1]
            self.anchor.check()
            before = os.stat(MANIFEST, dir_fd=self.parent, follow_symlinks=False)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_uid in (0, os.getuid()) and stat.S_IMODE(before.st_mode) == 0o444
                 and 0 < before.st_size <= carrier.MAX_METADATA, 'manifest-custody')
            self.fd = os.open(MANIFEST, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                              dir_fd=self.parent)
            self.identity = carrier.identity(before)
            self.check()
            pieces, count = [], 0
            while True:
                clock.tick()
                chunk = os.read(self.fd, 65536)
                if not chunk:
                    break
                count += len(chunk)
                need(count <= before.st_size, 'manifest-growth')
                pieces.append(chunk)
            need(count == before.st_size, 'manifest-size')
            self.raw = b''.join(pieces)
            self.document = carrier.decode(self.raw)
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        self.clock.tick()
        need(self.fd is not None, 'closed-catalogue')
        self.anchor.check()
        need(carrier.identity(os.fstat(self.fd)) == self.identity == carrier.identity(
            os.stat(MANIFEST, dir_fd=self.parent, follow_symlinks=False)), 'manifest-name-held')
        need(carrier.identity(os.fstat(self.anchor.fd)) == self.alias_parent_witness == carrier.identity(
            os.stat('input-files', dir_fd=self.parent, follow_symlinks=False)), 'alias-parent-full-witness')

    def bind(self, expected, context):
        """Content-derived exact regular catalogue; no returned list grants authority."""
        self.check()
        doc = self.document
        need(type(doc) is dict and set(doc) == {'kind', 'origin_root', 'origin_receipt_sha256',
             'jdk_root', 'entries', 'regular_inputs', 'context'} and doc['kind'] == KIND
             and doc['origin_root'] == str(ORIGIN) and doc['origin_receipt_sha256'] == ORIGIN_PIN
             and doc['jdk_root'] == sdk.JDK, 'catalogue-selection')
        need(validate_context(doc['context']) == validate_context(context), 'catalogue-actual-envelope')
        need(type(doc['entries']) is list and len(doc['entries']) == len(expected)
             and 0 < len(expected) <= carrier.MAX_ENTRIES, 'catalogue-entry-bound')
        observed = {}
        for record in doc['entries']:
            self.clock.tick()
            need(type(record) is dict and set(record) >= {'role', 'path', 'kind'}, 'catalogue-row')
            key = (record['role'], record['path'])
            need(key in expected and key not in observed, 'catalogue-selected-entry')
            observed[key] = {name: value for name, value in record.items() if name not in ('role', 'path')}
        need(observed == expected, 'catalogue-complete-namespace')
        regular = [key for key, row in sorted(expected.items()) if row['kind'] == 'file']
        need(type(doc['regular_inputs']) is list and len(doc['regular_inputs']) == len(regular),
             'catalogue-complete-regulars')
        paths, aliases = set(), set()
        for index, (key, record) in enumerate(zip(regular, doc['regular_inputs'])):
            self.clock.tick()
            role, path = key
            selected = expected[key]
            target = str((ORIGIN if role == 'sdk' else Path(sdk.JDK)) / path)
            alias = 'input-files/' + str(index)
            need(type(record) is dict and set(record) == {'role', 'path', 'source_path', 'alias',
                 'sha256', 'size', 'mode'} and record == {'role': role, 'path': path,
                 'source_path': target, 'alias': alias, 'sha256': selected['sha256'],
                 'size': selected['size'], 'mode': selected['mode']}, 'catalogue-exact-regular')
            need(target not in paths and alias not in aliases, 'catalogue-duplicate-source-alias')
            paths.add(target)
            aliases.add(alias)
            name = str(index)
            info = os.stat(name, dir_fd=self.anchor.fd, follow_symlinks=False)
            need(stat.S_ISLNK(info.st_mode) and os.readlink(name, dir_fd=self.anchor.fd) == target,
                 'catalogue-exact-alias-target')
            witness = carrier.identity(info)
            need(witness == carrier.identity(os.stat(name, dir_fd=self.anchor.fd, follow_symlinks=False)),
                 'catalogue-alias-race')
            self.aliases[key] = (name, target, witness)
        carrier.names(self.anchor.fd, {str(i) for i in range(len(regular))}, self.clock)
        self.check_all()

    def _alias_leaf(self, role, path):
        # Only callers inside a same-held catalogue transaction use this leaf
        # join. The enclosing full checks bind manifest/ancestor/alias-parent
        # witnesses before and after all work; no proof is cached or renewed.
        self.clock.tick()
        need((role, path) in self.aliases, 'undeclared-regular-read')
        name, target, witness = self.aliases[(role, path)]
        before = os.stat(name, dir_fd=self.anchor.fd, follow_symlinks=False)
        need(stat.S_ISLNK(before.st_mode) and carrier.identity(before) == witness
             and os.readlink(name, dir_fd=self.anchor.fd) == target
             and carrier.identity(os.stat(name, dir_fd=self.anchor.fd, follow_symlinks=False)) == witness,
             'declared-alias-readback')
        self.clock.tick()

    def check_alias(self, role, path):
        self.check()
        self._alias_leaf(role, path)
        self.check()

    def check_all(self):
        self.check()
        carrier.names(self.anchor.fd, {name for name, _, _ in self.aliases.values()}, self.clock)
        for role, path in self.aliases:
            self._alias_leaf(role, path)
        # Full-nine alias-parent and manifest joins catch mutations after any
        # earlier leaf. This remains a finite observation, not atomicity.
        self.check()

    def close(self):
        try:
            if self.fd is not None:
                fd, self.fd = self.fd, None
                os.close(fd)
        finally:
            self.anchor.close()


class DeclaredRoot(carrier.Root):
    """Every regular stream has a declared alias gate and current physical join."""
    def __init__(self, role, catalogue, clock):
        self.role, self.catalogue = role, catalogue
        super().__init__(ORIGIN if role == 'sdk' else sdk.JDK, clock, origin_jdk=role == 'jdk')

    def parent(self, name):
        self.catalogue.check()
        self.catalogue._alias_leaf(self.role, name)
        result = super().parent(name)
        try:
            self.catalogue._alias_leaf(self.role, name)
            self.catalogue.check()
            return result
        except BaseException:
            os.close(result[0])
            raise


def _semantic_export(reader, original):
    """Same SDK module/registry predicates, every byte through read_regular."""
    need(original['baseline_inventory_sha256'] == sdk.BASELINE_INVENTORY, 'original-baseline')
    graph = original['graph_files']
    lock = json.loads(reader.read_regular('sdk', 'graph/MODULE.bazel.lock', 8*1024*1024),
                      object_pairs_hook=sdk.unique)
    hashes = lock['registryFileHashes']
    need(type(hashes) is dict and 0 < len(hashes) <= sdk.REGISTRY_MAX_ENTRIES, 'registry-hash-map')
    registry_rows, total = [], 0
    for url, sha in sorted(hashes.items()):
        reader.check()
        need(type(url) is str and (url == 'https://bcr.bazel.build/bazel_registry.json' or re.fullmatch(
             r'https://bcr\.bazel\.build/modules/[a-z][a-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._+-]*/(?:MODULE\.bazel|source\.json)',
             url) is not None), 'registry-url')
        carrier.digest(sha)
        relative = 'content_addressable/sha256/' + sha + '/file'
        raw = reader.read_regular('sdk', 'registry-cache/' + relative, sdk.REGISTRY_MAX_FILE)
        decoded = raw.decode('utf-8')
        if url.endswith('.json'):
            need(type(json.loads(decoded, object_pairs_hook=sdk.unique)) is dict, 'registry-json')
        else:
            need('\x00' not in decoded, 'registry-module-text')
        total += len(raw)
        need(total <= sdk.REGISTRY_MAX_BYTES, 'registry-byte-bound')
        registry_rows.append({'url': url, 'sha256': sha, 'size': len(raw), 'path': relative, 'mode': 0o444})
    registry = {'schema': sdk.REGISTRY_SCHEMA, 'lock_sha256': graph['MODULE.bazel.lock']['sha256'],
                'files': registry_rows, 'inventory_sha256': sdk.digest(sdk.canonical(registry_rows)),
                'total_bytes': total}
    need(registry == original['registry_metadata'], 'registry-complete-proof')
    repositories = {repo['canonical_name']: str(ORIGIN / 'repositories' / repo['canonical_name'])
                    for repo in original['repositories']}
    overrides = {}
    for module, binding in original['modules'].items():
        name = binding['canonical_name']
        need(name in repositories and name in (module, module + '+'), 'module-canonical-binding')
        repo = next(row for row in original['repositories'] if row['canonical_name'] == name)
        file = next(row for row in repo['files'] if row['path'] == 'MODULE.bazel' and row['kind'] == 'file')
        need(file['sha256'] == binding['module_file_sha256'], 'module-byte-binding')
        raw = reader.read_regular('sdk', 'repositories/' + name + '/MODULE.bazel', 8*1024*1024)
        parsed = ast.parse(raw.decode('utf-8'))
        calls = [node.value for node in parsed.body if isinstance(node, ast.Expr) and
                 isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and
                 node.value.func.id == 'module']
        need(len(calls) == 1, 'module-declaration-count')
        keys = [key for key in calls[0].keywords if key.arg == 'name']
        need(len(keys) == 1 and isinstance(keys[0].value, ast.Constant) and
             keys[0].value.value == module, 'module-declaration-name')
        overrides[module] = repositories[name]
    return {'repositories': repositories, 'module_overrides': overrides,
            'inventory_sha256': original['inventory_sha256'], 'mapping_sha256': original['mapping_sha256'],
            'graph_files': graph, 'registry_cache': str(ORIGIN / 'registry-cache'),
            'registry_inventory_sha256': registry['inventory_sha256']}


class HeldOriginalSDK:
    """Fresh full original input proof; never inherited native/runtime authority.

    The caller must independently qualify the selected producer's five evidence
    inputs and Source/HUB/delta before executing any native child. This class
    proves complete content/custody only and exports no execution capability.
    """
    def __init__(self, manifest_alias, manifest_physical, carrier_dir, carrier_pin, entry_ns, outer_until_ns, context):
        need(type(entry_ns) is int and type(outer_until_ns) is int and entry_ns > 0
             and outer_until_ns - entry_ns == 1200*10**9
             and time.monotonic_ns() >= entry_ns, 'original-integer-envelope')
        actual = validate_context(context)
        need(int(actual['ENTRY_NS']) == entry_ns and int(actual['DEADLINE_NS']) == outer_until_ns,
             'original-context-clock-join')
        self._context = carrier.encoded(actual)
        self.until_ns = entry_ns + 600*10**9
        self.clock = carrier.Clock(self.until_ns / 10**9)
        self.clock.until_ns = self.until_ns
        self.alias, self.physical = Path(manifest_alias), carrier.absolute(manifest_physical)
        self.carrier_dir, self.carrier_pin = carrier.absolute(carrier_dir), carrier.digest(carrier_pin)
        self.pid, self.thread, self.self = os.getpid(), threading.get_ident(), self
        self.stack = ExitStack()
        self.active = self.entered = self.finished = False
        self.roots = {}
        self._owners = ()

    def check(self):
        need(self.self is self and self.active and os.getpid() == self.pid
             and threading.get_ident() == self.thread and self.clock.until_ns == self.until_ns
             and self.clock.deadline == self.until_ns / 10**9, 'original-owner-clock')
        self.clock.tick()
        need(self.alias.resolve(strict=True) == self.physical, 'manifest-mapped-alias')
        self.catalogue.check()
        need(carrier.encoded(validate_context(self.catalogue.document['context'])) == self._context,
             'original-current-context')
        self.transport.join(self.carrier_dir, self.carrier_pin, self.clock.deadline)
        if self._owners:
            need(tuple(self.roots.items()) == self._owners and all(
                root.role == role and root.catalogue is self.catalogue and root.clock is self.clock
                and root.path == (ORIGIN if role == 'sdk' else Path(sdk.JDK))
                for role, root in self._owners), 'original-root-owners')
        for root in self.roots.values():
            root.check()

    def __enter__(self):
        need(not self.entered and self.self is self, 'original-reentry')
        self.entered = self.active = True
        try:
            need(self.alias.resolve(strict=True) == self.physical and self.physical.name == MANIFEST,
                 'manifest-physical-leaf')
            self.catalogue = Catalogue(self.physical, self.clock)
            self.stack.callback(self.catalogue.close)
            need(type(self.catalogue.document) is dict and
                 validate_context(self.catalogue.document.get('context')) == carrier.decode(self._context),
                 'initial-actual-envelope-join')
            transport = carrier.HeldCarrier(self.carrier_dir, self.carrier_pin, self.clock.deadline)
            # Bind the unchanged carrier owner to the same integer cutoff before
            # entry; no renewed clock and no proof owner/validator duplication.
            transport._clock.until_ns = transport._until_ns = self.until_ns
            self.transport = self.stack.enter_context(transport)
            report, proof, rows, unused = self.transport._binding()
            need(report['origin']['root'] == str(ORIGIN) and report['origin']['receipt_sha256'] == ORIGIN_PIN,
                 'independent-original-selection')
            self.expected = MappingProxyType({key: MappingProxyType(dict(value)) for key, value in rows.items()})
            self._nars = carrier.encoded(proof['nars'])
            self.catalogue.bind(self.expected, carrier.decode(self._context))
            self.roots = {role: self.stack.enter_context(DeclaredRoot(role, self.catalogue, self.clock))
                          for role in ('sdk', 'jdk')}
            self._owners = tuple(self.roots.items())
            raw = self.read_regular('sdk', 'receipt.json', carrier.MAX_METADATA)
            need(carrier.sha(raw) == ORIGIN_PIN, 'original-receipt-pin')
            self._original_raw = raw
            original = carrier.decode(raw)
            reconstructed = carrier.expected_entries(original, raw, self.clock,
                self.expected[('sdk', 'receipt.json')]['mode'],
                {name: self.expected[('sdk', 'graph/' + name)]['mode'] for name in sdk.GRAPH})
            need(set(reconstructed) == set(self.expected) and all(
                all(self.expected[key].get(field) == value for field, value in row.items())
                for key, row in reconstructed.items()), 'complete-original-reconstruction')
            self.check()
            observed, self.witnesses, nars = carrier._scan_nar(self.roots, self.expected, self.clock)
            need(observed == self.expected and carrier.encoded(nars) == self._nars, 'original-initial-full-content-nar')
            self.witnesses = MappingProxyType({key: tuple(value) for key, value in self.witnesses.items()})
            self.catalogue.check_all()
            self._mapping = carrier.encoded(_semantic_export(self, original))
            self.fence()
            return self
        except BaseException:
            self.active = False
            self.stack.__exit__(*sys.exc_info())
            raise

    def read_regular(self, role, path, limit):
        self.check()
        need(role in self.roots and (role, path) in self.expected
             and self.expected[(role, path)]['kind'] == 'file'
             and type(limit) is int and 0 < limit <= carrier.MAX_METADATA, 'selected-read')
        row = self.expected[(role, path)]
        need(row['size'] <= limit, 'selected-capture-bound')
        raw = carrier.read(self.roots[role], path, limit, row['sha256'])
        need(len(raw) == row['size'], 'selected-capture-size')
        self.check()
        return raw

    def finish(self):
        self.check()
        need(not self.finished, 'original-final-once')
        raw = self.read_regular('sdk', 'receipt.json', carrier.MAX_METADATA)
        need(raw == self._original_raw and carrier.encoded(_semantic_export(self, carrier.decode(raw)))
             == self._mapping, 'original-final-semantics')
        self.transport.full_final()
        # LAST complete original proof follows the final long transport read.
        observed, witnesses, nars = carrier._scan_nar(self.roots, self.expected, self.clock)
        need(observed == self.expected and {key: tuple(value) for key, value in witnesses.items()}
             == self.witnesses and carrier.encoded(nars) == self._nars,
             'original-final-full-content-namespace-nar')
        self.fence()
        self.finished = True

    def mapping(self):
        self.check()
        result = carrier.decode(self._mapping)
        self.check()
        return result

    def fence(self):
        """Complete current witness join after late SOURCE/publication IO.

        This never replaces finish's fresh full byte/NAR proof. It keeps that
        proof's exact current namespace and file witnesses live to acceptance.
        """
        self.check()
        self.catalogue.check_all()
        self.check()
        # LAST bulk IO is the physical original SDK/JDK sweep. The short
        # catalogue check afterwards joins the held/named alias-parent FULL
        # witness, so late alias rename/replace during this sweep also refuses.
        actual = carrier._fresh_namespace(self.roots, self.expected, self.clock)
        need({key: tuple(value) for key, value in actual.items()} == self.witnesses,
             'original-late-namespace-fence')
        self.catalogue.check()
        self.clock.tick()

    def __exit__(self, exc_type, exc, traceback):
        try:
            if exc_type is None:
                need(self.finished, 'original-final-required')
                self.fence()
        except BaseException:
            self.active = False
            self.stack.__exit__(*sys.exc_info())
            raise
        else:
            self.active = False
            self.stack.__exit__(exc_type, exc, traceback)
            if exc_type is None:
                self.clock.tick()

    def __copy__(self):
        raise ValueError('original SDK nontransferable')

    def __deepcopy__(self, memo):
        raise ValueError('original SDK nontransferable')

    def __reduce_ex__(self, protocol):
        raise ValueError('original SDK nontransferable')
