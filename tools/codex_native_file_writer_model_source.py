"""Exact N10 -> test-only login delta, complete SOURCE and regenerated HUB.

This family confers no compiler/model/native/scheduler/provider qualification.
"""
from contextlib import ExitStack, contextmanager
import copy
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

import codex_native_source_file_writer as tenth
import codex_native_acquisition_metadata as query
import codex_native_acquisition_material as material
import codex_native_sdk_carrier as carrier
import codex_protocol_history_query_tools as query_tools
import guard_native_file_writer_source_reserved as parent_guard

binding, source, protocol = tenth.parent, tenth.source, tenth.parent.protocol
BASE = 'integrations/codex-upstream/file-writer-models/'
CONFIG = BASE + 'qualified-parent.json'
CONFIG_SHA = 'fcca4a790b6baaaa8c87b0e584180cf45f946d9fb56aa6804bd5602a8a4fdbcf'
CONTROLS = BASE + 'native-source-controls.json'
CONTROL_SHA = '33517fe69d6708f1d0d6960515b157aef7c29e3e61c8ffd9fddb79bdb2986941'
KIND = 'omux-native-file-writer-model-source-v1'
INPUT_KIND = 'omux-native-file-writer-model-source-input-v1'
REPOSITORY = 'omux_native_file_writer_model_source_inputs'
PROFILE = 'native-file-writer-models-reserved'
OUTPUT = 'native-file-writer-model-source'
TARGET = '//tools:codex_native_file_writer_model_source_producer'
PATHS = frozenset(('codex-rs/login/BUILD.bazel', 'codex-rs/login/Cargo.toml',
    'codex-rs/login/src/auth/default_client.rs', 'codex-rs/login/src/auth/revoke.rs'))
PREIMAGE_FILES = {
    'codex-rs/login/BUILD.bazel': 'codex-rs/login/BUILD.bazel.preimage',
    'codex-rs/login/Cargo.toml': 'codex-rs/login/Cargo.toml',
    'codex-rs/login/src/auth/default_client.rs': 'codex-rs/login/src/auth/default_client.rs',
    'codex-rs/login/src/auth/revoke.rs': 'codex-rs/login/src/auth/revoke.rs',
}

FALSE_FLAGS = tuple(dict.fromkeys(tenth.FLAGS + ('models_compiled', 'models_passed', 'sdk_export_qualified')))
MODE = 'OMUX_NATIVE_FILE_WRITER_MODELS_MODE'
ENTRY = 'OMUX_NATIVE_FILE_WRITER_MODELS_ENTRY_NS'
UNTIL = 'OMUX_NATIVE_FILE_WRITER_MODELS_DEADLINE_NS'


def declared(name, maximum):
    return tenth.parent.ninth.parent.declared(name, maximum)


def decode(raw):
    return json.loads(raw, object_pairs_hook=source.unique)


def controls():
    raw = declared(CONTROLS, 16384)
    source.require(source.sha(raw) == CONTROL_SHA)
    value = decode(raw)
    source.require(value['kind'] == 'omux-native-file-writer-model-target-controls-v1'
        and value['schema_version'] == 1 and value['qualified_parent_required'] is True
        and value['status'] == 'DECLARED-DELTA-UNQUALIFIED'
        and set(value['delta']['paths']) == PATHS
        and value['target'] == '//codex-rs/login:login-file-writer-storage-tests'
        and value['binary_target'] == '//codex-rs/login:login-file-writer-storage-tests-bin'
        and value['cargo_feature'] == 'omux-native-file-writer-storage-models'
        and all(flag is False for flag in value['capabilities'].values()))
    return raw, value


def configuration():
    raw = declared(CONFIG, 16384)
    source.require(source.sha(raw) == CONFIG_SHA)
    value = decode(raw)
    source.require(type(value) is dict and set(value) == {
        'schema_version', 'kind', 'status', 'parent', 'model_controls_sha256'}
        and type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == INPUT_KIND
        and value['status'] == 'qualified-N10-parent-model-delta-uncompiled'
        and value['model_controls_sha256'] == CONTROL_SHA)
    row = value['parent']
    source.require(type(row) is dict and set(row) == {
        'root', 'receipt_sha256', 'receipt_bytes', 'inventory_sha256', 'producer'}
        and type(row['receipt_bytes']) is int and 0 < row['receipt_bytes'] <= source.MAX_METADATA)
    protocol.pin(row['receipt_sha256']); protocol.pin(row['inventory_sha256'])
    protocol.producer_pin(row['producer'])
    root = protocol.path(row['root'])
    epoch = Path(row['producer']['receipt']).parent
    prefix = str(epoch / 'output-base/execroot/_main/bazel-out') + '/'
    suffix = '/testlogs/tools/codex_native_source_file_writer_producer/test.outputs/native-source-file-writer-boundary'
    source.require(str(root).startswith(prefix) and str(root).endswith(suffix)
        and re.fullmatch(r'[A-Za-z0-9_-]+', str(root)[len(prefix):-len(suffix)]) is not None)
    return raw, value


def pinned_artifact(row):
    source.require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
        and type(row['bytes']) is int and 0 < row['bytes'] <= source.MAX_METADATA)
    protocol.pin(row['sha256'])
    raw = declared(row['path'], row['bytes'])
    source.require(len(raw) == row['bytes'] and source.sha(raw) == row['sha256'])
    return raw


def model_patch(control):
    raw = pinned_artifact(control['delta']['patch'])
    native = decode(pinned_artifact(control['delta']['manifest']))
    source.require(native['paths'] == [
        {'path': name, 'before': control['delta']['paths'][name]['before'],
         'after': control['delta']['paths'][name]['after'], 'logical_mode': '100644'}
        for name in sorted(PATHS)]
        and native['patch'] == {
            'sha256': source.sha(raw), 'bytes': len(raw)})
    expected = decode(pinned_artifact(control['tests']))
    source.require(expected['target'] == control['target']
        and len(expected['expected']) == 19 and len(set(expected['expected'])) == 19)
    return raw


def transform(files, raw, control):
    tenth.bounded_files(files)
    row = control['delta']['patch']
    source.require(type(raw) is bytes and len(raw) == row['bytes']
        and raw.endswith(b'\n') and source.sha(raw) == row['sha256'])
    for name in PATHS:
        pin = control['delta']['paths'][name]['before']
        source.require(name in files and files[name][0] == '100644'
            and len(files[name][1]) == pin['bytes'] and source.sha(files[name][1]) == pin['sha256'])
    changes = binding.ninth.parent.seventh.status.patch_io.apply_exact(
        raw.decode('utf-8'), {name: files[name][1] for name in PATHS})
    source.require(set(changes) == PATHS)
    result = dict(files)
    for name, after in changes.items():
        pin = control['delta']['paths'][name]['after']
        source.require(len(after) == pin['bytes'] and source.sha(after) == pin['sha256'])
        result[name] = ('100644', after)
    validate_transition(files, result, control)
    return result


def validate_transition(before, after, control):
    tenth.bounded_files(after)
    source.require(set(after) == set(before) and
        {name for name in before if before[name] != after[name]} == PATHS
        and all(before[name] == after[name] for name in before if name not in PATHS))
    for name in PATHS:
        pin = control['delta']['paths'][name]['after']
        source.require(after[name][0] == '100644' and len(after[name][1]) == pin['bytes']
            and source.sha(after[name][1]) == pin['sha256'])


class Inputs:
    """Complete declared N10 members/proofs; every physical read joins an alias.

    Held proof leaves stay alive until after final source/output fences.
    """
    def __init__(self, runfiles, rows, *, _repository=REPOSITORY, _kind=INPUT_KIND):
        source.require((_repository, _kind) in ((REPOSITORY, INPUT_KIND),
            ('omux_native_siwc_catalog_model_inputs', 'omux-native-siwc-catalog-model-input-v1'),
            ('omux_native_n10_content_inputs', 'omux-native-n10-content-input-v1'),
            ('omux_native_siwc_catalog_model_inputs', 'omux-native-siwc-catalog-retained-delivery-input-v1')))
        names = [row[2] for row in rows if len(row) == 3 and row[0] in ('', '_main') and row[1] == _repository]
        source.require(len(names) == 1 and re.fullmatch(r'[A-Za-z0-9_+.-]{1,256}', names[0]) is not None)
        self.stack, self.held = ExitStack(), {}
        try:
            self.alias = Path(runfiles) / names[0] / 'source-inputs.json'
            self.path = self.alias.resolve(strict=True)
            self.catalogue_alias_parent_path = self.alias.parent.resolve(strict=True)
            self.catalogue_alias_parent = source.directory(self.catalogue_alias_parent_path)
            self.stack.callback(os.close, self.catalogue_alias_parent)
            self.catalogue_alias_parent_anchor = tenth.witness(os.fstat(self.catalogue_alias_parent))
            alias_info = os.stat(self.alias.name, dir_fd=self.catalogue_alias_parent, follow_symlinks=False)
            source.require(stat.S_ISREG(alias_info.st_mode) or stat.S_ISLNK(alias_info.st_mode))
            self.catalogue_alias_anchor = tenth.witness(alias_info)
            self.catalogue_alias_literal = os.readlink(self.alias.name, dir_fd=self.catalogue_alias_parent) if stat.S_ISLNK(alias_info.st_mode) else None
            source.require(self.path.name == 'source-inputs.json' and self.path.parent.name == names[0]
                and self.path.parent.parent.name == 'external')
            self.parent = source.directory(self.path.parent)
            self.stack.callback(os.close, self.parent)
            self.parent_anchor = tenth.witness(os.fstat(self.parent))
            self.raw = self._capture(self.path, source.MAX_METADATA, declaration=True)
            doc = decode(self.raw)
            source.require(type(doc) is dict and set(doc) == {'kind', 'selection', 'inputs'}
                and doc['kind'] == _kind and type(doc['inputs']) is list and len(doc['inputs']) <= 10000)
            self.selection = doc['selection']
            self.rows = {}
            for index, row in enumerate(doc['inputs']):
                source.tick()
                source.require(type(row) is dict and set(row) == {'path', 'alias'}
                    and row['path'] not in self.rows and row['alias'] == 'input/' + str(index))
                protocol.path(row['path'])
                self.rows[row['path']] = self.path.parent / row['alias']
            self.alias_parent = source.directory(self.path.parent / 'input')
            self.stack.callback(os.close, self.alias_parent)
            self.alias_parent_anchor = tenth.witness(os.fstat(self.alias_parent))
            self.alias_witnesses = {}
            for path, alias in self.rows.items():
                info = os.stat(alias.name, dir_fd=self.alias_parent, follow_symlinks=False)
                source.require(stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid()
                    and os.readlink(alias.name, dir_fd=self.alias_parent) == path)
                self.alias_witnesses[path] = tenth.witness(info)
            self.check_all()
        except BaseException:
            self.stack.close()
            raise

    def _capture(self, path, maximum, *, declaration=False):
        path = Path(path)
        parent = source.directory(path.parent)
        fd = None
        try:
            before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            source.require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) in
                    ((0o444, 0o555, 0o644) if declaration else (0o444, 0o555))
                and 0 < before.st_size <= maximum)
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            anchor = tenth.witness(before)
            source.require(tenth.witness(os.fstat(fd)) == anchor)
            raw, mode = source.read(parent, path.name, maximum)
            source.require(tenth.witness(os.fstat(fd)) == anchor == tenth.witness(
                os.stat(path.name, dir_fd=parent, follow_symlinks=False)))
            self.held[str(path)] = (parent, fd, anchor, tenth.witness(os.fstat(parent)))
            self.stack.callback(os.close, parent); self.stack.callback(os.close, fd)
            parent = fd = None
            return raw
        finally:
            if fd is not None: os.close(fd)
            if parent is not None: os.close(parent)

    def read(self, path, pin, deadline, maximum=64*1024*1024):
        source.require(deadline == source.DEADLINE)
        self.check()
        path = str(path)
        source.require(path in self.rows and self.rows[path].resolve(strict=True) == Path(path))
        self.join_alias(path)
        raw = self._capture(Path(path), maximum) if path not in self.held else self._reread(path, maximum)
        source.require(source.sha(raw) == pin)
        self.join_alias(path)
        self.check()
        return raw

    def _reread(self, path, maximum):
        parent, fd, anchor, unused = self.held[path]
        source.require(tenth.witness(os.fstat(fd)) == anchor)
        raw, mode = source.read(parent, Path(path).name, maximum)
        source.require(len(raw) == anchor[6])
        return raw

    def read_json(self, path, pin, deadline):
        return decode(self.read(path, pin, deadline))

    def check(self):
        source.tick()
        source.require(self.alias.resolve(strict=True) == self.path
            and self.alias.parent.resolve(strict=True) == self.catalogue_alias_parent_path
            and tenth.witness(os.fstat(self.catalogue_alias_parent)) == self.catalogue_alias_parent_anchor
            and tenth.witness(os.stat(self.alias.name, dir_fd=self.catalogue_alias_parent, follow_symlinks=False)) == self.catalogue_alias_anchor
            and tenth.witness(os.fstat(self.parent)) == self.parent_anchor)
        if self.catalogue_alias_literal is not None:
            source.require(os.readlink(self.alias.name, dir_fd=self.catalogue_alias_parent) == self.catalogue_alias_literal)
        named = source.directory(self.catalogue_alias_parent_path)
        try: source.require(tenth.witness(os.fstat(named)) == self.catalogue_alias_parent_anchor)
        finally: os.close(named)
        named = source.directory(self.path.parent)
        try: source.require(tenth.witness(os.fstat(named)) == self.parent_anchor)
        finally: os.close(named)
        for path, (parent, fd, anchor, parent_anchor) in self.held.items():
            source.tick()
            source.require(tenth.witness(os.fstat(parent)) == parent_anchor
                and tenth.witness(os.fstat(fd)) == anchor == tenth.witness(
                    os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)))
            named = source.directory(Path(path).parent)
            try: source.require(tenth.witness(os.fstat(named)) == parent_anchor)
            finally: os.close(named)
        if hasattr(self, 'alias_parent'):
            source.require(tenth.witness(os.fstat(self.alias_parent)) == self.alias_parent_anchor)
            named = source.directory(self.path.parent / 'input')
            try: source.require(tenth.witness(os.fstat(named)) == self.alias_parent_anchor)
            finally: os.close(named)

    def join_alias(self, path):
        source.tick()
        alias = self.rows[path]
        source.require(tenth.witness(os.stat(alias.name, dir_fd=self.alias_parent, follow_symlinks=False))
            == self.alias_witnesses[path] and os.readlink(alias.name, dir_fd=self.alias_parent) == path
            and alias.resolve(strict=True) == Path(path).resolve(strict=True))

    def check_all(self):
        self.check()
        tenth.exact_names(self.alias_parent, {alias.name for alias in self.rows.values()})
        for path in self.rows: self.join_alias(path)
        self.check()

    def close(self):
        self.stack.close()

    def __enter__(self): return self
    def __exit__(self, *unused): self.close()



class HeldControls:
    """Bounded current controls and proof leaves, held across the joint terminal phase."""
    def __init__(self):
        self.stack, self.held, self.raws, self.aliases = ExitStack(), {}, {}, []

    def add(self, alias, pin=None, maximum=64*1024*1024):
        source.tick()
        source.require(len(self.held) < 32 and 0 < maximum <= 64*1024*1024)
        alias = Path(alias); physical = alias.resolve(strict=True)
        if str(physical) not in self.held:
            raw = Inputs._capture(self, physical, maximum, declaration=True)
            self.raws[str(physical)] = raw
        else:
            raw = self.raws[str(physical)]
            source.require(len(raw) <= maximum)
        if pin is not None: source.require(source.sha(raw) == pin)
        parent_path = alias.parent.resolve(strict=True)
        parent = source.directory(parent_path)
        self.stack.callback(os.close, parent)
        before = os.stat(alias.name, dir_fd=parent, follow_symlinks=False)
        source.require(stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode))
        literal = os.readlink(alias.name, dir_fd=parent) if stat.S_ISLNK(before.st_mode) else None
        self.aliases.append((alias, physical, parent_path, parent, tenth.witness(os.fstat(parent)),
            tenth.witness(before), literal))
        self.fence()
        return raw


    def carrier_proofs(self, selected, proofs, deadline):
        """Retain only five declared carrier provenance roles, never grants."""
        import codex_native_carrier_metadata as metadata
        source.require(deadline == source.DEADLINE and metadata._SCOPE.get() == deadline
            and type(proofs) is metadata.ProofInputs and type(selected) is dict)
        proofs.recheck(deadline)
        document = proofs.document
        source.require(type(document) is dict and set(document) == {'kind', 'proofs'}
            and document['kind'] == metadata.PROOF_KIND and type(document['proofs']) is dict
            and set(document['proofs']) == set(metadata.PROOF_ALIASES)
            and str(proofs.path) in self.held
            and source.sha(self.raws[str(proofs.path)]) == proofs.sha256
            and decode(self.raws[str(proofs.path)]) == document)
        rows = document['proofs']
        producer, report = selected['qualification']['producer'], selected['qualification']['report']
        outer_path = protocol.path(producer['receipt'])
        protocol.pin(producer['sha256']); protocol.pin(report['sha256'])
        source.require(outer_path.name == 'receipt.json' and protocol.UUID.fullmatch(outer_path.parent.name) is not None
            and len({row['path'] for row in rows.values()}) == 5)
        captured = {}
        def capture(role, path, pin):
            # All paths/pins are derived below from independent selection or
            # pinned outer/index bytes, before any owner0600 read is admitted.
            row = rows[role]
            source.require(type(row) is dict and set(row) == {'path', 'sha256', 'alias'}
                and row['path'] == str(path) and row['sha256'] == pin
                and row['alias'] == metadata.PROOF_ALIASES[role])
            protocol.pin(pin)
            aliases = [alias for alias, physical in proofs.aliases if physical == path]
            source.require(len(aliases) == 1 and str(aliases[0]).endswith('/' + metadata.PROOF_ALIASES[role]))
            proofs.join(role, path, pin, deadline)
            if str(path) not in self.held:
                source.require(len(self.held) < 32)
                parent = source.directory(path.parent); self.stack.callback(os.close, parent)
                before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                source.require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                    and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) in (0o444, 0o555, 0o600)
                    and 0 < before.st_size <= 64*1024*1024)
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
                self.stack.callback(os.close, fd)
                anchor = tenth.witness(before)
                source.require(tenth.witness(os.fstat(fd)) == anchor)
                raw, unused = source.read(parent, path.name, 64*1024*1024)
                source.require(source.sha(raw) == pin and tenth.witness(os.fstat(fd)) == anchor
                    == tenth.witness(os.stat(path.name, dir_fd=parent, follow_symlinks=False)))
                self.held[str(path)] = (parent, fd, anchor, tenth.witness(os.fstat(parent)))
                self.raws[str(path)] = raw
            original = self.held[str(path)][2]
            source.require(original[2] == os.getuid() and original[5] == 1
                and stat.S_ISREG(original[4]) and stat.S_IMODE(original[4]) in (0o444, 0o555, 0o600))
            captured[role] = self.add(aliases[0], pin)
            proofs.join(role, path, pin, deadline)
        capture('outer_receipt', outer_path, producer['sha256'])
        outer = decode(captured['outer_receipt'])
        index_pin = outer['test_evidence']['sha256']; protocol.pin(index_pin)
        capture('test_evidence', outer_path.parent / 'test-evidence.json', index_pin)
        index = decode(captured['test_evidence'])
        source.require(index['schema'] == 1 and index['targets'] == [metadata.SEAL_TARGET]
            and type(index['results']) is list and len(index['results']) == 1
            and index['results'][0]['target'] == metadata.SEAL_TARGET
            and index['results'][0]['state'] == 'observed')
        for role, original in (('test_log', 'test.log'), ('test_xml', 'test.xml')):
            entries = [row for row in index['results'][0]['files'] if row['source'] == original]
            source.require(len(entries) == 1 and entries[0]['state'] == 'copied'
                and re.fullmatch(r'[0-9a-f]{64}[.]evidence', entries[0]['file']) is not None)
            row = entries[0]
            capture(role, outer_path.parent / 'test-evidence' / row['file'], row['sha256'])
            source.require(type(row['bytes']) is int and row['bytes'] == len(captured[role]))
        report_path = protocol.path(report['path'])
        prefix = str(outer_path.parent / 'output-base/execroot/_main/bazel-out') + '/'
        suffix = '/testlogs/tools/' + metadata.SEAL_TARGET.split(':')[1] + '/test.outputs/sdk-private/native-sdk-carrier-producer.json'
        source.require(str(report_path).startswith(prefix) and str(report_path).endswith(suffix)
            and re.fullmatch(r'[A-Za-z0-9_.-]+', str(report_path)[len(prefix):-len(suffix)]) is not None)
        capture('program_report', report_path, report['sha256'])
        proofs.recheck(deadline); self.fence(); source.tick()
        return captured

    def add_alias(self, alias, physical):
        """Retain declared transport aliases without capturing full payload bytes."""
        source.tick()
        source.require(len(self.aliases) < 64)
        alias, physical = Path(alias), Path(physical)
        source.require(alias.resolve(strict=True) == physical)
        parent_path = alias.parent.resolve(strict=True)
        parent = source.directory(parent_path)
        self.stack.callback(os.close, parent)
        before = os.stat(alias.name, dir_fd=parent, follow_symlinks=False)
        source.require(stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode))
        literal = os.readlink(alias.name, dir_fd=parent) if stat.S_ISLNK(before.st_mode) else None
        self.aliases.append((alias, physical, parent_path, parent, tenth.witness(os.fstat(parent)),
            tenth.witness(before), literal))
        self.fence()

    def full(self):
        for path, raw in self.raws.items():
            source.tick()
            parent, fd, anchor, unused = self.held[path]
            again, mode = source.read(parent, Path(path).name, len(raw))
            source.require(again == raw)
        self.fence()

    def fence(self):
        source.tick()
        for path, (parent, fd, anchor, parent_anchor) in self.held.items():
            source.tick()
            source.require(tenth.witness(os.fstat(parent)) == parent_anchor
                and tenth.witness(os.fstat(fd)) == anchor == tenth.witness(
                    os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)))
            named = source.directory(Path(path).parent)
            try: source.require(tenth.witness(os.fstat(named)) == parent_anchor)
            finally: os.close(named)
        for alias, physical, parent_path, parent, parent_anchor, anchor, literal in self.aliases:
            source.tick()
            source.require(alias.parent.resolve(strict=True) == parent_path and alias.resolve(strict=True) == physical
                and tenth.witness(os.fstat(parent)) == parent_anchor
                and tenth.witness(os.stat(alias.name, dir_fd=parent, follow_symlinks=False)) == anchor)
            if literal is not None: source.require(os.readlink(alias.name, dir_fd=parent) == literal)
            named = source.directory(parent_path)
            try: source.require(tenth.witness(os.fstat(named)) == parent_anchor)
            finally: os.close(named)

    def close(self): self.stack.close()
    def __enter__(self): return self
    def __exit__(self, *unused): self.close()


def retain_model_controls(owner):
    raw_config, config = configuration(); raw_control, control = controls()
    root = binding.ninth.parent.ROOT
    for name, pin, maximum in [(CONFIG, CONFIG_SHA, 16384), (CONTROLS, CONTROL_SHA, 16384)] + [
        (row['path'], row['sha256'], row['bytes']) for row in
        (control['delta']['patch'], control['delta']['manifest'], control['tests'])]:
        owner.add(root / name, pin, maximum)
    return (raw_config, config), (raw_control, control)

def guardian(selected, inputs, *, _guard=None):
    authority = parent_guard if _guard is None else _guard
    source.require(authority.PROFILE in ('native-file-writer-source-reserved', 'native-siwc-catalog-source-reserved',
        'native-siwc-catalog-content-source-reserved'))
    projection_key = {'native-file-writer-source-reserved': 'native_file_writer_source_reservation',
        'native-siwc-catalog-source-reserved': 'native_siwc_catalog_source_reservation',
        'native-siwc-catalog-content-source-reserved': 'native_siwc_catalog_content_source_reservation'}[authority.PROFILE]
    producer = selected['producer']; protocol.producer_pin(producer)
    outer = inputs.read_json(Path(producer['receipt']), producer['sha256'], source.DEADLINE)
    reservation = outer[projection_key]
    source.require(reservation == authority.projection(reservation['original_entry_monotonic_ns'],
        reservation['original_deadline_monotonic_ns'], True, reservation['resident'])
        and outer['profile'] == authority.PROFILE and outer['targets'] == authority.ARGUMENTS[1:]
        and outer['source_commit'] == producer['source_commit'] and outer['graph_sha256'] == producer['graph_sha256']
        and outer['exit'] == 0 and outer['workload_exit'] == 0 and outer['controller_failure'] is None
        and outer['descendants_empty'] is True and outer['cleanup']['state'] == 'empty'
        and outer['source_dirty'] == 'false' and outer['verb'] == 'test' and outer['manager'] == 'system'
        and outer['cache_reuse_requested'] is False and outer['cache_policy'] is None and outer['cache_key'] is None
        and outer['test_evidence']['state'] == 'preserved')
    kernel = authority.kernel
    kernel.kernel_bounds(reservation['resident']['kernel_bounds'])
    binding.protocol.native.phase2_effective_runtime(outer['observed_properties']['RuntimeMaxUSec'],
        1200 if _guard is None else authority.ACTION_SECONDS)
    # Exact independently pinned outer bytes include all observed caps and epoch facts.
    evidence_path = Path(producer['receipt']).parent / 'test-evidence.json'
    evidence = inputs.read_json(evidence_path, outer['test_evidence']['sha256'], source.DEADLINE)
    source.require(evidence['schema'] == 1 and evidence['bazel_exit'] == 0
        and evidence['epoch_start_ns'] == outer['epoch_start_ns']
        and evidence['targets'] == outer['targets']
        and [row['target'] for row in evidence['results']] == outer['targets'])
    required = {producer['receipt'], str(evidence_path), selected['root'] + '/source-receipt.json'}
    for result in evidence['results']:
        source.require(result['state'] == 'observed')
        for member in ('test.log', 'test.xml'):
            matches = [entry for entry in result['files'] if entry['source'] == member]
            source.require(len(matches) == 1 and matches[0]['state'] == 'copied')
            row = matches[0]
            source.require(re.fullmatch(r'[0-9a-f]{64}[.]evidence', row['file']) is not None)
            file = Path(producer['receipt']).parent / 'test-evidence' / row['file']
            raw = inputs.read(file, row['sha256'], source.DEADLINE)
            source.require(type(row['bytes']) is int and len(raw) == row['bytes'] and len(raw) > 0)
            if member == 'test.xml': material.declared_xml_success(raw)
            required.add(str(file))
    return outer, required


@contextmanager
def parent_source(config, inputs, retained):
    row = config['parent']
    source.require(inputs.selection == row)
    inputs.check_all()
    outer, required = guardian(row, inputs)
    with ExitStack() as stack:
        proof = stack.enter_context(binding.SourceProofSession(binding.config()))
        original_raw, original = tenth.load_config()
        patch = tenth.read_patch(original)
        files = tenth.transform(proof.source_files, patch, original)
        report = tenth.receipt(proof.source_report, files, original, metadata_only=False)
        source.require(report['inventory_sha256'] == row['inventory_sha256']
            and source.sha(source.encoded(report)) == row['receipt_sha256'])
        captured = stack.enter_context(binding.SealedSource(Path(row['root']), row['receipt_sha256'],
            size=row['receipt_bytes']))
        captured.accept(report, files)
        trees = []
        for held in [item for unused, item in proof.snapshots] + [captured]:
            members = {'source/' + name: value for name, value in held.files.items()}
            members['source-receipt.json'] = ('100644', held.raw)
            physical = stat.S_IMODE(os.fstat(held.receipt).st_mode)
            source.require(physical in (0o444, 0o555))
            tree = tenth.TreeWitness(held.root, members, receipt_name='source-receipt.json' if physical == 0o444 else None)
            retained.append(tree)
            trees.append(tree)
        required.update(str(captured.root / 'source' / name) for name in files)
        source.require(set(inputs.rows) == required)
        yield proof, captured, trees, files, report
        proof.finish(); captured.recheck()
        source.require(tenth.load_config() == (original_raw, original) and tenth.read_patch(original) == patch)
        source.require(guardian(row, inputs)[0] == outer)
        for tree in trees: tree.check()
        inputs.check_all()


def verify_hub(before, after):
    metadata = binding.metadata
    source.require(type(before) is dict and type(after) is dict and set(before) == set(after)
        and {'BUILD.bazel', 'defs.bzl', 'data.bzl'} <= set(before) and len(before) <= 16
        and all(before[name] == after[name] for name in before if name != 'data.bzl'))
    old, new = metadata.dep_data(before['data.bzl']), metadata.dep_data(after['data.bzl'])
    expected = copy.deepcopy(old)
    protocol_row = expected[metadata.PACKAGE]
    source.require(protocol_row['deps'].count(metadata.ROLLOUT) == 1 and protocol_row['deps'].count(metadata.HISTORY) == 1)
    protocol_row['deps'].remove(metadata.ROLLOUT); del protocol_row['aliases'][metadata.ROLLOUT]
    additions = ['@crates//:hmac-0.12.1', '@crates//:libc-0.2.186', '@crates//:zeroize-1.8.2']
    app = expected['codex-rs/app-server']
    source.require(app['dev_deps'].count(additions[0]) == 1 and all(name not in app['deps'] for name in additions))
    app['dev_deps'].remove(additions[0]); app['deps'] = sorted(app['deps'] + additions)
    login = expected['codex-rs/login']
    source.require(all(name not in login['deps'] for name in additions)
        and [name for name in login['dev_deps'] if not name.startswith('@crates//:')] == ['//codex-rs/core/tests/common'])
    login['deps'] = sorted(login['deps'] + additions)
    # The empty feature is activated only on the new rust_test, not generated default dependencies.
    source.require(new == expected)
    return True


def make_report(parent_report, files, control, config, *, hub=None):
    source.require(parent_report['kind'] == tenth.KIND
        and parent_report['status'] == 'verified-tenth-file-writer-source-uncompiled'
        and parent_report['inventory_sha256'] == config['parent']['inventory_sha256']
        and len(parent_report['patch_sha256']) == 10
        and all(parent_report[name] is False for name in tenth.FLAGS))
    inventory = binding.ninth.parent.seventh.status.inventory(files)
    graph = set(parent_report['graph_files']) | {'codex-rs/login/BUILD.bazel', 'codex-rs/login/Cargo.toml'}
    return {'schema_version': 1, 'kind': KIND, 'status': 'verified-model-source-uncompiled',
        'commit': source.COMMIT, 'qualified_parent': config['parent'],
        'model_controls_sha256': CONTROL_SHA,
        'patch_sha256': parent_report['patch_sha256'] + [control['delta']['patch']['sha256']],
        'patches': parent_report['patches'] + [{'patch_sha256': control['delta']['patch']['sha256'], 'paths': sorted(PATHS)}],
        'model_preimages': {name: row['before'] for name, row in control['delta']['paths'].items()},
        'model_afterimages': {name: row['after'] for name, row in control['delta']['paths'].items()},
        'source_inventory': inventory, 'inventory_sha256': source.sha(source.canonical(inventory)),
        'tracked_files': len(files), 'source_bytes': sum(len(raw) for mode, raw in files.values()),
        'graph_files': {name: {'sha256': source.sha(files[name][1])} for name in sorted(graph)},
        'source_materialized': True, 'native_storage_boundary_source_present': True,
        'physical_mode_policy': 'bazel-retained-export-all-regular-and-directories-0555-v1',
        'generated_hub': None if hub is None else {name: {'sha256': source.sha(raw), 'bytes': len(raw)} for name, raw in sorted(hub.items())},
        **{name: False for name in FALSE_FLAGS}}



def producer_context():
    env = os.environ
    epoch, commit, graph = [env.get('OMUX_NATIVE_FILE_WRITER_MODELS_' + key) for key in ('EPOCH', 'SOURCE_COMMIT', 'GRAPH_SHA256')]
    source.require(type(epoch) is str and protocol.PRODUCER_SCOPE.fullmatch(epoch + '/receipt.json') is not None
        and type(commit) is str and re.fullmatch(r'[0-9a-f]{40}', commit) is not None)
    protocol.pin(graph)
    return {'mode': env.get(MODE), 'epoch': epoch, 'source_commit': commit, 'graph_sha256': graph,
        'entry_monotonic_ns': int(env[ENTRY]), 'deadline_monotonic_ns': int(env[UNTIL])}


def declaration_context(context):
    source.require(type(context) is dict and set(context) == {'mode', 'epoch', 'source_commit', 'graph_sha256',
        'entry_monotonic_ns', 'deadline_monotonic_ns'})
    return {'MODE': context['mode'], 'EPOCH': context['epoch'], 'SOURCE_COMMIT': context['source_commit'],
        'GRAPH_SHA256': context['graph_sha256'], 'ENTRY_NS': str(context['entry_monotonic_ns']),
        'DEADLINE_NS': str(context['deadline_monotonic_ns'])}

def admission():
    env = os.environ
    source.require(env.get(MODE) == PROFILE and env.get('TEST_TIMEOUT') and env.get('TEST_UNDECLARED_OUTPUTS_DIR'))
    context = producer_context()
    entry, until = context['entry_monotonic_ns'], context['deadline_monotonic_ns']
    source.require(0 < entry <= time.monotonic_ns() < until and until - entry == 1200*10**9
        and int(env['TEST_TIMEOUT']) >= 660 and source.DEADLINE is None and query.DEADLINE is None)
    return entry, until, float((entry + 600*10**9) / 10**9)


def reuse_admission(admitted):
    """Reuse an already held original clock; this is not source qualification."""
    source.require(type(admitted) is tuple and len(admitted) == 4)
    entry, until, cutoff, raw_context = admitted
    source.require(type(entry) is int and type(until) is int and type(cutoff) is float
        and type(raw_context) is bytes and len(raw_context) <= 16384
        and 0 < entry <= time.monotonic_ns() < entry + 600*10**9 < until
        and until - entry == 1200*10**9 and cutoff == float((entry + 600*10**9) / 10**9)
        and source.DEADLINE == query.DEADLINE == cutoff)
    context = producer_context()
    source.require(source.encoded(context) == raw_context and context['mode'] == PROFILE
        and context['entry_monotonic_ns'] == entry and context['deadline_monotonic_ns'] == until
        and os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR') and int(os.environ['TEST_TIMEOUT']) >= 660)
    return entry, until, cutoff


def original_hub(sdk_session):
    prefix = 'repositories/' + binding.metadata.HUB + '/'
    rows = {name[len(prefix):]: row for (role, name), row in sdk_session.expected.items()
        if role == 'sdk' and name.startswith(prefix)}
    source.require(0 < len(rows) <= 16 and {'BUILD.bazel', 'defs.bzl', 'data.bzl'} <= set(rows)
        and all('/' not in name and row['kind'] == 'file' and row['size'] <= binding.metadata.MAX_HUB_FILE
            for name, row in rows.items()))
    return {name: sdk_session.read_regular('sdk', prefix + name, binding.metadata.MAX_HUB_FILE)
        for name in sorted(rows)}


def regenerate(files, sdk_session, work, output, query_repository):
    source.require(isinstance(query_repository, Path) and not work.exists())
    work.mkdir(mode=0o700)
    fd = source.write_source(work / 'workspace', files)
    os.close(fd)
    for name in ('home', 'home/cargo', 'home/cache', 'home/config', 'home/state'):
        (work / name).mkdir(mode=0o700)
    tools = query_tools.verify_repository(query_repository, source.DEADLINE)
    source.require(tools['status'] == 'declared-fixed-query-tools-byte-qualified'
        and tools['inputs_rechecked'] is True)
    original = original_hub(sdk_session)
    mapping = sdk_session.mapping()
    plan = query.query_plan(work, work / 'workspace/source', mapping)
    source.require(query.execute_query(plan, output) == 0)
    generated = query.read_hub(work / 'output-base/external' / binding.metadata.HUB)
    verify_hub(original, generated)
    source.verify_written(work / 'workspace/source', files)
    source.require(query_tools.verify_repository(query_repository, source.DEADLINE) == tools
        and sdk_session.mapping() == mapping)
    return generated, plan, tools


def publish_receipt(fd, raw):
    source.require(type(raw) is bytes and 0 < len(raw) <= source.MAX_METADATA)
    writer = os.open('source-receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600, dir_fd=fd)
    with os.fdopen(writer, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fchmod(stream.fileno(), 0o444); os.fsync(stream.fileno())
        anchor = tenth.witness(os.fstat(stream.fileno()))
    held = os.open('source-receipt.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    try:
        source.require(tenth.witness(os.fstat(held)) == anchor == tenth.witness(
            os.stat('source-receipt.json', dir_fd=fd, follow_symlinks=False)))
        return held, anchor
    except BaseException:
        os.close(held)
        raise


def produce(output, inputs, work, publication, *, sdk_session=None, query_repository=None, context=None, sdk_qualification=None):
    """Called with one admitted cutoff; caller retains SDK/publication owners to final acceptance."""
    raw_config, config = configuration()
    raw_control, control = controls()
    patch = model_patch(control)
    output_fd = receipt_fd = tree = None
    transferred = False
    try:
        with parent_source(config, inputs, publication.parents) as (proof, captured, ancestors, before, parent_report):
            files = transform(before, patch, control)
            output_fd = source.write_source(output, files)
            hub = plan = tools = None
            if sdk_session is not None:
                hub, plan, tools = regenerate(files, sdk_session, work, output, query_repository)
                fd = source.write_source(output / 'hub', {name: ('100644', raw) for name, raw in hub.items()})
                try: os.fchmod(fd, 0o555)
                finally: os.close(fd)
            report = make_report(parent_report, files, control, config, hub=hub)
            if context is not None: report['producer_context'] = copy.deepcopy(context)
            if hub is not None:
                source.require(type(sdk_qualification) is dict and set(sdk_qualification) == {
                    'selector_sha256', 'selection', 'qualified_producer', 'declaration', 'proof_inputs'})
                report['sdk_input_qualification'] = copy.deepcopy(sdk_qualification)
                report['hub_query_plan'] = plan
                report['original_sdk'] = {'root': str(query.EXPORT_ROOT), 'receipt_sha256': query.EXPORT_SHA,
                    'mapping': sdk_session.mapping(), 'custody': 'fresh-declared-original-sdk-content-v1',
                    'declaration_sha256': source.sha(sdk_session.catalogue.raw),
                    'declaration_context': declaration_context(context),
                    'carrier_receipt_sha256': sdk_session.carrier_pin, 'complete_members': len(sdk_session.expected)}
                report['query_tool_closure'] = tools
            raw_report = source.encoded(report)
            receipt_fd, receipt_anchor = publish_receipt(output_fd, raw_report)
            os.fsync(output_fd)
            output_anchor = tenth.witness(os.fstat(output_fd))
            members = {'source/' + name: row for name, row in files.items()}
            if hub is not None: members.update({'hub/source/' + name: ('100644', raw) for name, raw in hub.items()})
            members['source-receipt.json'] = ('100644', raw_report)
            tree = tenth.TreeWitness(output, members, root_mode=0o700, receipt_name='source-receipt.json')
            source.verify_written(output / 'source', files)
            if hub is not None: source.verify_written(output / 'hub/source', {name: ('100644', raw) for name, raw in hub.items()})
            source.require(configuration() == (raw_config, config) and controls() == (raw_control, control)
                and model_patch(control) == patch)
            source.verify_written(output / 'source', files)
            if hub is not None: source.verify_written(output / 'hub/source', {name: ('100644', raw) for name, raw in hub.items()})
            again, mode = source.read(output_fd, 'source-receipt.json', source.MAX_METADATA)
            source.require(again == raw_report and mode == 0o444
                and tenth.witness(os.fstat(receipt_fd)) == receipt_anchor)
            tree.check()
        # All final parent full IO, guardians and descriptor closes precede this fence.
        source.require(configuration() == (raw_config, config) and controls() == (raw_control, control)
            and model_patch(control) == patch)
        inputs.check()
        os.fchmod(output_fd, 0o555)
        tree.accept_root_seal(output_anchor, tenth.witness(os.fstat(output_fd)))
        tree.check()
        publication.bind(output, output_fd, receipt_fd, receipt_anchor, tree, files, hub, raw_report)
        transferred = True
        return report
    finally:
        error = None
        for owner in (() if transferred else (tree,)):
            if owner is not None:
                try: owner.close()
                except BaseException as failure:
                    if error is None: error = failure
        for fd in (() if transferred else (receipt_fd, output_fd)):
            if fd is not None:
                try: os.close(fd)
                except BaseException as failure:
                    if error is None: error = failure
        if error is not None: raise error



MAX_DIRECTORY_FDS = 16384


class MemberDirectories:
    """One bounded retained-parent capability; final observations are not atomic."""
    def __init__(self):
        self.fds, self.trees = [], []

    def capacity(self):
        source.tick()
        source.require(len(self.fds) < MAX_DIRECTORY_FDS)

    def enroll(self, fd):
        # All opens/dups are preceded by capacity admission. Enroll before the
        # first fstat/validation so every failure retires the actual descriptor.
        self.fds.append(fd)
        return fd

    def capture(self, tree):
        source.tick()
        self.capacity()
        root_fd = self.enroll(os.dup(tree.fd))
        source.require(tenth.witness(os.fstat(root_fd)) == tree.anchor)
        self.capacity()
        parent_fd = self.enroll(source.directory(tree.root.parent))
        parent_anchor = tenth.witness(os.fstat(parent_fd))
        source.require(tenth.witness(os.stat(tree.root.name, dir_fd=parent_fd, follow_symlinks=False)) == tree.anchor)
        directories = {'': (root_fd, tree.anchor)}
        for path in sorted((name for name in tree.children if name), key=lambda name: (name.count('/'), name)):
            source.tick()
            prefix, unused, leaf = path.rpartition('/')
            fd = directories[prefix][0]
            expected = tree.members[path][0]
            source.require(tenth.witness(os.stat(leaf, dir_fd=fd, follow_symlinks=False)) == expected)
            self.capacity()
            held = self.enroll(os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd))
            source.require(tenth.witness(os.fstat(held)) == expected == tenth.witness(
                os.stat(leaf, dir_fd=fd, follow_symlinks=False)))
            directories[path] = (held, expected)
        self.trees.append((tree, parent_fd, parent_anchor, directories))

    def terminal(self):
        """Flat full-nine/literal join after last SDK IO; no listing or byte read."""
        source.tick()
        for tree, parent_fd, parent_anchor, directories in self.trees:
            for path, (expected, literal) in tree.members.items():
                source.tick()
                prefix, unused, leaf = path.rpartition('/')
                parent = directories[prefix][0]
                source.require(tenth.witness(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == expected)
                if literal is not None:
                    source.require(os.readlink(leaf, dir_fd=parent) == literal)
                    source.require(tenth.witness(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == expected)
            # Every directory's original witness rejects namespace additions,
            # removals and replacements, including directories with no files.
            for path, (held, expected) in directories.items():
                source.tick()
                named_parent, leaf = (parent_fd, tree.root.name) if not path else (
                    directories[path.rpartition('/')[0]][0], path.rpartition('/')[2])
                source.require(tenth.witness(os.fstat(held)) == expected == tenth.witness(
                    os.stat(leaf, dir_fd=named_parent, follow_symlinks=False)))
            source.require(tenth.witness(os.fstat(parent_fd)) == parent_anchor)
            # This is only the short canonical root/parent ancestry join, not
            # a recursive SOURCE reopen or another member namespace traversal.
            named = source.directory(tree.root.parent)
            try: source.require(tenth.witness(os.fstat(named)) == parent_anchor)
            finally: os.close(named)
            named = source.directory(tree.root)
            try: source.require(tenth.witness(os.fstat(named)) == tree.anchor)
            finally: os.close(named)

    def close(self):
        first = None
        retired, self.fds = self.fds, []
        self.trees = []
        for fd in reversed(retired):
            try: os.close(fd)
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first


class Publication:
    """Keep SOURCE/output physical continuity through last main control/SDK IO."""
    def __init__(self):
        self.parents, self.fd, self.receipt, self.tree = [], None, None, None
        self.active = False
        self.member_directories = MemberDirectories()
        self.members_captured = False

    def bind(self, path, fd, receipt, receipt_anchor, tree, files, hub, raw):
        source.require(not self.active and self.fd is None)
        self.path, self.fd, self.receipt, self.receipt_anchor = path, fd, receipt, receipt_anchor
        self.tree, self.files, self.hub, self.raw = tree, files, hub, raw
        self.active = True

    def capture(self):
        source.require(self.active and not self.members_captured)
        for tree in self.parents + [self.tree]: self.member_directories.capture(tree)
        self.members_captured = True

    def terminal(self):
        source.require(self.members_captured)
        self.member_directories.terminal()
        self.roots()

    def full(self):
        source.require(self.active)
        source.verify_written(self.path / 'source', self.files)
        if self.hub is not None:
            source.verify_written(self.path / 'hub/source', {name: ('100644', raw) for name, raw in self.hub.items()})
        raw, mode = source.read(self.fd, 'source-receipt.json', source.MAX_METADATA)
        source.require(raw == self.raw and mode == 0o444)
        self.fence()

    def fence(self):
        source.tick()
        for tree in self.parents: tree.check()
        if self.active:
            source.require(tenth.witness(os.fstat(self.receipt)) == self.receipt_anchor)
            self.tree.check()

    def roots(self):
        source.tick()
        for tree in self.parents + ([self.tree] if self.tree is not None else []):
            source.require(tenth.witness(os.fstat(tree.fd)) == tree.anchor)
            named = source.directory(tree.root)
            try: source.require(tenth.witness(os.fstat(named)) == tree.anchor)
            finally: os.close(named)
        if self.active:
            source.require(tenth.witness(os.fstat(self.receipt)) == self.receipt_anchor ==
                tenth.witness(os.stat('source-receipt.json', dir_fd=self.fd, follow_symlinks=False)))

    def close(self):
        error = None
        try: self.member_directories.close()
        except BaseException as failure: error = failure
        for tree in self.parents + ([self.tree] if self.tree is not None else []):
            try: tree.close()
            except BaseException as failure:
                if error is None: error = failure
        self.parents, self.tree = [], None
        for name in ('receipt', 'fd'):
            fd = getattr(self, name)
            setattr(self, name, None)
            if fd is not None:
                try: os.close(fd)
                except BaseException as failure:
                    if error is None: error = failure
        self.active = False
        if error is not None: raise error

    def __enter__(self): return self
    def __exit__(self, *unused): self.close()



SOURCE_PHASES = frozenset((
    'source-admission',
    'runfiles',
    'repository-map',
    'model-controls',
    'source-inputs',
    'carrier-selection',
    'carrier-declaration',
    'carrier-proofs',
    'producer-qualification',
    'sdk-declaration',
    'sdk-custody',
    'query-tools',
    'source-hub-production',
    'native-child',
    'final-publication-read',
    'final-sdk-read',
    'final-producer-recheck',
    'final-control-input-read',
    'final-owner-fences',
    'sdk-close',
    'final-publication-terminal',
    'input-close',
    'control-close',
    'publication-close',
    'completion',
    'post-sdk-close-fences',
    'post-input-close-fences',
    'post-control-close-fences',
))


def main(_native_child=None, _phase=None):
    source.require(_phase is None or callable(_phase))
    def phase(name):
        if _phase is not None: _phase(name)
    phase('source-admission')
    source.require(_native_child is None or callable(_native_child))
    source.require(sys.argv in ([sys.argv[0]], [sys.argv[0], '--source-only']))
    source_only = len(sys.argv) == 2
    entry, until, cutoff = admission()
    source.DEADLINE = query.DEADLINE = cutoff
    sdk_session = None
    try:
        source.tick()
        phase('runfiles')
        runfiles = Path(os.environ['TEST_SRCDIR']).resolve(strict=True)
        output = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True)
        with Publication() as published:
            with HeldControls() as retained:
                phase('repository-map')
                mapping = retained.add(runfiles / '_repo_mapping', maximum=1024*1024)
                rows = [row.split(',') for row in mapping.decode().splitlines()]
                source.require(all(len(row) == 3 for row in rows))
                phase('model-controls')
                initial_config, initial_control = retain_model_controls(retained)
                initial_context = producer_context()
                phase('source-inputs')
                with Inputs(runfiles, rows) as inputs:
                    if not source_only:
                        import codex_original_sdk_inputs as original_sdk
                        import codex_native_carrier_metadata as metadata
                        with metadata.proof_scope(cutoff):
                            phase('carrier-selection')
                            selected_raw = retained.add(binding.ninth.parent.ROOT / metadata.CONFIG, maximum=16384)
                            selected = metadata.selection(selected_raw)
                            phase('carrier-declaration')
                            root, aliases, declaration = metadata.declared_carrier(runfiles, rows, selected, cutoff)
                            for alias, physical in aliases: retained.add_alias(alias, physical)
                            phase('carrier-proofs')
                            proofs = metadata.declared_proofs(runfiles, rows, selected, cutoff)
                            retained.add(proofs.aliases[0][0], proofs.sha256, 65536)
                            for role, row in proofs.document['proofs'].items():
                                alias = next(alias for alias, physical in proofs.aliases if str(physical) == row['path'])
                                raw = retained.add(alias, row['sha256'])
                                if role == 'test_xml': material.declared_xml_success(raw)
                            retained.add(Path(declaration['selection_path']), declaration['selection_sha256'], 8192)
                            phase('producer-qualification')
                            qualified = metadata.qualify_producer(selected, cutoff, proofs)
                            phase('sdk-declaration')
                            manifest_alias, manifest = original_sdk.declared_manifest(runfiles, rows)
                            phase('sdk-custody')
                            sdk_session = original_sdk.HeldOriginalSDK(manifest_alias, manifest, root,
                                selected['carrier']['receipt_sha256'], entry, until, declaration_context(initial_context))
                            sdk_session.__enter__()
                            phase('query-tools')
                            query.declared_query_tools(runfiles, rows)
                            phase('source-hub-production')
                            report = produce(output / OUTPUT, inputs, output / 'model-hub-work', published,
                                sdk_session=sdk_session, query_repository=query.QUERY_REPOSITORY, context=initial_context,
                                sdk_qualification={'selector_sha256': source.sha(selected_raw), 'selection': selected,
                                    'qualified_producer': qualified, 'declaration': declaration, 'proof_inputs': proofs.record()})
                            if _native_child is not None:
                                # One fixed native target executes inside the same
                                # live source/HUB, proof and original SDK owners.
                                phase('native-child')
                                _native_child(published, sdk_session, report, retained, inputs, entry, until, cutoff)
                            phase('final-publication-read')
                            if not published.members_captured: published.capture()
                            # All owners span the last full source/output/carrier/original reads.
                            published.full()
                            phase('final-sdk-read')
                            sdk_session.finish()
                            phase('final-producer-recheck')
                            source.require(metadata.qualify_producer(selected, cutoff, proofs) == qualified)
                            metadata.recheck_aliases(aliases, cutoff); proofs.recheck(cutoff)
                            source.require(declared(metadata.CONFIG, 16384) == selected_raw)
                            source.require(configuration() == initial_config and controls() == initial_control
                                and producer_context() == initial_context)
                            phase('final-control-input-read')
                            retained.full(); inputs.check_all()
                            # One same-held terminal observation phase. Full byte/NAR
                            # work precedes all physical-only namespace/FD/root joins.
                            phase('final-owner-fences')
                            published.fence(); sdk_session.fence()
                            retained.fence(); inputs.check(); published.roots()
                            phase('sdk-close')
                            sdk_session.__exit__(None, None, None)
                            sdk_session = None
                            phase('post-sdk-close-fences')
                            retained.fence(); inputs.check(); published.roots()
                    else:
                        source.require(_native_child is None)
                        produce(output / OUTPUT, inputs, output / 'unused-work', published, context=initial_context)
                        published.capture()
                        published.full()
                        source.require(configuration() == initial_config and controls() == initial_control
                            and producer_context() == initial_context)
                        retained.full(); inputs.check_all(); published.fence()
                        retained.fence(); inputs.check(); published.roots()
                    phase('final-publication-terminal')
                    # SDK bulk walks and normal SDK close have completed. Every
                    # SOURCE/output member now joins its original witness via
                    # retained parents while all proof/control/alias owners live.
                    retained.fence(); inputs.check()
                    published.terminal()
                    retained.fence(); inputs.check(); published.roots()
                    phase('input-close')
                phase('post-input-close-fences')
                # Input close performs no full SOURCE/SDK work. Retain captured
                # controls and publication descriptors through that cleanup.
                retained.fence(); published.roots()
                phase('control-close')
            phase('post-control-close-fences')
            published.roots()
            phase('publication-close')
        phase('completion')
        source.tick()
        source.require(time.monotonic_ns() < entry + 600*10**9 and time.monotonic_ns() < until)
        print('native-file-writer-model-source: exact source composition' +
            (' and complete HUB regeneration' if not source_only else '') + '; compilation unqualified', flush=True)
        source.tick()
        source.require(time.monotonic_ns() < entry + 600*10**9 and time.monotonic_ns() < until)
    finally:
        try:
            if sdk_session is not None: sdk_session.__exit__(*sys.exc_info())
        finally:
            source.DEADLINE = query.DEADLINE = None


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, IndexError):
        print('native file-writer model source refused', file=sys.stderr)
        raise SystemExit(1) from None
