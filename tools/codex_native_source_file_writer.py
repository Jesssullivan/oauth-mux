"""Tenth source family: append reviewed File storage boundary to exact N9.

Source composition only. No compiler, native constructor, timer or issuer runs.
"""
import json
import os
from pathlib import Path
import stat
import sys
import time

import codex_native_acquisition_binding as parent

source = parent.source
KIND = 'omux-native-source-file-writer-boundary-v1'
CONFIG = 'integrations/codex-upstream/file-writer-boundary/native-source-file-writer-boundary-v1.json'
# Draft pins are replaced only after immutable reviewed native storage freeze.
CONFIG_SHA = 'fe7f6abe165993978b67058bd83a2ea3e65c40c20a91c84556e33ee82102f31c'
PATCH = 'integrations/codex-upstream/file-writer-boundary/native-file-writer-storage-v3.patch'
NEW = 'codex-rs/login/src/auth/managed_file_writer.rs'
PATHS = frozenset(('codex-rs/Cargo.lock', 'codex-rs/login/Cargo.toml', NEW,
    'codex-rs/login/src/auth/mod.rs', 'codex-rs/login/src/auth/storage.rs',
    'codex-rs/login/src/auth/storage_tests.rs'))
FLAGS = parent.ninth.FLAGS + ('original_file_writer_qualified',
    'original_writer_exclusion_qualified', 'native_file_commit_cas_qualified',
    'native_refresh_progress_qualified', 'native_scheduler_enabled',
    'issuer_qualified', 'installed_qualified')
MAX_ROWS = 50000
MAX_DEPTH = 64
PHASE = 'input'
PHASES = frozenset(('input', 'parent', 'patch', 'output', 'readback', 'terminal'))


def load_config():
    raw = parent.ninth.parent.declared(CONFIG, 16384)
    source.require(source.sha(raw) == CONFIG_SHA)
    value = json.loads(raw, object_pairs_hook=source.unique)
    source.require(type(value) is dict and set(value) == {
        'schema_version', 'kind', 'parent', 'storage', 'capabilities'}
        and type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == KIND
        and type(value['capabilities']) is dict and set(value['capabilities']) == set(FLAGS)
        and all(value['capabilities'][name] is False for name in FLAGS))
    ancestor = value['parent']
    source.require(type(ancestor) is dict and set(ancestor) == {
        'kind', 'receipt_sha256', 'inventory_sha256', 'patch_sha256'}
        and ancestor['kind'] == parent.ninth.KIND
        and ancestor['receipt_sha256'] == '9e18ed5731a4474d0e9981cfb08da6e3f3e130014615a2dd9a8e26f06246e344'
        and ancestor['inventory_sha256'] == '8542cbe124d74046f20c92df2e304661cd2a9bd9bc5b2df1bc700ce7bf867762'
        and type(ancestor['patch_sha256']) is list and len(ancestor['patch_sha256']) == 9)
    storage = value['storage']
    source.require(type(storage) is dict and set(storage) == {
        'patch_sha256', 'patch_bytes', 'native_manifest_sha256', 'paths'}
        and type(storage['paths']) is dict and set(storage['paths']) == PATHS
        and type(storage['patch_bytes']) is int and 0 < storage['patch_bytes'] <= source.MAX_PATCH)
    for pin in (ancestor['receipt_sha256'], ancestor['inventory_sha256'],
                storage['patch_sha256'], storage['native_manifest_sha256'],
                *ancestor['patch_sha256']):
        parent.protocol.pin(pin)
    for name, row in storage['paths'].items():
        source.require(type(row) is dict and set(row) == {'before', 'after'})
        for key in ('before', 'after'):
            pin = row[key]
            if key == 'before' and name == NEW:
                source.require(pin is None)
            else:
                source.require(type(pin) is dict and set(pin) == {'sha256', 'bytes'}
                    and type(pin['bytes']) is int and 0 < pin['bytes'] <= source.MAX_SOURCE)
                parent.protocol.pin(pin['sha256'])
    native_raw = parent.ninth.parent.declared('integrations/codex-upstream/file-writer-boundary/native-file-writer-storage-v3-manifest.json', 16384)
    source.require(source.sha(native_raw) == storage['native_manifest_sha256'])
    native = json.loads(native_raw, object_pairs_hook=source.unique)
    source.require(native['kind'] == 'omux-native-file-writer-storage-code-proposal-v3'
        and native['proposal_patch'] == {'sha256': storage['patch_sha256'], 'bytes': storage['patch_bytes']}
        and {row['path']: {'before': row['before'], 'after': row['after']} for row in native['paths']} == storage['paths']
        and len(native['paths']) == len(PATHS)
        and all(row['logical_mode'] == '100644' for row in native['paths']))
    return raw, value


def read_patch(config):
    row = config['storage']
    raw = parent.ninth.parent.declared(PATCH, row['patch_bytes'])
    source.require(len(raw) == row['patch_bytes'] and source.sha(raw) == row['patch_sha256'])
    return raw


def bounded_files(files):
    source.require(type(files) in (dict, type(parent.MappingProxyType({})))
        and 0 < len(files) <= MAX_ROWS)
    total = 0
    for name, row in files.items():
        source.tick()
        source.safe_name(name)
        source.require(len(name.split('/')) <= MAX_DEPTH and type(row) is tuple and len(row) == 2
            and row[0] in ('100644', '100755', '120000') and type(row[1]) is bytes)
        total += len(row[1])
        source.require(total <= source.MAX_SOURCE)


def transform(files, raw, config):
    bounded_files(files)
    pins = config['storage']['paths']
    source.require(type(raw) is bytes and len(raw) == config['storage']['patch_bytes']
        and len(raw) <= source.MAX_PATCH and raw.endswith(b'\n')
        and source.sha(raw) == config['storage']['patch_sha256'] and NEW not in files)
    for name in PATHS - {NEW}:
        before = pins[name]['before']
        source.require(name in files and files[name][0] == '100644'
            and len(files[name][1]) == before['bytes']
            and source.sha(files[name][1]) == before['sha256'])
    # Existing exact hunk/context/position parser, no subprocess/fuzzy patch.
    changes = parent.ninth.parent.seventh.status.patch_io.apply_exact(
        raw.decode('utf-8'), {name: files[name][1] for name in PATHS - {NEW}})
    source.require(set(changes) == PATHS)
    result = dict(files)
    for name, value in changes.items():
        pin = pins[name]['after']
        source.require(len(value) == pin['bytes'] and source.sha(value) == pin['sha256'])
        result[name] = ('100644', value)
    validate_transition(files, result, config)
    return result


def validate_transition(before, after, config):
    bounded_files(after)
    source.require(set(after) == set(before) | {NEW}
        and {name for name in before if before[name] != after[name]} == PATHS - {NEW}
        and all(before[name] == after[name] for name in before if name not in PATHS))
    for name, pin in config['storage']['paths'].items():
        source.require(after[name][0] == '100644'
            and len(after[name][1]) == pin['after']['bytes']
            and source.sha(after[name][1]) == pin['after']['sha256'])


def receipt(report, files, config, *, metadata_only):
    ancestor = config['parent']
    source.require(report['kind'] == parent.ninth.KIND
        and report['inventory_sha256'] == ancestor['inventory_sha256']
        and report['patch_sha256'] == ancestor['patch_sha256']
        and all(report[name] is False for name in parent.ninth.FLAGS))
    inventory = parent.ninth.parent.seventh.status.inventory(files)
    graph = set(report['graph_files']) | {'codex-rs/login/Cargo.toml'}
    value = {
        'schema_version': 1, 'kind': KIND,
        'status': ('verified-tenth-file-writer-composition-metadata-uncompiled' if metadata_only
                   else 'verified-tenth-file-writer-source-uncompiled'),
        'commit': source.COMMIT, 'original_ninth': ancestor,
        'native_storage_manifest_sha256': config['storage']['native_manifest_sha256'],
        'patch_sha256': report['patch_sha256'] + [config['storage']['patch_sha256']],
        'patches': report['patches'] + [{'patch_sha256': config['storage']['patch_sha256'],
                                       'paths': sorted(PATHS)}],
        'file_writer_preimages': {name: row['before'] for name, row in config['storage']['paths'].items()},
        'file_writer_afterimages': {name: row['after'] for name, row in config['storage']['paths'].items()},
        'inventory_sha256': source.sha(source.canonical(inventory)),
        'tracked_files': len(files), 'source_bytes': sum(len(raw) for _, raw in files.values()),
        'graph_files': {name: {'sha256': source.sha(files[name][1])} for name in sorted(graph)},
        'source_materialized': not metadata_only, 'native_storage_boundary_source_present': True,
        **{name: False for name in FLAGS},
    }
    if not metadata_only:
        value['source_inventory'] = inventory
        value['physical_mode_policy'] = 'bazel-retained-export-all-regular-and-directories-0555-v1'
    source.require(len(value['patch_sha256']) == 10)
    return value


def witness(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def exact_names(fd, expected):
    found = set()
    with os.scandir(fd) as entries:
        for entry in entries:
            source.tick()
            source.require(entry.name in expected and entry.name not in found and len(found) < len(expected))
            found.add(entry.name)
    source.require(found == expected)


class TreeWitness:
    """Bounded physical continuity after full bytes; no proof cache or link traversal."""
    def __init__(self, root, files, *, root_mode=0o555, receipt_name=None):
        bounded_files(files)
        self.root, self.files = Path(root), files
        source.require(root_mode in (0o700, 0o555)
            and (receipt_name is None or receipt_name == 'source-receipt.json' and receipt_name in files))
        self.root_mode, self.receipt_name = root_mode, receipt_name
        self.fd = source.directory(self.root)
        try:
            self.anchor = witness(os.fstat(self.fd))
            self.children = {'': set()}
            for path in files:
                parts = path.split('/')
                for index, name in enumerate(parts):
                    prefix = '/'.join(parts[:index])
                    self.children.setdefault(prefix, set()).add(name)
                    if index < len(parts) - 1:
                        self.children.setdefault('/'.join(parts[:index + 1]), set())
                source.require(len(self.children) + len(files) <= MAX_ROWS)
            self.members = self.scan()
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise

    def scan(self):
        observed = {}
        def walk(fd, prefix, depth):
            source.tick()
            source.require(depth <= MAX_DEPTH and witness(os.fstat(fd))[2] == os.getuid()
                           and stat.S_IMODE(os.fstat(fd).st_mode) == (self.root_mode if prefix == '' else 0o555))
            names = set()
            with os.scandir(fd) as entries:
                for item in entries:
                    source.tick()
                    source.require(item.name in self.children[prefix]
                        and item.name not in names and len(names) < len(self.children[prefix]))
                    names.add(item.name)
            source.require(names == self.children[prefix])
            for name in sorted(names):
                source.tick()
                path = prefix + '/' + name if prefix else name
                source.require(depth + 1 <= MAX_DEPTH)
                before = os.stat(name, dir_fd=fd, follow_symlinks=False)
                source.require(before.st_uid == os.getuid())
                if path in self.children:
                    source.require(stat.S_ISDIR(before.st_mode))
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        source.require(witness(os.fstat(child)) == witness(before))
                        observed[path] = (witness(before), None)
                        walk(child, path, depth + 1)
                        source.require(witness(os.fstat(child)) == witness(before)
                            == witness(os.stat(name, dir_fd=fd, follow_symlinks=False)))
                    finally:
                        os.close(child)
                else:
                    mode, raw = self.files[path]
                    if mode == '120000':
                        source.require(stat.S_ISLNK(before.st_mode))
                        literal = os.readlink(name, dir_fd=fd)
                        source.require(literal.encode() == raw)
                    else:
                        source.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                            and stat.S_IMODE(before.st_mode) == (0o444 if path == self.receipt_name else 0o555)
                            and before.st_size == len(raw))
                        leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                        try:
                            source.require(witness(os.fstat(leaf)) == witness(before))
                        finally:
                            os.close(leaf)
                        literal = None
                    source.require(witness(os.stat(name, dir_fd=fd, follow_symlinks=False)) == witness(before))
                    observed[path] = (witness(before), literal)
        source.require(witness(os.fstat(self.fd)) == self.anchor)
        walk(self.fd, '', 0)
        named = source.directory(self.root)
        try:
            source.require(witness(os.fstat(named)) == self.anchor == witness(os.fstat(self.fd)))
        finally:
            os.close(named)
        return observed

    def check(self):
        source.require(self.fd is not None and self.scan() == self.members)

    def accept_root_seal(self, before, after):
        # Only the deliberate owned root chmod changes this anchor. Member
        # witnesses, including the receipt, remain the original captured values.
        source.require(self.root_mode == 0o700 and self.anchor == before
            and witness(os.fstat(self.fd)) == after
            and after[:4] == before[:4] and stat.S_IMODE(after[4]) == 0o555
            and after[4] & ~0o777 == before[4] & ~0o777 and after[5:8] == before[5:8])
        self.anchor, self.root_mode = after, 0o555

    def close(self):
        if self.fd is not None:
            fd = self.fd
            self.fd = None
            os.close(fd)


def admission():
    env = os.environ
    source.require(env.get('OMUX_NATIVE_FILE_WRITER_SOURCE_MODE') == 'native-file-writer-source-reserved'
        and env.get('TEST_TIMEOUT') and env.get('TEST_UNDECLARED_OUTPUTS_DIR'))
    entry = int(env['OMUX_NATIVE_FILE_WRITER_SOURCE_ENTRY_NS'])
    deadline = int(env['OMUX_NATIVE_FILE_WRITER_SOURCE_DEADLINE_NS'])
    now = time.monotonic_ns()
    source.require(0 < entry <= now < deadline and deadline - entry == 1200 * 1_000_000_000)
    seconds = min(840, int(env['TEST_TIMEOUT']) - 60)
    source.require(1 <= seconds <= 840 and source.DEADLINE is None)
    return min(deadline / 1_000_000_000, time.monotonic() + seconds), deadline


def produce(output, *, metadata_only=False):
    global PHASE
    cutoff, original_ns = admission()
    source.DEADLINE = cutoff
    output_fd = None
    receipt_fd = None
    parent_trees = []
    output_tree = None
    try:
        try:
            PHASE = 'input'
            raw_config, config = load_config()
            selected = parent.config()
            source.require(selected['source']['receipt_sha256'] == config['parent']['receipt_sha256']
                and selected['source']['inventory_sha256'] == config['parent']['inventory_sha256'])
            with parent.SourceProofSession(selected) as proof:
                PHASE = 'parent'
                for _, captured in proof.snapshots:
                    parent_trees.append(TreeWitness(captured.root / 'source', captured.files))
                PHASE = 'patch'
                raw_patch = read_patch(config)
                files = transform(proof.source_files, raw_patch, config)
                report = receipt(proof.source_report, files, config, metadata_only=metadata_only)
                PHASE = 'output'
                if metadata_only:
                    base = source.directory(output.parent)
                    try:
                        os.mkdir(output.name, 0o700, dir_fd=base)
                        output_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=base)
                    finally:
                        os.close(base)
                else:
                    output_fd = source.write_source(output, files)
                raw_report = source.encoded(report)
                source.require(len(raw_report) <= source.MAX_METADATA)
                writer = os.open('source-receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=output_fd)
                with os.fdopen(writer, 'wb') as stream:
                    stream.write(raw_report)
                    stream.flush()
                    os.fchmod(stream.fileno(), 0o444)
                    os.fsync(stream.fileno())
                    receipt_anchor = witness(os.fstat(stream.fileno()))
                receipt_fd = os.open('source-receipt.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=output_fd)
                source.require(witness(os.fstat(receipt_fd)) == receipt_anchor)
                os.fsync(output_fd)
                output_anchor = witness(os.fstat(output_fd))
                output_members = {'source/' + name: row for name, row in files.items()} if not metadata_only else {}
                output_members['source-receipt.json'] = ('100644', raw_report)
                output_tree = TreeWitness(output, output_members, root_mode=0o700, receipt_name='source-receipt.json')
                PHASE = 'readback'
                proof.finish()
                if not metadata_only:
                    source.verify_written(output / 'source', files)
                source.require(load_config() == (raw_config, config) and read_patch(config) == raw_patch)
                value, mode = source.read(output_fd, 'source-receipt.json', source.MAX_METADATA)
                source.require(value == raw_report and mode == 0o444)
                for _, captured in proof.snapshots:
                    captured.check()
                named = source.directory(output)
                try:
                    source.require(witness(os.fstat(named)) == output_anchor == witness(os.fstat(output_fd)))
                finally:
                    os.close(named)
            # The parent proof closes first. Its late reads/close cannot bypass
            # the remaining held parent and fresh-output physical witnesses.
            source.tick()
            source.require(time.monotonic_ns() < original_ns)
            os.fchmod(output_fd, 0o555)
            sealed_anchor = witness(os.fstat(output_fd))
            source.require(sealed_anchor[:4] == output_anchor[:4]
                and stat.S_IMODE(sealed_anchor[4]) == 0o555
                and sealed_anchor[4] & ~0o777 == output_anchor[4] & ~0o777
                and sealed_anchor[5:8] == output_anchor[5:8])
            output_tree.accept_root_seal(output_anchor, sealed_anchor)
            for tree in parent_trees:
                tree.check()
            exact_names(output_fd, {'source-receipt.json'} if metadata_only else {'source', 'source-receipt.json'})
            source.require(witness(os.fstat(receipt_fd)) == receipt_anchor)
            named_receipt = os.open('source-receipt.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=output_fd)
            try:
                source.require(witness(os.fstat(named_receipt)) == receipt_anchor)
            finally:
                os.close(named_receipt)
            named = source.directory(output)
            try:
                source.require(witness(os.fstat(named)) == sealed_anchor == witness(os.fstat(output_fd)))
            finally:
                os.close(named)
            # LAST output IO: one complete physical pass includes the source,
            # receipt and root, after all retained-source/control reads and sealing.
            output_tree.check()
            PHASE = 'terminal'
        finally:
            # Keep the same float cutoff live across every owned descriptor close.
            cleanup_error = None
            for tree in parent_trees + ([output_tree] if output_tree is not None else []):
                try:
                    tree.close()
                except BaseException as error:
                    if cleanup_error is None:
                        cleanup_error = error
            for fd in (receipt_fd, output_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except BaseException as error:
                        if cleanup_error is None:
                            cleanup_error = error
            if cleanup_error is not None:
                raise cleanup_error
        source.require(source.DEADLINE == cutoff)
        source.tick()
        source.require(time.monotonic_ns() < original_ns)
        return report
    finally:
        source.DEADLINE = None

def main():
    source.require(sys.argv in ([sys.argv[0]], [sys.argv[0], '--metadata-only']))
    metadata_only = len(sys.argv) == 2
    output = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True)
    produce(output / ('native-source-file-writer-metadata' if metadata_only else 'native-source-file-writer-boundary'),
            metadata_only=metadata_only)
    print('Tenth File-writer source composed; native capability and all execution qualifications disabled')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, IndexError):
        print('native File-writer source refused at ' + (PHASE if PHASE in PHASES else 'input'), file=sys.stderr)
        raise SystemExit(1) from None
