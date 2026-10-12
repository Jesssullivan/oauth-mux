"""Fresh selected-N10 content custody; historical ancestors are not reexecuted."""
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import stat
import re
from types import MappingProxyType
import codex_native_file_writer_model_source as family

source, tenth, binding = family.source, family.tenth, family.binding
CONFIG = 'integrations/codex-upstream/native-n10-content-input.json'
CONFIG_SHA = '510c6dbd6b34b3e844ebc6f6b90c2c235c974c50677b3f5a2f17b7168eb62830'
REPOSITORY = 'omux_native_n10_content_inputs'
INPUT_KIND = 'omux-native-n10-content-input-v1'
METHOD = 'fresh-selected-N10-inventory-content-v1'


def configuration():
    raw = family.declared(CONFIG, 16384)
    source.require(source.sha(raw) == CONFIG_SHA)
    value = family.decode(raw)
    source.require(type(value) is dict and set(value) == {'schema_version', 'kind', 'status', 'parent'}
        and type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == INPUT_KIND and value['status'] == 'selected-N10-content-uncompiled'
        and value['parent'] == family.configuration()[1]['parent'])
    return raw, value


class ContentSource(binding.SealedSource):
    """Retire every descriptor before attempting all closes, including refusal."""
    def __exit__(self, *unused):
        owned = []
        for name in ('receipt', 'tree', 'held'):
            fd = getattr(self, name)
            setattr(self, name, None)
            if fd is not None: owned.append(fd)
        first = None
        for fd in owned:
            try: os.close(fd)
            except BaseException as failure:
                if first is None: first = failure
        if first is not None: raise first


class Inputs(family.Inputs):
    def __init__(self, runfiles, rows):
        super().__init__(runfiles, rows, _repository=REPOSITORY, _kind=INPUT_KIND)

    def _capture(self, path, maximum, *, declaration=False):
        # Source/receipt modes stay readonly. Original guardian metadata has
        # its own exact owner-private0600 role after independent selection.
        if declaration:
            source.require(Path(path) == self.path and self.path.name == 'source-inputs.json'
                and self.path.parent.name == self.alias.parent.name and self.path.parent.parent.name == 'external')
        private_proof = not declaration and str(path) in getattr(self, 'provenance_paths', ())
        # All new input descriptors enter the owner before any fstat/validation.
        # Failure retires the entire Inputs scope; there is no retry admission.
        path = Path(path)
        parent = source.directory(path.parent)
        self.stack.callback(os.close, parent)
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        source.require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) in
                ((0o444, 0o555, 0o644) if declaration else ((0o600, 0o444, 0o555) if private_proof else (0o444, 0o555)))
            and 0 < before.st_size <= maximum)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        self.stack.callback(os.close, fd)
        anchor = tenth.witness(before)
        source.require(tenth.witness(os.fstat(fd)) == anchor)
        raw, unused = source.read(parent, path.name, maximum)
        source.require(tenth.witness(os.fstat(fd)) == anchor == tenth.witness(
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)))
        self.held[str(path)] = (parent, fd, anchor, tenth.witness(os.fstat(parent)))
        return raw

    def admit_provenance(self, selected):
        source.require(selected == configuration()[1]['parent'] == self.selection)
        _authenticate_provenance(self, selected, family.parent_guard.PROFILE, family.parent_guard.ARGUMENTS[1:])

    def hold_source(self, selected):
        # The original root/tree/receipt descriptors remain owned by Inputs
        # through all later source/HUB/SDK/native work, not just this context.
        return self.stack.enter_context(ContentSource(Path(selected['root']), selected['receipt_sha256'],
            size=selected['receipt_bytes'], modes=(0o444, 0o555)))



class ModelProofInputs(family.Inputs):
    """Only selected content-family model provenance has owner0600 roles."""
    def __init__(self, runfiles, rows):
        super().__init__(runfiles, rows, _repository='omux_native_siwc_catalog_model_inputs',
            _kind='omux-native-siwc-catalog-model-input-v1')

    _capture = Inputs._capture

    def admit_content_provenance(self, selected):
        source.require(selected == self.selection)
        _authenticate_provenance(self, selected, 'native-siwc-catalog-content-source-reserved', [
            '//tools:codex_native_siwc_catalog_content_source_test',
            '//tools:codex_native_siwc_catalog_content_source_producer'])


def _authenticate_provenance(owner, selected, profile, targets):
    outer_path = Path(selected['producer']['receipt'])
    index_path = outer_path.parent / 'test-evidence.json'
    source.require(str(outer_path) in owner.rows and str(index_path) in owner.rows)
    # Only the independently pinned original outer and its authenticated
    # index may introduce the six exact original evidence roles.
    owner.provenance_paths = frozenset((str(outer_path), str(index_path)))
    outer = owner.read_json(outer_path, selected['producer']['sha256'], source.DEADLINE)
    source.require(outer['profile'] == profile
        and outer['targets'] == targets
        and outer['exit'] == 0 and outer['workload_exit'] == 0)
    index = owner.read_json(index_path, outer['test_evidence']['sha256'], source.DEADLINE)
    source.require(index['schema'] == 1 and index['targets'] == outer['targets']
        and type(index['results']) is list and [row['target'] for row in index['results']] == outer['targets'])
    paths = set(owner.provenance_paths)
    for result in index['results']:
        source.require(result['state'] == 'observed')
        for role in ('test.log', 'test.xml'):
            entries = [row for row in result['files'] if row['source'] == role]
            source.require(len(entries) == 1 and entries[0]['state'] == 'copied')
            row = entries[0]
            source.require(re.fullmatch(r'[0-9a-f]{64}[.]evidence', row['file']) is not None)
            family.protocol.pin(row['sha256'])
            path = str(outer_path.parent / 'test-evidence' / row['file'])
            source.require(path in owner.rows and path not in paths)
            paths.add(path)
    source.require(len(paths) == 2 + 2 * len(targets))
    owner.provenance_paths = frozenset(paths)
    owner.check_all()



def validate_report(raw, selected):
    source.require(type(raw) is bytes and len(raw) == selected['receipt_bytes']
        and source.sha(raw) == selected['receipt_sha256'])
    report = family.decode(raw)
    original_raw, original = tenth.load_config()
    expected_patches = original['parent']['patch_sha256'] + [original['storage']['patch_sha256']]
    source.require(type(report) is dict and report['kind'] == tenth.KIND
        and report['status'] == 'verified-tenth-file-writer-source-uncompiled'
        and report['schema_version'] == 1 and report['commit'] == source.COMMIT
        and report['inventory_sha256'] == selected['inventory_sha256']
        and report['tracked_files'] == 8553 and report['source_bytes'] == 84807456
        and report['patch_sha256'] == expected_patches and len(expected_patches) == 10
        and report['native_storage_manifest_sha256'] == original['storage']['native_manifest_sha256']
        and report['file_writer_preimages'] == {name: row['before'] for name, row in original['storage']['paths'].items()}
        and report['file_writer_afterimages'] == {name: row['after'] for name, row in original['storage']['paths'].items()}
        and report['source_materialized'] is True and report['native_storage_boundary_source_present'] is True
        and report['physical_mode_policy'] == 'bazel-retained-export-all-regular-and-directories-0555-v1'
        and all(report[name] is False for name in tenth.FLAGS))
    inventory = report['source_inventory']
    source.require(type(inventory) is dict and len(inventory) == report['tracked_files']
        and source.sha(source.canonical(inventory)) == selected['inventory_sha256']
        and type(report['graph_files']) is dict and set(source.GRAPH) <= set(report['graph_files']))
    for name, row in inventory.items():
        source.safe_name(name)
        source.require(type(row) is dict and set(row) == {'mode', 'sha256'}
            and row['mode'] in ('100644', '100755', '120000'))
        family.protocol.pin(row['sha256'])
    for name, row in report['graph_files'].items():
        source.require(name in inventory and type(row) is dict and set(row) == {'sha256'}
            and row['sha256'] == inventory[name]['sha256'] and inventory[name]['mode'] != '120000')
    # The independent raw receipt pin authenticates its exact ordered history;
    # no ancestry root, identity record, or prior clock is reused as current proof.
    source.require(tenth.load_config() == (original_raw, original))
    return report


def capture_files(report, inputs, captured):
    """Bounded nofollow bytes/literals plus original nine-field member joins."""
    inventory = report['source_inventory']
    source.require(type(inventory) is dict and 0 < len(inventory) <= tenth.MAX_ROWS
        and type(report['source_bytes']) is int and 0 < report['source_bytes'] <= source.MAX_SOURCE)
    files, members, parents, total = {}, {}, {}, 0
    for name, row in sorted(inventory.items()):
        source.tick(); source.safe_name(name)
        source.require(type(row) is dict and set(row) == {'mode', 'sha256'}
            and row['mode'] in ('100644', '100755', '120000'))
        family.protocol.pin(row['sha256'])
        physical = captured.root / 'source' / name
        source.require(str(physical) in inputs.rows)
        inputs.join_alias(str(physical)); captured.check()
        with ExitStack() as stack:
            parent = source.directory(physical.parent)
            stack.callback(os.close, parent)
            parent_anchor = tenth.witness(os.fstat(parent))
            source.require(parent_anchor[2] == os.getuid() and stat.S_IMODE(parent_anchor[4]) == 0o555)
            prefix = 'source' + ('/' + str(Path(name).parent) if str(Path(name).parent) != '.' else '')
            source.require(prefix not in parents or parents[prefix] == parent_anchor)
            parents[prefix] = parent_anchor
            before = os.stat(physical.name, dir_fd=parent, follow_symlinks=False)
            anchor = tenth.witness(before)
            source.require(before.st_uid == os.getuid())
            if row['mode'] == '120000':
                source.require(stat.S_ISLNK(before.st_mode))
                literal = os.readlink(physical.name, dir_fd=parent)
                raw = literal.encode()
                # This input contract, like the declared N10 rule, permits only
                # selected internal links to a regular member.
                target = physical.resolve(strict=True)
                source.require(target.is_relative_to(captured.root / 'source'))
                target_name = str(target.relative_to(captured.root / 'source'))
                source.require(target_name in inventory and inventory[target_name]['mode'] in ('100644', '100755'))
            else:
                source.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and stat.S_IMODE(before.st_mode) == 0o555 and 0 <= before.st_size <= source.MAX_SOURCE - total)
                fd = os.open(physical.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
                stack.callback(os.close, fd)
                source.require(tenth.witness(os.fstat(fd)) == anchor)
                chunks, count = [], 0
                while True:
                    source.tick()
                    chunk = os.read(fd, min(1024*1024, before.st_size - count + 1))
                    if not chunk: break
                    count += len(chunk)
                    source.require(count <= before.st_size)
                    chunks.append(chunk)
                source.require(count == before.st_size and tenth.witness(os.fstat(fd)) == anchor)
                raw, literal = b''.join(chunks), None
            total += len(raw)
            source.require(total <= source.MAX_SOURCE and source.sha(raw) == row['sha256']
                and tenth.witness(os.stat(physical.name, dir_fd=parent, follow_symlinks=False)) == anchor
                and tenth.witness(os.fstat(parent)) == parent_anchor)
            files[name] = (row['mode'], raw)
            members['source/' + name] = (anchor, literal)
        inputs.join_alias(str(physical)); captured.check()
    source.require(len(files) == report['tracked_files'] and total == report['source_bytes'])
    for name, pin in report['graph_files'].items():
        source.require(name in files and source.sha(files[name][1]) == pin['sha256'])
    return MappingProxyType(files), members, parents


@contextmanager
def source_intake(config, inputs, retained):
    selector_raw, selector = configuration()
    selected = selector['parent']
    source.require(type(inputs) is Inputs and selected == config['parent'] == inputs.selection)
    inputs.admit_provenance(selected)
    inputs.check_all()
    outer, required = family.guardian(selected, inputs)
    raw = inputs.read(Path(selected['root']) / 'source-receipt.json', selected['receipt_sha256'], source.DEADLINE)
    report = validate_report(raw, selected)
    captured = inputs.hold_source(selected)
    source.require(captured.raw == raw)
    files, original_members, original_parents = capture_files(report, inputs, captured)
    members = {'source/' + name: value for name, value in files.items()}
    members['source-receipt.json'] = ('100644', raw)
    physical = stat.S_IMODE(os.fstat(captured.receipt).st_mode)
    source.require(physical in (0o444, 0o555))
    tree = tenth.TreeWitness(captured.root, members, receipt_name='source-receipt.json' if physical == 0o444 else None)
    retained.append(tree)  # Publication owns the original tree through terminal close.
    source.require(all(tree.members[name] == value for name, value in original_members.items())
        and all(tree.members[name][0] == value for name, value in original_parents.items()))
    captured.accept(report, files)
    tree.check()
    required.update(str(captured.root / 'source' / name) for name in files)
    source.require(set(inputs.rows) == required)
    inputs.check_all()
    # First tuple item is this current content owner, not a SourceProofSession.
    yield inputs, captured, [tree], files, report
    captured.recheck(); tree.check()
    source.require(configuration() == (selector_raw, selector)
        and family.guardian(selected, inputs)[0] == outer)
    inputs.check_all(); captured.check(); tree.check()
