"""Fresh public runtime admission; controller invokes inside its original deadline."""
import os
from pathlib import Path
import stat
import time
import codex_fresh_native_runtime as fresh

KIND = 'omux-fresh-native-runtime-selection-v1'
MAX_SELECTION = 16 * 1024 * 1024
HOME_COORD = Path('/home/jess/.local/state/omux-execution-20261005')
NATIVE_STATE = Path('/srv/fast-local/jess/state/codex/omux-native-candidate-20261007')
PACKAGE_SUFFIX = '/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_fresh_native_runtime_package/test.outputs/fresh-native-runtime'


def operator_path(value, filename):
    path = fresh.canonical_path(value)
    fresh.require(path.name == filename and path.parent in (HOME_COORD, NATIVE_STATE))
    return path


def validate_outer(selected):
    import uuid
    fresh.require(set(selected) == {'kind','package_selection','package_run','producer_graph_sha256',
        'producer_source_sha256','archive','manifest','receipt','bundle_directory'} and selected['kind'] == KIND)
    for role in ('package_selection','package_run','archive','manifest','receipt'):
        pin = selected[role]
        fresh.require(set(pin) == {'path','sha256','bytes'} and isinstance(pin['path'],str)
            and isinstance(pin['sha256'],str) and fresh.HASH.fullmatch(pin['sha256'])
            and type(pin['bytes']) is int and 0 <= pin['bytes'] <=
                (fresh.runtime.MAX_ARCHIVE_BYTES if role == 'archive' else fresh.MAX_METADATA))
    operator_path(selected['package_selection']['path'], 'package-selection.json')
    run = fresh.canonical_path(selected['package_run']['path'])
    fresh.require(run.parent.parent == HOME_COORD and run.name == 'receipt.json'
        and str(uuid.UUID(run.parent.name)) == run.parent.name)
    def package_path(value, leaf):
        path = fresh.canonical_path(value)
        text = str(path.parent)
        fresh.require(path.name == leaf and text.endswith(PACKAGE_SUFFIX))
        base = Path(text[:-len(PACKAGE_SUFFIX)])
        fresh.require(base.name == 'output-base' and base.parent.parent == HOME_COORD)
        epoch = base.parent.name
        if epoch.startswith('cache-v2-'):
            fresh.require(fresh.HASH.fullmatch(epoch[len('cache-v2-'):]))
        else:
            fresh.require(str(uuid.UUID(epoch)) == epoch)
        return path.parent
    parent = package_path(selected['archive']['path'],'fresh-native-runtime.tar.gz')
    fresh.require(package_path(selected['manifest']['path'],'runtime-manifest.json') == parent
        and package_path(selected['receipt']['path'],'runtime-receipt.json') == parent)
    root = fresh.canonical_path(selected['bundle_directory'])
    fresh.require(root.parent == parent and fresh.HASH.fullmatch(root.name)
        and fresh.HASH.fullmatch(selected['producer_graph_sha256'])
        and fresh.HASH.fullmatch(selected['producer_source_sha256']))


def sealed_members(root):
    """Finite exact tree inventory; no following symlinks or ambient directories."""
    result, directories = set(), set()
    pending = [('', fresh.trusted(root))]
    try:
        while pending:
            prefix, fd = pending.pop()
            try:
                info = os.fstat(fd)
                fresh.require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o555)
                names = os.listdir(fd)
                fresh.require(len(names) <= 256 and len(result) <= 256)
                for name in names:
                    fresh.tick()
                    fresh.require(name not in ('.', '..') and '/' not in name)
                    path = prefix + name
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        directories.add(path)
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        pending.append((path+'/', child))
                    else:
                        fresh.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in (0o444, 0o555))
                        result.add(path)
                fresh.require(len(result) <= 256 and len(pending) <= 128)
            finally:
                os.close(fd)
    finally:
        for _, fd in pending:
            os.close(fd)
    return result, directories


class Admission:
    def __init__(self, selection_path, selection_sha256, selection_bytes, deadline_ns):
        self.deadline = deadline_ns / 10**9
        fresh.DEADLINE = self.deadline
        self.selection_path = operator_path(str(selection_path),'fresh-runtime-selection.json')
        self.selection_pin = {'path':str(self.selection_path), 'sha256':selection_sha256,
            'bytes':selection_bytes}
        self.recheck()

    def recheck(self):
        try:
            return self._recheck()
        except (KeyError, TypeError, AttributeError, IndexError) as error:
            raise ValueError('fresh runtime admission refused') from None

    def _recheck(self):
        fresh.DEADLINE = self.deadline
        selected = fresh.parse(fresh.read_selected(self.selection_path, self.selection_pin, MAX_SELECTION))
        validate_outer(selected)
        fresh.require(set(selected) == {'kind','package_selection','package_run','producer_graph_sha256',
            'producer_source_sha256','archive','manifest','receipt','bundle_directory'}
            and selected['kind'] == KIND)
        def read(pin, maximum):
            return fresh.read_selected(fresh.canonical_path(pin['path']), pin, maximum)
        package_raw = read(selected['package_selection'], MAX_SELECTION)
        package = fresh.parse(package_raw)
        fresh.validate_selection_paths(package)
        producer_run = fresh.parse(read(selected['package_run'], fresh.MAX_METADATA))
        run_path = fresh.canonical_path(selected['package_run']['path'])
        run_home = Path('/home/jess/.local/state/omux-execution-20261005')
        fresh.require(run_path.parent.parent == run_home and run_path.name == 'receipt.json'
            and str(producer_run['id']) == run_path.parent.name)
        import uuid
        fresh.require(str(uuid.UUID(producer_run['id'])) == producer_run['id'])
        fresh.require(producer_run['profile'] == 'standard' and producer_run['exit'] == 0
            and producer_run['workload_exit'] == 0 and producer_run['descendants_empty'] is True
            and producer_run['controller_failure'] is None
            and producer_run['targets'] == ['//tools:codex_fresh_native_runtime_package']
            and producer_run['test_evidence']['state'] == 'preserved'
            and fresh.HASH.fullmatch(selected['producer_graph_sha256'])
            and producer_run['graph_sha256'] == selected['producer_graph_sha256'])
        graph_inputs = producer_run['graph_inputs']
        fresh.require('tools/codex_fresh_native_runtime.py' in graph_inputs
            and fresh.HASH.fullmatch(selected['producer_source_sha256']))
        if package.get('kind') == 'omux-staged-native-package-selection-v1':
            from codex_staged_native_package_consumer import validate_producer_graph
            validate_producer_graph(graph_inputs)
        fresh.require(set(package['files']) == fresh.package_roles(package))
        staged_values = None
        if package.get('kind') == 'omux-staged-native-package-selection-v1':
            from codex_staged_native_package_consumer import load_inputs
            values,protocol_values,staged_values = load_inputs(package,
                lambda role,pin,maximum:read(pin,maximum))
        else:
            values = {name:read(pin, fresh.runtime.MAX_ORIGINAL_BYTES if name == 'codex'
                else fresh.MAX_METADATA) for name,pin in package['files'].items()}
        protocol = package['protocol_schema_files']
        fresh.require(isinstance(protocol,dict) and 0 < len(protocol) <= 4096)
        total = 0
        if staged_values is None:
            protocol_values = {}
        for name, pin in (() if staged_values is not None else protocol.items()):
            raw = read(pin, fresh.MAX_PROTOCOL)
            total += len(raw)
            fresh.require(total <= fresh.MAX_PROTOCOL)
            fresh.parse(raw)
            protocol_values[name] = raw
        fresh.validate_protocol_inventory(package)
        chain = fresh.validate_chain(package, values, protocol_values,staged_values)
        receipt_raw = read(selected['receipt'], fresh.MAX_METADATA)
        receipt = fresh.parse(receipt_raw)
        payload = read(selected['archive'], fresh.runtime.MAX_ARCHIVE_BYTES)
        manifest_raw = read(selected['manifest'], fresh.runtime.MAX_METADATA)
        manifest, files = fresh.verify_runtime_files(payload, receipt)
        fresh.require(receipt['chain'] == chain and fresh.encoded(manifest) == manifest_raw
            and fresh.digest(manifest_raw) == receipt['manifest_sha256'])
        for evidence in (receipt, manifest):
            fresh.require(evidence['selection_sha256'] == selected['package_selection']['sha256']
                and evidence['producer_source_sha256'] == selected['producer_source_sha256']
                and evidence['producer_target'] == '//tools:codex_fresh_native_runtime_package')
        rows = {name:{'sha256':fresh.digest(raw),'bytes':len(raw),
            'mode':0o444 if name == fresh.runtime.CA else 0o555} for name,raw in files.items()}
        fresh.require(receipt['runtime_inventory'] == rows and len(rows) <= fresh.MAX_RUNTIME_FILES)
        root = fresh.canonical_path(selected['bundle_directory'])
        output_base = producer_run.get('output_base')
        if output_base is None:
            output_base = str(run_path.parent/'output-base')
        output_base = fresh.canonical_path(output_base)
        fresh.require(output_base == run_path.parent/'output-base' or
            output_base.parent.parent == run_home and output_base.name == 'output-base'
            and output_base.parent.name.startswith('cache-v2-'))
        package_outputs = output_base/'execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_fresh_native_runtime_package/test.outputs/fresh-native-runtime'
        fresh.require(root.parent == package_outputs and all(
            fresh.canonical_path(selected[role]['path']).parent == package_outputs
            for role in ('archive','manifest','receipt')))
        backend = receipt['executable']
        fresh.require(root.name == backend['packaged_sha256'])
        expected = {'codex','native-source-receipt.json',*('runtime/'+name for name in files)}
        expected_dirs = {str(parent) for name in expected for parent in Path(name).parents
            if str(parent) != '.'}
        fresh.require(sealed_members(root) == (expected, expected_dirs))
        for name,raw in {'codex':files[fresh.runtime.BACKEND],
                'native-source-receipt.json':receipt_raw,
                **{'runtime/'+name:value for name,value in files.items()}}.items():
            path = root/name
            pin = {'path':str(path),'sha256':fresh.digest(raw),'bytes':len(raw)}
            fresh.require(read(pin, fresh.runtime.MAX_BACKEND_BYTES) == raw)
            expected_mode = 0o444 if name in ('native-source-receipt.json','runtime/'+fresh.runtime.CA) else 0o555
            fresh.require(stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) == expected_mode)
        self.root = root
        self.selected = selected
        self.archive = fresh.canonical_path(selected['archive']['path'])
        self.manifest = fresh.canonical_path(selected['manifest']['path'])
        self.receipt = fresh.canonical_path(selected['receipt']['path'])
        self.facts = {'kind':fresh.KIND,'status':fresh.STATUS,'selection_sha256':self.selection_pin['sha256'],
            'archive_sha256':selected['archive']['sha256'],'receipt_sha256':selected['receipt']['sha256'],
            'package_selection_sha256':selected['package_selection']['sha256'],
            'candidate_cache_key':chain['candidate_cache_key'],'native_support':False,
            'provider_evaluation':False,'experimental_text_policy_compiled':True}
        return self.facts

    def close(self):
        pass
