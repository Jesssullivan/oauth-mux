"""Fresh maintained Codex runtime producer and public chain/ELF validators.

Only the declared Bazel target may run main. No historical runtime receipts,
provider calls, installation, or original-source mutation are performed.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / 'delivery'))
sys.path.insert(0, str(_ROOT / 'integrations/codex-owner-runtime'))
import portable
import runtime_package as runtime
from codex_live_source import BASE_RECEIPT_SHA, BASE_INVENTORY, COMMIT
from codex_native_profile import QUALIFICATION_GATES, STATE, PRODUCTION, COMBINED_MODE, CLI, BAZEL, CLI_CONTEXT_FIELDS
from codex_retained_sdk_export import SCHEMA as EXPORT_SCHEMA

KIND = 'omux-fresh-native-runtime-v1'
STATUS = 'experimental-qualified-native-runtime'
SELECTION_KIND = 'omux-fresh-native-package-selection-v1'
ROLES = frozenset(('source', 'export', 'compile', 'qualification_run',
    'qualification', 'qualification_xml', 'schema_run', 'config_schema', 'codex'))
JSON_ROLES = ROLES - {'codex', 'qualification_xml'}
MAX_METADATA = 256 * 1024 * 1024
MAX_PROTOCOL = 128 * 1024 * 1024
MAX_RUNTIME_FILES = 64
HASH = re.compile(r'[0-9a-f]{64}')
DEADLINE = None
PHASE2_PRIOR_TRANSITION = {
    'schema_version': 1,
    'amendment_sha256': 'dcc9aa881b415d041e582e0271efc6e0fca7dff2d35918de5e65848c5b9ce6f5',
    'prior_epoch': '34f674c0-9705-4135-b07d-7375fad6aa48',
    'prior_cleanup_receipt_sha256': '589b8f7c13e7c0d46393b40fb4fd377a4788ad4a5777721a99ee6c41cc514e9c',
    'from_controller_graph_sha256': '3fd85968c22ea532a2612a680c8ec8d1bfbe7e750f17e10805e2945a98468159',
    'to_controller_graph_sha256': '76dd5eda91e2ead7a131cb27d88c6cca6fecb48a2013a8ffb4e56adcf1a4d603',
    'from_provenance_sha256': '70d7fad0f82f7883e38ddfec2d343845f036dea4a6171ee213637e0b37669595',
    'to_provenance_sha256': 'fe79bd14702570ea829266247e858a8449ef5030f166f969675746f5f5adffb7',
    'from_attempt': 4,
    'first_attempt': 5,
    'aggregate_before': 6,
    'aggregate_max': 8,
}
PHASE2_FAILED_EPOCH = '275e4094-af7e-4c26-a390-bf8aa960310e'
PHASE2_FAILED_RECEIPT = '960f154b3ddcc7b05c9ea11b054dc6ddc329782eb9f14d50301e966dfa97b260'


def require(ok, message='fresh runtime contract refused'):
    if not ok:
        raise ValueError(message)


def tick():
    require(DEADLINE is None or time.monotonic() < DEADLINE,
        'fresh runtime deadline reached')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def unique(pairs):
    out = {}
    for name, value in pairs:
        require(name not in out, 'duplicate fresh runtime metadata key')
        out[name] = value
    return out


def parse(value):
    require(len(value) <= MAX_METADATA, 'fresh runtime metadata bound')
    return json.loads(value, object_pairs_hook=unique)


def canonical_path(value):
    require(isinstance(value, str) and value.startswith('/') and
        str(Path(value)) == value and '..' not in Path(value).parts and
        not any(c.isspace() or c in ':\\' for c in value),
        'fresh runtime canonical selected path required')
    return Path(value)


def trusted(path):
    path = canonical_path(str(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(path.parts[1:]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            shared = index < len(path.parts)-2 and info.st_mode & stat.S_ISVTX
            require(info.st_uid in (0, os.getuid()) and
                (not info.st_mode & 0o022 or shared), 'fresh runtime parent custody')
        require(os.fstat(fd).st_uid == os.getuid(), 'fresh runtime leaf directory ownership')
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_selected(path, pin, maximum):
    tick()
    require(set(pin) == {'path', 'sha256', 'bytes'} and
        HASH.fullmatch(pin['sha256']) and type(pin['bytes']) is int and
        0 <= pin['bytes'] <= maximum and str(path) == pin['path'],
        'fresh runtime selected file pin')
    parent = trusted(path.parent)
    try:
        child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(child)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                not before.st_mode & 0o022 and before.st_size == pin['bytes'],
                'fresh runtime selected file custody')
            values, count = [], 0
            while True:
                tick()
                value = os.read(child, 1024 * 1024)
                if not value:
                    break
                count += len(value)
                require(count <= maximum, 'fresh runtime file bound')
                values.append(value)
            after = os.fstat(child)
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'fresh runtime selected bytes changed')
            value = b''.join(values)
            require(count == pin['bytes'] and digest(value) == pin['sha256'],
                'fresh runtime selected bytes differ')
            return value
        finally:
            os.close(child)
    finally:
        os.close(parent)


def output_file(root, name, value, mode):
    path = root / name
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = trusted(path.parent)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def validate_public_receipt_path(role, value):
    home = Path('/home/jess/.local/state/omux-execution-20261005')
    fast = Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005')
    require(role in ('source','export'), 'fresh public receipt role')
    path = canonical_path(value)
    allowed = (home,) if role == 'source' else (home,fast)
    roots = [root for root in allowed if path.is_relative_to(root)]
    require(len(roots) == 1, 'fresh public receipt exact root')
    relative = path.relative_to(roots[0])
    require(bool(relative.parts), 'fresh public receipt missing epoch')
    epoch_ok = bool(re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',relative.parts[0]))
    if role == 'export' and roots[0] == fast and relative.parts[1:] == ('sdk-private','sdk-export','receipt.json'):
        require(epoch_ok, 'fresh public export run epoch')
        return '//tools:codex_retained_sdk_export_run'
    suffix = (('codex_live_source_producer','codex-live-source','source-receipt.json')
        if role == 'source' else ('codex_retained_sdk_export_producer','sdk-private/sdk-export','receipt.json'))
    expected = ('output-base','execroot','_main','bazel-out','k8-fastbuild','testlogs','tools',suffix[0],
        'test.outputs',*suffix[1].split('/'),suffix[2])
    source_cache = role == 'source' and bool(re.fullmatch(r'cache-v2-[0-9a-f]{64}',relative.parts[0]))
    require(len(relative.parts) == len(expected)+1 and (epoch_ok or source_cache)
        and relative.parts[1:] == expected, 'fresh public receipt exact producer suffix')
    return '//tools:'+suffix[0]


def validate_export_producer(selection, exported):
    expected = validate_public_receipt_path('export', selection['files']['export']['path'])
    require(exported.get('producer') == expected, 'fresh export exact producer binding')


def validate_selection_paths(selection):
    """Refuse reads outside the exact public producer/guard output namespaces."""
    if selection.get('kind') == 'omux-protocol-history-native-package-selection-v1':
        from codex_protocol_history_package_consumer import validate_paths
        return validate_paths(selection)
    if selection.get('kind') == 'omux-staged-native-package-selection-v1':
        from codex_staged_native_package_consumer import validate_paths
        return validate_paths(selection)
    home = '/home/jess/.local/state/omux-execution-20261005/'
    require(selection['kind'] == SELECTION_KIND and set(selection['files']) == ROLES,
        'fresh runtime exact operator selection roles')
    for role, pin in selection['files'].items():
        path = str(canonical_path(pin['path']))
        if role in ('source','export'):
            validate_public_receipt_path(role, path)
        elif role in ('compile','qualification_run','schema_run','qualification','qualification_xml'):
            relative = canonical_path(path).relative_to(STATE)
            leaf = ('native-qualification.json' if role=='qualification' else
                'native-qualification.xml' if role=='qualification_xml' else 'receipt.json')
            require(len(relative.parts)==2 and relative.parts[1]==leaf and
                re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',relative.parts[0]),
                'fresh runtime guarded public metadata scope')
        else:
            relative = canonical_path(path).relative_to(STATE)
            suffix = 'codex-rs/cli/codex' if role=='codex' else 'bazel/schema/native-config.schema.json'
            require(len(relative.parts)>=8 and re.fullmatch(r'cache-v2-[0-9a-f]{64}',relative.parts[0]) and
                relative.parts[1:5]==('output-base','execroot','_main','bazel-out') and
                re.fullmatch(r'[A-Za-z0-9_.-]+-opt',relative.parts[5]) and relative.parts[6]=='bin'
                and '/'.join(relative.parts[7:])==suffix, 'fresh runtime exact declared binary/schema scope')
    for name, pin in selection['protocol_schema_files'].items():
        path = canonical_path(pin['path'])
        relative = path.relative_to(STATE)
        parts = PurePosixPath(name).parts
        require(len(parts)>=3 and parts[0] in ('stable','experimental') and parts[1]=='json'
            and str(PurePosixPath(name))==name and not any(p in ('','.','..') for p in parts)
            and name.endswith('.json') and len(relative.parts)>=12 and
            re.fullmatch(r'cache-v2-[0-9a-f]{64}',relative.parts[0]) and
            relative.parts[1:5]==('output-base','execroot','_main','bazel-out') and
            re.fullmatch(r'[A-Za-z0-9_.-]+-opt',relative.parts[5]) and relative.parts[6:9]==('bin','bazel','schema')
            and relative.parts[9]=='public-schema-bundle.'+parts[0] and
            '/'.join(relative.parts[10:])=='/'.join(parts[1:]), 'fresh runtime exact public protocol JSON scope')


def validate_protocol_inventory(selection):
    """Enumerate only the complete two declared public JSON schema subtrees."""
    if selection.get('kind') == 'omux-protocol-history-native-package-selection-v1':
        from codex_protocol_history_package_consumer import validate_protocol_inventory as verify
        return verify(selection)
    roots = selection['protocol_schema_roots']
    require(set(roots) == {'stable','experimental'}, 'fresh protocol JSON root modes differ')
    observed = set()
    for mode, value in roots.items():
        root = canonical_path(value)
        relative = root.relative_to(STATE)
        require(len(relative.parts) == 11 and re.fullmatch(r'cache-v2-[0-9a-f]{64}', relative.parts[0])
            and relative.parts[1:5] == ('output-base','execroot','_main','bazel-out')
            and re.fullmatch(r'[A-Za-z0-9_.-]+-opt', relative.parts[5])
            and relative.parts[6:] == ('bin','bazel','schema','public-schema-bundle.'+mode,'json'),
            'fresh protocol JSON root leaves declared native schema output')
        fd = trusted(root)
        def walk(parent, prefix=''):
            for name in sorted(os.listdir(parent)):
                tick()
                require(name not in ('','.','..') and '/' not in name and
                    not any(c in name for c in '\\\0\r\n\t'), 'fresh protocol JSON member name')
                info = os.stat(name,dir_fd=parent,follow_symlinks=False)
                require(info.st_uid == os.getuid() and not info.st_mode & 0o022,
                    'fresh protocol JSON member custody')
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                    try:
                        walk(child,prefix+name+'/')
                    finally:
                        os.close(child)
                else:
                    require(stat.S_ISREG(info.st_mode) and name.endswith('.json'),
                        'fresh protocol JSON foreign member')
                    observed.add(mode+'/json/'+prefix+name)
                    require(len(observed) <= 4096, 'fresh protocol JSON inventory bound')
        try:
            walk(fd)
        finally:
            os.close(fd)
    require(observed == set(selection['protocol_schema_files']),
        'fresh protocol JSON subtree complete membership differs')


def validate_fresh_completion_receipts(selection, values, source, exported):
    from codex_native_fresh_completion import consumed_dispatches
    from codex_native_profile import core_codegen_policy
    import codex_native_profile as native
    require(selection['files']['compile'] == selection['files']['qualification_run']
        and values['compile'] == values['qualification_run'], 'fresh completion actual combined receipt required')
    history = consumed_dispatches()
    require(len(history) == 8, 'fresh completion exact eight consumed dispatches')
    receipts, key = {}, None
    policy = core_codegen_policy()
    for role, attempt, mode, targets in (
            ('qualification_run',9,COMBINED_MODE,(*tuple(QUALIFICATION_GATES),CLI)),
            ('schema_run',10,'schema',('//bazel/schema:native-config-schema','//bazel/schema:public-schema-bundle'))):
        value = parse(values[role])
        require(value['profile'] == 'codex-native' and type(value['exit']) is int and value['exit'] == 0
            and type(value['workload_exit']) is int and value['workload_exit'] == 0
            and value['descendants_empty'] is True and value['controller_failure'] is None
            and value['test_evidence']['state'] == ('preserved' if attempt == 9 else 'not-applicable')
            and value['native_candidate_cache'] is None
            and value['native_sdk']['mode'] == mode and value['targets'] == list(targets)
            and value['native_sdk']['source_and_export_verified_after_cleanup'] is True
            and value['native_sdk']['source_receipt_sha256'] == selection['files']['source']['sha256']
            and value['native_sdk']['export_receipt_sha256'] == selection['files']['export']['sha256'],
            'fresh completion successful guarded action required')
        candidate = value['native_fresh_completion']
        require(candidate['kind'] == 'omux-native-fresh-core-completion-v1'
            and type(candidate['global_attempt']) is int and candidate['global_attempt'] == attempt
            and type(candidate['max_global_attempts']) is int and candidate['max_global_attempts'] == 10
            and candidate['verified_before_launch'] is True and candidate['verified_after_cleanup'] is True
            and HASH.fullmatch(candidate['key']) and HASH.fullmatch(candidate['provenance_sha256'])
            and candidate['key'] == candidate['provenance_sha256'] and candidate['core_codegen'] == policy,
            'fresh completion dedicated provenance required')
        require(value['manager'] == 'system' and value['source_dirty'] == 'false'
            and re.fullmatch(r'[0-9a-f]{40}',value['source_commit'])
            and candidate['source_commit'] == value['source_commit']
            and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value['id'])
            and value['unit'] == 'omux-execution-'+value['id']+'.service'
            and value['output_base'] == candidate['output_base']
            and HASH.fullmatch(candidate['selector_sha256']), 'fresh completion owned clean controller binding')
        observed = (candidate['key'],candidate['provenance_sha256'],candidate['workspace'],candidate['output_base'])
        require(key is None or key == observed, 'fresh completion same new output namespace required')
        key = observed
        root = STATE/('cache-v2-'+key[0])
        sdk = value['native_sdk']
        require(canonical_path(key[2]) == root/'native-input/source'
            and canonical_path(key[3]) == root/'output-base'
            and sdk['plan']['candidate_output_base'] == key[3]
            and sdk['plan']['source_inventory_sha256'] == source['inventory_sha256']
            and sdk['plan']['export_inventory_sha256'] == exported['inventory_sha256']
            and sdk['plan']['core_codegen'] == policy
            and sdk['aggregate_seconds'] == 3600
            and type(sdk['original_entry_monotonic_ns']) is int
            and type(sdk['original_deadline_monotonic_ns']) is int
            and sdk['original_deadline_monotonic_ns']-sdk['original_entry_monotonic_ns'] == 3600*10**9
            and sdk['plan']['argv'][0] == BAZEL
            and canonical_path(selection['files'][role]['path']) == STATE/value['id']/'receipt.json',
            'fresh completion exact policy source output and original deadline required')
        argv = sdk['plan']['argv']
        require(sdk['plan']['cwd'] == key[2]
            and sdk['plan']['mapping_sha256'] == exported['mapping_sha256']
            and sdk['plan']['environment']['USE_BAZEL_VERSION'] == native.BAZEL_VERSION
            and [flag for flag in argv if flag.startswith('--'+native.CORE_CODEGEN_SETTING+'=')]
                == native.core_codegen_arguments()
            and all(flag in argv for flag in ('--lockfile_mode=error','--repository_disable_download',
                '--sandbox_default_allow_network=false','--jobs=1','--host_jvm_args=-Xmx768m',
                '--repo_contents_cache=','--disk_cache=','--remote_executor=','--remote_cache='))
            and (attempt != 9 or '--local_test_jobs=1' in argv), 'fresh completion fixed emitted plan required')
        expected = list(history)
        if attempt == 10:
            prior = receipts['qualification_run']
            expected.append({'id':prior['id'],'sha256':selection['files']['qualification_run']['sha256'],
                'cache_key':key[0],'attempt':9})
        require(candidate['previous_dispatches'] == expected, 'fresh completion all consumed dispatches retained')
        receipts[role] = value
    qualification, schema = receipts['qualification_run'], receipts['schema_run']
    require(qualification['id'] != schema['id'] and HASH.fullmatch(qualification['graph_sha256'])
        and qualification['graph_sha256'] == schema['graph_sha256'], 'fresh completion same frozen graph required')
    require(qualification['source_commit'] == schema['source_commit']
        and qualification['native_fresh_completion']['selector_sha256'] ==
            schema['native_fresh_completion']['selector_sha256'], 'fresh completion same source selector required')
    receipts['compile'] = qualification
    return receipts,key,True


def validate_action_receipts(selection, values, source, exported):
    """Join real successful action receipts; retain the historical three-role chain."""
    if selection.get('kind') == 'omux-staged-native-package-selection-v1':
        from codex_staged_native_package_consumer import validate_receipts
        return validate_receipts(selection,values,source,exported)
    receipts = {}
    cache = None
    combined = selection['files']['compile'] == selection['files']['qualification_run']
    if parse(values['qualification_run']).get('native_fresh_completion') is not None:
        return validate_fresh_completion_receipts(selection, values, source, exported)
    history = parse(values['qualification_run'])['native_candidate_cache'].get('transition_history') if combined else None
    phase2 = combined and isinstance(history, list) and len(history) == 2
    maximum = 7 if phase2 else 6
    first_attempt = 6 if phase2 else 5
    aggregate_before = 7 if phase2 else 6
    aggregate_max = 9 if phase2 else 8
    if combined:
        require(values['compile'] == values['qualification_run'],
            'combined compile and qualification must select the same actual receipt bytes')
    roles = (('qualification_run', COMBINED_MODE, (*tuple(QUALIFICATION_GATES), CLI)),
            ('schema_run', 'schema', ('//bazel/schema:native-config-schema', '//bazel/schema:public-schema-bundle'))) if combined else (
            ('compile', 'cli-opt', (CLI,)),
            ('qualification_run', 'qualification', tuple(QUALIFICATION_GATES)),
            ('schema_run', 'schema', ('//bazel/schema:native-config-schema', '//bazel/schema:public-schema-bundle')))
    for role, mode, targets in roles:
        value = parse(values[role])
        require(value['profile'] == 'codex-native' and value['exit'] == value['workload_exit'] == 0
            and value['descendants_empty'] is True and value['controller_failure'] is None
            and value['native_sdk']['mode'] == mode
            and value['native_sdk']['source_and_export_verified_after_cleanup'] is True
            and value['native_sdk']['source_receipt_sha256'] == selection['files']['source']['sha256']
            and value['native_sdk']['export_receipt_sha256'] == selection['files']['export']['sha256']
            and set(value['targets']) == set(targets) and len(value['targets']) == len(targets),
            'fresh runtime successful guarded action join differs')
        candidate = value['native_candidate_cache']
        require(candidate is not None and candidate['max_attempts'] == maximum
            and type(candidate['attempt']) is int and 1 <= candidate['attempt'] <= maximum
            and HASH.fullmatch(candidate['key']) and HASH.fullmatch(candidate['provenance_sha256']),
            'fresh runtime owned candidate provenance missing')
        key = (candidate['key'], candidate['provenance_sha256'], candidate['workspace'], candidate['output_base'])
        require(cache is None or cache == key, 'fresh runtime different candidate action chains')
        cache = key
        require(canonical_path(candidate['output_base']) == STATE/('cache-v2-'+candidate['key'])/'output-base'
            and value['native_sdk']['plan']['candidate_output_base'] == candidate['output_base']
            and value['native_sdk']['plan']['source_inventory_sha256'] == source['inventory_sha256']
            and value['native_sdk']['plan']['export_inventory_sha256'] == exported['inventory_sha256'],
            'fresh runtime actual output base/source/export join differs')
        receipt_path = canonical_path(selection['files'][role]['path'])
        require(receipt_path == STATE/value['id']/'receipt.json',
            'fresh runtime guarded action receipt path differs')
        receipts[role] = value
    require(len({r['native_candidate_cache']['attempt'] for r in receipts.values()}) == (2 if combined else 3)
        and len({r['id'] for r in receipts.values()}) == (2 if combined else 3),
        'fresh runtime distinct selected guarded actions required')
    if combined:
        qualification, schema = receipts['qualification_run'], receipts['schema_run']
        require(qualification['graph_sha256'] == schema['graph_sha256']
            and qualification['native_candidate_cache']['attempt'] == first_attempt
            and schema['native_candidate_cache']['attempt'] == first_attempt + 1,
            'combined actual graph and final two attempts required')
        history = qualification['native_candidate_cache'].get('transition_history')
        require(isinstance(history, list) and len(history) == (2 if phase2 else 1)
            and history == schema['native_candidate_cache'].get('transition_history'),
            'combined explicit identical cache transition required')
        transition = history[-1]
        required = {'schema_version', 'amendment_sha256', 'prior_epoch',
            'prior_cleanup_receipt_sha256', 'from_controller_graph_sha256',
            'to_controller_graph_sha256', 'from_provenance_sha256', 'to_provenance_sha256',
            'from_attempt', 'first_attempt', 'aggregate_before', 'aggregate_max'}
        require(set(transition) == required and transition['schema_version'] == (2 if phase2 else 1)
            and transition['from_attempt'] == first_attempt - 1 and transition['first_attempt'] == first_attempt
            and transition['aggregate_before'] == aggregate_before and transition['aggregate_max'] == aggregate_max
            and transition['from_provenance_sha256'] == (PHASE2_PRIOR_TRANSITION['to_provenance_sha256'] if phase2 else cache[0])
            and transition['to_provenance_sha256'] == cache[1]
            and transition['to_controller_graph_sha256'] == qualification['graph_sha256']
            and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                transition['prior_epoch'])
            and all(isinstance(transition[k], str) and HASH.fullmatch(transition[k])
                for k in required if k.endswith('_sha256')),
            'combined closed cache transition provenance differs')
        if phase2:
            require(encoded(history[0]) == encoded(PHASE2_PRIOR_TRANSITION)
                and cache[0] == PHASE2_PRIOR_TRANSITION['from_provenance_sha256']
                and transition['from_controller_graph_sha256'] == PHASE2_PRIOR_TRANSITION['to_controller_graph_sha256']
                and transition['prior_epoch'] == PHASE2_FAILED_EPOCH
                and transition['prior_cleanup_receipt_sha256'] == PHASE2_FAILED_RECEIPT,
                'phase2 must preserve exact phase1 amendment and actual failed fifth attempt')
        for receipt in receipts.values():
            candidate = receipt['native_candidate_cache']
            if phase2:
                budget = receipt['native_sdk']
                require(candidate.get('phase2_verified_before_launch') is True
                    and type(budget.get('aggregate_seconds')) is int and budget['aggregate_seconds'] == 3600
                    and type(budget.get('original_entry_monotonic_ns')) is int
                    and budget['original_entry_monotonic_ns'] >= 0
                    and type(budget.get('original_deadline_monotonic_ns')) is int
                    and budget['original_deadline_monotonic_ns'] == budget['original_entry_monotonic_ns'] + 3600 * 10**9,
                    'phase2 actual receipt must retain original-entry native deadline')
            require(candidate.get('origin_provenance_sha256') == cache[0]
                and candidate.get('aggregate_attempt') == candidate['attempt'] + 2
                and candidate.get('aggregate_max_attempts') == aggregate_max
                and candidate.get('transition_verified_after_cleanup') is True,
                'combined counters/origin and final transition readback required')
        previous = qualification['native_candidate_cache'].get('aggregate_previous_dispatches')
        after = schema['native_candidate_cache'].get('aggregate_previous_dispatches')
        require(isinstance(previous, list) and len(previous) == aggregate_before
            and isinstance(after, list) and len(after) == aggregate_before + 1 and after[:aggregate_before] == previous
            and after[aggregate_before] == {'id':qualification['id'],
                'sha256':selection['files']['qualification_run']['sha256'],
                'cache_key':cache[0], 'attempt':first_attempt},
            'combined global predecessor history must preserve all consumed dispatches')
        require(len({row['id'] for row in previous}) == aggregate_before,
            'combined global predecessor invocations must be distinct')
        if phase2:
            require(previous[-1] == {'id':PHASE2_FAILED_EPOCH, 'sha256':PHASE2_FAILED_RECEIPT,
                'cache_key':cache[0], 'attempt':5}, 'phase2 cannot drop or rewrite failed fifth dispatch')
        for row in previous:
            require(set(row) == {'id','sha256','cache_key','attempt'}
                and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',row['id'])
                and HASH.fullmatch(row['sha256']) and HASH.fullmatch(row['cache_key'])
                and type(row['attempt']) is int and 1 <= row['attempt'] <= maximum,
                'combined exact historical dispatch evidence required')
        receipts['compile'] = qualification
    return receipts, cache, combined


def validate_combined_cli(group, selection, values, receipt, source, exported):
    fresh_candidate = receipt.get('native_fresh_completion')
    candidate = receipt['native_staged_compilation'] if selection.get('kind') == 'omux-staged-native-package-selection-v1' else (
        fresh_candidate if fresh_candidate is not None else receipt['native_candidate_cache'])
    context = {
        'invocation_id': receipt['id'],
        'output_base': candidate['output_base'],
        'source_receipt_sha256': selection['files']['source']['sha256'],
        'export_receipt_sha256': selection['files']['export']['sha256'],
        'source_inventory_sha256': source['inventory_sha256'],
        'export_inventory_sha256': exported['inventory_sha256'],
        'candidate_cache_key': candidate['key'],
        'candidate_provenance_sha256': candidate['provenance_sha256'],
        'controller_graph_sha256': receipt['graph_sha256'],
        'bazel': BAZEL, 'workload_exit': 0, 'descendants_empty': True,
        'source_and_export_verified_after_cleanup': True,
    }
    require(set(context) == CLI_CONTEXT_FIELDS and group.get('cli_context') == context
        and receipt['native_sdk']['plan']['argv'][0] == BAZEL,
        'combined actual CLI context must join the real successful guarded action')
    pin = selection['files']['codex']
    relative = canonical_path(pin['path']).relative_to(
        canonical_path(context['output_base'])/'execroot/_main/bazel-out')
    require(len(relative.parts) == 5 and relative.parts[1:] == ('bin','codex-rs','cli','codex')
        and re.fullmatch(r'[A-Za-z0-9_.-]+-opt', relative.parts[0]),
        'combined actual CLI exact explicit label output required')
    expected = {'kind': 'actual-explicit-cli-target-v1', 'target': CLI,
        'configuration': relative.parts[0], **pin}
    require(group.get('cli_artifact') == expected and values['codex'].startswith(b'\x7fELF')
        and len(values['codex']) == pin['bytes'] and digest(values['codex']) == pin['sha256'],
        'combined actual CLI bytes differ from post-cleanup artifact evidence')

def package_roles(selection):
    if selection.get('kind') == 'omux-protocol-history-native-package-selection-v1':
        from codex_protocol_history_package_consumer import ROLES as protocol_roles
        return protocol_roles
    if selection.get('kind') == 'omux-staged-native-package-selection-v1':
        from codex_staged_native_package_consumer import ROLES as staged_roles
        return staged_roles
    require(selection.get('kind') == SELECTION_KIND, 'fresh exact selection kind required')
    return ROLES


def validate_chain(selection, values, protocol_values, staged_values=None):
    """Consume independently selected source/build/test/schema evidence bytes."""
    if selection.get('kind') == 'omux-protocol-history-native-package-selection-v1':
        from codex_protocol_history_package_consumer import validate_chain as verify
        require(isinstance(staged_values,dict), 'protocol-history declared actual evidence required')
        return verify(selection,values,protocol_values,staged_values)
    validate_selection_paths(selection)
    roles = package_roles(selection)
    require(set(selection['files']) == roles and set(values) == roles,
        'fresh runtime exact input roles')
    for role, value in values.items():
        pin = selection['files'][role]
        require(digest(value) == pin['sha256'] and len(value) == pin['bytes'],
            'fresh runtime chain input byte pins differ')
    require(set(protocol_values) == set(selection['protocol_schema_files']),
        'fresh runtime selected protocol byte roles differ')
    for name, value in protocol_values.items():
        pin = selection['protocol_schema_files'][name]
        require(digest(value) == pin['sha256'] and len(value) == pin['bytes']
            and isinstance(parse(value),dict), 'fresh runtime protocol byte pins differ')
    source, exported = parse(values['source']), parse(values['export'])
    validate_export_producer(selection, exported)
    pins = selection['patch_sha256']
    require(len(pins) == 3 and all(HASH.fullmatch(p) for p in pins),
        'fresh runtime three native patches required')
    require(source['status'] == 'verified-fresh-native-candidate' and source['commit'] == COMMIT
        and source['baseline_receipt_sha256'] == BASE_RECEIPT_SHA
        and source['baseline_inventory_sha256'] == BASE_INVENTORY
        and source['patch_sha256'] == pins
        and all(source[k] is False for k in ('native_support', 'native_compile_passed', 'provider_evaluation')),
        'fresh runtime source binding differs')
    inventory = source['source_inventory']
    require(len(inventory) == source['tracked_files'] and
        digest(json.dumps(inventory, sort_keys=True).encode()) == source['inventory_sha256'],
        'fresh runtime source inventory digest differs')
    require(exported['schema'] == EXPORT_SCHEMA and exported['qualification_only'] is False
        and exported['baseline_inventory_sha256'] == BASE_INVENTORY
        and exported['graph_files'] == source['baseline_graph_files'],
        'fresh runtime retained SDK binding differs')
    source_root = canonical_path(selection['source_root'])
    export_root = canonical_path(selection['export_root'])
    require(selection['files']['source']['path'] == str(source_root/'source-receipt.json')
        and selection['files']['export']['path'] == str(export_root/'receipt.json'),
        'fresh runtime source/export selected receipt paths differ')
    declaration = source['native_schema_declaration']
    require(declaration['target'] == '//bazel/schema:native-config-schema'
        and declaration['before_sha256'] == '9e047e20da76b99608595a8abfb23b5e8633c5ba454f2de548b8e70744c72df6'
        and inventory[declaration['path']]['sha256'] == declaration['after_sha256'],
        'fresh runtime generated schema source declaration differs')
    receipts, cache, combined = validate_action_receipts(selection, values, source, exported)
    staged_chain = None
    if selection['kind'] == 'omux-staged-native-package-selection-v1':
        from codex_staged_native_package_consumer import validate_artifacts
        require(isinstance(staged_values,dict), 'staged actual qualification logs required')
        staged_chain = validate_artifacts(selection,values,protocol_values,staged_values,receipts)
    group = parse(values['qualification'])
    require(group['schema'] == 'omux-native-grouped-qualification-v1'
        and group['passed'] == 14 and group['failed'] == group['ignored'] == 0
        and group['native_support'] is False and group['provider_evaluation'] is False
        and group['xml_sha256'] == digest(values['qualification_xml'])
        and set(group['targets']) == set(QUALIFICATION_GATES),
        'fresh runtime grouped14 qualification differs')
    if combined:
        validate_combined_cli(group, selection, values, receipts['qualification_run'], source, exported)
    qualified_root = STATE/receipts['qualification_run']['id']
    require(selection['files']['qualification']['path'] == str(qualified_root/'native-qualification.json')
        and selection['files']['qualification_xml']['path'] == str(qualified_root/'native-qualification.xml'),
        'fresh runtime qualification output path differs')
    xml = ET.fromstring(values['qualification_xml'])
    require(xml.tag == 'testsuites' and xml.attrib == {'tests':'14','failures':'0','errors':'0','skipped':'0'},
        'fresh runtime grouped XML counts differ')
    suites = xml.findall('testsuite')
    require(len(suites) == 3 and {s.get('name') for s in suites} == set(QUALIFICATION_GATES),
        'fresh runtime grouped XML targets differ')
    for target, names in QUALIFICATION_GATES.items():
        row = group['targets'][target]
        require(row['tests'] == sorted(names) and HASH.fullmatch(row['log_sha256']),
            'fresh runtime exact grouped gate names differ')
        suite = next(s for s in suites if s.get('name') == target)
        cases = suite.findall('testcase')
        require(suite.get('tests') == str(len(names)) and
            all(suite.get(k) == '0' for k in ('failures','errors','skipped')) and
            len(cases) == len(names) and sorted(c.get('name') for c in cases) == sorted(names)
            and all(c.get('classname') == target and len(c) == 0 for c in cases),
            'fresh runtime exact grouped XML gates differ')
        props = suite.findall('properties/property')
        require(len(props) == 1 and props[0].attrib ==
            {'name':'actual_test_log_sha256','value':row['log_sha256']},
            'fresh runtime grouped XML log binding differs')
    output_base = canonical_path(cache[3])
    def artifact(path, suffix):
        path = canonical_path(path)
        relative = path.relative_to(output_base/'execroot/_main/bazel-out')
        require(len(relative.parts) >= 3 and re.fullmatch(r'[A-Za-z0-9_.-]+-opt', relative.parts[0])
            and relative.parts[1] == 'bin' and '/'.join(relative.parts[2:]) == suffix,
            'fresh runtime declared generated artifact path differs')
        return relative.parts[0]
    config = artifact(selection['files']['codex']['path'], 'codex-rs/cli/codex')
    require(artifact(selection['files']['config_schema']['path'], 'bazel/schema/native-config.schema.json') == config,
        'fresh runtime selected configurations differ')
    config_schema = parse(values['config_schema'])
    definitions = config_schema.get('definitions', config_schema.get('$defs', {}))
    require(definitions['OmuxBrokerContextMode']['enum'] == ['full_native','text_transcript_v1']
        and definitions['OmuxBrokerConfig']['properties']['context_mode']['default'] == 'full_native',
        'fresh runtime generated config policy missing')
    schema_files = selection['protocol_schema_files']
    require(isinstance(schema_files, dict) and 0 < len(schema_files) <= 4096
        and {'stable', 'experimental'} == {name.split('/')[0] for name in schema_files},
        'fresh runtime protocol schema modes missing')
    for name, pin in schema_files.items():
        parts = PurePosixPath(name).parts
        require(len(parts) >= 3 and parts[1] == 'json' and str(PurePosixPath(name)) == name and
            not any(p in ('', '.', '..') for p in parts) and name.endswith('.json'),
            'fresh runtime protocol schema selected name differs')
        suffix = 'bazel/schema/public-schema-bundle.'+parts[0]+'/'+('/'.join(parts[1:]))
        require(artifact(pin['path'], suffix) == config,
            'fresh runtime protocol schema generated output join differs')
    require(set(selection['protocol_schema_roots']) == {'stable','experimental'} and all(
        selection['protocol_schema_roots'][mode] == str(output_base/'execroot/_main/bazel-out'/config/'bin/bazel/schema'/('public-schema-bundle.'+mode)/'json')
        for mode in ('stable','experimental')), 'fresh runtime protocol JSON root join differs')
    chain = {'upstream_commit': COMMIT, 'patch_sha256': pins,
        'source_inventory_sha256':source['inventory_sha256'],
        'export_inventory_sha256':exported['inventory_sha256'],
        'candidate_cache_key':cache[0], 'candidate_provenance_sha256':cache[1],
        'configuration':config,
        'compile_invocation_id':receipts['compile']['id'],
        'qualification_invocation_id':receipts['qualification_run']['id'],
        'schema_invocation_id':receipts['schema_run']['id'],
        'input_files': selection['files'], 'protocol_schema_files':schema_files,
        'protocol_schema_roots':selection['protocol_schema_roots'],
        'qualified_tests':group['targets'],
        **({'fresh_completion': {'kind':'omux-native-fresh-core-completion-v1',
            'qualification':receipts['qualification_run']['native_fresh_completion'],
            'schema':receipts['schema_run']['native_fresh_completion']}}
            if receipts['qualification_run'].get('native_fresh_completion') is not None else {})}
    if combined:
        chain.update(compile_evidence_kind='successful-explicit-cli-target-in-qualification',
            cli_artifact=group['cli_artifact'], cli_context=group['cli_context'])
        if staged_chain is not None:
            chain['compile_evidence_kind'] = 'staged-explicit-cli-build-rehashed-in-qualification'
            chain['native_staged_compilation'] = staged_chain
        elif receipts['qualification_run'].get('native_fresh_completion') is None:
            chain['candidate_cache_transition'] = receipts['qualification_run']['native_candidate_cache']['transition_history']
    return chain


def verify_runtime_files(payload, receipt):
    """Check this fresh manifest plus every portable ELF dependency edge."""
    require(receipt['kind'] == KIND and receipt['status'] == STATUS and
        receipt['native_support'] is False and receipt['provider_evaluation'] is False
        and receipt['experimental_text_policy_compiled'] is True and
        len(payload) == receipt['archive_bytes'] and digest(payload) == receipt['archive_sha256']
        and len(payload) <= runtime.MAX_ARCHIVE_BYTES, 'fresh runtime archive receipt differs')
    with gzip.GzipFile(fileobj=io.BytesIO(payload)) as stream:
        raw = stream.read(runtime.MAX_RUNTIME_BYTES + runtime.MAX_METADATA_BYTES + 1)
    require(len(raw) <= runtime.MAX_RUNTIME_BYTES + runtime.MAX_METADATA_BYTES,
        'fresh runtime decompression bound')
    files, modes = {}, {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            name = member.name
            bound = runtime.MAX_BACKEND_BYTES if name == runtime.BACKEND else (
                runtime.MAX_METADATA_BYTES if name == runtime.MANIFEST else portable._MAX_FILE)
            require(member.isfile() and name not in files and len(files) <= MAX_RUNTIME_FILES
                and str(PurePosixPath(name)) == name and not name.startswith('/')
                and not any(p in ('', '.', '..') for p in PurePosixPath(name).parts)
                and not any(c in name for c in '\\\0\r\n\t') and 0 <= member.size <= bound
                and member.mode in (0o644,0o755), 'fresh runtime unsafe archive member')
            value = archive.extractfile(member).read(bound+1)
            require(len(value) == member.size, 'fresh runtime truncated archive member')
            files[name], modes[name] = value, member.mode
    require(digest(files[runtime.MANIFEST]) == receipt['manifest_sha256']
        and modes[runtime.MANIFEST] == 0o644, 'fresh runtime manifest pin differs')
    manifest = parse(files[runtime.MANIFEST])
    require(manifest['kind'] == KIND and manifest['status'] == STATUS and
        manifest['native_support'] is False and manifest['provider_evaluation'] is False
        and manifest['experimental_text_policy_compiled'] is True
        and manifest['chain'] == receipt['chain'] and manifest['executable'] == receipt['executable']
        and manifest['selection_sha256'] == receipt['selection_sha256']
        and manifest['producer_source_sha256'] == receipt['producer_source_sha256']
        and manifest['producer_target'] == receipt['producer_target'] == '//tools:codex_fresh_native_runtime_package',
        'fresh runtime manifest identity differs')
    require(set(files) == set(manifest['files']) | {runtime.MANIFEST}
        and sum(len(v) for n,v in files.items() if n != runtime.MANIFEST) <= runtime.MAX_RUNTIME_BYTES,
        'fresh runtime exact membership differs')
    for name, row in manifest['files'].items():
        require(row == {'sha256':digest(files[name]),'bytes':len(files[name]),'mode':modes[name]},
            'fresh runtime archive member bytes differ')
    require(receipt['runtime_inventory'] == {n:{'sha256':row['sha256'],'bytes':row['bytes'],
        'mode':0o444 if n==runtime.CA else 0o555} for n,row in manifest['files'].items()},
        'fresh runtime sealed inventory differs')
    info = manifest['runtime']
    dependencies = info['dependencies']
    require(dependencies == sorted(set(dependencies)) and 0 < len(dependencies) < MAX_RUNTIME_FILES
        and info['loader'] in dependencies and info['caBundle'] == runtime.CA
        and info['backendInterpreter'] == portable._BACKEND_INTERPRETER
        and set(files) == {runtime.MANIFEST,'bin/codex',runtime.BACKEND,runtime.CA,*dependencies},
        'fresh runtime closed dependency membership differs')
    names = {Path(n).name for n in dependencies}
    for name in [runtime.BACKEND,*dependencies]:
        require(name == runtime.BACKEND or name == runtime.PREFIX+'lib/'+portable._basename(name),
            'fresh runtime dependency leaves library directory')
        metadata = portable.elf_metadata(files[name],
            max_bytes=runtime.MAX_BACKEND_BYTES if name == runtime.BACKEND else portable._MAX_FILE)
        require(metadata['machine'] == 62 and all('/' not in n and n in names for n in metadata['needed']),
            'fresh runtime ELF edge leaves closed graph')
        if name == runtime.BACKEND:
            require(metadata['interpreter'] == portable._BACKEND_INTERPRETER and
                metadata['rpath'] == ['$ORIGIN/../lib'], 'fresh runtime backend lookup differs')
        else:
            require(metadata['interpreter'] in (None, portable._BACKEND_INTERPRETER) and
                all(n == '$ORIGIN' for n in metadata['rpath']), 'fresh runtime library lookup differs')
    require(files['bin/codex'] == runtime.codex_launcher(Path(info['loader']).name),
        'fresh runtime fixed launcher differs')
    portable._verify_ca_bundle(files[runtime.CA])
    require(digest(files[runtime.BACKEND]) == receipt['executable']['packaged_sha256']
        and len(files[runtime.BACKEND]) == receipt['executable']['packaged_bytes'],
        'fresh runtime packaged backend differs')
    return manifest, {n:v for n,v in files.items() if n != runtime.MANIFEST}


def package(selection, values, protocol_values, runtime_files, args, output, staged_values=None):
    validate_protocol_inventory(selection)
    chain = validate_chain(selection, values, protocol_values,staged_values)
    original = values['codex']
    require(0 < len(original) <= runtime.MAX_ORIGINAL_BYTES,
        'fresh runtime original backend bound')
    private = output/'.transform'
    private.mkdir(mode=0o700)
    try:
        copied = private/'codex'
        output_file(private, 'codex', original, 0o755)
        runtime.run_tool([str(args.strip), '--strip-all', str(copied)], args.tool_path)
        stripped = portable._read(copied, max_bytes=runtime.MAX_BACKEND_BYTES)
        metadata = portable.elf_metadata(stripped, max_bytes=runtime.MAX_BACKEND_BYTES)
        loader, witness = runtime.select_loader(metadata, runtime_files)
        runtime.run_tool([str(args.patchelf), '--set-interpreter', str(loader), str(copied)], args.tool_path)
        files, runtime_info = runtime.assemble_runtime(copied, runtime_files, args.patchelf, args.ca_bundle)
    finally:
        if (private/'codex').exists():
            (private/'codex').unlink()
        private.rmdir()
    executable = {'backend_max_bytes':runtime.MAX_BACKEND_BYTES,
        'original_sha256':digest(original),'original_bytes':len(original),
        'stripped_sha256':digest(stripped),'stripped_bytes':len(stripped),
        'packaged_sha256':digest(files[runtime.BACKEND]),'packaged_bytes':len(files[runtime.BACKEND])}
    inventory = {name:{'sha256':digest(v),'bytes':len(v),'mode':0o644 if name==runtime.CA else 0o755}
        for name,v in sorted(files.items())}
    require(0 < len(inventory) <= MAX_RUNTIME_FILES, 'fresh runtime finite file count')
    manifest = {'schema_version':1,'kind':KIND,'status':STATUS,'target':'x86_64-linux',
        'native_support':False,'provider_evaluation':False,'experimental_text_policy_compiled':True,
        'chain':chain,'executable':executable,'runtime':runtime_info,'files':inventory,
        'selection_sha256':args.selected_sha256,
        'producer_source_sha256':digest(Path(__file__).read_bytes()),
        'producer_target':'//tools:codex_fresh_native_runtime_package',
        'loader_relocation':witness,
        'declared_tools':{'strip_sha256':digest(portable._read(args.strip.resolve())),
            'patchelf_sha256':digest(portable._read(args.patchelf.resolve()))}}
    payload = runtime.archive_bytes(files, manifest)
    receipt = {'schema_version':1,'kind':KIND,'status':STATUS,
        'native_support':False,'provider_evaluation':False,'experimental_text_policy_compiled':True,
        'chain':chain,'executable':executable,'runtime':runtime_info,
        'selection_sha256':args.selected_sha256,
        'producer_source_sha256':manifest['producer_source_sha256'],
        'producer_target':'//tools:codex_fresh_native_runtime_package',
        'archive_sha256':digest(payload),'archive_bytes':len(payload),
        'manifest_sha256':digest(encoded(manifest)),
        'runtime_inventory':{n:{'sha256':r['sha256'],'bytes':r['bytes'],
            'mode':0o444 if n==runtime.CA else 0o555} for n,r in inventory.items()},
        'scope':'Fresh experimental maintained native carrier; no provider or seamless handoff proof.'}
    # archive_bytes uses the existing deterministic json_bytes representation.
    require(runtime.json_bytes(manifest) == encoded(manifest), 'fresh manifest canonical encoding differs')
    verify_runtime_files(payload, receipt)
    root = output/executable['packaged_sha256']
    root.mkdir(mode=0o700)
    output_file(root, 'codex', files[runtime.BACKEND], 0o555)
    for name, value in files.items():
        output_file(root, 'runtime/'+name, value, 0o444 if name==runtime.CA else 0o555)
    output_file(root, 'native-source-receipt.json', encoded(receipt), 0o444)
    for folder, _, _ in os.walk(root, topdown=False, followlinks=False):
        os.chmod(folder, 0o555, follow_symlinks=False)
    require({p.name for p in root.iterdir()} == {'codex','runtime','native-source-receipt.json'},
        'fresh runtime digest directory membership differs')
    for name, row in receipt['runtime_inventory'].items():
        path = root/'runtime'/name
        require(path.stat().st_mode & 0o777 == row['mode'] and
            read_selected(path, {'path':str(path),'sha256':row['sha256'],'bytes':row['bytes']}, runtime.MAX_BACKEND_BYTES) == files[name],
            'fresh runtime sealed readback differs')
    require(root.name == digest(read_selected(root/'codex',
        {'path':str(root/'codex'),'sha256':executable['packaged_sha256'],'bytes':executable['packaged_bytes']},
        runtime.MAX_BACKEND_BYTES)), 'fresh runtime digest leaf differs')
    require(read_selected(root/'native-source-receipt.json',
        {'path':str(root/'native-source-receipt.json'),'sha256':digest(encoded(receipt)),'bytes':len(encoded(receipt))},
        MAX_METADATA) == encoded(receipt), 'fresh runtime duplicate receipt readback differs')
    for role,pin in selection['files'].items():
        read_selected(canonical_path(pin['path']),pin,
            runtime.MAX_ORIGINAL_BYTES if role=='codex' else MAX_METADATA)
    for pin in selection['protocol_schema_files'].values():
        read_selected(canonical_path(pin['path']),pin,MAX_METADATA)
    if selection.get('kind') == 'omux-staged-native-package-selection-v1':
        from codex_staged_native_package_consumer import validate_receipts,envelopes,read_extra
        receipts,_,_ = validate_receipts(selection,values,parse(values['source']),parse(values['export']))
        after = read_extra(selection,envelopes(selection,values,receipts),receipts)
        require(validate_chain(selection,values,protocol_values,after) == chain,
            'staged complete chain/output rehash changed after packaging cleanup')
    if selection.get('kind') == 'omux-protocol-history-native-package-selection-v1':
        from codex_protocol_history_package_consumer import load_inputs
        after_values,after_protocol,after_extra = load_inputs(selection,
            lambda role,pin,maximum:read_selected(canonical_path(pin['path']),pin,maximum))
        require(validate_chain(selection,after_values,after_protocol,after_extra) == chain,
            'protocol-history full completed chain changed after packaging')
    validate_protocol_inventory(selection)
    output_file(output, 'fresh-native-runtime.tar.gz', payload, 0o444)
    output_file(output, 'runtime-manifest.json', encoded(manifest), 0o444)
    output_file(output, 'runtime-receipt.json', encoded(receipt), 0o444)
    return receipt


def main():
    global DEADLINE
    DEADLINE = time.monotonic()+900
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for name in ('selection','selection-sha-file','input-aliases','strip','patchelf',
            'ca-bundle','runtime-files-manifest'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--tool-path',required=True)
    args = parser.parse_args()
    root = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True)
    parent = trusted(root)
    try:
        os.mkdir('fresh-native-runtime',0o700,dir_fd=parent)
    finally:
        os.close(parent)
    output = root/'fresh-native-runtime'
    sha = args.selection_sha_file.read_text().strip()
    require(HASH.fullmatch(sha), 'fresh runtime independently selected metadata SHA')
    selection_raw = args.selection.read_bytes()
    require(len(selection_raw) <= MAX_METADATA and digest(selection_raw) == sha,
        'fresh runtime selected operator declaration differs')
    selection = parse(selection_raw)
    validate_selection_paths(selection)
    aliases = parse(args.input_aliases.read_bytes())
    entries = {**selection['files'],
        **{'protocol/'+n:p for n,p in selection['protocol_schema_files'].items()}}
    staged_values = None
    if selection.get('kind') == 'omux-protocol-history-native-package-selection-v1':
        entries.update({'protocol-history/'+name:pin for name,pin in selection['protocol_history_artifact_files'].items()})
    if selection.get('kind') == 'omux-staged-native-package-selection-v1':
        entries.update({'staged/'+name:pin for name,pin in selection['staged_artifact_files'].items()})
    require(set(aliases) == set(entries), 'fresh runtime declared input aliases differ')
    values, protocol_values, protocol_bytes = {}, {}, 0
    args.selected_sha256 = sha
    runfiles = _ROOT.parent
    def selected_alias(role,pin):
        alias = runfiles/aliases[role]
        path = alias.resolve(strict=True)
        require(str(path) == pin['path'], 'fresh runtime declared alias resolution differs')
        return path
    if selection.get('kind') == 'omux-protocol-history-native-package-selection-v1':
        from codex_protocol_history_package_consumer import load_inputs
        values,protocol_values,staged_values = load_inputs(selection,
            lambda role,pin,maximum:read_selected(selected_alias(role,pin),pin,maximum),selected_alias)
    if selection.get('kind') == 'omux-staged-native-package-selection-v1':
        from codex_staged_native_package_consumer import load_inputs
        values,protocol_values,staged_values = load_inputs(selection,
            lambda role,pin,maximum:read_selected(selected_alias(role,pin),pin,maximum),selected_alias)
    for role, pin in (() if staged_values is not None else entries.items()):
        path = selected_alias(role,pin)
        maximum = runtime.MAX_ORIGINAL_BYTES if role=='codex' else MAX_METADATA
        value = read_selected(path,pin,maximum)
        if role.startswith('protocol/'):
            protocol_bytes += len(value)
            require(protocol_bytes <= MAX_PROTOCOL, 'fresh protocol schema aggregate bound')
            require(isinstance(parse(value),dict), 'fresh protocol schema is not JSON object')
            protocol_values[role.removeprefix('protocol/')] = value
        else:
            values[role] = value
    runtime_files = runtime.read_runtime_inputs(args.runtime_files_manifest, runfiles)
    require(sum(p.stat().st_size for p in runtime_files) <= runtime.MAX_DECLARED_RUNTIME_BYTES,
        'fresh declared runtime library bound')
    receipt = package(selection,values,protocol_values,runtime_files,args,output,staged_values)
    # Prove all selected original inputs remain byte-identical after packaging.
    for role,pin in entries.items():
        if role.startswith(('staged/','protocol-history/')):
            continue  # read_extra streamed and rehashed each declared library/log after cleanup.
        read_selected(canonical_path(pin['path']),pin,
            runtime.MAX_ORIGINAL_BYTES if role=='codex' else MAX_METADATA)
    print('fresh experimental native runtime package completed; provider proof unrun')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError,
            tarfile.TarError, ET.ParseError):
        print('fresh native runtime producer refused',file=sys.stderr)
        raise SystemExit(1) from None
