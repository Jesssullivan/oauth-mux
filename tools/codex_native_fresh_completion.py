"""One fresh fixed-core completion, then one successful-predecessor schema action.

Only execution_guard constructs Admission. This does not open, repair or adopt
the exhausted candidate's source/output/marker. Historical receipts stay failed.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import xml.etree.ElementTree as ET
from types import SimpleNamespace

import codex_native_profile as native
from codex_sdk_profile import require, unique_object, verify_inventory, EXPORT_MODE_POLICY, hash_regular
from codex_fresh_source import trusted_parent

KIND = 'omux-native-fresh-core-completion-v1'
SELECTOR = native.STATE / 'native-fresh-completion.json'
HASH = re.compile(r'[0-9a-f]{64}')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
MAX_METADATA = 8 * 1024 * 1024
MAX_GLOBAL = 10
JOURNAL = 'fresh-completion-journal.json'
INPUTS = {
    "source_root": "/home/jess/.local/state/omux-execution-20261005/cache-v2-4689a690587ec00080acae0eb6ba13df894a284b47e0ce7a6ee828bed0cb8d9d/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_live_source_producer/test.outputs/codex-live-source",
    "source_receipt_sha256": "1e292ed6c2521b21a9d78d2c499df3cea70f6e0581e9daa946021eb83bbbd191",
    "source_inventory_sha256": "5e7628d20807b41c795d08d2ed6f0e6107d394b718f25dd22e9705206c38cc69",
    "export_root": "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/e5b17d7e-d19d-4cb2-be22-41a86b98af7b/sdk-private/sdk-export",
    "export_receipt_sha256": "1aa4c87d689f464e576a5c6a51b4c6350a8f0346f6b94299856d01db5147d4f0",
    "export_inventory_sha256": "b1c33e2042aecfd8b79b0ca031f18c82f4d934f098fccdbaf287764f4c6fc299",
    "patch_sha256": [
        "5b9eb9d8ffc19ac6e53429186b3dc3e51ab05ab9bbb30564c3b621d7d5383ef6",
        "3851e3d5c1901cafa7cd0bae63a7ac84b1baac7b1f6be3102cc7b185e97ecd53",
        "84ec6ddc333361b4785ac0c9b0a212ce7b25f200fb22c30eb0abdc21883c5ec5"
    ],
    "mapping_sha256": "3416c08d3ddff96ec9e0b76d7d89eaa2b75cc8d81f0a9f661d8b8466d1343657"
}
_HISTORY = [
    [
        "6ab04062-5dce-424a-9873-0079c72ca63d",
        "4c271d5f621b8dde2f1d7e4ec884e0952c56cefd5868e7a9ef2ae0dae6215b92",
        "114776d86a66e7feed83235431bc57096ffe5522b9e2fcca6d32881588cf2ea5",
        1
    ],
    [
        "42d44a8d-1f65-4a4f-9b38-b212aa0f4aaf",
        "4f218d143caea1b185d5df122c206af2372616c2c4b28461e8a26b305c12ca93",
        "c1e21ac7ddb62ffc8862f21a7038f482781bf86147f6c41471a1ce91240ca482",
        1
    ],
    [
        "c7eaff60-669c-497e-9a16-322a17a6d5ac",
        "87199d816aa31eaa9c6a5d58321f3e05ac9c0ac9e338e8b3189aa5bd4f52e981",
        "70d7fad0f82f7883e38ddfec2d343845f036dea4a6171ee213637e0b37669595",
        1
    ],
    [
        "23b62181-53dc-4391-ad43-a4146ca70c6b",
        "e42a1f6d0b0ee0b9a03d5781626fe30732d4f5a86fb5e086a67e16fc7968b755",
        "70d7fad0f82f7883e38ddfec2d343845f036dea4a6171ee213637e0b37669595",
        2
    ],
    [
        "550f07e2-f46f-4906-87d6-9593a7f8bb81",
        "8d57ef2eb6616a3e65f9d42d282958ef46328eb9d5810255756d28c67db972fe",
        "70d7fad0f82f7883e38ddfec2d343845f036dea4a6171ee213637e0b37669595",
        3
    ],
    [
        "34f674c0-9705-4135-b07d-7375fad6aa48",
        "589b8f7c13e7c0d46393b40fb4fd377a4788ad4a5777721a99ee6c41cc514e9c",
        "70d7fad0f82f7883e38ddfec2d343845f036dea4a6171ee213637e0b37669595",
        4
    ],
    [
        "275e4094-af7e-4c26-a390-bf8aa960310e",
        "960f154b3ddcc7b05c9ea11b054dc6ddc329782eb9f14d50301e966dfa97b260",
        "70d7fad0f82f7883e38ddfec2d343845f036dea4a6171ee213637e0b37669595",
        5
    ],
    [
        "5a973300-9c1b-49b1-99ff-8460317eaeba",
        "12543b3f84d6db2fd4c70074248da87627f5666df14c783f281ab7bc5f2013c0",
        "70d7fad0f82f7883e38ddfec2d343845f036dea4a6171ee213637e0b37669595",
        6
    ]
]
CODEGEN_OPTIONS = ('-Copt-level=0', '-Clto=off', '-Ccodegen-units=16',
    '-Cdebug-assertions=off', '-Coverflow-checks=off')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def controller_inventory(root, graph, deadline):
    """Finite current declared controller bytes, lexical digest/traversal order."""
    require(isinstance(graph, (tuple, list)) and len(graph) == 2
        and isinstance(graph[1], list) and 0 < len(graph[1]) <= 4096
        and len(set(graph[1])) == len(graph[1]), 'fresh controller graph bound')
    result, total, pathname_bytes = {}, 0, 0
    for name in graph[1]:
        require(isinstance(name, str) and name and len(name) <= 4096
            and str(Path(name)) == name and not Path(name).is_absolute()
            and '..' not in Path(name).parts and '\\' not in name,
            'fresh controller graph pathname refused')
        pathname_bytes += len(name.encode())
        require(pathname_bytes <= 128*1024, 'fresh controller graph pathname bound')
        fd = trusted_parent(Path(root) / Path(name).parent)
        try:
            pin, count, _ = hash_regular(fd, Path(name).name, 16*1024*1024,
                on_read=lambda count:native.tick(deadline))
        finally:
            os.close(fd)
        total += count
        require(total <= 64*1024*1024, 'fresh controller graph bytes bound')
        result[name] = pin
    digest = hashlib.sha256()
    for name, pin in sorted(result.items()):
        digest.update(name.encode()+b'\0'+bytes.fromhex(pin))
    traversal = sorted(result, key=lambda name:(Path(name).parent.parts,Path(name).name))
    require(canonical((digest.hexdigest(), traversal)) == canonical(graph),
        'fresh current declared controller graph differs')
    return result


def consumed_dispatches():
    return [dict(id=row[0], sha256=row[1], cache_key=row[2], attempt=row[3])
        for row in _HISTORY]


def selected(args):
    values = (getattr(args, 'native_fresh_completion', None),
        getattr(args, 'native_fresh_completion_sha256', None),
        getattr(args, 'native_global_attempt', None))
    if all(value is None for value in values):
        return False
    require(all(value is not None for value in values)
        and args.profile == 'codex-native' and args.manager == 'system'
        and args.state_dir == native.STATE and args.source_dirty == 'false'
        and isinstance(args.source_commit, str)
        and re.fullmatch(r'[0-9a-f]{40}', args.source_commit)
        and type(values[2]) is int
        and (args.native_mode, values[2]) in ((native.COMBINED_MODE, 9), ('schema', 10))
        and Path(values[0]) == SELECTOR and str(values[0]) == str(SELECTOR)
        and isinstance(values[1], str) and HASH.fullmatch(values[1])
        and not args.native_owned_candidate_cache
        and getattr(args, 'native_cache_attempt', None) is None
        and all(getattr(args, name, None) is None for name in (
            'native_cache_transition', 'native_cache_transition_sha256',
            'native_cache_phase2', 'native_cache_phase2_sha256'))
        and not getattr(args, 'reuse_owned_cache', False),
        'fresh completion requires exact exclusive fixed global role')
    return True


def fixed_codegen():
    selected = native.core_codegen_policy()
    policy = selected['policy']
    require(policy == {
        'kind': 'omux-native-fixed-core-codegen-v1', 'configuration': 'opt',
        'setting': '@rules_rust//rust/settings:experimental_per_crate_rustc_flag',
        'crate_root_prefix': 'codex-rs/core/src/lib.rs',
        'options': list(CODEGEN_OPTIONS), 'applies_to': 'target-configuration-only',
        'rust_version': '1.95.0',
        'rules_rust_repository': 'rules_rs++rules_rust+rules_rust'},
        'fresh completion exact fixed codegen tuple required')
    require(selected['sha256'] == hashlib.sha256(canonical(policy)).hexdigest(),
        'fresh completion codegen digest differs')
    return selected


def bindings(args, tools, graph, locked_path, manager, verified_inputs=None):
    require(selected(args) and manager == 'system'
        and getattr(args, 'native_aggregate_seconds', None) == 3600,
        'fresh completion original budget required')
    require(str(args.native_source_root) == INPUTS['source_root']
        and args.native_source_sha256 == INPUTS['source_receipt_sha256']
        and str(args.native_export_root) == INPUTS['export_root']
        and args.native_export_sha256 == INPUTS['export_receipt_sha256']
        and args.native_patch_sha256 == INPUTS['patch_sha256'],
        'fresh completion fixed public source/export selectors required')
    require(set(tools) == {'bazel', 'python', 'systemd_run', 'systemctl',
        'bootstrap', 'closure', 'java', 'bash'} and all(isinstance(value, str)
        and value.startswith('/nix/store/') and '..' not in Path(value).parts
        and not any(char.isspace() for char in value) for value in tools.values())
        and tools['bazel'] == native.BAZEL
        and isinstance(locked_path, str)
        and all(part.startswith('/nix/store/') and '..' not in Path(part).parts
            and not any(char.isspace() for char in part)
            for part in locked_path.split(':')),
        'fresh completion immutable declared tools required')
    source, export = native.verify_inputs(args) if verified_inputs is None else verified_inputs
    require(source['inventory_sha256'] == INPUTS['source_inventory_sha256']
        and export['inventory_sha256'] == INPUTS['export_inventory_sha256']
        and export['mapping_sha256'] == INPUTS['mapping_sha256'],
        'fresh completion full sealed inventory differs')
    return {'kind': KIND, 'uid': os.getuid(), 'gid': os.getgid(),
        'manager': manager, 'tools': tools, 'locked_path': locked_path,
        'source_commit': args.source_commit, 'controller_graph': graph,
        'source_root': str(args.native_source_root),
        'source_receipt_sha256': args.native_source_sha256,
        'source_inventory_sha256': source['inventory_sha256'],
        'source_graph': source['graph_files'], 'patch_sha256': args.native_patch_sha256,
        'export_root': str(args.native_export_root),
        'export_receipt_sha256': args.native_export_sha256,
        'export_inventory_sha256': export['inventory_sha256'],
        'mapping_sha256': export['mapping_sha256'],
        'core_codegen': fixed_codegen(), 'modes': {
            native.COMBINED_MODE: native.MODES[native.COMBINED_MODE],
            'schema': native.MODES['schema']},
        'consumed_dispatches': consumed_dispatches(),
        'global_roles': {'completion': 9, 'conditional_schema': 10, 'maximum': 10},
        'limits': {'memory': 4294967296, 'swap': 0, 'tasks': 512,
            'cpu_percent': 200, 'jobs': 1, 'heap_mib': 768,
            'aggregate_seconds': 3600, 'postcheck_reserve_seconds': 120},
        'network': 'private', 'downloads': False, 'remote': False,
        'ambient_caches': False, 'test_sharding': False,
        'bazel_dispatcher_environment': {'USE_BAZEL_VERSION': native.BAZEL_VERSION},
        'module_resolution_policy': native.MODULE_RESOLUTION_POLICY}


def witness(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_small(fd, name, deadline, expected=None):
    require(name and '/' not in name and name not in ('.', '..'),
        'fresh completion finite leaf required')
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        before = os.fstat(child)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_gid == os.getgid() and before.st_nlink == 1
            and not before.st_mode & 0o022 and 0 <= before.st_size <= MAX_METADATA,
            'fresh completion metadata custody refused')
        chunks, count = [], 0
        while True:
            native.tick(deadline)
            value = os.read(child, 1024 * 1024)
            if not value:
                break
            count += len(value)
            require(count <= MAX_METADATA, 'fresh completion metadata bound')
            chunks.append(value)
        require(count == before.st_size and witness(before) == witness(os.fstat(child))
            == witness(os.stat(name, dir_fd=fd, follow_symlinks=False)),
            'fresh completion held metadata changed')
        raw = b''.join(chunks)
        pin = hashlib.sha256(raw).hexdigest()
        require(expected is None or isinstance(expected, str)
            and HASH.fullmatch(expected) and pin == expected,
            'fresh completion metadata pin differs')
        return raw, pin
    finally:
        os.close(child)


def read_json(fd, name, deadline, expected=None):
    raw, pin = read_small(fd, name, deadline, expected)
    return json.loads(raw, object_pairs_hook=unique_object), pin


def read_receipt(row, deadline):
    require(set(row) == {'id', 'sha256', 'cache_key', 'attempt'}
        and UUID.fullmatch(row['id']) and HASH.fullmatch(row['sha256'])
        and HASH.fullmatch(row['cache_key']) and type(row['attempt']) is int,
        'fresh completion closed public receipt row')
    fd = trusted_parent(native.STATE / row['id'])
    try:
        return read_json(fd, 'receipt.json', deadline, row['sha256'])[0]
    finally:
        os.close(fd)


def historical_receipts(deadline, verify_previous):
    for index, row in enumerate(consumed_dispatches()):
        value = read_receipt(row, deadline)
        facts = value['native_candidate_cache']
        require(value['id'] == row['id'] and value['profile'] == 'codex-native'
            and value['manager'] == 'system'
            and value['unit'] == 'omux-execution-' + row['id'] + '.service'
            and type(value['exit']) is int and value['exit'] != 0
            and type(value['workload_exit']) is int and value['workload_exit'] != 0
            and value['descendants_empty'] is True
            and facts['key'] == row['cache_key'] and type(facts['attempt']) is int
            and facts['attempt'] == row['attempt'],
            'fresh completion historical failure identity differs')
        if index == 7:
            require(value['exit'] == 125 and value['workload_exit'] == 9
                and value['test_evidence']['state'] == 'preservation-failed'
                and value['native_sdk']['source_and_export_verified_after_cleanup'] is False
                and facts.get('transition_verified_after_cleanup') is None,
                'fresh completion must preserve actual failed OOM outcomes')
        require(verify_previous(value) is True,
            'fresh completion historical owned unit/cgroup not empty')


def validate_document(document, selected_bindings, inventory):
    require(isinstance(document, dict) and set(document) == {
        'schema_version', 'kind', 'bindings', 'controller_inventory', 'previous_dispatches'}
        and type(document['schema_version']) is int and document['schema_version'] == 1
        and document['kind'] == KIND
        and canonical(document['bindings']) == canonical(selected_bindings)
        and document['controller_inventory'] == inventory
        and document['previous_dispatches'] == consumed_dispatches(),
        'fresh completion closed independently pinned declaration differs')


def verify_success(receipt, expected_facts, graph, source_pin, export_pin, mode):
    require(receipt['profile'] == 'codex-native' and receipt['manager'] == 'system'
        and type(receipt['exit']) is int and receipt['exit'] == 0
        and type(receipt['workload_exit']) is int and receipt['workload_exit'] == 0
        and receipt['controller_failure'] is None and receipt['descendants_empty'] is True
        and receipt['native_candidate_cache'] is None
        and receipt['native_fresh_completion'] == expected_facts
        and expected_facts['verified_before_launch'] is True
        and expected_facts['verified_after_cleanup'] is True
        and receipt['graph_sha256'] == graph[0]
        and receipt['source_commit'] == expected_facts['source_commit']
        and receipt['source_dirty'] == 'false'
        and UUID.fullmatch(receipt['id'])
        and receipt['unit'] == 'omux-execution-' + receipt['id'] + '.service'
        and receipt['output_base'] == expected_facts['output_base']
        and receipt['native_sdk']['mode'] == mode
        and receipt['targets'] == list(native.MODES[mode][1])
        and receipt['native_sdk']['source_and_export_verified_after_cleanup'] is True
        and receipt['native_sdk']['source_receipt_sha256'] == source_pin
        and receipt['native_sdk']['export_receipt_sha256'] == export_pin
        and receipt['native_sdk']['plan']['core_codegen'] == fixed_codegen()
        and receipt['native_sdk']['plan']['source_inventory_sha256'] == INPUTS['source_inventory_sha256']
        and receipt['native_sdk']['plan']['export_inventory_sha256'] == INPUTS['export_inventory_sha256']
        and receipt['native_sdk']['plan']['mapping_sha256'] == INPUTS['mapping_sha256']
        and receipt['native_sdk']['plan']['cwd'] == expected_facts['workspace']
        and receipt['native_sdk']['plan']['environment']['USE_BAZEL_VERSION'] == native.BAZEL_VERSION
        and [value for value in receipt['native_sdk']['plan']['argv']
            if value.startswith('--' + native.CORE_CODEGEN_SETTING + '=')]
                == native.core_codegen_arguments()
        and all(value in receipt['native_sdk']['plan']['argv'] for value in (
            '--lockfile_mode=error', '--repository_disable_download',
            '--sandbox_default_allow_network=false', '--jobs=1',
            '--host_jvm_args=-Xmx768m', '--repo_contents_cache=', '--disk_cache=',
            '--remote_executor=', '--remote_cache='))
        and (mode != native.COMBINED_MODE
            or '--local_test_jobs=1' in receipt['native_sdk']['plan']['argv'])
        and receipt['native_sdk']['plan']['candidate_output_base'] == expected_facts['output_base']
        and receipt['native_sdk']['aggregate_seconds'] == 3600
        and type(receipt['native_sdk']['original_entry_monotonic_ns']) is int
        and type(receipt['native_sdk']['original_deadline_monotonic_ns']) is int
        and receipt['native_sdk']['original_deadline_monotonic_ns']
            == receipt['native_sdk']['original_entry_monotonic_ns'] + 3600 * 10**9
        and receipt['test_evidence']['state']
            == ('preserved' if mode == native.COMBINED_MODE else 'not-applicable'),
        'fresh completion actual successful guarded role required')


def verify_qualification(run, receipt, deadline):
    """Re-read actual named log/XML/CLI evidence before granting schema."""
    facts = receipt['native_fresh_completion']
    parent = trusted_parent(run)
    try:
        manifest, _ = read_json(parent, 'test-evidence.json', deadline,
            receipt['test_evidence']['sha256'])
        group, _ = read_json(parent, 'native-qualification.json', deadline)
        xml, xml_pin = read_small(parent, 'native-qualification.xml', deadline)
    finally:
        os.close(parent)
    require(manifest['targets'] == list(native.MODES[native.COMBINED_MODE][1])
        and len(manifest['results']) == 4
        and group['schema'] == 'omux-native-grouped-qualification-v1'
        and group['passed'] == 14 and group['failed'] == group['ignored'] == 0
        and group['native_support'] is False and group['provider_evaluation'] is False
        and group['xml_sha256'] == xml_pin
        and set(group['targets']) == set(native.QUALIFICATION_GATES),
        'fresh completion actual grouped14 evidence differs')
    rows = {row['target']: row for row in manifest['results']}
    require(len(rows) == 4 and set(rows) == set(native.MODES[native.COMBINED_MODE][1])
        and rows[native.CLI]['state'] == 'missing-test-directory'
        and rows[native.CLI]['files'] == [], 'fresh completion actual explicit CLI request differs')
    logs = trusted_parent(run / 'test-evidence')
    try:
        for target, names in native.QUALIFICATION_GATES.items():
            copied = [entry for entry in rows[target]['files']
                if entry['source'] == 'test.log' and entry['state'] == 'copied']
            require(len(copied) == 1, 'fresh completion one actual log per target')
            entry = copied[0]
            value, pin = read_small(logs, entry['file'], deadline, entry['sha256'])
            require(native.qualification_log(value, target) == sorted(names)
                and group['targets'][target] == {'log_sha256': pin, 'tests': sorted(names)},
                'fresh completion exact named log binding differs')
    finally:
        os.close(logs)
    document = ET.fromstring(xml)
    require(document.tag == 'testsuites'
        and document.attrib == {'tests':'14','failures':'0','errors':'0','skipped':'0'},
        'fresh completion XML total differs')
    suites = document.findall('testsuite')
    require(len(suites) == 3 and {suite.get('name') for suite in suites}
        == set(native.QUALIFICATION_GATES), 'fresh completion XML exact suites')
    for target, names in native.QUALIFICATION_GATES.items():
        suite = next(item for item in suites if item.get('name') == target)
        cases = suite.findall('testcase')
        require(suite.get('tests') == str(len(names))
            and all(suite.get(key) == '0' for key in ('failures','errors','skipped'))
            and len(cases) == len(names) and sorted(case.get('name') for case in cases) == sorted(names)
            and all(case.get('classname') == target and len(case) == 0 for case in cases)
            and [item.attrib for item in suite.findall('properties/property')]
                == [{'name':'actual_test_log_sha256','value':group['targets'][target]['log_sha256']}],
            'fresh completion XML named/actual-log binding differs')
    context = {'invocation_id': receipt['id'], 'output_base': facts['output_base'],
        'source_receipt_sha256': receipt['native_sdk']['source_receipt_sha256'],
        'export_receipt_sha256': receipt['native_sdk']['export_receipt_sha256'],
        'source_inventory_sha256': receipt['native_sdk']['plan']['source_inventory_sha256'],
        'export_inventory_sha256': receipt['native_sdk']['plan']['export_inventory_sha256'],
        'candidate_cache_key': facts['key'], 'candidate_provenance_sha256': facts['provenance_sha256'],
        'controller_graph_sha256': receipt['graph_sha256'], 'bazel': native.BAZEL,
        'workload_exit': 0, 'descendants_empty': True,
        'source_and_export_verified_after_cleanup': True}
    native.source_io.DEADLINE = deadline
    require(group['cli_context'] == context
        and group['cli_artifact'] == native.combined_cli_artifact(context),
        'fresh completion actual post-cleanup CLI evidence differs')


def terminal_receipt(admission, receipt):
    """Predict journal pin before writing the controller's exact receipt bytes."""
    raw = json.dumps(receipt, sort_keys=True) + '\n'
    try:
        admission.finish(receipt, hashlib.sha256(raw.encode()).hexdigest())
    except (OSError, ValueError, KeyError, TypeError):
        # Preserve a failed actual action; never expose raw exception values.
        receipt['exit'] = 125
        receipt['native_fresh_completion']['terminal_record'] = 'uncommitted'
        raw = json.dumps(receipt, sort_keys=True) + '\n'
    return raw


class Admission:
    def __init__(self, args, run, tools, graph, locked_path, manager, verify_previous):
        require(selected(args), 'fresh completion selected policy required')
        self.args, self.run, self.tools = args, run, tools
        self.graph, self.locked_path, self.manager = graph, locked_path, manager
        self.verify_previous = verify_previous
        self.global_attempt = args.native_global_attempt
        self.verified_before_launch = False
        self.verified_after_cleanup = None
        self.lock_fd = self.root_fd = self.output_fd = None
        self.journal_sha = None
        self.provenance = bindings(args, tools, graph, locked_path, manager)
        inventory = controller_inventory(Path.cwd(), graph, args.native_deadline)
        parent = trusted_parent(SELECTOR.parent)
        try:
            document, _ = read_json(parent, SELECTOR.name, args.native_deadline,
                args.native_fresh_completion_sha256)
        finally:
            os.close(parent)
        validate_document(document, self.provenance, inventory)
        self.document = document
        self.key = hashlib.sha256(canonical(self.provenance)).hexdigest()
        self.root = native.STATE / ('cache-v2-' + self.key)
        self.source = self.root / 'native-input/source'
        self.lease = SimpleNamespace(output_base=self.root / 'output-base')
        self.previous_dispatches = consumed_dispatches()
        historical_receipts(args.native_deadline, verify_previous)
        parent = trusted_parent(native.STATE)
        try:
            if self.global_attempt == 9:
                # Only an actually absent root is allowed. No mkdir(exist_ok).
                os.mkdir(self.root.name, 0o700, dir_fd=parent)
            self.root_fd = os.open(self.root.name, os.O_RDONLY | os.O_DIRECTORY
                | os.O_NOFOLLOW, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            root_info = os.fstat(self.root_fd)
            require(root_info.st_uid == os.getuid() and root_info.st_gid == os.getgid()
                and stat.S_IMODE(root_info.st_mode) == 0o700, 'fresh completion root custody')
            self.root_identity = (root_info.st_dev, root_info.st_ino)
            self.lock_fd = os.open('fresh-completion.lock',
                os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT | os.O_EXCL if self.global_attempt == 9 else 0),
                0o600, dir_fd=self.root_fd)
            held = os.fstat(self.lock_fd)
            require(stat.S_ISREG(held.st_mode) and held.st_uid == os.getuid()
                and held.st_gid == os.getgid() and held.st_nlink == 1
                and stat.S_IMODE(held.st_mode) == 0o600, 'fresh completion lock custody')
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.lock_identity = (held.st_dev, held.st_ino)
            if self.global_attempt == 9:
                require(os.listdir(self.root_fd) == ['fresh-completion.lock'],
                    'fresh completion root must be actually empty before creation')
                os.mkdir('output-base', 0o700, dir_fd=self.root_fd)
                source = native.validate_source(args.native_source_root, args.native_source_sha256,
                    args.native_patch_sha256, args.native_deadline)
                native.source_io.DEADLINE = args.native_deadline
                self.source = native.copy_source(args.native_source_root, source, self.root)
                self.write_journal('pending', run.name, None, 9, first=True)
            else:
                self.admit_schema()
                self.write_journal('pending', run.name, None, 10)
            require(set(os.listdir(self.root_fd)) == {'fresh-completion.lock', JOURNAL,
                'native-input', 'output-base'}, 'fresh completion foreign root member')
            self.output_fd = os.open('output-base', os.O_RDONLY | os.O_DIRECTORY
                | os.O_NOFOLLOW, dir_fd=self.root_fd)
            info = os.fstat(self.output_fd)
            require(info.st_uid == os.getuid() and info.st_gid == os.getgid()
                and stat.S_IMODE(info.st_mode) == 0o700, 'fresh completion output custody')
            self.output_identity = (info.st_dev, info.st_ino)
            if self.global_attempt == 9:
                require(not os.listdir(self.output_fd), 'fresh completion output base is not empty')
            self.verify_source_copy()
            self.verified_before_launch = True
        except BaseException:
            self.close()
            raise

    @property
    def fresh_verified_before_launch(self):
        return self.verified_before_launch is True

    def facts(self):
        return {'kind': KIND, 'key': self.key, 'provenance_sha256': self.key,
            'source_commit': self.args.source_commit,
            'workspace': str(self.source), 'output_base': str(self.lease.output_base),
            'global_attempt': self.global_attempt, 'max_global_attempts': MAX_GLOBAL,
            'previous_dispatches': self.previous_dispatches,
            'core_codegen': fixed_codegen(), 'selector_sha256': self.args.native_fresh_completion_sha256,
            'verified_before_launch': self.verified_before_launch,
            'verified_after_cleanup': self.verified_after_cleanup}

    def check_directories(self):
        parent = trusted_parent(native.STATE)
        try:
            root = os.stat(self.root.name, dir_fd=parent, follow_symlinks=False)
        finally:
            os.close(parent)
        output = os.stat('output-base', dir_fd=self.root_fd, follow_symlinks=False)
        lock = os.stat('fresh-completion.lock', dir_fd=self.root_fd, follow_symlinks=False)
        require((root.st_dev, root.st_ino) == self.root_identity
            and (os.fstat(self.root_fd).st_dev, os.fstat(self.root_fd).st_ino) == self.root_identity
            and (output.st_dev, output.st_ino) == self.output_identity
            and (os.fstat(self.output_fd).st_dev, os.fstat(self.output_fd).st_ino) == self.output_identity
            and stat.S_ISDIR(root.st_mode) and stat.S_ISDIR(output.st_mode)
            and (lock.st_dev, lock.st_ino) == self.lock_identity
            and (os.fstat(self.lock_fd).st_dev, os.fstat(self.lock_fd).st_ino) == self.lock_identity
            and stat.S_ISREG(lock.st_mode) and lock.st_nlink == 1
            and lock.st_uid == os.getuid() and lock.st_gid == os.getgid()
            and stat.S_IMODE(lock.st_mode) == 0o600
            and root.st_uid == output.st_uid == os.getuid()
            and root.st_gid == output.st_gid == os.getgid()
            and stat.S_IMODE(root.st_mode) == stat.S_IMODE(output.st_mode) == 0o700,
            'fresh completion named output/root changed')

    def verify_source_copy(self):
        receipt = native.validate_source(self.args.native_source_root, self.args.native_source_sha256,
            self.args.native_patch_sha256, self.args.native_deadline)
        fd = trusted_parent(self.source)
        try:
            verify_inventory(fd, receipt['source_inventory'], EXPORT_MODE_POLICY,
                on_read=lambda count: native.tick(self.args.native_deadline))
        finally:
            os.close(fd)

    def write_journal(self, status, epoch, receipt_sha, attempt, first=False):
        require(status in ('pending', 'qualified-completion', 'closed')
            and UUID.fullmatch(epoch) and attempt in (9, 10),
            'fresh completion fixed journal role')
        value = {'schema_version':1, 'kind':KIND, 'key':self.key,
            'status':status, 'epoch':epoch, 'receipt_sha256':receipt_sha,
            'global_attempt':attempt}
        if not first:
            read_small(self.root_fd, JOURNAL, self.args.native_deadline, self.journal_sha)
        name = JOURNAL if first else 'journal-next-' + self.run.name
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=self.root_fd)
        raw = canonical(value) + b'\n'
        try:
            view = memoryview(raw)
            while view:
                native.tick(self.args.native_deadline)
                count = os.write(fd, view)
                require(count > 0, 'fresh completion journal short write')
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        if not first:
            os.replace(name, JOURNAL, src_dir_fd=self.root_fd, dst_dir_fd=self.root_fd)
        os.fsync(self.root_fd)
        self.journal_sha = hashlib.sha256(raw).hexdigest()
        read_small(self.root_fd, JOURNAL, self.args.native_deadline, self.journal_sha)

    def admit_schema(self):
        journal, pin = read_json(self.root_fd, JOURNAL, self.args.native_deadline)
        require(set(journal) == {'schema_version','kind','key','status','epoch',
            'receipt_sha256','global_attempt'} and journal['schema_version'] == 1
            and journal['kind'] == KIND and journal['key'] == self.key
            and journal['status'] == 'qualified-completion'
            and type(journal['global_attempt']) is int and journal['global_attempt'] == 9
            and UUID.fullmatch(journal['epoch']) and HASH.fullmatch(journal['receipt_sha256']),
            'fresh completion schemas require completed fresh journal')
        self.journal_sha = pin
        row = {'id':journal['epoch'], 'sha256':journal['receipt_sha256'],
            'cache_key':self.key, 'attempt':9}
        previous = read_receipt(row, self.args.native_deadline)
        expected = self.facts()
        expected.update(global_attempt=9, verified_before_launch=True,
            verified_after_cleanup=True, previous_dispatches=consumed_dispatches())
        verify_success(previous, expected, self.graph, self.args.native_source_sha256,
            self.args.native_export_sha256, native.COMBINED_MODE)
        require(self.verify_previous(previous) is True,
            'fresh completion predecessor owned unit/cgroup not empty')
        verify_qualification(native.STATE / previous['id'], previous, self.args.native_deadline)
        self.previous_dispatches.append(row)

    def verify_after_cleanup(self, verified_inputs):
        self.check_directories()
        # The owning controller just completed the real full source/export
        # verifier. Reuse that actual result; do not repeat the multi-GB pass
        # inside the same120s cleanup reserve.
        current = bindings(self.args, self.tools, self.graph, self.locked_path, self.manager,
            verified_inputs=verified_inputs)
        inventory = controller_inventory(Path.cwd(), self.graph, self.args.native_deadline)
        parent = trusted_parent(SELECTOR.parent)
        try:
            document, _ = read_json(parent, SELECTOR.name, self.args.native_deadline,
                self.args.native_fresh_completion_sha256)
        finally:
            os.close(parent)
        validate_document(document, current, inventory)
        require(canonical(current) == canonical(self.provenance)
            and canonical(document) == canonical(self.document),
            'fresh completion provenance changed during workload')
        historical_receipts(self.args.native_deadline, self.verify_previous)
        self.verify_source_copy()
        read_small(self.root_fd, JOURNAL, self.args.native_deadline, self.journal_sha)
        self.verified_after_cleanup = True

    def finish(self, receipt, receipt_sha):
        # The controller predicts exact receipt bytes under its held lease;
        # schema rehashes the actual fsynced file before this journal grants it.
        accepted = False
        try:
            verify_success(receipt, self.facts(), self.graph, self.args.native_source_sha256,
                self.args.native_export_sha256, self.args.native_mode)
            if self.global_attempt == 9:
                verify_qualification(self.run, receipt, self.args.native_deadline)
            accepted = True
            status = 'qualified-completion' if self.global_attempt == 9 else 'closed'
        except (OSError, ValueError, KeyError, TypeError, ET.ParseError):
            status = 'closed'
        self.write_journal(status, self.run.name, receipt_sha, self.global_attempt)
        if not accepted and receipt['exit'] == 0:
            raise ValueError('fresh completion terminal qualification refused')

    def close(self):
        for name in ('output_fd', 'lock_fd', 'root_fd'):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)
