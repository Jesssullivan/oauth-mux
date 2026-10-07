"""Finite offline native candidate profile; launches only through execution_guard."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import math
import xml.etree.ElementTree as ET
import codex_live_source as source_io
from codex_sdk_profile import metadata, require, verify_inventory, EXPORT_MODE_POLICY, hash_regular
from codex_fresh_source import trusted_parent
from codex_retained_sdk_export import validate_export
from codex_live_source import BASE_RECEIPT_SHA, BASE_INVENTORY, COMMIT, GRAPH, write_source, read

BAZEL = '/nix/store/ia8gp7v2h790lwdx7a7p5clh063v0qy1-bazel-9.0.1/bin/bazel'
BAZEL_VERSION = '9.0.1'
MODULE_RESOLUTION_POLICY = 'locked-registry-module-identities-with-sealed-repository-overrides-v1'
STATE = Path('/srv/fast-local/jess/state/codex/omux-native-candidate-20261007')
CORE = '//codex-rs/core:core-unit-tests'
CONFIG = '//codex-rs/config:config-unit-tests'
LOGIN = '//codex-rs/login:login-unit-tests'
QUALIFICATION_GATES = {
    CORE: (
        'auth_broker::tests::unix_transport::native_completed_waits_for_committed_terminal_report',
        'auth_broker::tests::unix_transport::uncommitted_terminal_report_never_exposes_native_completed',
        'broker_text_context::tests::real_history_projection_preserves_native_records_and_exact_text',
        'broker_text_context::tests::typed_guard_rejects_plaintext_that_native_serde_suppresses',
        'broker_text_context::tests::typed_guard_rejects_visible_reasoning_summary',
        'broker_text_context::tests::raw_guard_precedes_real_modality_stripping',
        'broker_text_context::tests::opaque_compaction_tools_agent_messages_and_unknown_records_are_refused',
        'broker_text_context::tests::text_shaped_tool_metadata_cannot_be_dropped_by_request_preparation',
        'broker_text_context::tests::a_prompt_change_after_raw_snapshot_is_refused',
        'broker_text_context::tests::fingerprints_are_canonical_and_context_reports_never_expose_native_payloads',
        'client::tests::native_text_policy_builds_actual_wire_input_and_freezes_the_complete_request',
    ),
    CONFIG: ('config_toml::tests::omux_text_context_mode_is_explicit_and_unknown_modes_fail',),
    LOGIN: (
        'server::server_bind_tests::occupied_callback_port_never_contacts_its_owner',
        'server::server_bind_tests::available_callback_port_binds_only_loopback',
    ),
}
PRODUCTION = ('//codex-rs/core:core', '//codex-rs/app-server:app-server', '//codex-rs/config:config', '//codex-rs/app-server-protocol:app-server-protocol', '//codex-rs/tui:tui', '//codex-rs/cli:codex', '//codex-rs/config-schema:codex-write-config-schema', '//bazel/schema:public-schema-bundle')
CLI = '//codex-rs/cli:codex'
COMBINED_MODE = 'qualification-cli'
CLI_CONTEXT_FIELDS = frozenset(('invocation_id', 'output_base',
    'source_receipt_sha256', 'export_receipt_sha256', 'source_inventory_sha256',
    'export_inventory_sha256', 'candidate_cache_key', 'candidate_provenance_sha256',
    'controller_graph_sha256', 'bazel', 'workload_exit', 'descendants_empty',
    'source_and_export_verified_after_cleanup'))
MAX_CLI_BYTES = 1024 * 1024 * 1024
MODES = {
    COMBINED_MODE: ('test', (CORE, CONFIG, LOGIN, CLI), None),
    'qualification': ('test', (CORE, CONFIG, LOGIN), None),
    'analysis': ('build', PRODUCTION, None), 'production8': ('build', PRODUCTION, None),
    'cli-opt': ('build', ('//codex-rs/cli:codex',), None),
    'core-completion-committed': ('test', (CORE,), 'native_completed_waits_for_committed_terminal_report'),
    'core-completion-uncommitted': ('test', (CORE,), 'uncommitted_terminal_report_never_exposes_native_completed'),
    'core-text': ('test', (CORE,), 'broker_text_context::tests'),
    'client-text': ('test', (CORE,), 'client::tests::native_text_policy_builds_actual_wire_input_and_freezes_the_complete_request'),
    'config-text': ('test', ('//codex-rs/config:config-unit-tests',), 'config_toml::tests::omux_text_context_mode_is_explicit_and_unknown_modes_fail'),
    'schema': ('build', ('//bazel/schema:native-config-schema', '//bazel/schema:public-schema-bundle'), None),
    'login-bind': ('test', ('//codex-rs/login:login-unit-tests',), 'server::server_bind_tests'),
}

def tick(deadline):
    require(deadline is None or time.monotonic() < deadline, 'native aggregate deadline reached')

def validate_source(root, receipt_sha256, patch_pins, deadline=None):
    on_read = lambda count: tick(deadline)
    require(len(patch_pins) == 3 and all(re.fullmatch(r'[0-9a-f]{64}', p) for p in patch_pins), 'native patch pins required')
    fd = trusted_parent(Path(root))
    try:
        receipt = metadata(fd, 'source-receipt.json', receipt_sha256, on_read=on_read)
        require(receipt['schema_version'] == 1 and receipt['status'] == 'verified-fresh-native-candidate'
            and receipt['commit'] == COMMIT and receipt['baseline_receipt_sha256'] == BASE_RECEIPT_SHA
            and receipt['baseline_inventory_sha256'] == BASE_INVENTORY
            and receipt['patch_sha256'] == list(patch_pins)
            and all(receipt[k] is False for k in ('native_support', 'native_compile_passed', 'provider_evaluation')),
            'native source receipt binding refused')
        inventory = receipt['source_inventory']
        require(hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest() == receipt['inventory_sha256'], 'source inventory binding refused')
        sourcefd = os.open('source', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            count = verify_inventory(sourcefd, inventory, EXPORT_MODE_POLICY, on_read=on_read)
        finally:
            os.close(sourcefd)
        require(count == receipt['source_bytes'] and len(inventory) == receipt['tracked_files'], 'source counts refused')
        require(set(receipt['graph_files']) == set(GRAPH) and all(
            receipt['graph_files'][name] == {'sha256': inventory[name]['sha256']} for name in GRAPH), 'source graph binding refused')
        require(set(receipt['baseline_graph_files']) == set(GRAPH), 'baseline graph binding refused')
        return receipt
    finally:
        os.close(fd)

def verify_inputs(args):
    receipt = validate_source(args.native_source_root, args.native_source_sha256, args.native_patch_sha256, args.native_deadline)
    exported = validate_export(args.native_export_root, args.native_export_sha256,
        BASE_INVENTORY, receipt['baseline_graph_files'], on_read=lambda count: tick(args.native_deadline))
    for name in ('MODULE.bazel', 'MODULE.bazel.lock', 'codex-rs/Cargo.lock', 'codex-rs/Cargo.toml'):
        require(receipt['graph_files'][name] == exported['graph_files'][name], 'changed resolution graph requires new qualified export')
    return receipt, exported

def copy_source(root, receipt, run):
    # All paths and bytes were verified; read each through held nofollow FDs again.
    source = Path(root) / 'source'
    files = {}
    for name, row in receipt['source_inventory'].items():
        fd = trusted_parent(source / str(Path(name).parent))
        try:
            if row['mode'] == '120000':
                value = os.readlink(Path(name).name, dir_fd=fd).encode()
            else:
                value, _ = read(fd, Path(name).name, 512 * 1024 * 1024)
            require(hashlib.sha256(value).hexdigest() == row['sha256'], 'source changed during copy')
            files[name] = (row['mode'], value)
        finally:
            os.close(fd)
    fd = write_source(run / 'native-input', files)
    os.close(fd)
    os.chmod(run / 'native-input', 0o555)
    return run / 'native-input/source'

def command(args, run, locked_path, bash, candidate=None):
    source_io.DEADLINE = args.native_deadline
    receipt, exported = verify_inputs(args)
    # validate_export has already qualified every explicitly selected public
    # registry metadata byte against the retained MODULE lock's exact hashes.
    registry_cache = exported['registry_cache']
    require(Path(registry_cache) == args.native_export_root / 'registry-cache',
            'registry cache must remain in the sealed qualified export')
    source = candidate.source if candidate is not None else copy_source(args.native_source_root, receipt, run)
    for name in ('home', 'home/cache', 'home/config', 'home/state'):
        (run / name).mkdir(mode=0o700)
    status = run / 'native-workspace-status'
    require(re.fullmatch(r'/nix/store/[a-z0-9]{32}-bash-[^/\s]+/bin/bash', bash), 'immutable Bash required')
    with status.open('xb') as stream:
        stream.write(('#!' + bash + '\nprintf "STABLE_GIT_COMMIT ' + COMMIT + '\\n"\n').encode())
        stream.flush()
        os.fchmod(stream.fileno(), 0o500)
        os.fsync(stream.fileno())
    verb, targets, test_filter = MODES[args.native_mode]
    argv = [BAZEL, '--batch', '--output_user_root=' + str(run / 'user-root'), '--output_base=' + str(candidate.lease.output_base if candidate is not None else run / 'output-base'),
        '--host_jvm_args=-Xmx768m', '--host_jvm_args=-XX:ActiveProcessorCount=1', '--ignore_all_rc_files', verb,
        '--compilation_mode=opt', '--lockfile_mode=error', '--repository_disable_download',
        '--repository_cache=' + registry_cache, '--repo_contents_cache=', '--disk_cache=', '--remote_executor=', '--remote_cache=',
        '--experimental_remote_downloader=', '--bes_backend=', '--jobs=1', '--loading_phase_threads=2', '--legacy_globbing_threads=2',
        '--experimental_fsvc_threads=2', '--spawn_strategy=sandboxed', '--sandbox_default_allow_network=false',
        '--incompatible_strict_action_env', '--action_env=PATH=' + locked_path, '--repo_env=PATH=' + locked_path,
        '--repo_env=BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN=1', '--repo_env=BAZEL_NO_APPLE_CPP_TOOLCHAIN=1',
        '--xcode_version_config=//:disable_xcode', '--host_platform=//:local_linux',
        '--@rules_cc//cc/toolchains/args/archiver_flags:use_libtool_on_macos=False', '--@llvm//config:experimental_stub_libgcc_s',
        '--platforms=//codex-rs/core:owner-linux', '--extra_toolchains=//codex-rs/core:owner-local-test-toolchain',
        '--workspace_status_command=' + str(status), '--symlink_prefix=' + str(run / 'bazel-'),
        '--noenable_runfiles', '--nobuild_runfile_links']
    for name, directory in sorted(exported['repositories'].items()):
        require(re.fullmatch(r'[A-Za-z0-9._+~-]{1,256}', name) and Path(directory) == args.native_export_root / 'repositories' / name, 'repository mapping refused')
        argv.append('--override_repository=' + name + '=' + str(directory))
    require(isinstance(exported['module_overrides'], dict), 'qualified module overrides required')
    for name, directory in sorted(exported['module_overrides'].items()):
        require(re.fullmatch(r'[a-z][a-z0-9._-]{0,127}', name) and directory in exported['repositories'].values(), 'module override mapping refused')
        # Registry MODULE bytes retain their locked version identities. Local
        # repository bytes are already selected by exact override_repository.
    if args.native_mode == 'analysis':
        argv.append('--nobuild')
    if verb == 'test':
        argv += ['--local_test_jobs=1', '--test_sharding_strategy=disabled', '--test_timeout=1200', '--test_env=RUST_TEST_THREADS=1',
            '--test_env=RUST_MIN_STACK=8388608', '--test_env=PATH=' + locked_path, '--nocache_test_results',
            '--nozip_undeclared_test_outputs', '--test_output=errors']
        if args.native_mode in ('qualification', COMBINED_MODE):
            argv += ['--test_arg=--exact', '--test_arg=--format=pretty', '--test_arg=--color=never']
            argv += ['--test_arg=' + name for names in QUALIFICATION_GATES.values() for name in names]
        else:
            argv.append('--test_filter=' + test_filter)
    return {'argv': argv + list(targets), 'cwd': str(source), 'source_inventory_sha256': receipt['inventory_sha256'],
        'candidate_cache_root': str(candidate.root) if candidate is not None else None,
        'candidate_output_base': str(candidate.lease.output_base) if candidate is not None else None,
        'export_inventory_sha256': exported['inventory_sha256'], 'mapping_sha256': exported['mapping_sha256'],
        'environment': {'PATH': locked_path, 'USE_BAZEL_VERSION': BAZEL_VERSION,
            'HOME': str(run / 'home'), 'XDG_CACHE_HOME': str(run / 'home/cache'),
            'XDG_CONFIG_HOME': str(run / 'home/config'), 'XDG_STATE_HOME': str(run / 'home/state')}}


def completion_deadline(args, original_entry_ns, candidate=None):
    """Select a closed native budget from the original invocation entry clock."""
    require(type(original_entry_ns) is int and original_entry_ns >= 0,
        'native original entry clock required')
    path = getattr(args, 'native_cache_phase2', None)
    pin = getattr(args, 'native_cache_phase2_sha256', None)
    require((path is None) == (pin is None), 'native phase2 complete selector required')
    seconds = getattr(args, 'native_aggregate_seconds', 1200)
    require(type(seconds) is int, 'native aggregate seconds must be exact integer')
    if path is None:
        require(seconds == 1200, 'ordinary native budget must remain unchanged')
    else:
        require(args.profile == 'codex-native' and args.manager == 'system'
            and args.native_owned_candidate_cache is True
            and (args.native_mode, args.native_cache_attempt) in ((COMBINED_MODE, 6), ('schema', 7))
            and getattr(args, 'native_cache_transition', None) is None
            and getattr(args, 'native_cache_transition_sha256', None) is None
            and seconds == 3600 and isinstance(pin, str) and re.fullmatch(r'[0-9a-f]{64}', pin)
            and candidate is not None and candidate.phase2_verified_before_launch is True,
            'native phase2 deadline requires fully verified closed candidate')
    return (original_entry_ns + seconds * 10**9) / 10**9


def phase2_effective_runtime(value, maximum):
    """Read back only the native retry's finite remaining workload duration."""
    require(type(value) is str and len(value) <= 64
        and type(maximum) is int and 0 < maximum <= 3480,
        'native phase2 effective runtime invalid')
    matches = list(re.finditer(r'([0-9]+(?:\.[0-9]{1,6})?)(us|ms|s|min|h)', value))
    require(matches and ''.join(match.group(0) for match in matches) == value.replace(' ', ''),
        'native phase2 effective runtime invalid')
    scales = {'us':1, 'ms':1000, 's':1000000, 'min':60000000, 'h':3600000000}
    total = sum(int(float(match.group(1)) * scales[match.group(2)]) for match in matches)
    require(0 < total <= maximum * 1000000,
        'native phase2 effective runtime exceeds original remaining budget')
    return total

def runtime(args):
    tick(args.native_deadline)
    # Reserve 120 seconds inside the same aggregate budget for verified cleanup
    # and full source/export readback. Exhaustion still fails closed.
    remaining = math.floor(args.native_deadline - time.monotonic() - 120)
    require(remaining > 0, 'native runtime budget exhausted')
    return remaining

def qualification_log(value, target):
    """Validate actual stable libtest output, not the umbrella Bazel XML count."""
    expected = set(QUALIFICATION_GATES[target])
    matches = re.findall(rb'^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED|ignored)\r?$', value, re.MULTILINE)
    require(len(matches) == len(expected), 'qualification named gate count differs')
    require(all(status == b'ok' for _, status in matches), 'qualification gate failed or ignored')
    observed = [name.decode('ascii') for name, _ in matches]
    require(len(set(observed)) == len(observed) and set(observed) == expected,
            'qualification exact named gates differ')
    summaries = re.findall(rb'test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;', value)
    require(summaries == [(str(len(expected)).encode(), b'0', b'0')],
            'qualification actual libtest counts differ')
    return sorted(observed)


def combined_cli_artifact(context):
    """Read actual explicit CLI output only after successful verified cleanup."""
    require(isinstance(context, dict) and set(context) == CLI_CONTEXT_FIELDS,
        'combined CLI exact cleanup context required')
    require(context['workload_exit'] == 0 and type(context['workload_exit']) is int
        and context['descendants_empty'] is True
        and context['source_and_export_verified_after_cleanup'] is True
        and context['bazel'] == BAZEL
        and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            context['invocation_id']),
        'combined CLI successful cleanup/tool context required')
    for name in CLI_CONTEXT_FIELDS - {'invocation_id', 'output_base', 'bazel',
            'workload_exit', 'descendants_empty', 'source_and_export_verified_after_cleanup'}:
        require(isinstance(context[name], str) and re.fullmatch(r'[0-9a-f]{64}', context[name]),
            'combined CLI exact provenance digest required')
    output = STATE / ('cache-v2-' + context['candidate_cache_key']) / 'output-base'
    require(context['output_base'] == str(output), 'combined CLI exact output base required')
    root = output / 'execroot/_main/bazel-out'
    parent = trusted_parent(root)
    configurations = []
    try:
        names = os.listdir(parent)
        require(len(names) <= 64, 'combined CLI configuration inventory bound')
        for name in names:
            if not re.fullmatch(r'[A-Za-z0-9_.-]+-opt', name):
                continue
            directory = root / name / 'bin/codex-rs/cli'
            try:
                held = trusted_parent(directory)
            except FileNotFoundError:
                continue
            try:
                try:
                    info = os.stat('codex', dir_fd=held, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                require(stat.S_ISREG(info.st_mode), 'combined CLI output must be regular')
                configurations.append((name, directory))
            finally:
                os.close(held)
        require(len(configurations) == 1, 'combined CLI requires one actual declared output')
    finally:
        os.close(parent)
    configuration, directory = configurations[0]
    parent = trusted_parent(directory)
    child = None
    try:
        child = os.open('codex', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(child)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_nlink == 1 and not before.st_mode & 0o022
            and before.st_mode & 0o111 and 4 <= before.st_size <= MAX_CLI_BYTES,
            'combined CLI output custody/size refused')
        require(os.pread(child, 4, 0) == b'\x7fELF', 'combined CLI actual ELF required')
        sha, count = hashlib.sha256(), 0
        while True:
            tick(source_io.DEADLINE)
            value = os.read(child, 1024 * 1024)
            if not value:
                break
            count += len(value)
            require(count <= MAX_CLI_BYTES, 'combined CLI output bound')
            sha.update(value)
        witness = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(count == before.st_size and witness(before) == witness(os.fstat(child))
            == witness(os.stat('codex', dir_fd=parent, follow_symlinks=False)),
            'combined CLI output changed during actual hash')
        return {'kind': 'actual-explicit-cli-target-v1', 'target': CLI,
            'configuration': configuration, 'path': str(directory / 'codex'),
            'sha256': sha.hexdigest(), 'bytes': count}
    finally:
        if child is not None:
            os.close(child)
        os.close(parent)

def qualification_evidence(run, manifest, context=None):
    cli = None
    if context is not None:
        require(isinstance(context, dict) and set(context) == CLI_CONTEXT_FIELDS,
            'combined CLI exact cleanup context required')
        require(context['invocation_id'] == run.name, 'combined CLI invocation differs')
        require(set(manifest['targets']) == set(MODES[COMBINED_MODE][1])
            and len(manifest['targets']) == 4 and len(manifest['results']) == 4
            and {row['target'] for row in manifest['results']} == set(MODES[COMBINED_MODE][1]),
            'combined qualification exact four requested targets differ')
        cli_rows = [row for row in manifest['results'] if row['target'] == CLI]
        require(len(cli_rows) == 1 and cli_rows[0]['state'] == 'missing-test-directory'
            and cli_rows[0]['files'] == [], 'combined CLI must remain an explicit non-test target')
        manifest = dict(manifest, results=[row for row in manifest['results'] if row['target'] != CLI])
        cli = combined_cli_artifact(context)
    require({row['target'] for row in manifest['results']} == set(QUALIFICATION_GATES)
        and len(manifest['results']) == len(QUALIFICATION_GATES),
        'qualification exact target set differs')
    fd = trusted_parent(run / 'test-evidence')
    rows = {}
    try:
        for row in manifest['results']:
            entries = [e for e in row['files'] if e['source'] == 'test.log' and e['state'] == 'copied']
            require(len(entries) == 1, 'qualification requires one copied log per target')
            entry = entries[0]
            digest, _, value = hash_regular(fd, entry['file'], 64 * 1024 * 1024, True)
            require(digest == entry['sha256'], 'qualification log changed')
            rows[row['target']] = {'log_sha256': digest,
                'tests': qualification_log(value, row['target'])}
    finally:
        os.close(fd)
    count = sum(len(row['tests']) for row in rows.values())
    xml = ET.Element('testsuites', tests=str(count), failures='0', errors='0', skipped='0')
    for target, row in sorted(rows.items()):
        suite = ET.SubElement(xml, 'testsuite', name=target, tests=str(len(row['tests'])),
            failures='0', errors='0', skipped='0')
        props = ET.SubElement(suite, 'properties')
        ET.SubElement(props, 'property', name='actual_test_log_sha256', value=row['log_sha256'])
        for name in row['tests']:
            ET.SubElement(suite, 'testcase', classname=target, name=name)
    raw = ET.tostring(xml, encoding='utf-8', xml_declaration=True) + b'\n'
    receipt = {'schema': 'omux-native-grouped-qualification-v1',
        'evidence': 'exact stable libtest names and counts from SHA256-verified actual logs',
        'targets': rows, 'passed': count, 'failed': 0, 'ignored': 0,
        'xml_sha256': hashlib.sha256(raw).hexdigest(),
        'native_support': False, 'provider_evaluation': False}
    if cli is not None:
        require(count == 14, 'combined qualification requires all fourteen named gates')
        receipt.update(cli_artifact=cli, cli_context=dict(context))
    parent = trusted_parent(run)
    try:
        for name, value in (('native-qualification.xml', raw),
                ('native-qualification.json', (json.dumps(receipt, sort_keys=True) + '\n').encode())):
            child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(child, 'wb') as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)
    return receipt
def meaningful_tests(run, manifest, mode, context=None):
    if mode == COMBINED_MODE:
        require(context is not None, 'combined qualification cleanup context missing')
        return qualification_evidence(run, manifest, context)
    require(context is None, 'historical native modes do not accept combined context')
    if mode == 'qualification':
        return qualification_evidence(run, manifest)
    minimum = {'core-text': 8, 'login-bind': 2}.get(mode, 1)
    fd = trusted_parent(run / 'test-evidence')
    try:
        observed = False
        for row in manifest['results']:
            for entry in row['files']:
                if entry['source'] != 'test.log' or entry['state'] != 'copied':
                    continue
                digest, _, value = hash_regular(fd, entry['file'], 64 * 1024 * 1024, True)
                require(digest == entry['sha256'], 'test evidence changed')
                counts = re.findall(rb'test result: ok\. ([0-9]+) passed; 0 failed;', value)
                require(counts and sum(int(n) for n in counts) >= minimum, 'selected native test filter ran too few tests')
                observed = True
        require(observed, 'native test log missing')
    finally:
        os.close(fd)

def readonly_paths(args, plan):
    paths = {str(args.native_source_root), str(args.native_export_root), plan['cwd'], str(Path.cwd())}
    if plan.get('candidate_cache_root') is not None:
        paths.add(plan['candidate_cache_root'])
    require(all(Path(p).is_absolute() and not any(c.isspace() or c in ':\\' for c in p) for p in paths), 'noncanonical readonly native path')
    return sorted(paths)

def verify_readonly(actual, args, plan):
    expected = set(readonly_paths(args, plan))
    observed = set()
    for entry in actual.get('BindReadOnlyPaths', '').split():
        parts = entry.split(':')
        require(1 <= len(parts) <= 3 and parts[0] in expected, 'unexpected native readonly mount')
        require(len(parts) == 1 or parts[1] == parts[0], 'native mount target changed')
        require(len(parts) < 3 or parts[2] in ('', 'rbind'), 'native mount option changed')
        observed.add(parts[0])
    require(observed == expected, 'native readonly mounts unproved')
    writable = actual.get('BindPaths', '').split()
    if plan.get('candidate_output_base') is None:
        require(not writable, 'unexpected writable native mount')
    else:
        require(len(writable) == 1, 'candidate cache requires one writable output base')
        parts = writable[0].split(':')
        require(1 <= len(parts) <= 3 and parts[0] == plan['candidate_output_base']
            and (len(parts) == 1 or parts[1] == parts[0])
            and (len(parts) < 3 or parts[2] in ('', 'rbind')), 'candidate writable mount mismatch')
