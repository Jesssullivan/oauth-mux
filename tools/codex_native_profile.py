"""Finite offline native candidate profile; launches only through execution_guard."""
import hashlib
import json
import os
from pathlib import Path
import re
import time
import math
import codex_live_source as source_io
from codex_sdk_profile import metadata, require, verify_inventory, EXPORT_MODE_POLICY, hash_regular
from codex_fresh_source import trusted_parent
from codex_retained_sdk_export import validate_export
from codex_live_source import BASE_RECEIPT_SHA, BASE_INVENTORY, COMMIT, GRAPH, write_source, read

BAZEL = '/nix/store/ia8gp7v2h790lwdx7a7p5clh063v0qy1-bazel-9.0.1/bin/bazel'
STATE = Path('/srv/fast-local/jess/state/codex/omux-native-candidate-20261007')
CORE = '//codex-rs/core:core-unit-tests'
PRODUCTION = ('//codex-rs/core:core', '//codex-rs/app-server:app-server', '//codex-rs/config:config', '//codex-rs/app-server-protocol:app-server-protocol', '//codex-rs/tui:tui', '//codex-rs/cli:codex', '//codex-rs/config-schema:codex-write-config-schema', '//bazel/schema:public-schema-bundle')
MODES = {
    'analysis': ('build', PRODUCTION, None), 'production8': ('build', PRODUCTION, None),
    'cli-opt': ('build', ('//codex-rs/cli:codex',), None),
    'core-completion-committed': ('test', (CORE,), 'native_completed_waits_for_committed_terminal_report'),
    'core-completion-uncommitted': ('test', (CORE,), 'uncommitted_terminal_report_never_exposes_native_completed'),
    'core-text': ('test', (CORE,), 'broker_text_context::tests'),
    'client-text': ('test', (CORE,), 'client::tests::native_text_policy_builds_actual_wire_input_and_freezes_the_complete_request'),
    'config-text': ('test', ('//codex-rs/config:config-unit-tests',), 'config_toml::tests::omux_text_context_mode_is_explicit_and_unknown_modes_fail'),
    'schema': ('build', PRODUCTION[-2:], None),
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
        argv.append('--override_module=' + name + '=' + directory)
    if args.native_mode == 'analysis':
        argv.append('--nobuild')
    if verb == 'test':
        argv += ['--local_test_jobs=1', '--test_sharding_strategy=disabled', '--test_timeout=1200', '--test_env=RUST_TEST_THREADS=1',
            '--test_env=RUST_MIN_STACK=8388608', '--test_env=PATH=' + locked_path, '--nocache_test_results',
            '--nozip_undeclared_test_outputs', '--test_output=errors', '--test_filter=' + test_filter]
    return {'argv': argv + list(targets), 'cwd': str(source), 'source_inventory_sha256': receipt['inventory_sha256'],
        'candidate_cache_root': str(candidate.root) if candidate is not None else None,
        'candidate_output_base': str(candidate.lease.output_base) if candidate is not None else None,
        'export_inventory_sha256': exported['inventory_sha256'], 'mapping_sha256': exported['mapping_sha256'],
        'environment': {'PATH': locked_path, 'HOME': str(run / 'home'), 'XDG_CACHE_HOME': str(run / 'home/cache'),
            'XDG_CONFIG_HOME': str(run / 'home/config'), 'XDG_STATE_HOME': str(run / 'home/state')}}

def runtime(args):
    tick(args.native_deadline)
    # Reserve 120 seconds inside the same aggregate budget for verified cleanup
    # and full source/export readback. Exhaustion still fails closed.
    remaining = math.floor(args.native_deadline - time.monotonic() - 120)
    require(remaining > 0, 'native runtime budget exhausted')
    return remaining

def meaningful_tests(run, manifest, mode):
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
