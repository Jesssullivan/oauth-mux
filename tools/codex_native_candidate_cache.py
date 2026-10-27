"""Finite own-candidate batch-Bazel continuation; never adopt a historical base."""
import hashlib
import json
import os
from pathlib import Path
import re
from guard_cache import CacheLease, read_marker, trusted_directory, verify_cleanup_receipt
from codex_sdk_profile import metadata, require, verify_inventory, EXPORT_MODE_POLICY
from codex_fresh_source import trusted_parent
import codex_native_profile as native

MAX_ATTEMPTS = 6

def completion_allowed(cleanup, integrity):
    return cleanup is True and integrity is True

def valid_attempt(attempt, previous=None):
    require(type(attempt) is int and 1 <= attempt <= MAX_ATTEMPTS,
            'candidate continuation attempt out of bounds')
    require(previous is None or type(previous) is int and 1 <= previous < MAX_ATTEMPTS,
            'previous candidate attempt out of bounds')
    require(attempt == (1 if previous is None else previous + 1),
            'candidate continuation attempt sequence mismatch')

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def bindings(args, tools, controller_graph, locked_path, manager):
    receipt, export = native.verify_inputs(args)
    require(args.state_dir == native.STATE and manager in ('user', 'system') and
        1 <= args.native_cache_attempt <= MAX_ATTEMPTS, 'finite candidate continuation required')
    require(all(isinstance(v, str) and v.startswith('/nix/store/') and
        '..' not in Path(v).parts and not any(c.isspace() for c in v) for v in tools.values()),
        'candidate cache tools must be locked immutable inputs')
    return {'policy': 'omux-native-own-candidate-cache-v1', 'uid': os.getuid(), 'gid': os.getgid(),
        'manager': manager, 'tools': tools, 'controller_graph': controller_graph,
        'source_root': str(args.native_source_root), 'source_receipt_sha256': args.native_source_sha256,
        'source_inventory_sha256': receipt['inventory_sha256'], 'source_graph': receipt['graph_files'],
        'patch_sha256': args.native_patch_sha256, 'export_root': str(args.native_export_root),
        'export_receipt_sha256': args.native_export_sha256, 'export_inventory_sha256': export['inventory_sha256'],
        'mapping_sha256': export['mapping_sha256'], 'locked_path': locked_path,
        'bazel_dispatcher_environment': {'USE_BAZEL_VERSION': native.BAZEL_VERSION},
        'module_resolution_policy': native.MODULE_RESOLUTION_POLICY,
        'modes': native.MODES, 'platform': '//codex-rs/core:owner-linux',
        'toolchain': '//codex-rs/core:owner-local-test-toolchain', 'batch': True,
        'limits': {'memory': 4294967296, 'tasks': 512, 'cpu_percent': 200,
            'aggregate_seconds': 1200, 'postcheck_reserve_seconds': 120, 'heap_mib': 768, 'jobs': 1},
        'network': 'private', 'repository_download': False, 'remote': False,
        'ambient_caches': False, 'test_sharding': False}

def prior_receipt(state, cache_root, key, attempt):
    try:
        fd = trusted_directory(cache_root)
    except FileNotFoundError:
        valid_attempt(attempt)
        return None
    try:
        marker = read_marker(fd)
    finally:
        os.close(fd)
    require(marker['key'] == key and marker['schema'] == 2 and marker['clean'] is True,
            'dirty or foreign candidate cache refused')
    require(marker['last_run'] is not None, 'incomplete candidate initialization refused')
    verify_cleanup_receipt(state, marker['last_run'], marker['cleanup_receipt_sha256'])
    fd = trusted_parent(state / marker['last_run'])
    try:
        receipt = metadata(fd, 'receipt.json', marker['cleanup_receipt_sha256'])
    finally:
        os.close(fd)
    previous = receipt.get('native_candidate_cache')
    require(isinstance(previous, dict) and previous['key'] == key and
        previous['max_attempts'] == MAX_ATTEMPTS,
        'candidate continuation attempt or binding mismatch')
    valid_attempt(attempt, previous['attempt'])
    require(receipt['profile'] == 'codex-native' and receipt['descendants_empty'] is True
        and receipt['native_sdk']['source_and_export_verified_after_cleanup'] is True,
        'previous candidate source/cgroup cleanup unproved')
    require(receipt['unit'] == 'omux-execution-' + receipt['id'] + '.service', 'previous unit ownership mismatch')
    return receipt

class Candidate:
    def __init__(self, args, run, tools, controller_graph, locked_path, manager, verify_previous):
        self.provenance = bindings(args, tools, controller_graph, locked_path, manager)
        self.key = hashlib.sha256(canonical(self.provenance)).hexdigest()
        self.root = native.STATE / ('cache-v2-' + self.key)
        self.attempt = args.native_cache_attempt
        previous = prior_receipt(native.STATE, self.root, self.key, self.attempt)
        if previous is not None:
            require(verify_previous(previous) is True, 'previous owned unit or cgroup is not empty')
        self.lease = CacheLease(native.STATE, self.key, run.name, policy_version=2)
        self.lease.__enter__()
        # CacheLease now owns its additional lock and has durably marked dirty.
        # Any exception leaves the dirty fence; nothing automatically clears it.
        self.source = self.root / 'native-input/source'
        try:
            native.source_io.DEADLINE = args.native_deadline
            try:
                self.lease.output_base.mkdir(mode=0o700)
            except FileExistsError:
                # CacheLease already verified this exact nofollow directory.
                pass
            receipt = native.validate_source(args.native_source_root, args.native_source_sha256,
                args.native_patch_sha256, args.native_deadline)
            if previous is None:
                self.source = native.copy_source(args.native_source_root, receipt, self.root)
            else:
                fd = trusted_parent(self.source)
                try:
                    verify_inventory(fd, receipt['source_inventory'], EXPORT_MODE_POLICY,
                        on_read=lambda count: native.tick(args.native_deadline))
                finally:
                    os.close(fd)
        except BaseException:
            self.lease.close()
            raise

    def facts(self):
        return {'key': self.key, 'attempt': self.attempt, 'max_attempts': MAX_ATTEMPTS,
            'workspace': str(self.source), 'output_base': str(self.lease.output_base),
            'provenance_sha256': hashlib.sha256(canonical(self.provenance)).hexdigest(),
            'reuse_scope': 'this exact sealed candidate; batch; finite modes',
            'previous_cleanup_required': True}

    def close(self):
        self.lease.close()

    def may_complete(self, cleanup, integrity):
        return completion_allowed(cleanup, integrity)
