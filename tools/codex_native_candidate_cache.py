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

def valid_attempt(attempt, previous=None, *, max_attempts=MAX_ATTEMPTS):
    require(type(max_attempts) is int and max_attempts in (MAX_ATTEMPTS, 7),
            'candidate attempt ceiling must be explicit finite policy')
    require(type(attempt) is int and 1 <= attempt <= max_attempts,
            'candidate continuation attempt out of bounds')
    require(previous is None or type(previous) is int and 1 <= previous < max_attempts,
            'previous candidate attempt out of bounds')
    require(attempt == (1 if previous is None else previous + 1),
            'candidate continuation attempt sequence mismatch')

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def bindings(args, tools, controller_graph, locked_path, manager):
    receipt, export = native.verify_inputs(args)
    phase2 = phase2_requested(args)
    aggregate = getattr(args, 'native_aggregate_seconds', 1200)
    require(type(aggregate) is int and aggregate == (3600 if phase2 else 1200),
            'native wallclock policy requires exact explicit phase2 selector')
    require(args.state_dir == native.STATE and manager in ('user', 'system') and
        1 <= args.native_cache_attempt <= (7 if phase2 else MAX_ATTEMPTS),
        'finite candidate continuation required')
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
            'aggregate_seconds': aggregate, 'postcheck_reserve_seconds': 120, 'heap_mib': 768, 'jobs': 1},
        'network': 'private', 'repository_download': False, 'remote': False,
        'ambient_caches': False, 'test_sharding': False}

def prior_receipt(state, cache_root, key, attempt, *, max_attempts=MAX_ATTEMPTS,
                  previous_max_attempts=None):
    expected_previous_max = max_attempts if previous_max_attempts is None else previous_max_attempts
    require((max_attempts, expected_previous_max) in ((6, 6), (7, 6), (7, 7)),
            'candidate ceiling transition must preserve prior recorded ceiling')
    try:
        fd = trusted_directory(cache_root)
    except FileNotFoundError:
        valid_attempt(attempt, max_attempts=max_attempts)
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
        previous['max_attempts'] == expected_previous_max,
        'candidate continuation attempt or binding mismatch')
    valid_attempt(attempt, previous['attempt'], max_attempts=max_attempts)
    require(receipt['profile'] == 'codex-native' and receipt['descendants_empty'] is True
        and receipt['native_sdk']['source_and_export_verified_after_cleanup'] is True,
        'previous candidate source/cgroup cleanup unproved')
    require(receipt['unit'] == 'omux-execution-' + receipt['id'] + '.service', 'previous unit ownership mismatch')
    return receipt

# One reviewed controller-only transition from the frozen C26 candidate.
TRANSITION_KEY = '70d7fad0f82f7883e38ddfec2d343845f036dea4a6171ee213637e0b37669595'
TRANSITION_PRIOR_EPOCH = '34f674c0-9705-4135-b07d-7375fad6aa48'
TRANSITION_PRIOR_RECEIPT = '589b8f7c13e7c0d46393b40fb4fd377a4788ad4a5777721a99ee6c41cc514e9c'
TRANSITION_OLD_GRAPH = '3fd85968c22ea532a2612a680c8ec8d1bfbe7e750f17e10805e2945a98468159'
TRANSITION_OLD_COMMIT = '0df036609e9dfc752963e8862579a677ef2e535a'
TRANSITION_CHANGED = frozenset((
    'tools/codex_native_candidate_cache.py', 'tools/codex_native_candidate_cache_test.py',
    'tools/execution_guard.py', 'tools/execution_guard_test.py',
    'tools/codex_native_profile.py', 'tools/codex_native_profile_test.py',
    'tools/codex_fresh_native_runtime.py', 'tools/codex_fresh_native_runtime_test.py',
))
TRANSITION_REQUIRED = frozenset((
    'tools/codex_native_candidate_cache.py', 'tools/execution_guard.py',
    'tools/codex_native_profile.py', 'tools/codex_fresh_native_runtime.py',
))
TRANSITION_FIELDS = frozenset((
    'schema_version', 'scope', 'origin_key', 'old_bindings', 'new_bindings',
    'old_controller_inventory', 'new_controller_inventory', 'reviewed_file_changes',
    'old_source_commit', 'new_source_commit', 'prior_epoch', 'prior_receipt_sha256',
    'previous_dispatches', 'from_attempt', 'first_attempt', 'max_attempts',
    'aggregate_before', 'aggregate_max',
))

def transition_digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def sha(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value),
            'transition exact SHA256 required')
    return value

def transition_graph(inventory):
    require(isinstance(inventory, dict) and 0 < len(inventory) <= 4096,
            'transition bounded controller graph required')
    digest = hashlib.sha256()
    size = 0
    for path, value in sorted(inventory.items()):
        require(isinstance(path, str) and path and len(path) <= 4096
            and not Path(path).is_absolute() and str(Path(path)) == path
            and '..' not in Path(path).parts and '\\' not in path,
            'transition graph pathname refused')
        size += len(path.encode())
        require(size <= 128 * 1024, 'transition graph paths exceed bound')
        digest.update(path.encode() + b'\0' + bytes.fromhex(sha(value)))
    # graph_digest hashes lexical paths but returns os.walk selection order:
    # files in each directory precede its sorted descendant directories.
    selected = sorted(inventory,
        key=lambda path: (Path(path).parent.parts, Path(path).name))
    return digest.hexdigest(), selected

def controller_inventory(root, graph, deadline):
    from codex_sdk_profile import hash_regular
    require(isinstance(graph, (tuple, list)) and len(graph) == 2
            and isinstance(graph[1], list), 'actual controller graph required')
    inventory, total = {}, 0
    for path in graph[1]:
        require(isinstance(path, str) and str(Path(path)) == path
            and not Path(path).is_absolute() and '..' not in Path(path).parts,
            'actual controller graph path refused')
        parent = trusted_parent(Path(root) / Path(path).parent)
        try:
            digest, count, _ = hash_regular(parent, Path(path).name, 16 * 1024 * 1024,
                on_read=lambda count: native.tick(deadline))
        finally:
            os.close(parent)
        total += count
        require(total <= 64 * 1024 * 1024 and path not in inventory,
                'actual controller graph exceeds bound')
        inventory[path] = digest
    require(canonical(transition_graph(inventory)) == canonical(graph),
            'actual controller graph inventory mismatch')
    return inventory

def validate_transition_document(document, current, actual_inventory, args):
    require(isinstance(document, dict) and set(document) == TRANSITION_FIELDS,
            'closed transition amendment required')
    require(type(document['schema_version']) is int and document['schema_version'] == 1
            and document['scope'] == 'c26-qualification-cli-controller-only'
            and document['origin_key'] == TRANSITION_KEY
            and document['old_source_commit'] == TRANSITION_OLD_COMMIT
            and isinstance(document['new_source_commit'], str)
            and re.fullmatch(r'[0-9a-f]{40}', document['new_source_commit'])
            and document['new_source_commit'] == args.source_commit
            and args.source_dirty == 'false'
            and document['prior_epoch'] == TRANSITION_PRIOR_EPOCH
            and document['prior_receipt_sha256'] == TRANSITION_PRIOR_RECEIPT,
            'transition origin epoch/source amendment mismatch')
    for name, fixed in (('from_attempt', 4), ('first_attempt', 5), ('max_attempts', 6),
                        ('aggregate_before', 6), ('aggregate_max', 8)):
        require(type(document[name]) is int and document[name] == fixed,
                'transition finite counters must not reset')
    before, after = document['old_bindings'], document['new_bindings']
    require(isinstance(before, dict) and isinstance(after, dict)
            and set(before) == set(current) == set(after)
            and transition_digest(before) == TRANSITION_KEY
            and canonical(after) == canonical(current)
            and transition_digest(after) != TRANSITION_KEY,
            'transition old/new provenance mismatch')
    for field in before:
        if field not in ('controller_graph', 'modes'):
            require(canonical(before[field]) == canonical(after[field]),
                    'transition immutable native/export/tools/action policy changed')
    old_modes, new_modes = before['modes'], after['modes']
    expected = ['test', [native.CORE, native.CONFIG, native.LOGIN, '//codex-rs/cli:codex'], None]
    require(isinstance(old_modes, dict) and isinstance(new_modes, dict)
            and 'qualification-cli' not in old_modes
            and set(new_modes) == set(old_modes) | {'qualification-cli'}
            and new_modes['qualification-cli'] == expected
            and all(canonical(new_modes[name]) == canonical(value)
                    for name, value in old_modes.items()),
            'transition only exact combined mode addition permitted')
    old_graph = transition_graph(document['old_controller_inventory'])
    new_graph = transition_graph(document['new_controller_inventory'])
    require(old_graph[0] == TRANSITION_OLD_GRAPH
            and canonical(old_graph) == canonical(before['controller_graph'])
            and canonical(new_graph) == canonical(after['controller_graph'])
            and document['new_controller_inventory'] == actual_inventory
            and set(document['old_controller_inventory']) == set(actual_inventory),
            'transition reviewed complete controller inventories mismatch')
    changed = {path for path in actual_inventory
               if document['old_controller_inventory'][path] != actual_inventory[path]}
    require(TRANSITION_REQUIRED <= changed <= TRANSITION_CHANGED,
            'transition unreviewed graph or action definitions changed')
    expected_changes = [
        {'path': path, 'before_sha256': document['old_controller_inventory'][path],
         'after_sha256': actual_inventory[path]} for path in sorted(changed)]
    require(document['reviewed_file_changes'] == expected_changes,
            'transition exact reviewed file amendment pins differ')
    history = document['previous_dispatches']
    require(isinstance(history, list) and len(history) == 6,
            'transition requires all six prior dispatches')
    require(history[-1] == {'id': TRANSITION_PRIOR_EPOCH, 'sha256': TRANSITION_PRIOR_RECEIPT,
                           'cache_key': TRANSITION_KEY, 'attempt': 4},
            'transition latest dispatch anchor differs')
    for row in history:
        require(isinstance(row, dict) and set(row) == {'id', 'sha256', 'cache_key', 'attempt'}
                and isinstance(row['id'], str)
                and re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', row['id'])
                and type(row['attempt']) is int and 1 <= row['attempt'] <= 6,
                'transition prior dispatch shape differs')
        sha(row['sha256'])
        sha(row['cache_key'])
    require(len({row['id'] for row in history}) == 6
            and len({(row['cache_key'], row['attempt']) for row in history}) == 6,
            'transition dispatch epochs and consumed attempts must be distinct')
    require([row['attempt'] for row in history if row['cache_key'] == TRANSITION_KEY]
            == [1, 2, 3, 4], 'transition preserves all four origin attempts')
    other_keys = {row['cache_key'] for row in history if row['cache_key'] != TRANSITION_KEY}
    for key in other_keys:
        sequence = [row['attempt'] for row in history if row['cache_key'] == key]
        require(sequence == list(range(1, len(sequence) + 1)),
                'transition cannot skip or duplicate older-key attempts')
    return document

def read_transition(args, current, graph):
    path = getattr(args, 'native_cache_transition', None)
    digest = getattr(args, 'native_cache_transition_sha256', None)
    require((path is None) == (digest is None), 'transition exact amendment pin required')
    if path is None:
        return None
    require(args.native_owned_candidate_cache and args.manager == 'system'
            and args.native_mode in ('qualification-cli', 'schema')
            and args.native_cache_attempt in (5, 6),
            'transition restricted to two final owned native invocations')
    parent = trusted_parent(path.parent)
    try:
        # Exact SHA is explicitly reviewed before admission, never inferred
        # from a supplied path or rewritten in the cache owner marker.
        from codex_sdk_profile import hash_regular
        actual_sha, _, raw = hash_regular(parent, path.name, 1024 * 1024, capture=True,
            on_read=lambda count: native.tick(args.native_deadline))
        require(actual_sha == sha(digest), 'transition amendment bytes differ')
        def unique(pairs):
            value = {}
            for key, item in pairs:
                require(key not in value, 'transition duplicate JSON key')
                value[key] = item
            return value
        document = json.loads(raw, object_pairs_hook=unique)
    finally:
        os.close(parent)
    actual = controller_inventory(Path.cwd(), graph, args.native_deadline)
    validate_transition_document(document, current, actual, args)
    return document

def transition_history(document, amendment_sha256):
    return [{
        'schema_version': 1, 'amendment_sha256': amendment_sha256,
        'prior_epoch': document['prior_epoch'],
        'prior_cleanup_receipt_sha256': document['prior_receipt_sha256'],
        'from_controller_graph_sha256': document['old_bindings']['controller_graph'][0],
        'to_controller_graph_sha256': document['new_bindings']['controller_graph'][0],
        'from_provenance_sha256': TRANSITION_KEY,
        'to_provenance_sha256': transition_digest(document['new_bindings']),
        'from_attempt': 4, 'first_attempt': 5, 'aggregate_before': 6, 'aggregate_max': 8,
    }]

def verify_transition_previous(args, document, previous, amendment_sha256):
    require(isinstance(previous, dict), 'transition refuses missing origin cache')
    prior = previous['native_candidate_cache']
    expected_history = transition_history(document, amendment_sha256)
    history = document['previous_dispatches']
    # Each historical dispatch is an actual durable receipt; failures consume
    # counters and are never promoted into qualification/CLI success.
    for row in history:
        parent = trusted_parent(native.STATE / row['id'])
        try:
            record = metadata(parent, 'receipt.json', row['sha256'],
                              on_read=lambda count: native.tick(args.native_deadline))
        finally:
            os.close(parent)
        require(record['id'] == row['id'] and record['profile'] == 'codex-native'
                and record['native_candidate_cache']['key'] == row['cache_key']
                and record['native_candidate_cache']['attempt'] == row['attempt'],
                'transition prior aggregate receipt mismatch')
    if args.native_cache_attempt == 5:
        require(args.native_mode == 'qualification-cli'
                and previous['id'] == TRANSITION_PRIOR_EPOCH
                and prior['attempt'] == 4 and prior['provenance_sha256'] == TRANSITION_KEY
                and previous['graph_sha256'] == TRANSITION_OLD_GRAPH
                and previous['source_commit'] == TRANSITION_OLD_COMMIT
                and not prior.get('transition_history'),
                'transition must begin from exact frozen fourth attempt')
        return history
    require(args.native_cache_attempt == 6 and args.native_mode == 'schema'
            and prior['attempt'] == 5 and previous['exit'] == 0
            and previous['workload_exit'] == 0 and previous['controller_failure'] is None
            and previous['native_sdk']['mode'] == 'qualification-cli'
            and prior['origin_provenance_sha256'] == TRANSITION_KEY
            and prior['provenance_sha256'] == transition_digest(document['new_bindings'])
            and prior['transition_history'] == expected_history
            and prior['aggregate_attempt'] == 7
            and prior['aggregate_previous_dispatches'] == history,
            'schema transition requires actual successful combined predecessor')
    parent = trusted_parent(native.STATE / previous['id'])
    try:
        marker_fd = trusted_directory(native.STATE / ('cache-v2-' + TRANSITION_KEY))
        try:
            marker = read_marker(marker_fd)
        finally:
            os.close(marker_fd)
        require(marker['clean'] is True and marker['last_run'] == previous['id'],
                'transition latest schema predecessor marker differs')
        predecessor_digest = sha(marker['cleanup_receipt_sha256'])
        metadata(parent, 'receipt.json', predecessor_digest,
                 on_read=lambda count: native.tick(args.native_deadline))
    finally:
        os.close(parent)
    return history + [{'id': previous['id'], 'sha256': predecessor_digest,
                       'cache_key': TRANSITION_KEY, 'attempt': 5}]


# Root engineering-policy amendment after the exact failed fifth invocation.
# The first transition remains immutable and independently verifiable.
PHASE2_MAX_ATTEMPTS = 7
PHASE2_PRIOR_EPOCH = '275e4094-af7e-4c26-a390-bf8aa960310e'
PHASE2_PRIOR_RECEIPT = '960f154b3ddcc7b05c9ea11b054dc6ddc329782eb9f14d50301e966dfa97b260'
PHASE2_OLD_COMMIT = 'bbffd3c60a8189690028ff8ca5c5a7d12095c58d'
PHASE2_OLD_GRAPH = '76dd5eda91e2ead7a131cb27d88c6cca6fecb48a2013a8ffb4e56adcf1a4d603'
PHASE2_OLD_PROVENANCE = 'fe79bd14702570ea829266247e858a8449ef5030f166f969675746f5f5adffb7'
PHASE2_PRIOR_AMENDMENT = 'dcc9aa881b415d041e582e0271efc6e0fca7dff2d35918de5e65848c5b9ce6f5'
PHASE2_PRIOR_HISTORY = [{"aggregate_before":6,"aggregate_max":8,"amendment_sha256":"dcc9aa881b415d041e582e0271efc6e0fca7dff2d35918de5e65848c5b9ce6f5","first_attempt":5,"from_attempt":4,"from_controller_graph_sha256":"3fd85968c22ea532a2612a680c8ec8d1bfbe7e750f17e10805e2945a98468159","from_provenance_sha256":"70d7fad0f82f7883e38ddfec2d343845f036dea4a6171ee213637e0b37669595","prior_cleanup_receipt_sha256":"589b8f7c13e7c0d46393b40fb4fd377a4788ad4a5777721a99ee6c41cc514e9c","prior_epoch":"34f674c0-9705-4135-b07d-7375fad6aa48","schema_version":1,"to_controller_graph_sha256":"76dd5eda91e2ead7a131cb27d88c6cca6fecb48a2013a8ffb4e56adcf1a4d603","to_provenance_sha256":"fe79bd14702570ea829266247e858a8449ef5030f166f969675746f5f5adffb7"}]
PHASE2_PREVIOUS_DISPATCHES = [{"id":"6ab04062-5dce-424a-9873-0079c72ca63d","sha256":"4c271d5f621b8dde2f1d7e4ec884e0952c56cefd5868e7a9ef2ae0dae6215b92","cache_key":"114776d86a66e7feed83235431bc57096ffe5522b9e2fcca6d32881588cf2ea5","attempt":1},{"id":"42d44a8d-1f65-4a4f-9b38-b212aa0f4aaf","sha256":"4f218d143caea1b185d5df122c206af2372616c2c4b28461e8a26b305c12ca93","cache_key":"c1e21ac7ddb62ffc8862f21a7038f482781bf86147f6c41471a1ce91240ca482","attempt":1},{"id":"c7eaff60-669c-497e-9a16-322a17a6d5ac","sha256":"87199d816aa31eaa9c6a5d58321f3e05ac9c0ac9e338e8b3189aa5bd4f52e981","cache_key":"70d7fad0f82f7883e38ddfec2d343845f036dea4a6171ee213637e0b37669595","attempt":1},{"id":"23b62181-53dc-4391-ad43-a4146ca70c6b","sha256":"e42a1f6d0b0ee0b9a03d5781626fe30732d4f5a86fb5e086a67e16fc7968b755","cache_key":"70d7fad0f82f7883e38ddfec2d343845f036dea4a6171ee213637e0b37669595","attempt":2},{"id":"550f07e2-f46f-4906-87d6-9593a7f8bb81","sha256":"8d57ef2eb6616a3e65f9d42d282958ef46328eb9d5810255756d28c67db972fe","cache_key":"70d7fad0f82f7883e38ddfec2d343845f036dea4a6171ee213637e0b37669595","attempt":3},{"id":"34f674c0-9705-4135-b07d-7375fad6aa48","sha256":"589b8f7c13e7c0d46393b40fb4fd377a4788ad4a5777721a99ee6c41cc514e9c","cache_key":"70d7fad0f82f7883e38ddfec2d343845f036dea4a6171ee213637e0b37669595","attempt":4},{"id":"275e4094-af7e-4c26-a390-bf8aa960310e","sha256":"960f154b3ddcc7b05c9ea11b054dc6ddc329782eb9f14d50301e966dfa97b260","cache_key":"70d7fad0f82f7883e38ddfec2d343845f036dea4a6171ee213637e0b37669595","attempt":5}]
PHASE2_FIELDS = TRANSITION_FIELDS | {'prior_transition_history', 'prior_amendment_sha256'}

def phase2_requested(args):
    path = getattr(args, 'native_cache_phase2', None)
    digest = getattr(args, 'native_cache_phase2_sha256', None)
    require((path is None) == (digest is None), 'phase2 exact amendment pin required')
    require(path is None or (getattr(args, 'native_cache_transition', None) is None
        and getattr(args, 'native_cache_transition_sha256', None) is None),
        'phase2 and original transition selectors are exclusive')
    return path is not None

def validate_phase2_document(document, current, actual_inventory, args):
    require(isinstance(document, dict) and set(document) == PHASE2_FIELDS,
            'closed phase2 amendment required')
    require(type(document['schema_version']) is int and document['schema_version'] == 2
            and document['scope'] == 'c26-native-budget-phase2'
            and document['origin_key'] == TRANSITION_KEY
            and document['old_source_commit'] == PHASE2_OLD_COMMIT
            and isinstance(document['new_source_commit'], str)
            and re.fullmatch(r'[0-9a-f]{40}', document['new_source_commit'])
            and document['new_source_commit'] == args.source_commit
            and args.source_dirty == 'false'
            and document['prior_epoch'] == PHASE2_PRIOR_EPOCH
            and document['prior_receipt_sha256'] == PHASE2_PRIOR_RECEIPT
            and document['prior_amendment_sha256'] == PHASE2_PRIOR_AMENDMENT
            and canonical(document['prior_transition_history']) == canonical(PHASE2_PRIOR_HISTORY),
            'phase2 exact prior source/receipt/transition differs')
    for name, fixed in (('from_attempt', 5), ('first_attempt', 6), ('max_attempts', 7),
                        ('aggregate_before', 7), ('aggregate_max', 9)):
        require(type(document[name]) is int and document[name] == fixed,
                'phase2 finite counters must preserve consumed fifth attempt')
    before, after = document['old_bindings'], document['new_bindings']
    require(isinstance(before, dict) and isinstance(after, dict)
            and set(before) == set(current) == set(after)
            and transition_digest(before) == PHASE2_OLD_PROVENANCE
            and canonical(after) == canonical(current)
            and transition_digest(after) != PHASE2_OLD_PROVENANCE,
            'phase2 old/new provenance mismatch')
    for name in before:
        if name not in ('controller_graph', 'limits'):
            require(canonical(before[name]) == canonical(after[name]),
                    'phase2 immutable native/export/tools/mode/action policy changed')
    old_limits, new_limits = before['limits'], after['limits']
    require(isinstance(old_limits, dict) and isinstance(new_limits, dict)
            and set(old_limits) == set(new_limits)
            and type(old_limits.get('aggregate_seconds')) is int
            and old_limits['aggregate_seconds'] == 1200
            and type(new_limits.get('aggregate_seconds')) is int
            and new_limits['aggregate_seconds'] == 3600
            and all(canonical(new_limits[name]) == canonical(value)
                    for name, value in old_limits.items() if name != 'aggregate_seconds'),
            'phase2 only aggregate native wallclock may change')
    old_graph = transition_graph(document['old_controller_inventory'])
    new_graph = transition_graph(document['new_controller_inventory'])
    require(old_graph[0] == PHASE2_OLD_GRAPH
            and canonical(old_graph) == canonical(before['controller_graph'])
            and canonical(new_graph) == canonical(after['controller_graph'])
            and document['new_controller_inventory'] == actual_inventory
            and set(document['old_controller_inventory']) == set(actual_inventory),
            'phase2 reviewed complete controller inventories mismatch')
    changed = {path for path in actual_inventory
               if document['old_controller_inventory'][path] != actual_inventory[path]}
    require(TRANSITION_REQUIRED <= changed <= TRANSITION_CHANGED,
            'phase2 unreviewed graph or action definitions changed')
    require(document['reviewed_file_changes'] == [
        {'path': path, 'before_sha256': document['old_controller_inventory'][path],
         'after_sha256': actual_inventory[path]} for path in sorted(changed)],
        'phase2 exact reviewed file amendment pins differ')
    require(canonical(document['previous_dispatches']) == canonical(PHASE2_PREVIOUS_DISPATCHES),
            'phase2 preserves all seven exact prior dispatches')
    return document

def read_phase2(args, current, graph):
    if not phase2_requested(args):
        return None
    require(args.native_owned_candidate_cache and args.manager == 'system'
            and (args.native_mode, args.native_cache_attempt)
                in (('qualification-cli', 6), ('schema', 7))
            and getattr(args, 'native_aggregate_seconds', None) == 3600,
            'phase2 restricted to exact final two owned native invocations')
    path = args.native_cache_phase2
    parent = trusted_parent(path.parent)
    try:
        from codex_sdk_profile import hash_regular
        actual_sha, _, raw = hash_regular(parent, path.name, 1024 * 1024, capture=True,
            on_read=lambda count: native.tick(args.native_deadline))
        require(actual_sha == sha(args.native_cache_phase2_sha256),
                'phase2 amendment bytes differ')
        def unique(pairs):
            value = {}
            for key, item in pairs:
                require(key not in value, 'phase2 duplicate JSON key')
                value[key] = item
            return value
        document = json.loads(raw, object_pairs_hook=unique)
    finally:
        os.close(parent)
    actual = controller_inventory(Path.cwd(), graph, args.native_deadline)
    return validate_phase2_document(document, current, actual, args)

def phase2_history(document, amendment_sha256):
    return [dict(row) for row in document['prior_transition_history']] + [{
        'schema_version': 2, 'amendment_sha256': amendment_sha256,
        'prior_epoch': document['prior_epoch'],
        'prior_cleanup_receipt_sha256': document['prior_receipt_sha256'],
        'from_controller_graph_sha256': document['old_bindings']['controller_graph'][0],
        'to_controller_graph_sha256': document['new_bindings']['controller_graph'][0],
        'from_provenance_sha256': PHASE2_OLD_PROVENANCE,
        'to_provenance_sha256': transition_digest(document['new_bindings']),
        'from_attempt': 5, 'first_attempt': 6, 'aggregate_before': 7, 'aggregate_max': 9,
    }]

def verify_phase2_previous(args, document, previous, amendment_sha256):
    require(isinstance(previous, dict), 'phase2 refuses missing origin cache')
    prior = previous['native_candidate_cache']
    history = document['previous_dispatches']
    # Rehash every consumed actual receipt; none is relabelled as success.
    for row in history:
        parent = trusted_parent(native.STATE / row['id'])
        try:
            record = metadata(parent, 'receipt.json', row['sha256'],
                              on_read=lambda count: native.tick(args.native_deadline))
        finally:
            os.close(parent)
        require(record['id'] == row['id'] and record['profile'] == 'codex-native'
                and record['native_candidate_cache']['key'] == row['cache_key']
                and record['native_candidate_cache']['attempt'] == row['attempt']
                and record['descendants_empty'] is True
                and record['native_sdk']['source_and_export_verified_after_cleanup'] is True,
                'phase2 actual prior aggregate receipt/integrity mismatch')
    require(prior.get('origin_provenance_sha256') == TRANSITION_KEY
            and prior.get('transition_verified_after_cleanup') is True,
            'phase2 prior origin and terminal transition readback required')
    if args.native_cache_attempt == 6:
        require(args.native_mode == 'qualification-cli'
                and previous['id'] == PHASE2_PRIOR_EPOCH
                and previous['source_commit'] == PHASE2_OLD_COMMIT
                and previous['graph_sha256'] == PHASE2_OLD_GRAPH
                and previous['exit'] == 125 and previous['workload_exit'] == 124
                and previous['controller_failure'] is None
                and previous['native_sdk']['mode'] == 'qualification-cli'
                and prior['attempt'] == 5 and prior['max_attempts'] == 6
                and prior['provenance_sha256'] == PHASE2_OLD_PROVENANCE
                and prior['transition_history'] == document['prior_transition_history']
                and prior['aggregate_attempt'] == 7 and prior['aggregate_max_attempts'] == 8
                and prior['aggregate_previous_dispatches'] == history[:-1],
                'phase2 must begin from exact failed fifth invocation')
        return history
    require(args.native_cache_attempt == 7 and args.native_mode == 'schema'
            and prior['attempt'] == 6 and prior['max_attempts'] == 7
            and previous['exit'] == 0 and previous['workload_exit'] == 0
            and previous['controller_failure'] is None
            and previous['source_commit'] == document['new_source_commit']
            and previous['graph_sha256'] == document['new_bindings']['controller_graph'][0]
            and previous['native_sdk']['mode'] == 'qualification-cli'
            and prior['provenance_sha256'] == transition_digest(document['new_bindings'])
            and prior['transition_history'] == phase2_history(document, amendment_sha256)
            and prior['aggregate_attempt'] == 8 and prior['aggregate_max_attempts'] == 9
            and prior['aggregate_previous_dispatches'] == history
            and prior.get('phase2_verified_before_launch') is True,
            'phase2 schema requires actual successful combined sixth invocation')
    parent = trusted_parent(native.STATE / previous['id'])
    try:
        marker_fd = trusted_directory(native.STATE / ('cache-v2-' + TRANSITION_KEY))
        try:
            marker = read_marker(marker_fd)
        finally:
            os.close(marker_fd)
        require(marker['clean'] is True and marker['key'] == TRANSITION_KEY
                and marker['schema'] == 2 and marker['last_run'] == previous['id'],
                'phase2 latest schema predecessor marker differs')
        predecessor_digest = sha(marker['cleanup_receipt_sha256'])
        metadata(parent, 'receipt.json', predecessor_digest,
                 on_read=lambda count: native.tick(args.native_deadline))
    finally:
        os.close(parent)
    return history + [{'id': previous['id'], 'sha256': predecessor_digest,
                       'cache_key': TRANSITION_KEY, 'attempt': 6}]

class Candidate:
    def __init__(self, args, run, tools, controller_graph, locked_path, manager, verify_previous):
        self.provenance = bindings(args, tools, controller_graph, locked_path, manager)
        self.args = args
        self.controller_graph = controller_graph
        self.transition = read_transition(args, self.provenance, controller_graph)
        self.phase2 = read_phase2(args, self.provenance, controller_graph)
        self._phase2_verified_before_launch = False
        self.transition_verified_after_cleanup = None
        self.aggregate_previous_dispatches = None
        self.key = TRANSITION_KEY if (self.transition is not None or self.phase2 is not None) else transition_digest(self.provenance)
        self.root = native.STATE / ('cache-v2-' + self.key)
        self.attempt = args.native_cache_attempt
        if self.phase2 is not None:
            previous = prior_receipt(native.STATE, self.root, self.key, self.attempt,
                max_attempts=7, previous_max_attempts=6 if self.attempt == 6 else 7)
        else:
            previous = prior_receipt(native.STATE, self.root, self.key, self.attempt)
        if previous is not None:
            require(verify_previous(previous) is True, 'previous owned unit or cgroup is not empty')
        if self.transition is not None:
            self.aggregate_previous_dispatches = verify_transition_previous(
                args, self.transition, previous, args.native_cache_transition_sha256)
        if self.phase2 is not None:
            self.aggregate_previous_dispatches = verify_phase2_previous(
                args, self.phase2, previous, args.native_cache_phase2_sha256)
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
        self._phase2_verified_before_launch = self.phase2 is not None

    @property
    def phase2_verified_before_launch(self):
        return self._phase2_verified_before_launch is True

    def facts(self):
        result = {'key': self.key, 'attempt': self.attempt, 'max_attempts': 7 if self.phase2 is not None else MAX_ATTEMPTS,
            'workspace': str(self.source), 'output_base': str(self.lease.output_base),
            'provenance_sha256': hashlib.sha256(canonical(self.provenance)).hexdigest(),
            'reuse_scope': 'this exact sealed candidate; batch; finite modes',
            'previous_cleanup_required': True}
        if self.transition is not None:
            result.update(origin_provenance_sha256=TRANSITION_KEY,
                transition_history=transition_history(self.transition, self.args.native_cache_transition_sha256),
                aggregate_attempt=self.attempt + 2, aggregate_max_attempts=8,
                aggregate_previous_dispatches=self.aggregate_previous_dispatches,
                transition_verified_after_cleanup=self.transition_verified_after_cleanup,
                reuse_scope='exact C26 origin; reviewed controller-only amendment; attempts five and six')
        if self.phase2 is not None:
            result.update(origin_provenance_sha256=TRANSITION_KEY,
                transition_history=phase2_history(self.phase2, self.args.native_cache_phase2_sha256),
                aggregate_attempt=self.attempt + 2, aggregate_max_attempts=9,
                aggregate_previous_dispatches=self.aggregate_previous_dispatches,
                transition_verified_after_cleanup=self.transition_verified_after_cleanup,
                phase2_verified_before_launch=self.phase2_verified_before_launch,
                reuse_scope='exact C26 origin; root engineering-policy phase2; attempts six and seven')
        return result

    def verify_transition_after_cleanup(self):
        if self.phase2 is not None:
            observed = read_phase2(self.args, self.provenance, self.controller_graph)
            require(canonical(observed) == canonical(self.phase2),
                    'phase2 amendment changed before terminal cleanup readback')
            self.transition_verified_after_cleanup = True
        elif self.transition is not None:
            observed = read_transition(self.args, self.provenance, self.controller_graph)
            require(canonical(observed) == canonical(self.transition),
                    'transition amendment changed before terminal cleanup readback')
            self.transition_verified_after_cleanup = True

    def close(self):
        self.lease.close()

    def may_complete(self, cleanup, integrity):
        return completion_allowed(cleanup, integrity) and (
            (self.transition is None and self.phase2 is None)
            or self.transition_verified_after_cleanup is True)
