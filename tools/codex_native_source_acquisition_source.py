"""Ninth source: complete actual N5 -> exact refresh -> exact acquisition v3."""
import os
import json
from pathlib import Path
import sys
import time
import codex_native_source_acquisition_binding as binding

parent = binding.parent
source = parent.source
PATCH = 'integrations/codex-upstream/native-source-acquisition-v3.patch'
PATCH_SHA = '2cadbd4c7a5a29653c835d7ff85ddb536e9950d9490186453a466af6fa1f5f90'
PATCH_BYTES = 51506
KIND = 'omux-native-source-acquisition-source-v1'
PREIMAGES = {
 'codex-rs/Cargo.lock': 'f1e3b7f0f5ff53e0f02c34ba05e0d2e3ad82535eeec70caa17366793997051cc',
 'codex-rs/app-server/Cargo.toml': 'fc4c938f1dbe246080f5bb0445eca8800d2d03fc62c33e7573869a72a8d5b87e',
 'codex-rs/app-server/src/lib.rs': 'c8e04310ebeeee0639b6769e4f15c6808b618d14fa7dd5d84ebe53610d1f9a01',
 'codex-rs/app-server/src/owner_control.rs': 'ddf145fa4e2f7858f1ccd47053ba02636def7bb267c484e106743f4dbdc50417',
 'codex-rs/app-server/src/owner_source_context.rs': '0ae0f46e3c2c16db7ae97241f44565281d9b1740edc37c4fd7fd59dec736044b',
 'codex-rs/core/src/native_peer.rs': '20dcb0de30f0f2c0ab1d2834aa6f9aab41dce544a95288b4eff448defe08e684'}
AFTERIMAGES = {
 'codex-rs/Cargo.lock': '546f8829d56d2a7d412ecdb1327d6baea90b78825011e6b9bd6ad07f42a396d0',
 'codex-rs/app-server/Cargo.toml': '28e919ea849f0e3e7f659e2045c89481f8454c4b11ddeba7fb8ef8e564e978f5',
 'codex-rs/app-server/src/lib.rs': 'cb815c1a1ed1ab518909c2282f724b97018e4fd88fcc6aedefb463a7d23addac',
 'codex-rs/app-server/src/owner_control.rs': 'b7170e1a60b72fff6261ccc1845b674799c65560e6e83b736f3272352a762e31',
 'codex-rs/app-server/src/owner_source_acquisition.rs': 'ad7116d71d6ef3a5f08e12246510cc94ea5794304b9ed7a4730dc79af4689e6b',
 'codex-rs/app-server/src/owner_source_context.rs': 'dccc7ebbc51628157d9e5256e94892afb0ff0ce4942ef6e651c01861518c4c22',
 'codex-rs/core/src/native_peer.rs': '6683fe3ea226458c5ca8fae11be5d907ea67aaf4e96b835f5f00d1409c82486a'}
NEW = 'codex-rs/app-server/src/owner_source_acquisition.rs'
PHASE = 'input'
PHASES = frozenset(('input', 'parent', 'patch', 'output', 'readback'))
FLAGS = parent.FLAGS + ('context_rotation_runtime_qualified', 'finite_kernel_shutdown_proven',
    'credential_acquisition_qualified', 'native_image_qualified', 'source_consent_qualified')

def read_patch():
    raw = parent.declared(PATCH, PATCH_BYTES)
    source.require(len(raw) == PATCH_BYTES and source.sha(raw) == PATCH_SHA)
    return raw

def transform(files, raw):
    source.require(type(raw) is bytes and len(raw) == PATCH_BYTES and len(raw) <= source.MAX_PATCH
        and raw.endswith(b'\n') and source.sha(raw) == PATCH_SHA and NEW not in files)
    lines = raw.decode('utf-8').splitlines(keepends=True)
    seen = set()
    for at, line in enumerate(lines):
        if line.startswith('diff --git '):
            parts = line.removesuffix('\n').split(' ')
            source.require(len(parts) == 4 and parts[2].startswith('a/'))
            name = parts[2][2:]
            source.require(name in AFTERIMAGES and name not in seen and parts[3] == 'b/' + name)
            if name == NEW:
                source.require(lines[at+1:at+4] == ['new file mode 100644\n', '--- /dev/null\n', f'+++ b/{name}\n'])
            else:
                source.require(lines[at+1:at+3] == [f'--- a/{name}\n', f'+++ b/{name}\n'])
            seen.add(name)
    source.require(seen == set(AFTERIMAGES) and set(PREIMAGES) <= set(files))
    for name, pin in PREIMAGES.items():
        source.require(files[name][0] == '100644' and source.sha(files[name][1]) == pin)
    changes = parent.seventh.status.patch_io.apply_exact(''.join(lines), {name: files[name][1] for name in PREIMAGES})
    source.require(set(changes) == set(AFTERIMAGES))
    result = dict(files)
    for name, raw_after in changes.items():
        source.require(source.sha(raw_after) == AFTERIMAGES[name])
        result[name] = ('100644', raw_after)
    validate_transition(files, result)
    return result

def validate_transition(before, after):
    source.require(set(after) == set(before) | {NEW}
        and {name for name in before if before[name] != after[name]} == set(PREIMAGES)
        and all(before[name] == after[name] for name in before if name not in PREIMAGES)
        and all(after[name][0] == '100644' for name in AFTERIMAGES)
        and all(before[name][0] == '100644' for name in PREIMAGES))
    for name in parent.seventh.history.GRAPH:
        source.require(name in before and name in after
            and (name == 'codex-rs/Cargo.lock' or before[name] == after[name]))
    source.require(source.sha(after['codex-rs/Cargo.lock'][1]) == AFTERIMAGES['codex-rs/Cargo.lock'])

def load_parent(config, witness):
    witness()
    report, before = parent.load_seventh(config)
    refresh = parent.read_patch()
    result = parent.transform(before, refresh)
    receipt = parent.expected_receipt(report, result, config)
    source.require(len(receipt['patch_sha256']) == 8 and all(receipt[name] is False for name in parent.FLAGS))
    witness()
    return receipt, result, refresh

def expected_receipt(report, result, config):
    inventory = parent.seventh.status.inventory(result)
    return {'schema_version': 1, 'kind': KIND, 'status': 'verified-ninth-acquisition-source-uncompiled',
        'commit': source.COMMIT, 'actual_seventh_source_root': config['root'],
        'actual_seventh_receipt_sha256': config['receipt_sha256'],
        'actual_seventh_inventory_sha256': config['inventory_sha256'],
        'patch_sha256': report['patch_sha256'] + [PATCH_SHA],
        'patches': report['patches'] + [{'patch_sha256': PATCH_SHA, 'paths': sorted(AFTERIMAGES)}],
        'acquisition_preimages': PREIMAGES, 'acquisition_afterimages': AFTERIMAGES,
        'source_inventory': inventory, 'inventory_sha256': source.sha(source.canonical(inventory)),
        'tracked_files': len(result), 'source_bytes': sum(len(raw) for _, raw in result.values()),
        'graph_files': {name: {'sha256': source.sha(result[name][1])} for name in report['graph_files']},
        'dependency_graph_changes': {'codex-rs/Cargo.lock': AFTERIMAGES['codex-rs/Cargo.lock'],
            'codex-rs/app-server/Cargo.toml': AFTERIMAGES['codex-rs/app-server/Cargo.toml']},
        'patch_position_policy': 'unique-file-exact-original-and-cumulative-destination-v1',
        'physical_mode_policy': 'bazel-retained-export-all-regular-and-directories-0555-v1',
        'acquisition_source_present': True, **{name: False for name in FLAGS}}

def verify_output(output, receipt_pin, inventory_pin):
    """Reconstruct and verify a caller-pinned actual ninth output, without a clock reset."""
    source.require(source.DEADLINE is not None and isinstance(output, Path))
    for pin in (receipt_pin, inventory_pin):
        source.require(type(pin) is str and len(pin) == 64 and all(c in '0123456789abcdef' for c in pin))
    config, value = binding.load()
    root = source.directory(output)
    try:
        anchor = parent.seventh.parent.identity(root)
        source.require(anchor[3] == 0o555)
        with binding.hold(config, value) as witness:
            report, before, refresh = load_parent(config, witness)
            raw_patch = read_patch(); files = transform(before, raw_patch)
            expected = expected_receipt(report, files, config)
            raw, mode = source.read(root, 'source-receipt.json', source.MAX_METADATA)
            source.require(mode in (0o444, 0o555) and source.sha(raw) == receipt_pin
                and json.loads(raw, object_pairs_hook=source.unique) == expected
                and source.sha(source.encoded(expected)) == receipt_pin
                and expected['inventory_sha256'] == inventory_pin)
            source.verify_written(output / 'source', files)
            again_report, again_files, again_refresh = load_parent(config, witness)
            source.require((again_report, again_files, again_refresh) == (report, before, refresh)
                and binding.load() == (config, value) and read_patch() == raw_patch)
            source.verify_written(output / 'source', files)
            again, again_mode = source.read(root, 'source-receipt.json', source.MAX_METADATA)
            source.require(again == raw and again_mode == mode)
            named = source.directory(output)
            try: source.require(parent.seventh.parent.identity(named) == anchor)
            finally: os.close(named)
        return expected, files
    finally: os.close(root)

def produce(output, seconds):
    global PHASE
    source.require(type(seconds) is int and 1 <= seconds <= 840)
    source.DEADLINE = time.monotonic() + seconds
    root = None
    try:
        PHASE = 'input'
        config, value = binding.load()
        with binding.hold(config, value) as witness:
            PHASE = 'parent'
            report, before, refresh = load_parent(config, witness)
            PHASE = 'patch'
            raw = read_patch(); result = transform(before, raw)
            receipt = expected_receipt(report, result, config)
            PHASE = 'output'; root = source.write_source(output, result)
            PHASE = 'readback'; source.verify_written(output / 'source', result)
            after_report, after_files, after_refresh = load_parent(config, witness)
            source.require(after_report == report and after_files == before and after_refresh == refresh
                and binding.load() == (config, value) and read_patch() == raw)
            source.verify_written(output / 'source', result)
            named = source.directory(output)
            try: source.require(parent.seventh.parent.identity(named) == parent.seventh.parent.identity(root))
            finally: os.close(named)
            witness(); source.tick()
            writer = os.open('source-receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root)
            with os.fdopen(writer, 'wb') as stream:
                stream.write(source.encoded(receipt)); stream.flush(); os.fchmod(stream.fileno(), 0o444); os.fsync(stream.fileno())
            os.fsync(root); source.tick()
        # A failed terminal N5 witness leaves an explicitly unqualified 0700
        # partial output; verify_output requires the successful 0555 boundary.
        source.tick(); os.fchmod(root, 0o555)
        return receipt
    finally:
        if root is not None: os.close(root)
        source.DEADLINE = None

def main():
    source.require(len(sys.argv) == 1 and os.environ.get('TEST_TIMEOUT') and os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR'))
    output = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True)
    produce(output / 'native-source-acquisition-source', min(840, int(os.environ['TEST_TIMEOUT']) - 60))
    print('Ninth source composed; SDK schema compiler native acquisition and provider proof unqualified')

if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, IndexError):
        print('native acquisition source refused at ' + (PHASE if PHASE in PHASES else 'input'), file=sys.stderr)
        raise SystemExit(1) from None
