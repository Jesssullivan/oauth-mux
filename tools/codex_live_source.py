"""Prepare a fresh, receipt-bound public native candidate without subprocesses.

Invoke only as the declared Bazel producer under the execution guard. Never
modify the prepared parent or the frozen native output base. Diagnostic output
is categorical; source text and native values never enter diagnostics.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time

BASE = Path('/srv/fast-local/jess/state/codex/omux-codex-owner-development-20261004')
BASE_RECEIPT = 'verify-prepared-receipt-a8f6d68c30bb4099bb524ed55817d804.json'
BASE_RECEIPT_SHA = 'e3c6d45bc93119ddf1da8bee6e02de3c7c3a3bbe52bb6d2664eb4b7b3d7b5273'
BASE_INVENTORY = '3400115fae8ef204f2ce085880b40887bcb14e2080236ba87a34be9b14fe7d3b'
COMMIT = '00c972ed5d6ff6499317fd41b7f23605b8e6850d'
PATCH_DIRECTORY = Path('/srv/fast-local/jess/git/oauth-mux/docs/agent-notes')
PATCHES = ('2026-10-07-native-text-portability.UNAPPLIED.native.patch',
           '2026-10-07-live-handoff-boundary.UNAPPLIED.native.patch',
           '2026-10-07-native-enrollment-action.UNAPPLIED.native.patch')
ALLOWED = frozenset(('codex-rs/core/src/broker_text_context.rs',
    'codex-rs/core/src/broker_text_context_tests.rs',
    'codex-rs/core/src/lib.rs', 'codex-rs/config/src/config_toml.rs',
    'codex-rs/core/src/native_owner_startup_tests.rs', 'codex-rs/core/src/client_common.rs',
    'codex-rs/core/src/compact_remote_v2_attempt.rs', 'codex-rs/core/src/session/turn.rs',
    'codex-rs/core/src/client.rs', 'codex-rs/core/src/auth_broker.rs',
    'codex-rs/core/src/client_tests.rs', 'codex-rs/core/BUILD.bazel', 'codex-rs/login/src/server.rs',
    'codex-rs/login/src/server_bind_tests.rs'))
NEW = frozenset(('codex-rs/core/src/broker_text_context.rs',
                 'codex-rs/core/src/broker_text_context_tests.rs',
                 'codex-rs/login/src/server_bind_tests.rs'))
GRAPH = ('.bazelversion', '.bazelrc', 'MODULE.bazel', 'MODULE.bazel.lock', 'codex-rs/Cargo.lock',
         'codex-rs/Cargo.toml', 'codex-rs/core/Cargo.toml', 'codex-rs/core/BUILD.bazel',
         'codex-rs/config/BUILD.bazel', 'codex-rs/cli/BUILD.bazel',
         'codex-rs/login/BUILD.bazel', 'defs.bzl')
MAX_SOURCE = 512 * 1024 * 1024
MAX_METADATA = 8 * 1024 * 1024
MAX_PATCH = 4 * 1024 * 1024
HASH = re.compile(r'[0-9a-f]{64}')
DEADLINE = None
# Only fixed public categories may enter diagnostics. Never format exceptions,
# source, paths, patch contents, or native values into the refusal message.
PHASE = 'baseline'
PHASES = frozenset(('baseline', 'patch/1', 'patch/2', 'patch/3', 'dependency', 'output'))


def require(value):
    if not value:
        raise ValueError('native source contract refused')


def tick():
    require(DEADLINE is None or time.monotonic() < DEADLINE)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def canonical(value):
    return json.dumps(value, sort_keys=True).encode()


def safe_name(value):
    require(isinstance(value, str) and value and len(value) <= 4096)
    require(not value.startswith('/') and '\\' not in value
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    require(all(part not in ('', '.', '..') for part in value.split('/')))


def directory(path):
    require(path.is_absolute() and '..' not in path.parts)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            tick()
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            require(info.st_uid in (0, os.getuid()) and
                    (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX))
        info = os.fstat(fd)
        require(info.st_uid == os.getuid() and not info.st_mode & 0o022)
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(fd, name, limit):
    tick()
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        before = os.fstat(child)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and not before.st_mode & 0o022 and 0 <= before.st_size <= limit)
        chunks, count = [], 0
        while True:
            tick()
            value = os.read(child, min(1024 * 1024, limit + 1 - count))
            if not value:
                break
            count += len(value)
            require(count <= limit)
            chunks.append(value)
        after = os.fstat(child)
        require(count == before.st_size and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        return b''.join(chunks), stat.S_IMODE(before.st_mode)
    finally:
        os.close(child)


def baseline():
    fd = directory(BASE)
    try:
        raw, _ = read(fd, BASE_RECEIPT, MAX_METADATA)
    finally:
        os.close(fd)
    require(sha(raw) == BASE_RECEIPT_SHA)
    receipt = json.loads(raw, object_pairs_hook=unique)
    require(receipt['phase'] == 'verify-prepared' and receipt['commit'] == COMMIT
            and receipt['complete_inventory_sha256'] == BASE_INVENTORY)
    inventory, links = receipt['files'], receipt['generated_output_links']
    require(isinstance(inventory, dict) and len(inventory) == receipt['tracked_files'] == 8546)
    require(sha(canonical(inventory)) == BASE_INVENTORY)
    require(set(links) == {'bazel-bin', 'bazel-out', 'bazel-source', 'bazel-testlogs'})
    source_fd = directory(BASE / 'source')
    observed, total = {}, 0
    def walk(fd, prefix='', depth=0):
        nonlocal total
        require(depth <= 64)
        for name in sorted(os.listdir(fd)):
            tick()
            path = prefix + name
            safe_name(path)
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(info.st_uid == os.getuid())
            if path in links:
                require(stat.S_ISLNK(info.st_mode) and os.readlink(name, dir_fd=fd) == links[path])
            elif stat.S_ISDIR(info.st_mode):
                require(not info.st_mode & 0o022)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    walk(child, path + '/', depth + 1)
                finally:
                    os.close(child)
            else:
                require(path in inventory)
                if stat.S_ISLNK(info.st_mode):
                    mode, value = '120000', os.readlink(name, dir_fd=fd).encode()
                else:
                    value, physical = read(fd, name, MAX_SOURCE - total)
                    require(physical in (0o644, 0o755))
                    mode = '100755' if physical == 0o755 else '100644'
                total += len(value)
                require(total <= MAX_SOURCE and len(observed) < 50000)
                require(inventory[path] == {'mode': mode, 'sha256': sha(value)})
                observed[path] = (mode, value)
    try:
        walk(source_fd)
    finally:
        os.close(source_fd)
    require(set(observed) == set(inventory) and total == receipt['source_bytes'])
    return observed


def apply_native_patch(files, raw):
    """Strict exact-context apply_patch subset: add/update, no fuzzy application."""
    require(len(raw) <= MAX_PATCH and raw.endswith(b'\n'))
    lines = raw.decode('utf-8').splitlines(keepends=True)
    require(lines[0] == '*** Begin Patch\n' and lines[-1] == '*** End Patch\n')
    result, changed, index = dict(files), set(), 1
    while index < len(lines) - 1:
        header = lines[index]
        match = re.fullmatch(r'\*\*\* (Add|Update) File: ([^\n]+)\n', header)
        require(match is not None)
        kind, name = match.groups()
        safe_name(name)
        require(name in ALLOWED and name not in changed)
        changed.add(name)
        index += 1
        body = []
        while index < len(lines) - 1 and not lines[index].startswith('*** '):
            body.append(lines[index])
            index += 1
        if kind == 'Add':
            require(name in NEW and name not in result and body
                    and all(line.startswith('+') for line in body))
            result[name] = ('100644', ''.join(line[1:] for line in body).encode())
            continue
        require(name not in NEW and name in result and result[name][0] == '100644')
        source = result[name][1].decode('utf-8').splitlines(keepends=True)
        cursor, body_index = 0, 0
        while body_index < len(body):
            tick()
            require(body[body_index].startswith('@@') and body[body_index].endswith('\n'))
            body_index += 1
            before, after = [], []
            while body_index < len(body) and not body[body_index].startswith('@@'):
                line = body[body_index]
                require(line[:1] in (' ', '+', '-'))
                if line[:1] in (' ', '-'):
                    before.append(line[1:])
                if line[:1] in (' ', '+'):
                    after.append(line[1:])
                body_index += 1
            require(before)
            matches = [offset for offset in range(cursor, len(source) - len(before) + 1)
                       if source[offset:offset + len(before)] == before]
            require(len(matches) == 1)
            offset = matches[0]
            source[offset:offset + len(before)] = after
            cursor = offset + len(after)
        result[name] = (result[name][0], ''.join(source).encode())
    require(changed and index == len(lines) - 1)
    return result, changed


def declare_pinned_sha2(files):
    """Verify the reviewed native patch's exact retained crate hub declaration.

    Native compilation uses the explicit reviewed Bazel edge. The producer
    performs no additional graph rewrite and requires Cargo metadata unchanged.
    """
    name = 'codex-rs/core/BUILD.bazel'
    before = files[name][1]
    old = b'    deps_extra = [":native-peer-bridge"],\n'
    new = b'    deps_extra = [":native-peer-bridge", "@crates//:sha2-0.10.9"],\n'
    require(b'sha2 = { workspace = true }\n' not in files['codex-rs/core/Cargo.toml'][1])
    require(before.count(new) == 1 and old not in before)
    after = before
    result = dict(files)
    result[name] = (files[name][0], after)
    return result, {'path': name, 'dependency': '@crates//:sha2-0.10.9',
                    'before_sha256': sha(before), 'after_sha256': sha(after),
                    'origin': 'reviewed-text-patch-no-producer-graph-rewrite'}


def declare_config_schema(files):
    """Append one fixed declared generator action to an exact baseline BUILD."""
    name = 'bazel/schema/BUILD.bazel'
    mode, before = files[name]
    require(mode == '100644' and sha(before) ==
        '9e047e20da76b99608595a8abfb23b5e8633c5ba454f2de548b8e70744c72df6')
    addition = b'''
# Maintained candidate: generate changed config schema as a declared action.
genrule(
    name = "native-config-schema",
    tools = ["//codex-rs/config-schema:codex-write-config-schema"],
    outs = ["native-config.schema.json"],
    cmd = "$(location //codex-rs/config-schema:codex-write-config-schema) --out \\"$@\\"",
    tags = ["manual"],
)
'''
    result = dict(files)
    result[name] = (mode, before + addition)
    return result, {'path': name,
        'target': '//bazel/schema:native-config-schema',
        'before_sha256': sha(before), 'after_sha256': sha(before + addition),
        'origin': 'fixed-reviewed-maintained-source-generator-overlay'}
def verify_written(source, files):
    """Read every materialized byte through nofollow directory descriptors."""
    fd = directory(source)
    observed = {}
    expected_directories = set()
    for name in files:
        parts = name.split('/')
        expected_directories.update('/'.join(parts[:index]) for index in range(1, len(parts)))
    directories = set()
    def walk(parent, prefix='', depth=0):
        require(depth <= 64 and stat.S_IMODE(os.fstat(parent).st_mode) == 0o555)
        for name in sorted(os.listdir(parent)):
            tick()
            path = prefix + name
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(info.st_uid == os.getuid())
            if stat.S_ISDIR(info.st_mode):
                directories.add(path)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    walk(child, path + '/', depth + 1)
                finally:
                    os.close(child)
            elif stat.S_ISLNK(info.st_mode):
                observed[path] = ('120000', os.readlink(name, dir_fd=parent).encode())
            else:
                require(path in files and files[path][0] in ('100644', '100755'))
                value, physical = read(parent, name, MAX_SOURCE)
                require(physical == 0o555)
                observed[path] = (files[path][0], value)
    try:
        walk(fd)
        require(observed == files and directories == expected_directories)
    finally:
        os.close(fd)


def write_source(root, files):
    parent = directory(root.parent)
    root_fd = None
    try:
        os.mkdir(root.name, 0o700, dir_fd=parent)
        root_fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        witness = os.fstat(root_fd)
        os.mkdir('source', 0o700, dir_fd=root_fd)
        source_fd = os.open('source', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            for name, (mode, value) in sorted(files.items()):
                tick()
                safe_name(name)
                fd = os.dup(source_fd)
                try:
                    for part in name.split('/')[:-1]:
                        try:
                            os.mkdir(part, 0o700, dir_fd=fd)
                        except FileExistsError:
                            pass
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        os.close(fd)
                        fd = child
                    if mode == '120000':
                        target = value.decode()
                        require(not PurePosixPath(target).is_absolute() and '\x00' not in target)
                        normalized = os.path.normpath(str(PurePosixPath(name).parent / target))
                        require(normalized != '..' and not normalized.startswith('../'))
                        os.symlink(target, name.split('/')[-1], dir_fd=fd)
                    else:
                        child = os.open(name.split('/')[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                        0o600, dir_fd=fd)
                        with os.fdopen(child, 'wb') as stream:
                            stream.write(value)
                            stream.flush()
                            os.fchmod(stream.fileno(), 0o555)
                            os.fsync(stream.fileno())
                finally:
                    os.close(fd)
            for folder, _, _ in os.walk(root / 'source', topdown=False, followlinks=False):
                tick()
                os.chmod(folder, 0o555, follow_symlinks=False)
            os.fsync(source_fd)
        finally:
            os.close(source_fd)
        visible = os.stat(root.name, dir_fd=parent, follow_symlinks=False)
        require((visible.st_dev, visible.st_ino) == (witness.st_dev, witness.st_ino))
        verify_written(root / 'source', files)
        return root_fd
    except BaseException:
        if root_fd is not None:
            os.close(root_fd)
        raise
    finally:
        os.close(parent)


def produce(output, patch_pins, seconds):
    global DEADLINE, PHASE
    PHASE = 'baseline'
    DEADLINE = time.monotonic() + seconds
    require(1 <= seconds <= 1100 and len(patch_pins) == len(PATCHES)
            and all(HASH.fullmatch(value) for value in patch_pins))
    files = baseline()
    baseline_graph = {name: {'sha256': sha(files[name][1])} for name in GRAPH}
    patch_fd = directory(PATCH_DIRECTORY)
    changes = []
    try:
        for index, (name, pin) in enumerate(zip(PATCHES, patch_pins), 1):
            PHASE = ('patch/1', 'patch/2', 'patch/3')[index - 1]
            raw, _ = read(patch_fd, name, MAX_PATCH)
            require(sha(raw) == pin)
            files, changed = apply_native_patch(files, raw)
            changes.append({'patch_sha256': pin, 'paths': sorted(changed)})
    finally:
        os.close(patch_fd)
    PHASE = 'dependency'
    files, native_declaration = declare_pinned_sha2(files)
    files, schema_declaration = declare_config_schema(files)
    require(all({'sha256': sha(files[name][1])} == baseline_graph[name]
                for name in GRAPH if name != 'codex-rs/core/BUILD.bazel'))
    require(set(NEW) <= set(files) and sum(len(value) for _, value in files.values()) <= MAX_SOURCE)
    inventory = {name: {'mode': mode, 'sha256': sha(value)} for name, (mode, value) in files.items()}
    receipt = {'schema_version': 1, 'status': 'verified-fresh-native-candidate',
        'commit': COMMIT, 'baseline_receipt_sha256': BASE_RECEIPT_SHA,
        'baseline_inventory_sha256': BASE_INVENTORY, 'patch_sha256': list(patch_pins),
        'patches': changes, 'source_inventory': inventory, 'inventory_sha256': sha(canonical(inventory)),
        'native_build_declaration': native_declaration,
        'native_schema_declaration': schema_declaration,
        'graph_files': {name: {'sha256': sha(files[name][1])} for name in GRAPH},
        'baseline_graph_files': baseline_graph,
        'tracked_files': len(files), 'source_bytes': sum(len(value) for _, value in files.values()),
        'physical_mode_policy': 'bazel-retained-export-all-regular-and-directories-0555-v1',
        'graph_resolution': 'retained-crate-hub-with-explicit-pinned-native-sha2-dependency; offline-analysis-unrun',
        'native_support': False, 'native_compile_passed': False, 'provider_evaluation': False}
    PHASE = 'output'
    fd = write_source(output, files)
    try:
        tick()
        child = os.open('source-receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600, dir_fd=fd)
        with os.fdopen(child, 'wb') as stream:
            stream.write(encoded(receipt))
            stream.flush()
            os.fchmod(stream.fileno(), 0o444)
            os.fsync(stream.fileno())
        os.fsync(fd)
        os.fchmod(fd, 0o555)
    finally:
        os.close(fd)
    # Root independently qualifies all produced bytes through the native guard.
    return receipt


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--patch-sha256', action='append', required=True)
    parser.add_argument('--output-directory', type=Path)
    args = parser.parse_args()
    require(os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR') and os.environ.get('TEST_TIMEOUT'))
    seconds = min(1100, int(os.environ['TEST_TIMEOUT']) - 60)
    root = args.output_directory or Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True) / 'codex-live-source'
    require(root.is_absolute() and '..' not in root.parts and root.name not in ('', '.', '..'))
    produce(root, args.patch_sha256, seconds)
    print('native source producer completed; compilation unrun')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError):
        stage = PHASE if PHASE in PHASES else 'baseline'
        print('native source producer refused at ' + stage, file=sys.stderr)
        raise SystemExit(1) from None
