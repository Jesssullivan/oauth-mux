"""Bazel-invoked structural catalogue; no SDK/native qualification.

PRIVATE DRAFT. A complete current-origin catalogue is published BUILD last.
The consuming original-SDK reader authenticates all declared bytes and NARs.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

# repository_ctx copies these exact declared source files into one owned helper
# directory. Isolated Python ignores ambient PYTHONPATH and user/site packages.
sys.path.insert(0, str(Path(__file__).parent))
import codex_original_sdk_inputs as inputs

core, sdk = inputs.carrier, inputs.sdk
PLAN = '.original-sdk-plan.json'
STAGE = '.original-sdk-stage'
MODE = inputs.MODE
FIELDS = inputs.CONTEXT_FIELDS


def envelope(env):
    value = {name: env.get('OMUX_NATIVE_FILE_WRITER_MODELS_' + name) for name in FIELDS}
    inputs.validate_context(value)
    entry, until = int(value['ENTRY_NS']), int(value['DEADLINE_NS'])
    core.need(until - entry == 1200*10**9 and time.monotonic_ns() >= entry, 'declaration-original-clock')
    core.need(re.fullmatch(r'(?:/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005|'
        r'/home/jess/\.local/state/omux-execution-20261005)/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',
        value['EPOCH']) is not None and re.fullmatch(r'[0-9a-f]{40}', value['SOURCE_COMMIT']) is not None,
        'declaration-epoch-source')
    core.digest(value['GRAPH_SHA256'])
    clock = core.Clock((entry + 600*10**9)/10**9)
    clock.until_ns = entry + 600*10**9
    clock.tick()
    return value, clock


def catalogue(clock, stack, context):
    """Read only the pinned recipe; remaining regular objects are stat-only."""
    actual = inputs.validate_context(context)
    core.need(clock.until_ns == int(actual['ENTRY_NS']) + 600*10**9
              and clock.deadline == clock.until_ns/10**9, 'catalogue-context-cutoff')
    roots = {'sdk': stack.enter_context(core.Root(inputs.ORIGIN, clock)),
             'jdk': stack.enter_context(core.Root(sdk.JDK, clock, origin_jdk=True))}
    raw = core.read(roots['sdk'], 'receipt.json', core.MAX_METADATA, inputs.ORIGIN_PIN)
    receipt = core.decode(raw)
    fd, info = roots['sdk'].open('receipt.json')
    os.close(fd)
    modes = {}
    for name in sdk.GRAPH:
        clock.tick()
        fd, row = roots['sdk'].open('graph/' + name)
        os.close(fd)
        modes[name] = stat.S_IMODE(row[4])
    entries = core.expected_entries(receipt, raw, clock, stat.S_IMODE(info[4]), modes)
    for (role, path), row in entries.items():
        clock.tick()
        if row['kind'] == 'file' and 'size' not in row:
            # Graph receipt pins content but not size. A bounded physical size
            # here is structural; actual full SHA+size is checked by the action.
            fd, witness = roots[role].open(path)
            os.close(fd)
            core.need(0 <= witness[6] <= sdk.MAX_FILE, 'declaration-file-size')
            row['size'] = witness[6]
    witnesses = core._fresh_namespace(roots, entries, clock)
    regular = []
    for role, path in sorted(entries):
        clock.tick()
        row = entries[(role, path)]
        if row['kind'] == 'file':
            target = str((inputs.ORIGIN if role == 'sdk' else Path(sdk.JDK)) / path)
            regular.append({'role': role, 'path': path, 'source_path': target,
                            'alias': 'input-files/' + str(len(regular)),
                            'sha256': row['sha256'], 'size': row['size'], 'mode': row['mode']})
    document = {'kind': inputs.KIND, 'origin_root': str(inputs.ORIGIN),
                'origin_receipt_sha256': inputs.ORIGIN_PIN, 'jdk_root': sdk.JDK,
                'entries': [{'role': role, 'path': path, **row} for (role, path), row in sorted(entries.items())],
                'regular_inputs': regular, 'context': actual}
    value = {'document': document, 'witnesses': [[role, path, witness]
               for (role, path), witness in sorted(witnesses.items())]}
    core.need(len(core.encoded(value)) <= core.MAX_METADATA, 'declaration-metadata-bound')
    for root in roots.values():
        root.check()
    return value


def build(document):
    files = [row['alias'] for row in document['regular_inputs']] + [inputs.MANIFEST]
    return '\n'.join(['package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(repr(files)), 'filegroup(name = "inputs", srcs = {})'.format(repr(files)), ''])


class Publication:
    """Owned outputs only; stat-identity cleanup is not atomic compare-delete."""
    def __init__(self, directory, clock, event=lambda name: None):
        self.clock, self.event = clock, event
        self.path = core.absolute(directory)
        self.root = sdk.open_dir(self.path)
        self.stage = self.aliases = None
        self.records, self.alias_records, self.published = {}, {}, {}
        self.file_fds, self.cleanup_records = {}, {}
        self.accepted = False
        try:
            core.need(os.fstat(self.root).st_uid == os.getuid(), 'publication-owner')
            self.identity = core.identity(os.fstat(self.root), True)
            for name in (STAGE, 'input-files', inputs.MANIFEST, 'BUILD.bazel'):
                try:
                    os.stat(name, dir_fd=self.root, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise ValueError('original SDK declaration refused: output exists')
            os.mkdir(STAGE, 0o700, dir_fd=self.root)
            self.stage = os.open(STAGE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=self.root)
            self.stage_identity = core.identity(os.fstat(self.stage), True)
            self.check_root()
        except BaseException:
            self.close()
            raise

    def check_root(self):
        self.clock.tick()
        named = sdk.open_dir(self.path)
        try:
            core.need(core.identity(os.fstat(named), True) == self.identity ==
                      core.identity(os.fstat(self.root), True), 'publication-named-root')
        finally:
            os.close(named)

    def file(self, name, raw):
        self.check_root()
        core.need(name in (inputs.MANIFEST, 'BUILD.bazel') and name not in self.records
                  and len(self.file_fds) < 2 and len(raw) <= core.MAX_METADATA, 'publication-file-bound')
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.stage)
        try:
            core.write_all(fd, raw, self.clock)
            os.fchmod(fd, 0o444)
            os.fsync(fd)
            self.records[name] = core.identity(os.fstat(fd))
            self.cleanup_records[name] = self.records[name]
            # Enroll the bounded readonly owner before any fallible identity IO.
            held = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                           dir_fd=self.stage)
            self.file_fds[name] = held
            core.need(core.identity(os.fstat(held)) == self.records[name] == core.identity(
                os.stat(name, dir_fd=self.stage, follow_symlinks=False)), 'publication-writer-reader-join')
        finally:
            os.close(fd)

    def renamed_file(self, name, raw, before):
        """Authenticate this same held creator inode across the authorized move."""
        self.check_root()
        fd = self.file_fds[name]
        held = core.identity(os.fstat(fd))
        named = core.identity(os.stat(name, dir_fd=self.root, follow_symlinks=False))
        # Cleanup ownership is distinct from a content/readiness witness. It is
        # bound to the creator-held inode, never merely the new destination name.
        core.need(held[:4] == before[:4] and stat.S_ISREG(held[4]) and held[5] == 1
                  and named == held, 'publication-moved-file-owner')
        self.cleanup_records[name] = held
        # Only ctime can change at rename. Every other field remains exact.
        core.need(held[:8] == before[:8], 'publication-moved-file-immutable')
        os.lseek(fd, 0, os.SEEK_SET)
        total, digest = 0, hashlib.sha256()
        while True:
            self.clock.tick()
            block = os.read(fd, 65536)
            if not block:
                break
            total += len(block)
            core.need(total <= len(raw), 'publication-moved-file-growth')
            digest.update(block)
        core.need(total == len(raw) and digest.hexdigest() == core.sha(raw)
                  and core.identity(os.fstat(fd)) == held == core.identity(
                  os.stat(name, dir_fd=self.root, follow_symlinks=False)),
                  'publication-moved-file-bytes-name-held')
        # Advance authority only after complete actual-byte and full-nine joins.
        self.records[name] = held

    def aliases_readback(self, parent):
        self.check_root()
        core.need(core.identity(os.fstat(self.aliases), True) == self.alias_identity ==
                  core.identity(os.stat('input-files', dir_fd=parent, follow_symlinks=False), True),
                  'publication-named-alias-parent')
        core.names(self.aliases, set(self.alias_records), self.clock)
        for name, (target, witness) in self.alias_records.items():
            self.clock.tick()
            before = os.stat(name, dir_fd=self.aliases, follow_symlinks=False)
            core.need(stat.S_ISLNK(before.st_mode) and core.identity(before) == witness
                      and os.readlink(name, dir_fd=self.aliases) == target
                      and core.identity(os.stat(name, dir_fd=self.aliases, follow_symlinks=False)) == witness,
                      'publication-alias-readback')

    def publish(self, document):
        self.check_root()
        os.mkdir('input-files', 0o700, dir_fd=self.stage)
        self.aliases = os.open('input-files', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=self.stage)
        self.alias_identity = core.identity(os.fstat(self.aliases), True)
        for index, row in enumerate(document['regular_inputs']):
            self.clock.tick()
            name, target = str(index), row['source_path']
            core.need(row['alias'] == 'input-files/' + name, 'publication-alias-order')
            os.symlink(target, name, dir_fd=self.aliases)
            self.alias_records[name] = (target, core.identity(
                os.stat(name, dir_fd=self.aliases, follow_symlinks=False)))
        # Keep this owned private directory writable until its parent changes.
        # Linux cross-parent directory rename requires write access to update
        # '..'. The published alias directory is sealed before any event/BUILD.
        self.alias_identity = core.identity(os.fstat(self.aliases), True)
        os.fsync(self.aliases)
        self.aliases_readback(self.stage)
        raws = {inputs.MANIFEST: core.encoded(document),
                'BUILD.bazel': build(document).encode('utf-8')}
        for name, raw in raws.items():
            self.file(name, raw)
        os.fsync(self.stage)
        # Publish aliases and metadata first. BUILD is the last visible target.
        for name in ('input-files', inputs.MANIFEST, 'BUILD.bazel'):
            self.check_root()
            witness = self.alias_identity if name == 'input-files' else self.records[name]
            core.need((core.identity(os.stat(name, dir_fd=self.stage, follow_symlinks=False), True)
                      if name == 'input-files' else core.identity(os.stat(name, dir_fd=self.stage, follow_symlinks=False)))
                      == witness, 'publication-stage-name')
            try:
                os.stat(name, dir_fd=self.root, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('original SDK declaration refused: foreign output')
            if name != 'input-files':
                core.need(core.identity(os.fstat(self.file_fds[name])) == witness,
                          'publication-staged-file-held')
            os.rename(name, name, src_dir_fd=self.stage, dst_dir_fd=self.root)
            if name == 'input-files':
                # Join the moved owned directory before changing its held mode.
                core.need(core.identity(os.fstat(self.aliases), True) == witness == core.identity(
                    os.stat(name, dir_fd=self.root, follow_symlinks=False), True),
                    'publication-moved-alias-parent')
                os.fchmod(self.aliases, 0o555)
                self.alias_identity = core.identity(os.fstat(self.aliases), True)
                core.need(self.alias_identity == core.identity(os.stat(name, dir_fd=self.root,
                    follow_symlinks=False), True), 'publication-sealed-alias-parent')
                os.fsync(self.aliases)
                witness = self.alias_identity
            else:
                self.renamed_file(name, raws[name], witness)
                witness = self.records[name]
            self.published[name] = witness
            os.fsync(self.root)
            self.event('ready-published' if name == 'BUILD.bazel' else 'metadata-published')
            self.aliases_readback(self.root)
        self.final(document)

    def final(self, document):
        self.aliases_readback(self.root)
        for name, raw in ((inputs.MANIFEST, core.encoded(document)),
                          ('BUILD.bazel', build(document).encode('utf-8'))):
            self.check_root()
            core.need(core.identity(os.fstat(self.file_fds[name])) == self.records[name],
                      'publication-final-continuous-file-held')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.root)
            try:
                need_size, parts, count = len(raw), [], 0
                core.need(core.identity(os.fstat(fd)) == self.records[name], 'publication-file-held')
                while True:
                    self.clock.tick()
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    count += len(chunk)
                    core.need(count <= need_size, 'publication-file-growth')
                    parts.append(chunk)
                core.need(b''.join(parts) == raw and core.identity(os.fstat(fd)) == self.records[name]
                          == core.identity(os.stat(name, dir_fd=self.root, follow_symlinks=False)),
                          'publication-file-readback')
            finally:
                os.close(fd)
        self.aliases_readback(self.root)

    def close(self, rollback=True):
        error = None
        if rollback and not self.accepted and self.stage is not None:
            try:
                self.rollback()
            except BaseException as exc:
                error = exc
        if not rollback or self.accepted:
            for name, fd in self.file_fds.items():
                try:
                    current = core.identity(os.fstat(fd))
                    before = self.records[name]
                    owned_name = None
                    for parent in (self.root, self.stage):
                        if parent is None:
                            continue
                        try:
                            if core.identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == current:
                                owned_name = parent
                                break
                        except FileNotFoundError:
                            pass
                    if current[:4] == before[:4] and stat.S_ISREG(current[4]) and current[5] == 1 \
                            and owned_name is not None:
                        self.cleanup_records[name] = current
                    core.need(current == before and owned_name == self.root,
                              'publication-terminal-file-held-name')
                except BaseException as exc:
                    if error is None:
                        error = exc
        owned = tuple(self.file_fds.values()) + (self.aliases, self.stage, self.root)
        self.file_fds = {}
        self.aliases = self.stage = self.root = None
        for fd in owned:
            if fd is None:
                continue
            try:
                os.close(fd)
            except BaseException as exc:
                if error is None:
                    error = exc
        if error is not None:
            raise error

    def cleanup_closed(self):
        """Reopen only proven owned output names after terminal report failure.

        Never reopen/delete SDK/JDK origin paths, or retry ambiguous numeric FDs.
        Foreign replacements are retained. Original outer ownership cleanup is
        the ultimate bound for interrupted/uncompleted cleanup.
        """
        core.need(self.root is None and self.stage is None and self.aliases is None and not self.file_fds,
                  'cleanup-resources-detached')
        # Enroll the newly returned descriptor before any fallible identity IO.
        # Identity refusal still precedes every filesystem cleanup mutation.
        self.root = sdk.open_dir(self.path)
        root = self.root
        try:
            core.need(core.identity(os.fstat(root), True) == self.identity,
                      'foreign-cleanup-root')
            try:
                selected = os.stat(STAGE, dir_fd=root, follow_symlinks=False)
                if stat.S_ISDIR(selected.st_mode) and core.identity(selected, True) == self.stage_identity:
                    self.stage = os.open(STAGE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                         dir_fd=root)
                    core.need(core.identity(os.fstat(self.stage), True) == self.stage_identity,
                              'cleanup-stage-open-race')
            except FileNotFoundError:
                pass
            if hasattr(self, 'alias_identity'):
                for parent in (root, self.stage):
                    if parent is None:
                        continue
                    try:
                        selected = os.stat('input-files', dir_fd=parent, follow_symlinks=False)
                        if stat.S_ISDIR(selected.st_mode) and core.identity(selected, True) == self.alias_identity:
                            self.aliases = os.open('input-files', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                                   dir_fd=parent)
                            core.need(core.identity(os.fstat(self.aliases), True) == self.alias_identity,
                                      'cleanup-alias-open-race')
                            break
                    except FileNotFoundError:
                        pass
            self.rollback()
        finally:
            self.close(rollback=False)

    def rollback(self):
        """No public-origin deletion; retain all foreign named replacements."""
        # Refusal cleanup does not consult an expired proof clock. It checks
        # held/name ownership instead; original outer guard bounds interruption.
        if self.aliases is not None:
            old = core.identity(os.fstat(self.aliases), True)
            core.need(old == self.alias_identity, 'cleanup-owned-alias-handle')
            os.fchmod(self.aliases, 0o700)
            changed = core.identity(os.fstat(self.aliases), True)
            for name, (target, witness) in self.alias_records.items():
                try:
                    info = os.stat(name, dir_fd=self.aliases, follow_symlinks=False)
                    if core.identity(info) == witness and stat.S_ISLNK(info.st_mode) and \
                            os.readlink(name, dir_fd=self.aliases) == target:
                        os.unlink(name, dir_fd=self.aliases)
                except FileNotFoundError:
                    pass
            for parent in (self.root, self.stage):
                if parent is None:
                    continue
                try:
                    info = os.stat('input-files', dir_fd=parent, follow_symlinks=False)
                    if core.identity(info, True) == changed and not os.listdir(self.aliases):
                        os.rmdir('input-files', dir_fd=parent)
                except FileNotFoundError:
                    pass
        for name, witness in self.cleanup_records.items():
            # While the creator FD is live, a mutated owned object may still be
            # deleted; a replacement inode never becomes a cleanup capability.
            fd = self.file_fds.get(name)
            if fd is not None:
                current = core.identity(os.fstat(fd))
                if current[:4] != witness[:4] or not stat.S_ISREG(current[4]) or current[5] != 1:
                    continue
                witness = current
            for parent in (self.root, self.stage):
                if parent is None:
                    continue
                try:
                    if core.identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == witness:
                        os.unlink(name, dir_fd=parent)
                except FileNotFoundError:
                    pass
        try:
            if self.stage is not None and core.identity(os.stat(STAGE, dir_fd=self.root, follow_symlinks=False), True) \
                    == self.stage_identity and not os.listdir(self.stage):
                os.rmdir(STAGE, dir_fd=self.root)
        except FileNotFoundError:
            pass


def main():
    sdk.require_utf8_filesystem()
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', required=True, choices=('plan', 'materialize'))
    parser.add_argument('--directory', required=True)
    parser.add_argument('--plan-sha256')
    args = parser.parse_args()
    context, clock = envelope(os.environ)
    directory = core.absolute(args.directory)
    publication = None
    try:
        with ExitStack() as stack:
            current = catalogue(clock, stack, context)
            raw = core.encoded(current)
            root = sdk.open_dir(directory)
            stack.callback(os.close, root)
            if args.phase == 'plan':
                fd = os.open(PLAN, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=root)
                try:
                    core.write_all(fd, raw, clock)
                    os.fchmod(fd, 0o444)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(root)
                report = {'kind': inputs.KIND, 'plan_sha256': core.sha(raw),
                          'regular_inputs': [row['source_path'] for row in current['document']['regular_inputs']]}
            else:
                core.digest(args.plan_sha256)
                fd = os.open(PLAN, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root)
                try:
                    selected = core.identity(os.fstat(fd))
                    core.need(stat.S_ISREG(selected[4]) and selected[5] == 1 and selected[6] <= core.MAX_METADATA,
                              'plan-regular-bound')
                    h, count = hashlib.sha256(), 0
                    while True:
                        clock.tick()
                        block = os.read(fd, 65536)
                        if not block:
                            break
                        count += len(block)
                        core.need(count <= core.MAX_METADATA, 'plan-size-bound')
                        h.update(block)
                    core.need(h.hexdigest() == args.plan_sha256 == core.sha(raw)
                              and core.identity(os.fstat(fd)) == selected == core.identity(
                              os.stat(PLAN, dir_fd=root, follow_symlinks=False)), 'fresh-plan-identity-content')
                finally:
                    os.close(fd)
                publication = Publication(directory, clock)
                stack.callback(publication.close, rollback=False)
                publication.publish(current['document'])
                # Complete current-origin structural fence follows publication IO.
                again = catalogue(clock, stack, context)
                core.need(again == current,
                          'origin-final-publication-witness')
                publication.final(current['document'])
                report = {'kind': inputs.KIND, 'plan_sha256': args.plan_sha256,
                          'regular_count': len(current['document']['regular_inputs']), 'published': True}
        # All registered closures complete before the original cutoff check.
        # A flushed JSON report is not acceptance if its final check refuses.
        clock.tick()
        sys.stdout.write(core.encoded(report).decode('ascii') + '\n')
        sys.stdout.flush()
        clock.tick()
        if publication is not None:
            publication.accepted = True
    except BaseException:
        if publication is not None:
            publication.cleanup_closed()
        raise

if __name__ == '__main__':
    main()
