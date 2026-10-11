"""Bazel repository entrypoint for the separately qualified SDK carrier.

The caller supplies the original integer guardian envelope. Sealing reuses
its original cutoff; no phase acquires a fresh allowance. This entrypoint never
selects an origin, reads a legacy repository, or qualifies a native runtime.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path

import codex_native_sdk_carrier as carrier

ORIGIN = '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/e5b17d7e-d19d-4cb2-be22-41a86b98af7b/sdk-private/sdk-export'
ORIGIN_SHA = '1aa4c87d689f464e576a5c6a51b4c6350a8f0346f6b94299856d01db5147d4f0'
JDK = '/nix/store/siln89j8b6k5wdzw4asl69bma0k96nns-openjdk-headless-21.0.10+7'
MODE = 'native-sdk-carrier-seal-reserved'
FILES = ('payload.bin', 'manifest.json', 'origin-receipt.json', 'receipt.json')


def need(value, category):
    if not value:
        raise ValueError('SDK carrier declaration refused: ' + category)


def digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def original_cutoff(entry_ns, deadline_ns, *, now_ns=None):
    need(type(entry_ns) is int and type(deadline_ns) is int and entry_ns > 0
         and deadline_ns - entry_ns == 1200 * 10**9, 'original-envelope')
    now_ns = time.monotonic_ns() if now_ns is None else now_ns
    cutoff_ns = deadline_ns - 30 * 10**9
    need(type(now_ns) is int and entry_ns <= now_ns < cutoff_ns, 'expired-envelope')
    return cutoff_ns / 10**9


def context(environ):
    entry = integer(environ.get('OMUX_SDK_CARRIER_ENTRY_NS', ''))
    deadline = integer(environ.get('OMUX_SDK_CARRIER_DEADLINE_NS', ''))
    value = {'mode': environ.get('OMUX_SDK_CARRIER_MODE'),
             'epoch': environ.get('OMUX_SDK_CARRIER_EPOCH'),
             'source_commit': environ.get('OMUX_SDK_CARRIER_SOURCE_COMMIT'),
             'graph_sha256': environ.get('OMUX_SDK_CARRIER_GRAPH_SHA256'),
             'entry_monotonic_ns': entry, 'deadline_monotonic_ns': deadline,
             'work_cutoff_monotonic_ns': deadline - 30 * 10**9}
    need(value['mode'] == MODE, 'guarded-seal-mode')
    cutoff = original_cutoff(entry, deadline)
    carrier.producer_binding(value, cutoff)
    return value, cutoff


def private_child(base, name, clock):
    base = Path(base)
    fd = carrier.sdk.open_dir(base)
    try:
        need(os.fstat(fd).st_uid == os.getuid(), 'owned-output-parent')
        os.mkdir(name, 0o700, dir_fd=fd)
        created = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISDIR(created.st_mode) and created.st_uid == os.getuid()
             and stat.S_IMODE(created.st_mode) == 0o700, 'created-private-child')
        root = carrier.Root(base / name, clock, sealed=False,
                            expected_identity=carrier.identity(created, True), owned=True)
        try:
            need(root.chain[-2][2] == carrier.identity(os.fstat(fd), True)
                 and carrier.identity(os.stat(name, dir_fd=fd, follow_symlinks=False), True)
                 == carrier.identity(created, True), 'named-private-child')
            root.check()
            os.fsync(fd)
        except BaseException:
            root.close()
            raise
        return root
    finally:
        os.close(fd)


def seal(directory, absolute_deadline, producer_context):
    # Carrier seal independently authenticates the entire origin, streams all
    # declared SDK/JDK bytes, and rechecks held/named custody before acceptance.
    receipt = carrier.seal(Path(ORIGIN), ORIGIN_SHA, Path(directory), absolute_deadline,
                           producer_context=producer_context)
    pin = carrier.sha(carrier.encoded(receipt))
    report = carrier.publication_report(Path(directory), pin, absolute_deadline)
    need(report['kind'] == 'omux-native-sdk-carrier-v1-publication', 'publication-kind')
    return {'kind': 'omux-native-sdk-carrier-declaration-result-v1',
            'entry_monotonic_ns': producer_context['entry_monotonic_ns'],
            'deadline_monotonic_ns': producer_context['deadline_monotonic_ns'],
            'origin_receipt_sha256': ORIGIN_SHA, 'carrier_receipt_sha256': pin,
            'files': report['files']}


class HeldLeaves:
    """Four live nofollow descriptors; no proof survives this qualification.

    Full binding is still required once on this same held Root. Repeated full
    byte equality preserves that binding's manifest/NAR/lineage proof; these
    descriptors authenticate publication custody, not an independent SDK.
    """
    def __init__(self, root):
        self.root, self.files = root, {}
        try:
            carrier.names(root.fd, set(carrier.FILES), root.clock)
            for name in carrier.FILES:
                fd, witness = root.open(name)
                self.files[name] = (fd, witness)
                limit = carrier.MAX_BYTES if name == 'payload.bin' else carrier.MAX_METADATA
                need(witness[6] <= limit and stat.S_IMODE(witness[4]) == 0o444,
                     'held-publication-size-mode')
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        self.root.check()
        carrier.names(self.root.fd, set(carrier.FILES), self.root.clock)
        for name, (fd, witness) in self.files.items():
            self.root.clock.tick()
            need(carrier.identity(os.fstat(fd)) == witness
                 and carrier.identity(os.stat(name, dir_fd=self.root.fd,
                                              follow_symlinks=False)) == witness,
                 'held-publication-custody')
        self.root.check()

    def readback(self):
        self.check()
        rows = []
        for name in carrier.FILES:
            fd, witness = self.files[name]
            os.lseek(fd, 0, os.SEEK_SET)
            digest, count = hashlib.sha256(), 0
            while True:
                self.root.clock.tick()
                block = os.read(fd, 65536)
                if not block:
                    break
                count += len(block)
                need(count <= witness[6], 'held-publication-byte-bound')
                digest.update(block)
            need(count == witness[6] and carrier.identity(os.fstat(fd)) == witness,
                 'held-publication-readback')
            rows.append({'name': name, 'sha256': digest.hexdigest(), 'size': count})
        self.check()
        return rows

    def close(self):
        for fd, _ in self.files.values():
            os.close(fd)
        self.files = {}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def qualify(receipt_leaf, outputs, producer_context, cutoff):
    clock = carrier.Clock(cutoff)
    selected = Path(receipt_leaf).resolve(strict=True)
    need(selected.name == 'receipt.json', 'declared-receipt-leaf')
    with carrier.Root(selected.parent, clock) as source, HeldLeaves(source) as held_source:
        raw = carrier.read(source, 'receipt.json', carrier.MAX_METADATA)
        pin = carrier.sha(raw)
        receipt, _, _, _ = carrier.binding(source, pin, clock)
        need(receipt['producer_context'] == producer_context and
             receipt['origin']['receipt_sha256'] == ORIGIN_SHA and
             receipt['origin']['root'] == ORIGIN, 'actual-acquisition-context')
        original_files = held_source.readback()
        expected_files = {
            'receipt.json': (pin, len(raw)),
            'origin-receipt.json': (receipt['origin']['receipt_sha256'], receipt['origin']['receipt_bytes']),
            'manifest.json': (receipt['manifest_sha256'], receipt['manifest_bytes']),
            'payload.bin': (receipt['payload_sha256'], receipt['payload_bytes'])}
        need(all((row['sha256'], row['size']) == expected_files[row['name']]
                 for row in original_files), 'held-binding-publication-join')
        with private_child(outputs, 'sdk-private', clock) as private:
            destination = carrier.Output(private.path / 'sdk-carrier', clock)
            retained_leaves = None
            try:
                for name in FILES:
                    held_source.check()
                    incoming, before = held_source.files[name]
                    os.lseek(incoming, 0, os.SEEK_SET)
                    outgoing = None
                    try:
                        outgoing = destination.create(name)
                        digest, count = hashlib.sha256(), 0
                        while True:
                            clock.tick()
                            block = os.read(incoming, 65536)
                            if not block:
                                break
                            count += len(block)
                            need(count <= before[6], 'retained-copy-size')
                            digest.update(block)
                            carrier.write_all(outgoing, block, clock)
                        need((digest.hexdigest(), count) == expected_files[name]
                             and carrier.identity(os.fstat(incoming)) == before,
                             'retained-copy-readback')
                        os.fsync(outgoing)
                        os.fchmod(outgoing, 0o444)
                        created = carrier.identity(os.fstat(outgoing))
                        need(stat.S_ISREG(created[4]) and created[5] == 1
                             and carrier.identity(os.stat(name, dir_fd=destination.root.fd,
                                                          follow_symlinks=False)) == created,
                             'retained-created-leaf-custody')
                        destination.materialized[name] = created
                        destination.root.leaves[name] = created
                    finally:
                        if outgoing is not None:
                            os.close(outgoing)
                held_source.check()
                destination.finish()
                # Fresh retained descriptors join the exclusive writer witnesses.
                # Actual full bytes must equal the already fully bound source;
                # no prior origin or NAR proof is accepted for different bytes.
                retained_leaves = HeldLeaves(destination.root)
                retained_files = retained_leaves.readback()
                need(retained_files == original_files, 'retained-full-byte-binding')
                program = {'kind': 'omux-native-sdk-carrier-producer-v1',
                           'producer': '//tools:codex_native_sdk_carrier_seal_producer',
                           'carrier_receipt_sha256': pin, 'origin_receipt_sha256': ORIGIN_SHA,
                           'producer_context': producer_context, 'files': retained_files,
                           'all_four_leaves_rechecked': True, 'sdk_execution_qualified': False,
                           'metadata_qualified': False, 'compiler_qualified': False,
                           'runtime_qualified': False}
                # This is the last accepted-program artifact. Failure retains
                # partial owned diagnostics without deleting foreign objects.
                private.check()
                out = os.open('native-sdk-carrier-producer.json',
                              os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=private.fd)
                try:
                    carrier.write_all(out, carrier.encoded(program), clock)
                    os.fsync(out)
                    os.fchmod(out, 0o444)
                    program_identity = carrier.identity(os.fstat(out))
                finally:
                    os.close(out)
                need(held_source.readback() == original_files,
                     'final-source-carrier-publication')
                need(retained_leaves.readback() == retained_files,
                     'final-retained-carrier-publication')
                need(carrier.read(private, 'native-sdk-carrier-producer.json', 65536)
                     == carrier.encoded(program), 'final-program-publication')
                need(carrier.identity(os.stat('native-sdk-carrier-producer.json', dir_fd=private.fd,
                                               follow_symlinks=False)) == program_identity,
                     'named-program-publication')
                private.check()
                held_source.check()
                retained_leaves.check()
                return program
            finally:
                if retained_leaves is not None:
                    retained_leaves.close()
                destination.close()


def integer(value):
    need(type(value) is str and re.fullmatch('[0-9]{1,20}', value) is not None, 'integer-envelope')
    return int(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', choices=('acquire', 'qualify'), required=True)
    parser.add_argument('--directory')
    parser.add_argument('--carrier-receipt')
    args = parser.parse_args()
    producer_context, cutoff = context(os.environ)
    if args.phase == 'acquire':
        need(args.directory is not None and args.carrier_receipt is None, 'acquire-arguments')
        with private_child(args.directory, 'carrier-private', carrier.Clock(cutoff)) as private:
            result = seal(private.path / 'carrier', cutoff, producer_context)
            private.check()
    else:
        need(args.directory is None and args.carrier_receipt is not None, 'qualification-arguments')
        result = qualify(args.carrier_receipt, os.environ['TEST_UNDECLARED_OUTPUTS_DIR'],
                         producer_context, cutoff)
    original_cutoff(producer_context['entry_monotonic_ns'], producer_context['deadline_monotonic_ns'])
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
