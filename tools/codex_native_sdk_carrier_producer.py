"""Bazel repository entrypoint for the separately qualified SDK carrier.

The caller supplies the original integer guardian envelope. Sealing reuses
its original cutoff; no phase acquires a fresh allowance. This entrypoint never
selects an origin, reads a legacy repository, or qualifies a native runtime.
"""
import argparse
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


def qualify(receipt_leaf, outputs, producer_context, cutoff):
    clock = carrier.Clock(cutoff)
    selected = Path(receipt_leaf).resolve(strict=True)
    need(selected.name == 'receipt.json', 'declared-receipt-leaf')
    with carrier.Root(selected.parent, clock) as source:
        raw = carrier.read(source, 'receipt.json', carrier.MAX_METADATA)
        pin = carrier.sha(raw)
        receipt = carrier.validate_binding(source.path, pin, cutoff)
        need(receipt['producer_context'] == producer_context and
             receipt['origin']['receipt_sha256'] == ORIGIN_SHA and
             receipt['origin']['root'] == ORIGIN, 'actual-acquisition-context')
        original_publication = carrier.publication_report(source.path, pin, cutoff)
        with private_child(outputs, 'sdk-private', clock) as private:
            destination = carrier.Output(private.path / 'sdk-carrier', clock)
            try:
                for name in FILES:
                    incoming, before = source.open(name)
                    outgoing = None
                    try:
                        outgoing = destination.create(name)
                        count = 0
                        while True:
                            clock.tick()
                            block = os.read(incoming, 65536)
                            if not block:
                                break
                            count += len(block)
                            need(count <= before[6], 'retained-copy-size')
                            carrier.write_all(outgoing, block, clock)
                        need(count == before[6] and carrier.identity(os.fstat(incoming)) == before,
                             'retained-copy-readback')
                        os.fsync(outgoing)
                        os.fchmod(outgoing, 0o444)
                    finally:
                        os.close(incoming)
                        if outgoing is not None:
                            os.close(outgoing)
                source.check()
                destination.finish()
                retained = carrier.publication_report(destination.path, pin, cutoff)
                program = {'kind': 'omux-native-sdk-carrier-producer-v1',
                           'producer': '//tools:codex_native_sdk_carrier_seal_producer',
                           'carrier_receipt_sha256': pin, 'origin_receipt_sha256': ORIGIN_SHA,
                           'producer_context': producer_context, 'files': retained['files'],
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
                source.check()
                need(carrier.publication_report(source.path, pin, cutoff) == original_publication,
                     'final-source-carrier-publication')
                need(carrier.publication_report(destination.path, pin, cutoff) == retained,
                     'final-retained-carrier-publication')
                need(carrier.read(private, 'native-sdk-carrier-producer.json', 65536)
                     == carrier.encoded(program), 'final-program-publication')
                need(carrier.identity(os.stat('native-sdk-carrier-producer.json', dir_fd=private.fd,
                                               follow_symlinks=False)) == program_identity,
                     'named-program-publication')
                private.check()
                return program
            finally:
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
