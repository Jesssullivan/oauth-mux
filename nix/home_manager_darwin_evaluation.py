"""Declared offline Darwin HM evaluation, no generation realization/activation.

Only three declared regular archives are passed by the Bazel rule. File-only
built-in fetchTarball preserves source links and authenticates complete NARs;
a dummy-store refusal is terminal, never a live-store or remote URL retry.
"""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time

import evaluation_runner as owned
import home_manager_darwin_generation as generated


def original_clock(environment):
    values = []
    for name in ('OMUX_DARWIN_HM_ENTRY_NS', 'OMUX_DARWIN_HM_DEADLINE_NS'):
        value = environment.get(name)
        generated.require(type(value) is str and re.fullmatch('[1-9][0-9]{0,19}', value) is not None)
        values.append(int(value))
    entry, deadline = values
    generated.require(entry <= time.monotonic_ns() and deadline - entry == 1200 * 10**9)
    until = min(entry + 600 * 10**9, deadline - 30 * 10**9)
    generated.Clock(until).tick()
    return until


def command(args):
    generated.require(re.fullmatch('sha256-[A-Za-z0-9+/]{43}=', args.artifact_nar) is not None
                      and re.fullmatch('[0-9a-f]{40}', args.source_revision) is not None
                      and re.fullmatch('[a-p]{32}', args.extension_id) is not None)
    # JSON's interpolation characters are escaped for Nix double-quoted strings;
    # no caller string becomes Nix code or a shell argument.
    quote = lambda value: json.dumps(value, ensure_ascii=False).replace('${', '\\${')
    def archive(path, pin):
        selected = Path(path).resolve(strict=True)
        generated.require(selected.is_file())
        return 'builtins.fetchTarball { url = ' + quote(selected.as_uri()) + '; sha256 = ' + quote(pin) + '; }'
    values = {'nixpkgsSource': archive(args.nixpkgs_archive, 'sha256-WncT27+3BOkgTaJZLnCsf3LcYf9RXMuR9ONSN4rzQ7s='),
              'homeManagerSource': archive(args.home_manager_archive, 'sha256-Sxu1NLTD/Ern6hFGLlZmtKCSct3YQXZI/lls8RE1XeM='),
              'artifactDirectory': archive(args.artifact_archive, args.artifact_nar),
              'artifactNarHash': quote(args.artifact_nar), 'artifactSourceRevision': quote(args.source_revision),
              'channel': quote(args.channel), 'extensionId': quote(args.extension_id)}
    expression = 'import ' + quote(str(Path(args.expression).resolve(strict=True))) + ' { ' + ' '.join(
        key + ' = ' + value + ';' for key, value in values.items()) + ' }'
    return [args.nix, '--extra-experimental-features', 'nix-command', '--store', 'dummy://?read-only=false',
            'eval', '--impure', '--offline', '--json', '--option', 'allow-import-from-derivation', 'false',
            '--option', 'builders', '', '--option', 'substituters', '', '--option', 'max-jobs', '0',
            '--expr', expression]


def evaluate(argv, home, until_ns):
    """Keep original cutoff, bounded pipes and unreaped direct-child custody.

    Same ownership primitives as the existing evaluator; this separate entry
    accepts a bounded structured definition, without changing its boolean API.
    """
    clock = generated.Clock(until_ns); clock.tick()
    cleanup_until = min(time.monotonic() + 65, until_ns / 10**9)
    work_until = min(time.monotonic() + 60, cleanup_until - 5)
    generated.require(time.monotonic() < work_until)
    output, error_output = bytearray(), bytearray()
    handlers, primary, cleanup_error, selected = {}, None, None, None
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, env=owned.evaluator_environment(home))
    def interrupted(signum, frame): raise KeyboardInterrupt
    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            handlers[signum] = signal.getsignal(signum); signal.signal(signum, interrupted)
        selected = selectors.DefaultSelector()
        selected.register(process.stdout, selectors.EVENT_READ, True)
        selected.register(process.stderr, selectors.EVENT_READ, False)
        while selected.get_map():
            generated.require(time.monotonic() < work_until); clock.tick()
            for key, _ in selected.select(min(1, max(0, work_until-time.monotonic()))):
                generated.require(time.monotonic() < work_until); clock.tick()
                raw = os.read(key.fileobj.fileno(), 4096)
                if not raw: selected.unregister(key.fileobj); continue
                target = output if key.data else error_output
                target.extend(raw)
                generated.require(len(target) <= (65536 if key.data else 32768))
        generated.require(owned.wait_unreaped(process, work_until) == 0)
        generated.require(time.monotonic() < work_until); clock.tick()
    except BaseException as error:
        primary = error
    finally:
        if selected is not None:
            try: selected.close()
            except BaseException as error: cleanup_error = error
        try: owned.cleanup_owned_group(process, deadline=cleanup_until)
        except BaseException as error: cleanup_error = cleanup_error or error
        for stream in (process.stdout, process.stderr):
            try: stream.close()
            except BaseException as error: cleanup_error = cleanup_error or error
        for signum, handler in handlers.items():
            try: signal.signal(signum, handler)
            except BaseException as error: cleanup_error = cleanup_error or error
        if time.monotonic() >= cleanup_until and cleanup_error is None:
            cleanup_error = ValueError('Darwin evaluator cleanup expired')
    if primary is not None:
        if cleanup_error is not None: primary.cleanup_category = owned.cleanup_failure_category(cleanup_error)
        raise primary
    if cleanup_error is not None:
        raise owned.EvaluationFailure('darwin-hm-definition', 'evaluation-cleanup-refused') from cleanup_error
    clock.tick()
    generated.specification(output)
    clock.tick()
    return bytes(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('nix', 'expression', 'nixpkgs-archive', 'home-manager-archive', 'artifact-archive',
                 'artifact-nar', 'source-revision', 'channel', 'extension-id', 'out'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    generated.require(args.channel in ('development', 'release'))
    until = original_clock(os.environ)
    with tempfile.TemporaryDirectory(prefix='omux-darwin-hm-evaluation-') as home:
        raw = evaluate(command(args), home, until)
    clock = generated.Clock(until); clock.tick()
    # Exclusive action output, individually fsynced; no acceptance marker on
    # publication/cleanup/deadline refusal. Partial action diagnostics may remain.
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            clock.tick(); count = os.write(fd, raw[offset:]); generated.require(count > 0); offset += count
        os.fsync(fd); os.fchmod(fd, 0o444); clock.tick()
    finally: os.close(fd)
    clock.tick()


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        print('Darwin Home Manager evaluation refused', file=sys.stderr)
        if getattr(error, 'cleanup_category', None) is not None:
            print('Owned evaluator cleanup: ' + error.cleanup_category, file=sys.stderr)
        raise SystemExit(125)
