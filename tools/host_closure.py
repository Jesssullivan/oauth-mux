"""Declared offline closure resolution and fixed operator-input presence metadata."""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time
import threading

NAMES = ('BAZEL_REMOTE_EXECUTOR', 'BAZEL_REMOTE_CACHE', 'BAZEL_REMOTE_INSTANCE_NAME', 'GF_BAZEL_SUBSTRATE_MODE', 'GF_BAZEL_REMOTE_EXECUTION_PLATFORM')
MAX_SECONDS = 120

class MetadataError(ValueError):
    pass

def failure_category(stderr):
    text = stderr.decode('utf-8',errors='replace').lower()
    for needles,category in [(("allow-import-from-derivation","import from derivation"),'IFD-disabled'),(("cannot write modified lock","lock file requires changes"),'lock-mutation'),(("experimental nix feature",),'experimental-feature'),(("daemon","connection refused","connection reset"),'daemon-connect'),(("unfree","license"),'license-policy'),(("permission denied","read-only file system"),'permission'),(("not available in the nix store","cannot fetch","unable to download","offline"),'offline-cache-miss'),(("attribute","undefined variable"),'expression-attribute'),(("syntax error",),'expression-syntax'),(("no such file",),'declared-input-missing')]:
        if any(needle in text for needle in needles): return category
    return 'evaluation-failed'

def configuration():
    values = {name: os.environ.get(name, '') for name in NAMES}
    if any(len(value) > 8192 for value in values.values()):
        raise ValueError('bounded configuration rejected')
    executor, cache = values[NAMES[0]], values[NAMES[1]]
    scheme = lambda value: bool(re.match(r'^(?:grpc|grpcs|http|https)://', value))
    return {'mode':'config', 'present':{name:bool(value) for name,value in values.items()}, 'endpoint_equality':bool(executor and cache and executor == cache), 'executor_scheme_allowed':scheme(executor), 'cache_scheme_allowed':scheme(cache), 'substrate_executor_backed':values[NAMES[3]] == 'executor-backed', 'platform_mentions_darwin':bool(re.search(r'darwin|macos', values[NAMES[4]], re.I))}

def evaluate(command):
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, env={key:value for key,value in os.environ.items() if key in {'HOME','PATH'}})
    output = bytearray()
    stderr = bytearray()
    with selectors.DefaultSelector() as selected:
        selected.register(proc.stdout, selectors.EVENT_READ, True)
        selected.register(proc.stderr, selectors.EVENT_READ, False)
        counts = {True:0, False:0}
        deadline = time.monotonic() + MAX_SECONDS
        handlers = {}
        def interrupted(signum, frame): raise KeyboardInterrupt
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP): handlers[signum] = signal.signal(signum, interrupted)
        try:
            while selected.get_map():
                if time.monotonic() >= deadline:
                    raise ValueError('offline evaluation deadline')
                for key,_ in selected.select(min(1, max(0, deadline-time.monotonic()))):
                    data = os.read(key.fileobj.fileno(), 4096)
                    if not data:
                        selected.unregister(key.fileobj)
                        continue
                    counts[key.data] += len(data)
                    if counts[key.data] > (8192 if key.data else 32768):
                        raise ValueError('offline evaluation output bound')
                    if key.data: output.extend(data)
                    else: stderr.extend(data)
        finally:
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            try: status = proc.wait(timeout=5)
            finally:
                proc.stdout.close()
                proc.stderr.close()
                for signum,handler in handlers.items(): signal.signal(signum,handler)
    if status != 0: raise MetadataError(failure_category(stderr))
    return bytes(output).decode('ascii').strip()

def resolve(args):
    with tempfile.TemporaryDirectory(prefix='omux-closure-metadata-') as scratch:
        root = Path(scratch)
        for source,destination in [(args.flake,'flake.nix'),(args.lock,'flake.lock'),(args.zig_index,'tools/zig-index.json'),(args.codex_manifest,'tools/codex_upstream_archives.json')]:
            with open(source,'rb') as stream: data = stream.read(1048577)
            if len(data) > 1048576: raise ValueError('declared input size rejected')
            target = root / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        value = evaluate([args.nix,'--extra-experimental-features','nix-command flakes','eval','--offline','--no-write-lock-file','--option','allow-import-from-derivation','false','--raw',str(root)+'#packages.aarch64-darwin.bazel-closure.outPath'])
    match = re.fullmatch(r'/nix/store/([0-9a-z]{32}-omux-bazel-closure)', value)
    if not match: raise ValueError('public closure result rejected')
    return {'mode':'resolve','closure_basename':match.group(1),'system':'aarch64-darwin'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=('resolve','config'),required=True)
    for name in ('nix','flake','lock','zig-index','codex-manifest'): parser.add_argument('--'+name,required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(configuration() if args.mode == 'config' else resolve(args),sort_keys=True))
        return 0
    except (OSError,ValueError,subprocess.TimeoutExpired,UnicodeError,KeyboardInterrupt) as error:
        print(json.dumps({'mode':args.mode,'passed':False,'gate':'bounded declared metadata unavailable','failure_category':str(error) if isinstance(error,MetadataError) else 'bounded-execution-or-input'},sort_keys=True))
        return 2

if __name__ == '__main__': raise SystemExit(main())
