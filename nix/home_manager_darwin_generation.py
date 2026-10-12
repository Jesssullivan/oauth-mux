"""Read-only declared generated HM objects; never activate, sign or query jobs.

The selected definition is an explicit input, not proof of genuine HM execution.
An actual evaluator/realizer receipt and platform acceptance remain separate.
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

KIND = 'omux-darwin-home-manager-generation-definition-v1'
SELECT = 'omux-darwin-home-manager-generated-inputs-v1'
MAX_DOCUMENT = 65536
MAX_SOURCES = 32


def require(value):
    if not value:
        raise ValueError('Darwin generated Home Manager definition refused')


def fields(value, names):
    require(type(value) is dict and set(value) == set(names))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(rows):
    value = {}
    for key, item in rows:
        require(key not in value)
        value[key] = item
    return value


def pin(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None)
    return value


def absolute(value):
    require(type(value) is str and 0 < len(value) <= 4096 and value.startswith('/')
            and value != '/' and all(part not in ('', '.', '..') for part in value.split('/')[1:])
            and len(value.split('/')) <= 16 and not any(ord(c) < 32 for c in value))
    return Path(value)


def relative(value):
    require(type(value) is str and 0 < len(value) <= 4096 and not value.startswith('/')
            and all(part not in ('', '.', '..') for part in value.split('/'))
            and len(value.split('/')) <= 12 and not any(ord(c) < 32 for c in value))
    return value


def witness(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class Clock:
    def __init__(self, until_ns):
        require(type(until_ns) is int and until_ns > 0)
        self.until_ns = until_ns

    def tick(self):
        require(time.monotonic_ns() < self.until_ns)


class Held:
    """Original complete nofollow parent and named/held leaf identities."""
    def __init__(self, path, clock, kind):
        self.path, self.clock, self.kind = absolute(str(path)), clock, kind
        require(kind in ('regular', 'control', 'directory', 'symlink'))
        self.chain, self.fd, self.stamp, self.pending = [], None, None, None
        try:
            # Own the opened FD before metadata IO or list enrollment can fail.
            self.pending = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.chain.append(('/', self.pending, None))
            self.pending = None
            fd = self.chain[-1][1]
            self.chain[-1] = ('/', fd, witness(os.fstat(fd)))
            for part in self.path.parts[1:-1]:
                clock.tick()
                parent = self.chain[-1][1]
                info = os.stat(part, dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
                        and (not info.st_mode & 0o022 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX))
                self.pending = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                child = self.pending
                self.chain.append((part, child, witness(info)))
                self.pending = None
                require(witness(os.fstat(child)) == witness(info))
            parent = self.chain[-1][1]
            info = os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)
            require(info.st_uid in (0, os.getuid()))
            self.stamp = witness(info)
            if kind == 'symlink':
                require(stat.S_ISLNK(info.st_mode))
            else:
                require((stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                         and stat.S_IMODE(info.st_mode) in ((0o444, 0o644) if kind == 'control' else (0o444,)))
                        if kind in ('regular', 'control') else stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022)
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                if kind == 'directory': flags |= os.O_DIRECTORY
                self.fd = os.open(self.path.name, flags, dir_fd=parent)
                require(witness(os.fstat(self.fd)) == self.stamp)
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        self.clock.tick()
        for index, (name, fd, stamp) in enumerate(self.chain):
            require(witness(os.fstat(fd)) == stamp)
            if index:
                require(witness(os.stat(name, dir_fd=self.chain[index-1][1], follow_symlinks=False)) == stamp)
        require(witness(os.stat(self.path.name, dir_fd=self.chain[-1][1], follow_symlinks=False)) == self.stamp)
        if self.fd is not None: require(witness(os.fstat(self.fd)) == self.stamp)

    def read(self):
        require(self.kind in ('regular', 'control') and self.stamp[6] <= MAX_DOCUMENT)
        self.check()
        blocks, count = [], 0
        while True:
            self.clock.tick()
            part = os.pread(self.fd, min(65536, MAX_DOCUMENT + 1 - count), count)
            if not part: break
            blocks.append(part); count += len(part)
            require(count <= MAX_DOCUMENT)
        self.check()
        require(count == self.stamp[6])
        return b''.join(blocks)

    def link(self, expected):
        require(self.kind == 'symlink')
        self.check()
        require(os.readlink(self.path.name, dir_fd=self.chain[-1][1]) == str(expected))
        self.check()

    def close(self):
        # A transfer interrupted after chain enrollment can leave pending and
        # chain naming the same FD. Snapshot one ordered attempt per FD before
        # detach; never retry a numeric FD after a possibly successful close.
        handles = list(dict.fromkeys(([self.pending] if self.pending is not None else []) + ([self.fd] if self.fd is not None else []) + [item[1] for item in reversed(self.chain)]))
        self.pending, self.fd, self.chain = None, None, []
        failure = None
        for fd in handles:
            try: os.close(fd)
            except OSError as error:
                if failure is None: failure = error
        if failure is not None: raise failure

    def __enter__(self): return self
    def __exit__(self, *unused): self.close()


def specification(raw):
    value = json.loads(raw, object_pairs_hook=unique)
    fields(value, ('schemaVersion', 'kind', 'scope', 'activation', 'generatedBytes', 'appleAcceptance',
        'runtimeCollector', 'generationPath', 'generationDerivation', 'homeFilesPath', 'agentsPath',
        'agentSourcePath', 'agentText', 'homeFiles', 'channel', 'identity', 'homeDirectory',
        'desiredProgramArguments', 'generatedProgramArguments', 'artifact', 'predicates'))
    require(value['schemaVersion'] == 1 and type(value['schemaVersion']) is int and value['kind'] == KIND
            and value['scope'] == 'genuine-pinned-darwin-home-manager-evaluation-only'
            and value['activation'] == value['appleAcceptance'] == 'unproved'
            and value['generatedBytes'] == 'unrealized-unverified'
            and value['runtimeCollector'] == 'darwin-live-binding-unimplemented')
    require(value['channel'] in ('development', 'release'))
    label = 'ai.xoxd.omux.dev' if value['channel'] == 'development' else 'ai.xoxd.omux'
    require(value['identity'] == label and type(value['agentText']) is str
            and len(value['agentText'].encode()) <= MAX_DOCUMENT)
    for name in ('generationPath', 'generationDerivation', 'homeFilesPath', 'agentsPath', 'agentSourcePath', 'homeDirectory'):
        absolute(value[name])
    fields(value['artifact'], ('root', 'manifestSha256', 'narHash', 'sourceRevision'))
    absolute(value['artifact']['root']); pin(value['artifact']['manifestSha256'])
    require(type(value['homeFiles']) is dict and 0 < len(value['homeFiles']) <= MAX_SOURCES)
    for name, row in value['homeFiles'].items():
        relative(name); fields(row, ('source', 'text', 'kind')); absolute(row['source'])
        require(row['kind'] in ('regular', 'directory')
                and ((type(row['text']) is str and len(row['text'].encode()) <= MAX_DOCUMENT)
                     if row['kind'] == 'regular' else row['text'] is None))
    require(type(value['predicates']) is dict and value['predicates']
            and all(item is True for item in value['predicates'].values()))
    return value


def alias_join(alias, path):
    require(str(Path(alias).resolve(strict=True)) == str(path))


def observe(spec, aliases, deadline_ns, *, before_final=None):
    """Actual generated-object topology/bytes only; no HM/signing qualification."""
    clock = Clock(deadline_ns)
    require(before_final is None or callable(before_final))
    sources = {spec['agentSourcePath']: spec['agentText'].encode()}
    for row in spec['homeFiles'].values():
        if row['kind'] == 'regular':
            raw = row['text'].encode()
            require(row['source'] not in sources or sources[row['source']] == raw)
            sources[row['source']] = raw
    require(set(aliases) == set(sources) and len(sources) <= MAX_SOURCES)
    selected = []
    with ExitStack() as stack:
        def hold(path, kind):
            item = stack.enter_context(Held(path, clock, kind)); selected.append(item); return item
        generation = hold(spec['generationPath'], 'directory')
        hold(generation.path/'LaunchAgents', 'symlink').link(spec['agentsPath'])
        hold(generation.path/'home-files', 'symlink').link(spec['homeFilesPath'])
        agents = hold(spec['agentsPath'], 'directory')
        require(set(os.listdir(agents.fd)) == {spec['identity']+'.plist'})
        hold(agents.path/(spec['identity']+'.plist'), 'symlink').link(spec['agentSourcePath'])
        home = hold(spec['homeFilesPath'], 'directory')
        for name, row in spec['homeFiles'].items():
            clock.tick()
            hold(home.path/name, 'symlink').link(row['source'])
            if row['kind'] == 'directory': hold(row['source'], 'directory')
        for path, raw in sources.items():
            alias_join(aliases[path], path)
            source = hold(path, 'regular')
            require(source.read() == raw)
            alias_join(aliases[path], path)
        encoded = json.dumps({'kind': 'omux-darwin-selected-generated-objects-observation-v1',
            'scope': 'selected-generation-topology-and-bytes-only', 'channel': spec['channel'],
            'agentSha256': sha(spec['agentText'].encode()), 'regularSources': len(sources),
            'generationPath': spec['generationPath'], 'generationWitness': list(generation.stamp),
            'agentsPath': spec['agentsPath'], 'homeFilesPath': spec['homeFilesPath'],
            'regularSourceBodies': [{'source': path, 'sha256': sha(raw), 'bytes': len(raw), 'mode': 292}
                                   for path, raw in sorted(sources.items())],
            'genuineEvaluatorReceipt': 'not-authenticated-by-this-observer',
            'activation': 'unproved', 'appleAcceptance': 'unproved', 'liveService': 'unproved',
            'nativePeer': 'unsupported', 'liveHandoff': 'unproved'}, sort_keys=True)
        require(len(encoded.encode()) + 1 <= MAX_DOCUMENT)
        if before_final is not None: before_final()
        for path, alias in aliases.items():
            clock.tick(); alias_join(alias, path)
        # Complete final original name/FD fence after every body, alias and
        # caller control read, while every original object remains held.
        require(set(os.listdir(agents.fd)) == {spec['identity']+'.plist'})
        for item in selected: item.check()
        clock.tick()
    clock.tick()
    return encoded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--layout', required=True)
    parser.add_argument('--entry-monotonic-ns', type=int)
    parser.add_argument('--deadline-monotonic-ns', type=int)
    args = parser.parse_args()
    for name, key in (('entry_monotonic_ns', 'OMUX_DARWIN_HM_ENTRY_NS'),
                      ('deadline_monotonic_ns', 'OMUX_DARWIN_HM_DEADLINE_NS')):
        supplied = os.environ.get(key)
        if getattr(args, name) is None:
            require(type(supplied) is str and re.fullmatch('[1-9][0-9]{0,19}', supplied) is not None)
            setattr(args, name, int(supplied))
        elif supplied is not None:
            require(supplied == str(getattr(args, name)))
    require(0 < args.entry_monotonic_ns <= time.monotonic_ns()
            and args.deadline_monotonic_ns-args.entry_monotonic_ns == 1200*10**9)
    until = min(args.deadline_monotonic_ns-30*10**9, args.entry_monotonic_ns+600*10**9)
    clock = Clock(until)
    # Layout is a bounded regular declared control. Cold selection refuses
    # before resolving or reading any future generation or source object.
    with Held(Path(args.layout).resolve(strict=True), clock, 'control') as held:
        raw = held.read(); layout = json.loads(raw, object_pairs_hook=unique)
        fields(layout, ('schemaVersion', 'kind', 'selection'))
        require(type(layout['schemaVersion']) is int and layout['schemaVersion'] == 1 and layout['kind'] == SELECT)
        require(layout['selection'] is not None)
        choice = layout['selection']; fields(choice, ('spec', 'sources'))
        fields(choice['spec'], ('path', 'sha256', 'alias'))
        root = Path(args.layout).parent
        spec_path = absolute(choice['spec']['path'])
        alias_join(root/relative(choice['spec']['alias']), spec_path)
        with Held(spec_path, clock, 'control') as specification_file:
            spec_raw = specification_file.read(); require(sha(spec_raw) == pin(choice['spec']['sha256']))
            spec = specification(spec_raw)
            aliases = {}
            require(type(choice['sources']) is dict and 0 < len(choice['sources']) <= MAX_SOURCES)
            for path, row in choice['sources'].items():
                absolute(path); fields(row, ('sha256', 'alias')); pin(row['sha256'])
                aliases[path] = root/relative(row['alias'])
            expected = {spec['agentSourcePath']: sha(spec['agentText'].encode())}
            expected.update({row['source']: sha(row['text'].encode()) for row in spec['homeFiles'].values() if row['kind'] == 'regular'})
            require(set(expected) == set(choice['sources']) and all(choice['sources'][path]['sha256'] == digest for path, digest in expected.items()))
            def final_controls():
                require(specification_file.read() == spec_raw)
                alias_join(root/relative(choice['spec']['alias']), spec_path)
                require(held.read() == raw)
                alias_join(args.layout, held.path)
            result = observe(spec, aliases, until, before_final=final_controls)
    clock.tick()
    require(sys.stdout.write(result + '\n') == len(result) + 1)
    sys.stdout.flush()
    # Provisional JSON is diagnostic if write/flush consumes the original
    # cutoff; only the actual terminal0/0 invocation can qualify this scope.
    clock.tick()


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError):
        print('Darwin generated Home Manager observation refused', file=sys.stderr)
        raise SystemExit(125)
