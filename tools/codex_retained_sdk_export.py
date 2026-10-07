"""Finite retained public SDK export. Proposal: never run against live output base.

Qualification emits an explicit selection; export requires its independently
selected SHA256. A qualification receipt alone never authorizes compilation.
"""
import argparse
import ast
import hashlib
import json
import os
import posixpath
from pathlib import Path
import re
import stat
import time

BASE = Path('/srv/fast-local/jess/state/codex/omux-bazel9-codex-owner-20261004/fb3edda211c2b41f7c6600796d3b28d1')
CACHE = Path('/home/jess/.cache/bazel-repo-contents-cache')
SOURCE = Path('/srv/fast-local/jess/state/codex/omux-codex-owner-development-20261004/source')
BASELINE = SOURCE.parent / 'verify-prepared-receipt-a8f6d68c30bb4099bb524ed55817d804.json'
BASELINE_SHA = 'e3c6d45bc93119ddf1da8bee6e02de3c7c3a3bbe52bb6d2664eb4b7b3d7b5273'
BASELINE_INVENTORY = '3400115fae8ef204f2ce085880b40887bcb14e2080236ba87a34be9b14fe7d3b'
SCHEMA = 'omux-retained-native-sdk-export-v1'
JDK = '/nix/store/siln89j8b6k5wdzw4asl69bma0k96nns-openjdk-headless-21.0.10+7'
MAX_REPOS, MAX_FILES, MAX_BYTES, MAX_FILE = 1600, 500000, 16*1024**3, 1024**3
GRAPH = ('MODULE.bazel', 'MODULE.bazel.lock', 'codex-rs/Cargo.lock', 'codex-rs/Cargo.toml',
         'codex-rs/core/Cargo.toml','codex-rs/core/BUILD.bazel','codex-rs/config/BUILD.bazel',
         'codex-rs/cli/BUILD.bazel','codex-rs/login/BUILD.bazel','defs.bzl','.bazelversion','.bazelrc')

def need(ok, message):
    if not ok:
        raise ValueError(message)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def digest(value):
    return hashlib.sha256(value).hexdigest()

def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON field')
        result[key] = value
    return result

class Budget:
    def __init__(self, deadline, callback=None):
        remaining = deadline-time.time()
        need(0 < remaining <= 1200, 'expired or excessive deadline')
        self.deadline, self.callback = time.monotonic()+remaining, callback
        self.files, self.bytes = 0, 0
    def check(self, count=0):
        need(time.monotonic() < self.deadline, 'absolute export deadline reached')
        self.bytes += count
        need(self.bytes <= MAX_BYTES, 'export byte bound')
        if self.callback:
            self.callback(count)

def open_dir(path, private=False):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'noncanonical parent')
    fd = os.open('/', os.O_RDONLY|os.O_DIRECTORY)
    try:
        for index, component in enumerate(path.parts[1:]):
            nxt = os.open(component, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
            info = os.fstat(fd)
            shared_ancestor = index < len(path.parts)-2 and info.st_mode & stat.S_ISVTX
            need(info.st_uid in (0, os.getuid()) and (not info.st_mode & 0o022 or shared_ancestor),
                 'unsafe public parent custody')
        if private:
            info = os.fstat(fd)
            need(info.st_uid == os.getuid() and not info.st_mode & 0o077, 'output parent must be private')
        return fd
    except BaseException:
        os.close(fd)
        raise

def read_file(fd, name, budget, output=None, capture=False):
    budget.check()
    inp = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=fd)
    try:
        before = os.fstat(inp)
        need(stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.getuid()) and not before.st_mode & 0o022
             and before.st_size <= MAX_FILE, 'unsafe file custody/type/size')
        h, count, parts, tail = hashlib.sha256(), 0, [], b''
        textual = Path(name).suffix in ('.bzl','.bazel','.sh','.py','.json') or name in ('BUILD','WORKSPACE')
        forbidden = tuple(str(path).encode() for path in (BASE,CACHE,SOURCE))
        while True:
            budget.check()
            block = os.read(inp, 1024*1024)
            if not block:
                break
            budget.check(len(block)); count += len(block); h.update(block)
            if textual and not capture:
                combined = tail+block
                need(not any(prefix in combined for prefix in forbidden),
                     'wrapper embeds retained public path; requires explicit reviewed byte transform')
                tail = combined[-512:]
            need(count <= MAX_FILE, 'file grew beyond bound')
            if output is not None:
                output.write(block)
            elif capture:
                parts.append(block)
        after = os.fstat(inp)
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and count == before.st_size,
             'input mutated during read')
        return h.hexdigest(), count, b''.join(parts)
    finally:
        os.close(inp)

def inventory(path, budget, output=None, sealed=False):
    root = open_dir(path)
    rows, nix = [], set()
    def walk(fd, prefix):
        budget.check()
        before = os.fstat(fd)
        for name in sorted(os.listdir(fd)):
            budget.check(); budget.files += 1
            need(budget.files <= MAX_FILES and name not in ('.git', 'action_cache', 'server', 'command.log')
                 and '\n' not in name and '\x00' not in name, 'forbidden or excessive repository entry')
            rel = prefix + name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            need(info.st_uid in (0,os.getuid()) and (stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o022), 'entry custody')
            if stat.S_ISDIR(info.st_mode):
                if output:
                    (output / rel).mkdir(mode=0o700)
                child = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=fd)
                try:
                    walk(child, rel+'/')
                finally:
                    os.close(child)
                rows.append({'path':rel,'kind':'directory','mode':0o555})
                if sealed:
                    need(stat.S_IMODE(info.st_mode)==0o555,'unsealed directory')
            elif stat.S_ISREG(info.st_mode):
                mode = 0o555 if info.st_mode & 0o111 else 0o444
                if sealed:
                    need(stat.S_IMODE(info.st_mode) == mode, 'unsealed file')
                if output:
                    out = os.open(output/rel,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with os.fdopen(out,'wb') as stream:
                        sha,size,_ = read_file(fd,name,budget,stream)
                        stream.flush(); os.fsync(stream.fileno())
                    os.chmod(output/rel,mode)
                else:
                    sha,size,_ = read_file(fd,name,budget)
                rows.append({'path':rel,'kind':'file','sha256':sha,'size':size,'mode':mode})
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(name,dir_fd=fd)
                need(target and '\n' not in target and '\x00' not in target, 'unsafe link spelling')
                need(os.stat(name,dir_fd=fd,follow_symlinks=False) == info,'link mutated')
                if output:
                    os.symlink(target,output/rel)
                rows.append({'path':rel,'kind':'symlink','target':target})
            else:
                raise ValueError('unsupported repository object')
        after = os.fstat(fd)
        need((before.st_mtime_ns,before.st_ctime_ns) == (after.st_mtime_ns,after.st_ctime_ns),'directory changed')
    try:
        walk(root,'')
    finally:
        os.close(root)
    return sorted(rows,key=lambda row:row['path'])

def relocate_links(repositories):
    """Resolve a finite public object graph without following source symlinks."""
    aliases, objects = {}, {}
    for repo in repositories:
        name = repo['canonical_name']
        for alias in (repo['source_root'], str(BASE/'external'/name)):
            previous = aliases.get(alias)
            need(previous is None or previous == name,'ambiguous canonical repository alias')
            aliases[alias] = name
        repo['source_files'] = repo['files']
        for item in repo['source_files']:
            objects[name+'/'+item['path']] = item
        objects[name] = {'kind':'directory'}
    def mapped(repo, item):
        target = item['target']
        absolute = posixpath.normpath(target if target.startswith('/') else
                    posixpath.join(repo['source_root'],posixpath.dirname(item['path']),target))
        if absolute == JDK or absolute.startswith(JDK+'/'):
            need(repo['canonical_name']=='rules_java++toolchains+local_jdk' and
                 item['path'] in ('bin','include','lib','nix-support','share') and
                 absolute == JDK+'/'+item['path'],'unselected immutable store link')
            fd = open_dir(absolute)
            try:
                info = os.fstat(fd)
                need(info.st_uid==0 and not info.st_mode & 0o222,'mutable store target')
            finally:
                os.close(fd)
            return absolute
        for alias in sorted(aliases,key=len,reverse=True):
            if absolute == alias or absolute.startswith(alias+'/'):
                tail = absolute[len(alias):].lstrip('/')
                return aliases[alias] + ('/'+tail if tail else '')
        raise ValueError('link escapes finite qualified public repositories')
    links = {}
    for repo in repositories:
        rewritten = []
        for item in repo['source_files']:
            item = dict(item)
            if item['kind']=='symlink':
                destination = mapped(repo,item)
                key = repo['canonical_name']+'/'+item['path']
                links[key] = destination
                item['target'] = destination if destination.startswith('/') else posixpath.relpath(
                    destination,posixpath.dirname(key))
            rewritten.append(item)
        repo['files'] = rewritten
        repo['source_inventory_sha256'] = repo['inventory_sha256']
        repo['inventory_sha256'] = digest(canonical(rewritten))
    def resolve(key, visited):
        need(len(visited)<64 and key not in visited,'cyclic or excessive repository link chain')
        if key.startswith(JDK+'/'):
            return
        parts = key.split('/')
        for count in range(1,len(parts)+1):
            prefix = '/'.join(parts[:count])
            if prefix in links:
                destination = links[prefix]
                suffix = '/'.join(parts[count:])
                resolve(destination+('/'+suffix if suffix else ''),visited|{key})
                return
        need(key in objects,'dangling repository link')
    for key in links:
        resolve(key,set())

def qualify(budget):
    fd = open_dir(BASELINE.parent)
    try:
        sha,_,raw = read_file(fd,BASELINE.name,budget,capture=True)
        need(sha == BASELINE_SHA,'baseline receipt pin')
        baseline = json.loads(raw,object_pairs_hook=unique)
    finally:
        os.close(fd)
    need(baseline['complete_inventory_sha256'] == BASELINE_INVENTORY,'baseline inventory')
    graph = {name:{'sha256':baseline['files'][name]['sha256']} for name in GRAPH}
    for name in GRAPH:
        parent = open_dir((SOURCE/name).parent)
        try:
            sha,_,_ = read_file(parent,Path(name).name,budget)
            need(sha == graph[name]['sha256'],'baseline graph byte mismatch')
        finally:
            os.close(parent)
    repositories, modules = [], {}
    fd = open_dir(BASE/'external')
    try:
        names = sorted(os.listdir(fd))
        for name in names:
            budget.check()
            if name.endswith('.marker') or name in ('_main','bazel_tools'):
                continue
            need(re.fullmatch(r'[A-Za-z0-9_+.~-]+',name),'canonical repository name')
            info = os.stat(name,dir_fd=fd,follow_symlinks=False)
            root = BASE/'external'/name
            kind = 'generated'
            if stat.S_ISLNK(info.st_mode):
                target = Path(os.readlink(name,dir_fd=fd))
                relative = target.relative_to(CACHE)
                need(len(relative.parts)==2 and re.fullmatch(r'[0-9a-f]{64}',relative.parts[0]) and
                     re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',relative.parts[1]),'unexpected cache parent')
                root,kind = target,'cache'
            else:
                need(stat.S_ISDIR(info.st_mode),'repository root type')
            rows = inventory(root,budget)
            module_file = next((item for item in rows if item['path']=='MODULE.bazel' and item['kind']=='file'),None)
            if module_file and (name.endswith('+') and '+' not in name[:-1] or name=='platforms'):
                parent = open_dir(root)
                try:
                    sha,size,raw = read_file(parent,'MODULE.bazel',budget,capture=True)
                    need(size <= 8*1024*1024 and sha==module_file['sha256'],'module metadata pin')
                finally:
                    os.close(parent)
                parsed = ast.parse(raw.decode('utf-8'))
                calls = [node.value for node in parsed.body if isinstance(node,ast.Expr) and
                         isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and
                         node.value.func.id=='module']
                need(len(calls)==1,'unique top-level module declaration required')
                keywords = [key for key in calls[0].keywords if key.arg=='name']
                need(len(keywords)==1 and isinstance(keywords[0].value,ast.Constant) and
                     isinstance(keywords[0].value.value,str),'literal module name required')
                module = keywords[0].value.value
                need(re.fullmatch(r'[a-z][a-z0-9._-]*',module) and name in (module,module+'+') and
                     module not in modules,'module declaration/repository identity mismatch')
                modules[module] = {'canonical_name':name,'module_file_sha256':sha}
            repositories.append({'canonical_name':name,'root_kind':kind,'source_root':str(root),
                                 'inventory_sha256':digest(canonical(rows)),'files':rows})
            need(len(repositories)<=MAX_REPOS,'repository count bound')
    finally:
        os.close(fd)
    relocate_links(repositories)
    return {'schema':SCHEMA,'baseline_receipt_sha256':BASELINE_SHA,
            'baseline_inventory_sha256':BASELINE_INVENTORY,'graph_files':graph,
            'repositories':repositories,'inventory_sha256':digest(canonical(repositories)),
            'mapping_sha256':graph['MODULE.bazel.lock']['sha256'],'excluded':['_main','bazel_tools','*.marker'],
            'qualification_only':True,'nix_store_roots':[JDK],'modules':modules,
            'nix_inventory':inventory(Path(JDK),budget)}

def load(path, sha, budget):
    fd = open_dir(Path(path).parent)
    try:
        actual,_,raw = read_file(fd,Path(path).name,budget,capture=True)
        need(actual == sha,'selection receipt digest')
        return json.loads(raw,object_pairs_hook=unique)
    finally:
        os.close(fd)

def validate_export(root, receipt_sha256, source_inventory_sha256, graph_files, *, on_read=None):
    budget = Budget(time.time()+1200,on_read)
    root = Path(root)
    receipt = load(root/'receipt.json',receipt_sha256,budget)
    need(receipt['schema']==SCHEMA and receipt['baseline_inventory_sha256']==source_inventory_sha256
         and receipt['graph_files']==graph_files and not receipt['qualification_only'],'export binding')
    for name, pin in graph_files.items():
        parent = open_dir((root/'graph'/name).parent)
        try:
            sha,_,_ = read_file(parent,Path(name).name,budget)
            need(sha==pin['sha256'],'exported graph byte mismatch')
        finally:
            os.close(parent)
    need(receipt['mapping_sha256']==graph_files['MODULE.bazel.lock']['sha256'],'mapping content binding')
    need(receipt['nix_store_roots']==[JDK] and inventory(Path(JDK),budget,sealed=True)==receipt['nix_inventory'],
         'immutable store bytes changed')
    repositories = {}
    need(0 < len(receipt['repositories']) <= MAX_REPOS,'export repository bound')
    parentfd = open_dir(root/'repositories')
    try:
        need(set(os.listdir(parentfd)) == {r['canonical_name'] for r in receipt['repositories']},
             'unselected exported repository')
    finally:
        os.close(parentfd)
    for repo in receipt['repositories']:
        name = repo['canonical_name']
        need(re.fullmatch(r'[A-Za-z0-9_+.~-]+',name) and name not in repositories,'repository identity')
        rows = inventory(root/'repositories'/name,budget,sealed=True)
        need(rows==repo['files'] and digest(canonical(rows))==repo['inventory_sha256'],'export byte inventory')
        repositories[name] = str(root/'repositories'/name)
    need(digest(canonical(receipt['repositories']))==receipt['inventory_sha256'],'aggregate inventory')
    module_overrides = {}
    for module, binding in receipt['modules'].items():
        name = binding['canonical_name']
        need(name in repositories and name in (module,module+'+'),'module canonical binding')
        entry = next(repo for repo in receipt['repositories'] if repo['canonical_name']==name)
        pin = next(item for item in entry['files'] if item['path']=='MODULE.bazel' and item['kind']=='file')
        need(pin['sha256']==binding['module_file_sha256'],'module override byte binding')
        parentfd = open_dir(Path(repositories[name]))
        try:
            sha,size,raw = read_file(parentfd,'MODULE.bazel',budget,capture=True)
            need(sha==pin['sha256'] and size <= 8*1024*1024,'module override file pin')
        finally:
            os.close(parentfd)
        parsed = ast.parse(raw.decode('utf-8'))
        calls = [node.value for node in parsed.body if isinstance(node,ast.Expr) and
                 isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and
                 node.value.func.id=='module']
        need(len(calls)==1,'module override declaration count')
        keywords = [key for key in calls[0].keywords if key.arg=='name']
        need(len(keywords)==1 and isinstance(keywords[0].value,ast.Constant) and
             keywords[0].value.value==module,'module override declaration name')
        module_overrides[module] = repositories[name]
    return dict(repositories=repositories,module_overrides=module_overrides,inventory_sha256=receipt['inventory_sha256'],
                mapping_sha256=receipt['mapping_sha256'],graph_files=receipt['graph_files'])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase',choices=('qualify','export'),default='qualify')
    parser.add_argument('--deadline-unix',type=float)
    parser.add_argument('--selection')
    parser.add_argument('--selection-sha256')
    parser.add_argument('--selection-sha-file')
    args = parser.parse_args()
    budget = Budget(args.deadline_unix if args.deadline_unix is not None else time.time()+900)
    parent = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR'])
    fd = open_dir(parent,private=True)
    try:
        if args.phase == 'qualify':
            receipt = qualify(budget)
            name = 'sdk-selection.json'
            raw = canonical(receipt)
            out = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=fd)
            with os.fdopen(out,'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            shaout = os.open('sdk-selection.sha256',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=fd)
            with os.fdopen(shaout,'wb') as stream:
                stream.write((digest(raw)+'\n').encode()); stream.flush(); os.fsync(stream.fileno())
            os.fsync(fd)
            return
        if args.phase == 'export':
            need(args.selection and args.selection_sha_file,'export requires declared selected metadata')
            selected = Path(args.selection).resolve(strict=True)
            sha_path = Path(args.selection_sha_file).resolve(strict=True)
            need(selected.name=='sdk-selection.json' and sha_path.name=='sdk-selection.sha256' and
                 selected.parent==sha_path.parent and 'external' in selected.parts and
                 (selected.parent.name=='omux_sdk_selection' or selected.parent.name.endswith('+omux_sdk_selection')),
                 'selection must resolve only to the declared local repository')
            parentfd = open_dir(sha_path.parent)
            try:
                _,size,raw = read_file(parentfd,sha_path.name,budget,capture=True)
                need(size==65 and re.fullmatch(rb'[0-9a-f]{64}\n',raw),'root selected SHA file')
            finally:
                os.close(parentfd)
            args.selection, args.selection_sha256 = str(selected),raw.decode().strip()
            need(selected.stat().st_size <= 256*1024*1024,'selection metadata bound')
        need(args.selection and args.selection_sha256,'export requires frozen explicit selection')
        selection = load(args.selection,args.selection_sha256,budget)
        need(selection == qualify(budget),'retained selection changed or has unreviewed fields')
        os.mkdir('sdk-export',0o700,dir_fd=fd)
        root = parent/'sdk-export'
        (root/'repositories').mkdir(mode=0o700)
        (root/'graph').mkdir(mode=0o700)
        for name, pin in selection['graph_files'].items():
            path = root/'graph'/name
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            parentfd = open_dir((SOURCE/name).parent)
            try:
                out = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
                with os.fdopen(out,'wb') as stream:
                    sha,_,_ = read_file(parentfd,Path(name).name,budget,stream)
                    need(sha==pin['sha256'],'graph export mismatch')
                    stream.flush(); os.fsync(stream.fileno())
            finally:
                os.close(parentfd)
        for repo in selection['repositories']:
            destination = root/'repositories'/repo['canonical_name']
            destination.mkdir(mode=0o700)
            rows = inventory(Path(repo['source_root']),budget,output=destination)
            need(rows==repo['source_files'],'copy differs from qualified repository')
            for item in repo['files']:
                if item['kind'] == 'symlink':
                    os.unlink(destination/item['path'])
                    os.symlink(item['target'],destination/item['path'])
            for item in sorted(repo['files'],key=lambda row:row['path'],reverse=True):
                if item['kind']=='directory':
                    os.chmod(destination/item['path'],0o555)
            os.chmod(destination,0o555)
            need(inventory(destination,budget,sealed=True)==repo['files'],'copy readback mismatch')
        selection['qualification_only'] = False
        selection['selection_sha256'] = args.selection_sha256
        selection['producer'] = '//tools:codex_retained_sdk_export_producer'
        selection['counts'] = {'entries_read':budget.files,'bytes_read':budget.bytes}
        raw = canonical(selection)
        out = os.open(root/'receipt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        with os.fdopen(out,'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.chmod(root/'repositories',0o555)
        for parentpath, subdirs, files in os.walk(root/'graph',topdown=False,followlinks=False):
            os.chmod(parentpath,0o555)
        os.chmod(root,0o555)
        os.fsync(fd)
    finally:
        os.close(fd)

if __name__ == '__main__':
    main()
