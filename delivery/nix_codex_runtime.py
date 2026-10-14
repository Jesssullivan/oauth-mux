"""Declared Linux/Nix direct-main candidate; no portable profile promotion.

Only the fixed Bazel producer calls assemble. Original ELF lookup bytes remain
unchanged. Registered roots and explicit selected lookup edges are recorded for
the genuine constructor. This evaluation artifact does not establish complete
dynamic-loader search behavior or credential acquisition authority.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import time
import portable

PROFILE = 'linux_nix_direct_main_v1'
ROOT_RE = re.compile(r'/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._-]+')
MAX_FILES, MAX_ALIASES, MAX_EDGES = 32, 32, 64
MAX_BYTES = 256 * 1024 * 1024
PACKAGE_OUTPUT_NAMES = ('fresh-native-runtime.tar.gz', 'runtime-manifest.json',
    'runtime-receipt.json', 'registration-receipt.json', 'package-selection.json')

def original_package_deadline(environment, *, clock_ns=time.monotonic_ns):
    require(environment.get('OMUX_NATIVE_PACKAGE_MODE') == 'native-acquisition-package-reserved',
            'package requires exact original guardian clock')
    values = []
    for name in ('OMUX_NATIVE_PACKAGE_ENTRY_NS', 'OMUX_NATIVE_PACKAGE_DEADLINE_NS'):
        value = environment.get(name)
        require(type(value) is str and re.fullmatch(r'[1-9][0-9]{0,18}',value) is not None,
                'package requires canonical original monotonic clock')
        values.append(int(value))
    entry, deadline = values
    require(deadline-entry == 1200*10**9 and deadline < 2**63,
            'package original guardian envelope differs')
    now = clock_ns()
    require(entry <= now < deadline-30*10**9, 'package original guardian deadline exhausted')
    return (deadline-30*10**9)/10**9

def package_output_inventory(directory, deadline):
    def witness(value):
        return (value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_uid,
                value.st_gid,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    result = {'schema_version':1, 'kind':'omux-native-acquisition-package-output-v1',
        'purpose':'evaluation-only', 'acquisitionContract':'unsupported', 'files':{}}
    for name in PACKAGE_OUTPUT_NAMES:
        path = Path(directory)/name
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_mode & 0o777 == 0o444,
                'package output inventory requires sealed regular leaf')
        require(0 < before.st_size <= (MAX_BYTES if name.endswith('.tar.gz') else 16*1024*1024),
                'package output inventory finite size')
        hasher, count = hashlib.sha256(), 0
        with path.open('rb') as stream:
            require(stream.fileno() >= 0 and witness(os.fstat(stream.fileno())) == witness(before),
                    'package output inventory opened leaf drift')
            while True:
                require(time.monotonic() < deadline, 'package output inventory original deadline')
                raw = stream.read(65536)
                if not raw:
                    break
                count += len(raw)
                require(count <= before.st_size, 'package output inventory growth')
                hasher.update(raw)
            require(witness(os.fstat(stream.fileno())) == witness(before) and witness(path.lstat()) == witness(before) and count == before.st_size,
                    'package output inventory named or held drift')
        result['files'][name] = {'sha256':hasher.hexdigest(), 'bytes':count}
    return result
BACKEND = 'lib/codex/libexec/codex.bin'
CA = 'lib/codex/share/ca-bundle.crt'
LOADER = 'lib/codex/lib/ld-linux-x86-64.so.2'

def require(value, label):
    if not value:
        raise ValueError(label)

def tick(until):
    require(type(until) is float and time.monotonic() < until, 'nix runtime original deadline')

def root_of(path):
    value = str(path)
    parts = value.split('/')
    require(len(parts) >= 4 and ROOT_RE.fullmatch('/'.join(parts[:4])) is not None,
            'nix runtime selected path namespace')
    require(all(p not in ('', '.', '..') for p in parts[4:]) and len(value) <= 4096
            and all(32 <= ord(c) < 127 and c != '\\' for c in value), 'nix runtime path bound')
    return '/'.join(parts[:4])

def witness(info):
    return {'mode':info.st_mode, 'uid':info.st_uid, 'gid':info.st_gid,
            'nlink':info.st_nlink, 'size':info.st_size, 'ino':info.st_ino,
            'dev':(os.major(info.st_dev)<<32)|os.minor(info.st_dev),
            'mtime_ns':info.st_mtime_ns, 'ctime_ns':info.st_ctime_ns}

def safe_parents(path, until):
    tick(until)
    root = Path(root_of(path))
    store = os.lstat('/nix/store')
    require(stat.S_ISDIR(store.st_mode) and store.st_uid == 0 and not store.st_mode & 0o6002
            and (not store.st_mode & 0o020 or store.st_mode & 0o1000),
            'nix runtime store ownership')
    current = root
    for part in (None, *Path(path).relative_to(root).parts[:-1]):
        if part is not None:
            current /= part
        status = os.lstat(current)
        require(stat.S_ISDIR(status.st_mode) and status.st_uid == 0 and not status.st_mode & 0o6222,
                'nix runtime immutable parent')
        tick(until)

def read_regular(path, until):
    safe_parents(path, until)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o222
                and 0 < before.st_size <= 128*1024*1024, 'nix runtime immutable file bound')
        values, size = [], 0
        while True:
            tick(until)
            value = os.read(fd, 65536)
            if not value:
                break
            size += len(value)
            require(size <= before.st_size, 'nix runtime file growth')
            values.append(value)
        require(size == before.st_size and witness(before) == witness(os.fstat(fd))
                == witness(os.lstat(path)), 'nix runtime file drift')
        return b''.join(values), witness(before)
    finally:
        os.close(fd)

def launcher():
    return ("#!/bin/sh\nset -eu\nunset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH\n"
            "launch_dir=${0%/*}\nif [ \"$launch_dir\" = \"$0\" ]; then launch_dir=.; fi\n"
            "pkg_root=$(CDPATH= cd -P \"$launch_dir/..\" && pwd -P) || exit 1\n"
            "runtime=$pkg_root/lib/codex\n"
            "SSL_CERT_FILE=\"$runtime/share/ca-bundle.crt\"\nexport SSL_CERT_FILE\n"
            'exec "$runtime/libexec/codex.bin" "$@"\n').encode('ascii')

def elf_info(value):
    info = portable.elf_metadata(value, max_bytes=512*1024*1024)
    offset = struct.unpack_from('<Q',value,32)[0]
    size,count = struct.unpack_from('<HH',value,54)
    loads, dynamic, dynamic_segment = [], None, None
    for index in range(count):
        tag,_,position,virtual,_,length,_,_ = struct.unpack_from('<IIQQQQQQ',value,offset+index*size)
        if tag == 1:
            require(position+length <= len(value) and virtual+length < 2**64,
                    'nix direct ELF LOAD range')
            loads.append((position,virtual,length))
        elif tag == 2:
            require(dynamic_segment is None and length % 16 == 0 and position+length <= len(value),
                    'nix direct unique bounded dynamic segment')
            dynamic_segment = (position,virtual,length)
            dynamic = value[position:position+length]
    info['soname'] = None
    info['legacy_rpath'] = False
    if dynamic is None:
        return info
    position,virtual,length = dynamic_segment
    mappings = [p+virtual-v for p,v,n in loads if virtual >= v
                and virtual-v <= n and length <= n-(virtual-v)]
    require(mappings == [position], 'nix direct unique dynamic virtual-to-file mapping')
    entries = []
    for pos in range(0,len(dynamic),16):
        tag,address = struct.unpack_from('<qQ',dynamic,pos)
        if tag == 0:
            break
        entries.append((tag,address))
    tables = [v for t,v in entries if t == 5]
    sizes = [v for t,v in entries if t == 10]
    strings = [(t,v) for t,v in entries if t in (14,15,29)]
    if not strings:
        return info
    require(len(tables) == len(sizes) == 1, 'nix direct ELF string table')
    mappings = [p+tables[0]-v for p,v,n in loads if tables[0] >= v
                and tables[0]-v <= n and sizes[0] <= n-(tables[0]-v)]
    require(len(mappings) == 1, 'nix direct ELF string mapping')
    table = value[mappings[0]:mappings[0]+sizes[0]]
    sonames = [portable._cstring(table,v) for t,v in strings if t == 14]
    require(len(sonames) <= 1, 'nix direct unique SONAME')
    info['soname'] = sonames[0] if sonames else None
    runpath = [portable._cstring(table,v) for t,v in strings if t == 29]
    rpath = [portable._cstring(table,v) for t,v in strings if t == 15]
    info['legacy_rpath'] = bool(rpath)
    require(len(runpath) <= 1 and len(rpath) <= 1, 'nix direct unique lookup paths')
    info['rpath'] = (runpath or rpath or [''])[0].split(':') if (runpath or rpath) else []
    return info

def assemble(backend, declared_files, ca_bundle, until, *, registration=None, store_paths=None):
    tick(until)
    require(type(backend) is bytes and 0 < len(backend) <= 512*1024*1024,
            'nix direct backend bound')
    metadata = elf_info(backend)
    interpreter = metadata['interpreter']
    require(metadata['machine'] == 62 and type(interpreter) is str, 'nix direct original interpreter')
    root_of(interpreter)
    require(0 < len(declared_files) <= MAX_FILES and len(set(map(str,declared_files))) == len(declared_files),
            'nix direct declared finite inputs')
    selected = {}
    for path in declared_files:
        physical = str(path.resolve(strict=True))
        root_of(physical)
        value, status = read_regular(physical, until)
        require(physical not in selected or selected[physical][0] == value, 'nix direct ambiguous input')
        selected[physical] = (value, status)
    aliases = {}
    def resolve(name):
        current = str(name)
        seen = set()
        for _ in range(MAX_ALIASES+1):
            tick(until)
            root_of(current)
            safe_parents(current, until)
            info = os.lstat(current)
            if not stat.S_ISLNK(info.st_mode):
                require(current in selected, 'nix direct undeclared resolved file')
                return current
            require(info.st_uid == 0 and current not in seen, 'nix direct unsafe alias')
            seen.add(current)
            target = os.readlink(current)
            require(0 < len(target) <= 4096 and witness(info) == witness(os.lstat(current)), 'nix direct alias drift')
            if not target.startswith('/'):
                require(all(part not in ('', '.', '..') for part in target.split('/')), 'nix direct unsupported relative alias')
            aliases[current] = {'path':current,'target':target,'status':witness(info)}
            require(len(aliases) <= MAX_ALIASES, 'nix direct alias cap')
            current = os.path.normpath(target if target.startswith('/') else str(Path(current).parent/target))
        raise ValueError('nix direct alias depth')
    loader = resolve(interpreter)
    names = sorted(selected)
    indexes = {name:index for index,name in enumerate(names)}
    loader_info = elf_info(selected[loader][0])
    loaded = {loader_info['soname']:loader} if loader_info['soname'] else {}
    edges, pending, visited = [], [(255, metadata)], set()
    pending.append((indexes[loader], loader_info))
    while pending:
        source, info = pending.pop(0)
        if source in visited:
            continue
        visited.add(source)
        require(info['machine'] == 62, 'nix direct ELF machine')
        require(not info['legacy_rpath'], 'nix direct RPATH unsupported')
        for needed in info['needed']:
            require('/' not in needed and 0 < len(needed) <= 255, 'nix direct ELF name')
            target = loaded.get(needed)
            # This profile accepts only absolute Nix lookup paths. No cache,
            # default host paths, caller cwd or inherited environment supplies an edge.
            for directory in info['rpath']:
                if target is not None:
                    break
                root_of(directory)
                candidate = str(Path(directory)/needed)
                try:
                    target = resolve(candidate)
                except FileNotFoundError:
                    continue
                break
            require(target is not None, 'nix direct unresolved ELF edge')
            target_info = elf_info(selected[target][0])
            loaded[needed] = target
            if target_info['soname']:
                require(target_info['soname'] not in loaded or loaded[target_info['soname']] == target,
                        'nix direct conflicting SONAME')
                loaded[target_info['soname']] = target
            edges.append({'source_index':source,'needed':needed,'target_index':indexes[target]})
            require(len(edges) <= MAX_EDGES, 'nix direct edge cap')
            pending.append((indexes[target],target_info))
    old_names = names
    names = [name for index,name in enumerate(old_names) if index in visited]
    indexes = {name:index for index,name in enumerate(names)}
    for edge in edges:
        if edge['source_index'] != 255:
            edge['source_index'] = indexes[old_names[edge['source_index']]]
        edge['target_index'] = indexes[old_names[edge['target_index']]]
    required_roots = sorted({root_of(name) for name in [*names,*aliases,interpreter]})
    # Only the declared immutable bootstrap registration is consumed. Native
    # evaluation does not consult an ambient Nix daemon/database or run nix-store.
    from nix_interpreter_closure import registrations, reachable
    require(registration is not None and store_paths is not None,'nix direct declared registration missing')
    registration_raw = portable._read(registration,max_bytes=4*1024*1024)
    roots_raw = portable._read(store_paths,max_bytes=1024*1024)
    tick(until)
    declared_roots = roots_raw.decode('ascii').splitlines()
    require(len(declared_roots)==len(set(declared_roots)) and declared_roots==sorted(declared_roots),
            'nix direct declared registration roots')
    records = registrations(registration_raw.decode('ascii'),declared_roots)
    roots = reachable(records,required_roots)
    require(all(ROOT_RE.fullmatch(root) for root in roots), 'nix direct registered root namespace')
    require(len(roots) <= MAX_FILES, 'nix direct root cap')
    root_statuses = {}
    for root in roots:
        safe_parents(str(Path(root)/'witness'),until)
        root_statuses[root] = witness(os.lstat(root))
    registration_rows = []
    for root in roots:
        tick(until)
        refs = records[root]['references']
        require(len(refs) == len(set(refs)), 'nix direct registration duplicates')
        require(set(refs) <= set(roots), 'nix direct registration leaves declared closure')
        raw_row = records[root]['record']
        nar, size = raw_row[1], raw_row[2]
        require(re.fullmatch(r'sha256:(?:[0-9abcdfghijklmnpqrsvwxyz]{52}|[0-9a-f]{64})',nar)
                and size.isdigit() and int(size) > 0, 'nix direct declared nar fields')
        registration_rows.append({'path':root,'narHash':nar,'narSize':int(size),'references':sorted(refs)})
    rows = [{'path':name,'sha256':hashlib.sha256(selected[name][0]).hexdigest(),
             'bytes':len(selected[name][0]),'status':selected[name][1]} for name in names]
    require(sum(r['bytes'] for r in rows) <= MAX_BYTES, 'nix direct payload cap')
    proof = {'schema_version':1,'status':'registered-linux-nix-runtime-closure-proof-candidate',
             'native_support':False,'loader_lookup_qualified':False,
             'target':'x86_64-linux','original_interpreter':interpreter,
             'interpreter_file_index':indexes[loader],
             'roots':[{'path':root,'status':root_statuses[root]} for root in roots],
             'files':rows,'aliases':[aliases[p] for p in sorted(aliases)],'edges':edges,
             'registration_rows':registration_rows}
    # Re-read every selected byte and alias after queries; a query result never
    # excuses source drift. Deployment must requalify this local witness per host.
    for name in names:
        require(read_regular(name,until) == selected[name], 'nix direct terminal file drift')
    for alias in aliases.values():
        require(witness(os.lstat(alias['path'])) == alias['status'] and os.readlink(alias['path']) == alias['target'],
                'nix direct terminal alias drift')
    for root in roots:
        safe_parents(str(Path(root)/'witness'),until)
        require(witness(os.lstat(root)) == root_statuses[root], 'nix direct terminal root drift')
    ca = portable._read(ca_bundle)
    portable._verify_ca_bundle(ca)
    proof_bytes = (json.dumps(proof,sort_keys=True,indent=2)+'\n').encode('ascii')
    require(len(proof_bytes) <= 256*1024, 'nix direct proof bound')
    tick(until)
    files = {'bin/codex':launcher(),BACKEND:backend,CA:ca,LOADER:selected[loader][0]}
    info = {'launchProfile':PROFILE,'loader_lookup_qualified':False,'original_interpreter':interpreter,
            'registration_receipt_sha256':hashlib.sha256(proof_bytes).hexdigest(),
            'loader':LOADER,'dependencies':[LOADER],'caBundle':CA,
            'backendInterpreter':interpreter,'backend_max_bytes':512*1024*1024}
    return files,info,proof_bytes
