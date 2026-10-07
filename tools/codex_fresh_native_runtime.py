"""Fresh maintained Codex runtime producer and public chain/ELF validators.

Only the declared Bazel target may run main. No historical runtime receipts,
provider calls, installation, or original-source mutation are performed.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / 'delivery'))
sys.path.insert(0, str(_ROOT / 'integrations/codex-owner-runtime'))
import portable
import runtime_package as runtime
from codex_live_source import BASE_RECEIPT_SHA, BASE_INVENTORY, COMMIT
from codex_native_profile import QUALIFICATION_GATES, STATE, PRODUCTION
from codex_retained_sdk_export import SCHEMA as EXPORT_SCHEMA

KIND = 'omux-fresh-native-runtime-v1'
STATUS = 'experimental-qualified-native-runtime'
SELECTION_KIND = 'omux-fresh-native-package-selection-v1'
ROLES = frozenset(('source', 'export', 'compile', 'qualification_run',
    'qualification', 'qualification_xml', 'schema_run', 'config_schema', 'codex'))
JSON_ROLES = ROLES - {'codex', 'qualification_xml'}
MAX_METADATA = 256 * 1024 * 1024
MAX_PROTOCOL = 128 * 1024 * 1024
MAX_RUNTIME_FILES = 64
HASH = re.compile(r'[0-9a-f]{64}')
DEADLINE = None


def require(ok, message='fresh runtime contract refused'):
    if not ok:
        raise ValueError(message)


def tick():
    require(DEADLINE is None or time.monotonic() < DEADLINE,
        'fresh runtime deadline reached')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def unique(pairs):
    out = {}
    for name, value in pairs:
        require(name not in out, 'duplicate fresh runtime metadata key')
        out[name] = value
    return out


def parse(value):
    require(len(value) <= MAX_METADATA, 'fresh runtime metadata bound')
    return json.loads(value, object_pairs_hook=unique)


def canonical_path(value):
    require(isinstance(value, str) and value.startswith('/') and
        str(Path(value)) == value and '..' not in Path(value).parts and
        not any(c.isspace() or c in ':\\' for c in value),
        'fresh runtime canonical selected path required')
    return Path(value)


def trusted(path):
    path = canonical_path(str(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(path.parts[1:]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            shared = index < len(path.parts)-2 and info.st_mode & stat.S_ISVTX
            require(info.st_uid in (0, os.getuid()) and
                (not info.st_mode & 0o022 or shared), 'fresh runtime parent custody')
        require(os.fstat(fd).st_uid == os.getuid(), 'fresh runtime leaf directory ownership')
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_selected(path, pin, maximum):
    tick()
    require(set(pin) == {'path', 'sha256', 'bytes'} and
        HASH.fullmatch(pin['sha256']) and type(pin['bytes']) is int and
        0 <= pin['bytes'] <= maximum and str(path) == pin['path'],
        'fresh runtime selected file pin')
    parent = trusted(path.parent)
    try:
        child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(child)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                not before.st_mode & 0o022 and before.st_size == pin['bytes'],
                'fresh runtime selected file custody')
            values, count = [], 0
            while True:
                tick()
                value = os.read(child, 1024 * 1024)
                if not value:
                    break
                count += len(value)
                require(count <= maximum, 'fresh runtime file bound')
                values.append(value)
            after = os.fstat(child)
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'fresh runtime selected bytes changed')
            value = b''.join(values)
            require(count == pin['bytes'] and digest(value) == pin['sha256'],
                'fresh runtime selected bytes differ')
            return value
        finally:
            os.close(child)
    finally:
        os.close(parent)


def output_file(root, name, value, mode):
    path = root / name
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = trusted(path.parent)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def validate_selection_paths(selection):
    """Refuse reads outside the exact public producer/guard output namespaces."""
    home = '/home/jess/.local/state/omux-execution-20261005/'
    require(selection['kind'] == SELECTION_KIND and set(selection['files']) == ROLES,
        'fresh runtime exact operator selection roles')
    for role, pin in selection['files'].items():
        path = str(canonical_path(pin['path']))
        if role in ('source','export'):
            suffix = ('/tools/codex_live_source_producer/test.outputs/codex-live-source/source-receipt.json'
                if role=='source' else '/tools/codex_retained_sdk_export_producer/test.outputs/sdk-private/sdk-export/receipt.json')
            require(path.startswith(home) and
                '/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs' in path and
                path.endswith(suffix), 'fresh runtime source/export public output scope')
        elif role in ('compile','qualification_run','schema_run','qualification','qualification_xml'):
            relative = canonical_path(path).relative_to(STATE)
            leaf = ('native-qualification.json' if role=='qualification' else
                'native-qualification.xml' if role=='qualification_xml' else 'receipt.json')
            require(len(relative.parts)==2 and relative.parts[1]==leaf and
                re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',relative.parts[0]),
                'fresh runtime guarded public metadata scope')
        else:
            relative = canonical_path(path).relative_to(STATE)
            suffix = 'codex-rs/cli/codex' if role=='codex' else 'bazel/schema/native-config.schema.json'
            require(len(relative.parts)>=8 and re.fullmatch(r'cache-v2-[0-9a-f]{64}',relative.parts[0]) and
                relative.parts[1:5]==('output-base','execroot','_main','bazel-out') and
                re.fullmatch(r'[A-Za-z0-9_.-]+-opt',relative.parts[5]) and relative.parts[6]=='bin'
                and '/'.join(relative.parts[7:])==suffix, 'fresh runtime exact declared binary/schema scope')
    for name, pin in selection['protocol_schema_files'].items():
        path = canonical_path(pin['path'])
        relative = path.relative_to(STATE)
        parts = PurePosixPath(name).parts
        require(len(parts)>=3 and parts[0] in ('stable','experimental') and parts[1]=='json'
            and str(PurePosixPath(name))==name and not any(p in ('','.','..') for p in parts)
            and name.endswith('.json') and len(relative.parts)>=12 and
            re.fullmatch(r'cache-v2-[0-9a-f]{64}',relative.parts[0]) and
            relative.parts[1:5]==('output-base','execroot','_main','bazel-out') and
            re.fullmatch(r'[A-Za-z0-9_.-]+-opt',relative.parts[5]) and relative.parts[6:9]==('bin','bazel','schema')
            and relative.parts[9]=='public-schema-bundle.'+parts[0] and
            '/'.join(relative.parts[10:])=='/'.join(parts[1:]), 'fresh runtime exact public protocol JSON scope')


def validate_protocol_inventory(selection):
    """Enumerate only the complete two declared public JSON schema subtrees."""
    roots = selection['protocol_schema_roots']
    require(set(roots) == {'stable','experimental'}, 'fresh protocol JSON root modes differ')
    observed = set()
    for mode, value in roots.items():
        root = canonical_path(value)
        relative = root.relative_to(STATE)
        require(len(relative.parts) == 11 and re.fullmatch(r'cache-v2-[0-9a-f]{64}', relative.parts[0])
            and relative.parts[1:5] == ('output-base','execroot','_main','bazel-out')
            and re.fullmatch(r'[A-Za-z0-9_.-]+-opt', relative.parts[5])
            and relative.parts[6:] == ('bin','bazel','schema','public-schema-bundle.'+mode,'json'),
            'fresh protocol JSON root leaves declared native schema output')
        fd = trusted(root)
        def walk(parent, prefix=''):
            for name in sorted(os.listdir(parent)):
                tick()
                require(name not in ('','.','..') and '/' not in name and
                    not any(c in name for c in '\\\0\r\n\t'), 'fresh protocol JSON member name')
                info = os.stat(name,dir_fd=parent,follow_symlinks=False)
                require(info.st_uid == os.getuid() and not info.st_mode & 0o022,
                    'fresh protocol JSON member custody')
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                    try:
                        walk(child,prefix+name+'/')
                    finally:
                        os.close(child)
                else:
                    require(stat.S_ISREG(info.st_mode) and name.endswith('.json'),
                        'fresh protocol JSON foreign member')
                    observed.add(mode+'/json/'+prefix+name)
                    require(len(observed) <= 4096, 'fresh protocol JSON inventory bound')
        try:
            walk(fd)
        finally:
            os.close(fd)
    require(observed == set(selection['protocol_schema_files']),
        'fresh protocol JSON subtree complete membership differs')


def validate_chain(selection, values, protocol_values):
    """Consume independently selected source/build/test/schema evidence bytes."""
    validate_selection_paths(selection)
    require(selection['kind'] == SELECTION_KIND and set(selection['files']) == ROLES
        and set(values) == ROLES, 'fresh runtime exact input roles')
    for role, value in values.items():
        pin = selection['files'][role]
        require(digest(value) == pin['sha256'] and len(value) == pin['bytes'],
            'fresh runtime chain input byte pins differ')
    require(set(protocol_values) == set(selection['protocol_schema_files']),
        'fresh runtime selected protocol byte roles differ')
    for name, value in protocol_values.items():
        pin = selection['protocol_schema_files'][name]
        require(digest(value) == pin['sha256'] and len(value) == pin['bytes']
            and isinstance(parse(value),dict), 'fresh runtime protocol byte pins differ')
    source, exported = parse(values['source']), parse(values['export'])
    pins = selection['patch_sha256']
    require(len(pins) == 3 and all(HASH.fullmatch(p) for p in pins),
        'fresh runtime three native patches required')
    require(source['status'] == 'verified-fresh-native-candidate' and source['commit'] == COMMIT
        and source['baseline_receipt_sha256'] == BASE_RECEIPT_SHA
        and source['baseline_inventory_sha256'] == BASE_INVENTORY
        and source['patch_sha256'] == pins
        and all(source[k] is False for k in ('native_support', 'native_compile_passed', 'provider_evaluation')),
        'fresh runtime source binding differs')
    inventory = source['source_inventory']
    require(len(inventory) == source['tracked_files'] and
        digest(json.dumps(inventory, sort_keys=True).encode()) == source['inventory_sha256'],
        'fresh runtime source inventory digest differs')
    require(exported['schema'] == EXPORT_SCHEMA and exported['qualification_only'] is False
        and exported['baseline_inventory_sha256'] == BASE_INVENTORY
        and exported['graph_files'] == source['baseline_graph_files'],
        'fresh runtime retained SDK binding differs')
    source_root = canonical_path(selection['source_root'])
    export_root = canonical_path(selection['export_root'])
    require(selection['files']['source']['path'] == str(source_root/'source-receipt.json')
        and selection['files']['export']['path'] == str(export_root/'receipt.json'),
        'fresh runtime source/export selected receipt paths differ')
    declaration = source['native_schema_declaration']
    require(declaration['target'] == '//bazel/schema:native-config-schema'
        and declaration['before_sha256'] == '9e047e20da76b99608595a8abfb23b5e8633c5ba454f2de548b8e70744c72df6'
        and inventory[declaration['path']]['sha256'] == declaration['after_sha256'],
        'fresh runtime generated schema source declaration differs')
    receipts = {}
    cache = None
    for role, mode, targets in (
            ('compile', 'cli-opt', ('//codex-rs/cli:codex',)),
            ('qualification_run', 'qualification', tuple(QUALIFICATION_GATES)),
            ('schema_run', 'schema', ('//bazel/schema:native-config-schema', '//bazel/schema:public-schema-bundle'))):
        value = parse(values[role])
        require(value['profile'] == 'codex-native' and value['exit'] == value['workload_exit'] == 0
            and value['descendants_empty'] is True and value['controller_failure'] is None
            and value['native_sdk']['mode'] == mode
            and value['native_sdk']['source_and_export_verified_after_cleanup'] is True
            and value['native_sdk']['source_receipt_sha256'] == selection['files']['source']['sha256']
            and value['native_sdk']['export_receipt_sha256'] == selection['files']['export']['sha256']
            and set(value['targets']) == set(targets) and len(value['targets']) == len(targets),
            'fresh runtime successful guarded action join differs')
        candidate = value['native_candidate_cache']
        require(candidate is not None and candidate['max_attempts'] == 6
            and type(candidate['attempt']) is int and 1 <= candidate['attempt'] <= 6
            and HASH.fullmatch(candidate['key']) and HASH.fullmatch(candidate['provenance_sha256']),
            'fresh runtime owned candidate provenance missing')
        key = (candidate['key'], candidate['provenance_sha256'], candidate['workspace'], candidate['output_base'])
        require(cache is None or cache == key, 'fresh runtime different candidate action chains')
        cache = key
        require(canonical_path(candidate['output_base']) == STATE/('cache-v2-'+candidate['key'])/'output-base'
            and value['native_sdk']['plan']['candidate_output_base'] == candidate['output_base']
            and value['native_sdk']['plan']['source_inventory_sha256'] == source['inventory_sha256']
            and value['native_sdk']['plan']['export_inventory_sha256'] == exported['inventory_sha256'],
            'fresh runtime actual output base/source/export join differs')
        receipt_path = canonical_path(selection['files'][role]['path'])
        require(receipt_path == STATE/value['id']/'receipt.json',
            'fresh runtime guarded action receipt path differs')
        receipts[role] = value
    require(len({r['native_candidate_cache']['attempt'] for r in receipts.values()}) == 3,
        'fresh runtime distinct selected guarded actions required')
    group = parse(values['qualification'])
    require(group['schema'] == 'omux-native-grouped-qualification-v1'
        and group['passed'] == 14 and group['failed'] == group['ignored'] == 0
        and group['native_support'] is False and group['provider_evaluation'] is False
        and group['xml_sha256'] == digest(values['qualification_xml'])
        and set(group['targets']) == set(QUALIFICATION_GATES),
        'fresh runtime grouped14 qualification differs')
    qualified_root = STATE/receipts['qualification_run']['id']
    require(selection['files']['qualification']['path'] == str(qualified_root/'native-qualification.json')
        and selection['files']['qualification_xml']['path'] == str(qualified_root/'native-qualification.xml'),
        'fresh runtime qualification output path differs')
    xml = ET.fromstring(values['qualification_xml'])
    require(xml.tag == 'testsuites' and xml.attrib == {'tests':'14','failures':'0','errors':'0','skipped':'0'},
        'fresh runtime grouped XML counts differ')
    suites = xml.findall('testsuite')
    require(len(suites) == 3 and {s.get('name') for s in suites} == set(QUALIFICATION_GATES),
        'fresh runtime grouped XML targets differ')
    for target, names in QUALIFICATION_GATES.items():
        row = group['targets'][target]
        require(row['tests'] == sorted(names) and HASH.fullmatch(row['log_sha256']),
            'fresh runtime exact grouped gate names differ')
        suite = next(s for s in suites if s.get('name') == target)
        cases = suite.findall('testcase')
        require(suite.get('tests') == str(len(names)) and
            all(suite.get(k) == '0' for k in ('failures','errors','skipped')) and
            len(cases) == len(names) and sorted(c.get('name') for c in cases) == sorted(names)
            and all(c.get('classname') == target and len(c) == 0 for c in cases),
            'fresh runtime exact grouped XML gates differ')
        props = suite.findall('properties/property')
        require(len(props) == 1 and props[0].attrib ==
            {'name':'actual_test_log_sha256','value':row['log_sha256']},
            'fresh runtime grouped XML log binding differs')
    output_base = canonical_path(cache[3])
    def artifact(path, suffix):
        path = canonical_path(path)
        relative = path.relative_to(output_base/'execroot/_main/bazel-out')
        require(len(relative.parts) >= 3 and re.fullmatch(r'[A-Za-z0-9_.-]+-opt', relative.parts[0])
            and relative.parts[1] == 'bin' and '/'.join(relative.parts[2:]) == suffix,
            'fresh runtime declared generated artifact path differs')
        return relative.parts[0]
    config = artifact(selection['files']['codex']['path'], 'codex-rs/cli/codex')
    require(artifact(selection['files']['config_schema']['path'], 'bazel/schema/native-config.schema.json') == config,
        'fresh runtime selected configurations differ')
    config_schema = parse(values['config_schema'])
    definitions = config_schema.get('definitions', config_schema.get('$defs', {}))
    require(definitions['OmuxBrokerContextMode']['enum'] == ['full_native','text_transcript_v1']
        and definitions['OmuxBrokerConfig']['properties']['context_mode']['default'] == 'full_native',
        'fresh runtime generated config policy missing')
    schema_files = selection['protocol_schema_files']
    require(isinstance(schema_files, dict) and 0 < len(schema_files) <= 4096
        and {'stable', 'experimental'} == {name.split('/')[0] for name in schema_files},
        'fresh runtime protocol schema modes missing')
    for name, pin in schema_files.items():
        parts = PurePosixPath(name).parts
        require(len(parts) >= 3 and parts[1] == 'json' and str(PurePosixPath(name)) == name and
            not any(p in ('', '.', '..') for p in parts) and name.endswith('.json'),
            'fresh runtime protocol schema selected name differs')
        suffix = 'bazel/schema/public-schema-bundle.'+parts[0]+'/'+('/'.join(parts[1:]))
        require(artifact(pin['path'], suffix) == config,
            'fresh runtime protocol schema generated output join differs')
    require(set(selection['protocol_schema_roots']) == {'stable','experimental'} and all(
        selection['protocol_schema_roots'][mode] == str(output_base/'execroot/_main/bazel-out'/config/'bin/bazel/schema'/('public-schema-bundle.'+mode)/'json')
        for mode in ('stable','experimental')), 'fresh runtime protocol JSON root join differs')
    return {'upstream_commit': COMMIT, 'patch_sha256': pins,
        'source_inventory_sha256':source['inventory_sha256'],
        'export_inventory_sha256':exported['inventory_sha256'],
        'candidate_cache_key':cache[0], 'candidate_provenance_sha256':cache[1],
        'configuration':config,
        'compile_invocation_id':receipts['compile']['id'],
        'qualification_invocation_id':receipts['qualification_run']['id'],
        'schema_invocation_id':receipts['schema_run']['id'],
        'input_files': selection['files'], 'protocol_schema_files':schema_files,
        'protocol_schema_roots':selection['protocol_schema_roots'],
        'qualified_tests':group['targets']}


def verify_runtime_files(payload, receipt):
    """Check this fresh manifest plus every portable ELF dependency edge."""
    require(receipt['kind'] == KIND and receipt['status'] == STATUS and
        receipt['native_support'] is False and receipt['provider_evaluation'] is False
        and receipt['experimental_text_policy_compiled'] is True and
        len(payload) == receipt['archive_bytes'] and digest(payload) == receipt['archive_sha256']
        and len(payload) <= runtime.MAX_ARCHIVE_BYTES, 'fresh runtime archive receipt differs')
    with gzip.GzipFile(fileobj=io.BytesIO(payload)) as stream:
        raw = stream.read(runtime.MAX_RUNTIME_BYTES + runtime.MAX_METADATA_BYTES + 1)
    require(len(raw) <= runtime.MAX_RUNTIME_BYTES + runtime.MAX_METADATA_BYTES,
        'fresh runtime decompression bound')
    files, modes = {}, {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            name = member.name
            bound = runtime.MAX_BACKEND_BYTES if name == runtime.BACKEND else (
                runtime.MAX_METADATA_BYTES if name == runtime.MANIFEST else portable._MAX_FILE)
            require(member.isfile() and name not in files and len(files) <= MAX_RUNTIME_FILES
                and str(PurePosixPath(name)) == name and not name.startswith('/')
                and not any(p in ('', '.', '..') for p in PurePosixPath(name).parts)
                and not any(c in name for c in '\\\0\r\n\t') and 0 <= member.size <= bound
                and member.mode in (0o644,0o755), 'fresh runtime unsafe archive member')
            value = archive.extractfile(member).read(bound+1)
            require(len(value) == member.size, 'fresh runtime truncated archive member')
            files[name], modes[name] = value, member.mode
    require(digest(files[runtime.MANIFEST]) == receipt['manifest_sha256']
        and modes[runtime.MANIFEST] == 0o644, 'fresh runtime manifest pin differs')
    manifest = parse(files[runtime.MANIFEST])
    require(manifest['kind'] == KIND and manifest['status'] == STATUS and
        manifest['native_support'] is False and manifest['provider_evaluation'] is False
        and manifest['experimental_text_policy_compiled'] is True
        and manifest['chain'] == receipt['chain'] and manifest['executable'] == receipt['executable']
        and manifest['selection_sha256'] == receipt['selection_sha256']
        and manifest['producer_source_sha256'] == receipt['producer_source_sha256']
        and manifest['producer_target'] == receipt['producer_target'] == '//tools:codex_fresh_native_runtime_package',
        'fresh runtime manifest identity differs')
    require(set(files) == set(manifest['files']) | {runtime.MANIFEST}
        and sum(len(v) for n,v in files.items() if n != runtime.MANIFEST) <= runtime.MAX_RUNTIME_BYTES,
        'fresh runtime exact membership differs')
    for name, row in manifest['files'].items():
        require(row == {'sha256':digest(files[name]),'bytes':len(files[name]),'mode':modes[name]},
            'fresh runtime archive member bytes differ')
    require(receipt['runtime_inventory'] == {n:{'sha256':row['sha256'],'bytes':row['bytes'],
        'mode':0o444 if n==runtime.CA else 0o555} for n,row in manifest['files'].items()},
        'fresh runtime sealed inventory differs')
    info = manifest['runtime']
    dependencies = info['dependencies']
    require(dependencies == sorted(set(dependencies)) and 0 < len(dependencies) < MAX_RUNTIME_FILES
        and info['loader'] in dependencies and info['caBundle'] == runtime.CA
        and info['backendInterpreter'] == portable._BACKEND_INTERPRETER
        and set(files) == {runtime.MANIFEST,'bin/codex',runtime.BACKEND,runtime.CA,*dependencies},
        'fresh runtime closed dependency membership differs')
    names = {Path(n).name for n in dependencies}
    for name in [runtime.BACKEND,*dependencies]:
        require(name == runtime.BACKEND or name == runtime.PREFIX+'lib/'+portable._basename(name),
            'fresh runtime dependency leaves library directory')
        metadata = portable.elf_metadata(files[name],
            max_bytes=runtime.MAX_BACKEND_BYTES if name == runtime.BACKEND else portable._MAX_FILE)
        require(metadata['machine'] == 62 and all('/' not in n and n in names for n in metadata['needed']),
            'fresh runtime ELF edge leaves closed graph')
        if name == runtime.BACKEND:
            require(metadata['interpreter'] == portable._BACKEND_INTERPRETER and
                metadata['rpath'] == ['$ORIGIN/../lib'], 'fresh runtime backend lookup differs')
        else:
            require(metadata['interpreter'] in (None, portable._BACKEND_INTERPRETER) and
                all(n == '$ORIGIN' for n in metadata['rpath']), 'fresh runtime library lookup differs')
    require(files['bin/codex'] == runtime.codex_launcher(Path(info['loader']).name),
        'fresh runtime fixed launcher differs')
    portable._verify_ca_bundle(files[runtime.CA])
    require(digest(files[runtime.BACKEND]) == receipt['executable']['packaged_sha256']
        and len(files[runtime.BACKEND]) == receipt['executable']['packaged_bytes'],
        'fresh runtime packaged backend differs')
    return manifest, {n:v for n,v in files.items() if n != runtime.MANIFEST}


def package(selection, values, protocol_values, runtime_files, args, output):
    validate_protocol_inventory(selection)
    chain = validate_chain(selection, values, protocol_values)
    original = values['codex']
    require(0 < len(original) <= runtime.MAX_ORIGINAL_BYTES,
        'fresh runtime original backend bound')
    private = output/'.transform'
    private.mkdir(mode=0o700)
    try:
        copied = private/'codex'
        output_file(private, 'codex', original, 0o755)
        runtime.run_tool([str(args.strip), '--strip-all', str(copied)], args.tool_path)
        stripped = portable._read(copied, max_bytes=runtime.MAX_BACKEND_BYTES)
        metadata = portable.elf_metadata(stripped, max_bytes=runtime.MAX_BACKEND_BYTES)
        loader, witness = runtime.select_loader(metadata, runtime_files)
        runtime.run_tool([str(args.patchelf), '--set-interpreter', str(loader), str(copied)], args.tool_path)
        files, runtime_info = runtime.assemble_runtime(copied, runtime_files, args.patchelf, args.ca_bundle)
    finally:
        if (private/'codex').exists():
            (private/'codex').unlink()
        private.rmdir()
    executable = {'backend_max_bytes':runtime.MAX_BACKEND_BYTES,
        'original_sha256':digest(original),'original_bytes':len(original),
        'stripped_sha256':digest(stripped),'stripped_bytes':len(stripped),
        'packaged_sha256':digest(files[runtime.BACKEND]),'packaged_bytes':len(files[runtime.BACKEND])}
    inventory = {name:{'sha256':digest(v),'bytes':len(v),'mode':0o644 if name==runtime.CA else 0o755}
        for name,v in sorted(files.items())}
    require(0 < len(inventory) <= MAX_RUNTIME_FILES, 'fresh runtime finite file count')
    manifest = {'schema_version':1,'kind':KIND,'status':STATUS,'target':'x86_64-linux',
        'native_support':False,'provider_evaluation':False,'experimental_text_policy_compiled':True,
        'chain':chain,'executable':executable,'runtime':runtime_info,'files':inventory,
        'selection_sha256':args.selected_sha256,
        'producer_source_sha256':digest(Path(__file__).read_bytes()),
        'producer_target':'//tools:codex_fresh_native_runtime_package',
        'loader_relocation':witness,
        'declared_tools':{'strip_sha256':digest(portable._read(args.strip.resolve())),
            'patchelf_sha256':digest(portable._read(args.patchelf.resolve()))}}
    payload = runtime.archive_bytes(files, manifest)
    receipt = {'schema_version':1,'kind':KIND,'status':STATUS,
        'native_support':False,'provider_evaluation':False,'experimental_text_policy_compiled':True,
        'chain':chain,'executable':executable,'runtime':runtime_info,
        'selection_sha256':args.selected_sha256,
        'producer_source_sha256':manifest['producer_source_sha256'],
        'producer_target':'//tools:codex_fresh_native_runtime_package',
        'archive_sha256':digest(payload),'archive_bytes':len(payload),
        'manifest_sha256':digest(encoded(manifest)),
        'runtime_inventory':{n:{'sha256':r['sha256'],'bytes':r['bytes'],
            'mode':0o444 if n==runtime.CA else 0o555} for n,r in inventory.items()},
        'scope':'Fresh experimental maintained native carrier; no provider or seamless handoff proof.'}
    # archive_bytes uses the existing deterministic json_bytes representation.
    require(runtime.json_bytes(manifest) == encoded(manifest), 'fresh manifest canonical encoding differs')
    verify_runtime_files(payload, receipt)
    root = output/executable['packaged_sha256']
    root.mkdir(mode=0o700)
    output_file(root, 'codex', files[runtime.BACKEND], 0o555)
    for name, value in files.items():
        output_file(root, 'runtime/'+name, value, 0o444 if name==runtime.CA else 0o555)
    output_file(root, 'native-source-receipt.json', encoded(receipt), 0o444)
    for folder, _, _ in os.walk(root, topdown=False, followlinks=False):
        os.chmod(folder, 0o555, follow_symlinks=False)
    require({p.name for p in root.iterdir()} == {'codex','runtime','native-source-receipt.json'},
        'fresh runtime digest directory membership differs')
    for name, row in receipt['runtime_inventory'].items():
        path = root/'runtime'/name
        require(path.stat().st_mode & 0o777 == row['mode'] and
            read_selected(path, {'path':str(path),'sha256':row['sha256'],'bytes':row['bytes']}, runtime.MAX_BACKEND_BYTES) == files[name],
            'fresh runtime sealed readback differs')
    require(root.name == digest(read_selected(root/'codex',
        {'path':str(root/'codex'),'sha256':executable['packaged_sha256'],'bytes':executable['packaged_bytes']},
        runtime.MAX_BACKEND_BYTES)), 'fresh runtime digest leaf differs')
    require(read_selected(root/'native-source-receipt.json',
        {'path':str(root/'native-source-receipt.json'),'sha256':digest(encoded(receipt)),'bytes':len(encoded(receipt))},
        MAX_METADATA) == encoded(receipt), 'fresh runtime duplicate receipt readback differs')
    for role,pin in selection['files'].items():
        read_selected(canonical_path(pin['path']),pin,
            runtime.MAX_ORIGINAL_BYTES if role=='codex' else MAX_METADATA)
    for pin in selection['protocol_schema_files'].values():
        read_selected(canonical_path(pin['path']),pin,MAX_METADATA)
    validate_protocol_inventory(selection)
    output_file(output, 'fresh-native-runtime.tar.gz', payload, 0o444)
    output_file(output, 'runtime-manifest.json', encoded(manifest), 0o444)
    output_file(output, 'runtime-receipt.json', encoded(receipt), 0o444)
    return receipt


def main():
    global DEADLINE
    DEADLINE = time.monotonic()+900
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for name in ('selection','selection-sha-file','input-aliases','strip','patchelf',
            'ca-bundle','runtime-files-manifest'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--tool-path',required=True)
    args = parser.parse_args()
    root = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True)
    parent = trusted(root)
    try:
        os.mkdir('fresh-native-runtime',0o700,dir_fd=parent)
    finally:
        os.close(parent)
    output = root/'fresh-native-runtime'
    sha = args.selection_sha_file.read_text().strip()
    require(HASH.fullmatch(sha), 'fresh runtime independently selected metadata SHA')
    selection_raw = args.selection.read_bytes()
    require(len(selection_raw) <= MAX_METADATA and digest(selection_raw) == sha,
        'fresh runtime selected operator declaration differs')
    selection = parse(selection_raw)
    validate_selection_paths(selection)
    aliases = parse(args.input_aliases.read_bytes())
    entries = {**selection['files'],
        **{'protocol/'+n:p for n,p in selection['protocol_schema_files'].items()}}
    require(set(aliases) == set(entries), 'fresh runtime declared input aliases differ')
    values, protocol_values, protocol_bytes = {}, {}, 0
    args.selected_sha256 = sha
    runfiles = _ROOT.parent
    for role, pin in entries.items():
        alias = runfiles/aliases[role]
        path = alias.resolve(strict=True)
        require(str(path) == pin['path'], 'fresh runtime declared alias resolution differs')
        maximum = runtime.MAX_ORIGINAL_BYTES if role=='codex' else MAX_METADATA
        value = read_selected(path,pin,maximum)
        if role.startswith('protocol/'):
            protocol_bytes += len(value)
            require(protocol_bytes <= MAX_PROTOCOL, 'fresh protocol schema aggregate bound')
            require(isinstance(parse(value),dict), 'fresh protocol schema is not JSON object')
            protocol_values[role.removeprefix('protocol/')] = value
        else:
            values[role] = value
    runtime_files = runtime.read_runtime_inputs(args.runtime_files_manifest, runfiles)
    require(sum(p.stat().st_size for p in runtime_files) <= runtime.MAX_DECLARED_RUNTIME_BYTES,
        'fresh declared runtime library bound')
    receipt = package(selection,values,protocol_values,runtime_files,args,output)
    # Prove all selected original inputs remain byte-identical after packaging.
    for role,pin in entries.items():
        read_selected(canonical_path(pin['path']),pin,
            runtime.MAX_ORIGINAL_BYTES if role=='codex' else MAX_METADATA)
    print('fresh experimental native runtime package completed; provider proof unrun')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError,
            tarfile.TarError, ET.ParseError):
        print('fresh native runtime producer refused',file=sys.stderr)
        raise SystemExit(1) from None
