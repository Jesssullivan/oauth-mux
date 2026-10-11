"""Disjoint ninth compiler producer and retained readback; never spends a ledger.

Only the exact guarded Bazel TEST producer may launch its single cold child.
Missing actual Root/plan/query/output selections refuse rather than mint pins.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import subprocess
import sys
from types import SimpleNamespace
import xml.etree.ElementTree as ET

KIND = 'omux-native-acquisition-compilation-v1'
SELECTION_KIND = KIND + '-selection'
TARGETS = ('//codex-rs/core:core-unit-tests', '//codex-rs/config:config-unit-tests',
    '//codex-rs/login:login-unit-tests', '//codex-rs/cli:codex',
    '//bazel/schema:native-config-schema', '//bazel/schema:public-schema-bundle')
CAPS = {'seconds':1200, 'call_seconds':15, 'cleanup_seconds':30,
    'memory_bytes':4026531840, 'tasks':480, 'cpu_percent':190, 'swap_bytes':0,
    'resident_reservation_required':True}
HASH = re.compile(r'[0-9a-f]{64}\Z')
PUBLIC_ROOT=Path('/srv/fast-local/jess/git/oauth-mux')
GOAL_SNAPSHOT_PREFIX='docs/agent-notes/2026-10-10-native-acquisition-input-lift.UNAPPLIED/ledger-snapshots/'

def require(value):
    if value is not True:
        raise ValueError('native-acquisition-compilation-refused')

def tick(deadline):
    require(type(deadline) is float and time.monotonic() < deadline)

def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'

def unique(pairs):
    result = {}
    for key,value in pairs:
        require(key not in result)
        result[key] = value
    return result

def read_bytes(path, pin, deadline, maximum=64*1024*1024):
    tick(deadline)
    require(type(pin) is str and HASH.fullmatch(pin) is not None)
    path=Path(path)
    require(path.is_absolute() and '..' not in path.parts)
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            tick(deadline)
            following=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            os.close(parent);parent=following
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
    finally:os.close(parent)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) in (0o444,0o555)
            and 0 < before.st_size <= maximum)
        chunks=[]; size=0
        while True:
            tick(deadline)
            raw=os.read(fd,min(1024*1024,maximum+1-size))
            if not raw: break
            chunks.append(raw); size+=len(raw); require(size<=maximum)
        after=os.fstat(fd)
        require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
            == (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns))
        raw=b''.join(chunks)
        require(hashlib.sha256(raw).hexdigest()==pin)
        return raw
    finally: os.close(fd)

def read_json(path,pin,deadline,maximum=64*1024*1024):
    return json.loads(read_bytes(path,pin,deadline,maximum),object_pairs_hook=unique)

def selected_document(path,pin,deadline):
    value=read_json(path,pin,deadline,1024*1024)
    require(type(value) is dict and set(value)=={'schema_version','kind','material',
        'ledger','plan','query','controller_inventory_sha256'}
        and type(value['schema_version']) is int and value['schema_version']==1
        and value['kind']==SELECTION_KIND)
    for role in ('ledger','plan','query'):
        row=value[role]
        require(type(row) is dict and set(row)==({'path','sha256'} if role=='ledger' else {'path','sha256','producer'})
            and type(row['path']) is str and Path(row['path']).is_absolute()
            and type(row['sha256']) is str and HASH.fullmatch(row['sha256']) is not None)
    require(type(value['controller_inventory_sha256']) is str
        and HASH.fullmatch(value['controller_inventory_sha256']) is not None)
    return value

def ledger(document,deadline):
    row=document['ledger']; value=read_json(row['path'],row['sha256'],deadline,1024*1024)
    require(type(value) is dict and set(value)=={'schema_version','kind','actor',
        'phase','aggregate','dispatched','remaining','material_sha256','controller_inventory_sha256',
        'goal_snapshot','compiler_controller'}
        and type(value['schema_version']) is int and value['schema_version']==1
        and value['kind']=='omux-native-acquisition-root-dispatch-ledger-v1'
        and value['actor']=='Root' and value['phase']=='after-pre-action-advancement'
        and all(type(value[name]) is int for name in ('aggregate','dispatched','remaining'))
        and (value['aggregate'],value['dispatched'],value['remaining'])==(8,8,0)
        and value['material_sha256']==hashlib.sha256(encoded(document['material'])).hexdigest()
        and value['controller_inventory_sha256']==document['controller_inventory_sha256'])
    controller=value['compiler_controller']
    require(type(controller) is dict and set(controller)=={'source_commit','graph_sha256'}
        and type(controller['source_commit']) is str
        and re.fullmatch(r'[0-9a-f]{40}',controller['source_commit']) is not None
        and type(controller['graph_sha256']) is str and HASH.fullmatch(controller['graph_sha256']) is not None)
    snapshot=value['goal_snapshot']
    require(type(snapshot) is dict and set(snapshot)=={'path','sha256','bytes'}
        and type(snapshot['sha256']) is str and HASH.fullmatch(snapshot['sha256']) is not None
        and type(snapshot['bytes']) is int and 0<snapshot['bytes']<=8*1024*1024
        and type(snapshot['path']) is str
        and snapshot['path']==GOAL_SNAPSHOT_PREFIX+snapshot['sha256']+'.json')
    # Classify the exact canonical public relative namespace before any parent IO.
    raw=read_bytes(PUBLIC_ROOT/snapshot['path'],snapshot['sha256'],deadline,8*1024*1024)
    require(len(raw)==snapshot['bytes'])
    full=json.loads(raw,object_pairs_hook=unique)
    require(type(full) is dict and type(full.get('native_dispatch_ledger')) is dict)
    actual=full['native_dispatch_ledger']
    require(all(type(actual.get(field)) is int for field in
        ('aggregate_maximum','dispatched','current_dispatch','remaining'))
        and tuple(actual[field] for field in ('aggregate_maximum','dispatched','current_dispatch','remaining'))
        ==(8,8,8,0))
    return value

def prerequisites(document,deadline,material_verifier):
    """Real qualified plan/query receipts; selection alone confers no authority."""
    tick(deadline); snapshot=ledger(document,deadline)
    material=material_verifier(document['material'],deadline)
    require(type(material) is dict and set(material)=={'source_inventory_sha256',
        'sdk_inventory_sha256','mapping_sha256','patch_sha256'}
        and type(material['patch_sha256']) is list and len(material['patch_sha256'])==9
        and all(type(pin) is str and HASH.fullmatch(pin) is not None
            for pin in material['patch_sha256']+ [material['source_inventory_sha256'],
                material['sdk_inventory_sha256'],material['mapping_sha256']]))
    require(controller_inputs(material,deadline)==document['controller_inventory_sha256'])
    evidence={}
    for role in ('plan','query'):
        row=document[role]
        import codex_native_acquisition_material as ninth
        outer=ninth.producer_success({'root':str(Path(row['path']).parent),'producer':row['producer']},
            '//tools:codex_native_acquisition_'+role+'_producer','native-acquisition-'+role,deadline)
        # producer_success verifies this role's independently pinned actor/graph.
        # The source/SDK actor in material is not the later compiler actor.
        value=read_json(row['path'],row['sha256'],deadline)
        require(type(value) is dict and set(value)=={'schema_version','kind','material',
            'controller_inventory_sha256','caps','verb','targets','qualified','exit','closure_rechecked'}
            and type(value['schema_version']) is int and value['schema_version']==1
            and value['kind']=='omux-native-acquisition-'+role+'-qualification-v1'
            and value['material']==material and value['caps']==CAPS
            and value['controller_inventory_sha256']==document['controller_inventory_sha256']
            and value['verb']=='test' and value['targets']==list(TARGETS)
            and value['qualified'] is True and type(value['exit']) is int and value['exit']==0
            and value['closure_rechecked'] is True)
        evidence[role]=value
    tick(deadline)
    require(ledger(document,deadline)==snapshot
        and controller_inputs(material,deadline)==document['controller_inventory_sha256'])
    return material,evidence

def controller_inputs(material,deadline):
    import codex_native_acquisition_metadata as producer
    tick(deadline);require(producer.QUERY_REPOSITORY is not None)
    qualified=producer.query_tools.verify_repository(producer.QUERY_REPOSITORY,deadline)
    require(qualified['inputs_rechecked'] is True)
    value={'schema_version':1,'kind':'omux-native-acquisition-controller-inputs-v1',
        'query_selection_sha256':qualified['selection_sha256'],
        'query_mapping_sha256':qualified['mapping_sha256'],
        'query_tools':qualified['query_tools'],'material':material}
    return producer.source.sha(producer.source.encoded(value))

def qualify_material(selection,deadline):
    import codex_native_acquisition_material as ninth
    source,files,parent,report,mappings=ninth.qualify_selection(selection,deadline)
    require(len(source['patch_sha256'])==9 and bool(files)
        and report['source_inventory_sha256']==source['inventory_sha256'])
    return {'source_inventory_sha256':source['inventory_sha256'],
        'sdk_inventory_sha256':report['inventory_sha256'],
        'mapping_sha256':report['mapping_sha256'],'patch_sha256':source['patch_sha256']}

def artifact(row,deadline):
    require(type(row) is dict and set(row)=={'path','sha256','bytes','role'}
        and type(row['path']) is str and Path(row['path']).is_absolute()
        and type(row['bytes']) is int and row['bytes']>0)
    raw=read_bytes(row['path'],row['sha256'],deadline,
        1024*1024*1024 if row['role']=='native-cli' else 64*1024*1024)
    require(len(raw)==row['bytes'])
    if row['role'] in ('config-schema','stable-schema','experimental-schema'):
        value=json.loads(raw,object_pairs_hook=unique); require(type(value) is dict)
        if row['role']=='config-schema':
            definitions=value.get('definitions',value.get('$defs',{}))
            require(definitions['OmuxBrokerContextMode']['enum']==['full_native','text_transcript_v1']
                and definitions['OmuxBrokerConfig']['properties']['context_mode']['default']=='full_native')
    elif row['role']=='test-xml':
        xml=ET.fromstring(raw)
        suites=[xml] if xml.tag=='testsuite' else list(xml.findall('testsuite'))
        require(xml.tag in ('testsuite','testsuites') and bool(suites)
            and all(int(suite.get('tests','0'))>0 and all(int(suite.get(name,'0'))==0
                for name in ('failures','errors','skipped')) for suite in suites))
    elif row['role']=='native-cli':
        require(len(raw)>=64 and raw[:6]==b'\x7fELF\x02\x01'
            and raw[18:20]==b'\x3e\x00')
    else: require(row['role']=='test-log')
    return row

def readback(document,selection,deadline):
    """Retained actual controller result; no success from a proposed output pin."""
    import codex_native_acquisition_material as ninth
    require(type(selection) is dict and set(selection)=={'path','sha256','producer'})
    receipt_path=Path(selection['path']);receipt_pin=selection['sha256']
    outer=ninth.producer_success({'root':str(receipt_path.parent),'producer':selection['producer']},
        '//tools:codex_native_acquisition_compilation_producer','native-acquisition-compilation',deadline)
    compiler=ledger(document,deadline)['compiler_controller']
    require(outer['source_commit']==compiler['source_commit']
        and outer['graph_sha256']==compiler['graph_sha256'])
    material,_=prerequisites(document,deadline,qualify_material)
    receipt=read_json(receipt_path,receipt_pin,deadline)
    require(type(receipt) is dict and set(receipt)=={'schema_version','kind','material',
        'ledger_sha256','controller_inventory_sha256','caps','verb','targets','exit',
        'workload_exit','cleanup_empty','resident_verified_after','artifacts',
        'schema_producer_qualified','native_compile_passed','live_handoff_proven'}
        and type(receipt['schema_version']) is int and receipt['schema_version']==1
        and receipt['kind']==KIND and receipt['material']==material
        and receipt['ledger_sha256']==document['ledger']['sha256']
        and receipt['controller_inventory_sha256']==document['controller_inventory_sha256']
        and receipt['caps']==CAPS and receipt['verb']=='test' and receipt['targets']==list(TARGETS)
        and type(receipt['exit']) is int and receipt['exit']==0
        and type(receipt['workload_exit']) is int and receipt['workload_exit']==0
        and receipt['cleanup_empty'] is False and receipt['resident_verified_after'] is False
        and receipt['schema_producer_qualified'] is False and receipt['native_compile_passed'] is False
        and receipt['live_handoff_proven'] is False)
    rows=receipt['artifacts']; require(type(rows) is list and 7<=len(rows)<=4096)
    require(all(type(row) is dict and type(row.get('bytes')) is int and row['bytes']>0 for row in rows)
        and sum(row['bytes'] for row in rows)<=1536*1024*1024)
    require(len({row['path'] for row in rows})==len(rows))
    roles=[artifact(row,deadline)['role'] for row in rows]
    require(roles.count('config-schema')==1 and roles.count('native-cli')==1
        and roles.count('test-xml')==3 and roles.count('test-log')==3
        and 'stable-schema' in roles and 'experimental-schema' in roles)
    artifact_closure(receipt_path.parent/'artifacts',rows,deadline)
    # Repeat the actual material proof after every artifact read, plus receipt rehash.
    require(prerequisites(document,deadline,qualify_material)[0]==material
        and read_json(receipt_path,receipt_pin,deadline)==receipt)
    return {'schema_version':1,'kind':KIND+'-qualified-readback','receipt_sha256':receipt_pin,
        'outer_receipt_sha256':selection['producer']['sha256'],'material':material,
        'schema_producer_qualified':True,'native_compile_passed':True,
        'outer_cleanup_qualified':True,'live_handoff_proven':False}

def artifact_closure(root,rows,deadline):
    import codex_native_profile as native
    names={}
    for row in rows:
        path=Path(row['path']);require(path.is_relative_to(root))
        name=str(path.relative_to(root));require(name not in names);names[name]=row
    actual=set()
    def visit(directory):
        tick(deadline);require(not directory.is_symlink())
        entries=list(directory.iterdir());require(0<len(entries)<=4096)
        for entry in entries:
            tick(deadline);require(not entry.is_symlink())
            if entry.is_dir():visit(entry)
            else:require(entry.is_file());actual.add(str(entry.relative_to(root)))
    visit(root);require(actual==set(names))
    fixed={'native-cli':'native-cli','schema/config.json':'config-schema'}
    for target in TARGETS[:3]:
        name=target.split(':')[1]
        fixed['tests/'+name+'/test.xml']='test-xml'
        fixed['tests/'+name+'/test.log']='test-log'
        row=names['tests/'+name+'/test.log']
        native.qualification_log(read_bytes(row['path'],row['sha256'],deadline),target)
    for name,row in names.items():
        if name in fixed:require(row['role']==fixed[name])
        else:
            require(name.endswith('.json') and (name.startswith('schema/stable/')
                or name.startswith('schema/experimental/')))
            require(row['role']==('stable-schema' if name.startswith('schema/stable/') else 'experimental-schema'))
    require(set(fixed)<=set(names))

def command(document,work,deadline):
    prerequisites(document,deadline,qualify_material)
    return fixed_plan(document['material'],work,deadline)

def fixed_plan(selection,work,deadline):
    """Own finite mode; generic immutable builder receives already qualified bytes."""
    import codex_native_acquisition_material as ninth
    import codex_native_profile as native
    import codex_native_acquisition_metadata as producer
    require(TARGETS[:4]==(native.CORE,native.CONFIG,native.LOGIN,native.CLI))
    source,files,parent,report,mappings=ninth.qualify_selection(selection,deadline)
    candidate_source=work/'source'
    producer.source.DEADLINE=producer.DEADLINE=deadline
    producer.source.write_source(candidate_source,files)
    args=SimpleNamespace(native_export_root=Path(selection['sdk']['root']),native_mode='ninth-final')
    # candidate is disjoint and fresh; no historical native candidate/cache selectors.
    candidate=SimpleNamespace(source=candidate_source,root=work,
        lease=SimpleNamespace(output_base=work/'output-base'))
    descriptor=producer.query_tools.verify_repository(producer.QUERY_REPOSITORY,deadline)['query_tools']
    require(type(descriptor) is dict)
    bash=descriptor['tools']['bash']
    plan=native.command_from_verified_inputs(args,work,producer.LOCKED_PATH,bash,candidate,
        (source,mappings),{'ninth-final':('test',TARGETS,None)},gates=native.QUALIFICATION_GATES)
    require(plan['argv'][-6:]==list(TARGETS))
    plan['environment']['CARGO_NET_OFFLINE']='true'
    plan['argv'].insert(plan['argv'].index('test')+1,'--repo_env=CARGO_NET_OFFLINE=true')
    remaining=int(deadline-time.monotonic()-90);require(remaining>0)
    plan['argv']=[('--test_timeout='+str(remaining)) if token=='--test_timeout=1200' else token
        for token in plan['argv']]
    return plan

def run_once(plan,output,deadline):
    """One invocation, original cutoff; no retries or replacement compiler."""
    tick(deadline); require(deadline-time.monotonic()>90)
    logs=output/'logs'; logs.mkdir(mode=0o700)
    paths=[logs/'stdout',logs/'stderr']
    streams=[];child=None
    try:
        for path in paths:streams.append(open(path,'xb',buffering=0))
        child=subprocess.Popen(plan['argv'],cwd=plan['cwd'],env=plan['environment'],
            stdin=subprocess.DEVNULL,stdout=streams[0],stderr=streams[1])
        while child.poll() is None:
            require(time.monotonic()<deadline-90
                and all(os.fstat(stream.fileno()).st_size<=16*1024*1024 for stream in streams))
            time.sleep(min(0.05,max(0,deadline-90-time.monotonic())))
        require(type(child.returncode) is int and child.returncode==0)
        return child.returncode
    finally:
        try:
            if child is not None and child.poll() is None:
                child.kill(); child.wait(timeout=max(0.001,min(15,deadline-time.monotonic())))
        finally:
            for stream in streams:stream.close()

def retain_artifacts(output_base,destination,deadline):
    """Exhaustively retain one actual optimized configuration; refuse links/extras."""
    root=Path(output_base)/'execroot/_main/bazel-out'
    configurations=[path for path in root.iterdir() if re.fullmatch(r'[A-Za-z0-9_.-]+-opt',path.name)
        and path.is_dir() and not path.is_symlink()]
    require(len(configurations)==1)
    config=configurations[0]; rows=[]; total=0
    def copy(path,relative,role):
        nonlocal total
        tick(deadline)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            info=os.fstat(fd);require(stat.S_ISREG(info.st_mode) and 0<info.st_size<=1024*1024*1024)
            parts=[];count=0
            while True:
                tick(deadline);raw=os.read(fd,1024*1024)
                if not raw:break
                parts.append(raw);count+=len(raw);require(count<=1024*1024*1024)
            after=os.fstat(fd)
            require((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
                ==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns))
        finally:os.close(fd)
        raw=b''.join(parts);total+=len(raw);require(total<=1536*1024*1024 and len(rows)<4096)
        target=destination/relative;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with target.open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        target.chmod(0o444)
        row={'path':str(target),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'role':role}
        artifact(row,deadline);rows.append(row)
    copy(config/'bin/codex-rs/cli/codex','native-cli','native-cli')
    schema=config/'bin/bazel/schema'
    copy(schema/'native-config.schema.json','schema/config.json','config-schema')
    for mode in ('stable','experimental'):
        base=schema/('public-schema-bundle.'+mode)/'json'; require(base.is_dir() and not base.is_symlink())
        count=0
        def visit(directory):
            nonlocal count
            tick(deadline);entries=list(directory.iterdir());require(0<len(entries)<=4096)
            for entry in sorted(entries):
                tick(deadline);require(not entry.is_symlink())
                if entry.is_dir():visit(entry)
                else:
                    require(entry.is_file() and entry.suffix=='.json')
                    copy(entry,'schema/'+mode+'/'+str(entry.relative_to(base)),mode+'-schema');count+=1
        visit(base);require(count>0)
    for target in TARGETS[:3]:
        package,name=target[2:].split(':');base=config/'testlogs'/package/name
        for suffix,role in (('xml','test-xml'),('log','test-log')):
            copy(base/('test.'+suffix),'tests/'+name+'/test.'+suffix,role)
    return rows

def produce(document,output,deadline):
    import codex_native_acquisition_metadata as producer
    require(type(deadline) is float and 0<deadline-time.monotonic()<=840)
    producer.DEADLINE=producer.source.DEADLINE=deadline
    producer.declared_selection()
    material,evidence=prerequisites(document,deadline,qualify_material)
    require(not output.exists());output.mkdir(mode=0o700)
    work=output/'work';work.mkdir(mode=0o700)
    plan=fixed_plan(document['material'],work,deadline)
    run_once(plan,output,deadline)
    rows=retain_artifacts(work/'output-base',output/'artifacts',deadline)
    artifact_closure(output/'artifacts',rows,deadline)
    require(prerequisites(document,deadline,qualify_material)[0]==material)
    qualified=producer.query_tools.verify_repository(producer.QUERY_REPOSITORY,deadline)
    require(qualified['status']=='declared-fixed-query-tools-byte-qualified' and qualified['inputs_rechecked'] is True)
    receipt={'schema_version':1,'kind':KIND,'material':material,
        'ledger_sha256':document['ledger']['sha256'],
        'controller_inventory_sha256':document['controller_inventory_sha256'],
        'caps':CAPS,'verb':'test','targets':list(TARGETS),'exit':0,'workload_exit':0,
        'cleanup_empty':False,'resident_verified_after':False,'artifacts':rows,
        'schema_producer_qualified':False,'native_compile_passed':False,'live_handoff_proven':False}
    # Inner producer cannot claim outer cleanup; consumer must join actual guardian.
    path=output/'receipt.json'
    with path.open('xb') as stream:stream.write(encoded(receipt));stream.flush();os.fsync(stream.fileno())
    path.chmod(0o444)
    for directory,subdirs,files in os.walk(output/'artifacts',topdown=False):
        tick(deadline);Path(directory).chmod(0o555)
    fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    output.chmod(0o555)
    return receipt

def main():
    import codex_native_acquisition_binding as binding
    import codex_protocol_history_query_tools as query_tools
    entry=float(time.monotonic());require(len(sys.argv)==1)
    timeout=os.environ.get('TEST_TIMEOUT');require(type(timeout) is str and timeout.isdigit())
    deadline=query_tools.consumer_deadline(entry,min(840,int(timeout)-60));tick(deadline)
    binding.source.DEADLINE=deadline
    config=binding.config();row=config['compile']
    require(type(row) is dict and set(row)=={'path','sha256'})
    document=selected_document(row['path'],row['sha256'],deadline)
    output=os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR');require(type(output) is str and Path(output).is_absolute())
    produce(document,Path(output)/'native-acquisition-compilation',deadline)

if __name__=='__main__':main()
