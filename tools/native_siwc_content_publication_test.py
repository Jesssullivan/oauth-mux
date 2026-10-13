"""Actual local transport primitives; no SOURCE/SDK/native authority fixtures."""
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import native_siwc_content_publication as publication


class PublicationTests(unittest.TestCase):
    def scope(self):
        stack=ExitStack();self.addCleanup(stack.close)
        directory=stack.enter_context(tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']))
        root=Path(directory).resolve();run=root/'11111111-1111-4111-8111-111111111111';run.mkdir(mode=0o700)
        stack.enter_context(patch.object(publication.resident,'PUBLIC_ROOTS',(root,)))
        entry=time.monotonic_ns()-10**9
        context={'MODE':'native-file-writer-models-reserved','ENTRY_NS':str(entry),
            'DEADLINE_NS':str(entry+1200*10**9),'EPOCH':str(run),'SOURCE_COMMIT':'a'*40,'GRAPH_SHA256':'b'*64}
        owner=publication.CapturedPublication(context);self.addCleanup(owner.close)
        return root,run,owner

    def trees(self,run,owner):
        source=run/'source-input';source.mkdir(mode=0o700)
        (source/'sub').mkdir(mode=0o700)
        for path,raw in ((source/'one',b'public-one'),(source/'sub/two',b'public-two')):
            path.write_bytes(raw);path.chmod(0o555)
        (source/'alias').symlink_to('one');(source/'sub').chmod(0o555);source.chmod(0o555)
        expected={name:{'mode':mode,'sha256':hashlib.sha256(raw).hexdigest()}
            for name,mode,raw in (('one','100644',b'public-one'),('sub/two','100755',b'public-two'),('alias','120000',b'one'))}
        original=publication.Tree(owner,source);original.discover(expected)
        destination=run/'destination';destination.mkdir(mode=0o700)
        fresh=publication.Tree(owner,destination,writable=True)
        return original,fresh,expected

    def test_actual_complete_copy_rehashes_literals_modes_and_new_inodes(self):
        unused,run,owner=self.scope();original,fresh,expected=self.trees(run,owner)
        publication._copy(owner,original,fresh,expected)
        self.assertEqual(set(fresh.members),set(expected));self.assertEqual(os.readlink(fresh.path/'alias'),'one')
        for name in ('one','sub/two'):
            self.assertEqual((fresh.path/name).read_bytes(),(original.path/name).read_bytes())
            self.assertNotEqual(fresh.members[name][0][1],original.members[name][0][1])
            self.assertEqual(fresh.members[name][0][4]&0o777,0o555)
        self.assertLess(len(owner.fds.fds),publication.MAX_FDS)
        self.assertFalse(owner.finished)
        with self.assertRaises(ValueError):owner.record()

    def test_actual_same_byte_original_replacement_during_durable_write_refuses(self):
        unused,run,owner=self.scope();original,fresh,expected=self.trees(run,owner)
        fsync=os.fsync;armed=[True]
        def change(fd):
            if armed[0]:
                armed[0]=False;original.path.chmod(0o700)
                temporary=original.path/'replacement';temporary.write_bytes(b'public-one');temporary.chmod(0o555)
                temporary.replace(original.path/'one');original.path.chmod(0o555)
            return fsync(fd)
        with patch.object(publication.os,'fsync',change):
            with self.assertRaises(ValueError):publication._copy(owner,original,fresh,expected)
        self.assertFalse(armed[0])

    def test_actual_extra_directory_and_link_retarget_are_not_ignored(self):
        for fault in ('extra','link'):
            unused,run,owner=self.scope();original,fresh,expected=self.trees(run,owner)
            if fault=='extra':
                original.path.chmod(0o700);(original.path/'unexpected').mkdir();original.path.chmod(0o555)
            else:
                original.path.chmod(0o700);(original.path/'alias').unlink();(original.path/'alias').symlink_to('sub/two');original.path.chmod(0o555)
            with self.assertRaises(ValueError):original.fence()

    def test_readonly_source_member_rejects_private_metadata_mode(self):
        unused,run,owner=self.scope();original,fresh,expected=self.trees(run,owner)
        (original.path/'one').chmod(0o400)
        with self.assertRaises(ValueError):publication.Tree(owner,original.path).discover(expected)

    def test_original_outer_window_is_delivery_only_and_never_reset(self):
        unused,run,owner=self.scope();original,fresh,expected=self.trees(run,owner)
        with patch.object(publication.time,'monotonic_ns',return_value=owner.entry+601*10**9):
            publication._copy(owner,original,fresh,expected)
        self.assertEqual(owner.cutoff,owner.until-30*10**9)
        self.assertFalse(owner.finished)
        with patch.object(publication.time,'monotonic_ns',return_value=owner.cutoff):
            with self.assertRaises(ValueError):owner.tick()
        self.assertEqual(owner.cutoff,owner.until-30*10**9)

    def test_global_fd_limit_and_enrollment_failure_retire_real_descriptors(self):
        unused,run,owner=self.scope()
        records=publication.Descriptors()
        with patch.object(publication,'MAX_FDS',1):
            first=records.open(run,os.O_RDONLY|os.O_DIRECTORY)
            with self.assertRaises(ValueError):records.open(run,os.O_RDONLY|os.O_DIRECTORY)
            self.assertEqual(records.fds,[first])
        records.close()
        with self.assertRaises(OSError):os.fstat(first)
        class FailingList(list):
            def append(self,fd):raise MemoryError('synthetic allocation fault')
        records=publication.Descriptors();records.fds=FailingList()
        fd=os.open(run,os.O_RDONLY|os.O_DIRECTORY)
        with self.assertRaises(MemoryError):records.enroll(fd)
        with self.assertRaises(OSError):os.fstat(fd)
        records.close()

    def test_close_attempts_all_and_body_identity_survives_close_failure(self):
        unused,run,owner=self.scope();fds=[owner.fds.open(run,os.O_RDONLY|os.O_DIRECTORY) for unused in range(3)]
        close=os.close;attempts=[];first=MemoryError('synthetic body');cleanup=OSError('synthetic close')
        def fail(fd):
            attempts.append(fd);close(fd)
            if fd==fds[1]:raise cleanup
        try:
            with patch.object(publication.os,'close',fail):
                with owner:raise first
        except MemoryError as error:
            self.assertIs(error,first);self.assertIs(error.__cause__,cleanup)
        else:self.fail('first body exception was suppressed')
        self.assertTrue(set(fds)<=set(attempts));self.assertEqual(len(attempts),len(set(attempts)))
        self.assertEqual(owner.fds.fds,[])

    def test_actual_empty_lock_requires_live_parent_exclusion_and_dirty_current_marker(self):
        root,run,owner=self.scope();key='c'*64;namespace=root/('cache-v2-'+key);namespace.mkdir(mode=0o700);(namespace/'output-base').mkdir(mode=0o700)
        marker={'schema':2,'key':key,'clean':False,'last_run':run.name,'cleanup_receipt_sha256':None}
        (namespace/'owner.json').write_bytes(publication.encoded(marker));(namespace/'owner.json').chmod(0o600)
        lock=os.open(namespace/'cache.lock',os.O_CREAT|os.O_RDWR,0o600);self.addCleanup(os.close,lock)
        facts={'kind':'omux-native-siwc-content-dependency-lease-v1','key':key,'namespace':namespace.name,
            'output_base':str(namespace/'output-base'),'run_id':run.name,'checkout':str(root),
            'source_commit':owner.context['SOURCE_COMMIT'],'graph_sha256':owner.context['GRAPH_SHA256'],
            'entry_monotonic_ns':owner.entry,'deadline_monotonic_ns':owner.until}
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        self.assertEqual(publication._lease_view(owner,facts),namespace/'output-base');owner.fence()
        fcntl.flock(lock,fcntl.LOCK_UN)
        with self.assertRaises(ValueError):owner.fence()
        # A clean-looking JSON record cannot replace exclusion by a live owner.
        root2,run2,owner2=self.scope();namespace2=root2/('cache-v2-'+key);namespace2.mkdir(mode=0o700);(namespace2/'output-base').mkdir(mode=0o700)
        (namespace2/'owner.json').write_bytes(publication.encoded({**marker,'last_run':run2.name}));(namespace2/'owner.json').chmod(0o600)
        (namespace2/'cache.lock').touch(mode=0o600)
        facts2={**facts,'namespace':namespace2.name,'output_base':str(namespace2/'output-base'),'run_id':run2.name,
            'entry_monotonic_ns':owner2.entry,'deadline_monotonic_ns':owner2.until}
        with self.assertRaises(ValueError):publication._lease_view(owner2,facts2)

    def test_unknown_context_or_shifted_deadline_cannot_create_delivery_scope(self):
        unused,run,owner=self.scope()
        for context in ({**owner.context,'MODE':'unknown'},
            {**owner.context,'DEADLINE_NS':str(owner.until+1)}, {**owner.context,'EPOCH':str(run/'other')}):
            with self.assertRaises(ValueError):publication.CapturedPublication(context)

    def test_executable_mode_is_bound_to_retained_policy_and_receipt_role_is_separate(self):
        unused,run,owner=self.scope();original,fresh,expected=self.trees(run,owner)
        self.assertEqual(expected['one']['mode'],'100644');self.assertEqual(expected['sub/two']['mode'],'100755')
        self.assertEqual(original.members['one'][0][4]&0o777,0o555)
        (original.path/'sub/two').chmod(0o444)
        with self.assertRaises(ValueError):publication.Tree(owner,original.path).discover(expected)
        (original.path/'sub/two').chmod(0o555);original.path.chmod(0o700)
        raw=b'public receipt role';receipt=original.path/'source-receipt.json';receipt.write_bytes(raw);receipt.chmod(0o444);original.path.chmod(0o555)
        expected={**expected,'source-receipt.json':{'mode':'100644','sha256':hashlib.sha256(raw).hexdigest()}}
        current=publication.Tree(owner,original.path);current.discover(expected)
        self.assertEqual(current.members['source-receipt.json'][0][4]&0o777,0o444)
        receipt.chmod(0o600)
        with self.assertRaises(ValueError):publication.Tree(owner,original.path).discover(expected)

    def test_unselected_names_refuse_with_iterator_closed_and_no_eager_inventory(self):
        unused,run,owner=self.scope();original,fresh,expected=self.trees(run,owner)
        before=set(os.listdir('/proc/self/fd'))
        with self.assertRaises(ValueError):publication._names(owner,original.fd,set())
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)
        self.assertEqual(publication._names(owner,original.fd,{'one','sub','alias'}),{'one','sub','alias'})

    def test_late_directory_seal_replacement_does_not_inherit_creator_fsync(self):
        for target in ('one','alias'):
            unused,run,owner=self.scope();original,fresh,expected=self.trees(run,owner)
            chmod=os.fchmod;armed=[True];changed=[]
            def change(fd,mode):
                if armed[0] and fd==fresh.fd and mode==0o555:
                    # Replace after each created leaf has been fsynced, but
                    # before this owner seals its still-writable root. No
                    # root privileges or production permission bypass needed.
                    self.assertEqual(os.fstat(fd).st_mode&0o777,0o700)
                    armed[0]=False;original_anchor=publication.witness(os.lstat(fresh.path/target))
                    replacement=fresh.path/'replacement'
                    if target=='one':
                        replacement.write_bytes(b'public-one');replacement.chmod(0o555)
                    else:replacement.symlink_to('one')
                    replacement.replace(fresh.path/target)
                    changed.append((original_anchor,publication.witness(os.lstat(fresh.path/target))))
                return chmod(fd,mode)
            with patch.object(publication.os,'fchmod',change):
                with self.assertRaises(ValueError):publication._copy(owner,original,fresh,expected)
            self.assertFalse(armed[0]);self.assertEqual(len(changed),1)
            self.assertNotEqual(changed[0][0][1],changed[0][1][1])
            self.assertEqual(os.fstat(fresh.fd).st_mode&0o777,0o555)
            if target=='one':self.assertEqual((fresh.path/target).read_bytes(),b'public-one')
            else:self.assertEqual(os.readlink(fresh.path/target),'one')

    def test_after_append_failure_detaches_before_close_and_drain_never_retries(self):
        unused,run,owner=self.scope()
        class AfterAppend(list):
            def append(self,fd):super().append(fd);raise MemoryError('synthetic after append')
        records=publication.Descriptors();records.fds=AfterAppend()
        fd=os.open(run,os.O_RDONLY|os.O_DIRECTORY);close=os.close;attempts=[]
        def fail(number):attempts.append(number);close(number);raise OSError('synthetic close')
        with patch.object(publication.os,'close',fail):
            with self.assertRaises(MemoryError):records.enroll(fd)
            records.close()
        self.assertEqual(attempts,[fd]);self.assertEqual(records.fds,[])
        with self.assertRaises(OSError):os.fstat(fd)

    def test_failed_xml_wrapper_or_nested_error_cannot_hide_behind_clean_suite(self):
        good=b'<testsuites failures="0"><testsuite tests="1" failures="0" errors="0" skipped="0"><testcase/></testsuite></testsuites>'
        publication._xml_success(good)
        for bad in (good.replace(b'failures="0"',b'failures="1"',1),
                good.replace(b'<testcase/>',b'<testcase><failure/></testcase>'),
                good.replace(b'<testcase/>',b'<testcase><error/></testcase>'),
                good.replace(b'<testcase/>',b'<testcase><skipped/></testcase>')):
            with self.assertRaises(ValueError):publication._xml_success(bad)

    def test_receipt_writer_identity_and_extent_refuse_replacement_before_any_bulk_read(self):
        for fault in ('same-byte','oversized'):
            unused,run,owner=self.scope();container=run/publication.DIRECTORY;container.mkdir(mode=0o700)
            owner.container=publication.Tree(owner,container,writable=True)
            actual=os.open;armed=[True]
            def replace(path,flags,mode=0o777,*,dir_fd=None):
                if armed[0] and path==publication.RECEIPT and flags&os.O_ACCMODE==os.O_RDONLY:
                    armed[0]=False;os.unlink(publication.RECEIPT,dir_fd=owner.container.fd)
                    new=actual(publication.RECEIPT,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=owner.container.fd)
                    try:
                        if fault=='same-byte':os.write(new,b'public receipt')
                        else:os.ftruncate(new,publication.MAX_METADATA+1)
                        os.fchmod(new,0o444)
                    finally:os.close(new)
                return actual(path,flags,mode,dir_fd=dir_fd)
            with patch.object(publication.os,'open',replace),patch.object(publication.os,'pread',side_effect=AssertionError('replacement bulk read')):
                with self.assertRaises(ValueError):publication._publish_receipt(owner,b'public receipt')
            self.assertFalse(armed[0])

    def test_close_and_success_output_expiry_cannot_return_zero(self):
        unused,run,owner=self.scope();close=owner.close;expired=[False]
        def closing():close();expired[0]=True
        def now():return owner.cutoff if expired[0] else owner.entry+1
        with patch.object(owner,'close',closing),patch.object(publication.time,'monotonic_ns',now):
            with self.assertRaises(ValueError):
                with owner:pass
        unused,run,owner=self.scope();owner.finished=True;owner._record={'public':'heavy capture seam'}
        env={'TEST_TIMEOUT':'840','OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST':str(run/'native-content-delivery-request.json'),
            'OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST_SHA256':'a'*64}
        env.update({'OMUX_NATIVE_FILE_WRITER_MODELS_'+key:value for key,value in owner.context.items()})
        expired=[False]
        def emitted(*args,**kwargs):expired[0]=True
        def now():return owner.cutoff if expired[0] else owner.entry+1
        with patch.dict(os.environ,env),patch.object(publication.sys,'argv',['public-delivery']),patch.object(publication,'capture',return_value=owner), \
                patch.object(publication.time,'monotonic_ns',now),patch('builtins.print',side_effect=emitted) as marker:
            with self.assertRaises(ValueError):publication.main()
        marker.assert_called_once();self.assertEqual(owner.cutoff,owner.until-30*10**9)

    def test_fixed_container_seal_updates_only_its_owned_mode_transition(self):
        unused,run,owner=self.scope();original,unused_fresh,expected=self.trees(run,owner)
        container=run/publication.DIRECTORY;container.mkdir(mode=0o700)
        owner.container=publication.Tree(owner,container,writable=True)
        (container/publication.LEAF).mkdir(mode=0o700)
        fresh=publication.Tree(owner,container/publication.LEAF,writable=True)
        publication._copy(owner,original,fresh,expected)
        publication._publish_receipt(owner,b'public receipt')
        publication._seal_container(owner,fresh)
        fresh.fence();owner.container.fence()
        self.assertEqual(os.stat(container).st_mode&0o777,0o555)
        self.assertEqual(fresh.chain[-2][2],publication.witness(os.stat(container)))
        self.assertEqual(owner._reread(owner.receipt_fd,owner.receipt_anchor),b'public receipt')
        container.chmod(0o700);(container/'unselected').write_bytes(b'public extra')
        with self.assertRaises(ValueError):publication._seal_container(owner,fresh)

    def test_complete_fixed_capture_preserves_reports_and_rejects_failed_source_checkpoint(self):
        # Synthetic coordinator documents exercise the real worker boundary;
        # they are neither actual SOURCE success nor compiled native evidence.
        root,run,owner=self.scope();context=dict(owner.context);owner.close()
        key='e'*64;namespace=root/('cache-v2-'+key);namespace.mkdir(mode=0o700)
        base=namespace/'output-base';base.mkdir(mode=0o700)
        marker={'schema':2,'key':key,'clean':False,'last_run':run.name,'cleanup_receipt_sha256':None}
        (namespace/'owner.json').write_bytes(publication.encoded(marker));(namespace/'owner.json').chmod(0o600)
        lock=os.open(namespace/'cache.lock',os.O_CREAT|os.O_RDWR,0o600);self.addCleanup(os.close,lock)
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        facts={'kind':'omux-native-siwc-content-dependency-lease-v1','key':key,'namespace':namespace.name,
            'output_base':str(base),'run_id':run.name,'checkout':str(root),'source_commit':context['SOURCE_COMMIT'],
            'graph_sha256':context['GRAPH_SHA256'],'entry_monotonic_ns':int(context['ENTRY_NS']),
            'deadline_monotonic_ns':int(context['DEADLINE_NS'])}
        configuration='public-fastbuild';epoch=time.time_ns()-10**9
        original=base/'execroot/_main/bazel-out'/configuration/'testlogs/tools'/publication.TARGETS[1].split(':')[1]/'test.outputs'/publication.LEAF
        (original/'source').mkdir(parents=True,mode=0o700);(original/'hub/source').mkdir(parents=True,mode=0o700)
        inventory={}
        for index in range(8557):
            relative='public-'+str(index);raw=b'x';(original/'source'/relative).write_bytes(raw)
            (original/'source'/relative).chmod(0o555)
            inventory[relative]={'mode':'100644','sha256':hashlib.sha256(raw).hexdigest()}
        hub={}
        for relative in ('BUILD.bazel','defs.bzl','data.bzl'):
            raw=b'public inert hub fixture';(original/'hub/source'/relative).write_bytes(raw)
            (original/'hub/source'/relative).chmod(0o555);hub[relative]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
        report={'kind':'omux-native-siwc-catalog-content-source-v1','status':'verified-siwc-catalog-content-source-uncompiled',
            'source_bytes':8557,'tracked_files':8557,'patch_sha256':['f'*64]*12,'historical_ancestor_reexecution':False,
            'native_runtime_qualified':False,'physical_mode_policy':'bazel-retained-export-all-regular-and-directories-0555-v1',
            'source_inventory':inventory,'generated_hub':hub,
            'inventory_sha256':hashlib.sha256(json.dumps(inventory,sort_keys=True).encode()).hexdigest(),
            'producer_context':{'mode':context['MODE'],'epoch':str(run),'source_commit':context['SOURCE_COMMIT'],
                'graph_sha256':context['GRAPH_SHA256'],'entry_monotonic_ns':facts['entry_monotonic_ns'],
                'deadline_monotonic_ns':facts['deadline_monotonic_ns']}}
        raw=publication.encoded(report);(original/'source-receipt.json').write_bytes(raw);(original/'source-receipt.json').chmod(0o444)
        for directory in (original/'source',original/'hub/source',original/'hub',original):directory.chmod(0o555)
        (run/publication.DIRECTORY).mkdir(mode=0o700);(run/'test-evidence').mkdir(mode=0o700)
        results=[]
        for target in publication.TARGETS:
            files=[]
            for kind,body in (('test.log',b'public fixture log'),('test.xml',b'<testsuite tests="1" failures="0" errors="0"><testcase/></testsuite>')):
                filename=hashlib.sha256((target+'\0'+configuration+'\0'+kind).encode()).hexdigest()+'.evidence'
                (run/'test-evidence'/filename).write_bytes(body);(run/'test-evidence'/filename).chmod(0o600)
                files.append({'source':kind,'state':'copied','file':filename,'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body)})
            results.append({'target':target,'state':'observed','configuration':configuration,'files':files})
        evidence={'schema':1,'bazel_exit':0,'epoch_start_ns':epoch,'targets':list(publication.TARGETS),'results':results}
        evidence_raw=publication.encoded(evidence);(run/'test-evidence.json').write_bytes(evidence_raw);(run/'test-evidence.json').chmod(0o600)
        clocks={'source_until_ns':facts['entry_monotonic_ns']+600*10**9,'work_until_ns':facts['deadline_monotonic_ns']-30*10**9,
            'outer_until_ns':facts['deadline_monotonic_ns']}
        phase={'schema_version':1,'kind':'omux-native-siwc-content-source-phase-v1','id':run.name,'profile':publication.PROFILE,
            'targets':list(publication.TARGETS),'source_commit':context['SOURCE_COMMIT'],'graph_sha256':context['GRAPH_SHA256'],
            'context':context,'clocks':clocks,'exit':0,'workload_exit':0,'epoch_start_ns':epoch,'output_base':str(base),
            'cache_reuse_requested':True,'cache_policy':2,'cache_key':key,'dependency_lease':facts,'command':[], 'limits':{},
            'worker':dict.fromkeys(('unit','invocation','pid','start_ticks','cgroup','kernel_bounds'),'synthetic fixture'),
            'cleanup':{'state':'empty','ownership':'verified','readback_attempts':2},'descendants_empty':True,
            'test_evidence':{'state':'preserved','manifest':'test-evidence.json','sha256':hashlib.sha256(evidence_raw).hexdigest()},
            'native_siwc_catalog_content_source_reservation':{'scope':'fixed-native-siwc-catalog-content-source-reserved-v1',
                'verified_after_cleanup':True,'original_entry_monotonic_ns':facts['entry_monotonic_ns'],
                'original_deadline_monotonic_ns':facts['deadline_monotonic_ns'],'action_cap_seconds':840}}
        phase_raw=publication.encoded(phase);(run/'source-phase-receipt.json').write_bytes(phase_raw);(run/'source-phase-receipt.json').chmod(0o400)
        request={'schema_version':1,'kind':'omux-native-siwc-content-delivery-request-v1','context':context,'clocks':clocks,
            'dependency_lease':facts,'source_phase_receipt_sha256':hashlib.sha256(phase_raw).hexdigest(),
            'test_evidence_sha256':hashlib.sha256(evidence_raw).hexdigest(),'configuration':configuration}
        request_path=run/'native-content-delivery-request.json';request_raw=publication.encoded(request)
        request_path.write_bytes(request_raw);request_path.chmod(0o400)
        with publication.capture(request_path,hashlib.sha256(request_raw).hexdigest(),context) as captured:
            record=captured.record();self.assertEqual(record['source_receipt']['sha256'],hashlib.sha256(raw).hexdigest())
            retained=Path(record['root']);self.assertEqual((retained/'source-receipt.json').read_bytes(),raw)
            document=publication.decode((retained.parent/publication.RECEIPT).read_bytes())
            self.assertEqual(len(document['publication']['members']),8557+3+1)
            self.assertFalse(document['source_qualification_extended']);self.assertFalse(document['original_action_sdk_custody_inherited'])
        phase['workload_exit']=3;phase_raw=publication.encoded(phase)
        (run/'source-phase-receipt.json').chmod(0o600);(run/'source-phase-receipt.json').write_bytes(phase_raw);(run/'source-phase-receipt.json').chmod(0o400)
        request['source_phase_receipt_sha256']=hashlib.sha256(phase_raw).hexdigest();request_raw=publication.encoded(request)
        request_path.chmod(0o600);request_path.write_bytes(request_raw);request_path.chmod(0o400)
        with self.assertRaises(ValueError):publication.capture(request_path,hashlib.sha256(request_raw).hexdigest(),context)

    def test_last_marker_read_cannot_hide_source_or_output_member_drift(self):
        for domain in ('source','output'):
            root,run,owner=self.scope();original,fresh,expected=self.trees(run,owner)
            publication._copy(owner,original,fresh,expected);owner.trees=[original,fresh]
            key='d'*64;namespace=root/('cache-v2-'+key);namespace.mkdir(mode=0o700);(namespace/'output-base').mkdir(mode=0o700)
            marker={'schema':2,'key':key,'clean':False,'last_run':run.name,'cleanup_receipt_sha256':None}
            (namespace/'owner.json').write_bytes(publication.encoded(marker));(namespace/'owner.json').chmod(0o600)
            lock=os.open(namespace/'cache.lock',os.O_CREAT|os.O_RDWR,0o600);self.addCleanup(os.close,lock)
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            facts={'kind':'omux-native-siwc-content-dependency-lease-v1','key':key,'namespace':namespace.name,
                'output_base':str(namespace/'output-base'),'run_id':run.name,'checkout':str(root),
                'source_commit':owner.context['SOURCE_COMMIT'],'graph_sha256':owner.context['GRAPH_SHA256'],
                'entry_monotonic_ns':owner.entry,'deadline_monotonic_ns':owner.until}
            publication._lease_view(owner,facts)
            reread=owner._reread;armed=[True]
            def change(fd,anchor):
                raw=reread(fd,anchor)
                if armed[0] and fd==owner.marker_fd:
                    armed[0]=False;target=(original if domain=='source' else fresh).path/'one'
                    target.chmod(0o644);target.write_bytes(b'public-one');target.chmod(0o555)
                return raw
            with patch.object(owner,'_reread',change):
                with self.assertRaises(ValueError):owner.fence()
            self.assertFalse(armed[0])


if __name__=='__main__':unittest.main()
