"""Provider-free receiver/clock/transaction models; never invoke SSH or systemd."""
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest import mock
import yoga_install_inputs_receiver as receiver
import yoga_install_inputs_stage as sender

TOKEN='f9bed9a4-e4ee-4e86-9a1c-61f6b13c182e'
DEADLINE=10**18

class FixtureDirectory(receiver.Directory):
    # Fixture-only canonical sticky /tmp accommodation. All fixture children
    # still undergo the production nofollow, held/named ownership checks.
    def __init__(self,path,deadline,**keywords):
        self.constructing=True
        actual=os.fstat
        def synthetic(fd):
            value=actual(fd)
            named=os.readlink('/proc/self/fd/'+str(fd))
            if named=='/tmp' and value.st_uid==0 and stat.S_IMODE(value.st_mode)==0o1777:
                fields=list(value)
                fields[0]=stat.S_IFDIR|0o755
                return os.stat_result(fields)
            return value
        with mock.patch.object(receiver.os,'fstat',side_effect=synthetic):
            super().__init__(path,deadline,**keywords)
        # Retain the actual canonical sticky-root identity; check accepts no
        # other writable path. This exemption is never in production.
        for index,fd in enumerate(self.fds):
            self.pins[index]=receiver.identity(actual(fd))
        self.constructing=False
        self.check()

    def check(self):
        if not self.constructing:
            super().check()

class ReceiverTest(unittest.TestCase):
    def test_cross_clock_preserves_elapsed_analysis_and_ssh(self):
        entry=100
        deadline=entry+receiver.MAX_NS
        timestamp=900000000000
        cutoff=receiver.freeze_clock(timestamp,entry,deadline,entry+10**9,entry+17*10**9)
        self.assertEqual(cutoff,timestamp+1123*10**9)

    def test_cross_clock_wrong_types_duration_or_order_refuse(self):
        values=(500,100,100+receiver.MAX_NS,200,300)
        for index,value in ((0,True),(1,False),(2,100+receiver.MAX_NS+1),(3,400),(4,100+receiver.MAX_NS)):
            bad=list(values);bad[index]=value
            with self.assertRaises(ValueError):
                receiver.freeze_clock(*bad)

    def test_remote_delayed_launch_cannot_renew_cutoff(self):
        with mock.patch.object(receiver.time,'monotonic_ns',return_value=1000):
            with self.assertRaises(ValueError):
                receiver.validate_remote_clock(10,900)

    def effective(self):
        value={key:'' for key in receiver.SHOW}
        value.update(Id=receiver.unit_name(TOKEN),LoadState='loaded',ActiveState='active',
            SubState='running',MainPID='123',ControlGroup='/user.slice/user-'+str(os.getuid())+'.slice/user@'+str(os.getuid())+'.service/app.slice/'+receiver.unit_name(TOKEN),
            Slice='app.slice',MemoryMax='268435456',MemorySwapMax='0',TasksMax='32',
            CPUQuotaPerSecUSec='100ms',RuntimeMaxUSec='10s',TimeoutStopUSec='5s',PrivateNetwork='yes',
            NoNewPrivileges='yes',ProtectSystem='strict',ProtectHome='yes',
            ReadWritePaths=receiver.PARENT,KillMode='control-group',Transient='yes',
            RemainAfterExit='yes',InvocationID='a'*32,
            Environment=' '.join(key+'='+value for key,value in receiver.FIXED_ENV.items()),
            UnsetEnvironment=' '.join(receiver.UNSET))
        return value

    def test_actual_effective_cap_duration_variants(self):
        for duration in ('100ms','0.100000s','100000us'):
            value=self.effective();value['CPUQuotaPerSecUSec']=duration
            self.assertEqual(receiver.verify_unit(value,TOKEN,10000000)[0],123)

    def test_effective_network_caps_parent_or_foreign_identity_refuse(self):
        for key,value in (('PrivateNetwork','no'),('TasksMax','33'),('MemoryMax','268435457'),
            ('CPUQuotaPerSecUSec','100001us'),('TimeoutStopUSec','6s'),('ReadWritePaths','/srv'),
            ('Id','foreign.service'),('InvocationID','0'*32),('MainPID','0'),
            ('ControlGroup','/user.slice/user-foreign.slice/'+receiver.unit_name(TOKEN))):
            actual=self.effective();actual[key]=value
            with self.assertRaises(ValueError):
                receiver.verify_unit(actual,TOKEN,10000000)

    def test_properties_duplicate_and_incomplete_refuse(self):
        raw='\n'.join(key+'='+value for key,value in self.effective().items()).encode()
        self.assertEqual(receiver.properties(raw),self.effective())
        for bad in (raw+b'\nId=x',b'Id=x',raw+b'\nUnknown=x'):
            with self.assertRaises(ValueError):
                receiver.properties(bad)

    def test_exact_receiver_command_and_full_frozen_tail(self):
        with mock.patch.object(receiver.time,'monotonic_ns',return_value=100):
            command,maximum=receiver.receiver_command(TOKEN,20*10**9+100,'# frozen source')
        self.assertIn('--unit='+receiver.unit_name(TOKEN),command)
        self.assertIn('ReadWritePaths='+receiver.PARENT,command)
        self.assertIn('CPUQuota=10%',command)
        self.assertIn('RuntimeMaxSec=45',command)
        self.assertEqual(maximum,45000000)
        expected_source=("# frozen source\ntry:\n worker('"+TOKEN+
                         "',20000000100)\nexcept BaseException:\n sys.exit(125)\n")
        self.assertEqual(command[-6:],['--',receiver.PYTHON,'-I','-S','-c',expected_source])
        with self.assertRaises(ValueError):
            receiver.unit_name(TOKEN+';command')

    def test_complete_declared_tool_closure_missing_reference_refuses(self):
        roots=[str(Path(*Path(path).parts[:4])) for path in receiver.TOOLS]
        rows=[{'path':root,'references':[root],'narSize':1,'narHash':'sha256:'+'a'*64}
              for root in sorted(set(roots))]
        self.assertEqual(sender.closure(rows),rows)
        rows[0]['references'].append('/nix/store/undeclared')
        with self.assertRaises(ValueError):
            sender.closure(rows)

    def test_original_two_cleanup_tails_do_not_overlap_or_renew(self):
        entry=100
        deadline=entry+receiver.MAX_NS
        remote_timestamp=7000000000000
        reply=entry+200*10**9
        cutoff=receiver.freeze_clock(remote_timestamp,entry,deadline,reply-10**9,reply)
        self.assertEqual(cutoff+receiver.RESERVE_NS-remote_timestamp,deadline-reply-receiver.RESERVE_NS)
        self.assertLess(cutoff+receiver.RESERVE_NS-remote_timestamp,deadline-reply)

    def test_metadata_environment_loader_or_proxy_substitution_refuses(self):
        for key,value in (('Environment','PATH=/usr/bin'),('UnsetEnvironment','PYTHONPATH')):
            actual=self.effective();actual[key]=value
            with self.assertRaises(ValueError):receiver.verify_unit(actual,TOKEN,10000000)

    def test_exact_staging_profile_and_no_readonly_label_promotion(self):
        import guard_yoga_install_inputs_profile as profile
        import guard_yoga_delivery_profile as old
        self.assertEqual(profile.selected(['run',sender.LABEL]),{'PrivateNetwork':'no'})
        for args in (['run','//tools:yoga_controller_qualify'],['test',sender.LABEL],
                     ['run',sender.LABEL,'--arbitrary'],['run','//delivery:install']):
            with self.assertRaises(ValueError):profile.selected(args)
        with self.assertRaises(ValueError):old.selected(['run',sender.LABEL])
        with self.assertRaises(ValueError):profile.finite(['run',sender.LABEL],'user',TOKEN,())
        with self.assertRaises(ValueError):profile.finite(['run',sender.LABEL],'system',TOKEN,(True,))
        profile.finite(['run',sender.LABEL],'system',TOKEN,())

    def test_regular_placeholder_requires_leaf_nonrecursive_readback(self):
        import guard_yoga_install_inputs_profile as profile
        agent=profile.Agent.__new__(profile.Agent)
        agent.namespace=Path('/fixed/private/inputs')
        agent.source='/run/user/1000/gnupg/S.gpg-agent.ssh'
        agent.check=mock.Mock()
        good={'BindReadOnlyPaths':str(agent.namespace)+':/omux-yoga-install-inputs:rbind '+agent.source+':'+profile.ALIAS,
              'BindPaths':''}
        self.assertTrue(agent.verify_bindings(good))
        for extra in (':rbind',':norbind'):
            bad=dict(good,BindReadOnlyPaths=good['BindReadOnlyPaths']+extra)
            with self.assertRaises(ValueError):agent.verify_bindings(bad)
        with self.assertRaises(ValueError):agent.verify_bindings(dict(good,BindPaths='/foreign'))


    def test_actual_guard_command_uses_only_closed_stage_and_offline_cache_pair(self):
        import execution_guard as guard
        import guard_resident_enrollment_profile as policy
        now=time.monotonic_ns()
        prior={'sha256':'a'*64,'path':'/fixed/prior/qualification.json'}
        command,env=guard.yoga_delivery_command('/nix/store/fixed/bin/bazel',Path('/fixed/run'),
            ['run',sender.LABEL],now+receiver.MAX_NS,prior,
            source_commit='1'*40,source_dirty='false',repository_cache=policy.REPOSITORY_CACHE,
            nixpkgs_source=policy.NIXPKGS_SOURCE)
        self.assertIn('run',command)
        self.assertIn('--repository_disable_download',command)
        self.assertIn('--repo_contents_cache=',command)
        self.assertIn('--repository_cache='+str(policy.REPOSITORY_CACHE),command)
        self.assertEqual(env['OMUX_YOGA_DELIVERY_MODE'],'stage-install-inputs')
        self.assertEqual(int(env['OMUX_YOGA_DELIVERY_DEADLINE_NS'])-
            int(env['OMUX_YOGA_INSTALL_INPUTS_ENTRY_NS']),receiver.MAX_NS)
        with self.assertRaises(ValueError):
            guard.yoga_delivery_command('bazel',Path('/fixed/run'),['run','//delivery:install'],
                                        now+receiver.MAX_NS,prior)

    def test_actual_guard_effective_sender_caps_and_cgroup_drift(self):
        import execution_guard as guard
        import guard_yoga_install_inputs_profile as profile
        isolation={**guard.SANDBOX,**guard.selected_profile(profile.PROFILE,['run',sender.LABEL])}
        self.assertEqual(isolation['PrivateNetwork'],'no')
        actual=dict(guard.PROPERTIES,**isolation)
        actual.update(MemoryMax='4026531840',TasksMax='480',CPUQuotaPerSecUSec='1.900000s',
                      RuntimeMaxUSec='60s',PrivateNetwork='no',
                      UnsetEnvironment=' '.join(guard.DELEGATION_ENV))
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            values={'memory.max':'4026531840','memory.swap.max':'0','pids.max':'480',
                    'memory.oom.group':'1','cpu.max':'190000 100000'}
            for name,value in values.items():(root/name).write_text(value+'\n')
            with mock.patch.object(guard,'verify_system_masks'):
                guard.verify(actual,root,manager='system',isolation=isolation,
                             profile=profile.PROFILE,runtime_seconds=60)
                actual['PrivateNetwork']='yes'
                with self.assertRaises(ValueError):
                    guard.verify(actual,root,manager='system',isolation=isolation,
                                 profile=profile.PROFILE,runtime_seconds=60)
                actual['PrivateNetwork']='no'
                for name,bad in (('memory.max','4026531841'),('pids.max','481'),
                                 ('cpu.max','190001 100000')):
                    (root/name).write_text(bad+'\n')
                    with self.assertRaises(ValueError):
                        guard.verify(actual,root,manager='system',isolation=isolation,
                             profile=profile.PROFILE,runtime_seconds=60)
                    (root/name).write_text(values[name]+'\n')
            self.assertEqual(guard.workload_pids_observation(None,profile.PROFILE).expected_limit,480)

    def test_missing_unit_status_four_only_for_closed_absence(self):
        value=self.effective()
        value.update(LoadState='not-found',ActiveState='inactive',SubState='dead',
                     MainPID='0',ControlGroup='',InvocationID='')
        raw=lambda value:'\n'.join(key+'='+item for key,item in value.items()).encode()
        with mock.patch.object(receiver,'bounded',return_value=(4,raw(value))):
            self.assertEqual(receiver.show(TOKEN,DEADLINE,missing=True),value)
        value['LoadState']='loaded'
        with mock.patch.object(receiver,'bounded',return_value=(4,raw(value))):
            with self.assertRaises(ValueError):receiver.show(TOKEN,DEADLINE,missing=True)

    def test_actual_cleanup_accepts_captured_loaded_or_collected_unit_only(self):
        before=self.effective()
        before.update(MainPID='0',SubState='exited')
        for collected in (False,True):
            final=dict(before,LoadState='not-found' if collected else 'loaded',
                ActiveState='inactive',SubState='dead',ControlGroup='',
                InvocationID='' if collected else before['InvocationID'])
            group=mock.Mock(events=101,procs=102)
            with mock.patch.object(receiver,'show',side_effect=[before,final]), \
                 mock.patch.object(receiver,'session_peer',return_value=('owned',)), \
                 mock.patch.object(receiver,'bounded') as operation, \
                 mock.patch.object(receiver.os,'pread',side_effect=[b'populated 0\n',b'']), \
                 mock.patch.object(receiver,'process',side_effect=FileNotFoundError):
                self.assertTrue(receiver.cleanup_unit(TOKEN,(123,456,1000),'a'*32,('owned',),group,DEADLINE,work_deadline=DEADLINE,source='# public source'))
                self.assertEqual(operation.call_args.args[0],
                    [receiver.SYSTEMCTL,'--user','stop',receiver.unit_name(TOKEN)])
            for fault in ('populated','foreign-invocation','foreign-id'):
                bad=dict(final)
                if fault=='foreign-invocation':bad['InvocationID']='b'*32
                if fault=='foreign-id':bad['Id']='foreign.service'
                with mock.patch.object(receiver,'show',side_effect=[before,bad]), \
                     mock.patch.object(receiver,'session_peer',return_value=('owned',)), \
                     mock.patch.object(receiver,'bounded'), \
                     mock.patch.object(receiver.os,'pread',side_effect=[b'populated 1\n' if fault=='populated' else b'populated 0\n',b'']):
                    with self.assertRaises(ValueError):
                        receiver.cleanup_unit(TOKEN,(123,456,1000),'a'*32,('owned',),group,DEADLINE,work_deadline=DEADLINE,source='# public source')

    def test_default_query_does_not_read_resident_environment(self):
        value={'Id':receiver.DEFAULT_UNIT,'LoadState':'not-found','ActiveState':'inactive',
               'SubState':'dead','MainPID':'0','ControlGroup':''}
        raw='\n'.join(key+'='+item for key,item in value.items()).encode()
        held=mock.Mock(path=Path('/sys/fs/cgroup/user.slice/user-'+str(os.getuid())+
            '.slice/user@'+str(os.getuid())+'.service/app.slice'),fd=100)
        with mock.patch.object(receiver,'bounded',return_value=(4,raw)) as operation, \
             mock.patch.object(receiver,'Directory',return_value=held), \
             mock.patch.object(receiver.os,'stat',side_effect=FileNotFoundError):
            self.assertEqual(receiver.default_disposition(DEADLINE,cleanup_deadline=DEADLINE),
                {'default_named_unit_inactive_or_missing':True,'cgroup_absent':True})
            self.assertEqual(operation.call_args.args[0][-1],
                '--property='+','.join(receiver.DEFAULT_SHOW))
            self.assertNotIn('Environment',operation.call_args.args[0][-1])
            self.assertEqual(operation.call_args.kwargs['cleanup_deadline'],DEADLINE)

    def test_profile_postcleanup_query_uses_same_original_deadline(self):
        import guard_yoga_install_inputs_profile as profile
        disposition={'default_named_unit_inactive_or_missing':True,'cgroup_absent':True}
        with mock.patch.object(profile,'LOCAL_DISPOSITION',(('peer',),disposition)), \
             mock.patch.object(profile,'AGENT',None), \
             mock.patch.object(receiver,'session_peer',return_value=('peer',)), \
             mock.patch.object(receiver,'default_disposition',return_value=disposition) as query:
            self.assertEqual(profile.observe(DEADLINE,cleanup=True),disposition)
            query.assert_called_once_with(DEADLINE,cleanup_deadline=DEADLINE)

    def test_actual_submitted_receiver_public_command_and_executable_join(self):
        source='# exact declared public receiver'
        expected=b'\0'.join(os.fsencode(item) for item in
            (receiver.PYTHON,'-I','-S','-c',receiver.worker_code(TOKEN,DEADLINE,source)))+b'\0'
        for raw in (expected,b'/foreign/private-unknown-command\0',expected+b'extra'):
            with mock.patch.object(receiver,'process',return_value=(123,456,os.getuid())), \
                 mock.patch.object(receiver.os,'readlink',return_value=receiver.PYTHON), \
                 mock.patch.object(receiver.os,'open',return_value=100), \
                 mock.patch.object(receiver.os,'read',side_effect=[raw,b'']), \
                 mock.patch.object(receiver.os,'close') as release:
                if raw==expected:
                    self.assertEqual(receiver.receiver_process(123,TOKEN,DEADLINE,source,DEADLINE),
                        (123,456,os.getuid()))
                else:
                    with self.assertRaises(ValueError):
                        receiver.receiver_process(123,TOKEN,DEADLINE,source,DEADLINE)
                release.assert_called_once_with(100)
        with mock.patch.object(receiver,'process',return_value=(123,456,os.getuid())), \
             mock.patch.object(receiver.os,'readlink',return_value='/foreign/python'), \
             mock.patch.object(receiver.os,'open') as opened:
            with self.assertRaises(ValueError):
                receiver.receiver_process(123,TOKEN,DEADLINE,source,DEADLINE)
            opened.assert_not_called()

    def test_failed_live_submission_join_prevents_named_stop(self):
        before=self.effective()
        with mock.patch.object(receiver,'show',return_value=before), \
             mock.patch.object(receiver,'session_peer',return_value=('owned',)), \
             mock.patch.object(receiver,'receiver_process',side_effect=ValueError('wrong submitted source')), \
             mock.patch.object(receiver,'bounded') as operation:
            with self.assertRaises(ValueError):
                receiver.cleanup_unit(TOKEN,(123,456,1000),'a'*32,('owned',),mock.Mock(),
                    DEADLINE,work_deadline=DEADLINE,source='# exact public source')
            operation.assert_not_called()


class TransactionTest(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.parent=Path(self.temporary.name)
        self.raws=(b'opaque-public-archive-fixture',b'public-original-receipt-fixture')
        self.rows=((receiver.ARCHIVE,len(self.raws[0]),hashlib.sha256(self.raws[0]).hexdigest()),
                   ('receipt.json',len(self.raws[1]),hashlib.sha256(self.raws[1]).hexdigest()))
        self.patches=[mock.patch.object(receiver,'PARENT',str(self.parent)),
                      mock.patch.object(receiver,'FILES',self.rows),
                      mock.patch.object(receiver,'Directory',FixtureDirectory)]
        for value in self.patches:value.start()
        self.deadline=time.monotonic_ns()+60*10**9

    def tearDown(self):
        for value in reversed(self.patches):value.stop()
        self.temporary.cleanup()

    def stream(self,*,corrupt=False,truncate=False):
        read,write=os.pipe()
        try:
            for index,(role,count,digest) in enumerate(self.rows):
                os.write(write,receiver.canonical({'role':role,'bytes':count,'sha256':digest})+b'\n')
                raw=self.raws[index]
                if corrupt and index==0:raw=b'x'*len(raw)
                if truncate and index==0:
                    os.write(write,raw[:2]);break
                os.write(write,raw)
            if not truncate:os.write(write,receiver.canonical({'end':receiver.SCOPE})+b'\n')
        finally:os.close(write)
        return read

    def test_actual_exclusive_two_file_publication_and_independent_rehash(self):
        fd=self.stream();transaction=receiver.Transaction(self.deadline)
        try:
            result=transaction.receive(fd)
            self.assertTrue(result['destination_rehashed'])
            receiver.destination_readback(self.deadline)
            root=self.parent/receiver.EPOCH
            for row,raw in zip(self.rows,self.raws):
                path=root/row[0]
                self.assertEqual(path.read_bytes(),raw)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o400)
            self.assertFalse(any(path.name.endswith('.receiving') for path in root.rglob('*')))
        finally:
            os.close(fd);transaction.close()

    def test_corruption_or_truncation_never_names_receipt_and_cleans_owned_tree(self):
        for options in ({'corrupt':True},{'truncate':True}):
            fd=self.stream(**options);transaction=receiver.Transaction(self.deadline)
            try:
                with self.assertRaises(ValueError):transaction.receive(fd)
                self.assertFalse((self.parent/receiver.EPOCH/'receipt.json').exists())
            finally:
                os.close(fd);transaction.close()
            self.assertFalse((self.parent/receiver.EPOCH).exists())

    def test_existing_epoch_foreign_or_partial_never_adopted(self):
        root=self.parent/receiver.EPOCH;root.mkdir()
        (root/'foreign').write_bytes(b'not ours')
        with self.assertRaises(ValueError):receiver.Transaction(self.deadline)
        self.assertEqual((root/'foreign').read_bytes(),b'not ours')

    def test_expired_work_uses_same_original_cleanup_tail(self):
        transaction=receiver.Transaction(self.deadline);transaction.create()
        with mock.patch.object(receiver.time,'monotonic_ns',return_value=self.deadline+1):
            transaction.close()
        self.assertFalse((self.parent/receiver.EPOCH).exists())

    def test_failed_first_open_keeps_creation_pin_for_safe_cleanup(self):
        transaction=receiver.Transaction(self.deadline)
        actual=os.open
        def fail(name,*args,**kwargs):
            if name==receiver.EPOCH:raise PermissionError()
            return actual(name,*args,**kwargs)
        with mock.patch.object(receiver.os,'open',side_effect=fail):
            with self.assertRaises(PermissionError):transaction.create()
        transaction.close()
        self.assertFalse((self.parent/receiver.EPOCH).exists())

    def test_uncaptured_creation_refuses_destructive_cleanup(self):
        transaction=receiver.Transaction(self.deadline)
        actual_stat,actual_mkdir=os.stat,os.mkdir
        made={'epoch':False}
        def create(name,*args,**kwargs):
            result=actual_mkdir(name,*args,**kwargs)
            if name==receiver.EPOCH:made['epoch']=True
            return result
        def fail(name,*args,**kwargs):
            if name==receiver.EPOCH and made['epoch']:raise PermissionError()
            return actual_stat(name,*args,**kwargs)
        with mock.patch.object(receiver.os,'mkdir',side_effect=create), \
             mock.patch.object(receiver.os,'stat',side_effect=fail):
            with self.assertRaises(PermissionError):transaction.create()
        self.assertTrue(made['epoch'])
        self.assertEqual(len(transaction.created),1)
        self.assertEqual(transaction.created[0][1:], [receiver.EPOCH,None])
        self.assertEqual(transaction.dirs,[])
        with mock.patch.object(receiver.os,'unlink') as unlink, \
             mock.patch.object(receiver.os,'rmdir') as rmdir:
            with self.assertRaises(ValueError):transaction.close()
            unlink.assert_not_called()
            rmdir.assert_not_called()
        self.assertTrue((self.parent/receiver.EPOCH).is_dir())

    def test_destination_rebound_during_receive_refuses_and_preserves_foreign(self):
        transaction=receiver.Transaction(self.deadline);transaction.create()
        root=self.parent/receiver.EPOCH
        root.rename(self.parent/'retired')
        root.mkdir();(root/'foreign').write_bytes(b'foreign')
        with self.assertRaises(ValueError):transaction.close()
        self.assertEqual((root/'foreign').read_bytes(),b'foreign')

    def test_final_collision_is_not_replaced_and_cleanup_does_not_delete_foreign(self):
        actual=os.link
        def collide(src,dst,*args,**kwargs):
            parent=kwargs['dst_dir_fd']
            fd=os.open(dst,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
            try:os.write(fd,b'foreign')
            finally:os.close(fd)
            return actual(src,dst,*args,**kwargs)
        fd=self.stream();transaction=receiver.Transaction(self.deadline)
        try:
            with mock.patch.object(receiver.os,'link',side_effect=collide):
                with self.assertRaises(FileExistsError):transaction.receive(fd)
            with self.assertRaises(ValueError):transaction.close()
            root=self.parent/receiver.EPOCH
            self.assertEqual((root/receiver.ARCHIVE).read_bytes(),b'foreign')
            self.assertFalse((root/'receipt.json').exists())
        finally:
            os.close(fd)


    def test_first_temp_fstat_fault_closes_fd_and_preserves_unknown_name(self):
        transaction=receiver.Transaction(self.deadline)
        actual_open,actual_stat=os.open,os.fstat
        chosen={'fd':None,'failed':False}
        def capture(name,*args,**kwargs):
            fd=actual_open(name,*args,**kwargs)
            if isinstance(name,str) and name.endswith('.receiving'):chosen['fd']=fd
            return fd
        def fail(fd):
            if fd==chosen['fd'] and not chosen['failed']:
                chosen['failed']=True
                raise OSError('fixture fstat failure')
            return actual_stat(fd)
        incoming=self.stream()
        try:
            with mock.patch.object(receiver.os,'open',side_effect=capture),mock.patch.object(receiver.os,'fstat',side_effect=fail):
                with self.assertRaises(OSError):transaction.receive(incoming)
            with self.assertRaises(ValueError):transaction.close()
            with self.assertRaises(OSError):actual_stat(chosen['fd'])
            path=self.parent/receiver.EPOCH/Path(receiver.ARCHIVE).parent/('.'+Path(receiver.ARCHIVE).name+'.receiving')
            self.assertTrue(path.is_file())
            self.assertFalse((self.parent/receiver.EPOCH/'receipt.json').exists())
        finally:os.close(incoming)


if __name__=='__main__':unittest.main()
