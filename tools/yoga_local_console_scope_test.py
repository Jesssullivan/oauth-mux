"""Real pipe/pidfd/anchored-directory fixtures; no manager/console/provider use."""
import os
import hashlib
from pathlib import Path
import select
import io
import tempfile
import time
import unittest
from unittest import mock
import yoga_local_console_scope as route
import yoga_local_console_qualification as launcher
# Declared successor models run through this existing closed Yoga test target.
from yoga_installed_console_selection_test import Models as InstalledConsoleSelectionModels
from yoga_local_parent_envelope_test import DirectGuardianModels as LocalParentEnvelopeModels


class Models(unittest.TestCase):
    def arguments(self):
        return ['run',route.LABEL,'--selection','/srv/selection.json','--selection-sha256','a'*64,
            '--output','/srv/qualification.json','--deadline-monotonic-ns','1200000000100']

    def test_exact_route_and_early_refusal_before_external_or_console(self):
        with mock.patch.object(route.qualification,'budget'):
            self.assertEqual(route.request(self.arguments())[-1],1200000000100)
        bad = [self.arguments()[:-2],self.arguments()+['--other','x'],
            ['test',*self.arguments()[1:]], ['run','//tools:yoga_session_qualification',*self.arguments()[2:]],
            ['run',route.LABEL,*reversed(self.arguments()[2:])]]
        with (mock.patch.object(route.subprocess,'run',side_effect=AssertionError('external')) as external,
              mock.patch.object(route.qualification,'identity_capture',side_effect=AssertionError('console')) as console):
            for arguments in bad:
                with self.subTest(arguments=arguments), mock.patch.object(launcher.sys,'stdin') as stdin:
                    stdin.fileno.return_value = 0
                    self.assertEqual(launcher.main(arguments),125)
            external.assert_not_called();console.assert_not_called()

    def test_caps_zero_swap_exact_cpu_and_no_standard_overlap(self):
        values = {'memory.max':str(route.MEMORY),'memory.swap.max':'0','pids.max':'480','cpu.max':'190000 100000','memory.oom.group':'1'}
        self.assertEqual(route.cap_values(values),values)
        for key,bad in [('memory.max','4294967296'),('memory.swap.max','1'),('pids.max','512'),
                        ('cpu.max','200000 100000'),('cpu.max','max 100000'),('memory.oom.group','0')]:
            with self.subTest(key=key),self.assertRaises(ValueError): route.cap_values(dict(values,**{key:bad}))

    def test_real_regular_descriptor_is_not_operator_terminal(self):
        with tempfile.TemporaryFile() as stream,self.assertRaises(ValueError):
            route.terminal_identity(stream.fileno())

    def test_uncontained_console_refuses_before_manager_or_cgroup_reads(self):
        with (mock.patch.object(route.yoga,'file_bytes',return_value=b'0::/user.slice/unrelated.scope\n'),
              mock.patch.object(route.kernel,'open_chain',side_effect=AssertionError('cgroup')),
              mock.patch.object(route.subprocess,'run',side_effect=AssertionError('manager'))):
            with self.assertRaises(ValueError):route.ProjectEnvelope({},100,1200000000100)

    def test_project_slice_and_envelope_names_must_share_exact_uuid(self):
        a,b='a'*32,'b'*32
        raw=('0::/omuxyogaconsole'+a+'.slice/omux-yoga-console-envelope-'+b+'.scope\n').encode()
        with (mock.patch.object(route.yoga,'file_bytes',return_value=raw),
              mock.patch.object(route.kernel,'open_chain',side_effect=AssertionError('cgroup'))):
            with self.assertRaises(ValueError):route.ProjectEnvelope({},100,1200000000100)

    def test_real_terminal_rebinding_and_selected_audit_session_refuse(self):
        a,b=os.openpty();c,d=os.openpty();held=os.dup(b)
        try:
            identity=route.terminal_identity(held)
            route.recheck_terminal(held,identity)
            os.dup2(d,held)
            with self.assertRaises(ValueError):route.recheck_terminal(held,identity)
            uid=os.getuid()
            value={'host':{'machineIdSha256':hashlib.sha256(b'machine').hexdigest(),
                           'bootIdSha256':hashlib.sha256(b'boot').hexdigest()},
                   'seat':{'sessionId':'model','seatId':'seat0'},'operatorTerminal':os.ttyname(b)}
            record=('UID='+str(uid)+'\nSEAT=seat0\nTYPE=wayland\nACTIVE=1\nREMOTE=0\nAUDIT=13\n').encode()
            def fixture(path,*unused,**kwargs):
                return {'/etc/machine-id':b'machine','/proc/sys/kernel/random/boot_id':b'boot',
                    '/run/systemd/sessions/model':record,
                    '/proc/'+str(os.getpid())+'/sessionid':b'14',
                    '/proc/'+str(os.getpid())+'/loginuid':str(uid).encode()}[path]
            with mock.patch.object(route.yoga,'file_bytes',side_effect=fixture),self.assertRaises(ValueError):
                route.yoga.local_identity(value,1200000000100,uid,b)
        finally:
            for fd in (a,b,c,d,held):os.close(fd)

    def test_actual_scope_helper_and_pipe_hold_go_until_caps_identity_and_resident_match(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root);fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            scope=object.__new__(route.Scope);scope.pid=os.getpid();scope.pidfd=os.pidfd_open(scope.pid,0)
            scope.chain=[(path,fd,route.resident.stable(os.fstat(fd)))];scope.bounds=None
            scope.initial=route.kernel.process(scope.pid);scope.invocation='a'*32
            scope.group='/system.slice/omux-yoga-console-fixture.scope';scope.seconds=10
            scope.manager=mock.Mock(entry=100,deadline=1200000000100)
            facts={'LoadState':'loaded','ActiveState':'active','SubState':'running',
                'InvocationID':scope.invocation,'ControlGroup':scope.group,'MemoryMax':str(route.MEMORY),
                'MemorySwapMax':'0','MemoryOOMGroup':'yes','TasksMax':'480','CPUQuotaPerSecUSec':'1.9s','RuntimeMaxUSec':'10s'}
            scope.manager.show.return_value=facts
            for name,value in {'memory.max':str(route.MEMORY),'memory.swap.max':'0','pids.max':'480',
                               'cpu.max':'190000 100000','cgroup.procs':str(scope.pid),
                               'pids.current':'1','cgroup.events':'populated 1\nfrozen 0','memory.oom.group':'1'}.items():
                (path/name).write_text(value)
            read,write=os.pipe();reservation=mock.Mock()
            try:
                with mock.patch.object(route.kernel,'remaining',return_value=10):
                    (path/'memory.swap.max').write_text('1')
                    with self.assertRaises(ValueError):route.release_go(write,scope,reservation)
                    self.assertFalse(select.select([read],[],[],0)[0])
                    (path/'memory.swap.max').write_text('0');facts['InvocationID']='b'*32
                    with self.assertRaises(ValueError):route.release_go(write,scope,reservation)
                    self.assertFalse(select.select([read],[],[],0)[0])
                    facts['InvocationID']=scope.invocation
                    reservation.observe.side_effect=ValueError('resident drift')
                    with self.assertRaises(ValueError):route.release_go(write,scope,reservation)
                    self.assertFalse(select.select([read],[],[],0)[0])
                    reservation.observe.side_effect=None
                    route.release_go(write,scope,reservation);self.assertEqual(os.read(read,1),b'G')
            finally:
                os.close(read);os.close(write);os.close(scope.pidfd);scope.close()

    def test_real_pidfd_requires_ready_and_retains_failed_wait_status(self):
        read,write = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(write); os.read(read,1); os._exit(7)
        os.close(read)
        fd = os.pidfd_open(child,0)
        scope = object.__new__(route.Scope);scope.pidfd=fd;scope.exit_status=None
        try:
            with self.assertRaises(ValueError): scope.terminal(7 << 8)
            os.close(write);write=None
            self.assertTrue(select.select([fd],[],[],5)[0])
            pid,status = os.waitpid(child,0);self.assertEqual(pid,child)
            self.assertEqual(scope.terminal(status),7)
            with self.assertRaises(ValueError):scope.terminal(status)
        finally:
            if write is not None:os.close(write)
            os.close(fd)

    def test_real_anchored_directory_refuses_replacement_and_foreign_absence(self):
        with tempfile.TemporaryDirectory() as root:
            parent=Path(root);leaf=parent/'scope';leaf.mkdir()
            a=os.open(parent,os.O_RDONLY|os.O_DIRECTORY);b=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY)
            scope=object.__new__(route.Scope)
            scope.chain=[(parent,a,route.resident.stable(os.fstat(a))),
                         (leaf,b,route.resident.stable(os.fstat(b)))]
            try:
                self.assertTrue(scope.anchored())
                leaf.rmdir();self.assertFalse(scope.anchored(allow_absent=True))
                with self.assertRaises(ValueError):scope.anchored()
                leaf.mkdir()
                with self.assertRaises(ValueError):scope.anchored(allow_absent=True)
            finally:scope.close()

    def test_absent_owned_scope_requires_two_exact_manager_readbacks(self):
        scope=object.__new__(route.Scope);scope.exit_status=7
        scope.manager=mock.Mock(entry=100,deadline=1200000000100)
        scope.manager.show.return_value={'LoadState':'not-found','ActiveState':'inactive',
            'InvocationID':'','ControlGroup':''}
        scope.anchored=mock.Mock(return_value=False)
        with mock.patch.object(route.kernel,'remaining',return_value=10):
            self.assertTrue(scope.cleanup())
            self.assertEqual(scope.manager.show.call_count,2)
            scope.manager.show.return_value['InvocationID']='b'*32
            with self.assertRaises(ValueError):scope.cleanup()
            scope.manager.show.return_value['InvocationID']=''
            scope.manager.show.return_value['ActiveState']='active'
            with self.assertRaises(ValueError):scope.cleanup()

    def test_reaped_worker_does_not_skip_owned_descendant_cleanup_and_drift_refuses_stop(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root);fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            scope=object.__new__(route.Scope);scope.chain=[(path,fd,route.resident.stable(os.fstat(fd)))]
            scope.exit_status=7;scope.invocation='a'*32;scope.group='/fixture';scope.seconds=10
            scope.manager=mock.Mock(entry=100,deadline=1200000000100)
            facts={'LoadState':'loaded','ActiveState':'active','InvocationID':scope.invocation,
                'ControlGroup':scope.group,'MemoryMax':str(route.MEMORY),'MemorySwapMax':'0',
                'MemoryOOMGroup':'yes','TasksMax':'480','CPUQuotaPerSecUSec':'1.9s','RuntimeMaxUSec':'10s'}
            scope.manager.show.return_value=facts
            values={'memory.max':str(route.MEMORY),'memory.swap.max':'0','pids.max':'480',
                    'cpu.max':'190000 100000','memory.oom.group':'1'}
            scope.bounds=values
            for name,value in dict(values,**{'cgroup.procs':'123','cgroup.events':'populated 1'}).items():
                (path/name).write_text(value)
            def stop(invocation):
                self.assertEqual(invocation,scope.invocation)
                facts['ActiveState']='inactive'
                (path/'cgroup.procs').write_text('');(path/'cgroup.events').write_text('populated 0')
            scope.manager.stop.side_effect=stop
            try:
                with mock.patch.object(route.kernel,'remaining',return_value=10):
                    with self.assertRaises(ValueError):scope.cleanup()
                    facts['InvocationID']='b'*32
                    with self.assertRaises(ValueError):route.settle_reaped(scope,False)
                    scope.manager.stop.assert_not_called()
                    facts['InvocationID']=scope.invocation
                    self.assertTrue(route.settle_reaped(scope,False))
                    scope.manager.stop.assert_called_once_with(scope.invocation)
                    self.assertEqual(scope.exit_status,7)
                    scope.manager.show.reset_mock()
                    self.assertTrue(route.settle_reaped(scope,True));scope.manager.show.assert_not_called()
            finally:scope.close()

    def test_ready_unreaped_child_settles_owned_descendants_once_and_preserves_exit(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root);fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            scope=object.__new__(route.Scope);scope.chain=[(path,fd,route.resident.stable(os.fstat(fd)))]
            scope.exit_status=None;scope.invocation='a'*32;scope.group='/fixture';scope.seconds=10
            scope.manager=mock.Mock(entry=100,deadline=1200000000100)
            facts={'LoadState':'loaded','ActiveState':'active','InvocationID':scope.invocation,
                'ControlGroup':scope.group,'MemoryMax':str(route.MEMORY),'MemorySwapMax':'0',
                'MemoryOOMGroup':'yes','TasksMax':'480','CPUQuotaPerSecUSec':'1.9s','RuntimeMaxUSec':'10s'}
            scope.manager.show.return_value=facts
            scope.bounds={'memory.max':str(route.MEMORY),'memory.swap.max':'0','pids.max':'480',
                'cpu.max':'190000 100000','memory.oom.group':'1'}
            for name,value in dict(scope.bounds,**{'cgroup.procs':'123','cgroup.events':'populated 1'}).items():
                (path/name).write_text(value)
            def stop(invocation):
                self.assertEqual(invocation,scope.invocation)
                facts['ActiveState']='inactive'
                (path/'cgroup.procs').write_text('');(path/'cgroup.events').write_text('populated 0')
            scope.manager.stop.side_effect=stop
            child=os.fork()
            if child == 0:os._exit(7)
            scope.pidfd=os.pidfd_open(child);marked=[]
            try:
                self.assertTrue(select.select([scope.pidfd],[],[],5)[0])
                entry=time.monotonic_ns();deadline=entry+1200*10**9
                with mock.patch.object(route.kernel,'remaining',return_value=10), \
                        mock.patch.object(route.os,'waitpid',wraps=os.waitpid) as reaper:
                    self.assertTrue(route.terminate_child(child,scope.pidfd,scope,False,False,
                        entry,deadline,lambda:marked.append(True)))
                    reaper.assert_called_once_with(child,os.WNOHANG)
                self.assertEqual(marked,[True]);self.assertEqual(scope.exit_status,7)
                scope.manager.stop.assert_called_once_with(scope.invocation)
                with mock.patch.object(route.kernel,'remaining',return_value=10):
                    self.assertTrue(scope.cleanup())
                with mock.patch.object(route.os,'waitpid',side_effect=AssertionError('second reap')):
                    self.assertTrue(route.terminate_child(child,scope.pidfd,scope,True,True,
                        100,1200000000100,lambda:marked.append(True)))
                self.assertEqual(marked,[True])
            finally:
                if not marked:os.waitpid(child,0)
                os.close(scope.pidfd);scope.close()

    def test_live_child_first_stop_can_remove_scope_without_second_stop(self):
        child=os.fork()
        if child == 0:
            select.select([],[],[],10);os._exit(0)
        scope=object.__new__(route.Scope);scope.pidfd=os.pidfd_open(child);scope.exit_status=None
        scope.manager=mock.Mock(entry=100,deadline=1200000000100)
        scope.manager.show.return_value={'LoadState':'not-found','ActiveState':'inactive',
            'InvocationID':'','ControlGroup':''}
        scope.anchored=mock.Mock(return_value=False)
        scope.stop_owned=mock.Mock(side_effect=lambda:route.signal.pidfd_send_signal(scope.pidfd,route.signal.SIGKILL))
        marked=[]
        try:
            self.assertFalse(select.select([scope.pidfd],[],[],0)[0])
            entry=time.monotonic_ns();deadline=entry+1200*10**9
            with mock.patch.object(route.kernel,'remaining',return_value=10):
                self.assertTrue(route.terminate_child(child,scope.pidfd,scope,False,False,
                    entry,deadline,lambda:marked.append(True)))
            scope.stop_owned.assert_called_once_with()
            self.assertEqual(scope.manager.show.call_count,2)
            self.assertEqual(marked,[True]);self.assertEqual(scope.exit_status,-route.signal.SIGKILL)
        finally:
            if not marked:
                route.signal.pidfd_send_signal(scope.pidfd,route.signal.SIGKILL);os.waitpid(child,0)
            os.close(scope.pidfd)

    def test_partial_creation_refusal_retains_only_generated_unit_and_unknown_ownership(self):
        manager=mock.Mock(unit='omux-yoga-console-'+('a'*8+'-'+ 'a'*4+'-'+ 'a'*4+'-'+ 'a'*4+'-'+ 'a'*12)+'.scope')
        projection=route.refusal_projection(manager,None,True,False,True,False)
        self.assertEqual(projection['scopeUnit'],manager.unit)
        self.assertIsNone(projection['scopeInvocationId'])
        self.assertFalse(projection['initialScopeOwnershipVerified']);self.assertFalse(projection['ownedCleanupEmpty'])
        self.assertFalse(projection['qualificationProduced']);self.assertFalse(projection['consoleEnvelopeCleanupQualified'])
        with (mock.patch.object(route,'run',side_effect=route.Refusal(projection)),
              mock.patch.object(launcher.sys,'stdout',new_callable=io.StringIO) as output,
              mock.patch.object(launcher.sys,'stderr',new_callable=io.StringIO)):
            self.assertEqual(launcher.main(self.arguments()),125)
            self.assertIn(manager.unit,output.getvalue())

    def test_offline_exact_bazel_command_and_fresh_state(self):
        selection={'sourceRoot':'/srv/sealed','controllerTools':{'bazel':'/nix/store/tool/bin/bazel','java_home':'/nix/store/jdk'}}
        with mock.patch.object(route.qualification,'budget'):
            command=route.command(selection,'/srv/sealed','/srv/new/output-base',self.arguments())
            self.assertEqual(command[-10:],[route.LABEL,'--',*self.arguments()[2:]])
            self.assertIn('--remote_executor=',command);self.assertIn('--remote_cache=',command)
            self.assertIn('--disk_cache=',command);self.assertIn('--repository_disable_download',command)
            self.assertIn('--nosystem_rc',command);self.assertIn('--nohome_rc',command)
            with self.assertRaises(ValueError):route.command(selection,'/srv/sealed','/srv/sealed/base',self.arguments())

    def test_original_clock_has_no_extension_and_final_reserve(self):
        with mock.patch.object(route.kernel.time,'monotonic_ns',return_value=1170000000100):
            with self.assertRaises(ValueError):route.kernel.remaining(100,1200000000100)
            self.assertEqual(route.kernel.remaining(100,1200000000100,cleanup=True),30)
            with self.assertRaises(ValueError):route.kernel.remaining(100,1200000000101,cleanup=True)


if __name__ == '__main__':unittest.main()
