"""Custody/real byte-stage models; never run daemon, Qt, browser or provider."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import dev_stage_complete_retained as adapter
import portable
from dev_generation import GenerationError, select_generation


class CompleteRetainedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.epoch = self.base / '5102699b-2ebf-44f1-a454-62b098e49658'
        self.epoch.mkdir(mode=0o700)
        self.entry = time.monotonic_ns() - 10**9
        self.deadline = self.entry + 1200 * 10**9
        self.graph = 'd' * 64  # Synthetic graph; no actual guard admission claimed.
        self.admission = {'schemaVersion':1,'scope':adapter.SCOPE,'label':adapter.LABEL,
            'epoch':self.epoch.name,'entryMonotonicNs':self.entry,
            'deadlineMonotonicNs':self.deadline,'graphSha256':self.graph}
        self.write('dev-stage-admission.json',json.dumps(self.admission).encode())
        self.write('supervisor.json',json.dumps({'id':self.epoch.name,'pid':os.getpid(),
            'start_ticks':adapter.process(os.getpid())}).encode())
        self.write('go',b'')
        self.output = self.epoch / ('output-base/sandbox/processwrapper-sandbox/1/execroot/_main/'
            'bazel-out/k8-fastbuild/testlogs/delivery/dev_stage_complete_retained/test.outputs')
        self.output.mkdir(parents=True,mode=0o700)
        self.environment = {'OMUX_EXECUTION_GUARD':str(self.epoch),
            adapter.ENTRY_ENV:str(self.entry),adapter.DEADLINE_ENV:str(self.deadline),
            'TEST_UNDECLARED_OUTPUTS_DIR':str(self.output)}

    def write(self,name,data):
        path = self.epoch/name
        path.write_bytes(data)
        path.chmod(0o600)

    def inputs(self):
        from test_dev_generation import GenerationTest
        fixture = GenerationTest(methodName='runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        assembly, inputs = fixture.complete_inputs()
        metadata = self.base/'metadata.json'
        metadata.write_text(json.dumps(fixture.metadata))
        witness = self.base/'resolution.json'
        witness.write_text('null')  # Existing structural fixture, not live tool resolution.
        args = SimpleNamespace(core=assembly.cli,daemon=assembly.daemon,control=inputs['control'],
            extension=fixture.extension,metadata=metadata,resolution_witness=witness,
            runtime_file=inputs['runtime_files'],qt_runtime_file=inputs['qt_runtime_files'],
            qt_plugin=inputs['qt_plugins'],patchelf=inputs['patchelf'],ca_bundle=inputs['ca_bundle'])
        return args, assembly

    def test_single_actual_stage_and_independent_four_pin_selection_survive_output_sealing(self):
        args, assembly = self.inputs()
        with patch.object(portable,'_patch',side_effect=assembly.patch_fixture), \
                patch.object(adapter,'produce',wraps=adapter.produce) as producer:
            facts = adapter.run(args,self.environment)
        self.assertEqual(producer.call_count,1)
        root = self.epoch/adapter.CHILD
        selected = facts['selection']
        self.assertEqual(set(selected['artifacts']),{'core','daemon','control','extension'})
        self.assertEqual(hashlib.sha256((self.output/'dev-stage-receipt.json').read_bytes()).hexdigest(),
            facts['receiptSha256'])
        self.assertEqual(json.loads((self.output/'dev-stage-selection.json').read_bytes()),facts)
        for path in self.output.iterdir(): path.chmod(0o444)
        generation = select_generation(root,selected['generation'],selected['receiptSha256'],
            expected_artifacts=selected['artifacts'],require_portable=True)
        self.assertIsNotNone(generation.control)
        self.assertEqual(generation.control.stat().st_mode & 0o777,0o700)
        self.assertFalse(facts['outerCleanupVerified'])
        self.assertFalse(facts['qtExecuted'])
        self.assertFalse(facts['daemonRestarted'])
        self.assertFalse(facts['chromiumReloaded'])
        self.assertFalse(facts['providerAccess'])

    def test_untrusted_missing_stale_or_typed_admission_refuses_before_stage(self):
        args = SimpleNamespace(runtime_file=[1],qt_runtime_file=[1],qt_plugin=[1])
        cases = [{**self.environment,'OMUX_EXECUTION_GUARD':''},
            {**self.environment,adapter.DEADLINE_ENV:str(self.deadline+1)},
            {**self.environment,adapter.ENTRY_ENV:'true'}]
        with patch.object(adapter,'produce',side_effect=AssertionError('producer called')):
            for environment in cases:
                with self.assertRaises((ValueError,OSError,GenerationError)):
                    adapter.run(args,environment)
            self.write('dev-stage-admission.json',json.dumps({**self.admission,'schemaVersion':True}).encode())
            with self.assertRaises(ValueError): adapter.run(args,self.environment)
        self.assertFalse((self.epoch/adapter.CHILD).exists())

    def test_closed_epoch_or_reused_child_never_replaces_retained_bytes(self):
        with adapter_context(self.environment) as epoch:
            root = epoch.allocate()
            (root/'sentinel').write_bytes(b'preserve me')
            with self.assertRaises(FileExistsError): epoch.allocate()
            self.assertEqual((root/'sentinel').read_bytes(),b'preserve me')
        self.write('receipt.json',b'{}')
        with self.assertRaises(ValueError): adapter.Epoch(self.environment)

    def test_wrong_output_namespace_and_symlink_refuse_before_input_or_stage_io(self):
        args = SimpleNamespace(runtime_file=[1],qt_runtime_file=[1],qt_plugin=[1])
        other = self.base/'other'
        other.mkdir(mode=0o700)
        linked = self.output.with_name('linked')
        linked.symlink_to(self.output)
        for path in (other,linked):
            with patch.object(adapter,'artifact',side_effect=AssertionError('input read')):
                with self.assertRaises(ValueError):
                    adapter.run(args,{**self.environment,'TEST_UNDECLARED_OUTPUTS_DIR':str(path)})
        saved = self.output.with_name('saved')
        self.output.rename(saved)
        self.output.symlink_to(other)
        with patch.object(adapter,'artifact',side_effect=AssertionError('input read')):
            with self.assertRaises(OSError): adapter.run(args,self.environment)
        self.assertFalse((self.epoch/adapter.CHILD).exists())

    def test_epoch_parent_replacement_cannot_publish_self_consistent_selection(self):
        args, assembly = self.inputs()
        original = adapter.produce
        moved = self.epoch.with_name('retained-original')
        def replace_parent(*values,**options):
            result = original(*values,**options)
            self.epoch.rename(moved)
            self.epoch.mkdir(mode=0o700)
            return result
        with patch.object(portable,'_patch',side_effect=assembly.patch_fixture), \
                patch.object(adapter,'produce',side_effect=replace_parent):
            with self.assertRaises((ValueError,OSError)):
                adapter.run(args,self.environment)
        self.assertTrue((moved/adapter.CHILD/'current').is_symlink())
        self.assertFalse(any((moved/self.output.relative_to(self.epoch)).iterdir()))

    def test_original_deadline_reserve_never_renews_and_rejects_boolean_clock(self):
        entry,deadline = 10,10+1200*10**9
        adapter.budget(entry,deadline,clock=lambda:entry+1)
        for start,end,now in ((entry,deadline,deadline-adapter.RESERVE_NS),
                (entry,deadline+1,entry+1),(True,deadline,entry+1),
                (entry,deadline,entry-1)):
            with self.assertRaises(ValueError): adapter.budget(start,end,clock=lambda:now)

    def redirect_output_ancestor(self):
        ancestor = self.output.parents[2]  # testlogs, not the final output leaf
        retained = ancestor.with_name('retained-testlogs')
        before = self.output.stat()
        ancestor.rename(retained)
        ancestor.symlink_to(retained)
        self.assertEqual((before.st_dev,before.st_ino),
            (self.output.stat().st_dev,self.output.stat().st_ino))
        return retained / self.output.relative_to(ancestor)

    def test_redirected_output_ancestor_to_same_inode_refuses_before_publication(self):
        args, assembly = self.inputs()
        original = adapter.produce
        outputs = []
        def redirect(*values,**options):
            result = original(*values,**options)
            outputs.append(self.redirect_output_ancestor())
            return result
        with patch.object(portable,'_patch',side_effect=assembly.patch_fixture), \
                patch.object(adapter,'produce',side_effect=redirect):
            with self.assertRaises(OSError): adapter.run(args,self.environment)
        self.assertTrue((self.epoch/adapter.CHILD/'current').is_symlink())
        self.assertEqual(list(outputs[0].iterdir()),[])

    def test_redirected_output_ancestor_after_publication_refuses_final_success(self):
        args, assembly = self.inputs()
        original = adapter.publish
        calls = []
        def redirect(descriptor,name,data):
            original(descriptor,name,data)
            calls.append(name)
            if name == 'dev-stage-selection.json': self.redirect_output_ancestor()
        with patch.object(portable,'_patch',side_effect=assembly.patch_fixture), \
                patch.object(adapter,'publish',side_effect=redirect):
            with self.assertRaises(OSError): adapter.run(args,self.environment)
        self.assertEqual(calls,['dev-stage-receipt.json','dev-stage-selection.json'])
        self.assertTrue((self.epoch/adapter.CHILD/'current').is_symlink())

    def test_redirected_epoch_ancestor_to_same_inode_refuses_held_admission(self):
        retained = self.base.with_name(self.base.name+'-retained')
        with adapter_context(self.environment) as epoch:
            before = self.epoch.stat()
            self.base.rename(retained)
            self.base.symlink_to(retained)
            try:
                self.assertEqual((before.st_dev,before.st_ino),
                    (self.epoch.stat().st_dev,self.epoch.stat().st_ino))
                with self.assertRaises(OSError): epoch.recheck()
            finally:
                self.base.unlink()
                retained.rename(self.base)


class adapter_context:
    def __init__(self,environment): self.environment = environment
    def __enter__(self):
        self.epoch = adapter.Epoch(self.environment)
        return self.epoch
    def __exit__(self,*_): self.epoch.close()


if __name__ == '__main__': unittest.main()
