"""Real retained0555/canonical NAR fixtures; modeled guardian, no Nix/action."""
import copy
import json
import os
from pathlib import Path
import shutil
import stat
import time
import unittest
from unittest.mock import patch
import home_manager_artifact_test as fixtures
import home_manager_bundle as bundle
import home_manager_bundle_test as pair_fixtures
import home_manager_current_retained_artifact as retained

class RetainedCurrentArtifactTest(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.ArtifactTest('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture;logical=f.export();original,raw=f.retained()
        self.root=f.base/'current';self.root.mkdir(mode=0o700)
        shutil.copytree(original,self.root/'artifact')
        _,nodes,_,nar,size=retained.artifact.tree_bytes(self.root/'artifact',time.monotonic()+60)
        self.inventory={'schemaVersion':1,'nodes':nodes}
        self.write(self.root/'inventory.json',retained.artifact.encoded(self.inventory))
        extension=b'fixture-extension';metadata=b'fixture-extension-metadata'
        self.write(self.root/'extension.zip',extension);self.write(self.root/'extension-metadata.json',metadata)
        self.write(self.root.parent/'current-home-manager.tar.gz',f.archive.read_bytes())
        receipt={k:False for k in ('shipped','activationQualified','browserQualified','custodyQualified','continuityQualified','liveQualified')}
        entry=time.monotonic_ns()
        receipt.update({'schemaVersion':1,'kind':'omux-current-home-manager-artifact-v1','sourceRevision':fixtures.REVISION,
            'sourceDirty':True,'graphSha256':'b'*64,'originalEntryMonotonicNs':entry,'originalDeadlineMonotonicNs':entry+1200000000000,
            'archiveSha256':logical['archiveSha256'],'archiveBytes':logical['archiveBytes'],'manifestSha256':logical['manifestSha256'],
            'narHash':nar,'narSize':size,'system':'x86_64-linux','channel':'development','nativeBins':retained.artifact.NATIVE_BINS,
            'extensionSha256':retained.current.sha(extension),'extensionBytes':len(extension),
            'extensionMetadataSha256':retained.current.sha(metadata),
            'sourceQualification':'original-coordinator-source-and-declared-current-graph'})
        raw=retained.artifact.encoded(receipt);self.receipt=receipt;self.write(self.root/'receipt.json',raw)
        self.selection={'root':str(self.root),'receiptSha256':retained.current.sha(raw),
            'inventorySha256':retained.current.sha((self.root/'inventory.json').read_bytes()),'producer':{'modeled':'guardian-boundary'}}
        for path in (self.root/'artifact').rglob('*'):
            if path.is_file():path.chmod(0o555)
        self.root.chmod(0o555)
        self.scratch=f.base/'scratch';self.scratch.mkdir(mode=0o700)
        self.authority=patch.object(retained.current,'producer_authority',return_value={})
        self.authority.start();self.addCleanup(self.authority.stop)

    def write(self,path,data):
        path.write_bytes(data);path.chmod(0o444)

    def transport(self):return retained.selected_transport(self.selection,time.monotonic()+120)

    def test_real_transport_keeps_original_nar_and_bytes_then_owned_canonical_restores_modes(self):
        before=retained.artifact.tree_bytes(self.root/'artifact',time.monotonic()+120)
        with self.assertRaises(ValueError):
            retained.current.inventory_binding(self.inventory,before[1],before[3],before[4],self.receipt)
        proof,files,inventory,_=self.transport();work=time.monotonic()+120
        account=bundle.ReconstructionBudget(retained.artifact.MAX_BYTES+4*1024*1024,work)
        with bundle.private_tree(self.scratch,work+60,admission_deadline=work) as worker:
            with retained.CanonicalArtifact(self.selection,worker,work,account) as owner:
                self.assertEqual(stat.S_IMODE((owner.path/'release-manifest.json').stat().st_mode),0o444)
                self.assertEqual(owner.verify(work)['narHash'],self.receipt['narHash'])
                retained.artifact.verify_copied_bundle(*retained.artifact.tree_bytes(owner.path,work)[:2])
                self.assertGreater(account.allocated,0)
        self.assertEqual(list(self.scratch.iterdir()),[])
        self.assertEqual(retained.artifact.tree_bytes(self.root/'artifact',work),before)
        self.assertEqual(self.transport()[0],proof)

    def test_wrong_transport_mode_or_link_refused(self):
        path=self.root/'artifact/release-manifest.json';path.chmod(0o444)
        with self.assertRaisesRegex(ValueError,'0555'):self.transport()
        path.chmod(0o555);parent=path.parent;parent.chmod(0o700)
        path.unlink();path.symlink_to('absent')
        try:
            with self.assertRaises(ValueError):self.transport()
        finally:parent.chmod(0o555)

    def test_inventory_wrong_mode_missing_and_extra_node_refused(self):
        for kind in ('mode','missing','extra'):
            modified=copy.deepcopy(self.inventory)
            if kind=='mode':
                node=next(n for n in modified['nodes'] if n['type']=='regular' and not n['executable']);node['executable']=True
            elif kind=='missing':modified['nodes'].pop()
            else:modified['nodes'].append({'path':'foreign','type':'regular','size':0,'executable':False})
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                retained.retained_tree(self.root/'artifact',modified,self.receipt,time.monotonic()+120)

    def test_late_original_byte_change_refused_by_owner(self):
        work=time.monotonic()+120;account=bundle.ReconstructionBudget(retained.artifact.MAX_BYTES+4*1024*1024,work)
        with bundle.private_tree(self.scratch,work+60,admission_deadline=work) as worker:
            with retained.CanonicalArtifact(self.selection,worker,work,account) as owner:
                path=self.root/'artifact/release-manifest.json';raw=path.read_bytes()
                path.chmod(0o600);path.write_bytes(b'X'+raw[1:]);path.chmod(0o555)
                with self.assertRaises(ValueError):owner.verify(work)
        self.assertEqual(list(self.scratch.iterdir()),[])

    def test_canonical_mode_drift_refused_without_changing_source(self):
        work=time.monotonic()+120;account=bundle.ReconstructionBudget(retained.artifact.MAX_BYTES+4*1024*1024,work)
        before=self.transport()[0]
        with bundle.private_tree(self.scratch,work+60,admission_deadline=work) as worker:
            with retained.CanonicalArtifact(self.selection,worker,work,account) as owner:
                (owner.path/'release-manifest.json').chmod(0o555)
                with self.assertRaises(ValueError):owner.verify(work)
        self.assertEqual(self.transport()[0],before)

    def test_closed_owner_refuses_and_private_cleanup_refusal_propagates(self):
        from contextlib import contextmanager
        work=time.monotonic()+120;account=bundle.ReconstructionBudget(retained.artifact.MAX_BYTES+4*1024*1024,work)
        original=bundle.private_tree
        @contextmanager
        def refused(*args,**kwargs):
            with original(*args,**kwargs) as worker:yield worker
            raise ValueError('modeled-owned-cleanup-refusal')
        with self.assertRaisesRegex(ValueError,'cleanup-refusal'):
            with refused(self.scratch,work+60,admission_deadline=work) as worker:
                owner=retained.CanonicalArtifact(self.selection,worker,work,account);owner.close()
                with self.assertRaisesRegex(ValueError,'closed'):owner.verify(work)
        self.assertEqual(list(self.scratch.iterdir()),[])

    def test_real_evaluator_routes_canonical_owner_and_preserves_original_transport(self):
        paired=pair_fixtures.BundleTests('runTest');paired.setUp();self.addCleanup(paired.doCleanups)
        (paired.retained/'pair').chmod(0o555)
        work=time.monotonic()+120;account=bundle.ReconstructionBudget(retained.artifact.MAX_BYTES+4*1024*1024,work)
        before=self.transport()[0]
        with bundle.private_tree(self.scratch,work+60,admission_deadline=work) as worker:
            with retained.CanonicalArtifact(self.selection,worker,work,account) as owner:
                os.mkdir('home',0o700,dir_fd=worker.fd)
                receipt=(self.root/'receipt.json').read_bytes()
                clock=(self.receipt['originalEntryMonotonicNs'],self.receipt['originalDeadlineMonotonicNs'])
                with paired.model_nix():
                    result=bundle.evaluator.evaluate_acquired_pair('/declared/native-nix',paired.modules,paired.lock,
                        str(paired.retained/'pair'),bundle.PAIR_SHA,str(owner.path),receipt,self.selection['receiptSha256'],
                        str(worker.path/'home'),deadline=work,current_selection=self.selection,original_clock=clock,
                        canonical_artifact=owner)
                self.assertTrue(result['artifactCustodyBeforeAfterMatched'])
                self.assertEqual(result['artifactFamily'],'current-coordinator-artifact-v1')
                self.assertEqual(result['artifact']['narHash'],self.receipt['narHash'])
                self.assertGreater(account.allocated,0)
        self.assertEqual(self.transport()[0],before)
        self.assertEqual(list(self.scratch.iterdir()),[])

    def test_expiry_after_accounting_refuses_before_creation(self):
        work=time.monotonic()+120;account=bundle.ReconstructionBudget(retained.artifact.MAX_BYTES+4*1024*1024,work)
        transport=self.transport();expired=[False];original_check=retained.acquired.check_deadline;original_record=account.record
        def check(deadline):
            if expired[0]:raise ValueError('modeled-original-work-expiry')
            return original_check(deadline)
        def record(info):original_record(info);expired[0]=True
        with bundle.private_tree(self.scratch,work+60,admission_deadline=work) as worker:
            with patch.object(retained,'selected_transport',return_value=transport), \
                 patch.object(retained.acquired,'check_deadline',side_effect=check), \
                 patch.object(account,'record',side_effect=record),patch.object(retained.os,'mkdir') as creation:
                with self.assertRaisesRegex(ValueError,'work-expiry'):
                    retained.CanonicalArtifact(self.selection,worker,work,account)
                creation.assert_not_called()
        self.assertEqual(list(self.scratch.iterdir()),[])

    def test_close_fault_drains_every_owned_file_directory_and_ancestor(self):
        work=time.monotonic()+120;account=bundle.ReconstructionBudget(retained.artifact.MAX_BYTES+4*1024*1024,work)
        with bundle.private_tree(self.scratch,work+60,admission_deadline=work) as worker:
            owner=retained.CanonicalArtifact(self.selection,worker,work,account)
            descriptors=[row[0] for row in owner.tree.files.values()]+[row[0] for row in owner.tree.dirs.values()]+[row[2] for row in owner.parent.chain]
            original=os.close;attempted=[]
            def close(fd):
                attempted.append(fd);original(fd)
                if len(attempted)==1:raise OSError('modeled-close-fault')
            with patch.object(bundle.os,'close',side_effect=close),self.assertRaises(OSError):owner.close()
            self.assertEqual(set(attempted),set(descriptors));self.assertEqual(len(attempted),len(descriptors))
            self.assertIsNone(owner.tree);self.assertIsNone(owner.parent)
        self.assertEqual(list(self.scratch.iterdir()),[])

    def acquisition_refusal(self,kind,proof=False):
        work=time.monotonic()+120;account=bundle.ReconstructionBudget(retained.artifact.MAX_BYTES+4*1024*1024,work)
        transport=self.transport();opened=[];closed=[]
        original_open,original_stat,original_close=os.open,os.fstat,os.close
        def open_file(path,flags,*args,**kwargs):
            fd=original_open(path,flags,*args,**kwargs)
            if not opened and ((kind=='directory' and path=='current-artifact' and flags&os.O_DIRECTORY)
                    or (kind=='regular' and flags&os.O_CREAT and not flags&os.O_DIRECTORY)):
                opened.append(fd)
            return fd
        def fstat(fd):
            if opened and fd==opened[0]:
                if proof:
                    values=list(original_stat(fd));values[1]+=1
                    return os.stat_result(values)
                raise OSError('modeled-new-descriptor-fstat-refusal')
            return original_stat(fd)
        def close(fd):
            if opened and fd==opened[0]:closed.append(fd)
            return original_close(fd)
        with bundle.private_tree(self.scratch,work+60,admission_deadline=work) as worker:
            with patch.object(retained,'selected_transport',return_value=transport), \
                 patch.object(retained.os,'open',side_effect=open_file), \
                 patch.object(retained.os,'fstat',side_effect=fstat),patch.object(retained.os,'close',side_effect=close):
                with self.assertRaises(ValueError if proof else OSError):
                    retained.CanonicalArtifact(self.selection,worker,work,account)
                self.assertEqual(len(opened),1);self.assertEqual(closed,opened)
                with self.assertRaises(OSError):original_stat(opened[0])
        self.assertEqual(list(self.scratch.iterdir()),[])

    def test_new_directory_post_open_fstat_and_identity_refusal_close_once(self):
        for proof in (False,True):
            with self.subTest(proof=proof):self.acquisition_refusal('directory',proof)

    def test_new_regular_initial_fstat_refusal_closes_once(self):
        self.acquisition_refusal('regular')

if __name__=='__main__':unittest.main()
