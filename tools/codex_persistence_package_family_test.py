"""Offline material-family refusals; no native, provider or real selected inputs."""
import copy
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import codex_persistence_package_family as subject
import codex_protocol_history_native as protocol
import guard_native_metadata_sdk_reserved as admission
import guard_resident_owner_status_persistence_source_reserved as source_admission
import guard_native_seed_plan_reserved as kernel


class PersistencePackageModels(unittest.TestCase):
    def resident(self):
        return {'scope':'sampled-fixed-default-cgroup-kernel-reservation-v1',
            'kernel_bounds':{'memory.max':'268435456','memory.swap.max':'0',
                'pids.max':'32','cpu.max':'10000 100000'}, 'observations':2,
            'initial_direct_process_count':2,
            **{name:True for name in ('initial_direct_processes_retained',
                'outer_pid_namespace_matched','hierarchical_caps')},
            **{name:False for name in ('descendant_process_inventory','installation_qualified',
                'health_observed','custody_observed','resident_signalled','whole_host_reservation')}}

    def receipt(self, target):
        resident = self.resident()
        if target == subject.SOURCE_TARGET:
            profile = source_admission.PROFILE
            key = 'resident_owner_status_persistence_source_reservation'
            value = source_admission.projection(100*10**9,1300*10**9,True,resident)
        else:
            profile = admission.SDK if target == subject.SDK_TARGET else admission.METADATA
            key = 'native_metadata_sdk_reservation'
            value = admission.projection(profile,100*10**9,1300*10**9,True,resident)
        return {'profile':profile,key:value,'cache_reuse_requested':False,
            'cache_policy':None,'cache_key':None,'observed_properties':{
                'MemoryMax':'4026531840','MemorySwapMax':'0','TasksMax':'480',
                'CPUQuotaPerSecUSec':'1.9s','PrivateNetwork':'yes',
                'KillMode':'control-group','SendSIGKILL':'yes','OOMPolicy':'kill','RemainAfterExit':'yes'}}

    def test_exact_three_material_policies_refuse_cross_scope_caps_cache_and_cleanup_join(self):
        for target in (subject.SOURCE_TARGET,subject.METADATA_TARGET,subject.SDK_TARGET):
            receipt = self.receipt(target)
            profile, targets = subject.producer_policy(receipt,target)
            self.assertEqual(profile,receipt['profile'])
            self.assertIn(target,targets)
            self.assertEqual(len(targets),3 if target == subject.SOURCE_TARGET else 1)
            key = next(name for name in receipt if name.endswith('_reservation'))
            for mutate in (
                lambda r:r.update(profile='standard'),
                lambda r:r.update(cache_reuse_requested=True),
                lambda r:r[key].update(verified_after_cleanup=False),
                lambda r:r[key].update(original_deadline_monotonic_ns=1301*10**9),
                lambda r:r[key]['resident'].update(whole_host_reservation=True),
                lambda r:r['observed_properties'].update(TasksMax='512'),
                lambda r:r['observed_properties'].update(CPUQuotaPerSecUSec='2s')):
                changed=copy.deepcopy(receipt);mutate(changed)
                with self.assertRaises(ValueError):subject.producer_policy(changed,target)
        with self.assertRaises(ValueError):subject.producer_policy({},'//tools:codex_retained_sdk_export_producer')

    def test_fixed_n3_and_six_patch_reconstruction_cannot_promote_native_or_schema(self):
        report={'kind':subject.persistence.KIND,
            'status':'verified-owner-status-persistence-source-pending-sdk-and-schema',
            'patch_sha256':['a'*64]*6, **{name:False for name in ('sdk_metadata_qualified',
                'schema_producer_qualified','native_compile_passed','native_support',
                'provider_evaluation','live_handoff_proven')}}
        original=(subject.producer.source.DEADLINE,subject.producer.DEADLINE)
        with patch.object(subject.producer,'load_candidate',return_value=(report,{},{})) as reconstruction:
            result=subject.load_source(subject.producer.binding.ROOT,subject.producer.binding.RECEIPT_SHA,
                report['patch_sha256'],time.monotonic()+30)
            self.assertIs(result[0],report)
            for root,pin,patches in ((Path('/model/unselected'),subject.producer.binding.RECEIPT_SHA,report['patch_sha256']),
                (subject.producer.binding.ROOT,'f'*64,report['patch_sha256']),
                (subject.producer.binding.ROOT,subject.producer.binding.RECEIPT_SHA,report['patch_sha256'][:-1])):
                with self.assertRaises(ValueError):subject.load_source(root,pin,patches,time.monotonic()+30)
            report['schema_producer_qualified']=True
            with self.assertRaises(ValueError):subject.load_source(subject.producer.binding.ROOT,
                subject.producer.binding.RECEIPT_SHA,report['patch_sha256'],time.monotonic()+30)
            self.assertGreaterEqual(reconstruction.call_count,3)
        self.assertEqual((subject.producer.source.DEADLINE,subject.producer.DEADLINE),original)

    def test_actual_sealed_graph_extra_symlink_hardlink_and_deadline_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'graph';root.mkdir(mode=0o700)
            path=root/'MODULE.bazel';path.write_bytes(b'module(name="test_only")\n');path.chmod(0o444)
            root.chmod(0o555)
            try:
                subject.graph_shape(root,{'MODULE.bazel':{}},time.monotonic()+30)
                with self.assertRaises(ValueError):subject.graph_shape(root,{'MODULE.bazel':{}},time.monotonic()-1)
                root.chmod(0o700);extra=root/'extra';extra.write_bytes(b'unselected');root.chmod(0o555)
                with self.assertRaises(ValueError):subject.graph_shape(root,{'MODULE.bazel':{}},time.monotonic()+30)
                root.chmod(0o700);extra.unlink();path.unlink();path.symlink_to('/model/never-read');root.chmod(0o555)
                with self.assertRaises(ValueError):subject.graph_shape(root,{'MODULE.bazel':{}},time.monotonic()+30)
                root.chmod(0o700);path.unlink();path.write_bytes(b'x');path.chmod(0o444)
                os.link(path,Path(temporary)/'alias');root.chmod(0o555)
                with self.assertRaises(ValueError):subject.graph_shape(root,{'MODULE.bazel':{}},time.monotonic()+30)
            finally:root.chmod(0o700)

    def test_real_closed_sdk_claim_rejects_old_kind_and_future_compiler_schema_flags(self):
        graph={'MODULE.bazel.lock':{'sha256':'a'*64}}
        source={'inventory_sha256':'b'*64,'graph_files':graph}
        document={'source':{'root':str(subject.producer.binding.ROOT),'receipt_sha256':subject.producer.binding.RECEIPT_SHA},
            'sdk':{'inventory_sha256':'c'*64}}
        metadata={name:None for name in protocol.METADATA_FIELDS|subject.METADATA_EXTRA}
        metadata.update(schema_version=1,kind=subject.producer.OUTPUT_KIND,
            status='verified-strict-regenerated-owner-status-persistence-hub',
            inputs=subject.producer.selected_document(),binding_receipt_sha256=subject.producer.BINDING_SHA,
            source_inventory_sha256='b'*64,source_graph=graph,selector_sha256='d'*64,query_exit=0)
        metadata.update({name:True for name in ('module_lock_unchanged','cargo_lock_unchanged','source_and_export_rechecked')})
        metadata.update({name:False for name in ('sdk_export_qualified','schema_producer_qualified',
            'live_handoff_proven','native_compile_passed','native_support','provider_evaluation')})
        report={name:None for name in protocol.SDK_FIELDS|subject.SDK_EXTRA}
        report.update(schema_version=1,kind=subject.export.KIND,status='verified-selected-owner-status-persistence-sdk',
            source_root=document['source']['root'],source_receipt_sha256=document['source']['receipt_sha256'],
            source_inventory_sha256='b'*64,graph_files=graph,mapping_sha256='a'*64,inventory_sha256='c'*64,
            retained_export_root=str(subject.producer.EXPORT_ROOT),retained_export_receipt_sha256=subject.producer.EXPORT_SHA,
            binding_receipt_sha256=subject.producer.BINDING_SHA,sdk_export_qualified=True,metadata=metadata,
            metadata_receipt_sha256=subject.producer.source.sha(subject.producer.source.encoded(metadata)),
            repositories=[{'canonical_name':'test_only'}],counts={'entries':{
                'qualification':1,'copy':1,'sealed_readback':1},'bytes':1})
        report.update({name:False for name in ('schema_producer_qualified','live_handoff_proven',
            'native_compile_passed','native_support','provider_evaluation')})
        subject.sdk_claim(report,document,source,protocol.SDK_FIELDS,protocol.METADATA_FIELDS)
        for name,value in (('kind',protocol.selected_sdk.KIND),('schema_producer_qualified',True),
            ('native_compile_passed',True),('live_handoff_proven',True),('sdk_export_qualified',False),
            ('binding_receipt_sha256','e'*64),('schema_version',True)):
            changed=copy.deepcopy(report);changed[name]=value
            with self.assertRaises(ValueError):subject.sdk_claim(changed,document,source,protocol.SDK_FIELDS,protocol.METADATA_FIELDS)
        changed=copy.deepcopy(report);changed['metadata']['query_exit']=True
        changed['metadata_receipt_sha256']=subject.producer.source.sha(subject.producer.source.encoded(changed['metadata']))
        with self.assertRaises(ValueError):subject.sdk_claim(changed,document,source,protocol.SDK_FIELDS,protocol.METADATA_FIELDS)

    def test_new_model_route_is_distinct_and_old_cohorts_remain_exact(self):
        self.assertEqual(admission.COHORTS[admission.SDK],(subject.SDK_TARGET,))
        self.assertEqual(admission.COHORTS[admission.METADATA],(subject.METADATA_TARGET,))
        self.assertIn(admission.PACKAGE_MODEL,kernel.WORKLOAD_PROFILES)
        vector=['test',*admission.COHORTS[admission.PACKAGE_MODEL]]
        self.assertEqual(admission.selected(admission.PACKAGE_MODEL,vector),{'PrivateNetwork':'yes'})
        for changed in (['run',*vector[1:]],vector+['//tools:codex_persistence_native_runtime_package'],vector[:-1]):
            with self.assertRaises(ValueError):admission.selected(admission.PACKAGE_MODEL,changed)


if __name__ == '__main__':unittest.main()
