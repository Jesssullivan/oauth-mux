"""Full selected-graph SDK copy models; external native tools never execute."""
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
import codex_live_source as source
import codex_protocol_history_metadata as metadata
import codex_protocol_history_metadata_producer as producer
import codex_protocol_history_metadata_test as models
import codex_protocol_history_source as history
import codex_protocol_history_sdk_export as selected
import codex_retained_sdk_export as sdk


class SelectedSdkModels(unittest.TestCase):
    def fixture(self, root):
        model=models.MetadataProducerModels()
        before,parent,document,export,exported,old=model.fixture(root)
        registry=export/"registry-cache/content_addressable/sha256"/("8"*64)
        registry.mkdir(parents=True,mode=0o700)
        for directory in (registry.parent,registry.parent.parent,registry.parent.parent.parent):
            directory.chmod(0o700)
        (registry/"file").write_bytes(b"public synthetic registry")
        (registry/"file").chmod(0o444)
        rows=[]
        for name in exported["repositories"]:
            path=export/"repositories"/name
            path.mkdir(mode=0o700,exist_ok=True)
            for directory,_,_ in os.walk(path,topdown=False):Path(directory).chmod(0o555)
            entries=sdk.inventory(path,sdk.Budget(sdk.time.time()+60),sealed=True)
            rows.append({"canonical_name":name,"source_root":str(path),"files":entries,
                "source_files":entries,"inventory_sha256":sdk.digest(sdk.canonical(entries)),
                "source_inventory_sha256":sdk.digest(sdk.canonical(entries)),"absent_links":[]})
        for directory,_,_ in os.walk(export/"registry-cache",topdown=False):Path(directory).chmod(0o555)
        retained={"repositories":rows,"modules":{},"registry_metadata":{"fixture":"exact public CAS"},
            "nix_store_roots":[sdk.JDK],"nix_inventory":[]}
        raw=source.encoded(retained)
        (export/"receipt.json").write_bytes(raw);(export/"receipt.json").chmod(0o444)
        digest=source.sha(raw);document["export_receipt_sha256"]=digest
        return model,(before,parent,document,export,exported,old),retained,digest

    def export(self,root,fixture,mutation=None):
        model,values,retained,digest=fixture
        before,parent,document,export,exported,old=values
        real_inventory=sdk.inventory
        def inventory(path,*args,**kwargs):
            if Path(path)==Path(sdk.JDK):return []
            return real_inventory(path,*args,**kwargs)
        with (patch.object(producer,"EXPORT_ROOT",export),patch.object(producer,"EXPORT_SHA",digest),patch.object(
                producer,"SOURCE_SCOPE",re.compile(re.escape(document["source_root"]))),patch.object(
                history,"load_parent",return_value=(before,parent)),patch.object(sdk,"validate_export",
                return_value=exported),patch.object(sdk,"registry_metadata",return_value=retained["registry_metadata"]),
                patch.object(sdk,"inventory",side_effect=inventory)):
            model.run_producer(root,values)
            if mutation:mutation()
            previous=os.umask(0o077)  # Same private output policy as the declared main.
            try:return selected.export(document,root/"result",root/"selected-sdk",producer.time.monotonic()+60)
            finally:os.umask(previous)

    def test_full_copy_replaces_only_regenerated_hub_and_exports_changed_graph(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                fixture=self.fixture(root)
                report=self.export(root,fixture)
                self.assertEqual(report["kind"],selected.KIND)
                self.assertEqual(report["source_receipt_sha256"],fixture[1][2]["source_receipt_sha256"])
                self.assertEqual((root/"selected-sdk/repositories"/metadata.HUB/"data.bzl").read_bytes(),
                    fixture[0].changed(fixture[1][5])["data.bzl"])
                self.assertEqual((root/"sdk/repositories"/metadata.HUB/"data.bzl").read_bytes(),
                    fixture[1][5]["data.bzl"])
                self.assertEqual(report["graph_files"],report["metadata"]["source_graph"])
                self.assertEqual(report["modules"],fixture[2]["modules"])
                self.assertEqual(report["registry_metadata"],fixture[2]["registry_metadata"])
                self.assertEqual(json.loads((root/"selected-sdk/receipt.json").read_bytes()),report)
                self.assertEqual((root/"selected-sdk").stat().st_mode&0o777,0o555)
                for field in ("native_compile_passed","native_support","provider_evaluation"):
                    self.assertIs(report[field],False)
            finally:models.MetadataProducerModels().clean(root)

    def test_changed_generated_hub_refuses_before_sdk_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                fixture=self.fixture(root)
                def replace():
                    path=root/"result/hub/defs.bzl"
                    path.chmod(0o600);path.write_bytes(b"unqualified changed generated wrapper")
                    path.chmod(0o444)
                with self.assertRaises(ValueError):self.export(root,fixture,mutation=replace)
                self.assertFalse((root/"selected-sdk/receipt.json").exists())
            finally:models.MetadataProducerModels().clean(root)

    def test_main_passes_identical_original_deadline_to_query_and_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);document={"synthetic":"declared"}
            environment={"TEST_TIMEOUT":"900","TEST_TMPDIR":str(root),
                "TEST_UNDECLARED_OUTPUTS_DIR":str(root)}
            repository=root/"declared-query-tools"
            def declared_selection():
                # Model the real declaration's required query repository handoff.
                selected.producer.QUERY_REPOSITORY=repository
                return document,"f"*64
            with patch.dict(os.environ,environment),patch.object(selected.os,"umask"),patch.object(
                    selected.producer,"QUERY_REPOSITORY"),patch.object(
                    selected.producer,"declared_selection",side_effect=declared_selection),patch.object(
                    selected.time,"monotonic",return_value=100.0),patch.object(
                    selected.producer,"produce") as generate,patch.object(selected,"export") as export,patch.object(
                    selected.producer.query_tools,"verify_repository",return_value={"inputs_rechecked":True}) as verify:
                selected.main()
            self.assertEqual(generate.call_args.kwargs["absolute_deadline"],940.0)
            self.assertEqual(export.call_args.args[-1],940.0)
            verify.assert_called_once_with(repository,940.0)

    def test_same_absolute_deadline_cannot_be_extended_by_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            with patch.object(selected.producer,"hold_root") as held:
                for deadline in (producer.time.monotonic()-1,producer.time.monotonic()+841,True):
                    with self.assertRaises(ValueError):
                        selected.export({},root/"metadata",root/"sdk",deadline)
                held.assert_not_called()


if __name__=="__main__":
    unittest.main()
