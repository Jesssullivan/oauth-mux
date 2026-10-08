"""Distinct selected-graph SDK export; old retained export/receipts stay unchanged."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

import codex_live_source as source
import codex_protocol_history_metadata as metadata
import codex_protocol_history_metadata_producer as producer
import codex_protocol_history_source as history
import codex_retained_sdk_export as sdk

KIND = "omux-protocol-history-sdk-export-v1"
PHASE = "selection"


def require(value):
    metadata.require(value)


def load_retained(budget):
    fd=sdk.open_dir(producer.EXPORT_ROOT)
    try:
        digest,_,raw=sdk.read_file(fd,"receipt.json",budget,capture=True)
        require(digest==producer.EXPORT_SHA)
        return json.loads(raw,object_pairs_hook=source.unique)
    finally:os.close(fd)


def seal_directories(root):
    for directory,_,_ in os.walk(root,topdown=False,followlinks=False):
        os.chmod(directory,0o555)


def copy_tree(original, destination, expected, budget):
    destination.mkdir(mode=0o700)
    budget.export_pass("copy")
    require(sdk.inventory(original,budget,output=destination,sealed=True)==expected)
    seal_directories(destination)
    budget.export_pass("sealed_readback")
    require(sdk.inventory(destination,budget,sealed=True)==expected)


def verify_export(root, report, budget):
    require(type(report) is dict and report["kind"]==KIND
        and report["status"]=="verified-selected-protocol-history-sdk"
        and report["metadata"]["kind"]==producer.OUTPUT_KIND
        and report["metadata"]["source_and_export_rechecked"] is True
        and report["metadata"]["query_exit"]==0 and type(report["metadata"]["query_exit"]) is int
        and report["source_receipt_sha256"]==report["metadata"]["inputs"]["source_receipt_sha256"]
        and report["graph_files"]==report["metadata"]["source_graph"]
        and report["retained_export_receipt_sha256"]==producer.EXPORT_SHA
        and report["native_compile_passed"] is False and report["native_support"] is False
        and report["provider_evaluation"] is False)
    fd=sdk.open_dir(root/"repositories")
    try:require(set(os.listdir(fd))=={row["canonical_name"] for row in report["repositories"]})
    finally:os.close(fd)
    for row in report["repositories"]:
        require(sdk.inventory(root/"repositories"/row["canonical_name"],budget,sealed=True)==row["files"]
            and sdk.digest(sdk.canonical(row["files"]))==row["inventory_sha256"])
    require(sdk.digest(sdk.canonical(report["repositories"]))==report["inventory_sha256"])
    absences=sdk.public_link_absences(report["repositories"],budget)
    for row in report["repositories"]:
        require(row.get("absent_links",[])==[item for item in absences
            if item["origin"].split("/")[0]==row["canonical_name"]])
    for name,pin in report["graph_files"].items():
        fd=sdk.open_dir((root/"graph"/name).parent)
        try:
            digest,_,_=sdk.read_file(fd,Path(name).name,budget)
            require(digest==pin["sha256"])
        finally:os.close(fd)
    require(sdk.registry_metadata(root/"graph/MODULE.bazel.lock",
        report["graph_files"]["MODULE.bazel.lock"]["sha256"],root/"registry-cache",budget,sealed=True)
        ==report["registry_metadata"])
    require(report["nix_store_roots"]==[sdk.JDK]
        and sdk.inventory(Path(sdk.JDK),budget,sealed=True)==report["nix_inventory"])
    return True


def export(document, metadata_root, output, absolute_deadline):
    global PHASE
    require(type(absolute_deadline) is float and 0<absolute_deadline-time.monotonic()<=840)
    producer.validate_document(document)
    source.DEADLINE=absolute_deadline;producer.DEADLINE=absolute_deadline
    budget=sdk.Budget(time.time()+absolute_deadline-time.monotonic(),producer.tick)
    held=[]
    try:
        PHASE="inputs"
        for root in (Path(document["source_root"]),producer.EXPORT_ROOT,metadata_root):
            held.append((root,producer.hold_root(root)))
        fd=source.directory(metadata_root)
        try:raw,mode=source.read(fd,"metadata-receipt.json",source.MAX_METADATA)
        finally:os.close(fd)
        require(mode==0o444)
        regenerated=json.loads(raw,object_pairs_hook=source.unique)
        source_report,files,parent=producer.load_candidate(document)
        require(regenerated["kind"]==producer.OUTPUT_KIND
            and regenerated["status"]=="verified-strict-regenerated-protocol-history-hub"
            and regenerated["inputs"]==document
            and regenerated["source_inventory_sha256"]==source_report["inventory_sha256"]
            and regenerated["source_graph"]==source_report["graph_files"]
            and regenerated["module_lock_unchanged"] is True and regenerated["cargo_lock_unchanged"] is True
            and regenerated["source_and_export_rechecked"] is True
            and type(regenerated["query_exit"]) is int and regenerated["query_exit"]==0
            and regenerated["sdk_export_qualified"] is False)
        qualified=sdk.validate_export(producer.EXPORT_ROOT,producer.EXPORT_SHA,
            source.BASE_INVENTORY,parent["baseline_graph_files"],on_read=producer.tick)
        retained=load_retained(budget)
        generated=producer.read_hub(metadata_root/"hub")
        previous=producer.read_hub(producer.EXPORT_ROOT/"repositories"/metadata.HUB)
        require(metadata.verify_hub_delta(previous,generated) is True
            and regenerated["generated_hub"]=={name:{"sha256":source.sha(value),"bytes":len(value),"mode":0o444}
                for name,value in sorted(generated.items())})
        require(regenerated["parent_export_inventory_sha256"]==qualified["inventory_sha256"])
        PHASE="copy"
        output.mkdir(mode=0o700)
        (output/"repositories").mkdir(mode=0o700);(output/"graph").mkdir(mode=0o700)
        budget.authorize_export_passes()
        repositories=[]
        for old in retained["repositories"]:
            name=old["canonical_name"]
            origin=metadata_root/"hub" if name==metadata.HUB else producer.EXPORT_ROOT/"repositories"/name
            expected=({} if name==metadata.HUB else old["files"])
            if name==metadata.HUB:
                expected=sdk.inventory(origin,sdk.Budget(time.time()+max(1,min(1200,absolute_deadline-time.monotonic())),
                    producer.tick),sealed=True)
            copy_tree(origin,output/"repositories"/name,expected,budget)
            row=dict(old);row["files"]=expected
            row["inventory_sha256"]=sdk.digest(sdk.canonical(expected))
            row["source_root"]=str(origin)
            if name==metadata.HUB:
                row["source_files"]=expected;row["source_inventory_sha256"]=row["inventory_sha256"]
                row["absent_links"]=[]
            repositories.append(row)
        for name,pin in source_report["graph_files"].items():
            path=output/"graph"/name
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            require(source.sha(files[name][1])==pin["sha256"])
            with path.open("xb") as stream:
                stream.write(files[name][1]);stream.flush()
                os.fchmod(stream.fileno(),0o444);os.fsync(stream.fileno())
        registry_expected=sdk.inventory(producer.EXPORT_ROOT/"registry-cache",
            sdk.Budget(time.time()+max(1,min(1200,absolute_deadline-time.monotonic())),producer.tick),sealed=True)
        copy_tree(producer.EXPORT_ROOT/"registry-cache",output/"registry-cache",registry_expected,budget)
        seal_directories(output/"repositories");seal_directories(output/"graph")
        report={"schema_version":1,"kind":KIND,"status":"verified-selected-protocol-history-sdk",
            "metadata_receipt_sha256":source.sha(raw),"metadata":regenerated,
            "source_root":document["source_root"],"source_receipt_sha256":document["source_receipt_sha256"],
            "source_inventory_sha256":source_report["inventory_sha256"],
            "graph_files":source_report["graph_files"],"mapping_sha256":source_report["graph_files"]["MODULE.bazel.lock"]["sha256"],
            "retained_export_root":str(producer.EXPORT_ROOT),"retained_export_receipt_sha256":producer.EXPORT_SHA,
            "repositories":repositories,"inventory_sha256":sdk.digest(sdk.canonical(repositories)),
            "modules":retained["modules"],"registry_metadata":retained["registry_metadata"],
            "nix_store_roots":retained["nix_store_roots"],"nix_inventory":retained["nix_inventory"],
            "counts":{"entries":budget.entry_counts(),"bytes":budget.bytes},
            "native_compile_passed":False,"native_support":False,"provider_evaluation":False}
        PHASE="readback"
        # A separate complete sealed readback, under the SAME original deadline.
        verifier=sdk.Budget(time.time()+max(0.001,min(1200,absolute_deadline-time.monotonic())),producer.tick)
        require(verify_export(output,report,verifier) is True)
        after,_,_=producer.load_candidate(document)
        require(after==source_report and sdk.validate_export(producer.EXPORT_ROOT,producer.EXPORT_SHA,
            source.BASE_INVENTORY,parent["baseline_graph_files"],on_read=producer.tick)==qualified)
        for root,lease in held:producer.recheck_root(root,lease)
        fd=source.directory(output)
        try:
            out=os.open("receipt.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            with os.fdopen(out,"wb") as stream:
                stream.write(source.encoded(report));stream.flush()
                os.fchmod(stream.fileno(),0o444);os.fsync(stream.fileno())
            os.fsync(fd);os.fchmod(fd,0o555)
        finally:os.close(fd)
        return report
    finally:
        for _,(fd,_) in held:os.close(fd)
        source.DEADLINE=None


def main():
    os.umask(0o077)
    document,pin=producer.declared_selection()
    seconds=min(840,int(os.environ["TEST_TIMEOUT"])-60)
    deadline=time.monotonic()+seconds
    temporary=Path(os.environ["TEST_TMPDIR"]).resolve(strict=True)
    outputs=Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)
    # Metadata is freshly generated in THIS action, not caller supplied.
    metadata_root=outputs/"protocol-history-metadata"
    producer.produce(document,pin,temporary/"protocol-history-sdk-work",metadata_root,seconds,
        absolute_deadline=deadline)
    export(document,metadata_root,outputs/"protocol-history-sdk-export",deadline)
    print("selected graph SDK exported; native compilation and provider evaluation unrun")


if __name__=="__main__":
    try:main()
    except (ValueError,OSError,KeyError,TypeError,UnicodeError,SyntaxError,json.JSONDecodeError,subprocess.SubprocessError):
        print("protocol history SDK export refused at "+PHASE,file=sys.stderr)
        raise SystemExit(1) from None
