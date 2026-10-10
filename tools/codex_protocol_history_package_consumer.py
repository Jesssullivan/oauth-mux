"""Strict protocol-history package reader; no native dispatch or cache admission."""
import json
import os
from pathlib import Path, PurePosixPath
import re
import xml.etree.ElementTree as ET

import codex_fresh_native_runtime as fresh
import codex_native_profile as native
import codex_native_staged_compilation as io
import codex_protocol_history_source as history
import codex_protocol_history_metadata_producer as metadata
import codex_protocol_history_native as protocol
import codex_protocol_history_completed_inputs as completed
import codex_protocol_history_cli as cli
import codex_retained_sdk_export as sdk

KIND = "omux-protocol-history-native-package-selection-v1"
ROLES = fresh.ROLES | {"protocol_run","protocol_artifacts","schema_artifacts","cli_artifacts"}
RUNS = ("protocol_run","schema_run","qualification_run")
ENVELOPES = ("protocol_artifacts","schema_artifacts","cli_artifacts")
TOP = frozenset(("kind","source_root","export_root","patch_sha256","files",
    "protocol_schema_files","protocol_schema_roots","native_cli_selection","protocol_history_artifact_files"))
SMALL = 8*1024*1024
SOURCE_FIELDS = frozenset(("schema_version","kind","status","commit","parent_source_root",
    "parent_source_receipt_sha256","parent_source_inventory_sha256","patch_sha256","patches",
    "source_inventory","inventory_sha256","tracked_files","source_bytes","graph_files",
    "parent_graph_files","physical_mode_policy","dependency_change","graph_resolution",
    "sdk_metadata_qualified","native_support","native_compile_passed","provider_evaluation"))


def selected(value):
    return type(value) is dict and value.get("kind") in (KIND, "omux-owner-status-persistence-native-package-selection-v1")


def validate_producer_graph(paths, persistence=False):
    fresh.require(type(paths) is list and len(paths)==len(set(paths)) and 0<len(paths)<=4096
        and {"tools/codex_fresh_native_runtime.py","tools/codex_protocol_history_package_consumer.py",
            "tools/codex_protocol_history_completed_inputs.py","tools/codex_protocol_history_cli.py",
            "tools/codex_protocol_history_native.py"}<=set(paths),
        "protocol-history package graph omitted its actual verification ABI")
    if persistence:
        fresh.require({'tools/codex_persistence_package_family.py',
            'tools/codex_owner_status_persistence_metadata_producer.py',
            'tools/codex_owner_status_persistence_sdk_export.py',
            'tools/codex_owner_status_persistence_source.py',
            'tools/codex_owner_status_persistence_binding.py',
            'tools/codex_owner_status_source.py','tools/codex_owner_status_binding.py',
            'tools/guard_native_metadata_sdk_reserved.py',
            'tools/guard_resident_owner_status_persistence_source_reserved.py'} <= set(paths),
            'persistence package graph omitted its material verification ABI')


def file_pin(pin, mode=False, maximum=SMALL):
    fresh.require(type(pin) is dict and set(pin)==({"path","sha256","bytes","mode"} if mode
        else {"path","sha256","bytes"}) and type(pin["sha256"]) is str
        and fresh.HASH.fullmatch(pin["sha256"]) and type(pin["bytes"]) is int
        and 0<pin["bytes"]<=maximum,"protocol-history exact bounded file pin required")
    fresh.canonical_path(pin["path"])
    if mode:
        fresh.require(type(pin["mode"]) is int and 0<=pin["mode"]<=0o777
            and not pin["mode"] & 0o133,"protocol-history evidence mode differs")


def _run_path(value, leaf):
    path=fresh.canonical_path(value);relative=path.relative_to(fresh.STATE)
    fresh.require(len(relative.parts)==2 and protocol.UUID.fullmatch(relative.parts[0])
        and relative.parts[1]==leaf,"protocol-history exact owned receipt/evidence path required")


def _producer_path(role,value):
    path=str(fresh.canonical_path(value))
    suffix=("/source-receipt.json" if role=="source" else "/receipt.json")
    root=path[:-len(suffix)] if path.endswith(suffix) else ""
    if role=="source":
        fresh.require(metadata.SOURCE_SCOPE.fullmatch(root),"protocol-history source output scope differs")
    else:
        fresh.require(re.fullmatch(
            r"(?:/home/jess/\.local/state/omux-execution-20261005|/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005)/"
            r"(?:cache-v2-[0-9a-f]{64}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})/output-base/execroot/_main/bazel-out/"
            r"[A-Za-z0-9_-]+/testlogs/tools/codex_protocol_history_sdk_export_producer/test.outputs/protocol-history-sdk-export",root),
            "protocol-history SDK output scope differs")


def _artifact_path(value, root_prefix, suffix):
    path=fresh.canonical_path(value);relative=path.relative_to(fresh.STATE)
    fresh.require(len(relative.parts)>=8 and re.fullmatch(root_prefix+r"[0-9a-f]{64}",relative.parts[0])
        and relative.parts[1:5]==("output-base","execroot","_main","bazel-out")
        and re.fullmatch(r"[A-Za-z0-9_.-]+-opt",relative.parts[5])
        and relative.parts[6]=="bin" and "/".join(relative.parts[7:])==suffix,
        "protocol-history actual declared output scope differs")
    return relative.parts[5]


def validate_paths(selection):
    fresh.require(selected(selection) and set(selection)==TOP and set(selection["files"])==ROLES
        and set(selection["protocol_schema_roots"])=={"stable","experimental"},
        "protocol-history exact thirteen-role selection required")
    for role,pin in selection["files"].items():
        file_pin(pin,maximum=fresh.runtime.MAX_ORIGINAL_BYTES if role=="codex" else fresh.MAX_METADATA)
        if role in ("source","export"):
            if selection['kind'] == 'omux-owner-status-persistence-native-package-selection-v1':
                from codex_persistence_package_family import role_root
                suffix = '/source-receipt.json' if role == 'source' else '/receipt.json'
                fresh.require(pin['path'].endswith(suffix), 'persistence receipt leaf differs')
                role_root('source' if role == 'source' else 'sdk', pin['path'][:-len(suffix)])
            else:
                _producer_path(role,pin["path"])
        elif role in ("protocol_run","compile","qualification_run","schema_run"):
            _run_path(pin["path"],"receipt.json")
        elif role in ("protocol_artifacts","schema_artifacts"):_run_path(pin["path"],protocol.ARTIFACTS)
        elif role=="cli_artifacts":_run_path(pin["path"],cli.ARTIFACTS)
        elif role in ("qualification","qualification_xml"):
            _run_path(pin["path"],"native-qualification.json" if role=="qualification" else "native-qualification.xml")
        else:_artifact_path(pin["path"],"protocol-history-cli-" if role=="codex" else
            "protocol-history-checks-","codex-rs/cli/codex" if role=="codex" else "bazel/schema/native-config.schema.json")
    fresh.require(selection["files"]["source"]["path"]==selection["source_root"]+"/source-receipt.json"
        and selection["files"]["export"]["path"]==selection["export_root"]+"/receipt.json",
        "protocol-history selected source/SDK roots differ")
    extras=selection["protocol_history_artifact_files"]
    fresh.require(type(extras) is dict and len(extras)==7,"protocol-history exact seven actual log inputs required")
    for name,pin in extras.items():
        file_pin(pin,True)
        fresh.require(name==pin["path"],"protocol-history extra pin map key differs")
        relative=fresh.canonical_path(name).relative_to(fresh.STATE)
        fresh.require(len(relative.parts) in (2,3) and protocol.UUID.fullmatch(relative.parts[0]) and (
            len(relative.parts)==2 and relative.parts[1]=="test-evidence.json" or
            len(relative.parts)==3 and relative.parts[1]=="test-evidence"
            and re.fullmatch(r"[0-9a-f]{64}\.evidence",relative.parts[2])),
            "protocol-history extra input leaves actual copied evidence")
    pins=selection["protocol_schema_files"]
    fresh.require(type(pins) is dict and 0<len(pins)<=4096,"protocol-history bounded complete JSON inputs required")
    for name,pin in pins.items():
        file_pin(pin)
        parts=PurePosixPath(name).parts
        fresh.require(len(parts)>=3 and parts[0] in ("stable","experimental") and parts[1]=="json"
            and str(PurePosixPath(name))==name and not any(p in ("",".","..") for p in parts)
            and name.endswith(".json"),"protocol-history generated schema member name differs")
        _artifact_path(pin["path"],"protocol-history-checks-",
            "bazel/schema/public-schema-bundle."+parts[0]+"/"+"/".join(parts[1:]))
    for mode,root in selection["protocol_schema_roots"].items():
        _artifact_path(root,"protocol-history-checks-","bazel/schema/public-schema-bundle."+mode+"/json")


def _without_mode(pin):
    return {key:value for key,value in pin.items() if key!="mode"}


def source_sdk(selection,values):
    if selection['kind'] == 'omux-owner-status-persistence-native-package-selection-v1':
        from codex_persistence_package_family import load_source, verify_sdk, INPUT_KIND
        document = selection['native_cli_selection']['inputs']
        protocol.validate_selection(document)
        fresh.require(document['kind'] == INPUT_KIND, 'persistence package requires its distinct native input family')
        report, _, _ = load_source(Path(selection['source_root']), selection['files']['source']['sha256'],
            selection['patch_sha256'], fresh.DEADLINE)
        fresh.require(fresh.parse(values['source']) == report, 'actual reconstructed N3 source receipt differs')
        for role, root_role in (('source','source'),('export','sdk')):
            row = document[root_role]
            fresh.require(row['root'] == selection[role + '_root']
                and row['receipt_sha256'] == selection['files'][role]['sha256'], 'persistence native input receipt join differs')
        protocol.producer_success(document['source'], '//tools:codex_owner_status_persistence_source_producer',
            'owner-status-persistence-source', fresh.DEADLINE)
        protocol.producer_success(document['sdk'], '//tools:codex_owner_status_persistence_sdk_export_producer',
            'owner-status-persistence-sdk-export', fresh.DEADLINE)
        exported, qualified = verify_sdk(Path(selection['export_root']), selection['files']['export']['sha256'],
            report, document, fresh.DEADLINE, protocol.SDK_FIELDS, protocol.METADATA_FIELDS, protocol.read_json)
        fresh.require(fresh.parse(values['export']) == exported, 'actual SDK receipt bytes differ')
        return report, exported, qualified
    source,exported=fresh.parse(values["source"]),fresh.parse(values["export"])
    fresh.require(type(source) is dict and set(source)==SOURCE_FIELDS
        and type(source["schema_version"]) is int and source["schema_version"]==1
        and source["kind"]==history.KIND and source["status"]=="verified-protocol-history-source-pending-sdk-metadata"
        and source["commit"]==fresh.COMMIT and source["parent_source_root"]==str(history.PARENT)
        and source["parent_source_receipt_sha256"]==history.PARENT_RECEIPT_SHA
        and source["parent_source_inventory_sha256"]==history.PARENT_INVENTORY_SHA
        and source["patch_sha256"]==history.PARENT_PATCHES+[history.PATCH_SHA]==selection["patch_sha256"]
        and all(source[name] is False for name in ("sdk_metadata_qualified","native_support",
            "native_compile_passed","provider_evaluation")),"protocol-history exact source producer chain differs")
    inventory=source["source_inventory"]
    fresh.require(type(inventory) is dict and type(source["tracked_files"]) is int
        and source["tracked_files"]==len(inventory)==8549
        and type(source["source_bytes"]) is int and 0<source["source_bytes"]<=source_io_limit()
        and fresh.digest(json.dumps(inventory,sort_keys=True).encode())==source["inventory_sha256"],
        "protocol-history source inventory/count binding differs")
    for name,row in inventory.items():
        source_name(name)
        fresh.require(type(row) is dict and set(row)=={"mode","sha256"} and row["mode"] in ("100644","100755","120000")
            and type(row["sha256"]) is str and fresh.HASH.fullmatch(row["sha256"]),"protocol-history source inventory row differs")
    for graph in ("graph_files","parent_graph_files"):
        fresh.require(set(source[graph])==set(history.GRAPH)
            and all(type(pin) is dict and set(pin)=={"sha256"} and fresh.HASH.fullmatch(pin["sha256"])
                for pin in source[graph].values()),"protocol-history source graph scope differs")
    fresh.require(all(source["graph_files"][name]["sha256"]==inventory[name]["sha256"] for name in history.GRAPH)
        and source["physical_mode_policy"]=="bazel-retained-export-all-regular-and-directories-0555-v1"
        and source["dependency_change"]=={"package":"codex-app-server-protocol","removed_normal":"codex-rollout",
            "existing_normal":"codex-history","changed_paths":sorted(history.ALLOWED)}
        and source["graph_resolution"]=="new-rules-rs-metadata-and-sdk-export-required",
        "protocol-history source dependency declaration differs")
    fresh.require(type(exported) is dict and set(exported)==protocol.SDK_FIELDS
        and exported["kind"]=="omux-protocol-history-sdk-export-v1"
        and exported["status"]=="verified-selected-protocol-history-sdk"
        and type(exported["schema_version"]) is int and exported["schema_version"]==1
        and exported["source_root"]==selection["source_root"]
        and exported["source_receipt_sha256"]==selection["files"]["source"]["sha256"]
        and exported["source_inventory_sha256"]==source["inventory_sha256"]
        and exported["graph_files"]==source["graph_files"]
        and exported["mapping_sha256"]==source["graph_files"]["MODULE.bazel.lock"]["sha256"]
        and exported["retained_export_root"]==str(metadata.EXPORT_ROOT)
        and exported["retained_export_receipt_sha256"]==metadata.EXPORT_SHA
        and all(exported[name] is False for name in ("native_compile_passed","native_support","provider_evaluation")),
        "protocol-history selected SDK source/graph chain differs")
    m=exported["metadata"]
    fresh.require(type(m) is dict and set(m)==protocol.METADATA_FIELDS
        and type(m["schema_version"]) is int and m["schema_version"]==1
        and m["kind"]==metadata.OUTPUT_KIND and m["status"]=="verified-strict-regenerated-protocol-history-hub"
        and m["inputs"]=={"kind":metadata.KIND,"source_root":selection["source_root"],
            "source_receipt_sha256":selection["files"]["source"]["sha256"],"export_root":str(metadata.EXPORT_ROOT),
            "export_receipt_sha256":metadata.EXPORT_SHA}
        and m["source_inventory_sha256"]==source["inventory_sha256"] and m["source_graph"]==source["graph_files"]
        and fresh.digest(metadata.source.encoded(m))==exported["metadata_receipt_sha256"]
        and type(m["selector_sha256"]) is str and fresh.HASH.fullmatch(m["selector_sha256"])
        and type(m["query_exit"]) is int and m["query_exit"]==0
        and all(m[name] is True for name in ("module_lock_unchanged","cargo_lock_unchanged","source_and_export_rechecked"))
        and all(m[name] is False for name in ("sdk_export_qualified","native_compile_passed","native_support","provider_evaluation")),
        "protocol-history strict metadata claim differs")
    fresh.require(type(exported["repositories"]) is list and 0<len(exported["repositories"])<=sdk.MAX_REPOS,
        "protocol-history SDK repository count differs")
    names={row["canonical_name"] for row in exported["repositories"]}
    fresh.require(len(names)==len(exported["repositories"]) and metadata.metadata.HUB in names
        and all(type(name) is str and re.fullmatch(r"[A-Za-z0-9_+.~-]+",name) for name in names)
        and sdk.digest(sdk.canonical(exported["repositories"]))==exported["inventory_sha256"],
        "protocol-history exact SDK aggregate differs")
    repositories={name:str(Path(selection["export_root"])/"repositories"/name) for name in names}
    for row in exported["repositories"]:
        fresh.require(type(row["files"]) is list and sdk.digest(sdk.canonical(row["files"]))==row["inventory_sha256"],
            "protocol-history SDK repository inventory digest differs")
    hub=next(row for row in exported["repositories"] if row["canonical_name"]==metadata.metadata.HUB)
    fresh.require(0<len(hub["files"])<=16 and all(row["kind"]=="file" and "/" not in row["path"]
        and row["mode"]==0o444 and type(row["size"]) is int and 0<=row["size"]<=SMALL
        for row in hub["files"]) and m["generated_hub"]=={row["path"]:{"sha256":row["sha256"],
            "bytes":row["size"],"mode":row["mode"]} for row in hub["files"]}
        and hub["source_files"]==hub["files"] and hub["source_inventory_sha256"]==hub["inventory_sha256"]
        and hub["source_root"]==str(Path(selection["export_root"]).parent/"protocol-history-metadata/hub")
        and all(row["source_root"]==str(metadata.EXPORT_ROOT/"repositories"/row["canonical_name"])
            for row in exported["repositories"] if row["canonical_name"]!=metadata.metadata.HUB)
        and exported["nix_store_roots"]==[sdk.JDK],
        "protocol-history actual generated hub/origin and immutable store differ")
    modules=exported["modules"]
    fresh.require(type(modules) is dict and all(type(name) is str and type(binding) is dict
        and binding["canonical_name"] in names for name,binding in modules.items()),"protocol-history SDK module map differs")
    qualified={"repositories":repositories,"module_overrides":{name:repositories[row["canonical_name"]]
        for name,row in modules.items()},"registry_cache":str(Path(selection["export_root"])/"registry-cache"),
        "inventory_sha256":exported["inventory_sha256"],"mapping_sha256":exported["mapping_sha256"]}
    parent_qualified={"repositories":{name:str(metadata.EXPORT_ROOT/"repositories"/name) for name in names},
        "registry_cache":str(metadata.EXPORT_ROOT/"registry-cache")}
    work=fresh.canonical_path(m["query_plan"]["environment"]["HOME"]).parent
    fresh.require(m["query_plan"]==metadata.query_plan(work,work/"workspace/source",parent_qualified),
        "protocol-history metadata fixed offline query differs")
    return source,exported,qualified


def source_io_limit():
    return metadata.source.MAX_SOURCE


def source_name(name):
    metadata.source.safe_name(name)


def validate_receipts(selection,values):
    validate_paths(selection)
    for role in ("source","export",*RUNS,*ENVELOPES):
        pin=selection["files"][role]
        fresh.require(fresh.digest(values[role])==pin["sha256"] and len(values[role])==pin["bytes"],
            "protocol-history receipt-first byte pin differs")
    source,exported,qualified=source_sdk(selection,values)
    receipts={role:fresh.parse(values[role]) for role in RUNS}
    envelopes={role:fresh.parse(values[role]) for role in ENVELOPES}
    top=selection["native_cli_selection"]
    facts=receipts["qualification_run"]["native_protocol_history_cli"]
    fresh.require(top==facts["bindings"]["cli_selection"]
        and top["inputs"]==receipts["protocol_run"]["native_protocol_history"]["bindings"]["selection"]
        and top["inputs"]["source"]["root"]==selection["source_root"]
        and top["inputs"]["sdk"]["root"]==selection["export_root"]
        and top["inputs"]["source"]["receipt_sha256"]==selection["files"]["source"]["sha256"]
        and top["inputs"]["sdk"]["receipt_sha256"]==selection["files"]["export"]["sha256"]
        and top["inputs"]["source"]["inventory_sha256"]==source["inventory_sha256"]
        and top["inputs"]["sdk"]["inventory_sha256"]==exported["inventory_sha256"]
        and selection["files"]["compile"]==selection["files"]["qualification_run"]
        and values.get("compile",values["qualification_run"])==values["qualification_run"]
        and len({receipt["id"] for receipt in receipts.values()})==3,
        "protocol-history exact independent protocol/schema/CLI receipt joins differ")
    for stage,role,envelope in ((1,"protocol_run","protocol_artifacts"),(2,"schema_run","schema_artifacts")):
        prior=top["predecessors"][str(stage)]
        fresh.require(prior["id"]==receipts[role]["id"]
            and prior["sha256"]==selection["files"][role]["sha256"]
            and prior["artifacts_sha256"]==selection["files"][envelope]["sha256"],
            "protocol-history actual predecessor pin differs")
    completed.validate_completed_receipts(top,{1:receipts["protocol_run"],2:receipts["schema_run"]},
        {1:envelopes["protocol_artifacts"],2:envelopes["schema_artifacts"]},qualified,fresh.DEADLINE,rehash=True)
    cli.validate_completed_success(receipts["qualification_run"],top,(source,qualified),fresh.DEADLINE)
    cli.recheck_closed_custody(receipts["qualification_run"],top,fresh.DEADLINE)
    old_bindings=receipts["protocol_run"]["native_protocol_history"]["bindings"]
    fresh.require(all(protocol.canonical(facts["bindings"][name])==protocol.canonical(old_bindings[name])
        for name in ("controller_inventory","controller_graph","tools","locked_path","boot_host","source_sdk_custody")),
        "protocol-history CLI must preserve the actual predecessor controller/tool/custody graph")
    fresh.require(protocol.canonical(cli.collect_artifacts(fresh.STATE/receipts["qualification_run"]["id"],
        receipts["qualification_run"],fresh.DEADLINE))==protocol.canonical(envelopes["cli_artifacts"]),
        "protocol-history actual CLI/fourteen envelope changed")
    for role,envelope in zip(RUNS,ENVELOPES):
        receipt=receipts[role];record=envelopes[envelope]
        leaf=cli.ARTIFACTS if role=="qualification_run" else protocol.ARTIFACTS
        f=receipt["native_protocol_history_cli" if role=="qualification_run" else "native_protocol_history"]
        fresh.require(selection["files"][role]["path"]==str(fresh.STATE/receipt["id"]/"receipt.json")
            and selection["files"][envelope]["path"]==str(fresh.STATE/receipt["id"]/leaf)
            and selection["files"][envelope]["sha256"]==f["artifacts_sha256"]
            and record["id"]==receipt["id"] and record["source_receipt_sha256"]==selection["files"]["source"]["sha256"]
            and record["sdk_receipt_sha256"]==selection["files"]["export"]["sha256"]
            and record["controller_graph_sha256"]==receipt["graph_sha256"],
            "protocol-history envelope actual action pin differs")
    return receipts,envelopes,source,exported,qualified


def evidence_files(selection,records,receipts):
    old=records["protocol_artifacts"]["artifacts"]
    new=records["cli_artifacts"]["artifacts"]
    fresh.require(set(old)=={"manifest","logs"} and set(old["logs"])==set(protocol.GATES)
        and set(new)=={"cli","cli_context","qualification"}
        and set(new["qualification"])=={"manifest","group","xml","logs"}
        and set(new["qualification"]["logs"])==set(native.QUALIFICATION_GATES),
        "protocol-history complete old16/new14 actual evidence required")
    expected={}
    for artifact in (old,new["qualification"]):
        for pin in (artifact["manifest"],*artifact["logs"].values()):
            file_pin(pin,True)
            fresh.require(pin["path"] not in expected,"protocol-history duplicate evidence file")
            expected[pin["path"]]=pin
    fresh.require(expected==selection["protocol_history_artifact_files"] and len(expected)==7,
        "protocol-history exact declared copied manifest/logs differ")
    for role,pin in (("qualification",new["qualification"]["group"]),
            ("qualification_xml",new["qualification"]["xml"])):
        file_pin(pin,True)
        fresh.require(_without_mode(pin)==selection["files"][role],"protocol-history14 group/XML pin differs")
    for role,artifact in (("protocol_run",old),("qualification_run",new["qualification"])):
        root=fresh.STATE/receipts[role]["id"]
        fresh.require(artifact["manifest"]["path"]==str(root/"test-evidence.json")
            and artifact["manifest"]["sha256"]==receipts[role]["test_evidence"]["sha256"],
            "protocol-history actual preserved manifest differs")
        for pin in artifact["logs"].values():
            fresh.require(fresh.canonical_path(pin["path"]).parent==root/"test-evidence",
                "protocol-history actual copied log epoch differs")
    return expected


def read_extra(selection,records,receipts,alias=None):
    expected=evidence_files(selection,records,receipts);values={}
    for name,pin in expected.items():
        if alias is not None:
            fresh.require(str(alias("protocol-history/"+name,pin))==name,
                "protocol-history evidence is not a declared input")
        fresh.require(io.artifact_file(Path(name),fresh.DEADLINE,SMALL)==pin,
            "protocol-history actual copied evidence mode/bytes differ")
        values[name]=fresh.read_selected(Path(name),_without_mode(pin),SMALL)
    return values


def schema_inventory(selection,receipts):
    # Reuse the bounded physical JSON walker with the independently verified
    # actual predecessor schema output-base; it supplies no dispatch authority.
    from codex_staged_native_package_consumer import validate_schema_inventory
    validate_schema_inventory(selection,{"schema_run":{"native_staged_compilation":{
        "output_base":receipts["schema_run"]["native_protocol_history"]["output_base"]}}})


def load_inputs(selection,read,alias=None):
    validate_paths(selection)
    values={role:read(role,selection["files"][role],fresh.MAX_METADATA)
        for role in ("source","export",*RUNS,*ENVELOPES)}
    values["compile"]=values["qualification_run"]
    receipts,records,_,_,_=validate_receipts(selection,values)
    # Only an actual completed chain can expose executable or generated bytes.
    extra=read_extra(selection,records,receipts,alias)
    schema_inventory(selection,receipts)
    for role in sorted(ROLES-set(values)):
        values[role]=read(role,selection["files"][role],fresh.runtime.MAX_ORIGINAL_BYTES if role=="codex" else SMALL)
    protocol_values={};total=len(values["config_schema"])
    for name,pin in selection["protocol_schema_files"].items():
        value=read("protocol/"+name,pin,SMALL);total+=len(value)
        fresh.require(total<=64*1024*1024 and type(fresh.parse(value)) is dict,"protocol-history JSON aggregate differs")
        protocol_values[name]=value
    return values,protocol_values,extra


def qualification(selection,values,extra,receipts,records,source,exported):
    qualified=records["cli_artifacts"]["artifacts"]
    group=fresh.parse(values["qualification"])
    facts=receipts["qualification_run"]["native_protocol_history_cli"]
    context={"invocation_id":receipts["qualification_run"]["id"],"output_base":facts["output_base"],
        "source_receipt_sha256":selection["files"]["source"]["sha256"],
        "export_receipt_sha256":selection["files"]["export"]["sha256"],
        "source_inventory_sha256":source["inventory_sha256"],"export_inventory_sha256":exported["inventory_sha256"],
        "candidate_cache_key":facts["key"],"candidate_provenance_sha256":facts["provenance_sha256"],
        "controller_graph_sha256":receipts["qualification_run"]["graph_sha256"],"bazel":fresh.BAZEL,
        "workload_exit":0,"descendants_empty":True,"source_and_export_verified_after_cleanup":True}
    fresh.require(set(context)==native.CLI_CONTEXT_FIELDS and group["cli_context"]==context==qualified["cli_context"],
        "protocol-history actual CLI cleanup context differs")
    config=_artifact_path(selection["files"]["codex"]["path"],"protocol-history-cli-","codex-rs/cli/codex")
    actual={"kind":"actual-explicit-cli-target-v1","target":fresh.CLI,"configuration":config,
        **selection["files"]["codex"]}
    fresh.require(group["cli_artifact"]==qualified["cli"]==actual and values["codex"].startswith(b"\x7fELF")
        and type(group["passed"]) is int and group["passed"]==14 and type(group["failed"]) is int
        and group["failed"]==0 and type(group["ignored"]) is int and group["ignored"]==0
        and group["schema"]=="omux-native-grouped-qualification-v1"
        and group["xml_sha256"]==fresh.digest(values["qualification_xml"])
        and group["native_support"] is False and group["provider_evaluation"] is False
        and set(group["targets"])==set(native.QUALIFICATION_GATES),
        "protocol-history actual explicit CLI/fourteen qualification differs")
    evidence=qualified["qualification"]
    manifest=fresh.parse(extra[evidence["manifest"]["path"]])
    fresh.require(manifest["targets"]==list(native.MODES[native.COMBINED_MODE][1])
        and len(manifest["results"])==4,"protocol-history actual explicit CLI/14 manifest differs")
    xml=ET.fromstring(values["qualification_xml"])
    fresh.require(xml.tag=="testsuites" and xml.attrib=={"tests":"14","failures":"0","errors":"0","skipped":"0"},
        "protocol-history actual14 XML totals differ")
    suites=xml.findall("testsuite")
    fresh.require(len(suites)==3 and {s.get("name") for s in suites}==set(native.QUALIFICATION_GATES),
        "protocol-history actual14 XML targets differ")
    for target,names in native.QUALIFICATION_GATES.items():
        pin=evidence["logs"][target];raw=extra[pin["path"]]
        rows=[row for row in manifest["results"] if row["target"]==target]
        fresh.require(len(rows)==1 and rows[0]["state"]=="observed","protocol-history actual14 target absent")
        entries=[entry for entry in rows[0]["files"] if entry["source"]=="test.log" and entry["state"]=="copied"]
        fresh.require(len(entries)==1 and pin["path"]==str(fresh.STATE/receipts["qualification_run"]["id"]/
            "test-evidence"/entries[0]["file"]) and entries[0]["sha256"]==pin["sha256"]
            ==group["targets"][target]["log_sha256"] and native.qualification_log(raw,target)==sorted(names),
            "protocol-history actual accepted14 log differs")
        row=group["targets"][target];suite=next(s for s in suites if s.get("name")==target)
        cases=suite.findall("testcase");props=suite.findall("properties/property")
        fresh.require(row["tests"]==sorted(names) and suite.get("tests")==str(len(names))
            and all(suite.get(k)=="0" for k in ("failures","errors","skipped")) and len(cases)==len(names)
            and sorted(c.get("name") for c in cases)==sorted(names)
            and all(c.get("classname")==target and len(c)==0 for c in cases)
            and len(props)==1 and props[0].attrib=={"name":"actual_test_log_sha256","value":pin["sha256"]},
            "protocol-history actual14 XML names/log pins differ")
    rows=[row for row in manifest["results"] if row["target"]==fresh.CLI]
    fresh.require(len(rows)==1 and rows[0]["state"]=="missing-test-directory" and rows[0]["files"]==[],
        "protocol-history explicit CLI must not invent a test result")
    old=records["protocol_artifacts"]["artifacts"]
    old_manifest=fresh.parse(extra[old["manifest"]["path"]])
    fresh.require(old_manifest["targets"]==list(protocol.MODES[protocol.STAGES[1]][1])
        and len(old_manifest["results"])==2 and {row["target"] for row in old_manifest["results"]}==set(protocol.GATES),
        "protocol-history actual predecessor test set differs")
    for target in protocol.GATES:
        pin=old["logs"][target];rows=[row for row in old_manifest["results"] if row["target"]==target]
        fresh.require(len(rows)==1 and rows[0]["state"]=="observed","protocol-history predecessor target absent")
        entries=[entry for entry in rows[0]["files"] if entry["source"]=="test.log" and entry["state"]=="copied"]
        fresh.require(len(entries)==1 and pin["path"]==str(fresh.STATE/receipts["protocol_run"]["id"]/
            "test-evidence"/entries[0]["file"]) and pin["sha256"]==entries[0]["sha256"]
            and protocol.named_log(extra[pin["path"]],target)==sorted(protocol.GATES[target]),
            "protocol-history actual predecessor named tests differ")
    return config,group,context,actual


def validate_chain(selection,values,protocol_values,extra):
    validate_paths(selection)
    fresh.require(set(values)==ROLES and set(protocol_values)==set(selection["protocol_schema_files"]),
        "protocol-history complete declared byte role set differs")
    for role,value in values.items():
        pin=selection["files"][role]
        fresh.require(len(value)==pin["bytes"] and fresh.digest(value)==pin["sha256"],
            "protocol-history actual role bytes differ")
    receipts,records,source,exported,_=validate_receipts(selection,values)
    fresh.require(read_extra(selection,records,receipts)==extra,"protocol-history actual evidence changed")
    config,group,context,actual=qualification(selection,values,extra,receipts,records,source,exported)
    schema=records["schema_artifacts"]["artifacts"]
    fresh.require(set(schema)=={"config_schema","protocol_schema_files","protocol_schema_roots"}
        and _without_mode(schema["config_schema"])==selection["files"]["config_schema"]
        and schema["protocol_schema_roots"]==selection["protocol_schema_roots"],
        "protocol-history actual complete schema envelope differs")
    pins={mode+"/json/"+rest:pin for name,pin in schema["protocol_schema_files"].items()
        for mode,rest in [name.split("/",1)]}
    fresh.require({name:_without_mode(pin) for name,pin in pins.items()}==selection["protocol_schema_files"],
        "protocol-history actual complete schema pins differ")
    fresh.require(_artifact_path(selection["files"]["config_schema"]["path"],"protocol-history-checks-",
        "bazel/schema/native-config.schema.json")==config,"protocol-history CLI/schema configurations differ")
    config_schema=fresh.parse(values["config_schema"])
    definitions=config_schema.get("definitions",config_schema.get("$defs",{}))
    fresh.require(definitions["OmuxBrokerContextMode"]["enum"]==["full_native","text_transcript_v1"]
        and definitions["OmuxBrokerConfig"]["properties"]["context_mode"]["default"]=="full_native",
        "protocol-history actual native text schema policy differs")
    total=len(values["config_schema"])
    for name,value in protocol_values.items():
        pin=selection["protocol_schema_files"][name];total+=len(value)
        fresh.require(fresh.digest(value)==pin["sha256"] and len(value)==pin["bytes"]
            and type(fresh.parse(value)) is dict and total<=64*1024*1024,
            "protocol-history complete actual JSON byte set differs")
    for pin in (schema["config_schema"],*pins.values()):
        fresh.require(io.artifact_file(Path(pin["path"]),fresh.DEADLINE,SMALL)==pin,
            "protocol-history actual schema output custody differs")
    schema_inventory(selection,receipts)
    facts=receipts["qualification_run"]["native_protocol_history_cli"]
    return {**({'material_family':selection['kind']} if selection['kind'] ==
        'omux-owner-status-persistence-native-package-selection-v1' else {}),
        "upstream_commit":fresh.COMMIT,"patch_sha256":selection["patch_sha256"],
        "source_inventory_sha256":source["inventory_sha256"],"export_inventory_sha256":exported["inventory_sha256"],
        "candidate_cache_key":facts["key"],"candidate_provenance_sha256":facts["provenance_sha256"],
        "configuration":config,"compile_invocation_id":receipts["qualification_run"]["id"],
        "qualification_invocation_id":receipts["qualification_run"]["id"],
        "schema_invocation_id":receipts["schema_run"]["id"],"input_files":selection["files"],
        "protocol_schema_files":selection["protocol_schema_files"],"protocol_schema_roots":selection["protocol_schema_roots"],
        "qualified_tests":group["targets"],"compile_evidence_kind":"protocol-history-explicit-cli-and-fourteen",
        "cli_artifact":actual,"cli_context":context,"native_protocol_history":{
            "protocol":receipts["protocol_run"]["native_protocol_history"],
            "schema":receipts["schema_run"]["native_protocol_history"],
            "cli":facts,"artifact_envelopes":{name:selection["files"][name] for name in ENVELOPES},
            "artifact_files":selection["protocol_history_artifact_files"]}}

def validate_protocol_inventory(selection):
    validate_paths(selection)
    values={role:fresh.read_selected(Path(selection["files"][role]["path"]),selection["files"][role],fresh.MAX_METADATA)
        for role in ("source","export",*RUNS,*ENVELOPES)}
    values["compile"]=values["qualification_run"]
    receipts,_,_,_,_=validate_receipts(selection,values)
    schema_inventory(selection,receipts)
