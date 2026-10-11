"""Exact N3 material family for package validation; no native dispatch or selectors."""
import os
from pathlib import Path
import re
import stat
import time
from decimal import Decimal
import codex_owner_status_persistence_metadata_producer as producer
import codex_owner_status_persistence_sdk_export as export
import codex_owner_status_persistence_source as persistence
import codex_retained_sdk_export as sdk

PACKAGE_KIND = "omux-owner-status-persistence-native-package-selection-v1"
INPUT_KIND = "omux-owner-status-persistence-native-selection-v1"
SDK_EXTRA = frozenset(("binding_receipt_sha256", "sdk_export_qualified",
                       "schema_producer_qualified", "live_handoff_proven"))
METADATA_EXTRA = frozenset(("binding_receipt_sha256", "schema_producer_qualified", "live_handoff_proven"))
SOURCE_TARGET = "//tools:codex_owner_status_persistence_source_producer"
SDK_TARGET = "//tools:codex_owner_status_persistence_sdk_export_producer"
METADATA_TARGET = "//tools:codex_owner_status_persistence_metadata_producer"
SDK_SCOPE = re.compile(r"(?:/home/jess/\.local/state/omux-execution-20261005|"
    r"/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005)/"
    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/output-base/execroot/_main/bazel-out/"
    r"[A-Za-z0-9_-]+/testlogs/tools/codex_owner_status_persistence_sdk_export_producer/"
    r"test.outputs/owner-status-persistence-sdk-export\Z")


def require(value):
    if value is not True:
        raise ValueError("persistence-package-family-refused")


def role_root(role, root):
    require(type(root) is str and role in ("source", "sdk"))
    require(root == str(producer.binding.ROOT) if role == "source" else SDK_SCOPE.fullmatch(root) is not None)


def producer_policy(receipt, target):
    import guard_native_seed_plan_reserved as kernel
    if target == SOURCE_TARGET:
        import guard_resident_owner_status_persistence_source_reserved as admission
        profile, targets = admission.PROFILE, admission.ARGUMENTS[1:]
        value = receipt['resident_owner_status_persistence_source_reservation']
        expected = admission.projection(value['original_entry_monotonic_ns'],
            value['original_deadline_monotonic_ns'], True, value['resident'])
    else:
        require(target in (SDK_TARGET, METADATA_TARGET))
        import guard_native_metadata_sdk_reserved as admission
        profile = admission.SDK if target == SDK_TARGET else admission.METADATA
        targets = list(admission.COHORTS[profile])
        value = receipt['native_metadata_sdk_reservation']
        expected = admission.projection(profile, value['original_entry_monotonic_ns'],
            value['original_deadline_monotonic_ns'], True, value['resident'])
    require(value == expected and receipt['profile'] == profile
        and receipt['cache_reuse_requested'] is False
        and receipt['cache_policy'] is None and receipt['cache_key'] is None)
    observed = receipt['observed_properties']
    require(all(observed.get(name) == setting for name, setting in {
        'MemoryMax':'4026531840','MemorySwapMax':'0','TasksMax':'480','PrivateNetwork':'yes',
        'KillMode':'control-group','SendSIGKILL':'yes','OOMPolicy':'kill','RemainAfterExit':'yes'}.items()))
    token = observed.get('CPUQuotaPerSecUSec')
    match = re.fullmatch(r'([0-9]{1,7}(?:[.][0-9]{1,6})?)(us|ms|s)', token) if type(token) is str else None
    require(match is not None and Decimal(match[1])*{'us':1,'ms':1000,'s':1000000}[match[2]] == 1900000)
    resident = value['resident']
    require(type(resident) is dict and set(resident) == {'scope','kernel_bounds','observations',
        'initial_direct_processes_retained','initial_direct_process_count','outer_pid_namespace_matched',
        'hierarchical_caps','descendant_process_inventory','installation_qualified','health_observed',
        'custody_observed','resident_signalled','whole_host_reservation'}
        and resident['scope'] == 'sampled-fixed-default-cgroup-kernel-reservation-v1'
        and type(resident['observations']) is int and 0 < resident['observations'] <= 65535
        and type(resident['initial_direct_process_count']) is int and 0 < resident['initial_direct_process_count'] <= 32
        and all(resident[name] is True for name in ('initial_direct_processes_retained','outer_pid_namespace_matched','hierarchical_caps'))
        and all(resident[name] is False for name in ('descendant_process_inventory','installation_qualified','health_observed',
            'custody_observed','resident_signalled','whole_host_reservation')))
    kernel.kernel_bounds(resident['kernel_bounds'])
    require(resident['initial_direct_process_count'] <= int(resident['kernel_bounds']['pids.max']))
    return profile, targets


def load_source(root, receipt_pin, patches, deadline):
    role_root("source", str(root))
    require(receipt_pin == producer.binding.RECEIPT_SHA)
    old_source, old_producer = producer.source.DEADLINE, producer.DEADLINE
    producer.source.DEADLINE = producer.DEADLINE = deadline
    try:
        document = producer.selected_document()
        report, files, parent = producer.load_candidate(document)
        require(report["kind"] == persistence.KIND
            and report["status"] == "verified-owner-status-persistence-source-pending-sdk-and-schema"
            and report["patch_sha256"] == list(patches)
            and len(patches) == 6
            and all(report[name] is False for name in ("sdk_metadata_qualified", "schema_producer_qualified",
                "native_compile_passed", "native_support", "provider_evaluation", "live_handoff_proven")))
        return report, files, parent
    finally:
        producer.source.DEADLINE, producer.DEADLINE = old_source, old_producer


def sdk_claim(report, document, source_report, sdk_fields, metadata_fields):
    require(type(report) is dict and set(report) == sdk_fields | SDK_EXTRA
        and type(report["schema_version"]) is int and report["schema_version"] == 1
        and report["kind"] == export.KIND
        and report["status"] == "verified-selected-owner-status-persistence-sdk"
        and report["source_root"] == document["source"]["root"]
        and report["source_receipt_sha256"] == document["source"]["receipt_sha256"]
        and report["source_inventory_sha256"] == source_report["inventory_sha256"]
        and report["graph_files"] == source_report["graph_files"]
        and report["mapping_sha256"] == source_report["graph_files"]["MODULE.bazel.lock"]["sha256"]
        and report["inventory_sha256"] == document["sdk"]["inventory_sha256"]
        and type(report['repositories']) is list and 0 < len(report['repositories']) <= sdk.MAX_REPOS
        and type(report['counts']) is dict and set(report['counts']) == {'entries','bytes'}
        and type(report['counts']['bytes']) is int and 0 <= report['counts']['bytes'] <= sdk.MAX_BYTES
        and type(report['counts']['entries']) is dict
        and set(report['counts']['entries']) == {'qualification','copy','sealed_readback'}
        and all(type(value) is int and 0 <= value <= sdk.MAX_FILES for value in report['counts']['entries'].values())
        and report["retained_export_root"] == str(producer.EXPORT_ROOT)
        and report["retained_export_receipt_sha256"] == producer.EXPORT_SHA
        and report["binding_receipt_sha256"] == producer.BINDING_SHA
        and report["sdk_export_qualified"] is True
        and all(report[name] is False for name in ("schema_producer_qualified", "live_handoff_proven",
            "native_compile_passed", "native_support", "provider_evaluation")))
    m = report["metadata"]
    require(type(m) is dict and set(m) == metadata_fields | METADATA_EXTRA
        and type(m["schema_version"]) is int and m["schema_version"] == 1
        and m["kind"] == producer.OUTPUT_KIND
        and m["status"] == "verified-strict-regenerated-owner-status-persistence-hub"
        and m["inputs"] == producer.selected_document()
        and m["binding_receipt_sha256"] == producer.BINDING_SHA
        and m["source_inventory_sha256"] == source_report["inventory_sha256"]
        and m["source_graph"] == source_report["graph_files"]
        and producer.source.sha(producer.source.encoded(m)) == report["metadata_receipt_sha256"]
        and type(m["selector_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", m["selector_sha256"]) is not None
        and type(m["query_exit"]) is int and m["query_exit"] == 0
        and all(m[name] is True for name in ("module_lock_unchanged", "cargo_lock_unchanged", "source_and_export_rechecked"))
        and all(m[name] is False for name in ("sdk_export_qualified", "schema_producer_qualified",
            "live_handoff_proven", "native_compile_passed", "native_support", "provider_evaluation")))


def verify_sdk(root, receipt_pin, source_report, document, deadline, sdk_fields, metadata_fields, reader):
    role_root("sdk", str(root))
    report = reader(root / "receipt.json", receipt_pin, deadline, 64 * 1024 * 1024)
    sdk_claim(report, document, source_report, sdk_fields, metadata_fields)
    require(reader(root.parent / 'owner-status-persistence-metadata/metadata-receipt.json',
        report['metadata_receipt_sha256'], deadline, 64 * 1024 * 1024) == report['metadata'])
    old_source, old_producer = producer.source.DEADLINE, producer.DEADLINE
    producer.source.DEADLINE = producer.DEADLINE = deadline
    budget = sdk.Budget(time.time() + max(0.001, deadline - time.monotonic()), producer.tick)
    try:
        producer.tick()
        hold = producer.hold_root(root)
        try:
            # Full actual sealed byte/registry/JDK/absence proof, not the claim flags.
            require(export.verify_export(root, report, budget) is True)
            retained, files, parent = producer.load_candidate(producer.selected_document())
            require(retained == source_report)
            qualified = sdk.validate_export(producer.EXPORT_ROOT, producer.EXPORT_SHA,
                producer.source.BASE_INVENTORY, parent['baseline_graph_files'], on_read=producer.tick)
            old = export.load_retained(budget)
            require(report["modules"] == old["modules"] and report["registry_metadata"] == old["registry_metadata"]
                and report["nix_inventory"] == old["nix_inventory"])
            new_repos = {row["canonical_name"]: row for row in report["repositories"]}
            old_repos = {row["canonical_name"]: row for row in old["repositories"]}
            require(len(new_repos) == len(report["repositories"]) and set(new_repos) == set(old_repos))
            hub = producer.metadata.HUB
            require(all(new_repos[name] == {**old_repos[name], "source_root": str(producer.EXPORT_ROOT / "repositories" / name)}
                        for name in old_repos if name != hub))
            previous = producer.read_hub(producer.EXPORT_ROOT / "repositories" / hub)
            generated = producer.read_hub(root / "repositories" / hub)
            producer.metadata.verify_hub_delta(previous, generated)
            require(report["metadata"]["generated_hub"] == {name: {"sha256": producer.source.sha(raw),
                "bytes": len(raw), "mode": 0o444} for name, raw in generated.items()}
                and report["metadata"]["retained_hub"] == {name: {"sha256": producer.source.sha(raw), "bytes": len(raw)}
                    for name, raw in previous.items()}
                and report["metadata"]["parent_export_inventory_sha256"] == qualified["inventory_sha256"])
            work = Path(report["metadata"]["query_plan"]["environment"]["HOME"]).parent
            require(report["metadata"]["query_plan"] == producer.query_plan(work, work / "workspace/source", qualified))
            row = new_repos[hub]
            require(row["source_root"] == str(root.parent / "owner-status-persistence-metadata/hub")
                and row["source_files"] == row["files"] and row["source_inventory_sha256"] == row["inventory_sha256"])
            fd = sdk.open_dir(root)
            try:
                require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o555
                    and set(os.listdir(fd)) == {"repositories", "graph", "registry-cache", "receipt.json"})
            finally: os.close(fd)
            graph_shape(root / 'graph', report['graph_files'], deadline)
            require(producer.load_candidate(producer.selected_document())[0] == source_report)
            producer.recheck_root(root, hold)
            require(reader(root / "receipt.json", receipt_pin, deadline, 64 * 1024 * 1024) == report)
        finally: os.close(hold[0])
    finally:
        producer.source.DEADLINE, producer.DEADLINE = old_source, old_producer
    repositories = {name: str(root / "repositories" / name) for name in new_repos}
    return report, {"repositories": repositories, "module_overrides": {name: repositories[row["canonical_name"]]
        for name, row in report["modules"].items()}, "registry_cache": str(root / "registry-cache"),
        "inventory_sha256": report["inventory_sha256"], "mapping_sha256": report["mapping_sha256"],
        "graph_files": report['graph_files'],
        "registry_inventory_sha256": report['registry_metadata']['inventory_sha256']}


def graph_shape(root, files, deadline):
    """Exact sealed physical graph, including empty/extra-directory refusal."""
    names = set(files)
    directories = {''} | {str(parent) for name in names for parent in Path(name).parents
                           if str(parent) != '.'}
    def visit(relative=''):
        require(time.monotonic() < deadline)
        fd = sdk.open_dir(root / relative)
        try:
            require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o555)
            expected = {name[len(relative)+1:].split('/')[0] if relative else name.split('/')[0]
                        for name in names if not relative or name.startswith(relative+'/')}
            require(set(os.listdir(fd)) == expected)
            for name in expected:
                require(time.monotonic() < deadline)
                child = relative+'/'+name if relative else name
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if child in directories:
                    require(stat.S_ISDIR(info.st_mode))
                    visit(child)
                else:
                    require(child in names and stat.S_ISREG(info.st_mode)
                        and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o444)
        finally:
            os.close(fd)
    visit()
