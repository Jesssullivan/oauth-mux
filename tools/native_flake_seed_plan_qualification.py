"""One fixed provider-free fresh private restore and actual missing-plan test.

No realization, shared-store query, selector write, native admission or retry.
The matching successful outer execution receipt is a separate required join.
"""
import argparse
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

import nar_descriptor as nar
import native_flake_seed_plan as plan
import native_flake_seed_plan_inputs as inputs
import native_flake_schedule as schedule
import native_flake_sources as sources
import nix_private_store_seed as seed
import nix_private_store_qualification as proof
from verify_declared_nars import metadata_alias_roots

PHASE = "admission"


def phase(value):
    global PHASE
    PHASE = value


def read(file, maximum, deadline):
    proof.tick(deadline)
    # Only the fixed declared argv files may follow Bazel's runfile alias.
    selected = Path(file).resolve(strict=True)
    with nar.open_regular(str(selected), "") as stream:
        before = os.fstat(stream.fileno())
        inputs.require(0 < before.st_size <= maximum)
        raw = bytearray()
        while len(raw) <= maximum:
            proof.tick(deadline)
            part = stream.read(min(65536, maximum+1-len(raw)))
            if not part:
                break
            raw.extend(part)
        with nar.open_regular(str(Path(file).resolve(strict=True)), "") as named:
            inputs.require(len(raw) == before.st_size
                and inputs.witness(before) == inputs.witness(os.fstat(stream.fileno()))
                == inputs.witness(os.fstat(named.fileno())))
        return bytes(raw)


def helper_pins(deadline):
    return {name: seed.sha(read(Path(__file__).parent/name, 1024**2, deadline))
        for name in ("native_flake_schedule.py", "native_flake_sources.py", "nix_private_store_seed.py",
            "nix_private_store_qualification.py", "nar_descriptor.py", "verify_declared_nars.py",
            "verify_cached_nars.py", "nix_source_probe.py", "nix_interpreter_closure.py")}


def qualify(selected_raw, selection_sha256, bundle_raw, mapping_sha256, bundle_path,
            runtime_raw, runtime_metadata, source_raw, source_path, project, wrapper_raw, parent, deadline,
            *, implementation=None, runner=proof.run):
    """Reusable actual method; model child calls may be injected only in tests."""
    proof.tick(deadline)
    inputs.require(seed.sha(selected_raw) == selection_sha256
        and seed.sha(bundle_raw) == mapping_sha256)
    selected = inputs.selection(inputs.decode(selected_raw, inputs.MAX_SELECTION))
    bundle = inputs.decode(bundle_raw, inputs.MAX_MAPPING)
    inputs.require(bundle["selection_sha256"] == selection_sha256)
    opener = inputs.bundle_opener(bundle, bundle_path)
    phase("declared-metadata")
    metadata = inputs.declared_metadata(bundle, bundle_path, selected, deadline)
    phase("producer-success")
    receipt = inputs.producer_success(selected, metadata)
    phase("locked-source-proof")
    source_report = sources.verify(project["flake.lock"], source_raw, Path(source_path).parent,
        metadata_alias_roots(source_path), deadline=deadline)
    phase("obligations-join")
    body, runtime, records = plan.join_obligations(metadata["obligations"],
        selected["obligations"]["sha256"], runtime_raw, source_report, project, seed.sha(wrapper_raw))
    inputs.require(type(runtime_metadata) is dict
        and set(runtime_metadata) == {"native", "paths", "registration", "inventory"}
        and all(seed.sha(runtime_metadata[name]) == runtime["metadata_sha256"][name]
            for name in ("native", "paths", "registration"))
        and seed.sha(runtime_metadata["inventory"]) == body["seed_file_inventory_sha256"])
    actual_helpers = helper_pins(deadline) if implementation is None else implementation
    inputs.require(body["implementation_sha256"] == actual_helpers)
    _, chosen = plan.candidates(body, inputs.candidate_records(selected, metadata))
    expected = set(records) | set(chosen)
    inputs.require(set(bundle["roots"]) == expected)
    for logical, descriptor in runtime["descriptors"].items():
        inputs.require(seed.encoded(bundle["roots"][logical]["descriptor"]) == seed.encoded(descriptor))
    for logical, item in body["generated"].items():
        inputs.require(seed.encoded(bundle["roots"][logical]["descriptor"]) == seed.encoded(item["descriptor"]))
    retained_roots = frozenset(logical for logical, item in body["generated"].items()
        if "artifact_root" in item)
    inputs.require(retained_roots == frozenset(logical for logical, item in bundle["roots"].items()
        if item.get("retained_transport") == inputs.RETAINED_TRANSPORT))
    phase("fresh-private-missing-plan")
    result = plan.restore_plan(body, runtime, records, chosen,
        {root: row["descriptor"] for root, row in bundle["roots"].items()}, opener,
        parent, deadline, runner=runner, retained_roots=retained_roots)
    phase("selected-input-readback")
    again = inputs.declared_metadata(bundle, bundle_path, selected, deadline)
    inputs.require(again == metadata)
    phase("producer-success-readback")
    inputs.producer_success(selected, again)
    phase("locked-source-readback")
    inputs.require(sources.verify(project["flake.lock"], source_raw, Path(source_path).parent,
        metadata_alias_roots(source_path), deadline=deadline) == source_report)
    if implementation is None:
        inputs.require(helper_pins(deadline) == actual_helpers)
    proof.tick(deadline)
    result.update(status="selected-fresh-private-missing-plan-qualified",
        selection_sha256=selection_sha256, mapping_sha256=mapping_sha256,
        producer_epoch=receipt["id"], producer_receipt_sha256=selected["producer"]["receipt"]["sha256"],
        producer_source_commit=selected["producer"]["source_commit"],
        producer_graph_sha256=selected["producer"]["graph_sha256"],
        obligations_sha256=selected["obligations"]["sha256"],
        input_metadata_rechecked=True, locked_sources_rechecked=True,
        qualification_provider_requests=0, outer_success_and_owned_empty_required=True)
    return result


def work_envelope(entry, timeout, environment):
    """Old TEST clock stays unchanged; only the fixed reserved route clamps it."""
    inputs.require(re.fullmatch(r"[0-9]{1,5}",timeout) and int(timeout)>proof.CLEANUP_SECONDS)
    deadline = float(entry+min(schedule.MAX_SECONDS,int(timeout)-proof.CLEANUP_SECONDS))
    names = ("OMUX_NATIVE_SEED_RESERVED_PROFILE","OMUX_NATIVE_SEED_ROOT_ENTRY_NS",
        "OMUX_NATIVE_SEED_ROOT_DEADLINE_NS")
    values = tuple(environment.get(name) for name in names)
    if all(value is None for value in values):
        return deadline,None
    inputs.require(all(type(value) is str for value in values)
        and values[0]=="native-seed-plan-reserved"
        and all(re.fullmatch(r"[1-9][0-9]{0,19}",value) for value in values[1:]))
    original_entry,original_deadline = map(int,values[1:])
    now = int(entry*10**9)
    inputs.require(original_deadline-original_entry==1200*10**9
        and original_entry<=now<original_deadline-60*10**9)
    # restore_plan's existing finally has a30s private cleanup tail. Keep that
    # tail before the guardian's separate final30s, without renewing either.
    deadline = min(deadline,math.nextafter((original_deadline-60*10**9)/10**9,-math.inf))
    return deadline,{"profile":values[0],"original_entry_monotonic_ns":original_entry,
        "original_deadline_monotonic_ns":original_deadline,
        "outer_work_deadline_monotonic_ns":original_deadline-30*10**9,
        "private_cleanup_deadline_monotonic_ns":int(deadline*10**9)+30*10**9}


def main():
    entry = float(time.monotonic())
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("selection", "sha256-file", "mapping", "mapping-sha256-file", "seed", "descriptors",
                 "flake", "lock", "zig-index", "archives", "wrapper", "native", "paths",
                 "registration", "inventory"):
        parser.add_argument("--"+name, required=True)
    args = parser.parse_args()
    marker = os.environ.get("OMUX_EXECUTION_GUARD", "")
    inputs.require(any(re.fullmatch(re.escape(root)+"/"+inputs.UUID, marker)
        for root in inputs.COORDINATORS))
    timeout = os.environ.get("TEST_TIMEOUT", "")
    deadline,reservation = work_envelope(entry,timeout,os.environ)
    with open("/proc/self/status", encoding="ascii") as stream:
        platform = proof.platform(stream.read(65537), os.getuid())
    files = {"selection": (args.selection, inputs.MAX_SELECTION),
        "mapping": (args.mapping, inputs.MAX_MAPPING), "seed": (args.seed, seed.MAX_METADATA),
        "descriptors": (args.descriptors, nar.MAX_METADATA_BYTES),
        "wrapper": (args.wrapper, 65536), "sha256": (args.sha256_file, 65),
        "mapping-sha256": (args.mapping_sha256_file, 65)}
    for name in ("native", "paths", "registration", "inventory"):
        files[name] = (getattr(args, name), seed.MAX_METADATA)
    for filename, attr in zip(schedule.PROJECT_FILES, ("flake", "lock", "zig_index", "archives")):
        files[filename] = (getattr(args, attr), 2*1024**2)
    before = {name: read(file, limit, deadline) for name, (file, limit) in files.items()}
    inputs.require(all(re.fullmatch(rb"[a-f0-9]{64}\n", before[name])
        for name in ("sha256", "mapping-sha256")))
    result = qualify(before["selection"], before["sha256"][:-1].decode("ascii"),
        before["mapping"], before["mapping-sha256"][:-1].decode("ascii"),
        args.mapping, before["seed"], {name: before[name] for name in ("native", "paths", "registration", "inventory")},
        before["descriptors"], args.descriptors,
        {name: before[name] for name in schedule.PROJECT_FILES}, before["wrapper"],
        os.environ["TEST_TMPDIR"], deadline)
    phase("declared-file-readback")
    inputs.require({name: read(file, limit, deadline) for name, (file, limit) in files.items()} == before)
    result.update(platform=platform, guard_epoch=Path(marker).name,
        original_entry_monotonic_ns=int(entry*10**9), original_work_deadline_monotonic_ns=int(deadline*10**9),
        declared_files_rechecked=True, producer_implementation_rechecked=True)
    if reservation is not None:
        result["reserved_execution_envelope"] = reservation
    output = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"])/"native-flake-seed-plan.json"
    raw = inputs.encode(result)
    inputs.require(len(raw) <= proof.MAX_OUTPUT)
    proof.tick(deadline)
    fd = os.open(output, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    proof.tick(deadline)
    print("selected native flake missing plan retained; realization and complete build seed remain unqualified")


if __name__ == "__main__":
    try:
        def interrupted(signum, frame):
            raise KeyboardInterrupt
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, interrupted)
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, ET.ParseError,
            subprocess.SubprocessError, KeyboardInterrupt) as error:
        diagnostic = inputs.metadata_failure(error)
        if diagnostic is not None:
            print("declared metadata refused; role="+diagnostic["role"]+"; reason="+diagnostic["reason"], file=sys.stderr)
        operation = plan.restore_failure(error)
        if PHASE == "fresh-private-missing-plan" and operation is not None:
            print("native flake restore refused; operation="+operation
                +"; reason="+plan.restore_failure_reason(error), file=sys.stderr)
        print("native flake seed plan refused at "+PHASE, file=sys.stderr)
        raise SystemExit(1) from None
