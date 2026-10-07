"""Pure declarative update proposals and readback predicates (TIN-5443).

The caller must obtain authenticated runtime observations and independently
verified artifact facts. This module performs no IO, activation or migration.
Neither a proposal nor a synthetic fixture grants deployment authorization.
"""
import re

CHANNELS = {"development": "dev", "release": "default"}
MAX_FENCE_SECONDS = 30


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def integer(value):
    return type(value) is int and 0 <= value <= (1 << 63) - 1


def refused(reason):
    return {"schema_version": 1, "decision": "refused", "reason": reason,
            "activation_authorized": False}


def artifact(record):
    value = record["artifact"]
    channel = value["channel"]
    if (record.get("schemaVersion") != 1 or record.get("owner") != "home-manager"
            or record.get("payload_verified") is not True or channel not in CHANNELS
            or not digest(value["manifestSha256"]) or not isinstance(value.get("target"), str)):
        raise ValueError("artifact")
    return value


def runtime_valid(runtime):
    return (runtime.get("authenticated") is True and runtime.get("schema_version") == 1
            and runtime.get("custody_available") is True
            and all(integer(runtime.get(name)) for name in
                    ("protocol_version", "storage_schema", "snapshot_schema", "custody_format", "revision", "checkpoint_sequence"))
            and digest(runtime.get("preservation_commitment")))


def plan_update(current, target, runtime, now):
    """Return a review proposal only; unknown schema or absent fence refuses.

    'payload_verified' and 'authenticated' describe the caller's actual
    collector/control observations; they are never inferred from a store path.
    The first slice requires no schema migration and zero accepted active work.
    """
    try:
        previous, proposed = artifact(current), artifact(target)
        if previous["channel"] != proposed["channel"] or previous["target"] != proposed["target"]:
            return refused("artifact_context_mismatch")
        if not runtime_valid(runtime):
            return refused("runtime_readback_unavailable")
        channel = proposed["channel"]
        if (runtime.get("channel") != channel or runtime.get("instance") != CHANNELS[channel]
                or runtime.get("artifact_digest") != previous["manifestSha256"]):
            return refused("runtime_context_mismatch")
        compatibility = proposed.get("compatibility")
        if not isinstance(compatibility, dict) or compatibility.get("schema_version") != 1:
            return refused("compatibility_unknown")
        for runtime_name, readable, writable in (
                ("storage_schema", "storage_read", "storage_write"),
                ("snapshot_schema", "snapshot_read", "snapshot_write")):
            # This slice refuses both automatic upgrade migrations and schema
            # downgrade. A previous package is assessed against CURRENT state.
            if (runtime[runtime_name] not in compatibility.get(readable, [])
                    or compatibility.get(writable) != runtime[runtime_name]):
                return refused("schema_incompatible")
        if (runtime["protocol_version"] not in compatibility.get("protocol_read", [])
                or runtime["custody_format"] not in compatibility.get("custody_formats", [])):
            return refused("protocol_or_custody_incompatible")
        required = runtime.get("required_features")
        preserved = compatibility.get("preserves_features")
        valid_features = lambda values: isinstance(values, list) and 0 < len(values) <= 32 and all(
            isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_.-]{0,47}", value) for value in values)
        if not valid_features(required) or not valid_features(preserved) or not set(required) <= set(preserved):
            return refused("preservation_capability_missing")
        fence = runtime.get("update_fence")
        if not isinstance(fence, dict) or not digest(fence.get("id")):
            return refused("update_fence_unavailable")
        if (not integer(now) or not integer(fence.get("expires_at"))
                or not 0 < fence["expires_at"] - now <= MAX_FENCE_SECONDS):
            return refused("update_fence_expired_or_unbounded")
        if (fence.get("quiescent") is not True or fence.get("revision") != runtime["revision"]
                or runtime.get("active_work") != 0 or type(runtime.get("active_work")) is not int):
            return refused("custody_not_quiescent")
        return {
            "schema_version": 1, "decision": "proposal", "activation_authorized": False,
            "channel": channel, "instance": CHANNELS[channel], "platform": proposed["target"],
            "previous_artifact": previous["manifestSha256"], "target_artifact": proposed["manifestSha256"],
            "runtime_schema": {name: runtime[name] for name in
                               ("protocol_version", "storage_schema", "snapshot_schema", "custody_format")},
            "required_features": sorted(set(required)),
            "fence_id": fence["id"], "expires_at": fence["expires_at"],
            "before": {name: runtime[name] for name in
                       ("revision", "checkpoint_sequence", "preservation_commitment")},
            "scope": "deployment-only-no-custody-restore",
        }
    except (AttributeError, KeyError, TypeError, ValueError):
        return refused("verified_update_inputs_unavailable")


def check_readback(proposal, runtime, now):
    """Check preservation after an independently authorized generation switch.

    The opaque commitment covers credential-generation, tombstone, renewal and
    replay/accepted-work authority. No account identifiers or secret hashes are
    included. This is a readback predicate, not proof of an activation operation.
    """
    try:
        if proposal.get("decision") != "proposal" or not runtime_valid(runtime):
            return refused("readback_unavailable")
        if not integer(now) or now >= proposal["expires_at"]:
            return refused("update_fence_expired_or_unbounded")
        if (runtime.get("channel") != proposal["channel"] or runtime.get("instance") != proposal["instance"]
                or runtime.get("artifact_digest") != proposal["target_artifact"]
                or any(runtime.get(name) != value for name, value in proposal["runtime_schema"].items())):
            return refused("readback_context_mismatch")
        fence = runtime.get("update_fence", {})
        if (fence.get("id") != proposal["fence_id"] or fence.get("expires_at") != proposal["expires_at"]
                or fence.get("revision") != proposal["before"]["revision"]
                or fence.get("quiescent") is not True or runtime.get("active_work") != 0
                or type(runtime.get("active_work")) is not int
                or not isinstance(runtime.get("required_features"), list)
                or not set(proposal["required_features"]) <= set(runtime["required_features"])):
            return refused("readback_fence_mismatch")
        before = proposal["before"]
        if (runtime["revision"] < before["revision"] or runtime["checkpoint_sequence"] < before["checkpoint_sequence"]
                or runtime["preservation_commitment"] != before["preservation_commitment"]):
            return refused("custody_preservation_failed")
        return {"schema_version": 1, "decision": "readback_predicates_passed", "activation_authorized": False,
                "channel": proposal["channel"], "instance": proposal["instance"],
                "previous_artifact": proposal["previous_artifact"], "target_artifact": proposal["target_artifact"],
                "before": before, "after": {name: runtime[name] for name in before},
                "scope": "deployment-only-no-custody-restore"}
    except (AttributeError, KeyError, TypeError, ValueError):
        return refused("readback_unavailable")
