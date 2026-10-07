"""Strict retained-candidate paginated native resume checkpoint predicate.

R-HOOK-CONVERGENCE-20261004 / R-N13. Reads supplied bounded bytes only.
The rollout's own session_meta.history_mode must declare pagination; SQLite
mode alone and a UI feature flag do not authorize this format. No legacy or
stock capability is inferred. This helper creates no history or authority.
"""
import json

MAX_HISTORY_BYTES = 1024 * 1024
MAX_ORDINAL = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("native JSON contains duplicate keys")
        result[key] = value
    return result


def ordinal(record):
    value = record.get("ordinal") if isinstance(record, dict) else None
    # bool is an int subclass in Python; the native writer emits a u64 number.
    require(type(value) is int and 0 <= value <= MAX_ORDINAL,
            "cold native metadata append envelope changed")
    return value


def validate_paginated_checkpoint(prefix, appended, thread, original_cwd):
    require(type(prefix) is bytes and type(appended) is bytes
            and 0 < len(prefix) <= MAX_HISTORY_BYTES
            and 0 < len(appended) <= MAX_HISTORY_BYTES
            and prefix.endswith(b"\n") and appended.endswith(b"\n"),
            "cold native metadata append envelope changed")
    original = prefix.splitlines()
    root = json.loads(original[0], object_pairs_hook=strict_object)
    require(isinstance(root, dict) and root.get("type") == "session_meta"
            and isinstance(root.get("payload"), dict)
            and root["payload"].get("history_mode") == "paginated",
            "cold native metadata append envelope changed")
    # ordinal_state_for_rollout reads the final valid original record and uses
    # checked_add(1). The caller has already validated every original JSON line;
    # never infer the next ordinal from record count or SQLite history_mode.
    previous = ordinal(json.loads(original[-1], object_pairs_hook=strict_object))
    require(previous < MAX_ORDINAL, "cold native metadata append envelope changed")
    suffix = appended.splitlines()
    require(len(suffix) == 1, "cold native resume appended unexpected history")
    event = json.loads(suffix[0], object_pairs_hook=strict_object)
    require(isinstance(event, dict) and set(event) == {"timestamp", "ordinal", "type", "payload"}
            and event["type"] == "event_msg" and isinstance(event["timestamp"], str)
            and isinstance(event["payload"], dict) and ordinal(event) == previous + 1,
            "cold native metadata append envelope changed")
    body = event["payload"]
    require(set(body) == {"type", "thread_id", "thread_settings"}
            and body["type"] == "thread_settings_applied" and body["thread_id"] == thread
            and isinstance(body["thread_settings"], dict),
            "cold native append was not settings metadata")
    settings = body["thread_settings"]
    required = {"model", "model_provider_id", "approval_policy", "approvals_reviewer", "permission_profile",
                "cwd", "collaboration_mode", "disabled_plugin_ids"}
    optional = {"service_tier", "active_permission_profile", "runtime_workspace_roots", "reasoning_effort",
                "reasoning_summary", "personality"}
    require(required <= set(settings) <= required | optional and settings["cwd"] == original_cwd
            and settings["approval_policy"] == "never" and settings["disabled_plugin_ids"] == [],
            "cold native settings snapshot changed provider-free policy")
