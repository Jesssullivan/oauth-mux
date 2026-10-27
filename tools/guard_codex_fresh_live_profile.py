"""One qualified fresh runtime variant of the existing exact live proof."""
import re
from pathlib import Path
import guard_codex_live_profile as live

VARIABLE = "OMUX_CODEX_FRESH_RUNTIME_SELECTION"
SHA_VARIABLE = VARIABLE + "_SHA256"
BYTES_VARIABLE = VARIABLE + "_BYTES"
DEFINE = "--define=omux_codex_live_runtime=fresh"
MAX_SELECTION = 16*1024*1024
OPERATOR_ROOTS = (Path("/home/jess/.local/state/omux-execution-20261005"),
    Path("/srv/fast-local/jess/state/codex/omux-native-candidate-20261007"))

def finite(profile,arguments,retained,selection,sha256,size):
    values = (selection,sha256,size)
    if all(value is None for value in values):
        return False
    if (profile != "codex-live" or arguments != ["test",live.LABEL] or retained is not None
            or selection is None or type(sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}",sha256)
            or type(size) is not int or not 0 < size <= MAX_SELECTION):
        raise ValueError("fresh-live-exclusive-qualified-selection")
    text = str(selection)
    live.binding_selector(text)
    if (not text.startswith("/") or any(part in ("",".","..") for part in text.split("/")[1:])
            or Path(text).parent not in OPERATOR_ROOTS or Path(text).name != "fresh-runtime-selection.json"):
        raise ValueError("fresh-live-public-selection-namespace")
    return True

def readonly_bindings(admission,live_binding):
    return [live_binding,live.binding_selector(str(admission.root.parent))+":"+
        live.binding_selector(str(admission.root.parent)),
        live.binding_selector(str(admission.selection_path))+":"+
        live.binding_selector(str(admission.selection_path))]

def verify_readonly(actual,expected):
    values = []
    for value in actual.get("BindReadOnlyPaths","").split():
        parts = value.split(":")
        if len(parts) == 3 and parts[2] == "rbind":
            parts.pop()
        if len(parts) != 2:
            raise ValueError("fresh-live-readonly-bind-refused")
        values.append(":".join(parts))
    if len(values) != len(expected) or set(values) != set(expected) or actual.get("BindPaths","").strip():
        raise ValueError("fresh-live-readonly-bind-refused")

def binding_facts(actual,expected):
    try:
        verify_readonly(actual,expected)
        matched = True
    except ValueError:
        matched = False
    return {"expected_entries":len(expected),"actual_entries":min(len(actual.get("BindReadOnlyPaths","").split()),4),
        "runtime_package_and_selector_readonly":matched,
        "writable_bind_present":bool(actual.get("BindPaths","").strip())}
