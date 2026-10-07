"""Finite history-witness failure labels; never native bytes or exception text."""

STAGES = {
    "first-native-history-path": "path",
    "first-native-history-custody": "custody",
    "second-native-history-path": "path",
    "second-native-history-custody": "custody",
}
PREDICATES = {
    "native persistent history did not materialize": "history-path-unmaterialized",
    "native history left its private owned home": "history-path-custody",
    "native history parent changed custody": "history-parent-symlink",
    "native private file custody changed": "history-file-custody",
    "native private file exceeded its bound": "history-file-bound",
}
KINDS = ("file-absent", "file-permission", "file-kind", "file-os",
         "encoding", "type", "value", "other")
CATEGORIES = (*PREDICATES.values(), "history-stage-unknown",
              *(f"history-{stage}-{kind}" for stage in ("path", "custody") for kind in KINDS))


def classify(error, phase):
    # PHASE is only compared to the shared helper's four literal stages.
    # No unknown stage, repr, str(exception), argument or filename is emitted.
    stage = STAGES.get(phase) if type(phase) is str else None
    if stage is None:
        return "history-stage-unknown"
    if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str:
        predicate = PREDICATES.get(error.args[0])
        if predicate is not None:
            return predicate
    if isinstance(error, FileNotFoundError):
        kind = "file-absent"
    elif isinstance(error, PermissionError):
        kind = "file-permission"
    elif isinstance(error, (IsADirectoryError, NotADirectoryError)):
        kind = "file-kind"
    elif isinstance(error, OSError):
        kind = "file-os"
    elif isinstance(error, UnicodeError):
        kind = "encoding"
    elif isinstance(error, (TypeError, AttributeError)):
        kind = "type"
    elif isinstance(error, ValueError):
        kind = "value"
    else:
        kind = "other"
    return f"history-{stage}-{kind}"
