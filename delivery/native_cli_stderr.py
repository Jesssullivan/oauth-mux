"""Closed stderr categories for bounded private CLI diagnostics, never acceptance.

R-HOOK-CONVERGENCE-20261004 / R-N13. Return literal categories only. Do not
return or persist diagnostic bytes, variable paths, addresses or operation IDs.
Recognizing a marker is not a proved cause; every nonempty stderr still fails.
"""
import json
import re

MAX_BYTES = 1024 * 1024
CATEGORIES = (
    "stderr-empty", "stderr-instance-mismatch",
    "stderr-safe-allocator-leak-prefix", "stderr-zig-error-prefix",
    "stderr-mutation-guidance", "stderr-unrecognized",
    "stderr-colored-safe-allocator-leak-prefix", "stderr-colored-zig-error-prefix",
    "stderr-safe-allocator-leak-after-preamble", "stderr-zig-error-after-preamble",
    "stderr-zig-warning-prefix", "stderr-colored-zig-warning-prefix",
    "stderr-json-other", "stderr-unrecognized-escape-leading",
    "stderr-unrecognized-ascii-leading", "stderr-unrecognized-nonascii-leading",
    "stderr-zig-info-prefix", "stderr-colored-zig-info-prefix",
    "stderr-zig-debug-prefix", "stderr-colored-zig-debug-prefix",
    "stderr-scoped-zig-error-prefix", "stderr-colored-scoped-zig-error-prefix",
    "stderr-scoped-zig-warning-prefix", "stderr-colored-scoped-zig-warning-prefix",
    "stderr-scoped-zig-info-prefix", "stderr-colored-scoped-zig-info-prefix",
    "stderr-scoped-zig-debug-prefix", "stderr-colored-scoped-zig-debug-prefix",
    "stderr-zig-memory-map-fallback-format", "stderr-colored-zig-memory-map-fallback-format",
    "stderr-unrecognized-whitespace-leading",
    "stderr-shell-init-current-directory-format",
    "stderr-shell-working-directory-format",
    "stderr-loader-version-information-format",
    "stderr-loader-symbol-size-format",
)
# Only exact codes emitted by pinned Zig 0.17 log.defaultLogFileTerminal.
COLOR_CODES = (b"\x1b[0m", b"\x1b[1m", b"\x1b[2m", b"\x1b[31m",
               b"\x1b[32m", b"\x1b[33m", b"\x1b[35m")
# std/log.zig uses level.asText() + optional "(scope)" + ": ". Recognize
# only an anchored, bounded ASCII identifier spelling; never return a scope.
SCOPED_PREFIX = re.compile(rb"(error|warning|info|debug)\([A-Za-z_][A-Za-z0-9_]{0,63}\): ")
SCOPED_CATEGORIES = {
    b"error": ("stderr-scoped-zig-error-prefix", "stderr-colored-scoped-zig-error-prefix"),
    b"warning": ("stderr-scoped-zig-warning-prefix", "stderr-colored-scoped-zig-warning-prefix"),
    b"info": ("stderr-scoped-zig-info-prefix", "stderr-colored-scoped-zig-info-prefix"),
    b"debug": ("stderr-scoped-zig-debug-prefix", "stderr-colored-scoped-zig-debug-prefix"),
}
# Pinned Io/Threaded.zig:19033 uses the default scope, not a Threaded scope.
# Exact whole-line format recognition is still not evidence of its call site.
MEMORY_MAP_FALLBACK = re.compile(
    rb"warning: memory mapping failed with [A-Za-z_][A-Za-z0-9_]{0,63}, falling back to file operations\n")


# Read-only catalogue from selected glibc 2.42 ld-linux and this host's /bin/sh
# (Bash). A matched format never proves that binary or a removed cwd caused it.
SHELL_CWD_PREFIXES = (
    (b"shell-init: error retrieving current directory: getcwd: cannot access parent directories: ",
     "stderr-shell-init-current-directory-format"),
    (b"job-working-directory: error retrieving current directory: getcwd: cannot access parent directories: ",
     "stderr-shell-working-directory-format"),
)


def platform_stderr_shape(diagnostics):
    # Examine one complete bounded ASCII line only. Paths, strerror text, symbol
    # names and all following private lines remain local and are never returned.
    line, newline, _ = diagnostics.partition(b"\n")
    if (not newline or len(line) > 3 * 4096 + 128
            or any(byte < 0x20 or byte > 0x7e for byte in line)):
        return None
    for prefix, category in SHELL_CWD_PREFIXES:
        if line.startswith(prefix) and len(line) > len(prefix):
            return category
    def field(value):
        return 0 < len(value) <= 4096 and all(0x20 <= byte <= 0x7e for byte in value)
    head, marker, tail = line.partition(b": no version information available (required by ")
    if marker and tail.endswith(b")"):
        executable, separator, library = head.partition(b": ")
        if separator and field(executable) and field(library) and field(tail[:-1]):
            return "stderr-loader-version-information-format"
    executable, marker, symbol_tail = line.partition(b": Symbol `")
    suffix = b"' has different size in shared object, consider re-linking"
    if marker and symbol_tail.endswith(suffix) and field(executable) and field(symbol_tail[:-len(suffix)]):
        return "stderr-loader-symbol-size-format"
    return None


def classify(diagnostics, params, strict_object):
    if not isinstance(diagnostics, (bytes, bytearray)) or len(diagnostics) > MAX_BYTES:
        return "stderr-unrecognized"
    if not diagnostics:
        return "stderr-empty"
    if diagnostics == b"Omux artifact instance mismatch\n":
        return "stderr-instance-mismatch"
    # Removing a finite color spelling is for recognition only, never for
    # sanitizing/forwarding private bytes or making a failed invocation pass.
    visible = bytes(diagnostics)
    for code in COLOR_CODES:
        visible = visible.replace(code, b"")
    colored = visible != diagnostics
    if MEMORY_MAP_FALLBACK.fullmatch(visible):
        return ("stderr-colored-zig-memory-map-fallback-format" if colored
                else "stderr-zig-memory-map-fallback-format")
    for prefix, plain, decorated in (
            (b"error(SafeAllocator): leaked ", "stderr-safe-allocator-leak-prefix",
             "stderr-colored-safe-allocator-leak-prefix"),
            (b"error: ", "stderr-zig-error-prefix", "stderr-colored-zig-error-prefix"),
            (b"warning: ", "stderr-zig-warning-prefix", "stderr-colored-zig-warning-prefix")):
        if visible.startswith(prefix):
            return decorated if colored else plain
    if b"\nerror(SafeAllocator): leaked " in visible:
        return "stderr-safe-allocator-leak-after-preamble"
    if b"\nerror: " in visible:
        return "stderr-zig-error-after-preamble"
    # Preserve known error-after-preamble recognition before new generic shapes.
    for prefix, plain, decorated in (
            (b"info: ", "stderr-zig-info-prefix", "stderr-colored-zig-info-prefix"),
            (b"debug: ", "stderr-zig-debug-prefix", "stderr-colored-zig-debug-prefix")):
        if visible.startswith(prefix):
            return decorated if colored else plain
    scoped = SCOPED_PREFIX.match(visible)
    if scoped is not None:
        plain, decorated = SCOPED_CATEGORIES[scoped[1]]
        return decorated if colored else plain
    try:
        guidance = json.loads(diagnostics, object_pairs_hook=strict_object)
    except (ValueError, UnicodeDecodeError, RecursionError):
        if diagnostics[0] == 0x1b:
            return "stderr-unrecognized-escape-leading"
        if diagnostics[0] in b" \t\r\n":
            return "stderr-unrecognized-whitespace-leading"
        platform = platform_stderr_shape(diagnostics)
        if platform is not None:
            return platform
        if diagnostics[0] < 0x80:
            return "stderr-unrecognized-ascii-leading"
        return "stderr-unrecognized-nonascii-leading"
    if isinstance(params, dict) and "operation_id" in params and guidance == {
            "operation_id": params["operation_id"], "status": "unresolved",
            "query": {"method": "operation.status", "params": params},
            "message": "Query this operation in the same daemon installation before repeating the action. The CLI does not replay it."}:
        return "stderr-mutation-guidance"
    return "stderr-json-other"
