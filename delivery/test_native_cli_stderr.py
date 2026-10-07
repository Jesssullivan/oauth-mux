"""Classification cannot make stderr-free success from a nonempty private stream."""
import json
import unittest
import native_cli_stderr as stderr

PARAMS = {"operation_id": "synthetic-operation"}
PRIVATE = b"private fixture tail that must never be returned"


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


class StderrTests(unittest.TestCase):
    def classify(self, value, params=PARAMS):
        result = stderr.classify(value, params, strict_object)
        self.assertIn(result, stderr.CATEGORIES)
        self.assertNotIn("private fixture", result)
        if value:
            self.assertNotEqual(result, "stderr-empty")
        return result

    def test_empty_is_only_empty(self):
        self.assertEqual(self.classify(b""), "stderr-empty")
        self.assertEqual(self.classify(b"\n"), "stderr-unrecognized-whitespace-leading")

    def test_exact_instance_marker_only(self):
        self.assertEqual(self.classify(b"Omux artifact instance mismatch\n"), "stderr-instance-mismatch")
        self.assertNotEqual(self.classify(b"Omux artifact instance mismatch\n" + PRIVATE),
                            "stderr-instance-mismatch")

    def test_known_plain_allocator_error_and_warning(self):
        for prefix, expected in (
                (b"error(SafeAllocator): leaked ", "stderr-safe-allocator-leak-prefix"),
                (b"error: ", "stderr-zig-error-prefix"),
                (b"warning: ", "stderr-zig-warning-prefix")):
            self.assertEqual(self.classify(prefix + PRIVATE), expected)

    def test_exact_pinned_color_codes(self):
        self.assertEqual(self.classify(
            b"\x1b[31m\x1b[1merror\x1b[0m\x1b[2m\x1b[1m(SafeAllocator): \x1b[0mleaked " + PRIVATE),
            "stderr-colored-safe-allocator-leak-prefix")
        self.assertEqual(self.classify(b"\x1b[31merror: \x1b[0m" + PRIVATE),
                         "stderr-colored-zig-error-prefix")
        self.assertEqual(self.classify(b"\x1b[33mwarning: \x1b[0m" + PRIVATE),
                         "stderr-colored-zig-warning-prefix")

    def test_known_marker_after_unknown_preamble_is_not_cause_proof(self):
        self.assertEqual(self.classify(PRIVATE + b"\nerror(SafeAllocator): leaked " + PRIVATE),
                         "stderr-safe-allocator-leak-after-preamble")
        self.assertEqual(self.classify(PRIVATE + b"\nerror: " + PRIVATE),
                         "stderr-zig-error-after-preamble")
        self.assertNotEqual(self.classify(PRIVATE + b" error(SafeAllocator): leaked "),
                            "stderr-safe-allocator-leak-after-preamble")

    def test_unknown_escape_ascii_and_binary_families_stay_private(self):
        self.assertEqual(self.classify(b"\x1b[999m" + PRIVATE), "stderr-unrecognized-escape-leading")
        self.assertEqual(self.classify(PRIVATE), "stderr-unrecognized-ascii-leading")
        self.assertEqual(self.classify(b"\xff" + PRIVATE), "stderr-unrecognized-nonascii-leading")

    def test_exact_original_operation_guidance_only(self):
        value = {"operation_id": PARAMS["operation_id"], "status": "unresolved",
                 "query": {"method": "operation.status", "params": PARAMS},
                 "message": "Query this operation in the same daemon installation before repeating the action. The CLI does not replay it."}
        payload = json.dumps(value).encode()
        self.assertEqual(self.classify(payload), "stderr-mutation-guidance")
        self.assertEqual(self.classify(payload, {"operation_id": "different-synthetic-operation"}),
                         "stderr-json-other")
        value["unexpected"] = "private fixture"
        self.assertEqual(self.classify(json.dumps(value).encode()), "stderr-json-other")

    def test_duplicate_json_and_oversized_unknown_remain_refusals(self):
        self.assertEqual(self.classify(b'{"kind":1,"kind":2}'), "stderr-unrecognized-ascii-leading")
        self.assertEqual(self.classify(b"x" * (stderr.MAX_BYTES + 1)), "stderr-unrecognized")

    def test_scoped_levels_ignore_private_scope_and_payload(self):
        for prefix, expected in (
                (b"error", "stderr-scoped-zig-error-prefix"),
                (b"warning", "stderr-scoped-zig-warning-prefix"),
                (b"info", "stderr-scoped-zig-info-prefix"),
                (b"debug", "stderr-scoped-zig-debug-prefix")):
            for scope in (b"Threaded", b"SafeAllocator", b"synthetic_private_identifier"):
                with self.subTest(prefix=prefix, scope=scope):
                    self.assertEqual(self.classify(prefix + b"(" + scope + b"): " + PRIVATE), expected)
                    self.assertEqual(self.classify(b"\x1b[1m" + prefix + b"\x1b[0m(" + scope
                                                   + b"): " + PRIVATE),
                                     expected.replace("stderr-", "stderr-colored-", 1))

    def test_scoped_prefix_requires_complete_bounded_known_spelling(self):
        for malformed in (b"err(Threaded): ", b"warn(Threaded): ", b"ERROR(Threaded): ",
                          b"error(): ", b"error(1Threaded): ", b"error(Threaded) ",
                          b"error(Threaded):", b"error(Threaded):\t", b"error(Threaded):\n",
                          b"error(Threaded/path): ", b"error(private scope): ",
                          b"error(\xff): ", b"error(" + b"x" * 65 + b"): ",
                          b"error(Threaded\x1b[999m): "):
            with self.subTest(prefix=malformed):
                self.assertEqual(self.classify(malformed + PRIVATE), "stderr-unrecognized-ascii-leading")
        self.assertEqual(self.classify(PRIVATE + b"\nerror(Threaded): " + PRIVATE),
                         "stderr-unrecognized-ascii-leading")
        self.assertEqual(self.classify(b"\x1b[999merror(Threaded): " + PRIVATE),
                         "stderr-unrecognized-escape-leading")

    def test_unscoped_info_and_debug_are_shapes_only(self):
        self.assertEqual(self.classify(b"info: " + PRIVATE), "stderr-zig-info-prefix")
        self.assertEqual(self.classify(b"debug: " + PRIVATE), "stderr-zig-debug-prefix")
        self.assertEqual(self.classify(b"\x1b[32minfo: \x1b[0m" + PRIVATE),
                         "stderr-colored-zig-info-prefix")
        self.assertEqual(self.classify(b"\x1b[35mdebug: \x1b[0m" + PRIVATE),
                         "stderr-colored-zig-debug-prefix")

    def test_memory_mapping_format_requires_exact_whole_line(self):
        exact = b"warning: memory mapping failed with AccessDenied, falling back to file operations\n"
        self.assertEqual(self.classify(exact), "stderr-zig-memory-map-fallback-format")
        self.assertEqual(self.classify(b"\x1b[33m" + exact + b"\x1b[0m"),
                         "stderr-colored-zig-memory-map-fallback-format")
        for different in (exact[:-1], exact + PRIVATE, exact + b"\n",
                          exact.replace(b"AccessDenied", PRIVATE),
                          exact.replace(b"AccessDenied", b"x" * 65),
                          exact.replace(b"AccessDenied", b"\xff")):
            self.assertEqual(self.classify(different), "stderr-zig-warning-prefix")

    def test_known_errors_after_new_generic_preambles_keep_priority(self):
        for preamble in (b"info(worker): ", b"warning(worker): ", b"error(worker): ",
                         b"debug(worker): ", b"info: ", b"debug: "):
            self.assertEqual(self.classify(preamble + PRIVATE + b"\nerror(SafeAllocator): leaked " + PRIVATE),
                             "stderr-safe-allocator-leak-after-preamble")
            self.assertEqual(self.classify(preamble + PRIVATE + b"\nerror: " + PRIVATE),
                             "stderr-zig-error-after-preamble")
        self.assertEqual(self.classify(b"error: " + PRIVATE + b"\nerror(SafeAllocator): leaked " + PRIVATE),
                         "stderr-zig-error-prefix")

    def test_unknown_whitespace_is_nonempty_and_does_not_trim_to_acceptance(self):
        for prefix in (b" ", b"\t", b"\r", b"\n", b" \t\r\n"):
            self.assertEqual(self.classify(prefix), "stderr-unrecognized-whitespace-leading")
            self.assertEqual(self.classify(prefix + PRIVATE), "stderr-unrecognized-whitespace-leading")
            self.assertEqual(self.classify(prefix + b"error(Threaded): " + PRIVATE),
                             "stderr-unrecognized-whitespace-leading")

    def test_available_shell_cwd_formats_discard_private_details(self):
        for prefix, expected in (
                (b"shell-init: error retrieving current directory: getcwd: cannot access parent directories: ",
                 "stderr-shell-init-current-directory-format"),
                (b"job-working-directory: error retrieving current directory: getcwd: cannot access parent directories: ",
                 "stderr-shell-working-directory-format")):
            self.assertEqual(self.classify(prefix + PRIVATE + b"\n" + PRIVATE), expected)
            for malformed in (prefix + PRIVATE, PRIVATE + b"\n" + prefix + PRIVATE + b"\n",
                              prefix[:-2] + PRIVATE + b"\n", prefix + b"\n"):
                self.assertEqual(self.classify(malformed), "stderr-unrecognized-ascii-leading")

    def test_available_loader_formats_match_complete_bounded_lines(self):
        version = (b"/synthetic/private/omux: /synthetic/private/lib.so: no version information available "
                   b"(required by /synthetic/private/backend)\n")
        symbol = b"/synthetic/private/omux: Symbol `synthetic_private_name' has different size in shared object, consider re-linking\n"
        self.assertEqual(self.classify(version + PRIVATE), "stderr-loader-version-information-format")
        self.assertEqual(self.classify(symbol + PRIVATE), "stderr-loader-symbol-size-format")
        for malformed in (version[:-1], version.replace(b")\n", b")ignored\n"),
                version.replace(b"/synthetic/private/backend", b"x" * 4097),
                version.replace(b"/synthetic/private/lib.so", b""),
                version.replace(b"/synthetic/private/lib.so", b"\x00private"),
                symbol[:-1], symbol.replace(b"re-linking", b"re-linking-ignored"),
                symbol.replace(b"synthetic_private_name", b"x" * 4097),
                symbol.replace(b"synthetic_private_name", b"")):
            self.assertEqual(self.classify(malformed), "stderr-unrecognized-ascii-leading")

    def test_platform_shapes_keep_old_log_priority_and_stream_bound(self):
        prefix = b"shell-init: error retrieving current directory: getcwd: cannot access parent directories: "
        self.assertEqual(self.classify(prefix + PRIVATE + b"\nerror(SafeAllocator): leaked " + PRIVATE),
                         "stderr-safe-allocator-leak-after-preamble")
        self.assertEqual(self.classify(prefix + PRIVATE + b"x" * stderr.MAX_BYTES + b"\n"),
                         "stderr-unrecognized")
        self.assertEqual(self.classify(b" " + prefix + PRIVATE + b"\n"), "stderr-unrecognized-whitespace-leading")
        self.assertEqual(self.classify(b"\x1b[999m" + prefix + PRIVATE + b"\n"), "stderr-unrecognized-escape-leading")

if __name__ == "__main__":
    unittest.main()
