"""Static history-failure privacy/stage predicates; no native process execution."""
import unittest
import native_history_diagnostic as subject


class HistoryFailureTests(unittest.TestCase):
    def test_each_original_static_predicate_has_its_exact_closed_label(self):
        for message, category in subject.PREDICATES.items():
            self.assertEqual(subject.classify(ValueError(message), "first-native-history-path"), category)
            self.assertIn(category, subject.CATEGORIES)

    def test_original_stages_distinguish_path_and_custody_failures(self):
        errors = (
            (FileNotFoundError("private-secret-like-path"), "file-absent"),
            (PermissionError("private-secret-like-path"), "file-permission"),
            (IsADirectoryError("private-secret-like-path"), "file-kind"),
            (NotADirectoryError("private-secret-like-path"), "file-kind"),
            (OSError("private-secret-like-path"), "file-os"),
            (UnicodeError("private-secret-like-path"), "encoding"),
            (TypeError("private-secret-like-value"), "type"),
            (AttributeError("private-secret-like-value"), "type"),
            (ValueError("private-secret-like-value"), "value"),
            (RuntimeError("private-secret-like-value"), "other"),
        )
        for phase, stage in subject.STAGES.items():
            for error, kind in errors:
                category = subject.classify(error, phase)
                self.assertEqual(category, "history-" + stage + "-" + kind)
                self.assertIn(category, subject.CATEGORIES)
                self.assertNotIn("private", category)

    def test_unknown_phase_and_unknown_arguments_never_become_diagnostics(self):
        for phase in ("private-secret-like-stage", None, {}, 1):
            self.assertEqual(subject.classify(ValueError("private-secret-like-message"), phase),
                             "history-stage-unknown")
        for error in (ValueError(), ValueError("private-secret-like-message", "private-tail"),
                      ValueError({"private-secret-like-key": "private-secret-like-value"})):
            self.assertEqual(subject.classify(error, "second-native-history-custody"),
                             "history-custody-value")

    def test_exception_string_and_argument_string_hooks_are_never_called(self):
        class PrivateValue(ValueError):
            def __str__(self):
                raise AssertionError("private exception rendered")
        class PrivateArgument:
            def __str__(self):
                raise AssertionError("private argument rendered")
        for error in (PrivateValue("private-secret-like-message"), ValueError(PrivateArgument())):
            self.assertEqual(subject.classify(error, "first-native-history-path"), "history-path-value")


if __name__ == "__main__":
    unittest.main()
