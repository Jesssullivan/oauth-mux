"""Bounded pure native checkpoint predicates, not an installed resume proof."""
import copy
import json
import unittest

import native_resumed_checkpoint as checkpoint


THREAD = "synthetic-native-thread"
CWD = "/synthetic-native-work"


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def prefix(last=0, mode="paginated"):
    root = {"timestamp": "fixture", "ordinal": 0, "type": "session_meta",
            "payload": {"history_mode": mode, "id": THREAD, "session_id": THREAD}}
    result = encoded(root)
    if last:
        result += encoded({"timestamp": "fixture", "ordinal": last,
                           "type": "event_msg", "payload": {"type": "fixture_metadata"}})
    return result


def event(number=1):
    return {"timestamp": "fixture", "ordinal": number, "type": "event_msg",
            "payload": {"type": "thread_settings_applied", "thread_id": THREAD,
                        "thread_settings": {
                            "model": "fixture-model", "model_provider_id": "fixture-provider",
                            "approval_policy": "never", "approvals_reviewer": "fixture",
                            "permission_profile": {}, "cwd": CWD,
                            "collaboration_mode": {}, "disabled_plugin_ids": []}}}


class CheckpointTests(unittest.TestCase):
    def validate(self, value, original=None):
        checkpoint.validate_paginated_checkpoint(
            prefix() if original is None else original, encoded(value), THREAD, CWD)

    def test_exact_paginated_checkpoint_and_tail_ordinal(self):
        self.validate(event())
        # The next ordinal comes from the original tail, not prefix line count.
        self.validate(event(8), prefix(last=7))
        self.validate(event(checkpoint.MAX_ORDINAL), prefix(last=checkpoint.MAX_ORDINAL - 1))

    def test_missing_ordinal_refused(self):
        value = event()
        del value["ordinal"]
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_complete_json_without_native_record_terminator_refused(self):
        with self.assertRaises(ValueError):
            checkpoint.validate_paginated_checkpoint(
                prefix(), encoded(event())[:-1], THREAD, CWD)

    def test_boolean_noninteger_negative_and_overflow_ordinals_refused(self):
        for number in (True, False, "1", 1.0, None, -1, checkpoint.MAX_ORDINAL + 1):
            with self.subTest(number=number), self.assertRaises(ValueError):
                self.validate(event(number))

    def test_gap_and_regressed_ordinal_refused(self):
        for number in (0, 6, 7, 9):
            with self.subTest(number=number), self.assertRaises(ValueError):
                self.validate(event(number), prefix(last=7))

    def test_original_tail_requires_integer_u64_and_room_for_next(self):
        for number in (True, "7", -1, checkpoint.MAX_ORDINAL, checkpoint.MAX_ORDINAL + 1):
            original = prefix() + encoded({"ordinal": number, "type": "event_msg", "payload": {}})
            with self.subTest(number=number), self.assertRaises(ValueError):
                self.validate(event(), original)

    def test_rollout_declares_paginated_format_not_sql_or_ui_guess(self):
        for mode in ("legacy", None, "future"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.validate(event(), prefix(mode=mode))

    def test_extra_envelope_field_refused(self):
        value = event()
        value["unexpected"] = True
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_extra_events_refused_even_if_each_is_settings(self):
        with self.assertRaises(ValueError):
            checkpoint.validate_paginated_checkpoint(
                prefix(), encoded(event()) + encoded(event(2)), THREAD, CWD)

    def test_duplicate_ordinal_refused(self):
        payload = encoded(event()).replace(b'"ordinal":1', b'"ordinal":1,"ordinal":1', 1)
        with self.assertRaises(ValueError):
            checkpoint.validate_paginated_checkpoint(prefix(), payload, THREAD, CWD)

    def test_original_thread_event_kind_and_provider_free_policy_preserved(self):
        mutations = (
            ("thread", lambda value: value["payload"].update(thread_id="different-fixture-thread")),
            ("kind", lambda value: value["payload"].update(type="user_message")),
            ("cwd", lambda value: value["payload"]["thread_settings"].update(cwd="/other-fixture-work")),
            ("approval", lambda value: value["payload"]["thread_settings"].update(approval_policy="on-request")),
            ("plugin", lambda value: value["payload"]["thread_settings"].update(disabled_plugin_ids=["fixture"])),
            ("extra-setting", lambda value: value["payload"]["thread_settings"].update(unexpected=True)),
        )
        for label, mutate in mutations:
            value = copy.deepcopy(event())
            mutate(value)
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.validate(value)


if __name__ == "__main__":
    unittest.main()
