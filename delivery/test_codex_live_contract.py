"""Provider-free predicates only; never invokes a daemon, native process or provider."""
import copy
import json
import unittest
from unittest import mock
from pathlib import Path

import test_installed_codex_live_continuity as fixture

def receipt():
    return {
        "schema_version": 1,
        "scope": "operator_drain_same_process_completed_turn_substitution",
        "transition_reason": "operator_drain", "application": "omux-maintained-codex",
        "application_version": "0.157.0", "model": "fixture-model", "provider_usage_records": 2,
        "native_context_mode": "text_transcript_v1", "reasoning_summary": "none", "reasoning_effort": "low",
        "minimum_reasoning_effort_verified": True, "native_detach_proven": False,
        "integration_restoration_proven": False,
        "upstream_commit": "a" * 40, "candidate_patch_sha256": "b" * 64,
        "runtime_archive_sha256": "c" * 64, "accounts": ["account_a", "account_b"],
        "submitted_turns": 2, "accepted_completed_turns": 2, "tool_calls": 0,
        "same_process": True, "same_native_owner": True, "same_native_thread": True,
        "native_store_identity_preserved": True, "accepted_history_prefix_preserved": True,
        "accepted_work_repeated": False, "empty_native_resume_checkpoint_proven": True,
        "accepted_history_cold_resume_proven": False, "provider_rejection_handoff_proven": False,
        "concurrent_handoff_proven": False, "full_native_account_lifecycle_proven": False,
    }

def history(events):
    return ((), (), b"", b"".join(json.dumps(item).encode() + b"\n" for item in events))

def completed_events():
    return [
        {"type": "response_item", "payload": {"type": "message", "role": "user",
                                             "content": [{"type": "input_text", "text": "fixture prompt"}]}},
        {"type": "response_item", "payload": {"type": "message", "role": "assistant",
                                             "content": [{"type": "output_text", "text": "OMUX_A_DONE"}]}},
        {"type": "token_usage_record", "payload": {}},
        {"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "OMUX_A_DONE"}},
    ]

class LiveContractTest(unittest.TestCase):
    def setUp(self):
        self.scenario = fixture.LiveScenario({"model": "fixture-model", "authorized_source_paths": []})
        self.previous = history([])

    def complete(self, events):
        return self.scenario.completed_text(history(events), self.previous, "OMUX_A_DONE")

    def terminal_constructor(self, *, cli_overrides=None, resume=None):
        launch = mock.Mock(return_value=mock.Mock(pid=123))
        observer = mock.Mock()
        profile = {} if cli_overrides is None else {"cli_overrides": cli_overrides}
        with mock.patch.object(fixture.tui.pty, "openpty", return_value=(101, 102)), \
             mock.patch.object(fixture.tui.fcntl, "ioctl"), \
             mock.patch.object(fixture.tui.os, "set_blocking"), \
             mock.patch.object(fixture.tui.os, "close"), \
             mock.patch.object(fixture.tui.selectors, "DefaultSelector"):
            terminal = fixture.tui.TerminalProcess(
                Path("/fixture/candidate"), {"TERM": "fixture"}, Path("/fixture/work"),
                resume=resume, popen_factory=launch,
                failure_observer=observer, **profile)
        self.assertIs(terminal.failure_observer, observer)
        self.assertIs(terminal.process, launch.return_value)
        return launch.call_args

    def test_actual_constructor_preserves_default_and_optional_hooks(self):
        called = self.terminal_constructor()
        command = called.args[0]
        self.assertIn("--pty-exec", command)
        self.assertNotIn("--cli-overrides", command)
        self.assertTrue(called.kwargs["start_new_session"])
        self.assertEqual(0o077, called.kwargs["umask"])

    def test_actual_constructor_carries_only_explicit_selected_profile(self):
        selected = ('omux_broker.context_mode="text_transcript_v1"',
                    'model_reasoning_summary="none"', 'model_reasoning_effort="low"')
        resume = "11111111-1111-1111-1111-111111111111"
        called = self.terminal_constructor(cli_overrides=selected, resume=resume)
        command = called.args[0]
        self.assertEqual(resume, command[-3])
        self.assertEqual("--cli-overrides", command[-2])
        self.assertEqual(list(selected), json.loads(command[-1]))

    def test_actual_pty_exec_rejects_widened_profile_before_native_exec(self):
        selected = ['omux_broker.context_mode="text_transcript_v1"',
                    'model_reasoning_summary="auto"', 'model_reasoning_effort="low"']
        arguments = ["fixture.py", "--pty-exec", "/fixture/candidate", "/fixture/work", "123",
                     "--cli-overrides", json.dumps(selected)]
        libc = mock.Mock()
        libc.prctl.return_value = 0
        with mock.patch.object(fixture.tui.sys, "argv", arguments), \
             mock.patch.object(Path, "resolve", lambda self, **kwargs: self), \
             mock.patch.object(fixture.tui.os, "getppid", return_value=123), \
             mock.patch.object(fixture.tui.os, "chdir"), \
             mock.patch.object(fixture.tui.os, "execve") as native_exec, \
             mock.patch.object(fixture.tui.ctypes, "CDLL", return_value=libc), \
             mock.patch.object(fixture.tui.fcntl, "ioctl"):
            with self.assertRaises(ValueError):
                fixture.tui.main()
            native_exec.assert_not_called()

    def test_narrow_receipt_accepts_closed_predicates(self):
        fixture.validate_receipt(receipt())

    def test_receipt_rejects_broader_claims(self):
        for field in ("accepted_history_cold_resume_proven", "provider_rejection_handoff_proven",
                      "concurrent_handoff_proven", "full_native_account_lifecycle_proven",
                      "native_detach_proven", "integration_restoration_proven"):
            value = receipt()
            value[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                fixture.validate_receipt(value)

    def test_receipt_rejects_extra_private_fields_and_raw_identifiers(self):
        for key in ("access_token", "account_id", "thread_id", "source_path", "diagnostics"):
            value = receipt()
            value[key] = "fixture-private-field"
            with self.subTest(field=key), self.assertRaises(ValueError):
                fixture.validate_receipt(value)

    def test_receipt_rejects_replay_tools_and_integer_booleans(self):
        for key, replacement in (("tool_calls", 1), ("accepted_work_repeated", True),
                                 ("same_process", 1), ("submitted_turns", 3)):
            value = receipt()
            value[key] = replacement
            with self.subTest(field=key), self.assertRaises(ValueError):
                fixture.validate_receipt(value)

    def test_supported_minimum_effort_is_catalog_bound(self):
        catalog = {"models": [{"slug": "fixture-model", "input_modalities": ["text"],
                              "supported_reasoning_levels": [{"effort": "medium"}, {"effort": "low"}]}]}
        self.assertEqual("low", fixture.minimum_reasoning_effort(catalog, "fixture-model"))
        with self.assertRaises(ValueError):
            fixture.minimum_reasoning_effort(catalog, "fixture-missing")
        catalog["models"][0]["supported_reasoning_levels"] = []
        with self.assertRaises(ValueError):
            fixture.minimum_reasoning_effort(catalog, "fixture-model")

    def test_readable_reasoning_is_outside_text_policy(self):
        for body in ({"type": "reasoning", "summary": [{"type": "summary_text", "text": "fixture"}]},
                     {"type": "reasoning", "summary": [], "content": [{"type": "reasoning_text", "text": "fixture"}]}):
            events = completed_events()
            events.insert(1, {"type": "response_item", "payload": body})
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.complete(events)
        events = completed_events()
        events.insert(1, {"type": "response_item", "payload": {"type": "reasoning", "summary": [], "content": None}})
        self.assertTrue(self.complete(events))

    def test_completed_text_requires_actual_completion_and_usage_record(self):
        self.assertTrue(self.complete(completed_events()))
        self.assertFalse(self.complete(completed_events()[:-1]))
        self.assertFalse(self.complete([item for item in completed_events()
                                        if item["type"] != "token_usage_record"]))

    def test_task_complete_error_cannot_prove_success(self):
        events = completed_events()
        events[-1]["payload"]["error"] = {"message": "fixture failure"}
        self.assertFalse(self.complete(events))

    def test_tool_record_and_nontext_input_fail_closed(self):
        for payload in ({"type": "function_call"}, {"type": "message", "role": "user",
                       "content": [{"type": "input_image", "image_url": "fixture"}]}):
            events = completed_events()
            events.insert(1, {"type": "response_item", "payload": payload})
            with self.subTest(kind=payload["type"]), self.assertRaises(ValueError):
                self.complete(events)

    def test_repeated_accepted_text_and_wrong_final_text_are_not_completion(self):
        events = completed_events()
        events.insert(1, copy.deepcopy(events[1]))
        self.assertFalse(self.complete(events))
        events = completed_events()
        events[1]["payload"]["content"][0]["text"] = "fixture unexpected output"
        self.assertFalse(self.complete(events))

if __name__ == "__main__":
    unittest.main()
