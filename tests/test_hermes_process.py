"""Bounded process-control tests for the Hermes adapter; no model calls."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from cis.errors import (
    ExecutionOutputIncomplete, ExecutionProviderFailure, ExecutionTimedOut,
)
from cis.execution.adapters.hermes_process import (
    HermesProcessController, HermesProcessResult,
)


def _envelope(**overrides):
    base = {
        "summary": "done", "changed_files": ["a.py"],
        "checks_run": ["unit"], "blocker": None,
        "usage": {"tokens_used": 12, "cost_micros": 500},
        "session_id": "sess-1",
    }
    base.update(overrides)
    return base


class HermesProcessControllerTests(unittest.TestCase):
    def workspace(self):
        return tempfile.TemporaryDirectory(prefix="cis-hermes-process-")

    def make_binary(self, content=b"hermes-binary-v1"):
        handle = tempfile.NamedTemporaryFile(
            prefix="cis-hermes-bin-", delete=False)
        handle.write(content)
        handle.close()
        os.chmod(handle.name, 0o755)
        return handle.name

    def test_safe_flags_and_isolated_home_override_hostile_parent_env(self):
        captured = {}

        def runner(argv, *, prompt, cwd, env, timeout_seconds, output_limit):
            captured["env"] = env
            captured["argv"] = argv
            return 0, json.dumps(_envelope()).encode(), b"", 10

        hostile_env = {
            "HOME": "/root", "PATH": "/evil/bin",
            "HERMES_SAFE_MODE": "0", "HERMES_IGNORE_USER_CONFIG": "0",
            "HERMES_IGNORE_RULES": "0",
            "ANTHROPIC_API_KEY": "sk-should-never-be-forwarded",
            "OPENROUTER_API_KEY": "or-should-never-be-forwarded",
        }
        binary = self.make_binary()
        try:
            with mock.patch.dict(os.environ, hostile_env, clear=True):
                controller = HermesProcessController(
                    hermes_bin=binary, provider="anthropic", model="sonnet",
                    runner=runner)
                with self.workspace() as workspace:
                    controller.execute(
                        prompt="authorized card", workspace=workspace,
                        wall_time_ms=1000, cost_limit_micros=20_000)
        finally:
            os.unlink(binary)

        env = captured["env"]
        self.assertEqual(env["HERMES_SAFE_MODE"], "1")
        self.assertEqual(env["HERMES_IGNORE_USER_CONFIG"], "1")
        self.assertEqual(env["HERMES_IGNORE_RULES"], "1")
        self.assertNotEqual(env["HOME"], "/root")
        self.assertNotIn("/evil/bin", env["PATH"])
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertNotIn("OPENROUTER_API_KEY", env)
        self.assertIn("--safe-mode", captured["argv"])
        self.assertEqual(
            captured["argv"][captured["argv"].index("--toolsets") + 1],
            "file,terminal")

    def test_liveness_is_side_effect_free_and_never_calls_provider(self):
        binary = self.make_binary()
        calls = []

        def runner(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("liveness must never invoke the runner")

        try:
            controller = HermesProcessController(
                hermes_bin=binary, provider="anthropic", model="sonnet",
                runner=runner)
            self.assertTrue(controller.liveness())
        finally:
            os.unlink(binary)
        self.assertEqual(calls, [])

    def test_liveness_false_for_missing_binary(self):
        controller = HermesProcessController(
            hermes_bin="/no/such/hermes-binary", provider="anthropic",
            model="sonnet", runner=lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("unused")))
        self.assertFalse(controller.liveness())

    def test_valid_report_is_parsed(self):
        def runner(*_args, **_kwargs):
            return 0, json.dumps(_envelope()).encode(), b"", 15

        binary = self.make_binary()
        try:
            controller = HermesProcessController(
                hermes_bin=binary, provider="anthropic", model="sonnet",
                runner=runner)
            with self.workspace() as workspace:
                result = controller.execute(
                    prompt="authorized card", workspace=workspace,
                    wall_time_ms=1000, cost_limit_micros=20_000)
        finally:
            os.unlink(binary)
        self.assertIsInstance(result, HermesProcessResult)
        self.assertEqual(result.report["summary"], "done")
        self.assertEqual(result.tokens_used, 12)
        self.assertEqual(result.cost_micros, 500)
        self.assertEqual(result.session_id, "sess-1")

    def test_nonzero_exit_is_refused(self):
        def runner(*_args, **_kwargs):
            return 1, b"", b"boom", 5

        binary = self.make_binary()
        try:
            controller = HermesProcessController(
                hermes_bin=binary, provider="anthropic", model="sonnet",
                runner=runner)
            with self.workspace() as workspace:
                with self.assertRaises(ExecutionProviderFailure):
                    controller.execute(
                        prompt="authorized", workspace=workspace,
                        wall_time_ms=1000, cost_limit_micros=20_000)
        finally:
            os.unlink(binary)

    def test_exit_zero_empty_stdout_is_refused(self):
        def runner(*_args, **_kwargs):
            return 0, b"   \n", b"", 5

        binary = self.make_binary()
        try:
            controller = HermesProcessController(
                hermes_bin=binary, provider="anthropic", model="sonnet",
                runner=runner)
            with self.workspace() as workspace:
                with self.assertRaises(ExecutionOutputIncomplete):
                    controller.execute(
                        prompt="authorized", workspace=workspace,
                        wall_time_ms=1000, cost_limit_micros=20_000)
        finally:
            os.unlink(binary)

    def test_malformed_report_or_usage_is_refused(self):
        cases = (
            b"not-json",
            json.dumps(_envelope(extra_key="nope")).encode(),
            json.dumps(_envelope(usage={"tokens_used": -1, "cost_micros": 0})).encode(),
            json.dumps(_envelope(usage={"tokens_used": 1, "cost_micros": -1})).encode(),
            json.dumps(_envelope(session_id="  ")).encode(),
            json.dumps(_envelope(summary="")).encode(),
        )
        binary = self.make_binary()
        try:
            for output in cases:
                def runner(*_args, _output=output, **_kwargs):
                    return 0, _output, b"", 1
                with self.subTest(output=output):
                    controller = HermesProcessController(
                        hermes_bin=binary, provider="anthropic",
                        model="sonnet", runner=runner)
                    with self.workspace() as workspace:
                        with self.assertRaises(ExecutionOutputIncomplete):
                            controller.execute(
                                prompt="authorized", workspace=workspace,
                                wall_time_ms=1000, cost_limit_micros=20_000)
        finally:
            os.unlink(binary)

    def test_timeout_and_output_cap_failures_are_propagated(self):
        def timeout_runner(*_args, **_kwargs):
            raise ExecutionTimedOut("exceeded wall time", wall_time_ms=1000)

        def overflow_runner(*_args, **_kwargs):
            raise ExecutionOutputIncomplete(
                "exceeded output envelope", output_limit_bytes=1024)

        binary = self.make_binary()
        try:
            with self.workspace() as workspace:
                controller = HermesProcessController(
                    hermes_bin=binary, provider="anthropic", model="sonnet",
                    runner=timeout_runner)
                with self.assertRaises(ExecutionTimedOut):
                    controller.execute(
                        prompt="authorized", workspace=workspace,
                        wall_time_ms=50, cost_limit_micros=20_000)

                controller = HermesProcessController(
                    hermes_bin=binary, provider="anthropic", model="sonnet",
                    runner=overflow_runner)
                with self.assertRaises(ExecutionOutputIncomplete):
                    controller.execute(
                        prompt="authorized", workspace=workspace,
                        wall_time_ms=1000, cost_limit_micros=20_000)
        finally:
            os.unlink(binary)

    def test_simulated_auth_lock_failure_is_classified_not_suppressed(self):
        def runner(*_args, **_kwargs):
            return 1, b"", b"auth lock: read-only filesystem; cannot refresh token", 3

        binary = self.make_binary()
        try:
            controller = HermesProcessController(
                hermes_bin=binary, provider="anthropic", model="sonnet",
                runner=runner)
            with self.workspace() as workspace:
                with self.assertRaises(ExecutionProviderFailure) as ctx:
                    controller.execute(
                        prompt="authorized", workspace=workspace,
                        wall_time_ms=1000, cost_limit_micros=20_000)
        finally:
            os.unlink(binary)
        self.assertIn("auth lock", ctx.exception.detail["stderr"])

    def test_execution_identity_changes_with_binary_bytes_provider_and_model(self):
        binary_a = self.make_binary(b"binary-version-a")
        binary_b = self.make_binary(b"binary-version-b")
        try:
            base = HermesProcessController(
                hermes_bin=binary_a, provider="anthropic", model="sonnet",
                runner=lambda *a, **k: None)
            different_bytes = HermesProcessController(
                hermes_bin=binary_b, provider="anthropic", model="sonnet",
                runner=lambda *a, **k: None)
            different_provider = HermesProcessController(
                hermes_bin=binary_a, provider="openrouter", model="sonnet",
                runner=lambda *a, **k: None)
            different_model = HermesProcessController(
                hermes_bin=binary_a, provider="anthropic", model="opus",
                runner=lambda *a, **k: None)

            identities = {
                base.execution_identity,
                different_bytes.execution_identity,
                different_provider.execution_identity,
                different_model.execution_identity,
            }
            self.assertEqual(len(identities), 4)
        finally:
            os.unlink(binary_a)
            os.unlink(binary_b)


if __name__ == "__main__":
    unittest.main()
