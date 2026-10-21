"""Bounded process-control tests; no paid Claude calls are made."""

from __future__ import annotations

import inspect
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

from cis.errors import (
    ExecutionBudgetExhausted, ExecutionOutputIncomplete, ExecutionTimedOut,
)
from cis.execution.adapters.claude_process import (
    ClaudeProcessController, _run_bounded,
)


class ClaudeProcessControllerTests(unittest.TestCase):
    def workspace(self):
        return tempfile.TemporaryDirectory(prefix="cis-claude-process-")

    def test_command_is_fresh_compact_noninteractive_and_spend_bounded(self):
        command = ClaudeProcessController().command(
            session_id="11111111-1111-4111-8111-111111111111",
            cost_limit_micros=250_000, workspace="/tmp/workspace")
        joined = " ".join(command)
        self.assertIn("--output-format json", joined)
        self.assertIn("--safe-mode", command)
        self.assertIn("--no-session-persistence", command)
        self.assertIn("--max-budget-usd 0.25", joined)
        self.assertNotIn("--verbose", command)
        self.assertNotIn("--include-hook-events", command)
        self.assertNotIn("--continue", command)
        self.assertNotIn("--resume", command)
        self.assertEqual(command[command.index("--disallowedTools") + 1], "Bash")
        self.assertIn("--bind /tmp/workspace /workspace", joined)
        self.assertNotIn("/mnt/projects/cis-clean", joined)
        self.assertEqual(command.count("--strict-mcp-config"), 1)
        self.assertEqual(command.count("--mcp-config"), 1)
        mcp_config = json.loads(
            command[command.index("--mcp-config") + 1])
        self.assertEqual(mcp_config, {"mcpServers": {}})
        self.assertEqual(mcp_config["mcpServers"], {})
        self.assertNotIn(
            "mcp_config",
            inspect.signature(ClaudeProcessController).parameters)

    def test_parses_one_structured_report_and_usage(self):
        envelope = {
            "structured_output": {
                "summary": "done", "changed_files": ["a.py"],
                "checks_run": ["unit"], "blocker": None,
            },
            "usage": {"input_tokens": 10, "output_tokens": 4,
                      "cache_read_input_tokens": 2},
            "total_cost_usd": 0.01,
        }
        def runner(*_args, **_kwargs):
            return 0, json.dumps(envelope).encode(), b"", 30
        with self.workspace() as workspace:
            result = ClaudeProcessController(runner=runner).execute(
                prompt="authorized card", workspace=workspace,
                wall_time_ms=1000, cost_limit_micros=20_000)
        self.assertEqual(result.report["summary"], "done")
        self.assertEqual(result.tokens_used, 16)
        self.assertEqual(result.cost_micros, 10_000)

    def test_malformed_or_empty_report_refuses(self):
        cases = (b"not-json", json.dumps({"result": "prose", "usage": {},
                                          "total_cost_usd": 0}).encode())
        for output in cases:
            with self.subTest(output=output):
                def runner(*_args, **_kwargs):
                    return 0, output, b"", 1
                with self.workspace() as workspace:
                    with self.assertRaises(ExecutionOutputIncomplete):
                        ClaudeProcessController(runner=runner).execute(
                            prompt="authorized", workspace=workspace,
                            wall_time_ms=1000, cost_limit_micros=20_000)

    def test_actual_cost_overrun_refuses_even_if_cli_claimed_to_cap_it(self):
        envelope = {
            "structured_output": {"summary": "done"},
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "total_cost_usd": 0.03,
        }
        def runner(*_args, **_kwargs):
            return 0, json.dumps(envelope).encode(), b"", 1
        with self.workspace() as workspace:
            with self.assertRaises(ExecutionBudgetExhausted):
                ClaudeProcessController(runner=runner).execute(
                    prompt="authorized", workspace=workspace,
                    wall_time_ms=1000, cost_limit_micros=20_000)

    def test_real_process_output_cap_terminates(self):
        argv = [sys.executable, "-c", "print('x' * 200000)"]
        with tempfile.TemporaryDirectory() as workspace:
            with self.assertRaises(ExecutionOutputIncomplete):
                _run_bounded(argv, prompt=b"", cwd=workspace,
                             timeout_seconds=2, output_limit=1024)

    def test_real_process_wall_timeout_terminates(self):
        argv = [sys.executable, "-c", "import time; time.sleep(5)"]
        with tempfile.TemporaryDirectory() as workspace:
            with self.assertRaises(ExecutionTimedOut):
                _run_bounded(argv, prompt=b"", cwd=workspace,
                             timeout_seconds=0.05, output_limit=1024)

    def test_child_that_never_reads_prompt_is_still_wall_bounded(self):
        argv = [sys.executable, "-c", "import time; time.sleep(5)"]
        with tempfile.TemporaryDirectory() as workspace:
            with self.assertRaises(ExecutionTimedOut):
                _run_bounded(argv, prompt=b"x" * (2 * 1024 * 1024),
                             cwd=workspace, timeout_seconds=0.05,
                             output_limit=1024)

    def test_nonblocking_stdin_backpressure_is_retried(self):
        argv = [sys.executable, "-c",
                "import sys; data=sys.stdin.buffer.read(); print(len(data))"]
        real_write = os.write
        calls = 0

        def one_backpressure(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise BlockingIOError()
            return real_write(fd, data)

        with tempfile.TemporaryDirectory() as workspace:
            with mock.patch(
                    "cis.execution.adapters.claude_process.os.write",
                    side_effect=one_backpressure):
                code, stdout, _stderr, _elapsed = _run_bounded(
                    argv, prompt=b"bounded", cwd=workspace,
                    timeout_seconds=2, output_limit=1024)
        self.assertEqual(code, 0)
        self.assertEqual(stdout.strip(), b"7")
        self.assertGreaterEqual(calls, 2)


if __name__ == "__main__":
    unittest.main()
