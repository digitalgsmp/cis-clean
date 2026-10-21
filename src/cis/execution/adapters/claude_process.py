"""Bounded process control for the Claude Code execution adapter.

This module is infrastructure, not authority.  It never chooses a task and it
never admits evidence.  Its one job is to make a previously unbounded external
worker invocation wall-time/output bounded and machine-readable.  Spend is
bounded by Claude CLI's native ``--max-budget-usd`` implementation and then
audited from its result.  This controller does not claim a spend guarantee
independent of that external CLI implementation.

The controller deliberately does not claim token-budget enforcement: the
installed Claude CLI exposes a native spend cap but no token cap.  Callers must
therefore not advertise this controller as satisfying ``token_limit``.
"""

from __future__ import annotations

import json
import os
import selectors
import signal
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...errors import (
    ExecutionBudgetExhausted,
    ExecutionOutputIncomplete,
    ExecutionProviderFailure,
    ExecutionTimedOut,
)


DEFAULT_OUTPUT_LIMIT = 256 * 1024
_REPORT_SCHEMA = json.dumps({
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "summary": {"type": "string"},
        "changed_files": {"type": "array", "items": {"type": "string"}},
        "checks_run": {"type": "array", "items": {"type": "string"}},
        "blocker": {"type": ["string", "null"]},
    },
    "required": ["summary", "changed_files", "checks_run", "blocker"],
}, separators=(",", ":"), sort_keys=True)
_EMPTY_STRICT_MCP_CONFIG = json.dumps(
    {"mcpServers": {}}, separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True)
class ClaudeProcessResult:
    report: Mapping[str, Any]
    exit_code: int
    wall_time_ms: int
    tokens_used: int
    cost_micros: int
    session_id: str
    stdout_bytes: int
    stderr_bytes: int


def _terminate_group(proc: subprocess.Popen, grace_seconds: float = 1.0) -> None:
    """Terminate the whole child group; return only after it has exited."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + grace_seconds
    while proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - OS failure
        raise ExecutionProviderFailure(
            "worker process group did not terminate after SIGKILL") from exc


def _run_bounded(argv: Sequence[str], *, prompt: bytes, cwd: str,
                 timeout_seconds: float,
                 output_limit: int) -> tuple[int, bytes, bytes, int]:
    """Run one child with hard wall-time and combined-output bounds."""
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            list(argv), cwd=cwd, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise ExecutionProviderFailure(
            "Claude worker could not be launched", detail=str(exc)) from exc

    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    os.set_blocking(proc.stdin.fileno(), False)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
    selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
    selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
    chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    prompt_offset = 0
    total = 0
    deadline = started + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_group(proc)
                raise ExecutionTimedOut(
                    "Claude worker exceeded its wall-time budget",
                    wall_time_ms=int(timeout_seconds * 1000))
            events = selector.select(min(remaining, 0.1))
            for key, _ in events:
                if key.data == "stdin":
                    try:
                        written = os.write(key.fd, prompt[prompt_offset:])
                    except BlockingIOError:
                        # Ordinary backpressure on a nonblocking pipe. Keep
                        # draining output and retry when the selector next
                        # reports stdin writable; the same wall deadline still
                        # covers this entire interval.
                        continue
                    except BrokenPipeError:
                        written = 0
                        prompt_offset = len(prompt)
                    else:
                        prompt_offset += written
                    if prompt_offset >= len(prompt):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                chunks[key.data].append(data)
                total += len(data)
                if total > output_limit:
                    _terminate_group(proc)
                    raise ExecutionOutputIncomplete(
                        "Claude worker exceeded the bounded output envelope",
                        output_limit_bytes=output_limit)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_group(proc)
            raise ExecutionTimedOut(
                "Claude worker exceeded its wall-time budget",
                wall_time_ms=int(timeout_seconds * 1000))
        try:
            exit_code = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            _terminate_group(proc)
            raise ExecutionTimedOut(
                "Claude worker exceeded its wall-time budget",
                wall_time_ms=int(timeout_seconds * 1000)) from exc
    finally:
        selector.close()
        if not proc.stdin.closed:
            proc.stdin.close()
        proc.stdout.close()
        proc.stderr.close()
    elapsed_ms = int((time.monotonic() - started) * 1000)
    return exit_code, b"".join(chunks["stdout"]), b"".join(chunks["stderr"]), elapsed_ms


class ClaudeProcessController:
    """Launch one fresh, noninteractive Claude session under declared bounds.

    Wall time and captured output are controlled by this process. Spend relies
    on the CLI's native cap and is independently checked after return; the
    latter is forensic detection, not recovery of money already spent if the
    external CLI failed to honor its own cap.
    """

    def __init__(self, *, claude_bin: str = "claude", model: str = "sonnet",
                 effort: str = "medium", output_limit: int = DEFAULT_OUTPUT_LIMIT,
                 bwrap_bin: str = "/usr/bin/bwrap",
                 credentials_path: str = "/home/eric/.claude/.credentials.json",
                 runner=_run_bounded) -> None:
        self.claude_bin = shutil.which(claude_bin) or claude_bin
        self.model = model
        self.effort = effort
        self.output_limit = int(output_limit)
        self.bwrap_bin = bwrap_bin
        self.credentials_path = credentials_path
        self._runner = runner

    @property
    def execution_identity(self) -> str:
        return f"claude:{self.model}:{self.effort}"

    def liveness(self) -> bool:
        return (Path(self.bwrap_bin).is_file()
                and Path(self.claude_bin).is_file()
                and Path(self.credentials_path).is_file())

    def command(self, *, session_id: str, cost_limit_micros: int,
                workspace: str) -> list[str]:
        dollars = format(Decimal(cost_limit_micros) / Decimal(1_000_000), "f")
        claude = [
            "/claude", "-p", "--model", self.model,
            "--effort", self.effort,
            "--output-format", "json",
            "--json-schema", _REPORT_SCHEMA,
            "--safe-mode", "--strict-mcp-config", "--mcp-config",
            _EMPTY_STRICT_MCP_CONFIG,
            "--no-session-persistence",
            "--session-id", session_id,
            "--permission-mode", "acceptEdits",
            "--allowedTools", "Edit Read Write Glob Grep",
            "--disallowedTools", "Bash",
            "--max-budget-usd", dollars,
        ]
        # The live repository is never mounted.  Claude receives one disposable
        # writable tree, its credential as a single read-only file, and only
        # the OS files required by the static CLI and TLS/DNS.
        return [
            self.bwrap_bin, "--die-with-parent", "--new-session",
            "--unshare-pid", "--unshare-ipc", "--unshare-uts",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/etc/ssl", "/etc/ssl",
            "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf",
            "--ro-bind", "/etc/hosts", "/etc/hosts",
            "--ro-bind", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
            "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
            "--dir", "/home", "--dir", "/home/worker",
            "--dir", "/home/worker/.claude",
            "--ro-bind", self.credentials_path,
            "/home/worker/.claude/.credentials.json",
            "--bind", workspace, "/workspace", "--chdir", "/workspace",
            "--setenv", "HOME", "/home/worker",
            "--setenv", "PATH", "/usr/bin",
            "--ro-bind", self.claude_bin, "/claude",
            *claude,
        ]

    def execute(self, *, prompt: str, workspace: str,
                wall_time_ms: int, cost_limit_micros: int) -> ClaudeProcessResult:
        if not prompt.strip():
            raise ExecutionOutputIncomplete("authorized Claude card is empty")
        root = Path(workspace).resolve()
        if not root.is_dir():
            raise ExecutionProviderFailure(
                "isolated Claude workspace does not exist", workspace=str(root))
        session_id = str(uuid.uuid4())
        argv = self.command(
            session_id=session_id, cost_limit_micros=cost_limit_micros,
            workspace=str(root))
        code, stdout, stderr, elapsed = self._runner(
            argv, prompt=prompt.encode("utf-8"), cwd=str(root),
            timeout_seconds=wall_time_ms / 1000.0,
            output_limit=self.output_limit)
        if code != 0:
            raise ExecutionProviderFailure(
                "Claude worker returned a nonzero exit",
                exit_code=code, stderr=stderr.decode("utf-8", "replace")[:1000])
        try:
            envelope = json.loads(stdout.decode("utf-8", "strict"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ExecutionOutputIncomplete(
                "Claude worker did not return one JSON envelope") from exc
        if not isinstance(envelope, dict):
            raise ExecutionOutputIncomplete(
                "Claude worker JSON envelope is not an object")
        report = envelope.get("structured_output")
        if report is None:
            # Current CLI versions may return the schema-constrained value in
            # result. Accept a mapping directly or a JSON string, never prose.
            report = envelope.get("result")
            if isinstance(report, str):
                try:
                    report = json.loads(report)
                except ValueError as exc:
                    raise ExecutionOutputIncomplete(
                        "Claude worker result is not structured JSON") from exc
        if not isinstance(report, dict) or not str(report.get("summary", "")).strip():
            raise ExecutionOutputIncomplete(
                "Claude worker returned no complete structured report")
        usage = envelope.get("usage") or {}
        if not isinstance(usage, dict):
            raise ExecutionOutputIncomplete("Claude worker usage is malformed")
        token_fields = (
            "input_tokens", "cache_creation_input_tokens",
            "cache_read_input_tokens", "output_tokens",
            "reasoning_output_tokens",
        )
        try:
            tokens = sum(int(usage.get(name) or 0) for name in token_fields)
            cost_micros = int(Decimal(str(envelope["total_cost_usd"])) * 1_000_000)
        except (KeyError, ValueError, TypeError, ArithmeticError) as exc:
            raise ExecutionOutputIncomplete(
                "Claude worker returned no complete usage accounting") from exc
        if cost_micros > cost_limit_micros:
            # Audit a failure of the native CLI cap. This refuses the result,
            # but it cannot undo provider spend already incurred.
            raise ExecutionBudgetExhausted(
                "Claude worker exceeded its authorized spend cap",
                cost_micros=cost_micros, cost_limit_micros=cost_limit_micros)
        return ClaudeProcessResult(
            report=report, exit_code=code, wall_time_ms=elapsed,
            tokens_used=tokens, cost_micros=cost_micros,
            session_id=session_id, stdout_bytes=len(stdout),
            stderr_bytes=len(stderr))
