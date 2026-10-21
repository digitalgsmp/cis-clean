"""Bounded process control for a CIS-owned Hermes execution adapter.

This module is infrastructure, not authority. It never chooses a task and it
never admits evidence. Its one job is to make CIS correctness independent of
Hermes' own safe-mode startup behavior: the child process is launched with an
explicit, closed-allowlist environment (never a copy of the parent's), its
final output is parsed under a closed schema, and any failure to start, run
within bounds, or return a well-formed report is surfaced as a typed CIS
error rather than silently treated as "no edits occurred".

Whether authorized edits occurred in the workspace is not this controller's
decision: it returns the parsed report and leaves classification of candidate
artifacts to the common candidate adapter. This controller never inspects or
mutates the live repository.
"""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...errors import (
    ExecutionOutputIncomplete,
    ExecutionProviderFailure,
    ExecutionTimedOut,
)


DEFAULT_OUTPUT_LIMIT = 256 * 1024
SANDBOX_PROFILE = "hermes-oneshot-v1"

_REPORT_KEYS = frozenset({"summary", "changed_files", "checks_run", "blocker"})
_ENVELOPE_KEYS = _REPORT_KEYS | {"usage", "session_id"}
_USAGE_KEYS = frozenset({"tokens_used", "cost_micros"})


@dataclass(frozen=True)
class HermesProcessResult:
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
            "Hermes worker process group did not terminate after SIGKILL") from exc


def _run_bounded(argv: Sequence[str], *, prompt: bytes, cwd: str,
                  env: Mapping[str, str], timeout_seconds: float,
                  output_limit: int) -> tuple[int, bytes, bytes, int]:
    """Run one child with hard wall-time and combined-output bounds."""
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            list(argv), cwd=cwd, env=dict(env), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise ExecutionProviderFailure(
            "Hermes worker could not be launched", detail=str(exc)) from exc

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
                    "Hermes worker exceeded its wall-time budget",
                    wall_time_ms=int(timeout_seconds * 1000))
            events = selector.select(min(remaining, 0.1))
            for key, _ in events:
                if key.data == "stdin":
                    try:
                        written = os.write(key.fd, prompt[prompt_offset:])
                    except BlockingIOError:
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
                        "Hermes worker exceeded the bounded output envelope",
                        output_limit_bytes=output_limit)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_group(proc)
            raise ExecutionTimedOut(
                "Hermes worker exceeded its wall-time budget",
                wall_time_ms=int(timeout_seconds * 1000))
        try:
            exit_code = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            _terminate_group(proc)
            raise ExecutionTimedOut(
                "Hermes worker exceeded its wall-time budget",
                wall_time_ms=int(timeout_seconds * 1000)) from exc
    finally:
        selector.close()
        if not proc.stdin.closed:
            proc.stdin.close()
        proc.stdout.close()
        proc.stderr.close()
    elapsed_ms = int((time.monotonic() - started) * 1000)
    return exit_code, b"".join(chunks["stdout"]), b"".join(chunks["stderr"]), elapsed_ms


def _validate_envelope(raw: bytes) -> tuple[Mapping[str, Any], int, int, str]:
    text = raw.decode("utf-8", "strict").strip()
    if not text:
        raise ExecutionOutputIncomplete("Hermes worker returned no output")
    try:
        envelope = json.loads(text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ExecutionOutputIncomplete(
            "Hermes worker did not return one JSON envelope") from exc
    if not isinstance(envelope, dict) or set(envelope.keys()) != _ENVELOPE_KEYS:
        raise ExecutionOutputIncomplete(
            "Hermes worker envelope has unexpected or missing keys")

    summary = envelope["summary"]
    changed_files = envelope["changed_files"]
    checks_run = envelope["checks_run"]
    blocker = envelope["blocker"]
    if not isinstance(summary, str) or not summary.strip():
        raise ExecutionOutputIncomplete("Hermes worker report has no summary")
    if not isinstance(changed_files, list) or not all(
            isinstance(item, str) for item in changed_files):
        raise ExecutionOutputIncomplete("Hermes worker changed_files is malformed")
    if not isinstance(checks_run, list) or not all(
            isinstance(item, str) for item in checks_run):
        raise ExecutionOutputIncomplete("Hermes worker checks_run is malformed")
    if blocker is not None and not isinstance(blocker, str):
        raise ExecutionOutputIncomplete("Hermes worker blocker is malformed")

    usage = envelope["usage"]
    if not isinstance(usage, dict) or set(usage.keys()) != _USAGE_KEYS:
        raise ExecutionOutputIncomplete("Hermes worker usage is malformed")
    tokens_used = usage["tokens_used"]
    cost_micros = usage["cost_micros"]
    if (not isinstance(tokens_used, int) or isinstance(tokens_used, bool)
            or tokens_used < 0):
        raise ExecutionOutputIncomplete("Hermes worker returned invalid tokens_used")
    if (not isinstance(cost_micros, int) or isinstance(cost_micros, bool)
            or cost_micros < 0):
        raise ExecutionOutputIncomplete("Hermes worker returned invalid cost_micros")

    session_id = envelope["session_id"]
    if not isinstance(session_id, str) or not session_id.strip():
        raise ExecutionOutputIncomplete("Hermes worker returned no session_id")

    report = {
        "summary": summary, "changed_files": changed_files,
        "checks_run": checks_run, "blocker": blocker,
    }
    return report, tokens_used, cost_micros, session_id


class HermesProcessController:
    """Launch one fresh, noninteractive Hermes oneshot session under declared
    bounds, in an environment built from a closed allowlist rather than a
    copy of this process' own environment.

    This controller does not claim a spend guarantee independent of the
    Hermes CLI's own implementation; it only bounds wall time, bounds
    captured output, and refuses any result that is not a complete,
    well-formed report.
    """

    def __init__(self, *, hermes_bin: str = "hermes", provider: str,
                 model: str, output_limit: int = DEFAULT_OUTPUT_LIMIT,
                 runner=_run_bounded) -> None:
        self.hermes_bin = shutil.which(hermes_bin) or hermes_bin
        self.provider = provider
        self.model = model
        self.output_limit = int(output_limit)
        self._runner = runner
        self._state_root = Path(
            tempfile.mkdtemp(prefix="cis-hermes-state-"))

    @property
    def execution_identity(self) -> str:
        try:
            digest = hashlib.sha256(
                Path(self.hermes_bin).read_bytes()).hexdigest()
        except OSError:
            digest = "unresolved"
        return (f"hermes:{self.hermes_bin}:{digest}:{self.provider}:"
                f"{self.model}:{SANDBOX_PROFILE}")

    def liveness(self) -> bool:
        return Path(self.hermes_bin).is_file()

    def _build_env(self) -> dict[str, str]:
        home = self._state_root / "home"
        config = self._state_root / "config"
        data = self._state_root / "data"
        cache = self._state_root / "cache"
        for path in (home, config, data, cache):
            path.mkdir(parents=True, exist_ok=True)
        bin_dir = str(Path(self.hermes_bin).parent)
        path_value = "/usr/bin:/bin"
        if bin_dir not in ("", "."):
            path_value = f"{bin_dir}:{path_value}"
        return {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(config),
            "XDG_DATA_HOME": str(data),
            "XDG_CACHE_HOME": str(cache),
            "PATH": path_value,
            "HERMES_SAFE_MODE": "1",
            "HERMES_IGNORE_USER_CONFIG": "1",
            "HERMES_IGNORE_RULES": "1",
        }

    def command(self, *, workspace: str) -> list[str]:
        return [
            self.hermes_bin, "oneshot",
            "--provider", self.provider,
            "--model", self.model,
            "--safe-mode",
            "--toolsets", "file,terminal",
            "--output-format", "json",
            "--cwd", workspace,
        ]

    def execute(self, *, prompt: str, workspace: str,
                wall_time_ms: int, cost_limit_micros: int) -> HermesProcessResult:
        if not prompt.strip():
            raise ExecutionOutputIncomplete("authorized Hermes card is empty")
        root = Path(workspace).resolve()
        if not root.is_dir():
            raise ExecutionProviderFailure(
                "isolated Hermes workspace does not exist", workspace=str(root))
        argv = self.command(workspace=str(root))
        env = self._build_env()
        code, stdout, stderr, elapsed = self._runner(
            argv, prompt=prompt.encode("utf-8"), cwd=str(root), env=env,
            timeout_seconds=wall_time_ms / 1000.0,
            output_limit=self.output_limit)
        if code != 0:
            raise ExecutionProviderFailure(
                "Hermes worker returned a nonzero exit",
                exit_code=code, stderr=stderr.decode("utf-8", "replace")[:1000])
        report, tokens_used, cost_micros, session_id = _validate_envelope(stdout)
        return HermesProcessResult(
            report=report, exit_code=code, wall_time_ms=elapsed,
            tokens_used=tokens_used, cost_micros=cost_micros,
            session_id=session_id, stdout_bytes=len(stdout),
            stderr_bytes=len(stderr))
