"""Layer-3 coding-agent candidate-authoring adapter.

The worker receives a verified task-card projection and edits only a disposable
copy of the source tree mounted at ``/workspace``.  The live repository is not
visible in the bubblewrap filesystem.  Returned files are candidate artifacts,
not accepted source and not verification evidence.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...canonical import canonical_json
from ...card_factory import render_card_markdown, verify_card
from ...errors import ExecutionArtifactInvalid, ExecutionRefused
from ..port import ExecutionPort, ExecutionRequest, ExecutionResult, ExecutionUsage
from .claude_process import ClaudeProcessController
from .coding_agent import CodingAgentController


AUTHOR_OPERATION = "reconstruct_module"
MAX_WORKSPACE_FILES = 50_000
MAX_WORKSPACE_FILE_BYTES = 64 * 1024 * 1024
MAX_CANDIDATE_FILES = 128
MAX_CANDIDATE_BYTES = 4 * 1024 * 1024


def _copy_source(source: Path, destination: Path) -> None:
    ignored = shutil.ignore_patterns(
        ".git", ".pytest_cache", "__pycache__", "*.pyc", "*.pyo")
    shutil.copytree(source, destination, ignore=ignored, dirs_exist_ok=True)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot(root: Path) -> dict[str, tuple[str, int, str]]:
    """Bounded metadata snapshot. Symlinks are facts, never followed."""
    result: dict[str, tuple[str, int, str]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[relative] = ("symlink", 0, str(path.readlink()))
        elif path.is_file():
            size = path.stat().st_size
            if size > MAX_WORKSPACE_FILE_BYTES:
                raise ExecutionArtifactInvalid(
                    "workspace file exceeds the bounded scan envelope",
                    path=relative, size=size)
            result[relative] = ("file", size, _file_sha256(path))
        if len(result) > MAX_WORKSPACE_FILES:
            raise ExecutionArtifactInvalid(
                "workspace contains too many artifacts to scan",
                limit=MAX_WORKSPACE_FILES)
    return result


def _allowed(path: str, scopes: Sequence[str]) -> bool:
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts:
        return False
    for raw in scopes:
        scope = raw.rstrip("/")
        scoped = Path(scope)
        if not scope or scoped.is_absolute() or ".." in scoped.parts:
            continue
        if path == scope or path.startswith(scope + "/"):
            return True
    return False


class CodingAgentAdapter(ExecutionPort):
    """Produce a scope-checked candidate in an isolated disposable tree.

    This is the provider-neutral base.  Subclasses bind a concrete
    ``adapter_id`` and a default controller (e.g. ``ClaudeCodeAdapter``).
    """

    requires_frozen_task_contract = True
    requires_task_card = True
    _CAPABILITIES = (AUTHOR_OPERATION,)
    # There is no coding-agent CLI token cap.  The supervised gateway therefore
    # refuses this adapter today instead of mistaking observed tokens for an
    # enforced limit.
    enforced_budget_dimensions = ("wall_time_ms", "cost_limit_micros")

    def __init__(self, *, adapter_id: str, source_root: str,
                 controller: CodingAgentController) -> None:
        if not isinstance(adapter_id, str) or not adapter_id.strip():
            raise ExecutionRefused(
                "coding-agent adapter requires a nonblank adapter_id")
        self.adapter_id = adapter_id
        self.source_root = Path(source_root).resolve()
        self.controller = controller

    def capabilities(self) -> Sequence[str]:
        return self._CAPABILITIES

    def liveness(self) -> bool:
        return self.source_root.is_dir() and self.controller.liveness()

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        request.verify_token()
        if request.operation != AUTHOR_OPERATION:
            raise ExecutionRefused(
                "coding-agent adapter does not declare this operation",
                operation=request.operation)
        if request.budget is None:
            raise ExecutionRefused(
                "coding-agent execution requires a bounded budget")
        card_value = request.payload.get("task_card")
        contract_value = request.payload.get("frozen_task_contract")
        if not isinstance(card_value, Mapping) or not isinstance(contract_value, Mapping):
            raise ExecutionRefused(
                "coding-agent execution requires an authority-derived card and contract")
        card = dict(card_value)
        contract = dict(contract_value)
        try:
            verify_card(card)
        except Exception as exc:
            raise ExecutionRefused("task card digest did not verify") from exc
        if (str(card["authorization_binding_hash"]) != str(request.binding_hash)
                or str(card["authorization_id"]) != str(contract.get("authorization_id"))
                or str(card["task_contract_hash"]) != str(contract.get("task_contract_hash"))
                or str(card["task_contract_id"]) != str(contract.get("task_contract_id"))
                or tuple(card["allowed_paths"]) != tuple(request.allowed_scope)
                or set(card["forbidden_actions"]) != set(request.forbidden_actions)):
            raise ExecutionRefused(
                "task card is not bound to this exact execution request")

        prompt = render_card_markdown(card)
        with tempfile.TemporaryDirectory(prefix="cis-coding-agent-candidate-") as temp:
            workspace = Path(temp) / "workspace"
            _copy_source(self.source_root, workspace)
            before = _snapshot(workspace)
            outcome = self.controller.execute(
                prompt=prompt, workspace=str(workspace),
                wall_time_ms=request.budget.wall_time_ms,
                cost_limit_micros=request.budget.cost_limit_micros)
            after = _snapshot(workspace)
            changed = sorted(
                path for path in set(before) | set(after)
                if before.get(path) != after.get(path))
            outside = [path for path in changed
                       if not _allowed(path, request.allowed_scope)]
            if outside:
                raise ExecutionArtifactInvalid(
                    "coding-agent candidate changed paths outside authorized scope",
                    paths=outside)
            changed_symlinks = [
                path for path in changed
                if ((before.get(path) and before[path][0] == "symlink")
                    or (after.get(path) and after[path][0] == "symlink"))]
            if changed_symlinks:
                raise ExecutionArtifactInvalid(
                    "coding-agent candidate created, removed, or replaced a symlink",
                    paths=changed_symlinks)
            if len(changed) > MAX_CANDIDATE_FILES:
                raise ExecutionArtifactInvalid(
                    "coding-agent candidate changed too many files",
                    count=len(changed), limit=MAX_CANDIDATE_FILES)
            artifacts: dict[str, str | None] = {}
            candidate_bytes = 0
            for path in changed:
                if path not in after:
                    artifacts[path] = None
                    continue
                candidate_bytes += after[path][1]
                if candidate_bytes > MAX_CANDIDATE_BYTES:
                    raise ExecutionArtifactInvalid(
                        "coding-agent candidate exceeds the bounded artifact envelope",
                        bytes=candidate_bytes, limit=MAX_CANDIDATE_BYTES)
                data = (workspace / path).read_bytes()
                try:
                    artifacts[path] = data.decode("utf-8", "strict")
                except UnicodeDecodeError as exc:
                    raise ExecutionArtifactInvalid(
                        "coding-agent candidate contains a non-text artifact",
                        path=path) from exc

        candidate_sha = hashlib.sha256(
            canonical_json(artifacts).encode("utf-8")).hexdigest()
        return ExecutionResult(
            status="completed", exit_code=0,
            outputs={
                "candidate_files": artifacts,
                "candidate_sha256": candidate_sha,
                "task_card_hash": str(card["card_hash"]),
                "worker_report": dict(outcome.report),
            },
            checks_performed=(
                "task_card_digest_recomputed",
                "authorization_binding_matched",
                "isolated_scope_diff_checked",
            ),
            evidence=(
                f"task_card_hash={card['card_hash']}",
                f"candidate_sha256={candidate_sha}",
                f"session_id={outcome.session_id}",
                "live_repository_mutation=none_disposable_workspace",
            ),
            usage=ExecutionUsage(
                wall_time_ms=outcome.wall_time_ms,
                tokens_used=outcome.tokens_used,
                cost_micros=outcome.cost_micros),
        )


class ClaudeCodeAdapter(CodingAgentAdapter):
    """Claude Code binding of the coding-agent adapter.

    Thin subclass that supplies ``adapter_id`` ``"claude_code"`` and defaults
    the controller to :class:`.ClaudeProcessController`.
    """

    def __init__(self, *, source_root: str,
                 controller: CodingAgentController | None = None) -> None:
        super().__init__(
            adapter_id="claude_code", source_root=source_root,
            controller=controller or ClaudeProcessController())