"""Layer-3 adapter: the contained nonroot worker, reached through the Layer-2 port.

ADR-ARCH-003. This is replaceable execution infrastructure, never authority. It
is reached only through ``cis.execution.gateway``; nothing above Layer 2 names
the container runtime, the image, the worker's argument order or its exit codes.

IT WRITES NO EVIDENCE. The adapter returns an ``ExecutionResult`` and nothing
else. The gateway records the ``backend_runs`` row and admits the
``evidence_records`` row, exactly as it already does for every other backend.
There is no second evidence path, no second verifier and no promotion here.

THE AUTHORITATIVE RESULT MAPPING LIVES HERE, IN ONE PLACE
---------------------------------------------------------
The worker distinguishes three outcomes; the gateway's record carries two
fields. The mapping is declared once, as a closed table, so no caller invents
its own reading:

    SOURCE_PASS           -> status 'completed', exit 0
        Verification completed and every declared vector passed.
        THIS IS THE ONLY OUTCOME THAT SATISFIES submitted_execution_completed.
    SOURCE_FAIL           -> status 'failed',    exit 1
        Verification completed; the source failed one or more valid vectors.
    HARNESS_FAILURE       -> status 'failed',    exit 2
        The apparatus could not establish a reliable verdict. Says NOTHING
        about the source.
    RESOURCE_EXHAUSTION   -> status 'failed',    exit 3
        A per-vector timeout or the total wall-clock budget. INFRASTRUCTURE,
        and never simultaneously an ordinary source failure.

NO UNSUCCESSFUL OR INDETERMINATE OUTCOME SATISFIES
``submitted_execution_completed``, because only SOURCE_PASS yields status
'completed' with exit 0. The frozen Verifier is unchanged and unamended: every
unsuccessful outcome reaches it as VERIFIED_FAIL, which is correct. The
distinction between them survives in the durable evidence lines below, where it
is recorded rather than gating - promoting it into a gating check would mean
changing the closed SUPPORTED_CHECKS set, which is a separate decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Mapping, Sequence

from ...errors import ExecutionRefused
from ..port import ExecutionPort, ExecutionRequest, ExecutionResult

#: The sealed worker image and its one declared verification operation.
IMAGE = "cis-contained-worker:proof-v4"
WORKER_OPERATION = "verify-authored-source"

#: Container restrictions, declared here and never widened by a caller.
_SANDBOX = (
    "--network", "none", "--read-only", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true",
    "--pids-limit", "32", "--memory", "64m", "--cpus", "0.50",
    "--user", "65532:65532",
)

#: Outer bound on the whole container. The worker enforces its own per-vector
#: and total budgets; this is the backstop if the runtime itself wedges.
CONTAINER_TIMEOUT_SECONDS = 300

#: verdict -> (status, exit_code, classification). Closed, and the only mapping.
_MAPPING: dict[str, tuple[str, int, str]] = {
    "SOURCE_PASS": ("completed", 0, "SOURCE_PASS"),
    "SOURCE_FAIL": ("failed", 1, "SOURCE_FAIL"),
    "HARNESS_FAILURE": ("failed", 2, "HARNESS_FAILURE"),
    "RESOURCE_EXHAUSTION": ("failed", 3, "RESOURCE_EXHAUSTION"),
}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _default_runner(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)


class ContainedWorkerAdapter(ExecutionPort):
    """Runs one declared verification in the sealed nonroot worker."""

    adapter_id = "contained_worker"

    #: Declared, not inferred (ADR-ARCH-003 clause 3).
    _CAPABILITIES = ("verify_authored_source",)

    def __init__(self, *, image: str = IMAGE,
                 runner: Callable[..., subprocess.CompletedProcess] | None = None,
                 container_cmd: Sequence[str] = ("docker",),
                 timeout_seconds: float = CONTAINER_TIMEOUT_SECONDS) -> None:
        self.image = image
        self._run = runner or _default_runner
        self._container_cmd = tuple(container_cmd)
        self.timeout_seconds = float(timeout_seconds)
        #: Set after a dispatch so the caller can record what actually ran.
        self.last_binding: dict[str, Any] = {}

    def capabilities(self) -> Sequence[str]:
        return self._CAPABILITIES

    def liveness(self) -> bool:
        """Declared liveness: the sealed image is present and inspectable.

        Reads nothing from the backend's private files and parses no log
        (ADR-ARCH-003 clause 3).
        """
        try:
            done = self._run(
                [*self._container_cmd, "image", "inspect", "--format", "{{.Id}}",
                 self.image], 30)
        except Exception:
            return False
        return int(getattr(done, "returncode", 1)) == 0

    # ---- the one mapping, applied in one place -------------------------------

    @staticmethod
    def classify(verdict: str, payload: Mapping[str, Any]) -> tuple[str, int, str]:
        """Map a worker verdict to (status, exit_code, classification).

        A HARNESS_FAILURE whose own classification names resource exhaustion is
        reported as RESOURCE_EXHAUSTION, so a timeout is INFRASTRUCTURE and is
        never also an ordinary source failure.
        """
        if verdict == "HARNESS_FAILURE" and \
                str(payload.get("classification", "")) == "RESOURCE_EXHAUSTION":
            return _MAPPING["RESOURCE_EXHAUSTION"]
        return _MAPPING.get(verdict, _MAPPING["HARNESS_FAILURE"])

    # ---- execution -----------------------------------------------------------

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        request.verify_token()

        if request.operation not in self._CAPABILITIES:
            raise ExecutionRefused("operation is not declared by this backend",
                                   operation=request.operation)
        if not request.allowed_scope:
            raise ExecutionRefused("request carries no allowed scope",
                                   request_id=request.request_id)

        source = request.payload.get("authored_source")
        vectors = request.payload.get("vectors")
        entrypoint = request.payload.get("entrypoint")
        if not isinstance(source, str) or not source.strip():
            raise ExecutionRefused("request carries no authored source",
                                   request_id=request.request_id)
        if not isinstance(vectors, (list, tuple)) or not vectors:
            raise ExecutionRefused("request declares no test vectors",
                                   request_id=request.request_id)
        if not isinstance(entrypoint, str) or not entrypoint:
            raise ExecutionRefused("request declares no entrypoint",
                                   request_id=request.request_id)

        workdir = tempfile.mkdtemp(prefix="cis-cw-")
        contract_dir = os.path.join(workdir, "contract")
        workspace = os.path.join(workdir, "workspace")
        os.makedirs(contract_dir)
        os.makedirs(workspace)
        # The worker runs as uid 65532 and must own its workspace. The CONTRACT
        # directory is mounted read-only, so this grants nothing there.
        os.chmod(workspace, 0o777)
        try:
            src_bytes = source.encode("utf-8")
            with open(os.path.join(contract_dir, "duration_candidate.py"), "wb") as fh:
                fh.write(src_bytes)

            task_contract = {
                "task_contract_id": str(request.payload.get("task_contract_id", "")),
                "operation": "verify_authored_source",
                "allowed_scope": list(request.allowed_scope),
                "forbidden_actions": list(request.forbidden_actions),
                "required_checks": list(request.required_checks),
            }
            tc_bytes = json.dumps(task_contract, sort_keys=True, indent=1).encode()
            with open(os.path.join(contract_dir, "task-contract.json"), "wb") as fh:
                fh.write(tc_bytes)

            declaration = {
                "source_filename": "duration_candidate.py",
                "source_module": "duration_candidate",
                "entrypoint": entrypoint,
                "source_sha256": _sha256_bytes(src_bytes),
                "vectors": list(vectors),
                "expected_test_count": len(vectors),
            }
            in_bytes = json.dumps(declaration, sort_keys=True, indent=1).encode()
            with open(os.path.join(contract_dir, "input.json"), "wb") as fh:
                fh.write(in_bytes)

            bundle_hash = _sha256_bytes(tc_bytes)
            input_hash = _sha256_bytes(in_bytes)

            argv = [
                *self._container_cmd, "run", "--rm", *_SANDBOX,
                "-v", f"{contract_dir}:/contract:ro",
                "-v", f"{workspace}:/workspace",
                self.image,
                # THE SIX-ARGUMENT FROZEN INVOCATION, PRESERVED EXACTLY.
                WORKER_OPERATION,
                bundle_hash,
                str(request.payload.get("task_contract_hash", "none")),
                str(request.binding_hash or "none"),
                input_hash,
                request.request_hash[:32],
            ]
            try:
                done = self._run(argv, self.timeout_seconds)
                worker_exit = int(done.returncode)
            except subprocess.TimeoutExpired:
                worker_exit = 124
                done = None

            evidence_path = os.path.join(workspace, "worker-evidence.txt")
            worker_evidence = ""
            if os.path.isfile(evidence_path):
                with open(evidence_path, encoding="utf-8", errors="replace") as fh:
                    worker_evidence = fh.read()

            verdict, payload = self._read_verdict(worker_evidence, done, worker_exit)
            status, exit_code, classification = self.classify(verdict, payload)

            runner_sha = _field(worker_evidence, "trusted_runner_sha256")
            worker_sha = _field(worker_evidence, "worker_sha256")

            self.last_binding = {
                "source_sha256": declaration["source_sha256"],
                "vector_contract_sha256": input_hash,
                "task_contract_bundle_sha256": bundle_hash,
                "authorization_binding_hash": request.binding_hash,
                "trusted_runner_sha256": runner_sha,
                "worker_sha256": worker_sha,
                "image": self.image,
                "verdict": verdict,
                "classification": classification,
            }

            # These lines ARE the durable distinction. The Verifier will map
            # every unsuccessful outcome to VERIFIED_FAIL; which one it was
            # remains legible here.
            evidence = (
                f"operation={request.operation}",
                f"adapter={self.adapter_id}",
                f"image={self.image}",
                f"worker_operation={WORKER_OPERATION}",
                f"verdict={verdict}",
                f"classification={classification}",
                f"worker_exit={worker_exit}",
                f"source_sha256={declaration['source_sha256']}",
                f"vector_contract_sha256={input_hash}",
                f"task_contract_bundle_sha256={bundle_hash}",
                f"authorization_binding_hash={request.binding_hash}",
                f"trusted_runner_sha256={runner_sha}",
                f"worker_sha256={worker_sha}",
                f"declared_vectors={len(vectors)}",
                f"allowed_scope={','.join(request.allowed_scope)}",
                f"forbidden_actions={','.join(request.forbidden_actions)}",
                f"stopped_at={request.stopping_condition}",
                f"returned_to={request.return_point}",
            )

            # checks_performed is EMPTY unless the verification actually
            # completed and passed. A backend never reports a check it did not
            # establish, and an unsuccessful run establishes none.
            performed = tuple(request.required_checks) if status == "completed" else ()

            return ExecutionResult(
                status=status,
                exit_code=exit_code,
                outputs={
                    "verdict": verdict,
                    "classification": classification,
                    "source_sha256": declaration["source_sha256"],
                    "vector_contract_sha256": input_hash,
                    "trusted_runner_sha256": runner_sha,
                    "worker_evidence": worker_evidence,
                    "declared_vectors": len(vectors),
                },
                checks_performed=performed,
                evidence=evidence,
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    @staticmethod
    def _read_verdict(worker_evidence: str, done, worker_exit: int):
        """Derive the verdict from the worker's own evidence file.

        If no evidence was produced at all, the apparatus failed; that is a
        HARNESS_FAILURE and never a statement about the source.
        """
        if worker_exit == 124:
            return "HARNESS_FAILURE", {"classification": "RESOURCE_EXHAUSTION"}
        verdict = _field(worker_evidence, "verdict")
        if not verdict:
            return "HARNESS_FAILURE", {"reason": "worker produced no evidence"}
        payload: dict[str, Any] = {}
        raw = _field(worker_evidence, "verdict_json")
        if raw:
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = {}
        return verdict, payload


def _field(text: str, key: str) -> str:
    """Read one ``key=value`` line from the worker's evidence file."""
    for line in text.splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    return ""
