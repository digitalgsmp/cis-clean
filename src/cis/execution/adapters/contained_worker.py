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
'completed' with exit 0. The deterministic Verifier independently checks this
adapter attestation against the authoritative execution-input row. Every
unsuccessful outcome reaches it as VERIFIED_FAIL, while the distinction between
source failure and apparatus failure survives in the durable evidence lines.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable, Mapping, Sequence

from ...canonical import canonical_json
from ...errors import (
    ExecutionArtifactInvalid, ExecutionRefused, ExecutionTimedOut,
)
from ..port import ExecutionPort, ExecutionRequest, ExecutionResult, ExecutionUsage

#: The sealed worker image and its one declared verification operation.
IMAGE = "sha256:83e36e14606362123429ac046f0c0ece134de6bda84870e1b59dcfb6fb0541e5"
TRUSTED_RUNNER_SHA256 = "f6a02b18827d71734024b2b776573d81baa26aab4a5f368cf5d6f06ae583ceac"
WORKER_SHA256 = "f8b520a828f7a05274a5442979da23cd2d73a3480670a601765e03287fdfd2f8"
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

_WORKER_EVIDENCE_KEYS = frozenset({
    "schema", "run_nonce", "uid", "gid", "operation",
    "task_contract_bundle_sha256", "task_contract_hash",
    "authorization_binding_hash", "input_sha256", "verdict",
    "runner_exit", "verdict_json", "nets", "cap_eff", "no_new_privs",
    "pids_max", "memory_max", "cpu_max", "rootfs_write",
    "rootfs_probe_cleanup", "contract_write", "contract_probe_cleanup",
    "workspace_write", "trusted_runner_sha256", "worker_sha256",
    "resource_exhaustion_classification", "promotion", "host_action",
})


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _default_runner(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)


class ContainedWorkerAdapter(ExecutionPort):
    """Runs one declared verification in the sealed nonroot worker."""

    adapter_id = "contained_worker"
    #: The gateway must resolve a verified execution-input binding and derive
    #: the request payload from it alone; see cis.execution.gateway.
    requires_execution_input = True
    requires_frozen_task_contract = True
    expected_trusted_runner_sha256 = TRUSTED_RUNNER_SHA256
    expected_worker_sha256 = WORKER_SHA256

    #: Declared, not inferred (ADR-ARCH-003 clause 3).
    _CAPABILITIES = ("verify_authored_source",)

    #: This adapter makes no model/provider call: it runs one sealed
    #: container and reads back a fixed evidence ledger. token_limit and
    #: cost_limit_micros are therefore structurally unreachable — measured
    #: usage for both is always zero, so they can never exceed a positive
    #: authorized budget. wall_time_ms is the one dimension this adapter
    #: actually meters and terminates on, by binding the subprocess timeout
    #: to the authorized budget. Declaring all three (rather than just
    #: wall_time_ms) is what tells the gateway this backend's zero-cost,
    #: zero-token enforcement is a true invariant, not an omission.
    enforced_budget_dimensions = (
        "wall_time_ms", "token_limit", "cost_limit_micros")

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

    @property
    def execution_image_identity(self) -> str:
        return self.image

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

        src_bytes = source.encode("utf-8")
        source_sha = _sha256_bytes(src_bytes)
        vector_bytes = canonical_json(list(vectors)).encode("utf-8")
        vector_sha = _sha256_bytes(vector_bytes)
        expected_source = str(request.payload.get("candidate_sha256", ""))
        expected_vectors = str(request.payload.get("vector_contract_sha256", ""))
        if source_sha != expected_source:
            raise ExecutionRefused(
                "authored source does not match its authorized digest",
                request_id=request.request_id)
        if vector_sha != expected_vectors:
            raise ExecutionRefused(
                "test vectors do not match their authorized digest",
                request_id=request.request_id)
        for field in ("execution_input_hash", "task_contract_id",
                      "task_contract_hash", "expected_trusted_runner_sha256",
                      "expected_worker_sha256"):
            if not str(request.payload.get(field, "")):
                raise ExecutionRefused(
                    "request is missing an authorized execution-input fact",
                    request_id=request.request_id, field=field)

        workdir = tempfile.mkdtemp(prefix="cis-cw-")
        contract_dir = os.path.join(workdir, "contract")
        workspace = os.path.join(workdir, "workspace")
        os.makedirs(contract_dir)
        os.makedirs(workspace)
        # The worker runs as uid 65532 and must own its workspace. The CONTRACT
        # directory is mounted read-only, so this grants nothing there.
        os.chmod(workspace, 0o777)
        try:
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
                "source_sha256": source_sha,
                "vectors": list(vectors),
                "expected_test_count": len(vectors),
            }
            in_bytes = json.dumps(declaration, sort_keys=True, indent=1).encode()
            with open(os.path.join(contract_dir, "input.json"), "wb") as fh:
                fh.write(in_bytes)

            bundle_hash = _sha256_bytes(tc_bytes)
            input_hash = _sha256_bytes(in_bytes)

            # Derived solely from the authorized request, never from caller
            # input: this is the one name a cleanup call is ever allowed to
            # name, so a leaked container cannot be reached by any other
            # identifier a caller might supply.
            container_name = f"cis-cw-{request.request_hash[:32]}"

            argv = [
                *self._container_cmd, "run", "--rm",
                "--name", container_name, *_SANDBOX,
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

            # The outer backstop never widens: a supervised request's own
            # authorized wall budget may only narrow it, never exceed it.
            effective_timeout = self.timeout_seconds
            if request.budget is not None:
                effective_timeout = min(
                    request.budget.wall_time_ms / 1000.0, self.timeout_seconds)

            started_at = time.monotonic()
            try:
                done = self._run(argv, effective_timeout)
                worker_exit = int(done.returncode)
            except subprocess.TimeoutExpired:
                elapsed_ms = int((time.monotonic() - started_at) * 1000)
                torn_down, teardown_detail = self._cleanup_container(
                    container_name)
                if not torn_down:
                    # A timeout whose container cannot be proven gone is not
                    # a timeout the caller may act on: it would let a live
                    # container stand behind a recorded verdict. Fail closed
                    # with the typed artifact refusal instead of masking it.
                    raise ExecutionArtifactInvalid(
                        "contained worker timed out and its container "
                        "teardown could not be proven",
                        request_id=request.request_id,
                        container_name=container_name,
                        **teardown_detail,
                    )
                if request.budget is not None:
                    # A budgeted timeout is infrastructure, not a worker
                    # verdict: it must reach the caller as the typed refusal
                    # the supervision coordinator maps to its "timeout"
                    # failure class, never as a generic failed result.
                    raise ExecutionTimedOut(
                        "contained worker exceeded its authorized wall-time "
                        "budget",
                        request_id=request.request_id,
                        measured_wall_time_ms=elapsed_ms,
                        wall_time_ms=request.budget.wall_time_ms,
                    )
                worker_exit = 124
                done = None
            else:
                elapsed_ms = int((time.monotonic() - started_at) * 1000)

            evidence_path = os.path.join(workspace, "worker-evidence.txt")
            worker_evidence = ""
            if os.path.isfile(evidence_path):
                with open(evidence_path, encoding="utf-8", errors="replace") as fh:
                    worker_evidence = fh.read()

            observed, failures = self._verify_worker_evidence(
                worker_evidence, worker_exit=worker_exit,
                request=request, bundle_hash=bundle_hash, input_hash=input_hash)
            runner_sha = observed.get("trusted_runner_sha256", "")
            worker_sha = observed.get("worker_sha256", "")
            if runner_sha != str(request.payload["expected_trusted_runner_sha256"]):
                failures.append("trusted_runner_sha256_mismatch")
            if worker_sha != str(request.payload["expected_worker_sha256"]):
                failures.append("worker_sha256_mismatch")

            if worker_exit == 124:
                verdict = "HARNESS_FAILURE"
                classification = "RESOURCE_EXHAUSTION"
                status, exit_code, _ = _MAPPING[classification]
            elif failures:
                verdict = "HARNESS_FAILURE"
                classification = "HARNESS_FAILURE"
                status, exit_code, _ = _MAPPING[classification]
            else:
                verdict = observed["verdict"]
                verdict_payload = json.loads(observed["verdict_json"])
                status, exit_code, classification = self.classify(
                    verdict, verdict_payload)

            self.last_binding = {
                "execution_input_hash": str(request.payload["execution_input_hash"]),
                "source_sha256": source_sha,
                "vector_contract_sha256": vector_sha,
                "entrypoint": entrypoint,
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
                "schema=cis-contained-adapter-attestation-v1",
                f"operation={request.operation}",
                f"adapter={self.adapter_id}",
                f"image={self.image}",
                f"worker_operation={WORKER_OPERATION}",
                f"execution_input_hash={request.payload['execution_input_hash']}",
                f"task_contract_id={request.payload['task_contract_id']}",
                f"task_contract_hash={request.payload['task_contract_hash']}",
                f"entrypoint={entrypoint}",
                f"verdict={verdict}",
                f"classification={classification}",
                f"attestation_valid={'false' if failures else 'true'}",
                f"attestation_failures={','.join(sorted(set(failures))) if failures else 'none'}",
                f"worker_exit={worker_exit}",
                f"source_sha256={source_sha}",
                f"vector_contract_sha256={vector_sha}",
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

            # This adapter calls no model or provider: measured tokens and
            # cost are always zero, by construction rather than by omission
            # (see ``enforced_budget_dimensions`` above). Only a budgeted
            # (supervised) request carries usage at all, so an ordinary
            # request's result and hash stay byte-identical to before.
            usage = (
                ExecutionUsage(wall_time_ms=elapsed_ms, tokens_used=0,
                               cost_micros=0)
                if request.budget is not None else None
            )

            return ExecutionResult(
                status=status,
                exit_code=exit_code,
                outputs={
                    "verdict": verdict,
                    "classification": classification,
                    "execution_input_hash": str(request.payload["execution_input_hash"]),
                    "source_sha256": source_sha,
                    "vector_contract_sha256": vector_sha,
                    "entrypoint": entrypoint,
                    "trusted_runner_sha256": runner_sha,
                    "worker_evidence": worker_evidence,
                    "declared_vectors": len(vectors),
                },
                checks_performed=(),
                evidence=evidence,
                usage=usage,
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def _cleanup_container(self, container_name: str) -> tuple[bool, dict[str, Any]]:
        """Deterministic teardown after a subprocess timeout.

        Issues exactly two fixed commands, both naming only the
        ``container_name`` derived from this exact authorized request (see
        the call site): ``docker rm -f <name>`` and, to prove the outcome
        rather than trust the first command's exit status, ``docker inspect
        <name>``. Absence is proven only when the probe itself ran and
        returned nonzero. This never raises; the caller alone decides which
        typed refusal, if any, reaches the gateway.
        """
        try:
            cleanup = self._run(
                [*self._container_cmd, "rm", "-f", container_name], 30)
            cleanup_exit = int(getattr(cleanup, "returncode", -1))
        except Exception as exc:
            return False, {"cleanup_error": type(exc).__name__}
        try:
            probe = self._run(
                [*self._container_cmd, "inspect", container_name], 30)
            probe_exit = int(getattr(probe, "returncode", 0))
        except Exception as exc:
            return False, {
                "cleanup_exit": cleanup_exit, "probe_error": type(exc).__name__,
            }
        if probe_exit == 0:
            return False, {"cleanup_exit": cleanup_exit, "probe_exit": probe_exit}
        return True, {"cleanup_exit": cleanup_exit, "probe_exit": probe_exit}

    @staticmethod
    def _verify_worker_evidence(worker_evidence: str, *, worker_exit: int,
                                request: ExecutionRequest, bundle_hash: str,
                                input_hash: str) -> tuple[dict[str, str], list[str]]:
        """Parse the closed worker ledger and bind it to this exact request."""
        if worker_exit == 124:
            return {}, ["container_timeout"]
        observed: dict[str, str] = {}
        failures: list[str] = []
        for line in worker_evidence.splitlines():
            key, separator, value = line.partition("=")
            if not separator or not key or key in observed:
                failures.append("malformed_or_duplicate_worker_evidence")
                continue
            observed[key] = value.strip()
        if set(observed) != _WORKER_EVIDENCE_KEYS:
            failures.append("worker_evidence_key_set_mismatch")
        expected = {
            "schema": "cis-contained-worker-evidence-v4",
            "run_nonce": request.request_hash[:32],
            "operation": "verify_authored_source",
            "task_contract_bundle_sha256": bundle_hash,
            "task_contract_hash": str(request.payload["task_contract_hash"]),
            "authorization_binding_hash": str(request.binding_hash),
            "input_sha256": input_hash,
            "promotion": "none",
            "host_action": "none",
        }
        for key, value in expected.items():
            if observed.get(key) != value:
                failures.append(f"{key}_mismatch")
        try:
            verdict_payload = json.loads(observed.get("verdict_json", ""))
        except (TypeError, ValueError):
            verdict_payload = {}
            failures.append("verdict_json_invalid")
        verdict = observed.get("verdict", "")
        if verdict not in _MAPPING or verdict_payload.get("verdict") != verdict:
            failures.append("verdict_mismatch")
        expected_exit = {"SOURCE_PASS": 0, "SOURCE_FAIL": 1,
                         "HARNESS_FAILURE": 2}.get(verdict)
        try:
            runner_exit = int(observed.get("runner_exit", ""))
        except ValueError:
            runner_exit = -1
        if expected_exit is None or worker_exit != expected_exit or runner_exit != expected_exit:
            failures.append("verdict_exit_mismatch")
        return observed, failures
