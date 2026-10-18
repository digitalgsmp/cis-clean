"""A real nonroot Docker worker behind the CIS execution port.

The adapter receives a gateway-minted request whose payload contains a
verified frozen task contract. It creates a read-only contract bundle, exposes
one empty writable workspace, and starts a fresh container with no network,
no capabilities, no-new-privileges, a read-only root filesystem, and bounded
CPU, memory, processes and wall time. The worker can produce a candidate and
evidence; it cannot promote either one.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from ..assurance.task_contract import verify_row
from ..errors import CisError, ExecutionRefused
from ..execution.port import ExecutionPort, ExecutionRequest, ExecutionResult
from ..policy.compiler import verify_compiled_envelope
from .policy_obligations import (
    CHECK_FACTS, CONTAINMENT_CHECKS, PRODUCED_POLICY_EVIDENCE,
    satisfied_labels, verify_required_obligations,
)

IMAGE = "cis-contained-worker:proof-v2"
WORKER_UID = 65532
WORKER_GID = 65532
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return (json.dumps(dict(value), sort_keys=True, separators=(",", ":"))
                + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ExecutionRefused("worker input is not canonical JSON") from exc


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _parse_evidence(content: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in content.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or key in parsed:
            raise ExecutionRefused("worker evidence is not a unique key/value ledger")
        parsed[key] = value
    return parsed


class ContainedNonrootWorker(ExecutionPort):
    """Runs one frozen reconstruction contract in one fresh container."""

    adapter_id = "contained_nonroot"
    requires_frozen_task_contract = True
    #: Every contained_nonroot dispatch must additionally carry a verified
    #: MASTER/TASK policy envelope bound to this exact authorization; the
    #: gateway refuses before adapter entry if one is missing, forged or
    #: stale, and there is no constructor flag anywhere that disables this.
    requires_policy_envelope = True
    policy_enforcement_point = "cis.worker.contained_nonroot"
    enforced_policy_prohibitions = (
        "host:promote", "host:restart_service", "model:any", "network:any",
        "privilege:escalate", "write:/mnt/projects/cis",
    )
    enforced_policy_checks = CONTAINMENT_CHECKS
    produced_policy_evidence = PRODUCED_POLICY_EVIDENCE

    def __init__(self, *, image: str = IMAGE, timeout_seconds: float = 10,
                 runner: Callable[..., subprocess.CompletedProcess] | None = None,
                 liveness_probe: Callable[[], str | None] | None = None) -> None:
        self.image = image
        self.timeout_seconds = timeout_seconds
        self._run = runner or subprocess.run
        self._liveness_probe = liveness_probe
        self._image_id: str | None = None

    def capabilities(self) -> Sequence[str]:
        return ("reconstruct_module",)

    def liveness(self) -> bool:
        if self._liveness_probe is not None:
            image_id = self._liveness_probe()
            if not isinstance(image_id, str) or _IMAGE_ID.fullmatch(image_id) is None:
                self._image_id = None
                return False
            self._image_id = image_id
            return True
        completed = self._run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", self.image],
            text=True, capture_output=True, check=False,
        )
        image_id = (completed.stdout or "").strip()
        if completed.returncode != 0 or _IMAGE_ID.fullmatch(image_id) is None:
            self._image_id = None
            return False
        self._image_id = image_id
        return True

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        request.verify_token()
        if self._image_id is None and not self.liveness():
            raise ExecutionRefused("contained worker image is not live")
        verified_facts = {"host.image_digest_resolved"}
        if request.operation not in self.capabilities():
            raise ExecutionRefused("contained worker operation is not declared",
                                   operation=request.operation)
        if not request.allowed_scope:
            raise ExecutionRefused("contained worker scope is empty")

        raw_contract = request.payload.get("frozen_task_contract")
        if not isinstance(raw_contract, Mapping):
            raise ExecutionRefused(
                "contained worker requires a verified frozen task contract")
        contract = dict(raw_contract)
        verified_facts.update(self._verify_contract_binding(request, contract))
        envelope, policy_facts = self._verify_policy_binding(request, contract)
        verified_facts.update(policy_facts)

        contract_bytes = _canonical_bytes(contract)
        input_bytes = _canonical_bytes(request.contract_view())
        bundle_hash = _sha256(contract_bytes)
        input_hash = _sha256(input_bytes)
        name = "cis-worker-" + uuid.uuid4().hex[:12]
        run_nonce = request.payload.get("run_nonce")
        if not isinstance(run_nonce, str) or len(run_nonce) != 64:
            raise ExecutionRefused("contained worker requires a run nonce")

        with tempfile.TemporaryDirectory(prefix="cis-worker-contract-") as cdir, \
                tempfile.TemporaryDirectory(prefix="cis-worker-output-") as odir:
            contract_dir, output_dir = Path(cdir), Path(odir)
            (contract_dir / "task-contract.json").write_bytes(contract_bytes)
            (contract_dir / "input.json").write_bytes(input_bytes)
            os.chmod(contract_dir / "task-contract.json", 0o444)
            os.chmod(contract_dir / "input.json", 0o444)
            os.chmod(contract_dir, 0o755)
            os.chmod(output_dir, 0o777)

            command = self._command(
                name=name, contract_dir=contract_dir, output_dir=output_dir,
                bundle_hash=bundle_hash,
                task_contract_hash=str(contract["task_contract_hash"]),
                binding_hash=str(contract["authorization_binding_hash"]),
                input_hash=input_hash, run_nonce=run_nonce,
            )
            try:
                completed = self._run(
                    command, text=True, capture_output=True,
                    timeout=self.timeout_seconds, check=False,
                )
            except subprocess.TimeoutExpired as exc:
                self._force_remove(name)
                self._require_absent(name)
                raise ExecutionRefused(
                    "contained worker exceeded its wall-time bound",
                    timeout_seconds=self.timeout_seconds,
                ) from exc

            if completed.returncode != 0:
                self._force_remove(name)
                self._require_absent(name)
                raise ExecutionRefused(
                    "contained worker refused or failed",
                    exit_code=completed.returncode,
                    stderr=(completed.stderr or "").strip()[:500],
                )

            self._require_absent(name)
            verified_facts.add("host.teardown_absence_verified")
            candidate_path = output_dir / "candidate.txt"
            evidence_path = output_dir / "worker-evidence.txt"
            if not candidate_path.is_file() or not evidence_path.is_file():
                raise ExecutionRefused(
                    "contained worker returned without required artifacts")
            candidate = candidate_path.read_bytes()
            evidence_text = evidence_path.read_text(encoding="utf-8")

        evidence = _parse_evidence(evidence_text)
        verified_facts.update(self._verify_evidence(
            evidence=evidence, candidate=candidate, bundle_hash=bundle_hash,
            input_hash=input_hash, contract=contract, run_nonce=run_nonce,
        ))
        policy_evidence = verify_required_obligations(
            required_checks=set(envelope["required_checks"]),
            required_evidence=set(envelope["required_evidence"]),
            verified_facts=verified_facts,
        )
        checks_performed = satisfied_labels(CHECK_FACTS, verified_facts)
        return ExecutionResult(
            status="completed",
            exit_code=0,
            outputs={
                "operation": request.operation,
                "candidate_content": candidate.decode("utf-8"),
                "candidate_sha256": _sha256(candidate),
                "task_contract_hash": str(contract["task_contract_hash"]),
                "image_id": self._image_id,
                "host_action": None,
            },
            checks_performed=checks_performed,
            evidence=(
                *tuple(evidence_text.splitlines()),
                *(f"{label}=verified" for label in policy_evidence),
            ),
        )

    @staticmethod
    def _verify_contract_binding(request: ExecutionRequest,
                                 contract: Mapping[str, Any]) -> frozenset[str]:
        required = (
            "task_contract_id", "authorization_id",
            "authorization_binding_hash", "target_module_id",
            "task_contract_hash", "state",
        )
        missing = [key for key in required if not contract.get(key)]
        if missing:
            raise ExecutionRefused("frozen task contract is incomplete",
                                   missing=missing)
        if contract["state"] != "FROZEN":
            raise ExecutionRefused("task contract is not FROZEN")
        if contract["authorization_binding_hash"] != request.binding_hash:
            raise ExecutionRefused(
                "task contract is not bound to this execution authorization")
        if contract["authorization_id"] != request.request_id.removeprefix("req-"):
            raise ExecutionRefused(
                "task contract authorization id does not match the request")
        if contract["target_module_id"] != request.payload.get("target_module_id"):
            raise ExecutionRefused("task contract target does not match the request")
        try:
            verify_row(contract)
        except (CisError, KeyError, TypeError, ValueError) as exc:
            raise ExecutionRefused(
                "frozen task contract digest did not verify") from exc
        return frozenset({
            "host.authorization_binding_recomputed",
            "host.frozen_task_contract_recomputed",
        })

    @staticmethod
    def _verify_policy_binding(request: ExecutionRequest,
                               contract: Mapping[str, Any],
                               ) -> tuple[dict, frozenset[str]]:
        """Refuse before any container runs unless a policy envelope is
        present, bound to this exact task contract, and internally
        tamper-free.

        This is the worker's own half of the mandatory policy binding; the
        gateway has already verified staleness against the currently loaded
        catalog before this payload was ever built, so this check is the
        same defense-in-depth re-verification ``_verify_contract_binding``
        already performs for the task contract — the worker trusts nothing
        it is handed without checking it for itself.
        """
        raw_envelope = request.payload.get("policy_envelope")
        if not isinstance(raw_envelope, Mapping):
            raise ExecutionRefused(
                "contained worker requires a verified policy envelope")
        envelope = dict(raw_envelope)
        try:
            verify_compiled_envelope(envelope)
        except (CisError, KeyError, TypeError, ValueError) as exc:
            raise ExecutionRefused(
                "policy envelope could not be verified") from exc
        if envelope["task_contract_id"] != contract["task_contract_id"]:
            raise ExecutionRefused(
                "policy envelope is not bound to this task contract")
        if envelope["task_contract_hash"] != contract["task_contract_hash"]:
            raise ExecutionRefused(
                "policy envelope does not carry this task contract's hash")
        selector = envelope["selector"]
        if (selector["module"] != request.payload.get("target_module_id")
                or selector["operation"] != request.operation):
            raise ExecutionRefused("policy envelope selector does not match request")
        if not set(envelope["prohibited_actions"]) <= set(request.forbidden_actions):
            raise ExecutionRefused("request omitted a policy prohibition")
        if not set(envelope["required_checks"]) <= set(request.required_checks):
            raise ExecutionRefused("request omitted a policy-required check")
        narrowed = envelope["narrowed_scope"]
        if narrowed is not None and not set(request.allowed_scope) <= set(narrowed):
            raise ExecutionRefused("request scope exceeds the policy envelope")
        if not set(envelope["required_evidence"]) <= set(
                ContainedNonrootWorker.produced_policy_evidence):
            raise ExecutionRefused(
                "policy envelope requires unsupported worker evidence")
        return envelope, frozenset({"host.policy_envelope_recompiled"})

    @staticmethod
    def _verify_evidence(*, evidence: Mapping[str, str], candidate: bytes,
                         bundle_hash: str, input_hash: str,
                         contract: Mapping[str, Any],
                         run_nonce: str) -> frozenset[str]:
        expected = {
            "schema": "cis-contained-worker-evidence-v3",
            "run_nonce": run_nonce,
            "uid": str(WORKER_UID),
            "gid": str(WORKER_GID),
            "operation": "reconstruct_module",
            "task_contract_bundle_sha256": bundle_hash,
            "task_contract_hash": str(contract["task_contract_hash"]),
            "authorization_binding_hash":
                str(contract["authorization_binding_hash"]),
            "input_sha256": input_hash,
            "candidate_sha256": _sha256(candidate),
            "nets": "lo,",
            "cap_eff": "0000000000000000",
            "no_new_privs": "1",
            "pids_max": "32",
            "memory_max": "67108864",
            "cpu_max": "50000 100000",
            "rootfs_write": "denied",
            "contract_write": "denied",
            "workspace_write": "allowed",
            "host_action": "none",
        }
        if set(evidence) != set(expected):
            raise ExecutionRefused(
                "contained worker evidence key set did not verify",
                missing=sorted(set(expected) - set(evidence)),
                unexpected=sorted(set(evidence) - set(expected)),
            )
        mismatches = {
            key: {"expected": value, "recorded": evidence.get(key)}
            for key, value in expected.items() if evidence.get(key) != value
        }
        if mismatches:
            raise ExecutionRefused("contained worker evidence did not verify",
                                   mismatches=mismatches)
        return frozenset({
            "attestation.capabilities_zero",
            "attestation.cgroup_limits_exact",
            "attestation.contract_write_denied",
            "attestation.identity_nonroot",
            "attestation.network_loopback_only",
            "attestation.no_new_privileges",
            "attestation.rootfs_write_denied",
            "attestation.workspace_write_allowed",
            "host.candidate_digest_recomputed",
        })

    def _command(self, *, name: str, contract_dir: Path, output_dir: Path,
                 bundle_hash: str, task_contract_hash: str,
                 binding_hash: str, input_hash: str,
                 run_nonce: str) -> list[str]:
        if self._image_id is None or _IMAGE_ID.fullmatch(self._image_id) is None:
            raise ExecutionRefused("contained worker image identity is unverified")
        return [
            "docker", "run", "--rm", "--name", name,
            "--pull", "never",
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--pids-limit", "32", "--memory", "64m", "--cpus", "0.50",
            "--user", f"{WORKER_UID}:{WORKER_GID}",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m",
            "--mount", f"type=bind,src={contract_dir},dst=/contract,readonly",
            "--mount", f"type=bind,src={output_dir},dst=/workspace",
            self._image_id, "reconstruct-module", bundle_hash,
            task_contract_hash, binding_hash, input_hash, run_nonce,
        ]

    def _force_remove(self, name: str) -> None:
        removed = self._run(["docker", "rm", "-f", name], text=True,
                            capture_output=True, check=False)
        message = ((removed.stderr or "") + (removed.stdout or "")).lower()
        acceptable = ("no such container" in message
                      or "removal of container" in message
                      and "already in progress" in message)
        if removed.returncode != 0 and not acceptable:
            raise ExecutionRefused(
                "worker container force-removal could not be verified",
                container_name=name, docker_error=message.strip()[:500],
            )

    def _require_absent(self, name: str) -> None:
        for attempt in range(21):
            inspected = self._run(["docker", "inspect", name], text=True,
                                  capture_output=True, check=False)
            message = ((inspected.stderr or "")
                       + (inspected.stdout or "")).lower()
            if inspected.returncode != 0:
                if ("no such object" in message
                        or "no such container" in message):
                    return
                raise ExecutionRefused(
                    "worker container absence could not be verified",
                    container_name=name, docker_error=message.strip()[:500],
                )
            if attempt < 20:
                time.sleep(0.05)
        raise ExecutionRefused(
            "worker container residue remains after teardown",
            container_name=name,
        )


__all__ = [
    "ContainedNonrootWorker", "CONTAINMENT_CHECKS", "IMAGE",
    "WORKER_UID", "WORKER_GID",
]
