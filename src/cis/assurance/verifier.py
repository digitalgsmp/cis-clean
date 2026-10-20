"""The deterministic verifier.

One frozen task contract in, one ``verification_results`` row out. The verifier
is a pure function of recorded authority: given the same ledger it returns the
same outcome, the same ``checks_performed``, the same findings and the same
``result_hash``, forever. Nothing here reads a clock, a socket, an environment
variable or a file outside the authority it was handed.

WHAT IT KNOWS NOTHING ABOUT
---------------------------

It does not know that a reviewer exists. It imports nothing from
``cis.assurance.reviewer``, its contract declares
``independence:cis.assurance.reviewer``, and the contract registry refuses to
load a contract set in which either module can reach the other through any
chain of dependencies. If a future edit made this module depend on the reviewer
— or the reviewer on it — ``python3 -m cis verify`` would fail before any test
ran.

ITS OWN INPUT PORT
------------------

``VerifierInputPort`` assembles the verifier's packet from authority and
persists it as a ``verification_inputs`` row. That row is a NEW append-only
table and not a new column on ``backend_runs``: the run ledger was written and
hashed under slice 1, and adding to it would invalidate digests that are
supposed to stand forever. The verifier links forward instead.

WHAT "SUBMITTED EVIDENCE" MEANS HERE
------------------------------------

The immutable record of the governed run the authorization produced: the
``backend_runs`` row, the ``evidence_records`` row it points at, and the
digests derivable from the validated architecture. The verifier does not
re-execute anything, and this increment has no worker that could: it verifies a
submission, which is precisely the boundary a real nonroot contained worker
will later sit behind.

FAIL CLOSED, TWO DIFFERENT WAYS
-------------------------------

A tampered task contract is an INTEGRITY failure and the verifier REFUSES: it
records no result at all, because a recorded VERIFIED_FAIL would quietly
legitimise the tampered row as a thing that was assessed. A missing, incomplete
or non-recomputing SUBMISSION is an ASSESSMENT outcome and produces a recorded
``VERIFIED_FAIL`` with a reason code, because that is a fact about the work.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from ..authority.authorization import binding_hash_of_row
from ..canonical import sha256_hex, sha256_text
from ..errors import VerificationRefused
from .authority import (
    AssuranceAuthority, VERIFIED_FAIL, VERIFIED_PASS, VERIFIER_MODULE,
)
from .execution_input import verify_row as verify_execution_input_row
from .task_contract import verify_row

#: Checks the verifier always performs, over and above a task contract's own
#: ``required_checks``. Declared, never inferred.
VERIFIER_OWN_CHECKS: tuple[str, ...] = (
    "submitted_execution_completed",
    "submitted_artifacts_present",
)

#: Every check this verifier is able to perform. A task contract that requires
#: something absent from this set is refused as unsupported rather than passed
#: on a check nobody ran.
SUPPORTED_CHECKS: frozenset[str] = frozenset({
    "task_contract_digest_recomputes",
    "authorization_binding_recomputes",
    "submitted_evidence_present",
    "submitted_evidence_digest_recomputes",
    "submitted_execution_completed",
    "submitted_artifacts_present",
    "contract_registry_valid",
    "blueprint_baseline_matches",
    "canonical_authorization_basis_present",
    "execution_input_binding_recomputes",
    "candidate_source_binding_recomputes",
    "vector_contract_binding_recomputes",
    "authorized_entrypoint_binding_recomputes",
    "worker_image_identity_recomputes",
    "trusted_runner_identity_matches_expected",
    "worker_identity_matches_expected",
    "result_classification_recorded",
})

REASON_ALL_CHECKS_COVERED = "ALL_REQUIRED_CHECKS_COVERED"
REASON_MISSING_EVIDENCE = "MISSING_SUBMITTED_EVIDENCE"
REASON_EXECUTION_NOT_COMPLETED = "SUBMITTED_EXECUTION_NOT_COMPLETED"
REASON_EVIDENCE_DIGEST_MISMATCH = "SUBMITTED_EVIDENCE_DIGEST_MISMATCH"
REASON_BINDING_MISMATCH = "AUTHORIZATION_BINDING_DOES_NOT_RECOMPUTE"
REASON_BASELINE_MOVED = "BASELINE_MOVED_SINCE_AUTHORIZATION"
REASON_NO_CANONICAL_BASIS = "NO_CANONICAL_AUTHORIZATION_BASIS"
REASON_MISSING_ARTIFACT = "REQUIRED_ARTIFACT_ABSENT"
REASON_REGISTRY_INVALID = "CONTRACT_REGISTRY_INVALID"
REASON_UNSUPPORTED_CHECK = "REQUIRED_CHECK_NOT_SUPPORTED_BY_VERIFIER"
REASON_EXECUTION_INPUT_MISSING = "EXECUTION_INPUT_BINDING_MISSING_OR_MISMATCHED"
REASON_CANDIDATE_BINDING = "CANDIDATE_SOURCE_BINDING_MISMATCH"
REASON_VECTOR_BINDING = "VECTOR_CONTRACT_BINDING_MISMATCH"
REASON_ENTRYPOINT_BINDING = "AUTHORIZED_ENTRYPOINT_BINDING_MISMATCH"
REASON_IMAGE_BINDING = "WORKER_IMAGE_IDENTITY_MISMATCH"
REASON_RUNNER_BINDING = "TRUSTED_RUNNER_IDENTITY_MISMATCH"
REASON_WORKER_BINDING = "WORKER_IDENTITY_MISMATCH"
REASON_RESULT_CLASSIFICATION = "RESULT_CLASSIFICATION_INVALID_OR_UNBOUND"

#: Which reason code a failing check reports. Ordered, so a submission that
#: fails several checks always reports the same one.
_REASON_FOR_CHECK: tuple[tuple[str, str], ...] = (
    # Preserve the established fail-closed disposition: an incomplete
    # submission is first reported as missing its declared artifact set.
    ("submitted_artifacts_present", REASON_MISSING_ARTIFACT),
    ("submitted_evidence_present", REASON_MISSING_EVIDENCE),
    ("submitted_execution_completed", REASON_EXECUTION_NOT_COMPLETED),
    ("submitted_evidence_digest_recomputes", REASON_EVIDENCE_DIGEST_MISMATCH),
    ("authorization_binding_recomputes", REASON_BINDING_MISMATCH),
    ("blueprint_baseline_matches", REASON_BASELINE_MOVED),
    ("canonical_authorization_basis_present", REASON_NO_CANONICAL_BASIS),
    ("contract_registry_valid", REASON_REGISTRY_INVALID),
    ("execution_input_binding_recomputes", REASON_EXECUTION_INPUT_MISSING),
    ("candidate_source_binding_recomputes", REASON_CANDIDATE_BINDING),
    ("vector_contract_binding_recomputes", REASON_VECTOR_BINDING),
    ("authorized_entrypoint_binding_recomputes", REASON_ENTRYPOINT_BINDING),
    ("worker_image_identity_recomputes", REASON_IMAGE_BINDING),
    ("trusted_runner_identity_matches_expected", REASON_RUNNER_BINDING),
    ("worker_identity_matches_expected", REASON_WORKER_BINDING),
    ("result_classification_recorded", REASON_RESULT_CLASSIFICATION),
)

_ATTESTATION_BINDING_BASE_KEYS = frozenset({
    "attestation_sha256", "result_hash", "result_record_sha256"})
_ATTESTATION_BINDING_WITH_USAGE_KEYS = (
    _ATTESTATION_BINDING_BASE_KEYS | {"usage"})
_USAGE_KEYS = frozenset({"wall_time_ms", "tokens_used", "cost_micros"})


def _usage_is_valid(usage: Any) -> bool:
    """Mirror the exact usage validation applied elsewhere to this same
    gateway-bound mapping, so the verifier accepts only what a real
    measurement can look like."""
    return (
        isinstance(usage, Mapping)
        and set(usage) == _USAGE_KEYS
        and all(isinstance(value, int) and not isinstance(value, bool)
                and value >= 0 for value in usage.values())
    )


_ATTESTATION_KEYS = frozenset({
    "schema", "operation", "adapter", "image", "worker_operation",
    "execution_input_hash", "task_contract_id", "task_contract_hash",
    "entrypoint", "verdict", "classification", "attestation_valid",
    "attestation_failures", "worker_exit", "source_sha256",
    "vector_contract_sha256", "task_contract_bundle_sha256",
    "authorization_binding_hash", "trusted_runner_sha256", "worker_sha256",
    "declared_vectors", "allowed_scope", "forbidden_actions", "stopped_at",
    "returned_to",
})


def _parse_attestation(evidence: Mapping[str, Any] | None,
                       run: Mapping[str, Any] | None) -> dict[str, str] | None:
    """Parse only the adapter's closed, unique key/value attestation schema."""
    if evidence is None:
        return None
    text = evidence.get("original_language")
    if not isinstance(text, str) or not text:
        return None
    try:
        binding = json.loads(str(evidence["content"]))
    except (KeyError, TypeError, ValueError):
        return None
    if not isinstance(binding, dict):
        return None
    keys = set(binding)
    if keys == _ATTESTATION_BINDING_WITH_USAGE_KEYS:
        if not _usage_is_valid(binding["usage"]):
            return None
    elif keys != _ATTESTATION_BINDING_BASE_KEYS:
        return None
    if (binding["attestation_sha256"] != sha256_text(text)
            or run is None
            or binding["result_hash"] != str(run["result_hash"])):
        return None
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or key in parsed:
            return None
        parsed[key] = value.strip()
    if set(parsed) != _ATTESTATION_KEYS:
        return None
    return parsed


@dataclass(frozen=True)
class VerifierPacket:
    """The verifier's assembled, hashable input facts."""

    task_contract: Mapping[str, Any]
    authorization: Mapping[str, Any] | None
    run: Mapping[str, Any] | None
    evidence: Mapping[str, Any] | None
    execution_input: Mapping[str, Any] | None
    attestation: Mapping[str, str] | None
    artifacts: Mapping[str, Any]
    recomputed_task_contract_hash: str
    recomputed_binding_hash: str | None
    recomputed_execution_input_hash: str | None

    @property
    def input_id(self) -> str:
        suffix = sha256_hex({
            "task_contract_id": self.task_contract["task_contract_id"],
            "run_id": self.run["run_id"] if self.run else None,
            "evidence_id": self.evidence["evidence_id"] if self.evidence else None,
            "artifacts": dict(self.artifacts),
        })[:12]
        return f"vin-{suffix}"


class VerifierInputPort:
    """Assembles the verifier's packet from authority. Appends one input row.

    Separate from the assessment on purpose: the assessment is a pure function
    of the packet, so it can be tested without a store and cannot acquire a
    hidden input.
    """

    def __init__(self, *, store, blueprint, authority: AssuranceAuthority) -> None:
        self._store = store
        self._blueprint = blueprint
        self._authority = authority

    def assemble(self, task_contract_id: str) -> VerifierPacket:
        contract = self._authority.ledger.require_task_contract(task_contract_id)

        # Integrity first. A tampered contract is never assessed.
        recomputed_task_contract_hash = verify_row(contract)

        authorization = self._store.one(
            "SELECT * FROM execution_authorizations WHERE authorization_id = ?",
            (str(contract["authorization_id"]),),
        )
        recomputed_binding = None
        if authorization is not None:
            recomputed_binding = binding_hash_of_row(authorization)

        run = self._store.one(
            "SELECT * FROM backend_runs WHERE authorization_id = ? ORDER BY seq",
            (str(contract["authorization_id"]),),
        )
        evidence = None
        if run is not None and run["evidence_id"] is not None:
            evidence = self._store.one(
                "SELECT * FROM evidence_records WHERE evidence_id = ?",
                (str(run["evidence_id"]),),
            )

        execution_input = self._store.one(
            "SELECT * FROM task_execution_inputs WHERE task_contract_id = ?",
            (task_contract_id,),
        )
        recomputed_execution_input_hash = None
        if execution_input is not None:
            # Like task-contract corruption, authority corruption is refused,
            # never legitimised as a VERIFIED_FAIL assessment.
            recomputed_execution_input_hash = verify_execution_input_row(
                execution_input)
        attestation = _parse_attestation(
            evidence.as_dict() if evidence else None,
            run.as_dict() if run else None)

        artifacts = self._artifacts(contract, run, evidence, attestation)
        return VerifierPacket(
            task_contract=contract.as_dict(),
            authorization=authorization.as_dict() if authorization else None,
            run=run.as_dict() if run else None,
            evidence=evidence.as_dict() if evidence else None,
            execution_input=(execution_input.as_dict()
                             if execution_input else None),
            attestation=attestation,
            artifacts=artifacts,
            recomputed_task_contract_hash=recomputed_task_contract_hash,
            recomputed_binding_hash=recomputed_binding,
            recomputed_execution_input_hash=recomputed_execution_input_hash,
        )

    def _artifacts(self, contract, run, evidence, attestation) -> dict:
        """The declared artifacts, each present or explicitly absent."""
        target = str(contract["target_module_id"])
        module_contract_hash = None
        if target in self._blueprint.registry.contracts:
            module_contract_hash = self._blueprint.registry.get(
                target).contract_hash
        return {
            "execution_evidence": (
                str(evidence["content_hash"]) if evidence else None
            ),
            "run_result_hash": str(run["result_hash"]) if run else None,
            "module_contract_hash": module_contract_hash,
            "execution_input_hash": (
                attestation.get("execution_input_hash") if attestation else None
            ),
            "candidate_source_sha256": (
                attestation.get("source_sha256") if attestation else None
            ),
            "vector_contract_sha256": (
                attestation.get("vector_contract_sha256")
                if attestation else None
            ),
        }

    def persist(self, packet: VerifierPacket):
        """Append the packet as a ``verification_inputs`` row."""
        return self._authority.verifier.record_inputs(
            input_id=packet.input_id,
            task_contract_id=str(packet.task_contract["task_contract_id"]),
            submitted_run_id=(
                str(packet.run["run_id"]) if packet.run else None
            ),
            submitted_evidence_id=(
                str(packet.evidence["evidence_id"]) if packet.evidence else None
            ),
            submitted_artifacts=packet.artifacts,
            recomputed_task_contract_hash=packet.recomputed_task_contract_hash,
            recomputed_binding_hash=packet.recomputed_binding_hash or "",
        )


def assess(packet: VerifierPacket, *, baseline_hash: str,
           canonical_basis_present: bool, registry_valid: bool) -> dict:
    """The deterministic assessment. A pure function of its arguments.

    Returns ``{"outcome", "reason_code", "checks_performed", "findings"}``.
    """
    contract = packet.task_contract
    required = set(json.loads(str(contract["required_checks_json"])))
    unsupported = sorted(required - SUPPORTED_CHECKS)

    performed = sorted(required | set(VERIFIER_OWN_CHECKS))
    results: dict[str, bool] = {}
    detail: dict[str, Any] = {}

    results["task_contract_digest_recomputes"] = (
        packet.recomputed_task_contract_hash
        == str(contract["task_contract_hash"])
    )
    results["authorization_binding_recomputes"] = bool(
        packet.authorization is not None
        and packet.recomputed_binding_hash is not None
        and packet.recomputed_binding_hash
        == str(packet.authorization["binding_hash"])
        and packet.recomputed_binding_hash
        == str(contract["authorization_binding_hash"])
    )
    results["submitted_evidence_present"] = bool(
        packet.run is not None and packet.evidence is not None
    )
    results["submitted_execution_completed"] = bool(
        packet.run is not None
        and str(packet.run["status"]) == "completed"
        and int(packet.run["exit_code"]) == 0
    )
    if packet.evidence is None:
        results["submitted_evidence_digest_recomputes"] = False
    else:
        recomputed = sha256_text(str(packet.evidence["content"]))
        results["submitted_evidence_digest_recomputes"] = (
            recomputed == str(packet.evidence["content_hash"])
        )
        detail["evidence_digest"] = recomputed

    declared_artifacts = json.loads(str(contract["required_artifacts_json"]))
    absent = sorted(
        name for name in declared_artifacts
        if not packet.artifacts.get(name)
    )
    results["submitted_artifacts_present"] = not absent
    detail["absent_artifacts"] = absent

    results["blueprint_baseline_matches"] = bool(
        packet.authorization is not None
        and str(packet.authorization["baseline_hash"]) == baseline_hash
    )
    results["canonical_authorization_basis_present"] = bool(
        canonical_basis_present)
    results["contract_registry_valid"] = bool(registry_valid)

    exi = packet.execution_input
    attestation = packet.attestation
    results["execution_input_binding_recomputes"] = bool(
        exi is not None
        and packet.recomputed_execution_input_hash is not None
        and packet.recomputed_execution_input_hash
        == str(exi["execution_input_hash"])
        and str(exi["task_contract_id"]) == str(contract["task_contract_id"])
        and str(exi["task_contract_hash"]) == str(contract["task_contract_hash"])
        and str(exi["authorization_binding_hash"])
        == str(contract["authorization_binding_hash"])
        and attestation is not None
        and attestation["execution_input_hash"]
        == str(exi["execution_input_hash"])
        and attestation["task_contract_id"] == str(contract["task_contract_id"])
        and attestation["task_contract_hash"] == str(contract["task_contract_hash"])
        and attestation["authorization_binding_hash"]
        == str(contract["authorization_binding_hash"])
    )
    results["candidate_source_binding_recomputes"] = bool(
        exi is not None and attestation is not None
        and attestation["source_sha256"] == str(exi["candidate_sha256"])
    )
    results["vector_contract_binding_recomputes"] = bool(
        exi is not None and attestation is not None
        and attestation["vector_contract_sha256"]
        == str(exi["vector_contract_sha256"])
    )
    results["authorized_entrypoint_binding_recomputes"] = bool(
        exi is not None and attestation is not None
        and attestation["entrypoint"] == str(exi["authorized_entrypoint"])
    )
    results["worker_image_identity_recomputes"] = bool(
        exi is not None and attestation is not None
        and attestation["image"] == str(exi["worker_image"])
    )
    results["trusted_runner_identity_matches_expected"] = bool(
        exi is not None and attestation is not None
        and attestation["trusted_runner_sha256"]
        == str(exi["expected_trusted_runner_sha256"])
    )
    results["worker_identity_matches_expected"] = bool(
        exi is not None and attestation is not None
        and attestation["worker_sha256"]
        == str(exi["expected_worker_sha256"])
    )
    closed_result = {
        "SOURCE_PASS": ("SOURCE_PASS", "completed", 0, 0, "true", "none"),
        "SOURCE_FAIL": ("SOURCE_FAIL", "failed", 1, 1, "true", "none"),
        "HARNESS_FAILURE": (
            "HARNESS_FAILURE", "failed", 2, None, "false", None),
        "RESOURCE_EXHAUSTION": (
            "HARNESS_FAILURE", "failed", 3, 124, "false", None),
    }
    classification = (attestation.get("classification")
                      if attestation else None)
    expected_result = closed_result.get(classification)
    result_binding = False
    if (attestation is not None and packet.run is not None
            and expected_result is not None):
        verdict, status, exit_code, worker_exit, valid, failures = expected_result
        try:
            observed_worker_exit = int(attestation["worker_exit"])
        except ValueError:
            observed_worker_exit = -999
        result_binding = bool(
            attestation["schema"] == "cis-contained-adapter-attestation-v1"
            and attestation["operation"] == "verify_authored_source"
            and attestation["worker_operation"] == "verify-authored-source"
            and attestation["verdict"] == verdict
            and str(packet.run["status"]) == status
            and int(packet.run["exit_code"]) == exit_code
            and attestation["attestation_valid"] == valid
            and (worker_exit is None or observed_worker_exit == worker_exit)
            and (failures is None
                 or attestation["attestation_failures"] == failures)
        )
    results["result_classification_recorded"] = result_binding

    findings = [
        {"check": name, "passed": bool(results.get(name, False)),
         "supported": name in SUPPORTED_CHECKS}
        for name in performed
    ]
    if absent:
        findings.append({"check": "submitted_artifacts_present",
                         "absent_artifacts": absent, "passed": False,
                         "supported": True})

    if unsupported:
        return {
            "outcome": VERIFIED_FAIL,
            "reason_code": REASON_UNSUPPORTED_CHECK,
            "checks_performed": performed,
            "findings": findings + [{"check": "verifier_supports_required_checks",
                                     "passed": False, "supported": False,
                                     "unsupported": unsupported}],
        }

    # Failure precedence is explicit rather than an accidental consequence of
    # alphabetically sorting check names. This keeps a missing/malformed
    # submission from masquerading as a more specific binding mismatch.
    ordered_failures = [
        (name, reason) for name, reason in _REASON_FOR_CHECK
        if name in performed and not results.get(name, False)
    ]
    ordered_failures.extend(
        (name, REASON_MISSING_EVIDENCE) for name in performed
        if not results.get(name, False)
        and name not in {check for check, _ in _REASON_FOR_CHECK}
    )
    for name, reason in ordered_failures:
            return {
                "outcome": VERIFIED_FAIL,
                "reason_code": reason,
                "checks_performed": performed,
                "findings": findings,
            }

    return {
        "outcome": VERIFIED_PASS,
        "reason_code": REASON_ALL_CHECKS_COVERED,
        "checks_performed": performed,
        "findings": findings,
    }


class Verifier:
    """The verifier module's whole public surface: ``verify``.

    Constructed from a store and a blueprint, like every other Layer-2 module
    in this environment. It builds its own ``AssuranceAuthority`` handle and
    uses ONLY the verifier facade; the reviewer and promotion facades are not
    referenced anywhere in this file.
    """

    module_id = VERIFIER_MODULE

    def __init__(self, store, blueprint,
                 authority: AssuranceAuthority | None = None) -> None:
        self._store = store
        self._blueprint = blueprint
        self._authority = (authority if authority is not None
                           else AssuranceAuthority(store))
        self.inputs = VerifierInputPort(
            store=store, blueprint=blueprint, authority=self._authority)

    @staticmethod
    def result_id(task_contract_id: str, input_id: str) -> str:
        suffix = sha256_hex({"task_contract_id": task_contract_id,
                             "input_id": input_id})[:12]
        return f"vres-{suffix}"

    def verify(self, task_contract_id: str):
        """Verify one frozen task contract, or refuse.

        Idempotent: a task contract whose verification is already recorded
        returns that recorded row rather than appending a second, because the
        submitted evidence is immutable and a second verification could only
        restate the first.
        """
        existing = self._authority.ledger.verification_result(task_contract_id)
        if existing is not None:
            return existing

        packet = self.inputs.assemble(task_contract_id)
        input_row = self.inputs.persist(packet)

        target = str(packet.task_contract["target_module_id"])
        try:
            self._blueprint.registry.validate()
            registry_valid = True
        except Exception:  # pragma: no cover - the loaded registry is valid
            registry_valid = False
        basis = self._blueprint.canonical_authorization_basis(target)

        assessment = assess(
            packet,
            baseline_hash=self._blueprint.baseline_hash,
            canonical_basis_present=basis is not None,
            registry_valid=registry_valid,
        )
        if assessment["outcome"] not in (VERIFIED_PASS, VERIFIED_FAIL):
            raise VerificationRefused(  # pragma: no cover - closed vocabulary
                "assessment produced an outcome outside the vocabulary",
                outcome=assessment["outcome"],
            )
        return self._authority.verifier.record_result(
            result_id=self.result_id(task_contract_id,
                                     str(input_row["input_id"])),
            task_contract_id=task_contract_id,
            input_id=str(input_row["input_id"]),
            outcome=assessment["outcome"],
            reason_code=assessment["reason_code"],
            checks_performed=assessment["checks_performed"],
            findings=assessment["findings"],
        )
