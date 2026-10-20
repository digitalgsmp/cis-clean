"""The independent reviewer.

Author is not verifier, and verifier is not reviewer (ADR-ARCH-004 clause 5).
This module is the second half of that rule, and its independence is
structural rather than asserted:

  * it imports NOTHING from ``cis.assurance.verifier`` — not the input port,
    not the packet, not the assessment, not a constant;
  * its contract declares ``independence:cis.assurance.verifier`` and the
    verifier's contract declares ``independence:cis.assurance.reviewer``, and
    ``ContractRegistry`` refuses to load a set in which either module reaches
    the other through ANY chain of dependencies;
  * it assembles its OWN packet from authority through its own input port,
    rather than reading the ``verification_inputs`` row the verifier assembled
    as if that were the evidence;
  * it RECOMPUTES every digest it relies on — the task contract, authorization,
    verification input, verification result, execution input and evidence —
    and refuses to review anything whose recorded digest does not recompute;
  * for authored source, it independently parses the closed worker attestation
    and binds it to the exact candidate, vectors, entrypoint, apparatus, run and
    verifier-input packet before it can return PASS.

WHAT A CYCLE IS IN THIS INCREMENT
---------------------------------

Review cycles 1 to 3 are BOUNDED REVIEW AND RECOVERY DECISIONS OVER IMMUTABLE
SUBMITTED EVIDENCE. The submission does not change between cycles, and nothing
in this increment can change it: there is no worker here that could produce a
revised submission or execute a replacement candidate. Each cycle therefore
records what the reviewer decided to ask for, and records in authority — in
``objection_cycles.replacement_execution_wiring`` — that the execution of that
request belongs with a separately authorized contained-worker execution. This
module reviews but cannot itself execute remediation.

Because the evidence is immutable and the assessment is deterministic, a
submission that draws objections draws them again on cycle 2 and cycle 3, and
the third cycle escalates. That is the honest behaviour of a bounded review
loop with no remediation path yet, and it is exactly what makes a FOURTH cycle
unnecessary as well as impossible.

THE FOURTH CYCLE
----------------

``review`` refuses with ``ObjectionCyclesExhausted`` once three cycles stand
recorded — before it assembles a packet, before it touches the ledger. That is
the API level of the three-level bound; ``AssuranceAuthority`` holds the ledger
level and migration 0004 holds the SQL level.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from ..authority.authorization import binding_hash_of_row
from ..canonical import sha256_hex, sha256_text
from ..errors import ObjectionCyclesExhausted, ReviewRefused
from .authority import (
    AssuranceAuthority, MAX_OBJECTION_CYCLES, RECOVERY_ESCALATE,
    RECOVERY_REPLACEMENT_CANDIDATE, RECOVERY_REVISED_SUBMISSION, REVIEW_OBJECTIONS,
    REVIEW_PASS, VERIFIED_PASS, verification_result_hash_of_row,
)
from .execution_input import verify_row as verify_execution_input_row
from .task_contract import verify_row

#: The reviewer's declared lineage. A separate lineage from the author and from
#: the verifier is the point of the rule, so it is recorded on every review
#: rather than left implicit.
REVIEWER_LINEAGE = "cis.assurance.reviewer/independent_lineage_v1"

REASON_REVIEW_PASS = "SUBMISSION_AND_VERIFICATION_BOTH_STAND"
REASON_VERIFICATION_DID_NOT_PASS = "VERIFICATION_DID_NOT_PASS"
REASON_ARTIFACTS_INCOMPLETE = "DECLARED_ARTIFACTS_INCOMPLETE"
REASON_NO_REVISED_SUBMISSION = "NO_REVISED_SUBMISSION_AVAILABLE"
REASON_BINDING_FAILED = "INDEPENDENT_CANDIDATE_EVIDENCE_BINDING_FAILED"

#: An objection a reviewer can raise, as a closed vocabulary.
OBJECTION_VERIFICATION_FAILED = "VERIFICATION_OUTCOME_IS_NOT_A_PASS"
OBJECTION_ARTIFACT_ABSENT = "DECLARED_ARTIFACT_ABSENT_FROM_SUBMISSION"
OBJECTION_PRIOR_REQUEST_UNMET = "PRIOR_CYCLE_REQUEST_REMAINS_UNMET"
OBJECTION_BINDING_FAILED = "CANDIDATE_OR_EVIDENCE_BINDING_DID_NOT_RECOMPUTE"

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

_ATTESTATION_BINDING_BASE_KEYS = frozenset({
    "attestation_sha256", "result_hash", "result_record_sha256"})
_ATTESTATION_BINDING_WITH_USAGE_KEYS = (
    _ATTESTATION_BINDING_BASE_KEYS | {"usage"})
_USAGE_KEYS = frozenset({"wall_time_ms", "tokens_used", "cost_micros"})


def _usage_is_valid(usage: Any) -> bool:
    """Independently validate the optional gateway usage mapping: exact
    keys, and values that are ints (never bools) that are not negative."""
    return (
        isinstance(usage, Mapping)
        and set(usage) == _USAGE_KEYS
        and all(isinstance(value, int) and not isinstance(value, bool)
                and value >= 0 for value in usage.values())
    )


def _verification_input_hash(row: Mapping[str, Any]) -> str:
    return sha256_hex({
        "__hash_domain__": "cis.assurance.verification_inputs.v1",
        "input_id": str(row["input_id"]),
        "task_contract_id": str(row["task_contract_id"]),
        "submitted_run_id": row["submitted_run_id"],
        "submitted_evidence_id": row["submitted_evidence_id"],
        "submitted_artifacts": json.loads(
            str(row["submitted_artifacts_json"])),
        "recomputed_task_contract_hash": str(
            row["recomputed_task_contract_hash"]),
        "recomputed_binding_hash": str(row["recomputed_binding_hash"]),
        "assembled_by": str(row["assembled_by"]),
    })


def _parse_attestation(evidence: Mapping[str, Any] | None,
                       run: Mapping[str, Any] | None) -> dict[str, str] | None:
    """Independent parser; no verifier code or verifier packet is reused."""
    if evidence is None or run is None:
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
            or binding["result_hash"] != str(run["result_hash"])):
        return None
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or key in parsed:
            return None
        parsed[key] = value.strip()
    return parsed if set(parsed) == _ATTESTATION_KEYS else None


@dataclass(frozen=True)
class ReviewPacket:
    """The reviewer's independently assembled review packet.

    It carries the reviewer's OWN recomputations, not the verifier's. A field
    named ``recorded_*`` is what authority says; a field named ``recomputed_*``
    is what the reviewer derived for itself.
    """

    task_contract: Mapping[str, Any]
    authorization: Mapping[str, Any]
    run: Mapping[str, Any] | None
    evidence: Mapping[str, Any] | None
    verification_input: Mapping[str, Any]
    execution_input: Mapping[str, Any] | None
    attestation: Mapping[str, str] | None
    verification: Mapping[str, Any]
    prior_cycles: tuple[Mapping[str, Any], ...]
    cycle_index: int
    recomputed_task_contract_hash: str
    recomputed_binding_hash: str
    recomputed_verification_result_hash: str
    recomputed_evidence_digest: str | None
    recomputed_verification_input_hash: str
    recomputed_execution_input_hash: str | None
    binding_failures: tuple[str, ...]

    def payload(self) -> dict:
        return {
            "__hash_domain__": "cis.assurance.review_packet.v1",
            "task_contract_id": self.task_contract["task_contract_id"],
            "authorization_id": self.authorization["authorization_id"],
            "run_id": self.run["run_id"] if self.run else None,
            "evidence_id": (self.evidence["evidence_id"]
                            if self.evidence else None),
            "verification_result_id": self.verification["result_id"],
            "verification_input_id": self.verification_input["input_id"],
            "execution_input_hash": self.recomputed_execution_input_hash,
            "cycle_index": self.cycle_index,
            "prior_cycle_numbers": [int(c["cycle_number"])
                                    for c in self.prior_cycles],
            "prior_recovery_decisions": [str(c["recovery_decision"])
                                         for c in self.prior_cycles],
            "recomputed_task_contract_hash": self.recomputed_task_contract_hash,
            "recomputed_binding_hash": self.recomputed_binding_hash,
            "recomputed_verification_result_hash":
                self.recomputed_verification_result_hash,
            "recomputed_evidence_digest": self.recomputed_evidence_digest,
            "recomputed_verification_input_hash":
                self.recomputed_verification_input_hash,
            "binding_failures": list(self.binding_failures),
        }

    @property
    def packet_hash(self) -> str:
        return sha256_hex(self.payload())

    @property
    def review_id(self) -> str:
        suffix = sha256_hex({
            "task_contract_id": self.task_contract["task_contract_id"],
            "cycle_index": self.cycle_index,
            "packet_hash": self.packet_hash,
        })[:12]
        return f"rev-{suffix}"


class ReviewerInputPort:
    """The reviewer's own path to authority.

    It reads the same append-only tables the verifier reads, and it reads them
    itself. It never calls the verifier, never imports it, and never treats a
    ``verification_inputs`` row as the submission: that row is the verifier's
    account of what it looked at, which is a thing to check rather than a thing
    to trust.
    """

    def __init__(self, *, store, blueprint, authority: AssuranceAuthority) -> None:
        self._store = store
        self._blueprint = blueprint
        self._authority = authority

    def assemble(self, task_contract_id: str, *, cycle_index: int) -> ReviewPacket:
        ledger = self._authority.ledger
        contract = ledger.require_task_contract(task_contract_id)

        # The reviewer's own integrity check, from its own code path.
        recomputed_task_contract_hash = verify_row(contract)

        authorization = self._store.one(
            "SELECT * FROM execution_authorizations WHERE authorization_id = ?",
            (str(contract["authorization_id"]),),
        )
        if authorization is None:
            raise ReviewRefused(
                "the task contract's authorization is absent from authority",
                task_contract_id=task_contract_id,
                authorization_id=str(contract["authorization_id"]),
            )
        recomputed_binding = binding_hash_of_row(authorization)
        if recomputed_binding != str(authorization["binding_hash"]):
            raise ReviewRefused(
                "the authorization binding does not recompute, so there is "
                "nothing a review could honestly be about",
                task_contract_id=task_contract_id,
                recorded=str(authorization["binding_hash"]),
                recomputed=recomputed_binding,
            )
        if recomputed_binding != str(contract["authorization_binding_hash"]):
            raise ReviewRefused(
                "the task contract links to a binding that is not the "
                "authorization's own",
                task_contract_id=task_contract_id,
                recorded=str(contract["authorization_binding_hash"]),
                recomputed=recomputed_binding,
            )

        verification = ledger.verification_result(task_contract_id)
        if verification is None:
            raise ReviewRefused(
                "there is no verification result to review; the declared flow "
                "is FROZEN -> VERIFIED_PASS/VERIFIED_FAIL -> PASS/OBJECTIONS",
                task_contract_id=task_contract_id,
            )
        recomputed_verification = verification_result_hash_of_row(verification)
        if recomputed_verification != str(verification["result_hash"]):
            raise ReviewRefused(
                "the recorded verification digest does not recompute from its "
                "own source fields",
                task_contract_id=task_contract_id,
                recorded=str(verification["result_hash"]),
                recomputed=recomputed_verification,
            )

        verification_input = ledger.verification_input(task_contract_id)
        if verification_input is None:
            raise ReviewRefused(
                "the verification result has no recorded input packet",
                task_contract_id=task_contract_id)
        if str(verification_input["input_id"]) != str(verification["input_id"]):
            raise ReviewRefused(
                "the verification result does not cite this task's input packet",
                task_contract_id=task_contract_id)
        recomputed_verification_input = _verification_input_hash(
            verification_input)
        if recomputed_verification_input != str(verification_input["inputs_hash"]):
            raise ReviewRefused(
                "the verifier input packet does not recompute from its own fields",
                task_contract_id=task_contract_id,
                recorded=str(verification_input["inputs_hash"]),
                recomputed=recomputed_verification_input)

        run = self._store.one(
            "SELECT * FROM backend_runs WHERE authorization_id = ? ORDER BY seq",
            (str(contract["authorization_id"]),),
        )
        evidence = None
        recomputed_evidence_digest = None
        if run is not None and run["evidence_id"] is not None:
            evidence = self._store.one(
                "SELECT * FROM evidence_records WHERE evidence_id = ?",
                (str(run["evidence_id"]),),
            )
        if evidence is not None:
            recomputed_evidence_digest = sha256_text(str(evidence["content"]))
            if recomputed_evidence_digest != str(evidence["content_hash"]):
                raise ReviewRefused(
                    "submitted evidence does not recompute its own digest",
                    task_contract_id=task_contract_id,
                    evidence_id=str(evidence["evidence_id"]),
                )

        execution_input = self._store.one(
            "SELECT * FROM task_execution_inputs WHERE task_contract_id = ?",
            (task_contract_id,),
        )
        recomputed_execution_input = None
        if execution_input is not None:
            recomputed_execution_input = verify_execution_input_row(
                execution_input)
        run_dict = run.as_dict() if run else None
        evidence_dict = evidence.as_dict() if evidence else None
        attestation = _parse_attestation(evidence_dict, run_dict)
        binding_failures = self._binding_failures(
            contract=contract, authorization=authorization,
            verification_input=verification_input, run=run,
            evidence=evidence, execution_input=execution_input,
            attestation=attestation)

        return ReviewPacket(
            task_contract=contract.as_dict(),
            authorization=authorization.as_dict(),
            run=run_dict,
            evidence=evidence_dict,
            verification_input=verification_input.as_dict(),
            execution_input=(execution_input.as_dict()
                             if execution_input else None),
            attestation=attestation,
            verification=verification.as_dict(),
            prior_cycles=tuple(row.as_dict()
                               for row in ledger.objection_cycles(task_contract_id)),
            cycle_index=cycle_index,
            recomputed_task_contract_hash=recomputed_task_contract_hash,
            recomputed_binding_hash=recomputed_binding,
            recomputed_verification_result_hash=recomputed_verification,
            recomputed_evidence_digest=recomputed_evidence_digest,
            recomputed_verification_input_hash=recomputed_verification_input,
            recomputed_execution_input_hash=recomputed_execution_input,
            binding_failures=tuple(binding_failures),
        )

    @staticmethod
    def _binding_failures(*, contract, authorization, verification_input,
                          run, evidence, execution_input,
                          attestation) -> list[str]:
        """Independently bind authored-source review to the exact submission."""
        if str(contract["template_id"]) != "verify_authored_source.v1":
            return []
        failures: list[str] = []
        if execution_input is None:
            return ["execution_input_missing"]
        if attestation is None:
            return ["closed_attestation_missing_or_invalid"]

        expected = {
            "schema": "cis-contained-adapter-attestation-v1",
            "operation": "verify_authored_source",
            "worker_operation": "verify-authored-source",
            "execution_input_hash": str(execution_input["execution_input_hash"]),
            "task_contract_id": str(contract["task_contract_id"]),
            "task_contract_hash": str(contract["task_contract_hash"]),
            "authorization_binding_hash": str(authorization["binding_hash"]),
            "entrypoint": str(execution_input["authorized_entrypoint"]),
            "image": str(execution_input["worker_image"]),
            "source_sha256": str(execution_input["candidate_sha256"]),
            "vector_contract_sha256": str(
                execution_input["vector_contract_sha256"]),
            "trusted_runner_sha256": str(
                execution_input["expected_trusted_runner_sha256"]),
            "worker_sha256": str(execution_input["expected_worker_sha256"]),
            "stopped_at": str(authorization["stopping_condition"]),
            "returned_to": str(authorization["return_point"]),
            "allowed_scope": ",".join(sorted(json.loads(
                str(authorization["allowed_scope_json"])))),
            "forbidden_actions": ",".join(sorted(json.loads(
                str(authorization["forbidden_actions_json"])))),
            "verdict": "SOURCE_PASS",
            "classification": "SOURCE_PASS",
            "attestation_valid": "true",
            "attestation_failures": "none",
            "worker_exit": "0",
        }
        if run is not None:
            expected["adapter"] = str(run["adapter_id"])
        for key, value in expected.items():
            if attestation.get(key) != value:
                failures.append(f"{key}_mismatch")
        if run is None or str(run["status"]) != "completed" or int(
                run["exit_code"]) != 0:
            failures.append("run_result_not_source_pass")
        try:
            vectors = json.loads(bytes(
                execution_input["vector_contract"]).decode("utf-8"))
            declared_vectors = int(attestation["declared_vectors"])
        except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            failures.append("declared_vectors_invalid")
        else:
            if not isinstance(vectors, list) or declared_vectors != len(vectors):
                failures.append("declared_vectors_mismatch")

        submitted = json.loads(str(
            verification_input["submitted_artifacts_json"]))
        independently_assembled = {
            "execution_evidence": (str(evidence["content_hash"])
                                   if evidence else None),
            "run_result_hash": str(run["result_hash"]) if run else None,
            "execution_input_hash": attestation["execution_input_hash"],
            "candidate_source_sha256": attestation["source_sha256"],
            "vector_contract_sha256": attestation["vector_contract_sha256"],
        }
        for name, value in independently_assembled.items():
            if submitted.get(name) != value:
                failures.append(f"verifier_input_{name}_mismatch")
        if (verification_input["submitted_run_id"]
                != (run["run_id"] if run else None)):
            failures.append("verifier_input_run_mismatch")
        if (verification_input["submitted_evidence_id"]
                != (evidence["evidence_id"] if evidence else None)):
            failures.append("verifier_input_evidence_mismatch")
        if str(verification_input["recomputed_task_contract_hash"]) != str(
                contract["task_contract_hash"]):
            failures.append("verifier_input_task_contract_hash_mismatch")
        if str(verification_input["recomputed_binding_hash"]) != str(
                authorization["binding_hash"]):
            failures.append("verifier_input_authorization_binding_mismatch")
        return sorted(set(failures))

    def submitted_artifacts(self, packet: ReviewPacket) -> dict:
        """The reviewer's own reading of which declared artifacts are present.

        Derived from the run and evidence rows directly, not copied from the
        verifier's ``submitted_artifacts_json``.
        """
        target = str(packet.task_contract["target_module_id"])
        module_contract_hash = None
        if target in self._blueprint.registry.contracts:
            module_contract_hash = self._blueprint.registry.get(
                target).contract_hash
        return {
            "execution_evidence": (
                str(packet.evidence["content_hash"]) if packet.evidence else None
            ),
            "run_result_hash": (
                str(packet.run["result_hash"]) if packet.run else None
            ),
            "module_contract_hash": module_contract_hash,
            "execution_input_hash": (
                packet.attestation.get("execution_input_hash")
                if packet.attestation else None),
            "candidate_source_sha256": (
                packet.attestation.get("source_sha256")
                if packet.attestation else None),
            "vector_contract_sha256": (
                packet.attestation.get("vector_contract_sha256")
                if packet.attestation else None),
        }


def assess(packet: ReviewPacket, artifacts: Mapping[str, Any]) -> dict:
    """The reviewer's deterministic judgement. A pure function.

    Returns ``{"outcome", "reason_code", "objections", "recovery_decision"}``.
    ``recovery_decision`` is ``None`` on a PASS.
    """
    objections: list[dict] = []

    if str(packet.verification["outcome"]) != VERIFIED_PASS:
        objections.append({
            "objection": OBJECTION_VERIFICATION_FAILED,
            "detail": {"verification_outcome": str(packet.verification["outcome"]),
                       "verification_reason_code":
                           str(packet.verification["reason_code"])},
        })

    if packet.binding_failures:
        objections.append({
            "objection": OBJECTION_BINDING_FAILED,
            "detail": {"failures": list(packet.binding_failures)},
        })

    declared = json.loads(str(packet.task_contract["required_artifacts_json"]))
    absent = sorted(name for name in declared if not artifacts.get(name))
    if absent:
        objections.append({
            "objection": OBJECTION_ARTIFACT_ABSENT,
            "detail": {"absent": absent},
        })

    if packet.prior_cycles and objections:
        # The submission is immutable, so a request made in an earlier cycle
        # cannot have been met inside this increment. Say so explicitly rather
        # than letting an unchanged objection look like a new finding.
        objections.append({
            "objection": OBJECTION_PRIOR_REQUEST_UNMET,
            "detail": {
                "prior_cycle_numbers": [int(c["cycle_number"])
                                        for c in packet.prior_cycles],
                "why": "submitted evidence is immutable and this increment "
                       "has no contained worker to produce a revised "
                       "submission or execute a replacement candidate",
            },
        })

    if not objections:
        return {
            "outcome": REVIEW_PASS,
            "reason_code": REASON_REVIEW_PASS,
            "objections": [],
            "recovery_decision": None,
        }

    cycle_number = packet.cycle_index + 1
    if cycle_number >= MAX_OBJECTION_CYCLES:
        recovery = RECOVERY_ESCALATE
    elif any(o["objection"] == OBJECTION_ARTIFACT_ABSENT for o in objections):
        recovery = RECOVERY_REVISED_SUBMISSION
    else:
        recovery = RECOVERY_REPLACEMENT_CANDIDATE

    if any(o["objection"] == OBJECTION_BINDING_FAILED for o in objections):
        reason = REASON_BINDING_FAILED
    elif any(o["objection"] == OBJECTION_ARTIFACT_ABSENT for o in objections):
        reason = REASON_ARTIFACTS_INCOMPLETE
    elif packet.prior_cycles:
        reason = REASON_NO_REVISED_SUBMISSION
    else:
        reason = REASON_VERIFICATION_DID_NOT_PASS

    return {
        "outcome": REVIEW_OBJECTIONS,
        "reason_code": reason,
        "objections": objections,
        "recovery_decision": recovery,
    }


class Reviewer:
    """The reviewer module's whole public surface: ``review``."""

    module_id = "cis.assurance.reviewer"
    lineage = REVIEWER_LINEAGE

    def __init__(self, store, blueprint,
                 authority: AssuranceAuthority | None = None, *,
                 lineage: str = REVIEWER_LINEAGE) -> None:
        self._store = store
        self._blueprint = blueprint
        self._authority = (authority if authority is not None
                           else AssuranceAuthority(store))
        self._lineage = lineage
        self.inputs = ReviewerInputPort(
            store=store, blueprint=blueprint, authority=self._authority)

    @staticmethod
    def cycle_id(task_contract_id: str, cycle_number: int) -> str:
        suffix = sha256_hex({"task_contract_id": task_contract_id,
                             "cycle_number": cycle_number})[:12]
        return f"oc-{suffix}"

    def review(self, task_contract_id: str):
        """Perform one independent review cycle, or refuse.

        Returns ``(review_row, objection_cycle_row_or_None)``.
        """
        facade = self._authority.reviewer
        # API-level fourth-cycle denial: this raises before anything is read.
        cycle_index = facade.next_cycle_index(task_contract_id)

        packet = self.inputs.assemble(task_contract_id, cycle_index=cycle_index)
        artifacts = self.inputs.submitted_artifacts(packet)
        judgement = assess(packet, artifacts)

        review = facade.record_review(
            review_id=packet.review_id,
            task_contract_id=task_contract_id,
            verification_result_id=str(packet.verification["result_id"]),
            cycle_index=cycle_index,
            outcome=judgement["outcome"],
            reason_code=judgement["reason_code"],
            reviewer_lineage=self._lineage,
            packet_hash=packet.packet_hash,
            recomputed_task_contract_hash=packet.recomputed_task_contract_hash,
            recomputed_verification_result_hash=(
                packet.recomputed_verification_result_hash),
            objections=judgement["objections"],
        )
        if judgement["outcome"] != REVIEW_OBJECTIONS:
            return review, None

        cycle = facade.open_objection_cycle(
            cycle_id=self.cycle_id(task_contract_id, cycle_index + 1),
            task_contract_id=task_contract_id,
            review_id=str(review["review_id"]),
            objections=judgement["objections"],
            recovery_decision=judgement["recovery_decision"],
        )
        return review, cycle

    def cycles_remaining(self, task_contract_id: str) -> int:
        return self._authority.ledger.cycles_remaining(task_contract_id)

    def escalated(self, task_contract_id: str) -> bool:
        return self._authority.ledger.is_escalated(task_contract_id)


__all__ = [
    "MAX_OBJECTION_CYCLES", "ObjectionCyclesExhausted", "REVIEWER_LINEAGE",
    "ReviewPacket", "Reviewer", "ReviewerInputPort", "assess",
]
