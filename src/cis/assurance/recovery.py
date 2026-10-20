"""Deterministic operational self-assessment for bounded recovery.

This module grants no authority and executes nothing.  It independently
recomputes the immutable facts behind the latest objection cycle and records a
closed recovery specification: what failed, what a later recovery MUST
preserve, and the only fields it may change.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from ..authority.store import AuthorityStore, Row
from ..authority.trajectory import INDEPENDENT_REVIEW, TrajectoryAuthority
from ..canonical import canonical_json, sha256_hex
from ..errors import OperationalAssessmentRefused
from .authority import (
    AssuranceAuthority, RECOVERY_ESCALATE, RECOVERY_REPLACEMENT_CANDIDATE,
    RECOVERY_REVISED_SUBMISSION, review_result_hash_of_row,
    verification_result_hash_of_row,
)
from .execution_input import ExecutionInputAuthority

HASH_DOMAIN = "cis.assurance.operational_assessment.v1"

REPLACEMENT_REQUIRED = "REPLACEMENT_CANDIDATE_REQUIRED"
REVISED_REQUIRED = "REVISED_SUBMISSION_REQUIRED"
ESCALATION_REQUIRED = "ESCALATION_REQUIRED"

CANDIDATE_FAILURE = "CANDIDATE_OR_RESULT_FAILURE"
ARTIFACT_FAILURE = "SUBMISSION_ARTIFACT_FAILURE"
BOUND_EXHAUSTED = "RECOVERY_BOUND_EXHAUSTED"

SOURCE_INTEGRITY_CHECKS = (
    "parent_objection_cycle_recomputes",
    "parent_review_result_recomputes",
    "parent_verification_result_recomputes",
    "parent_execution_input_recomputes",
)

REPLACEMENT_CHECKS = SOURCE_INTEGRITY_CHECKS + (
    "replacement_preserves_vector_contract",
    "replacement_preserves_entrypoint",
    "replacement_preserves_apparatus_identity",
    "replacement_uses_fresh_authorization_and_task_contract",
)

RESUBMISSION_CHECKS = SOURCE_INTEGRITY_CHECKS + (
    "resubmission_preserves_candidate_source",
    "resubmission_preserves_vector_contract",
    "resubmission_preserves_entrypoint",
    "resubmission_preserves_apparatus_identity",
    "resubmission_uses_fresh_authorization_and_task_contract",
)

ESCALATION_CHECKS = SOURCE_INTEGRITY_CHECKS + (
    "no_recovery_execution_authorized",
)


def _loads(value: Any) -> Any:
    try:
        return json.loads(str(value))
    except (TypeError, json.JSONDecodeError) as exc:
        raise OperationalAssessmentRefused(
            "recovery source contains malformed canonical JSON") from exc


def objection_cycle_hash_of_row(row: Mapping[str, Any]) -> str:
    return sha256_hex({
        "__hash_domain__": "cis.assurance.objection_cycle.v1",
        "cycle_id": str(row["cycle_id"]),
        "task_contract_id": str(row["task_contract_id"]),
        "review_id": str(row["review_id"]),
        "cycle_number": int(row["cycle_number"]),
        "objections": _loads(row["objections_json"]),
        "recovery_decision": str(row["recovery_decision"]),
        "replacement_execution_wiring": str(
            row["replacement_execution_wiring"]),
        "terminal": int(row["terminal"]),
    })


def assessment_payload(*, assessment_id: str, task_contract_id: str,
                       cycle_id: str, review_id: str, cycle_number: int,
                       disposition: str, failure_class: str,
                       preserved_bindings: Mapping[str, Any],
                       permitted_changes: list[str],
                       required_checks: list[str],
                       source_facts_hash: str) -> dict:
    return {
        "__hash_domain__": HASH_DOMAIN,
        "assessment_id": assessment_id,
        "task_contract_id": task_contract_id,
        "cycle_id": cycle_id,
        "review_id": review_id,
        "cycle_number": cycle_number,
        "disposition": disposition,
        "failure_class": failure_class,
        "preserved_bindings": dict(preserved_bindings),
        "permitted_changes": list(permitted_changes),
        "required_checks": list(required_checks),
        "source_facts_hash": source_facts_hash,
    }


def assessment_hash_of_row(row: Mapping[str, Any]) -> str:
    return sha256_hex(assessment_payload(
        assessment_id=str(row["assessment_id"]),
        task_contract_id=str(row["task_contract_id"]),
        cycle_id=str(row["cycle_id"]), review_id=str(row["review_id"]),
        cycle_number=int(row["cycle_number"]),
        disposition=str(row["disposition"]),
        failure_class=str(row["failure_class"]),
        preserved_bindings=_loads(row["preserved_bindings_json"]),
        permitted_changes=_loads(row["permitted_changes_json"]),
        required_checks=_loads(row["required_checks_json"]),
        source_facts_hash=str(row["source_facts_hash"]),
    ))


class OperationalSelfAssessment:
    """Single owner and deterministic producer of operational assessments."""

    module_id = "cis.assurance.recovery"
    owned_authority = ("operational_assessments",)

    def __init__(self, store: AuthorityStore) -> None:
        self._store = store
        self._assurance = AssuranceAuthority(store)
        self._inputs = ExecutionInputAuthority(store, self._assurance)
        self._trajectory = TrajectoryAuthority(store)

    def for_cycle(self, cycle_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM operational_assessments WHERE cycle_id = ?",
            (cycle_id,))

    def verify(self, assessment_id: str) -> Row:
        row = self._store.one(
            "SELECT * FROM operational_assessments WHERE assessment_id = ?",
            (assessment_id,))
        if row is None:
            raise OperationalAssessmentRefused(
                "no such operational assessment", assessment_id=assessment_id)
        if str(row["hash_domain"]) != HASH_DOMAIN:
            raise OperationalAssessmentRefused(
                "operational assessment carries an unknown hash domain",
                assessment_id=assessment_id)
        recomputed = assessment_hash_of_row(row)
        if recomputed != str(row["assessment_hash"]):
            raise OperationalAssessmentRefused(
                "operational assessment digest does not recompute",
                assessment_id=assessment_id,
                recorded=str(row["assessment_hash"]), recomputed=recomputed)
        return row

    def assess(self, task_contract_id: str) -> Row:
        contract = self._assurance.verify_task_contract(task_contract_id)
        cycles = self._assurance.ledger.objection_cycles(task_contract_id)
        if not cycles:
            raise OperationalAssessmentRefused(
                "operational assessment requires a recorded objection cycle",
                task_contract_id=task_contract_id)
        cycle = cycles[-1]
        cycle_id = str(cycle["cycle_id"])
        existing = self.for_cycle(cycle_id)
        if existing is not None:
            return self.verify(str(existing["assessment_id"]))

        recomputed_cycle = objection_cycle_hash_of_row(cycle)
        if recomputed_cycle != str(cycle["cycle_hash"]):
            raise OperationalAssessmentRefused(
                "objection-cycle digest does not recompute", cycle_id=cycle_id)
        review = self._store.one(
            "SELECT * FROM review_results WHERE review_id = ?",
            (cycle["review_id"],))
        if review is None or str(review["task_contract_id"]) != task_contract_id:
            raise OperationalAssessmentRefused(
                "objection cycle does not resolve to its review", cycle_id=cycle_id)
        recomputed_review = review_result_hash_of_row(review)
        if recomputed_review != str(review["review_hash"]):
            raise OperationalAssessmentRefused(
                "review-result digest does not recompute", review_id=review["review_id"])
        verification = self._assurance.ledger.verification_result(task_contract_id)
        if verification is None:
            raise OperationalAssessmentRefused(
                "objection has no verification result", task_contract_id=task_contract_id)
        recomputed_verification = verification_result_hash_of_row(verification)
        if recomputed_verification != str(verification["result_hash"]):
            raise OperationalAssessmentRefused(
                "verification-result digest does not recompute",
                task_contract_id=task_contract_id)
        execution_input = self._inputs.verify(task_contract_id)

        decision = str(cycle["recovery_decision"])
        if decision == RECOVERY_REPLACEMENT_CANDIDATE:
            disposition, failure_class = REPLACEMENT_REQUIRED, CANDIDATE_FAILURE
            permitted = ["candidate_source"]
            required_checks = list(REPLACEMENT_CHECKS)
        elif decision == RECOVERY_REVISED_SUBMISSION:
            disposition, failure_class = REVISED_REQUIRED, ARTIFACT_FAILURE
            permitted = ["execution_evidence"]
            required_checks = list(RESUBMISSION_CHECKS)
        elif decision == RECOVERY_ESCALATE:
            disposition, failure_class = ESCALATION_REQUIRED, BOUND_EXHAUSTED
            permitted = []
            required_checks = list(ESCALATION_CHECKS)
        else:  # protected by SQL, retained as a fail-closed code boundary
            raise OperationalAssessmentRefused(
                "unknown recovery decision", recovery_decision=decision)

        preserved = {
            "target_module_id": str(contract["target_module_id"]),
            "vector_contract_sha256": str(
                execution_input["vector_contract_sha256"]),
            "authorized_entrypoint": str(
                execution_input["authorized_entrypoint"]),
            "worker_image": str(execution_input["worker_image"]),
            "expected_trusted_runner_sha256": str(
                execution_input["expected_trusted_runner_sha256"]),
            "expected_worker_sha256": str(
                execution_input["expected_worker_sha256"]),
        }
        if decision != RECOVERY_REPLACEMENT_CANDIDATE:
            preserved["candidate_sha256"] = str(
                execution_input["candidate_sha256"])
        source_facts_hash = sha256_hex({
            "cycle_hash": recomputed_cycle,
            "review_hash": recomputed_review,
            "verification_result_hash": recomputed_verification,
            "execution_input_hash": str(execution_input["execution_input_hash"]),
        })
        assessment_id = "osa-" + sha256_hex({
            "cycle_id": cycle_id, "source_facts_hash": source_facts_hash,
        })[:12]
        payload = assessment_payload(
            assessment_id=assessment_id, task_contract_id=task_contract_id,
            cycle_id=cycle_id, review_id=str(review["review_id"]),
            cycle_number=int(cycle["cycle_number"]),
            disposition=disposition, failure_class=failure_class,
            preserved_bindings=preserved, permitted_changes=permitted,
            required_checks=required_checks,
            source_facts_hash=source_facts_hash)
        digest = sha256_hex(payload)
        row = self._store.insert("operational_assessments", {
            "assessment_id": assessment_id,
            "task_contract_id": task_contract_id,
            "cycle_id": cycle_id,
            "review_id": str(review["review_id"]),
            "cycle_number": int(cycle["cycle_number"]),
            "disposition": disposition,
            "failure_class": failure_class,
            "preserved_bindings_json": canonical_json(preserved),
            "permitted_changes_json": canonical_json(permitted),
            "required_checks_json": canonical_json(required_checks),
            "source_facts_hash": source_facts_hash,
            "hash_domain": HASH_DOMAIN,
            "assessment_hash": digest,
            "created_at": self._store.now(), "seq": self._store.next_seq(),
        })
        self._trajectory.record(
            event_id=f"ev-osa-{assessment_id[4:]}", scope="micro",
            stage=INDEPENDENT_REVIEW,
            event_type="operational_self_assessment_recorded",
            module_id=str(contract["target_module_id"]),
            transaction_id=None,
            detail={"assessment_id": assessment_id,
                    "task_contract_id": task_contract_id,
                    "disposition": disposition,
                    "permitted_changes": permitted,
                    "assessment_hash": digest})
        return row


__all__ = ["OperationalSelfAssessment", "assessment_hash_of_row"]
