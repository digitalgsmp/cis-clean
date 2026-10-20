"""Append-only authority for one declared bounded-recovery attempt.

An :class:`~cis.assurance.recovery.OperationalSelfAssessment` records what a
future recovery MUST preserve and the one closed set of facts it may change;
it grants no authority. ``recovery_attempts`` (migration 0011) is the single
owner of the forward link from that assessment to the fresh child task
contract and execution-input binding authorized and issued for the replacement
attempt, recorded only after every fact has been independently
recomputed from stored authority — never from a caller's assertion.

NO EXECUTION AUTHORITY LIVES HERE. This module appends exactly one table and
dispatches, executes, verifies and promotes nothing.

A DISTINCT HASH DOMAIN. ``attempt_hash`` is sha256 over a canonical payload
tagged ``cis.assurance.recovery_attempt.v1``, distinct from the assessment,
task-contract and execution-input domains even though the facts recorded here
overlap with all three.

ONE RECOVERY PER ASSESSMENT, EVER. A second call for the same
``assessment_id`` either returns the identical row already recorded (an
idempotent retry) or refuses outright if the caller now names a different
child (a retry that disagrees with itself is never silently accepted).
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from ..authority.store import AuthorityStore, Row
from ..canonical import sha256_hex
from ..errors import RecoveryAttemptRefused
from .authority import AssuranceAuthority
from .execution_input import ExecutionInputAuthority
from .recovery import REPLACEMENT_REQUIRED, OperationalSelfAssessment

HASH_DOMAIN = "cis.assurance.recovery_attempt.v1"

#: Facts the operational assessment declares a replacement candidate MUST
#: preserve bit-for-bit. Checked independently, never trusted from the
#: assessment's say-so alone: both the assessment's own recorded bindings and
#: the parent/child execution-input rows must agree.
_PRESERVED_EXECUTION_INPUT_FIELDS = (
    "vector_contract_sha256",
    "authorized_entrypoint",
    "worker_image",
    "expected_trusted_runner_sha256",
    "expected_worker_sha256",
)

MAX_GENERATION = 3


def _loads(value: Any) -> Any:
    try:
        return json.loads(str(value))
    except (TypeError, json.JSONDecodeError) as exc:
        raise RecoveryAttemptRefused(
            "recovery attempt source contains malformed canonical JSON") from exc


def attempt_payload(*, attempt_id: str, assessment_id: str,
                    parent_task_contract_id: str, child_authorization_id: str,
                    child_task_contract_id: str,
                    parent_execution_input_hash: str,
                    child_execution_input_hash: str, candidate_sha256: str,
                    generation: int) -> dict:
    return {
        "__hash_domain__": HASH_DOMAIN,
        "attempt_id": attempt_id,
        "assessment_id": assessment_id,
        "parent_task_contract_id": parent_task_contract_id,
        "child_authorization_id": child_authorization_id,
        "child_task_contract_id": child_task_contract_id,
        "parent_execution_input_hash": parent_execution_input_hash,
        "child_execution_input_hash": child_execution_input_hash,
        "candidate_sha256": candidate_sha256,
        "generation": generation,
    }


def attempt_hash_of_row(row: Mapping[str, Any]) -> str:
    return sha256_hex(attempt_payload(
        attempt_id=str(row["attempt_id"]),
        assessment_id=str(row["assessment_id"]),
        parent_task_contract_id=str(row["parent_task_contract_id"]),
        child_authorization_id=str(row["child_authorization_id"]),
        child_task_contract_id=str(row["child_task_contract_id"]),
        parent_execution_input_hash=str(row["parent_execution_input_hash"]),
        child_execution_input_hash=str(row["child_execution_input_hash"]),
        candidate_sha256=str(row["candidate_sha256"]),
        generation=int(row["generation"]),
    ))


class RecoveryAttemptAuthority:
    """Single owner of ``recovery_attempts``."""

    module_id = "cis.assurance.recovery_attempt"
    owned_authority = ("recovery_attempts",)

    def __init__(self, store: AuthorityStore) -> None:
        self._store = store
        self._assurance = AssuranceAuthority(store)
        self._inputs = ExecutionInputAuthority(store, self._assurance)
        self._assessments = OperationalSelfAssessment(store)

    # -- reads ----------------------------------------------------------

    def for_assessment(self, assessment_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM recovery_attempts WHERE assessment_id = ?",
            (assessment_id,))

    def for_child(self, child_task_contract_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM recovery_attempts WHERE child_task_contract_id = ?",
            (child_task_contract_id,))

    def verify(self, attempt_id: str) -> Row:
        row = self._store.one(
            "SELECT * FROM recovery_attempts WHERE attempt_id = ?",
            (attempt_id,))
        if row is None:
            raise RecoveryAttemptRefused(
                "no such recovery attempt", attempt_id=attempt_id)
        if str(row["hash_domain"]) != HASH_DOMAIN:
            raise RecoveryAttemptRefused(
                "recovery attempt carries an unknown hash domain",
                attempt_id=attempt_id)
        recomputed = attempt_hash_of_row(row)
        if recomputed != str(row["attempt_hash"]):
            raise RecoveryAttemptRefused(
                "recovery attempt digest does not recompute",
                attempt_id=attempt_id,
                recorded=str(row["attempt_hash"]), recomputed=recomputed)
        return row

    def _generation_for(self, parent_task_contract_id: str) -> int:
        prior = self.for_child(parent_task_contract_id)
        if prior is None:
            return 1
        return int(self.verify(str(prior["attempt_id"]))["generation"]) + 1

    # -- the one append path ---------------------------------------------

    def record(self, assessment_id: str, *, child_task_contract_id: str) -> Row:
        """Append one immutable recovery-attempt lineage, or refuse.

        Every fact is independently recomputed before anything is written:
        the assessment must verify and require a replacement candidate; the
        parent and child task contracts and execution-input bindings must
        each verify on their own; the child must be fresh (never yet
        verified); both must share the same target module and
        ``verify_authored_source.v1`` template; every field the assessment
        declares preserved must be bit-identical between parent and child;
        the candidate must have actually changed; and the recovery
        generation, derived from the parent's own lineage, must not exceed
        the fixed bound of three.
        """
        assessment = self._assessments.verify(assessment_id)
        if str(assessment["disposition"]) != REPLACEMENT_REQUIRED:
            raise RecoveryAttemptRefused(
                "recovery attempts may only carry out a replacement-candidate "
                "assessment", assessment_id=assessment_id,
                disposition=str(assessment["disposition"]))

        existing = self.for_assessment(assessment_id)
        if existing is not None:
            existing = self.verify(str(existing["attempt_id"]))
            if str(existing["child_task_contract_id"]) != str(child_task_contract_id):
                raise RecoveryAttemptRefused(
                    "this assessment already carries a recorded recovery "
                    "attempt under a different child task contract",
                    assessment_id=assessment_id,
                    recorded_child=str(existing["child_task_contract_id"]),
                    requested_child=str(child_task_contract_id))
            return existing

        parent_task_contract_id = str(assessment["task_contract_id"])
        if child_task_contract_id == parent_task_contract_id:
            raise RecoveryAttemptRefused(
                "a recovery attempt's child must differ from its parent",
                task_contract_id=parent_task_contract_id)

        parent_contract = self._assurance.verify_task_contract(
            parent_task_contract_id)
        parent_input = self._inputs.verify(parent_task_contract_id)
        child_contract = self._assurance.verify_task_contract(
            child_task_contract_id)
        child_input = self._inputs.verify(child_task_contract_id)

        if str(child_contract["template_id"]) != str(parent_contract["template_id"]):
            raise RecoveryAttemptRefused(
                "recovery child must be issued under the same template as "
                "its parent", parent_template=str(parent_contract["template_id"]),
                child_template=str(child_contract["template_id"]))
        if str(child_contract["target_module_id"]) != str(
                parent_contract["target_module_id"]):
            raise RecoveryAttemptRefused(
                "recovery child must target the same module as its parent",
                parent_module=str(parent_contract["target_module_id"]),
                child_module=str(child_contract["target_module_id"]))

        if self._assurance.ledger.verification_result(
                child_task_contract_id) is not None:
            raise RecoveryAttemptRefused(
                "recovery child task contract already carries a "
                "verification result and is no longer fresh",
                task_contract_id=child_task_contract_id)

        preserved = _loads(assessment["preserved_bindings_json"])
        for field in _PRESERVED_EXECUTION_INPUT_FIELDS:
            preserved_value = preserved.get(field)
            parent_value = str(parent_input[field])
            child_value = str(child_input[field])
            if preserved_value != parent_value or child_value != parent_value:
                raise RecoveryAttemptRefused(
                    f"recovery child does not preserve {field}",
                    preserved=preserved_value, parent=parent_value,
                    child=child_value)

        if str(child_input["candidate_sha256"]) == str(
                parent_input["candidate_sha256"]):
            raise RecoveryAttemptRefused(
                "recovery child does not change the candidate it was "
                "required to replace",
                candidate_sha256=str(child_input["candidate_sha256"]))

        generation = self._generation_for(parent_task_contract_id)
        if generation > MAX_GENERATION:
            raise RecoveryAttemptRefused(
                "recovery generation exceeds the fixed bound",
                generation=generation, max_generation=MAX_GENERATION)

        attempt_id = "rca-" + sha256_hex({
            "assessment_id": assessment_id,
            "child_task_contract_id": child_task_contract_id,
        })[:12]
        payload = attempt_payload(
            attempt_id=attempt_id, assessment_id=assessment_id,
            parent_task_contract_id=parent_task_contract_id,
            child_authorization_id=str(child_contract["authorization_id"]),
            child_task_contract_id=child_task_contract_id,
            parent_execution_input_hash=str(parent_input["execution_input_hash"]),
            child_execution_input_hash=str(child_input["execution_input_hash"]),
            candidate_sha256=str(child_input["candidate_sha256"]),
            generation=generation)
        digest = sha256_hex(payload)
        return self._store.insert("recovery_attempts", {
            "attempt_id": attempt_id,
            "assessment_id": assessment_id,
            "parent_task_contract_id": parent_task_contract_id,
            "child_authorization_id": str(child_contract["authorization_id"]),
            "child_task_contract_id": child_task_contract_id,
            "parent_execution_input_hash": str(
                parent_input["execution_input_hash"]),
            "child_execution_input_hash": str(
                child_input["execution_input_hash"]),
            "candidate_sha256": str(child_input["candidate_sha256"]),
            "generation": generation,
            "hash_domain": HASH_DOMAIN,
            "attempt_hash": digest,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })


__all__ = [
    "HASH_DOMAIN",
    "MAX_GENERATION",
    "RecoveryAttemptAuthority",
    "attempt_hash_of_row",
    "attempt_payload",
]
