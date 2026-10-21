"""The single owner of the assurance ledger, behind three disjoint facades.

Seven append-only tables, one owning module (ADR-ARCH-001 clause 5):
``task_contracts``, ``verification_inputs``, ``verification_results``,
``review_results``, ``objection_cycles``, ``promotion_decisions`` and
``review_route_receipts``.

ONE OWNER, THREE FACADES
------------------------

Single ownership and separation of duties pull in opposite directions if they
are confused with each other. Splitting the ledger across three owning modules
would create three writers of one interlocking set of facts, and the
conjunction a promotion decision depends on would then be computed across
owners that cannot see each other's constraints. So ownership stays single, and
SEPARATION IS ENFORCED AT THE FACADE, not at the table:

  * ``AssuranceAuthority.verifier``  — appends verification inputs and the one
    verification result. It cannot append a review, a cycle or a promotion.
  * ``AssuranceAuthority.reviewer``  — appends review results, objection
    cycles, and reviewer-route receipts. It cannot append a verification
    input, a verification result or a promotion.
  * ``AssuranceAuthority.promotion`` — appends promotion decisions. It cannot
    append anything else.

The three facades expose pairwise-disjoint public method names, and
``tests/test_assurance.py`` asserts that disjointness rather than trusting it.
``AssuranceAuthority.ledger`` is a fourth facade that is READ-ONLY and shared:
derived state is a read, and three private copies of one derivation would be
the duplicate-state failure reconstruction exists to remove.

SANCTIONED REVIEWER-ROUTE RECEIPT ADMISSION
--------------------------------------------

``ReviewerFacade.record_route_receipt`` is the only sanctioned behavioral path
into ``review_route_receipts`` (Unit 9A2b). It runs
``cis.assurance.review_route.verify_receipt`` first — the pure, offline
closed-schema and policy check — and only then checks the receipt against
authority itself: the cited review must exist and the receipt must exactly
match that review's task contract, verification result, packet hash, reviewer
lineage, outcome and objections; the cited verification result must be the
exact row the review itself rests on; and ``response_evidence_id`` must name
an existing ``evidence_records`` row whose kind, source_ref, content digest and
parsed ``{verdict, objections}`` content exactly match the receipt. The
evidence is an observation that a response was received, never authority by
itself (ADR-ARCH-002) — the validated receipt, checked against the ledger, is
what becomes authority. ``review_id`` is UNIQUE in migration 0015, so a second
receipt for one review is refused at the SQL layer as well.

A receipt is additionally bound to the worker-model request lifecycle that
``cis.execution.worker_session`` owns (migration 0013), so a caller cannot get
a receipt admitted on evidence it merely asserts: ``reviewer_request_id`` must
name an existing ``worker_model_requests`` row whose adapter and response
schema agree with the receipt; that row's ``worker_sessions`` row must exist,
carry ``logical_role = 'REVIEWER'`` and the same adapter; the request must
have exactly one terminal ``worker_session_events`` row, and it must be
``REQUEST_SUCCEEDED`` citing both the receipt's ``response_evidence_id`` and a
nonblank ``run_id``; and that ``run_id`` must name a ``backend_runs`` row that
is ``completed`` and whose authorization, adapter and evidence exactly match
the request, the receipt's adapter and the receipt's evidence. This binds the
receipt to the gateway/adapter execution that was actually dispatched and
supervised — it is not a cryptographic attestation from the model provider,
only the trusted boundary this increment owns.

STATE IS DERIVED
----------------

There is no status column to advance. ``AssuranceLedger.state_of`` reads the
append-only rows and returns one of ``ASSURANCE_STATES``:

    FROZEN -> VERIFIED_PASS | VERIFIED_FAIL -> PASS | OBJECTIONS
           -> ESCALATED (after the third objection cycle)
           -> PROMOTION_AUTHORIZED | PROMOTION_DENIED

THE FOURTH OBJECTION CYCLE
--------------------------

Impossible at three levels, by construction:

  1. API     — ``ReviewerFacade.open_objection_cycle`` and the reviewer module
               refuse once three cycles stand recorded;
  2. LEDGER  — ``_next_cycle_number`` refuses any number other than exactly
               one more than the highest recorded, and refuses above three;
  3. SQL     — ``objection_cycles.cycle_number`` is CHECKed to 1..3 and UNIQUE
               per task contract, ``review_results.cycle_index`` is CHECKed to
               0..2 and UNIQUE per task contract, and ``objection_cycles``
               holds a UNIQUE review_id so one review cannot open two cycles.

NO HOST ACTION
--------------

Nothing in this module imports ``os``, ``subprocess``, ``shutil``, ``socket``
or any other way to reach the host, and ``promotion_decisions.host_action`` is
CHECKed to the single value ``NONE_RECORD_ONLY``. A promotion decision is a
record that a decision was made. It is not a deployment.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from ..authority.runs import COMPLETED as RUN_COMPLETED
from ..authority.store import AuthorityStore, Row
from ..authority.trajectory import (
    INDEPENDENT_REVIEW, INDEPENDENT_VERIFICATION, MICRO, PROMOTION_DECISION,
    TASK_CONTRACT, TrajectoryAuthority,
)
from ..canonical import canonical_json, sha256_hex, sha256_text
from ..errors import (
    AssuranceRefused, ObjectionCyclesExhausted, PromotionRefused,
    ReviewRefused, VerificationRefused,
)
from . import review_route
from .task_contract import (
    FrozenTaskContract, STATE_FROZEN, TASK_CONTRACT_HASH_DOMAIN, verify_row,
)

#: The evidence kind an admitted external-reviewer response is recorded
#: under. Fixed to a single value so ``record_route_receipt`` can refuse any
#: other kind of evidence as a binding candidate.
EXTERNAL_MODEL_REVIEW_RESPONSE_KIND = "external_model_review_response"

# -- state vocabulary --------------------------------------------------------

STATE_VERIFIED_PASS = "VERIFIED_PASS"
STATE_VERIFIED_FAIL = "VERIFIED_FAIL"
STATE_PASS = "PASS"
STATE_OBJECTIONS = "OBJECTIONS"
STATE_ESCALATED = "ESCALATED"
STATE_PROMOTION_AUTHORIZED = "PROMOTION_AUTHORIZED"
STATE_PROMOTION_DENIED = "PROMOTION_DENIED"

ASSURANCE_STATES: tuple[str, ...] = (
    STATE_FROZEN,
    STATE_VERIFIED_PASS,
    STATE_VERIFIED_FAIL,
    STATE_PASS,
    STATE_OBJECTIONS,
    STATE_ESCALATED,
    STATE_PROMOTION_AUTHORIZED,
    STATE_PROMOTION_DENIED,
)

#: The declared flow, as a structured fact rather than as prose. Read by the
#: projection and asserted by the suite, so the documented state machine and
#: the implemented one cannot drift.
ASSURANCE_FLOW: Mapping[str, tuple[str, ...]] = {
    STATE_FROZEN: (STATE_VERIFIED_PASS, STATE_VERIFIED_FAIL),
    STATE_VERIFIED_PASS: (STATE_PASS, STATE_OBJECTIONS),
    STATE_VERIFIED_FAIL: (STATE_PASS, STATE_OBJECTIONS),
    STATE_OBJECTIONS: (STATE_PASS, STATE_OBJECTIONS, STATE_ESCALATED),
    STATE_PASS: (STATE_PROMOTION_AUTHORIZED, STATE_PROMOTION_DENIED),
    STATE_ESCALATED: (STATE_PROMOTION_DENIED,),
    STATE_PROMOTION_AUTHORIZED: (),
    STATE_PROMOTION_DENIED: (),
}

#: The hard bound. Three objection cycles, then escalation.
MAX_OBJECTION_CYCLES = 3

VERIFIED_PASS = STATE_VERIFIED_PASS
VERIFIED_FAIL = STATE_VERIFIED_FAIL
REVIEW_PASS = STATE_PASS
REVIEW_OBJECTIONS = STATE_OBJECTIONS

REVIEW_PENDING = "PENDING"
REVIEW_COMPLETE = "COMPLETE"

PROMOTION_AUTHORIZED = STATE_PROMOTION_AUTHORIZED
PROMOTION_DENIED = STATE_PROMOTION_DENIED

#: The one legal value of ``promotion_decisions.host_action``.
HOST_ACTION_NONE = "NONE_RECORD_ONLY"

#: The one legal value of ``objection_cycles.replacement_execution_wiring``.
REPLACEMENT_WIRING_DEFERRED = "DEFERRED_TO_CONTAINED_WORKER_CAPABILITY"

RECOVERY_REVISED_SUBMISSION = "REQUEST_REVISED_SUBMISSION"
RECOVERY_REPLACEMENT_CANDIDATE = "REQUEST_REPLACEMENT_CANDIDATE"
RECOVERY_ESCALATE = "ESCALATE"
RECOVERY_DECISIONS: tuple[str, ...] = (
    RECOVERY_REVISED_SUBMISSION,
    RECOVERY_REPLACEMENT_CANDIDATE,
    RECOVERY_ESCALATE,
)

#: The module recorded in ``verification_inputs.assembled_by``. The column is
#: CHECKed to this value in SQL, so a reviewer-assembled packet can never be
#: stored as a verifier input.
VERIFIER_MODULE = "cis.assurance.verifier"


def _dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


# ---------------------------------------------------------------------------
# Read-only derived ledger
# ---------------------------------------------------------------------------

class AssuranceLedger:
    """Read-only reads and derivations over the assurance tables.

    Shared by every facade and by the projection. It appends nothing: the class
    holds no reference to ``AuthorityStore.insert`` beyond what the store
    exposes, and no method here writes.
    """

    def __init__(self, store: AuthorityStore) -> None:
        self._store = store

    # -- task contracts -----------------------------------------------------

    def task_contract(self, task_contract_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM task_contracts WHERE task_contract_id = ?",
            (task_contract_id,),
        )

    def task_contracts(self) -> list[Row]:
        return self._store.query("SELECT * FROM task_contracts ORDER BY seq")

    def task_contract_for_authorization(self, authorization_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM task_contracts WHERE authorization_id = ?",
            (authorization_id,),
        )

    def require_task_contract(self, task_contract_id: str) -> Row:
        row = self.task_contract(task_contract_id)
        if row is None:
            raise AssuranceRefused("no such task contract",
                                   task_contract_id=task_contract_id)
        return row

    # -- verification -------------------------------------------------------

    def verification_input(self, task_contract_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM verification_inputs WHERE task_contract_id = ?",
            (task_contract_id,),
        )

    def verification_result(self, task_contract_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM verification_results WHERE task_contract_id = ?",
            (task_contract_id,),
        )

    # -- review -------------------------------------------------------------

    def reviews(self, task_contract_id: str) -> list[Row]:
        return self._store.query(
            "SELECT * FROM review_results WHERE task_contract_id = ? "
            "ORDER BY cycle_index",
            (task_contract_id,),
        )

    def latest_review(self, task_contract_id: str) -> Row | None:
        rows = self.reviews(task_contract_id)
        return rows[-1] if rows else None

    def objection_cycles(self, task_contract_id: str) -> list[Row]:
        return self._store.query(
            "SELECT * FROM objection_cycles WHERE task_contract_id = ? "
            "ORDER BY cycle_number",
            (task_contract_id,),
        )

    def objection_cycle_count(self, task_contract_id: str) -> int:
        return len(self.objection_cycles(task_contract_id))

    def cycles_remaining(self, task_contract_id: str) -> int:
        return max(0, MAX_OBJECTION_CYCLES
                   - self.objection_cycle_count(task_contract_id))

    def is_escalated(self, task_contract_id: str) -> bool:
        return (self.objection_cycle_count(task_contract_id)
                >= MAX_OBJECTION_CYCLES)

    # -- promotion ----------------------------------------------------------

    def promotion_decisions(self, task_contract_id: str) -> list[Row]:
        return self._store.query(
            "SELECT * FROM promotion_decisions WHERE task_contract_id = ? "
            "ORDER BY seq",
            (task_contract_id,),
        )

    def latest_promotion(self, task_contract_id: str) -> Row | None:
        rows = self.promotion_decisions(task_contract_id)
        return rows[-1] if rows else None

    # -- reviewer-route receipts ---------------------------------------------

    def route_receipt_for_review(self, review_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM review_route_receipts WHERE review_id = ?",
            (review_id,),
        )

    def route_receipts_for_task(self, task_contract_id: str) -> list[Row]:
        return self._store.query(
            "SELECT * FROM review_route_receipts WHERE task_contract_id = ? "
            "ORDER BY seq",
            (task_contract_id,),
        )

    # -- derived state ------------------------------------------------------

    def review_status(self, task_contract_id: str) -> str:
        return (REVIEW_COMPLETE
                if self.latest_review(task_contract_id) is not None
                else REVIEW_PENDING)

    def state_of(self, task_contract_id: str) -> str:
        """The single derived assurance state. Never stored.

        Read in the order a reader of the ledger would read it: the newest fact
        that settles the question wins, and the absence of every later fact
        leaves the contract exactly FROZEN.
        """
        self.require_task_contract(task_contract_id)

        promotion = self.latest_promotion(task_contract_id)
        if promotion is not None:
            return str(promotion["decision"])

        if self.is_escalated(task_contract_id):
            return STATE_ESCALATED

        review = self.latest_review(task_contract_id)
        if review is not None:
            return str(review["outcome"])

        verification = self.verification_result(task_contract_id)
        if verification is not None:
            return str(verification["outcome"])

        return STATE_FROZEN

    def verification_passed(self, task_contract_id: str) -> bool:
        row = self.verification_result(task_contract_id)
        return row is not None and str(row["outcome"]) == VERIFIED_PASS

    def review_passed(self, task_contract_id: str) -> bool:
        row = self.latest_review(task_contract_id)
        return row is not None and str(row["outcome"]) == REVIEW_PASS

    def snapshot(self, task_contract_id: str) -> dict:
        """Everything a read-only surface needs about one task contract."""
        contract = self.require_task_contract(task_contract_id)
        verification = self.verification_result(task_contract_id)
        reviews = self.reviews(task_contract_id)
        cycles = self.objection_cycles(task_contract_id)
        promotion = self.latest_promotion(task_contract_id)
        return {
            "task_contract": contract.as_dict(),
            "state": self.state_of(task_contract_id),
            "review_status": self.review_status(task_contract_id),
            "verification": verification.as_dict() if verification else None,
            "verification_input": (
                self.verification_input(task_contract_id).as_dict()
                if self.verification_input(task_contract_id) else None
            ),
            "reviews": [row.as_dict() for row in reviews],
            "objection_cycles": [row.as_dict() for row in cycles],
            "objection_cycles_used": len(cycles),
            "objection_cycles_remaining": self.cycles_remaining(task_contract_id),
            "max_objection_cycles": MAX_OBJECTION_CYCLES,
            "escalated": self.is_escalated(task_contract_id),
            "promotion": promotion.as_dict() if promotion else None,
            "promotion_conjunction": {
                "verification_passed": self.verification_passed(task_contract_id),
                "review_passed": self.review_passed(task_contract_id),
                "authorizable": (self.verification_passed(task_contract_id)
                                 and self.review_passed(task_contract_id)
                                 and not self.is_escalated(task_contract_id)),
            },
        }


# ---------------------------------------------------------------------------
# Write facades
# ---------------------------------------------------------------------------

class _Facade:
    def __init__(self, store: AuthorityStore, ledger: AssuranceLedger,
                 trajectory: TrajectoryAuthority) -> None:
        self._store = store
        self._ledger = ledger
        self._trajectory = trajectory

    @property
    def ledger(self) -> AssuranceLedger:
        return self._ledger

    def _event(self, stage: str, event_type: str, *, task_contract_id: str,
               module_id: str | None, detail: Mapping[str, Any]) -> None:
        suffix = sha256_hex({"tc": task_contract_id, "stage": stage,
                             "event": event_type,
                             "detail": dict(detail)})[:12]
        self._trajectory.record(
            event_id=f"ev-asr-{suffix}",
            scope=MICRO,
            stage=stage,
            event_type=event_type,
            module_id=module_id,
            detail={"task_contract_id": task_contract_id, **dict(detail)},
        )


class TaskContractFacade(_Facade):
    """Freezes compiled task contracts. Appends nothing else."""

    def freeze(self, compiled: FrozenTaskContract) -> Row:
        """Append one immutable FROZEN task contract.

        The compiled object's digest is recomputed here before the append, so a
        caller that hand-built a ``FrozenTaskContract`` with a digest that does
        not follow from its own fields cannot get it into authority.
        """
        if compiled.state != STATE_FROZEN:
            raise AssuranceRefused(
                "a task contract is appended FROZEN and in no other state",
                task_contract_id=compiled.task_contract_id,
                state=compiled.state,
            )
        existing = self._ledger.task_contract_for_authorization(
            compiled.authorization_id)
        if existing is not None:
            raise AssuranceRefused(
                "this authorization already has a frozen task contract; a "
                "second one would be a second bounded unit of work under one "
                "ALLOW",
                authorization_id=compiled.authorization_id,
                task_contract_id=str(existing["task_contract_id"]),
            )
        row = self._store.insert("task_contracts", {
            "task_contract_id": compiled.task_contract_id,
            "authorization_id": compiled.authorization_id,
            "authorization_binding_hash": compiled.authorization_binding_hash,
            "target_module_id": compiled.target_module_id,
            "template_id": compiled.template_id,
            "template_hash": compiled.template_hash,
            "state": STATE_FROZEN,
            "allowed_paths_json": _dump(list(compiled.allowed_paths)),
            "forbidden_actions_json": _dump(list(compiled.forbidden_actions)),
            "required_checks_json": _dump(list(compiled.required_checks)),
            "required_artifacts_json": _dump(list(compiled.required_artifacts)),
            "stopping_condition": compiled.stopping_condition,
            "return_point": compiled.return_point,
            "hash_domain": TASK_CONTRACT_HASH_DOMAIN,
            "task_contract_hash": compiled.task_contract_hash,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })
        self._event(
            TASK_CONTRACT, "task_contract_frozen",
            task_contract_id=compiled.task_contract_id,
            module_id=compiled.target_module_id,
            detail={"authorization_id": compiled.authorization_id,
                    "template_id": compiled.template_id,
                    "hash_domain": TASK_CONTRACT_HASH_DOMAIN,
                    "task_contract_hash": compiled.task_contract_hash,
                    "allowed_path_count": len(compiled.allowed_paths)},
        )
        return row


class VerifierFacade(_Facade):
    """Appends verifier inputs and the one verification result.

    Disjoint from the reviewer and promotion facades by method name and by
    table: nothing here can append a review, a cycle or a decision.
    """

    def record_inputs(self, *, input_id: str, task_contract_id: str,
                      submitted_run_id: str | None,
                      submitted_evidence_id: str | None,
                      submitted_artifacts: Mapping[str, Any],
                      recomputed_task_contract_hash: str,
                      recomputed_binding_hash: str) -> Row:
        self._ledger.require_task_contract(task_contract_id)
        if self._ledger.verification_input(task_contract_id) is not None:
            raise VerificationRefused(
                "verifier inputs for this task contract are already recorded; "
                "the submitted evidence is immutable, so a second assembly "
                "could only restate the first",
                task_contract_id=task_contract_id,
            )
        inputs_hash = sha256_hex({
            "__hash_domain__": "cis.assurance.verification_inputs.v1",
            "input_id": input_id,
            "task_contract_id": task_contract_id,
            "submitted_run_id": submitted_run_id,
            "submitted_evidence_id": submitted_evidence_id,
            "submitted_artifacts": dict(submitted_artifacts),
            "recomputed_task_contract_hash": recomputed_task_contract_hash,
            "recomputed_binding_hash": recomputed_binding_hash,
            "assembled_by": VERIFIER_MODULE,
        })
        return self._store.insert("verification_inputs", {
            "input_id": input_id,
            "task_contract_id": task_contract_id,
            "submitted_run_id": submitted_run_id,
            "submitted_evidence_id": submitted_evidence_id,
            "submitted_artifacts_json": _dump(dict(submitted_artifacts)),
            "recomputed_task_contract_hash": recomputed_task_contract_hash,
            "recomputed_binding_hash": recomputed_binding_hash,
            "inputs_hash": inputs_hash,
            "assembled_by": VERIFIER_MODULE,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })

    def record_result(self, *, result_id: str, task_contract_id: str,
                      input_id: str, outcome: str, reason_code: str,
                      checks_performed: Sequence[str],
                      findings: Sequence[Mapping[str, Any]]) -> Row:
        contract = self._ledger.require_task_contract(task_contract_id)
        if outcome not in (VERIFIED_PASS, VERIFIED_FAIL):
            raise VerificationRefused("unknown verification outcome",
                                      outcome=outcome)
        state = self._ledger.state_of(task_contract_id)
        if state != STATE_FROZEN:
            raise VerificationRefused(
                "verification follows a FROZEN task contract and nothing else; "
                "this contract has already moved on",
                task_contract_id=task_contract_id, state=state,
                allowed_from=STATE_FROZEN,
            )
        result_hash = verification_result_hash(
            result_id=result_id, task_contract_id=task_contract_id,
            input_id=input_id, outcome=outcome, reason_code=reason_code,
            checks_performed=checks_performed, findings=findings,
        )
        row = self._store.insert("verification_results", {
            "result_id": result_id,
            "task_contract_id": task_contract_id,
            "input_id": input_id,
            "outcome": outcome,
            "reason_code": reason_code,
            "checks_performed_json": _dump(list(checks_performed)),
            "findings_json": _dump([dict(f) for f in findings]),
            "result_hash": result_hash,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })
        self._event(
            INDEPENDENT_VERIFICATION, "verification_recorded",
            task_contract_id=task_contract_id,
            module_id=str(contract["target_module_id"]),
            detail={"result_id": result_id, "outcome": outcome,
                    "reason_code": reason_code,
                    "result_hash": result_hash},
        )
        return row


class ReviewerFacade(_Facade):
    """Appends review results and objection cycles. Nothing else.

    This facade holds the API-level half of the three-level bound on objection
    cycles: it refuses a review once three cycles stand recorded, and it
    refuses an objection cycle whose number is not exactly the next one.
    """

    def next_cycle_index(self, task_contract_id: str) -> int:
        """The cycle_index the next review must carry, or refuse."""
        used = self._ledger.objection_cycle_count(task_contract_id)
        if used >= MAX_OBJECTION_CYCLES:
            raise ObjectionCyclesExhausted(
                f"{MAX_OBJECTION_CYCLES} objection cycles are recorded and the "
                "task contract is ESCALATED; a fourth review cycle cannot "
                "exist",
                task_contract_id=task_contract_id,
                objection_cycles_used=used,
                max_objection_cycles=MAX_OBJECTION_CYCLES,
            )
        reviews = self._ledger.reviews(task_contract_id)
        if len(reviews) != used:
            raise ReviewRefused(
                "the review ledger and the objection-cycle ledger disagree; "
                "refusing rather than guessing which is current",
                task_contract_id=task_contract_id,
                reviews=len(reviews), objection_cycles=used,
            )
        return used

    def record_review(self, *, review_id: str, task_contract_id: str,
                      verification_result_id: str, cycle_index: int,
                      outcome: str, reason_code: str, reviewer_lineage: str,
                      packet_hash: str, recomputed_task_contract_hash: str,
                      recomputed_verification_result_hash: str,
                      objections: Sequence[Mapping[str, Any]]) -> Row:
        contract = self._ledger.require_task_contract(task_contract_id)
        if outcome not in (REVIEW_PASS, REVIEW_OBJECTIONS):
            raise ReviewRefused("unknown review outcome", outcome=outcome)
        expected = self.next_cycle_index(task_contract_id)
        if cycle_index != expected:
            raise ReviewRefused(
                "review cycle_index is not the next one in sequence",
                task_contract_id=task_contract_id,
                cycle_index=cycle_index, expected=expected,
            )
        if self._ledger.verification_result(task_contract_id) is None:
            raise ReviewRefused(
                "there is no verification result to review; review follows "
                "verification in the declared flow",
                task_contract_id=task_contract_id,
            )
        review_hash = review_result_hash(
            review_id=review_id, task_contract_id=task_contract_id,
            verification_result_id=verification_result_id,
            cycle_index=cycle_index, outcome=outcome, reason_code=reason_code,
            reviewer_lineage=reviewer_lineage, packet_hash=packet_hash,
            recomputed_task_contract_hash=recomputed_task_contract_hash,
            recomputed_verification_result_hash=(
                recomputed_verification_result_hash),
            objections=objections)
        row = self._store.insert("review_results", {
            "review_id": review_id,
            "task_contract_id": task_contract_id,
            "verification_result_id": verification_result_id,
            "cycle_index": cycle_index,
            "outcome": outcome,
            "reason_code": reason_code,
            "reviewer_lineage": reviewer_lineage,
            "packet_hash": packet_hash,
            "recomputed_task_contract_hash": recomputed_task_contract_hash,
            "recomputed_verification_result_hash":
                recomputed_verification_result_hash,
            "objections_json": _dump([dict(o) for o in objections]),
            "review_hash": review_hash,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })
        self._event(
            INDEPENDENT_REVIEW, "review_recorded",
            task_contract_id=task_contract_id,
            module_id=str(contract["target_module_id"]),
            detail={"review_id": review_id, "outcome": outcome,
                    "cycle_index": cycle_index, "reason_code": reason_code,
                    "reviewer_lineage": reviewer_lineage,
                    "review_hash": review_hash},
        )
        return row

    def open_objection_cycle(self, *, cycle_id: str, task_contract_id: str,
                             review_id: str,
                             objections: Sequence[Mapping[str, Any]],
                             recovery_decision: str) -> Row:
        """Append one bounded review/recovery decision, or refuse.

        The recovery decision is a DECISION about immutable submitted
        evidence. ``replacement_execution_wiring`` is written as the single
        deferred value because executing a replacement candidate needs the real
        nonroot contained worker, which this increment does not have and does
        not pretend to have.
        """
        contract = self._ledger.require_task_contract(task_contract_id)
        if recovery_decision not in RECOVERY_DECISIONS:
            raise ReviewRefused("unknown recovery decision",
                                recovery_decision=recovery_decision,
                                known=list(RECOVERY_DECISIONS))
        used = self._ledger.objection_cycle_count(task_contract_id)
        if used >= MAX_OBJECTION_CYCLES:
            raise ObjectionCyclesExhausted(
                f"{MAX_OBJECTION_CYCLES} objection cycles are already "
                "recorded; a fourth cannot be opened",
                task_contract_id=task_contract_id,
                objection_cycles_used=used,
                max_objection_cycles=MAX_OBJECTION_CYCLES,
            )
        cycle_number = used + 1
        review = self._store.one(
            "SELECT * FROM review_results WHERE review_id = ?", (review_id,)
        )
        if review is None:
            raise ReviewRefused("objection cycle cites an unknown review",
                                review_id=review_id)
        if str(review["outcome"]) != REVIEW_OBJECTIONS:
            raise ReviewRefused(
                "only a review that returned OBJECTIONS opens a cycle",
                review_id=review_id, outcome=str(review["outcome"]),
            )
        if int(review["cycle_index"]) != cycle_number - 1:
            raise ReviewRefused(
                "the review's cycle_index does not line up with the cycle it "
                "would open",
                review_id=review_id, cycle_index=int(review["cycle_index"]),
                cycle_number=cycle_number,
            )
        terminal = 1 if cycle_number == MAX_OBJECTION_CYCLES else 0
        cycle_hash = sha256_hex({
            "__hash_domain__": "cis.assurance.objection_cycle.v1",
            "cycle_id": cycle_id,
            "task_contract_id": task_contract_id,
            "review_id": review_id,
            "cycle_number": cycle_number,
            "objections": [dict(o) for o in objections],
            "recovery_decision": recovery_decision,
            "replacement_execution_wiring": REPLACEMENT_WIRING_DEFERRED,
            "terminal": terminal,
        })
        row = self._store.insert("objection_cycles", {
            "cycle_id": cycle_id,
            "task_contract_id": task_contract_id,
            "review_id": review_id,
            "cycle_number": cycle_number,
            "objections_json": _dump([dict(o) for o in objections]),
            "recovery_decision": recovery_decision,
            "replacement_execution_wiring": REPLACEMENT_WIRING_DEFERRED,
            "terminal": terminal,
            "cycle_hash": cycle_hash,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })
        self._event(
            INDEPENDENT_REVIEW, "objection_cycle_opened",
            task_contract_id=task_contract_id,
            module_id=str(contract["target_module_id"]),
            detail={"cycle_id": cycle_id, "cycle_number": cycle_number,
                    "recovery_decision": recovery_decision,
                    "replacement_execution_wiring":
                        REPLACEMENT_WIRING_DEFERRED,
                    "terminal": bool(terminal),
                    "objection_cycles_remaining":
                        MAX_OBJECTION_CYCLES - cycle_number},
        )
        return row

    def record_route_receipt(self, receipt: Mapping[str, Any]) -> Row:
        """Append one reviewer-route receipt, or refuse before the append.

        The only sanctioned behavioral path into ``review_route_receipts``.
        ``cis.assurance.review_route.verify_receipt`` runs first — the pure,
        offline closed-schema and reviewer-policy check — and only a receipt
        that already passes it is checked against the ledger: the cited
        review must exist and the receipt must restate that review's own
        facts exactly, the cited verification result must be the exact row
        the review rests on, and the cited response evidence must be the
        exact observation the receipt claims it is.
        """
        review_route.verify_receipt(receipt)

        review = self._store.one(
            "SELECT * FROM review_results WHERE review_id = ?",
            (receipt["review_id"],),
        )
        if review is None:
            raise ReviewRefused(
                "route receipt cites an unknown review",
                review_id=receipt["review_id"],
            )

        receipt_objections = [dict(o) for o in receipt["objections"]]
        parsed_objections = json.loads(str(review["objections_json"]))
        disagreements = [
            name for name, mismatched in (
                ("task_contract_id", str(review["task_contract_id"])
                 != str(receipt["task_contract_id"])),
                ("verification_result_id",
                 str(review["verification_result_id"])
                 != str(receipt["verification_result_id"])),
                ("review_packet_hash", str(review["packet_hash"])
                 != str(receipt["review_packet_hash"])),
                ("reviewer_lineage", str(review["reviewer_lineage"])
                 != str(receipt["reviewer_lineage"])),
                ("verdict", str(review["outcome"]) != str(receipt["verdict"])),
                ("objections", parsed_objections != receipt_objections),
            ) if mismatched
        ]
        if disagreements:
            raise ReviewRefused(
                "route receipt does not exactly match the review it cites",
                review_id=receipt["review_id"], disagreements=disagreements,
            )

        verification = self._store.one(
            "SELECT * FROM verification_results WHERE result_id = ?",
            (receipt["verification_result_id"],),
        )
        if verification is None:
            raise ReviewRefused(
                "route receipt cites an unknown verification result",
                verification_result_id=receipt["verification_result_id"],
            )
        if (str(verification["task_contract_id"])
                != str(receipt["task_contract_id"])):
            raise ReviewRefused(
                "the cited verification result does not belong to the "
                "cited task contract",
                verification_result_id=receipt["verification_result_id"],
                task_contract_id=receipt["task_contract_id"],
            )

        evidence = self._store.one(
            "SELECT * FROM evidence_records WHERE evidence_id = ?",
            (receipt["response_evidence_id"],),
        )
        if evidence is None:
            raise ReviewRefused(
                "route receipt cites no recorded response evidence",
                response_evidence_id=receipt["response_evidence_id"],
            )
        if str(evidence["kind"]) != EXTERNAL_MODEL_REVIEW_RESPONSE_KIND:
            raise ReviewRefused(
                "response evidence has the wrong kind",
                expected=EXTERNAL_MODEL_REVIEW_RESPONSE_KIND,
                got=str(evidence["kind"]),
            )
        expected_source_ref = (
            f"openrouter:generation:{receipt['reviewer_request_id']}")
        if str(evidence["source_ref"]) != expected_source_ref:
            raise ReviewRefused(
                "response evidence source_ref does not name this reviewer "
                "request",
                expected=expected_source_ref, got=str(evidence["source_ref"]),
            )
        recomputed_content_hash = sha256_text(str(evidence["content"]))
        if recomputed_content_hash != str(evidence["content_hash"]):
            raise ReviewRefused(
                "response evidence does not recompute its own content digest",
                response_evidence_id=receipt["response_evidence_id"],
            )
        if recomputed_content_hash != str(receipt["response_sha256"]):
            raise ReviewRefused(
                "response evidence content does not match response_sha256",
                expected=receipt["response_sha256"],
                got=recomputed_content_hash,
            )
        try:
            parsed_response = json.loads(str(evidence["content"]))
        except ValueError as exc:
            raise ReviewRefused(
                "response evidence content is not valid JSON",
                response_evidence_id=receipt["response_evidence_id"],
            ) from exc
        if (not isinstance(parsed_response, dict)
                or set(parsed_response) != {"verdict", "objections"}):
            raise ReviewRefused(
                "response evidence content is not the closed "
                "{verdict, objections} shape",
                response_evidence_id=receipt["response_evidence_id"],
            )
        if parsed_response["verdict"] != receipt["verdict"]:
            raise ReviewRefused(
                "response evidence verdict does not match the receipt",
                expected=receipt["verdict"], got=parsed_response["verdict"],
            )
        if parsed_response["objections"] != receipt_objections:
            raise ReviewRefused(
                "response evidence objections do not match the receipt",
                expected=receipt_objections,
                got=parsed_response["objections"],
            )

        request = self._store.one(
            "SELECT * FROM worker_model_requests WHERE request_id = ?",
            (receipt["reviewer_request_id"],),
        )
        if request is None:
            raise ReviewRefused(
                "route receipt cites a reviewer request that was never "
                "issued through the worker session authority",
                reviewer_request_id=receipt["reviewer_request_id"],
            )
        if (str(request["adapter_id"]) != str(receipt["reviewer_adapter_id"])
                or str(request["response_schema_sha256"])
                != str(receipt["response_schema_sha256"])):
            raise ReviewRefused(
                "the reviewer request does not match the receipt's adapter "
                "or response schema",
                reviewer_request_id=receipt["reviewer_request_id"],
            )

        session = self._store.one(
            "SELECT * FROM worker_sessions WHERE session_id = ?",
            (request["session_id"],),
        )
        if session is None:
            raise ReviewRefused(
                "the reviewer request's worker session does not exist",
                session_id=request["session_id"],
            )
        if (str(session["logical_role"]) != "REVIEWER"
                or str(session["adapter_id"])
                != str(receipt["reviewer_adapter_id"])):
            raise ReviewRefused(
                "the reviewer request's worker session is not a REVIEWER "
                "session on the receipt's adapter",
                session_id=request["session_id"],
                logical_role=str(session["logical_role"]),
            )

        request_events = self._store.query(
            "SELECT * FROM worker_session_events WHERE request_id = ? "
            "ORDER BY seq",
            (receipt["reviewer_request_id"],),
        )
        terminal_events = [
            e for e in request_events
            if str(e["event_type"]) in ("REQUEST_SUCCEEDED", "REQUEST_FAILED")
        ]
        if (len(terminal_events) != 1
                or str(terminal_events[0]["event_type"]) != "REQUEST_SUCCEEDED"):
            raise ReviewRefused(
                "the reviewer request does not have exactly one terminal "
                "REQUEST_SUCCEEDED event",
                reviewer_request_id=receipt["reviewer_request_id"],
                terminal_event_count=len(terminal_events),
            )
        success_event = terminal_events[0]
        run_id = success_event["run_id"]
        if (str(success_event["evidence_id"])
                != str(receipt["response_evidence_id"])
                or run_id is None or not str(run_id).strip()):
            raise ReviewRefused(
                "the reviewer request's REQUEST_SUCCEEDED event does not "
                "cite this receipt's response evidence and a run",
                reviewer_request_id=receipt["reviewer_request_id"],
            )

        backend_run = self._store.one(
            "SELECT * FROM backend_runs WHERE run_id = ?", (run_id,),
        )
        if (backend_run is None
                or str(backend_run["status"]) != RUN_COMPLETED
                or str(backend_run["authorization_id"])
                != str(request["authorization_id"])
                or str(backend_run["adapter_id"])
                != str(receipt["reviewer_adapter_id"])
                or str(backend_run["evidence_id"])
                != str(receipt["response_evidence_id"])):
            raise ReviewRefused(
                "the backend run bound to the reviewer request's success "
                "event does not exist, is not completed, or does not match "
                "the request's authorization and adapter or the receipt's "
                "evidence",
                run_id=run_id,
            )

        row = self._store.insert("review_route_receipts", {
            "receipt_id": receipt["receipt_id"],
            "task_contract_id": receipt["task_contract_id"],
            "verification_result_id": receipt["verification_result_id"],
            "review_id": receipt["review_id"],
            "review_packet_hash": receipt["review_packet_hash"],
            "implementer_request_id": receipt["implementer_request_id"],
            "implementer_adapter_id": receipt["implementer_adapter_id"],
            "reviewer_request_id": receipt["reviewer_request_id"],
            "reviewer_adapter_id": receipt["reviewer_adapter_id"],
            "provider_id": receipt["provider_id"],
            "model_id": receipt["model_id"],
            "implementer_lineage": receipt["implementer_lineage"],
            "reviewer_lineage": receipt["reviewer_lineage"],
            "response_schema_sha256": receipt["response_schema_sha256"],
            "response_evidence_id": receipt["response_evidence_id"],
            "response_sha256": receipt["response_sha256"],
            "verdict": receipt["verdict"],
            "objections_json": canonical_json(receipt_objections),
            "hash_domain": receipt["hash_domain"],
            "receipt_hash": receipt["receipt_hash"],
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })
        contract = self._ledger.require_task_contract(
            str(receipt["task_contract_id"]))
        self._event(
            INDEPENDENT_REVIEW, "route_receipt_recorded",
            task_contract_id=str(receipt["task_contract_id"]),
            module_id=str(contract["target_module_id"]),
            detail={
                "receipt_id": receipt["receipt_id"],
                "review_id": receipt["review_id"],
                "reviewer_request_id": receipt["reviewer_request_id"],
                "provider_id": receipt["provider_id"],
                "model_id": receipt["model_id"],
                "receipt_hash": receipt["receipt_hash"],
                "verdict": receipt["verdict"],
            },
        )
        return row


class PromotionFacade(_Facade):
    """Appends promotion decisions, and performs no host action of any kind."""

    def record_decision(self, *, decision_id: str, task_contract_id: str,
                        decision: str, reason_code: str,
                        verification_result_id: str | None,
                        review_id: str | None) -> Row:
        contract = self._ledger.require_task_contract(task_contract_id)
        if decision not in (PROMOTION_AUTHORIZED, PROMOTION_DENIED):
            raise PromotionRefused("unknown promotion decision",
                                   decision=decision)
        if decision == PROMOTION_AUTHORIZED:
            # The conjunction, enforced at the ledger as well as by the
            # promotion module, so the facade cannot be driven past it.
            if not self._ledger.verification_passed(task_contract_id):
                raise PromotionRefused(
                    "PROMOTION_AUTHORIZED requires a recorded VERIFIED_PASS",
                    task_contract_id=task_contract_id,
                )
            if not self._ledger.review_passed(task_contract_id):
                raise PromotionRefused(
                    "PROMOTION_AUTHORIZED requires a recorded review PASS",
                    task_contract_id=task_contract_id,
                )
            if self._ledger.is_escalated(task_contract_id):
                raise PromotionRefused(
                    "an ESCALATED task contract cannot be promotion-authorized",
                    task_contract_id=task_contract_id,
                )
            if verification_result_id is None or review_id is None:
                raise PromotionRefused(
                    "PROMOTION_AUTHORIZED must cite the verification result "
                    "and the review it rests on",
                    task_contract_id=task_contract_id,
                )
            verification = self._ledger.verification_result(task_contract_id)
            review = self._ledger.latest_review(task_contract_id)
            if (verification is None or review is None
                    or str(verification_result_id) != str(verification["result_id"])
                    or str(review_id) != str(review["review_id"])
                    or str(review["verification_result_id"])
                    != str(verification["result_id"])
                    or str(review["recomputed_verification_result_hash"])
                    != str(verification["result_hash"])
                    or review_result_hash_of_row(review)
                    != str(review["review_hash"])):
                raise PromotionRefused(
                    "PROMOTION_AUTHORIZED requires the exact current review "
                    "and verification to be integrity-bound to each other",
                    task_contract_id=task_contract_id)
        decision_hash = sha256_hex({
            "__hash_domain__": "cis.assurance.promotion_decision.v1",
            "decision_id": decision_id,
            "task_contract_id": task_contract_id,
            "decision": decision,
            "reason_code": reason_code,
            "verification_result_id": verification_result_id,
            "review_id": review_id,
            "host_action": HOST_ACTION_NONE,
        })
        row = self._store.insert("promotion_decisions", {
            "decision_id": decision_id,
            "task_contract_id": task_contract_id,
            "decision": decision,
            "reason_code": reason_code,
            "verification_result_id": verification_result_id,
            "review_id": review_id,
            "host_action": HOST_ACTION_NONE,
            "decision_hash": decision_hash,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })
        self._event(
            PROMOTION_DECISION, "promotion_decision_recorded",
            task_contract_id=task_contract_id,
            module_id=str(contract["target_module_id"]),
            detail={"decision_id": decision_id, "decision": decision,
                    "reason_code": reason_code,
                    "host_action": HOST_ACTION_NONE,
                    "decision_hash": decision_hash},
        )
        return row


# ---------------------------------------------------------------------------
# Hash helpers shared across the increment
# ---------------------------------------------------------------------------

def verification_result_hash(*, result_id: str, task_contract_id: str,
                             input_id: str, outcome: str, reason_code: str,
                             checks_performed: Sequence[str],
                             findings: Sequence[Mapping[str, Any]]) -> str:
    """Recomputable from the stored row alone.

    The reviewer recomputes this from the verification result's own source
    fields, which is how an independent reviewer checks a recorded digest
    without asking the verifier for anything.
    """
    return sha256_hex({
        "__hash_domain__": "cis.assurance.verification_result.v1",
        "result_id": result_id,
        "task_contract_id": task_contract_id,
        "input_id": input_id,
        "outcome": outcome,
        "reason_code": reason_code,
        "checks_performed": list(checks_performed),
        "findings": [dict(f) for f in findings],
    })


def verification_result_hash_of_row(row: Mapping[str, Any]) -> str:
    return verification_result_hash(
        result_id=str(row["result_id"]),
        task_contract_id=str(row["task_contract_id"]),
        input_id=str(row["input_id"]),
        outcome=str(row["outcome"]),
        reason_code=str(row["reason_code"]),
        checks_performed=json.loads(str(row["checks_performed_json"])),
        findings=json.loads(str(row["findings_json"])),
    )


def review_result_hash(*, review_id: str, task_contract_id: str,
                       verification_result_id: str, cycle_index: int,
                       outcome: str, reason_code: str, reviewer_lineage: str,
                       packet_hash: str, recomputed_task_contract_hash: str,
                       recomputed_verification_result_hash: str,
                       objections: Sequence[Mapping[str, Any]]) -> str:
    return sha256_hex({
        "__hash_domain__": "cis.assurance.review_result.v1",
        "review_id": review_id,
        "task_contract_id": task_contract_id,
        "verification_result_id": verification_result_id,
        "cycle_index": cycle_index,
        "outcome": outcome,
        "reason_code": reason_code,
        "reviewer_lineage": reviewer_lineage,
        "packet_hash": packet_hash,
        "recomputed_task_contract_hash": recomputed_task_contract_hash,
        "recomputed_verification_result_hash":
            recomputed_verification_result_hash,
        "objections": [dict(o) for o in objections],
    })


def review_result_hash_of_row(row: Mapping[str, Any]) -> str:
    return review_result_hash(
        review_id=str(row["review_id"]),
        task_contract_id=str(row["task_contract_id"]),
        verification_result_id=str(row["verification_result_id"]),
        cycle_index=int(row["cycle_index"]), outcome=str(row["outcome"]),
        reason_code=str(row["reason_code"]),
        reviewer_lineage=str(row["reviewer_lineage"]),
        packet_hash=str(row["packet_hash"]),
        recomputed_task_contract_hash=str(row["recomputed_task_contract_hash"]),
        recomputed_verification_result_hash=str(
            row["recomputed_verification_result_hash"]),
        objections=json.loads(str(row["objections_json"])),
    )


# ---------------------------------------------------------------------------
# The owner
# ---------------------------------------------------------------------------

class AssuranceAuthority:
    """Owner of the seven assurance tables; reached only through its facades."""

    owned_authority = (
        "task_contracts", "verification_inputs", "verification_results",
        "review_results", "objection_cycles", "promotion_decisions",
        "review_route_receipts",
    )

    def __init__(self, store: AuthorityStore,
                 trajectory: TrajectoryAuthority | None = None) -> None:
        self._store = store
        self._trajectory = (trajectory if trajectory is not None
                            else TrajectoryAuthority(store))
        self.ledger = AssuranceLedger(store)
        self.task_contracts = TaskContractFacade(
            store, self.ledger, self._trajectory)
        self.verifier = VerifierFacade(store, self.ledger, self._trajectory)
        self.reviewer = ReviewerFacade(store, self.ledger, self._trajectory)
        self.promotion = PromotionFacade(store, self.ledger, self._trajectory)

    # -- integrity ----------------------------------------------------------

    def verify_task_contract(self, task_contract_id: str) -> Row:
        """Refuse unless the stored task contract recomputes its own digest."""
        row = self.ledger.require_task_contract(task_contract_id)
        verify_row(row)
        return row

    @staticmethod
    def facade_method_names() -> dict[str, set[str]]:
        """The public write-method names of the three disjoint facades.

        Exposed so the separation can be asserted from outside rather than
        described in a comment.
        """
        def names(cls: type) -> set[str]:
            return {
                name for name in vars(cls)
                if not name.startswith("_") and callable(getattr(cls, name))
            }

        return {
            "verifier": names(VerifierFacade),
            "reviewer": names(ReviewerFacade),
            "promotion": names(PromotionFacade),
        }
