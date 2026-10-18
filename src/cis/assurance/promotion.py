"""Promotion decisions. Records only; performs no host action.

``PROMOTION_AUTHORIZED`` is a CONJUNCTION and nothing less: a recorded
``VERIFIED_PASS`` from the verifier AND a recorded ``PASS`` from the
independent reviewer, over the same frozen task contract, with no objection
cycle having escalated it. Either half missing, or pending, or failed, and the
decision is ``PROMOTION_DENIED`` with the reason code that says which half.

THIS MODULE DOES NOT PROMOTE ANYTHING
-------------------------------------

It records that a decision was made. It copies no file, writes no unit, starts
no service and touches no host. That is not an omission to be filled in later
by this module: the host is a different trust domain, the handoff to it is a
different capability, and a module that both decided and acted would be the
single place where an unreviewed decision could become an applied change.

The claim is checked, not asserted. This file imports ``os``, ``subprocess``,
``shutil``, ``socket``, ``pathlib`` and ``sys`` nowhere; ``host_action`` is
CHECKed in SQL to the single value ``NONE_RECORD_ONLY``; and
``tests/test_assurance.py`` reads this module's own source to assert the
absence of every one of those imports.

IT DOES NOT CALL THE VERIFIER OR THE REVIEWER
---------------------------------------------

It reads their RECORDED results through the assurance ledger. Its contract
declares strict independence from both, so the registry refuses a contract set
in which promotion could reach either one and re-run it to get an answer it
preferred.
"""

from __future__ import annotations

from ..canonical import sha256_hex
from .authority import (
    AssuranceAuthority, HOST_ACTION_NONE, PROMOTION_AUTHORIZED,
    PROMOTION_DENIED, REVIEW_PENDING,
)

REASON_CONJUNCTION_SATISFIED = "VERIFICATION_PASSED_AND_REVIEW_PASSED"
REASON_VERIFICATION_PENDING = "VERIFICATION_NOT_RECORDED"
REASON_VERIFICATION_FAILED = "VERIFICATION_DID_NOT_PASS"
REASON_REVIEW_PENDING = "REVIEW_NOT_RECORDED"
REASON_REVIEW_OBJECTIONS = "REVIEW_RAISED_OBJECTIONS"
REASON_ESCALATED = "OBJECTION_CYCLES_EXHAUSTED_AND_ESCALATED"
REASON_ALREADY_DECIDED = "PROMOTION_ALREADY_DECIDED"

#: The only host action this increment is capable of recording.
HOST_ACTION = HOST_ACTION_NONE


class PromotionRecorder:
    """Records one promotion decision per request, and acts on nothing."""

    module_id = "cis.assurance.promotion"

    def __init__(self, store, authority: AssuranceAuthority | None = None) -> None:
        self._store = store
        self._authority = (authority if authority is not None
                           else AssuranceAuthority(store))

    @staticmethod
    def decision_id(task_contract_id: str, attempt: int) -> str:
        suffix = sha256_hex({"task_contract_id": task_contract_id,
                             "attempt": attempt})[:12]
        return f"pd-{suffix}"

    def evaluate(self, task_contract_id: str) -> dict:
        """The decision, derived from the ledger. Writes nothing.

        Separated from ``decide`` so the conjunction can be read without
        recording anything — a read-only surface needs the answer, not a new
        row every time somebody looks.
        """
        ledger = self._authority.ledger
        ledger.require_task_contract(task_contract_id)

        verification = ledger.verification_result(task_contract_id)
        review = ledger.latest_review(task_contract_id)

        if ledger.is_escalated(task_contract_id):
            return self._denied(REASON_ESCALATED, verification, review)
        if verification is None:
            return self._denied(REASON_VERIFICATION_PENDING, None, review)
        if not ledger.verification_passed(task_contract_id):
            return self._denied(REASON_VERIFICATION_FAILED, verification, review)
        if review is None or ledger.review_status(task_contract_id) == REVIEW_PENDING:
            return self._denied(REASON_REVIEW_PENDING, verification, None)
        if not ledger.review_passed(task_contract_id):
            return self._denied(REASON_REVIEW_OBJECTIONS, verification, review)

        return {
            "decision": PROMOTION_AUTHORIZED,
            "reason_code": REASON_CONJUNCTION_SATISFIED,
            "verification_result_id": str(verification["result_id"]),
            "review_id": str(review["review_id"]),
            "host_action": HOST_ACTION,
        }

    @staticmethod
    def _denied(reason_code: str, verification, review) -> dict:
        return {
            "decision": PROMOTION_DENIED,
            "reason_code": reason_code,
            # A denial still cites what it looked at, when there was something
            # to look at. A denial with no linkage is unreviewable.
            "verification_result_id": (str(verification["result_id"])
                                       if verification is not None else None),
            "review_id": (str(review["review_id"])
                          if review is not None else None),
            "host_action": HOST_ACTION,
        }

    def decide(self, task_contract_id: str):
        """Record one promotion decision, or refuse.

        A task contract whose promotion is already decided returns the recorded
        decision rather than appending a second: the decision is a conclusion
        about a fixed set of immutable facts, so re-deciding would either
        restate it or contradict authority.
        """
        existing = self._authority.ledger.latest_promotion(task_contract_id)
        if existing is not None:
            return existing

        outcome = self.evaluate(task_contract_id)
        return self._authority.promotion.record_decision(
            decision_id=self.decision_id(task_contract_id, 1),
            task_contract_id=task_contract_id,
            decision=outcome["decision"],
            reason_code=outcome["reason_code"],
            verification_result_id=outcome["verification_result_id"],
            review_id=outcome["review_id"],
        )
