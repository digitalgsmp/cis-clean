"""Carries one recorded recovery attempt's child through the existing path.

``RecoveryAttemptAuthority`` records the forward link from an operational
assessment to a fresh child task contract and execution-input binding, but it
appends that link purely from recorded authority and never dispatches,
verifies, reviews or promotes anything. This module is the other half: given
an assessment and a SEPARATE, already-existing ALLOW authorization for the
child, it drives the replacement candidate through exactly the path a fresh
authored-source submission already uses — ``AuthoredSourceIssuer`` to freeze
and bind it, the selected ``ExecutionGateway`` to dispatch it, ``Verifier`` to
assess it, ``Reviewer`` to independently review it and ``PromotionRecorder``
to record the conjunction. Nothing here is a second verifier, a second
reviewer or a second promotion rule; there is exactly one assurance path, and
a recovered candidate walks the same one an original candidate would.

NO NEW TABLE. This module owns no authority of its own. The one new fact a
successful call produces is the ``recovery_attempts`` row
``RecoveryAttemptAuthority`` itself appends; every other row it causes to
exist is appended by the module that already owns that table.

A DISTINCT, SEPARATELY AUTHORIZED CHILD. A recovery that reused the very
authorization it is recovering from would not be a separate decision at all,
so the child authorization is required to differ from the parent's own, and
is independently re-verified as a live ALLOW scoped to
``verify_authored_source`` over the parent's exact target module before
anything is issued or dispatched. ``RecoveryExecutionRefused`` covers every
way that check can fail.

SAFE TO RESUME. Every step this module calls is itself idempotent given the
same inputs — ``AuthoredSourceIssuer.issue``, ``RecoveryAttemptAuthority.record``,
``Verifier.verify`` and ``PromotionRecorder.decide`` all return their already-
recorded row rather than re-appending — except dispatch, which claims one
attempt per authorization and refuses a replay, and review, which opens a
fresh cycle on every call. This module checks for an already-recorded run and
an already-recorded review before calling either, so re-running ``execute``
after a crash midway resumes rather than re-erroring or double-reviewing.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..authority.authorization import AuthorizationAuthority
from ..authority.runs import RunAuthority
from ..errors import AuthorizationRefused, RecoveryExecutionRefused
from .authority import AssuranceAuthority
from .issuance import AuthoredSourceIssuer
from .promotion import PromotionRecorder
from .recovery import REPLACEMENT_REQUIRED, OperationalSelfAssessment
from .recovery_attempt import RecoveryAttemptAuthority
from .reviewer import Reviewer
from .verifier import Verifier


class RecoveryExecutionAuthority:
    """Drives one recovery attempt's child through verify/review/promote."""

    module_id = "cis.assurance.recovery_execution"

    def __init__(self, *, store, blueprint, gateway,
                 authorizations: AuthorizationAuthority | None = None) -> None:
        self._store = store
        self._blueprint = blueprint
        self._gateway = gateway
        self._authorizations = (authorizations if authorizations is not None
                                else AuthorizationAuthority(store))
        self._runs = RunAuthority(store)
        self._assurance = AssuranceAuthority(store)
        self._assessments = OperationalSelfAssessment(store)
        self._issuer = AuthoredSourceIssuer(
            store=store, blueprint=blueprint,
            authorizations=self._authorizations, gateway=gateway)
        self._attempts = RecoveryAttemptAuthority(store)
        self._verifier = Verifier(store, blueprint, self._assurance)
        self._reviewer = Reviewer(store, blueprint, self._assurance)
        self._promotion = PromotionRecorder(store, self._assurance)

    def execute(self, assessment_id: str, *, child_authorization_id: str,
                candidate_source: bytes | str,
                vectors: Sequence[Mapping[str, Any]], entrypoint: str,
                active_objective_id: str | None) -> dict:
        """Carry out one bounded recovery over an existing child ALLOW.

        Refuses before issuing or dispatching anything if the child
        authorization is the parent's own, is not a live ALLOW scoped to
        ``verify_authored_source``, or targets a different module than the
        parent task contract it is meant to replace. Safe to call again with
        the same arguments: every step it drives is independently idempotent
        or is guarded here against being repeated.
        """
        assessment = self._assessments.verify(assessment_id)
        if str(assessment["disposition"]) != REPLACEMENT_REQUIRED:
            raise RecoveryExecutionRefused(
                "recovery execution requires a replacement-candidate "
                "assessment",
                assessment_id=assessment_id,
                disposition=str(assessment["disposition"]))
        parent_task_contract_id = str(assessment["task_contract_id"])
        parent_contract = self._assurance.verify_task_contract(
            parent_task_contract_id)
        parent_authorization_id = str(parent_contract["authorization_id"])

        if child_authorization_id == parent_authorization_id:
            raise RecoveryExecutionRefused(
                "a recovery child must be authorized separately from the "
                "parent it is recovering from",
                authorization_id=child_authorization_id)

        try:
            child_authorization = self._authorizations.verify(
                child_authorization_id,
                baseline_hash=self._blueprint.baseline_hash,
                active_objective_id=active_objective_id)
        except AuthorizationRefused as exc:
            raise RecoveryExecutionRefused(
                "recovery child authorization did not verify",
                authorization_id=child_authorization_id) from exc
        scope = self._authorizations.scope_of(child_authorization)
        if str(scope["operation"]) != "verify_authored_source":
            raise RecoveryExecutionRefused(
                "recovery child authorization does not permit "
                "authored-source verification",
                authorization_id=child_authorization_id,
                operation=str(scope["operation"]))
        if str(child_authorization["target_module_id"]) != str(
                parent_contract["target_module_id"]):
            raise RecoveryExecutionRefused(
                "recovery child authorization targets a different module "
                "than the parent it is meant to replace",
                parent_module=str(parent_contract["target_module_id"]),
                child_module=str(child_authorization["target_module_id"]))

        issued = self._issuer.issue(
            child_authorization_id, candidate_source=candidate_source,
            vectors=vectors, entrypoint=entrypoint,
            active_objective_id=active_objective_id)
        child_task_contract_id = str(issued["task_contract_id"])

        attempt = self._attempts.record(
            assessment_id, child_task_contract_id=child_task_contract_id)

        runs = self._runs.for_authorization(child_authorization_id)
        if not runs:
            if self._runs.claim_for_authorization(child_authorization_id) is not None:
                raise RecoveryExecutionRefused(
                    "recovery child authorization was claimed but produced no "
                    "recorded run",
                    authorization_id=child_authorization_id)
            run = self._gateway.dispatch(
                child_authorization_id,
                baseline_hash=self._blueprint.baseline_hash,
                active_objective_id=active_objective_id)
        else:
            run = runs[-1]

        verification = self._verifier.verify(child_task_contract_id)

        existing_review = self._assurance.ledger.latest_review(
            child_task_contract_id)
        if existing_review is None:
            review, cycle = self._reviewer.review(child_task_contract_id)
        else:
            review = existing_review
            cycles = self._assurance.ledger.objection_cycles(
                child_task_contract_id)
            cycle = cycles[-1] if cycles else None

        decision = self._promotion.decide(child_task_contract_id)

        return {
            "assessment_id": assessment_id,
            "attempt_id": str(attempt["attempt_id"]),
            "parent_task_contract_id": parent_task_contract_id,
            "child_authorization_id": child_authorization_id,
            "child_task_contract_id": child_task_contract_id,
            "execution_input_id": str(issued["execution_input_id"]),
            "run_id": str(run["run_id"]),
            "run_status": str(run["status"]),
            "verification": verification,
            "review": review,
            "cycle": cycle,
            "decision": decision,
        }


__all__ = ["RecoveryExecutionAuthority"]
