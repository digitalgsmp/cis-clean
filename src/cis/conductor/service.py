"""Layer-2 Conductor service: the single ingress-to-evidence boundary.

This service wraps the two existing public mutation operations — instruction
ingress and authorized execution — in an immutable authority-bound envelope.
It derives the operator identity locally, never accepts a caller-supplied
actor, and delegates all writes to the existing Workbench and authority
modules. Existing authorities remain owners of their own tables.
"""

from __future__ import annotations

from ..errors import CisError
from ..workbench import InstructionOutcome, Workbench
from .authority import (
    OPERATION_EXECUTION, OPERATION_INGRESS, TRUSTED_LOCAL_OPERATOR,
    ConductorAuthority,
)


class Conductor:
    """One boundary through which Layer 1 public mutations enter authority.

    The Conductor records an append-only envelope for every ingress and every
    authorized execution. It copies no verdicts; it links to the rows that
    already own the facts.
    """

    def __init__(self, workbench: Workbench,
                 authority: ConductorAuthority | None = None) -> None:
        self.workbench = workbench
        self.authority = authority if authority is not None \
            else ConductorAuthority(workbench.store)

    def ingest_instruction(self, verbatim: str) -> InstructionOutcome:
        """Layer-1 instruction ingress, wrapped in an envelope.

        The operator identity is derived locally; no actor parameter is
        accepted from the caller.

        A HOLD is enveloped exactly like an ALLOW: the envelope is evidence
        that the transaction was attempted and how it was disposed of, not
        evidence that anything was permitted. The verdict stays where its
        owner recorded it.

        The bound objective is the one that was active when the words arrived
        — the decision's ``prior_objective_id`` — because that is the context
        the ingress actually happened in. An objective this instruction went
        on to establish or supersede is a consequence of the transaction, not
        the context of it.
        """
        outcome = self.workbench.submit_instruction(verbatim)
        transaction_id = outcome.transaction_id
        intent_row = self.workbench.intent.transaction(transaction_id)
        if intent_row is None:  # pragma: no cover - the row was just written
            raise CisError("instruction vanished from authority",
                           transaction_id=transaction_id)
        self.authority.record_envelope(
            envelope_id=ConductorAuthority.ingress_envelope_id(transaction_id),
            operation=OPERATION_INGRESS,
            content_hash=str(intent_row["verbatim_hash"]),
            objective_id=outcome.decision["prior_objective_id"],
            baseline_hash=self.workbench.blueprint.baseline_hash,
            operator_identity=TRUSTED_LOCAL_OPERATOR,
            transaction_id=transaction_id,
        )
        return outcome

    def execute_authorization(self, authorization_id: str) -> dict:
        """Layer-1 authorized execution, wrapped in an envelope.

        Delegation to the existing gateway preserves the existing fail-closed
        behavior: if the authorization is unknown, not an ALLOW, stale, already
        executed or its binding does not recompute, the gateway refuses before
        any backend work — the refusal propagates and no envelope is recorded,
        so there is never a successful envelope for work that did not run. The
        gateway's own refusal trajectory event remains the evidence of the
        attempt.
        """
        result = self.workbench.execute(authorization_id)
        authorization = self.workbench.authorizations.get(authorization_id)
        if authorization is None:  # pragma: no cover - verified before the run
            raise CisError("authorization vanished from authority",
                           authorization_id=authorization_id)
        self.authority.record_envelope(
            envelope_id=ConductorAuthority.execution_envelope_id(authorization_id),
            operation=OPERATION_EXECUTION,
            content_hash=str(authorization["binding_hash"]),
            objective_id=str(authorization["objective_id"]),
            baseline_hash=str(authorization["baseline_hash"]),
            operator_identity=TRUSTED_LOCAL_OPERATOR,
            authorization_id=authorization_id,
            run_id=result["run_id"],
        )
        return result
