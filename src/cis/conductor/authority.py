"""Authority module for the Conductor envelope.

Owns exactly one table: ``conductor_envelopes``. Records are append-only and
verified by recomputing the envelope hash and cross-checking the linked
authority rows. No verdict, no verbatim text and no run result is stored here
— only linkage ids and recomputable hashes, so there is no second source of
truth.
"""

from __future__ import annotations

from typing import Any

from ..authority import AuthorityStore
from ..canonical import sha256_hex
from ..errors import AuthorizationRefused, BindingError


#: Operation kind for an instruction that crossed the L1/L2 boundary.
OPERATION_INGRESS = "instruction_ingress"

#: Operation kind for a verified authorized execution.
OPERATION_EXECUTION = "authorized_execution"

#: The operator identity is derived locally, never supplied by a caller.
TRUSTED_LOCAL_OPERATOR = "trusted_local_operator"


def _envelope_hash_payload(envelope_id: str, operation: str,
                           content_hash: str, objective_id: str | None,
                           baseline_hash: str, operator_identity: str,
                           transaction_id: str | None,
                           authorization_id: str | None,
                           run_id: str | None) -> dict[str, Any]:
    return {
        "envelope_id": envelope_id,
        "operation": operation,
        "content_hash": content_hash,
        "objective_id": objective_id,
        "baseline_hash": baseline_hash,
        "operator_identity": operator_identity,
        "transaction_id": transaction_id,
        "authorization_id": authorization_id,
        "run_id": run_id,
    }


def envelope_hash(*, envelope_id: str, operation: str, content_hash: str,
                  objective_id: str | None, baseline_hash: str,
                  operator_identity: str, transaction_id: str | None,
                  authorization_id: str | None, run_id: str | None) -> str:
    """Recomputable binding over the envelope fields and linkage ids."""
    return sha256_hex(_envelope_hash_payload(
        envelope_id, operation, content_hash, objective_id, baseline_hash,
        operator_identity, transaction_id, authorization_id, run_id,
    ))


class ConductorAuthority:
    """Append-only envelope records for the Conductor boundary."""

    def __init__(self, store: AuthorityStore) -> None:
        self._store = store

    @classmethod
    def ingress_envelope_id(cls, transaction_id: str) -> str:
        return f"env-ing-{transaction_id}"

    @classmethod
    def execution_envelope_id(cls, authorization_id: str) -> str:
        return f"env-exe-{authorization_id}"

    def record_envelope(self, *, envelope_id: str, operation: str,
                        content_hash: str, objective_id: str | None,
                        baseline_hash: str,
                        operator_identity: str = TRUSTED_LOCAL_OPERATOR,
                        transaction_id: str | None = None,
                        authorization_id: str | None = None,
                        run_id: str | None = None) -> Any:
        """Append one immutable envelope."""
        eh = envelope_hash(
            envelope_id=envelope_id, operation=operation,
            content_hash=content_hash, objective_id=objective_id,
            baseline_hash=baseline_hash, operator_identity=operator_identity,
            transaction_id=transaction_id, authorization_id=authorization_id,
            run_id=run_id,
        )
        return self._store.insert("conductor_envelopes", {
            "envelope_id": envelope_id,
            "operation": operation,
            "content_hash": content_hash,
            "objective_id": objective_id,
            "baseline_hash": baseline_hash,
            "operator_identity": operator_identity,
            "transaction_id": transaction_id,
            "authorization_id": authorization_id,
            "run_id": run_id,
            "envelope_hash": eh,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })

    def get(self, envelope_id: str) -> Any:
        return self._store.one(
            "SELECT * FROM conductor_envelopes WHERE envelope_id = ?",
            (envelope_id,),
        )

    def all(self) -> list[Any]:
        return self._store.query(
            "SELECT * FROM conductor_envelopes ORDER BY seq"
        )

    def for_transaction(self, transaction_id: str) -> list[Any]:
        return self._store.query(
            "SELECT * FROM conductor_envelopes WHERE transaction_id = ? "
            "ORDER BY seq",
            (transaction_id,),
        )

    def for_authorization(self, authorization_id: str) -> list[Any]:
        return self._store.query(
            "SELECT * FROM conductor_envelopes WHERE authorization_id = ? "
            "ORDER BY seq",
            (authorization_id,),
        )

    def verify(self, envelope_id: str) -> Any:
        """Fail-closed envelope integrity check.

        Recomputes the envelope hash and cross-checks the linked intent,
        authorization and run rows. Any tampering with the envelope or with the
        authority rows it links to is refused.
        """
        row = self.get(envelope_id)
        if row is None:
            raise AuthorizationRefused(
                "no such conductor envelope",
                envelope_id=envelope_id,
            )
        recomputed = envelope_hash(
            envelope_id=str(row["envelope_id"]),
            operation=str(row["operation"]),
            content_hash=str(row["content_hash"]),
            objective_id=row["objective_id"],
            baseline_hash=str(row["baseline_hash"]),
            operator_identity=str(row["operator_identity"]),
            transaction_id=row["transaction_id"],
            authorization_id=row["authorization_id"],
            run_id=row["run_id"],
        )
        if recomputed != str(row["envelope_hash"]):
            raise BindingError(
                "conductor envelope hash does not recompute",
                envelope_id=envelope_id,
                recorded=str(row["envelope_hash"]),
                recomputed=recomputed,
            )

        self._cross_check(row)
        return row

    def _cross_check(self, row: Any) -> None:
        operation = str(row["operation"])
        content_hash = str(row["content_hash"])
        baseline_hash = str(row["baseline_hash"])
        objective_id = row["objective_id"]

        if operation == OPERATION_INGRESS:
            transaction_id = row["transaction_id"]
            if transaction_id is None:
                raise BindingError(
                    "ingress envelope has no transaction linkage",
                    envelope_id=row["envelope_id"],
                )
            intent = self._store.one(
                "SELECT verbatim_hash FROM intent_transactions "
                "WHERE transaction_id = ?",
                (transaction_id,),
            )
            if intent is None:
                raise BindingError(
                    "ingress envelope links to an unknown transaction",
                    envelope_id=row["envelope_id"],
                    transaction_id=transaction_id,
                )
            if str(intent["verbatim_hash"]) != content_hash:
                raise BindingError(
                    "ingress envelope content does not match instruction",
                    envelope_id=row["envelope_id"],
                    recorded_content=content_hash,
                    intent_content=str(intent["verbatim_hash"]),
                )
            decision = self._store.one(
                "SELECT prior_objective_id FROM continuity_decisions "
                "WHERE transaction_id = ?",
                (transaction_id,),
            )
            if decision is None:
                raise BindingError(
                    "ingress envelope has no continuity decision",
                    envelope_id=row["envelope_id"],
                    transaction_id=transaction_id,
                )
            if (decision["prior_objective_id"] or None) != objective_id:
                raise BindingError(
                    "ingress envelope objective does not match decision context",
                    envelope_id=row["envelope_id"],
                    recorded_objective=objective_id,
                    decision_objective=decision["prior_objective_id"],
                )
            auth = self._store.one(
                "SELECT baseline_hash FROM execution_authorizations "
                "WHERE transaction_id = ?",
                (transaction_id,),
            )
            if auth is None:
                raise BindingError(
                    "ingress envelope has no authorization for cross-check",
                    envelope_id=row["envelope_id"],
                    transaction_id=transaction_id,
                )
            if str(auth["baseline_hash"]) != baseline_hash:
                raise BindingError(
                    "ingress envelope baseline does not match authorization",
                    envelope_id=row["envelope_id"],
                    recorded_baseline=baseline_hash,
                    authorization_baseline=str(auth["baseline_hash"]),
                )

        elif operation == OPERATION_EXECUTION:
            authorization_id = row["authorization_id"]
            if authorization_id is None:
                raise BindingError(
                    "execution envelope has no authorization linkage",
                    envelope_id=row["envelope_id"],
                )
            auth = self._store.one(
                "SELECT binding_hash, objective_id, baseline_hash "
                "FROM execution_authorizations WHERE authorization_id = ?",
                (authorization_id,),
            )
            if auth is None:
                raise BindingError(
                    "execution envelope links to an unknown authorization",
                    envelope_id=row["envelope_id"],
                    authorization_id=authorization_id,
                )
            if str(auth["binding_hash"]) != content_hash:
                raise BindingError(
                    "execution envelope content does not match authorization binding",
                    envelope_id=row["envelope_id"],
                    recorded_content=content_hash,
                    authorization_binding=str(auth["binding_hash"]),
                )
            if str(auth["objective_id"]) != objective_id:
                raise BindingError(
                    "execution envelope objective does not match authorization",
                    envelope_id=row["envelope_id"],
                    recorded_objective=objective_id,
                    authorization_objective=str(auth["objective_id"]),
                )
            if str(auth["baseline_hash"]) != baseline_hash:
                raise BindingError(
                    "execution envelope baseline does not match authorization",
                    envelope_id=row["envelope_id"],
                    recorded_baseline=baseline_hash,
                    authorization_baseline=str(auth["baseline_hash"]),
                )
            run_id = row["run_id"]
            if run_id is not None:
                run = self._store.one(
                    "SELECT authorization_id FROM backend_runs WHERE run_id = ?",
                    (run_id,),
                )
                if run is None:
                    raise BindingError(
                        "execution envelope links to an unknown run",
                        envelope_id=row["envelope_id"],
                        run_id=run_id,
                    )
                if str(run["authorization_id"]) != authorization_id:
                    raise BindingError(
                        "execution envelope run does not match authorization",
                        envelope_id=row["envelope_id"],
                        authorization_id=authorization_id,
                        run_authorization=str(run["authorization_id"]),
                    )

        else:
            raise BindingError(
                "unknown envelope operation",
                envelope_id=row["envelope_id"],
                operation=operation,
            )
