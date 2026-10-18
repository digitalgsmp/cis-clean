"""Owner of ``continuity_decisions``.

This is the authority behind the recorded acceptance criterion at
dev_continuity_events revision 178: a question or a semantic memory fragment
must recover and preserve prior intent rather than silently redirect
development. The active objective is DERIVED from the latest decision here,
never stored as a mutable flag (ADR-ARCH-002).
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from ..canonical import sha256_hex
from .store import AuthorityStore, Row

#: Only this classification may replace the active trajectory.
REDIRECTION = "redirection"

TREATED_AS_CUE = "retrieval_cue"
TREATED_AS_SUPERSESSION = "objective_supersession"


def decision_hash(*, transaction_id: str, classification: str, treated_as: str,
                  prior_objective_id: str | None, active_objective_id: str | None,
                  antecedents: Sequence[Mapping[str, Any]],
                  disposition: str) -> str:
    """The canonical hash of a continuity decision.

    Recomputable from the stored row alone, which is what lets an execution
    authorization bind to the decision that produced it.
    """
    return sha256_hex({
        "transaction_id": transaction_id,
        "classification": classification,
        "treated_as": treated_as,
        "prior_objective_id": prior_objective_id,
        "active_objective_id": active_objective_id,
        "antecedents": [dict(a) for a in antecedents],
        "disposition": disposition,
    })


class ContinuityAuthority:
    owned_authority = ("continuity_decisions",)

    def __init__(self, store: AuthorityStore) -> None:
        self._store = store

    # -- writes -------------------------------------------------------------

    def record_decision(self, *, decision_id: str, transaction_id: str,
                        classification: str, treated_as: str,
                        prior_objective_id: str | None,
                        active_objective_id: str | None,
                        antecedents: Sequence[Mapping[str, Any]],
                        disposition: str, rationale: str) -> Row:
        return self._store.insert("continuity_decisions", {
            "decision_id": decision_id,
            "transaction_id": transaction_id,
            "classification": classification,
            "treated_as": treated_as,
            "prior_objective_id": prior_objective_id,
            "active_objective_id": active_objective_id,
            "antecedents_json": json.dumps(
                [dict(a) for a in antecedents], sort_keys=True
            ),
            "disposition": disposition,
            "rationale": rationale,
            "decision_hash": decision_hash(
                transaction_id=transaction_id,
                classification=classification,
                treated_as=treated_as,
                prior_objective_id=prior_objective_id,
                active_objective_id=active_objective_id,
                antecedents=antecedents,
                disposition=disposition,
            ),
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })

    # -- reads --------------------------------------------------------------

    def decision(self, decision_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM continuity_decisions WHERE decision_id = ?",
            (decision_id,),
        )

    def latest(self) -> Row | None:
        return self._store.one(
            "SELECT * FROM continuity_decisions ORDER BY seq DESC LIMIT 1"
        )

    def for_transaction(self, transaction_id: str) -> list[Row]:
        return self._store.query(
            "SELECT * FROM continuity_decisions WHERE transaction_id = ? ORDER BY seq",
            (transaction_id,),
        )

    def active_objective_id(self) -> str | None:
        """Derived: the objective governing current direction.

        A superseded objective is not erased; it simply stops being the one the
        latest decision names (ADR-ARCH-004 clause 1).
        """
        latest = self.latest()
        if latest is not None:
            value = latest["active_objective_id"]
            return str(value) if value is not None else None
        row = self._store.one("SELECT * FROM objectives ORDER BY seq DESC LIMIT 1")
        return str(row["objective_id"]) if row else None

    def superseded_objective_ids(self) -> list[str]:
        rows = self._store.query(
            "SELECT DISTINCT prior_objective_id FROM continuity_decisions "
            "WHERE prior_objective_id IS NOT NULL "
            "AND prior_objective_id <> active_objective_id ORDER BY prior_objective_id"
        )
        return [str(row["prior_objective_id"]) for row in rows]

    def all(self) -> list[Row]:
        return self._store.query("SELECT * FROM continuity_decisions ORDER BY seq")
