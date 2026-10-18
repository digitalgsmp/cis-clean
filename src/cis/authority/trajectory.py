"""Owner of ``trajectory_events`` — the append-only spine of the projection.

Two scopes, one table:
  * ``macro`` — reconstruction stage and selected-module progress;
  * ``micro`` — the steps of one transaction.

The "you are here" marker is NOT stored here. It is derived from the highest
``seq``, so there is exactly one authoritative record of position and no second
copy to drift (ADR-ARCH-002).
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from .store import AuthorityStore, Row

MACRO = "macro"
MICRO = "micro"

#: Stages that may be recorded on the micro (transaction) scope.  They are owned
#: by the trajectory authority and declared here so the manifest loader can
#: harden proven_slice.trajectory_stage without repeating the vocabulary.
HUMAN_INTENT = "HUMAN_INTENT"
AUTHORITATIVE_CONTEXT = "AUTHORITATIVE_CONTEXT"
CONTINUITY = "CONTINUITY"
REVIEW_AUTHORIZATION = "REVIEW_AUTHORIZATION"
GOVERNED_EXECUTION = "GOVERNED_EXECUTION"
EVIDENCE = "EVIDENCE"

#: Slice-2 assurance increment stages. They are appended to the vocabulary
#: rather than replacing any slice-1 stage, so every recorded event and every
#: proven_slice link that referred to the original six still resolves.
TASK_CONTRACT = "TASK_CONTRACT"
INDEPENDENT_VERIFICATION = "INDEPENDENT_VERIFICATION"
INDEPENDENT_REVIEW = "INDEPENDENT_REVIEW"
PROMOTION_DECISION = "PROMOTION_DECISION"

MICRO_STAGES: tuple[str, ...] = (
    HUMAN_INTENT,
    AUTHORITATIVE_CONTEXT,
    CONTINUITY,
    REVIEW_AUTHORIZATION,
    GOVERNED_EXECUTION,
    EVIDENCE,
    TASK_CONTRACT,
    INDEPENDENT_VERIFICATION,
    INDEPENDENT_REVIEW,
    PROMOTION_DECISION,
)

#: The subset the assurance increment owns. Declared here, with the rest of the
#: vocabulary, so the manifest loader can harden assurance_slice links against
#: it without repeating the list.
ASSURANCE_MICRO_STAGES: tuple[str, ...] = (
    TASK_CONTRACT,
    INDEPENDENT_VERIFICATION,
    INDEPENDENT_REVIEW,
    PROMOTION_DECISION,
)


class TrajectoryAuthority:
    owned_authority = ("trajectory_events",)

    def __init__(self, store: AuthorityStore) -> None:
        self._store = store

    def record(self, *, event_id: str, scope: str, stage: str, event_type: str,
               module_id: str | None = None, transaction_id: str | None = None,
               detail: Mapping[str, Any] | None = None) -> Row:
        return self._store.insert("trajectory_events", {
            "event_id": event_id,
            "seq": self._store.next_seq(),
            "scope": scope,
            "stage": stage,
            "module_id": module_id,
            "transaction_id": transaction_id,
            "event_type": event_type,
            "detail_json": json.dumps(dict(detail or {}), sort_keys=True),
            "created_at": self._store.now(),
        })

    def events(self, *, scope: str | None = None,
               transaction_id: str | None = None) -> list[Row]:
        clauses: list[str] = []
        params: list[Any] = []
        if scope is not None:
            clauses.append("scope = ?")
            params.append(scope)
        if transaction_id is not None:
            clauses.append("transaction_id = ?")
            params.append(transaction_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return self._store.query(
            f"SELECT * FROM trajectory_events {where} ORDER BY seq", params
        )

    def latest(self) -> Row | None:
        """The single row from which position is derived."""
        return self._store.one(
            "SELECT * FROM trajectory_events ORDER BY seq DESC LIMIT 1"
        )

    def count(self) -> int:
        row = self._store.one("SELECT COUNT(*) AS n FROM trajectory_events")
        return int(row["n"]) if row else 0
