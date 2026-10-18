"""Owner of ``evidence_records`` and ``evidence_conflicts``.

An evidence record is an immutable observation that something was measured. It
does not become authority by being retrieved, ranked highly or cited
(ADR-ARCH-002), and it does not become authority by being cited twice: nothing
in this table is an execution-authorization basis. When evidence disagrees with
itself this module records the conflict and the caller fails closed; no
resolution is invented.

Two things live here and must not be conflated, which is what the structured
``kind`` column is for. ADMITTED knowledge — a preserved human exchange, an
accepted decision — arrives through ``admit`` with an ``admission_basis``
naming the trusted import path. GENERATED derivatives — what CIS recorded about
its own execution — arrive from the Layer-2 gateway with the verified
authorization as their basis. ``cis.continuity.retrieval.provenance_of`` reads
that one column to tier them, and ranks a human's own words above a machine
restatement of them. Neither tier confers permission.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from ..canonical import sha256_text
from .store import AuthorityStore, Row


class EvidenceAuthority:
    owned_authority = ("evidence_records", "evidence_conflicts")

    def __init__(self, store: AuthorityStore) -> None:
        self._store = store

    # -- writes -------------------------------------------------------------

    def admit(self, *, evidence_id: str, kind: str, source_ref: str,
              content: str, admission_basis: str,
              original_language: str | None = None) -> Row:
        """Record one observation.

        ``original_language`` preserves the antecedent's own words, so a later
        retrieval can show the user the phrasing they actually used rather than
        a paraphrase of it.
        """
        if not admission_basis.strip():
            raise ValueError("admission_basis must name the trusted import basis")
        return self._store.insert("evidence_records", {
            "evidence_id": evidence_id,
            "kind": kind,
            "source_ref": source_ref,
            "original_language": original_language if original_language is not None else content,
            "content": content,
            "content_hash": sha256_text(content),
            "admission_basis": admission_basis,
            "observed_at": self._store.now(),
            "seq": self._store.next_seq(),
        })

    # Deliberately no generic record alias: evidence admission is a
    # privileged import path and is not exposed by the Workbench HTTP API.

    def record_conflict(self, *, conflict_id: str, subject: str,
                        detail: Mapping[str, Any]) -> Row:
        return self._store.insert("evidence_conflicts", {
            "conflict_id": conflict_id,
            "subject": subject,
            "detail_json": json.dumps(dict(detail), sort_keys=True),
            "detected_at": self._store.now(),
            "seq": self._store.next_seq(),
        })

    # -- reads --------------------------------------------------------------

    def get(self, evidence_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM evidence_records WHERE evidence_id = ?", (evidence_id,)
        )

    def all(self) -> list[Row]:
        return self._store.query("SELECT * FROM evidence_records ORDER BY seq")

    def of_kind(self, kind: str) -> list[Row]:
        return self._store.query(
            "SELECT * FROM evidence_records WHERE kind = ? ORDER BY seq", (kind,)
        )

    def conflicts(self) -> list[Row]:
        return self._store.query("SELECT * FROM evidence_conflicts ORDER BY seq")
