"""Append-only authority for ingested MASTER/TASK policy-document sources.

This is the structured-source facade of ``cis.policy.authority``: that module
family owns ``policy_sources`` and this facade does nothing else. No prose is
ever parsed here and no
model is ever consulted — ``ingest`` accepts only a document that already
satisfies ``cis.policy.schema.parse_policy``, and ``current_policy_set``
rebuilds and whole-set-validates ``PolicySet`` from the ledger on every call,
the same discipline ``cis.policy.schema.PolicySet.validate`` documents for
itself and ``cis.assurance.authority.AssuranceLedger`` uses for derived state.

IDEMPOTENCY AND REFUSAL
-----------------------

A ``policy_id`` names one fixed document, forever, the same way a frozen task
contract or a recorded contract digest is fixed the instant it exists:

  * ingesting byte-identical content under a ``policy_id`` already on record
    is a no-op that returns the existing row — the same submission arriving
    twice must not create two rows or two meanings;
  * ingesting DIFFERENT content under a ``policy_id`` already on record
    refuses outright (``PolicySourceConflict``) — a policy document does not
    get silently revised in place. A real change is a NEW ``policy_id`` (or a
    new version in the same ``lineage_id``, superseding the old one through
    the ordinary supersession mechanism ``PolicySet.validate`` already
    enforces).

Both the SQL ``UNIQUE`` constraint on ``policy_id`` and the no-update/no-delete
triggers (migration 0008) back this at the storage layer, so a caller that
bypassed this module entirely still could not quietly rewrite a recorded
document.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, Mapping, Sequence

from ..authority.store import AuthorityStore, Row
from ..errors import (
    PolicyInvalidSupersession, PolicyRefused, PolicySourceConflict,
    PolicyTampered,
)
from .schema import (
    DOCUMENT_HASH_DOMAIN, STATUS_SUPERSEDED, PolicyDocument, PolicySet,
    parse_policy,
)


def _dump(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def document_from_row(row: Mapping[str, Any]) -> PolicyDocument:
    """Recompute and return the ``PolicyDocument`` a stored row carries.

    Refuses unless the row's own digest and hash domain recompute, so a
    tampered or forged source row can never silently contribute to a compiled
    policy set.
    """
    try:
        document = parse_policy({
            "policy_id": str(row["policy_id"]),
            "lineage_id": str(row["lineage_id"]),
            "kind": str(row["kind"]),
            "version": int(row["version"]),
            "status": str(row["status"]),
            "supersedes": row["supersedes"],
            "conflicts_with": json.loads(str(row["conflicts_with_json"])),
            "selector": (
                json.loads(str(row["selector_json"]))
                if row["selector_json"] is not None else None
            ),
            "effect_kinds": json.loads(str(row["effect_kinds_json"])),
            "prohibited_actions": json.loads(str(row["prohibited_actions_json"])),
            "required_checks": json.loads(str(row["required_checks_json"])),
            "required_evidence": json.loads(str(row["required_evidence_json"])),
            "narrowed_scope": (
                json.loads(str(row["narrowed_scope_json"]))
                if row["narrowed_scope_json"] is not None else None
            ),
            "hold": bool(row["hold"]),
            "rationale": str(row["rationale"]),
            "evidence_basis": json.loads(str(row["evidence_basis_json"])),
        })
    except (KeyError, TypeError, ValueError, json.JSONDecodeError,
            PolicyRefused) as exc:
        raise PolicyTampered("stored policy source is malformed") from exc
    if str(row["hash_domain"]) != DOCUMENT_HASH_DOMAIN:
        raise PolicyTampered(
            "stored policy source carries an unknown hash domain",
            policy_id=document.policy_id,
            recorded=str(row["hash_domain"]), expected=DOCUMENT_HASH_DOMAIN,
        )
    if document.document_hash != str(row["document_hash"]):
        raise PolicyTampered(
            "stored policy source does not recompute its own digest",
            policy_id=document.policy_id,
            recorded=str(row["document_hash"]),
            recomputed=document.document_hash,
        )
    return document


class PolicySourceAuthority:
    """Source-admission facade of the single ``cis.policy.authority`` owner."""

    owned_authority = ("policy_sources",)

    def __init__(self, store: AuthorityStore) -> None:
        self._store = store

    def row_for_policy_id(self, policy_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM policy_sources WHERE policy_id = ?", (policy_id,),
        )

    @staticmethod
    def _effective_set(documents: Sequence[PolicyDocument]) -> PolicySet:
        """Derive lifecycle state without rewriting an admitted source row."""
        by_id = {document.policy_id: document for document in documents}
        superseded_ids = {
            document.supersedes for document in documents
            if document.supersedes is not None
        }
        for document in documents:
            if document.supersedes is None:
                continue
            target = by_id.get(document.supersedes)
            if target is not None and document.version <= target.version:
                raise PolicyInvalidSupersession(
                    "a superseding policy version must be greater than its target",
                    policy_id=document.policy_id,
                    version=document.version,
                    supersedes=document.supersedes,
                    target_version=target.version,
                )
        effective = tuple(
            replace(document, status=STATUS_SUPERSEDED)
            if document.policy_id in superseded_ids else document
            for document in documents
        )
        policy_set = PolicySet(effective)
        policy_set.validate()
        return policy_set

    def _stored_documents(self) -> tuple[PolicyDocument, ...]:
        rows = self._store.query("SELECT * FROM policy_sources ORDER BY seq")
        return tuple(document_from_row(row) for row in rows)

    def _values(self, document: PolicyDocument, provenance: str) -> dict:
        return {
            "policy_source_id": "psrc-" + document.document_hash,
            "policy_id": document.policy_id,
            "lineage_id": document.lineage_id,
            "kind": document.kind,
            "version": document.version,
            "status": document.status,
            "supersedes": document.supersedes,
            "conflicts_with_json": _dump(list(document.conflicts_with)),
            "selector_json": (
                _dump(dict(document.selector))
                if document.selector is not None else None
            ),
            "effect_kinds_json": _dump(list(document.effect_kinds)),
            "prohibited_actions_json": _dump(list(document.prohibited_actions)),
            "required_checks_json": _dump(list(document.required_checks)),
            "required_evidence_json": _dump(list(document.required_evidence)),
            "narrowed_scope_json": (
                _dump(list(document.narrowed_scope))
                if document.narrowed_scope is not None else None
            ),
            "hold": document.hold,
            "rationale": document.rationale,
            "evidence_basis_json": _dump(list(document.evidence_basis)),
            "hash_domain": DOCUMENT_HASH_DOMAIN,
            "document_hash": document.document_hash,
            "provenance": provenance,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        }

    def ingest_many(self, raw_documents: Sequence[Mapping[str, object]], *,
                    provenance: str) -> list[Row]:
        """Validate the resulting whole set, then append all new rows atomically."""
        if not isinstance(provenance, str) or not provenance.strip():
            raise PolicySourceConflict(
                "policy source ingestion requires non-empty provenance")
        documents = tuple(parse_policy(raw) for raw in raw_documents)
        ids = [document.policy_id for document in documents]
        if len(set(ids)) != len(ids):
            raise PolicySourceConflict("policy ingestion batch repeats policy_id",
                                       policy_ids=ids)
        stored = self._stored_documents()
        existing = {document.policy_id: document for document in stored}
        new_documents: list[PolicyDocument] = []
        for document in documents:
            prior = existing.get(document.policy_id)
            if prior is not None:
                if prior.document_hash != document.document_hash:
                    raise PolicySourceConflict(
                        "policy_id is already recorded with different content; "
                        "a policy document's content is fixed once ingested",
                        policy_id=document.policy_id,
                        recorded_document_hash=prior.document_hash,
                        submitted_document_hash=document.document_hash,
                    )
                continue
            new_documents.append(document)
        self._effective_set((*stored, *new_documents))
        values = [self._values(document, provenance.strip())
                  for document in new_documents]
        return self._store.insert_batch("policy_sources", values)

    def ingest(self, raw: Mapping[str, object], *, provenance: str) -> Row:
        """Validate and append one policy document, or refuse.

        ``provenance`` is a required, non-empty record of where the document
        came from (a baseline source file, an operator submission, etc.) — a
        source row with no stated origin is not something this ledger will
        record.
        """
        document = parse_policy(raw)
        existing = self.row_for_policy_id(document.policy_id)
        self.ingest_many((raw,), provenance=provenance)
        return existing or self.row_for_policy_id(document.policy_id)  # type: ignore[return-value]

    def current_policy_set(self) -> PolicySet:
        """Deterministically rebuild and whole-set-validate current policy.

        Re-read from the append-only ledger and re-validated on every call —
        there is no cached, trusted-once result, and no document contributes
        unless its own stored digest recomputes.
        """
        return self._effective_set(self._stored_documents())


__all__ = ["PolicySourceAuthority", "document_from_row"]
