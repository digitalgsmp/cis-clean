"""Owner of ``execution_authorizations`` — the structured execution contract.

ADR-ARCH-004 clause 3: the contract is the machine-readable definition of
allowed scope, forbidden actions, required checks, required evidence, stopping
condition and return point. It CONSTRAINS execution and cannot create
authority, and a model must not expand scope merely by writing a broader
contract — which is why the scope is part of the binding hash and the binding
hash is recomputed from authority before any dispatch.

``required_evidence`` names the CANONICAL ACCEPTED AUTHORITY under which the
work was permitted — for this slice, the validated manifest entry and
``evidence_basis`` of the target module, labeled as such. It is not a list of
retrieved antecedent ids, and it never contains an ``intent:tx-*`` or
``evi-run-*`` reference, because a prior request and a record of past execution
are not authority to do new work. Antecedents retrieved for continuity travel
beside the authorization as contextual evidence and are not a permission
condition; what decides permission is recorded here and nowhere else.

The binding is exact. It covers, in one hash:
  * the instruction           — verbatim_hash of the exact user words;
  * the continuity decision   — decision_id and its recomputable decision_hash;
  * the authorization itself  — authorization_id, verdict, target module;
  * the scope                 — allowed scope, forbidden actions, required
                                checks, required evidence, stopping condition,
                                return point;
  * the baseline              — the blueprint and contract-registry state the
                                authorization was issued against;
  * the objective             — the objective governing at issue time.

Anything mutated or stale fails closed: the recomputed binding will not match,
or the objective will no longer be the active one, or the baseline will have
moved.

Stated limitation — the binding is an INTEGRITY hash, not a MAC. ``binding_hash``
is an unkeyed sha256 over public fields, so it detects an inconsistent row:
an edited column (refused outright by the append-only triggers), a copied hash
over a widened scope, a verbatim or decision digest that no longer recomputes
from its source. It does NOT prove provenance. A caller that already holds the
raw append primitive (``AuthorityStore.insert``) can append a fully
self-consistent ALLOW naming a different operation and recompute a matching
binding, and that row verifies. The control that actually stands between a
caller and that primitive in this slice is architectural, not cryptographic:
``AuthorizationAuthority.record`` is the only writer of this table, the L1
surface reaches nothing below the Layer-2 service, and no route exposes
``insert``. An unforgeable issuance proof needs a key and a key owner, which
this slice does not have and does not pretend to have.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from ..canonical import sha256_hex, sha256_text
from ..errors import AuthorizationRefused, BindingError, StaleAuthorization
from .continuity import decision_hash as recompute_decision_hash
from .store import AuthorityStore, Row

ALLOW = "ALLOW"
HOLD = "HOLD"

#: Reason codes. A HOLD always carries one; they are a closed vocabulary so a
#: caller can branch on the reason without parsing prose.
REASON_IN_AUTHORITY = "WORK_INSIDE_CANONICAL_AUTHORITY"
REASON_RETRIEVAL_CUE = "RETRIEVAL_CUE_NOT_EXECUTION_REQUEST"
REASON_OUTSIDE_AUTHORITY = "WORK_OUTSIDE_CANONICAL_AUTHORITY"
REASON_NO_CANONICAL_BASIS = "NO_CANONICAL_AUTHORIZATION_BASIS"
REASON_EVIDENCE_CONFLICT = "EVIDENCE_CONFLICT_RECORDED"
REASON_OBJECTIVE_UNSET = "NO_ACTIVE_OBJECTIVE"
REASON_OBJECTIVE_SELF_ESTABLISHED = "OBJECTIVE_ESTABLISHED_BY_THIS_REQUEST"

#: There is deliberately no reason code meaning "no antecedent evidence was
#: retrieved". Retrieval is continuity, not permission: an instruction that
#: recovers nothing is not thereby refused, and an instruction that recovers a
#: great deal is not thereby allowed. The codes above are the whole vocabulary.

_SCOPE_FIELDS = (
    "operation", "allowed_scope", "forbidden_actions", "required_checks",
    "required_evidence", "stopping_condition", "return_point",
)


def binding_payload(*, authorization_id: str, transaction_id: str,
                    decision_id: str, objective_id: str | None, verdict: str,
                    target_module_id: str | None, verbatim_hash: str,
                    decision_hash: str, baseline_hash: str,
                    scope: Mapping[str, Any]) -> dict:
    """The exact, ordered set of facts an authorization binds together."""
    missing = [name for name in _SCOPE_FIELDS if name not in scope]
    if missing:
        raise AuthorizationRefused(
            "execution contract is incomplete", missing=missing
        )
    return {
        "authorization_id": authorization_id,
        "transaction_id": transaction_id,
        "decision_id": decision_id,
        "objective_id": objective_id,
        "verdict": verdict,
        "target_module_id": target_module_id,
        "verbatim_hash": verbatim_hash,
        "decision_hash": decision_hash,
        "baseline_hash": baseline_hash,
        "scope": {name: scope[name] for name in _SCOPE_FIELDS},
    }


def binding_hash(**kwargs: Any) -> str:
    return sha256_hex(binding_payload(**kwargs))


def binding_hash_of_row(row: Mapping[str, Any]) -> str:
    """Recompute an authorization's binding hash from the stored row ALONE.

    ``AuthorizationAuthority.verify`` deliberately does more than this: it
    re-derives the verbatim and decision digests from their own source rows
    first, so a row that is self-consistent but inconsistent with its sources
    still fails. This function is the narrower check — "does this row's
    recorded binding follow from this row's own columns" — and it exists so
    that a reader which already holds the row, and must not be given a path
    into the slice-1 verification policy, can perform it independently.

    The assurance increment's verifier and its reviewer each call this from
    their own code paths. They share this function rather than each other,
    which is the difference between a common dependency and a coupling.
    """
    return binding_hash(
        authorization_id=str(row["authorization_id"]),
        transaction_id=str(row["transaction_id"]),
        decision_id=str(row["decision_id"]),
        objective_id=(str(row["objective_id"])
                      if row["objective_id"] is not None else None),
        verdict=str(row["verdict"]),
        target_module_id=row["target_module_id"],
        verbatim_hash=str(row["verbatim_hash"]),
        decision_hash=str(row["decision_hash"]),
        baseline_hash=str(row["baseline_hash"]),
        scope={
            "operation": str(row["operation"]),
            "allowed_scope": json.loads(str(row["allowed_scope_json"])),
            "forbidden_actions": json.loads(str(row["forbidden_actions_json"])),
            "required_checks": json.loads(str(row["required_checks_json"])),
            "required_evidence": json.loads(str(row["required_evidence_json"])),
            "stopping_condition": str(row["stopping_condition"]),
            "return_point": str(row["return_point"]),
        },
    )


class AuthorizationAuthority:
    owned_authority = ("execution_authorizations",)

    def __init__(self, store: AuthorityStore) -> None:
        self._store = store

    # -- writes -------------------------------------------------------------

    def record(self, *, authorization_id: str, transaction_id: str,
               decision_id: str, objective_id: str | None, verdict: str,
               reason_code: str, reason: str, target_module_id: str | None,
               scope: Mapping[str, Any], verbatim_hash: str,
               decision_hash: str, baseline_hash: str) -> Row:
        digest = binding_hash(
            authorization_id=authorization_id,
            transaction_id=transaction_id,
            decision_id=decision_id,
            objective_id=objective_id,
            verdict=verdict,
            target_module_id=target_module_id,
            verbatim_hash=verbatim_hash,
            decision_hash=decision_hash,
            baseline_hash=baseline_hash,
            scope=scope,
        )
        return self._store.insert("execution_authorizations", {
            "authorization_id": authorization_id,
            "transaction_id": transaction_id,
            "decision_id": decision_id,
            "objective_id": objective_id,
            "verdict": verdict,
            "reason_code": reason_code,
            "reason": reason,
            "target_module_id": target_module_id,
            "operation": scope["operation"],
            "allowed_scope_json": json.dumps(scope["allowed_scope"], sort_keys=True),
            "forbidden_actions_json": json.dumps(scope["forbidden_actions"], sort_keys=True),
            "required_checks_json": json.dumps(scope["required_checks"], sort_keys=True),
            "required_evidence_json": json.dumps(scope["required_evidence"], sort_keys=True),
            "stopping_condition": scope["stopping_condition"],
            "return_point": scope["return_point"],
            "verbatim_hash": verbatim_hash,
            "decision_hash": decision_hash,
            "baseline_hash": baseline_hash,
            "binding_hash": digest,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })

    # -- reads --------------------------------------------------------------

    def get(self, authorization_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM execution_authorizations WHERE authorization_id = ?",
            (authorization_id,),
        )

    def all(self) -> list[Row]:
        return self._store.query("SELECT * FROM execution_authorizations ORDER BY seq")

    def scope_of(self, row: Mapping[str, Any]) -> dict:
        return {
            "operation": row["operation"],
            "allowed_scope": json.loads(row["allowed_scope_json"]),
            "forbidden_actions": json.loads(row["forbidden_actions_json"]),
            "required_checks": json.loads(row["required_checks_json"]),
            "required_evidence": json.loads(row["required_evidence_json"]),
            "stopping_condition": row["stopping_condition"],
            "return_point": row["return_point"],
        }

    # -- verification -------------------------------------------------------

    def verify(self, authorization_id: str, *, baseline_hash: str,
               active_objective_id: str | None) -> Row:
        """Re-derive the authorization from authority, or refuse.

        Four independent refusals, all fail-closed:
          1. unknown authorization;
          2. binding does not recompute — mutated, forged or inconsistent;
          3. verdict is not ALLOW;
          4. stale — the objective it was issued under is no longer the active
             one, or the reconstruction baseline has moved since it was issued.
        """
        row = self.get(authorization_id)
        if row is None:
            raise AuthorizationRefused(
                "no such authorization", authorization_id=authorization_id
            )

        intent = self._store.one(
            "SELECT verbatim_instruction, verbatim_hash FROM intent_transactions "
            "WHERE transaction_id = ?",
            (row["transaction_id"],),
        )
        decision = self._store.one(
            "SELECT * FROM continuity_decisions "
            "WHERE decision_id = ?",
            (row["decision_id"],),
        )
        if intent is None or decision is None:
            raise BindingError(
                "authorization does not resolve to its instruction and decision",
                authorization_id=authorization_id,
            )

        computed_verbatim_hash = sha256_text(str(intent["verbatim_instruction"]))
        if computed_verbatim_hash != intent["verbatim_hash"]:
            raise BindingError(
                "stored verbatim hash does not match the immutable instruction",
                authorization_id=authorization_id,
                recorded=str(intent["verbatim_hash"]),
                recomputed=computed_verbatim_hash,
            )
        try:
            antecedents = json.loads(str(decision["antecedents_json"]))
        except json.JSONDecodeError as exc:
            raise BindingError(
                "continuity antecedents are not valid canonical JSON",
                authorization_id=authorization_id,
            ) from exc
        computed_decision_hash = recompute_decision_hash(
            transaction_id=str(decision["transaction_id"]),
            classification=str(decision["classification"]),
            treated_as=str(decision["treated_as"]),
            prior_objective_id=(
                str(decision["prior_objective_id"])
                if decision["prior_objective_id"] is not None else None
            ),
            active_objective_id=(
                str(decision["active_objective_id"])
                if decision["active_objective_id"] is not None else None
            ),
            antecedents=antecedents,
            disposition=str(decision["disposition"]),
        )
        if computed_decision_hash != decision["decision_hash"]:
            raise BindingError(
                "stored decision hash does not match the continuity source fields",
                authorization_id=authorization_id,
                recorded=str(decision["decision_hash"]),
                recomputed=computed_decision_hash,
            )

        recomputed = binding_hash(
            authorization_id=str(row["authorization_id"]),
            transaction_id=str(row["transaction_id"]),
            decision_id=str(row["decision_id"]),
            objective_id=(
                str(row["objective_id"]) if row["objective_id"] is not None else None
            ),
            verdict=str(row["verdict"]),
            target_module_id=row["target_module_id"],
            verbatim_hash=computed_verbatim_hash,
            decision_hash=computed_decision_hash,
            baseline_hash=str(row["baseline_hash"]),
            scope=self.scope_of(row),
        )
        if recomputed != row["binding_hash"]:
            raise BindingError(
                "authorization binding does not recompute from authority",
                authorization_id=authorization_id,
                recorded=str(row["binding_hash"]),
                recomputed=recomputed,
            )

        if row["verdict"] != ALLOW:
            raise AuthorizationRefused(
                "authorization is not an ALLOW",
                authorization_id=authorization_id,
                verdict=str(row["verdict"]),
                reason_code=str(row["reason_code"]),
            )

        if active_objective_id is None or row["objective_id"] != active_objective_id:
            raise StaleAuthorization(
                "authorization was issued under an objective that no longer governs",
                authorization_id=authorization_id,
                issued_under=str(row["objective_id"]),
                active_objective_id=active_objective_id,
            )

        if row["baseline_hash"] != baseline_hash:
            raise StaleAuthorization(
                "reconstruction baseline moved after the authorization was issued",
                authorization_id=authorization_id,
                issued_against=str(row["baseline_hash"]),
                current=baseline_hash,
            )

        return row
