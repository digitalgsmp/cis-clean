"""Pure deterministic compiler for closed MASTER/TASK policy documents."""

from __future__ import annotations

from ..canonical import sha256_hex
from ..errors import (
    PolicyBaselineMissing, PolicyConflict, PolicyHold, PolicyTampered,
    PolicyWeakensMaster,
)
from .schema import (
    MASTER_BASELINE_HASH_DOMAIN, POLICY_SET_HASH_DOMAIN, PolicyEnvelope,
    PolicySelector, PolicySet, parse_policy, verify_envelope_integrity,
)


def master_baseline_hash(masters) -> str:
    return sha256_hex({
        "__hash_domain__": MASTER_BASELINE_HASH_DOMAIN,
        "masters": [doc.as_dict() for doc in
                    sorted(masters, key=lambda item: item.policy_id)],
    })


def compile_envelope(policy_set: PolicySet, *,
                     selector: PolicySelector, task_contract_id: str,
                     task_contract_hash: str) -> PolicyEnvelope:
    """Compile one immutable envelope, or refuse before backend entry."""
    if not isinstance(task_contract_id, str) or not task_contract_id:
        raise PolicyBaselineMissing("policy envelope requires a task contract id")
    if not isinstance(task_contract_hash, str) or not task_contract_hash:
        raise PolicyBaselineMissing("policy envelope requires a task contract hash")
    policy_set.validate()
    masters = policy_set.active_masters()
    if not masters:
        raise PolicyBaselineMissing(
            "no ACTIVE master policy exists; execution has no mandatory baseline",
            selector=selector.as_dict(),
        )
    tasks = policy_set.matching_tasks(selector.as_dict())
    selected = (*masters, *tasks)

    # An independently verified envelope must carry enough source history to
    # prove every selected document's supersession claim.  Effects still come
    # only from the ACTIVE documents in ``selected``; ``carried`` adds their
    # transitive superseded ancestors solely as immutable verification input.
    by_id = {document.policy_id: document for document in policy_set.documents}
    carried_by_id = {document.policy_id: document for document in selected}
    frontier = list(selected)
    while frontier:
        document = frontier.pop()
        if document.supersedes is None:
            continue
        ancestor = by_id[document.supersedes]
        if ancestor.policy_id not in carried_by_id:
            carried_by_id[ancestor.policy_id] = ancestor
            frontier.append(ancestor)
    carried = tuple(sorted(carried_by_id.values(),
                           key=lambda item: item.policy_id))

    selected_by_lineage = {doc.lineage_id: doc for doc in selected}
    conflicts: set[tuple[str, str]] = set()
    for doc in selected:
        for other_lineage in doc.conflicts_with:
            if other_lineage in selected_by_lineage:
                conflicts.add(tuple(sorted((doc.lineage_id, other_lineage))))
    if conflicts:
        raise PolicyConflict(
            "applicable policies conflict; execution is held",
            conflicts=[list(pair) for pair in sorted(conflicts)],
            selector=selector.as_dict(),
        )

    master_scope = None
    for doc in masters:
        if doc.narrowed_scope is not None:
            scope = frozenset(doc.narrowed_scope)
            master_scope = scope if master_scope is None else master_scope & scope

    effective_scope = master_scope
    for doc in tasks:
        if doc.narrowed_scope is None:
            continue
        requested = frozenset(doc.narrowed_scope)
        if master_scope is not None and not requested <= master_scope:
            raise PolicyWeakensMaster(
                "task policy attempts to widen the MASTER scope",
                policy_id=doc.policy_id,
                task_scope=sorted(requested),
                master_scope=sorted(master_scope),
            )
        effective_scope = requested if effective_scope is None else effective_scope & requested

    holding = sorted(doc.policy_id for doc in selected if doc.hold)
    if holding:
        raise PolicyHold(
            "an applicable policy declares HOLD",
            selector=selector.as_dict(), holding_policies=holding,
        )

    baseline_hash = master_baseline_hash(masters)
    set_hash = sha256_hex({
        "__hash_domain__": POLICY_SET_HASH_DOMAIN,
        "selector": selector.as_dict(),
        "master_baseline_hash": baseline_hash,
        "selected_policies": [
            doc.as_dict() for doc in sorted(selected, key=lambda item: item.policy_id)
        ],
    })
    return PolicyEnvelope(
        task_contract_id=task_contract_id,
        task_contract_hash=task_contract_hash,
        selector=selector.as_dict(),
        master_baseline_hash=baseline_hash,
        master_policy_ids=tuple(sorted(doc.policy_id for doc in masters)),
        task_policy_ids=tuple(sorted(doc.policy_id for doc in tasks)),
        selected_policies=tuple(doc.as_dict() for doc in carried),
        prohibited_actions=tuple(sorted({x for doc in selected for x in doc.prohibited_actions})),
        required_checks=tuple(sorted({x for doc in selected for x in doc.required_checks})),
        required_evidence=tuple(sorted({x for doc in selected for x in doc.required_evidence})),
        narrowed_scope=tuple(sorted(effective_scope)) if effective_scope is not None else None,
        policy_set_hash=set_hash,
    )


def verify_compiled_envelope(envelope) -> PolicyEnvelope:
    """Recompile the carried source policies and refuse semantic forgery."""
    verify_envelope_integrity(envelope)
    try:
        policies = tuple(parse_policy(item) for item in envelope["selected_policies"])
        selector = PolicySelector(**dict(envelope["selector"]))
        recomputed = compile_envelope(
            PolicySet(policies), selector=selector,
            task_contract_id=str(envelope["task_contract_id"]),
            task_contract_hash=str(envelope["task_contract_hash"]),
        )
    except Exception as exc:
        if isinstance(exc, PolicyTampered):
            raise
        raise PolicyTampered("policy envelope source policies do not recompile") from exc
    if recomputed.as_dict() != dict(envelope):
        raise PolicyTampered(
            "policy envelope effects do not match its selected source policies")
    return recomputed


__all__ = ["compile_envelope", "master_baseline_hash", "verify_compiled_envelope"]
