"""The closed policy-document schema and the compiled-envelope value object.

WHAT THIS IS, AND WHAT IT IS NOT
---------------------------------

This is a schema for ENFORCEMENT POLICY, not for documentation. A policy
document that merely describes an intention is not recorded here — every field
below is read by code (``cis.policy.compiler``) that derives a binding
decision from it. Nothing in this module parses prose, infers a selector from
free text, or treats a narrative string as an input to any decision. A field
that is not one of the fifteen named below does not exist, by refusal.

MASTER and TASK are both ``PolicyDocument`` values, distinguished by ``kind``:

  * MASTER policies are mandatory invariants. They carry no selector — they
    apply to every operation this compiler ever resolves — and at least one
    ACTIVE master document must exist for a policy set to compile anything
    at all (a reconstruction with no master baseline refuses rather than
    running ungoverned).
  * TASK policies are selected only by an EXACT structured selector match
    (project, module, operation, risk — four closed-vocabulary dimensions,
    matched by equality and nothing softer). A TASK policy may narrow what a
    MASTER policy already restricts; it can never widen it, and the schema
    gives it no field capable of doing so — there is no "allow", "grant" or
    "widen" effect kind in existence. ``effect_kinds`` is a closed vocabulary
    of exactly PROHIBIT, REQUIRE_CHECK, REQUIRE_EVIDENCE, NARROW_SCOPE and
    HOLD, and a document must declare exactly the effect kinds its own
    populated fields exhibit — nothing more, nothing silent.

CLOSED VOCABULARIES, CANONICAL ORDERING, DOMAIN-TAGGED HASHES
---------------------------------------------------------------

Every enum here is a frozen tuple; an unrecognised value refuses at parse,
before a document is ever recorded (same discipline as
``cis.contracts.registry.parse_contract``). Every hash in this module is
sha256 over canonical JSON whose first key is a literal domain tag, so a
policy-document digest, a master-baseline digest and a compiled-envelope
digest can never collide in meaning even where they cover overlapping facts —
exactly the reasoning ``cis.assurance.task_contract`` gives for its own
independent hash domain.

This schema is independent of, and not sized to match, ADR-ARCH-001's frozen
sixteen-field MODULE contract. It happens to have sixteen fields of its own;
that is a coincidence of this document's shape, not a reuse of that rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from ..canonical import sha256_hex
from ..errors import (
    PolicyAmbiguous, PolicyConflict, PolicyCyclicSupersession,
    PolicyInvalidSupersession, PolicySchemaInvalid, PolicyTampered,
)

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

KIND_MASTER = "MASTER"
KIND_TASK = "TASK"
KINDS: tuple[str, ...] = (KIND_MASTER, KIND_TASK)

STATUS_ACTIVE = "ACTIVE"
STATUS_SUPERSEDED = "SUPERSEDED"
STATUSES: tuple[str, ...] = (STATUS_ACTIVE, STATUS_SUPERSEDED)

#: The exact, closed selector dimensions a TASK policy is matched on. No other
#: dimension exists, and none of these is matched by anything softer than
#: equality — no prefix, no glob, no regex, no semantic similarity.
SELECTOR_FIELDS: tuple[str, ...] = ("project", "module", "operation", "risk")

EFFECT_PROHIBIT = "PROHIBIT"
EFFECT_REQUIRE_CHECK = "REQUIRE_CHECK"
EFFECT_REQUIRE_EVIDENCE = "REQUIRE_EVIDENCE"
EFFECT_NARROW_SCOPE = "NARROW_SCOPE"
EFFECT_HOLD = "HOLD"

#: The whole vocabulary of what a policy may ever do. Deliberately absent:
#: anything that grants, widens or allows. A policy cannot add a path, a tool,
#: a capability, network reach, a credential, budget or host action, or any
#: authorization, because no effect kind exists that means any of those
#: things — the refusal is structural, not a runtime check that could be
#: forgotten.
EFFECT_KINDS: tuple[str, ...] = (
    EFFECT_PROHIBIT, EFFECT_REQUIRE_CHECK, EFFECT_REQUIRE_EVIDENCE,
    EFFECT_NARROW_SCOPE, EFFECT_HOLD,
)

#: The exact fifteen semantic fields of a policy document (sixteen with
#: ``policy_id`` folded in as the sixteenth below — see module docstring).
REQUIRED_FIELDS: tuple[str, ...] = (
    "policy_id",
    "lineage_id",
    "kind",
    "version",
    "status",
    "supersedes",
    "conflicts_with",
    "selector",
    "effect_kinds",
    "prohibited_actions",
    "required_checks",
    "required_evidence",
    "narrowed_scope",
    "hold",
    "rationale",
    "evidence_basis",
)

_LIST_FIELDS = frozenset({
    "conflicts_with", "effect_kinds", "prohibited_actions",
    "required_checks", "required_evidence", "evidence_basis",
})

DOCUMENT_HASH_DOMAIN = "cis.policy.document.v1"
MASTER_BASELINE_HASH_DOMAIN = "cis.policy.master_baseline.v1"
POLICY_SET_HASH_DOMAIN = "cis.policy.set.v1"
ENVELOPE_HASH_DOMAIN = "cis.policy.envelope.v1"


def _refuse(message: str, **detail: object) -> None:
    raise PolicySchemaInvalid(message, **detail)


# ---------------------------------------------------------------------------
# The policy document
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyDocument:
    policy_id: str
    lineage_id: str
    kind: str
    version: int
    status: str
    supersedes: str | None
    conflicts_with: tuple[str, ...]
    selector: Mapping[str, str] | None
    effect_kinds: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    required_checks: tuple[str, ...]
    required_evidence: tuple[str, ...]
    narrowed_scope: tuple[str, ...] | None
    hold: bool
    rationale: str
    evidence_basis: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "lineage_id": self.lineage_id,
            "kind": self.kind,
            "version": self.version,
            "status": self.status,
            "supersedes": self.supersedes,
            "conflicts_with": list(self.conflicts_with),
            "selector": dict(self.selector) if self.selector is not None else None,
            "effect_kinds": list(self.effect_kinds),
            "prohibited_actions": list(self.prohibited_actions),
            "required_checks": list(self.required_checks),
            "required_evidence": list(self.required_evidence),
            "narrowed_scope": (
                list(self.narrowed_scope) if self.narrowed_scope is not None else None
            ),
            "hold": self.hold,
            "rationale": self.rationale,
            "evidence_basis": list(self.evidence_basis),
        }

    @property
    def document_hash(self) -> str:
        return sha256_hex({"__hash_domain__": DOCUMENT_HASH_DOMAIN, **self.as_dict()})


def parse_policy(raw: Mapping[str, object]) -> PolicyDocument:
    """Validate one policy document and return it, or refuse.

    Refusal happens before the document is ever recorded, exactly like
    ``cis.contracts.registry.parse_contract`` — an unknown field, an unknown
    status, an unknown effect kind, or a declared effect that does not match
    the fields actually populated are every one a ``PolicySchemaInvalid``
    refusal, not a warning.
    """
    if not isinstance(raw, Mapping):
        _refuse("policy document is not an object", got=type(raw).__name__)

    present = set(raw)
    required = set(REQUIRED_FIELDS)
    missing = sorted(required - present)
    if missing:
        _refuse("policy document is missing required field(s)", missing=missing,
                policy_id=raw.get("policy_id"))
    unexpected = sorted(present - required)
    if unexpected:
        _refuse("policy document carries unexpected field(s)",
                unexpected=unexpected, policy_id=raw.get("policy_id"))

    policy_id = raw["policy_id"]
    if not isinstance(policy_id, str) or not policy_id.strip():
        _refuse("policy_id must be a non-empty string", policy_id=policy_id)
    policy_id = policy_id.strip()

    lineage_id = raw["lineage_id"]
    if not isinstance(lineage_id, str) or not lineage_id.strip():
        _refuse("lineage_id must be a non-empty string", policy_id=policy_id)
    lineage_id = lineage_id.strip()

    kind = raw["kind"]
    if kind not in KINDS:
        _refuse("unknown policy kind", policy_id=policy_id, kind=kind,
                known=list(KINDS))

    version = raw["version"]
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        _refuse("version must be a positive integer", policy_id=policy_id,
                version=version)

    status = raw["status"]
    if status not in STATUSES:
        _refuse("unknown policy status", policy_id=policy_id, status=status,
                known=list(STATUSES))

    supersedes = raw["supersedes"]
    if supersedes is not None and (
        not isinstance(supersedes, str) or not supersedes.strip()
    ):
        _refuse("supersedes must be null or a non-empty policy_id",
                policy_id=policy_id, supersedes=supersedes)
    if supersedes is not None and supersedes.strip() == policy_id:
        _refuse("a policy document cannot supersede itself", policy_id=policy_id)

    for name in sorted(_LIST_FIELDS):
        value = raw[name]
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item.strip() for item in value
        ):
            _refuse(f"field '{name}' must be a list of non-empty strings",
                    policy_id=policy_id, field=name)
        if len(set(value)) != len(value):
            _refuse(f"field '{name}' repeats an entry",
                    policy_id=policy_id, field=name)

    if lineage_id in raw["conflicts_with"]:
        _refuse("a policy document cannot declare conflict with its own lineage",
                policy_id=policy_id)

    effect_kinds = tuple(sorted(set(raw["effect_kinds"])))
    unknown_effects = sorted(set(effect_kinds) - set(EFFECT_KINDS))
    if unknown_effects:
        _refuse("unknown effect kind(s) — a policy may only narrow scope, add "
                "prohibitions, checks or evidence, or hold; it can never widen "
                "a path, tool, capability, network, credential, budget, host "
                "action or authorization",
                policy_id=policy_id, unknown=unknown_effects,
                known=list(EFFECT_KINDS))
    if not effect_kinds:
        _refuse("a policy document must declare at least one effect",
                policy_id=policy_id)

    selector = raw["selector"]
    if kind == KIND_MASTER:
        if selector is not None:
            _refuse("a MASTER policy applies universally and carries no "
                    "selector", policy_id=policy_id)
    else:
        if not isinstance(selector, Mapping):
            _refuse("a TASK policy must carry a structured selector",
                    policy_id=policy_id)
        if set(selector) != set(SELECTOR_FIELDS):
            _refuse("selector must carry exactly project, module, operation "
                    "and risk", policy_id=policy_id,
                    present=sorted(selector), required=list(SELECTOR_FIELDS))
        for key in SELECTOR_FIELDS:
            if not isinstance(selector[key], str) or not selector[key].strip():
                _refuse(f"selector.{key} must be a non-empty string",
                        policy_id=policy_id)
        selector = {key: selector[key].strip() for key in SELECTOR_FIELDS}

    prohibited_actions = tuple(raw["prohibited_actions"])
    required_checks = tuple(raw["required_checks"])
    required_evidence = tuple(raw["required_evidence"])

    narrowed_scope = raw["narrowed_scope"]
    if narrowed_scope is not None:
        if not isinstance(narrowed_scope, list) or not narrowed_scope or not all(
            isinstance(item, str) and item.strip() for item in narrowed_scope
        ):
            _refuse("narrowed_scope must be null or a non-empty list of "
                    "non-empty strings", policy_id=policy_id)
        if len(set(narrowed_scope)) != len(narrowed_scope):
            _refuse("narrowed_scope repeats an entry", policy_id=policy_id)
        narrowed_scope = tuple(narrowed_scope)

    hold = raw["hold"]
    if not isinstance(hold, bool):
        _refuse("hold must be a boolean", policy_id=policy_id, hold=hold)

    rationale = raw["rationale"]
    if not isinstance(rationale, str) or not rationale.strip():
        _refuse("rationale must be a non-empty string", policy_id=policy_id)

    evidence_basis = tuple(raw["evidence_basis"])
    if not evidence_basis:
        _refuse("evidence_basis must name at least one authority",
                policy_id=policy_id)

    # Effect declaration must exactly match the fields actually populated —
    # no silent effect, and no declared-but-empty effect.
    observed = set()
    if prohibited_actions:
        observed.add(EFFECT_PROHIBIT)
    if required_checks:
        observed.add(EFFECT_REQUIRE_CHECK)
    if required_evidence:
        observed.add(EFFECT_REQUIRE_EVIDENCE)
    if narrowed_scope is not None:
        observed.add(EFFECT_NARROW_SCOPE)
    if hold:
        observed.add(EFFECT_HOLD)
    if observed != set(effect_kinds):
        _refuse("declared effect_kinds does not match the populated fields",
                policy_id=policy_id, declared=sorted(effect_kinds),
                observed=sorted(observed))

    return PolicyDocument(
        policy_id=policy_id, lineage_id=lineage_id, kind=kind, version=version,
        status=status, supersedes=(supersedes.strip() if supersedes else None),
        conflicts_with=tuple(sorted(set(raw["conflicts_with"]))),
        selector=selector, effect_kinds=effect_kinds,
        prohibited_actions=prohibited_actions, required_checks=required_checks,
        required_evidence=required_evidence, narrowed_scope=narrowed_scope,
        hold=hold, rationale=rationale.strip(), evidence_basis=evidence_basis,
    )


# ---------------------------------------------------------------------------
# The validated set
# ---------------------------------------------------------------------------

@dataclass
class PolicySet:
    """A validated collection of policy documents.

    Validation is structural and runs over the WHOLE set every time one is
    built — there is no cached, trusted-once result. ``current_set()`` in
    ``cis.policy.authority`` rebuilds one of these from the append-only ledger
    on every call, for the same reason ``AuthorizationAuthority.verify``
    recomputes every digest from source on every call rather than trusting an
    earlier pass.
    """

    documents: tuple[PolicyDocument, ...] = field(default_factory=tuple)

    def validate(self) -> None:
        by_id: dict[str, PolicyDocument] = {}
        for doc in self.documents:
            if doc.policy_id in by_id:
                _refuse("duplicate policy_id", policy_id=doc.policy_id)
            by_id[doc.policy_id] = doc

        # Supersession must resolve, stay within one lineage, and the
        # superseded document must actually be marked SUPERSEDED.
        for doc in self.documents:
            if doc.supersedes is None:
                continue
            target = by_id.get(doc.supersedes)
            if target is None:
                raise PolicyInvalidSupersession(
                    "supersedes names a policy document that does not exist",
                    policy_id=doc.policy_id, supersedes=doc.supersedes)
            if target.lineage_id != doc.lineage_id:
                raise PolicyInvalidSupersession(
                    "supersedes crosses lineages",
                    policy_id=doc.policy_id, supersedes=doc.supersedes,
                    lineage_id=doc.lineage_id, target_lineage_id=target.lineage_id)
            if target.status != STATUS_SUPERSEDED:
                raise PolicyInvalidSupersession(
                    "the document a policy supersedes is not recorded as "
                    "SUPERSEDED", policy_id=doc.policy_id,
                    supersedes=doc.supersedes, target_status=target.status)

        known_lineages = {doc.lineage_id for doc in self.documents}
        for doc in self.documents:
            unknown = sorted(set(doc.conflicts_with) - known_lineages)
            if unknown:
                raise PolicyConflict(
                    "conflicts_with names an unknown policy lineage",
                    policy_id=doc.policy_id, unknown_lineages=unknown)

        # No cycle in the supersedes graph, over the whole set.
        remaining = {doc.policy_id: doc.supersedes for doc in self.documents}
        settled: set[str] = set()
        while remaining:
            ready = [pid for pid, target in remaining.items()
                     if target is None or target in settled]
            if not ready:
                raise PolicyCyclicSupersession(
                    "cyclic supersession among policy documents",
                    unresolved=sorted(remaining))
            for pid in sorted(ready):
                settled.add(pid)
                del remaining[pid]

        # Exactly one ACTIVE document per lineage.
        active_by_lineage: dict[str, list[str]] = {}
        for doc in self.documents:
            if doc.status == STATUS_ACTIVE:
                active_by_lineage.setdefault(doc.lineage_id, []).append(doc.policy_id)
        for lineage_id, ids in sorted(active_by_lineage.items()):
            if len(ids) > 1:
                raise PolicyAmbiguous(
                    "more than one ACTIVE policy document in one lineage",
                    lineage_id=lineage_id, active=sorted(ids))

        # Conflict declarations are structural and symmetric. Whether both
        # sides apply together is decided by the compiler for one selector.
        active_docs = {doc.lineage_id: doc for doc in self.documents
                       if doc.status == STATUS_ACTIVE}
        for lineage_id, doc in sorted(active_docs.items()):
            for other_lineage in doc.conflicts_with:
                other = active_docs.get(other_lineage)
                if other is None:
                    continue  # the conflicting lineage has no active document
                if lineage_id not in other.conflicts_with:
                    raise PolicyConflict(
                        "conflict declaration is not symmetric — a one-sided "
                        "claim is not a conflict",
                        lineage_id=lineage_id, conflicts_with=other_lineage)

    def active_masters(self) -> tuple[PolicyDocument, ...]:
        return tuple(sorted(
            (doc for doc in self.documents
             if doc.kind == KIND_MASTER and doc.status == STATUS_ACTIVE),
            key=lambda doc: doc.policy_id,
        ))

    def matching_tasks(self, selector: Mapping[str, str]) -> tuple[PolicyDocument, ...]:
        exact = {key: selector[key] for key in SELECTOR_FIELDS}
        return tuple(sorted(
            (doc for doc in self.documents
             if doc.kind == KIND_TASK and doc.status == STATUS_ACTIVE
             and doc.selector == exact),
            key=lambda doc: doc.policy_id,
        ))


@dataclass(frozen=True)
class PolicySelector:
    project: str
    module: str
    operation: str
    risk: str

    def __post_init__(self) -> None:
        for name in SELECTOR_FIELDS:
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                _refuse(f"selector.{name} must be a non-empty string")

    def as_dict(self) -> dict:
        return {"project": self.project, "module": self.module,
                "operation": self.operation, "risk": self.risk}


# ---------------------------------------------------------------------------
# The compiled envelope
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyEnvelope:
    """The compiled, binding result: one MASTER baseline plus any selected
    TASK narrowing, with nothing in it capable of widening anything."""

    task_contract_id: str
    task_contract_hash: str
    selector: Mapping[str, str]
    master_baseline_hash: str
    master_policy_ids: tuple[str, ...]
    task_policy_ids: tuple[str, ...]
    selected_policies: tuple[Mapping[str, object], ...]
    prohibited_actions: tuple[str, ...]
    required_checks: tuple[str, ...]
    required_evidence: tuple[str, ...]
    narrowed_scope: tuple[str, ...] | None
    policy_set_hash: str
    hash_domain: str = ENVELOPE_HASH_DOMAIN

    def hash_payload(self) -> dict:
        return {
            "__hash_domain__": self.hash_domain,
            "task_contract_id": self.task_contract_id,
            "task_contract_hash": self.task_contract_hash,
            "selector": dict(self.selector),
            "master_baseline_hash": self.master_baseline_hash,
            "master_policy_ids": list(self.master_policy_ids),
            "task_policy_ids": list(self.task_policy_ids),
            "selected_policies": [dict(item) for item in self.selected_policies],
            "prohibited_actions": list(self.prohibited_actions),
            "required_checks": list(self.required_checks),
            "required_evidence": list(self.required_evidence),
            "narrowed_scope": (
                list(self.narrowed_scope) if self.narrowed_scope is not None else None
            ),
            "policy_set_hash": self.policy_set_hash,
        }

    @property
    def envelope_hash(self) -> str:
        return sha256_hex(self.hash_payload())

    def as_dict(self) -> dict:
        return {**self.hash_payload(), "envelope_hash": self.envelope_hash}


def verify_envelope_integrity(envelope: Mapping[str, object]) -> str:
    """Refuse unless a compiled envelope recomputes its own hash.

    This is the half of policy verification that needs no authority access at
    all: given only the envelope's own fields, does the declared
    ``envelope_hash`` follow from them under the declared domain tag. The
    contained worker calls exactly this — it has no authority dependency by
    architecture (ADR-SEED-018), so it cannot check staleness against live
    policy authority, but it can and does catch a forged or mutated envelope
    crossing its own boundary: a copied hash over a widened ``narrowed_scope``
    or a stripped prohibition will not recompute.
    """
    required = (
        "task_contract_id", "task_contract_hash", "selector",
        "master_baseline_hash", "master_policy_ids",
        "task_policy_ids", "selected_policies", "prohibited_actions", "required_checks",
        "required_evidence", "narrowed_scope", "policy_set_hash",
        "__hash_domain__", "envelope_hash",
    )
    missing = [key for key in required if key not in envelope]
    if missing:
        raise PolicyTampered("policy envelope is incomplete", missing=missing)
    unexpected = sorted(set(envelope) - set(required))
    if unexpected:
        raise PolicyTampered("policy envelope carries unexpected fields",
                             unexpected=unexpected)
    if envelope["__hash_domain__"] != ENVELOPE_HASH_DOMAIN:
        raise PolicyTampered(
            "policy envelope carries an unknown hash domain",
            recorded=envelope["__hash_domain__"], expected=ENVELOPE_HASH_DOMAIN)
    selector = envelope["selector"]
    if not isinstance(selector, Mapping) or set(selector) != set(SELECTOR_FIELDS):
        raise PolicyTampered("policy envelope selector is malformed")
    for name in SELECTOR_FIELDS:
        if not isinstance(selector[name], str) or not selector[name]:
            raise PolicyTampered("policy envelope selector is malformed",
                                 field=name)
    for name in ("master_policy_ids", "task_policy_ids", "prohibited_actions",
                 "required_checks", "required_evidence"):
        value = envelope[name]
        if (not isinstance(value, (list, tuple))
                or not all(isinstance(item, str) and item for item in value)):
            raise PolicyTampered("policy envelope field is malformed", field=name)
    selected_policies = envelope["selected_policies"]
    if (not isinstance(selected_policies, (list, tuple))
            or not selected_policies
            or not all(isinstance(item, Mapping) for item in selected_policies)):
        raise PolicyTampered("policy envelope selected_policies is malformed")
    narrowed = envelope["narrowed_scope"]
    if narrowed is not None and (
        not isinstance(narrowed, (list, tuple))
        or not all(isinstance(item, str) and item for item in narrowed)
    ):
        raise PolicyTampered("policy envelope narrowed_scope is malformed")
    for name in ("task_contract_id", "task_contract_hash",
                 "master_baseline_hash", "policy_set_hash", "envelope_hash"):
        if not isinstance(envelope[name], str) or not envelope[name]:
            raise PolicyTampered("policy envelope digest is malformed", field=name)
    recomputed = sha256_hex({
        "__hash_domain__": ENVELOPE_HASH_DOMAIN,
        "task_contract_id": envelope["task_contract_id"],
        "task_contract_hash": envelope["task_contract_hash"],
        "selector": dict(selector),
        "master_baseline_hash": envelope["master_baseline_hash"],
        "master_policy_ids": list(envelope["master_policy_ids"]),
        "task_policy_ids": list(envelope["task_policy_ids"]),
        "selected_policies": [dict(item) for item in selected_policies],
        "prohibited_actions": list(envelope["prohibited_actions"]),
        "required_checks": list(envelope["required_checks"]),
        "required_evidence": list(envelope["required_evidence"]),
        "narrowed_scope": (
            list(envelope["narrowed_scope"])
            if envelope["narrowed_scope"] is not None else None
        ),
        "policy_set_hash": envelope["policy_set_hash"],
    })
    if recomputed != envelope["envelope_hash"]:
        raise PolicyTampered(
            "policy envelope digest does not recompute from its own fields",
            recorded=envelope["envelope_hash"], recomputed=recomputed)
    return recomputed


__all__ = [
    "DOCUMENT_HASH_DOMAIN", "EFFECT_HOLD", "EFFECT_KINDS", "EFFECT_NARROW_SCOPE",
    "EFFECT_PROHIBIT", "EFFECT_REQUIRE_CHECK", "EFFECT_REQUIRE_EVIDENCE",
    "ENVELOPE_HASH_DOMAIN", "KIND_MASTER", "KIND_TASK", "KINDS",
    "MASTER_BASELINE_HASH_DOMAIN", "POLICY_SET_HASH_DOMAIN", "PolicyDocument",
    "PolicyEnvelope", "PolicySelector", "PolicySet", "REQUIRED_FIELDS",
    "SELECTOR_FIELDS", "STATUSES", "STATUS_ACTIVE", "STATUS_SUPERSEDED",
    "parse_policy", "verify_envelope_integrity",
]
