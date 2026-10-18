"""The Workbench application service.

This is the module that implements the conceptual chain of handoff A2 for one
instruction:

    HUMAN INTENT -> INTERPRETATION -> AUTHORITATIVE CONTEXT -> WORK
    DECOMPOSITION -> POLICY -> EXECUTION CONTRACT -> AUTHORIZATION

and stops there. It authorizes; it does not execute. Execution is the Layer-2
gateway's, and this module never holds, names or configures a backend.

The behaviours it owes to recorded authority:

* The user's exact words are preserved as immutable source evidence, and the
  interpretation is written beside them as a labeled derivative that never
  outranks them (ADR-ARCH-004 clause 1).
* A question or a vague memory fragment is a RETRIEVAL CUE. It recovers
  antecedents and leaves the active objective exactly where it was. Only an
  explicit redirection supersedes it, and the superseded objective is retained
  (dev_continuity_events revision 178).
* Execution is permitted only when the work is already inside canonical
  authority — here, the blueprint's selected modules — and is bounded by a
  structured execution contract. A contract alone cannot create authority, and
  a broader contract cannot widen scope (ADR-ARCH-004 clauses 2 and 3).

TWO CONCERNS, DELIBERATELY SEPARATE
-----------------------------------

1. CONTINUITY ANTECEDENTS. Prior immutable human exchanges and admitted
   knowledge are retrieved so meaning survives, memory cues are answerable and
   context is explainable. Retrieval is deterministic, transparent, and prefers
   the human's original words over anything CIS generated about its own
   execution. Antecedents travel with the outcome as CONTEXTUAL CONTINUITY
   EVIDENCE.

2. EXECUTION AUTHORIZATION BASIS. Whether work may run is decided only from
   canonical accepted authority for the target module: the validated
   reconstruction manifest's selected-module entry and its non-empty
   ``evidence_basis``, the module's own contract, the module's reconstruction
   status, the active objective, and the absence of recorded evidence
   conflicts. ``_verdict`` does not receive the antecedents at all, which is
   the structural reason text overlap cannot grant permission.

The failure this separation exists to prevent is self-bootstrapping: a request
must never be able to manufacture the authority that permits it. Submitting the
same words twice creates a second immutable record of the request and changes
no canonical authority, so it cannot turn a HOLD into an ALLOW. For the same
reason an instruction that establishes the first objective does not then get
authorized under the objective it just created; direction has to pre-exist the
work that claims to serve it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..authority.authorization import (
    ALLOW, AuthorizationAuthority, HOLD, REASON_EVIDENCE_CONFLICT,
    REASON_IN_AUTHORITY, REASON_NO_CANONICAL_BASIS,
    REASON_OBJECTIVE_SELF_ESTABLISHED, REASON_OBJECTIVE_UNSET,
    REASON_OUTSIDE_AUTHORITY, REASON_RETRIEVAL_CUE,
)
from ..authority.continuity import (
    ContinuityAuthority, TREATED_AS_CUE, TREATED_AS_SUPERSESSION,
)
from ..authority.evidence import EvidenceAuthority
from ..authority.intent import IntentAuthority
from ..authority.runs import RunAuthority
from ..authority.store import AuthorityStore
from ..authority.trajectory import MACRO, MICRO, TrajectoryAuthority
from ..blueprint import Blueprint, CanonicalBasis, load_blueprint
from ..blueprint.manifest import IN_SCOPE_RECONSTRUCTION_STATUSES
from ..canonical import sha256_hex
from ..continuity import classify, retrieve_antecedents
from ..errors import CisError
from ..execution.gateway import ExecutionGateway
from ..policy.resolver import AutomaticPolicyResolver
from .projection import TrajectoryProjection

#: Labels the antecedent list for any reader of an outcome, so its role cannot
#: be mistaken. It is continuity context. It is not why anything was allowed.
ANTECEDENT_ROLE = "CONTEXTUAL_CONTINUITY_EVIDENCE_NOT_AUTHORIZATION_BASIS"


@dataclass(frozen=True)
class InstructionOutcome:
    transaction_id: str
    verbatim: str
    interpretation: str
    classification: dict
    objective: dict
    antecedents: list[dict]
    decision: dict
    authorization: dict
    authorization_basis: dict | None = None

    def as_dict(self) -> dict:
        return {
            "transaction_id": self.transaction_id,
            "verbatim": self.verbatim,
            "interpretation": self.interpretation,
            "interpretation_label": "DERIVATIVE_INTERPRETATION_SOURCE_LINKED",
            "classification": self.classification,
            "objective": self.objective,
            # Two separate channels, never one. ``antecedents`` is continuity
            # context recovered for meaning; ``authorization_basis`` is the
            # canonical accepted authority the verdict was actually derived
            # from, or null when nothing was authorized.
            "antecedents": self.antecedents,
            "antecedents_role": ANTECEDENT_ROLE,
            "authorization_basis": self.authorization_basis,
            "continuity_decision": self.decision,
            "authorization": self.authorization,
        }


class Workbench:
    def __init__(self, store: AuthorityStore, *,
                 blueprint: Blueprint | None = None,
                 gateway: ExecutionGateway | None = None) -> None:
        self.store = store
        self.blueprint = blueprint if blueprint is not None else load_blueprint()
        self.intent = IntentAuthority(store)
        self.continuity = ContinuityAuthority(store)
        self.evidence = EvidenceAuthority(store)
        self.authorizations = AuthorizationAuthority(store)
        self.runs = RunAuthority(store)
        self.trajectory = TrajectoryAuthority(store)
        self.policy_resolver = AutomaticPolicyResolver(store)
        self.gateway = gateway if gateway is not None else ExecutionGateway(
            authorizations=self.authorizations,
            runs=self.runs,
            evidence=self.evidence,
            trajectory=self.trajectory,
            policy_envelope_resolver=self.policy_resolver.resolve,
            authorization_check_resolver=self.execution_preflight_checks,
        )
        self.projection = TrajectoryProjection(
            blueprint=self.blueprint,
            trajectory=self.trajectory,
            intent=self.intent,
            continuity=self.continuity,
            runs=self.runs,
            authorizations=self.authorizations,
        )
        self._bootstrap_macro()

    def execution_preflight_checks(self, row: Mapping[str, Any]) -> tuple[str, ...]:
        """Independently recompute authorization-level checks before execution."""
        performed: set[str] = set()
        target = row.get("target_module_id")
        if str(row.get("baseline_hash")) == self.blueprint.baseline_hash:
            performed.add("blueprint_baseline_matches")
        if isinstance(target, str) and target in self.blueprint.registry.contracts:
            performed.add("contract_registry_valid")
        if isinstance(target, str):
            basis = self.blueprint.canonical_authorization_basis(target)
            if basis is not None:
                recorded = self.authorizations.scope_of(row)["required_evidence"]
                if sorted(recorded) == sorted(basis.required_evidence):
                    performed.add("canonical_authorization_basis_present")
        return tuple(sorted(performed))

    # -- bootstrap ----------------------------------------------------------

    def _bootstrap_macro(self) -> None:
        """Record the macro stage once, from the blueprint.

        The stage is not re-asserted on every instruction: it is an authority
        fact with one owner, and the projection derives the current position
        from the blueprint plus the latest event.
        """
        existing = self.trajectory.events(scope=MACRO)
        stage = self.blueprint.current_stage
        if any(row["stage"] == stage for row in existing):
            return
        self.trajectory.record(
            event_id=f"ev-macro-{stage}",
            scope=MACRO,
            stage=stage,
            event_type="macro_stage_entered",
            detail={
                "blueprint_id": self.blueprint.document["blueprint_id"],
                "manifest_hash": self.blueprint.manifest_hash,
                "baseline_hash": self.blueprint.baseline_hash,
                "selected_module_count": len(self.blueprint.selected_module_ids),
            },
        )

    # -- objective ----------------------------------------------------------

    def set_initial_objective(self, statement: str, *,
                              established_by: str = "bootstrap") -> dict:
        objective_id = f"obj-{sha256_hex(statement)[:12]}"
        if self.intent.objective(objective_id) is None:
            self.intent.record_objective(
                objective_id=objective_id,
                statement=statement,
                established_by=established_by,
            )
        return {"objective_id": objective_id, "statement": statement}

    def active_objective(self) -> dict | None:
        objective_id = self.continuity.active_objective_id()
        if objective_id is None:
            return None
        row = self.intent.objective(objective_id)
        return row.as_dict() if row is not None else None

    # -- evidence -----------------------------------------------------------

    def import_authoritative_evidence(self, *, evidence_id: str, kind: str,
                                      source_ref: str, content: str,
                                      admission_basis: str,
                                      original_language: str | None = None) -> dict:
        """Privileged bootstrap/import seam; deliberately absent from L1 API."""
        row = self.evidence.admit(
            evidence_id=evidence_id, kind=kind, source_ref=source_ref,
            content=content, admission_basis=admission_basis,
            original_language=original_language,
        )
        return row.as_dict()

    # -- the slice ----------------------------------------------------------

    def submit_instruction(self, verbatim: str) -> InstructionOutcome:
        """Accept one instruction and return a bounded ALLOW or HOLD."""
        transaction_id = f"tx-{sha256_hex({'verbatim': verbatim, 'n': self.intent.count()})[:12]}"

        decision_class = classify(verbatim)
        interpretation = self._interpret(verbatim, decision_class)

        self.intent.record_instruction(
            transaction_id=transaction_id,
            verbatim=verbatim,
            interpretation=interpretation,
            actor="human_operator",
        )
        self._micro(transaction_id, "HUMAN_INTENT", "instruction_recorded",
                    detail={"verbatim_preserved": True,
                            "classification": decision_class.classification})

        retrieval_corpus = [
            *self.intent.antecedent_records(
                exclude_transaction_id=transaction_id
            ),
            *[row.as_dict() for row in self.evidence.all()],
        ]
        antecedents = retrieve_antecedents(verbatim, retrieval_corpus)
        self._micro(transaction_id, "AUTHORITATIVE_CONTEXT", "antecedents_retrieved",
                    detail={"count": len(antecedents),
                            "role": ANTECEDENT_ROLE,
                            "evidence_ids": [a.evidence_id for a in antecedents]})

        prior_objective_id = self.continuity.active_objective_id()
        objective_id, disposition, treated_as = self._resolve_objective(
            transaction_id=transaction_id,
            verbatim=verbatim,
            classification=decision_class,
            prior_objective_id=prior_objective_id,
        )

        decision_id = f"dec-{transaction_id}"
        decision_row = self.continuity.record_decision(
            decision_id=decision_id,
            transaction_id=transaction_id,
            classification=decision_class.classification,
            treated_as=treated_as,
            prior_objective_id=prior_objective_id,
            active_objective_id=objective_id,
            antecedents=[a.as_dict() for a in antecedents],
            disposition=disposition,
            rationale=decision_class.rationale,
        )
        self._micro(transaction_id, "CONTINUITY", "continuity_decision_recorded",
                    detail={"decision_id": decision_id, "disposition": disposition,
                            "treated_as": treated_as,
                            "active_objective_id": objective_id,
                            "prior_objective_id": prior_objective_id})

        # The antecedents are NOT passed on from here. Authorization is decided
        # from canonical authority alone; the retrieved context stops at the
        # continuity record and the outcome.
        authorization, basis = self._authorize(
            transaction_id=transaction_id,
            decision_row=decision_row,
            classification=decision_class,
            objective_id=objective_id,
            verbatim=verbatim,
        )

        objective_row = self.intent.objective(objective_id) if objective_id else None
        return InstructionOutcome(
            transaction_id=transaction_id,
            verbatim=verbatim,
            interpretation=interpretation,
            classification=decision_class.as_dict(),
            objective=objective_row.as_dict() if objective_row else {},
            antecedents=[a.as_dict() for a in antecedents],
            decision=decision_row.as_dict(),
            authorization=authorization,
            authorization_basis=basis.as_dict() if basis is not None else None,
        )

    def execute(self, authorization_id: str) -> dict:
        """Run an authorization through the Layer-2 gateway.

        The Workbench passes an id and a baseline; it does not know what
        executes.
        """
        return self.gateway.dispatch(
            authorization_id,
            baseline_hash=self.blueprint.baseline_hash,
            active_objective_id=self.continuity.active_objective_id(),
        )

    # -- internals ----------------------------------------------------------

    def _interpret(self, verbatim: str, classification) -> str:
        """A labeled, source-linked derivative of the user's words.

        Deliberately mechanical: it restates the classification and the
        recovered target rather than paraphrasing intent, because a paraphrase
        that drifts is exactly the failure ADR-ARCH-004 clause 1 forbids.
        """
        target = self._resolve_target(verbatim)
        return (
            f"classification={classification.classification}; "
            f"retrieval_cue={classification.is_retrieval_cue}; "
            f"fragment={classification.is_fragment}; "
            f"resolved_target={target or 'none'}; "
            f"basis={classification.rationale}"
        )

    def _resolve_target(self, verbatim: str) -> str | None:
        """Exact-match the instruction against selected module ids.

        No fuzzy matching: an instruction that does not name a selected module
        resolves to nothing, and nothing is what produces a HOLD.
        """
        text = verbatim.lower()
        matches = [
            module_id
            for module_id in self.blueprint.selected_module_ids
            if module_id.lower() in text
        ]
        if len(matches) == 1:
            return matches[0]
        return None

    def _resolve_objective(self, *, transaction_id: str, verbatim: str,
                           classification, prior_objective_id: str | None,
                           ) -> tuple[str | None, str, str]:
        if classification.redirects:
            statement = verbatim.strip()
            objective_id = f"obj-{sha256_hex(statement)[:12]}"
            if self.intent.objective(objective_id) is None:
                self.intent.record_objective(
                    objective_id=objective_id,
                    statement=statement,
                    established_by=transaction_id,
                )
            disposition = (
                "OBJECTIVE_SUPERSEDED_BY_EXPLICIT_REDIRECTION"
                if prior_objective_id
                else "OBJECTIVE_ESTABLISHED"
            )
            return objective_id, disposition, TREATED_AS_SUPERSESSION

        if prior_objective_id is None:
            if classification.is_retrieval_cue:
                return (
                    None,
                    "NO_ACTIVE_OBJECTIVE_PRESERVED_RETRIEVAL_CUE",
                    TREATED_AS_CUE,
                )
            # An ordinary work instruction can establish direction; a question
            # or memory fragment above cannot.
            statement = verbatim.strip()
            objective_id = f"obj-{sha256_hex(statement)[:12]}"
            if self.intent.objective(objective_id) is None:
                self.intent.record_objective(
                    objective_id=objective_id,
                    statement=statement,
                    established_by=transaction_id,
                )
            return objective_id, "OBJECTIVE_ESTABLISHED", TREATED_AS_CUE

        if classification.is_retrieval_cue:
            disposition = (
                "ACTIVE_OBJECTIVE_PRESERVED_FRAGMENT_TREATED_AS_RETRIEVAL_CUE"
                if classification.is_fragment
                else "ACTIVE_OBJECTIVE_PRESERVED_QUESTION_TREATED_AS_RETRIEVAL_CUE"
            )
            return prior_objective_id, disposition, TREATED_AS_CUE

        if classification.classification == "correction":
            return prior_objective_id, "ACTIVE_OBJECTIVE_REFINED_BY_CORRECTION", TREATED_AS_CUE

        return prior_objective_id, "ACTIVE_OBJECTIVE_PRESERVED_ADDITION_RECORDED", TREATED_AS_CUE

    def _authorize(self, *, transaction_id: str, decision_row: Mapping[str, Any],
                   classification, objective_id: str | None,
                   verbatim: str) -> tuple[dict, CanonicalBasis | None]:
        """Record one verdict, derived only from canonical authority.

        Note the signature: no antecedents, no scores, no retrieved ids. The
        only inputs are the user's words (to resolve which module is named),
        the classification of those words, the active objective, and what the
        validated blueprint and contract registry say about the named module.
        """
        authorization_id = f"auth-{transaction_id}"
        target = self._resolve_target(verbatim)
        intent_row = self.intent.transaction(transaction_id)
        if intent_row is None:  # pragma: no cover - the row was just written
            raise CisError("instruction vanished from authority",
                           transaction_id=transaction_id)

        conflicts = self.evidence.conflicts()
        basis = (
            self.blueprint.canonical_authorization_basis(target)
            if target is not None else None
        )

        verdict, reason_code, reason = self._verdict(
            classification=classification, target=target,
            objective_id=objective_id, basis=basis,
            objective_self_established=self._objective_self_established(
                objective_id=objective_id, transaction_id=transaction_id,
                verbatim_hash=str(intent_row["verbatim_hash"]),
            ),
            conflict_count=len(conflicts),
        )

        scope = self._scope_for(verdict=verdict, target=target, basis=basis)

        row = self.authorizations.record(
            authorization_id=authorization_id,
            transaction_id=transaction_id,
            decision_id=str(decision_row["decision_id"]),
            objective_id=objective_id,
            verdict=verdict,
            reason_code=reason_code,
            reason=reason,
            target_module_id=target,
            scope=scope,
            verbatim_hash=str(intent_row["verbatim_hash"]),
            decision_hash=str(decision_row["decision_hash"]),
            baseline_hash=self.blueprint.baseline_hash,
        )
        self._micro(transaction_id, "REVIEW_AUTHORIZATION",
                    "authorization_recorded",
                    module_id=target,
                    detail={"authorization_id": authorization_id,
                            "verdict": verdict, "reason_code": reason_code,
                            "authorization_basis_kind":
                                basis.basis_kind if basis else None,
                            "binding_hash": str(row["binding_hash"])})
        granting = basis if verdict == ALLOW else None
        out = row.as_dict()
        out["scope"] = scope
        # Only an ALLOW carries a basis. A HOLD on a module that happens to
        # have one must not display it, or a reader would see authority that
        # was never applied.
        out["authorization_basis"] = granting.as_dict() if granting else None
        return out, granting

    def _objective_self_established(self, *, objective_id: str | None,
                                     transaction_id: str,
                                     verbatim_hash: str) -> bool:
        """Did THESE WORDS create the objective they would be judged under?

        If so the objective is not independent authority for them: the request
        would be authorizing itself one step removed. Direction from the
        bootstrap seam, or from an earlier exchange that said something else,
        is independent.

        The comparison is on the verbatim hash and not only on the transaction
        id, and that is the whole point. Comparing ids alone would leave the
        rejected retry loophole intact one level up: submit a work instruction
        with no objective set, be held, submit the identical words again, and
        the second copy would be authorized under the objective the first copy
        established. Identical words therefore never clear this check, however
        many times they are sent.
        """
        if objective_id is None:
            return False
        objective = self.intent.objective(objective_id)
        if objective is None:  # pragma: no cover - written before this read
            return False
        established_by = str(objective["established_by"])
        if established_by == transaction_id:
            return True
        origin = self.intent.transaction(established_by)
        return origin is not None and str(origin["verbatim_hash"]) == verbatim_hash

    def _verdict(self, *, classification, target: str | None,
                 objective_id: str | None, basis: CanonicalBasis | None,
                 objective_self_established: bool,
                 conflict_count: int) -> tuple[str, str, str]:
        """HOLD unless every canonical condition holds. Closed vocabulary.

        Deliberately a pure function of canonical facts. There is no parameter
        through which conversation volume, repetition or token overlap could
        reach this decision.
        """
        if conflict_count:
            return (HOLD, REASON_EVIDENCE_CONFLICT,
                    "evidence conflicts are recorded and unresolved, so the "
                    "slice fails closed rather than inventing a resolution")
        if objective_id is None:
            return (HOLD, REASON_OBJECTIVE_UNSET,
                    "there is no active objective for the work to belong to")
        if objective_self_established:
            return (HOLD, REASON_OBJECTIVE_SELF_ESTABLISHED,
                    "these exact words established the objective they would be "
                    "authorized under, and a request may not supply its own "
                    "direction; the objective is recorded, and an instruction "
                    "that is not a repetition of it can be authorized under it")
        if classification.is_retrieval_cue:
            return (HOLD, REASON_RETRIEVAL_CUE,
                    "the instruction is a retrieval cue, not a request to "
                    "execute work, so the active objective is preserved and "
                    "nothing is authorized")
        if target is None:
            return (HOLD, REASON_OUTSIDE_AUTHORITY,
                    "the instruction does not name exactly one module the "
                    "blueprint selects, so the work is not already inside "
                    "canonical authority")
        if (self.blueprint.reconstruction_status(target)
                not in IN_SCOPE_RECONSTRUCTION_STATUSES):
            return (HOLD, REASON_OUTSIDE_AUTHORITY,
                    "the named module is not in this slice's reconstruction scope")
        if basis is None:
            return (HOLD, REASON_NO_CANONICAL_BASIS,
                    "the validated architecture supplies no canonical evidence "
                    "basis for this module, and nothing else may stand in for "
                    "it — no quantity of surrounding conversation is authority")
        return (ALLOW, REASON_IN_AUTHORITY,
                "the target module is already selected by the validated "
                "reconstruction architecture and carries a canonical evidence "
                "basis, an objective established independently of this request "
                "governs, and the scope below bounds the work")

    def _scope_for(self, *, verdict: str, target: str | None,
                   basis: CanonicalBasis | None) -> dict:
        if verdict != ALLOW or target is None or basis is None:
            return {
                "operation": "none",
                "allowed_scope": [],
                "forbidden_actions": ["any execution"],
                "required_checks": [],
                "required_evidence": [],
                "stopping_condition": "no execution is authorized",
                "return_point": "workbench:submit_instruction",
            }
        contract = self.blueprint.registry.get(target)
        return {
            "operation": "reconstruct_module",
            # Scope is derived from the module's own contract, so a broader
            # contract cannot be written by the requester to widen it.
            "allowed_scope": [f"module:{target}", f"layer:{contract.layer}"],
            "forbidden_actions": sorted(
                set(contract.forbidden_dependencies)
                | {"write:/mnt/projects/cis", "network:any", "model:any"}
            ),
            "required_checks": ["contract_registry_valid",
                                "blueprint_baseline_matches",
                                "canonical_authorization_basis_present"],
            # The canonical accepted authority the work runs under, labeled as
            # such. Never a retrieved antecedent id, and never a record of past
            # execution.
            "required_evidence": basis.required_evidence,
            "stopping_condition": contract.verification,
            "return_point": "workbench:trajectory",
        }

    def _micro(self, transaction_id: str, stage: str, event_type: str, *,
               module_id: str | None = None,
               detail: Mapping[str, Any] | None = None) -> None:
        suffix = sha256_hex({"tx": transaction_id, "stage": stage,
                             "event": event_type})[:12]
        self.trajectory.record(
            event_id=f"ev-{suffix}",
            scope=MICRO,
            stage=stage,
            event_type=event_type,
            module_id=module_id,
            transaction_id=transaction_id,
            detail=detail,
        )
