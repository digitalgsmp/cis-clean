"""The read-only assurance projection.

Generated from authority, never edited, never read back as an input to
authority (ADR-ARCH-002). It is the only thing in the increment a Layer-1
surface is allowed to touch, and it holds no write path at all.

WHY ``proven_slice`` IS NOT TOUCHED
-----------------------------------

``blueprint.proven_slice`` means one specific thing: the slice-1 path from a
human instruction to recorded evidence, and whether each of its links has
actually been driven. Widening it to cover assurance would silently change what
every existing reader of that projection is being told, and a reader who saw
``5 of 5`` yesterday would see a different denominator today for reasons that
have nothing to do with slice 1.

So assurance progress is a SEPARATE projection over a separate manifest
section, ``assurance_slice``, with its own links and its own counts.
``TrajectoryProjection`` is untouched, and ``journey()`` still reports exactly
what it reported before this increment.

THE ORDER RECONCILIATION
------------------------

``order_reconciliation`` is read straight out of the validated manifest and
reported, not computed. It records which lettered boundary proofs this
increment delivers (L, H, I, J, K) and which remain mandatory and outstanding
(A-G, M, N, O), gating the later real nonroot contained-worker capability. No
letter is waived, and the projection refuses to show a waiver because the
manifest loader refuses to load one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from ..authority.trajectory import (
    ASSURANCE_MICRO_STAGES, MICRO, TrajectoryAuthority,
)
from .authority import (
    ASSURANCE_FLOW, ASSURANCE_STATES, AssuranceAuthority,
    MAX_OBJECTION_CYCLES, REVIEW_PENDING, STATE_ESCALATED,
    STATE_PROMOTION_AUTHORIZED, STATE_PROMOTION_DENIED,
)
from .task_contract import TASK_CONTRACT_HASH_DOMAIN, TEMPLATES


def _to_plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _to_plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_to_plain(v) for v in value]
    return value


@dataclass
class AssuranceProjection:
    """Read-only views over the assurance ledger."""

    store: Any
    blueprint: Any
    authority: AssuranceAuthority | None = None
    trajectory: TrajectoryAuthority | None = None

    def __post_init__(self) -> None:
        if self.authority is None:
            self.authority = AssuranceAuthority(self.store)
        if self.trajectory is None:
            self.trajectory = TrajectoryAuthority(self.store)

    @classmethod
    def for_service(cls, service: Any) -> "AssuranceProjection":
        """Build a projection over the authority a Layer-2 service already holds.

        This exists so the Layer-1 surface can construct the read model
        without naming an authority handle itself. ADR-SEED-018's governing
        boundary rule is enforced in this environment by a test that reads
        ``interface/api.py`` and asserts the tokens ``store``, ``insert(``,
        ``AuthorityStore`` and ``execute_raw`` do not appear in it at all; a
        constructor call that reached for the handle directly would pass the
        architecture and fail that test, correctly. Resolving the handle here
        keeps the rule true of the source and not merely of the behaviour.
        """
        return cls(store=getattr(service, "store"),
                   blueprint=service.blueprint)

    # -- the declared machine ----------------------------------------------

    def declared_flow(self) -> dict:
        """The state vocabulary and transitions, as the code declares them."""
        return {
            "states": list(ASSURANCE_STATES),
            "transitions": {state: list(nexts)
                            for state, nexts in ASSURANCE_FLOW.items()},
            "max_objection_cycles": MAX_OBJECTION_CYCLES,
            "fourth_cycle_is_impossible_at": [
                "api:cis.assurance.reviewer.review refuses once three cycles "
                "are recorded",
                "ledger:AssuranceAuthority.ReviewerFacade.open_objection_cycle "
                "refuses a cycle number above three or out of sequence",
                "sql:objection_cycles.cycle_number CHECK BETWEEN 1 AND 3 with "
                "UNIQUE(task_contract_id, cycle_number), and "
                "review_results.cycle_index CHECK BETWEEN 0 AND 2",
            ],
            "task_contract_hash_domain": TASK_CONTRACT_HASH_DOMAIN,
            "templates": sorted(TEMPLATES),
        }

    # -- order reconciliation ----------------------------------------------

    def order_reconciliation(self) -> dict:
        """Reported from the manifest, never recomputed here."""
        return _to_plain(
            self.blueprint.assurance_increment["order_reconciliation"])

    # -- micro-stage visibility --------------------------------------------

    def micro_stages(self) -> list[dict]:
        """Which assurance micro stages have actually been recorded."""
        recorded = [row for row in self.trajectory.events(scope=MICRO)
                    if str(row["stage"]) in set(ASSURANCE_MICRO_STAGES)]
        counts: dict[str, int] = {}
        for row in recorded:
            counts[str(row["stage"])] = counts.get(str(row["stage"]), 0) + 1
        return [
            {
                "stage": stage,
                "recorded_events": counts.get(stage, 0),
                "observed": counts.get(stage, 0) > 0,
                "derived_from": (f"trajectory_events:stage={stage}"
                                 if counts.get(stage, 0)
                                 else "trajectory_events:no_matching_stage"),
            }
            for stage in ASSURANCE_MICRO_STAGES
        ]

    def events(self, task_contract_id: str | None = None) -> list[dict]:
        """The assurance micro events, in sequence order."""
        out = []
        for row in self.trajectory.events(scope=MICRO):
            if str(row["stage"]) not in set(ASSURANCE_MICRO_STAGES):
                continue
            detail = json.loads(str(row["detail_json"]))
            if (task_contract_id is not None
                    and detail.get("task_contract_id") != task_contract_id):
                continue
            out.append({
                "seq": int(row["seq"]),
                "stage": str(row["stage"]),
                "event_type": str(row["event_type"]),
                "module_id": row["module_id"],
                "detail": detail,
            })
        return out

    # -- the assurance journey ---------------------------------------------

    def journey(self) -> dict:
        """Plain-language assurance path, from the manifest and the ledger.

        Separate from ``TrajectoryProjection.journey``, which still means the
        slice-1 path and nothing else.
        """
        section = self.blueprint.assurance_slice
        recorded = {item["stage"] for item in self.micro_stages()
                    if item["observed"]}
        links = []
        for link in section["links"]:
            item = _to_plain(link)
            item["achieved"] = link["trajectory_stage"] in recorded
            item["derived_from"] = (
                f"trajectory_events:stage={link['trajectory_stage']}"
                if item["achieved"] else "trajectory_events:no_matching_stage"
            )
            links.append(item)
        return {
            "increment_id": str(section["increment_id"]),
            "statement": str(section["statement"]),
            "links": links,
            "achieved": sum(1 for link in links if link["achieved"]),
            "total": len(links),
        }

    # -- task contracts -----------------------------------------------------

    def task_contract(self, task_contract_id: str) -> dict:
        snapshot = self.authority.ledger.snapshot(task_contract_id)
        snapshot["events"] = self.events(task_contract_id)
        snapshot["next_states"] = list(
            ASSURANCE_FLOW.get(snapshot["state"], ()))
        snapshot["allowed_paths"] = json.loads(
            str(snapshot["task_contract"]["allowed_paths_json"]))
        return snapshot

    def task_contracts(self) -> list[dict]:
        ledger = self.authority.ledger
        out = []
        for row in ledger.task_contracts():
            task_contract_id = str(row["task_contract_id"])
            out.append({
                "task_contract_id": task_contract_id,
                "authorization_id": str(row["authorization_id"]),
                "target_module_id": str(row["target_module_id"]),
                "template_id": str(row["template_id"]),
                "state": ledger.state_of(task_contract_id),
                "review_status": ledger.review_status(task_contract_id),
                "objection_cycles_used":
                    ledger.objection_cycle_count(task_contract_id),
                "objection_cycles_remaining":
                    ledger.cycles_remaining(task_contract_id),
                "escalated": ledger.is_escalated(task_contract_id),
                "verification_passed":
                    ledger.verification_passed(task_contract_id),
                "review_passed": ledger.review_passed(task_contract_id),
                "task_contract_hash": str(row["task_contract_hash"]),
                "hash_domain": str(row["hash_domain"]),
            })
        return out

    # -- counts -------------------------------------------------------------

    def counts(self) -> dict:
        rows = self.task_contracts()
        by_state: dict[str, int] = {state: 0 for state in ASSURANCE_STATES}
        for row in rows:
            by_state[row["state"]] = by_state.get(row["state"], 0) + 1
        return {
            "task_contracts": len(rows),
            "by_state": by_state,
            "review_pending": sum(1 for row in rows
                                  if row["review_status"] == REVIEW_PENDING),
            "escalated": sum(1 for row in rows if row["escalated"]),
            "promotion_authorized": by_state.get(
                STATE_PROMOTION_AUTHORIZED, 0),
            "promotion_denied": by_state.get(STATE_PROMOTION_DENIED, 0),
            "objection_cycles_recorded": sum(
                row["objection_cycles_used"] for row in rows),
        }

    # -- composed -----------------------------------------------------------

    def full(self, task_contract_id: str | None = None) -> dict:
        out: dict = {
            "increment": _to_plain(self.blueprint.assurance_increment),
            "declared_flow": self.declared_flow(),
            "order_reconciliation": self.order_reconciliation(),
            "journey": self.journey(),
            "micro_stages": self.micro_stages(),
            "counts": self.counts(),
            "task_contracts": self.task_contracts(),
            "host_independent": True,
            "host_action_performed": None,
        }
        if task_contract_id is not None:
            out["task_contract"] = self.task_contract(task_contract_id)
        return out
