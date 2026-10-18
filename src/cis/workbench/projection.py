"""The Workbench trajectory projection.

A projection, generated from authority, never edited in place and never read
back as an input to authority (ADR-ARCH-002). It exposes three things:

* MACRO — the current reconstruction stage and progress across the selected
  modules;
* MICRO — the ordered steps of one transaction;
* YOU ARE HERE — a marker DERIVED from the highest-sequence trajectory event.
  It is computed here and stored nowhere, which is the whole point: a second
  copy of "where we are" is the duplicate-state failure that reconstruction
  exists to remove.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from ..authority.authorization import ALLOW, AuthorizationAuthority
from ..authority.continuity import ContinuityAuthority
from ..authority.intent import IntentAuthority
from ..authority.runs import COMPLETED, RunAuthority
from ..authority.trajectory import MACRO, MICRO, TrajectoryAuthority
from ..blueprint import Blueprint
from ..errors import EvidenceConflict


def _to_plain(value: Any) -> Any:
    """Recursively convert frozen manifest views into plain JSON-safe objects.

    Projections are generated outputs, not authority; they must serialize.
    """
    if isinstance(value, Mapping):
        return {k: _to_plain(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_to_plain(v) for v in value]
    return value


@dataclass
class TrajectoryProjection:
    blueprint: Blueprint
    trajectory: TrajectoryAuthority
    intent: IntentAuthority
    continuity: ContinuityAuthority
    runs: RunAuthority
    authorizations: AuthorizationAuthority

    # -- macro --------------------------------------------------------------

    def macro(self) -> dict:
        """Reconstruction stage and selected-module progress."""
        order = self.blueprint.dependency_order()
        executed = self._executed_modules()
        authorized = self._authorized_modules()

        modules = []
        for module_id in order:
            if not self.blueprint.is_selected(module_id):
                continue
            entry = self.blueprint.module(module_id)
            if module_id in executed:
                progress = "EXECUTED"
            elif module_id in authorized:
                progress = "AUTHORIZED"
            else:
                progress = "CONTRACTED"
            modules.append({
                "module_id": module_id,
                "layer": self.blueprint.registry.get(module_id).layer,
                "dependency_position": order.index(module_id),
                "reconstruction_status": entry["reconstruction_status"],
                "progress": progress,
                "capability": entry["capability"],
                # The module's canonical authorization basis, shown as the
                # manifest records it. A projection reports authority; it is
                # never read back as one (ADR-ARCH-002).
                "evidence_basis": entry["evidence_basis"],
            })

        return {
            "blueprint_id": self.blueprint.document["blueprint_id"],
            "current_stage": self.blueprint.current_stage,
            "stages": _to_plain(self.blueprint.stages),
            "baseline_hash": self.blueprint.baseline_hash,
            "modules": modules,
            "counts": {
                "selected": len(modules),
                "contracted": sum(1 for m in modules if m["progress"] == "CONTRACTED"),
                "authorized": sum(1 for m in modules if m["progress"] == "AUTHORIZED"),
                "executed": sum(1 for m in modules if m["progress"] == "EXECUTED"),
            },
            "deferred_modules": _to_plain(self.blueprint.document["deferred_modules"]),
        }

    def _authorized_modules(self) -> set[str]:
        return {
            str(row["target_module_id"])
            for row in self.authorizations.all()
            if row["verdict"] == ALLOW and row["target_module_id"]
        }

    def _executed_modules(self) -> set[str]:
        executed: set[str] = set()
        for run in self.runs.all():
            if run["status"] != COMPLETED:
                continue
            authorization = self.authorizations.get(str(run["authorization_id"]))
            if authorization and authorization["target_module_id"]:
                executed.add(str(authorization["target_module_id"]))
        return executed

    # -- reconstruction journey -------------------------------------------

    def journey(self) -> dict:
        """Plain-language build path derived from blueprint and trajectory.

        The manifest owns the intended sequence and meaning.  Recorded
        trajectory events own what has actually occurred.  This method joins
        them for presentation without persisting another progress record.
        """
        marker = self.you_are_here()
        current_stage = marker["macro_stage"]
        stages = []
        current_index: int | None = None
        for index, stage in enumerate(self.blueprint.stages):
            item = dict(stage)
            item["position"] = index + 1
            item["is_current"] = stage["stage_id"] == current_stage
            if item["is_current"]:
                current_index = index
            stages.append(item)

        next_stage = None
        start = (current_index + 1) if current_index is not None else 0
        for stage in stages[start:]:
            if stage["status"] != "COMPLETE":
                next_stage = dict(stage)
                break

        recorded_micro_stages = {
            str(row["stage"])
            for row in self.trajectory.events(scope=MICRO)
        }
        proven_links = []
        for link in self.blueprint.proven_slice["links"]:
            item = dict(link)
            item["achieved"] = link["trajectory_stage"] in recorded_micro_stages
            item["derived_from"] = (
                f"trajectory_events:stage={link['trajectory_stage']}"
                if item["achieved"] else "trajectory_events:no_matching_stage"
            )
            proven_links.append(item)

        return {
            "blueprint_id": self.blueprint.document["blueprint_id"],
            "baseline_hash": self.blueprint.baseline_hash,
            "destination": _to_plain(self.blueprint.destination),
            "stages": stages,
            "you_are_here": {
                "stage_id": current_stage,
                "derived_from": marker["derived_from"],
            },
            "next_stage": next_stage,
            "proven_slice": {
                "links": proven_links,
                "achieved": sum(1 for link in proven_links if link["achieved"]),
                "total": len(proven_links),
            },
        }

    # -- micro --------------------------------------------------------------

    def micro(self, transaction_id: str) -> dict:
        """The ordered steps of one transaction."""
        events = self.trajectory.events(transaction_id=transaction_id)
        intent = self.intent.transaction(transaction_id)
        decisions = self.continuity.for_transaction(transaction_id)
        return {
            "transaction_id": transaction_id,
            "verbatim": str(intent["verbatim_instruction"]) if intent else None,
            "interpretation": {
                "label": str(intent["interpretation_label"]),
                "text": str(intent["interpretation"]),
                "source": str(intent["interpretation_source"]),
            } if intent else None,
            "continuity_decisions": [row.as_dict() for row in decisions],
            "steps": [
                {
                    "seq": int(row["seq"]),
                    "stage": str(row["stage"]),
                    "event_type": str(row["event_type"]),
                    "module_id": row["module_id"],
                    "detail": json.loads(str(row["detail_json"])),
                }
                for row in events
            ],
        }

    # -- you are here -------------------------------------------------------

    def you_are_here(self) -> dict:
        """Derived position. Never stored, never duplicated.

        Macro position comes from the blueprint's current stage; micro position
        comes from the single highest-sequence trajectory event. If no event
        exists the marker says so rather than inventing a position.
        """
        latest = self.trajectory.latest()
        if latest is None:
            return {
                "derived_from": "trajectory_events:none",
                "macro_stage": self.blueprint.current_stage,
                "micro_stage": None,
                "event_type": None,
                "module_id": None,
                "transaction_id": None,
                "seq": None,
            }
        return {
            "derived_from": f"trajectory_events:seq={int(latest['seq'])}",
            "macro_stage": self._macro_stage_at(latest),
            "micro_stage": str(latest["stage"]) if latest["scope"] == MICRO else None,
            "event_type": str(latest["event_type"]),
            "module_id": latest["module_id"],
            "transaction_id": latest["transaction_id"],
            "seq": int(latest["seq"]),
        }

    def _macro_stage_at(self, latest: Any) -> str:
        if latest["scope"] == MACRO:
            return self._validate_macro_stage(str(latest["stage"]))
        macro_events = self.trajectory.events(scope=MACRO)
        if macro_events:
            return self._validate_macro_stage(str(macro_events[-1]["stage"]))
        return self.blueprint.current_stage

    def _validate_macro_stage(self, stage: str) -> str:
        """Fail closed when recorded authority drifts from manifest authority."""
        stage_ids = {
            str(s["stage_id"]) for s in self.blueprint.document["macro"]["stages"]
        }
        if stage not in stage_ids:
            raise EvidenceConflict(
                "recorded macro trajectory stage is absent from manifest stages",
                recorded_stage=stage, declared_stages=sorted(stage_ids))
        if stage != self.blueprint.current_stage:
            raise EvidenceConflict(
                "recorded macro trajectory stage disagrees with manifest current_stage",
                recorded_stage=stage, current_stage=self.blueprint.current_stage)
        return stage

    # -- composed -----------------------------------------------------------

    def full(self, transaction_id: str | None = None) -> dict:
        out: dict = {
            "you_are_here": self.you_are_here(),
            "macro": self.macro(),
            "journey": self.journey(),
        }
        if transaction_id is not None:
            out["micro"] = self.micro(transaction_id)
        else:
            out["transactions"] = [
                str(row["transaction_id"]) for row in self.intent.history()
            ]
        return out
