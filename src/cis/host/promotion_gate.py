"""Apply and roll back candidates only under recorded promotion authority.

This module does not decide whether work should be promoted. It enforces the
decision made by ``cis.assurance.promotion``. Before touching its sealed target
root it appends a plan containing the exact candidate and prior bytes. Apply
and rollback completions are separate append-only events, so interruption
leaves a resumable operation rather than an ambiguous mutable status.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping

from ..canonical import sha256_hex
from ..errors import HostActionRefused

PROMOTION_AUTHORIZED = "PROMOTION_AUTHORIZED"
_REFERENCE_ROOT = Path("/mnt/projects/cis")


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class HostPromotionGate:
    """The sole bounded writer of a configured promotion target root."""

    module_id = "cis.host.promotion_gate"
    owned_authority = ("host_promotion_plans", "host_promotion_events")

    def __init__(self, store, *, target_root: str | Path) -> None:
        self._store = store
        self._root = Path(target_root).resolve()
        if self._root == _REFERENCE_ROOT or _REFERENCE_ROOT in self._root.parents:
            raise HostActionRefused(
                "promotion target may not be the protected reference environment",
                target_root=str(self._root),
            )
        self._root.mkdir(parents=True, exist_ok=True)

    def apply(self, *, task_contract_id: str,
              candidate_content: str | bytes) -> Mapping[str, Any]:
        candidate = (candidate_content.encode("utf-8")
                     if isinstance(candidate_content, str)
                     else bytes(candidate_content))
        decision = self._authorized_decision(task_contract_id)
        self._verify_candidate_evidence(task_contract_id, _digest(candidate))
        target_relative = self._target_relative(task_contract_id)
        target = self._safe_target(target_relative)
        plan = self._plan_for(task_contract_id)
        if plan is None:
            previous_present = target.is_file()
            previous = target.read_bytes() if previous_present else None
            application_id = "hpa-" + sha256_hex({
                "task_contract_id": task_contract_id,
                "decision_id": str(decision["decision_id"]),
                "target_relative_path": target_relative,
                "candidate_sha256": _digest(candidate),
            })[:16]
            plan_hash = sha256_hex({
                "__hash_domain__": "cis.host.promotion_plan.v1",
                "application_id": application_id,
                "task_contract_id": task_contract_id,
                "promotion_decision_id": str(decision["decision_id"]),
                "target_relative_path": target_relative,
                "candidate_sha256": _digest(candidate),
                "previous_present": previous_present,
                "previous_sha256": _digest(previous) if previous is not None else None,
            })
            plan = self._store.insert("host_promotion_plans", {
                "application_id": application_id,
                "task_contract_id": task_contract_id,
                "promotion_decision_id": str(decision["decision_id"]),
                "target_relative_path": target_relative,
                "candidate_content": candidate,
                "candidate_sha256": _digest(candidate),
                "previous_present": int(previous_present),
                "previous_content": previous,
                "previous_sha256": (_digest(previous)
                                    if previous is not None else None),
                "plan_hash": plan_hash,
                "created_at": self._store.now(),
                "seq": self._store.next_seq(),
            })
        elif (bytes(plan["candidate_content"]) != candidate
              or str(plan["promotion_decision_id"]) != str(decision["decision_id"])):
            raise HostActionRefused(
                "an immutable promotion plan already binds different bytes or authority",
                task_contract_id=task_contract_id,
            )

        if self._event(str(plan["application_id"]), "ROLLED_BACK") is not None:
            raise HostActionRefused("a rolled-back application cannot be reapplied")
        if self._event(str(plan["application_id"]), "APPLIED") is None:
            self._atomic_write(target, bytes(plan["candidate_content"]))
            observed = _digest(target.read_bytes())
            if observed != str(plan["candidate_sha256"]):
                raise HostActionRefused("promoted target digest did not verify")
            self._append_event(plan, "APPLIED", observed)
        return self.status(str(plan["application_id"]))

    def rollback(self, application_id: str) -> Mapping[str, Any]:
        plan = self._store.one(
            "SELECT * FROM host_promotion_plans WHERE application_id = ?",
            (application_id,),
        )
        if plan is None:
            raise HostActionRefused("no such promotion application",
                                    application_id=application_id)
        if self._event(application_id, "APPLIED") is None:
            raise HostActionRefused("an unapplied plan cannot be rolled back",
                                    application_id=application_id)
        if self._event(application_id, "ROLLED_BACK") is not None:
            return self.status(application_id)
        if self._event(application_id, "ROLLBACK_STARTED") is None:
            self._append_event(plan, "ROLLBACK_STARTED", None)

        target = self._safe_target(str(plan["target_relative_path"]))
        if int(plan["previous_present"]):
            previous = bytes(plan["previous_content"])
            self._atomic_write(target, previous)
            observed = _digest(target.read_bytes())
            if observed != str(plan["previous_sha256"]):
                raise HostActionRefused("rollback target digest did not verify")
        else:
            if target.exists():
                target.unlink()
            observed = None
            if target.exists():
                raise HostActionRefused("rollback could not remove new target")
        self._append_event(plan, "ROLLED_BACK", observed)
        return self.status(application_id)

    def recover(self, application_id: str) -> Mapping[str, Any]:
        """Resume the sole incomplete action using only recorded plan bytes."""
        plan = self._store.one(
            "SELECT * FROM host_promotion_plans WHERE application_id = ?",
            (application_id,),
        )
        if plan is None:
            raise HostActionRefused("no such promotion application",
                                    application_id=application_id)
        if self._event(application_id, "ROLLBACK_STARTED") is not None:
            return self.rollback(application_id)
        if self._event(application_id, "APPLIED") is None:
            return self.apply(
                task_contract_id=str(plan["task_contract_id"]),
                candidate_content=bytes(plan["candidate_content"]),
            )
        return self.status(application_id)

    def status(self, application_id: str) -> dict[str, Any]:
        plan = self._store.one(
            "SELECT * FROM host_promotion_plans WHERE application_id = ?",
            (application_id,),
        )
        if plan is None:
            raise HostActionRefused("no such promotion application",
                                    application_id=application_id)
        events = self._store.query(
            "SELECT * FROM host_promotion_events WHERE application_id = ? "
            "ORDER BY seq", (application_id,),
        )
        event_types = [str(row["event_type"]) for row in events]
        state = ("ROLLED_BACK" if "ROLLED_BACK" in event_types else
                 "ROLLBACK_STARTED" if "ROLLBACK_STARTED" in event_types else
                 "APPLIED" if "APPLIED" in event_types else "PLANNED")
        return {
            "application_id": application_id,
            "task_contract_id": str(plan["task_contract_id"]),
            "promotion_decision_id": str(plan["promotion_decision_id"]),
            "target_relative_path": str(plan["target_relative_path"]),
            "candidate_sha256": str(plan["candidate_sha256"]),
            "previous_sha256": plan["previous_sha256"],
            "state": state,
            "events": event_types,
        }

    def _authorized_decision(self, task_contract_id: str):
        rows = self._store.query(
            "SELECT * FROM promotion_decisions WHERE task_contract_id = ? "
            "ORDER BY seq", (task_contract_id,),
        )
        if not rows or str(rows[-1]["decision"]) != PROMOTION_AUTHORIZED:
            raise HostActionRefused(
                "host apply requires a recorded PROMOTION_AUTHORIZED decision",
                task_contract_id=task_contract_id,
            )
        return rows[-1]

    def _verify_candidate_evidence(self, task_contract_id: str,
                                   candidate_sha256: str) -> None:
        row = self._store.one(
            "SELECT e.original_language FROM task_contracts tc "
            "JOIN backend_runs r ON r.authorization_id = tc.authorization_id "
            "JOIN evidence_records e ON e.evidence_id = r.evidence_id "
            "WHERE tc.task_contract_id = ? AND r.status = 'completed'",
            (task_contract_id,),
        )
        if row is None:
            raise HostActionRefused("candidate has no completed execution evidence")
        expected_line = f"candidate_sha256={candidate_sha256}"
        if expected_line not in str(row["original_language"]).splitlines():
            raise HostActionRefused(
                "candidate bytes do not match submitted worker evidence",
                candidate_sha256=candidate_sha256,
            )

    def _target_relative(self, task_contract_id: str) -> str:
        row = self._store.one(
            "SELECT target_module_id FROM task_contracts "
            "WHERE task_contract_id = ?", (task_contract_id,),
        )
        if row is None:
            raise HostActionRefused("task contract is absent",
                                    task_contract_id=task_contract_id)
        parts = str(row["target_module_id"]).split(".")
        if not parts or any(not p or p in (".", "..") or "/" in p for p in parts):
            raise HostActionRefused("target module does not form a safe path")
        return "/".join(parts) + ".candidate"

    def _safe_target(self, relative: str) -> Path:
        candidate = (self._root / relative).resolve()
        if self._root != candidate and self._root not in candidate.parents:
            raise HostActionRefused("promotion target escapes the sealed root")
        return candidate

    def _plan_for(self, task_contract_id: str):
        return self._store.one(
            "SELECT * FROM host_promotion_plans WHERE task_contract_id = ?",
            (task_contract_id,),
        )

    def _event(self, application_id: str, event_type: str):
        return self._store.one(
            "SELECT * FROM host_promotion_events "
            "WHERE application_id = ? AND event_type = ?",
            (application_id, event_type),
        )

    def _append_event(self, plan: Mapping[str, Any], event_type: str,
                      observed_sha256: str | None) -> None:
        application_id = str(plan["application_id"])
        event_id = "hpe-" + sha256_hex({
            "application_id": application_id,
            "event_type": event_type,
        })[:16]
        event_hash = sha256_hex({
            "__hash_domain__": "cis.host.promotion_event.v1",
            "event_id": event_id,
            "application_id": application_id,
            "event_type": event_type,
            "observed_sha256": observed_sha256,
        })
        self._store.insert("host_promotion_events", {
            "event_id": event_id,
            "application_id": application_id,
            "event_type": event_type,
            "observed_sha256": observed_sha256,
            "event_hash": event_hash,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })

    @staticmethod
    def _atomic_write(target: Path, content: bytes) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=".cis-promotion-", dir=target.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


__all__ = ["HostPromotionGate"]
