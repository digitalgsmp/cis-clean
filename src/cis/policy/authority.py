"""Single append-only owner for compiled policy envelopes."""

from __future__ import annotations

import json
from typing import Any, Mapping

from ..authority.store import AuthorityStore, Row
from ..errors import PolicyRefused, PolicyStale, PolicyTampered
from .compiler import verify_compiled_envelope
from .schema import ENVELOPE_HASH_DOMAIN, PolicyEnvelope


def _dump(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def envelope_from_row(row: Mapping[str, Any]) -> PolicyEnvelope:
    try:
        envelope = PolicyEnvelope(
            task_contract_id=str(row["task_contract_id"]),
            task_contract_hash=str(row["task_contract_hash"]),
            selector=json.loads(str(row["selector_json"])),
            master_baseline_hash=str(row["master_baseline_hash"]),
            master_policy_ids=tuple(json.loads(str(row["master_policy_ids_json"]))),
            task_policy_ids=tuple(json.loads(str(row["task_policy_ids_json"]))),
            selected_policies=tuple(json.loads(str(row["selected_policies_json"]))),
            prohibited_actions=tuple(json.loads(str(row["prohibited_actions_json"]))),
            required_checks=tuple(json.loads(str(row["required_checks_json"]))),
            required_evidence=tuple(json.loads(str(row["required_evidence_json"]))),
            narrowed_scope=(
                tuple(json.loads(str(row["narrowed_scope_json"])))
                if row["narrowed_scope_json"] is not None else None
            ),
            policy_set_hash=str(row["policy_set_hash"]),
            hash_domain=str(row["hash_domain"]),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PolicyTampered("stored policy envelope is malformed") from exc
    return verify_compiled_envelope({**envelope.as_dict(),
                                     "envelope_hash": str(row["envelope_hash"])})


class PolicyAuthority:
    owned_authority = ("policy_envelopes",)

    def __init__(self, store: AuthorityStore) -> None:
        self._store = store

    def row_for_task_contract(self, task_contract_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM policy_envelopes WHERE task_contract_id = ?",
            (task_contract_id,),
        )

    def append(self, envelope: PolicyEnvelope) -> Row:
        contract = self._store.one(
            "SELECT task_contract_hash FROM task_contracts WHERE task_contract_id = ?",
            (envelope.task_contract_id,),
        )
        if contract is None:
            raise PolicyRefused("policy envelope names no frozen task contract",
                                task_contract_id=envelope.task_contract_id)
        if str(contract["task_contract_hash"]) != envelope.task_contract_hash:
            raise PolicyRefused("policy envelope task-contract hash is stale or forged",
                                task_contract_id=envelope.task_contract_id)
        verify_compiled_envelope(envelope.as_dict())
        if self.row_for_task_contract(envelope.task_contract_id) is not None:
            raise PolicyRefused("task contract already has a policy envelope",
                                task_contract_id=envelope.task_contract_id)
        return self._store.insert("policy_envelopes", {
            "policy_envelope_id": "pe-" + envelope.envelope_hash,
            "task_contract_id": envelope.task_contract_id,
            "task_contract_hash": envelope.task_contract_hash,
            "selector_json": _dump(dict(envelope.selector)),
            "master_baseline_hash": envelope.master_baseline_hash,
            "master_policy_ids_json": _dump(list(envelope.master_policy_ids)),
            "task_policy_ids_json": _dump(list(envelope.task_policy_ids)),
            "selected_policies_json": _dump(
                [dict(item) for item in envelope.selected_policies]),
            "prohibited_actions_json": _dump(list(envelope.prohibited_actions)),
            "required_checks_json": _dump(list(envelope.required_checks)),
            "required_evidence_json": _dump(list(envelope.required_evidence)),
            "narrowed_scope_json": (
                _dump(list(envelope.narrowed_scope))
                if envelope.narrowed_scope is not None else None
            ),
            "policy_set_hash": envelope.policy_set_hash,
            "hash_domain": ENVELOPE_HASH_DOMAIN,
            "envelope_hash": envelope.envelope_hash,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })

    def resolve(self, task_contract_id: str, *,
                expected_task_contract_hash: str,
                expected_policy_set_hash: str) -> dict | None:
        row = self.row_for_task_contract(task_contract_id)
        if row is None:
            return None
        envelope = envelope_from_row(row)
        if envelope.task_contract_hash != expected_task_contract_hash:
            raise PolicyStale("policy envelope no longer matches the task contract")
        if envelope.policy_set_hash != expected_policy_set_hash:
            raise PolicyStale("policy envelope no longer matches applicable policy")
        return envelope.as_dict()


__all__ = ["PolicyAuthority", "envelope_from_row"]
