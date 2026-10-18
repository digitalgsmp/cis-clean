"""Deterministic regeneration proof across every declared derived view.

The gate owns no authority and persists no projection.  It constructs fresh
projection objects twice, compares canonical hashes for every declared
surface, and proves that the complete authority digest is unchanged before,
between and after those reads.  A cold-start caller can compare the returned
``surface_set_hash`` before and after reopening the same authority database.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from ..assurance.projection import AssuranceProjection
from ..canonical import sha256_hex
from ..errors import ProjectionRegenerationRefused
from ..workbench.projection import TrajectoryProjection


DECLARED_SURFACES = (
    "blueprint.summary",
    "contracts.registry",
    "workbench.trajectory",
    "assurance.progress",
)

_SAFE_TABLE = re.compile(r"^[a-z][a-z0-9_]*$")


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(v) for v in value]
    return value


@dataclass(frozen=True)
class RegenerationProof:
    inventory: tuple[str, ...]
    surface_hashes: Mapping[str, str]
    surface_set_hash: str
    authority_digest: str
    proof_hash: str
    passes: int = 2
    authority_unchanged: bool = True
    byte_identical: bool = True

    def as_dict(self) -> dict:
        return {
            "inventory": list(self.inventory),
            "surface_hashes": dict(self.surface_hashes),
            "surface_set_hash": self.surface_set_hash,
            "authority_digest": self.authority_digest,
            "proof_hash": self.proof_hash,
            "passes": self.passes,
            "authority_unchanged": self.authority_unchanged,
            "byte_identical": self.byte_identical,
        }


class ProjectionRegenerationGate:
    """Fail-closed, read-only proof over all manifest-declared projections."""

    module_id = "cis.projection.regeneration_gate"

    def __init__(self, service: Any) -> None:
        self._service = service
        self._store = service.store
        self._blueprint = service.blueprint

    def _inventory(self) -> tuple[str, ...]:
        declared = tuple(
            str(item["surface_id"])
            for item in self._blueprint.projection_regeneration["surfaces"]
        )
        if declared != DECLARED_SURFACES:
            raise ProjectionRegenerationRefused(
                "projection inventory is incomplete, reordered, or unknown",
                declared=list(declared), required=list(DECLARED_SURFACES))
        return declared

    def _authority_digest(self) -> str:
        tables = [
            str(row["name"])
            for row in self._store.query(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name")
        ]
        if any(not _SAFE_TABLE.fullmatch(table) for table in tables):
            raise ProjectionRegenerationRefused(
                "authority contains a table name outside the safe vocabulary",
                tables=tables)
        content = {
            table: [row.as_dict() for row in self._store.query(
                f'SELECT * FROM "{table}" ORDER BY rowid')]
            for table in tables
        }
        return sha256_hex(content)

    def _fresh_surfaces(self) -> dict[str, Any]:
        service = self._service
        blueprint = self._blueprint
        trajectory = TrajectoryProjection(
            blueprint=blueprint,
            trajectory=service.trajectory,
            intent=service.intent,
            continuity=service.continuity,
            runs=service.runs,
            authorizations=service.authorizations,
        )
        assurance = AssuranceProjection(store=self._store, blueprint=blueprint)
        transaction_ids = [
            str(row["transaction_id"]) for row in service.intent.history()
        ]
        task_contract_ids = [
            str(row["task_contract_id"])
            for row in assurance.authority.ledger.task_contracts()
        ]
        return {
            "blueprint.summary": blueprint.as_summary(),
            "contracts.registry": {
                "registry_hash": blueprint.registry.registry_hash,
                "dependency_order": blueprint.registry.dependency_order(),
                "by_layer": blueprint.registry.by_layer(),
                "authority_owners": blueprint.registry.authority_owners(),
                "independence_pairs": blueprint.registry.independence_pairs(),
            },
            "workbench.trajectory": {
                "full": trajectory.full(),
                "micro_by_transaction": {
                    transaction_id: trajectory.micro(transaction_id)
                    for transaction_id in transaction_ids
                },
            },
            "assurance.progress": {
                "full": assurance.full(),
                "task_by_id": {
                    task_contract_id: assurance.task_contract(task_contract_id)
                    for task_contract_id in task_contract_ids
                },
            },
        }

    def prove(self) -> RegenerationProof:
        inventory = self._inventory()
        before = self._authority_digest()
        first = self._fresh_surfaces()
        middle = self._authority_digest()
        second = self._fresh_surfaces()
        after = self._authority_digest()

        if tuple(first) != inventory or tuple(second) != inventory:
            raise ProjectionRegenerationRefused(
                "a declared projection was not regenerated",
                declared=list(inventory), first=list(first), second=list(second))
        if before != middle or middle != after:
            raise ProjectionRegenerationRefused(
                "projection regeneration changed authority",
                before=before, middle=middle, after=after)

        first_hashes = {name: sha256_hex(_plain(first[name])) for name in inventory}
        second_hashes = {name: sha256_hex(_plain(second[name])) for name in inventory}
        if first_hashes != second_hashes:
            raise ProjectionRegenerationRefused(
                "two fresh regenerations from unchanged authority differ",
                first=first_hashes, second=second_hashes)

        surface_set_hash = sha256_hex(first_hashes)
        proof_hash = sha256_hex({
            "gate": self.module_id,
            "inventory": list(inventory),
            "surface_set_hash": surface_set_hash,
            "authority_digest": before,
            "passes": 2,
        })
        return RegenerationProof(
            inventory=inventory,
            surface_hashes=first_hashes,
            surface_set_hash=surface_set_hash,
            authority_digest=before,
            proof_hash=proof_hash,
        )
