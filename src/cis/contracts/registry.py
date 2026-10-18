"""Module-contract registry and validator.

ADR-ARCH-001 clause 3 freezes SIXTEEN required semantic fields. Clause 4
forbids collapsing evidence_produced into verification or recovery_behavior
into failure_boundary. Clause 5: exactly one module may own any given
authority, and an incomplete or malformed contract is refused BEFORE it is
recorded.

This module is the field-level validator ADR-ARCH-001 clause 7(b) requires:
it validates structured fields and never recovers an operational fact from
narrative prose (ADR-ARCH-002, derive-from-fields).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

from ..canonical import sha256_hex
from ..errors import ContractError

# ---------------------------------------------------------------------------
# Frozen schema
# ---------------------------------------------------------------------------

#: The exact sixteen semantic fields, in the order ADR-ARCH-001 clause 3 lists
#: them. Order is cosmetic; membership is enforced exactly.
REQUIRED_FIELDS: tuple[str, ...] = (
    "module_id",
    "responsibility",
    "layer",
    "owned_authority",
    "reads",
    "writes",
    "mutation_interface",
    "depends_on",
    "forbidden_dependencies",
    "trust_domain",
    "execution_location",
    "failure_boundary",
    "recovery_behavior",
    "replacement_contract",
    "evidence_produced",
    "verification",
)

#: Fields carried as a list of strings. An empty list is the machine encoding
#: of 'none' (ADR-ARCH-001 clause 3 permits 'none' for owned_authority).
_LIST_FIELDS = frozenset(
    {"owned_authority", "reads", "writes", "depends_on", "forbidden_dependencies",
     "evidence_produced"}
)

#: Fields carried as a non-empty string.
_TEXT_FIELDS = frozenset(
    {"module_id", "responsibility", "layer", "mutation_interface", "trust_domain",
     "execution_location", "failure_boundary", "recovery_behavior",
     "replacement_contract", "verification"}
)

LAYERS: tuple[str, ...] = ("L1", "L2", "L3")

#: Prefix a contract uses inside ``forbidden_dependencies`` to declare STRICT
#: MUTUAL INDEPENDENCE from another module, rather than the ordinary direct
#: "must not depend on" rule.
#:
#: An ordinary forbidden-dependency entry is a module id and is checked
#: DIRECTLY, because the sanctioned architecture is full of legitimate indirect
#: reach (L1 reaches authority through an L2 read model, and a transitive rule
#: would declare the accepted architecture illegal). Strict independence is the
#: opposite requirement and is needed exactly once: author-is-not-verifier.
#: A reviewer whose packet is assembled by the verifier it is reviewing is not
#: an independent reviewer, and an indirect path is enough to destroy that
#: independence, so this declaration is checked over the TRANSITIVE closure in
#: both directions and is required to be SYMMETRIC.
#:
#: The token is a structured field value, not prose: ``parse_contract`` refuses
#: a blank or malformed one and ``validate`` refuses an unknown or asymmetric
#: target. No decision in this module is recovered from narrative text.
INDEPENDENCE_PREFIX = "independence:"

#: failure_boundary must state fail_closed or fail_open explicitly
#: (ADR-ARCH-001 clause 3).
_FAILURE_TOKENS = ("fail_closed", "fail_open")


@dataclass(frozen=True)
class ModuleContract:
    """One module's frozen 16-field contract."""

    module_id: str
    responsibility: str
    layer: str
    owned_authority: tuple[str, ...]
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    mutation_interface: str
    depends_on: tuple[str, ...]
    forbidden_dependencies: tuple[str, ...]
    trust_domain: str
    execution_location: str
    failure_boundary: str
    recovery_behavior: str
    replacement_contract: str
    evidence_produced: tuple[str, ...]
    verification: str

    @property
    def independence_from(self) -> tuple[str, ...]:
        """Modules this contract declares STRICT MUTUAL INDEPENDENCE from.

        Derived from ``forbidden_dependencies``; there is no seventeenth field
        (ADR-ARCH-001 clause 3 freezes sixteen).
        """
        return tuple(
            entry[len(INDEPENDENCE_PREFIX):]
            for entry in self.forbidden_dependencies
            if entry.startswith(INDEPENDENCE_PREFIX)
        )

    @property
    def forbidden_modules(self) -> tuple[str, ...]:
        """The ordinary, directly-checked forbidden dependencies."""
        return tuple(
            entry for entry in self.forbidden_dependencies
            if not entry.startswith(INDEPENDENCE_PREFIX)
        )

    def as_dict(self) -> dict:
        out: dict = {}
        for name in REQUIRED_FIELDS:
            value = getattr(self, name)
            out[name] = list(value) if isinstance(value, tuple) else value
        return out

    @property
    def contract_hash(self) -> str:
        return sha256_hex(self.as_dict())


# ---------------------------------------------------------------------------
# Field-level validation
# ---------------------------------------------------------------------------

def _refuse(message: str, **detail: object) -> None:
    raise ContractError(message, **detail)


def parse_contract(raw: Mapping[str, object]) -> ModuleContract:
    """Validate one contract document and return it, or refuse.

    Refusal happens before the contract is recorded anywhere
    (ADR-ARCH-001 clause 5).
    """
    if not isinstance(raw, Mapping):
        _refuse("contract document is not an object", got=type(raw).__name__)

    present = set(raw)
    required = set(REQUIRED_FIELDS)

    missing = sorted(required - present)
    if missing:
        _refuse("contract is missing required field(s)", missing=missing,
                module_id=raw.get("module_id"))

    unexpected = sorted(present - required)
    if unexpected:
        _refuse("contract carries unexpected field(s)", unexpected=unexpected,
                module_id=raw.get("module_id"))

    for name in sorted(_TEXT_FIELDS):
        value = raw[name]
        if not isinstance(value, str) or not value.strip():
            _refuse(f"field '{name}' must be a non-empty string",
                    module_id=raw.get("module_id"), field=name)

    for name in sorted(_LIST_FIELDS):
        value = raw[name]
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item.strip() for item in value
        ):
            _refuse(f"field '{name}' must be a list of non-empty strings",
                    module_id=raw.get("module_id"), field=name)
        if len(set(value)) != len(value):
            _refuse(f"field '{name}' repeats an entry",
                    module_id=raw.get("module_id"), field=name)

    module_id = str(raw["module_id"])

    if raw["layer"] not in LAYERS:
        _refuse("layer must be one of L1, L2, L3 (ADR-SEED-018)",
                module_id=module_id, layer=raw["layer"])

    # One sentence: two responsibilities means two modules (clause 3).
    responsibility = str(raw["responsibility"]).strip()
    if responsibility.count(".") > 1 or (
        responsibility.endswith(".") and responsibility.count(".") > 1
    ):
        _refuse("responsibility must be exactly one sentence",
                module_id=module_id, responsibility=responsibility)

    failure_boundary = str(raw["failure_boundary"])
    if not any(token in failure_boundary for token in _FAILURE_TOKENS):
        _refuse("failure_boundary must state fail_closed or fail_open explicitly",
                module_id=module_id, failure_boundary=failure_boundary)

    # Clause 4 — fields do not collapse.
    if str(raw["recovery_behavior"]).strip() == failure_boundary.strip():
        _refuse("recovery_behavior must not duplicate failure_boundary "
                "(ADR-ARCH-001 clause 4)", module_id=module_id)
    if [str(raw["verification"]).strip()] == [s.strip() for s in raw["evidence_produced"]]:
        _refuse("evidence_produced must not collapse into verification "
                "(ADR-ARCH-001 clause 4)", module_id=module_id)

    # A module that writes authority must declare a sanctioned mutation path.
    writes = list(raw["writes"])
    mutation_interface = str(raw["mutation_interface"]).strip()
    if writes and mutation_interface == "none":
        _refuse("module declares writes but no mutation_interface "
                "(ADR-ARCH-001 clause 5)", module_id=module_id, writes=writes)

    # Authority it owns must be authority it declares it writes.
    owned = list(raw["owned_authority"])
    unwritten = sorted(set(owned) - set(writes))
    if unwritten:
        _refuse("owned_authority is not covered by writes",
                module_id=module_id, authority=unwritten)

    if module_id in set(raw["depends_on"]):
        _refuse("module depends on itself", module_id=module_id)

    # A strict-independence declaration must name something.
    for entry in raw["forbidden_dependencies"]:
        if not str(entry).startswith(INDEPENDENCE_PREFIX):
            continue
        target = str(entry)[len(INDEPENDENCE_PREFIX):].strip()
        if not target:
            _refuse("strict independence declaration names no module",
                    module_id=module_id, entry=entry)
        if target == module_id:
            _refuse("module declares strict independence from itself",
                    module_id=module_id)

    return ModuleContract(
        module_id=module_id,
        responsibility=responsibility,
        layer=str(raw["layer"]),
        owned_authority=tuple(owned),
        reads=tuple(raw["reads"]),
        writes=tuple(writes),
        mutation_interface=mutation_interface,
        depends_on=tuple(raw["depends_on"]),
        forbidden_dependencies=tuple(raw["forbidden_dependencies"]),
        trust_domain=str(raw["trust_domain"]),
        execution_location=str(raw["execution_location"]),
        failure_boundary=failure_boundary,
        recovery_behavior=str(raw["recovery_behavior"]),
        replacement_contract=str(raw["replacement_contract"]),
        evidence_produced=tuple(raw["evidence_produced"]),
        verification=str(raw["verification"]),
    )


# ---------------------------------------------------------------------------
# Registry-level invariants
# ---------------------------------------------------------------------------

@dataclass
class ContractRegistry:
    """The validated set of module contracts, plus the graph invariants.

    Registry-level rules enforced here:
      * duplicate module_id is refused (ids are stable and never reused);
      * one owner per authority (ADR-ARCH-001 clause 5);
      * every ``depends_on`` entry names a module that exists;
      * a declared forbidden dependency is never also a declared dependency;
      * no dependency cycle, so a deterministic dependency order exists;
      * nothing depends on an L1 module — the control surface is never a
        dependency (ADR-SEED-018);
      * no L1 module depends directly on an L3 module: L1 reaches execution
        infrastructure only through the L2 boundary (ADR-SEED-018 governing
        boundary rule, ADR-ARCH-003 clause 1);
      * no L3 module depends on an L2 module that owns authority — replaceable
        execution infrastructure never depends on an owner of CIS authority
        (ADR-ARCH-001 clause 8). An L3 adapter depending on the L2 execution
        CONTRACT is permitted and expected: that is what "held behind the
        CIS-owned Layer-2 boundary" means, and the contract module owns no
        authority.

    Forbidden-dependency enforcement is DIRECT, not transitive, on purpose.
    The sanctioned architecture is precisely "L1 reaches authority through an
    L2 read model", so a transitive-closure rule would declare the accepted
    architecture illegal.

    The one place a transitive rule IS correct is opted into explicitly, by a
    ``independence:<module_id>`` entry in ``forbidden_dependencies``. Such a
    pair must be declared by both sides and neither side may reach the other
    through any chain of dependencies. That is the registry-enforced form of
    author-is-not-verifier: ``cis.assurance.verifier`` and
    ``cis.assurance.reviewer`` declare it of each other, so a future edit that
    made the reviewer depend on the verifier — directly or through anything at
    all — would fail at contract load rather than at review time.
    """

    contracts: dict[str, ModuleContract] = field(default_factory=dict)

    # -- construction -------------------------------------------------------

    @classmethod
    def from_documents(cls, documents: Iterable[Mapping[str, object]]) -> "ContractRegistry":
        registry = cls()
        for document in documents:
            registry.add(parse_contract(document))
        registry.validate()
        return registry

    def add(self, contract: ModuleContract) -> None:
        if contract.module_id in self.contracts:
            _refuse("duplicate module_id", module_id=contract.module_id)
        owners = self.authority_owners()
        for authority in contract.owned_authority:
            if authority in owners:
                _refuse("duplicate authority ownership — exactly one module may "
                        "own an authority (ADR-ARCH-001 clause 5)",
                        authority=authority,
                        owners=[owners[authority], contract.module_id])
        self.contracts[contract.module_id] = contract

    # -- invariants ---------------------------------------------------------

    def authority_owners(self) -> dict[str, str]:
        owners: dict[str, str] = {}
        for contract in self.contracts.values():
            for authority in contract.owned_authority:
                owners[authority] = contract.module_id
        return owners

    def validate(self) -> None:
        known = set(self.contracts)
        for module_id, contract in sorted(self.contracts.items()):
            absent = sorted(set(contract.depends_on) - known)
            if absent:
                _refuse("depends_on names a module that is not in the registry",
                        module_id=module_id, absent=absent)

            violated = sorted(set(contract.depends_on) & set(contract.forbidden_modules))
            if violated:
                _refuse("forbidden dependency violation",
                        module_id=module_id, forbidden=violated)

            for dependency in sorted(contract.depends_on):
                dependency_contract = self.contracts[dependency]
                if dependency_contract.layer == "L1":
                    _refuse("nothing may depend on an L1 control-surface module "
                            "(ADR-SEED-018)",
                            module_id=module_id, dependency=dependency)
                if contract.layer == "L1" and dependency_contract.layer == "L3":
                    _refuse("L1 may not depend directly on L3; it reaches execution "
                            "infrastructure only through the L2 boundary",
                            module_id=module_id, dependency=dependency)
                if (contract.layer == "L3" and dependency_contract.layer == "L2"
                        and dependency_contract.owned_authority):
                    _refuse("L3 execution infrastructure may not depend on an L2 "
                            "module that owns CIS authority",
                            module_id=module_id, dependency=dependency,
                            owned_authority=list(dependency_contract.owned_authority))

        # A write to authority owned by another module is a contract violation
        # regardless of filesystem permission (ADR-ARCH-001 clause 5).
        owners = self.authority_owners()
        for module_id, contract in sorted(self.contracts.items()):
            for target in contract.writes:
                owner = owners.get(target)
                if owner is not None and owner != module_id:
                    _refuse("module writes authority owned by another module",
                            module_id=module_id, authority=target, owner=owner)

        self.dependency_order()  # refuses on a cycle
        self._validate_independence()

    # -- strict mutual independence ----------------------------------------

    def _validate_independence(self) -> None:
        """Enforce every declared strict-independence pair.

        Three refusals, all structural:

          * the named module must exist — an independence claim against a
            module that is not in the registry proves nothing;
          * the declaration must be SYMMETRIC — independence is a property of
            a pair, and a one-sided claim would let the other side quietly
            take a dependency that destroys it;
          * neither module may appear in the other's TRANSITIVE dependency
            closure — this is the registry-enforced separation that makes
            author-is-not-verifier a loadable fact instead of a promise.

        The rule runs after ``dependency_order``, so the closure is computed
        over a graph already known to be acyclic.
        """
        for module_id, contract in sorted(self.contracts.items()):
            for target in sorted(contract.independence_from):
                other = self.contracts.get(target)
                if other is None:
                    _refuse("strict independence names a module that is not in "
                            "the registry", module_id=module_id, independent_of=target)
                if module_id not in other.independence_from:
                    _refuse("strict independence must be declared by both "
                            "modules — a one-sided claim is not a separation",
                            module_id=module_id, independent_of=target)
                forward = self.transitive_dependencies(module_id)
                if target in forward:
                    _refuse("strict independence violated: the module reaches "
                            "the module it declares itself independent of",
                            module_id=module_id, independent_of=target,
                            via=sorted(forward & ({target} | set(other.depends_on))))
                backward = self.transitive_dependencies(target)
                if module_id in backward:
                    _refuse("strict independence violated: the module it "
                            "declares itself independent of reaches it",
                            module_id=module_id, independent_of=target,
                            via=sorted(backward & ({module_id} | set(contract.depends_on))))

    def transitive_dependencies(self, module_id: str) -> set[str]:
        """Every module reachable from ``module_id`` through ``depends_on``."""
        seen: set[str] = set()
        frontier = [module_id]
        while frontier:
            current = frontier.pop()
            for dependency in self.contracts[current].depends_on:
                if dependency in seen or dependency not in self.contracts:
                    continue
                seen.add(dependency)
                frontier.append(dependency)
        return seen

    def independence_pairs(self) -> list[list[str]]:
        """Every declared strict-independence pair, deduplicated and sorted."""
        pairs = {
            tuple(sorted((module_id, target)))
            for module_id, contract in self.contracts.items()
            for target in contract.independence_from
        }
        return [list(pair) for pair in sorted(pairs)]

    def dependency_order(self) -> list[str]:
        """Deterministic topological order: dependencies before dependents."""
        remaining = {
            module_id: set(contract.depends_on)
            for module_id, contract in self.contracts.items()
        }
        ordered: list[str] = []
        while remaining:
            ready = sorted(m for m, deps in remaining.items() if not deps - set(ordered))
            if not ready:
                _refuse("dependency cycle in module contracts",
                        unresolved=sorted(remaining))
            for module_id in ready:
                ordered.append(module_id)
                del remaining[module_id]
        return ordered

    # -- projections --------------------------------------------------------

    @property
    def registry_hash(self) -> str:
        return sha256_hex(
            {module_id: contract.as_dict() for module_id, contract in self.contracts.items()}
        )

    def by_layer(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {layer: [] for layer in LAYERS}
        for module_id, contract in sorted(self.contracts.items()):
            out[contract.layer].append(module_id)
        return out

    def get(self, module_id: str) -> ModuleContract:
        try:
            return self.contracts[module_id]
        except KeyError:
            _refuse("unknown module_id", module_id=module_id)
            raise  # unreachable


def load_registry(directory: str | Path) -> ContractRegistry:
    """Load every ``*.contract.json`` under ``directory``, in filename order."""
    path = Path(directory)
    if not path.is_dir():
        _refuse("contract directory does not exist", directory=str(path))
    documents: list[Mapping[str, object]] = []
    for file_path in sorted(path.glob("*.contract.json")):
        try:
            documents.append(json.loads(file_path.read_text(encoding="utf-8")))
        except json.JSONDecodeError as exc:
            _refuse("contract document is not valid JSON",
                    file=file_path.name, error=str(exc))
    if not documents:
        _refuse("contract directory contains no contracts", directory=str(path))
    return ContractRegistry.from_documents(documents)
