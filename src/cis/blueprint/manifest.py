"""The reconstruction blueprint, as operational input.

The manifest is not prose about the reconstruction: the application reads it to
decide which modules exist, which stage is current, and whether an instruction
targets anything the blueprint actually selected. A HOLD verdict can be caused
purely by this file.

The manifest is also the canonical EXECUTION AUTHORIZATION BASIS for this
slice. A selected-module entry carries the accepted authority that permits work
on that module (``evidence_basis``), and because the manifest bytes are inside
``baseline_hash`` the entry cannot drift from the authorization that cites it
without every prior authorization going stale. This is the only thing in the
slice that may permit execution on a module: nothing a request carries, and
nothing retrieval ranks, can substitute for it. ``canonical_authorization_basis``
returns ``None`` rather than a weak basis, and the loader refuses a selected
module whose ``evidence_basis`` is absent, empty or blank, so the fail-closed
boundary exists in both places.

Dependency order is deliberately NOT stored in the manifest. It is derived from
the contracts' ``depends_on`` by a deterministic topological sort, because a
literal order list here would be a second writable record of a fact the
contracts already own (ADR-ARCH-002). The manifest identifies the order by
naming its authority and its derivation; this loader refuses a manifest that
tries to carry the order itself.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..authority.trajectory import ASSURANCE_MICRO_STAGES, MICRO_STAGES
from ..canonical import sha256_hex, sha256_text
from ..contracts import ContractRegistry, load_registry
from ..errors import BlueprintError, EvidenceConflict

_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MANIFEST_PATH = _ROOT / "blueprint" / "reconstruction_manifest.json"
DEFAULT_CONTRACTS_DIR = _ROOT / "contracts"

STAGE_STATUSES = ("COMPLETE", "ACTIVE", "PARTIAL", "NOT_STARTED")

_RECONSTRUCTION_STATUSES = (
    "RECONSTRUCTED_IN_SLICE_001",
    "RECONSTRUCTED_IN_SLICE_002",
    "RECONSTRUCTED_IN_SLICE_003",
    "RECONSTRUCTED_IN_SLICE_004",
    "RECONSTRUCTED_IN_SLICE_005",
    "RECONSTRUCTED_IN_SLICE_006",
    "RECONSTRUCTED_IN_SLICE_006B2",
    "RECONSTRUCTED_IN_SLICE_007A",
    "RECONSTRUCTED_IN_SLICE_007B",
    "RECONSTRUCTED_IN_SLICE_007C",
    "RECONSTRUCTED_IN_SLICE_008A",
    "DEFERRED_NEXT_SLICE",
    "DEFERRED_NOT_AUTHORIZED",
)

#: The reconstruction statuses that put a module inside this environment's
#: execution scope. A later slice adds its own status rather than rewriting the
#: earlier one, so no slice-1 module's recorded status ever changes.
IN_SCOPE_RECONSTRUCTION_STATUSES = (
    "RECONSTRUCTED_IN_SLICE_001",
    "RECONSTRUCTED_IN_SLICE_002",
    "RECONSTRUCTED_IN_SLICE_003",
    "RECONSTRUCTED_IN_SLICE_004",
    "RECONSTRUCTED_IN_SLICE_005",
    "RECONSTRUCTED_IN_SLICE_006",
    "RECONSTRUCTED_IN_SLICE_006B2",
    "RECONSTRUCTED_IN_SLICE_007A",
    "RECONSTRUCTED_IN_SLICE_007B",
    "RECONSTRUCTED_IN_SLICE_007C",
    "RECONSTRUCTED_IN_SLICE_008A",
)

#: The closed status vocabulary of an A-O boundary-proof letter.
LETTER_PROVEN = "PROVEN_IN_THIS_INCREMENT"
LETTER_OUTSTANDING = "MANDATORY_OUTSTANDING"
_LETTER_STATUSES = (LETTER_PROVEN, LETTER_OUTSTANDING)

#: Exactly the fifteen letters the order reconciliation must account for.
ORDER_LETTERS: tuple[str, ...] = tuple("ABCDEFGHIJKLMNO")

#: The only acceptable value of ``order_reconciliation.waiver``. A manifest
#: that tries to waive a letter is refused at load, which is why no projection
#: has to decide whether a waiver is legitimate.
NO_WAIVER = "NONE — no A-O boundary proof is waived by this increment"


class _FrozenMapping(Mapping):
    """A hash of a mapping that refuses mutation but is still deep-copyable."""

    __slots__ = ("_data",)

    def __init__(self, data: dict[str, Any]) -> None:
        object.__setattr__(self, "_data", data)

    def __getattr__(self, name: str) -> Any:
        if name == "_data":
            return object.__getattribute__(self, "_data")
        raise AttributeError(name)

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __setitem__(self, key: str, value: Any) -> None:
        raise TypeError("'FrozenMapping' object does not support item assignment")

    def __delitem__(self, key: str) -> None:
        raise TypeError("'FrozenMapping' object does not support item deletion")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping):
            return dict(self) == dict(other)
        return NotImplemented

    __hash__ = None

    def __deepcopy__(self, memo: dict) -> dict:
        from copy import deepcopy as _deepcopy

        def _thaw(value):
            if isinstance(value, _FrozenMapping):
                return {_thaw(k): _thaw(v) for k, v in value._data.items()}
            if isinstance(value, _FrozenList):
                return [_thaw(v) for v in value]
            return _deepcopy(value, memo)

        return _thaw(self)


class _FrozenList(tuple):
    """Immutable list with a deep-copy path back to a plain mutable list."""

    def __setitem__(self, index: int, value: Any) -> None:
        raise TypeError("'FrozenList' object does not support item assignment")

    def __delitem__(self, index: int) -> None:
        raise TypeError("'FrozenList' object does not support item deletion")

    def append(self, value: Any) -> None:
        raise AttributeError("'FrozenList' object has no attribute 'append'")

    def pop(self, index: int = -1) -> Any:
        raise AttributeError("'FrozenList' object has no attribute 'pop'")

    def extend(self, values: Any) -> None:
        raise AttributeError("'FrozenList' object has no attribute 'extend'")

    def insert(self, index: int, value: Any) -> None:
        raise AttributeError("'FrozenList' object has no attribute 'insert'")

    def remove(self, value: Any) -> None:
        raise AttributeError("'FrozenList' object has no attribute 'remove'")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (list, tuple)):
            return len(self) == len(other) and all(a == b for a, b in zip(self, other))
        return NotImplemented

    __hash__ = None

    def __deepcopy__(self, memo: dict) -> list:
        from copy import deepcopy as _deepcopy
        return [_deepcopy(v, memo) for v in self]


def _deepfreeze(value: Any) -> Any:
    """Return a deeply immutable view of the parsed manifest document.

    dicts become ``_FrozenMapping``, lists become ``_FrozenList``, recursively.
    Accessor results keep the same frozen type, so canonical state cannot drift.
    """
    if isinstance(value, dict):
        return _FrozenMapping({k: _deepfreeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return _FrozenList(_deepfreeze(v) for v in value)
    return value


_REQUIRED_TOP_LEVEL = (
    "schema_version", "blueprint_id", "title", "clean_environment",
    "reference_environment", "dependency_order", "macro", "destination",
    "slice", "proven_slice", "assurance_slice", "assurance_increment",
    "projection_regeneration",
    "selected_modules", "deferred_modules", "preserved_capabilities",
    "acceptance_criteria",
)


#: Names the one kind of canonical execution-authorization basis this slice
#: recognises. It is a validated manifest fact bound into ``baseline_hash`` —
#: not a retrieval result, not token overlap, not anything a request supplies.
CANONICAL_BASIS_KIND = "VALIDATED_RECONSTRUCTION_MANIFEST_MODULE_EVIDENCE_BASIS"


@dataclass(frozen=True)
class CanonicalBasis:
    """The accepted authority under which work on one module may be authorized.

    Every field is read from the validated manifest and the contract registry.
    The object carries no scores, no matched terms and no antecedent ids,
    because none of those are authority (ADR-ARCH-002): an evidence record does
    not become authority by being retrieved, ranked highly or cited.
    """

    module_id: str
    reconstruction_status: str
    contract_ref: str
    evidence_basis: tuple[str, ...]
    manifest_hash: str
    baseline_hash: str
    basis_kind: str = CANONICAL_BASIS_KIND

    @property
    def authority_source(self) -> str:
        return (
            "blueprint/reconstruction_manifest.json::selected_modules"
            f"[{self.module_id}].evidence_basis"
        )

    @property
    def required_evidence(self) -> list[str]:
        """The ``required_evidence`` an authorization for this module carries.

        Each entry names an accepted authority reference and labels it as the
        canonical basis, so a reader of a recorded ALLOW can never mistake it
        for a retrieved antecedent id.
        """
        return [
            f"canonical_evidence_basis:{self.module_id}:{ref}"
            for ref in self.evidence_basis
        ]

    def as_dict(self) -> dict:
        return {
            "basis_kind": self.basis_kind,
            "authority_source": self.authority_source,
            "module_id": self.module_id,
            "reconstruction_status": self.reconstruction_status,
            "contract": self.contract_ref,
            "evidence_basis": list(self.evidence_basis),
            "required_evidence": self.required_evidence,
            "bound_into": {
                "manifest_hash": self.manifest_hash,
                "baseline_hash": self.baseline_hash,
            },
        }


@dataclass(frozen=True)
class Blueprint:
    """Validated blueprint plus the contract registry it selects."""

    document: Mapping[str, Any]
    registry: ContractRegistry
    manifest_hash: str

    def __post_init__(self) -> None:
        # Always store a deeply frozen document so canonical state cannot be
        # mutated after loading, regardless of whether a caller used the loader
        # or constructed a Blueprint directly.
        object.__setattr__(self, "document", _deepfreeze(self.document))

    # -- macro --------------------------------------------------------------

    @property
    def current_stage(self) -> str:
        return str(self.document["macro"]["current_stage"])

    @property
    def stages(self) -> tuple[Mapping[str, Any], ...]:
        return self.document["macro"]["stages"]

    @property
    def destination(self) -> Mapping[str, Any]:
        return self.document["destination"]

    @property
    def proven_slice(self) -> Mapping[str, Any]:
        """The slice-1 proven path. Its meaning and its counts are unchanged
        by the assurance increment, which has its own section below."""
        return self.document["proven_slice"]

    @property
    def assurance_slice(self) -> Mapping[str, Any]:
        return self.document["assurance_slice"]

    @property
    def assurance_increment(self) -> Mapping[str, Any]:
        return self.document["assurance_increment"]

    @property
    def order_reconciliation(self) -> Mapping[str, Any]:
        return self.document["assurance_increment"]["order_reconciliation"]

    @property
    def projection_regeneration(self) -> Mapping[str, Any]:
        return self.document["projection_regeneration"]

    def order_letters(self, status: str | None = None) -> list[str]:
        """The A-O letters, optionally filtered to one declared status."""
        return [
            str(entry["letter"])
            for entry in self.order_reconciliation["letters"]
            if status is None or str(entry["status"]) == status
        ]

    def stage(self, stage_id: str) -> Mapping[str, Any]:
        for stage in self.stages:
            if stage["stage_id"] == stage_id:
                return stage
        raise BlueprintError("unknown macro stage", stage_id=stage_id)

    # -- modules ------------------------------------------------------------

    @property
    def selected_modules(self) -> tuple[Mapping[str, Any], ...]:
        return self.document["selected_modules"]

    @property
    def selected_module_ids(self) -> list[str]:
        return [str(entry["module_id"]) for entry in self.document["selected_modules"]]

    def module(self, module_id: str) -> dict:
        for entry in self.selected_modules:
            if entry["module_id"] == module_id:
                return entry
        raise BlueprintError("module is not selected by the blueprint",
                             module_id=module_id)

    def is_selected(self, module_id: str) -> bool:
        return module_id in set(self.selected_module_ids)

    def dependency_order(self) -> list[str]:
        """Derived, never stored. Dependencies before dependents."""
        return self.registry.dependency_order()

    def reconstruction_status(self, module_id: str) -> str:
        return str(self.module(module_id)["reconstruction_status"])

    def evidence_basis(self, module_id: str) -> list[str]:
        return [str(ref) for ref in self.module(module_id)["evidence_basis"]]

    def canonical_authorization_basis(self, module_id: str) -> CanonicalBasis | None:
        """The canonical authority permitting work on ``module_id``, or ``None``.

        ``None`` is the fail-closed answer and the only alternative to a basis:
        there is no partial, inferred or overlap-derived basis. A module that is
        not selected, has no contract, or carries no non-blank evidence_basis
        has no canonical authorization basis, and no amount of surrounding
        conversation can create one.

        ``reconstruction_status`` is reported, not judged, here — whether a
        status is in scope for this slice is the Workbench's policy call and
        carries its own distinct reason code.
        """
        if not self.is_selected(module_id):
            return None
        if module_id not in self.registry.contracts:
            return None
        entry = self.module(module_id)
        refs = tuple(
            str(ref).strip()
            for ref in (entry.get("evidence_basis") or [])
            if isinstance(ref, str) and str(ref).strip()
        )
        if not refs:
            return None
        return CanonicalBasis(
            module_id=module_id,
            reconstruction_status=str(entry["reconstruction_status"]),
            contract_ref=str(entry["contract"]),
            evidence_basis=refs,
            manifest_hash=self.manifest_hash,
            baseline_hash=self.baseline_hash,
        )

    # -- baseline -----------------------------------------------------------

    @property
    def baseline_hash(self) -> str:
        """The reconstruction baseline an authorization is issued against.

        Covers the blueprint document and every module contract. If either
        changes, authorizations issued before the change are stale by
        definition and fail closed.
        """
        return sha256_hex({
            "manifest_hash": self.manifest_hash,
            "contract_registry_hash": self.registry.registry_hash,
        })

    # -- projection ---------------------------------------------------------

    def as_summary(self) -> dict:
        order = self.dependency_order()
        return {
            "blueprint_id": self.document["blueprint_id"],
            "title": self.document["title"],
            "schema_version": self.document["schema_version"],
            "manifest_hash": self.manifest_hash,
            "contract_registry_hash": self.registry.registry_hash,
            "baseline_hash": self.baseline_hash,
            "current_stage": self.current_stage,
            "stages": [dict(stage) for stage in self.stages],
            "dependency_order": order,
            "dependency_order_derivation": dict(self.document["dependency_order"]),
            "selected_modules": [
                {
                    "module_id": entry["module_id"],
                    "reconstruction_status": entry["reconstruction_status"],
                    "capability": entry["capability"],
                    "evidence_basis": entry["evidence_basis"],
                    "layer": self.registry.get(str(entry["module_id"])).layer,
                    "dependency_position": order.index(str(entry["module_id"])),
                }
                for entry in self.selected_modules
            ],
            "deferred_modules": [dict(entry) for entry in self.document["deferred_modules"]],
            "acceptance_criteria": list(self.document["acceptance_criteria"]),
            # The assurance increment's identity and its A-O reconciliation
            # travel with the blueprint summary, because an operator reading
            # what this environment claims must see what it does NOT claim in
            # the same place.
            "assurance_increment": {
                "increment_id": str(self.assurance_increment["increment_id"]),
                "title": str(self.assurance_increment["title"]),
                "order_letters_proven": self.order_letters(LETTER_PROVEN),
                "order_letters_outstanding": self.order_letters(LETTER_OUTSTANDING),
                "waiver": str(self.order_reconciliation["waiver"]),
                "gated_capability": str(
                    self.order_reconciliation["gated_capability"]),
            },
        }


# ---------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------

def _refuse(message: str, **detail: object) -> None:
    raise BlueprintError(message, **detail)


def _validate_assurance_slice(document: dict, selected_id_set: set[str]) -> None:
    """The assurance increment's own proven-path section.

    Validated exactly as strictly as ``proven_slice``, and kept entirely
    separate from it: a link here must name an ASSURANCE micro stage, so an
    assurance link can never be mistaken for a slice-1 link or counted in the
    slice-1 denominator.
    """
    section = document["assurance_slice"]
    for field in ("increment_id", "statement"):
        if not isinstance(section.get(field), str) or not section[field].strip():
            _refuse("assurance_slice is missing required content", field=field)
    links = section.get("links")
    if not isinstance(links, list) or not links:
        _refuse("assurance_slice carries no links")
    link_ids = [link.get("link_id") for link in links]
    if any(not isinstance(i, str) or not i.strip() for i in link_ids):
        _refuse("assurance_slice contains a blank link_id")
    if len(set(link_ids)) != len(link_ids):
        _refuse("assurance_slice contains duplicate link_id", link_ids=link_ids)
    assurance_stages = set(ASSURANCE_MICRO_STAGES)
    for link in links:
        for field in ("plain_language", "trajectory_stage"):
            if not isinstance(link.get(field), str) or not link[field].strip():
                _refuse("assurance_slice link is missing required content",
                        link_id=link.get("link_id"), field=field)
        stage = str(link["trajectory_stage"]).strip()
        if stage not in assurance_stages:
            _refuse("assurance_slice link trajectory_stage is not a declared "
                    "assurance stage", link_id=link.get("link_id"),
                    trajectory_stage=stage,
                    declared_stages=sorted(assurance_stages))
        carried_by = link.get("carried_by")
        if not isinstance(carried_by, list) or not carried_by:
            _refuse("assurance_slice link carries no module",
                    link_id=link["link_id"])
        unknown = sorted(
            m for m in carried_by
            if not isinstance(m, str) or not m.strip() or m not in selected_id_set
        )
        if unknown:
            raise EvidenceConflict(
                "assurance_slice link carried_by names a module the blueprint "
                "does not select",
                link_id=link.get("link_id"), carried_by=unknown,
            )


def _validate_order_reconciliation(document: dict, selected_id_set: set[str],
                                   deferred_ids: set[str]) -> None:
    """The A-O reconciliation. Refuses anything that would soften it.

    Five refusals:

      * the letters must be exactly A through O, each once — a reconciliation
        that silently omits a letter is how an unproven boundary disappears;
      * every status must be in the closed vocabulary;
      * a PROVEN letter must name selected modules that carry it, and an
        OUTSTANDING letter must name the deferred capability it gates, so no
        letter can be proven by nothing or deferred to nowhere;
      * the waiver field must be exactly ``NO_WAIVER``, so a waiver cannot be
        loaded at all and no reader has to adjudicate one;
      * while any letter is outstanding the gated capability must be a
        declared deferred module; once every letter is proven it must be null.
    """
    increment = document["assurance_increment"]
    for field in ("increment_id", "title"):
        if not isinstance(increment.get(field), str) or not increment[field].strip():
            _refuse("assurance_increment is missing required content", field=field)
    for field in ("host_independence", "review_cycle_semantics",
                  "order_reconciliation"):
        if not isinstance(increment.get(field), dict):
            _refuse("assurance_increment is missing a required section",
                    field=field)

    order = increment["order_reconciliation"]
    if order.get("waiver") != NO_WAIVER:
        _refuse("the order reconciliation must state that no A-O boundary "
                "proof is waived; a manifest carrying any other waiver value "
                "is refused at load",
                waiver=order.get("waiver"), required=NO_WAIVER)

    letters = order.get("letters")
    if not isinstance(letters, list):
        _refuse("the order reconciliation carries no letters")
    seen = [str(entry.get("letter")) for entry in letters]
    if seen != list(ORDER_LETTERS):
        _refuse("the order reconciliation must account for exactly the "
                "letters A through O, in order, each once",
                letters=seen, required=list(ORDER_LETTERS))

    outstanding = [entry for entry in letters
                   if entry.get("status") == LETTER_OUTSTANDING]
    gated = order.get("gated_capability")
    if outstanding:
        if not isinstance(gated, str) or gated not in deferred_ids:
            raise EvidenceConflict(
                "the order reconciliation gates a capability the manifest "
                "does not declare as deferred",
                gated_capability=gated, deferred_modules=sorted(deferred_ids),
            )
    elif gated is not None:
        _refuse("a fully proven A-O reconciliation must not retain a gated "
                "capability", gated_capability=gated)

    for entry in letters:
        letter = str(entry["letter"])
        if not isinstance(entry.get("label"), str) or not entry["label"].strip():
            _refuse("order letter carries no label", letter=letter)
        status = entry.get("status")
        if status not in _LETTER_STATUSES:
            _refuse("unknown order letter status", letter=letter,
                    status=status, known=list(_LETTER_STATUSES))
        if status == LETTER_PROVEN:
            carried_by = entry.get("carried_by")
            if not isinstance(carried_by, list) or not carried_by:
                _refuse("a proven order letter must name the modules that "
                        "carry it", letter=letter)
            unknown = sorted(
                m for m in carried_by
                if not isinstance(m, str) or m not in selected_id_set
            )
            if unknown:
                raise EvidenceConflict(
                    "a proven order letter is carried by a module the "
                    "blueprint does not select",
                    letter=letter, carried_by=unknown,
                )
        else:
            gated_by = entry.get("gated_by")
            if not isinstance(gated_by, str) or gated_by not in deferred_ids:
                raise EvidenceConflict(
                    "an outstanding order letter must be gated by a declared "
                    "deferred capability",
                    letter=letter, gated_by=entry.get("gated_by"),
                    deferred_modules=sorted(deferred_ids),
                )

    declared_proven = order.get("statuses")
    if list(declared_proven or []) != list(_LETTER_STATUSES):
        _refuse("the order reconciliation must declare exactly the closed "
                "status vocabulary it uses",
                statuses=declared_proven, required=list(_LETTER_STATUSES))


def _validate_projection_regeneration(document: dict,
                                      selected_id_set: set[str]) -> None:
    """Refuse an incomplete or self-asserted projection inventory."""
    section = document["projection_regeneration"]
    if section.get("gate_module") != "cis.projection.regeneration_gate":
        _refuse("projection regeneration names an unknown gate module",
                gate_module=section.get("gate_module"))
    if section["gate_module"] not in selected_id_set:
        raise EvidenceConflict(
            "projection regeneration gate is not selected",
            gate_module=section["gate_module"])
    surfaces = section.get("surfaces")
    if not isinstance(surfaces, list) or not surfaces:
        _refuse("projection regeneration carries no surface inventory")
    required_ids = [
        "blueprint.summary", "contracts.registry",
        "workbench.trajectory", "assurance.progress",
    ]
    surface_ids = [item.get("surface_id") for item in surfaces]
    if surface_ids != required_ids:
        _refuse("projection regeneration inventory must be complete and ordered",
                surfaces=surface_ids, required=required_ids)
    for item in surfaces:
        module_id = item.get("module_id")
        if module_id not in selected_id_set:
            raise EvidenceConflict(
                "projection surface is carried by an unselected module",
                surface_id=item.get("surface_id"), module_id=module_id)
        inputs = item.get("authority_inputs")
        if (not isinstance(inputs, list) or not inputs
                or not all(isinstance(value, str) and value.strip()
                           for value in inputs)):
            _refuse("projection surface carries no authority inputs",
                    surface_id=item.get("surface_id"))
    generated = set(document["preserved_capabilities"]["generated_projections"])
    inventory_modules = {str(item["module_id"]) for item in surfaces}
    if not generated.issubset(inventory_modules):
        raise EvidenceConflict(
            "a generated projection is absent from the regeneration inventory",
            missing=sorted(generated - inventory_modules))


def load_blueprint(manifest_path: str | Path | None = None,
                   contracts_dir: str | Path | None = None) -> Blueprint:
    path = Path(manifest_path) if manifest_path else DEFAULT_MANIFEST_PATH
    if not path.is_file():
        _refuse("manifest not found", path=str(path))
    raw_text = path.read_text(encoding="utf-8")
    try:
        document = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        _refuse("manifest is not valid JSON", path=str(path), error=str(exc))

    missing = sorted(set(_REQUIRED_TOP_LEVEL) - set(document))
    if missing:
        _refuse("manifest is missing required section(s)", missing=missing)

    dependency_order = document["dependency_order"]
    if dependency_order.get("representation") != "DERIVED":
        _refuse("dependency order must be DERIVED from the contracts",
                representation=dependency_order.get("representation"))
    if any(isinstance(value, list) for value in dependency_order.values()):
        _refuse("manifest must not carry a literal dependency order — the "
                "contracts own it (ADR-ARCH-002)")

    macro = document["macro"]
    stage_ids = [stage["stage_id"] for stage in macro["stages"]]
    if len(set(stage_ids)) != len(stage_ids):
        _refuse("duplicate macro stage_id", stage_ids=stage_ids)
    for stage in macro["stages"]:
        if stage["status"] not in STAGE_STATUSES:
            _refuse("unknown macro stage status", stage_id=stage["stage_id"],
                    status=stage["status"])
        if not stage.get("evidence_basis"):
            _refuse("macro stage carries no evidence basis",
                    stage_id=stage["stage_id"])
        if not isinstance(stage.get("plain_language"), str) or not stage["plain_language"].strip():
            _refuse("macro stage carries no plain-language meaning",
                    stage_id=stage["stage_id"])
    if macro["current_stage"] not in stage_ids:
        _refuse("current_stage is not one of the declared stages",
                current_stage=macro["current_stage"])
    active = [s["stage_id"] for s in macro["stages"] if s["status"] == "ACTIVE"]
    if active != [macro["current_stage"]]:
        raise EvidenceConflict(
            "exactly one stage must be ACTIVE and it must be current_stage",
            current_stage=macro["current_stage"], active=active,
        )

    destination = document["destination"]
    if not isinstance(destination.get("statement"), str) or not destination["statement"].strip():
        _refuse("destination carries no plain-language statement")
    flow = destination.get("flow")
    if not isinstance(flow, list) or not flow:
        _refuse("destination carries no ordered flow")
    flow_ids = [step.get("step_id") for step in flow]
    if any(not isinstance(step_id, str) or not step_id.strip() for step_id in flow_ids):
        _refuse("destination flow contains a blank step_id")
    if len(set(flow_ids)) != len(flow_ids):
        _refuse("destination flow contains duplicate step_id", step_ids=flow_ids)
    capabilities = document["preserved_capabilities"]
    direct_capabilities = set(capabilities) - {"comment", "deferred_to_a_later_slice"}
    deferred_capabilities = set(capabilities.get("deferred_to_a_later_slice", {}))
    known_capabilities = direct_capabilities | deferred_capabilities
    for step in flow:
        for field in ("plain_language", "question_it_answers"):
            if not isinstance(step.get(field), str) or not step[field].strip():
                _refuse("destination flow step is missing plain-language content",
                        step_id=step.get("step_id"), field=field)
        refs = step.get("capabilities")
        if not isinstance(refs, list) or not refs:
            _refuse("destination flow step carries no capability",
                    step_id=step["step_id"])
        unknown = sorted(set(refs) - known_capabilities)
        if unknown:
            _refuse("destination flow cites an unknown preserved capability",
                    step_id=step["step_id"], capabilities=unknown)

    selected_ids = [str(entry["module_id"]) for entry in document["selected_modules"]]
    if len(set(selected_ids)) != len(selected_ids):
        _refuse("duplicate module_id in selected_modules", module_ids=selected_ids)
    selected_id_set = set(selected_ids)

    # proven_slice links are authority about what this slice has actually
    # driven end to end, so each link must name a trajectory stage the
    # micro sequence declares and modules the blueprint actually selects.
    # Otherwise a link could claim a proven path through something that does
    # not exist, and the projection would read it as achievable.
    links = document["proven_slice"].get("links")
    if not isinstance(links, list) or not links:
        _refuse("proven_slice carries no links")
    link_ids = [link.get("link_id") for link in links]
    if any(not isinstance(link_id, str) or not link_id.strip() for link_id in link_ids):
        _refuse("proven_slice contains a blank link_id")
    if len(set(link_ids)) != len(link_ids):
        _refuse("proven_slice contains duplicate link_id", link_ids=link_ids)
    micro_stage_set = set(MICRO_STAGES)
    for link in links:
        for field in ("plain_language", "trajectory_stage"):
            if not isinstance(link.get(field), str) or not link[field].strip():
                _refuse("proven_slice link is missing required content",
                        link_id=link.get("link_id"), field=field)
        trajectory_stage = str(link["trajectory_stage"]).strip()
        if trajectory_stage not in micro_stage_set:
            _refuse("proven_slice link trajectory_stage is not a declared stage",
                    link_id=link.get("link_id"), trajectory_stage=trajectory_stage,
                    declared_stages=sorted(micro_stage_set))
        carried_by = link.get("carried_by")
        if not isinstance(carried_by, list) or not carried_by:
            _refuse("proven_slice link carries no module",
                    link_id=link["link_id"])
        unknown_carriers = sorted(
            m for m in carried_by
            if not isinstance(m, str) or not m.strip() or m not in selected_id_set
        )
        if unknown_carriers:
            raise EvidenceConflict(
                "proven_slice link carried_by names a module the blueprint does not select",
                link_id=link.get("link_id"),
                carried_by=unknown_carriers,
                selected_modules=sorted(selected_id_set),
            )

    deferred_ids = {
        str(entry.get("module_id")) for entry in document["deferred_modules"]
    }
    _validate_assurance_slice(document, selected_id_set)
    _validate_order_reconciliation(document, selected_id_set, deferred_ids)
    _validate_projection_regeneration(document, selected_id_set)

    registry = load_registry(contracts_dir or DEFAULT_CONTRACTS_DIR)

    for entry in document["selected_modules"]:
        module_id = str(entry["module_id"])
        for field in ("contract", "reconstruction_status", "capability", "evidence_basis"):
            if not entry.get(field):
                _refuse("selected module is missing a required manifest field",
                        module_id=module_id, field=field)
        if entry["reconstruction_status"] not in _RECONSTRUCTION_STATUSES:
            _refuse("unknown reconstruction_status", module_id=module_id,
                    reconstruction_status=entry["reconstruction_status"])
        # The evidence_basis of a selected module IS the canonical execution
        # authorization basis for that module, so an absent, empty, non-list or
        # blank-only basis is refused here rather than silently producing a
        # module that nothing can ever be authorized against.
        basis = entry.get("evidence_basis")
        if (not isinstance(basis, list) or not basis
                or not all(isinstance(ref, str) and ref.strip() for ref in basis)):
            _refuse("selected module carries no canonical evidence_basis, so "
                    "the manifest cannot be the authorization basis for it",
                    module_id=module_id, evidence_basis=basis)
        if module_id not in registry.contracts:
            raise EvidenceConflict(
                "blueprint selects a module that has no contract",
                module_id=module_id,
            )

    unselected = sorted(set(registry.contracts) - set(selected_ids))
    if unselected:
        raise EvidenceConflict(
            "a contract exists for a module the blueprint does not select",
            module_ids=unselected,
        )

    for entry in document["deferred_modules"]:
        if entry["reconstruction_status"] not in _RECONSTRUCTION_STATUSES:
            _refuse("unknown reconstruction_status in deferred_modules",
                    module_id=entry.get("module_id"))
        if str(entry["module_id"]) in registry.contracts:
            raise EvidenceConflict(
                "a module is both deferred and contracted",
                module_id=entry["module_id"],
            )

    return Blueprint(
        document=document,
        registry=registry,
        manifest_hash=sha256_text(raw_text),
    )
