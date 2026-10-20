"""Shared fixtures. Everything here is in-memory, deterministic and offline."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from cis.authority import MIGRATIONS_DIR, AuthorityStore
from cis.blueprint import load_blueprint
from cis.canonical import canonical_json
from cis.conductor import Conductor
from cis.workbench import Workbench

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / "contracts"
MANIFEST_PATH = ROOT / "blueprint" / "reconstruction_manifest.json"


def migration_ids() -> list[str]:
    """The migration ids on disk, in the order the store applies them.

    Derived rather than listed, so adding a migration cannot leave a count
    assertion silently describing an older schema.
    """
    return [path.stem for path in sorted(MIGRATIONS_DIR.glob("*.sql"))]


def authority_tables() -> set[str]:
    """Every authority table the migrations create, plus the ledger the store
    creates in code."""
    tables = {"schema_migrations"}
    for migration_id in migration_ids():
        body = (MIGRATIONS_DIR / f"{migration_id}.sql").read_text(encoding="utf-8")
        tables |= set(re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?(\w+)", body))
    return tables

#: The recorded continuity acceptance criterion, in Eric's own words
#: (dev_continuity_events revision 178). Used as the antecedent a vague memory
#: fragment must recover.
ANTECEDENT_VERBATIM = (
    "so the continuity of perspective you said I was supplying with semantic "
    "memories will be built into the pipeline and my questions wont keep "
    "sending us down rabbit holes causing important concepts to go dormant"
)

OBJECTIVE = (
    "Reconstruct the CIS Workbench trajectory projection in the clean environment"
)


def expected_module_count() -> int:
    """The selected-module count, DERIVED from the authoritative manifest.

    ADR-ARCH-002: record once, derive everywhere. A literal here would be a
    second record of a fact the blueprint already owns, and every addition
    would require editing it in nine places.
    """
    import json
    path = Path(__file__).resolve().parents[1] / "blueprint" / "reconstruction_manifest.json"
    with open(path, encoding="utf-8") as handle:
        return len(json.load(handle)["selected_modules"])


def blueprint():
    return load_blueprint(MANIFEST_PATH, CONTRACTS_DIR)


#: Alias so ``workbench(blueprint=...)`` can shadow the name as a keyword and
#: still reach the loader.
_default_blueprint = blueprint


def blueprint_without_canonical_basis(module_id: str = "cis.workbench.projection"):
    """A Blueprint whose named module carries no canonical evidence_basis.

    Built by constructing ``Blueprint`` directly, which deliberately bypasses
    ``load_blueprint``. The loader refuses such a manifest outright, so this is
    the only way to reach the second half of the fail-closed boundary: what the
    Workbench does if a module with no canonical authorization basis ever
    reaches it anyway.
    """
    from cis.blueprint import Blueprint
    loaded = blueprint()
    document = copy.deepcopy(dict(loaded.document))
    for entry in document["selected_modules"]:
        if entry["module_id"] == module_id:
            entry["evidence_basis"] = []
    return Blueprint(document=document, registry=loaded.registry,
                     manifest_hash=loaded.manifest_hash)


def fresh_store() -> AuthorityStore:
    return AuthorityStore(":memory:")


def workbench(*, with_evidence: bool = True, with_objective: bool = True,
              store: AuthorityStore | None = None, blueprint=None,
              **kwargs: Any) -> Workbench:
    wb = Workbench(store or fresh_store(),
                   blueprint=blueprint if blueprint is not None
                   else _default_blueprint(),
                   **kwargs)
    if with_objective:
        wb.set_initial_objective(OBJECTIVE)
    if with_evidence:
        seed_evidence(wb)
    return wb


def seed_evidence(wb: Workbench) -> None:
    wb.import_authoritative_evidence(
        evidence_id="evi-rev178",
        kind="user_instruction",
        source_ref="dev_continuity_events:WB.1:178",
        content=(
            "continuity acceptance criterion: questions and semantic memory "
            "fragments must recover and preserve prior intent rather than "
            "silently redirect development or allow concepts to go dormant"
        ),
        admission_basis="accepted:dev_continuity_events:WB.1:178",
        original_language=ANTECEDENT_VERBATIM,
    )
    wb.import_authoritative_evidence(
        evidence_id="evi-adr-arch-002",
        kind="project_decision",
        source_ref="project_decisions:ADR-ARCH-002",
        content=(
            "every fact has exactly one authoritative record and one owning "
            "module; a projection is derived from authority and never read back "
            "into it"
        ),
        admission_basis="accepted:project_decisions:ADR-ARCH-002",
    )
    wb.import_authoritative_evidence(
        evidence_id="evi-adr-arch-003",
        kind="project_decision",
        source_ref="project_decisions:ADR-ARCH-003",
        content=(
            "exactly one CIS-owned Layer-2 module family is the sole call path "
            "to any execution backend, and nothing above Layer 2 may name a "
            "backend or its ports, paths, configuration or log format"
        ),
        admission_basis="accepted:project_decisions:ADR-ARCH-003",
    )


def contract_document(module_id: str) -> dict:
    path = CONTRACTS_DIR / f"{module_id}.contract.json"
    return json.loads(path.read_text(encoding="utf-8"))


def minimal_contract(module_id: str = "cis.test.module", **overrides: Any) -> dict:
    """A valid 16-field contract, for mutation in negative tests."""
    document = {
        "module_id": module_id,
        "responsibility": "Does exactly one testable thing.",
        "layer": "L2",
        "owned_authority": [],
        "reads": ["nothing durable"],
        "writes": [],
        "mutation_interface": "none",
        "depends_on": [],
        "forbidden_dependencies": [],
        "trust_domain": "cis_clean_control_host",
        "execution_location": "in-process",
        "failure_boundary": "fail_closed on any invalid input",
        "recovery_behavior": "stateless, so a retry is identical",
        "replacement_contract": "any module exposing the same single call",
        "evidence_produced": ["a deterministic return value"],
        "verification": "python3 -m unittest tests.test_contracts",
    }
    document.update(overrides)
    return document


ALLOW_INSTRUCTION = "Reconstruct cis.workbench.projection in the clean environment"

#: The canonical accepted authority the manifest records for the target module.
#: An ALLOW must name exactly this, labeled as the canonical basis.
CANONICAL_REQUIRED_EVIDENCE = [
    "canonical_evidence_basis:cis.workbench.projection:handoff A18",
    "canonical_evidence_basis:cis.workbench.projection:"
    "ADR-ARCH-002 derivative clause",
]


def allow_outcome(wb=None):
    """A workbench plus one ALLOW authorization for a selected module."""
    wb = wb or workbench()
    outcome = wb.submit_instruction(ALLOW_INSTRUCTION)
    assert outcome.authorization["verdict"] == "ALLOW", outcome.authorization
    return wb, outcome


def conductor(wb=None) -> Conductor:
    return Conductor(wb or workbench())


def exercised_workbench():
    """A workbench whose authority has at least one row in every table.

    Driven through the Conductor, because ``conductor_envelopes`` is only
    seeded by the ingress boundary — the append-only suite would otherwise
    assert against an empty table and prove nothing about it.

    The slice-2 assurance tables are seeded the same way, and they need TWO
    task contracts to be seeded completely: a passing one never produces an
    ``objection_cycles`` row, and an objecting one never produces a
    ``PROMOTION_AUTHORIZED``. So one authorization is executed and assured to
    a pass, and a second — identical in scope, deliberately never executed —
    fails verification for missing evidence and draws one objection cycle.
    """
    wb = workbench()
    conduct = Conductor(wb)
    outcome = conduct.ingest_instruction(ALLOW_INSTRUCTION)
    assert outcome.authorization["verdict"] == "ALLOW", outcome.authorization
    run = conduct.execute_authorization(
        outcome.authorization["authorization_id"])
    passing_task_contract_id = assure(
        wb, outcome.authorization["authorization_id"])
    seed_policy_envelope(wb, passing_task_contract_id)
    seed_execution_input(wb, passing_task_contract_id)

    # Seed the slice-4 append-only host-handoff tables. Their behavioral path
    # is exercised through HostPromotionGate in test_host_promotion_gate; this
    # fixture supplies one referentially valid row so the generic trigger
    # proof cannot accidentally pass against an empty table.
    promotion_row = assurance_authority(wb).ledger.latest_promotion(
        passing_task_contract_id)
    application_id = "hpa-seed"
    wb.store.insert("host_promotion_plans", {
        "application_id": application_id,
        "task_contract_id": passing_task_contract_id,
        "promotion_decision_id": str(promotion_row["decision_id"]),
        "target_relative_path": "seed/target.candidate",
        "candidate_content": b"seed candidate\n",
        "candidate_sha256": "seed-candidate-sha256",
        "previous_present": 0,
        "previous_content": None,
        "previous_sha256": None,
        "plan_hash": "seed-plan-hash",
        "created_at": wb.store.now(),
        "seq": wb.store.next_seq(),
    })
    wb.store.insert("host_promotion_events", {
        "event_id": "hpe-seed-applied",
        "application_id": application_id,
        "event_type": "APPLIED",
        "observed_sha256": "seed-candidate-sha256",
        "event_hash": "seed-event-hash",
        "created_at": wb.store.now(),
        "seq": wb.store.next_seq(),
    })

    objecting = conduct.ingest_instruction(ALLOW_INSTRUCTION)
    assert objecting.authorization["verdict"] == "ALLOW", objecting.authorization
    objecting_task_contract_id = assure(
        wb, objecting.authorization["authorization_id"], cycles=1)

    # Seed Slice-6's append-only assessment authority. Its behavioral path is
    # tested with an authored-source execution input; this generic trigger
    # fixture needs only a referentially valid row so it cannot pass empty.
    cycle = wb.store.one(
        "SELECT * FROM objection_cycles WHERE task_contract_id = ?",
        (objecting_task_contract_id,))
    wb.store.insert("operational_assessments", {
        "assessment_id": "osa-seed",
        "task_contract_id": objecting_task_contract_id,
        "cycle_id": str(cycle["cycle_id"]),
        "review_id": str(cycle["review_id"]),
        "cycle_number": int(cycle["cycle_number"]),
        "disposition": "REPLACEMENT_CANDIDATE_REQUIRED",
        "failure_class": "CANDIDATE_OR_RESULT_FAILURE",
        "preserved_bindings_json": "{}",
        "permitted_changes_json": '["candidate_source"]',
        "required_checks_json": "[]",
        "source_facts_hash": "a" * 64,
        "hash_domain": "cis.assurance.operational_assessment.v1",
        "assessment_hash": "b" * 64,
        "created_at": wb.store.now(),
        "seq": wb.store.next_seq(),
    })

    # Seed Slice-6's append-only recovery-attempt authority. Its behavioral
    # path is tested with a fresh authored-source child; this generic trigger
    # fixture needs only a referentially valid row so it cannot pass empty.
    wb.store.insert("recovery_attempts", {
        "attempt_id": "rca-seed",
        "assessment_id": "osa-seed",
        "parent_task_contract_id": objecting_task_contract_id,
        "child_authorization_id": objecting.authorization["authorization_id"],
        "child_task_contract_id": passing_task_contract_id,
        "parent_execution_input_hash": "a" * 64,
        "child_execution_input_hash": "b" * 64,
        "candidate_sha256": "c" * 64,
        "generation": 1,
        "hash_domain": "cis.assurance.recovery_attempt.v1",
        "attempt_hash": "d" * 64,
        "created_at": wb.store.now(),
        "seq": wb.store.next_seq(),
    })

    # Seed Unit-7A worker-supervision authority for the generic append-only
    # trigger proof. Behavioral integrity is covered in test_worker_supervisor.
    supervision_id = "wsp-seed"
    wb.store.insert("worker_supervision_plans", {
        "supervision_id": supervision_id,
        "objective_id": objecting.authorization["objective_id"],
        "transaction_id": objecting.authorization["transaction_id"],
        "target_module_id": objecting.authorization["target_module_id"],
        "operation": objecting.authorization["scope"]["operation"],
        "routes_json": canonical_json([{
            "authorization_id": objecting.authorization["authorization_id"],
            "adapter_id": "deterministic_mock", "wall_time_ms": 1000,
            "token_limit": 1000, "cost_limit_micros": 1000,
        }]),
        "route_count": 1, "circuit_threshold": 1,
        "hash_domain": "cis.execution.worker_supervision.plan.v1",
        "plan_hash": "e" * 64,
        "created_at": wb.store.now(), "seq": wb.store.next_seq(),
    })
    wb.store.insert("worker_attempt_events", {
        "event_id": "wse-seed", "supervision_id": supervision_id,
        "route_index": 0,
        "authorization_id": objecting.authorization["authorization_id"],
        "adapter_id": "deterministic_mock", "event_type": "STARTED",
        "failure_class": None, "measured_wall_ms": None,
        "measured_tokens": None, "measured_cost_micros": None,
        "checkpoint_ref": None, "checkpoint_sha256": None,
        "run_id": None, "evidence_id": None,
        "hash_domain": "cis.execution.worker_supervision.event.v1",
        "event_hash": "f" * 64,
        "created_at": wb.store.now(), "seq": wb.store.next_seq(),
    })

    # Seed Unit-8A's three distinct append-only authorities in the same
    # generic fixture. A durable external session is not an execution attempt:
    # its header, issued model request and lifecycle fact remain separately
    # addressable even though this fixture anchors all three to the route
    # immediately above.
    wb.store.insert("worker_sessions", {
        "session_id": "wks-seed", "supervision_id": supervision_id,
        "route_index": 0,
        "objective_id": objecting.authorization["objective_id"],
        "transaction_id": objecting.authorization["transaction_id"],
        "target_module_id": objecting.authorization["target_module_id"],
        "operation": objecting.authorization["scope"]["operation"],
        "logical_role": "IMPLEMENTER", "adapter_id": "deterministic_mock",
        "hash_domain": "cis.execution.worker_session.header.v1",
        "session_hash": "1" * 64,
        "created_at": wb.store.now(), "seq": wb.store.next_seq(),
    })
    wb.store.insert("worker_model_requests", {
        "request_id": "wmr-seed", "session_id": "wks-seed",
        "supervision_id": supervision_id, "route_index": 0,
        "authorization_id": objecting.authorization["authorization_id"],
        "adapter_id": "deterministic_mock",
        "wall_time_ms": 1000, "token_limit": 1000,
        "cost_limit_micros": 1000,
        "prompt_sha256": "2" * 64, "context_sha256": "3" * 64,
        "response_schema_sha256": "4" * 64, "ordinal": 1,
        "hash_domain": "cis.execution.worker_session.request.v1",
        "request_hash": "5" * 64,
        "created_at": wb.store.now(), "seq": wb.store.next_seq(),
    })
    wb.store.insert("worker_session_events", {
        "event_id": "wkse-seed", "session_id": "wks-seed",
        "request_id": None, "event_type": "SESSION_OPENED",
        "external_session_ref": None, "checkpoint_ref": None,
        "checkpoint_sha256": None, "run_id": None, "evidence_id": None,
        "failure_class": None,
        "hash_domain": "cis.execution.worker_session.event.v1",
        "event_hash": "6" * 64,
        "created_at": wb.store.now(), "seq": wb.store.next_seq(),
    })

    # Recorded LAST, on purpose: a standing evidence conflict forces HOLD on
    # every later instruction, so seeding it earlier would stop the second
    # ALLOW this fixture needs from ever being issued.
    wb.evidence.record_conflict(
        conflict_id="cf-seed", subject="seeded for append-only proof",
        detail={"note": "recorded, never resolved in place"},
    )
    return wb, outcome, run


# ---------------------------------------------------------------------------
# Slice-2 assurance helpers
# ---------------------------------------------------------------------------

def compiler(wb):
    from cis.assurance.task_contract import TaskContractCompiler
    return TaskContractCompiler(authorizations=wb.authorizations,
                                blueprint=wb.blueprint)


def assurance_authority(wb):
    from cis.assurance.authority import AssuranceAuthority
    return AssuranceAuthority(wb.store)


def freeze_task_contract(wb, authorization_id, *,
                         template_id="reconstruct_module.v1",
                         allowed_paths=None):
    """Compile and freeze one task contract, returning the stored row."""
    compiled = compiler(wb).compile(
        authorization_id=authorization_id,
        template_id=template_id,
        allowed_paths=allowed_paths,
        active_objective_id=wb.continuity.active_objective_id(),
    )
    assurance_authority(wb).task_contracts.freeze(compiled)
    return compiled


def seed_policy_envelope(wb, task_contract_id):
    """Compile and append the minimal deterministic MASTER baseline."""
    from cis.policy.authority import PolicyAuthority
    from cis.policy.compiler import compile_envelope
    from cis.policy.schema import PolicySelector, PolicySet, parse_policy

    contract = assurance_authority(wb).ledger.require_task_contract(task_contract_id)
    master = parse_policy({
        "policy_id": "MASTER-CLEAN-BASELINE", "lineage_id": "clean-baseline",
        "kind": "MASTER", "version": 1, "status": "ACTIVE",
        "supersedes": None, "conflicts_with": [], "selector": None,
        "effect_kinds": ["PROHIBIT"],
        "prohibited_actions": ["network:any"], "required_checks": [],
        "required_evidence": [], "narrowed_scope": None, "hold": False,
        "rationale": "offline clean reconstruction baseline",
        "evidence_basis": ["ADR-ARCH-003"],
    })
    envelope = compile_envelope(
        PolicySet((master,)),
        selector=PolicySelector(
            project="cis", module=str(contract["target_module_id"]),
            operation="reconstruct_module", risk="HIGH"),
        task_contract_id=task_contract_id,
        task_contract_hash=str(contract["task_contract_hash"]),
    )
    PolicyAuthority(wb.store).append(envelope)
    # The generic append-only proof must exercise the source ledger as well as
    # the compiled-envelope ledger.  Use the real cumulative operational
    # catalog so the fixture proves the same admission path production uses.
    from cis.policy.source_catalog import ingest_source_catalog
    from cis.policy.sources import PolicySourceAuthority
    ingest_source_catalog(PolicySourceAuthority(wb.store))
    return envelope


def execution_input_authority(wb):
    from cis.assurance.execution_input import ExecutionInputAuthority
    return ExecutionInputAuthority(wb.store, assurance_authority(wb))


def seed_execution_input(wb, task_contract_id, **overrides):
    """Append one valid execution-input binding for ``task_contract_id``."""
    contract = assurance_authority(wb).ledger.require_task_contract(task_contract_id)
    candidate_source = b"def run():\n    return 1\n"
    vector_contract = canonical_json(
        [{"args": [1], "expect_value": 1}]).encode("utf-8")
    values = {
        "task_contract_id": task_contract_id,
        "candidate_source": candidate_source,
        "candidate_sha256": hashlib.sha256(candidate_source).hexdigest(),
        "vector_contract": vector_contract,
        "vector_contract_sha256": hashlib.sha256(vector_contract).hexdigest(),
        "authorized_entrypoint": "run",
        "task_contract_hash": str(contract["task_contract_hash"]),
        "authorization_binding_hash": str(contract["authorization_binding_hash"]),
        "worker_image": "sha256:" + "c" * 64,
        "expected_trusted_runner_sha256": "a" * 64,
        "expected_worker_sha256": "b" * 64,
    }
    values.update(overrides)
    return execution_input_authority(wb).append(**values)


def verifier(wb):
    from cis.assurance.verifier import Verifier
    return Verifier(wb.store, wb.blueprint)


def reviewer(wb):
    from cis.assurance.reviewer import Reviewer
    return Reviewer(wb.store, wb.blueprint)


def promotion(wb):
    from cis.assurance.promotion import PromotionRecorder
    return PromotionRecorder(wb.store)


def assurance_projection(wb):
    from cis.assurance.projection import AssuranceProjection
    return AssuranceProjection(store=wb.store, blueprint=wb.blueprint)


def assure(wb, authorization_id, *, cycles=0, promote=True):
    """Drive one authorization through the whole assurance increment.

    ``cycles`` is how many review cycles to run; 0 means "run reviews until
    one passes or the ledger refuses a further cycle", which is the ordinary
    path. A positive number runs exactly that many, which is what an
    objection-cycle test wants.
    """
    compiled = freeze_task_contract(wb, authorization_id)
    task_contract_id = compiled.task_contract_id
    verifier(wb).verify(task_contract_id)

    review = reviewer(wb)
    if cycles:
        for _ in range(cycles):
            review.review(task_contract_id)
    else:
        while True:
            result, cycle = review.review(task_contract_id)
            if cycle is None or review.escalated(task_contract_id):
                break
    if promote:
        promotion(wb).decide(task_contract_id)
    return task_contract_id


def allow_and_run(wb=None, instruction=ALLOW_INSTRUCTION):
    """A workbench with one executed ALLOW: the assurance increment's input."""
    wb = wb or workbench()
    outcome = wb.submit_instruction(instruction)
    assert outcome.authorization["verdict"] == "ALLOW", outcome.authorization
    authorization_id = outcome.authorization["authorization_id"]
    wb.execute(authorization_id)
    return wb, authorization_id
