#!/usr/bin/env python3
"""Worker-supervision proof: real timeout-then-fallback through contained_worker.

This card drives the two-route ``WorkerSupervisorAuthority`` plan
``build_scenario`` assembles -- a fast-budget route bound to an authored
source that never returns, and a generous-budget fallback route bound to a
valid authored source -- through ``SupervisedExecutionCoordinator`` and the
real Layer-2 gateway. It proves the timed-out route's deterministic container
name is read-only provably absent, independently re-verifies the fallback
route's recorded run and evidence, carries its task contract through the
verifier/reviewer/promotion conjunction, proves a replayed coordinator run
changes nothing durable, and writes the signed proof artifact.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, NamedTuple

from cis.assurance.promotion import PromotionRecorder
from cis.assurance.reviewer import Reviewer
from cis.assurance.verifier import Verifier
from cis.authority import AuthorityStore, Row
from cis.canonical import sha256_hex, sha256_text
from cis.conductor import Conductor
from cis.execution import ExecutionBudget
from cis.execution.worker_supervisor import (
    SupervisedExecutionCoordinator, WorkerSupervisorAuthority, event_payload,
)
from cis.workbench import Workbench


INSTRUCTION = "Verify authored source for cis.workbench.projection"
OBJECTIVE = "Prove bounded worker supervision across contained_worker routes"
ENTRYPOINT = "run"
INFINITE_LOOP_SOURCE = "def run(value):\n    while True:\n        pass\n"
VALID_SOURCE = "def run(value):\n    return value\n"
VECTORS = [{"args": [7], "expect_value": 7}]

ADAPTER_ID = "contained_worker"
FAST_ROUTE_WALL_TIME_MS = 1000
SLOW_ROUTE_WALL_TIME_MS = 15000
ROUTE_TOKEN_LIMIT = 1
ROUTE_COST_LIMIT_MICROS = 1
CIRCUIT_THRESHOLD = 2


class SupervisionScenario(NamedTuple):
    store: AuthorityStore
    wb: Workbench
    issued_timeout_route: dict
    issued_valid_route: dict
    plan: Row


@contextmanager
def build_scenario(authority_path: Path) -> Iterator[SupervisionScenario]:
    """Open ``authority_path`` fresh and assemble one supervision plan.

    Yields the still-open store, the bound ``Workbench``, the two prepared
    authored-source issuance records (the timeout route first, the valid
    route second) and the recorded ``WorkerSupervisorAuthority`` plan
    governing both. Nothing is dispatched; the caller executes inside this
    context. The store closes when the context exits.
    """
    with AuthorityStore(authority_path) as store:
        wb = Workbench(store)
        wb.gateway = wb.gateway.using(ADAPTER_ID)
        wb.authored_source_issuance.bind_gateway(wb.gateway)
        wb.set_initial_objective(
            OBJECTIVE, established_by="worker-supervision-proof")
        conductor = Conductor(wb)

        outcome = conductor.ingest_instruction(INSTRUCTION)
        if outcome.authorization["verdict"] != "ALLOW":
            raise RuntimeError(outcome.authorization)
        timeout_route_authorization_id = str(
            outcome.authorization["authorization_id"])

        first_row = wb.authorizations.get(timeout_route_authorization_id)
        valid_route_authorization_id = (
            timeout_route_authorization_id + "-fallback")
        wb.authorizations.record(
            authorization_id=valid_route_authorization_id,
            transaction_id=str(first_row["transaction_id"]),
            decision_id=str(first_row["decision_id"]),
            objective_id=str(first_row["objective_id"]),
            verdict=str(first_row["verdict"]),
            reason_code=str(first_row["reason_code"]),
            reason=str(first_row["reason"]),
            target_module_id=first_row["target_module_id"],
            scope=wb.authorizations.scope_of(first_row),
            verbatim_hash=str(first_row["verbatim_hash"]),
            decision_hash=str(first_row["decision_hash"]),
            baseline_hash=str(first_row["baseline_hash"]),
        )

        issued_timeout_route = wb.prepare_authored_source_verification(
            timeout_route_authorization_id,
            candidate_source=INFINITE_LOOP_SOURCE,
            vectors=VECTORS, entrypoint=ENTRYPOINT)
        issued_valid_route = wb.prepare_authored_source_verification(
            valid_route_authorization_id,
            candidate_source=VALID_SOURCE,
            vectors=VECTORS, entrypoint=ENTRYPOINT)

        supervisor = WorkerSupervisorAuthority(store)
        plan = supervisor.create_plan(
            [
                {"authorization_id": timeout_route_authorization_id,
                 "adapter_id": ADAPTER_ID,
                 "wall_time_ms": FAST_ROUTE_WALL_TIME_MS,
                 "token_limit": ROUTE_TOKEN_LIMIT,
                 "cost_limit_micros": ROUTE_COST_LIMIT_MICROS},
                {"authorization_id": valid_route_authorization_id,
                 "adapter_id": ADAPTER_ID,
                 "wall_time_ms": SLOW_ROUTE_WALL_TIME_MS,
                 "token_limit": ROUTE_TOKEN_LIMIT,
                 "cost_limit_micros": ROUTE_COST_LIMIT_MICROS},
            ],
            circuit_threshold=CIRCUIT_THRESHOLD)

        yield SupervisionScenario(
            store=store, wb=wb,
            issued_timeout_route=issued_timeout_route,
            issued_valid_route=issued_valid_route,
            plan=plan)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run_scenario(scenario: SupervisionScenario) -> dict[str, Any]:
    """Drive the real timeout-then-fallback walk and prove every claim.

    Everything here reads what ``build_scenario`` already recorded or what
    the coordinator's one real dispatch durably writes; nothing is minted,
    re-dispatched or trusted from an in-memory copy. Returns the finished
    proof payload; raises ``RuntimeError`` on the first claim that does not
    hold.
    """
    store = scenario.store
    wb = scenario.wb
    plan = scenario.plan
    supervision_id = str(plan["supervision_id"])
    active_objective_id = wb.continuity.active_objective_id()

    supervisor = WorkerSupervisorAuthority(store)
    coordinator = SupervisedExecutionCoordinator(
        supervisor=supervisor, gateway=wb.gateway, runs=wb.runs,
        evidence=wb.evidence)

    summary = coordinator.run(
        supervision_id, baseline_hash=wb.blueprint.baseline_hash,
        active_objective_id=active_objective_id)

    _require(summary["terminal_status"] == "SUCCEEDED",
             f"unexpected terminal status: {summary}")
    _require(summary["attempted_route_indexes"] == [0, 1],
             f"unexpected attempted routes: {summary}")
    _require(summary["failure_classes"] == {0: "timeout"},
             f"unexpected failure classes: {summary}")
    _require(summary["successful_route_index"] == 1,
             f"unexpected successful route: {summary}")

    # -- durable events: the fast route failed with no run of its own ------
    events = supervisor.events(supervision_id)
    route0_failed = next(
        e for e in events
        if int(e["route_index"]) == 0 and e["event_type"] == "FAILED")
    _require(str(route0_failed["failure_class"]) == "timeout",
             "route 0 did not fail with the timeout failure class")
    _require(route0_failed["run_id"] is None
             and route0_failed["evidence_id"] is None,
             "route 0's timeout event is bound to a run or evidence id, but "
             "a request refused before dispatch recorded either")

    route1_succeeded = next(
        e for e in events
        if int(e["route_index"]) == 1 and e["event_type"] == "SUCCEEDED")
    run_id = str(route1_succeeded["run_id"])
    evidence_id = str(route1_succeeded["evidence_id"])
    _require(bool(run_id.strip()) and bool(evidence_id.strip()),
             "route 1's success event carries a blank run or evidence id")
    for field in ("measured_wall_ms", "measured_tokens", "measured_cost_micros"):
        _require(int(route1_succeeded[field]) >= 0,
                 f"route 1's {field} measurement is negative")

    # -- read-only proof that the timed-out route's container is gone ------
    #
    # The container name is derived, never guessed: this recomputes the exact
    # ``ExecutionRequest`` the gateway built for route 0's one real dispatch
    # -- same verified authorization row, same adapter, same recorded budget,
    # same deterministic run-nonce formula -- and reads its ``request_hash``.
    # No token is minted (that only happens inside ``_dispatch_authorized``,
    # after the request is built) and nothing is re-dispatched; this is the
    # same construction the gateway's own dispatch already ran once, read
    # back rather than repeated.
    timeout_authorization_id = str(scenario.issued_timeout_route["authorization_id"])
    timeout_route = supervisor.resolve_route(supervision_id, 0)
    timeout_row = wb.authorizations.verify(
        timeout_authorization_id, baseline_hash=wb.blueprint.baseline_hash,
        active_objective_id=active_objective_id)
    timeout_adapter = wb.gateway._registry.get(str(timeout_route["adapter_id"]))
    timeout_run_nonce = sha256_hex({
        "domain": "cis.execution.attempt.v1",
        "authorization_id": timeout_authorization_id,
        "binding_hash": str(timeout_row["binding_hash"]),
        "adapter_id": timeout_adapter.adapter_id,
    })
    timeout_budget = ExecutionBudget(
        wall_time_ms=int(timeout_route["wall_time_ms"]),
        token_limit=int(timeout_route["token_limit"]),
        cost_limit_micros=int(timeout_route["cost_limit_micros"]))
    timeout_request = wb.gateway._request_for(
        timeout_row, timeout_adapter, run_nonce=timeout_run_nonce,
        budget=timeout_budget)
    timeout_container_name = f"cis-cw-{timeout_request.request_hash[:32]}"
    probe = subprocess.run(
        ["docker", "inspect", timeout_container_name],
        capture_output=True, text=True)
    _require(probe.returncode != 0,
             "the timed-out route's deterministic container name still "
             "inspects as present")

    # -- independent re-verification of the successful run and evidence ----
    run_row = wb.runs.get(run_id)
    _require(run_row is not None, "the successful run row is absent")
    evidence_row = wb.evidence.get(evidence_id)
    _require(evidence_row is not None, "the successful evidence row is absent")
    valid_authorization_id = str(scenario.issued_valid_route["authorization_id"])
    _require(
        sha256_text(str(evidence_row["content"])) == str(evidence_row["content_hash"])
        and str(evidence_row["kind"]) == "execution_evidence"
        and str(evidence_row["source_ref"]) == f"backend_runs:{run_id}"
        and str(evidence_row["admission_basis"])
        == f"verified_execution_authorization:{valid_authorization_id}",
        "the successful run's evidence does not independently verify")
    _require(
        str(run_row["status"]) == "completed"
        and str(run_row["evidence_id"]) == evidence_id
        and str(run_row["authorization_id"]) == valid_authorization_id,
        "the successful run row does not bind the fallback route it claims to")

    # -- assurance conjunction over the successful route's task contract ---
    task_contract_id = str(scenario.issued_valid_route["task_contract_id"])
    verification = Verifier(store, wb.blueprint).verify(task_contract_id)
    review, cycle = Reviewer(store, wb.blueprint).review(task_contract_id)
    decision = PromotionRecorder(store).decide(task_contract_id)
    _require(str(verification["outcome"]) == "VERIFIED_PASS",
             f"verification did not pass: {verification.as_dict()}")
    _require(str(review["outcome"]) == "PASS" and cycle is None,
             f"review did not pass cleanly: {review.as_dict()}")
    _require(str(decision["decision"]) == "PROMOTION_AUTHORIZED"
             and str(decision["host_action"]) == "NONE_RECORD_ONLY",
             f"promotion was not authorized: {decision.as_dict()}")

    # -- idempotence: replaying the coordinator changes nothing durable ----
    before = (len(supervisor.events(supervision_id)), len(wb.runs.all()))
    summary_again = coordinator.run(
        supervision_id, baseline_hash=wb.blueprint.baseline_hash,
        active_objective_id=active_objective_id)
    after = (len(supervisor.events(supervision_id)), len(wb.runs.all()))
    _require(summary_again == summary,
             "replaying the coordinator produced a different summary")
    _require(before == after,
             "replaying the coordinator changed durable event or run counts")

    return {
        "schema": "cis-worker-supervision-proof-v1",
        "supervision_id": supervision_id,
        "plan_hash": str(plan["plan_hash"]),
        "image": str(timeout_adapter.execution_image_identity),
        "routes": [
            {
                "authorization_id": timeout_authorization_id,
                "task_contract_id": str(
                    scenario.issued_timeout_route["task_contract_id"]),
                "task_contract_hash": str(
                    scenario.issued_timeout_route["task_contract_hash"]),
                "execution_input_hash": str(
                    scenario.issued_timeout_route["execution_input_hash"]),
            },
            {
                "authorization_id": valid_authorization_id,
                "task_contract_id": task_contract_id,
                "task_contract_hash": str(
                    scenario.issued_valid_route["task_contract_hash"]),
                "execution_input_hash": str(
                    scenario.issued_valid_route["execution_input_hash"]),
            },
        ],
        "summary": dict(summary),
        "events": [event_payload(e) for e in events],
        "timeout_route": {
            "container_name": timeout_container_name,
            "container_absent": True,
        },
        "successful_route": {
            "run_id": run_id,
            "result_hash": str(run_row["result_hash"]),
            "evidence_id": evidence_id,
            "content_hash": str(evidence_row["content_hash"]),
            "usage": {
                "measured_wall_ms": int(route1_succeeded["measured_wall_ms"]),
                "measured_tokens": int(route1_succeeded["measured_tokens"]),
                "measured_cost_micros": int(
                    route1_succeeded["measured_cost_micros"]),
            },
        },
        "verification": {"result_id": str(verification["result_id"]),
                         "outcome": str(verification["outcome"])},
        "review": {"review_id": str(review["review_id"]),
                  "outcome": str(review["outcome"])},
        "promotion": {"decision_id": str(decision["decision_id"]),
                     "decision": str(decision["decision"]),
                     "host_action": str(decision["host_action"])},
        "idempotence": {
            "before": {"event_count": before[0], "run_count": before[1]},
            "after": {"event_count": after[0], "run_count": after[1]},
        },
    }


def output(proof: dict[str, Any], output_path: Path) -> None:
    """Write the finished proof. The path is guaranteed not to exist yet --
    ``main`` refuses up front -- so a plain write is already atomic enough:
    there is no prior content it could ever clobber or interleave with."""
    output_path.write_text(
        json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    """Build the scenario, run the full proof, and write + print the result.

    Refuses before creating either path if a proof already stands at
    ``--authority`` or ``--output``, so every authority file this call ever
    removes on failure is one it just created itself. On any exception after
    that point it removes that authority file -- never a path that already
    existed -- so a half-finished database is never mistaken for a passing
    proof, and it re-raises rather than swallowing the failure.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    authority_path = Path(args.authority)
    output_path = Path(args.output)
    if authority_path.exists() or output_path.exists():
        raise SystemExit("refusing to replace an existing proof artifact")
    authority_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with build_scenario(authority_path) as scenario:
            proof = run_scenario(scenario)
    except Exception:
        if authority_path.exists():
            authority_path.unlink()
        raise
    output(proof, output_path)
    print(json.dumps(proof, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
