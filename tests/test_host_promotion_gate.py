"""Decision enforcement, durable apply, and authority-only rollback proofs."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from cis.assurance.authority import AssuranceAuthority
from cis.assurance.promotion import PromotionRecorder
from cis.assurance.reviewer import Reviewer
from cis.assurance.task_contract import TaskContractCompiler
from cis.assurance.verifier import Verifier
from cis.authority import EvidenceAuthority, RunAuthority, TrajectoryAuthority
from cis.errors import HostActionRefused
from cis.execution import AdapterRegistry, ExecutionGateway
from cis.execution.port import ExecutionPort, ExecutionResult
from cis.host import HostPromotionGate

from . import support

CANDIDATE = b"contained candidate bytes\n"


class CandidateAdapter(ExecutionPort):
    adapter_id = "contained_nonroot"
    requires_frozen_task_contract = True

    def capabilities(self):
        return ("reconstruct_module",)

    def execute(self, request):
        request.verify_token()
        contract = request.payload["frozen_task_contract"]
        candidate_hash = hashlib.sha256(CANDIDATE).hexdigest()
        return ExecutionResult(
            status="completed", exit_code=0,
            outputs={"candidate_content": CANDIDATE.decode(),
                     "candidate_sha256": candidate_hash},
            checks_performed=tuple(request.required_checks),
            evidence=(
                "schema=cis-contained-worker-evidence-v2",
                "uid=1000",
                f"task_contract_hash={contract['task_contract_hash']}",
                f"candidate_sha256={candidate_hash}",
                "host_action=none",
            ),
        )


def prepared():
    wb = support.workbench()
    outcome = wb.submit_instruction(
        "Reconstruct cis.worker.contained_nonroot in the clean environment")
    authorization_id = outcome.authorization["authorization_id"]
    compiled = TaskContractCompiler(
        authorizations=wb.authorizations, blueprint=wb.blueprint).compile(
            authorization_id=authorization_id,
            template_id="reconstruct_module.v1",
            active_objective_id=wb.continuity.active_objective_id(),
        )
    assurance = AssuranceAuthority(wb.store)
    assurance.task_contracts.freeze(compiled)

    def resolve(candidate_authorization_id):
        row = assurance.ledger.task_contract_for_authorization(
            candidate_authorization_id)
        if row is None:
            return None
        return assurance.verify_task_contract(
            str(row["task_contract_id"])).as_dict()

    registry = AdapterRegistry()
    registry.register(CandidateAdapter())
    wb.gateway = ExecutionGateway(
        authorizations=wb.authorizations,
        runs=RunAuthority(wb.store),
        evidence=EvidenceAuthority(wb.store),
        trajectory=TrajectoryAuthority(wb.store),
        registry=registry,
        adapter_id="contained_nonroot",
        task_contract_resolver=resolve,
        authorization_check_resolver=wb.execution_preflight_checks,
    )
    result = wb.execute(authorization_id)
    return wb, compiled.task_contract_id, result


def authorize_promotion(wb, task_contract_id):
    verification = Verifier(wb.store, wb.blueprint).verify(task_contract_id)
    assert verification["outcome"] == "VERIFIED_PASS"
    review, cycle = Reviewer(wb.store, wb.blueprint).review(task_contract_id)
    assert review["outcome"] == "PASS" and cycle is None
    decision = PromotionRecorder(wb.store).decide(task_contract_id)
    assert decision["decision"] == "PROMOTION_AUTHORIZED"


class HostPromotionGateTests(unittest.TestCase):
    def test_apply_is_refused_before_the_recorded_decision(self):
        wb, task_contract_id, result = prepared()
        with tempfile.TemporaryDirectory() as directory:
            gate = HostPromotionGate(wb.store, target_root=directory)
            with self.assertRaises(HostActionRefused):
                gate.apply(task_contract_id=task_contract_id,
                           candidate_content=result["outputs"]["candidate_content"])

    def test_authorized_apply_and_rollback_restore_prior_bytes(self):
        wb, task_contract_id, result = prepared()
        authorize_promotion(wb, task_contract_id)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "cis/worker/contained_nonroot.candidate"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"prior bytes\n")
            gate = HostPromotionGate(wb.store, target_root=directory)
            applied = gate.apply(
                task_contract_id=task_contract_id,
                candidate_content=result["outputs"]["candidate_content"])
            self.assertEqual(applied["state"], "APPLIED")
            self.assertEqual(target.read_bytes(), CANDIDATE)
            rolled_back = gate.rollback(applied["application_id"])
            self.assertEqual(rolled_back["state"], "ROLLED_BACK")
            self.assertEqual(target.read_bytes(), b"prior bytes\n")

    def test_interrupted_apply_recovers_from_the_recorded_plan(self):
        wb, task_contract_id, result = prepared()
        authorize_promotion(wb, task_contract_id)
        with tempfile.TemporaryDirectory() as directory:
            gate = HostPromotionGate(wb.store, target_root=directory)

            def interrupt(_target, _content):
                raise OSError("injected interruption after durable plan")

            gate._atomic_write = interrupt
            with self.assertRaises(OSError):
                gate.apply(
                    task_contract_id=task_contract_id,
                    candidate_content=result["outputs"]["candidate_content"])
            plan = wb.store.one("SELECT * FROM host_promotion_plans")
            self.assertIsNotNone(plan)
            self.assertIsNone(wb.store.one("SELECT * FROM host_promotion_events"))

            recovered = HostPromotionGate(
                wb.store, target_root=directory).recover(
                    str(plan["application_id"]))
            self.assertEqual(recovered["state"], "APPLIED")
            target = Path(directory) / recovered["target_relative_path"]
            self.assertEqual(target.read_bytes(), CANDIDATE)


if __name__ == "__main__":
    unittest.main()
