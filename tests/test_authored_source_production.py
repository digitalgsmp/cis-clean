"""Production issuance and complete assurance path for authored source."""

from __future__ import annotations

import unittest

from cis.assurance.promotion import PromotionRecorder
from cis.assurance.reviewer import Reviewer
from cis.assurance.verifier import Verifier
from cis.errors import CisError
from cis.execution import AdapterRegistry, ExecutionGateway

from . import support
from .test_authored_source_verifier import AttestingAdapter
from .test_execution_input_gateway import (
    RUNNER_DIGEST, WORKER_DIGEST, WORKER_IMAGE,
)


def production_workbench():
    wb = support.workbench()
    adapter = AttestingAdapter(WORKER_IMAGE)
    adapter.expected_trusted_runner_sha256 = RUNNER_DIGEST
    adapter.expected_worker_sha256 = WORKER_DIGEST
    registry = AdapterRegistry()
    registry.register(adapter)
    gateway = ExecutionGateway(
        authorizations=wb.authorizations, runs=wb.runs,
        evidence=wb.evidence, trajectory=wb.trajectory,
        registry=registry, adapter_id=adapter.adapter_id,
        authorization_check_resolver=wb.execution_preflight_checks,
        task_contract_resolver=(
            wb.authored_source_issuance.task_contract_for_authorization),
        execution_input_resolver=(
            wb.authored_source_issuance.execution_input_for_task),
    )
    wb.gateway = gateway
    wb.authored_source_issuance.bind_gateway(gateway)
    return wb, adapter


class ProductionIssuanceTests(unittest.TestCase):
    def test_closed_command_issues_verify_operation_and_full_conjunction(self):
        wb, adapter = production_workbench()
        outcome = wb.submit_instruction(
            "Verify authored source for cis.workbench.projection")
        self.assertEqual(outcome.authorization["verdict"], "ALLOW")
        self.assertEqual(outcome.authorization["scope"]["operation"],
                         "verify_authored_source")
        issued = wb.prepare_authored_source_verification(
            outcome.authorization["authorization_id"],
            candidate_source="def run(value):\n    return value\n",
            vectors=[{"args": [1], "expect_value": 1}], entrypoint="run")
        self.assertEqual(issued["adapter_id"], adapter.adapter_id)
        self.assertEqual(issued["worker_image"], WORKER_IMAGE)

        run = wb.execute(outcome.authorization["authorization_id"])
        verification = Verifier(wb.store, wb.blueprint).verify(
            issued["task_contract_id"])
        review, cycle = Reviewer(wb.store, wb.blueprint).review(
            issued["task_contract_id"])
        decision = PromotionRecorder(wb.store).decide(
            issued["task_contract_id"])
        self.assertEqual(run["status"], "completed")
        self.assertEqual(verification["outcome"], "VERIFIED_PASS")
        self.assertEqual(review["outcome"], "PASS")
        self.assertIsNone(cycle)
        self.assertEqual(decision["decision"], "PROMOTION_AUTHORIZED")
        self.assertEqual(decision["host_action"], "NONE_RECORD_ONLY")

    def test_identical_issuance_resumes_but_replacement_is_refused(self):
        wb, _ = production_workbench()
        outcome = wb.submit_instruction(
            "Verify authored source for cis.workbench.projection")
        kwargs = {
            "candidate_source": "def run(value):\n    return value\n",
            "vectors": [{"args": [1], "expect_value": 1}],
            "entrypoint": "run",
        }
        first = wb.prepare_authored_source_verification(
            outcome.authorization["authorization_id"], **kwargs)
        second = wb.prepare_authored_source_verification(
            outcome.authorization["authorization_id"], **kwargs)
        self.assertEqual(first, second)
        with self.assertRaises(CisError):
            wb.prepare_authored_source_verification(
                outcome.authorization["authorization_id"],
                **{**kwargs, "candidate_source":
                   "def run(value):\n    return value + 1\n"})

    def test_ordinary_instruction_still_issues_reconstruction_only(self):
        wb, _ = production_workbench()
        outcome = wb.submit_instruction(
            "Reconstruct cis.workbench.projection in the clean environment")
        self.assertEqual(outcome.authorization["scope"]["operation"],
                         "reconstruct_module")
        with self.assertRaises(CisError):
            wb.prepare_authored_source_verification(
                outcome.authorization["authorization_id"],
                candidate_source="def run():\n    return 1\n",
                vectors=[{"args": [], "expect_value": 1}], entrypoint="run")


if __name__ == "__main__":
    unittest.main()
