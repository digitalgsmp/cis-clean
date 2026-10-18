"""Acceptance tests for the Slice-2 assurance increment."""

import inspect
import json
import sqlite3
import unittest

from cis.assurance.authority import (
    AssuranceAuthority, MAX_OBJECTION_CYCLES, PROMOTION_AUTHORIZED,
    PROMOTION_DENIED, STATE_ESCALATED, STATE_PROMOTION_AUTHORIZED,
    VERIFIED_FAIL, VERIFIED_PASS,
)
from cis.assurance.promotion import PromotionRecorder
from cis.assurance.reviewer import Reviewer
from cis.assurance.task_contract import (
    TASK_CONTRACT_HASH_DOMAIN, TaskContractCompiler, verify_row,
)
from cis.assurance.verifier import Verifier
from cis.errors import (
    AppendOnlyViolation, ObjectionCyclesExhausted, ScopeWideningRefused,
    TaskContractTampered,
)
from cis.interface import WorkbenchApi

from . import support


class AssuranceFixture(unittest.TestCase):
    def passing(self):
        wb, authorization_id = support.allow_and_run()
        compiled = support.freeze_task_contract(wb, authorization_id)
        task_contract_id = compiled.task_contract_id
        verification = Verifier(wb.store, wb.blueprint).verify(task_contract_id)
        review, cycle = Reviewer(wb.store, wb.blueprint).review(task_contract_id)
        return wb, compiled, verification, review, cycle

    def failing(self):
        wb, outcome = support.allow_outcome()
        compiled = support.freeze_task_contract(
            wb, outcome.authorization["authorization_id"])
        verification = Verifier(wb.store, wb.blueprint).verify(
            compiled.task_contract_id)
        return wb, compiled, verification


class TaskContractTests(AssuranceFixture):
    def test_contract_is_frozen_in_an_independent_hash_domain(self):
        wb, outcome = support.allow_outcome()
        compiled = support.freeze_task_contract(
            wb, outcome.authorization["authorization_id"])
        row = AssuranceAuthority(wb.store).ledger.require_task_contract(
            compiled.task_contract_id)
        self.assertEqual(row["state"], "FROZEN")
        self.assertEqual(row["hash_domain"], TASK_CONTRACT_HASH_DOMAIN)
        self.assertEqual(verify_row(row), row["task_contract_hash"])
        self.assertNotEqual(row["task_contract_hash"],
                            row["authorization_binding_hash"])

    def test_contract_may_narrow_but_cannot_widen_paths(self):
        wb, outcome = support.allow_outcome()
        compiler = TaskContractCompiler(authorizations=wb.authorizations,
                                        blueprint=wb.blueprint)
        authorization_id = outcome.authorization["authorization_id"]
        envelope = compiler.envelope_for(
            template_id="reconstruct_module.v1",
            target_module_id="cis.workbench.projection")
        narrowed = compiler.compile(
            authorization_id=authorization_id,
            template_id="reconstruct_module.v1",
            allowed_paths=[envelope[0]],
            active_objective_id=wb.continuity.active_objective_id())
        self.assertEqual(narrowed.allowed_paths, (envelope[0],))
        with self.assertRaises(ScopeWideningRefused):
            compiler.compile(
                authorization_id=authorization_id,
                template_id="reconstruct_module.v1",
                allowed_paths=["../cis", "/mnt/projects/cis"],
                active_objective_id=wb.continuity.active_objective_id())

    def test_tampered_contract_is_refused_not_assessed(self):
        wb, outcome = support.allow_outcome()
        compiled = support.freeze_task_contract(
            wb, outcome.authorization["authorization_id"])
        wb.store.execute_raw(
            "DROP TRIGGER task_contracts_no_update")
        wb.store.execute_raw(
            "UPDATE task_contracts SET task_contract_hash = ? WHERE task_contract_id = ?",
            ("0" * 64, compiled.task_contract_id))
        with self.assertRaises(TaskContractTampered):
            Verifier(wb.store, wb.blueprint).verify(compiled.task_contract_id)
        self.assertIsNone(AssuranceAuthority(wb.store).ledger.verification_result(
            compiled.task_contract_id))


class VerificationReviewPromotionTests(AssuranceFixture):
    def test_missing_evidence_records_verified_fail(self):
        wb, compiled, result = self.failing()
        self.assertEqual(result["outcome"], VERIFIED_FAIL)
        self.assertEqual(result["reason_code"], "REQUIRED_ARTIFACT_ABSENT")

    def test_complete_submission_passes_both_independent_gates(self):
        wb, compiled, verification, review, cycle = self.passing()
        self.assertEqual(verification["outcome"], VERIFIED_PASS)
        self.assertEqual(review["outcome"], "PASS")
        self.assertIsNone(cycle)
        decision = PromotionRecorder(wb.store).decide(compiled.task_contract_id)
        self.assertEqual(decision["decision"], PROMOTION_AUTHORIZED)
        self.assertEqual(decision["host_action"], "NONE_RECORD_ONLY")
        self.assertEqual(AssuranceAuthority(wb.store).ledger.state_of(
            compiled.task_contract_id), STATE_PROMOTION_AUTHORIZED)

    def test_review_pending_denies_promotion(self):
        wb, authorization_id = support.allow_and_run()
        compiled = support.freeze_task_contract(wb, authorization_id)
        Verifier(wb.store, wb.blueprint).verify(compiled.task_contract_id)
        decision = PromotionRecorder(wb.store).decide(compiled.task_contract_id)
        self.assertEqual(decision["decision"], PROMOTION_DENIED)
        self.assertEqual(decision["reason_code"], "REVIEW_NOT_RECORDED")

    def test_three_objections_escalate_and_fourth_is_impossible(self):
        wb, compiled, verification = self.failing()
        reviewer = Reviewer(wb.store, wb.blueprint)
        for expected in range(1, MAX_OBJECTION_CYCLES + 1):
            review, cycle = reviewer.review(compiled.task_contract_id)
            self.assertEqual(review["outcome"], "OBJECTIONS")
            self.assertEqual(cycle["cycle_number"], expected)
        ledger = AssuranceAuthority(wb.store).ledger
        self.assertEqual(ledger.state_of(compiled.task_contract_id),
                         STATE_ESCALATED)
        self.assertTrue(reviewer.escalated(compiled.task_contract_id))
        with self.assertRaises(ObjectionCyclesExhausted):
            reviewer.review(compiled.task_contract_id)
        with self.assertRaises(sqlite3.IntegrityError):
            wb.store.execute_raw(
                "INSERT INTO objection_cycles VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("oc-four", compiled.task_contract_id, "missing-review", 4,
                 "[]", "ESCALATE",
                 "DEFERRED_TO_CONTAINED_WORKER_CAPABILITY", 1, "x", "t", 999))

    def test_escalation_denies_promotion(self):
        wb, compiled, verification = self.failing()
        reviewer = Reviewer(wb.store, wb.blueprint)
        for _ in range(3):
            reviewer.review(compiled.task_contract_id)
        decision = PromotionRecorder(wb.store).decide(compiled.task_contract_id)
        self.assertEqual(decision["decision"], PROMOTION_DENIED)
        self.assertEqual(decision["reason_code"],
                         "OBJECTION_CYCLES_EXHAUSTED_AND_ESCALATED")

    def test_verifier_reviewer_and_promotion_facades_are_disjoint(self):
        names = AssuranceAuthority.facade_method_names()
        self.assertTrue(names["verifier"].isdisjoint(names["reviewer"]))
        self.assertTrue(names["verifier"].isdisjoint(names["promotion"]))
        self.assertTrue(names["reviewer"].isdisjoint(names["promotion"]))
        reviewer_source = inspect.getsource(__import__(
            "cis.assurance.reviewer", fromlist=["*"]))
        verifier_source = inspect.getsource(__import__(
            "cis.assurance.verifier", fromlist=["*"]))
        self.assertNotIn("from .verifier", reviewer_source)
        self.assertNotIn("from .reviewer", verifier_source)


class LedgerProjectionSurfaceTests(AssuranceFixture):
    def test_every_new_authority_table_is_append_only(self):
        wb, _, _ = support.exercised_workbench()
        tables = AssuranceAuthority.owned_authority
        for table in tables:
            row = wb.store.one(f"SELECT * FROM {table} LIMIT 1")
            self.assertIsNotNone(row, table)
            key = next(iter(row))
            with self.assertRaises(AppendOnlyViolation, msg=table):
                wb.store.execute_raw(
                    f"UPDATE {table} SET {key} = {key} WHERE rowid = 1")
            with self.assertRaises(AppendOnlyViolation, msg=table):
                wb.store.execute_raw(f"DELETE FROM {table} WHERE rowid = 1")

    def test_projection_and_api_are_read_only_and_show_assurance(self):
        wb, compiled, verification, review, cycle = self.passing()
        api = WorkbenchApi(wb)
        response = api.dispatch("GET", "/assurance")
        self.assertEqual(response.status, 200)
        assurance = response.body["assurance"]
        self.assertEqual(assurance["counts"]["task_contracts"], 1)
        self.assertTrue(assurance["host_independent"])
        task = api.dispatch(
            "GET", f"/assurance/task/{compiled.task_contract_id}")
        self.assertEqual(task.status, 200)
        self.assertEqual(task.body["assurance"]["task_contract"]["state"],
                         "PASS")
        before = AssuranceAuthority(wb.store).ledger.snapshot(
            compiled.task_contract_id)
        api.dispatch("POST", "/assurance", {"decision": "PASS"})
        after = AssuranceAuthority(wb.store).ledger.snapshot(
            compiled.task_contract_id)
        self.assertEqual(before, after)

    def test_order_reconciliation_waives_no_boundary_test(self):
        wb = support.workbench()
        order = support.assurance_projection(wb).order_reconciliation()
        proven = {item["letter"] for item in order["letters"]
                  if item["status"] == "PROVEN_IN_THIS_INCREMENT"}
        outstanding = {item["letter"] for item in order["letters"]
                       if item["status"] == "MANDATORY_OUTSTANDING"}
        self.assertEqual(proven, set("ABCDEFGHIJKLMNO"))
        self.assertEqual(outstanding, set())
        self.assertTrue(order["waiver"].startswith("NONE"))


if __name__ == "__main__":
    unittest.main()
