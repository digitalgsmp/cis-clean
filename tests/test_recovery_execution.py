"""Tests for RecoveryExecutionAuthority: carrying a recovery through the
existing gateway/Verifier/Reviewer/PromotionRecorder path."""

from __future__ import annotations

import json
import unittest

from cis.assurance.recovery import OperationalSelfAssessment
from cis.assurance.recovery_attempt import RecoveryAttemptAuthority
from cis.assurance.recovery_execution import RecoveryExecutionAuthority
from cis.errors import RecoveryExecutionRefused

from . import support
from .test_authored_source_verifier import AttestingAdapter
from .test_execution_input_gateway import RUNNER_DIGEST, WORKER_DIGEST
from .test_operational_self_assessment import objecting_case

REPLACEMENT_CANDIDATE = b"def run(args):\n    return int(args[0])\n"
VECTORS = [{"args": [1], "expect_value": 1}]
ENTRYPOINT = "run"


def spawn_authorization(fixture, suffix, *, operation="verify_authored_source",
                        target_module_id=None):
    """A fresh authorization cloned from the parent fixture's own, with the
    operation and target independently overridable so the negative cases can
    build a self-consistent ALLOW that simply names the wrong thing."""
    original = fixture.wb.authorizations.get(fixture.verify_authorization_id)
    new_id = f"{fixture.verify_authorization_id}-{suffix}"
    scope = {
        "operation": operation,
        "allowed_scope": json.loads(str(original["allowed_scope_json"])),
        "forbidden_actions": json.loads(str(original["forbidden_actions_json"])),
        "required_checks": json.loads(str(original["required_checks_json"])),
        "required_evidence": json.loads(str(original["required_evidence_json"])),
        "stopping_condition": str(original["stopping_condition"]),
        "return_point": str(original["return_point"]),
    }
    fixture.wb.authorizations.record(
        authorization_id=new_id,
        transaction_id=str(original["transaction_id"]),
        decision_id=str(original["decision_id"]),
        objective_id=(str(original["objective_id"])
                      if original["objective_id"] is not None else None),
        verdict=str(original["verdict"]),
        reason_code=str(original["reason_code"]),
        reason=str(original["reason"]),
        target_module_id=(target_module_id if target_module_id is not None
                          else original["target_module_id"]),
        scope=scope,
        verbatim_hash=str(original["verbatim_hash"]),
        decision_hash=str(original["decision_hash"]),
        baseline_hash=str(original["baseline_hash"]),
    )
    return new_id


def recovery_case(*, suffix="child", child_overrides=None,
                  assessment_overrides=None):
    """A fresh objecting parent, its replacement-required assessment, a
    distinct child ALLOW for the same target and operation, and the
    authority wired over a dedicated attesting adapter for that child."""
    fixture, _ = objecting_case(overrides=assessment_overrides)
    assessment = OperationalSelfAssessment(fixture.wb.store).assess(
        fixture.compiled.task_contract_id)
    child_authorization_id = spawn_authorization(fixture, suffix)

    adapter = AttestingAdapter(fixture.exi_row["worker_image"],
                               overrides=child_overrides)
    adapter.adapter_id = f"attesting_recovery_{suffix}"
    adapter.expected_trusted_runner_sha256 = RUNNER_DIGEST
    adapter.expected_worker_sha256 = WORKER_DIGEST
    fixture.registry.register(adapter)
    gateway = fixture.gateway.using(adapter.adapter_id)

    authority = RecoveryExecutionAuthority(
        store=fixture.wb.store, blueprint=fixture.wb.blueprint,
        gateway=gateway, authorizations=fixture.wb.authorizations)
    return fixture, assessment, child_authorization_id, authority


def execute(authority, fixture, assessment, child_authorization_id, **kwargs):
    values = {
        "candidate_source": REPLACEMENT_CANDIDATE,
        "vectors": VECTORS,
        "entrypoint": ENTRYPOINT,
        "active_objective_id": fixture.wb.continuity.active_objective_id(),
    }
    values.update(kwargs)
    return authority.execute(
        str(assessment["assessment_id"]),
        child_authorization_id=child_authorization_id,
        **values)


class RecoveryExecutionTests(unittest.TestCase):
    def test_success_carries_the_replacement_to_promotion_authorized(self):
        fixture, assessment, child_authorization_id, authority = recovery_case()
        result = execute(authority, fixture, assessment, child_authorization_id)

        self.assertEqual(result["verification"]["outcome"], "VERIFIED_PASS")
        self.assertEqual(result["review"]["outcome"], "PASS")
        self.assertIsNone(result["cycle"])
        self.assertEqual(result["decision"]["decision"], "PROMOTION_AUTHORIZED")
        self.assertEqual(result["decision"]["host_action"], "NONE_RECORD_ONLY")
        self.assertEqual(result["run_status"], "completed")
        self.assertTrue(result["run_id"])

    def test_missing_child_authorization_is_refused(self):
        fixture, assessment, _, authority = recovery_case()
        with self.assertRaises(RecoveryExecutionRefused):
            execute(authority, fixture, assessment, "auth-missing")

    def test_reused_parent_authorization_is_refused(self):
        fixture, assessment, _, authority = recovery_case()
        with self.assertRaises(RecoveryExecutionRefused):
            execute(authority, fixture, assessment,
                    fixture.verify_authorization_id)

    def test_wrong_operation_child_authorization_is_refused(self):
        fixture, assessment, _, authority = recovery_case()
        wrong_operation_id = spawn_authorization(
            fixture, "wrong-op", operation="reconstruct_module")
        with self.assertRaises(RecoveryExecutionRefused):
            execute(authority, fixture, assessment, wrong_operation_id)

    def test_wrong_target_child_authorization_is_refused(self):
        fixture, assessment, _, authority = recovery_case()
        wrong_target_id = spawn_authorization(
            fixture, "wrong-target", target_module_id="cis.other.module")
        with self.assertRaises(RecoveryExecutionRefused):
            execute(authority, fixture, assessment, wrong_target_id)

    def test_a_failing_candidate_cannot_reach_promotion_authorized(self):
        fixture, assessment, child_authorization_id, authority = recovery_case(
            child_overrides={"classification": "SOURCE_FAIL",
                             "verdict": "SOURCE_FAIL", "worker_exit": "1"})
        result = execute(authority, fixture, assessment, child_authorization_id)

        self.assertEqual(result["verification"]["outcome"], "VERIFIED_FAIL")
        self.assertNotEqual(result["decision"]["decision"],
                            "PROMOTION_AUTHORIZED")
        self.assertEqual(result["decision"]["decision"], "PROMOTION_DENIED")

    def test_non_replacement_assessment_refuses_before_child_issuance(self):
        fixture, assessment, child_authorization_id, authority = recovery_case(
            assessment_overrides={"forged": "extra"})
        with self.assertRaises(RecoveryExecutionRefused):
            execute(authority, fixture, assessment, child_authorization_id)
        self.assertIsNone(
            authority._assurance.ledger.task_contract_for_authorization(
                child_authorization_id))

    def test_result_links_to_the_exact_recorded_attempt(self):
        fixture, assessment, child_authorization_id, authority = recovery_case()
        result = execute(authority, fixture, assessment, child_authorization_id)

        attempts = RecoveryAttemptAuthority(fixture.wb.store)
        attempt = attempts.verify(result["attempt_id"])
        self.assertEqual(str(attempt["parent_task_contract_id"]),
                         fixture.compiled.task_contract_id)
        self.assertEqual(str(attempt["child_task_contract_id"]),
                         result["child_task_contract_id"])
        self.assertEqual(str(attempt["child_authorization_id"]),
                         result["child_authorization_id"])
        self.assertEqual(
            attempts.for_assessment(str(assessment["assessment_id"])), attempt)

    def test_resuming_after_full_completion_is_safe_and_identical(self):
        fixture, assessment, child_authorization_id, authority = recovery_case()
        first = execute(authority, fixture, assessment, child_authorization_id)
        second = execute(authority, fixture, assessment, child_authorization_id)

        self.assertEqual(first, second)
        self.assertEqual(
            len(fixture.wb.runs.for_authorization(child_authorization_id)), 1)
        self.assertEqual(
            len(support.assurance_authority(fixture.wb).ledger.reviews(
                first["child_task_contract_id"])), 1)


if __name__ == "__main__":
    unittest.main()
