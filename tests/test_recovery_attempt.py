"""Tests for RecoveryAttemptAuthority: the append-only recovery-attempt ledger."""

from __future__ import annotations

import hashlib
import json
import unittest

from cis.assurance.recovery import OperationalSelfAssessment
from cis.assurance.recovery_attempt import RecoveryAttemptAuthority
from cis.errors import RecoveryAttemptRefused

from . import support
from .test_execution_input_gateway import CANDIDATE
from .test_operational_self_assessment import objecting_case


def spawn_verify_authorization(fixture, suffix):
    """A second verify_authored_source authorization, cloned from the fixture's own.

    Mirrors ``ExecutionInputGatewayFixture.setUp``'s own construction of its
    first verify-authorization, but reads the fields back off the already
    recorded row rather than off a kept-around outcome object, since the
    fixture itself does not expose one.
    """
    original = fixture.wb.authorizations.get(fixture.verify_authorization_id)
    new_id = f"{fixture.verify_authorization_id}-{suffix}"
    fixture.wb.authorizations.record(
        authorization_id=new_id,
        transaction_id=str(original["transaction_id"]),
        decision_id=str(original["decision_id"]),
        objective_id=(str(original["objective_id"])
                      if original["objective_id"] is not None else None),
        verdict=str(original["verdict"]),
        reason_code=str(original["reason_code"]),
        reason=str(original["reason"]),
        target_module_id=original["target_module_id"],
        scope={
            "operation": str(original["operation"]),
            "allowed_scope": json.loads(str(original["allowed_scope_json"])),
            "forbidden_actions": json.loads(str(original["forbidden_actions_json"])),
            "required_checks": json.loads(str(original["required_checks_json"])),
            "required_evidence": json.loads(str(original["required_evidence_json"])),
            "stopping_condition": str(original["stopping_condition"]),
            "return_point": str(original["return_point"]),
        },
        verbatim_hash=str(original["verbatim_hash"]),
        decision_hash=str(original["decision_hash"]),
        baseline_hash=str(original["baseline_hash"]),
    )
    return new_id


def spawn_child_task_contract(fixture, suffix, **exi_overrides):
    """A fresh, never-dispatched ``verify_authored_source.v1`` child contract.

    Built from a brand new authorization through the same two authorities
    production issuance itself calls (``TaskContractCompiler`` then
    ``ExecutionInputAuthority``), and never run through the gateway:
    ``RecoveryAttemptAuthority`` must accept a child purely from recorded
    authority, never from execution evidence.

    By default every execution-input field but the candidate matches the
    parent built by ``objecting_case`` exactly, because both ultimately come
    from the same fixture constants (``support.seed_execution_input``'s
    defaults and ``ExecutionInputGatewayFixture``'s constants coincide), so a
    bare call already produces a valid fresh replacement child.
    """
    authorization_id = spawn_verify_authorization(fixture, suffix)
    compiled = support.freeze_task_contract(
        fixture.wb, authorization_id, template_id="verify_authored_source.v1")
    support.seed_execution_input(
        fixture.wb, compiled.task_contract_id, **exi_overrides)
    return compiled.task_contract_id


class RecoveryAttemptAuthorityTests(unittest.TestCase):
    def test_valid_fresh_child_is_appended_and_verifies(self):
        fixture, _ = objecting_case()
        assessment = OperationalSelfAssessment(fixture.wb.store).assess(
            fixture.compiled.task_contract_id)
        child_task_contract_id = spawn_child_task_contract(fixture, "child")

        authority = RecoveryAttemptAuthority(fixture.wb.store)
        row = authority.record(
            str(assessment["assessment_id"]),
            child_task_contract_id=child_task_contract_id)

        self.assertEqual(row["parent_task_contract_id"],
                         fixture.compiled.task_contract_id)
        self.assertEqual(row["child_task_contract_id"], child_task_contract_id)
        self.assertEqual(row["generation"], 1)
        self.assertEqual(authority.verify(str(row["attempt_id"])), row)
        self.assertEqual(
            authority.for_assessment(str(assessment["assessment_id"])), row)
        self.assertEqual(authority.for_child(child_task_contract_id), row)

    def test_identical_retry_is_idempotent(self):
        fixture, _ = objecting_case()
        assessment = OperationalSelfAssessment(fixture.wb.store).assess(
            fixture.compiled.task_contract_id)
        child_task_contract_id = spawn_child_task_contract(fixture, "child")

        authority = RecoveryAttemptAuthority(fixture.wb.store)
        first = authority.record(
            str(assessment["assessment_id"]),
            child_task_contract_id=child_task_contract_id)
        second = authority.record(
            str(assessment["assessment_id"]),
            child_task_contract_id=child_task_contract_id)
        self.assertEqual(first, second)

    def test_a_differing_second_child_is_refused(self):
        fixture, _ = objecting_case()
        assessment = OperationalSelfAssessment(fixture.wb.store).assess(
            fixture.compiled.task_contract_id)
        first_child = spawn_child_task_contract(fixture, "child-1")
        second_child = spawn_child_task_contract(fixture, "child-2")

        authority = RecoveryAttemptAuthority(fixture.wb.store)
        authority.record(str(assessment["assessment_id"]),
                         child_task_contract_id=first_child)
        with self.assertRaises(RecoveryAttemptRefused):
            authority.record(str(assessment["assessment_id"]),
                             child_task_contract_id=second_child)

    def test_a_tampered_attempt_digest_is_refused(self):
        fixture, _ = objecting_case()
        assessment = OperationalSelfAssessment(fixture.wb.store).assess(
            fixture.compiled.task_contract_id)
        child_task_contract_id = spawn_child_task_contract(fixture, "child")
        authority = RecoveryAttemptAuthority(fixture.wb.store)
        row = authority.record(
            str(assessment["assessment_id"]),
            child_task_contract_id=child_task_contract_id)

        fixture.wb.store.execute_raw("DROP TRIGGER recovery_attempts_no_update")
        fixture.wb.store.execute_raw(
            "UPDATE recovery_attempts SET attempt_hash = ? WHERE attempt_id = ?",
            ("0" * 64, row["attempt_id"]))
        with self.assertRaises(RecoveryAttemptRefused):
            authority.verify(str(row["attempt_id"]))

    def test_drift_in_a_preserved_binding_is_refused(self):
        fixture, _ = objecting_case()
        assessment = OperationalSelfAssessment(fixture.wb.store).assess(
            fixture.compiled.task_contract_id)
        authority = RecoveryAttemptAuthority(fixture.wb.store)
        drifted_vectors = json.dumps(
            [{"args": [2], "expect_value": 2}]).encode("utf-8")
        cases = {
            "vector_contract_sha256": {
                "vector_contract": drifted_vectors,
                "vector_contract_sha256": hashlib.sha256(
                    drifted_vectors).hexdigest(),
            },
            "authorized_entrypoint": {"authorized_entrypoint": "other"},
            "worker_image": {"worker_image": "sha256:" + "d" * 64},
        }
        for index, (label, overrides) in enumerate(cases.items()):
            with self.subTest(drifted=label):
                child_task_contract_id = spawn_child_task_contract(
                    fixture, f"drift-{index}", **overrides)
                with self.assertRaises(RecoveryAttemptRefused):
                    authority.record(
                        str(assessment["assessment_id"]),
                        child_task_contract_id=child_task_contract_id)

    def test_unchanged_candidate_is_refused(self):
        fixture, _ = objecting_case()
        assessment = OperationalSelfAssessment(fixture.wb.store).assess(
            fixture.compiled.task_contract_id)
        child_task_contract_id = spawn_child_task_contract(
            fixture, "same-candidate",
            candidate_source=CANDIDATE,
            candidate_sha256=hashlib.sha256(CANDIDATE).hexdigest())
        authority = RecoveryAttemptAuthority(fixture.wb.store)
        with self.assertRaises(RecoveryAttemptRefused):
            authority.record(str(assessment["assessment_id"]),
                             child_task_contract_id=child_task_contract_id)

    def test_non_replacement_assessment_is_refused(self):
        fixture, _ = objecting_case(overrides={"forged": "extra"})
        assessment = OperationalSelfAssessment(fixture.wb.store).assess(
            fixture.compiled.task_contract_id)
        self.assertNotEqual(
            str(assessment["disposition"]), "REPLACEMENT_CANDIDATE_REQUIRED")
        child_task_contract_id = spawn_child_task_contract(fixture, "child")
        authority = RecoveryAttemptAuthority(fixture.wb.store)
        with self.assertRaises(RecoveryAttemptRefused):
            authority.record(str(assessment["assessment_id"]),
                             child_task_contract_id=child_task_contract_id)


if __name__ == "__main__":
    unittest.main()
