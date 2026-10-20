"""Slice 6A: deterministic assessment before any recovery authorization."""

from __future__ import annotations

import json
import unittest

from cis.assurance.recovery import OperationalSelfAssessment
from cis.assurance.reviewer import Reviewer
from cis.assurance.verifier import Verifier
from cis.errors import OperationalAssessmentRefused

from .test_authored_source_verifier import executed_case


def objecting_case(*, overrides=None, cycles=1):
    values = {"classification": "SOURCE_FAIL", "verdict": "SOURCE_FAIL",
              "worker_exit": "1"}
    values.update(overrides or {})
    fixture, _ = executed_case(overrides=values)
    Verifier(fixture.wb.store, fixture.wb.blueprint).verify(
        fixture.compiled.task_contract_id)
    reviewer = Reviewer(fixture.wb.store, fixture.wb.blueprint)
    latest = None
    for _ in range(cycles):
        _, latest = reviewer.review(fixture.compiled.task_contract_id)
    return fixture, latest


class OperationalSelfAssessmentTests(unittest.TestCase):
    def test_replacement_assessment_freezes_preserved_and_changeable_facts(self):
        fixture, cycle = objecting_case()
        assessor = OperationalSelfAssessment(fixture.wb.store)
        row = assessor.assess(fixture.compiled.task_contract_id)
        self.assertEqual(row["cycle_id"], cycle["cycle_id"])
        self.assertEqual(row["disposition"],
                         "REPLACEMENT_CANDIDATE_REQUIRED")
        self.assertEqual(json.loads(row["permitted_changes_json"]),
                         ["candidate_source"])
        preserved = json.loads(row["preserved_bindings_json"])
        self.assertEqual(preserved["vector_contract_sha256"],
                         fixture.exi_row["vector_contract_sha256"])
        self.assertEqual(preserved["authorized_entrypoint"], "run")
        self.assertEqual(preserved["worker_image"],
                         fixture.exi_row["worker_image"])
        self.assertEqual(assessor.assess(fixture.compiled.task_contract_id), row)

    def test_missing_artifact_requests_evidence_only_not_source_replacement(self):
        fixture, _ = objecting_case(overrides={"forged": "extra"})
        row = OperationalSelfAssessment(fixture.wb.store).assess(
            fixture.compiled.task_contract_id)
        self.assertEqual(row["disposition"], "REVISED_SUBMISSION_REQUIRED")
        self.assertEqual(json.loads(row["permitted_changes_json"]),
                         ["execution_evidence"])
        preserved = json.loads(row["preserved_bindings_json"])
        self.assertEqual(preserved["candidate_sha256"],
                         fixture.exi_row["candidate_sha256"])
        self.assertIn("resubmission_preserves_candidate_source",
                      json.loads(row["required_checks_json"]))

    def test_third_cycle_assesses_to_terminal_escalation(self):
        fixture, _ = objecting_case(cycles=3)
        row = OperationalSelfAssessment(fixture.wb.store).assess(
            fixture.compiled.task_contract_id)
        self.assertEqual(row["disposition"], "ESCALATION_REQUIRED")
        self.assertEqual(json.loads(row["permitted_changes_json"]), [])
        checks = json.loads(row["required_checks_json"])
        self.assertIn("no_recovery_execution_authorized", checks)
        self.assertNotIn("replacement_uses_fresh_authorization_and_task_contract",
                         checks)

    def test_tampered_objection_is_refused_not_assessed(self):
        fixture, cycle = objecting_case()
        fixture.wb.store.execute_raw("DROP TRIGGER objection_cycles_no_update")
        fixture.wb.store.execute_raw(
            "UPDATE objection_cycles SET cycle_hash = ? WHERE cycle_id = ?",
            ("0" * 64, cycle["cycle_id"]))
        with self.assertRaises(OperationalAssessmentRefused):
            OperationalSelfAssessment(fixture.wb.store).assess(
                fixture.compiled.task_contract_id)
        self.assertIsNone(fixture.wb.store.one(
            "SELECT * FROM operational_assessments"))


if __name__ == "__main__":
    unittest.main()
