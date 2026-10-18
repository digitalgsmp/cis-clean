"""The Workbench service: the whole chain for one instruction."""

import unittest

from cis.authority.authorization import ALLOW, HOLD
from cis.errors import ExecutionRefused

from . import support


class ChainTests(unittest.TestCase):
    def setUp(self):
        self.wb = support.workbench()

    def test_one_instruction_produces_exactly_one_of_each_record(self):
        outcome = self.wb.submit_instruction(support.ALLOW_INSTRUCTION)
        self.assertEqual(len(self.wb.intent.history()), 1)
        self.assertEqual(
            len(self.wb.continuity.for_transaction(outcome.transaction_id)), 1)
        self.assertEqual(len(self.wb.authorizations.all()), 1)

    def test_the_authorization_binds_to_this_instruction_and_this_decision(self):
        outcome = self.wb.submit_instruction(support.ALLOW_INSTRUCTION)
        authorization = self.wb.authorizations.get(
            outcome.authorization["authorization_id"])
        intent = self.wb.intent.transaction(outcome.transaction_id)
        decision = self.wb.continuity.decision(outcome.decision["decision_id"])
        self.assertEqual(authorization["transaction_id"], outcome.transaction_id)
        self.assertEqual(authorization["verbatim_hash"], intent["verbatim_hash"])
        self.assertEqual(authorization["decision_hash"], decision["decision_hash"])
        self.assertEqual(authorization["baseline_hash"],
                         self.wb.blueprint.baseline_hash)

    def test_the_outcome_is_self_describing(self):
        outcome = self.wb.submit_instruction(support.ALLOW_INSTRUCTION)
        payload = outcome.as_dict()
        for key in ("transaction_id", "verbatim", "interpretation",
                    "interpretation_label", "classification", "objective",
                    "antecedents", "antecedents_role", "authorization_basis",
                    "continuity_decision", "authorization"):
            self.assertIn(key, payload)
        self.assertEqual(payload["verbatim"], support.ALLOW_INSTRUCTION)

    def test_the_verdict_is_hold_by_default_when_nothing_qualifies(self):
        wb = support.workbench(with_evidence=False, with_objective=False)
        outcome = wb.submit_instruction("Do whatever seems best")
        self.assertEqual(outcome.authorization["verdict"], HOLD)

    def test_a_second_instruction_with_the_same_words_is_a_distinct_transaction(self):
        first = self.wb.submit_instruction(support.ALLOW_INSTRUCTION)
        second = self.wb.submit_instruction(support.ALLOW_INSTRUCTION)
        self.assertNotEqual(first.transaction_id, second.transaction_id)
        self.assertEqual(len(self.wb.intent.history()), 2)

    def test_execution_is_separate_from_authorization(self):
        outcome = self.wb.submit_instruction(support.ALLOW_INSTRUCTION)
        self.assertEqual(outcome.authorization["verdict"], ALLOW)
        self.assertEqual(self.wb.runs.all(), [])
        self.wb.execute(outcome.authorization["authorization_id"])
        self.assertEqual(len(self.wb.runs.all()), 1)

    def test_one_allow_authorizes_exactly_one_run(self):
        """Re-dispatch is refused, not quietly repeated."""
        outcome = self.wb.submit_instruction(support.ALLOW_INSTRUCTION)
        authorization_id = outcome.authorization["authorization_id"]
        first = self.wb.execute(authorization_id)
        with self.assertRaises(ExecutionRefused) as caught:
            self.wb.execute(authorization_id)
        self.assertEqual(caught.exception.detail["run_id"], first["run_id"])
        self.assertEqual(len(self.wb.runs.for_authorization(authorization_id)), 1)
        self.assertEqual(first["result_hash"],
                         str(self.wb.runs.get(first["run_id"])["result_hash"]))


class DeterminismTests(unittest.TestCase):
    def test_two_identical_sessions_produce_identical_authority(self):
        def session():
            wb = support.workbench()
            outcome = wb.submit_instruction(
                "I vaguely remember something about concepts going dormant")
            allow = wb.submit_instruction(support.ALLOW_INSTRUCTION)
            run = wb.execute(allow.authorization["authorization_id"])
            return {
                "cue": outcome.as_dict(),
                "allow": allow.as_dict(),
                "run": run,
                "trajectory": [
                    dict(row.as_dict()) for row in wb.trajectory.events()
                ],
            }

        self.assertEqual(session(), session())

    def test_the_baseline_hash_is_stable_across_instances(self):
        self.assertEqual(support.workbench().blueprint.baseline_hash,
                         support.workbench().blueprint.baseline_hash)


class ReferenceEnvironmentTests(unittest.TestCase):
    def test_every_allow_forbids_writing_to_the_reference_environment(self):
        _, outcome = support.allow_outcome()
        self.assertIn("write:/mnt/projects/cis",
                      outcome.authorization["scope"]["forbidden_actions"])

    def test_the_slice_never_names_a_reference_environment_database(self):
        from pathlib import Path
        src = Path(__file__).resolve().parents[1] / "src"
        for path in src.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("cis_memory.db", text, path.name)
            self.assertNotIn("cis_spine.db", text, path.name)


if __name__ == "__main__":
    unittest.main()
