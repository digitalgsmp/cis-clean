"""The trajectory projection: macro, micro, and a derived you-are-here."""

import json
import unittest
from pathlib import Path

from cis.errors import AppendOnlyViolation

from . import support

MIGRATION = (Path(__file__).resolve().parents[1] / "src" / "cis" / "authority"
             / "migrations" / "0001_core_authority.sql")


class MacroProjectionTests(unittest.TestCase):
    def setUp(self):
        self.wb = support.workbench()

    def test_macro_exposes_the_current_reconstruction_stage(self):
        macro = self.wb.projection.macro()
        self.assertEqual(macro["current_stage"],
                         "STEP_7_RESUME_PIPELINE_BUILD")
        statuses = {stage["stage_id"]: stage["status"] for stage in macro["stages"]}
        self.assertEqual(statuses["STEP_4_ARCHITECTURE_FREEZE"], "COMPLETE")
        self.assertEqual(statuses["STEP_5_CLEAN_MODULAR_RECONSTRUCTION"], "COMPLETE")
        self.assertEqual(statuses["STEP_7_RESUME_PIPELINE_BUILD"], "ACTIVE")

    def test_macro_exposes_selected_module_progress_in_dependency_order(self):
        macro = self.wb.projection.macro()
        self.assertEqual(len(macro["modules"]), support.expected_module_count())
        positions = [m["dependency_position"] for m in macro["modules"]]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(macro["counts"]["selected"], support.expected_module_count())
        self.assertEqual(macro["counts"]["contracted"], support.expected_module_count())
        self.assertEqual(macro["counts"]["executed"], 0)

    def test_progress_advances_from_contracted_to_authorized_to_executed(self):
        _, outcome = support.allow_outcome(self.wb)
        target = outcome.authorization["target_module_id"]

        macro = self.wb.projection.macro()
        progress = {m["module_id"]: m["progress"] for m in macro["modules"]}
        self.assertEqual(progress[target], "AUTHORIZED")
        self.assertEqual(macro["counts"]["authorized"], 1)

        self.wb.execute(outcome.authorization["authorization_id"])
        macro = self.wb.projection.macro()
        progress = {m["module_id"]: m["progress"] for m in macro["modules"]}
        self.assertEqual(progress[target], "EXECUTED")
        self.assertEqual(macro["counts"]["executed"], 1)

    def test_macro_carries_the_deferred_modules_rather_than_hiding_them(self):
        macro = self.wb.projection.macro()
        self.assertTrue(macro["deferred_modules"])
        for entry in macro["deferred_modules"]:
            self.assertIn("DEFERRED", entry["reconstruction_status"])


class MicroProjectionTests(unittest.TestCase):
    def setUp(self):
        self.wb, self.outcome = support.allow_outcome()
        self.transaction_id = self.outcome.transaction_id

    def test_micro_exposes_the_steps_of_one_transaction_in_order(self):
        micro = self.wb.projection.micro(self.transaction_id)
        stages = [step["stage"] for step in micro["steps"]]
        self.assertEqual(stages, [
            "HUMAN_INTENT", "AUTHORITATIVE_CONTEXT", "CONTINUITY",
            "REVIEW_AUTHORIZATION",
        ])
        seqs = [step["seq"] for step in micro["steps"]]
        self.assertEqual(seqs, sorted(seqs))

    def test_micro_carries_the_verbatim_and_the_labeled_interpretation(self):
        micro = self.wb.projection.micro(self.transaction_id)
        self.assertEqual(micro["verbatim"], support.ALLOW_INSTRUCTION)
        self.assertEqual(micro["interpretation"]["label"],
                         "DERIVATIVE_INTERPRETATION_SOURCE_LINKED")
        self.assertNotEqual(micro["interpretation"]["text"], micro["verbatim"])

    def test_micro_grows_with_execution(self):
        before = len(self.wb.projection.micro(self.transaction_id)["steps"])
        self.wb.execute(self.outcome.authorization["authorization_id"])
        after = self.wb.projection.micro(self.transaction_id)["steps"]
        self.assertEqual(len(after), before + 2)
        self.assertEqual([s["stage"] for s in after[-2:]],
                         ["GOVERNED_EXECUTION", "EVIDENCE"])

    def test_micro_for_an_unknown_transaction_is_empty_not_invented(self):
        micro = self.wb.projection.micro("tx-nonexistent")
        self.assertEqual(micro["steps"], [])
        self.assertIsNone(micro["verbatim"])


class JourneyProjectionTests(unittest.TestCase):
    def setUp(self):
        self.wb = support.workbench()

    def test_journey_exposes_destination_and_ordered_plain_language_stages(self):
        journey = self.wb.projection.journey()
        self.assertEqual(journey["destination"], self.wb.blueprint.destination)
        self.assertEqual(
            [stage["stage_id"] for stage in journey["stages"]],
            [stage["stage_id"] for stage in self.wb.blueprint.stages],
        )
        self.assertTrue(all(stage["plain_language"] for stage in journey["stages"]))

    def test_current_and_next_stage_are_derived_from_the_authoritative_sequence(self):
        journey = self.wb.projection.journey()
        current = [stage for stage in journey["stages"] if stage["is_current"]]
        self.assertEqual(len(current), 1)
        self.assertEqual(current[0]["stage_id"],
                         journey["you_are_here"]["stage_id"])
        self.assertEqual(current[0]["stage_id"],
                         "STEP_7_RESUME_PIPELINE_BUILD")
        self.assertIsNone(journey["next_stage"])

    def test_proven_slice_achievement_is_derived_from_recorded_events(self):
        before = self.wb.projection.journey()["proven_slice"]
        self.assertEqual(before["achieved"], 0)

        _, outcome = support.allow_outcome(self.wb)
        after_authorization = self.wb.projection.journey()["proven_slice"]
        self.assertEqual(after_authorization["achieved"], 3)

        self.wb.execute(outcome.authorization["authorization_id"])
        after_execution = self.wb.projection.journey()["proven_slice"]
        self.assertEqual(after_execution["achieved"], after_execution["total"])
        self.assertTrue(all(link["achieved"] for link in after_execution["links"]))

    def test_reading_the_journey_never_writes_progress(self):
        before = self.wb.trajectory.count()
        for _ in range(3):
            self.wb.projection.journey()
        self.assertEqual(self.wb.trajectory.count(), before)


class YouAreHereTests(unittest.TestCase):
    def test_the_marker_is_derived_from_the_highest_sequence_event(self):
        wb, outcome = support.allow_outcome()
        wb.execute(outcome.authorization["authorization_id"])
        marker = wb.projection.you_are_here()
        latest = wb.trajectory.latest()
        self.assertEqual(marker["seq"], int(latest["seq"]))
        self.assertEqual(marker["derived_from"],
                         f"trajectory_events:seq={int(latest['seq'])}")
        self.assertEqual(marker["event_type"], "execution_completed")
        self.assertEqual(marker["micro_stage"], "EVIDENCE")
        self.assertEqual(marker["macro_stage"],
                         "STEP_7_RESUME_PIPELINE_BUILD")

    def test_the_marker_moves_only_when_authority_moves(self):
        wb = support.workbench()
        first = wb.projection.you_are_here()
        self.assertEqual(wb.projection.you_are_here(), first)
        wb.submit_instruction("What is the current stage?")
        second = wb.projection.you_are_here()
        self.assertGreater(second["seq"], first["seq"])

    def test_the_marker_is_never_stored(self):
        """No column anywhere holds a position; the marker is computed."""
        schema = MIGRATION.read_text(encoding="utf-8").lower()
        for forbidden in ("you_are_here", "current_position", "is_current",
                          "current_stage", "is_active", "latest"):
            self.assertNotIn(forbidden, schema)

    def test_with_no_events_the_marker_reports_no_position(self):
        store = support.fresh_store()
        from cis.authority import (
            AuthorizationAuthority, ContinuityAuthority, IntentAuthority,
            RunAuthority, TrajectoryAuthority,
        )
        from cis.workbench.projection import TrajectoryProjection
        projection = TrajectoryProjection(
            blueprint=support.blueprint(),
            trajectory=TrajectoryAuthority(store),
            intent=IntentAuthority(store),
            continuity=ContinuityAuthority(store),
            runs=RunAuthority(store),
            authorizations=AuthorizationAuthority(store),
        )
        marker = projection.you_are_here()
        self.assertEqual(marker["derived_from"], "trajectory_events:none")
        self.assertIsNone(marker["seq"])
        self.assertEqual(marker["macro_stage"],
                         "STEP_7_RESUME_PIPELINE_BUILD")


class AppendOnlyProjectionTests(unittest.TestCase):
    def test_trajectory_events_cannot_be_rewritten_or_removed(self):
        wb, outcome = support.allow_outcome()
        wb.execute(outcome.authorization["authorization_id"])
        before = wb.trajectory.count()
        with self.assertRaises(AppendOnlyViolation):
            wb.store.execute_raw("UPDATE trajectory_events SET stage = 'DONE'")
        with self.assertRaises(AppendOnlyViolation):
            wb.store.execute_raw("DELETE FROM trajectory_events")
        self.assertEqual(wb.trajectory.count(), before)

    def test_the_macro_stage_is_recorded_once_not_on_every_instruction(self):
        wb = support.workbench()
        for i in range(3):
            wb.submit_instruction(f"What about point {i}?")
        macro_events = wb.trajectory.events(scope="macro")
        self.assertEqual(len(macro_events), 1)
        detail = json.loads(str(macro_events[0]["detail_json"]))
        self.assertEqual(detail["selected_module_count"], support.expected_module_count())

    def test_the_projection_is_regenerated_and_never_written_back(self):
        wb, outcome = support.allow_outcome()
        before = wb.trajectory.count()
        for _ in range(3):
            wb.projection.full(outcome.transaction_id)
        self.assertEqual(wb.trajectory.count(), before)


if __name__ == "__main__":
    unittest.main()
