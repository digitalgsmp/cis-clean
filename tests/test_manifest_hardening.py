"""Runtime authority hardening for the reconstruction manifest.

These tests exercise the three hardening boundaries:

1. post-load immutability of canonical manifest state;
2. validation of proven_slice links against declared stages and selected modules;
3. fail-closed behavior when a recorded macro trajectory stage disagrees with
   the manifest current stage.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cis.authority import (
    AuthorizationAuthority, ContinuityAuthority, IntentAuthority,
    RunAuthority, TrajectoryAuthority,
)
from cis.authority.store import AuthorityStore
from cis.blueprint import load_blueprint
from cis.errors import BlueprintError, EvidenceConflict
from cis.workbench.projection import TrajectoryProjection

from . import support

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / "contracts"
MANIFEST_PATH = ROOT / "blueprint" / "reconstruction_manifest.json"

_IMMUTABLE_RE = r"does not support item assignment|no attribute|unsupported"


def _manifest_copy() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _load_temp_manifest(document: dict) -> None:
    """Write the document to a temp file and load it."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "manifest.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return load_blueprint(path, CONTRACTS_DIR)


class ManifestMutationTests(unittest.TestCase):
    """Canonical manifest state must be immutable after loading."""

    def test_document_cannot_be_mutated_at_any_depth(self):
        blueprint = support.blueprint()
        baseline = blueprint.baseline_hash

        with self.assertRaisesRegex((TypeError, AttributeError), _IMMUTABLE_RE):
            blueprint.document["blueprint_id"] = "EVIL"  # type: ignore[index]
        with self.assertRaisesRegex((TypeError, AttributeError), _IMMUTABLE_RE):
            blueprint.document["macro"]["current_stage"] = "EVIL"  # type: ignore[index]
        with self.assertRaisesRegex((TypeError, AttributeError), _IMMUTABLE_RE):
            blueprint.document["selected_modules"][0]["module_id"] = (  # type: ignore[index]
                "EVIL")
        with self.assertRaisesRegex((AttributeError, TypeError), _IMMUTABLE_RE):
            blueprint.document["selected_modules"].append({})  # type: ignore[attr-defined]

        self.assertEqual(blueprint.baseline_hash, baseline)
        self.assertEqual(blueprint.manifest_hash, support.blueprint().manifest_hash)

    def test_accessor_results_cannot_mutate_canonical_state(self):
        blueprint = support.blueprint()
        baseline = blueprint.baseline_hash

        stages = blueprint.stages
        with self.assertRaisesRegex((TypeError, AttributeError), _IMMUTABLE_RE):
            stages[0]["status"] = "EVIL"  # type: ignore[index]
        with self.assertRaisesRegex((TypeError, AttributeError), _IMMUTABLE_RE):
            stages[0] = {}  # type: ignore[index]

        selected = blueprint.selected_modules
        with self.assertRaisesRegex((TypeError, AttributeError), _IMMUTABLE_RE):
            selected[0]["module_id"] = "EVIL"  # type: ignore[index]

        proven = blueprint.proven_slice
        with self.assertRaisesRegex((TypeError, AttributeError), _IMMUTABLE_RE):
            proven["links"][0]["link_id"] = "EVIL"  # type: ignore[index]

        destination = blueprint.destination
        with self.assertRaisesRegex((AttributeError, TypeError), _IMMUTABLE_RE):
            destination["flow"].append({})  # type: ignore[attr-defined]

        self.assertEqual(blueprint.baseline_hash, baseline)


class ProvenSliceValidationTests(unittest.TestCase):
    """proven_slice links must name declared macro stages and selected modules."""

    def test_unknown_carried_by_module_fails_at_load(self):
        document = _manifest_copy()
        document["proven_slice"]["links"][0]["carried_by"].append(
            "cis.unknown.module")
        with self.assertRaises(EvidenceConflict) as caught:
            _load_temp_manifest(document)
        self.assertIn("carried_by", str(caught.exception.message).lower())

    def test_unknown_trajectory_stage_fails_at_load(self):
        document = _manifest_copy()
        document["proven_slice"]["links"][0]["trajectory_stage"] = "UNKNOWN_STAGE"
        with self.assertRaises(BlueprintError) as caught:
            _load_temp_manifest(document)
        self.assertIn("trajectory_stage", str(caught.exception.message).lower())


class RecordedMacroStageTests(unittest.TestCase):
    """A stale or unknown recorded macro stage must fail closed."""

    def _projection(self) -> TrajectoryProjection:
        store = support.fresh_store()
        return TrajectoryProjection(
            blueprint=support.blueprint(),
            trajectory=TrajectoryAuthority(store),
            intent=IntentAuthority(store),
            continuity=ContinuityAuthority(store),
            runs=RunAuthority(store),
            authorizations=AuthorizationAuthority(store),
        )

    def test_unknown_recorded_macro_stage_fails_closed(self):
        projection = self._projection()
        projection.trajectory.record(
            event_id="ev-macro-bad",
            scope="macro",
            stage="STEP_UNKNOWN",
            event_type="macro_stage_entered",
            detail={"test": True},
        )
        with self.assertRaises(EvidenceConflict) as caught:
            projection.journey()
        self.assertIn("absent", str(caught.exception.message).lower())

    def test_recorded_macro_stage_disagreement_fails_closed(self):
        projection = self._projection()
        projection.trajectory.record(
            event_id="ev-macro-wrong",
            scope="macro",
            stage="STEP_4_ARCHITECTURE_FREEZE",
            event_type="macro_stage_entered",
            detail={"test": True},
        )
        with self.assertRaises(EvidenceConflict) as caught:
            projection.journey()
        self.assertIn("disagree", str(caught.exception.message).lower())

    def test_valid_recorded_macro_stage_is_accepted(self):
        projection = self._projection()
        current = support.blueprint().current_stage
        projection.trajectory.record(
            event_id=f"ev-macro-{current}",
            scope="macro",
            stage=current,
            event_type="macro_stage_entered",
            detail={"test": True},
        )
        journey = projection.journey()
        self.assertEqual(journey["you_are_here"]["stage_id"], current)
        self.assertIsNone(journey["next_stage"])


if __name__ == "__main__":
    unittest.main()
