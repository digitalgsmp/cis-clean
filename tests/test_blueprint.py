"""The reconstruction blueprint is operational input, not prose."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from cis.blueprint import STAGE_STATUSES, load_blueprint
from cis.blueprint.manifest import IN_SCOPE_RECONSTRUCTION_STATUSES
from cis.errors import BlueprintError, EvidenceConflict

from . import support


def _write(document: dict) -> Path:
    directory = Path(tempfile.mkdtemp(prefix="cis-clean-blueprint-"))
    path = directory / "manifest.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class BlueprintTests(unittest.TestCase):
    def setUp(self):
        self.blueprint = support.blueprint()
        self.document = copy.deepcopy(dict(self.blueprint.document))

    def test_identifies_the_current_macro_stage(self):
        self.assertEqual(self.blueprint.current_stage,
                         "STEP_7_RESUME_PIPELINE_BUILD")
        stage = self.blueprint.stage(self.blueprint.current_stage)
        self.assertEqual(stage["status"], "ACTIVE")

    def test_every_stage_has_a_known_status_and_an_evidence_basis(self):
        for stage in self.blueprint.stages:
            self.assertIn(stage["status"], STAGE_STATUSES)
            self.assertTrue(stage["evidence_basis"])

    def test_identifies_selected_modules_with_status_and_evidence(self):
        """Every selected module is reconstructed and carries its basis.

        A later slice records its own status rather than rewriting the earlier
        one, so the assertion is membership in the in-scope set and not
        equality with a single slice: a slice-1 module's recorded status must
        never change because slice 2 happened.
        """
        self.assertEqual(len(self.blueprint.selected_module_ids), 29)
        for module_id in self.blueprint.selected_module_ids:
            self.assertIn(self.blueprint.reconstruction_status(module_id),
                          IN_SCOPE_RECONSTRUCTION_STATUSES)
            self.assertTrue(self.blueprint.evidence_basis(module_id))

    def test_slice_one_modules_kept_their_recorded_status(self):
        slice_one = [
            module_id for module_id in self.blueprint.selected_module_ids
            if self.blueprint.reconstruction_status(module_id)
            == "RECONSTRUCTED_IN_SLICE_001"
        ]
        self.assertEqual(len(slice_one), 18)
        for module_id in slice_one:
            self.assertEqual(self.blueprint.reconstruction_status(module_id),
                             "RECONSTRUCTED_IN_SLICE_001")

    def test_dependency_order_is_derived_not_stored(self):
        # The fact lives in the contracts; the manifest names its authority.
        raw = json.dumps(self.document["dependency_order"])
        self.assertIn("DERIVED", raw)
        for value in self.document["dependency_order"].values():
            self.assertNotIsInstance(value, list)
        self.assertEqual(self.blueprint.dependency_order(),
                         self.blueprint.registry.dependency_order())

    def test_deferred_modules_are_named_rather_than_silently_dropped(self):
        deferred = self.document["deferred_modules"]
        self.assertTrue(deferred)
        for entry in deferred:
            self.assertTrue(entry["reason"])
            self.assertTrue(entry["evidence_basis"])
            self.assertNotIn(entry["module_id"], self.blueprint.registry.contracts)

    def test_every_selected_module_has_a_canonical_authorization_basis(self):
        for module_id in self.blueprint.selected_module_ids:
            basis = self.blueprint.canonical_authorization_basis(module_id)
            self.assertIsNotNone(basis, module_id)
            self.assertTrue(basis.evidence_basis, module_id)
            self.assertEqual(basis.module_id, module_id)
            self.assertEqual(basis.baseline_hash, self.blueprint.baseline_hash)
            for entry in basis.required_evidence:
                self.assertTrue(
                    entry.startswith(f"canonical_evidence_basis:{module_id}:"))

    def test_an_unselected_module_has_no_canonical_basis(self):
        self.assertIsNone(
            self.blueprint.canonical_authorization_basis("cis.review.independent"))
        self.assertIsNone(
            self.blueprint.canonical_authorization_basis("cis.not.a.module"))

    def test_baseline_hash_covers_manifest_and_contracts(self):
        baseline = self.blueprint.baseline_hash
        self.assertEqual(baseline, support.blueprint().baseline_hash)
        mutated = copy.deepcopy(self.document)
        mutated["title"] = mutated["title"] + " (edited)"
        other = load_blueprint(_write(mutated), support.CONTRACTS_DIR)
        self.assertNotEqual(other.baseline_hash, baseline)

    def test_reference_environment_is_declared_read_only(self):
        reference = self.document["reference_environment"]
        self.assertEqual(reference["path"], "/mnt/projects/cis")
        self.assertEqual(reference["role"], "READ-ONLY EVIDENCE")


class BlueprintRefusalTests(unittest.TestCase):
    def setUp(self):
        self.document = copy.deepcopy(dict(support.blueprint().document))

    def _refuse(self, mutate, expected=BlueprintError):
        mutated = copy.deepcopy(self.document)
        mutate(mutated)
        with self.assertRaises(expected):
            load_blueprint(_write(mutated), support.CONTRACTS_DIR)

    def test_missing_section_is_refused(self):
        self._refuse(lambda d: d.pop("macro"))

    def test_literal_dependency_order_is_refused(self):
        self._refuse(lambda d: d["dependency_order"].update(
            {"order": ["cis.authority.store"]}))

    def test_non_derived_dependency_order_is_refused(self):
        self._refuse(lambda d: d["dependency_order"].update(
            {"representation": "STORED"}))

    def test_unknown_stage_status_is_refused(self):
        self._refuse(lambda d: d["macro"]["stages"][0].update({"status": "DONE"}))

    def test_current_stage_must_exist(self):
        self._refuse(lambda d: d["macro"].update({"current_stage": "STEP_99"}))

    def test_two_active_stages_is_a_recorded_evidence_conflict(self):
        self._refuse(
            lambda d: d["macro"]["stages"][0].update({"status": "ACTIVE"}),
            EvidenceConflict,
        )

    def test_selecting_an_uncontracted_module_is_an_evidence_conflict(self):
        def mutate(d):
            d["selected_modules"].append({
                "module_id": "cis.not.built",
                "contract": "contracts/cis.not.built.contract.json",
                "reconstruction_status": "RECONSTRUCTED_IN_SLICE_001",
                "capability": "nothing",
                "evidence_basis": ["none"],
            })
        self._refuse(mutate, EvidenceConflict)

    def test_dropping_a_contracted_module_is_an_evidence_conflict(self):
        self._refuse(lambda d: d["selected_modules"].pop(), EvidenceConflict)

    def test_unknown_reconstruction_status_is_refused(self):
        self._refuse(lambda d: d["selected_modules"][0].update(
            {"reconstruction_status": "DONE"}))

    def test_a_module_cannot_be_both_deferred_and_contracted(self):
        self._refuse(
            lambda d: d["deferred_modules"].append({
                "module_id": "cis.interface.api",
                "reconstruction_status": "DEFERRED_NEXT_SLICE",
                "reason": "contradiction",
                "evidence_basis": ["none"],
            }),
            EvidenceConflict,
        )

    def test_an_empty_canonical_evidence_basis_is_refused(self):
        """The exact boundary: one non-blank reference, or no manifest at all.

        A selected module's evidence_basis IS the canonical authorization basis
        for that module, so an empty, blank, non-list or missing one is refused
        at load rather than producing a module nothing can be authorized
        against.
        """
        for emptied in ([], [""], ["   "], "handoff A18", None):
            with self.subTest(evidence_basis=emptied):
                self._refuse(lambda d, v=emptied: d["selected_modules"][0]
                             .update({"evidence_basis": v}))

    def test_a_single_non_blank_reference_is_enough(self):
        mutated = copy.deepcopy(self.document)
        mutated["selected_modules"][0]["evidence_basis"] = ["handoff A26"]
        loaded = load_blueprint(_write(mutated), support.CONTRACTS_DIR)
        module_id = mutated["selected_modules"][0]["module_id"]
        basis = loaded.canonical_authorization_basis(module_id)
        self.assertIsNotNone(basis)
        self.assertEqual(basis.evidence_basis, ("handoff A26",))

    def test_missing_manifest_is_refused(self):
        with self.assertRaises(BlueprintError):
            load_blueprint("/nonexistent/manifest.json", support.CONTRACTS_DIR)


if __name__ == "__main__":
    unittest.main()
