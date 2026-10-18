"""Projection-regeneration proof across every declared derived view."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from cis.authority import AuthorityStore
from cis.blueprint import load_blueprint
from cis.errors import BlueprintError, ProjectionRegenerationRefused
from cis.projection import ProjectionRegenerationGate
from cis.workbench import Workbench

from . import support


class ProjectionRegenerationTests(unittest.TestCase):
    def populated(self):
        wb, authorization_id = support.allow_and_run()
        support.assure(wb, authorization_id)
        return wb

    def test_every_declared_surface_regenerates_byte_identically(self):
        proof = ProjectionRegenerationGate(self.populated()).prove()
        self.assertEqual(proof.inventory, (
            "blueprint.summary", "contracts.registry",
            "workbench.trajectory", "assurance.progress"))
        self.assertEqual(set(proof.surface_hashes), set(proof.inventory))
        self.assertTrue(proof.byte_identical)
        self.assertTrue(proof.authority_unchanged)
        self.assertEqual(proof.passes, 2)

    def test_regeneration_is_repeatable_and_writes_nothing(self):
        wb = self.populated()
        gate = ProjectionRegenerationGate(wb)
        first = gate.prove()
        second = gate.prove()
        self.assertEqual(first.as_dict(), second.as_dict())
        self.assertEqual(first.authority_digest, second.authority_digest)

    def test_authority_change_changes_only_the_relevant_surface_set(self):
        wb = self.populated()
        before = ProjectionRegenerationGate(wb).prove()
        wb.submit_instruction("What does the projection show now?")
        after = ProjectionRegenerationGate(wb).prove()
        self.assertNotEqual(before.authority_digest, after.authority_digest)
        self.assertNotEqual(before.surface_set_hash, after.surface_set_hash)
        self.assertNotEqual(before.surface_hashes["workbench.trajectory"],
                            after.surface_hashes["workbench.trajectory"])
        self.assertEqual(before.surface_hashes["blueprint.summary"],
                         after.surface_hashes["blueprint.summary"])
        self.assertEqual(before.surface_hashes["contracts.registry"],
                         after.surface_hashes["contracts.registry"])

    def test_a_write_during_regeneration_fails_closed(self):
        wb = self.populated()
        gate = ProjectionRegenerationGate(wb)
        original = gate._fresh_surfaces
        calls = 0

        def mutating_build():
            nonlocal calls
            result = original()
            calls += 1
            if calls == 1:
                wb.submit_instruction("What changed during regeneration?")
            return result

        gate._fresh_surfaces = mutating_build
        with self.assertRaises(ProjectionRegenerationRefused):
            gate.prove()

    def test_file_backed_cold_start_reproduces_the_surface_set(self):
        with tempfile.TemporaryDirectory(prefix="cis-projection-proof-") as directory:
            db_path = Path(directory) / "authority.db"
            store = AuthorityStore(db_path)
            wb = support.workbench(store=store)
            _, outcome = support.allow_outcome(wb)
            wb.execute(outcome.authorization["authorization_id"])
            support.assure(wb, outcome.authorization["authorization_id"])
            before = ProjectionRegenerationGate(wb).prove()
            store.close()

            reopened = AuthorityStore(db_path)
            restarted = Workbench(reopened, blueprint=support.blueprint())
            after = ProjectionRegenerationGate(restarted).prove()
            self.assertEqual(before.surface_hashes, after.surface_hashes)
            self.assertEqual(before.surface_set_hash, after.surface_set_hash)
            self.assertEqual(before.authority_digest, after.authority_digest)
            reopened.close()

    def test_no_projection_or_proof_table_is_persisted(self):
        wb = self.populated()
        ProjectionRegenerationGate(wb).prove()
        tables = {
            str(row["name"]) for row in wb.store.query(
                "SELECT name FROM sqlite_master WHERE type='table'")
        }
        for forbidden in ("projection", "regeneration", "proof", "view_cache"):
            self.assertFalse(any(forbidden in table for table in tables), tables)


class ProjectionInventoryValidationTests(unittest.TestCase):
    def test_omitting_a_surface_is_refused_at_manifest_load(self):
        document = copy.deepcopy(dict(support.blueprint().document))
        document["projection_regeneration"]["surfaces"].pop()
        with tempfile.TemporaryDirectory(prefix="cis-projection-manifest-") as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(BlueprintError):
                load_blueprint(path, support.CONTRACTS_DIR)

    def test_generated_projection_modules_are_covered_by_inventory(self):
        blueprint = support.blueprint()
        inventory = {
            str(item["module_id"])
            for item in blueprint.projection_regeneration["surfaces"]
        }
        generated = set(
            blueprint.document["preserved_capabilities"]["generated_projections"])
        self.assertTrue(generated.issubset(inventory))


if __name__ == "__main__":
    unittest.main()
