"""Append-only policy-source ingestion proofs."""

from __future__ import annotations

import unittest

from cis.errors import (
    PolicyInvalidSupersession, PolicySourceConflict, PolicyTampered,
)
from cis.policy.sources import PolicySourceAuthority

from . import support


def raw_master(policy_id="MASTER-A", **changes):
    document = {
        "policy_id": policy_id, "lineage_id": policy_id, "kind": "MASTER",
        "version": 1, "status": "ACTIVE", "supersedes": None,
        "conflicts_with": [], "selector": None, "effect_kinds": ["PROHIBIT"],
        "prohibited_actions": ["network:any"], "required_checks": [],
        "required_evidence": [], "narrowed_scope": None, "hold": False,
        "rationale": "test master", "evidence_basis": ["TEST"],
    }
    document.update(changes)
    return document


class PolicySourceAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.wb = support.workbench()
        self.sources = PolicySourceAuthority(self.wb.store)

    def test_idempotent_identical_ingestion_is_a_no_op(self):
        first = self.sources.ingest(raw_master(), provenance="test:one")
        second = self.sources.ingest(raw_master(), provenance="test:one")
        self.assertEqual(first["policy_source_id"], second["policy_source_id"])
        rows = self.wb.store.query("SELECT * FROM policy_sources")
        self.assertEqual(len(rows), 1)

    def test_idempotent_ingestion_tolerates_different_provenance(self):
        first = self.sources.ingest(raw_master(), provenance="test:one")
        second = self.sources.ingest(raw_master(), provenance="test:two")
        self.assertEqual(first["policy_source_id"], second["policy_source_id"])
        self.assertEqual(str(second["provenance"]), "test:one")

    def test_changed_content_under_same_policy_id_refuses(self):
        self.sources.ingest(raw_master(), provenance="test:one")
        with self.assertRaises(PolicySourceConflict):
            self.sources.ingest(
                raw_master(rationale="a different rationale"),
                provenance="test:one",
            )
        rows = self.wb.store.query("SELECT * FROM policy_sources")
        self.assertEqual(len(rows), 1)

    def test_blank_provenance_refuses(self):
        with self.assertRaises(PolicySourceConflict):
            self.sources.ingest(raw_master(), provenance="   ")

    def test_current_policy_set_derives_exactly_the_ingested_documents(self):
        self.sources.ingest(raw_master("MASTER-A"), provenance="test:a")
        self.sources.ingest(
            raw_master("MASTER-B", prohibited_actions=["model:any"]),
            provenance="test:b",
        )
        policy_set = self.sources.current_policy_set()
        self.assertEqual(
            sorted(doc.policy_id for doc in policy_set.documents),
            ["MASTER-A", "MASTER-B"],
        )
        self.assertEqual(len(policy_set.active_masters()), 2)
        # Derivation is from stored rows alone, and is stable across calls.
        self.assertEqual(
            self.sources.current_policy_set().active_masters(),
            policy_set.active_masters(),
        )

    def test_empty_ledger_derives_an_empty_but_valid_policy_set(self):
        policy_set = self.sources.current_policy_set()
        self.assertEqual(policy_set.documents, ())
        self.assertEqual(policy_set.active_masters(), ())

    def test_forged_stored_row_refuses_on_derivation(self):
        self.sources.ingest(raw_master(), provenance="test:one")
        self.wb.store.execute_raw("DROP TRIGGER policy_sources_no_update")
        self.wb.store.execute_raw(
            "UPDATE policy_sources SET prohibited_actions_json = '[]' "
            "WHERE policy_id = 'MASTER-A'"
        )
        with self.assertRaises(PolicyTampered):
            self.sources.current_policy_set()

    def test_active_policy_can_evolve_by_forward_supersession(self):
        v1 = raw_master("MASTER-V1", lineage_id="master-lineage", version=1)
        v2 = raw_master("MASTER-V2", lineage_id="master-lineage", version=2,
                        supersedes="MASTER-V1",
                        prohibited_actions=["network:any", "model:any"])
        self.sources.ingest(v1, provenance="test:v1")
        self.sources.ingest(v2, provenance="test:v2")
        current = self.sources.current_policy_set()
        self.assertEqual([doc.policy_id for doc in current.active_masters()],
                         ["MASTER-V2"])
        self.assertEqual(len(self.wb.store.query("SELECT * FROM policy_sources")), 2)

    def test_invalid_update_is_refused_before_any_append(self):
        self.sources.ingest(raw_master("MASTER-V1", lineage_id="line", version=1),
                            provenance="test:v1")
        with self.assertRaises(PolicyInvalidSupersession):
            self.sources.ingest(
                raw_master("MASTER-V2", lineage_id="line", version=1,
                           supersedes="MASTER-V1"), provenance="test:bad")
        self.assertEqual(len(self.wb.store.query("SELECT * FROM policy_sources")), 1)

    def test_mutual_conflict_batch_is_admitted_atomically(self):
        a = raw_master("MASTER-A", lineage_id="a", conflicts_with=["b"])
        b = raw_master("MASTER-B", lineage_id="b", conflicts_with=["a"])
        rows = self.sources.ingest_many((a, b), provenance="test:batch")
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(self.wb.store.query("SELECT * FROM policy_sources")), 2)

    def test_invalid_batch_leaves_no_prefix(self):
        good = raw_master("MASTER-GOOD")
        bad = raw_master("MASTER-BAD", lineage_id="bad", version=2,
                         supersedes="MISSING")
        with self.assertRaises(PolicyInvalidSupersession):
            self.sources.ingest_many((good, bad), provenance="test:batch")
        self.assertEqual(self.wb.store.query("SELECT * FROM policy_sources"), [])


if __name__ == "__main__":
    unittest.main()
