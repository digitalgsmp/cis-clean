"""The clean authority: migrations, append-only enforcement, isolation."""

import tempfile
import unittest
from pathlib import Path

from cis.authority import (
    AuthorityStore, ContinuityAuthority, EvidenceAuthority, IntentAuthority,
    MIGRATIONS_DIR,
)
from cis.errors import AppendOnlyViolation, CisError

from . import support

#: Derived from the migration files, so the table a later migration adds is
#: covered by the append-only proof instead of being forgotten here.
_APPEND_ONLY_TABLES = tuple(sorted(support.authority_tables()))

#: The migrations this suite describes. Named so an undeclared addition fails
#: loudly rather than being absorbed by a derived count, and never limited to
#: migration 0001.
_EXPECTED_MIGRATIONS = [
    "0001_core_authority",
    "0002_append_only_triggers",
    "0003_conductor_envelope",
    "0004_assurance_increment",
    "0005_contained_worker_host_handoff",
    "0006_execution_attempt_claims",
    "0007_policy_envelopes",
    "0008_policy_sources",
]


class MigrationTests(unittest.TestCase):
    def test_migrations_apply_in_order(self):
        store = support.fresh_store()
        self.assertEqual(store.applied_migrations(), _EXPECTED_MIGRATIONS)
        self.assertEqual(store.applied_migrations(), support.migration_ids())

    def test_migrations_are_idempotent(self):
        store = support.fresh_store()
        self.assertEqual(store.migrate(), [])
        self.assertEqual(len(store.applied_migrations()),
                         len(support.migration_ids()))

    def test_migration_files_are_hashed_and_a_changed_file_is_refused(self):
        directory = Path(tempfile.mkdtemp(prefix="cis-clean-mig-"))
        path = directory / "0001_x.sql"
        path.write_text("CREATE TABLE t (a TEXT);", encoding="utf-8")
        store = AuthorityStore(":memory:")
        store.migrate(directory)
        path.write_text("CREATE TABLE t (a TEXT, b TEXT);", encoding="utf-8")
        with self.assertRaises(CisError):
            store.migrate(directory)

    def test_migration_file_count_matches_the_directory(self):
        self.assertEqual(support.migration_ids(), _EXPECTED_MIGRATIONS)
        self.assertEqual(len(sorted(MIGRATIONS_DIR.glob("*.sql"))),
                         len(_EXPECTED_MIGRATIONS))

    def test_a_file_backed_authority_persists_and_resumes_its_sequence(self):
        directory = Path(tempfile.mkdtemp(prefix="cis-clean-db-"))
        path = directory / "nested" / "authority.db"
        first = AuthorityStore(path)
        IntentAuthority(first).record_objective(
            objective_id="obj-1", statement="x", established_by="tx-1")
        first.close()

        second = AuthorityStore(path)
        self.assertEqual(second.applied_migrations(), _EXPECTED_MIGRATIONS)
        intent = IntentAuthority(second)
        self.assertIsNotNone(intent.objective("obj-1"))
        row = intent.record_objective(
            objective_id="obj-2", statement="y", established_by="tx-2")
        self.assertEqual(int(row["seq"]), 2)
        second.close()


class IsolationTests(unittest.TestCase):
    def test_opening_an_authority_in_the_reference_environment_is_refused(self):
        for path in ("/mnt/projects/cis/clean.db",
                     "/mnt/projects/cis/data/anything.db",
                     "/mnt/projects/cis"):
            with self.assertRaises(CisError) as caught:
                AuthorityStore(path)
            self.assertIn("reference environment", caught.exception.message)

    def test_the_clean_environment_is_allowed(self):
        directory = Path(tempfile.mkdtemp(prefix="cis-clean-ok-"))
        store = AuthorityStore(directory / "authority.db")
        store.close()


class AppendOnlyTests(unittest.TestCase):
    """Every authority table is seeded first, because a BEFORE trigger fires
    per row: a statement against an empty table changes nothing and therefore
    proves nothing."""

    def setUp(self):
        wb, self.outcome, self.run = support.exercised_workbench()
        self.store = wb.store
        self.intent = wb.intent
        self.evidence = wb.evidence
        self.intent.record_instruction(transaction_id="tx-1", verbatim="hello",
                                       interpretation="greeting", actor="operator")
        self.evidence.admit(
            evidence_id="evi-1", kind="note", source_ref="ref",
            content="observed", admission_basis="test:trusted-import")

    def test_every_append_only_table_was_actually_seeded(self):
        for table in _APPEND_ONLY_TABLES:
            row = self.store.one(f"SELECT COUNT(*) AS n FROM {table}")
            self.assertGreater(int(row["n"]), 0, table)

    def test_update_is_refused_on_every_authority_table(self):
        for table in _APPEND_ONLY_TABLES:
            with self.assertRaises(AppendOnlyViolation, msg=table):
                if table == "schema_migrations":
                    self.store.execute_raw(
                        "UPDATE schema_migrations SET applied_at = 'changed'")
                else:
                    self.store.execute_raw(f"UPDATE {table} SET seq = seq + 1000")

    def test_delete_is_refused_on_every_authority_table(self):
        for table in _APPEND_ONLY_TABLES:
            with self.assertRaises(AppendOnlyViolation, msg=table):
                self.store.execute_raw(f"DELETE FROM {table}")

    def test_the_verbatim_instruction_cannot_be_rewritten(self):
        with self.assertRaises(AppendOnlyViolation):
            self.store.execute_raw(
                "UPDATE intent_transactions SET verbatim_instruction = ? "
                "WHERE transaction_id = ?", ("something else", "tx-1"))
        row = self.intent.transaction("tx-1")
        self.assertEqual(row["verbatim_instruction"], "hello")

    def test_evidence_cannot_be_amended(self):
        with self.assertRaises(AppendOnlyViolation):
            self.store.execute_raw("UPDATE evidence_records SET content = 'x'")
        self.assertEqual(self.evidence.get("evi-1")["content"], "observed")

    def test_duplicate_primary_key_is_refused(self):
        with self.assertRaises(CisError):
            self.intent.record_instruction(
                transaction_id="tx-1", verbatim="again",
                interpretation="dup", actor="operator")

    def test_foreign_keys_are_enforced(self):
        continuity = ContinuityAuthority(self.store)
        with self.assertRaises(CisError):
            continuity.record_decision(
                decision_id="dec-x", transaction_id="tx-missing",
                classification="question", treated_as="retrieval_cue",
                prior_objective_id=None,
                active_objective_id=self.outcome.objective["objective_id"],
                antecedents=[], disposition="d", rationale="r")

    def test_sequence_is_unique_and_monotonic_across_tables(self):
        seqs = []
        for table in _APPEND_ONLY_TABLES:
            if table == "schema_migrations":
                continue
            seqs += [int(row["seq"]) for row in
                     self.store.query(f"SELECT seq FROM {table}")]
        self.assertEqual(len(seqs), len(set(seqs)))
        self.assertEqual(sorted(seqs), list(range(1, len(seqs) + 1)))


class ConflictTests(unittest.TestCase):
    def test_a_conflict_is_recorded_and_never_resolved_in_place(self):
        store = support.fresh_store()
        evidence = EvidenceAuthority(store)
        evidence.record_conflict(conflict_id="cf-1", subject="two owners",
                                 detail={"authority": "t", "owners": ["a", "b"]})
        rows = evidence.conflicts()
        self.assertEqual(len(rows), 1)
        self.assertIn("owners", rows[0]["detail_json"])
        with self.assertRaises(AppendOnlyViolation):
            store.execute_raw("UPDATE evidence_conflicts SET subject = 'resolved'")


if __name__ == "__main__":
    unittest.main()
