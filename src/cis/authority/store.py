"""The clean SQLite authority: connection, migration ledger, and the single
sanctioned mutation primitive every authority module writes through.

A governed writer mutates authority through this interface, never through a
direct filesystem SQLite write (handoff A21). Every write is an append;
UPDATE and DELETE are refused by trigger (migration 0002), so immutability is
enforced by the store rather than self-reported by its callers.

This module owns exactly one authority: ``schema_migrations``. Every other
table is owned by the authority module named in migration 0001, which writes
it through ``insert`` here.

Nothing in this module reads, writes, opens or names any database under
/mnt/projects/cis. The reference environment is evidence, not a target.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..canonical import sha256_text
from ..errors import AppendOnlyViolation, CisError

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

#: A deterministic clock. Wall-clock time would make every hash in the slice
#: irreproducible, so time is a logical monotonic counter from a fixed origin.
DEFAULT_EPOCH = "2026-10-13T00:00:00Z"

_REFERENCE_ENVIRONMENT = "/mnt/projects/cis"


@dataclass(frozen=True)
class Row(Mapping):
    """A read-only mapping view of one authority row."""

    _data: dict

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def as_dict(self) -> dict:
        return dict(self._data)


class AuthorityStore:
    def __init__(self, path: str | Path, *, epoch: str = DEFAULT_EPOCH) -> None:
        self.path = str(path)
        self._guard_reference_environment(self.path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._epoch = epoch
        self._tick = 0
        self._seq = 0
        self.migrate()
        self._seq = self._max_seq()

    @staticmethod
    def _guard_reference_environment(path: str) -> None:
        resolved = str(Path(path).resolve()) if path != ":memory:" else path
        if resolved == _REFERENCE_ENVIRONMENT or resolved.startswith(
            _REFERENCE_ENVIRONMENT + "/"
        ):
            raise CisError(
                "refusing to open an authority inside the read-only reference "
                "environment",
                path=path,
                reference_environment=_REFERENCE_ENVIRONMENT,
            )

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "AuthorityStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- migrations ---------------------------------------------------------

    def migrate(self, migrations_dir: Path | None = None) -> list[str]:
        """Apply unapplied migrations in filename order. Idempotent."""
        directory = migrations_dir or MIGRATIONS_DIR
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                migration_id TEXT PRIMARY KEY,
                sha256       TEXT NOT NULL,
                applied_at   TEXT NOT NULL
            )
            """
        )
        applied = {
            row["migration_id"]: row["sha256"]
            for row in self._conn.execute("SELECT * FROM schema_migrations")
        }
        newly: list[str] = []
        for file_path in sorted(directory.glob("*.sql")):
            migration_id = file_path.stem
            body = file_path.read_text(encoding="utf-8")
            digest = sha256_text(body)
            if migration_id in applied:
                if applied[migration_id] != digest:
                    raise CisError(
                        "applied migration no longer matches its recorded hash",
                        migration_id=migration_id,
                    )
                continue
            with self._conn:
                self._conn.executescript(body)
                self._conn.execute(
                    "INSERT INTO schema_migrations VALUES (?, ?, ?)",
                    (migration_id, digest, self.now()),
                )
            newly.append(migration_id)
        return newly

    def applied_migrations(self) -> list[str]:
        return [
            row["migration_id"]
            for row in self._conn.execute(
                "SELECT migration_id FROM schema_migrations ORDER BY migration_id"
            )
        ]

    # -- primitives ---------------------------------------------------------

    _SEQ_TABLES = (
        "objectives", "intent_transactions", "continuity_decisions",
        "evidence_records", "evidence_conflicts", "execution_authorizations",
        "backend_runs", "execution_attempt_claims", "trajectory_events",
        "conductor_envelopes",
        # Slice-2 assurance increment (migration 0004). Listed here so a
        # re-opened authority resumes `seq` across the assurance ledger too; a
        # table left out would let a later append reuse a sequence number that
        # an assurance row already holds.
        "task_contracts", "verification_inputs", "verification_results",
        "review_results", "objection_cycles", "promotion_decisions",
        # Slice-4 contained-worker host handoff. A plan is authority for a
        # resumable action; events record what actually completed.
        "host_promotion_plans", "host_promotion_events",
        # Policy increment. One compiled policy envelope per task contract.
        "policy_envelopes",
        # Automatic policy-source ingestion increment (migration 0008). One
        # append-only row per ingested MASTER/TASK policy document.
        "policy_sources",
        # Execution-input increment (migration 0009). One immutable binding of
        # the exact inputs a future contained verification would run over, per
        # frozen task contract.
        "task_execution_inputs",
        # Slice-6 operational self-assessment.  A verified objection is
        # translated into a bounded recovery specification, not permission.
        "operational_assessments",
        # Slice-7 bounded recovery.  One content-addressed row per carried-out
        # replacement-candidate recovery, forward-linked to the assessment
        # that required it and the fresh child it produced.
        "recovery_attempts",
        # Layer-2 worker supervision. Plans and attempt events are separate:
        # the plan authorizes no work and an event is not assurance evidence.
        "worker_supervision_plans", "worker_attempt_events",
        # Unit 8A1 worker-model sessions, opened from an already-verified
        # supervision route. Header, request and event are three separate
        # append-only tables for the same reason as the pair above.
        "worker_sessions", "worker_model_requests", "worker_session_events",
        # Unit 8A correction (migration 0014). A durable, provider-neutral
        # logical session and the route-bound legs explicitly attached to it
        # are separate append-only tables from the route-bound session itself.
        "worker_logical_sessions", "worker_session_legs",
    )

    def _max_seq(self) -> int:
        highest = 0
        for table in self._SEQ_TABLES:
            row = self._conn.execute(f"SELECT MAX(seq) AS m FROM {table}").fetchone()
            if row["m"] is not None:
                highest = max(highest, int(row["m"]))
        return highest

    def now(self) -> str:
        """The next logical timestamp.

        Deterministic and strictly increasing WITHIN one store instance. It is
        not a global clock: re-opening a file-backed authority restarts the
        tick at 1, so ``created_at`` values repeat across sessions. Ordering is
        therefore taken from ``seq`` everywhere in this slice — ``seq`` IS
        resumed from MAX(seq) across every authority table on open — and no
        module compares two ``created_at`` values. A wall clock would make
        every hash in the slice irreproducible, which is the trade being made.
        """
        self._tick += 1
        return f"{self._epoch}/t{self._tick:06d}"

    def next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def insert(self, table: str, values: Mapping[str, Any]) -> Row:
        """The sanctioned append. The only write path into authority."""
        columns = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        try:
            with self._conn:
                self._conn.execute(
                    f"INSERT INTO {table} ({columns}) VALUES ({marks})",
                    tuple(values.values()),
                )
        except sqlite3.IntegrityError as exc:
            raise CisError(
                f"authority refused the write to {table}: {exc}", table=table
            ) from exc
        return Row(dict(values))

    def insert_batch(self, table: str,
                     rows: Sequence[Mapping[str, Any]]) -> list[Row]:
        """Atomically append a validated batch to one authority table.

        This is the sanctioned path for facts whose validity is established
        over a whole set (for example symmetric policy conflicts). Either all
        rows become visible or none do; callers may not use it across tables.
        """
        if not rows:
            return []
        columns = tuple(rows[0])
        if any(tuple(row) != columns for row in rows):
            raise CisError("authority batch rows do not share one schema",
                           table=table)
        marks = ", ".join("?" for _ in columns)
        sql = (f"INSERT INTO {table} ({', '.join(columns)}) "
               f"VALUES ({marks})")
        try:
            with self._conn:
                self._conn.executemany(
                    sql, [tuple(row[column] for column in columns) for row in rows])
        except sqlite3.DatabaseError as exc:
            self._seq = self._max_seq()
            raise CisError(
                f"authority refused the batch write to {table}: {exc}",
                table=table,
            ) from exc
        return [Row(dict(row)) for row in rows]

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[Row]:
        return [Row(dict(row)) for row in self._conn.execute(sql, tuple(params))]

    def one(self, sql: str, params: Sequence[Any] = ()) -> Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute_raw(self, sql: str, params: Sequence[Any] = ()) -> None:
        """Direct statement execution, used to prove that append-only refusal
        holds even for a caller that bypasses the typed appenders."""
        try:
            with self._conn:
                self._conn.execute(sql, tuple(params))
        except sqlite3.DatabaseError as exc:
            if "append-only" in str(exc):
                raise AppendOnlyViolation(str(exc), sql=sql) from exc
            raise
