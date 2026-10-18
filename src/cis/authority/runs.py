"""Owner of execution-attempt claims and completed/failed backend runs.

A run row is the durable record that something was dispatched through the
Layer-2 port under a named authorization, with its result hashed. ``adapter_id``
is opaque here: no reader in this module interprets it, and no behaviour in
this module branches on its value.

An atomic claim is appended immediately before an adapter is invoked.  Its
UNIQUE authorization id makes one ALLOW equal one attempted boundary crossing,
including attempts that fail before a backend run result can be recorded.
"""

from __future__ import annotations

from .store import AuthorityStore, Row

COMPLETED = "completed"
FAILED = "failed"


class RunAuthority:
    owned_authority = ("execution_attempt_claims", "backend_runs")

    def __init__(self, store: AuthorityStore) -> None:
        self._store = store

    def record(self, *, run_id: str, authorization_id: str, adapter_id: str,
               request_hash: str, status: str, exit_code: int,
               result_hash: str, evidence_id: str | None,
               started_at: str | None = None,
               finished_at: str | None = None) -> Row:
        return self._store.insert("backend_runs", {
            "run_id": run_id,
            "authorization_id": authorization_id,
            "adapter_id": adapter_id,
            "request_hash": request_hash,
            "status": status,
            "exit_code": exit_code,
            "result_hash": result_hash,
            "evidence_id": evidence_id,
            "started_at": started_at or self._store.now(),
            "finished_at": finished_at or self._store.now(),
            "seq": self._store.next_seq(),
        })

    def claim(self, *, claim_id: str, authorization_id: str, adapter_id: str,
              request_hash: str, run_nonce: str) -> Row:
        return self._store.insert("execution_attempt_claims", {
            "claim_id": claim_id,
            "authorization_id": authorization_id,
            "adapter_id": adapter_id,
            "request_hash": request_hash,
            "run_nonce": run_nonce,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })

    def claim_for_authorization(self, authorization_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM execution_attempt_claims WHERE authorization_id = ?",
            (authorization_id,),
        )

    def get(self, run_id: str) -> Row | None:
        return self._store.one("SELECT * FROM backend_runs WHERE run_id = ?", (run_id,))

    def for_authorization(self, authorization_id: str) -> list[Row]:
        return self._store.query(
            "SELECT * FROM backend_runs WHERE authorization_id = ? ORDER BY seq",
            (authorization_id,),
        )

    def all(self) -> list[Row]:
        return self._store.query("SELECT * FROM backend_runs ORDER BY seq")
