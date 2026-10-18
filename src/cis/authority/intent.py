"""Owner of ``intent_transactions`` and ``objectives``.

Eric's verbatim instruction is immutable source evidence (ADR-ARCH-004
clause 1). An interpretation is written as a separate, explicitly labeled,
source-linked column; it never replaces, silently alters or outranks the
verbatim text, and nothing in this slice reads the interpretation where the
verbatim is what matters.
"""

from __future__ import annotations

from ..canonical import sha256_text
from .store import AuthorityStore, Row

INTERPRETATION_LABEL = "DERIVATIVE_INTERPRETATION_SOURCE_LINKED"


class IntentAuthority:
    owned_authority = ("intent_transactions", "objectives")

    def __init__(self, store: AuthorityStore) -> None:
        self._store = store

    # -- writes -------------------------------------------------------------

    def record_objective(self, *, objective_id: str, statement: str,
                         established_by: str) -> Row:
        return self._store.insert("objectives", {
            "objective_id": objective_id,
            "statement": statement,
            "established_by": established_by,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })

    def record_instruction(self, *, transaction_id: str, verbatim: str,
                           interpretation: str, actor: str) -> Row:
        """Append one intent transaction. ``verbatim`` is stored byte-exact."""
        return self._store.insert("intent_transactions", {
            "transaction_id": transaction_id,
            "verbatim_instruction": verbatim,
            "verbatim_hash": sha256_text(verbatim),
            "interpretation": interpretation,
            "interpretation_label": INTERPRETATION_LABEL,
            "interpretation_source":
                f"intent_transactions:{transaction_id}:verbatim_instruction",
            "actor": actor,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })

    # -- reads --------------------------------------------------------------

    def transaction(self, transaction_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM intent_transactions WHERE transaction_id = ?",
            (transaction_id,),
        )

    def objective(self, objective_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM objectives WHERE objective_id = ?", (objective_id,)
        )

    def history(self) -> list[Row]:
        return self._store.query("SELECT * FROM intent_transactions ORDER BY seq")

    def antecedent_records(self, *,
                           exclude_transaction_id: str | None = None) -> list[dict]:
        """Project prior human instructions into the retrieval-record shape."""
        rows = self.history()
        return [
            {
                "evidence_id": f"intent:{row['transaction_id']}",
                "kind": "prior_human_intent",
                "source_ref":
                    f"intent_transactions:{row['transaction_id']}:verbatim_instruction",
                "original_language": str(row["verbatim_instruction"]),
                "content": str(row["verbatim_instruction"]),
            }
            for row in rows
            if row["transaction_id"] != exclude_transaction_id
            and row["actor"] == "human_operator"
        ]

    def objectives(self) -> list[Row]:
        return self._store.query("SELECT * FROM objectives ORDER BY seq")

    def count(self) -> int:
        row = self._store.one("SELECT COUNT(*) AS n FROM intent_transactions")
        return int(row["n"]) if row else 0
