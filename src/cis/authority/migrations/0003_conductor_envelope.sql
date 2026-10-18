-- 0003_conductor_envelope
--
-- Layer-2 Conductor ingress-to-evidence increment. Every public mutation that
-- crosses the L1/L2 boundary is wrapped in an immutable authority-bound
-- envelope that records the exact content, the active objective and the
-- baseline at the time of the operation, and links to the intent transaction,
-- authorization and run rows it delegates to. No verdict, no verbatim text and
-- no run result is copied into the envelope: linkage ids plus recomputable
-- hashes are enough, and a copied value would be a second source of truth.

CREATE TABLE conductor_envelopes (
    envelope_id         TEXT PRIMARY KEY,
    operation           TEXT NOT NULL CHECK (operation IN ('instruction_ingress', 'authorized_execution')),
    content_hash        TEXT NOT NULL,
    objective_id        TEXT REFERENCES objectives(objective_id),
    baseline_hash       TEXT NOT NULL,
    operator_identity   TEXT NOT NULL,
    transaction_id      TEXT REFERENCES intent_transactions(transaction_id),
    authorization_id    TEXT REFERENCES execution_authorizations(authorization_id),
    run_id              TEXT REFERENCES backend_runs(run_id),
    envelope_hash       TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    seq                 INTEGER NOT NULL
);

CREATE TRIGGER conductor_envelopes_no_update BEFORE UPDATE ON conductor_envelopes
BEGIN SELECT RAISE(ABORT, 'append-only: conductor_envelopes'); END;
CREATE TRIGGER conductor_envelopes_no_delete BEFORE DELETE ON conductor_envelopes
BEGIN SELECT RAISE(ABORT, 'append-only: conductor_envelopes'); END;
