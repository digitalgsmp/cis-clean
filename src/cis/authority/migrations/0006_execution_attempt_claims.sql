-- One verified authorization may cross the execution boundary at most once.
-- The UNIQUE authorization_id constraint is the atomic replay/concurrency gate.
CREATE TABLE execution_attempt_claims (
    claim_id            TEXT PRIMARY KEY,
    authorization_id    TEXT NOT NULL UNIQUE
                        REFERENCES execution_authorizations(authorization_id),
    adapter_id          TEXT NOT NULL,
    request_hash        TEXT NOT NULL,
    run_nonce           TEXT NOT NULL UNIQUE,
    created_at          TEXT NOT NULL,
    seq                 INTEGER NOT NULL
);

CREATE UNIQUE INDEX idx_execution_claims_seq
    ON execution_attempt_claims(seq);

CREATE TRIGGER execution_attempt_claims_no_update
BEFORE UPDATE ON execution_attempt_claims
BEGIN SELECT RAISE(ABORT, 'append-only: execution_attempt_claims'); END;

CREATE TRIGGER execution_attempt_claims_no_delete
BEFORE DELETE ON execution_attempt_claims
BEGIN SELECT RAISE(ABORT, 'append-only: execution_attempt_claims'); END;
