-- 0011_recovery_attempts
--
-- Append-only record of one bounded recovery: an operational assessment that
-- required a replacement candidate, paired with the fresh task contract and
-- execution-input binding actually issued to carry out that replacement.
-- NOTHING HERE ALTERS AN EARLIER TABLE and nothing here executes, verifies or
-- promotes anything; it records a forward-linked fact about the exact child
-- issued for a recovery attempt. Execution and its outcome remain separate.
--
-- ONE RECOVERY PER ASSESSMENT, ONE ASSESSMENT PER CHILD. assessment_id and
-- child_authorization_id and child_task_contract_id are each UNIQUE: a given
-- objection's recovery specification can name exactly one attempt, and a
-- given fresh authorization/task contract can belong to exactly one recovery.
--
-- A DISTINCT HASH DOMAIN. hash_domain is CHECKed to the single value
-- 'cis.assurance.recovery_attempt.v1', distinct from every earlier domain
-- even though the facts recorded here overlap with task contracts and
-- execution inputs already frozen elsewhere.

CREATE TABLE recovery_attempts (
    attempt_id                     TEXT PRIMARY KEY CHECK (
                                        length(trim(attempt_id)) > 0),
    assessment_id                  TEXT NOT NULL UNIQUE
                                        REFERENCES operational_assessments(assessment_id),
    parent_task_contract_id        TEXT NOT NULL
                                        REFERENCES task_contracts(task_contract_id),
    child_authorization_id         TEXT NOT NULL UNIQUE
                                        REFERENCES execution_authorizations(authorization_id),
    child_task_contract_id         TEXT NOT NULL UNIQUE
                                        REFERENCES task_contracts(task_contract_id),
    parent_execution_input_hash    TEXT NOT NULL CHECK (
                                        length(parent_execution_input_hash) = 64),
    child_execution_input_hash     TEXT NOT NULL CHECK (
                                        length(child_execution_input_hash) = 64),
    candidate_sha256                TEXT NOT NULL CHECK (
                                        length(candidate_sha256) = 64),
    generation                      INTEGER NOT NULL CHECK (
                                        generation BETWEEN 1 AND 3),
    hash_domain                     TEXT NOT NULL CHECK (
                                        hash_domain
                                        = 'cis.assurance.recovery_attempt.v1'),
    attempt_hash                    TEXT NOT NULL CHECK (
                                        length(attempt_hash) = 64),
    created_at                      TEXT NOT NULL,
    seq                              INTEGER NOT NULL,

    CHECK (parent_task_contract_id != child_task_contract_id)
);

CREATE INDEX idx_recovery_attempts_parent
    ON recovery_attempts(parent_task_contract_id, seq);

CREATE TRIGGER recovery_attempts_no_update
BEFORE UPDATE ON recovery_attempts
BEGIN SELECT RAISE(ABORT, 'append-only: recovery_attempts'); END;

CREATE TRIGGER recovery_attempts_no_delete
BEFORE DELETE ON recovery_attempts
BEGIN SELECT RAISE(ABORT, 'append-only: recovery_attempts'); END;
