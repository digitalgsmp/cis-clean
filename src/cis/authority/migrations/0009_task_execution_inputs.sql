-- 0009_task_execution_inputs
--
-- Append-only authority for the EXACT inputs a future contained verification
-- of model-authored source would be run over. One table, one owning module:
-- cis.assurance.execution_input (ADR-ARCH-001 clause 5).
--
-- NOTHING HERE ALTERS AN EARLIER TABLE. There is no ALTER statement in this
-- file, no column is added to task_contracts, and no earlier digest is
-- recomputed under a new scheme. The row below links FORWARD to the frozen
-- task contract that already owns its own facts, exactly as migration 0004
-- linked forward into the slice-1 tables, so every task_contract_hash recorded
-- before this migration still recomputes bit-identically after it and
-- TASK_CONTRACT_HASH_DOMAIN is untouched.
--
-- A DISTINCT HASH DOMAIN. hash_domain is CHECKed to the single value
-- 'cis.assurance.execution_input.v1'. That is neither the task-contract domain
-- nor the undomained slice-1 authorization binding scheme, so an
-- execution-input digest can never be presented as proof of either, even
-- though the three cover overlapping facts.
--
-- EXACT BYTES, NOT A PATH AND NOT A DIGEST ALONE. candidate_source and
-- vector_contract hold the bytes themselves. A row that recorded only digests
-- would let the subject of a verification be swapped afterwards and still
-- recompute; a row that recorded a path would make the subject whatever that
-- path happened to hold at read time. The digest columns beside them are what
-- makes the stored bytes independently checkable, and the owning module
-- refuses a row whose digests do not match its own stored bytes.
--
-- ONE BINDING PER TASK CONTRACT, EVER. task_contract_id is UNIQUE, so a second
-- set of execution inputs under one frozen task contract cannot exist: the
-- inputs ARE part of what is being assured, and two bindings would mean two
-- different things had been authorized under one immutable contract. Combined
-- with the no-update and no-delete triggers, a duplicate has nowhere to go but
-- a refusal — there is no overwrite path at any layer.
--
-- NO TASK TYPE IS INTRODUCED HERE. This migration records inputs and nothing
-- else. verify_authored_source.v1 is NOT added by it, no template changes, and
-- nothing in this file dispatches, executes, verifies or promotes anything.

CREATE TABLE task_execution_inputs (
    execution_input_id              TEXT PRIMARY KEY CHECK (
                                        length(trim(execution_input_id)) > 0),
    task_contract_id                TEXT NOT NULL UNIQUE
                                        REFERENCES task_contracts(task_contract_id),

    -- The subject of the future verification, byte-exact, with its digest.
    candidate_source                BLOB NOT NULL,
    candidate_sha256                TEXT NOT NULL CHECK (
                                        length(candidate_sha256) = 64),

    -- The canonical vector contract that declares what passing would mean,
    -- byte-exact, with its digest.
    vector_contract                 BLOB NOT NULL,
    vector_contract_sha256          TEXT NOT NULL CHECK (
                                        length(vector_contract_sha256) = 64),

    -- The one callable the vector contract is declared against. Blank is
    -- refused here as well as in the owning module: an input set with no
    -- entrypoint names no verification at all.
    authorized_entrypoint           TEXT NOT NULL CHECK (
                                        length(trim(authorized_entrypoint)) > 0),

    -- Forward links into the frozen task contract and the ALLOW beneath it.
    -- Recorded as the contract already carries them, never re-derived here.
    task_contract_hash              TEXT NOT NULL CHECK (
                                        length(task_contract_hash) = 64),
    authorization_binding_hash      TEXT NOT NULL CHECK (
                                        length(authorization_binding_hash) = 64),

    -- The immutable apparatus identity this input set is bound to: a sealed
    -- image identified by its sha256 digest alone (never a mutable tag that
    -- could be repointed at different bytes after this row is written), and
    -- the two digests a later verification would be required to observe
    -- rather than accept on the worker's own word. SQL enforces digest SHAPE
    -- (length, prefix, lowercase); the owning module enforces the exact
    -- sha256-hex-character form.
    worker_image                    TEXT NOT NULL CHECK (
                                        length(worker_image) = 71
                                        AND substr(worker_image, 1, 7) = 'sha256:'
                                        AND worker_image = lower(worker_image)),
    expected_trusted_runner_sha256  TEXT NOT NULL CHECK (
                                        length(expected_trusted_runner_sha256) = 64
                                        AND expected_trusted_runner_sha256
                                            = lower(expected_trusted_runner_sha256)),
    expected_worker_sha256          TEXT NOT NULL CHECK (
                                        length(expected_worker_sha256) = 64
                                        AND expected_worker_sha256
                                            = lower(expected_worker_sha256)),

    hash_domain                     TEXT NOT NULL CHECK (
                                        hash_domain
                                        = 'cis.assurance.execution_input.v1'),
    execution_input_hash            TEXT NOT NULL CHECK (
                                        length(execution_input_hash) = 64),
    created_at                      TEXT NOT NULL,
    seq                             INTEGER NOT NULL
);

CREATE INDEX idx_task_execution_inputs_tc
    ON task_execution_inputs(task_contract_id, seq);

CREATE TRIGGER task_execution_inputs_no_update
BEFORE UPDATE ON task_execution_inputs
BEGIN SELECT RAISE(ABORT, 'append-only: task_execution_inputs'); END;
CREATE TRIGGER task_execution_inputs_no_delete
BEFORE DELETE ON task_execution_inputs
BEGIN SELECT RAISE(ABORT, 'append-only: task_execution_inputs'); END;
