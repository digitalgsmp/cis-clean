-- 0004_assurance_increment
--
-- Slice-2 assurance increment: an immutable task contract, one deterministic
-- verification, up to three bounded review cycles, and a record-only promotion
-- decision.
--
-- NOTHING HERE ALTERS A SLICE-1 TABLE. Every new table links FORWARD to the
-- rows that already own their facts (execution_authorizations, backend_runs,
-- evidence_records), so every digest recorded before this migration still
-- recomputes bit-identically after it. There is no ALTER statement in this
-- file and no column is added to backend_runs: the new facts a verifier needs
-- are persisted in verification_inputs below, which is a new append-only
-- table, exactly so the run ledger stays byte-stable.
--
-- Every table is APPEND-ONLY by trigger, as in 0002. State is DERIVED from the
-- rows here and is never stored as a mutable column (ADR-ARCH-002): the only
-- state column in the whole migration is task_contracts.state, and its CHECK
-- pins it to the single value FROZEN, which is what "immutable task contract"
-- means. FROZEN -> VERIFIED_PASS/VERIFIED_FAIL -> PASS/OBJECTIONS ->
-- ESCALATED / PROMOTION_* is read out of the append-only ledger.
--
-- A FOURTH OBJECTION CYCLE IS IMPOSSIBLE AT THREE LEVELS. This file is the
-- third of them: review_results.cycle_index is CHECKed to 0..2 and UNIQUE per
-- task contract, objection_cycles.cycle_number is CHECKed to 1..3 and UNIQUE
-- per task contract, and objection_cycles.review_id is UNIQUE so one review
-- can never open two cycles. The other two levels are the reviewer facade
-- (API) and AssuranceAuthority (ledger).

-- task_contracts — owner: cis.assurance.authority
-- The immutable, template-compiled unit of assured work. Its digest lives in
-- an INDEPENDENT hash domain (hash_domain below) so a task-contract digest can
-- never be confused with, substituted for, or replayed as an authorization
-- binding hash even when the covered facts coincide.
CREATE TABLE task_contracts (
    task_contract_id            TEXT PRIMARY KEY,
    authorization_id            TEXT NOT NULL UNIQUE
                                    REFERENCES execution_authorizations(authorization_id),
    authorization_binding_hash  TEXT NOT NULL,
    target_module_id            TEXT NOT NULL,
    template_id                 TEXT NOT NULL,
    template_hash               TEXT NOT NULL,
    state                       TEXT NOT NULL CHECK (state = 'FROZEN'),
    allowed_paths_json          TEXT NOT NULL,
    forbidden_actions_json      TEXT NOT NULL,
    required_checks_json        TEXT NOT NULL,
    required_artifacts_json     TEXT NOT NULL,
    stopping_condition          TEXT NOT NULL,
    return_point                TEXT NOT NULL,
    hash_domain                 TEXT NOT NULL
                                    CHECK (hash_domain = 'cis.assurance.task_contract.v1'),
    task_contract_hash          TEXT NOT NULL,
    created_at                  TEXT NOT NULL,
    seq                         INTEGER NOT NULL
);

-- verification_inputs — owner: cis.assurance.authority
-- The verifier's assembled input facts, persisted here rather than as new
-- columns on backend_runs. assembled_by is CHECKed to the verifier module so
-- the reviewer can never be the author of a verifier input row.
CREATE TABLE verification_inputs (
    input_id                        TEXT PRIMARY KEY,
    task_contract_id                TEXT NOT NULL UNIQUE
                                        REFERENCES task_contracts(task_contract_id),
    submitted_run_id                TEXT REFERENCES backend_runs(run_id),
    submitted_evidence_id           TEXT REFERENCES evidence_records(evidence_id),
    submitted_artifacts_json        TEXT NOT NULL,
    recomputed_task_contract_hash   TEXT NOT NULL,
    recomputed_binding_hash         TEXT NOT NULL,
    inputs_hash                     TEXT NOT NULL,
    assembled_by                    TEXT NOT NULL
                                        CHECK (assembled_by = 'cis.assurance.verifier'),
    created_at                      TEXT NOT NULL,
    seq                             INTEGER NOT NULL
);

-- verification_results — owner: cis.assurance.authority
-- Exactly one deterministic verification per task contract. The submitted
-- evidence is immutable, so a second verification could only restate the
-- first; UNIQUE on task_contract_id makes the restatement impossible rather
-- than merely unnecessary.
CREATE TABLE verification_results (
    result_id               TEXT PRIMARY KEY,
    task_contract_id        TEXT NOT NULL UNIQUE
                                REFERENCES task_contracts(task_contract_id),
    input_id                TEXT NOT NULL UNIQUE
                                REFERENCES verification_inputs(input_id),
    outcome                 TEXT NOT NULL CHECK (outcome IN (
                                'VERIFIED_PASS', 'VERIFIED_FAIL')),
    reason_code             TEXT NOT NULL,
    checks_performed_json   TEXT NOT NULL,
    findings_json           TEXT NOT NULL,
    result_hash             TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    seq                     INTEGER NOT NULL
);

-- review_results — owner: cis.assurance.authority
-- An independent review over one verification result. cycle_index 0 is the
-- first review; 1 and 2 are the reviews that follow objection cycles 1 and 2.
-- There is deliberately no cycle_index 3: a review after the third objection
-- cycle could only open a fourth, so the upper bound lives in the CHECK.
CREATE TABLE review_results (
    review_id                           TEXT PRIMARY KEY,
    task_contract_id                    TEXT NOT NULL
                                            REFERENCES task_contracts(task_contract_id),
    verification_result_id              TEXT NOT NULL
                                            REFERENCES verification_results(result_id),
    cycle_index                         INTEGER NOT NULL
                                            CHECK (cycle_index BETWEEN 0 AND 2),
    outcome                             TEXT NOT NULL CHECK (outcome IN (
                                            'PASS', 'OBJECTIONS')),
    reason_code                         TEXT NOT NULL,
    reviewer_lineage                    TEXT NOT NULL,
    packet_hash                         TEXT NOT NULL,
    recomputed_task_contract_hash       TEXT NOT NULL,
    recomputed_verification_result_hash TEXT NOT NULL,
    objections_json                     TEXT NOT NULL,
    review_hash                         TEXT NOT NULL,
    created_at                          TEXT NOT NULL,
    seq                                 INTEGER NOT NULL,
    UNIQUE (task_contract_id, cycle_index)
);

-- objection_cycles — owner: cis.assurance.authority
-- One bounded review/recovery decision over immutable submitted evidence.
-- replacement_execution_wiring is CHECKed to a single value that records, in
-- authority rather than in prose, that executing a replacement candidate is
-- NOT part of this increment: it belongs with the later real nonroot
-- contained-worker capability. Nothing here pretends remediation ran.
CREATE TABLE objection_cycles (
    cycle_id                        TEXT PRIMARY KEY,
    task_contract_id                TEXT NOT NULL
                                        REFERENCES task_contracts(task_contract_id),
    review_id                       TEXT NOT NULL UNIQUE
                                        REFERENCES review_results(review_id),
    cycle_number                    INTEGER NOT NULL
                                        CHECK (cycle_number BETWEEN 1 AND 3),
    objections_json                 TEXT NOT NULL,
    recovery_decision               TEXT NOT NULL CHECK (recovery_decision IN (
                                        'REQUEST_REVISED_SUBMISSION',
                                        'REQUEST_REPLACEMENT_CANDIDATE',
                                        'ESCALATE')),
    replacement_execution_wiring    TEXT NOT NULL CHECK (
                                        replacement_execution_wiring =
                                        'DEFERRED_TO_CONTAINED_WORKER_CAPABILITY'),
    terminal                        INTEGER NOT NULL CHECK (terminal IN (0, 1)),
    cycle_hash                      TEXT NOT NULL,
    created_at                      TEXT NOT NULL,
    seq                             INTEGER NOT NULL,
    UNIQUE (task_contract_id, cycle_number)
);

-- promotion_decisions — owner: cis.assurance.authority
-- A DECISION ONLY. host_action is CHECKed to the single value
-- NONE_RECORD_ONLY: this increment is host-independent, performs no host
-- promotion, and records no claim that it did. PROMOTION_AUTHORIZED requires
-- the conjunction of a passed verification and a passed review, so both
-- linkage columns are NOT NULL on that decision path and the module enforces
-- the conjunction before the append.
CREATE TABLE promotion_decisions (
    decision_id             TEXT PRIMARY KEY,
    task_contract_id        TEXT NOT NULL
                                REFERENCES task_contracts(task_contract_id),
    decision                TEXT NOT NULL CHECK (decision IN (
                                'PROMOTION_AUTHORIZED', 'PROMOTION_DENIED')),
    reason_code             TEXT NOT NULL,
    verification_result_id  TEXT REFERENCES verification_results(result_id),
    review_id               TEXT REFERENCES review_results(review_id),
    host_action             TEXT NOT NULL
                                CHECK (host_action = 'NONE_RECORD_ONLY'),
    decision_hash           TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    seq                     INTEGER NOT NULL,
    CHECK (decision <> 'PROMOTION_AUTHORIZED'
           OR (verification_result_id IS NOT NULL AND review_id IS NOT NULL))
);

CREATE INDEX idx_task_contracts_auth ON task_contracts(authorization_id, seq);
CREATE INDEX idx_verification_results_tc ON verification_results(task_contract_id, seq);
CREATE INDEX idx_review_results_tc ON review_results(task_contract_id, cycle_index);
CREATE INDEX idx_objection_cycles_tc ON objection_cycles(task_contract_id, cycle_number);
CREATE INDEX idx_promotion_decisions_tc ON promotion_decisions(task_contract_id, seq);

CREATE TRIGGER task_contracts_no_update BEFORE UPDATE ON task_contracts
BEGIN SELECT RAISE(ABORT, 'append-only: task_contracts'); END;
CREATE TRIGGER task_contracts_no_delete BEFORE DELETE ON task_contracts
BEGIN SELECT RAISE(ABORT, 'append-only: task_contracts'); END;

CREATE TRIGGER verification_inputs_no_update BEFORE UPDATE ON verification_inputs
BEGIN SELECT RAISE(ABORT, 'append-only: verification_inputs'); END;
CREATE TRIGGER verification_inputs_no_delete BEFORE DELETE ON verification_inputs
BEGIN SELECT RAISE(ABORT, 'append-only: verification_inputs'); END;

CREATE TRIGGER verification_results_no_update BEFORE UPDATE ON verification_results
BEGIN SELECT RAISE(ABORT, 'append-only: verification_results'); END;
CREATE TRIGGER verification_results_no_delete BEFORE DELETE ON verification_results
BEGIN SELECT RAISE(ABORT, 'append-only: verification_results'); END;

CREATE TRIGGER review_results_no_update BEFORE UPDATE ON review_results
BEGIN SELECT RAISE(ABORT, 'append-only: review_results'); END;
CREATE TRIGGER review_results_no_delete BEFORE DELETE ON review_results
BEGIN SELECT RAISE(ABORT, 'append-only: review_results'); END;

CREATE TRIGGER objection_cycles_no_update BEFORE UPDATE ON objection_cycles
BEGIN SELECT RAISE(ABORT, 'append-only: objection_cycles'); END;
CREATE TRIGGER objection_cycles_no_delete BEFORE DELETE ON objection_cycles
BEGIN SELECT RAISE(ABORT, 'append-only: objection_cycles'); END;

CREATE TRIGGER promotion_decisions_no_update BEFORE UPDATE ON promotion_decisions
BEGIN SELECT RAISE(ABORT, 'append-only: promotion_decisions'); END;
CREATE TRIGGER promotion_decisions_no_delete BEFORE DELETE ON promotion_decisions
BEGIN SELECT RAISE(ABORT, 'append-only: promotion_decisions'); END;
