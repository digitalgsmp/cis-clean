-- 0010_operational_assessments
--
-- The deterministic bridge between an independent review objection and a
-- future recovery authorization.  This table records what failed, which
-- immutable bindings a recovery must preserve, and the closed set of facts a
-- later recovery unit may replace.  It grants no execution authority.

CREATE TABLE operational_assessments (
    assessment_id              TEXT PRIMARY KEY,
    task_contract_id           TEXT NOT NULL
                                    REFERENCES task_contracts(task_contract_id),
    cycle_id                   TEXT NOT NULL UNIQUE
                                    REFERENCES objection_cycles(cycle_id),
    review_id                  TEXT NOT NULL
                                    REFERENCES review_results(review_id),
    cycle_number               INTEGER NOT NULL CHECK (cycle_number BETWEEN 1 AND 3),
    disposition                TEXT NOT NULL CHECK (disposition IN (
                                    'REPLACEMENT_CANDIDATE_REQUIRED',
                                    'REVISED_SUBMISSION_REQUIRED',
                                    'ESCALATION_REQUIRED')),
    failure_class              TEXT NOT NULL CHECK (failure_class IN (
                                    'CANDIDATE_OR_RESULT_FAILURE',
                                    'SUBMISSION_ARTIFACT_FAILURE',
                                    'RECOVERY_BOUND_EXHAUSTED')),
    preserved_bindings_json    TEXT NOT NULL,
    permitted_changes_json     TEXT NOT NULL,
    required_checks_json       TEXT NOT NULL,
    source_facts_hash          TEXT NOT NULL CHECK (length(source_facts_hash) = 64),
    hash_domain                TEXT NOT NULL CHECK (
                                    hash_domain = 'cis.assurance.operational_assessment.v1'),
    assessment_hash            TEXT NOT NULL CHECK (length(assessment_hash) = 64),
    created_at                 TEXT NOT NULL,
    seq                        INTEGER NOT NULL
);

CREATE INDEX idx_operational_assessments_tc
    ON operational_assessments(task_contract_id, seq);

CREATE TRIGGER operational_assessments_no_update
BEFORE UPDATE ON operational_assessments
BEGIN SELECT RAISE(ABORT, 'append-only: operational_assessments'); END;

CREATE TRIGGER operational_assessments_no_delete
BEFORE DELETE ON operational_assessments
BEGIN SELECT RAISE(ABORT, 'append-only: operational_assessments'); END;
