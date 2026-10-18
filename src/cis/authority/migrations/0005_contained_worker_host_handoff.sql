-- 0005_contained_worker_host_handoff
--
-- Append-only authority for applying an already-authorized candidate and for
-- restoring the prior bytes. The plan is written before host mutation and
-- contains both candidate and prior content, so an interrupted apply or
-- rollback is resumable from authority alone. State is derived from events.

CREATE TABLE host_promotion_plans (
    application_id          TEXT PRIMARY KEY,
    task_contract_id        TEXT NOT NULL UNIQUE
                                REFERENCES task_contracts(task_contract_id),
    promotion_decision_id   TEXT NOT NULL UNIQUE
                                REFERENCES promotion_decisions(decision_id),
    target_relative_path    TEXT NOT NULL,
    candidate_content       BLOB NOT NULL,
    candidate_sha256        TEXT NOT NULL,
    previous_present        INTEGER NOT NULL CHECK (previous_present IN (0, 1)),
    previous_content        BLOB,
    previous_sha256         TEXT,
    plan_hash               TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    seq                     INTEGER NOT NULL,
    CHECK ((previous_present = 0 AND previous_content IS NULL
                                AND previous_sha256 IS NULL)
        OR (previous_present = 1 AND previous_content IS NOT NULL
                                AND previous_sha256 IS NOT NULL))
);

CREATE TABLE host_promotion_events (
    event_id                TEXT PRIMARY KEY,
    application_id          TEXT NOT NULL
                                REFERENCES host_promotion_plans(application_id),
    event_type              TEXT NOT NULL CHECK (event_type IN (
                                'APPLIED', 'ROLLBACK_STARTED', 'ROLLED_BACK')),
    observed_sha256         TEXT,
    event_hash              TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    seq                     INTEGER NOT NULL,
    UNIQUE (application_id, event_type)
);

CREATE INDEX idx_host_promotion_events_application
    ON host_promotion_events(application_id, seq);

CREATE TRIGGER host_promotion_plans_no_update
BEFORE UPDATE ON host_promotion_plans
BEGIN SELECT RAISE(ABORT, 'append-only: host_promotion_plans'); END;
CREATE TRIGGER host_promotion_plans_no_delete
BEFORE DELETE ON host_promotion_plans
BEGIN SELECT RAISE(ABORT, 'append-only: host_promotion_plans'); END;
CREATE TRIGGER host_promotion_events_no_update
BEFORE UPDATE ON host_promotion_events
BEGIN SELECT RAISE(ABORT, 'append-only: host_promotion_events'); END;
CREATE TRIGGER host_promotion_events_no_delete
BEFORE DELETE ON host_promotion_events
BEGIN SELECT RAISE(ABORT, 'append-only: host_promotion_events'); END;
