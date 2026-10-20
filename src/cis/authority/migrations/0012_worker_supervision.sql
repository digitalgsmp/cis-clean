-- 0012_worker_supervision
-- Provider-neutral, append-only authority for bounded worker supervision.
-- Plans bind an ordered set of distinct, already-authorized attempts. Events
-- record orchestration observations; they are not verification or promotion.

CREATE TABLE worker_supervision_plans (
    supervision_id       TEXT PRIMARY KEY CHECK (length(trim(supervision_id)) > 0),
    objective_id         TEXT NOT NULL REFERENCES objectives(objective_id),
    transaction_id       TEXT NOT NULL REFERENCES intent_transactions(transaction_id),
    target_module_id     TEXT NOT NULL,
    operation            TEXT NOT NULL,
    routes_json          TEXT NOT NULL,
    route_count          INTEGER NOT NULL CHECK (route_count BETWEEN 1 AND 8),
    circuit_threshold    INTEGER NOT NULL CHECK (
                             circuit_threshold BETWEEN 1 AND route_count),
    hash_domain          TEXT NOT NULL CHECK (
                             hash_domain = 'cis.execution.worker_supervision.plan.v1'),
    plan_hash            TEXT NOT NULL CHECK (length(plan_hash) = 64),
    created_at           TEXT NOT NULL,
    seq                  INTEGER NOT NULL
);

CREATE TABLE worker_attempt_events (
    event_id             TEXT PRIMARY KEY CHECK (length(trim(event_id)) > 0),
    supervision_id       TEXT NOT NULL REFERENCES worker_supervision_plans(supervision_id),
    route_index          INTEGER NOT NULL CHECK (route_index >= 0),
    authorization_id     TEXT NOT NULL REFERENCES execution_authorizations(authorization_id),
    adapter_id           TEXT NOT NULL CHECK (length(trim(adapter_id)) > 0),
    event_type           TEXT NOT NULL CHECK (event_type IN (
                             'STARTED', 'CHECKPOINT', 'SUCCEEDED', 'FAILED', 'CIRCUIT_OPEN')),
    failure_class        TEXT CHECK (failure_class IS NULL OR failure_class IN (
                             'timeout', 'budget_exhausted', 'permission_wait',
                             'network_or_provider_failure',
                             'empty_or_incomplete_output', 'invalid_artifacts')),
    measured_wall_ms     INTEGER CHECK (measured_wall_ms IS NULL OR measured_wall_ms >= 0),
    measured_tokens      INTEGER CHECK (measured_tokens IS NULL OR measured_tokens >= 0),
    measured_cost_micros INTEGER CHECK (measured_cost_micros IS NULL OR measured_cost_micros >= 0),
    checkpoint_ref       TEXT,
    checkpoint_sha256    TEXT CHECK (
                             checkpoint_sha256 IS NULL OR length(checkpoint_sha256) = 64),
    run_id               TEXT REFERENCES backend_runs(run_id),
    evidence_id          TEXT REFERENCES evidence_records(evidence_id),
    hash_domain          TEXT NOT NULL CHECK (
                             hash_domain = 'cis.execution.worker_supervision.event.v1'),
    event_hash           TEXT NOT NULL CHECK (length(event_hash) = 64),
    created_at           TEXT NOT NULL,
    seq                  INTEGER NOT NULL,
    CHECK ((event_type = 'FAILED') = (failure_class IS NOT NULL)),
    CHECK ((event_type = 'CHECKPOINT') = (checkpoint_sha256 IS NOT NULL)),
    CHECK (event_type != 'SUCCEEDED' OR (run_id IS NOT NULL AND evidence_id IS NOT NULL))
);

CREATE UNIQUE INDEX idx_worker_attempt_started
    ON worker_attempt_events(supervision_id, route_index)
    WHERE event_type = 'STARTED';
CREATE UNIQUE INDEX idx_worker_attempt_terminal
    ON worker_attempt_events(supervision_id, route_index)
    WHERE event_type IN ('SUCCEEDED', 'FAILED');
CREATE UNIQUE INDEX idx_worker_circuit_open
    ON worker_attempt_events(supervision_id)
    WHERE event_type = 'CIRCUIT_OPEN';
CREATE INDEX idx_worker_attempt_events_order
    ON worker_attempt_events(supervision_id, seq);

CREATE TRIGGER worker_supervision_plans_no_update
BEFORE UPDATE ON worker_supervision_plans
BEGIN SELECT RAISE(ABORT, 'append-only: worker_supervision_plans'); END;
CREATE TRIGGER worker_supervision_plans_no_delete
BEFORE DELETE ON worker_supervision_plans
BEGIN SELECT RAISE(ABORT, 'append-only: worker_supervision_plans'); END;
CREATE TRIGGER worker_attempt_events_no_update
BEFORE UPDATE ON worker_attempt_events
BEGIN SELECT RAISE(ABORT, 'append-only: worker_attempt_events'); END;
CREATE TRIGGER worker_attempt_events_no_delete
BEFORE DELETE ON worker_attempt_events
BEGIN SELECT RAISE(ABORT, 'append-only: worker_attempt_events'); END;
