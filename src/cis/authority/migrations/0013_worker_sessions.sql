-- 0013_worker_sessions
-- Provider-neutral, append-only authority for worker-model sessions opened
-- against an already-verified worker_supervision route. A session header
-- binds no provider name, no prompt or context bytes — only sha256 digests
-- of them — and its own content address deliberately excludes the
-- supervision/route it was opened from, so a retry from the same route is
-- idempotent while a retry from a disagreeing route fails closed instead of
-- silently reusing another route's session.
--
-- This migration writes no behavior. It is the SQL foundation only (Unit
-- 8A): the full closed event vocabulary and conditional columns exist so a
-- later authority module can open a session, bind an external session,
-- checkpoint, issue further requests, suspend and close — without a further
-- migration — but nothing in this slice ever appends them.

CREATE TABLE worker_sessions (
    session_id        TEXT PRIMARY KEY CHECK (length(trim(session_id)) > 0),
    supervision_id    TEXT NOT NULL REFERENCES worker_supervision_plans(supervision_id),
    route_index       INTEGER NOT NULL CHECK (route_index >= 0),
    objective_id      TEXT NOT NULL REFERENCES objectives(objective_id),
    transaction_id    TEXT NOT NULL REFERENCES intent_transactions(transaction_id),
    target_module_id  TEXT NOT NULL CHECK (length(trim(target_module_id)) > 0),
    operation         TEXT NOT NULL CHECK (length(trim(operation)) > 0),
    logical_role      TEXT NOT NULL CHECK (logical_role IN (
                          'BRAIN', 'MENTOR', 'DRAFTER', 'IMPLEMENTER', 'REVIEWER')),
    adapter_id        TEXT NOT NULL CHECK (length(trim(adapter_id)) > 0),
    hash_domain       TEXT NOT NULL CHECK (
                          hash_domain = 'cis.execution.worker_session.header.v1'),
    session_hash      TEXT NOT NULL CHECK (length(session_hash) = 64),
    created_at        TEXT NOT NULL,
    seq               INTEGER NOT NULL
);

CREATE INDEX idx_worker_sessions_route
    ON worker_sessions(supervision_id, route_index);

CREATE TABLE worker_model_requests (
    request_id              TEXT PRIMARY KEY CHECK (length(trim(request_id)) > 0),
    session_id               TEXT NOT NULL REFERENCES worker_sessions(session_id),
    supervision_id            TEXT NOT NULL REFERENCES worker_supervision_plans(supervision_id),
    route_index               INTEGER NOT NULL CHECK (route_index >= 0),
    authorization_id          TEXT NOT NULL REFERENCES execution_authorizations(authorization_id),
    adapter_id                TEXT NOT NULL CHECK (length(trim(adapter_id)) > 0),
    wall_time_ms              INTEGER NOT NULL CHECK (wall_time_ms > 0),
    token_limit               INTEGER NOT NULL CHECK (token_limit > 0),
    cost_limit_micros         INTEGER NOT NULL CHECK (cost_limit_micros > 0),
    prompt_sha256             TEXT NOT NULL CHECK (length(prompt_sha256) = 64),
    context_sha256            TEXT NOT NULL CHECK (length(context_sha256) = 64),
    response_schema_sha256    TEXT NOT NULL CHECK (length(response_schema_sha256) = 64),
    ordinal                   INTEGER NOT NULL CHECK (ordinal >= 1),
    hash_domain               TEXT NOT NULL CHECK (
                                  hash_domain = 'cis.execution.worker_session.request.v1'),
    request_hash              TEXT NOT NULL CHECK (length(request_hash) = 64),
    created_at                TEXT NOT NULL,
    seq                       INTEGER NOT NULL
);

-- One request per supervision route: a route authorizes at most one gateway
-- boundary crossing, so it may not back two disagreeing requests. Likewise
-- one request per authorization and one request per session ordinal.
CREATE UNIQUE INDEX idx_worker_model_requests_route
    ON worker_model_requests(supervision_id, route_index);
CREATE UNIQUE INDEX idx_worker_model_requests_authorization
    ON worker_model_requests(authorization_id);
CREATE UNIQUE INDEX idx_worker_model_requests_session_ordinal
    ON worker_model_requests(session_id, ordinal);

CREATE TABLE worker_session_events (
    event_id               TEXT PRIMARY KEY CHECK (length(trim(event_id)) > 0),
    session_id             TEXT NOT NULL REFERENCES worker_sessions(session_id),
    request_id             TEXT REFERENCES worker_model_requests(request_id),
    event_type             TEXT NOT NULL CHECK (event_type IN (
                               'SESSION_OPENED', 'EXTERNAL_SESSION_BOUND',
                               'REQUEST_STARTED', 'REQUEST_CHECKPOINTED',
                               'REQUEST_SUCCEEDED', 'REQUEST_FAILED',
                               'SESSION_SUSPENDED', 'SESSION_CLOSED')),
    external_session_ref   TEXT,
    checkpoint_ref         TEXT,
    checkpoint_sha256      TEXT CHECK (
                               checkpoint_sha256 IS NULL OR length(checkpoint_sha256) = 64),
    run_id                 TEXT REFERENCES backend_runs(run_id),
    evidence_id            TEXT REFERENCES evidence_records(evidence_id),
    failure_class          TEXT CHECK (failure_class IS NULL OR failure_class IN (
                               'timeout', 'budget_exhausted', 'permission_wait',
                               'network_or_provider_failure',
                               'empty_or_incomplete_output', 'invalid_artifacts')),
    hash_domain            TEXT NOT NULL CHECK (
                               hash_domain = 'cis.execution.worker_session.event.v1'),
    event_hash             TEXT NOT NULL CHECK (length(event_hash) = 64),
    created_at             TEXT NOT NULL,
    seq                    INTEGER NOT NULL,
    CHECK ((event_type IN ('EXTERNAL_SESSION_BOUND', 'REQUEST_STARTED',
                            'REQUEST_CHECKPOINTED', 'REQUEST_SUCCEEDED', 'REQUEST_FAILED'))
           = (request_id IS NOT NULL)),
    CHECK ((event_type = 'EXTERNAL_SESSION_BOUND') = (external_session_ref IS NOT NULL)),
    CHECK ((event_type = 'REQUEST_CHECKPOINTED') = (checkpoint_ref IS NOT NULL)),
    CHECK ((event_type = 'REQUEST_CHECKPOINTED') = (checkpoint_sha256 IS NOT NULL)),
    CHECK ((event_type = 'REQUEST_SUCCEEDED') = (run_id IS NOT NULL)),
    CHECK ((event_type = 'REQUEST_SUCCEEDED') = (evidence_id IS NOT NULL)),
    CHECK ((event_type = 'REQUEST_FAILED') = (failure_class IS NOT NULL))
);

CREATE UNIQUE INDEX idx_worker_session_events_opened
    ON worker_session_events(session_id) WHERE event_type = 'SESSION_OPENED';
CREATE UNIQUE INDEX idx_worker_session_events_closed
    ON worker_session_events(session_id) WHERE event_type = 'SESSION_CLOSED';
CREATE UNIQUE INDEX idx_worker_session_events_external
    ON worker_session_events(session_id) WHERE event_type = 'EXTERNAL_SESSION_BOUND';
CREATE UNIQUE INDEX idx_worker_session_events_request_terminal
    ON worker_session_events(request_id)
    WHERE event_type IN ('REQUEST_SUCCEEDED', 'REQUEST_FAILED');
CREATE UNIQUE INDEX idx_worker_session_events_request_started
    ON worker_session_events(request_id) WHERE event_type = 'REQUEST_STARTED';
CREATE INDEX idx_worker_session_events_order
    ON worker_session_events(session_id, seq);

CREATE TRIGGER worker_sessions_no_update
BEFORE UPDATE ON worker_sessions
BEGIN SELECT RAISE(ABORT, 'append-only: worker_sessions'); END;
CREATE TRIGGER worker_sessions_no_delete
BEFORE DELETE ON worker_sessions
BEGIN SELECT RAISE(ABORT, 'append-only: worker_sessions'); END;
CREATE TRIGGER worker_model_requests_no_update
BEFORE UPDATE ON worker_model_requests
BEGIN SELECT RAISE(ABORT, 'append-only: worker_model_requests'); END;
CREATE TRIGGER worker_model_requests_no_delete
BEFORE DELETE ON worker_model_requests
BEGIN SELECT RAISE(ABORT, 'append-only: worker_model_requests'); END;
CREATE TRIGGER worker_session_events_no_update
BEFORE UPDATE ON worker_session_events
BEGIN SELECT RAISE(ABORT, 'append-only: worker_session_events'); END;
CREATE TRIGGER worker_session_events_no_delete
BEFORE DELETE ON worker_session_events
BEGIN SELECT RAISE(ABORT, 'append-only: worker_session_events'); END;
