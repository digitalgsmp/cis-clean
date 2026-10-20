-- 0014_worker_logical_sessions
-- Corrects the Unit 8A defect named in runtime/review-cards/
-- unit-8a-session-architecture-v1.md: migration 0013's worker_sessions row is
-- one route-bound provider session leg, not a durable provider-neutral
-- logical session, because its content address includes supervision_id,
-- route_index and adapter_id.
--
-- This migration does not rewrite 0013. worker_sessions and
-- worker_model_requests remain immutable route-bound session legs with their
-- existing API, unchanged. This migration adds the durable logical session
-- that was missing instead.
--
-- worker_logical_sessions is content-addressed only from the semantic fields
-- that identify conversation/work continuity: objective, transaction, target
-- module, operation and logical role. It names no supervision plan, route,
-- authorization, adapter, provider or external provider session reference.
--
-- worker_session_legs is the append-only association between a durable
-- logical session and the existing route-bound worker_sessions rows that
-- have been explicitly attached to it, in strict positive sequential order.
-- A route-bound session acquires durable continuity only when attached here;
-- there is no inferred or automatic backfill of migration-0013 rows.

CREATE TABLE worker_logical_sessions (
    logical_session_id  TEXT PRIMARY KEY CHECK (length(trim(logical_session_id)) > 0),
    objective_id        TEXT NOT NULL REFERENCES objectives(objective_id),
    transaction_id       TEXT NOT NULL REFERENCES intent_transactions(transaction_id),
    target_module_id     TEXT NOT NULL CHECK (length(trim(target_module_id)) > 0),
    operation            TEXT NOT NULL CHECK (length(trim(operation)) > 0),
    logical_role         TEXT NOT NULL CHECK (logical_role IN (
                             'BRAIN', 'MENTOR', 'DRAFTER', 'IMPLEMENTER', 'REVIEWER')),
    hash_domain          TEXT NOT NULL CHECK (
                             hash_domain = 'cis.execution.worker_session.logical.v1'),
    logical_session_hash TEXT NOT NULL CHECK (length(logical_session_hash) = 64),
    created_at           TEXT NOT NULL,
    seq                  INTEGER NOT NULL
);

CREATE TABLE worker_session_legs (
    leg_id              TEXT PRIMARY KEY CHECK (length(trim(leg_id)) > 0),
    logical_session_id  TEXT NOT NULL REFERENCES worker_logical_sessions(logical_session_id),
    session_id          TEXT NOT NULL REFERENCES worker_sessions(session_id),
    leg_ordinal         INTEGER NOT NULL CHECK (leg_ordinal >= 1),
    hash_domain         TEXT NOT NULL CHECK (
                            hash_domain = 'cis.execution.worker_session.leg.v1'),
    leg_hash            TEXT NOT NULL CHECK (length(leg_hash) = 64),
    created_at          TEXT NOT NULL,
    seq                 INTEGER NOT NULL
);

-- A route-bound session is a leg of at most one logical session, and a
-- logical session's legs occupy strictly distinct ordinals: together these
-- make aliasing, reordering or duplicate attachment a constraint violation,
-- not merely an application-level check.
CREATE UNIQUE INDEX idx_worker_session_legs_logical_ordinal
    ON worker_session_legs(logical_session_id, leg_ordinal);
CREATE UNIQUE INDEX idx_worker_session_legs_session
    ON worker_session_legs(session_id);

CREATE TRIGGER worker_logical_sessions_no_update
BEFORE UPDATE ON worker_logical_sessions
BEGIN SELECT RAISE(ABORT, 'append-only: worker_logical_sessions'); END;
CREATE TRIGGER worker_logical_sessions_no_delete
BEFORE DELETE ON worker_logical_sessions
BEGIN SELECT RAISE(ABORT, 'append-only: worker_logical_sessions'); END;
CREATE TRIGGER worker_session_legs_no_update
BEFORE UPDATE ON worker_session_legs
BEGIN SELECT RAISE(ABORT, 'append-only: worker_session_legs'); END;
CREATE TRIGGER worker_session_legs_no_delete
BEFORE DELETE ON worker_session_legs
BEGIN SELECT RAISE(ABORT, 'append-only: worker_session_legs'); END;
