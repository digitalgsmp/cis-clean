-- 0002_append_only_triggers
--
-- Append-only is enforced by the store. A writer cannot opt out, and an
-- agent that "knows better" still cannot rewrite history: the trigger aborts
-- the statement. This is the mechanism ADR-ARCH-002 relies on when it says a
-- derivative that disagrees with authority is regenerated and authority is
-- never edited to match it.

CREATE TRIGGER schema_migrations_no_update BEFORE UPDATE ON schema_migrations
BEGIN SELECT RAISE(ABORT, 'append-only: schema_migrations'); END;
CREATE TRIGGER schema_migrations_no_delete BEFORE DELETE ON schema_migrations
BEGIN SELECT RAISE(ABORT, 'append-only: schema_migrations'); END;

CREATE TRIGGER objectives_no_update BEFORE UPDATE ON objectives
BEGIN SELECT RAISE(ABORT, 'append-only: objectives'); END;
CREATE TRIGGER objectives_no_delete BEFORE DELETE ON objectives
BEGIN SELECT RAISE(ABORT, 'append-only: objectives'); END;

CREATE TRIGGER intent_transactions_no_update BEFORE UPDATE ON intent_transactions
BEGIN SELECT RAISE(ABORT, 'append-only: intent_transactions'); END;
CREATE TRIGGER intent_transactions_no_delete BEFORE DELETE ON intent_transactions
BEGIN SELECT RAISE(ABORT, 'append-only: intent_transactions'); END;

CREATE TRIGGER continuity_decisions_no_update BEFORE UPDATE ON continuity_decisions
BEGIN SELECT RAISE(ABORT, 'append-only: continuity_decisions'); END;
CREATE TRIGGER continuity_decisions_no_delete BEFORE DELETE ON continuity_decisions
BEGIN SELECT RAISE(ABORT, 'append-only: continuity_decisions'); END;

CREATE TRIGGER evidence_records_no_update BEFORE UPDATE ON evidence_records
BEGIN SELECT RAISE(ABORT, 'append-only: evidence_records'); END;
CREATE TRIGGER evidence_records_no_delete BEFORE DELETE ON evidence_records
BEGIN SELECT RAISE(ABORT, 'append-only: evidence_records'); END;

CREATE TRIGGER evidence_conflicts_no_update BEFORE UPDATE ON evidence_conflicts
BEGIN SELECT RAISE(ABORT, 'append-only: evidence_conflicts'); END;
CREATE TRIGGER evidence_conflicts_no_delete BEFORE DELETE ON evidence_conflicts
BEGIN SELECT RAISE(ABORT, 'append-only: evidence_conflicts'); END;

CREATE TRIGGER execution_authorizations_no_update BEFORE UPDATE ON execution_authorizations
BEGIN SELECT RAISE(ABORT, 'append-only: execution_authorizations'); END;
CREATE TRIGGER execution_authorizations_no_delete BEFORE DELETE ON execution_authorizations
BEGIN SELECT RAISE(ABORT, 'append-only: execution_authorizations'); END;

CREATE TRIGGER backend_runs_no_update BEFORE UPDATE ON backend_runs
BEGIN SELECT RAISE(ABORT, 'append-only: backend_runs'); END;
CREATE TRIGGER backend_runs_no_delete BEFORE DELETE ON backend_runs
BEGIN SELECT RAISE(ABORT, 'append-only: backend_runs'); END;

CREATE TRIGGER trajectory_events_no_update BEFORE UPDATE ON trajectory_events
BEGIN SELECT RAISE(ABORT, 'append-only: trajectory_events'); END;
CREATE TRIGGER trajectory_events_no_delete BEFORE DELETE ON trajectory_events
BEGIN SELECT RAISE(ABORT, 'append-only: trajectory_events'); END;
