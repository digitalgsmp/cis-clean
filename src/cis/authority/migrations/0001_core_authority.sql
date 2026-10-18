-- 0001_core_authority
--
-- The clean authority for reconstruction slice 1. Every table here is
-- APPEND-ONLY: UPDATE and DELETE are refused by trigger, not by convention,
-- so "immutable source evidence" (ADR-ARCH-004 clause 1) is enforced by the
-- store rather than self-reported by a writer.
--
-- One fact, one authoritative record, one owning module (ADR-ARCH-002).
-- Each table below names its owning module in a comment; the module-contract
-- registry is what enforces single ownership.

-- objectives — owner: cis.authority.intent
-- The active objective is DERIVED from continuity_decisions, never stored as
-- a mutable flag on this table (ADR-ARCH-002, derive-from-fields).
CREATE TABLE objectives (
    objective_id    TEXT PRIMARY KEY,
    statement       TEXT NOT NULL,
    established_by  TEXT NOT NULL,              -- intent_transactions.transaction_id
    created_at      TEXT NOT NULL,
    seq             INTEGER NOT NULL
);

-- intent_transactions — owner: cis.authority.intent
-- verbatim_instruction is IMMUTABLE SOURCE EVIDENCE. interpretation is a
-- labeled, source-linked derivative and never outranks it
-- (ADR-ARCH-004 clause 1, ROLE 1).
CREATE TABLE intent_transactions (
    transaction_id      TEXT PRIMARY KEY,
    verbatim_instruction TEXT NOT NULL,
    verbatim_hash       TEXT NOT NULL,          -- sha256 of exact bytes
    interpretation      TEXT NOT NULL,
    interpretation_label TEXT NOT NULL,         -- always a derivative label
    interpretation_source TEXT NOT NULL,        -- link back to the verbatim row
    actor               TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    seq                 INTEGER NOT NULL
);

-- continuity_decisions — owner: cis.authority.continuity
-- Records, for one transaction: how the exchange was classified, which
-- objective governs AFTER it, which objective governed before, the retrieved
-- antecedents, and the disposition. A superseded objective is never erased
-- (ADR-ARCH-004 clause 1).
CREATE TABLE continuity_decisions (
    decision_id         TEXT PRIMARY KEY,
    transaction_id      TEXT NOT NULL REFERENCES intent_transactions(transaction_id),
    classification      TEXT NOT NULL CHECK (classification IN (
                            'question', 'addition', 'correction', 'redirection'
                        )),
    treated_as          TEXT NOT NULL CHECK (treated_as IN (
                            'retrieval_cue', 'objective_supersession'
                        )),
    prior_objective_id  TEXT,
    active_objective_id TEXT REFERENCES objectives(objective_id),
    antecedents_json    TEXT NOT NULL DEFAULT '[]',
    disposition         TEXT NOT NULL,
    rationale           TEXT NOT NULL,
    decision_hash       TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    seq                 INTEGER NOT NULL
);

-- evidence_records — owner: cis.authority.evidence
-- An immutable observation that something was measured. Evidence is neither
-- authority nor derivative, and does not become authority by being retrieved
-- or ranked highly (ADR-ARCH-002).
CREATE TABLE evidence_records (
    evidence_id     TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    source_ref      TEXT NOT NULL,
    original_language TEXT NOT NULL,            -- the antecedent's own words
    content         TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    admission_basis TEXT NOT NULL,
    observed_at     TEXT NOT NULL,
    seq             INTEGER NOT NULL
);

-- evidence_conflicts — owner: cis.authority.evidence
-- When evidence disagrees with itself the slice fails closed and records the
-- conflict here. No resolution is invented.
CREATE TABLE evidence_conflicts (
    conflict_id     TEXT PRIMARY KEY,
    subject         TEXT NOT NULL,
    detail_json     TEXT NOT NULL,
    detected_at     TEXT NOT NULL,
    seq             INTEGER NOT NULL
);

-- execution_authorizations — owner: cis.authority.authorization
-- The structured execution contract of ADR-ARCH-004 clause 3: allowed scope,
-- forbidden actions, required checks/evidence, stopping condition, return
-- point. A contract alone cannot create authority.
-- binding_hash binds instruction + continuity decision + authorization +
-- scope + baseline together; it is recomputed before any dispatch.
CREATE TABLE execution_authorizations (
    authorization_id    TEXT PRIMARY KEY,
    transaction_id      TEXT NOT NULL REFERENCES intent_transactions(transaction_id),
    decision_id         TEXT NOT NULL REFERENCES continuity_decisions(decision_id),
    objective_id        TEXT REFERENCES objectives(objective_id),
    verdict             TEXT NOT NULL CHECK (verdict IN ('ALLOW', 'HOLD')),
    reason_code         TEXT NOT NULL,
    reason              TEXT NOT NULL,
    target_module_id    TEXT,
    operation           TEXT NOT NULL,
    allowed_scope_json  TEXT NOT NULL,
    forbidden_actions_json TEXT NOT NULL,
    required_checks_json TEXT NOT NULL,
    required_evidence_json TEXT NOT NULL,
    stopping_condition  TEXT NOT NULL,
    return_point        TEXT NOT NULL,
    verbatim_hash       TEXT NOT NULL,
    decision_hash       TEXT NOT NULL,
    baseline_hash       TEXT NOT NULL,
    binding_hash        TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    seq                 INTEGER NOT NULL
);

-- backend_runs — owner: cis.authority.runs
-- One governed execution through the Layer-2 port. adapter_id is an opaque
-- identifier here: no module above the port interprets it.
-- A REFUSED dispatch does not appear here. A refusal may have no valid
-- authorization to key a run row on, so refusals are recorded as
-- trajectory_events; 'refused' is deliberately absent from the status
-- vocabulary rather than present and never written.
CREATE TABLE backend_runs (
    run_id              TEXT PRIMARY KEY,
    authorization_id    TEXT NOT NULL REFERENCES execution_authorizations(authorization_id),
    adapter_id          TEXT NOT NULL,
    request_hash        TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('completed', 'failed')),
    exit_code           INTEGER NOT NULL,
    result_hash         TEXT NOT NULL,
    evidence_id         TEXT REFERENCES evidence_records(evidence_id),
    started_at          TEXT NOT NULL,
    finished_at         TEXT NOT NULL,
    seq                 INTEGER NOT NULL
);

-- trajectory_events — owner: cis.authority.trajectory
-- The append-only spine of the Workbench projection. "You are here" is
-- derived from the highest seq, never stored as its own column.
CREATE TABLE trajectory_events (
    event_id        TEXT PRIMARY KEY,
    seq             INTEGER NOT NULL,
    scope           TEXT NOT NULL CHECK (scope IN ('macro', 'micro')),
    stage           TEXT NOT NULL,
    module_id       TEXT,
    transaction_id  TEXT,
    event_type      TEXT NOT NULL,
    detail_json     TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL
);

CREATE INDEX idx_intent_seq ON intent_transactions(seq);
CREATE INDEX idx_decisions_tx ON continuity_decisions(transaction_id, seq);
CREATE INDEX idx_evidence_kind ON evidence_records(kind, seq);
CREATE INDEX idx_auth_tx ON execution_authorizations(transaction_id, seq);
CREATE INDEX idx_runs_auth ON backend_runs(authorization_id, seq);
CREATE UNIQUE INDEX idx_trajectory_seq ON trajectory_events(seq);
CREATE INDEX idx_trajectory_scope ON trajectory_events(scope, seq);
CREATE INDEX idx_trajectory_tx ON trajectory_events(transaction_id, seq);
