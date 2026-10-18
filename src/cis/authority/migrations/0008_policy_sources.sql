-- Append-only authority for ingested MASTER/TASK policy-document sources.
-- Owned by cis.policy.authority, alongside the compiled policy_envelopes
-- table from migration 0007. One row per policy_id, ever: the UNIQUE
-- constraint is what makes "same policy_id, changed content" refuse at the
-- SQL layer as well as in code, and the no-update/no-delete triggers make
-- every ingested document immutable once recorded.
CREATE TABLE policy_sources (
    policy_source_id            TEXT PRIMARY KEY,
    policy_id                   TEXT NOT NULL UNIQUE,
    lineage_id                  TEXT NOT NULL,
    kind                        TEXT NOT NULL CHECK (kind IN ('MASTER', 'TASK')),
    version                     INTEGER NOT NULL,
    status                      TEXT NOT NULL CHECK (status IN ('ACTIVE', 'SUPERSEDED')),
    supersedes                  TEXT,
    conflicts_with_json         TEXT NOT NULL,
    selector_json               TEXT,
    effect_kinds_json           TEXT NOT NULL,
    prohibited_actions_json     TEXT NOT NULL,
    required_checks_json        TEXT NOT NULL,
    required_evidence_json      TEXT NOT NULL,
    narrowed_scope_json         TEXT,
    hold                        INTEGER NOT NULL CHECK (hold IN (0, 1)),
    rationale                   TEXT NOT NULL,
    evidence_basis_json         TEXT NOT NULL,
    hash_domain                 TEXT NOT NULL
                                    CHECK (hash_domain = 'cis.policy.document.v1'),
    document_hash               TEXT NOT NULL,
    provenance                  TEXT NOT NULL,
    created_at                  TEXT NOT NULL,
    seq                         INTEGER NOT NULL
);

CREATE TRIGGER policy_sources_no_update
BEFORE UPDATE ON policy_sources
BEGIN SELECT RAISE(ABORT, 'append-only: policy_sources'); END;
CREATE TRIGGER policy_sources_no_delete
BEFORE DELETE ON policy_sources
BEGIN SELECT RAISE(ABORT, 'append-only: policy_sources'); END;
