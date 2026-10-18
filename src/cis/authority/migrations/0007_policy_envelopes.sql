-- Append-only compiled MASTER/TASK policy envelope authority.
CREATE TABLE policy_envelopes (
    policy_envelope_id          TEXT PRIMARY KEY,
    task_contract_id            TEXT NOT NULL UNIQUE
                                    REFERENCES task_contracts(task_contract_id),
    task_contract_hash          TEXT NOT NULL,
    selector_json               TEXT NOT NULL,
    master_baseline_hash        TEXT NOT NULL,
    master_policy_ids_json      TEXT NOT NULL,
    task_policy_ids_json        TEXT NOT NULL,
    selected_policies_json      TEXT NOT NULL,
    prohibited_actions_json     TEXT NOT NULL,
    required_checks_json        TEXT NOT NULL,
    required_evidence_json      TEXT NOT NULL,
    narrowed_scope_json         TEXT,
    policy_set_hash             TEXT NOT NULL,
    hash_domain                 TEXT NOT NULL
                                    CHECK (hash_domain = 'cis.policy.envelope.v1'),
    envelope_hash               TEXT NOT NULL,
    created_at                  TEXT NOT NULL,
    seq                         INTEGER NOT NULL
);

CREATE TRIGGER policy_envelopes_no_update
BEFORE UPDATE ON policy_envelopes
BEGIN SELECT RAISE(ABORT, 'append-only: policy_envelopes'); END;
CREATE TRIGGER policy_envelopes_no_delete
BEFORE DELETE ON policy_envelopes
BEGIN SELECT RAISE(ABORT, 'append-only: policy_envelopes'); END;
