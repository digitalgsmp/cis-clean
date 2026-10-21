-- 0015_review_route_receipts
--
-- Unit 9A2a: storage foundation only for the reviewer-route receipt
-- (cis.assurance.review_route). This migration persists the closed receipt
-- shape that cis.assurance.review_route.receipt_payload/receipt_hash already
-- validate in process; it adds no new validation of its own beyond what SQL
-- can enforce structurally, and it wires no caller. Nothing in this slice
-- reads or writes review_route_receipts yet: that is a later card.
--
-- review_route_receipts — owner: cis.assurance.authority
-- One immutable row per review, forward-linked to the task contract and
-- verification result it covers and to the review_results row it reports on.
-- review_id is UNIQUE so a review can produce at most one receipt, matching
-- the one-receipt-per-review rule of the written contract. The reviewer
-- policy fields (provider_id, model_id, reviewer_lineage) and hash_domain are
-- CHECKed to the single fixed value the policy in review_route.py admits;
-- a receipt naming any other adapter, provider, model or lineage is refused
-- by the authority itself, not merely by the in-process validator.
CREATE TABLE review_route_receipts (
    receipt_id               TEXT PRIMARY KEY CHECK (length(trim(receipt_id)) > 0),
    task_contract_id         TEXT NOT NULL
                                  REFERENCES task_contracts(task_contract_id),
    verification_result_id   TEXT NOT NULL
                                  REFERENCES verification_results(result_id),
    review_id                TEXT NOT NULL UNIQUE
                                  REFERENCES review_results(review_id),
    review_packet_hash       TEXT NOT NULL CHECK (length(review_packet_hash) = 64),
    implementer_request_id   TEXT NOT NULL CHECK (length(trim(implementer_request_id)) > 0),
    implementer_adapter_id   TEXT NOT NULL CHECK (length(trim(implementer_adapter_id)) > 0),
    reviewer_request_id      TEXT NOT NULL CHECK (length(trim(reviewer_request_id)) > 0),
    reviewer_adapter_id      TEXT NOT NULL CHECK (length(trim(reviewer_adapter_id)) > 0),
    provider_id               TEXT NOT NULL CHECK (provider_id = 'openrouter'),
    model_id                  TEXT NOT NULL CHECK (model_id = 'qwen/qwen3.7-max'),
    implementer_lineage       TEXT NOT NULL CHECK (length(trim(implementer_lineage)) > 0),
    reviewer_lineage          TEXT NOT NULL CHECK (reviewer_lineage = 'qwen'),
    response_schema_sha256    TEXT NOT NULL CHECK (length(response_schema_sha256) = 64),
    response_evidence_id      TEXT NOT NULL
                                  REFERENCES evidence_records(evidence_id),
    response_sha256           TEXT NOT NULL CHECK (length(response_sha256) = 64),
    verdict                   TEXT NOT NULL CHECK (verdict IN ('PASS', 'OBJECTIONS')),
    objections_json           TEXT NOT NULL,
    hash_domain               TEXT NOT NULL CHECK (
                                  hash_domain = 'cis.assurance.review_route_receipt.v1'),
    receipt_hash              TEXT NOT NULL CHECK (length(receipt_hash) = 64),
    created_at                TEXT NOT NULL,
    seq                       INTEGER NOT NULL,
    CHECK (implementer_adapter_id <> reviewer_adapter_id),
    CHECK (implementer_request_id <> reviewer_request_id),
    CHECK (implementer_lineage <> reviewer_lineage)
);

CREATE INDEX idx_review_route_receipts_task
    ON review_route_receipts(task_contract_id, seq);
CREATE INDEX idx_review_route_receipts_verification
    ON review_route_receipts(verification_result_id, seq);

CREATE TRIGGER review_route_receipts_no_update
BEFORE UPDATE ON review_route_receipts
BEGIN SELECT RAISE(ABORT, 'append-only: review_route_receipts'); END;
CREATE TRIGGER review_route_receipts_no_delete
BEFORE DELETE ON review_route_receipts
BEGIN SELECT RAISE(ABORT, 'append-only: review_route_receipts'); END;
