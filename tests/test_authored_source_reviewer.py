"""Unit 4: independent same-candidate review before promotion."""

from __future__ import annotations

import json
import unittest

from cis.assurance.authority import (
    AssuranceAuthority, PROMOTION_AUTHORIZED, PROMOTION_DENIED, REVIEW_PASS,
    review_result_hash_of_row,
)
from cis.assurance.promotion import PromotionRecorder
from cis.assurance.reviewer import Reviewer
from cis.assurance.verifier import Verifier
from cis.canonical import canonical_json, sha256_text
from cis.errors import PromotionRefused, ReviewRefused

from .test_authored_source_verifier import executed_case


def verified_case():
    fixture, adapter = executed_case()
    verification = Verifier(
        fixture.wb.store, fixture.wb.blueprint).verify(
            fixture.compiled.task_contract_id)
    return fixture, adapter, verification


class AuthoredSourceReviewerTests(unittest.TestCase):
    def _overwrite_evidence_content(self, fixture, new_content: dict) -> None:
        """Replace the admitted evidence row's content with ``new_content``,
        recomputing its digest exactly as admission does, so only the
        attestation-binding field set under test varies."""
        new_content_text = json.dumps(new_content)
        fixture.wb.store.execute_raw("DROP TRIGGER evidence_records_no_update")
        fixture.wb.store.execute_raw(
            "UPDATE evidence_records SET content = ?, content_hash = ? "
            "WHERE evidence_id = ?",
            (new_content_text, sha256_text(new_content_text),
             f"evi-run-{fixture.verify_authorization_id}"))

    def test_legacy_three_field_envelope_still_passes(self):
        # The pre-usage envelope, unmodified: proves the independent reviewer
        # still accepts the old shape byte-for-byte.
        fixture, _, _ = verified_case()
        review, cycle = Reviewer(
            fixture.wb.store, fixture.wb.blueprint).review(
                fixture.compiled.task_contract_id)
        self.assertEqual(review["outcome"], REVIEW_PASS)
        self.assertIsNone(cycle)

    def test_valid_optional_usage_field_still_passes(self):
        # Mutate before verification, like the verifier's own equivalent
        # test, so neither module's recorded packet is stale against the
        # evidence the reviewer independently re-reads.
        fixture, _ = executed_case()
        evidence = fixture.wb.store.one(
            "SELECT * FROM evidence_records WHERE evidence_id = ?",
            (f"evi-run-{fixture.verify_authorization_id}",))
        content = json.loads(str(evidence["content"]))
        content["usage"] = {
            "wall_time_ms": 12, "tokens_used": 345, "cost_micros": 6,
        }
        self._overwrite_evidence_content(fixture, content)
        Verifier(fixture.wb.store, fixture.wb.blueprint).verify(
            fixture.compiled.task_contract_id)

        review, cycle = Reviewer(
            fixture.wb.store, fixture.wb.blueprint).review(
                fixture.compiled.task_contract_id)
        self.assertEqual(review["outcome"], REVIEW_PASS)
        self.assertIsNone(cycle)

    def test_malformed_usage_field_fails_closed_with_binding_objection(self):
        malformed_cases = {
            "missing_key": {"wall_time_ms": 1, "tokens_used": 2},
            "extra_key": {"wall_time_ms": 1, "tokens_used": 2,
                          "cost_micros": 3, "extra": 4},
            "negative_value": {"wall_time_ms": -1, "tokens_used": 2,
                               "cost_micros": 3},
            "bool_value": {"wall_time_ms": True, "tokens_used": 2,
                           "cost_micros": 3},
            "non_mapping": "not-a-mapping",
        }
        for label, usage in malformed_cases.items():
            with self.subTest(usage=label):
                fixture, _ = executed_case()
                evidence = fixture.wb.store.one(
                    "SELECT * FROM evidence_records WHERE evidence_id = ?",
                    (f"evi-run-{fixture.verify_authorization_id}",))
                content = json.loads(str(evidence["content"]))
                content["usage"] = usage
                self._overwrite_evidence_content(fixture, content)
                Verifier(fixture.wb.store, fixture.wb.blueprint).verify(
                    fixture.compiled.task_contract_id)

                review, cycle = Reviewer(
                    fixture.wb.store, fixture.wb.blueprint).review(
                        fixture.compiled.task_contract_id)
                self.assertEqual(review["outcome"], "OBJECTIONS")
                self.assertEqual(
                    review["reason_code"],
                    "INDEPENDENT_CANDIDATE_EVIDENCE_BINDING_FAILED")
                objections = json.loads(str(review["objections_json"]))
                self.assertIn(
                    "CANDIDATE_OR_EVIDENCE_BINDING_DID_NOT_RECOMPUTE",
                    {item["objection"] for item in objections})
                self.assertIsNotNone(cycle)

    def test_unexpected_extra_top_level_evidence_field_fails_closed(self):
        fixture, _ = executed_case()
        evidence = fixture.wb.store.one(
            "SELECT * FROM evidence_records WHERE evidence_id = ?",
            (f"evi-run-{fixture.verify_authorization_id}",))
        content = json.loads(str(evidence["content"]))
        content["unexpected_field"] = "forged"
        self._overwrite_evidence_content(fixture, content)
        Verifier(fixture.wb.store, fixture.wb.blueprint).verify(
            fixture.compiled.task_contract_id)

        review, cycle = Reviewer(
            fixture.wb.store, fixture.wb.blueprint).review(
                fixture.compiled.task_contract_id)
        self.assertEqual(review["outcome"], "OBJECTIONS")
        self.assertEqual(review["reason_code"],
                         "INDEPENDENT_CANDIDATE_EVIDENCE_BINDING_FAILED")
        objections = json.loads(str(review["objections_json"]))
        self.assertIn(
            "CANDIDATE_OR_EVIDENCE_BINDING_DID_NOT_RECOMPUTE",
            {item["objection"] for item in objections})
        self.assertIsNotNone(cycle)

    def test_independent_review_of_same_candidate_enables_promotion(self):
        fixture, _, verification = verified_case()
        review, cycle = Reviewer(
            fixture.wb.store, fixture.wb.blueprint).review(
                fixture.compiled.task_contract_id)
        self.assertEqual(review["outcome"], REVIEW_PASS)
        self.assertEqual(review["verification_result_id"],
                         verification["result_id"])
        self.assertEqual(review["recomputed_verification_result_hash"],
                         verification["result_hash"])
        self.assertIsNone(cycle)
        decision = PromotionRecorder(fixture.wb.store).decide(
            fixture.compiled.task_contract_id)
        self.assertEqual(decision["decision"], PROMOTION_AUTHORIZED)
        self.assertEqual(decision["host_action"], "NONE_RECORD_ONLY")

    def test_self_consistent_evidence_substitution_draws_review_objection(self):
        fixture, _, _ = verified_case()
        evidence_id = f"evi-run-{fixture.verify_authorization_id}"
        evidence = fixture.wb.store.one(
            "SELECT * FROM evidence_records WHERE evidence_id = ?",
            (evidence_id,))
        text = str(evidence["original_language"]).replace(
            str(fixture.exi_row["candidate_sha256"]), "0" * 64)
        binding = json.loads(str(evidence["content"]))
        binding["attestation_sha256"] = sha256_text(text)
        content = canonical_json(binding)
        fixture.wb.store.execute_raw("DROP TRIGGER evidence_records_no_update")
        fixture.wb.store.execute_raw(
            "UPDATE evidence_records SET original_language = ?, content = ?, "
            "content_hash = ? WHERE evidence_id = ?",
            (text, content, sha256_text(content), evidence_id))

        review, cycle = Reviewer(
            fixture.wb.store, fixture.wb.blueprint).review(
                fixture.compiled.task_contract_id)
        self.assertEqual(review["outcome"], "OBJECTIONS")
        self.assertEqual(review["reason_code"],
                         "INDEPENDENT_CANDIDATE_EVIDENCE_BINDING_FAILED")
        objections = json.loads(str(review["objections_json"]))
        self.assertIn(
            "CANDIDATE_OR_EVIDENCE_BINDING_DID_NOT_RECOMPUTE",
            {item["objection"] for item in objections})
        self.assertIsNotNone(cycle)
        decision = PromotionRecorder(fixture.wb.store).decide(
            fixture.compiled.task_contract_id)
        self.assertEqual(decision["decision"], PROMOTION_DENIED)
        self.assertEqual(decision["reason_code"], "REVIEW_RAISED_OBJECTIONS")

    def test_corrupt_verifier_input_packet_is_refused_not_reviewed(self):
        fixture, _, _ = verified_case()
        fixture.wb.store.execute_raw(
            "DROP TRIGGER verification_inputs_no_update")
        fixture.wb.store.execute_raw(
            "UPDATE verification_inputs SET inputs_hash = ? "
            "WHERE task_contract_id = ?",
            ("0" * 64, fixture.compiled.task_contract_id))
        with self.assertRaises(ReviewRefused):
            Reviewer(fixture.wb.store, fixture.wb.blueprint).review(
                fixture.compiled.task_contract_id)
        self.assertIsNone(fixture.wb.store.one(
            "SELECT * FROM review_results WHERE task_contract_id = ?",
            (fixture.compiled.task_contract_id,)))

    def test_promotion_denies_self_consistent_review_link_mismatch(self):
        fixture, _, _ = verified_case()
        review, _ = Reviewer(
            fixture.wb.store, fixture.wb.blueprint).review(
                fixture.compiled.task_contract_id)
        forged = dict(review)
        forged["recomputed_verification_result_hash"] = "0" * 64
        forged["review_hash"] = review_result_hash_of_row(forged)
        fixture.wb.store.execute_raw("DROP TRIGGER review_results_no_update")
        fixture.wb.store.execute_raw(
            "UPDATE review_results SET recomputed_verification_result_hash = ?, "
            "review_hash = ? WHERE review_id = ?",
            (forged["recomputed_verification_result_hash"],
             forged["review_hash"], review["review_id"]))

        with self.assertRaises(PromotionRefused):
            AssuranceAuthority(fixture.wb.store).promotion.record_decision(
                decision_id="pd-forced-mismatch",
                task_contract_id=fixture.compiled.task_contract_id,
                decision=PROMOTION_AUTHORIZED,
                reason_code="forced",
                verification_result_id=review["verification_result_id"],
                review_id=review["review_id"])

        decision = PromotionRecorder(fixture.wb.store).decide(
            fixture.compiled.task_contract_id)
        self.assertEqual(decision["decision"], PROMOTION_DENIED)
        self.assertEqual(decision["reason_code"],
                         "REVIEW_NOT_BOUND_TO_VERIFIED_CANDIDATE")


if __name__ == "__main__":
    unittest.main()
