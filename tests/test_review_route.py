"""Tests for cis.assurance.review_route receipt policy and hashing."""

import unittest

from cis.assurance import review_route
from cis.canonical import sha256_hex
from cis.errors import ReviewRefused


def _kwargs(**overrides):
    """Default valid kwargs for receipt_payload, with overrides applied."""
    base = dict(
        receipt_id="r1",
        task_contract_id="tc1",
        verification_result_id="vr1",
        review_id="rev1",
        review_packet_hash="a" * 64,
        implementer_request_id="ireq1",
        implementer_adapter_id="iadp1",
        reviewer_request_id="rreq1",
        reviewer_adapter_id=review_route.REQUIRED_ADAPTER,
        provider_id=review_route.PROVIDER_ID,
        model_id=review_route.MODEL_ID,
        implementer_lineage="impl_lineage",
        reviewer_lineage=review_route.REVIEWER_LINEAGE,
        response_schema_sha256=review_route.RESPONSE_SCHEMA_SHA256,
        response_evidence_id="rev_ev1",
        response_sha256="c" * 64,
        verdict="PASS",
        objections=[],
    )
    base.update(overrides)
    return base


def _make_receipt(**overrides):
    """Build a payload with overrides, append a correct receipt_hash."""
    payload = review_route.receipt_payload(**_kwargs(**overrides))
    receipt = dict(payload)
    receipt["receipt_hash"] = review_route.receipt_hash(payload)
    return receipt


class TestResponseSchema(unittest.TestCase):
    """Test the published RESPONSE_SCHEMA constant."""

    def test_schema_is_closed_object(self):
        schema = review_route.RESPONSE_SCHEMA
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), {"verdict", "objections"})

    def test_verdict_enum(self):
        verdict_schema = review_route.RESPONSE_SCHEMA["properties"]["verdict"]
        self.assertEqual(verdict_schema["type"], "string")
        self.assertEqual(set(verdict_schema["enum"]), {"PASS", "OBJECTIONS"})

    def test_objections_is_array_of_closed_objects(self):
        objections_schema = review_route.RESPONSE_SCHEMA["properties"]["objections"]
        self.assertEqual(objections_schema["type"], "array")
        item_schema = objections_schema["items"]
        self.assertEqual(item_schema["type"], "object")
        self.assertFalse(item_schema["additionalProperties"])
        self.assertEqual(set(item_schema["required"]), {"code", "detail"})
        self.assertEqual(item_schema["properties"]["code"]["minLength"], 1)
        self.assertEqual(item_schema["properties"]["detail"]["minLength"], 1)

    def test_schema_sha256_matches_schema(self):
        self.assertEqual(
            review_route.RESPONSE_SCHEMA_SHA256,
            sha256_hex(review_route.RESPONSE_SCHEMA),
        )
        self.assertEqual(len(review_route.RESPONSE_SCHEMA_SHA256), 64)


class TestReceiptPayload(unittest.TestCase):
    """Test receipt_payload creation."""

    def test_creates_dict_with_all_fields(self):
        payload = review_route.receipt_payload(**_kwargs())

        self.assertEqual(set(payload.keys()), set(review_route.PAYLOAD_FIELDS))
        self.assertEqual(payload["hash_domain"], review_route.HASH_DOMAIN)
        self.assertEqual(payload["receipt_id"], "r1")
        self.assertEqual(payload["verdict"], "PASS")
        self.assertEqual(payload["objections"], [])

    def test_objections_must_be_a_list_not_dict(self):
        """Old dict shape {concern: text} is no longer accepted."""
        with self.assertRaises(ReviewRefused):
            review_route.receipt_payload(
                **_kwargs(
                    verdict="OBJECTIONS",
                    objections={"concern_1": "objection text 1"},
                )
            )

    def test_valid_objections_list(self):
        payload = review_route.receipt_payload(
            **_kwargs(
                verdict="OBJECTIONS",
                objections=[{"code": "C1", "detail": "something wrong"}],
            )
        )
        self.assertEqual(
            payload["objections"], [{"code": "C1", "detail": "something wrong"}]
        )

    def test_malformed_objection_missing_field(self):
        with self.assertRaises(ReviewRefused):
            review_route.receipt_payload(
                **_kwargs(
                    verdict="OBJECTIONS",
                    objections=[{"code": "C1"}],
                )
            )

    def test_malformed_objection_extra_field(self):
        with self.assertRaises(ReviewRefused):
            review_route.receipt_payload(
                **_kwargs(
                    verdict="OBJECTIONS",
                    objections=[{"code": "C1", "detail": "d", "extra": "x"}],
                )
            )

    def test_malformed_objection_blank_code(self):
        with self.assertRaises(ReviewRefused):
            review_route.receipt_payload(
                **_kwargs(
                    verdict="OBJECTIONS",
                    objections=[{"code": "   ", "detail": "d"}],
                )
            )

    def test_malformed_objection_blank_detail(self):
        with self.assertRaises(ReviewRefused):
            review_route.receipt_payload(
                **_kwargs(
                    verdict="OBJECTIONS",
                    objections=[{"code": "C1", "detail": ""}],
                )
            )

    def test_whitespace_identifier_rejected(self):
        with self.assertRaises(ReviewRefused):
            review_route.receipt_payload(**_kwargs(receipt_id="   "))

    def test_empty_identifier_rejected(self):
        with self.assertRaises(ReviewRefused):
            review_route.receipt_payload(**_kwargs(receipt_id=""))

    def test_pass_with_objections_rejected(self):
        with self.assertRaises(ReviewRefused):
            review_route.receipt_payload(
                **_kwargs(
                    verdict="PASS",
                    objections=[{"code": "C1", "detail": "d"}],
                )
            )

    def test_objections_without_objections_rejected(self):
        with self.assertRaises(ReviewRefused):
            review_route.receipt_payload(**_kwargs(verdict="OBJECTIONS", objections=[]))


class TestReceiptHash(unittest.TestCase):
    """Test receipt_hash computation."""

    def test_deterministic_hash(self):
        payload = review_route.receipt_payload(**_kwargs())

        hash1 = review_route.receipt_hash(payload)
        hash2 = review_route.receipt_hash(payload)
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in hash1))

    def test_hash_includes_domain(self):
        payload1 = review_route.receipt_payload(**_kwargs())
        payload2 = dict(payload1)
        payload2["hash_domain"] = "different.domain.v1"

        hash1 = review_route.receipt_hash(payload1)
        with self.assertRaises(ReviewRefused):
            review_route.receipt_hash(payload2)

    def test_rejects_missing_payload_field(self):
        payload = review_route.receipt_payload(**_kwargs())
        del payload["receipt_id"]
        with self.assertRaises(ReviewRefused):
            review_route.receipt_hash(payload)

    def test_rejects_extra_payload_field(self):
        payload = review_route.receipt_payload(**_kwargs())
        payload["extra_field"] = "x"
        with self.assertRaises(ReviewRefused):
            review_route.receipt_hash(payload)


class TestVerifyReceiptValid(unittest.TestCase):
    """Test verify_receipt with valid receipts."""

    def test_valid_pass_receipt(self):
        receipt = _make_receipt()
        result = review_route.verify_receipt(receipt)
        self.assertEqual(result, receipt["receipt_hash"])

    def test_valid_objections_receipt(self):
        receipt = _make_receipt(
            verdict="OBJECTIONS",
            objections=[
                {"code": "C1", "detail": "objection text 1"},
                {"code": "C2", "detail": "objection text 2"},
            ],
            implementer_lineage="lineage_x",
        )
        result = review_route.verify_receipt(receipt)
        self.assertEqual(result, receipt["receipt_hash"])


class TestVerifyReceiptFieldSet(unittest.TestCase):
    """Test verify_receipt rejects missing/extra receipt fields."""

    def test_missing_field(self):
        receipt = _make_receipt()
        del receipt["review_id"]
        with self.assertRaises(ReviewRefused) as ctx:
            review_route.verify_receipt(receipt)
        self.assertIn("exactly the expected fields", str(ctx.exception))

    def test_missing_receipt_hash(self):
        receipt = _make_receipt()
        del receipt["receipt_hash"]
        with self.assertRaises(ReviewRefused) as ctx:
            review_route.verify_receipt(receipt)
        self.assertIn("exactly the expected fields", str(ctx.exception))

    def test_extra_field(self):
        receipt = _make_receipt()
        receipt["unexpected_field"] = "x"
        with self.assertRaises(ReviewRefused) as ctx:
            review_route.verify_receipt(receipt)
        self.assertIn("exactly the expected fields", str(ctx.exception))


class TestVerifyReceiptPolicyValidation(unittest.TestCase):
    """Test verify_receipt policy field validation."""

    def test_wrong_provider(self):
        with self.assertRaises(ReviewRefused) as ctx:
            _make_receipt(provider_id="wrong_provider")
        self.assertIn("provider_id", str(ctx.exception))

    def test_wrong_model(self):
        with self.assertRaises(ReviewRefused) as ctx:
            _make_receipt(model_id="gpt-4")
        self.assertIn("model_id", str(ctx.exception))

    def test_wrong_adapter(self):
        with self.assertRaises(ReviewRefused) as ctx:
            _make_receipt(reviewer_adapter_id="wrong_adapter")
        self.assertIn("adapter_id", str(ctx.exception))

    def test_wrong_reviewer_lineage(self):
        with self.assertRaises(ReviewRefused) as ctx:
            _make_receipt(reviewer_lineage="llama")
        self.assertIn("lineage", str(ctx.exception))


class TestVerifyReceiptIdentifierValidation(unittest.TestCase):
    """Test verify_receipt identifier validation."""

    def test_same_request_ids(self):
        with self.assertRaises(ReviewRefused) as ctx:
            _make_receipt(
                implementer_request_id="same_req",
                reviewer_request_id="same_req",
            )
        self.assertIn("must differ", str(ctx.exception))

    def test_same_adapter_ids(self):
        with self.assertRaises(ReviewRefused) as ctx:
            _make_receipt(
                implementer_adapter_id=review_route.REQUIRED_ADAPTER,
                reviewer_adapter_id=review_route.REQUIRED_ADAPTER,
            )
        self.assertIn("must differ", str(ctx.exception))

    def test_same_lineages(self):
        with self.assertRaises(ReviewRefused) as ctx:
            _make_receipt(
                implementer_lineage=review_route.REVIEWER_LINEAGE,
                reviewer_lineage=review_route.REVIEWER_LINEAGE,
            )
        self.assertIn("must differ", str(ctx.exception))

    def test_whitespace_only_identifier_rejected(self):
        with self.assertRaises(ReviewRefused):
            _make_receipt(review_id="   ")


class TestVerifyReceiptDigestValidation(unittest.TestCase):
    """Test verify_receipt digest validation."""

    def test_malformed_review_packet_hash(self):
        with self.assertRaises(ReviewRefused) as ctx:
            _make_receipt(review_packet_hash="not_a_valid_digest")
        self.assertIn("64 lowercase hex", str(ctx.exception))

    def test_malformed_response_sha256(self):
        with self.assertRaises(ReviewRefused) as ctx:
            _make_receipt(response_sha256="TOO_SHORT")
        self.assertIn("64 lowercase hex", str(ctx.exception))

    def test_malformed_response_schema_sha256(self):
        with self.assertRaises(ReviewRefused) as ctx:
            _make_receipt(response_schema_sha256="UPPERCASE_HEX" * 8)
        self.assertIn("64 lowercase hex", str(ctx.exception))

    def test_wrong_schema_digest(self):
        with self.assertRaises(ReviewRefused) as ctx:
            _make_receipt(response_schema_sha256="f" * 64)
        self.assertIn("schema", str(ctx.exception))

    def test_malformed_receipt_hash_rejected(self):
        receipt = _make_receipt()
        receipt["receipt_hash"] = "not_hex"
        with self.assertRaises(ReviewRefused) as ctx:
            review_route.verify_receipt(receipt)
        self.assertIn("64 lowercase hex", str(ctx.exception))


class TestVerifyReceiptVerdictValidation(unittest.TestCase):
    """Test verify_receipt verdict and objections agreement."""

    def test_pass_with_objections(self):
        with self.assertRaises(ReviewRefused) as ctx:
            _make_receipt(
                verdict="PASS",
                objections=[{"code": "C1", "detail": "text"}],
            )
        self.assertIn("PASS", str(ctx.exception))

    def test_objections_without_objections(self):
        with self.assertRaises(ReviewRefused) as ctx:
            _make_receipt(verdict="OBJECTIONS", objections=[])
        self.assertIn("OBJECTIONS", str(ctx.exception))

    def test_invalid_verdict(self):
        with self.assertRaises(ReviewRefused) as ctx:
            _make_receipt(verdict="UNKNOWN")
        self.assertIn("PASS or OBJECTIONS", str(ctx.exception))

    def test_old_dict_shaped_objections_rejected(self):
        with self.assertRaises(ReviewRefused):
            _make_receipt(
                verdict="OBJECTIONS",
                objections={"concern_1": "objection text 1"},
            )

    def test_malformed_objection_item_rejected(self):
        with self.assertRaises(ReviewRefused):
            _make_receipt(
                verdict="OBJECTIONS",
                objections=[{"code": "C1", "wrong_field": "x"}],
            )


class TestVerifyReceiptTampering(unittest.TestCase):
    """Test verify_receipt detects tampering."""

    def test_tampered_receipt_id(self):
        receipt = _make_receipt()
        receipt["receipt_id"] = "tampered_r1"
        with self.assertRaises(ReviewRefused) as ctx:
            review_route.verify_receipt(receipt)
        self.assertIn("receipt_hash", str(ctx.exception))

    def test_tampered_verdict(self):
        receipt = _make_receipt()
        receipt["verdict"] = "OBJECTIONS"
        receipt["objections"] = [{"code": "C1", "detail": "text"}]
        with self.assertRaises(ReviewRefused) as ctx:
            review_route.verify_receipt(receipt)
        self.assertIn("receipt_hash", str(ctx.exception))

    def test_tampered_response_sha256(self):
        receipt = _make_receipt()
        receipt["response_sha256"] = "d" * 64
        with self.assertRaises(ReviewRefused) as ctx:
            review_route.verify_receipt(receipt)
        self.assertIn("receipt_hash", str(ctx.exception))

    def test_tampered_objections_content(self):
        receipt = _make_receipt(
            verdict="OBJECTIONS",
            objections=[{"code": "C1", "detail": "original"}],
        )
        receipt["objections"] = [{"code": "C1", "detail": "tampered"}]
        with self.assertRaises(ReviewRefused) as ctx:
            review_route.verify_receipt(receipt)
        self.assertIn("receipt_hash", str(ctx.exception))

    def test_wrong_stored_hash(self):
        receipt = _make_receipt()
        receipt["receipt_hash"] = "e" * 64
        with self.assertRaises(ReviewRefused) as ctx:
            review_route.verify_receipt(receipt)
        self.assertIn("receipt_hash", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
