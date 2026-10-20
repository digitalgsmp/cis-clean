"""Unit 3B: deterministic verification of exact authorized worker inputs."""

from __future__ import annotations

import json
import unittest

from cis.assurance.authority import VERIFIED_FAIL, VERIFIED_PASS
from cis.assurance.verifier import Verifier
from cis.canonical import sha256_text
from cis.errors import ExecutionInputTampered
from cis.execution.port import ExecutionPort, ExecutionResult

from .test_execution_input_gateway import ExecutionInputGatewayFixture


class AttestingAdapter(ExecutionPort):
    adapter_id = "attesting_contained_worker"
    requires_frozen_task_contract = True
    requires_execution_input = True

    def __init__(self, image, *, overrides=None):
        self.execution_image_identity = image
        self.overrides = dict(overrides or {})

    def capabilities(self):
        return ("verify_authored_source",)

    def execute(self, request):
        request.verify_token()
        payload = request.payload
        values = {
            "schema": "cis-contained-adapter-attestation-v1",
            "operation": "verify_authored_source",
            "adapter": self.adapter_id,
            "image": self.execution_image_identity,
            "worker_operation": "verify-authored-source",
            "execution_input_hash": payload["execution_input_hash"],
            "task_contract_id": payload["task_contract_id"],
            "task_contract_hash": payload["task_contract_hash"],
            "entrypoint": payload["entrypoint"],
            "verdict": "SOURCE_PASS", "classification": "SOURCE_PASS",
            "attestation_valid": "true", "attestation_failures": "none",
            "worker_exit": "0", "source_sha256": payload["candidate_sha256"],
            "vector_contract_sha256": payload["vector_contract_sha256"],
            "task_contract_bundle_sha256": "9" * 64,
            "authorization_binding_hash": request.binding_hash,
            "trusted_runner_sha256": payload["expected_trusted_runner_sha256"],
            "worker_sha256": payload["expected_worker_sha256"],
            "declared_vectors": str(len(payload["vectors"])),
            "allowed_scope": ",".join(request.allowed_scope),
            "forbidden_actions": ",".join(request.forbidden_actions),
            "stopped_at": request.stopping_condition,
            "returned_to": request.return_point,
        }
        values.update(self.overrides)
        return ExecutionResult(
            status="completed", exit_code=0, outputs={}, checks_performed=(),
            evidence=tuple(f"{key}={value}" for key, value in values.items()),
        )


def executed_case(*, overrides=None):
    fixture = ExecutionInputGatewayFixture(methodName="runTest")
    fixture.setUp()
    adapter = AttestingAdapter(
        fixture.exi_row["worker_image"], overrides=overrides)
    fixture.registry.register(adapter)
    fixture.dispatch(fixture.gateway.using(adapter.adapter_id))
    return fixture, adapter


class AuthoredSourceVerifierTests(unittest.TestCase):
    def test_exact_attestation_passes_all_required_checks(self):
        fixture, _ = executed_case()
        result = Verifier(fixture.wb.store, fixture.wb.blueprint).verify(
            fixture.compiled.task_contract_id)
        self.assertEqual(result["outcome"], VERIFIED_PASS)
        self.assertEqual(result["reason_code"], "ALL_REQUIRED_CHECKS_COVERED")

    def test_each_authorized_input_mismatch_fails_deterministically(self):
        cases = {
            "execution input": ("execution_input_hash", "0" * 64,
                                "EXECUTION_INPUT_BINDING_MISSING_OR_MISMATCHED"),
            "candidate": ("source_sha256", "0" * 64,
                          "CANDIDATE_SOURCE_BINDING_MISMATCH"),
            "vectors": ("vector_contract_sha256", "0" * 64,
                        "VECTOR_CONTRACT_BINDING_MISMATCH"),
            "entrypoint": ("entrypoint", "other",
                           "AUTHORIZED_ENTRYPOINT_BINDING_MISMATCH"),
            "image": ("image", "sha256:" + "0" * 64,
                      "WORKER_IMAGE_IDENTITY_MISMATCH"),
            "runner": ("trusted_runner_sha256", "0" * 64,
                       "TRUSTED_RUNNER_IDENTITY_MISMATCH"),
            "worker": ("worker_sha256", "0" * 64,
                       "WORKER_IDENTITY_MISMATCH"),
        }
        for label, (key, value, reason) in cases.items():
            with self.subTest(binding=label):
                fixture, _ = executed_case(overrides={key: value})
                result = Verifier(
                    fixture.wb.store, fixture.wb.blueprint).verify(
                        fixture.compiled.task_contract_id)
                self.assertEqual(result["outcome"], VERIFIED_FAIL)
                self.assertEqual(result["reason_code"], reason)

    def test_forged_result_classification_is_rejected(self):
        fixture, _ = executed_case(overrides={
            "classification": "SOURCE_FAIL", "verdict": "SOURCE_FAIL",
            "worker_exit": "1",
        })
        result = Verifier(fixture.wb.store, fixture.wb.blueprint).verify(
            fixture.compiled.task_contract_id)
        self.assertEqual(result["outcome"], VERIFIED_FAIL)
        self.assertEqual(result["reason_code"],
                         "RESULT_CLASSIFICATION_INVALID_OR_UNBOUND")

    def test_malformed_or_extra_attestation_field_fails_closed(self):
        fixture, adapter = executed_case(overrides={"forged": "yes"})
        result = Verifier(fixture.wb.store, fixture.wb.blueprint).verify(
            fixture.compiled.task_contract_id)
        self.assertEqual(result["outcome"], VERIFIED_FAIL)
        self.assertEqual(result["reason_code"], "REQUIRED_ARTIFACT_ABSENT")

    def test_substituted_attestation_text_cannot_reuse_the_evidence_digest(self):
        fixture, _ = executed_case()
        fixture.wb.store.execute_raw("DROP TRIGGER evidence_records_no_update")
        fixture.wb.store.execute_raw(
            "UPDATE evidence_records SET original_language = replace(" 
            "original_language, ?, ?) WHERE evidence_id = ?",
            (fixture.exi_row["candidate_sha256"], "0" * 64,
             f"evi-run-{fixture.verify_authorization_id}"))
        result = Verifier(fixture.wb.store, fixture.wb.blueprint).verify(
            fixture.compiled.task_contract_id)
        self.assertEqual(result["outcome"], VERIFIED_FAIL)
        self.assertEqual(result["reason_code"], "REQUIRED_ARTIFACT_ABSENT")

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
        # The pre-usage envelope, unmodified: proves the old shape is still
        # accepted byte-for-byte.
        fixture, _ = executed_case()
        result = Verifier(fixture.wb.store, fixture.wb.blueprint).verify(
            fixture.compiled.task_contract_id)
        self.assertEqual(result["outcome"], VERIFIED_PASS)

    def test_valid_optional_usage_field_still_passes(self):
        fixture, _ = executed_case()
        evidence = fixture.wb.store.one(
            "SELECT * FROM evidence_records WHERE evidence_id = ?",
            (f"evi-run-{fixture.verify_authorization_id}",))
        content = json.loads(str(evidence["content"]))
        content["usage"] = {
            "wall_time_ms": 12, "tokens_used": 345, "cost_micros": 6,
        }
        self._overwrite_evidence_content(fixture, content)

        result = Verifier(fixture.wb.store, fixture.wb.blueprint).verify(
            fixture.compiled.task_contract_id)
        self.assertEqual(result["outcome"], VERIFIED_PASS)
        self.assertEqual(result["reason_code"], "ALL_REQUIRED_CHECKS_COVERED")

    def test_malformed_usage_field_fails_closed(self):
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

                result = Verifier(fixture.wb.store, fixture.wb.blueprint).verify(
                    fixture.compiled.task_contract_id)
                self.assertEqual(result["outcome"], VERIFIED_FAIL)
                self.assertEqual(result["reason_code"], "REQUIRED_ARTIFACT_ABSENT")

    def test_unexpected_extra_top_level_evidence_field_fails_closed(self):
        fixture, _ = executed_case()
        evidence = fixture.wb.store.one(
            "SELECT * FROM evidence_records WHERE evidence_id = ?",
            (f"evi-run-{fixture.verify_authorization_id}",))
        content = json.loads(str(evidence["content"]))
        content["unexpected_field"] = "forged"
        self._overwrite_evidence_content(fixture, content)

        result = Verifier(fixture.wb.store, fixture.wb.blueprint).verify(
            fixture.compiled.task_contract_id)
        self.assertEqual(result["outcome"], VERIFIED_FAIL)
        self.assertEqual(result["reason_code"], "REQUIRED_ARTIFACT_ABSENT")

    def test_tampered_execution_input_authority_is_refused_not_assessed(self):
        fixture, _ = executed_case()
        fixture.wb.store.execute_raw(
            "DROP TRIGGER task_execution_inputs_no_update")
        fixture.wb.store.execute_raw(
            "UPDATE task_execution_inputs SET execution_input_hash = ? "
            "WHERE task_contract_id = ?",
            ("0" * 64, fixture.compiled.task_contract_id))
        with self.assertRaises(ExecutionInputTampered):
            Verifier(fixture.wb.store, fixture.wb.blueprint).verify(
                fixture.compiled.task_contract_id)
        self.assertIsNone(
            fixture.wb.store.one(
                "SELECT * FROM verification_results WHERE task_contract_id = ?",
                (fixture.compiled.task_contract_id,)))


if __name__ == "__main__":
    unittest.main()
