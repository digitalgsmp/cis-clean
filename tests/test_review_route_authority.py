"""Tests for Unit 9A2b: sanctioned reviewer-route receipt admission.

``ReviewerFacade.record_route_receipt`` is the only sanctioned behavioral path
into ``review_route_receipts``. Every positive case here goes through a real
task contract, a real deterministic verification, an independently assembled
``ReviewPacket``, a real ``ReviewerFacade.record_review`` call, and real
``EvidenceAuthority.admit`` evidence. A receipt that reaches the admission
point must also bind to a real worker-model request lifecycle (migration
0013): ``_seed_reviewer_lifecycle`` below inserts that lifecycle directly
against ``worker_supervision_plans``, ``worker_sessions``,
``worker_model_requests``, ``worker_session_events`` and ``backend_runs``,
since opening it through the real ``WorkerSessionAuthority``/
``WorkerSupervisorAuthority`` API needs a full supervision route this
fixture has no use for. The facade's own checks against the ledger are what
is actually exercised either way.
"""

import json
import unittest

from cis.assurance import review_route
from cis.assurance.reviewer import ReviewerInputPort
from cis.authority.runs import COMPLETED, RunAuthority
from cis.canonical import sha256_hex
from cis.errors import AppendOnlyViolation, CisError, ReviewRefused
from cis.execution.worker_session import (
    event_payload, request_payload, session_payload,
)

from . import support


def _assemble_packet(wb, task_contract_id, *, cycle_index=0):
    authority = support.assurance_authority(wb)
    port = ReviewerInputPort(store=wb.store, blueprint=wb.blueprint,
                             authority=authority)
    return port.assemble(task_contract_id, cycle_index=cycle_index)


def _prepare_review(wb, *, outcome, objections, review_id,
                    reviewer_lineage="qwen", reason_code="TEST_REASON"):
    """Drive one real task contract through verification and one real review.

    Returns (task_contract_id, verification_result_id, packet,
    authorization_id) so the caller can build a receipt that either matches
    or deliberately disagrees with what was actually recorded, and can seed
    the worker-request lifecycle the receipt's authorization must own.
    """
    wb2, authorization_id = support.allow_and_run(wb)
    compiled = support.freeze_task_contract(wb, authorization_id)
    task_contract_id = compiled.task_contract_id
    support.verifier(wb).verify(task_contract_id)
    packet = _assemble_packet(wb, task_contract_id)
    verification_result_id = packet.verification["result_id"]
    authority = support.assurance_authority(wb)
    authority.reviewer.record_review(
        review_id=review_id, task_contract_id=task_contract_id,
        verification_result_id=verification_result_id, cycle_index=0,
        outcome=outcome, reason_code=reason_code,
        reviewer_lineage=reviewer_lineage, packet_hash=packet.packet_hash,
        recomputed_task_contract_hash=packet.recomputed_task_contract_hash,
        recomputed_verification_result_hash=(
            packet.recomputed_verification_result_hash),
        objections=objections,
    )
    return task_contract_id, verification_result_id, packet, authorization_id


def _admit_response_evidence(wb, *, evidence_id, reviewer_request_id,
                             content):
    return wb.evidence.admit(
        evidence_id=evidence_id, kind="external_model_review_response",
        source_ref=f"openrouter:generation:{reviewer_request_id}",
        content=content, admission_basis="test:trusted-import",
    )


def _seed_worker_request(wb, authorization_id, *, request_id,
                         adapter_id=review_route.REQUIRED_ADAPTER,
                         response_schema_sha256=(
                             review_route.RESPONSE_SCHEMA_SHA256),
                         session_role="REVIEWER", session_adapter_id=None):
    """Append one real worker_sessions row and its worker_model_requests row,
    directly against migration 0013's tables. Returns the session_id."""
    auth = wb.authorizations.get(authorization_id)
    supervision_id = f"wsp-{request_id}"
    wb.store.insert("worker_supervision_plans", {
        "supervision_id": supervision_id,
        "objective_id": str(auth["objective_id"]),
        "transaction_id": str(auth["transaction_id"]),
        "target_module_id": str(auth["target_module_id"]),
        "operation": str(auth["operation"]),
        "routes_json": "[]", "route_count": 1, "circuit_threshold": 1,
        "hash_domain": "cis.execution.worker_supervision.plan.v1",
        "plan_hash": "9" * 64,
        "created_at": wb.store.now(), "seq": wb.store.next_seq(),
    })
    session_id = f"wks-{request_id}"
    session_row = {
        "session_id": session_id, "supervision_id": supervision_id,
        "route_index": 0, "objective_id": str(auth["objective_id"]),
        "transaction_id": str(auth["transaction_id"]),
        "target_module_id": str(auth["target_module_id"]),
        "operation": str(auth["operation"]), "logical_role": session_role,
        "adapter_id": session_adapter_id or adapter_id,
    }
    wb.store.insert("worker_sessions", {
        **session_row,
        "hash_domain": "cis.execution.worker_session.header.v1",
        "session_hash": sha256_hex(session_payload(session_row)),
        "created_at": wb.store.now(), "seq": wb.store.next_seq(),
    })
    request_row = {
        "request_id": request_id, "session_id": session_id,
        "supervision_id": supervision_id, "route_index": 0,
        "authorization_id": authorization_id, "adapter_id": adapter_id,
        "wall_time_ms": 1000, "token_limit": 1000, "cost_limit_micros": 1000,
        "prompt_sha256": "1" * 64, "context_sha256": "2" * 64,
        "response_schema_sha256": response_schema_sha256, "ordinal": 1,
    }
    wb.store.insert("worker_model_requests", {
        **request_row,
        "hash_domain": "cis.execution.worker_session.request.v1",
        "request_hash": sha256_hex(request_payload(request_row)),
        "created_at": wb.store.now(), "seq": wb.store.next_seq(),
    })
    return session_id


def _seed_worker_event(wb, *, session_id, request_id, event_type,
                       run_id=None, evidence_id=None, failure_class=None,
                       event_id=None):
    event_row = {
        "event_id": event_id or f"wkse-{request_id}-{event_type.lower()}",
        "session_id": session_id, "request_id": request_id,
        "event_type": event_type, "external_session_ref": None,
        "checkpoint_ref": None, "checkpoint_sha256": None,
        "run_id": run_id, "evidence_id": evidence_id,
        "failure_class": failure_class,
    }
    wb.store.insert("worker_session_events", {
        **event_row,
        "hash_domain": "cis.execution.worker_session.event.v1",
        "event_hash": sha256_hex(event_payload(event_row)),
        "created_at": wb.store.now(), "seq": wb.store.next_seq(),
    })


def _seed_backend_run(wb, *, run_id, authorization_id, adapter_id,
                      evidence_id, status=COMPLETED):
    RunAuthority(wb.store).record(
        run_id=run_id, authorization_id=authorization_id,
        adapter_id=adapter_id, request_hash="3" * 64, status=status,
        exit_code=0, result_hash="4" * 64, evidence_id=evidence_id,
    )


def _seed_reviewer_lifecycle(wb, authorization_id, *, reviewer_request_id,
                             response_evidence_id, run_id=None,
                             reviewer_adapter_id=review_route.REQUIRED_ADAPTER,
                             response_schema_sha256=(
                                 review_route.RESPONSE_SCHEMA_SHA256)):
    """Seed the complete, real worker-request lifecycle record_route_receipt
    now requires: a REVIEWER session, its request, a completed backend run
    and the REQUEST_SUCCEEDED event binding them together. Returns run_id.
    """
    run_id = run_id or f"run-{reviewer_request_id}"
    session_id = _seed_worker_request(
        wb, authorization_id, request_id=reviewer_request_id,
        adapter_id=reviewer_adapter_id,
        response_schema_sha256=response_schema_sha256)
    _seed_backend_run(wb, run_id=run_id, authorization_id=authorization_id,
                      adapter_id=reviewer_adapter_id,
                      evidence_id=response_evidence_id)
    _seed_worker_event(wb, session_id=session_id,
                       request_id=reviewer_request_id,
                       event_type="REQUEST_SUCCEEDED", run_id=run_id,
                       evidence_id=response_evidence_id)
    return run_id


def _receipt_kwargs(**overrides):
    base = dict(
        receipt_id="rrr-default",
        task_contract_id="tc-x",
        verification_result_id="vres-x",
        review_id="rev-x",
        review_packet_hash="a" * 64,
        implementer_request_id="ireq-default",
        implementer_adapter_id="iadp-default",
        reviewer_request_id="rreq-default",
        reviewer_adapter_id=review_route.REQUIRED_ADAPTER,
        provider_id=review_route.PROVIDER_ID,
        model_id=review_route.MODEL_ID,
        implementer_lineage="claude",
        reviewer_lineage=review_route.REVIEWER_LINEAGE,
        response_schema_sha256=review_route.RESPONSE_SCHEMA_SHA256,
        response_evidence_id="evi-default",
        response_sha256="c" * 64,
        verdict="PASS",
        objections=[],
    )
    base.update(overrides)
    return base


def _make_receipt(**overrides):
    payload = review_route.receipt_payload(**_receipt_kwargs(**overrides))
    receipt = dict(payload)
    receipt["receipt_hash"] = review_route.receipt_hash(payload)
    return receipt


class ReviewRouteReceiptPositiveTests(unittest.TestCase):
    """A real PASS and a real OBJECTIONS receipt, admitted end to end."""

    def test_record_route_receipt_pass(self):
        wb = support.workbench()
        (task_contract_id, verification_result_id, packet,
         authorization_id) = _prepare_review(
            wb, outcome="PASS", objections=[], review_id="rev-pass")
        evidence = _admit_response_evidence(
            wb, evidence_id="evi-pass",
            reviewer_request_id="rreq-pass",
            content=json.dumps({"verdict": "PASS", "objections": []},
                               sort_keys=True))
        _seed_reviewer_lifecycle(
            wb, authorization_id, reviewer_request_id="rreq-pass",
            response_evidence_id="evi-pass")
        receipt = _make_receipt(
            receipt_id="rrr-pass", task_contract_id=task_contract_id,
            verification_result_id=verification_result_id,
            review_id="rev-pass", review_packet_hash=packet.packet_hash,
            reviewer_request_id="rreq-pass",
            response_evidence_id="evi-pass",
            response_sha256=str(evidence["content_hash"]),
            verdict="PASS", objections=[],
        )
        authority = support.assurance_authority(wb)
        row = authority.reviewer.record_route_receipt(receipt)
        self.assertEqual(str(row["receipt_id"]), "rrr-pass")
        self.assertEqual(str(row["verdict"]), "PASS")
        self.assertEqual(str(row["receipt_hash"]), receipt["receipt_hash"])

    def test_record_route_receipt_objections(self):
        wb = support.workbench()
        objections = [{"code": "C1", "detail": "something is wrong"}]
        (task_contract_id, verification_result_id, packet,
         authorization_id) = _prepare_review(
            wb, outcome="OBJECTIONS", objections=objections,
            review_id="rev-obj")
        evidence = _admit_response_evidence(
            wb, evidence_id="evi-obj",
            reviewer_request_id="rreq-obj",
            content=json.dumps({"verdict": "OBJECTIONS",
                               "objections": objections}, sort_keys=True))
        _seed_reviewer_lifecycle(
            wb, authorization_id, reviewer_request_id="rreq-obj",
            response_evidence_id="evi-obj")
        receipt = _make_receipt(
            receipt_id="rrr-obj", task_contract_id=task_contract_id,
            verification_result_id=verification_result_id,
            review_id="rev-obj", review_packet_hash=packet.packet_hash,
            reviewer_request_id="rreq-obj",
            response_evidence_id="evi-obj",
            response_sha256=str(evidence["content_hash"]),
            verdict="OBJECTIONS", objections=objections,
        )
        authority = support.assurance_authority(wb)
        row = authority.reviewer.record_route_receipt(receipt)
        self.assertEqual(str(row["verdict"]), "OBJECTIONS")
        self.assertEqual(json.loads(str(row["objections_json"])), objections)


class ReviewRouteReceiptEvidenceTests(unittest.TestCase):
    """Every way the cited response evidence can fail to be what it claims."""

    def setUp(self):
        self.wb = support.workbench()
        (self.task_contract_id, self.verification_result_id,
         self.packet, self.authorization_id) = _prepare_review(
            self.wb, outcome="PASS", objections=[], review_id="rev-ev")
        self.authority = support.assurance_authority(self.wb)

    def _receipt(self, **overrides):
        defaults = dict(
            receipt_id="rrr-ev", task_contract_id=self.task_contract_id,
            verification_result_id=self.verification_result_id,
            review_id="rev-ev", review_packet_hash=self.packet.packet_hash,
            reviewer_request_id="rreq-ev", response_evidence_id="evi-ev",
            verdict="PASS", objections=[],
        )
        defaults.update(overrides)
        return _make_receipt(**defaults)

    def test_missing_evidence_rejected(self):
        receipt = self._receipt(response_sha256="d" * 64,
                                response_evidence_id="evi-absent")
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("response evidence", str(ctx.exception))

    def test_wrong_evidence_kind_rejected(self):
        content = json.dumps({"verdict": "PASS", "objections": []},
                             sort_keys=True)
        evidence = self.wb.evidence.admit(
            evidence_id="evi-wrong-kind", kind="note",
            source_ref="openrouter:generation:rreq-ev", content=content,
            admission_basis="test:trusted-import")
        receipt = self._receipt(response_evidence_id="evi-wrong-kind",
                                response_sha256=str(evidence["content_hash"]))
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("wrong kind", str(ctx.exception))

    def test_wrong_source_ref_rejected(self):
        content = json.dumps({"verdict": "PASS", "objections": []},
                             sort_keys=True)
        evidence = self.wb.evidence.admit(
            evidence_id="evi-wrong-source",
            kind="external_model_review_response",
            source_ref="openrouter:generation:some-other-request",
            content=content, admission_basis="test:trusted-import")
        receipt = self._receipt(response_evidence_id="evi-wrong-source",
                                response_sha256=str(evidence["content_hash"]))
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("source_ref", str(ctx.exception))

    def test_wrong_response_sha256_rejected(self):
        evidence = _admit_response_evidence(
            self.wb, evidence_id="evi-wrong-hash",
            reviewer_request_id="rreq-ev",
            content=json.dumps({"verdict": "PASS", "objections": []},
                               sort_keys=True))
        receipt = self._receipt(response_evidence_id="evi-wrong-hash",
                                response_sha256="f" * 64)
        self.assertNotEqual(str(evidence["content_hash"]), "f" * 64)
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("response_sha256", str(ctx.exception))

    def test_wrong_content_verdict_rejected(self):
        """Evidence content disagrees with the receipt's verdict."""
        evidence = _admit_response_evidence(
            self.wb, evidence_id="evi-wrong-verdict",
            reviewer_request_id="rreq-ev",
            content=json.dumps(
                {"verdict": "OBJECTIONS",
                 "objections": [{"code": "C1", "detail": "x"}]},
                sort_keys=True))
        receipt = self._receipt(response_evidence_id="evi-wrong-verdict",
                                response_sha256=str(evidence["content_hash"]),
                                verdict="PASS", objections=[])
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("verdict", str(ctx.exception))

    def test_wrong_content_objections_rejected(self):
        evidence = _admit_response_evidence(
            self.wb, evidence_id="evi-wrong-objections",
            reviewer_request_id="rreq-ev",
            content=json.dumps(
                {"verdict": "PASS", "objections": []}, sort_keys=True))
        # The receipt claims PASS too, but with the content's own objections
        # already empty this won't disagree, so use an evidence content that
        # disagrees with a PASS receipt: nonempty objections under PASS is
        # not constructible via receipt_payload (it refuses), so instead
        # disagree the other way: evidence carries extra, mismatched content
        # against a receipt that otherwise matches the review.
        content_mismatched = json.dumps(
            {"verdict": "PASS", "objections": [{"code": "C9", "detail": "d"}]},
            sort_keys=True)
        evidence2 = self.wb.evidence.admit(
            evidence_id="evi-wrong-objections-2",
            kind="external_model_review_response",
            source_ref="openrouter:generation:rreq-ev",
            content=content_mismatched, admission_basis="test:trusted-import")
        receipt = self._receipt(
            response_evidence_id="evi-wrong-objections-2",
            response_sha256=str(evidence2["content_hash"]),
            verdict="PASS", objections=[])
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("objections", str(ctx.exception))

    def test_evidence_content_not_closed_shape_rejected(self):
        content = json.dumps(
            {"verdict": "PASS", "objections": [], "extra": "field"},
            sort_keys=True)
        evidence = self.wb.evidence.admit(
            evidence_id="evi-extra-key",
            kind="external_model_review_response",
            source_ref="openrouter:generation:rreq-ev",
            content=content, admission_basis="test:trusted-import")
        receipt = self._receipt(response_evidence_id="evi-extra-key",
                                response_sha256=str(evidence["content_hash"]))
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("closed", str(ctx.exception))

    def test_evidence_content_not_json_rejected(self):
        content = "not json at all"
        evidence = self.wb.evidence.admit(
            evidence_id="evi-not-json",
            kind="external_model_review_response",
            source_ref="openrouter:generation:rreq-ev",
            content=content, admission_basis="test:trusted-import")
        receipt = self._receipt(response_evidence_id="evi-not-json",
                                response_sha256=str(evidence["content_hash"]))
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("JSON", str(ctx.exception))


class ReviewRouteReceiptLedgerMismatchTests(unittest.TestCase):
    """Every way the receipt can disagree with the review it cites."""

    def setUp(self):
        self.wb = support.workbench()
        (self.task_contract_id, self.verification_result_id,
         self.packet, self.authorization_id) = _prepare_review(
            self.wb, outcome="PASS", objections=[], review_id="rev-lm")
        self.authority = support.assurance_authority(self.wb)
        self.evidence = _admit_response_evidence(
            self.wb, evidence_id="evi-lm", reviewer_request_id="rreq-lm",
            content=json.dumps({"verdict": "PASS", "objections": []},
                               sort_keys=True))

    def _valid_receipt_kwargs(self, **overrides):
        defaults = dict(
            receipt_id="rrr-lm", task_contract_id=self.task_contract_id,
            verification_result_id=self.verification_result_id,
            review_id="rev-lm", review_packet_hash=self.packet.packet_hash,
            reviewer_request_id="rreq-lm", response_evidence_id="evi-lm",
            response_sha256=str(self.evidence["content_hash"]),
            verdict="PASS", objections=[],
        )
        defaults.update(overrides)
        return defaults

    def test_unknown_review_rejected(self):
        receipt = _make_receipt(**self._valid_receipt_kwargs(
            review_id="rev-does-not-exist"))
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("unknown review", str(ctx.exception))

    def test_wrong_task_contract_id_rejected(self):
        # Same store, a second authorization/task contract, so the id is
        # actually distinct from self.task_contract_id (ids are a
        # deterministic hash of inputs, and two fresh stores driven through
        # the same fixture instruction would otherwise collide).
        _wb, other_authorization_id = support.allow_and_run(self.wb)
        other_compiled = support.freeze_task_contract(
            self.wb, other_authorization_id)
        self.assertNotEqual(other_compiled.task_contract_id,
                            self.task_contract_id)
        receipt = _make_receipt(**self._valid_receipt_kwargs(
            task_contract_id=other_compiled.task_contract_id))
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("task_contract_id", ctx.exception.detail["disagreements"])

    def test_wrong_verification_result_id_rejected(self):
        receipt = _make_receipt(**self._valid_receipt_kwargs(
            verification_result_id="vres-does-not-match"))
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("verification_result_id",
                      ctx.exception.detail["disagreements"])

    def test_wrong_packet_hash_rejected(self):
        receipt = _make_receipt(**self._valid_receipt_kwargs(
            review_packet_hash="b" * 64))
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("review_packet_hash",
                      ctx.exception.detail["disagreements"])

    def test_wrong_verdict_rejected(self):
        """Receipt claims OBJECTIONS; the recorded review is PASS."""
        receipt = _make_receipt(**self._valid_receipt_kwargs(
            verdict="OBJECTIONS",
            objections=[{"code": "C1", "detail": "d"}]))
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("verdict", ctx.exception.detail["disagreements"])

    def test_wrong_objections_rejected(self):
        """Needs a recorded OBJECTIONS review whose objections differ from
        the receipt's."""
        objections = [{"code": "C1", "detail": "real objection"}]
        (task_contract_id, verification_result_id,
         packet, _lm_obj_authorization_id) = _prepare_review(
            self.wb, outcome="OBJECTIONS", objections=objections,
            review_id="rev-lm-obj")
        evidence = _admit_response_evidence(
            self.wb, evidence_id="evi-lm-obj",
            reviewer_request_id="rreq-lm-obj",
            content=json.dumps(
                {"verdict": "OBJECTIONS",
                 "objections": [{"code": "C2", "detail": "different"}]},
                sort_keys=True))
        receipt = _make_receipt(
            receipt_id="rrr-lm-obj", task_contract_id=task_contract_id,
            verification_result_id=verification_result_id,
            review_id="rev-lm-obj", review_packet_hash=packet.packet_hash,
            reviewer_request_id="rreq-lm-obj",
            response_evidence_id="evi-lm-obj",
            response_sha256=str(evidence["content_hash"]),
            verdict="OBJECTIONS",
            objections=[{"code": "C2", "detail": "different"}])
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("objections", ctx.exception.detail["disagreements"])

    def test_wrong_reviewer_lineage_rejected(self):
        """The recorded review used a lineage other than qwen; the receipt
        (which must say qwen, per the fixed reviewer policy) disagrees."""
        objections: list = []
        other_wb2, other_auth_id = support.allow_and_run(self.wb)
        compiled = support.freeze_task_contract(self.wb, other_auth_id)
        task_contract_id = compiled.task_contract_id
        support.verifier(self.wb).verify(task_contract_id)
        packet = _assemble_packet(self.wb, task_contract_id)
        verification_result_id = packet.verification["result_id"]
        self.authority.reviewer.record_review(
            review_id="rev-wrong-lineage", task_contract_id=task_contract_id,
            verification_result_id=verification_result_id, cycle_index=0,
            outcome="PASS", reason_code="TEST_REASON",
            reviewer_lineage="not-qwen", packet_hash=packet.packet_hash,
            recomputed_task_contract_hash=packet.recomputed_task_contract_hash,
            recomputed_verification_result_hash=(
                packet.recomputed_verification_result_hash),
            objections=objections,
        )
        evidence = _admit_response_evidence(
            self.wb, evidence_id="evi-wrong-lineage",
            reviewer_request_id="rreq-wrong-lineage",
            content=json.dumps({"verdict": "PASS", "objections": []},
                               sort_keys=True))
        receipt = _make_receipt(
            receipt_id="rrr-wrong-lineage", task_contract_id=task_contract_id,
            verification_result_id=verification_result_id,
            review_id="rev-wrong-lineage",
            review_packet_hash=packet.packet_hash,
            reviewer_request_id="rreq-wrong-lineage",
            response_evidence_id="evi-wrong-lineage",
            response_sha256=str(evidence["content_hash"]),
            verdict="PASS", objections=[],
        )
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("reviewer_lineage",
                      ctx.exception.detail["disagreements"])

    def test_verification_result_not_bound_to_task_rejected(self):
        """record_review trusts its caller's verification_result_id; this
        proves record_route_receipt independently checks that the cited
        verification result actually belongs to the cited task contract."""
        other_wb, other_authorization_id = support.allow_and_run()
        other_compiled = support.freeze_task_contract(
            other_wb, other_authorization_id)
        other_task_contract_id = other_compiled.task_contract_id
        support.verifier(other_wb).verify(other_task_contract_id)
        other_authority = support.assurance_authority(other_wb)
        other_verification_result_id = other_authority.ledger.verification_result(
            other_task_contract_id)["result_id"]

        wb3, auth_id3 = support.allow_and_run(self.wb)
        compiled3 = support.freeze_task_contract(self.wb, auth_id3)
        task_contract_id = compiled3.task_contract_id
        support.verifier(self.wb).verify(task_contract_id)
        packet = _assemble_packet(self.wb, task_contract_id)
        # Deliberately cite the OTHER task contract's verification result, a
        # thing record_review itself does not check.
        self.authority.reviewer.record_review(
            review_id="rev-mismatched-verification",
            task_contract_id=task_contract_id,
            verification_result_id=other_verification_result_id,
            cycle_index=0, outcome="PASS", reason_code="TEST_REASON",
            reviewer_lineage="qwen", packet_hash=packet.packet_hash,
            recomputed_task_contract_hash=packet.recomputed_task_contract_hash,
            recomputed_verification_result_hash=(
                packet.recomputed_verification_result_hash),
            objections=[],
        )
        evidence = _admit_response_evidence(
            self.wb, evidence_id="evi-mismatched-verification",
            reviewer_request_id="rreq-mismatched-verification",
            content=json.dumps({"verdict": "PASS", "objections": []},
                               sort_keys=True))
        receipt = _make_receipt(
            receipt_id="rrr-mismatched-verification",
            task_contract_id=task_contract_id,
            verification_result_id=other_verification_result_id,
            review_id="rev-mismatched-verification",
            review_packet_hash=packet.packet_hash,
            reviewer_request_id="rreq-mismatched-verification",
            response_evidence_id="evi-mismatched-verification",
            response_sha256=str(evidence["content_hash"]),
            verdict="PASS", objections=[],
        )
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("does not belong to", str(ctx.exception))


class ReviewRouteReceiptDuplicateAndAppendOnlyTests(unittest.TestCase):
    def setUp(self):
        self.wb = support.workbench()
        (self.task_contract_id, self.verification_result_id,
         self.packet, self.authorization_id) = _prepare_review(
            self.wb, outcome="PASS", objections=[], review_id="rev-dup2")
        self.authority = support.assurance_authority(self.wb)
        evidence = _admit_response_evidence(
            self.wb, evidence_id="evi-dup2", reviewer_request_id="rreq-dup2",
            content=json.dumps({"verdict": "PASS", "objections": []},
                               sort_keys=True))
        _seed_reviewer_lifecycle(
            self.wb, self.authorization_id, reviewer_request_id="rreq-dup2",
            response_evidence_id="evi-dup2")
        self.receipt = _make_receipt(
            receipt_id="rrr-dup2", task_contract_id=self.task_contract_id,
            verification_result_id=self.verification_result_id,
            review_id="rev-dup2", review_packet_hash=self.packet.packet_hash,
            reviewer_request_id="rreq-dup2", response_evidence_id="evi-dup2",
            response_sha256=str(evidence["content_hash"]),
            verdict="PASS", objections=[],
        )
        self.authority.reviewer.record_route_receipt(self.receipt)

    def test_duplicate_receipt_for_one_review_rejected(self):
        with self.assertRaises(CisError):
            self.authority.reviewer.record_route_receipt(self.receipt)

    def test_update_is_refused(self):
        with self.assertRaises(AppendOnlyViolation):
            self.wb.store.execute_raw(
                "UPDATE review_route_receipts SET verdict = 'OBJECTIONS' "
                "WHERE receipt_id = ?", ("rrr-dup2",))

    def test_delete_is_refused(self):
        with self.assertRaises(AppendOnlyViolation):
            self.wb.store.execute_raw(
                "DELETE FROM review_route_receipts WHERE receipt_id = ?",
                ("rrr-dup2",))


class ReviewRouteReceiptLookupTests(unittest.TestCase):
    def test_lookup_by_review_and_task_contract(self):
        wb = support.workbench()
        (task_contract_id, verification_result_id, packet,
         authorization_id) = _prepare_review(
            wb, outcome="PASS", objections=[], review_id="rev-lookup")
        authority = support.assurance_authority(wb)
        evidence = _admit_response_evidence(
            wb, evidence_id="evi-lookup",
            reviewer_request_id="rreq-lookup",
            content=json.dumps({"verdict": "PASS", "objections": []},
                               sort_keys=True))
        _seed_reviewer_lifecycle(
            wb, authorization_id, reviewer_request_id="rreq-lookup",
            response_evidence_id="evi-lookup")
        receipt = _make_receipt(
            receipt_id="rrr-lookup", task_contract_id=task_contract_id,
            verification_result_id=verification_result_id,
            review_id="rev-lookup", review_packet_hash=packet.packet_hash,
            reviewer_request_id="rreq-lookup",
            response_evidence_id="evi-lookup",
            response_sha256=str(evidence["content_hash"]),
            verdict="PASS", objections=[],
        )
        authority.reviewer.record_route_receipt(receipt)

        self.assertIsNone(
            authority.ledger.route_receipt_for_review("rev-no-such-review"))
        by_review = authority.ledger.route_receipt_for_review("rev-lookup")
        self.assertIsNotNone(by_review)
        self.assertEqual(str(by_review["receipt_id"]), "rrr-lookup")

        by_task = authority.ledger.route_receipts_for_task(task_contract_id)
        self.assertEqual(len(by_task), 1)
        self.assertEqual(str(by_task[0]["receipt_id"]), "rrr-lookup")
        self.assertEqual(
            authority.ledger.route_receipts_for_task("tc-no-such-task"), [])


class ReviewRouteReceiptWorkerLifecycleTests(unittest.TestCase):
    """A receipt must bind to a real worker-model request lifecycle, not
    just to caller-admitted evidence. Every way that binding can fail."""

    def setUp(self):
        self.wb = support.workbench()
        (self.task_contract_id, self.verification_result_id,
         self.packet, self.authorization_id) = _prepare_review(
            self.wb, outcome="PASS", objections=[], review_id="rev-wl")
        self.authority = support.assurance_authority(self.wb)
        self.evidence = _admit_response_evidence(
            self.wb, evidence_id="evi-wl", reviewer_request_id="rreq-wl",
            content=json.dumps({"verdict": "PASS", "objections": []},
                               sort_keys=True))

    def _receipt(self, **overrides):
        defaults = dict(
            receipt_id="rrr-wl", task_contract_id=self.task_contract_id,
            verification_result_id=self.verification_result_id,
            review_id="rev-wl", review_packet_hash=self.packet.packet_hash,
            reviewer_request_id="rreq-wl", response_evidence_id="evi-wl",
            response_sha256=str(self.evidence["content_hash"]),
            verdict="PASS", objections=[],
        )
        defaults.update(overrides)
        return _make_receipt(**defaults)

    def test_missing_request_rejected(self):
        """No worker_model_requests row was ever issued for this request."""
        receipt = self._receipt()
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("never issued", str(ctx.exception))

    def test_non_reviewer_role_rejected(self):
        """The request's session is real, but it is not a REVIEWER session."""
        session_id = _seed_worker_request(
            self.wb, self.authorization_id, request_id="rreq-wl",
            session_role="IMPLEMENTER")
        _seed_backend_run(
            self.wb, run_id="run-rreq-wl",
            authorization_id=self.authorization_id,
            adapter_id=review_route.REQUIRED_ADAPTER,
            evidence_id="evi-wl")
        _seed_worker_event(
            self.wb, session_id=session_id, request_id="rreq-wl",
            event_type="REQUEST_SUCCEEDED", run_id="run-rreq-wl",
            evidence_id="evi-wl")
        receipt = self._receipt()
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("not a REVIEWER session", str(ctx.exception))

    def test_adapter_mismatch_rejected(self):
        """The request was issued on a different adapter than the receipt
        claims."""
        _seed_worker_request(
            self.wb, self.authorization_id, request_id="rreq-wl",
            adapter_id="some_other_adapter")
        receipt = self._receipt()
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("does not match the receipt's adapter",
                      str(ctx.exception))

    def test_response_schema_mismatch_rejected(self):
        """The request was issued against a different response schema."""
        _seed_worker_request(
            self.wb, self.authorization_id, request_id="rreq-wl",
            response_schema_sha256="0" * 64)
        receipt = self._receipt()
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("does not match the receipt's adapter",
                      str(ctx.exception))

    def test_missing_terminal_event_rejected(self):
        """The request exists, but nothing ever reported it terminal."""
        _seed_worker_request(
            self.wb, self.authorization_id, request_id="rreq-wl")
        receipt = self._receipt()
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("exactly one terminal", str(ctx.exception))

    def test_failed_terminal_event_rejected(self):
        """The request ran, but failed rather than succeeded."""
        session_id = _seed_worker_request(
            self.wb, self.authorization_id, request_id="rreq-wl")
        _seed_worker_event(
            self.wb, session_id=session_id, request_id="rreq-wl",
            event_type="REQUEST_FAILED", failure_class="timeout")
        receipt = self._receipt()
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("exactly one terminal", str(ctx.exception))

    def test_success_event_cites_wrong_evidence_rejected(self):
        """The request succeeded, but its recorded evidence is not the one
        this receipt names."""
        other_evidence = _admit_response_evidence(
            self.wb, evidence_id="evi-wl-other",
            reviewer_request_id="rreq-wl-other",
            content=json.dumps({"verdict": "PASS", "objections": []},
                               sort_keys=True))
        _seed_reviewer_lifecycle(
            self.wb, self.authorization_id, reviewer_request_id="rreq-wl",
            response_evidence_id="evi-wl-other")
        receipt = self._receipt()
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("does not cite this receipt's response evidence",
                      str(ctx.exception))

    def test_backend_run_wrong_authorization_rejected(self):
        """The success event's run is real and completed, but it was
        dispatched under a different authorization than this request's."""
        other_wb, other_authorization_id = support.allow_and_run(self.wb)
        session_id = _seed_worker_request(
            self.wb, self.authorization_id, request_id="rreq-wl")
        _seed_backend_run(
            self.wb, run_id="run-rreq-wl",
            authorization_id=other_authorization_id,
            adapter_id=review_route.REQUIRED_ADAPTER,
            evidence_id="evi-wl")
        _seed_worker_event(
            self.wb, session_id=session_id, request_id="rreq-wl",
            event_type="REQUEST_SUCCEEDED", run_id="run-rreq-wl",
            evidence_id="evi-wl")
        receipt = self._receipt()
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("backend run", str(ctx.exception))

    def test_backend_run_not_completed_rejected(self):
        """The success event's run exists and otherwise matches, but it
        never completed."""
        session_id = _seed_worker_request(
            self.wb, self.authorization_id, request_id="rreq-wl")
        _seed_backend_run(
            self.wb, run_id="run-rreq-wl",
            authorization_id=self.authorization_id,
            adapter_id=review_route.REQUIRED_ADAPTER,
            evidence_id="evi-wl", status="failed")
        _seed_worker_event(
            self.wb, session_id=session_id, request_id="rreq-wl",
            event_type="REQUEST_SUCCEEDED", run_id="run-rreq-wl",
            evidence_id="evi-wl")
        receipt = self._receipt()
        with self.assertRaises(ReviewRefused) as ctx:
            self.authority.reviewer.record_route_receipt(receipt)
        self.assertIn("backend run", str(ctx.exception))

    def test_valid_lifecycle_admits_receipt(self):
        """The positive control: a real REVIEWER request, a real completed
        run and a real REQUEST_SUCCEEDED event admit the receipt."""
        _seed_reviewer_lifecycle(
            self.wb, self.authorization_id, reviewer_request_id="rreq-wl",
            response_evidence_id="evi-wl")
        receipt = self._receipt()
        row = self.authority.reviewer.record_route_receipt(receipt)
        self.assertEqual(str(row["receipt_id"]), "rrr-wl")


if __name__ == "__main__":
    unittest.main()
