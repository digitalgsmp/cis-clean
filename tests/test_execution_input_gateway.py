"""Unit 2B of workstream 4.37: the gateway bound to a real execution-input row.

Proof that ``ExecutionGateway`` can derive a token-covered request payload
entirely from a frozen ``verify_authored_source.v1`` task contract and its
bound ``task_execution_inputs`` row, that ``ExecutionGateway.using`` carries
both resolvers over to a swapped adapter, and — in ``GatewayRefusalTests`` —
that every way the pair can disagree refuses before the adapter is entered
and before the one-attempt claim is spent.
No task type is issued by production code yet, so this fixture mints its own
second ALLOW authorization directly through ``AuthorizationAuthority.record``,
over the same transaction, decision, objective, target and baseline as the
authoritative ``support.allow_outcome`` ALLOW, naming operation
``verify_authored_source`` instead.
"""

from __future__ import annotations

import hashlib
import unittest

from cis.assurance.execution_input import (
    execution_input_id_for,
    hash_of_row as execution_input_hash_of_row,
    verify_row as verify_execution_input_row,
)
from cis.assurance.task_contract import (
    hash_of_row as task_contract_hash_of_row,
    verify_row as verify_task_contract_row,
)
from cis.canonical import canonical_json
from cis.errors import ExecutionRefused
from cis.execution import AdapterRegistry, ExecutionGateway
from cis.execution.port import ExecutionPort, ExecutionResult

from . import support

CANDIDATE = b"def run(args):\n    return args[0]\n"
VECTOR_CONTRACT = canonical_json([{"args": [1], "expect_value": 1}]).encode("utf-8")
WORKER_IMAGE = "sha256:" + "c" * 64
RUNNER_DIGEST = "a" * 64
WORKER_DIGEST = "b" * 64

#: A different, equally well-formed immutable image identity: the one fact the
#: worker-image refusal turns on.
OTHER_WORKER_IMAGE = "sha256:" + "d" * 64

#: A task contract that is not the one this fixture froze.
FOREIGN_TASK_CONTRACT_ID = "tc-" + "f" * 12
FOREIGN_TASK_CONTRACT_HASH = hashlib.sha256(
    b"not the frozen task contract").hexdigest()
FOREIGN_BINDING_HASH = hashlib.sha256(b"not this authorization").hexdigest()

#: Lets a helper tell "resolver deliberately removed" apart from "resolver
#: left as the fixture's working one". ``None`` is itself a case under test.
_UNSET = object()


class RecordingAdapter(ExecutionPort):
    requires_frozen_task_contract = True
    requires_execution_input = True
    execution_image_identity = WORKER_IMAGE

    def __init__(self, adapter_id: str) -> None:
        self.adapter_id = adapter_id
        self.requests = []

    def capabilities(self):
        return ("verify_authored_source",)

    def execute(self, request):
        request.verify_token()
        self.requests.append(request)
        return ExecutionResult(
            status="completed", exit_code=0, outputs={},
            checks_performed=(), evidence=(),
        )


class ExecutionInputGatewayFixture(unittest.TestCase):
    """A frozen ``verify_authored_source.v1`` contract with a real binding."""

    def setUp(self):
        self.wb, outcome = support.allow_outcome()
        original = outcome.authorization

        self.verify_authorization_id = f"auth-verify-{original['transaction_id']}"
        scope = dict(original["scope"])
        scope["operation"] = "verify_authored_source"
        self.wb.authorizations.record(
            authorization_id=self.verify_authorization_id,
            transaction_id=original["transaction_id"],
            decision_id=original["decision_id"],
            objective_id=original["objective_id"],
            verdict="ALLOW",
            reason_code=original["reason_code"],
            reason=original["reason"],
            target_module_id=original["target_module_id"],
            scope=scope,
            verbatim_hash=original["verbatim_hash"],
            decision_hash=original["decision_hash"],
            baseline_hash=original["baseline_hash"],
        )

        self.compiled = support.freeze_task_contract(
            self.wb, self.verify_authorization_id,
            template_id="verify_authored_source.v1")
        frozen_contract = support.assurance_authority(self.wb).ledger.require_task_contract(
            self.compiled.task_contract_id)

        self.exi_row = support.execution_input_authority(self.wb).append(
            task_contract_id=self.compiled.task_contract_id,
            candidate_source=CANDIDATE,
            candidate_sha256=hashlib.sha256(CANDIDATE).hexdigest(),
            vector_contract=VECTOR_CONTRACT,
            vector_contract_sha256=hashlib.sha256(VECTOR_CONTRACT).hexdigest(),
            authorized_entrypoint="run",
            task_contract_hash=str(frozen_contract["task_contract_hash"]),
            authorization_binding_hash=str(
                frozen_contract["authorization_binding_hash"]),
            worker_image=WORKER_IMAGE,
            expected_trusted_runner_sha256=RUNNER_DIGEST,
            expected_worker_sha256=WORKER_DIGEST,
        )

        self.adapter = RecordingAdapter("recording_execution_input_adapter")
        self.adapter_2 = RecordingAdapter("recording_execution_input_adapter_2")
        self.registry = AdapterRegistry()
        self.registry.register(self.adapter)
        self.registry.register(self.adapter_2)

        ledger = support.assurance_authority(self.wb).ledger
        self.gateway = ExecutionGateway(
            authorizations=self.wb.authorizations, runs=self.wb.runs,
            evidence=self.wb.evidence, trajectory=self.wb.trajectory,
            registry=self.registry, adapter_id=self.adapter.adapter_id,
            task_contract_resolver=ledger.task_contract_for_authorization,
            execution_input_resolver=support.execution_input_authority(
                self.wb).verify,
            # The authorization's own required checks are recomputed by the
            # real Workbench preflight, never asserted by this fixture.
            authorization_check_resolver=self.wb.execution_preflight_checks,
        )

    def dispatch(self, gateway):
        return gateway.dispatch(
            self.verify_authorization_id,
            baseline_hash=self.wb.blueprint.baseline_hash,
            active_objective_id=self.wb.continuity.active_objective_id(),
        )


class GatewayDispatchTests(ExecutionInputGatewayFixture):
    def test_dispatch_reaches_adapter_with_derived_payload_and_valid_token(self):
        result = self.dispatch(self.gateway)

        self.assertEqual(len(self.adapter.requests), 1)
        request = self.adapter.requests[0]
        payload = request.payload

        self.assertEqual(payload["task_contract_id"], self.compiled.task_contract_id)
        self.assertEqual(payload["task_contract_hash"], self.compiled.task_contract_hash)
        self.assertIn("frozen_task_contract", payload)
        self.assertEqual(
            payload["frozen_task_contract"]["task_contract_id"],
            self.compiled.task_contract_id)
        self.assertEqual(payload["authored_source"], CANDIDATE.decode("utf-8"))
        self.assertEqual(payload["vectors"], [{"args": [1], "expect_value": 1}])
        self.assertEqual(payload["entrypoint"], "run")
        self.assertEqual(
            payload["candidate_sha256"], hashlib.sha256(CANDIDATE).hexdigest())
        self.assertEqual(
            payload["vector_contract_sha256"],
            hashlib.sha256(VECTOR_CONTRACT).hexdigest())
        self.assertEqual(payload["expected_trusted_runner_sha256"], RUNNER_DIGEST)
        self.assertEqual(payload["expected_worker_sha256"], WORKER_DIGEST)
        self.assertEqual(
            payload["execution_input_hash"], str(self.exi_row["execution_input_hash"]))

        authorization_row = self.wb.authorizations.get(self.verify_authorization_id)
        self.assertTrue(request.token)
        self.assertEqual(request.binding_hash, str(authorization_row["binding_hash"]))
        self.assertEqual(request.request_hash, result["request_hash"])
        self.assertEqual(result["status"], "completed")

    def test_using_preserves_resolvers_so_the_swapped_adapter_dispatches(self):
        swapped = self.gateway.using(self.adapter_2.adapter_id)
        result = self.dispatch(swapped)

        self.assertEqual(self.adapter.requests, [])
        self.assertEqual(len(self.adapter_2.requests), 1)
        payload = self.adapter_2.requests[0].payload
        self.assertEqual(payload["task_contract_id"], self.compiled.task_contract_id)
        self.assertEqual(
            payload["execution_input_hash"], str(self.exi_row["execution_input_hash"]))
        self.assertEqual(result["status"], "completed")


class GatewayRefusalTests(ExecutionInputGatewayFixture):
    """The negative half of Unit 2B, over the same real, passing fixture.

    Every case proves the same three facts together: ``dispatch`` raises
    ``ExecutionRefused``, the selected adapter's request list is still empty,
    and ``runs.claim_for_authorization`` is still ``None``. The first is the
    refusal; the second is pre-entry (nothing crossed the boundary, so no
    token was minted for it); the third is pre-claim (the one attempt this
    ALLOW authorizes was not spent, so fixing the real defect and dispatching
    again is still possible).

    The forgeries below are deliberately SELF-CONSISTENT: each recomputes its
    own digest from its own mutated fields, so the row-level integrity check
    passes and the forward link to the authorization and the frozen task
    contract is provably what refuses — not an accidental hash mismatch.
    """

    # -- helpers ------------------------------------------------------------

    def assert_refuses_before_entry(self, expected_message, *, adapter=None,
                                    task_contract_resolver=_UNSET,
                                    execution_input_resolver=_UNSET):
        """Build a gateway with resolver overrides and prove it refuses.

        Anything not overridden is the fixture's own working resolver, so each
        case varies exactly one fact away from the dispatch that is proven to
        succeed in ``GatewayDispatchTests``.
        """
        ledger = support.assurance_authority(self.wb).ledger
        adapter = adapter if adapter is not None else self.adapter
        gateway = ExecutionGateway(
            authorizations=self.wb.authorizations, runs=self.wb.runs,
            evidence=self.wb.evidence, trajectory=self.wb.trajectory,
            registry=self.registry, adapter_id=adapter.adapter_id,
            task_contract_resolver=(
                ledger.task_contract_for_authorization
                if task_contract_resolver is _UNSET
                else task_contract_resolver),
            execution_input_resolver=(
                support.execution_input_authority(self.wb).verify
                if execution_input_resolver is _UNSET
                else execution_input_resolver),
            authorization_check_resolver=self.wb.execution_preflight_checks,
        )

        with self.assertRaises(ExecutionRefused) as caught:
            self.dispatch(gateway)

        self.assertEqual(caught.exception.message, expected_message)
        self.assertEqual(adapter.requests, [])
        self.assertIsNone(
            self.wb.runs.claim_for_authorization(self.verify_authorization_id))
        return caught.exception

    def forged_execution_input(self, **overrides):
        """A mutated execution-input mapping that still stands up on its own.

        Digests are recomputed from the bytes actually present and the binding
        hash from the mutated row, then ``verify_row`` is called here so the
        helper proves its own premise: if the forgery were not self-consistent
        this would raise, and the test could never be mistaken for a pass of
        the row-level integrity check.
        """
        row = dict(self.exi_row)
        row.update(overrides)
        if "candidate_source" in overrides:
            row["candidate_sha256"] = hashlib.sha256(
                bytes(row["candidate_source"])).hexdigest()
        if "vector_contract" in overrides:
            row["vector_contract_sha256"] = hashlib.sha256(
                bytes(row["vector_contract"])).hexdigest()
        row["execution_input_hash"] = execution_input_hash_of_row(row)
        verify_execution_input_row(row)
        return row

    def forged_task_contract(self, **overrides):
        """A mutated frozen task contract that still recomputes its own digest."""
        row = dict(support.assurance_authority(self.wb).ledger
                   .require_task_contract(self.compiled.task_contract_id))
        row.update(overrides)
        row["task_contract_hash"] = task_contract_hash_of_row(row)
        verify_task_contract_row(row)
        return row

    # -- the resolver itself ------------------------------------------------

    def test_refuses_when_the_gateway_has_no_execution_input_resolver(self):
        self.assert_refuses_before_entry(
            "backend requires an execution-input binding but the gateway has "
            "no verified resolver",
            execution_input_resolver=None,
        )

    def test_refuses_when_the_resolver_reports_no_recorded_binding(self):
        self.assert_refuses_before_entry(
            "no execution-input binding is recorded for this task contract",
            execution_input_resolver=lambda _task_contract_id: None,
        )

    # -- the vector contract ------------------------------------------------

    def test_refuses_vector_contract_bytes_that_are_not_valid_json(self):
        forged = self.forged_execution_input(
            vector_contract=b'[{"args": [1], "expect_value": 1}')
        self.assert_refuses_before_entry(
            "vector contract bytes are not valid JSON",
            execution_input_resolver=lambda _task_contract_id: forged,
        )

    def test_refuses_vector_contract_bytes_that_are_valid_but_noncanonical(self):
        """Valid JSON, correct content, wrong encoding — still refused.

        The bytes decode to exactly the content the passing fixture uses, so
        only the encoding differs: key order and whitespace. A payload hashed
        from a non-canonical encoding would not recompute elsewhere, which is
        why "it parses" is not the standard.
        """
        noncanonical = b'[{"expect_value": 1, "args": [1]}]'
        self.assertNotEqual(noncanonical, VECTOR_CONTRACT)
        forged = self.forged_execution_input(vector_contract=noncanonical)
        self.assert_refuses_before_entry(
            "vector contract bytes are not the canonical encoding of their "
            "own content",
            execution_input_resolver=lambda _task_contract_id: forged,
        )

    def test_refuses_vector_data_that_is_not_a_nonempty_list_of_mappings(self):
        """Each case is canonically encoded, so only the shape can be at fault."""
        cases = {
            "empty list": [],
            "mapping, not a list": {"args": [1], "expect_value": 1},
            "scalar": 1,
            "null": None,
            "list of scalars": [1, 2],
        }
        for label, value in cases.items():
            with self.subTest(case=label):
                encoded = canonical_json(value).encode("utf-8")
                forged = self.forged_execution_input(vector_contract=encoded)
                self.assert_refuses_before_entry(
                    "vector contract must decode to a nonempty JSON list of "
                    "mappings",
                    execution_input_resolver=lambda _tcid, row=forged: row,
                )

    # -- the entrypoint -----------------------------------------------------

    def test_refuses_an_unsafe_authorized_entrypoint(self):
        """Including a Python keyword, which is a valid-looking name and a trap."""
        cases = {
            "empty": "",
            "keyword: class": "class",
            "keyword: lambda": "lambda",
            "keyword: import": "import",
            "keyword: None": "None",
            "attribute access": "os.system",
            "call expression": "run()",
            "statement injection": "run; print(1)",
            "not an identifier": "2run",
            "untrimmed": " run",
        }
        for label, entrypoint in cases.items():
            with self.subTest(case=label):
                forged = self.forged_execution_input(
                    authorized_entrypoint=entrypoint)
                self.assert_refuses_before_entry(
                    "authorized entrypoint is not a valid, non-reserved "
                    "identifier",
                    execution_input_resolver=lambda _tcid, row=forged: row,
                )

    # -- the forward links --------------------------------------------------

    def test_refuses_self_consistent_execution_input_link_mismatches(self):
        """A forgery that recomputes perfectly is still not bound to this work."""
        cases = {
            "task_contract_id": (
                {"task_contract_id": FOREIGN_TASK_CONTRACT_ID,
                 "execution_input_id": execution_input_id_for(
                     FOREIGN_TASK_CONTRACT_ID)},
                "execution-input binding is not bound to this task contract",
            ),
            "task_contract_hash": (
                {"task_contract_hash": FOREIGN_TASK_CONTRACT_HASH},
                "execution-input binding's task-contract hash does not match "
                "the frozen task contract",
            ),
            "authorization_binding_hash": (
                {"authorization_binding_hash": FOREIGN_BINDING_HASH},
                "execution-input binding's authorization binding hash does "
                "not match this authorization",
            ),
        }
        for label, (overrides, expected) in cases.items():
            with self.subTest(mismatched=label):
                forged = self.forged_execution_input(**overrides)
                self.assert_refuses_before_entry(
                    expected,
                    execution_input_resolver=lambda _tcid, row=forged: row,
                )

    def test_refuses_a_self_consistent_task_contract_from_another_template(self):
        """The template is pinned by id AND by hash, so neither alone suffices."""
        cases = {
            "template_id": (
                {"template_id": "reconstruct_module.v1"},
                "frozen task contract was not compiled from "
                "verify_authored_source.v1",
            ),
            "template_hash": (
                {"template_hash": hashlib.sha256(
                    b"not verify_authored_source.v1").hexdigest()},
                "frozen task contract's template hash does not match "
                "verify_authored_source.v1",
            ),
        }
        for label, (overrides, expected) in cases.items():
            with self.subTest(mismatched=label):
                forged = self.forged_task_contract(**overrides)
                self.assert_refuses_before_entry(
                    expected,
                    task_contract_resolver=lambda _auth_id, row=forged: row,
                )

    # -- the apparatus identity ---------------------------------------------

    def test_refuses_a_backend_configured_for_a_different_worker_image(self):
        """Both resolvers are the real ones; only the backend's image differs."""
        other = RecordingAdapter("recording_other_image_adapter")
        other.execution_image_identity = OTHER_WORKER_IMAGE
        self.registry.register(other)
        self.assertNotEqual(
            other.execution_image_identity, str(self.exi_row["worker_image"]))

        self.assert_refuses_before_entry(
            "execution-input binding was authorized against a different "
            "worker image than this backend is configured to run",
            adapter=other,
        )


if __name__ == "__main__":
    unittest.main()
