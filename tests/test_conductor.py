"""The Layer-2 Conductor: the single ingress-to-evidence boundary.

These tests prove behaviour, not implementation text: every assertion reads
back authority rows the Conductor actually wrote (or deliberately did not
write) and recomputes what ``verify`` recomputes, rather than asserting
anything about the source of ``service.py`` itself.
"""

from __future__ import annotations

import socket
import unittest

from cis.conductor import Conductor, ConductorAuthority
from cis.conductor.authority import OPERATION_EXECUTION, OPERATION_INGRESS
from cis.errors import AuthorizationRefused, BindingError, ExecutionRefused
from cis.interface import WorkbenchApi

from . import support


class IngressEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.wb = support.workbench()
        self.conduct = Conductor(self.wb)

    def test_an_allow_ingress_has_exactly_one_envelope_linked_to_its_rows(self):
        outcome = self.conduct.ingest_instruction(support.ALLOW_INSTRUCTION)
        self.assertEqual(outcome.authorization["verdict"], "ALLOW")

        envelopes = self.conduct.authority.for_transaction(outcome.transaction_id)
        self.assertEqual(len(envelopes), 1)
        row = envelopes[0]
        self.assertEqual(row["operation"], OPERATION_INGRESS)

        intent_row = self.wb.intent.transaction(outcome.transaction_id)
        self.assertEqual(row["content_hash"], intent_row["verbatim_hash"])
        self.assertEqual(row["objective_id"], outcome.decision["prior_objective_id"])
        auth_row = self.wb.authorizations.get(
            outcome.authorization["authorization_id"])
        self.assertEqual(row["baseline_hash"], auth_row["baseline_hash"])

        # verify() independently recomputes the same linkage and does not raise.
        verified = self.conduct.authority.verify(row["envelope_id"])
        self.assertEqual(verified["envelope_id"], row["envelope_id"])

    def test_a_hold_ingress_is_enveloped_exactly_like_an_allow(self):
        outcome = self.conduct.ingest_instruction("What is the current stage?")
        self.assertEqual(outcome.authorization["verdict"], "HOLD")

        envelopes = self.conduct.authority.for_transaction(outcome.transaction_id)
        self.assertEqual(len(envelopes), 1)
        row = envelopes[0]
        self.assertEqual(row["operation"], OPERATION_INGRESS)
        self.conduct.authority.verify(row["envelope_id"])

    def test_two_distinct_instructions_each_get_their_own_single_envelope(self):
        first = self.conduct.ingest_instruction("What is the current stage?")
        second = self.conduct.ingest_instruction(support.ALLOW_INSTRUCTION)
        self.assertEqual(len(self.conduct.authority.for_transaction(
            first.transaction_id)), 1)
        self.assertEqual(len(self.conduct.authority.for_transaction(
            second.transaction_id)), 1)
        self.assertEqual(len(self.conduct.authority.all()), 2)


class ExecutionEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.wb = support.workbench()
        self.conduct = Conductor(self.wb)
        outcome = self.conduct.ingest_instruction(support.ALLOW_INSTRUCTION)
        self.authorization_id = outcome.authorization["authorization_id"]

    def test_a_successful_execution_has_exactly_one_envelope_linked_to_its_rows(self):
        result = self.conduct.execute_authorization(self.authorization_id)

        envelopes = self.conduct.authority.for_authorization(self.authorization_id)
        self.assertEqual(len(envelopes), 1)
        row = envelopes[0]
        self.assertEqual(row["operation"], OPERATION_EXECUTION)
        self.assertEqual(row["run_id"], result["run_id"])

        auth_row = self.wb.authorizations.get(self.authorization_id)
        self.assertEqual(row["content_hash"], auth_row["binding_hash"])
        self.assertEqual(row["objective_id"], auth_row["objective_id"])
        self.assertEqual(row["baseline_hash"], auth_row["baseline_hash"])

        verified = self.conduct.authority.verify(row["envelope_id"])
        self.assertEqual(verified["run_id"], result["run_id"])


class VerificationFailsClosedTests(unittest.TestCase):
    def setUp(self):
        self.wb = support.workbench()
        self.conduct = Conductor(self.wb)
        self.outcome = self.conduct.ingest_instruction(support.ALLOW_INSTRUCTION)
        self.envelope_id = ConductorAuthority.ingress_envelope_id(
            self.outcome.transaction_id)

    def test_a_tampered_envelope_hash_does_not_recompute(self):
        # Controlled test-only bypass: a real offline rewrite of the append-only
        # table, simulating the only way this row could ever be wrong, since
        # nothing in the slice has a second writer of it.
        self.wb.store.execute_raw(
            "DROP TRIGGER conductor_envelopes_no_update")
        self.wb.store.execute_raw(
            "UPDATE conductor_envelopes SET content_hash = ? "
            "WHERE envelope_id = ?",
            ("0" * 64, self.envelope_id),
        )
        with self.assertRaises(BindingError) as caught:
            self.conduct.authority.verify(self.envelope_id)
        self.assertNotEqual(caught.exception.detail["recorded"],
                            caught.exception.detail["recomputed"])

    def test_corruption_of_the_linked_instruction_is_caught_by_cross_check(self):
        # The envelope row itself is untouched and its own hash still
        # recomputes; the corruption is in the authority row it cites, which
        # only the cross-check catches.
        self.wb.store.execute_raw(
            "DROP TRIGGER intent_transactions_no_update")
        self.wb.store.execute_raw(
            "UPDATE intent_transactions SET verbatim_hash = ? "
            "WHERE transaction_id = ?",
            ("0" * 64, self.outcome.transaction_id),
        )
        with self.assertRaises(BindingError) as caught:
            self.conduct.authority.verify(self.envelope_id)
        self.assertIn("does not match instruction", caught.exception.message)

    def test_verifying_a_nonexistent_envelope_is_refused(self):
        with self.assertRaises(AuthorizationRefused):
            self.conduct.authority.verify("env-does-not-exist")


class NoFalseSuccessfulEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.wb = support.workbench()
        self.conduct = Conductor(self.wb)
        outcome = self.conduct.ingest_instruction(support.ALLOW_INSTRUCTION)
        self.authorization_id = outcome.authorization["authorization_id"]

    def test_a_replayed_execution_is_refused_and_gains_no_second_envelope(self):
        self.conduct.execute_authorization(self.authorization_id)
        self.assertEqual(
            len(self.conduct.authority.for_authorization(self.authorization_id)), 1)

        with self.assertRaises(ExecutionRefused):
            self.conduct.execute_authorization(self.authorization_id)

        # The replay left no second, false-successful envelope behind.
        self.assertEqual(
            len(self.conduct.authority.for_authorization(self.authorization_id)), 1)

    def test_executing_an_unknown_authorization_records_no_envelope_at_all(self):
        with self.assertRaises(AuthorizationRefused):
            self.conduct.execute_authorization("auth-does-not-exist")
        self.assertEqual(
            len(self.conduct.authority.for_authorization("auth-does-not-exist")), 0)


class ApiRoutesThroughConductorTests(unittest.TestCase):
    """L1 POST routes must use the Conductor's envelope, not a bare Workbench
    mutation.

    A fake Conductor stands in for the real one so this proves the dispatcher
    actually calls ``conductor.ingest_instruction`` / ``execute_authorization``
    and returns exactly what the Conductor gave back — not merely that the
    right text appears somewhere in ``api.py``.
    """

    class _FakeOutcome:
        def as_dict(self):
            return {"transaction_id": "tx-fake", "marker": "from-fake-conductor"}

    class _FakeConductor:
        def __init__(self):
            self.ingress_calls: list[str] = []
            self.execute_calls: list[str] = []

        def ingest_instruction(self, verbatim):
            self.ingress_calls.append(verbatim)
            return ApiRoutesThroughConductorTests._FakeOutcome()

        def execute_authorization(self, authorization_id):
            self.execute_calls.append(authorization_id)
            return {"run_id": "run-fake", "status": "completed"}

    def setUp(self):
        self.wb = support.workbench()
        self.api = WorkbenchApi(self.wb)
        self.fake = self._FakeConductor()
        self.api.conductor = self.fake

    def test_post_instruction_dispatches_through_the_conductor(self):
        response = self.api.dispatch(
            "POST", "/instruction", {"verbatim": "hello"})
        self.assertEqual(self.fake.ingress_calls, ["hello"])
        self.assertEqual(response.body["marker"], "from-fake-conductor")

    def test_post_execute_dispatches_through_the_conductor(self):
        response = self.api.dispatch(
            "POST", "/execute", {"authorization_id": "auth-xyz"})
        self.assertEqual(self.fake.execute_calls, ["auth-xyz"])
        self.assertEqual(response.body["run"]["run_id"], "run-fake")

    def test_real_dispatch_produces_a_real_envelope_for_each_post_route(self):
        # With the real Conductor restored, each successful POST leaves
        # exactly the envelope trail Conductor.ingest_instruction /
        # execute_authorization promise — proof the wiring is not just a
        # mocked call but an end-to-end effect on authority.
        api = WorkbenchApi(support.workbench())
        allowed = api.dispatch(
            "POST", "/instruction", {"verbatim": support.ALLOW_INSTRUCTION})
        transaction_id = allowed.body["transaction_id"]
        self.assertEqual(
            len(api.conductor.authority.for_transaction(transaction_id)), 1)

        authorization_id = allowed.body["authorization"]["authorization_id"]
        executed = api.dispatch(
            "POST", "/execute", {"authorization_id": authorization_id})
        run_id = executed.body["run"]["run_id"]
        envelopes = api.conductor.authority.for_authorization(authorization_id)
        self.assertEqual(len(envelopes), 1)
        self.assertEqual(envelopes[0]["run_id"], run_id)


class DeterministicAndOfflineTests(unittest.TestCase):
    def test_two_independent_runs_produce_byte_identical_envelope_hashes(self):
        def run_once():
            wb = support.workbench()
            conduct = Conductor(wb)
            outcome = conduct.ingest_instruction(support.ALLOW_INSTRUCTION)
            authorization_id = outcome.authorization["authorization_id"]
            conduct.execute_authorization(authorization_id)
            ingress = conduct.authority.for_transaction(
                outcome.transaction_id)[0]
            execution = conduct.authority.for_authorization(
                authorization_id)[0]
            return ingress["envelope_hash"], execution["envelope_hash"]

        first = run_once()
        second = run_once()
        self.assertEqual(first, second)

    def test_the_conductor_never_touches_the_network(self):
        real_socket = socket.socket

        def trap(*args, **kwargs):
            raise AssertionError("the Conductor attempted to open a socket")

        socket.socket = trap
        try:
            wb = support.workbench()
            conduct = Conductor(wb)
            outcome = conduct.ingest_instruction(support.ALLOW_INSTRUCTION)
            conduct.execute_authorization(outcome.authorization["authorization_id"])
        finally:
            socket.socket = real_socket


if __name__ == "__main__":
    unittest.main()
