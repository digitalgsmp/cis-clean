"""Unit 8A: worker-model session, request and lifecycle-event authority."""

from __future__ import annotations

import unittest

from cis.errors import AppendOnlyViolation, WorkerSessionRefused
from cis.execution.worker_session import WorkerSessionAuthority
from cis.execution.worker_supervisor import WorkerSupervisorAuthority

from . import support


def route(authorization_id: str, adapter_id: str = "deterministic_mock", **overrides):
    result = {
        "authorization_id": authorization_id, "adapter_id": adapter_id,
        "wall_time_ms": 1000, "token_limit": 1000,
        "cost_limit_micros": 1000,
    }
    result.update(overrides)
    return result


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


class WorkerSessionAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.wb, self.outcome = support.allow_outcome()
        self.auth0 = self.outcome.authorization["authorization_id"]
        self.supervisor = WorkerSupervisorAuthority(self.wb.store)
        self.sessions = WorkerSessionAuthority(self.wb.store)
        self.plan = self.supervisor.create_plan(
            [route(self.auth0)], circuit_threshold=1)
        self.sid = self.plan["supervision_id"]

    # -- open_session / issue_request ------------------------------------

    def test_open_session_copies_exact_route_identity_and_is_idempotent(self):
        session = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        self.assertEqual(session["supervision_id"], self.sid)
        self.assertEqual(int(session["route_index"]), 0)
        self.assertEqual(session["objective_id"], self.plan["objective_id"])
        self.assertEqual(session["transaction_id"], self.plan["transaction_id"])
        self.assertEqual(session["target_module_id"], self.plan["target_module_id"])
        self.assertEqual(session["operation"], self.plan["operation"])
        self.assertEqual(session["logical_role"], "IMPLEMENTER")
        self.assertEqual(session["adapter_id"], "deterministic_mock")

        replay = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        self.assertEqual(replay["session_id"], session["session_id"])
        events = self.sessions.events(session["session_id"])
        opened = [e for e in events if e["event_type"] == "SESSION_OPENED"]
        self.assertEqual(len(opened), 1)

    def test_issue_request_copies_exact_authorization_adapter_and_budgets(self):
        session = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        request = self.sessions.issue_request(
            session["session_id"], DIGEST_A, DIGEST_B, DIGEST_C)
        self.assertEqual(request["session_id"], session["session_id"])
        self.assertEqual(request["supervision_id"], self.sid)
        self.assertEqual(request["authorization_id"], self.auth0)
        self.assertEqual(request["adapter_id"], "deterministic_mock")
        self.assertEqual(int(request["wall_time_ms"]), 1000)
        self.assertEqual(int(request["token_limit"]), 1000)
        self.assertEqual(int(request["cost_limit_micros"]), 1000)
        self.assertEqual(int(request["ordinal"]), 1)

        replay = self.sessions.issue_request(
            session["session_id"], DIGEST_A, DIGEST_B, DIGEST_C)
        self.assertEqual(replay["request_id"], request["request_id"])
        self.assertEqual(len(self.wb.store.query(
            "SELECT * FROM worker_model_requests")), 1)

    def test_disagreeing_second_request_on_same_route_is_refused(self):
        session = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        self.sessions.issue_request(
            session["session_id"], DIGEST_A, DIGEST_B, DIGEST_C)
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.issue_request(
                session["session_id"], DIGEST_B, DIGEST_B, DIGEST_C)

    def test_invalid_logical_role_is_refused(self):
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.open_session(self.sid, 0, "ARCHITECT")

    def test_invalid_digests_are_refused(self):
        session = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.issue_request(
                session["session_id"], DIGEST_A.upper(), DIGEST_B, DIGEST_C)
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.issue_request(
                session["session_id"], "short", DIGEST_B, DIGEST_C)

    # -- start_request / bind_external_session ----------------------------

    def test_start_request_refuses_until_supervisor_starts(self):
        session = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        request = self.sessions.issue_request(
            session["session_id"], DIGEST_A, DIGEST_B, DIGEST_C)
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.start_request(
                session["session_id"], request["request_id"])

        self.supervisor.start(self.sid, 0)
        started = self.sessions.start_request(
            session["session_id"], request["request_id"])
        self.assertEqual(started["event_type"], "REQUEST_STARTED")

        retry = self.sessions.start_request(
            session["session_id"], request["request_id"])
        self.assertEqual(retry["event_id"], started["event_id"])

        bound = self.sessions.bind_external_session(
            session["session_id"], request["request_id"], "external-ref-1")
        self.assertEqual(bound["event_type"], "EXTERNAL_SESSION_BOUND")
        self.assertEqual(bound["external_session_ref"], "external-ref-1")
        rebound = self.sessions.bind_external_session(
            session["session_id"], request["request_id"], "external-ref-1")
        self.assertEqual(rebound["event_id"], bound["event_id"])

        checkpoint = self.sessions.checkpoint_request(
            session["session_id"], request["request_id"],
            "artifact:checkpoint-1", DIGEST_A)
        self.assertEqual(checkpoint["event_type"], "REQUEST_CHECKPOINTED")
        recheckpoint = self.sessions.checkpoint_request(
            session["session_id"], request["request_id"],
            "artifact:checkpoint-1", DIGEST_A)
        self.assertEqual(recheckpoint["event_id"], checkpoint["event_id"])

        suspended = self.sessions.suspend_session(session["session_id"])
        self.assertEqual(suspended["event_type"], "SESSION_SUSPENDED")
        resuspended = self.sessions.suspend_session(session["session_id"])
        self.assertEqual(resuspended["event_id"], suspended["event_id"])

    # -- succeed_request ---------------------------------------------------

    def _started_request(self):
        session = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        request = self.sessions.issue_request(
            session["session_id"], DIGEST_A, DIGEST_B, DIGEST_C)
        self.supervisor.start(self.sid, 0)
        self.sessions.start_request(session["session_id"], request["request_id"])
        return session, request

    def test_succeed_request_refuses_before_supervisor_success(self):
        session, request = self._started_request()
        run = self.wb.execute(self.auth0)
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.succeed_request(
                session["session_id"], request["request_id"],
                run["run_id"], run["evidence_id"])

    def test_succeed_request_binds_exact_run_and_evidence_and_is_idempotent(self):
        session, request = self._started_request()
        run = self.wb.execute(self.auth0)
        self.supervisor.finish(
            self.sid, 0, succeeded=True, measured_wall_ms=1,
            measured_tokens=1, measured_cost_micros=1,
            run_id=run["run_id"], evidence_id=run["evidence_id"])

        succeeded = self.sessions.succeed_request(
            session["session_id"], request["request_id"],
            run["run_id"], run["evidence_id"])
        self.assertEqual(succeeded["event_type"], "REQUEST_SUCCEEDED")
        self.assertEqual(succeeded["run_id"], run["run_id"])
        self.assertEqual(succeeded["evidence_id"], run["evidence_id"])

        retry = self.sessions.succeed_request(
            session["session_id"], request["request_id"],
            run["run_id"], run["evidence_id"])
        self.assertEqual(retry["event_id"], succeeded["event_id"])

        with self.assertRaises(WorkerSessionRefused):
            self.sessions.fail_request(
                session["session_id"], request["request_id"], "timeout")

    def test_succeed_request_rejects_forged_run_or_evidence_binding(self):
        session, request = self._started_request()
        run = self.wb.execute(self.auth0)
        self.supervisor.finish(
            self.sid, 0, succeeded=True, measured_wall_ms=1,
            measured_tokens=1, measured_cost_micros=1,
            run_id=run["run_id"], evidence_id=run["evidence_id"])
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.succeed_request(
                session["session_id"], request["request_id"],
                "forged-run-id", run["evidence_id"])
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.succeed_request(
                session["session_id"], request["request_id"],
                run["run_id"], "forged-evidence-id")

    # -- fail_request --------------------------------------------------------

    def test_fail_request_requires_matching_class_and_is_idempotent(self):
        session, request = self._started_request()
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.fail_request(
                session["session_id"], request["request_id"], "timeout")

        self.supervisor.finish(
            self.sid, 0, succeeded=False, measured_wall_ms=1,
            measured_tokens=1, measured_cost_micros=1,
            failure_class="timeout")

        with self.assertRaises(WorkerSessionRefused):
            self.sessions.fail_request(
                session["session_id"], request["request_id"],
                "budget_exhausted")

        failed = self.sessions.fail_request(
            session["session_id"], request["request_id"], "timeout")
        self.assertEqual(failed["event_type"], "REQUEST_FAILED")
        self.assertEqual(failed["failure_class"], "timeout")

        retry = self.sessions.fail_request(
            session["session_id"], request["request_id"], "timeout")
        self.assertEqual(retry["event_id"], failed["event_id"])

        with self.assertRaises(WorkerSessionRefused):
            run = self.wb.execute(self.auth0)
            self.sessions.succeed_request(
                session["session_id"], request["request_id"],
                run["run_id"], run["evidence_id"])

    # -- close_session -------------------------------------------------------

    def test_close_session_is_idempotent_and_blocks_further_events(self):
        session, request = self._started_request()
        closed = self.sessions.close_session(session["session_id"])
        self.assertEqual(closed["event_type"], "SESSION_CLOSED")
        reclosed = self.sessions.close_session(session["session_id"])
        self.assertEqual(reclosed["event_id"], closed["event_id"])

        with self.assertRaises(WorkerSessionRefused):
            self.sessions.checkpoint_request(
                session["session_id"], request["request_id"],
                "artifact:late", DIGEST_A)
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.bind_external_session(
                session["session_id"], request["request_id"], "late-ref")
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.suspend_session(session["session_id"])
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.issue_request(
                session["session_id"], DIGEST_B, DIGEST_B, DIGEST_C)

    def test_request_to_session_mismatch_is_refused(self):
        other_auth = self.wb.submit_instruction(
            support.ALLOW_INSTRUCTION).authorization["authorization_id"]
        other_plan = self.supervisor.create_plan(
            [route(other_auth)], circuit_threshold=1)
        other_session = self.sessions.open_session(
            other_plan["supervision_id"], 0, "IMPLEMENTER")

        session, request = self._started_request()
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.start_request(
                other_session["session_id"], request["request_id"])

    def test_cross_session_aliasing_on_same_route_is_refused(self):
        first = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        second = self.sessions.open_session(self.sid, 0, "REVIEWER")
        self.assertNotEqual(first["session_id"], second["session_id"])

        request = self.sessions.issue_request(
            first["session_id"], DIGEST_A, DIGEST_B, DIGEST_C)
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.issue_request(
                second["session_id"], DIGEST_A, DIGEST_B, DIGEST_C)

        rows = self.wb.store.query("SELECT * FROM worker_model_requests")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["session_id"], first["session_id"])
        self.assertEqual(rows[0]["request_id"], request["request_id"])
        self.assertNotEqual(rows[0]["session_id"], second["session_id"])

    # -- append-only protection -----------------------------------------------

    def test_append_only_tables_reject_update_and_delete(self):
        session = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        self.sessions.issue_request(
            session["session_id"], DIGEST_A, DIGEST_B, DIGEST_C)
        for table in ("worker_sessions", "worker_model_requests",
                      "worker_session_events"):
            with self.assertRaises(AppendOnlyViolation):
                self.wb.store.execute_raw(f"UPDATE {table} SET seq = seq + 1")
            with self.assertRaises(AppendOnlyViolation):
                self.wb.store.execute_raw(f"DELETE FROM {table}")


def clone_authorization(wb, source_id: str, suffix: str, **changes):
    source = wb.authorizations.get(source_id)
    values = {
        "authorization_id": f"{source_id}-{suffix}",
        "transaction_id": str(source["transaction_id"]),
        "decision_id": str(source["decision_id"]),
        "objective_id": str(source["objective_id"]),
        "verdict": str(source["verdict"]),
        "reason_code": str(source["reason_code"]),
        "reason": str(source["reason"]),
        "target_module_id": str(source["target_module_id"]),
        "scope": wb.authorizations.scope_of(source),
        "verbatim_hash": str(source["verbatim_hash"]),
        "decision_hash": str(source["decision_hash"]),
        "baseline_hash": str(source["baseline_hash"]),
    }
    values.update(changes)
    return wb.authorizations.record(**values)


class WorkerLogicalSessionTests(unittest.TestCase):
    """Unit 8A correction: a durable, provider-neutral logical session and
    the route-bound legs explicitly attached to it (migration 0014)."""

    def setUp(self):
        self.wb, self.outcome = support.allow_outcome()
        self.auth0 = self.outcome.authorization["authorization_id"]
        self.auth1 = clone_authorization(
            self.wb, self.auth0, "fallback1")["authorization_id"]
        self.supervisor = WorkerSupervisorAuthority(self.wb.store)
        self.sessions = WorkerSessionAuthority(self.wb.store)
        # Two fallback routes of one plan: same objective/transaction/target/
        # operation, distinct authorizations and adapters — exactly the
        # "distinct authorized routes/adapters" the card's identity
        # invariant must hold across.
        self.plan = self.supervisor.create_plan(
            [route(self.auth0), route(self.auth1, adapter_id="other_adapter")],
            circuit_threshold=2)
        self.sid = self.plan["supervision_id"]

    def _identity(self):
        return dict(
            objective_id=self.plan["objective_id"],
            transaction_id=self.plan["transaction_id"],
            target_module_id=self.plan["target_module_id"],
            operation=self.plan["operation"], logical_role="IMPLEMENTER")

    def test_open_logical_session_is_idempotent(self):
        logical = self.sessions.open_logical_session(**self._identity())
        replay = self.sessions.open_logical_session(**self._identity())
        self.assertEqual(logical["logical_session_id"],
                         replay["logical_session_id"])
        self.assertEqual(
            len(self.wb.store.query("SELECT * FROM worker_logical_sessions")),
            1)

    def test_logical_identity_is_unchanged_across_distinct_routes_and_adapters(self):
        session_a = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        session_b = self.sessions.open_session(self.sid, 1, "IMPLEMENTER")
        self.assertNotEqual(session_a["adapter_id"], session_b["adapter_id"])

        logical_a = self.sessions.open_logical_session(
            objective_id=session_a["objective_id"],
            transaction_id=session_a["transaction_id"],
            target_module_id=session_a["target_module_id"],
            operation=session_a["operation"],
            logical_role=session_a["logical_role"])
        logical_b = self.sessions.open_logical_session(
            objective_id=session_b["objective_id"],
            transaction_id=session_b["transaction_id"],
            target_module_id=session_b["target_module_id"],
            operation=session_b["operation"],
            logical_role=session_b["logical_role"])
        self.assertEqual(logical_a["logical_session_id"],
                         logical_b["logical_session_id"])

    def test_two_route_sessions_attach_to_one_logical_session_in_ordered_legs(self):
        logical = self.sessions.open_logical_session(**self._identity())
        session_a = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        session_b = self.sessions.open_session(self.sid, 1, "IMPLEMENTER")

        leg_a = self.sessions.attach_route_session(
            logical["logical_session_id"], session_a["session_id"], 1)
        leg_b = self.sessions.attach_route_session(
            logical["logical_session_id"], session_b["session_id"], 2)

        legs = self.sessions.legs(logical["logical_session_id"])
        self.assertEqual([leg_a["leg_id"], leg_b["leg_id"]],
                         [legs[0]["leg_id"], legs[1]["leg_id"]])
        self.assertEqual(int(legs[0]["leg_ordinal"]), 1)
        self.assertEqual(int(legs[1]["leg_ordinal"]), 2)

    def test_each_legs_request_remains_bound_to_its_own_route_and_authorization(self):
        logical = self.sessions.open_logical_session(**self._identity())
        session_a = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        session_b = self.sessions.open_session(self.sid, 1, "IMPLEMENTER")
        self.sessions.attach_route_session(
            logical["logical_session_id"], session_a["session_id"], 1)
        self.sessions.attach_route_session(
            logical["logical_session_id"], session_b["session_id"], 2)

        request_a = self.sessions.issue_request(
            session_a["session_id"], DIGEST_A, DIGEST_B, DIGEST_C)
        request_b = self.sessions.issue_request(
            session_b["session_id"], DIGEST_A, DIGEST_B, DIGEST_C)
        self.assertEqual(request_a["authorization_id"], self.auth0)
        self.assertEqual(request_b["authorization_id"], self.auth1)
        self.assertNotEqual(request_a["request_id"], request_b["request_id"])

    def test_cross_identity_attachment_refuses(self):
        logical = self.sessions.open_logical_session(**self._identity())
        other_auth = self.wb.submit_instruction(
            support.ALLOW_INSTRUCTION).authorization["authorization_id"]
        other_plan = self.supervisor.create_plan(
            [route(other_auth)], circuit_threshold=1)
        other_session = self.sessions.open_session(
            other_plan["supervision_id"], 0, "IMPLEMENTER")
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.attach_route_session(
                logical["logical_session_id"], other_session["session_id"], 1)

    def test_cross_logical_role_attachment_refuses(self):
        logical = self.sessions.open_logical_session(**self._identity())
        session = self.sessions.open_session(self.sid, 0, "REVIEWER")
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.attach_route_session(
                logical["logical_session_id"], session["session_id"], 1)

    def test_duplicate_session_attachment_refuses(self):
        other_auth = self.wb.submit_instruction(
            support.ALLOW_INSTRUCTION).authorization["authorization_id"]
        other_plan = self.supervisor.create_plan(
            [route(other_auth)], circuit_threshold=1)
        logical_other = self.sessions.open_logical_session(
            objective_id=other_plan["objective_id"],
            transaction_id=other_plan["transaction_id"],
            target_module_id=other_plan["target_module_id"],
            operation=other_plan["operation"], logical_role="REVIEWER")

        logical = self.sessions.open_logical_session(**self._identity())
        session = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        self.sessions.attach_route_session(
            logical["logical_session_id"], session["session_id"], 1)

        # Identical retry is idempotent.
        self.sessions.attach_route_session(
            logical["logical_session_id"], session["session_id"], 1)
        self.assertEqual(
            len(self.wb.store.query("SELECT * FROM worker_session_legs")), 1)

        # The same route session cannot be re-attached to a second,
        # disagreeing logical session.
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.attach_route_session(
                logical_other["logical_session_id"], session["session_id"], 1)

    def test_disagreeing_ordinal_refuses(self):
        logical = self.sessions.open_logical_session(**self._identity())
        session_a = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        session_b = self.sessions.open_session(self.sid, 1, "IMPLEMENTER")
        self.sessions.attach_route_session(
            logical["logical_session_id"], session_a["session_id"], 1)

        # Reused ordinal 1 is taken; skipping to 3 is not the next ordinal.
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.attach_route_session(
                logical["logical_session_id"], session_b["session_id"], 1)
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.attach_route_session(
                logical["logical_session_id"], session_b["session_id"], 3)

        legs = self.sessions.legs(logical["logical_session_id"])
        self.assertEqual(len(legs), 1)

    def test_tampered_logical_session_digest_refuses(self):
        logical = self.sessions.open_logical_session(**self._identity())
        self.wb.store.execute_raw(
            "DROP TRIGGER worker_logical_sessions_no_update")
        self.wb.store.execute_raw(
            "UPDATE worker_logical_sessions SET logical_session_hash = ? "
            "WHERE logical_session_id = ?",
            ("0" * 64, logical["logical_session_id"]))
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.verify_logical_session(logical["logical_session_id"])

    def test_tampered_leg_digest_refuses(self):
        logical = self.sessions.open_logical_session(**self._identity())
        session = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        leg = self.sessions.attach_route_session(
            logical["logical_session_id"], session["session_id"], 1)
        self.wb.store.execute_raw("DROP TRIGGER worker_session_legs_no_update")
        self.wb.store.execute_raw(
            "UPDATE worker_session_legs SET leg_hash = ? WHERE leg_id = ?",
            ("0" * 64, leg["leg_id"]))
        with self.assertRaises(WorkerSessionRefused):
            self.sessions.verify_leg(leg["leg_id"])

    def test_append_only_tables_reject_update_and_delete(self):
        logical = self.sessions.open_logical_session(**self._identity())
        session = self.sessions.open_session(self.sid, 0, "IMPLEMENTER")
        self.sessions.attach_route_session(
            logical["logical_session_id"], session["session_id"], 1)
        for table in ("worker_logical_sessions", "worker_session_legs"):
            with self.assertRaises(AppendOnlyViolation):
                self.wb.store.execute_raw(f"UPDATE {table} SET seq = seq + 1")
            with self.assertRaises(AppendOnlyViolation):
                self.wb.store.execute_raw(f"DELETE FROM {table}")


if __name__ == "__main__":
    unittest.main()
