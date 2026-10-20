"""Unit 7A: append-only worker-supervision plan and event authority.

Unit 7B3 adds ``SupervisedExecutionCoordinator``, a bounded resumable
retry/fallback walk over that authority and the existing gateway.
"""

from __future__ import annotations

import json
import unittest

from cis.authority.runs import COMPLETED, FAILED
from cis.canonical import canonical_json
from cis.errors import (
    AppendOnlyViolation, ExecutionProviderFailure, WorkerSupervisionRefused,
)
from cis.execution import AdapterRegistry, ExecutionGateway, ExecutionResult, ExecutionUsage
from cis.execution.port import ExecutionPort
from cis.execution.worker_supervisor import (
    FAILURE_CLASSES, SupervisedExecutionCoordinator, WorkerSupervisorAuthority,
)

from . import support


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


def route(authorization_id: str, adapter_id: str = "deterministic_mock", **overrides):
    result = {
        "authorization_id": authorization_id, "adapter_id": adapter_id,
        "wall_time_ms": 1000, "token_limit": 1000,
        "cost_limit_micros": 1000,
    }
    result.update(overrides)
    return result


class WorkerSupervisorAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.wb, self.outcome = support.allow_outcome()
        self.auth0 = self.outcome.authorization["authorization_id"]
        self.auth1 = clone_authorization(self.wb, self.auth0, "fallback1")[
            "authorization_id"]
        self.auth2 = clone_authorization(self.wb, self.auth0, "fallback2")[
            "authorization_id"]
        self.supervisor = WorkerSupervisorAuthority(self.wb.store)

    def make_plan(self, count=2, threshold=2):
        ids = (self.auth0, self.auth1, self.auth2)[:count]
        return self.supervisor.create_plan(
            [route(value) for value in ids],
            circuit_threshold=threshold)

    def test_plan_is_canonical_hashed_and_idempotent(self):
        plan = self.make_plan()
        verified = self.supervisor.verify_plan(plan["supervision_id"])
        self.assertEqual(verified["plan_hash"], plan["plan_hash"])
        self.assertEqual(json.loads(plan["routes_json"])[0]["wall_time_ms"], 1000)
        replay = self.make_plan()
        self.assertEqual(replay["supervision_id"], plan["supervision_id"])
        self.assertEqual(len(self.wb.store.query(
            "SELECT * FROM worker_supervision_plans")), 1)

    def test_duplicate_non_allow_unknown_and_mixed_work_are_refused(self):
        with self.assertRaises(WorkerSupervisionRefused):
            self.supervisor.create_plan(
                [route(self.auth0), route(self.auth0)], circuit_threshold=1)
        hold = self.wb.submit_instruction("What is the current stage?")
        with self.assertRaises(WorkerSupervisionRefused):
            self.supervisor.create_plan(
                [route(hold.authorization["authorization_id"])],
                circuit_threshold=1)
        with self.assertRaises(WorkerSupervisionRefused):
            self.supervisor.create_plan([route("missing")], circuit_threshold=1)
        other = self.wb.submit_instruction(support.ALLOW_INSTRUCTION)
        with self.assertRaises(WorkerSupervisionRefused):
            self.supervisor.create_plan(
                [route(self.auth0), route(other.authorization["authorization_id"])],
                circuit_threshold=2)

    def test_positive_budgets_and_closed_route_schema_are_enforced(self):
        for field in ("wall_time_ms", "token_limit", "cost_limit_micros"):
            with self.assertRaises(WorkerSupervisionRefused):
                self.supervisor.create_plan(
                    [route(self.auth0, **{field: 0})], circuit_threshold=1)
        wider = route(self.auth0)
        wider["provider"] = "forbidden"
        with self.assertRaises(WorkerSupervisionRefused):
            self.supervisor.create_plan([wider], circuit_threshold=1)
        for invalid in (True, "1000"):
            with self.assertRaises(WorkerSupervisionRefused):
                self.supervisor.create_plan(
                    [route(self.auth0, wall_time_ms=invalid)],
                    circuit_threshold=1)

    def test_checkpoint_requires_active_attempt_and_success_requires_real_run(self):
        plan = self.make_plan(count=1, threshold=1)
        sid = plan["supervision_id"]
        digest = "a" * 64
        with self.assertRaises(WorkerSupervisionRefused):
            self.supervisor.checkpoint(
                sid, 0, checkpoint_ref="artifact:x", checkpoint_sha256=digest)
        started = self.supervisor.start(sid, 0)
        self.assertEqual(self.supervisor.start(sid, 0)["event_id"],
                         started["event_id"])
        checkpoint = self.supervisor.checkpoint(
            sid, 0, checkpoint_ref="artifact:x", checkpoint_sha256=digest)
        self.assertEqual(checkpoint["event_type"], "CHECKPOINT")
        with self.assertRaises(WorkerSupervisionRefused):
            self.supervisor.finish(
                sid, 0, succeeded=True, measured_wall_ms=1,
                measured_tokens=1, measured_cost_micros=1,
                run_id="missing", evidence_id="missing")
        run = self.wb.execute(self.auth0)
        terminal = self.supervisor.finish(
            sid, 0, succeeded=True, measured_wall_ms=1,
            measured_tokens=1, measured_cost_micros=1,
            run_id=run["run_id"], evidence_id=run["evidence_id"])
        self.assertEqual(terminal["event_type"], "SUCCEEDED")
        self.assertEqual(self.supervisor.finish(
            sid, 0, succeeded=True, measured_wall_ms=1,
            measured_tokens=1, measured_cost_micros=1,
            run_id=run["run_id"], evidence_id=run["evidence_id"])["event_id"],
            terminal["event_id"])
        with self.assertRaises(WorkerSupervisionRefused):
            self.supervisor.checkpoint(
                sid, 0, checkpoint_ref="artifact:y", checkpoint_sha256=digest)

    def test_ordered_fallback_taxonomy_budget_classification_and_circuit(self):
        plan = self.make_plan(count=3, threshold=2)
        sid = plan["supervision_id"]
        with self.assertRaises(WorkerSupervisionRefused):
            self.supervisor.start(sid, 1)
        self.supervisor.start(sid, 0)
        with self.assertRaises(WorkerSupervisionRefused):
            self.supervisor.finish(
                sid, 0, succeeded=False, measured_wall_ms=1001,
                measured_tokens=0, measured_cost_micros=0,
                failure_class="network_or_provider_failure")
        failed0 = self.supervisor.finish(
            sid, 0, succeeded=False, measured_wall_ms=1001,
            measured_tokens=0, measured_cost_micros=0,
            failure_class="timeout")
        self.assertEqual(failed0["failure_class"], "timeout")
        self.supervisor.start(sid, 1)
        failed1 = self.supervisor.finish(
            sid, 1, succeeded=False, measured_wall_ms=1,
            measured_tokens=1001, measured_cost_micros=0,
            failure_class="budget_exhausted")
        self.assertEqual(failed1["failure_class"], "budget_exhausted")
        self.assertTrue(any(e["event_type"] == "CIRCUIT_OPEN"
                            for e in self.supervisor.events(sid)))
        with self.assertRaises(WorkerSupervisionRefused):
            self.supervisor.start(sid, 2)
        self.assertEqual(FAILURE_CLASSES, {
            "timeout", "budget_exhausted", "permission_wait",
            "network_or_provider_failure", "empty_or_incomplete_output",
            "invalid_artifacts",
        })

    def test_terminal_conflict_and_append_only_storage_are_refused(self):
        plan = self.make_plan(count=1, threshold=1)
        sid = plan["supervision_id"]
        self.supervisor.start(sid, 0)
        self.supervisor.finish(
            sid, 0, succeeded=False, measured_wall_ms=1,
            measured_tokens=1, measured_cost_micros=1,
            failure_class="permission_wait")
        with self.assertRaises(WorkerSupervisionRefused):
            self.supervisor.finish(
                sid, 0, succeeded=False, measured_wall_ms=1,
                measured_tokens=1, measured_cost_micros=1,
                failure_class="invalid_artifacts")
        for table in ("worker_supervision_plans", "worker_attempt_events"):
            with self.assertRaises(AppendOnlyViolation):
                self.wb.store.execute_raw(f"UPDATE {table} SET seq = seq + 1")
            with self.assertRaises(AppendOnlyViolation):
                self.wb.store.execute_raw(f"DELETE FROM {table}")


class _ScriptedAdapter(ExecutionPort):
    """A purpose-built backend whose one call either returns a scripted
    result or raises a scripted exception, so the coordinator's fallback
    and typed-refusal mapping can be exercised deterministically."""

    enforced_budget_dimensions = (
        "wall_time_ms", "token_limit", "cost_limit_micros")

    def __init__(self, adapter_id, *, result=None, raises=None):
        self.adapter_id = adapter_id
        self._result = result
        self._raises = raises
        self.calls = 0

    def capabilities(self):
        return ("reconstruct_module",)

    def execute(self, request):
        request.verify_token()
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return self._result


class SupervisedExecutionCoordinatorTests(unittest.TestCase):
    """Unit 7B3: the deterministic retry/fallback coordinator."""

    def setUp(self):
        self.wb, self.outcome = support.allow_outcome()
        self.auth0 = self.outcome.authorization["authorization_id"]
        self.auth1 = clone_authorization(self.wb, self.auth0, "fallback1")[
            "authorization_id"]
        self.auth2 = clone_authorization(self.wb, self.auth0, "fallback2")[
            "authorization_id"]
        self.supervisor = WorkerSupervisorAuthority(self.wb.store)
        self.baseline_hash = self.wb.blueprint.baseline_hash
        self.active_objective_id = self.wb.continuity.active_objective_id()

    def _gateway(self, *adapters):
        registry = AdapterRegistry()
        for adapter in adapters:
            registry.register(adapter)
        return ExecutionGateway(
            authorizations=self.wb.authorizations, runs=self.wb.runs,
            evidence=self.wb.evidence, trajectory=self.wb.trajectory,
            registry=registry, adapter_id=adapters[0].adapter_id,
            authorization_check_resolver=self.wb.execution_preflight_checks,
        )

    def _coordinator(self, gateway):
        return SupervisedExecutionCoordinator(
            supervisor=self.supervisor, gateway=gateway,
            runs=self.wb.runs, evidence=self.wb.evidence)

    def _run(self, coordinator, supervision_id):
        return coordinator.run(
            supervision_id, baseline_hash=self.baseline_hash,
            active_objective_id=self.active_objective_id)

    def _usage(self, **overrides):
        values = {"wall_time_ms": 1, "tokens_used": 1, "cost_micros": 1}
        values.update(overrides)
        return ExecutionUsage(**values)

    def _completed(self, usage):
        return ExecutionResult(
            status="completed", exit_code=0, outputs={},
            checks_performed=(), evidence=("ran",), usage=usage)

    def _failed(self, usage):
        return ExecutionResult(
            status="failed", exit_code=1, outputs={},
            checks_performed=(), evidence=("ran",), usage=usage)

    def test_first_route_succeeds_without_a_fallback(self):
        adapter = _ScriptedAdapter(
            "scripted-0", result=self._completed(self._usage()))
        plan = self.supervisor.create_plan(
            [route(self.auth0, adapter_id="scripted-0")], circuit_threshold=1)
        sid = plan["supervision_id"]
        summary = self._run(self._coordinator(self._gateway(adapter)), sid)
        self.assertEqual(summary["terminal_status"], "SUCCEEDED")
        self.assertEqual(summary["successful_route_index"], 0)
        self.assertEqual(summary["attempted_route_indexes"], [0])
        self.assertEqual(summary["failure_classes"], {})
        run = self.wb.runs.get(summary["successful_run_id"])
        self.assertEqual(run["authorization_id"], self.auth0)
        self.assertIsNotNone(
            self.wb.evidence.get(summary["successful_evidence_id"]))
        self.assertEqual(adapter.calls, 1)

    def test_typed_timeout_then_second_route_succeeds(self):
        failing = _ScriptedAdapter("scripted-timeout", result=self._completed(
            self._usage(wall_time_ms=1_500)))
        succeeding = _ScriptedAdapter(
            "scripted-ok", result=self._completed(self._usage()))
        plan = self.supervisor.create_plan([
            route(self.auth0, adapter_id="scripted-timeout"),
            route(self.auth1, adapter_id="scripted-ok"),
        ], circuit_threshold=2)
        sid = plan["supervision_id"]
        summary = self._run(
            self._coordinator(self._gateway(failing, succeeding)), sid)
        self.assertEqual(summary["terminal_status"], "SUCCEEDED")
        self.assertEqual(summary["successful_route_index"], 1)
        self.assertEqual(summary["attempted_route_indexes"], [0, 1])
        self.assertEqual(summary["failure_classes"], {0: "timeout"})
        self.assertEqual(failing.calls, 1)
        self.assertEqual(succeeding.calls, 1)

    def test_provider_failure_falls_back_to_the_second_route(self):
        failing = _ScriptedAdapter(
            "scripted-provider-fail",
            raises=ExecutionProviderFailure("injected provider failure"))
        succeeding = _ScriptedAdapter(
            "scripted-ok", result=self._completed(self._usage()))
        plan = self.supervisor.create_plan([
            route(self.auth0, adapter_id="scripted-provider-fail"),
            route(self.auth1, adapter_id="scripted-ok"),
        ], circuit_threshold=2)
        sid = plan["supervision_id"]
        summary = self._run(
            self._coordinator(self._gateway(failing, succeeding)), sid)
        self.assertEqual(summary["terminal_status"], "SUCCEEDED")
        self.assertEqual(
            summary["failure_classes"], {0: "network_or_provider_failure"})
        self.assertEqual(summary["successful_route_index"], 1)

    def test_a_returned_failed_backend_result_falls_back(self):
        failing = _ScriptedAdapter(
            "scripted-failed-result", result=self._failed(self._usage()))
        succeeding = _ScriptedAdapter(
            "scripted-ok", result=self._completed(self._usage()))
        plan = self.supervisor.create_plan([
            route(self.auth0, adapter_id="scripted-failed-result"),
            route(self.auth1, adapter_id="scripted-ok"),
        ], circuit_threshold=2)
        sid = plan["supervision_id"]
        summary = self._run(
            self._coordinator(self._gateway(failing, succeeding)), sid)
        self.assertEqual(summary["failure_classes"], {0: "invalid_artifacts"})
        self.assertEqual(summary["terminal_status"], "SUCCEEDED")
        self.assertEqual(summary["successful_route_index"], 1)
        failed_run = self.wb.runs.for_authorization(self.auth0)[0]
        self.assertEqual(str(failed_run["status"]), FAILED)

    def test_circuit_open_stops_before_the_next_route(self):
        failing = _ScriptedAdapter(
            "scripted-provider-fail",
            raises=ExecutionProviderFailure("injected"))
        plan = self.supervisor.create_plan([
            route(self.auth0, adapter_id="scripted-provider-fail"),
            route(self.auth1, adapter_id="never-reached-1"),
            route(self.auth2, adapter_id="never-reached-2"),
        ], circuit_threshold=1)
        sid = plan["supervision_id"]
        summary = self._run(self._coordinator(self._gateway(failing)), sid)
        self.assertEqual(summary["terminal_status"], "CIRCUIT_OPEN")
        self.assertEqual(summary["attempted_route_indexes"], [0])
        self.assertEqual(
            summary["failure_classes"], {0: "network_or_provider_failure"})
        self.assertEqual(failing.calls, 1)
        self.assertTrue(any(e["event_type"] == "CIRCUIT_OPEN"
                            for e in self.supervisor.events(sid)))

    def test_route_exhaustion_when_every_route_fails_below_threshold(self):
        failing0 = _ScriptedAdapter(
            "scripted-fail-0", raises=ExecutionProviderFailure("injected-0"))
        failing1 = _ScriptedAdapter(
            "scripted-fail-1", raises=ExecutionProviderFailure("injected-1"))
        plan = self.supervisor.create_plan([
            route(self.auth0, adapter_id="scripted-fail-0"),
            route(self.auth1, adapter_id="scripted-fail-1"),
        ], circuit_threshold=2)
        sid = plan["supervision_id"]
        summary = self._run(
            self._coordinator(self._gateway(failing0, failing1)), sid)
        self.assertEqual(summary["terminal_status"], "EXHAUSTED")
        self.assertEqual(summary["attempted_route_indexes"], [0, 1])
        self.assertEqual(summary["failure_classes"], {
            0: "network_or_provider_failure", 1: "network_or_provider_failure"})
        self.assertNotIn("successful_route_index", summary)

    def test_terminal_routes_are_not_replayed_on_a_second_run(self):
        failing = _ScriptedAdapter(
            "scripted-fail", raises=ExecutionProviderFailure("injected"))
        succeeding = _ScriptedAdapter(
            "scripted-ok", result=self._completed(self._usage()))
        plan = self.supervisor.create_plan([
            route(self.auth0, adapter_id="scripted-fail"),
            route(self.auth1, adapter_id="scripted-ok"),
        ], circuit_threshold=2)
        sid = plan["supervision_id"]
        gateway = self._gateway(failing, succeeding)
        first = self._run(self._coordinator(gateway), sid)
        self.assertEqual(failing.calls, 1)
        self.assertEqual(succeeding.calls, 1)
        second = self._run(self._coordinator(gateway), sid)
        self.assertEqual(second, first)
        self.assertEqual(failing.calls, 1)
        self.assertEqual(succeeding.calls, 1)

    def test_a_claim_with_no_backend_run_recovers_without_redispatch(self):
        adapter = _ScriptedAdapter("scripted-unreached", result=None)
        plan = self.supervisor.create_plan(
            [route(self.auth0, adapter_id="scripted-unreached")],
            circuit_threshold=1)
        sid = plan["supervision_id"]
        self.supervisor.start(sid, 0)
        self.wb.runs.claim(
            claim_id=f"claim-{self.auth0}", authorization_id=self.auth0,
            adapter_id="scripted-unreached", request_hash="rh", run_nonce="rn")
        summary = self._run(self._coordinator(self._gateway(adapter)), sid)
        self.assertEqual(summary["terminal_status"], "EXHAUSTED")
        self.assertEqual(
            summary["failure_classes"], {0: "empty_or_incomplete_output"})
        self.assertEqual(adapter.calls, 0)

    def test_a_completed_run_with_durable_usage_resumes_without_redispatch(self):
        usage = self._usage(wall_time_ms=7, tokens_used=8, cost_micros=9)
        adapter = _ScriptedAdapter("scripted-ok", result=self._completed(usage))
        plan = self.supervisor.create_plan(
            [route(self.auth0, adapter_id="scripted-ok")], circuit_threshold=1)
        sid = plan["supervision_id"]
        gateway = self._gateway(adapter)
        self.supervisor.start(sid, 0)
        dispatched = gateway.with_supervision_resolver(
            self.supervisor.resolve_route).using("scripted-ok").dispatch_supervised(
            sid, 0, baseline_hash=self.baseline_hash,
            active_objective_id=self.active_objective_id)
        self.assertEqual(adapter.calls, 1)
        summary = self._run(self._coordinator(gateway), sid)
        self.assertEqual(adapter.calls, 1)
        self.assertEqual(summary["terminal_status"], "SUCCEEDED")
        self.assertEqual(summary["successful_run_id"], dispatched["run_id"])
        self.assertEqual(
            summary["successful_evidence_id"], dispatched["evidence_id"])
        terminal = next(e for e in self.supervisor.events(sid)
                        if e["event_type"] == "SUCCEEDED")
        self.assertEqual(int(terminal["measured_wall_ms"]), 7)
        self.assertEqual(int(terminal["measured_tokens"]), 8)
        self.assertEqual(int(terminal["measured_cost_micros"]), 9)

    def test_missing_durable_usage_is_refused_rather_than_guessed(self):
        plan = self.supervisor.create_plan(
            [route(self.auth0, adapter_id="scripted-unused")],
            circuit_threshold=1)
        sid = plan["supervision_id"]
        self.supervisor.start(sid, 0)
        self.wb.runs.claim(
            claim_id=f"claim-{self.auth0}", authorization_id=self.auth0,
            adapter_id="scripted-unused", request_hash="rh", run_nonce="rn")
        self.wb.evidence.admit(
            evidence_id="evi-missing-usage", kind="execution_evidence",
            source_ref="backend_runs:run-missing-usage",
            content=canonical_json({"attestation_sha256": "a" * 64}),
            admission_basis=f"verified_execution_authorization:{self.auth0}")
        self.wb.runs.record(
            run_id="run-missing-usage", authorization_id=self.auth0,
            adapter_id="scripted-unused", request_hash="rh",
            status=COMPLETED, exit_code=0, result_hash="rh",
            evidence_id="evi-missing-usage")
        coordinator = self._coordinator(
            self._gateway(_ScriptedAdapter("scripted-unused", result=None)))
        with self.assertRaises(WorkerSupervisionRefused):
            self._run(coordinator, sid)

    def test_malformed_durable_usage_is_refused_rather_than_guessed(self):
        plan = self.supervisor.create_plan(
            [route(self.auth0, adapter_id="scripted-unused")],
            circuit_threshold=1)
        sid = plan["supervision_id"]
        self.supervisor.start(sid, 0)
        self.wb.runs.claim(
            claim_id=f"claim-{self.auth0}", authorization_id=self.auth0,
            adapter_id="scripted-unused", request_hash="rh", run_nonce="rn")
        self.wb.evidence.admit(
            evidence_id="evi-malformed-usage", kind="execution_evidence",
            source_ref="backend_runs:run-malformed-usage",
            content=canonical_json({
                "attestation_sha256": "a" * 64,
                "usage": {"wall_time_ms": -1, "tokens_used": 1,
                          "cost_micros": 1},
            }),
            admission_basis=f"verified_execution_authorization:{self.auth0}")
        self.wb.runs.record(
            run_id="run-malformed-usage", authorization_id=self.auth0,
            adapter_id="scripted-unused", request_hash="rh",
            status=COMPLETED, exit_code=0, result_hash="rh",
            evidence_id="evi-malformed-usage")
        coordinator = self._coordinator(
            self._gateway(_ScriptedAdapter("scripted-unused", result=None)))
        with self.assertRaises(WorkerSupervisionRefused):
            self._run(coordinator, sid)

    def test_durable_usage_with_false_content_hash_is_refused(self):
        plan = self.supervisor.create_plan(
            [route(self.auth0, adapter_id="scripted-unused")],
            circuit_threshold=1)
        sid = plan["supervision_id"]
        self.supervisor.start(sid, 0)
        self.wb.runs.claim(
            claim_id=f"claim-{self.auth0}", authorization_id=self.auth0,
            adapter_id="scripted-unused", request_hash="rh", run_nonce="rn")
        evidence_id = "evi-false-usage-hash"
        content = canonical_json({
            "usage": {"wall_time_ms": 1, "tokens_used": 1,
                      "cost_micros": 1}})
        self.wb.store.insert("evidence_records", {
            "evidence_id": evidence_id, "kind": "execution_evidence",
            "source_ref": "backend_runs:run-false-usage-hash",
            "original_language": "forged", "content": content,
            "content_hash": "0" * 64,
            "admission_basis":
                f"verified_execution_authorization:{self.auth0}",
            "observed_at": self.wb.store.now(), "seq": self.wb.store.next_seq(),
        })
        self.wb.runs.record(
            run_id="run-false-usage-hash", authorization_id=self.auth0,
            adapter_id="scripted-unused", request_hash="rh",
            status=COMPLETED, exit_code=0, result_hash="rh",
            evidence_id=evidence_id)
        coordinator = self._coordinator(
            self._gateway(_ScriptedAdapter("scripted-unused", result=None)))
        with self.assertRaises(WorkerSupervisionRefused):
            self._run(coordinator, sid)


if __name__ == "__main__":
    unittest.main()
