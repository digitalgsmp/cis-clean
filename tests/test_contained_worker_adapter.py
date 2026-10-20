"""Unit 3A: closed evidence binding at the contained-worker adapter boundary."""

from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path

from cis.canonical import canonical_json
from cis.errors import (
    ExecutionArtifactInvalid, ExecutionRefused, ExecutionTimedOut,
)
from cis.execution import AdapterRegistry, ExecutionGateway
from cis.execution.adapters.contained_worker import (
    ContainedWorkerAdapter, WORKER_OPERATION,
)
from cis.execution.port import (
    ExecutionBudget, ExecutionPort, ExecutionRequest, ExecutionResult,
    ExecutionUsage, _mint_token,
)
from cis.execution.worker_supervisor import (
    SupervisedExecutionCoordinator, WorkerSupervisorAuthority,
)

from . import support


SOURCE = "def run(args):\n    return args[0]\n"
VECTORS = [{"args": [1], "expect_value": 1}]
IMAGE = "sha256:" + "c" * 64
RUNNER_SHA = "a" * 64
WORKER_SHA = "b" * 64


def request(budget=None, **payload_overrides):
    payload = {
        "authored_source": SOURCE,
        "vectors": VECTORS,
        "entrypoint": "run",
        "candidate_sha256": hashlib.sha256(SOURCE.encode()).hexdigest(),
        "vector_contract_sha256": hashlib.sha256(
            canonical_json(VECTORS).encode()).hexdigest(),
        "execution_input_hash": "e" * 64,
        "task_contract_id": "tc-bound",
        "task_contract_hash": "t" * 64,
        "expected_trusted_runner_sha256": RUNNER_SHA,
        "expected_worker_sha256": WORKER_SHA,
    }
    payload.update(payload_overrides)
    bare = ExecutionRequest(
        request_id="req-bound", operation="verify_authored_source",
        allowed_scope=("tests/cis/module",),
        forbidden_actions=("network:any", "host:promote"),
        required_checks=("candidate_source_binding_recomputes",),
        stopping_condition="stop after verification",
        return_point="assurance:verification_inputs",
        payload=payload, binding_hash="d" * 64, budget=budget,
    )
    return ExecutionRequest(
        # contract_view() renders a present budget as a plain hashable dict;
        # the live request needs the real ExecutionBudget object back, the
        # same substitution the gateway performs in dispatch_supervised.
        **{**bare.contract_view(), "budget": bare.budget},
        binding_hash=bare.binding_hash,
        token=_mint_token(binding_hash=bare.binding_hash,
                          request_hash=bare.request_hash),
    )


class FakeRunner:
    def __init__(self, *, verdict="SOURCE_PASS", returncode=0,
                 mutate=None, timeout=False,
                 cleanup_raises=False, cleanup_returncode=0,
                 probe_raises=False, probe_returncode=1):
        self.verdict = verdict
        self.returncode = returncode
        self.mutate = mutate
        self.timeout = timeout
        # Teardown-after-timeout behavior, modeled explicitly rather than
        # folded into the generic ``timeout`` flag: a probe_returncode of 1
        # (the docker convention for "no such object") is the only shape
        # that proves the container is gone.
        self.cleanup_raises = cleanup_raises
        self.cleanup_returncode = cleanup_returncode
        self.probe_raises = probe_raises
        self.probe_returncode = probe_returncode
        self.calls = []
        self.timeouts = []

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        self.timeouts.append(timeout)
        if len(argv) >= 3 and argv[1:3] == ["image", "inspect"]:
            # The liveness probe the gateway issues before any dispatch.
            # It carries no workspace mount, so it is answered here and
            # never reaches the worker-evidence-writing path below.
            return subprocess.CompletedProcess(argv, 0, "", "")
        if len(argv) == 4 and argv[1:3] == ["rm", "-f"]:
            # The fixed cleanup command issued only after a run timeout.
            if self.cleanup_raises:
                raise OSError("cleanup command could not be executed")
            return subprocess.CompletedProcess(argv, self.cleanup_returncode, "", "")
        if len(argv) == 3 and argv[1] == "inspect":
            # The fixed absence probe issued only after cleanup.
            if self.probe_raises:
                raise OSError("probe command could not be executed")
            return subprocess.CompletedProcess(argv, self.probe_returncode, "", "")
        if self.timeout:
            raise subprocess.TimeoutExpired(argv, timeout)
        workspace = Path(next(
            value for index, value in enumerate(argv)
            if argv[index - 1:index] == ["-v"] and value.endswith(":/workspace")
        ).split(":/workspace", 1)[0])
        bundle_hash, task_hash, binding_hash, input_hash, nonce = argv[-5:]
        verdict_json = json.dumps({"verdict": self.verdict}, separators=(",", ":"))
        values = {
            "schema": "cis-contained-worker-evidence-v4",
            "run_nonce": nonce, "uid": "65532", "gid": "65532",
            "operation": "verify_authored_source",
            "task_contract_bundle_sha256": bundle_hash,
            "task_contract_hash": task_hash,
            "authorization_binding_hash": binding_hash,
            "input_sha256": input_hash, "verdict": self.verdict,
            "runner_exit": str(self.returncode), "verdict_json": verdict_json,
            "nets": "lo,", "cap_eff": "0000000000000000",
            "no_new_privs": "1", "pids_max": "32",
            "memory_max": "67108864", "cpu_max": "50000 100000",
            "rootfs_write": "denied", "rootfs_probe_cleanup": "not_needed",
            "contract_write": "denied", "contract_probe_cleanup": "not_needed",
            "workspace_write": "allowed", "trusted_runner_sha256": RUNNER_SHA,
            "worker_sha256": WORKER_SHA,
            "resource_exhaustion_classification": "infrastructure_not_source",
            "promotion": "none", "host_action": "none",
        }
        if self.mutate:
            self.mutate(values)
        (workspace / "worker-evidence.txt").write_text(
            "\n".join(f"{key}={value}" for key, value in values.items()) + "\n",
            encoding="utf-8")
        return subprocess.CompletedProcess(argv, self.returncode, "", "")


class ContainedWorkerAdapterBindingTests(unittest.TestCase):
    def execute(self, fake, req=None):
        return ContainedWorkerAdapter(
            image=IMAGE, runner=fake, container_cmd=("docker",),
        ).execute(req or request())

    def test_valid_pass_is_bound_and_attested(self):
        result = self.execute(FakeRunner())
        evidence = dict(line.split("=", 1) for line in result.evidence)
        self.assertEqual((result.status, result.exit_code), ("completed", 0))
        self.assertEqual(evidence["attestation_valid"], "true")
        self.assertEqual(evidence["source_sha256"],
                         hashlib.sha256(SOURCE.encode()).hexdigest())
        self.assertEqual(evidence["vector_contract_sha256"],
                         hashlib.sha256(canonical_json(VECTORS).encode()).hexdigest())
        self.assertEqual(evidence["execution_input_hash"], "e" * 64)
        self.assertEqual(evidence["task_contract_hash"], "t" * 64)

    def test_refuses_candidate_or_vector_digest_mismatch_before_runner(self):
        for field in ("candidate_sha256", "vector_contract_sha256"):
            with self.subTest(field=field):
                fake = FakeRunner()
                with self.assertRaises(ExecutionRefused):
                    self.execute(fake, request(**{field: "0" * 64}))
                self.assertEqual(fake.calls, [])

    def test_exit_cannot_be_forged_by_pass_evidence(self):
        result = self.execute(FakeRunner(verdict="SOURCE_PASS", returncode=1))
        evidence = dict(line.split("=", 1) for line in result.evidence)
        self.assertEqual((result.status, result.exit_code), ("failed", 2))
        self.assertEqual(result.outputs["classification"], "HARNESS_FAILURE")
        self.assertEqual(evidence["attestation_valid"], "false")
        self.assertIn("verdict_exit_mismatch", evidence["attestation_failures"])

    def test_missing_or_unexpected_worker_field_is_harness_failure(self):
        for mutate in (lambda values: values.pop("worker_sha256"),
                       lambda values: values.update({"forged": "yes"})):
            with self.subTest(mutate=mutate):
                result = self.execute(FakeRunner(mutate=mutate))
                self.assertEqual((result.status, result.exit_code), ("failed", 2))

    def test_apparatus_digest_mismatch_is_harness_failure(self):
        result = self.execute(FakeRunner(
            mutate=lambda values: values.update(
                trusted_runner_sha256="f" * 64)))
        self.assertEqual((result.status, result.exit_code), ("failed", 2))
        self.assertEqual(result.outputs["classification"], "HARNESS_FAILURE")

    def test_source_failure_remains_a_valid_nonpassing_attestation(self):
        result = self.execute(FakeRunner(verdict="SOURCE_FAIL", returncode=1))
        evidence = dict(line.split("=", 1) for line in result.evidence)
        self.assertEqual((result.status, result.exit_code), ("failed", 1))
        self.assertEqual(evidence["attestation_valid"], "true")

    def test_timeout_is_resource_exhaustion_not_source_failure(self):
        result = self.execute(FakeRunner(timeout=True))
        self.assertEqual((result.status, result.exit_code), ("failed", 3))
        self.assertEqual(result.outputs["classification"], "RESOURCE_EXHAUSTION")

    def test_declares_exactly_the_three_supervised_budget_dimensions(self):
        self.assertEqual(
            set(ContainedWorkerAdapter().enforced_budget_dimensions),
            {"wall_time_ms", "token_limit", "cost_limit_micros"})


class ContainedWorkerAdapterBudgetTests(unittest.TestCase):
    """Unit 7C1: real wall-budget enforcement and usage reporting."""

    def execute(self, fake, req):
        return ContainedWorkerAdapter(
            image=IMAGE, runner=fake, container_cmd=("docker",),
        ).execute(req)

    def test_authorized_wall_time_is_the_exact_subprocess_timeout(self):
        fake = FakeRunner()
        budget = ExecutionBudget(
            wall_time_ms=5_000, token_limit=10, cost_limit_micros=10)
        self.execute(fake, request(budget=budget))
        self.assertEqual(fake.timeouts[0], 5.0)

    def test_authorized_wall_time_cannot_exceed_the_configured_backstop(self):
        fake = FakeRunner()
        budget = ExecutionBudget(
            wall_time_ms=10_000_000, token_limit=10, cost_limit_micros=10)
        adapter = ContainedWorkerAdapter(
            image=IMAGE, runner=fake, container_cmd=("docker",),
            timeout_seconds=7)
        adapter.execute(request(budget=budget))
        self.assertEqual(fake.timeouts[0], 7.0)

    def test_unbudgeted_request_keeps_the_adapter_backstop_as_its_timeout(self):
        fake = FakeRunner()
        self.execute(fake, request())
        self.assertEqual(fake.timeouts[0], 300.0)

    def test_budgeted_success_reports_elapsed_usage_with_zero_tokens_and_cost(self):
        fake = FakeRunner()
        budget = ExecutionBudget(
            wall_time_ms=5_000, token_limit=10, cost_limit_micros=10)
        result = self.execute(fake, request(budget=budget))
        self.assertEqual(result.status, "completed")
        self.assertIsNotNone(result.usage)
        self.assertGreaterEqual(result.usage.wall_time_ms, 0)
        self.assertEqual(result.usage.tokens_used, 0)
        self.assertEqual(result.usage.cost_micros, 0)

    def test_budgeted_ordinary_source_failure_also_reports_usage(self):
        fake = FakeRunner(verdict="SOURCE_FAIL", returncode=1)
        budget = ExecutionBudget(
            wall_time_ms=5_000, token_limit=10, cost_limit_micros=10)
        result = self.execute(fake, request(budget=budget))
        self.assertEqual(result.status, "failed")
        self.assertIsNotNone(result.usage)
        self.assertEqual(result.usage.tokens_used, 0)
        self.assertEqual(result.usage.cost_micros, 0)

    def test_unbudgeted_request_carries_no_usage_and_keeps_prior_shape(self):
        fake = FakeRunner()
        result = self.execute(fake, request())
        self.assertIsNone(result.usage)
        self.assertNotIn("usage", result.as_dict())

    def test_budget_exceeded_raises_typed_timeout_not_a_generic_failure(self):
        fake = FakeRunner(timeout=True)
        budget = ExecutionBudget(
            wall_time_ms=50, token_limit=10, cost_limit_micros=10)
        req = request(budget=budget)
        with self.assertRaises(ExecutionTimedOut) as caught:
            self.execute(fake, req)
        self.assertEqual(caught.exception.detail["wall_time_ms"], 50)
        self.assertGreaterEqual(caught.exception.detail["measured_wall_time_ms"], 0)

    def test_budget_exceeded_cleans_up_the_deterministic_container_name(self):
        fake = FakeRunner(timeout=True)
        budget = ExecutionBudget(
            wall_time_ms=50, token_limit=10, cost_limit_micros=10)
        req = request(budget=budget)
        with self.assertRaises(ExecutionTimedOut):
            self.execute(fake, req)
        # Exactly one sealed run, one fixed cleanup, one fixed absence
        # probe — all naming only the deterministic name this adapter
        # alone derived from the authorized request, never a
        # caller-supplied one.
        derived_name = f"cis-cw-{req.request_hash[:32]}"
        self.assertEqual(len(fake.calls), 3)
        run_dispatches = [c for c in fake.calls if WORKER_OPERATION in c]
        cleanup_calls = [c for c in fake.calls if c[1:3] == ["rm", "-f"]]
        probe_calls = [c for c in fake.calls if c[1] == "inspect"]
        self.assertEqual(len(run_dispatches), 1)
        self.assertEqual(len(cleanup_calls), 1)
        self.assertEqual(len(probe_calls), 1)
        self.assertEqual(cleanup_calls[0], ["docker", "rm", "-f", derived_name])
        self.assertEqual(probe_calls[0], ["docker", "inspect", derived_name])

    def test_unbudgeted_timeout_keeps_existing_resource_exhaustion_behavior(self):
        fake = FakeRunner(timeout=True)
        result = self.execute(fake, request())
        self.assertEqual((result.status, result.exit_code), ("failed", 3))
        self.assertEqual(result.outputs["classification"], "RESOURCE_EXHAUSTION")
        self.assertIsNone(result.usage)

    def test_teardown_not_proven_when_cleanup_command_cannot_execute(self):
        fake = FakeRunner(timeout=True, cleanup_raises=True)
        req = request()
        with self.assertRaises(ExecutionArtifactInvalid) as caught:
            self.execute(fake, req)
        self.assertEqual(caught.exception.detail["request_id"], req.request_id)
        self.assertEqual(
            caught.exception.detail["container_name"],
            f"cis-cw-{req.request_hash[:32]}")
        self.assertEqual(caught.exception.detail["cleanup_error"], "OSError")
        # Cleanup never executed, so the absence probe is never reached.
        probe_calls = [c for c in fake.calls if c[1] == "inspect"]
        self.assertEqual(probe_calls, [])

    def test_teardown_not_proven_when_container_still_present(self):
        fake = FakeRunner(timeout=True, probe_returncode=0)
        req = request()
        with self.assertRaises(ExecutionArtifactInvalid) as caught:
            self.execute(fake, req)
        self.assertEqual(caught.exception.detail["cleanup_exit"], 0)
        self.assertEqual(caught.exception.detail["probe_exit"], 0)
        derived_name = f"cis-cw-{req.request_hash[:32]}"
        cleanup_calls = [c for c in fake.calls if c[1:3] == ["rm", "-f"]]
        probe_calls = [c for c in fake.calls if c[1] == "inspect"]
        self.assertEqual(cleanup_calls, [["docker", "rm", "-f", derived_name]])
        self.assertEqual(probe_calls, [["docker", "inspect", derived_name]])

    def test_teardown_not_proven_when_absence_probe_cannot_execute(self):
        fake = FakeRunner(timeout=True, probe_raises=True)
        req = request()
        with self.assertRaises(ExecutionArtifactInvalid) as caught:
            self.execute(fake, req)
        self.assertEqual(caught.exception.detail["probe_error"], "OSError")
        self.assertNotIn("cleanup_error", caught.exception.detail)

    def test_budgeted_timeout_with_unproven_teardown_is_artifact_invalid_not_timeout(self):
        fake = FakeRunner(timeout=True, probe_returncode=0)
        budget = ExecutionBudget(
            wall_time_ms=50, token_limit=10, cost_limit_micros=10)
        with self.assertRaises(ExecutionArtifactInvalid):
            self.execute(fake, request(budget=budget))

    def test_six_argument_invocation_is_unchanged_by_budget_support(self):
        fake = FakeRunner()
        req = request()
        self.execute(fake, req)
        argv = fake.calls[0]
        tail = argv[-6:]
        self.assertEqual(tail[0], WORKER_OPERATION)
        self.assertEqual(tail[-1], req.request_hash[:32])
        self.assertIn("--name", argv)
        self.assertIn("--network", argv)


class _ImmediateFallbackAdapter(ExecutionPort):
    """A minimal second backend for the fallback route: no execution-input
    or task-contract binding, just a scripted completed result with usage,
    so the coordinator's fallback walk can be proven over a real adapter_id
    pair rather than purely scripted ones."""

    adapter_id = "contained_worker_test_fallback"
    enforced_budget_dimensions = (
        "wall_time_ms", "token_limit", "cost_limit_micros")

    def capabilities(self):
        return ("verify_authored_source",)

    def execute(self, request):
        request.verify_token()
        return ExecutionResult(
            status="completed", exit_code=0, outputs={},
            checks_performed=tuple(request.required_checks),
            evidence=("ran",),
            usage=ExecutionUsage(wall_time_ms=1, tokens_used=0, cost_micros=0),
        )


class ContainedWorkerSupervisedIntegrationTests(unittest.TestCase):
    """Unit 7C1: the real ``ContainedWorkerAdapter``, under the real
    ``SupervisedExecutionCoordinator``, proving a typed timeout advances
    fallback routing and leaves durable terminal events — not a scripted
    stand-in adapter."""

    def setUp(self):
        self.wb, outcome = support.allow_outcome()
        original = outcome.authorization
        transaction_id = original["transaction_id"]

        scope = dict(original["scope"])
        scope["operation"] = "verify_authored_source"

        self.auth_primary = f"auth-verify-primary-{transaction_id}"
        self.auth_fallback = f"auth-verify-fallback-{transaction_id}"
        for authorization_id in (self.auth_primary, self.auth_fallback):
            self.wb.authorizations.record(
                authorization_id=authorization_id,
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

        compiled = support.freeze_task_contract(
            self.wb, self.auth_primary, template_id="verify_authored_source.v1")
        frozen = support.assurance_authority(self.wb).ledger.require_task_contract(
            compiled.task_contract_id)
        support.execution_input_authority(self.wb).append(
            task_contract_id=compiled.task_contract_id,
            candidate_source=SOURCE.encode("utf-8"),
            candidate_sha256=hashlib.sha256(SOURCE.encode()).hexdigest(),
            vector_contract=canonical_json(VECTORS).encode("utf-8"),
            vector_contract_sha256=hashlib.sha256(
                canonical_json(VECTORS).encode()).hexdigest(),
            authorized_entrypoint="run",
            task_contract_hash=str(frozen["task_contract_hash"]),
            authorization_binding_hash=str(frozen["authorization_binding_hash"]),
            worker_image=IMAGE,
            expected_trusted_runner_sha256=RUNNER_SHA,
            expected_worker_sha256=WORKER_SHA,
        )

        self.timing_out_runner = FakeRunner(timeout=True)
        self.contained = ContainedWorkerAdapter(
            image=IMAGE, runner=self.timing_out_runner, container_cmd=("docker",))
        self.fallback = _ImmediateFallbackAdapter()
        registry = AdapterRegistry()
        registry.register(self.contained)
        registry.register(self.fallback)

        ledger = support.assurance_authority(self.wb).ledger
        self.gateway = ExecutionGateway(
            authorizations=self.wb.authorizations, runs=self.wb.runs,
            evidence=self.wb.evidence, trajectory=self.wb.trajectory,
            registry=registry, adapter_id=self.contained.adapter_id,
            task_contract_resolver=ledger.task_contract_for_authorization,
            execution_input_resolver=support.execution_input_authority(
                self.wb).verify,
            authorization_check_resolver=self.wb.execution_preflight_checks,
        )
        self.supervisor = WorkerSupervisorAuthority(self.wb.store)

    def test_typed_timeout_advances_to_fallback_and_records_terminal_events(self):
        plan = self.supervisor.create_plan([
            {"authorization_id": self.auth_primary,
             "adapter_id": self.contained.adapter_id,
             "wall_time_ms": 50, "token_limit": 1000,
             "cost_limit_micros": 1000},
            {"authorization_id": self.auth_fallback,
             "adapter_id": self.fallback.adapter_id,
             "wall_time_ms": 1000, "token_limit": 1000,
             "cost_limit_micros": 1000},
        ], circuit_threshold=2)
        sid = plan["supervision_id"]
        coordinator = SupervisedExecutionCoordinator(
            supervisor=self.supervisor, gateway=self.gateway,
            runs=self.wb.runs, evidence=self.wb.evidence)
        summary = coordinator.run(
            sid, baseline_hash=self.wb.blueprint.baseline_hash,
            active_objective_id=self.wb.continuity.active_objective_id())

        self.assertEqual(summary["terminal_status"], "SUCCEEDED")
        self.assertEqual(summary["attempted_route_indexes"], [0, 1])
        self.assertEqual(summary["failure_classes"], {0: "timeout"})
        self.assertEqual(summary["successful_route_index"], 1)

        events = self.supervisor.events(sid)
        terminal_by_route = {
            int(event["route_index"]): event["event_type"] for event in events
            if event["event_type"] in ("SUCCEEDED", "FAILED")}
        self.assertEqual(terminal_by_route, {0: "FAILED", 1: "SUCCEEDED"})

        # Four distinct calls reach the timed-out runner: the gateway's own
        # liveness probe, the one sealed run dispatch (which times out),
        # this unit's deterministic cleanup, and its absence probe — never
        # a second redispatch of the same route, and never more than one of
        # each kind.
        calls = self.timing_out_runner.calls
        self.assertEqual(len(calls), 4)

        liveness_calls = [c for c in calls if c[1:3] == ["image", "inspect"]]
        run_dispatches = [c for c in calls if WORKER_OPERATION in c]
        cleanup_calls = [c for c in calls if c[1:3] == ["rm", "-f"]]
        probe_calls = [c for c in calls if c[1] == "inspect"]
        self.assertEqual(len(liveness_calls), 1)
        self.assertEqual(len(run_dispatches), 1)
        self.assertEqual(len(cleanup_calls), 1)
        self.assertEqual(len(probe_calls), 1)

        self.assertEqual(cleanup_calls[0][:3], ["docker", "rm", "-f"])
        self.assertEqual(probe_calls[0][:2], ["docker", "inspect"])


if __name__ == "__main__":
    unittest.main()
