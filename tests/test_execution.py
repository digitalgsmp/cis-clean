"""The Layer-2 execution boundary: gating, determinism, replaceability, leaks."""

import re
import unittest
from pathlib import Path

from cis.authority.runs import COMPLETED
from cis.errors import (
    AuthorizationRefused, BindingError, CisError, ExecutionArtifactInvalid,
    ExecutionBudgetExhausted, ExecutionOutputIncomplete,
    ExecutionPermissionWaitRefused, ExecutionProviderFailure, ExecutionRefused,
    ExecutionTimedOut, StaleAuthorization,
)
from cis.execution import (
    AdapterRegistry, ExecutionBudget, ExecutionGateway, ExecutionRequest,
    ExecutionUsage,
)
from cis.execution.adapters.deterministic_mock import (
    DeterministicMockAdapter, SecondDeterministicAdapter,
)
from cis.execution.port import ExecutionPort, ExecutionResult, _mint_token

from . import support

SRC = Path(__file__).resolve().parents[1] / "src" / "cis"

#: The adapter package is the only place a backend may be named
#: (ADR-ARCH-003 clause 2). Everything else is checked for leaks.
_BOUNDARY = SRC / "execution"


def _request(**overrides) -> ExecutionRequest:
    fields = {
        "request_id": "req-1",
        "operation": "reconstruct_module",
        "allowed_scope": ("module:cis.workbench.projection",),
        "forbidden_actions": ("network:any",),
        "required_checks": ("contract_registry_valid",),
        "stopping_condition": "stop after one module",
        "return_point": "workbench:trajectory",
        "payload": {},
    }
    fields.update(overrides)
    return ExecutionRequest(**fields)


class BackendGateTests(unittest.TestCase):
    """The mock may run only with a valid ALLOW authorization."""

    def test_the_backend_refuses_a_request_with_no_token(self):
        with self.assertRaises(ExecutionRefused) as caught:
            DeterministicMockAdapter().execute(_request())
        self.assertIn("no authorization token", caught.exception.message)

    def test_the_backend_refuses_a_token_minted_for_other_content(self):
        other = _request(allowed_scope=("module:cis.authority.store",))
        token = _mint_token(binding_hash="bh", request_hash=other.request_hash)
        request = _request(token=token, binding_hash="bh")
        with self.assertRaises(ExecutionRefused) as caught:
            DeterministicMockAdapter().execute(request)
        self.assertIn("does not match", caught.exception.message)

    def test_the_backend_refuses_an_undeclared_operation(self):
        unbound = _request(operation="deploy_to_production")
        request = _request(
            operation="deploy_to_production",
            token=_mint_token(binding_hash="bh", request_hash=unbound.request_hash),
            binding_hash="bh")
        with self.assertRaises(ExecutionRefused):
            DeterministicMockAdapter().execute(request)

    def test_the_backend_refuses_an_empty_scope(self):
        unbound = _request(allowed_scope=())
        request = _request(
            allowed_scope=(),
            token=_mint_token(binding_hash="bh", request_hash=unbound.request_hash),
            binding_hash="bh")
        with self.assertRaises(ExecutionRefused):
            DeterministicMockAdapter().execute(request)

    def test_an_authorized_request_runs_and_is_deterministic(self):
        unbound = _request()
        request = _request(
            token=_mint_token(binding_hash="bh", request_hash=unbound.request_hash),
            binding_hash="bh")
        first = DeterministicMockAdapter().execute(request)
        second_request = _request(
            token=_mint_token(binding_hash="bh", request_hash=unbound.request_hash),
            binding_hash="bh")
        second = DeterministicMockAdapter().execute(second_request)
        self.assertEqual(first.status, "completed")
        self.assertEqual(first.result_hash, second.result_hash)


class GatewayGateTests(unittest.TestCase):
    def setUp(self):
        self.wb, self.outcome = support.allow_outcome()
        self.authorization_id = self.outcome.authorization["authorization_id"]

    def test_a_valid_allow_runs_through_the_gateway(self):
        result = self.wb.execute(self.authorization_id)
        self.assertEqual(result["status"], COMPLETED)
        self.assertEqual(result["exit_code"], 0)
        run = self.wb.runs.get(result["run_id"])
        self.assertEqual(run["authorization_id"], self.authorization_id)
        self.assertEqual(run["result_hash"], result["result_hash"])
        self.assertIsNotNone(self.wb.evidence.get(str(run["evidence_id"])))

    def test_a_hold_cannot_be_executed_and_leaves_no_completed_run(self):
        hold = self.wb.submit_instruction("What is the current stage?")
        hold_id = hold.authorization["authorization_id"]
        with self.assertRaises(AuthorizationRefused):
            self.wb.execute(hold_id)
        self.assertEqual(self.wb.runs.for_authorization(hold_id), [])

    def test_an_unknown_authorization_cannot_be_executed(self):
        with self.assertRaises(AuthorizationRefused):
            self.wb.execute("auth-nonexistent")

    def test_a_refusal_is_recorded_as_evidence_rather_than_silence(self):
        with self.assertRaises(AuthorizationRefused):
            self.wb.execute("auth-nonexistent")
        refusals = [
            row for row in self.wb.trajectory.events(scope="micro")
            if row["event_type"] == "execution_refused"
        ]
        self.assertTrue(refusals)
        self.assertIn("auth-nonexistent", str(refusals[-1]["detail_json"]))

    def test_a_stale_authorization_cannot_be_executed(self):
        self.wb.submit_instruction("New objective: prove something else entirely")
        with self.assertRaises(StaleAuthorization):
            self.wb.execute(self.authorization_id)
        self.assertEqual(self.wb.runs.for_authorization(self.authorization_id), [])

    def test_a_tampered_authorization_cannot_be_executed(self):
        row = self.wb.authorizations.get(self.authorization_id)
        forged = row.as_dict()
        forged["authorization_id"] = "auth-forged"
        forged["allowed_scope_json"] = '["module:cis.authority.store"]'
        forged["seq"] = self.wb.store.next_seq()
        forged["created_at"] = self.wb.store.now()
        self.wb.store.insert("execution_authorizations", forged)
        with self.assertRaises(BindingError):
            self.wb.execute("auth-forged")
        self.assertEqual(self.wb.runs.for_authorization("auth-forged"), [])

    def test_a_tampered_bound_operation_cannot_be_executed(self):
        row = self.wb.authorizations.get(self.authorization_id)
        forged = row.as_dict()
        forged["authorization_id"] = "auth-forged-operation"
        forged["operation"] = "verify_module"
        forged["seq"] = self.wb.store.next_seq()
        forged["created_at"] = self.wb.store.now()
        self.wb.store.insert("execution_authorizations", forged)
        with self.assertRaises(BindingError):
            self.wb.execute("auth-forged-operation")
        self.assertEqual(
            self.wb.runs.for_authorization("auth-forged-operation"), [])

    def test_the_gateway_builds_the_request_from_authority_not_from_the_caller(self):
        # Operation is part of the bound authorization, never caller input.
        import inspect
        signature = inspect.signature(self.wb.execute)
        self.assertEqual(list(signature.parameters), ["authorization_id"])

    def test_the_bound_operation_is_used(self):
        self.assertEqual(
            self.outcome.authorization["scope"]["operation"],
            "reconstruct_module",
        )
        result = self.wb.execute(self.authorization_id)
        self.assertEqual(result["outputs"]["operation"], "reconstruct_module")


class ReplacementTests(unittest.TestCase):
    """Backend replacement must require no change above the Layer-2 port."""

    def setUp(self):
        self.registry = AdapterRegistry()
        self.registry.register(DeterministicMockAdapter())
        self.registry.register(SecondDeterministicAdapter())

    def _workbench(self, adapter_id):
        store = support.fresh_store()
        wb = support.workbench(store=store)
        wb.gateway = ExecutionGateway(
            authorizations=wb.authorizations,
            runs=wb.runs,
            evidence=wb.evidence,
            trajectory=wb.trajectory,
            registry=self.registry,
            adapter_id=adapter_id,
            authorization_check_resolver=wb.execution_preflight_checks,
        )
        return support.allow_outcome(wb)

    def test_both_adapters_satisfy_the_same_call_site(self):
        results = {}
        for adapter_id in ("deterministic_mock", "deterministic_alternate"):
            wb, outcome = self._workbench(adapter_id)
            # Identical calling code for both backends.
            result = wb.execute(outcome.authorization["authorization_id"])
            self.assertEqual(result["status"], COMPLETED)
            run = wb.runs.get(result["run_id"])
            self.assertEqual(run["adapter_id"], adapter_id)
            results[adapter_id] = result["outputs"]["artifact_digest"]
        # Different backends really did the work.
        self.assertNotEqual(*results.values())

    def test_switching_backend_is_a_gateway_concern_only(self):
        wb, outcome = self._workbench("deterministic_mock")
        swapped = wb.gateway.using("deterministic_alternate")
        self.assertEqual(swapped.adapter_id, "deterministic_alternate")
        self.assertEqual(wb.gateway.adapter_id, "deterministic_mock")

    def test_an_unregistered_adapter_is_refused_at_construction(self):
        with self.assertRaises(CisError):
            self._workbench("some_other_harness")

    def test_a_non_conforming_adapter_cannot_register(self):
        class NotAnAdapter:
            adapter_id = "bogus"

        with self.assertRaises(CisError):
            AdapterRegistry().register(NotAnAdapter())

    def test_duplicate_adapter_id_is_refused(self):
        with self.assertRaises(CisError):
            self.registry.register(DeterministicMockAdapter())

    def test_adapter_claims_are_combined_with_independent_preflight(self):
        class SkippingAdapter(ExecutionPort):
            adapter_id = "skips_checks"

            def capabilities(self):
                return ("reconstruct_module",)

            def execute(self, request):
                request.verify_token()
                return ExecutionResult(status="completed", exit_code=0,
                                       outputs={}, checks_performed=(),
                                       evidence=("ran",))

        self.registry.register(SkippingAdapter())
        wb, outcome = self._workbench("skips_checks")
        result = wb.execute(outcome.authorization["authorization_id"])
        self.assertEqual(set(result["checks_performed"]), {
            "blueprint_baseline_matches",
            "canonical_authorization_basis_present",
            "contract_registry_valid",
        })

    def test_a_spent_capability_cannot_be_replayed(self):
        unbound = _request()
        request = _request(
            token=_mint_token(binding_hash="bh", request_hash=unbound.request_hash),
            binding_hash="bh")
        DeterministicMockAdapter().execute(request)
        with self.assertRaises(ExecutionRefused):
            DeterministicMockAdapter().execute(request)

    def test_a_failed_adapter_attempt_spends_the_authorization(self):
        class FailingAdapter(ExecutionPort):
            adapter_id = "fails_after_entry"
            calls = 0

            def capabilities(self):
                return ("reconstruct_module",)

            def execute(self, request):
                request.verify_token()
                self.calls += 1
                raise ExecutionRefused("injected adapter failure")

        adapter = FailingAdapter()
        self.registry.register(adapter)
        wb, outcome = self._workbench(adapter.adapter_id)
        authorization_id = outcome.authorization["authorization_id"]
        with self.assertRaises(ExecutionRefused):
            wb.execute(authorization_id)
        claim = wb.runs.claim_for_authorization(authorization_id)
        self.assertIsNotNone(claim)
        with self.assertRaises(ExecutionRefused):
            wb.execute(authorization_id)
        self.assertEqual(adapter.calls, 1)

    def test_missing_independent_preflight_check_refuses_before_claim(self):
        wb = support.workbench()
        wb.gateway = ExecutionGateway(
            authorizations=wb.authorizations, runs=wb.runs,
            evidence=wb.evidence, trajectory=wb.trajectory,
            registry=self.registry, adapter_id="deterministic_mock",
            authorization_check_resolver=lambda row: (),
        )
        outcome = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        authorization_id = outcome.authorization["authorization_id"]
        with self.assertRaises(ExecutionRefused) as caught:
            wb.execute(authorization_id)
        self.assertTrue(caught.exception.detail["uncovered"])
        self.assertIsNone(wb.runs.claim_for_authorization(authorization_id))

    def test_a_backend_that_declares_itself_not_live_is_refused(self):
        class DeadAdapter(DeterministicMockAdapter):
            adapter_id = "not_live"

            def liveness(self):
                return False

        self.registry.register(DeadAdapter())
        wb, outcome = self._workbench("not_live")
        with self.assertRaises(ExecutionRefused):
            wb.execute(outcome.authorization["authorization_id"])


class NoLeakAboveTheBoundaryTests(unittest.TestCase):
    """ADR-ARCH-003 clause 2 — nothing above Layer 2 may name a backend."""

    #: Every adapter id and class name that exists in the slice.
    _BACKEND_NAMES = (
        "deterministic_mock", "DeterministicMockAdapter",
        "deterministic_alternate", "SecondDeterministicAdapter",
    )

    #: Names of replaceable execution infrastructure that must not appear in
    #: CIS code at all, at any layer.
    _FOREIGN_BACKENDS = ("hermes", "deepseek", "openrouter", "ollama",
                         "llama.cpp", "vllm")

    def _modules_above_the_boundary(self):
        for path in sorted(SRC.rglob("*.py")):
            if _BOUNDARY in path.parents or path.parent == _BOUNDARY:
                continue
            yield path

    def test_no_backend_name_appears_above_the_execution_boundary(self):
        offenders = []
        for path in self._modules_above_the_boundary():
            text = path.read_text(encoding="utf-8")
            for name in self._BACKEND_NAMES:
                if name in text:
                    offenders.append((path.name, name))
        self.assertEqual(offenders, [])

    def test_no_port_number_or_backend_config_path_appears_above_the_boundary(self):
        pattern = re.compile(r"\b(?:86[0-9]{2}|8800)\b|\.hermes|config\.yaml")
        offenders = [
            path.name for path in self._modules_above_the_boundary()
            if pattern.search(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])

    def test_no_foreign_backend_is_named_anywhere_in_the_slice(self):
        offenders = []
        for path in sorted(SRC.rglob("*.py")):
            lowered = path.read_text(encoding="utf-8").lower()
            for name in self._FOREIGN_BACKENDS:
                if name in lowered:
                    offenders.append((path.name, name))
        self.assertEqual(offenders, [])

    def test_the_workbench_reaches_execution_only_through_the_gateway(self):
        text = (SRC / "workbench" / "service.py").read_text(encoding="utf-8")
        imports = [line for line in text.splitlines()
                   if "execution" in line and line.strip().startswith("from")]
        self.assertEqual(imports, ["from ..execution.gateway import ExecutionGateway"])

    def test_the_control_surface_holds_no_sql_and_no_authority_table(self):
        text = (SRC / "interface" / "api.py").read_text(encoding="utf-8")
        for token in ("SELECT ", "INSERT ", "sqlite3", "trajectory_events",
                      "execution_authorizations", "intent_transactions"):
            self.assertNotIn(token, text)


class ExecutionBudgetTests(unittest.TestCase):
    """Unit 7B1: the provider-neutral budget/failure vocabulary."""

    def test_a_valid_budget_round_trips_through_as_dict(self):
        budget = ExecutionBudget(
            wall_time_ms=30_000, token_limit=4_000, cost_limit_micros=500_000)
        self.assertEqual(budget.as_dict(), {
            "wall_time_ms": 30_000,
            "token_limit": 4_000,
            "cost_limit_micros": 500_000,
        })

    def test_a_zero_dimension_is_refused(self):
        with self.assertRaises(CisError):
            ExecutionBudget(wall_time_ms=0, token_limit=1, cost_limit_micros=1)

    def test_a_negative_dimension_is_refused(self):
        with self.assertRaises(CisError):
            ExecutionBudget(wall_time_ms=1, token_limit=-1, cost_limit_micros=1)

    def test_a_non_integer_dimension_is_refused(self):
        with self.assertRaises(CisError):
            ExecutionBudget(wall_time_ms=1.5, token_limit=1, cost_limit_micros=1)

    def test_a_bool_dimension_is_refused(self):
        with self.assertRaises(CisError):
            ExecutionBudget(wall_time_ms=True, token_limit=1, cost_limit_micros=1)

    def test_the_budget_is_immutable(self):
        budget = ExecutionBudget(
            wall_time_ms=1, token_limit=1, cost_limit_micros=1)
        with self.assertRaises(Exception):
            budget.wall_time_ms = 2

    def test_a_request_with_no_budget_hashes_as_before(self):
        without_budget = _request()
        self.assertIsNone(without_budget.budget)
        self.assertNotIn("budget", without_budget.contract_view())

    def test_a_requests_budget_is_covered_by_the_request_hash(self):
        budget = ExecutionBudget(
            wall_time_ms=1_000, token_limit=1_000, cost_limit_micros=1_000)
        plain = _request()
        with_budget = _request(budget=budget)
        self.assertNotEqual(plain.request_hash, with_budget.request_hash)

    def test_a_token_minted_for_the_unbudgeted_request_does_not_cover_the_budgeted_one(self):
        budget = ExecutionBudget(
            wall_time_ms=1_000, token_limit=1_000, cost_limit_micros=1_000)
        unbound = _request()
        token = _mint_token(binding_hash="bh", request_hash=unbound.request_hash)
        request = _request(token=token, binding_hash="bh", budget=budget)
        with self.assertRaises(ExecutionRefused) as caught:
            DeterministicMockAdapter().execute(request)
        self.assertIn("does not match", caught.exception.message)

    def test_a_token_minted_for_the_exact_budgeted_request_is_accepted(self):
        budget = ExecutionBudget(
            wall_time_ms=1_000, token_limit=1_000, cost_limit_micros=1_000)
        unbound = _request(budget=budget)
        token = _mint_token(binding_hash="bh", request_hash=unbound.request_hash)
        request = _request(token=token, binding_hash="bh", budget=budget)
        result = DeterministicMockAdapter().execute(request)
        self.assertEqual(result.status, "completed")

    def test_an_adapter_declares_no_enforced_budget_dimensions_by_default(self):
        self.assertEqual(ExecutionPort.enforced_budget_dimensions, ())
        self.assertEqual(
            DeterministicMockAdapter().enforced_budget_dimensions, ())


class ExecutionFailureVocabularyTests(unittest.TestCase):
    """Six typed, specific refusals — every one an ``ExecutionRefused``."""

    _CASES = (
        (ExecutionTimedOut, "EXECUTION_TIMED_OUT"),
        (ExecutionBudgetExhausted, "EXECUTION_BUDGET_EXHAUSTED"),
        (ExecutionPermissionWaitRefused, "EXECUTION_PERMISSION_WAIT_REFUSED"),
        (ExecutionProviderFailure, "EXECUTION_PROVIDER_FAILURE"),
        (ExecutionOutputIncomplete, "EXECUTION_OUTPUT_INCOMPLETE"),
        (ExecutionArtifactInvalid, "EXECUTION_ARTIFACT_INVALID"),
    )

    def test_each_failure_type_is_an_execution_refused_with_its_own_code(self):
        for cls, code in self._CASES:
            with self.subTest(cls=cls.__name__):
                self.assertTrue(issubclass(cls, ExecutionRefused))
                self.assertEqual(cls.code, code)

    def test_each_failure_type_is_distinct(self):
        classes = [cls for cls, _ in self._CASES]
        self.assertEqual(len(classes), len(set(classes)))

    def test_each_failure_type_can_be_raised_and_caught_as_execution_refused(self):
        for cls, _ in self._CASES:
            with self.subTest(cls=cls.__name__):
                with self.assertRaises(ExecutionRefused) as caught:
                    raise cls("injected", request_id="req-1")
                self.assertIsInstance(caught.exception, cls)
                self.assertEqual(caught.exception.detail["request_id"], "req-1")


class ExecutionUsageTests(unittest.TestCase):
    """Unit 7B2: the immutable, provider-neutral measured-usage vocabulary."""

    def test_a_valid_usage_round_trips_through_as_dict(self):
        usage = ExecutionUsage(wall_time_ms=100, tokens_used=10, cost_micros=5)
        self.assertEqual(usage.as_dict(), {
            "wall_time_ms": 100, "tokens_used": 10, "cost_micros": 5,
        })

    def test_zero_is_a_legitimate_measured_value(self):
        usage = ExecutionUsage(wall_time_ms=0, tokens_used=0, cost_micros=0)
        self.assertEqual(usage.as_dict()["wall_time_ms"], 0)

    def test_a_negative_dimension_is_refused(self):
        with self.assertRaises(CisError):
            ExecutionUsage(wall_time_ms=-1, tokens_used=0, cost_micros=0)

    def test_a_non_integer_dimension_is_refused(self):
        with self.assertRaises(CisError):
            ExecutionUsage(wall_time_ms=1.5, tokens_used=0, cost_micros=0)

    def test_a_bool_dimension_is_refused(self):
        with self.assertRaises(CisError):
            ExecutionUsage(wall_time_ms=True, tokens_used=0, cost_micros=0)

    def test_usage_is_immutable(self):
        usage = ExecutionUsage(wall_time_ms=1, tokens_used=1, cost_micros=1)
        with self.assertRaises(Exception):
            usage.wall_time_ms = 2

    def test_a_result_with_no_usage_hashes_and_records_as_before(self):
        without_usage = ExecutionResult(
            status="completed", exit_code=0, outputs={},
            checks_performed=(), evidence=())
        self.assertIsNone(without_usage.usage)
        self.assertNotIn("usage", without_usage.as_dict())

    def test_a_results_usage_is_in_as_dict_but_not_the_deterministic_hash(self):
        usage = ExecutionUsage(wall_time_ms=1, tokens_used=1, cost_micros=1)
        plain = ExecutionResult(
            status="completed", exit_code=0, outputs={},
            checks_performed=(), evidence=())
        with_usage = ExecutionResult(
            status="completed", exit_code=0, outputs={},
            checks_performed=(), evidence=(), usage=usage)
        self.assertIn("usage", with_usage.as_dict())
        self.assertEqual(plain.result_hash, with_usage.result_hash)


class _SupervisedAdapter(ExecutionPort):
    """A purpose-built backend that declares exact budget enforcement and
    returns whatever usage a test configures, so dispatch_supervised can be
    exercised independently of any real backend's actual timing."""

    adapter_id = "supervised_test_adapter"
    enforced_budget_dimensions = ("wall_time_ms", "token_limit", "cost_limit_micros")

    def __init__(self, *, usage=None):
        self._usage = usage

    def capabilities(self):
        return ("reconstruct_module",)

    def execute(self, request):
        request.verify_token()
        return ExecutionResult(
            status="completed", exit_code=0, outputs={},
            checks_performed=tuple(request.required_checks),
            evidence=("ran",), usage=self._usage,
        )


class _PartiallyEnforcingAdapter(_SupervisedAdapter):
    """Declares enforcement of only two of the three budget dimensions."""

    adapter_id = "partially_enforcing_test_adapter"
    enforced_budget_dimensions = ("wall_time_ms", "token_limit")


class SupervisedDispatchTests(unittest.TestCase):
    """Unit 7B2: authoritative supervision-route binding at the gateway."""

    def setUp(self):
        self.wb, self.outcome = support.allow_outcome()
        self.authorization_id = self.outcome.authorization["authorization_id"]
        self.baseline_hash = self.wb.blueprint.baseline_hash
        self.active_objective_id = self.wb.continuity.active_objective_id()

    def _gateway(self, adapter, resolver=None):
        registry = AdapterRegistry()
        registry.register(adapter)
        gateway = ExecutionGateway(
            authorizations=self.wb.authorizations, runs=self.wb.runs,
            evidence=self.wb.evidence, trajectory=self.wb.trajectory,
            registry=registry, adapter_id=adapter.adapter_id,
            authorization_check_resolver=self.wb.execution_preflight_checks,
        )
        if resolver is not None:
            gateway = gateway.with_supervision_resolver(resolver)
        return gateway

    def _route(self, **overrides):
        route = {
            "authorization_id": self.authorization_id,
            "adapter_id": "supervised_test_adapter",
            "wall_time_ms": 5_000,
            "token_limit": 2_000,
            "cost_limit_micros": 300_000,
        }
        route.update(overrides)
        return route

    def _dispatch(self, gateway, supervision_id="wsp-test", route_index=0):
        return gateway.dispatch_supervised(
            supervision_id, route_index,
            baseline_hash=self.baseline_hash,
            active_objective_id=self.active_objective_id,
        )

    def test_dispatch_supervised_takes_no_authorization_adapter_or_budget_argument(self):
        import inspect
        signature = inspect.signature(ExecutionGateway.dispatch_supervised)
        self.assertEqual(
            list(signature.parameters),
            ["self", "supervision_id", "route_index", "baseline_hash",
             "active_objective_id"],
        )

    def test_route_derives_authorization_and_adapter_solely_from_the_route(self):
        usage = ExecutionUsage(wall_time_ms=100, tokens_used=10, cost_micros=10)
        adapter = _SupervisedAdapter(usage=usage)
        gateway = self._gateway(adapter, resolver=lambda sid, idx: self._route())
        result = self._dispatch(gateway)
        self.assertEqual(result["status"], COMPLETED)
        run = self.wb.runs.get(result["run_id"])
        self.assertEqual(run["authorization_id"], self.authorization_id)
        self.assertEqual(run["adapter_id"], "supervised_test_adapter")

    def test_a_token_minted_for_the_derived_budget_reaches_the_adapter(self):
        # The adapter calls request.verify_token() itself; success proves the
        # minted token covers exactly the budgeted, route-derived request —
        # the budget arrived inside the token-covered request hash.
        usage = ExecutionUsage(wall_time_ms=1, tokens_used=1, cost_micros=1)
        adapter = _SupervisedAdapter(usage=usage)
        gateway = self._gateway(adapter, resolver=lambda sid, idx: self._route())
        result = self._dispatch(gateway)
        self.assertEqual(result["status"], COMPLETED)
        self.assertEqual(result["usage"], usage.as_dict())

    def test_no_resolver_is_refused(self):
        adapter = _SupervisedAdapter(usage=ExecutionUsage(
            wall_time_ms=0, tokens_used=0, cost_micros=0))
        gateway = self._gateway(adapter)
        with self.assertRaises(ExecutionRefused) as caught:
            self._dispatch(gateway)
        self.assertIn("no supervision-route resolver", caught.exception.message)

    def test_a_malformed_route_is_refused(self):
        adapter = _SupervisedAdapter(usage=ExecutionUsage(
            wall_time_ms=0, tokens_used=0, cost_micros=0))
        bad_route = self._route()
        del bad_route["cost_limit_micros"]
        gateway = self._gateway(adapter, resolver=lambda sid, idx: bad_route)
        with self.assertRaises(ExecutionRefused) as caught:
            self._dispatch(gateway)
        self.assertIn("closed schema", caught.exception.message)

    def test_a_route_naming_a_different_adapter_is_refused(self):
        adapter = _SupervisedAdapter(usage=ExecutionUsage(
            wall_time_ms=0, tokens_used=0, cost_micros=0))
        gateway = self._gateway(adapter, resolver=lambda sid, idx: self._route(
            adapter_id="some_other_adapter"))
        with self.assertRaises(ExecutionRefused) as caught:
            self._dispatch(gateway)
        self.assertIn("different adapter", caught.exception.message)

    def test_an_incomplete_enforcement_declaration_is_refused(self):
        adapter = _PartiallyEnforcingAdapter(usage=ExecutionUsage(
            wall_time_ms=0, tokens_used=0, cost_micros=0))
        gateway = self._gateway(adapter, resolver=lambda sid, idx: self._route(
            adapter_id="partially_enforcing_test_adapter"))
        with self.assertRaises(ExecutionRefused) as caught:
            self._dispatch(gateway)
        self.assertIn("every budget dimension", caught.exception.message)

    def test_missing_usage_is_refused_as_incomplete(self):
        adapter = _SupervisedAdapter(usage=None)
        gateway = self._gateway(adapter, resolver=lambda sid, idx: self._route())
        with self.assertRaises(ExecutionOutputIncomplete):
            self._dispatch(gateway)

    def test_wall_time_overage_is_refused_as_timed_out(self):
        usage = ExecutionUsage(wall_time_ms=6_000, tokens_used=1, cost_micros=1)
        adapter = _SupervisedAdapter(usage=usage)
        gateway = self._gateway(adapter, resolver=lambda sid, idx: self._route())
        with self.assertRaises(ExecutionTimedOut):
            self._dispatch(gateway)

    def test_token_overage_is_refused_as_budget_exhausted(self):
        usage = ExecutionUsage(wall_time_ms=1, tokens_used=3_000, cost_micros=1)
        adapter = _SupervisedAdapter(usage=usage)
        gateway = self._gateway(adapter, resolver=lambda sid, idx: self._route())
        with self.assertRaises(ExecutionBudgetExhausted):
            self._dispatch(gateway)

    def test_cost_overage_is_refused_as_budget_exhausted(self):
        usage = ExecutionUsage(wall_time_ms=1, tokens_used=1, cost_micros=400_000)
        adapter = _SupervisedAdapter(usage=usage)
        gateway = self._gateway(adapter, resolver=lambda sid, idx: self._route())
        with self.assertRaises(ExecutionBudgetExhausted):
            self._dispatch(gateway)

    def test_a_successful_supervised_dispatch_returns_usage_and_spends_the_claim(self):
        usage = ExecutionUsage(wall_time_ms=500, tokens_used=100, cost_micros=1_000)
        adapter = _SupervisedAdapter(usage=usage)
        gateway = self._gateway(adapter, resolver=lambda sid, idx: self._route())
        result = self._dispatch(gateway)
        self.assertEqual(result["usage"], usage.as_dict())
        with self.assertRaises(ExecutionRefused):
            self._dispatch(gateway)


class SupervisionSeamTests(unittest.TestCase):
    """The gateway must reach supervision authority only through a resolver
    bound by its caller, never by importing the supervisor module itself —
    that module may come to call this one, and a mutual import would cycle."""

    def test_gateway_does_not_import_the_worker_supervisor_authority(self):
        text = (SRC / "execution" / "gateway.py").read_text(encoding="utf-8")
        self.assertNotIn("WorkerSupervisorAuthority", text)
        self.assertNotIn("worker_supervisor", text)


if __name__ == "__main__":
    unittest.main()
