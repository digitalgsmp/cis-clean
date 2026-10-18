"""The Layer-2 execution boundary: gating, determinism, replaceability, leaks."""

import re
import unittest
from pathlib import Path

from cis.authority.runs import COMPLETED
from cis.errors import (
    AuthorizationRefused, BindingError, CisError, ExecutionRefused,
    StaleAuthorization,
)
from cis.execution import AdapterRegistry, ExecutionGateway, ExecutionRequest
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


if __name__ == "__main__":
    unittest.main()
