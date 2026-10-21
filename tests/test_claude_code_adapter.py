"""ExecutionPort binding for contained Claude candidate authoring."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cis.card_factory import CARD_HASH_DOMAIN, card_hash
from cis.errors import ExecutionArtifactInvalid, ExecutionRefused
from cis.execution import AdapterRegistry, ExecutionGateway
from cis.execution.adapters.claude_code import ClaudeCodeAdapter
from cis.execution.adapters.claude_process import ClaudeProcessResult
from cis.execution.port import ExecutionBudget, ExecutionRequest, _mint_token

from . import support


BINDING = "b" * 64


def card():
    fields = dict(
        task_contract_id="tc-author", task_contract_hash="t" * 64,
        authorization_id="auth-author",
        authorization_binding_hash=BINDING,
        target_module_id="cis.example", template_id="reconstruct_module.v1",
        template_hash="h" * 64, verbatim_instruction="Implement the unit",
        verbatim_hash="v" * 64, interpretation="Implement one bounded unit.",
        interpretation_label="DERIVATIVE_INTERPRETATION_SOURCE_LINKED",
        interpretation_source="intent_transactions:tx-1:verbatim_instruction",
        objective_id="obj-1", objective_statement="Build CIS",
        allowed_paths=["src/cis/example"],
        forbidden_actions=["network:any", "host:promote"],
        required_checks=["unit_tests"], required_artifacts=["source"],
        stopping_condition="stop after candidate", return_point="assurance",
        source_references=["intent_transactions:tx-1:verbatim_instruction"],
    )
    return {**fields, "hash_domain": CARD_HASH_DOMAIN,
            "card_hash": card_hash(**fields)}


def request(task_card=None):
    task_card = task_card or card()
    budget = ExecutionBudget(
        wall_time_ms=2_000, token_limit=10_000,
        cost_limit_micros=100_000)
    bare = ExecutionRequest(
        request_id="req-author", operation="reconstruct_module",
        allowed_scope=("src/cis/example",),
        forbidden_actions=("host:promote", "network:any"),
        required_checks=("unit_tests",),
        stopping_condition="stop after candidate", return_point="assurance",
        payload={
            "task_card": task_card,
            "frozen_task_contract": {
                "task_contract_id": "tc-author",
                "task_contract_hash": "t" * 64,
                "authorization_id": "auth-author",
            },
        }, budget=budget, binding_hash=BINDING)
    return ExecutionRequest(
        **{**bare.contract_view(), "budget": bare.budget},
        binding_hash=BINDING,
        token=_mint_token(binding_hash=BINDING,
                          request_hash=bare.request_hash))


class FakeController:
    bwrap_bin = __file__
    claude_bin = __file__
    credentials_path = __file__

    execution_identity = "fake:test"

    def __init__(self, change_path="src/cis/example/new.py"):
        self.change_path = change_path
        self.prompts = []

    def liveness(self) -> bool:
        return True

    def execute(self, *, prompt, workspace, wall_time_ms,
                cost_limit_micros):
        self.prompts.append(prompt)
        target = Path(workspace) / self.change_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("VALUE = 1\n", encoding="utf-8")
        return ClaudeProcessResult(
            report={"summary": "implemented"}, exit_code=0,
            wall_time_ms=10, tokens_used=20, cost_micros=30,
            session_id="11111111-1111-4111-8111-111111111111",
            stdout_bytes=10, stderr_bytes=0)


class SymlinkController(FakeController):
    def execute(self, *, prompt, workspace, wall_time_ms,
                cost_limit_micros):
        self.prompts.append(prompt)
        target = Path(workspace) / self.change_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target.unlink()
        target.symlink_to("/etc/passwd")
        return ClaudeProcessResult(
            report={"summary": "implemented"}, exit_code=0,
            wall_time_ms=10, tokens_used=20, cost_micros=30,
            session_id="11111111-1111-4111-8111-111111111111",
            stdout_bytes=10, stderr_bytes=0)


class ClaudeCodeAdapterTests(unittest.TestCase):
    def source(self):
        temp = tempfile.TemporaryDirectory(prefix="cis-claude-source-")
        root = Path(temp.name)
        (root / "src/cis/example").mkdir(parents=True)
        (root / "src/cis/example/original.py").write_text(
            "VALUE = 0\n", encoding="utf-8")
        return temp

    def test_returns_candidate_without_mutating_live_source(self):
        with self.source() as source:
            controller = FakeController()
            result = ClaudeCodeAdapter(
                source_root=source, controller=controller).execute(request())
            self.assertEqual(result.status, "completed")
            self.assertEqual(
                result.outputs["candidate_files"]["src/cis/example/new.py"],
                "VALUE = 1\n")
            self.assertFalse(Path(source, "src/cis/example/new.py").exists())
            self.assertIn("# Task Contract Card: tc-author", controller.prompts[0])

    def test_out_of_scope_change_is_rejected_and_live_source_is_untouched(self):
        with self.source() as source:
            adapter = ClaudeCodeAdapter(
                source_root=source,
                controller=FakeController("README.md"))
            with self.assertRaises(ExecutionArtifactInvalid):
                adapter.execute(request())
            self.assertFalse(Path(source, "README.md").exists())

    def test_tampered_card_is_refused_before_controller(self):
        forged = card()
        forged["verbatim_instruction"] = "widen scope"
        with self.source() as source:
            controller = FakeController()
            with self.assertRaises(ExecutionRefused):
                ClaudeCodeAdapter(
                    source_root=source, controller=controller).execute(
                        request(forged))
            self.assertEqual(controller.prompts, [])

    def test_new_symlink_candidate_is_rejected(self):
        with self.source() as source:
            adapter = ClaudeCodeAdapter(
                source_root=source, controller=SymlinkController())
            with self.assertRaises(ExecutionArtifactInvalid):
                adapter.execute(request())

    def test_replacing_allowed_file_with_symlink_is_rejected(self):
        with self.source() as source:
            adapter = ClaudeCodeAdapter(
                source_root=source,
                controller=SymlinkController(
                    "src/cis/example/original.py"))
            with self.assertRaises(ExecutionArtifactInvalid):
                adapter.execute(request())

    def test_oversized_candidate_is_rejected_before_reading_into_result(self):
        class LargeController(FakeController):
            def execute(inner_self, **kwargs):
                result = super(LargeController, inner_self).execute(**kwargs)
                target = Path(kwargs["workspace"]) / inner_self.change_path
                with target.open("wb") as stream:
                    stream.truncate(5 * 1024 * 1024)
                return result
        with self.source() as source:
            with self.assertRaises(ExecutionArtifactInvalid):
                ClaudeCodeAdapter(
                    source_root=source,
                    controller=LargeController()).execute(request())

    def test_budget_declaration_is_honest_and_supervised_route_will_refuse(self):
        self.assertEqual(
            set(ClaudeCodeAdapter(
                source_root="/does/not/matter",
                controller=FakeController()).enforced_budget_dimensions),
            {"wall_time_ms", "cost_limit_micros"})


class ClaudeGatewayBindingTests(unittest.TestCase):
    def setUp(self):
        self.wb, self.outcome = support.allow_outcome()
        self.authorization_id = self.outcome.authorization["authorization_id"]
        self.contract = support.freeze_task_contract(
            self.wb, self.authorization_id)
        self.source_dir = tempfile.TemporaryDirectory(
            prefix="cis-claude-gateway-")
        root = Path(self.source_dir.name)
        (root / "src/cis/workbench").mkdir(parents=True)
        self.adapter = ClaudeCodeAdapter(
            source_root=self.source_dir.name, controller=FakeController())

    def tearDown(self):
        self.source_dir.cleanup()

    def test_gateway_derives_card_from_contract_without_caller_payload(self):
        row = self.wb.authorizations.get(self.authorization_id)
        built = self.wb.gateway._request_for(
            row, self.adapter, run_nonce="n" * 64,
            budget=ExecutionBudget(1000, 1000, 1000))
        projected = self.wb.card_factory.card(
            self.contract.task_contract_id)
        self.assertEqual(built.payload["task_card"], projected)
        self.assertEqual(
            built.payload["task_card"]["authorization_id"],
            self.authorization_id)

    def test_gateway_without_card_resolver_refuses_before_adapter(self):
        registry = AdapterRegistry()
        registry.register(self.adapter)
        gateway = ExecutionGateway(
            authorizations=self.wb.authorizations, runs=self.wb.runs,
            evidence=self.wb.evidence, trajectory=self.wb.trajectory,
            registry=registry, adapter_id=self.adapter.adapter_id,
            task_contract_resolver=(
                self.wb.authored_source_issuance.task_contract_for_authorization))
        with self.assertRaises(ExecutionRefused):
            gateway._request_for(
                self.wb.authorizations.get(self.authorization_id),
                self.adapter, run_nonce="n" * 64,
                budget=ExecutionBudget(1000, 1000, 1000))

    def test_supervised_gateway_refuses_missing_token_enforcement_prelaunch(self):
        registry = AdapterRegistry()
        registry.register(self.adapter)
        route = {
            "authorization_id": self.authorization_id,
            "adapter_id": self.adapter.adapter_id,
            "wall_time_ms": 1000, "token_limit": 1000,
            "cost_limit_micros": 1000,
        }
        gateway = ExecutionGateway(
            authorizations=self.wb.authorizations, runs=self.wb.runs,
            evidence=self.wb.evidence, trajectory=self.wb.trajectory,
            registry=registry, adapter_id=self.adapter.adapter_id,
            task_contract_resolver=(
                self.wb.authored_source_issuance.task_contract_for_authorization),
            task_card_resolver=self.wb.card_factory.card,
            authorization_check_resolver=self.wb.execution_preflight_checks,
            supervision_route_resolver=lambda _sid, _index: route)
        with self.assertRaises(ExecutionRefused):
            gateway.dispatch_supervised(
                "sup-claude", 0,
                baseline_hash=self.wb.blueprint.baseline_hash,
                active_objective_id=self.wb.continuity.active_objective_id())
        self.assertIsNone(
            self.wb.runs.claim_for_authorization(self.authorization_id))


if __name__ == "__main__":
    unittest.main()
