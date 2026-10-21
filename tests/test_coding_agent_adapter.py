"""Generic CodingAgentAdapter behaviour: different adapter_id, different controller."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cis.card_factory import CARD_HASH_DOMAIN, card_hash
from cis.execution.adapters.claude_code import CodingAgentAdapter
from cis.execution.adapters.claude_process import ClaudeProcessResult
from cis.execution.port import ExecutionBudget, ExecutionRequest, _mint_token


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


class CustomController:
    """A coding-agent controller with a different identity than Claude."""

    @property
    def execution_identity(self) -> str:
        return "test-coder:mock"

    def liveness(self) -> bool:
        return True

    def execute(self, *, prompt, workspace, wall_time_ms, cost_limit_micros):
        target = Path(workspace) / "src/cis/example/new.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("CUSTOM = 42\n", encoding="utf-8")
        return ClaudeProcessResult(
            report={"summary": "custom-implemented"}, exit_code=0,
            wall_time_ms=10, tokens_used=20, cost_micros=30,
            session_id="22222222-2222-4222-8222-222222222222",
            stdout_bytes=10, stderr_bytes=0)


class CodingAgentAdapterTests(unittest.TestCase):

    def source(self):
        temp = tempfile.TemporaryDirectory(prefix="cis-gen-source-")
        root = Path(temp.name)
        (root / "src/cis/example").mkdir(parents=True)
        (root / "src/cis/example/original.py").write_text(
            "VALUE = 0\n", encoding="utf-8")
        return temp

    def test_generic_adapter_returns_candidate_without_mutating_source(self):
        """A CodingAgentAdapter with a non-Claude id/controller returns a
        scope-checked candidate and leaves the live source untouched."""
        with self.source() as source:
            controller = CustomController()
            adapter = CodingAgentAdapter(
                adapter_id="test_coder",
                source_root=source,
                controller=controller)

            self.assertEqual(adapter.adapter_id, "test_coder")
            self.assertEqual(adapter.capabilities(), ("reconstruct_module",))
            self.assertTrue(adapter.liveness())

            result = adapter.execute(request())

            self.assertEqual(result.status, "completed")
            self.assertEqual(
                result.outputs["candidate_files"]["src/cis/example/new.py"],
                "CUSTOM = 42\n")
            self.assertFalse(
                Path(source, "src/cis/example/new.py").exists(),
                "live source tree must be untouched")
            self.assertEqual(
                result.outputs["worker_report"]["summary"],
                "custom-implemented")
            self.assertEqual(
                result.evidence[-1],
                "live_repository_mutation=none_disposable_workspace")


if __name__ == "__main__":
    unittest.main()