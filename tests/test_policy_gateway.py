"""Gateway refusal proofs for mandatory policy-envelope binding."""

import unittest

from cis.errors import ExecutionRefused, PolicyStale
from cis.execution import AdapterRegistry, ExecutionGateway
from cis.execution.port import ExecutionPort, ExecutionResult
from cis.policy.authority import PolicyAuthority
from cis.policy.compiler import compile_envelope
from cis.policy.schema import PolicySelector, PolicySet, parse_policy

from . import support


class RecordingPolicyAdapter(ExecutionPort):
    adapter_id = "recording_policy_adapter"
    requires_frozen_task_contract = True
    requires_policy_envelope = True
    policy_enforcement_point = "cis.worker.contained_nonroot"
    enforced_policy_prohibitions = ("network:any",)
    enforced_policy_checks = ("policy_envelope_bound",)
    produced_policy_evidence = ("mapped-proof",)

    def __init__(self):
        self.requests = []

    def capabilities(self):
        return ("reconstruct_module",)

    def execute(self, request):
        request.verify_token()
        self.requests.append(request)
        return ExecutionResult(status="completed", exit_code=0,
                               outputs={"operation": request.operation},
                               checks_performed=("policy_envelope_bound",),
                               evidence=("mapped-proof=claimed",))


class PolicyGatewayTests(unittest.TestCase):
    def setUp(self):
        self.wb, outcome = support.allow_outcome()
        self.authorization_id = outcome.authorization["authorization_id"]
        self.contract = support.freeze_task_contract(
            self.wb, self.authorization_id)
        self.envelope = support.seed_policy_envelope(
            self.wb, self.contract.task_contract_id)
        self.adapter = RecordingPolicyAdapter()
        self.registry = AdapterRegistry()
        self.registry.register(self.adapter)

    def gateway(self, policy_resolver):
        ledger = support.assurance_authority(self.wb).ledger
        return ExecutionGateway(
            authorizations=self.wb.authorizations, runs=self.wb.runs,
            evidence=self.wb.evidence, trajectory=self.wb.trajectory,
            registry=self.registry, adapter_id=self.adapter.adapter_id,
            task_contract_resolver=ledger.task_contract_for_authorization,
            policy_envelope_resolver=policy_resolver,
            authorization_check_resolver=self.wb.execution_preflight_checks,
        )

    def verified_policy(self, _authorization_id):
        return PolicyAuthority(self.wb.store).resolve(
            self.contract.task_contract_id,
            expected_task_contract_hash=self.contract.task_contract_hash,
            expected_policy_set_hash=self.envelope.policy_set_hash,
        )

    def dispatch(self, gateway):
        return gateway.dispatch(
            self.authorization_id,
            baseline_hash=self.wb.blueprint.baseline_hash,
            active_objective_id=self.wb.continuity.active_objective_id(),
        )

    def test_verified_envelope_is_token_bound_into_request(self):
        self.dispatch(self.gateway(self.verified_policy))
        request = self.adapter.requests[0]
        self.assertEqual(request.payload["policy_envelope"]["envelope_hash"],
                         self.envelope.envelope_hash)
        self.assertIn("network:any", request.forbidden_actions)

    def test_missing_resolver_refuses_before_backend_and_claim(self):
        with self.assertRaises(ExecutionRefused):
            self.dispatch(self.gateway(None))
        self.assertEqual(self.adapter.requests, [])
        self.assertIsNone(self.wb.runs.claim_for_authorization(
            self.authorization_id))

    def test_forged_envelope_refuses_before_backend(self):
        forged = self.envelope.as_dict()
        forged["prohibited_actions"] = []
        with self.assertRaises(ExecutionRefused):
            self.dispatch(self.gateway(lambda _authorization_id: forged))
        self.assertEqual(self.adapter.requests, [])

    def test_stale_resolver_refuses_before_backend(self):
        def stale(_authorization_id):
            raise PolicyStale("injected stale policy")
        with self.assertRaises(ExecutionRefused):
            self.dispatch(self.gateway(stale))
        self.assertEqual(self.adapter.requests, [])

    def test_unsupported_policy_obligation_refuses_before_backend(self):
        task = parse_policy({
            "policy_id": "TASK-UNSUPPORTED", "lineage_id": "unsupported",
            "kind": "TASK", "version": 1, "status": "ACTIVE",
            "supersedes": None, "conflicts_with": [],
            "selector": {"project": "cis",
                         "module": "cis.workbench.projection",
                         "operation": "reconstruct_module", "risk": "HIGH"},
            "effect_kinds": ["REQUIRE_CHECK"], "prohibited_actions": [],
            "required_checks": ["not-implemented"], "required_evidence": [],
            "narrowed_scope": None, "hold": False,
            "rationale": "negative gateway proof", "evidence_basis": ["TEST"],
        })
        master = parse_policy(self.envelope.selected_policies[0])
        unsupported = compile_envelope(
            PolicySet((master, task)),
            selector=PolicySelector(project="cis",
                                    module="cis.workbench.projection",
                                    operation="reconstruct_module", risk="HIGH"),
            task_contract_id=self.contract.task_contract_id,
            task_contract_hash=self.contract.task_contract_hash,
        ).as_dict()
        with self.assertRaises(ExecutionRefused) as caught:
            self.dispatch(self.gateway(lambda _authorization_id: unsupported))
        self.assertIn("cannot deterministically satisfy",
                      caught.exception.message)
        self.assertEqual(self.adapter.requests, [])

    def test_unsupported_policy_evidence_refuses_before_backend(self):
        task = parse_policy({
            "policy_id": "TASK-UNSUPPORTED-EVIDENCE",
            "lineage_id": "unsupported-evidence", "kind": "TASK",
            "version": 1, "status": "ACTIVE", "supersedes": None,
            "conflicts_with": [],
            "selector": {"project": "cis",
                         "module": "cis.workbench.projection",
                         "operation": "reconstruct_module", "risk": "HIGH"},
            "effect_kinds": ["REQUIRE_EVIDENCE"], "prohibited_actions": [],
            "required_checks": [],
            "required_evidence": ["not-implemented"],
            "narrowed_scope": None, "hold": False,
            "rationale": "negative evidence proof", "evidence_basis": ["TEST"],
        })
        master = parse_policy(self.envelope.selected_policies[0])
        unsupported = compile_envelope(
            PolicySet((master, task)),
            selector=PolicySelector(project="cis",
                                    module="cis.workbench.projection",
                                    operation="reconstruct_module", risk="HIGH"),
            task_contract_id=self.contract.task_contract_id,
            task_contract_hash=self.contract.task_contract_hash,
        ).as_dict()
        with self.assertRaises(ExecutionRefused) as caught:
            self.dispatch(self.gateway(lambda _authorization_id: unsupported))
        self.assertIn("cannot deterministically satisfy",
                      caught.exception.message)
        self.assertEqual(self.adapter.requests, [])

    def test_non_verified_evidence_value_does_not_satisfy_policy(self):
        task = parse_policy({
            "policy_id": "TASK-MAPPED-EVIDENCE", "lineage_id": "mapped",
            "kind": "TASK", "version": 1, "status": "ACTIVE",
            "supersedes": None, "conflicts_with": [],
            "selector": {"project": "cis",
                         "module": "cis.workbench.projection",
                         "operation": "reconstruct_module", "risk": "HIGH"},
            "effect_kinds": ["REQUIRE_EVIDENCE"], "prohibited_actions": [],
            "required_checks": [], "required_evidence": ["mapped-proof"],
            "narrowed_scope": None, "hold": False,
            "rationale": "claimed is not verified", "evidence_basis": ["TEST"],
        })
        master = parse_policy(self.envelope.selected_policies[0])
        envelope = compile_envelope(
            PolicySet((master, task)),
            selector=PolicySelector(project="cis",
                                    module="cis.workbench.projection",
                                    operation="reconstruct_module", risk="HIGH"),
            task_contract_id=self.contract.task_contract_id,
            task_contract_hash=self.contract.task_contract_hash,
        ).as_dict()
        with self.assertRaises(ExecutionRefused) as caught:
            self.dispatch(self.gateway(lambda _authorization_id: envelope))
        self.assertIn("did not prove", caught.exception.message)
        self.assertEqual(len(self.adapter.requests), 1)


if __name__ == "__main__":
    unittest.main()
