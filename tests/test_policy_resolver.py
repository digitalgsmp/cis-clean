"""Automatic source admission and governed-task compilation proofs."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cis.errors import (
    ExecutionRefused, PolicyBaselineMissing, PolicyConflict, PolicyHold,
    PolicyProfileUnknown, PolicySourceConflict, PolicyStale,
)
from cis.execution import AdapterRegistry, ExecutionGateway
from cis.execution.port import ExecutionPort, ExecutionResult
from cis.policy.authority import PolicyAuthority
from cis.policy.profiles import derive_selector
from cis.policy.resolver import AutomaticPolicyResolver
from cis.policy.source_catalog import DEFAULT_SOURCE_CATALOG, load_source_catalog
from cis.policy.sources import PolicySourceAuthority
from cis.worker.contained_nonroot import ContainedNonrootWorker

from . import support


def master(policy_id="MASTER-TEST", **changes):
    raw = {
        "policy_id": policy_id, "lineage_id": policy_id, "kind": "MASTER",
        "version": 1, "status": "ACTIVE", "supersedes": None,
        "conflicts_with": [], "selector": None, "effect_kinds": ["PROHIBIT"],
        "prohibited_actions": ["network:any"], "required_checks": [],
        "required_evidence": [], "narrowed_scope": None, "hold": False,
        "rationale": "resolver test", "evidence_basis": ["TEST"],
    }
    raw.update(changes)
    return raw


def task(policy_id="TASK-TEST", **changes):
    raw = {
        "policy_id": policy_id, "lineage_id": policy_id, "kind": "TASK",
        "version": 1, "status": "ACTIVE", "supersedes": None,
        "conflicts_with": [],
        "selector": {"project": "cis", "module": "cis.workbench.projection",
                     "operation": "reconstruct_module", "risk": "HIGH"},
        "effect_kinds": ["REQUIRE_CHECK"], "prohibited_actions": [],
        "required_checks": ["policy_envelope_bound"],
        "required_evidence": [], "narrowed_scope": None, "hold": False,
        "rationale": "resolver task test", "evidence_basis": ["TEST"],
    }
    raw.update(changes)
    return raw


def catalog(*policies):
    directory = Path(tempfile.mkdtemp(prefix="cis-policy-catalog-"))
    path = directory / "sources.json"
    path.write_text(json.dumps({
        "schema_version": "1.0.0", "catalog_id": "TEST-CATALOG",
        "provenance": "test catalog", "policies": list(policies),
    }), encoding="utf-8")
    return path


class RecordingGovernedAdapter(ExecutionPort):
    adapter_id = "governed-test"
    requires_frozen_task_contract = True
    requires_policy_envelope = True
    enforced_policy_prohibitions = ("network:any",)
    enforced_policy_checks = ("policy_envelope_bound",)
    produced_policy_evidence = ()

    def __init__(self):
        self.requests = []

    def capabilities(self):
        return ("reconstruct_module",)

    def execute(self, request):
        request.verify_token()
        self.requests.append(request)
        return ExecutionResult("completed", 0, {},
                               ("policy_envelope_bound",), ("ran=true",))


class AutomaticPolicyResolverTests(unittest.TestCase):
    def setUp(self):
        self.wb, outcome = support.allow_outcome()
        self.authorization_id = outcome.authorization["authorization_id"]
        self.contract = support.freeze_task_contract(self.wb, self.authorization_id)

    def test_first_resolution_ingests_and_compiles_automatically(self):
        resolved = AutomaticPolicyResolver(self.wb.store).resolve(
            self.authorization_id)
        self.assertEqual(resolved["task_contract_id"],
                         self.contract.task_contract_id)
        self.assertEqual(len(self.wb.store.query("SELECT * FROM policy_sources")), 2)
        self.assertIsNotNone(PolicyAuthority(self.wb.store).row_for_task_contract(
            self.contract.task_contract_id))

    def test_repeat_resolution_is_idempotent(self):
        resolver = AutomaticPolicyResolver(self.wb.store)
        first = resolver.resolve(self.authorization_id)
        second = resolver.resolve(self.authorization_id)
        self.assertEqual(first, second)
        self.assertEqual(len(self.wb.store.query("SELECT * FROM policy_sources")), 2)
        self.assertEqual(len(self.wb.store.query("SELECT * FROM policy_envelopes")), 1)

    def test_new_applicable_policy_makes_existing_task_stale(self):
        resolver = AutomaticPolicyResolver(self.wb.store)
        resolver.resolve(self.authorization_id)
        PolicySourceAuthority(self.wb.store).ingest(
            task(), provenance="test:new-task-policy")
        with self.assertRaises(PolicyStale):
            resolver.resolve(self.authorization_id)

    def test_missing_catalog_refuses(self):
        resolver = AutomaticPolicyResolver(
            self.wb.store, source_catalog_path="/no/such/policy-catalog.json")
        with self.assertRaises(PolicySourceConflict):
            resolver.resolve(self.authorization_id)

    def test_unknown_catalog_schema_version_refuses(self):
        path = catalog(master())
        document = json.loads(path.read_text(encoding="utf-8"))
        document["schema_version"] = "2.0.0"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(PolicySourceConflict):
            load_source_catalog(path)

    def test_catalog_without_master_refuses(self):
        with self.assertRaises(PolicyBaselineMissing):
            AutomaticPolicyResolver(
                self.wb.store, source_catalog_path=catalog(task())
            ).resolve(self.authorization_id)

    def test_applicable_conflict_refuses(self):
        a = master("MASTER-A", lineage_id="a", conflicts_with=["b"])
        b = master("MASTER-B", lineage_id="b", conflicts_with=["a"])
        with self.assertRaises(PolicyConflict):
            AutomaticPolicyResolver(
                self.wb.store, source_catalog_path=catalog(a, b)
            ).resolve(self.authorization_id)

    def test_hold_refuses(self):
        holding = master(effect_kinds=["HOLD"], prohibited_actions=[], hold=True)
        with self.assertRaises(PolicyHold):
            AutomaticPolicyResolver(
                self.wb.store, source_catalog_path=catalog(holding)
            ).resolve(self.authorization_id)

    def test_unknown_profile_refuses_instead_of_guessing(self):
        with self.assertRaises(PolicyProfileUnknown):
            derive_selector(template_id="unknown.v1", operation="unknown",
                            target_module_id="cis.workbench.projection")

    def test_missing_master_refuses_before_backend_and_claim(self):
        adapter = RecordingGovernedAdapter()
        registry = AdapterRegistry()
        registry.register(adapter)
        resolver = AutomaticPolicyResolver(
            self.wb.store, source_catalog_path=catalog(task()))
        ledger = support.assurance_authority(self.wb).ledger
        gateway = ExecutionGateway(
            authorizations=self.wb.authorizations, runs=self.wb.runs,
            evidence=self.wb.evidence, trajectory=self.wb.trajectory,
            registry=registry, adapter_id=adapter.adapter_id,
            task_contract_resolver=ledger.task_contract_for_authorization,
            policy_envelope_resolver=resolver.resolve,
            authorization_check_resolver=self.wb.execution_preflight_checks,
        )
        with self.assertRaises(ExecutionRefused):
            gateway.dispatch(
                self.authorization_id,
                baseline_hash=self.wb.blueprint.baseline_hash,
                active_objective_id=self.wb.continuity.active_objective_id())
        self.assertEqual(adapter.requests, [])
        self.assertIsNone(self.wb.runs.claim_for_authorization(
            self.authorization_id))

    def test_default_operational_catalog_v2_supersedes_v1_within_worker_bounds(self):
        document = load_source_catalog(DEFAULT_SOURCE_CATALOG)
        policies = document["policies"]
        self.assertEqual(len(policies), 2)
        by_version = {p["version"]: p for p in policies}
        self.assertEqual(set(by_version), {1, 2})
        v1, v2 = by_version[1], by_version[2]

        self.assertEqual(v1["lineage_id"], v2["lineage_id"])
        self.assertGreater(v2["version"], v1["version"])
        self.assertEqual(v2["supersedes"], v1["policy_id"])

        self.assertTrue(
            set(v1["prohibited_actions"]).issubset(set(v2["prohibited_actions"])))

        self.assertTrue(set(v2["required_checks"]).issubset(
            set(ContainedNonrootWorker.enforced_policy_checks)))
        self.assertTrue(set(v2["required_evidence"]).issubset(
            set(ContainedNonrootWorker.produced_policy_evidence)))


if __name__ == "__main__":
    unittest.main()
