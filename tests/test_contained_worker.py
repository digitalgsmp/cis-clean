"""Unit boundary proofs for the nonroot contained worker adapter."""

from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path

from cis.errors import CisError, ExecutionRefused
from cis.assurance.task_contract import (
    TASK_CONTRACT_HASH_DOMAIN, task_contract_hash, template,
)
from cis.execution.port import ExecutionRequest, _mint_token
from cis.policy.compiler import compile_envelope
from cis.policy.schema import PolicySelector, PolicySet, parse_policy
from cis.worker.contained_nonroot import ContainedNonrootWorker
from cis.worker.policy_obligations import (
    CHECK_FACTS, CONTAINMENT_CHECKS, EVIDENCE_FACTS,
    PRODUCED_POLICY_EVIDENCE, VERIFIED_FACTS, validate_obligation_mapping,
)

TEST_IMAGE_ID = "sha256:" + "1" * 64


def _policy_envelope(contract, *, required_checks=(), required_evidence=()):
    effects = ["PROHIBIT"]
    if required_checks:
        effects.append("REQUIRE_CHECK")
    if required_evidence:
        effects.append("REQUIRE_EVIDENCE")
    master = parse_policy({
        "policy_id": "MASTER-CONTAINED", "lineage_id": "contained",
        "kind": "MASTER", "version": 1, "status": "ACTIVE",
        "supersedes": None, "conflicts_with": [], "selector": None,
        "effect_kinds": effects,
        "prohibited_actions": ["network:any"],
        "required_checks": list(required_checks),
        "required_evidence": list(required_evidence),
        "narrowed_scope": None, "hold": False,
        "rationale": "contained worker baseline", "evidence_basis": ["TEST"],
    })
    return compile_envelope(
        PolicySet((master,)),
        selector=PolicySelector(project="cis",
                                module="cis.worker.contained_nonroot",
                                operation="reconstruct_module", risk="HIGH"),
        task_contract_id=contract["task_contract_id"],
        task_contract_hash=contract["task_contract_hash"],
    ).as_dict()


def _request(**overrides):
    policy_checks = tuple(overrides.pop("policy_checks", ()))
    policy_evidence = tuple(overrides.pop("policy_evidence", ()))
    template_spec = template("reconstruct_module.v1")
    contract_values = {
        "task_contract_id": "tc-1",
        "authorization_id": "auth-1",
        "authorization_binding_hash": "binding-1",
        "target_module_id": "cis.worker.contained_nonroot",
        "template_id": template_spec.template_id,
        "template_hash": template_spec.template_hash,
        "state": "FROZEN",
        "allowed_paths": ["cis/worker/contained_nonroot.py"],
        "forbidden_actions": ["network:any", "host:promote"],
        "required_checks": ["contract_registry_valid"],
        "required_artifacts": ["execution_evidence"],
        "stopping_condition": "stop after candidate evidence",
        "return_point": "assurance:verification_inputs",
    }
    contract_hash = task_contract_hash(**contract_values)
    contract = {
        **{key: contract_values[key] for key in (
            "task_contract_id", "authorization_id",
            "authorization_binding_hash", "target_module_id", "template_id",
            "template_hash", "state", "stopping_condition", "return_point",
        )},
        "allowed_paths_json": json.dumps(contract_values["allowed_paths"]),
        "forbidden_actions_json": json.dumps(
            contract_values["forbidden_actions"]),
        "required_checks_json": json.dumps(contract_values["required_checks"]),
        "required_artifacts_json": json.dumps(
            contract_values["required_artifacts"]),
        "hash_domain": TASK_CONTRACT_HASH_DOMAIN,
        "task_contract_hash": contract_hash,
    }
    fields = {
        "request_id": "req-auth-1",
        "operation": "reconstruct_module",
        "allowed_scope": ("module:cis.worker.contained_nonroot",),
        "forbidden_actions": ("network:any", "host:promote"),
        "required_checks": tuple(sorted({"contract_registry_valid",
                                         *policy_checks})),
        "stopping_condition": "stop after candidate evidence",
        "return_point": "assurance:verification_inputs",
        "payload": {"target_module_id": "cis.worker.contained_nonroot",
                    "frozen_task_contract": contract,
                    "policy_envelope": _policy_envelope(
                        contract, required_checks=policy_checks,
                        required_evidence=policy_evidence),
                    "run_nonce": "a" * 64},
        "binding_hash": "binding-1",
    }
    fields.update(overrides)
    unbound = ExecutionRequest(**fields)
    return ExecutionRequest(**{**unbound.contract_view(),
                               "binding_hash": unbound.binding_hash,
                               "token": _mint_token(
                                   binding_hash="binding-1",
                                   request_hash=unbound.request_hash)})


class FakeDocker:
    def __init__(self, *, timeout=False, unexpected_evidence=False,
                 inspect_error=False, network_value="lo,",
                 claim_host_teardown=False):
        self.timeout = timeout
        self.unexpected_evidence = unexpected_evidence
        self.inspect_error = inspect_error
        self.network_value = network_value
        self.claim_host_teardown = claim_host_teardown
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        if command[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(command, 0, TEST_IMAGE_ID + "\n", "")
        if command[:3] == ["docker", "rm", "-f"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:2] == ["docker", "inspect"]:
            if self.inspect_error:
                return subprocess.CompletedProcess(
                    command, 1, "", "permission denied opening docker socket")
            return subprocess.CompletedProcess(
                command, 1, "", "Error: No such object: test")
        if command[:2] != ["docker", "run"]:
            raise AssertionError(command)
        if self.timeout:
            raise subprocess.TimeoutExpired(command, timeout=0.01)

        mounts = [command[index + 1] for index, value in enumerate(command)
                  if value == "--mount"]
        contract_dir = Path(mounts[0].split("src=", 1)[1].split(",dst=", 1)[0])
        output_dir = Path(mounts[1].split("src=", 1)[1].split(",dst=", 1)[0])
        task_hash, binding_hash, input_hash, run_nonce = command[-4:]
        bundle_hash = hashlib.sha256(
            (contract_dir / "task-contract.json").read_bytes()).hexdigest()
        candidate = (
            "schema=cis-contained-worker-candidate-v1\n"
            "operation=reconstruct_module\n"
            f"task_contract_hash={task_hash}\n"
            f"authorization_binding_hash={binding_hash}\n"
        ).encode()
        (output_dir / "candidate.txt").write_bytes(candidate)
        candidate_hash = hashlib.sha256(candidate).hexdigest()
        evidence = (
            "schema=cis-contained-worker-evidence-v3\n"
            f"run_nonce={run_nonce}\n"
            "uid=65532\n"
            "gid=65532\n"
            "operation=reconstruct_module\n"
            f"task_contract_bundle_sha256={bundle_hash}\n"
            f"task_contract_hash={task_hash}\n"
            f"authorization_binding_hash={binding_hash}\n"
            f"input_sha256={input_hash}\n"
            f"candidate_sha256={candidate_hash}\n"
            f"nets={self.network_value}\n"
            "cap_eff=0000000000000000\n"
            "no_new_privs=1\n"
            "pids_max=32\n"
            "memory_max=67108864\n"
            "cpu_max=50000 100000\n"
            "rootfs_write=denied\n"
            "contract_write=denied\n"
            "workspace_write=allowed\n"
            "host_action=none\n",
        )
        evidence = "".join(evidence)
        if self.unexpected_evidence:
            evidence += "unverified_claim=true\n"
        if self.claim_host_teardown:
            evidence += "container_teardown_verified=verified\n"
        (output_dir / "worker-evidence.txt").write_text(
            evidence, encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")


class ContainedWorkerTests(unittest.TestCase):
    def test_a_frozen_bound_contract_produces_only_a_candidate(self):
        fake = FakeDocker()
        worker = ContainedNonrootWorker(
            runner=fake, liveness_probe=lambda: TEST_IMAGE_ID)
        result = worker.execute(_request())
        self.assertEqual(result.status, "completed")
        self.assertIsNone(result.outputs["host_action"])
        self.assertIn("candidate_sha256", result.outputs)
        run = fake.commands[0]
        for expected in ("--network", "none", "--read-only", "--cap-drop",
                         "ALL", "no-new-privileges:true", "--pids-limit",
                         "--memory", "--cpus", "--user"):
            self.assertIn(expected, run)
        self.assertIn("teardown_verified", result.checks_performed)
        self.assertNotIn("contract_registry_valid", result.checks_performed)

    def test_supported_policy_evidence_is_derived_from_verified_facts(self):
        request = _request(
            policy_checks=("network_isolated", "teardown_verified"),
            policy_evidence=("contained_network_isolation_verified",
                             "container_teardown_verified"),
        )
        result = ContainedNonrootWorker(
            runner=FakeDocker(), liveness_probe=lambda: TEST_IMAGE_ID,
        ).execute(request)
        self.assertIn("network_isolated", result.checks_performed)
        self.assertIn("teardown_verified", result.checks_performed)
        self.assertIn("contained_network_isolation_verified=verified",
                      result.evidence)
        self.assertIn("container_teardown_verified=verified", result.evidence)

    def test_forged_underlying_attestation_cannot_satisfy_evidence_label(self):
        request = _request(
            policy_checks=("network_isolated",),
            policy_evidence=("contained_network_isolation_verified",),
        )
        with self.assertRaises(ExecutionRefused) as caught:
            ContainedNonrootWorker(
                runner=FakeDocker(network_value="eth0,"),
                liveness_probe=lambda: TEST_IMAGE_ID,
            ).execute(request)
        self.assertIn("evidence did not verify", caught.exception.message)

    def test_container_claim_cannot_substitute_for_host_teardown_fact(self):
        request = _request(
            policy_checks=("teardown_verified",),
            policy_evidence=("container_teardown_verified",),
        )
        with self.assertRaises(ExecutionRefused) as caught:
            ContainedNonrootWorker(
                runner=FakeDocker(claim_host_teardown=True),
                liveness_probe=lambda: TEST_IMAGE_ID,
            ).execute(request)
        self.assertIn("key set", caught.exception.message)

    def test_closed_mapping_covers_every_declared_label(self):
        self.assertEqual(set(CONTAINMENT_CHECKS), set(CHECK_FACTS))
        self.assertEqual(set(PRODUCED_POLICY_EVIDENCE), set(EVIDENCE_FACTS))
        validate_obligation_mapping()

    def test_mapping_to_unknown_fact_is_refused(self):
        with self.assertRaises(CisError):
            validate_obligation_mapping(
                checks={"bad-check": frozenset({"unknown.fact"})},
                evidence=EVIDENCE_FACTS,
                known_facts=VERIFIED_FACTS,
            )

    def test_missing_frozen_contract_is_refused(self):
        request = _request(payload={"target_module_id":
                                    "cis.worker.contained_nonroot"})
        with self.assertRaises(ExecutionRefused):
            ContainedNonrootWorker(runner=FakeDocker(),
                                   liveness_probe=lambda: TEST_IMAGE_ID).execute(request)

    def test_missing_policy_envelope_is_refused_before_docker(self):
        fake = FakeDocker()
        payload = dict(_request().payload)
        payload.pop("policy_envelope")
        with self.assertRaises(ExecutionRefused):
            ContainedNonrootWorker(runner=fake,
                                   liveness_probe=lambda: TEST_IMAGE_ID).execute(
                                       _request(payload=payload))
        self.assertEqual(fake.commands, [])

    def test_mutated_policy_envelope_is_refused_before_docker(self):
        fake = FakeDocker()
        payload = dict(_request().payload)
        payload["policy_envelope"] = dict(payload["policy_envelope"])
        payload["policy_envelope"]["prohibited_actions"] = []
        with self.assertRaises(ExecutionRefused):
            ContainedNonrootWorker(runner=fake,
                                   liveness_probe=lambda: TEST_IMAGE_ID).execute(
                                       _request(payload=payload))
        self.assertEqual(fake.commands, [])

    def test_mismatched_authorization_binding_is_refused_before_docker(self):
        fake = FakeDocker()
        payload = dict(_request().payload)
        payload["frozen_task_contract"] = {
            **payload["frozen_task_contract"],
            "authorization_binding_hash": "other",
        }
        with self.assertRaises(ExecutionRefused):
            ContainedNonrootWorker(runner=fake,
                                   liveness_probe=lambda: TEST_IMAGE_ID).execute(
                                       _request(payload=payload))
        self.assertEqual(fake.commands, [])

    def test_timeout_force_removes_and_verifies_absence(self):
        fake = FakeDocker(timeout=True)
        with self.assertRaises(ExecutionRefused) as caught:
            ContainedNonrootWorker(
                runner=fake, liveness_probe=lambda: TEST_IMAGE_ID,
                timeout_seconds=0.01).execute(_request())
        self.assertIn("wall-time", caught.exception.message)
        self.assertTrue(any(command[:3] == ["docker", "rm", "-f"]
                            for command in fake.commands))
        self.assertTrue(any(command[:2] == ["docker", "inspect"]
                            for command in fake.commands))

    def test_unexpected_attestation_field_is_refused(self):
        with self.assertRaises(ExecutionRefused) as caught:
            ContainedNonrootWorker(
                runner=FakeDocker(unexpected_evidence=True),
                liveness_probe=lambda: TEST_IMAGE_ID).execute(_request())
        self.assertIn("key set", caught.exception.message)

    def test_ambiguous_docker_inspect_error_is_not_absence(self):
        with self.assertRaises(ExecutionRefused) as caught:
            ContainedNonrootWorker(
                runner=FakeDocker(inspect_error=True),
                liveness_probe=lambda: TEST_IMAGE_ID).execute(_request())
        self.assertIn("absence could not be verified", caught.exception.message)

    def test_liveness_probe_cannot_substitute_a_mutable_tag(self):
        for invalid in ("mutable:tag", "sha256:latest", "sha256:" + "g" * 64):
            with self.subTest(invalid=invalid):
                worker = ContainedNonrootWorker(
                    runner=FakeDocker(), liveness_probe=lambda: invalid)
                with self.assertRaises(ExecutionRefused) as caught:
                    worker.execute(_request())
                self.assertIn("not live", caught.exception.message)

    def test_default_liveness_resolves_and_runs_only_the_image_digest(self):
        fake = FakeDocker()
        worker = ContainedNonrootWorker(runner=fake)
        result = worker.execute(_request())
        run = next(command for command in fake.commands
                   if command[:2] == ["docker", "run"])
        self.assertIn(TEST_IMAGE_ID, run)
        self.assertNotIn("cis-contained-worker:proof-v2", run)
        self.assertEqual(result.outputs["image_id"], TEST_IMAGE_ID)


if __name__ == "__main__":
    unittest.main()
