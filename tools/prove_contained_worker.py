#!/usr/bin/env python3
"""Real Docker A-O proof for the contained worker and host handoff."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path

from cis.assurance.authority import AssuranceAuthority
from cis.assurance.promotion import PromotionRecorder
from cis.assurance.reviewer import Reviewer
from cis.assurance.task_contract import (
    TASK_CONTRACT_HASH_DOMAIN, TaskContractCompiler, task_contract_hash,
    template,
)
from cis.assurance.verifier import Verifier
from cis.authority import (
    AuthorityStore, EvidenceAuthority, RunAuthority, TrajectoryAuthority,
)
from cis.execution import AdapterRegistry, ExecutionGateway
from cis.execution.port import ExecutionRequest, _mint_token
from cis.errors import ExecutionRefused
from cis.host import HostPromotionGate
from cis.policy.compiler import compile_envelope
from cis.policy.resolver import AutomaticPolicyResolver
from cis.policy.schema import PolicySelector, PolicySet, parse_policy
from cis.worker.contained_nonroot import IMAGE, ContainedNonrootWorker
from cis.workbench import Workbench

INSTRUCTION = "Reconstruct cis.worker.contained_nonroot in the clean environment"
OBJECTIVE = "Complete the nonroot contained-worker A-O boundary proof"


def checked(command, **kwargs):
    return subprocess.run(command, text=True, capture_output=True,
                          check=True, **kwargs)


def one_end_to_end() -> tuple[AuthorityStore, dict, str, dict, dict, dict]:
    store = AuthorityStore(":memory:")
    wb = Workbench(store)
    wb.set_initial_objective(OBJECTIVE, established_by="contained-worker-proof")
    outcome = wb.submit_instruction(INSTRUCTION)
    if outcome.authorization["verdict"] != "ALLOW":
        raise RuntimeError(outcome.authorization)
    authorization_id = outcome.authorization["authorization_id"]
    compiled = TaskContractCompiler(
        authorizations=wb.authorizations, blueprint=wb.blueprint).compile(
            authorization_id=authorization_id,
            template_id="reconstruct_module.v1",
            active_objective_id=wb.continuity.active_objective_id(),
        )
    assurance = AssuranceAuthority(store)
    assurance.task_contracts.freeze(compiled)

    def resolve(candidate_authorization_id):
        row = assurance.ledger.task_contract_for_authorization(
            candidate_authorization_id)
        if row is None:
            return None
        return assurance.verify_task_contract(
            str(row["task_contract_id"])).as_dict()

    registry = AdapterRegistry()
    registry.register(ContainedNonrootWorker())
    policy_resolver = AutomaticPolicyResolver(store)
    wb.gateway = ExecutionGateway(
        authorizations=wb.authorizations,
        runs=RunAuthority(store), evidence=EvidenceAuthority(store),
        trajectory=TrajectoryAuthority(store), registry=registry,
        adapter_id="contained_nonroot", task_contract_resolver=resolve,
        authorization_check_resolver=wb.execution_preflight_checks,
        policy_envelope_resolver=policy_resolver.resolve,
    )
    run = wb.execute(authorization_id)
    verification = Verifier(store, wb.blueprint).verify(
        compiled.task_contract_id)
    review, cycle = Reviewer(store, wb.blueprint).review(
        compiled.task_contract_id)
    decision = PromotionRecorder(store).decide(compiled.task_contract_id)
    if (verification["outcome"] != "VERIFIED_PASS"
            or review["outcome"] != "PASS" or cycle is not None
            or decision["decision"] != "PROMOTION_AUTHORIZED"):
        raise RuntimeError("assurance conjunction did not pass")
    return (store, run, compiled.task_contract_id,
            verification.as_dict(), review.as_dict(), decision.as_dict())


def kernel_boundary_from_adapter_evidence(store, run: dict) -> dict:
    row = EvidenceAuthority(store).get(run["evidence_id"])
    if row is None:
        raise RuntimeError("adapter evidence row is absent")
    facts = dict(line.split("=", 1) for line in
                 str(row["original_language"]).splitlines())
    required = {
        "uid": "65532", "gid": "65532", "nets": "lo,",
        "cap_eff": "0000000000000000", "no_new_privs": "1",
        "pids_max": "32", "memory_max": "67108864",
        "cpu_max": "50000 100000",
        "rootfs_write": "denied", "contract_write": "denied",
        "workspace_write": "allowed",
    }
    mismatch = {key: {"expected": value, "observed": facts.get(key)}
                for key, value in required.items() if facts.get(key) != value}
    if mismatch:
        raise RuntimeError({"kernel_boundary_mismatch": mismatch, "facts": facts})
    return facts


def timeout_cleanup_probe() -> dict:
    class StartedTimeoutRunner:
        def __init__(self):
            self.started = False
            self.process = None

        def __call__(self, command, **kwargs):
            if command[:2] != ["docker", "run"]:
                return subprocess.run(command, **kwargs)
            process = subprocess.Popen(command, text=True,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
            self.process = process
            name = command[command.index("--name") + 1]
            for _ in range(100):
                if subprocess.run(
                    ["docker", "inspect", name], capture_output=True,
                    text=True, check=False).returncode == 0:
                    self.started = True
                    break
                if process.poll() is not None:
                    break
                time.sleep(0.01)
            if not self.started:
                process.kill()
                raise RuntimeError("timeout probe container never started")
            raise subprocess.TimeoutExpired(command, timeout=0.01)

    template_spec = template("reconstruct_module.v1")
    contract_values = {
        "task_contract_id": "tc-timeout",
        "authorization_id": "auth-timeout",
        "authorization_binding_hash": "binding-timeout",
        "target_module_id": "cis.worker.contained_nonroot",
        "template_id": template_spec.template_id,
        "template_hash": template_spec.template_hash,
        "state": "FROZEN",
        "allowed_paths": ["cis/worker/contained_nonroot.py"],
        "forbidden_actions": ["network:any"],
        "required_checks": [],
        "required_artifacts": [],
        "stopping_condition": "timeout probe",
        "return_point": "proof",
    }
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
        "task_contract_hash": task_contract_hash(**contract_values),
    }
    master = parse_policy({
        "policy_id": "MASTER-TIMEOUT-PROBE", "lineage_id": "timeout-probe",
        "kind": "MASTER", "version": 1, "status": "ACTIVE",
        "supersedes": None, "conflicts_with": [], "selector": None,
        "effect_kinds": ["PROHIBIT"],
        "prohibited_actions": ["network:any"],
        "required_checks": [], "required_evidence": [],
        "narrowed_scope": None, "hold": False,
        "rationale": "timeout probe baseline", "evidence_basis": ["TEST"],
    })
    policy_envelope = compile_envelope(
        PolicySet((master,)),
        selector=PolicySelector(project="cis",
                                module="cis.worker.contained_nonroot",
                                operation="reconstruct_module", risk="HIGH"),
        task_contract_id=contract["task_contract_id"],
        task_contract_hash=contract["task_contract_hash"],
    ).as_dict()
    fields = {
        "request_id": "req-auth-timeout", "operation": "reconstruct_module",
        "allowed_scope": ("module:cis.worker.contained_nonroot",),
        "forbidden_actions": ("network:any",), "required_checks": (),
        "stopping_condition": "timeout probe", "return_point": "proof",
        "payload": {"target_module_id": "cis.worker.contained_nonroot",
                    "frozen_task_contract": contract,
                    "policy_envelope": policy_envelope,
                    "run_nonce": "f" * 64},
        "binding_hash": "binding-timeout",
    }
    unbound = ExecutionRequest(**fields)
    request = ExecutionRequest(
        **unbound.contract_view(), binding_hash="binding-timeout",
        token=_mint_token(binding_hash="binding-timeout",
                          request_hash=unbound.request_hash))
    runner = StartedTimeoutRunner()
    worker = ContainedNonrootWorker(runner=runner, timeout_seconds=0.01)
    try:
        worker.execute(request)
    except ExecutionRefused as exc:
        if "wall-time" not in exc.message:
            raise
    else:
        raise RuntimeError("timeout probe did not time out")
    if not runner.started:
        raise RuntimeError("timeout was injected before container start")
    if runner.process is not None:
        runner.process.wait(timeout=5)
    return {"timeout_injected": True, "container_started": True,
            "container_absent": True}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output",
                        default="runtime/worker-proof/final-proof.json")
    args = parser.parse_args()

    image = json.loads(checked([
        "docker", "image", "inspect", IMAGE,
        "--format", "{{json .}}",
    ]).stdout)
    first = one_end_to_end()
    second = one_end_to_end()
    first_store, first_run, task_contract_id, verification, review, decision = first
    _, second_run, _, second_verification, second_review, second_decision = second
    if first_run["result_hash"] != second_run["result_hash"]:
        raise RuntimeError("fresh-container result hashes differ")

    kernel = kernel_boundary_from_adapter_evidence(first_store, first_run)
    timeout = timeout_cleanup_probe()

    with tempfile.TemporaryDirectory(prefix="cis-promotion-proof-") as root:
        target = Path(root) / "cis/worker/contained_nonroot.candidate"
        target.parent.mkdir(parents=True)
        prior = b"prior-authority-state\n"
        target.write_bytes(prior)
        gate = HostPromotionGate(first_store, target_root=root)
        applied = gate.apply(
            task_contract_id=task_contract_id,
            candidate_content=first_run["outputs"]["candidate_content"],
        )
        # A fresh gate instance receives no candidate or prior bytes. It gets
        # both the rollback target and exact prior content from authority.
        rolled_back = HostPromotionGate(
            first_store, target_root=root).rollback(applied["application_id"])
        restored = target.read_bytes() == prior
        if not restored or rolled_back["state"] != "ROLLED_BACK":
            raise RuntimeError("authority-only rollback did not restore prior bytes")

    residue = checked([
        "docker", "ps", "-a", "--filter", "name=cis-worker-",
        "--format", "{{.Names}}",
    ]).stdout.splitlines()
    if residue:
        raise RuntimeError({"container_residue": residue})

    report = {
        "proof": "CONTAINED_WORKER_A_TO_O",
        "status": "PASS",
        "image": {
            "tag": IMAGE,
            "id": image["Id"],
            "configured_user": image["Config"]["User"],
        },
        "first_fresh_run": {
            "result_hash": first_run["result_hash"],
            "candidate_sha256": first_run["outputs"]["candidate_sha256"],
            "verification": verification["outcome"],
            "review": review["outcome"],
            "promotion_decision": decision["decision"],
        },
        "second_fresh_run": {
            "result_hash": second_run["result_hash"],
            "verification": second_verification["outcome"],
            "review": second_review["outcome"],
            "promotion_decision": second_decision["decision"],
        },
        "fresh_runs_identical": True,
        "kernel_boundary": kernel,
        "timeout_cleanup": timeout,
        "host_apply": {"state": applied["state"],
                       "decision_id": applied["promotion_decision_id"]},
        "authority_only_rollback": {"state": rolled_back["state"],
                                    "prior_bytes_restored": restored},
        "container_residue": [],
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
