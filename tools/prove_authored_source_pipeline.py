#!/usr/bin/env python3
"""Run the production authored-source path through the real sealed worker."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cis.assurance.promotion import PromotionRecorder
from cis.assurance.reviewer import Reviewer
from cis.assurance.verifier import Verifier
from cis.authority import AuthorityStore
from cis.conductor import Conductor
from cis.workbench import Workbench


INSTRUCTION = "Verify authored source for cis.workbench.projection"
OBJECTIVE = "Prove the production authored-source contained pipeline"
SOURCE = "def run(value):\n    return value\n"
VECTORS = [{"args": [1], "expect_value": 1},
           {"args": [42], "expect_value": 42}]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    authority_path = Path(args.authority)
    output_path = Path(args.output)
    if authority_path.exists() or output_path.exists():
        raise SystemExit("refusing to replace an existing proof artifact")
    authority_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with AuthorityStore(authority_path) as store:
        wb = Workbench(store)
        wb.gateway = wb.gateway.using("contained_worker")
        wb.authored_source_issuance.bind_gateway(wb.gateway)
        wb.set_initial_objective(OBJECTIVE, established_by="pipeline-proof")
        conductor = Conductor(wb)
        outcome = conductor.ingest_instruction(INSTRUCTION)
        if outcome.authorization["verdict"] != "ALLOW":
            raise RuntimeError(outcome.authorization)
        authorization_id = str(outcome.authorization["authorization_id"])
        issued = wb.prepare_authored_source_verification(
            authorization_id, candidate_source=SOURCE,
            vectors=VECTORS, entrypoint="run")
        run = conductor.execute_authorization(authorization_id)
        verification = Verifier(store, wb.blueprint).verify(
            issued["task_contract_id"])
        review, cycle = Reviewer(store, wb.blueprint).review(
            issued["task_contract_id"])
        decision = PromotionRecorder(store).decide(
            issued["task_contract_id"])
        if (run["status"] != "completed"
                or verification["outcome"] != "VERIFIED_PASS"
                or review["outcome"] != "PASS" or cycle is not None
                or decision["decision"] != "PROMOTION_AUTHORIZED"
                or decision["host_action"] != "NONE_RECORD_ONLY"):
            raise RuntimeError("production assurance conjunction did not pass")
        proof = {
            "schema": "cis-authored-source-production-proof-v1",
            "authorization_id": authorization_id,
            "task_contract_id": issued["task_contract_id"],
            "task_contract_hash": issued["task_contract_hash"],
            "execution_input_hash": issued["execution_input_hash"],
            "adapter_id": issued["adapter_id"],
            "worker_image": issued["worker_image"],
            "run_id": run["run_id"], "result_hash": run["result_hash"],
            "verification_result_id": verification["result_id"],
            "verification_outcome": verification["outcome"],
            "review_id": review["review_id"],
            "review_outcome": review["outcome"],
            "promotion_decision_id": decision["decision_id"],
            "promotion_decision": decision["decision"],
            "host_action": decision["host_action"],
        }
        output_path.write_text(
            json.dumps(proof, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        print(json.dumps(proof, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
