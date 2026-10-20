#!/usr/bin/env python3
"""Prove bounded replacement recovery through the real sealed worker."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cis.assurance.authority import RECOVERY_REPLACEMENT_CANDIDATE
from cis.assurance.promotion import PromotionRecorder
from cis.assurance.recovery import (
    REPLACEMENT_REQUIRED,
    OperationalSelfAssessment,
)
from cis.assurance.recovery_attempt import RecoveryAttemptAuthority
from cis.assurance.recovery_execution import RecoveryExecutionAuthority
from cis.assurance.reviewer import Reviewer
from cis.assurance.verifier import Verifier
from cis.authority import AuthorityStore
from cis.conductor import Conductor
from cis.workbench import Workbench


INSTRUCTION = "Verify authored source for cis.workbench.projection"
OBJECTIVE = "Prove bounded recovery through the contained pipeline"
BAD_SOURCE = "def run(value):\n    return value + 1\n"
GOOD_SOURCE = "def run(value):\n    return value\n"
VECTORS = [{"args": [1], "expect_value": 1}]
ENTRYPOINT = "run"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


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
        wb.set_initial_objective(OBJECTIVE, established_by="recovery-proof")
        conductor = Conductor(wb)

        parent_outcome = conductor.ingest_instruction(INSTRUCTION)
        parent_authorization_id = str(
            parent_outcome.authorization["authorization_id"])
        _require(parent_outcome.authorization["verdict"] == "ALLOW",
                 "parent verification was not authorized")
        parent_issued = wb.prepare_authored_source_verification(
            parent_authorization_id,
            candidate_source=BAD_SOURCE,
            vectors=VECTORS,
            entrypoint=ENTRYPOINT)
        parent_run = conductor.execute_authorization(parent_authorization_id)
        parent_task_contract_id = str(parent_issued["task_contract_id"])
        parent_verification = Verifier(store, wb.blueprint).verify(
            parent_task_contract_id)
        parent_review, parent_cycle = Reviewer(store, wb.blueprint).review(
            parent_task_contract_id)
        parent_decision = PromotionRecorder(store).decide(
            parent_task_contract_id)
        _require(parent_run["status"] == "failed"
                 and int(parent_run["exit_code"]) == 1,
                 "wrong parent candidate did not produce the expected "
                 "contained source failure")
        _require(parent_verification["outcome"] == "VERIFIED_FAIL",
                 "wrong parent candidate did not fail verification")
        _require(parent_review["outcome"] == "OBJECTIONS",
                 "wrong parent candidate did not receive objections")
        _require(parent_cycle is not None,
                 "wrong parent candidate did not open a recovery cycle")
        _require(str(parent_cycle["recovery_decision"])
                 == RECOVERY_REPLACEMENT_CANDIDATE,
                 "objection cycle did not call for a replacement candidate")
        _require(parent_decision["decision"] == "PROMOTION_DENIED",
                 "wrong parent candidate was not denied promotion")

        assessment = OperationalSelfAssessment(store).assess(
            parent_task_contract_id)
        _require(assessment["disposition"] == REPLACEMENT_REQUIRED,
                 "assessment did not require a replacement candidate")
        verified_assessment = OperationalSelfAssessment(store).verify(
            str(assessment["assessment_id"]))
        _require(str(verified_assessment["assessment_id"])
                 == str(assessment["assessment_id"]),
                 "assessment did not independently reverify")

        child_outcome = conductor.ingest_instruction(INSTRUCTION)
        child_authorization_id = str(
            child_outcome.authorization["authorization_id"])
        _require(child_outcome.authorization["verdict"] == "ALLOW",
                 "replacement verification was not separately authorized")
        _require(child_authorization_id != parent_authorization_id,
                 "replacement reused the parent authorization")

        recovery = RecoveryExecutionAuthority(
            store=store,
            blueprint=wb.blueprint,
            gateway=wb.gateway,
            authorizations=wb.authorizations)
        recovered = recovery.execute(
            str(assessment["assessment_id"]),
            child_authorization_id=child_authorization_id,
            candidate_source=GOOD_SOURCE,
            vectors=VECTORS,
            entrypoint=ENTRYPOINT,
            active_objective_id=wb.continuity.active_objective_id())
        attempt = RecoveryAttemptAuthority(store).verify(
            str(recovered["attempt_id"]))

        _require(recovered["run_status"] == "completed",
                 "replacement contained run did not complete")
        _require(recovered["verification"]["outcome"] == "VERIFIED_PASS",
                 "replacement did not pass verification")
        _require(recovered["review"]["outcome"] == "PASS",
                 "replacement did not pass independent review")
        _require(recovered["cycle"] is None,
                 "passing replacement unexpectedly opened an objection cycle")
        _require(recovered["decision"]["decision"] == "PROMOTION_AUTHORIZED",
                 "replacement was not promotion-authorized")
        _require(recovered["decision"]["host_action"] == "NONE_RECORD_ONLY",
                 "replacement promotion attempted a host action")
        _require(str(attempt["parent_task_contract_id"])
                 == parent_task_contract_id,
                 "attempt does not bind the assessed parent")
        _require(str(attempt["child_task_contract_id"])
                 == recovered["child_task_contract_id"],
                 "attempt does not bind the executed child")
        _require(str(attempt["child_authorization_id"])
                 == child_authorization_id,
                 "attempt does not bind the authorized child")

        proof = {
            "schema": "cis-contained-recovery-production-proof-v1",
            "assessment_id": str(assessment["assessment_id"]),
            "attempt_id": str(recovered["attempt_id"]),
            "parent_authorization_id": parent_authorization_id,
            "parent_task_contract_id": parent_task_contract_id,
            "parent_verification_outcome": str(
                parent_verification["outcome"]),
            "parent_review_outcome": str(parent_review["outcome"]),
            "parent_promotion_decision": str(parent_decision["decision"]),
            "child_authorization_id": child_authorization_id,
            "child_task_contract_id": str(
                recovered["child_task_contract_id"]),
            "child_run_id": str(recovered["run_id"]),
            "child_run_status": str(recovered["run_status"]),
            "child_verification_outcome": str(
                recovered["verification"]["outcome"]),
            "child_review_outcome": str(recovered["review"]["outcome"]),
            "child_promotion_decision": str(
                recovered["decision"]["decision"]),
            "host_action": str(recovered["decision"]["host_action"]),
        }
        output_path.write_text(
            json.dumps(proof, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        print(json.dumps(proof, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
