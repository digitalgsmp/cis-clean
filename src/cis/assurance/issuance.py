"""Production issuance of one immutable authored-source verification unit.

This module bridges an existing, canonical ALLOW whose operation is
``verify_authored_source`` to the already-separated authorities that freeze a
task contract and bind its exact execution inputs. It owns no table and never
executes work. Apparatus identity comes only from the selected Layer-2 gateway;
the caller cannot nominate an image, trusted runner or worker digest.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from ..canonical import canonical_json
from ..errors import CisError
from .authority import AssuranceAuthority
from .execution_input import ExecutionInputAuthority
from .task_contract import TaskContractCompiler


class AuthoredSourceIssuer:
    """Freeze and bind one resumable, non-replaceable verification unit."""

    module_id = "cis.assurance.issuance"

    def __init__(self, *, store, blueprint, authorizations, gateway) -> None:
        self._blueprint = blueprint
        self._authorizations = authorizations
        self._gateway = gateway
        self.assurance = AssuranceAuthority(store)
        self.execution_inputs = ExecutionInputAuthority(
            store, self.assurance)

    def task_contract_for_authorization(self, authorization_id: str):
        row = self.assurance.ledger.task_contract_for_authorization(
            authorization_id)
        if row is None:
            return None
        return self.assurance.verify_task_contract(str(row["task_contract_id"]))

    def execution_input_for_task(self, task_contract_id: str):
        return self.execution_inputs.verify(task_contract_id)

    def bind_gateway(self, gateway) -> None:
        """Bind the final dispatch boundary used for immutable identity."""
        self._gateway = gateway

    def issue(self, authorization_id: str, *, candidate_source: bytes | str,
              vectors: Sequence[Mapping[str, Any]], entrypoint: str,
              active_objective_id: str | None) -> dict:
        authorization = self._authorizations.verify(
            authorization_id, baseline_hash=self._blueprint.baseline_hash,
            active_objective_id=active_objective_id)
        scope = self._authorizations.scope_of(authorization)
        if str(scope["operation"]) != "verify_authored_source":
            raise CisError(
                "authorization does not permit authored-source verification",
                authorization_id=authorization_id,
                operation=str(scope["operation"]))

        existing_contract = self.assurance.ledger.task_contract_for_authorization(
            authorization_id)
        if existing_contract is None:
            compiled = TaskContractCompiler(
                authorizations=self._authorizations,
                blueprint=self._blueprint).compile(
                    authorization_id=authorization_id,
                    template_id="verify_authored_source.v1",
                    active_objective_id=active_objective_id)
            contract = self.assurance.task_contracts.freeze(compiled)
        else:
            contract = self.assurance.verify_task_contract(
                str(existing_contract["task_contract_id"]))
            if str(contract["template_id"]) != "verify_authored_source.v1":
                raise CisError(
                    "authorization is already frozen under another template",
                    authorization_id=authorization_id,
                    template_id=str(contract["template_id"]))

        source_bytes = (candidate_source.encode("utf-8")
                        if isinstance(candidate_source, str)
                        else bytes(candidate_source))
        vector_bytes = canonical_json(list(vectors)).encode("utf-8")
        identity = self._gateway.execution_identity("verify_authored_source")
        values = {
            "task_contract_id": str(contract["task_contract_id"]),
            "candidate_source": source_bytes,
            "candidate_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "vector_contract": vector_bytes,
            "vector_contract_sha256": hashlib.sha256(vector_bytes).hexdigest(),
            "authorized_entrypoint": entrypoint,
            "task_contract_hash": str(contract["task_contract_hash"]),
            "authorization_binding_hash": str(
                contract["authorization_binding_hash"]),
            "worker_image": identity["worker_image"],
            "expected_trusted_runner_sha256":
                identity["expected_trusted_runner_sha256"],
            "expected_worker_sha256": identity["expected_worker_sha256"],
        }
        existing_input = self.execution_inputs.for_task_contract(
            str(contract["task_contract_id"]))
        if existing_input is None:
            execution_input = self.execution_inputs.append(**values)
        else:
            execution_input = self.execution_inputs.verify(
                str(contract["task_contract_id"]))
            comparisons = {
                "candidate_source": source_bytes,
                "candidate_sha256": values["candidate_sha256"],
                "vector_contract": vector_bytes,
                "vector_contract_sha256": values["vector_contract_sha256"],
                "authorized_entrypoint": entrypoint,
                "worker_image": identity["worker_image"],
                "expected_trusted_runner_sha256":
                    identity["expected_trusted_runner_sha256"],
                "expected_worker_sha256": identity["expected_worker_sha256"],
            }
            mismatch = [name for name, value in comparisons.items()
                        if execution_input[name] != value]
            if mismatch:
                raise CisError(
                    "authored-source issuance cannot replace an existing "
                    "immutable execution-input binding",
                    authorization_id=authorization_id, mismatch=mismatch)
        return {
            "authorization_id": authorization_id,
            "task_contract_id": str(contract["task_contract_id"]),
            "task_contract_hash": str(contract["task_contract_hash"]),
            "execution_input_id": str(execution_input["execution_input_id"]),
            "execution_input_hash": str(execution_input["execution_input_hash"]),
            "adapter_id": identity["adapter_id"],
            "worker_image": identity["worker_image"],
        }


__all__ = ["AuthoredSourceIssuer"]
