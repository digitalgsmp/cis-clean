"""The sole call path from CIS to any execution backend.

ADR-ARCH-003 clause 1. Everything above this module reaches execution by
calling ``dispatch`` with an authorization id; it never holds an adapter, never
names one, and cannot widen the scope of what runs, because the request is
built here from the recorded authorization rather than from caller input.

The gate is fail-closed in four independent ways before anything executes:
unknown authorization, binding that does not recompute, verdict that is not
ALLOW, and staleness.

A refusal leaves evidence instead of leaving silence, and it leaves it as a
``trajectory_events`` row with ``event_type='execution_refused'`` — NOT as a
run. ``backend_runs`` has no ``refused`` status and never had one: a refusal
may have no valid authorization to key a run row on, so the run ledger would
have nothing to reference. ``_record_refusal`` below is the whole mechanism,
and migration 0001 states the same rule where the status vocabulary is
declared.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Mapping

from ..authority.authorization import AuthorizationAuthority
from ..authority.evidence import EvidenceAuthority
from ..authority.runs import COMPLETED, FAILED, RunAuthority
from ..authority.trajectory import MICRO, TrajectoryAuthority
from ..canonical import sha256_hex
from ..errors import AuthorizationRefused, CisError, ExecutionRefused
from ..policy.compiler import verify_compiled_envelope
from .adapters.deterministic_mock import DeterministicMockAdapter
from .port import AdapterRegistry, ExecutionPort, ExecutionRequest, _mint_token

#: The default adapter id lives here, at the Layer-2 boundary, and nowhere
#: above it. Changing backends is an environment decision, not a code change
#: in any caller.
_DEFAULT_ADAPTER_ENV = "CIS_CLEAN_EXECUTION_ADAPTER"
_BUILTIN_DEFAULT = DeterministicMockAdapter.adapter_id


def default_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(DeterministicMockAdapter())
    return registry


class ExecutionGateway:
    def __init__(self, *, authorizations: AuthorizationAuthority,
                 runs: RunAuthority, evidence: EvidenceAuthority,
                 trajectory: TrajectoryAuthority,
                 registry: AdapterRegistry | None = None,
                 adapter_id: str | None = None,
                 task_contract_resolver: (
                     Callable[[str], Mapping[str, Any] | None] | None
                 ) = None,
                 policy_envelope_resolver: (
                     Callable[[str], Mapping[str, Any] | None] | None
                 ) = None,
                 authorization_check_resolver: (
                     Callable[[Mapping[str, Any]], tuple[str, ...]] | None
                 ) = None) -> None:
        self._authorizations = authorizations
        self._runs = runs
        self._evidence = evidence
        self._trajectory = trajectory
        self._registry = registry if registry is not None else default_registry()
        self._task_contract_resolver = task_contract_resolver
        self._policy_envelope_resolver = policy_envelope_resolver
        self._authorization_check_resolver = authorization_check_resolver
        self._adapter_id = (
            adapter_id
            or os.environ.get(_DEFAULT_ADAPTER_ENV)
            or _BUILTIN_DEFAULT
        )
        # Fail fast rather than at dispatch time.
        self._registry.get(self._adapter_id)

    # -- introspection ------------------------------------------------------

    @property
    def adapter_id(self) -> str:
        return self._adapter_id

    def available_adapters(self) -> list[str]:
        return self._registry.ids()

    def capabilities(self) -> list[str]:
        return list(self._registry.get(self._adapter_id).capabilities())

    def using(self, adapter_id: str) -> "ExecutionGateway":
        """A gateway over the same authority with a different backend.

        This is the replacement path: a caller swaps the backend without
        knowing what either backend is.
        """
        return ExecutionGateway(
            authorizations=self._authorizations,
            runs=self._runs,
            evidence=self._evidence,
            trajectory=self._trajectory,
            registry=self._registry,
            adapter_id=adapter_id,
            task_contract_resolver=self._task_contract_resolver,
            policy_envelope_resolver=self._policy_envelope_resolver,
            authorization_check_resolver=self._authorization_check_resolver,
        )

    # -- dispatch -----------------------------------------------------------

    def _request_for(self, row: Mapping[str, Any], adapter: ExecutionPort,
                     *, run_nonce: str) -> ExecutionRequest:
        scope = self._authorizations.scope_of(row)
        payload: dict[str, Any] = {
            "target_module_id": row["target_module_id"],
            "objective_id": row["objective_id"],
            "transaction_id": row["transaction_id"],
            "run_nonce": run_nonce,
        }
        contract: Mapping[str, Any] | None = None
        allowed_scope = tuple(scope["allowed_scope"])
        forbidden_actions = set(scope["forbidden_actions"])
        required_checks = set(scope["required_checks"])
        if adapter.requires_frozen_task_contract:
            if self._task_contract_resolver is None:
                raise ExecutionRefused(
                    "backend requires a frozen task contract but the gateway "
                    "has no verified resolver",
                    authorization_id=str(row["authorization_id"]),
                )
            contract = self._task_contract_resolver(str(row["authorization_id"]))
            if contract is None:
                raise ExecutionRefused(
                    "backend requires a frozen task contract and none exists",
                    authorization_id=str(row["authorization_id"]),
                )
            contract = dict(contract)
            payload["frozen_task_contract"] = contract

        if adapter.requires_policy_envelope:
            if contract is None:
                raise ExecutionRefused(
                    "policy-governed backend requires a frozen task contract",
                    authorization_id=str(row["authorization_id"]),
                )
            if self._policy_envelope_resolver is None:
                raise ExecutionRefused(
                    "policy-governed backend has no verified envelope resolver",
                    authorization_id=str(row["authorization_id"]),
                )
            try:
                envelope = self._policy_envelope_resolver(
                    str(row["authorization_id"]))
            except CisError as exc:
                raise ExecutionRefused(
                    "current policy envelope did not verify",
                    authorization_id=str(row["authorization_id"]),
                ) from exc
            if envelope is None:
                raise ExecutionRefused(
                    "backend requires a frozen task contract and no bound "
                    "policy envelope exists",
                    authorization_id=str(row["authorization_id"]),
                )
            envelope = dict(envelope)
            try:
                verify_compiled_envelope(envelope)
            except CisError as exc:
                raise ExecutionRefused(
                    "policy envelope integrity did not verify",
                    authorization_id=str(row["authorization_id"]),
                ) from exc
            if envelope.get("task_contract_id") != contract.get("task_contract_id"):
                raise ExecutionRefused(
                    "policy envelope is not bound to this task contract",
                    authorization_id=str(row["authorization_id"]),
                )
            if envelope.get("task_contract_hash") != contract.get("task_contract_hash"):
                raise ExecutionRefused(
                    "policy envelope does not carry this task contract's hash",
                    authorization_id=str(row["authorization_id"]),
                )
            selector = envelope.get("selector", {})
            if (selector.get("module") != row["target_module_id"]
                    or selector.get("operation") != scope["operation"]):
                raise ExecutionRefused(
                    "policy envelope selector does not match this request",
                    authorization_id=str(row["authorization_id"]),
                )
            narrowed = envelope.get("narrowed_scope")
            if narrowed is not None:
                contract_paths = set(contract.get("allowed_paths", ()))
                if not set(narrowed) <= contract_paths:
                    raise ExecutionRefused(
                        "policy envelope scope exceeds the task contract",
                        authorization_id=str(row["authorization_id"]),
                    )
                allowed_scope = tuple(narrowed)
            unsupported_prohibitions = sorted(
                set(envelope["prohibited_actions"])
                - set(adapter.enforced_policy_prohibitions))
            unsupported_checks = sorted(
                set(envelope["required_checks"])
                - set(adapter.enforced_policy_checks))
            unsupported_evidence = sorted(
                set(envelope["required_evidence"])
                - set(adapter.produced_policy_evidence))
            if unsupported_prohibitions or unsupported_checks or unsupported_evidence:
                raise ExecutionRefused(
                    "backend cannot deterministically satisfy the policy envelope",
                    authorization_id=str(row["authorization_id"]),
                    unsupported_prohibitions=unsupported_prohibitions,
                    unsupported_checks=unsupported_checks,
                    unsupported_evidence=unsupported_evidence,
                )
            forbidden_actions.update(envelope["prohibited_actions"])
            required_checks.update(envelope["required_checks"])
            payload["policy_envelope"] = envelope
        return ExecutionRequest(
            request_id=f"req-{row['authorization_id']}",
            operation=str(scope["operation"]),
            allowed_scope=tuple(sorted(allowed_scope)),
            forbidden_actions=tuple(sorted(forbidden_actions)),
            required_checks=tuple(sorted(required_checks)),
            stopping_condition=str(scope["stopping_condition"]),
            return_point=str(scope["return_point"]),
            payload=payload,
        )

    def dispatch(self, authorization_id: str, *, baseline_hash: str,
                 active_objective_id: str | None) -> dict:
        """Verify, then run. Nothing executes before verification succeeds."""
        adapter: ExecutionPort = self._registry.get(self._adapter_id)

        try:
            row = self._authorizations.verify(
                authorization_id,
                baseline_hash=baseline_hash,
                active_objective_id=active_objective_id,
            )
        except AuthorizationRefused as exc:
            self._record_refusal(authorization_id, exc)
            raise

        # One verified ALLOW authorizes one attempted boundary crossing.  The
        # append-only claim survives adapter failure and its SQL UNIQUE
        # constraint is the atomic concurrency/replay gate.
        existing_claim = self._runs.claim_for_authorization(authorization_id)
        if existing_claim:
            existing_runs = self._runs.for_authorization(authorization_id)
            replay_detail = {
                "authorization_id": authorization_id,
                "claim_id": str(existing_claim["claim_id"]),
            }
            if existing_runs:
                replay_detail["run_id"] = str(existing_runs[0]["run_id"])
            exc = ExecutionRefused(
                "authorization has already been executed",
                **replay_detail,
            )
            self._record_refusal(authorization_id, exc)
            raise exc

        operation = str(self._authorizations.scope_of(row)["operation"])
        if operation not in adapter.capabilities():
            exc = ExecutionRefused(
                "backend does not declare this operation",
                operation=operation, authorization_id=authorization_id,
            )
            self._record_refusal(authorization_id, exc)
            raise exc

        if not adapter.liveness():
            exc = ExecutionRefused(
                "backend declares itself not live",
                authorization_id=authorization_id,
            )
            self._record_refusal(authorization_id, exc)
            raise exc

        performed_preflight = (
            set(self._authorization_check_resolver(row))
            if self._authorization_check_resolver is not None else set()
        )
        required = set(self._authorizations.scope_of(row)["required_checks"])
        uncovered_preflight = sorted(required - performed_preflight)
        if uncovered_preflight:
            exc = ExecutionRefused(
                "authorization preflight does not cover required checks",
                authorization_id=authorization_id,
                uncovered=uncovered_preflight,
            )
            self._record_refusal(authorization_id, exc)
            raise exc

        try:
            run_nonce = sha256_hex({
                "domain": "cis.execution.attempt.v1",
                "authorization_id": authorization_id,
                "binding_hash": str(row["binding_hash"]),
                "adapter_id": adapter.adapter_id,
            })
            unbound = self._request_for(row, adapter, run_nonce=run_nonce)
        except ExecutionRefused as exc:
            self._record_refusal(authorization_id, exc)
            raise
        request_hash = unbound.request_hash
        try:
            self._runs.claim(
                claim_id=f"claim-{authorization_id}",
                authorization_id=authorization_id,
                adapter_id=adapter.adapter_id,
                request_hash=request_hash,
                run_nonce=run_nonce,
            )
        except CisError as claim_error:
            exc = ExecutionRefused(
                "authorization execution claim was refused",
                authorization_id=authorization_id,
            )
            self._record_refusal(authorization_id, exc)
            raise exc from claim_error

        request = ExecutionRequest(
            **{
                **unbound.contract_view(),
                "binding_hash": str(row["binding_hash"]),
                "token": _mint_token(
                    binding_hash=str(row["binding_hash"]),
                    request_hash=request_hash,
                ),
            }
        )

        self._trajectory.record(
            event_id=f"ev-dispatch-{authorization_id}",
            scope=MICRO,
            stage="GOVERNED_EXECUTION",
            event_type="execution_dispatched",
            module_id=row["target_module_id"],
            transaction_id=str(row["transaction_id"]),
            detail={"authorization_id": authorization_id,
                    "request_hash": request_hash},
        )

        try:
            result = adapter.execute(request)
        except ExecutionRefused as exc:
            self._record_refusal(authorization_id, exc)
            raise

        policy_envelope = request.payload.get("policy_envelope")
        if isinstance(policy_envelope, Mapping):
            missing_policy_checks = sorted(
                set(policy_envelope["required_checks"])
                - set(result.checks_performed))
            # A bare label or a model-selected value is not proof.  Adapters
            # may satisfy a policy evidence obligation only with the generic
            # port representation ``label=verified`` after their own closed
            # semantic mapping has verified the underlying facts.
            evidence_keys = {
                key for item in result.evidence
                for key, separator, value in (item.partition("="),)
                if separator and value == "verified"
            }
            missing_policy_evidence = sorted(
                set(policy_envelope["required_evidence"]) - evidence_keys)
            if missing_policy_checks or missing_policy_evidence:
                exc = ExecutionRefused(
                    "backend result did not prove its policy obligations",
                    authorization_id=authorization_id,
                    missing_policy_checks=missing_policy_checks,
                    missing_policy_evidence=missing_policy_evidence,
                )
                self._record_refusal(authorization_id, exc)
                raise exc

        result = result.__class__(
            status=result.status,
            exit_code=result.exit_code,
            outputs=result.outputs,
            checks_performed=tuple(sorted(
                performed_preflight | set(result.checks_performed))),
            evidence=result.evidence,
        )

        status = COMPLETED if result.status == "completed" else FAILED
        evidence_id = f"evi-run-{authorization_id}"
        self._evidence.admit(
            evidence_id=evidence_id,
            kind="execution_evidence",
            source_ref=f"backend_runs:run-{authorization_id}",
            original_language="\n".join(result.evidence),
            content=sha256_hex(result.as_dict()),
            admission_basis=(
                f"verified_execution_authorization:{authorization_id}"
            ),
        )
        run = self._runs.record(
            run_id=f"run-{authorization_id}",
            authorization_id=authorization_id,
            adapter_id=adapter.adapter_id,
            request_hash=request_hash,
            status=status,
            exit_code=result.exit_code,
            result_hash=result.result_hash,
            evidence_id=evidence_id,
        )
        self._trajectory.record(
            event_id=f"ev-result-{authorization_id}",
            scope=MICRO,
            stage="EVIDENCE",
            event_type="execution_completed" if status == COMPLETED else "execution_failed",
            module_id=row["target_module_id"],
            transaction_id=str(row["transaction_id"]),
            detail={"run_id": run["run_id"], "result_hash": result.result_hash,
                    "exit_code": result.exit_code},
        )
        return {
            "run_id": str(run["run_id"]),
            "authorization_id": authorization_id,
            "status": status,
            "exit_code": result.exit_code,
            "request_hash": request_hash,
            "result_hash": result.result_hash,
            "evidence_id": evidence_id,
            "checks_performed": list(result.checks_performed),
            "outputs": dict(result.outputs),
        }

    # -- refusals -----------------------------------------------------------

    def _record_refusal(self, authorization_id: str, exc: CisError) -> None:
        """A refusal leaves evidence. It is never silent."""
        suffix = sha256_hex({"authorization_id": authorization_id,
                             "code": exc.code,
                             "n": self._refusal_count(authorization_id)})[:12]
        self._trajectory.record(
            event_id=f"ev-refused-{suffix}",
            scope=MICRO,
            stage="REVIEW_AUTHORIZATION",
            event_type="execution_refused",
            detail={"authorization_id": authorization_id, "code": exc.code,
                    "message": exc.message},
        )

    def _refusal_count(self, authorization_id: str) -> int:
        return sum(
            1
            for row in self._trajectory.events(scope=MICRO)
            if row["event_type"] == "execution_refused"
            and json.loads(str(row["detail_json"])).get("authorization_id")
            == authorization_id
        )
