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
import keyword
import os
from typing import Any, Callable, Mapping

from ..assurance.execution_input import verify_row as verify_execution_input_row
from ..assurance.task_contract import (
    VERIFY_AUTHORED_SOURCE_V1, verify_row as verify_task_contract_row,
)
from ..authority.authorization import AuthorizationAuthority
from ..authority.evidence import EvidenceAuthority
from ..authority.runs import COMPLETED, FAILED, RunAuthority
from ..authority.trajectory import MICRO, TrajectoryAuthority
from ..canonical import canonical_json, sha256_hex, sha256_text
from ..card_factory import verify_card
from ..errors import (
    AssuranceRefused, AuthorizationRefused, CisError, ExecutionBudgetExhausted,
    ExecutionOutputIncomplete, ExecutionRefused, ExecutionTimedOut,
)
from ..policy.compiler import verify_compiled_envelope
from .adapters.contained_worker import ContainedWorkerAdapter
from .adapters.deterministic_mock import DeterministicMockAdapter
from .port import (
    AdapterRegistry, ExecutionBudget, ExecutionPort, ExecutionRequest,
    _mint_token,
)

#: The closed schema a recorded supervision route must satisfy. Checked here,
#: locally, rather than by importing the module that owns supervision plans:
#: that module may come to call this one, and this one must never call back
#: into it.
_SUPERVISION_ROUTE_FIELDS = frozenset({
    "authorization_id", "adapter_id", "wall_time_ms", "token_limit",
    "cost_limit_micros",
})

#: The closed set of budget dimensions a supervised adapter must declare
#: exactly — no more, no fewer — before this gateway will trust its
#: enforcement of a route's budget.
_SUPERVISED_BUDGET_DIMENSIONS = frozenset({
    "wall_time_ms", "token_limit", "cost_limit_micros",
})


def _route_budget(route: Any) -> tuple[str, str, ExecutionBudget]:
    """Derive the authorization id, adapter id and budget solely from one
    recorded supervision route. The caller supplies none of these values."""
    if not isinstance(route, Mapping) or set(route) != _SUPERVISION_ROUTE_FIELDS:
        raise ExecutionRefused(
            "supervision route does not match the closed schema",
            required=sorted(_SUPERVISION_ROUTE_FIELDS))
    authorization_id = str(route["authorization_id"])
    adapter_id = str(route["adapter_id"])
    if not authorization_id or not adapter_id.strip():
        raise ExecutionRefused("supervision route identity must not be blank")
    for key in ("wall_time_ms", "token_limit", "cost_limit_micros"):
        value = route[key]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ExecutionRefused(
                "supervision route budget dimension must be a positive integer",
                field=key)
    budget = ExecutionBudget(
        wall_time_ms=int(route["wall_time_ms"]),
        token_limit=int(route["token_limit"]),
        cost_limit_micros=int(route["cost_limit_micros"]),
    )
    return authorization_id, adapter_id, budget

#: The default adapter id lives here, at the Layer-2 boundary, and nowhere
#: above it. Changing backends is an environment decision, not a code change
#: in any caller.
_DEFAULT_ADAPTER_ENV = "CIS_CLEAN_EXECUTION_ADAPTER"
_BUILTIN_DEFAULT = DeterministicMockAdapter.adapter_id


def default_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(DeterministicMockAdapter())
    registry.register(ContainedWorkerAdapter())
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
                 task_card_resolver: (
                     Callable[[str], Mapping[str, Any] | None] | None
                 ) = None,
                 policy_envelope_resolver: (
                     Callable[[str], Mapping[str, Any] | None] | None
                 ) = None,
                 authorization_check_resolver: (
                     Callable[[Mapping[str, Any]], tuple[str, ...]] | None
                 ) = None,
                 execution_input_resolver: (
                     Callable[[str], Mapping[str, Any] | None] | None
                 ) = None,
                 supervision_route_resolver: (
                     Callable[[str, int], Mapping[str, Any] | None] | None
                 ) = None) -> None:
        self._authorizations = authorizations
        self._runs = runs
        self._evidence = evidence
        self._trajectory = trajectory
        self._registry = registry if registry is not None else default_registry()
        self._task_contract_resolver = task_contract_resolver
        self._task_card_resolver = task_card_resolver
        self._policy_envelope_resolver = policy_envelope_resolver
        self._authorization_check_resolver = authorization_check_resolver
        self._execution_input_resolver = execution_input_resolver
        self._supervision_route_resolver = supervision_route_resolver
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

    def execution_identity(self, operation: str) -> dict[str, str]:
        """Return the selected backend's immutable issuance identity.

        This is the only production path by which Workbench issuance learns
        apparatus identity. A caller cannot submit image or binary digests.
        """
        adapter = self._registry.get(self._adapter_id)
        if operation not in adapter.capabilities():
            raise ExecutionRefused(
                "selected backend does not declare the issuance operation",
                operation=operation, adapter_id=adapter.adapter_id)
        values = {
            "adapter_id": adapter.adapter_id,
            "worker_image": adapter.execution_image_identity,
            "expected_trusted_runner_sha256":
                adapter.expected_trusted_runner_sha256,
            "expected_worker_sha256": adapter.expected_worker_sha256,
        }
        if any(not isinstance(value, str) or not value
               for value in values.values()):
            raise ExecutionRefused(
                "selected backend does not declare a complete immutable "
                "execution identity",
                operation=operation, adapter_id=adapter.adapter_id)
        return values  # type: ignore[return-value]

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
            task_card_resolver=self._task_card_resolver,
            policy_envelope_resolver=self._policy_envelope_resolver,
            authorization_check_resolver=self._authorization_check_resolver,
            execution_input_resolver=self._execution_input_resolver,
            supervision_route_resolver=self._supervision_route_resolver,
        )

    def with_authority_resolvers(self, *, task_contract_resolver,
                                 execution_input_resolver,
                                 task_card_resolver=None) -> "ExecutionGateway":
        """Return the same selected boundary with its authority ports bound."""
        return ExecutionGateway(
            authorizations=self._authorizations,
            runs=self._runs, evidence=self._evidence,
            trajectory=self._trajectory, registry=self._registry,
            adapter_id=self._adapter_id,
            task_contract_resolver=task_contract_resolver,
            task_card_resolver=(task_card_resolver
                                if task_card_resolver is not None
                                else self._task_card_resolver),
            policy_envelope_resolver=self._policy_envelope_resolver,
            authorization_check_resolver=self._authorization_check_resolver,
            execution_input_resolver=execution_input_resolver,
            supervision_route_resolver=self._supervision_route_resolver,
        )

    def with_supervision_resolver(self, resolver: (
            Callable[[str, int], Mapping[str, Any] | None]
    )) -> "ExecutionGateway":
        """Return the same selected boundary bound to one supervision-route
        resolver, so ``dispatch_supervised`` can derive authority solely from
        a recorded route without this module importing the supervisor
        authority that owns that route."""
        return ExecutionGateway(
            authorizations=self._authorizations,
            runs=self._runs, evidence=self._evidence,
            trajectory=self._trajectory, registry=self._registry,
            adapter_id=self._adapter_id,
            task_contract_resolver=self._task_contract_resolver,
            task_card_resolver=self._task_card_resolver,
            policy_envelope_resolver=self._policy_envelope_resolver,
            authorization_check_resolver=self._authorization_check_resolver,
            execution_input_resolver=self._execution_input_resolver,
            supervision_route_resolver=resolver,
        )

    # -- dispatch -----------------------------------------------------------

    def _request_for(self, row: Mapping[str, Any], adapter: ExecutionPort,
                     *, run_nonce: str,
                     budget: "ExecutionBudget | None" = None) -> ExecutionRequest:
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

        if adapter.requires_task_card:
            if contract is None:
                raise ExecutionRefused(
                    "task-card backend requires a frozen task contract",
                    authorization_id=str(row["authorization_id"]))
            if self._task_card_resolver is None:
                raise ExecutionRefused(
                    "task-card backend has no authority-derived card resolver",
                    authorization_id=str(row["authorization_id"]))
            try:
                resolved_card = self._task_card_resolver(
                    str(contract["task_contract_id"]))
                if resolved_card is None:
                    raise ExecutionRefused(
                        "no task card exists for the frozen task contract",
                        authorization_id=str(row["authorization_id"]))
                card = dict(resolved_card)
                verify_card(card)
            except CisError as exc:
                raise ExecutionRefused(
                    "authority-derived task card did not verify",
                    authorization_id=str(row["authorization_id"])) from exc
            if (str(card.get("task_contract_id"))
                    != str(contract.get("task_contract_id"))
                    or str(card.get("task_contract_hash"))
                    != str(contract.get("task_contract_hash"))
                    or str(card.get("authorization_id"))
                    != str(row["authorization_id"])
                    or str(card.get("authorization_binding_hash"))
                    != str(row["binding_hash"])):
                raise ExecutionRefused(
                    "task card is not bound to this authorization and contract",
                    authorization_id=str(row["authorization_id"]))
            payload["task_card"] = card

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

        if adapter.requires_execution_input:
            if contract is None:
                raise ExecutionRefused(
                    "backend requires a verified execution-input binding but "
                    "the gateway has no resolved frozen task contract",
                    authorization_id=str(row["authorization_id"]),
                )
            try:
                verify_task_contract_row(contract)
            except AssuranceRefused as exc:
                raise ExecutionRefused(
                    "frozen task contract did not independently verify",
                    authorization_id=str(row["authorization_id"]),
                ) from exc
            if str(contract.get("authorization_id")) != str(row["authorization_id"]):
                raise ExecutionRefused(
                    "frozen task contract is not bound to this authorization",
                    authorization_id=str(row["authorization_id"]),
                )
            if str(contract.get("template_id")) != VERIFY_AUTHORED_SOURCE_V1.template_id:
                raise ExecutionRefused(
                    "frozen task contract was not compiled from "
                    "verify_authored_source.v1",
                    authorization_id=str(row["authorization_id"]),
                )
            if str(contract.get("template_hash")) != VERIFY_AUTHORED_SOURCE_V1.template_hash:
                raise ExecutionRefused(
                    "frozen task contract's template hash does not match "
                    "verify_authored_source.v1",
                    authorization_id=str(row["authorization_id"]),
                )
            if str(contract.get("authorization_binding_hash")) != str(row["binding_hash"]):
                raise ExecutionRefused(
                    "frozen task contract's authorization binding hash does "
                    "not match this authorization",
                    authorization_id=str(row["authorization_id"]),
                )
            if self._execution_input_resolver is None:
                raise ExecutionRefused(
                    "backend requires an execution-input binding but the "
                    "gateway has no verified resolver",
                    authorization_id=str(row["authorization_id"]),
                )
            task_contract_id = str(contract["task_contract_id"])
            try:
                exi_row = self._execution_input_resolver(task_contract_id)
            except CisError as exc:
                raise ExecutionRefused(
                    "execution-input resolver refused",
                    authorization_id=str(row["authorization_id"]),
                    task_contract_id=task_contract_id,
                ) from exc
            if exi_row is None:
                raise ExecutionRefused(
                    "no execution-input binding is recorded for this task "
                    "contract",
                    authorization_id=str(row["authorization_id"]),
                    task_contract_id=task_contract_id,
                )
            try:
                execution_input_hash = verify_execution_input_row(exi_row)
            except AssuranceRefused as exc:
                raise ExecutionRefused(
                    "execution-input binding did not independently verify",
                    authorization_id=str(row["authorization_id"]),
                    task_contract_id=task_contract_id,
                ) from exc

            if str(exi_row["task_contract_id"]) != task_contract_id:
                raise ExecutionRefused(
                    "execution-input binding is not bound to this task "
                    "contract",
                    authorization_id=str(row["authorization_id"]),
                )
            if str(exi_row["task_contract_hash"]) != str(contract["task_contract_hash"]):
                raise ExecutionRefused(
                    "execution-input binding's task-contract hash does not "
                    "match the frozen task contract",
                    authorization_id=str(row["authorization_id"]),
                )
            if str(exi_row["authorization_binding_hash"]) != str(row["binding_hash"]):
                raise ExecutionRefused(
                    "execution-input binding's authorization binding hash "
                    "does not match this authorization",
                    authorization_id=str(row["authorization_id"]),
                )
            if str(exi_row["worker_image"]) != str(adapter.execution_image_identity):
                raise ExecutionRefused(
                    "execution-input binding was authorized against a "
                    "different worker image than this backend is configured "
                    "to run",
                    authorization_id=str(row["authorization_id"]),
                )

            try:
                authored_source = bytes(exi_row["candidate_source"]).decode(
                    "utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise ExecutionRefused(
                    "candidate source bytes are not valid UTF-8",
                    authorization_id=str(row["authorization_id"]),
                ) from exc

            try:
                vector_text = bytes(exi_row["vector_contract"]).decode(
                    "utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise ExecutionRefused(
                    "vector contract bytes are not valid UTF-8",
                    authorization_id=str(row["authorization_id"]),
                ) from exc
            try:
                vectors = json.loads(vector_text)
            except ValueError as exc:
                raise ExecutionRefused(
                    "vector contract bytes are not valid JSON",
                    authorization_id=str(row["authorization_id"]),
                ) from exc
            if (not isinstance(vectors, list) or not vectors
                    or not all(isinstance(item, Mapping) for item in vectors)):
                raise ExecutionRefused(
                    "vector contract must decode to a nonempty JSON list of "
                    "mappings",
                    authorization_id=str(row["authorization_id"]),
                )
            if canonical_json(vectors) != vector_text:
                raise ExecutionRefused(
                    "vector contract bytes are not the canonical encoding of "
                    "their own content",
                    authorization_id=str(row["authorization_id"]),
                )

            entrypoint = str(exi_row["authorized_entrypoint"])
            if not entrypoint.isidentifier() or keyword.iskeyword(entrypoint):
                raise ExecutionRefused(
                    "authorized entrypoint is not a valid, non-reserved "
                    "identifier",
                    authorization_id=str(row["authorization_id"]),
                )

            payload["authored_source"] = authored_source
            payload["vectors"] = vectors
            payload["entrypoint"] = entrypoint
            payload["task_contract_id"] = task_contract_id
            payload["task_contract_hash"] = str(contract["task_contract_hash"])
            payload["execution_input_hash"] = execution_input_hash
            payload["candidate_sha256"] = str(exi_row["candidate_sha256"])
            payload["vector_contract_sha256"] = str(exi_row["vector_contract_sha256"])
            payload["expected_trusted_runner_sha256"] = str(
                exi_row["expected_trusted_runner_sha256"])
            payload["expected_worker_sha256"] = str(exi_row["expected_worker_sha256"])

        return ExecutionRequest(
            request_id=f"req-{row['authorization_id']}",
            operation=str(scope["operation"]),
            allowed_scope=tuple(sorted(allowed_scope)),
            forbidden_actions=tuple(sorted(forbidden_actions)),
            required_checks=tuple(sorted(required_checks)),
            stopping_condition=str(scope["stopping_condition"]),
            return_point=str(scope["return_point"]),
            payload=payload,
            budget=budget,
        )

    def dispatch(self, authorization_id: str, *, baseline_hash: str,
                 active_objective_id: str | None) -> dict:
        """Verify, then run. Nothing executes before verification succeeds."""
        return self._dispatch_authorized(
            authorization_id, baseline_hash=baseline_hash,
            active_objective_id=active_objective_id)

    def dispatch_supervised(self, supervision_id: str, route_index: int, *,
                            baseline_hash: str,
                            active_objective_id: str | None) -> dict:
        """Dispatch one authorized, budgeted attempt named by a recorded
        supervision route. The caller supplies no authorization id, adapter
        id or budget: every one of those is derived solely from the route the
        resolver returns for ``(supervision_id, route_index)``.
        """
        context_id = f"supervision:{supervision_id}:{route_index}"
        if self._supervision_route_resolver is None:
            exc = ExecutionRefused(
                "no supervision-route resolver is bound to this gateway",
                supervision_id=supervision_id, route_index=route_index,
            )
            self._record_refusal(context_id, exc)
            raise exc

        route = self._supervision_route_resolver(supervision_id, route_index)
        try:
            authorization_id, route_adapter_id, budget = _route_budget(route)
        except ExecutionRefused as exc:
            self._record_refusal(context_id, exc)
            raise

        adapter: ExecutionPort = self._registry.get(self._adapter_id)
        if route_adapter_id != adapter.adapter_id:
            exc = ExecutionRefused(
                "supervision route names a different adapter than this "
                "gateway is bound to",
                authorization_id=authorization_id,
                route_adapter_id=route_adapter_id, adapter_id=adapter.adapter_id,
            )
            self._record_refusal(authorization_id, exc)
            raise exc

        if set(adapter.enforced_budget_dimensions) != _SUPERVISED_BUDGET_DIMENSIONS:
            exc = ExecutionRefused(
                "backend does not declare exact enforcement of every "
                "budget dimension",
                authorization_id=authorization_id, adapter_id=adapter.adapter_id,
                enforced=sorted(adapter.enforced_budget_dimensions),
            )
            self._record_refusal(authorization_id, exc)
            raise exc

        return self._dispatch_authorized(
            authorization_id, baseline_hash=baseline_hash,
            active_objective_id=active_objective_id, budget=budget,
            require_usage=True)

    def _dispatch_authorized(self, authorization_id: str, *,
                             baseline_hash: str,
                             active_objective_id: str | None,
                             budget: "ExecutionBudget | None" = None,
                             require_usage: bool = False) -> dict:
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
            unbound = self._request_for(
                row, adapter, run_nonce=run_nonce, budget=budget)
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
                # contract_view() renders the budget as a plain dict for
                # hashing; the live request needs the ExecutionBudget object
                # it was minted for, not that hashable rendering of it.
                "budget": unbound.budget,
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

        usage = None
        if require_usage:
            usage = result.usage
            if usage is None:
                exc = ExecutionOutputIncomplete(
                    "supervised execution returned no usage accounting",
                    authorization_id=authorization_id,
                )
                self._record_refusal(authorization_id, exc)
                raise exc
            if usage.wall_time_ms > budget.wall_time_ms:
                exc = ExecutionTimedOut(
                    "measured wall time exceeds the authorized route budget",
                    authorization_id=authorization_id,
                    measured_wall_time_ms=usage.wall_time_ms,
                    wall_time_ms=budget.wall_time_ms,
                )
                self._record_refusal(authorization_id, exc)
                raise exc
            if (usage.tokens_used > budget.token_limit
                    or usage.cost_micros > budget.cost_limit_micros):
                exc = ExecutionBudgetExhausted(
                    "measured usage exceeds the authorized route budget",
                    authorization_id=authorization_id,
                    measured_tokens=usage.tokens_used,
                    token_limit=budget.token_limit,
                    measured_cost_micros=usage.cost_micros,
                    cost_limit_micros=budget.cost_limit_micros,
                )
                self._record_refusal(authorization_id, exc)
                raise exc

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
            usage=result.usage,
        )

        status = COMPLETED if result.status == "completed" else FAILED
        evidence_id = f"evi-run-{authorization_id}"
        attestation_text = "\n".join(result.evidence)
        evidence_fields = {
            "attestation_sha256": sha256_text(attestation_text),
            "result_hash": result.result_hash,
            "result_record_sha256": sha256_hex(result.as_dict()),
        }
        if usage is not None:
            # Carries the exact measured usage a supervisor independently
            # validates when resuming after an interruption, rather than
            # trusting its own in-memory copy of a result that may never
            # have been durably recorded anywhere else. Ordinary unmetered
            # evidence (usage is None) is untouched, so its content stays
            # byte-compatible with every row admitted before this field
            # existed.
            evidence_fields["usage"] = usage.as_dict()
        evidence_content = canonical_json(evidence_fields)
        self._evidence.admit(
            evidence_id=evidence_id,
            kind="execution_evidence",
            source_ref=f"backend_runs:run-{authorization_id}",
            original_language=attestation_text,
            content=evidence_content,
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
        response = {
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
        if usage is not None:
            response["usage"] = usage.as_dict()
        return response

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
