"""Append-only authority for bounded, provider-neutral worker supervision.

This unit records immutable plans and attempt events only.  It does not mint
authorization, dispatch a backend, or accept a worker's completion claim as
verification.  Every route names a distinct existing ALLOW; one authorization
therefore still permits at most one gateway boundary crossing.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from ..authority.authorization import ALLOW, AuthorizationAuthority
from ..authority.evidence import EvidenceAuthority
from ..authority.runs import COMPLETED, FAILED, RunAuthority
from ..authority.store import AuthorityStore, Row
from ..canonical import canonical_json, sha256_hex, sha256_text
from ..errors import (
    ExecutionArtifactInvalid, ExecutionBudgetExhausted,
    ExecutionOutputIncomplete, ExecutionPermissionWaitRefused,
    ExecutionProviderFailure, ExecutionTimedOut, WorkerSupervisionRefused,
)
from .gateway import ExecutionGateway

PLAN_DOMAIN = "cis.execution.worker_supervision.plan.v1"
EVENT_DOMAIN = "cis.execution.worker_supervision.event.v1"
FAILURE_CLASSES = frozenset({
    "timeout", "budget_exhausted", "permission_wait",
    "network_or_provider_failure", "empty_or_incomplete_output",
    "invalid_artifacts",
})
MAX_ROUTES = 8


def _route(route: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "authorization_id", "adapter_id", "wall_time_ms", "token_limit",
        "cost_limit_micros",
    }
    if set(route) != required:
        raise WorkerSupervisionRefused(
            "route fields do not match the closed schema",
            required=sorted(required), received=sorted(route))
    for key in ("wall_time_ms", "token_limit", "cost_limit_micros"):
        value = route[key]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise WorkerSupervisionRefused(
                "every route budget must be a positive integer", field=key)
    result = {
        "authorization_id": str(route["authorization_id"]),
        "adapter_id": str(route["adapter_id"]),
        "wall_time_ms": route["wall_time_ms"],
        "token_limit": route["token_limit"],
        "cost_limit_micros": route["cost_limit_micros"],
    }
    if not result["authorization_id"] or not result["adapter_id"].strip():
        raise WorkerSupervisionRefused("route identity must not be blank")
    return result


def plan_payload(*, supervision_id: str, objective_id: str,
                 transaction_id: str, target_module_id: str, operation: str,
                 routes: Sequence[Mapping[str, Any]],
                 circuit_threshold: int) -> dict[str, Any]:
    return {
        "__hash_domain__": PLAN_DOMAIN,
        "supervision_id": supervision_id,
        "objective_id": objective_id,
        "transaction_id": transaction_id,
        "target_module_id": target_module_id,
        "operation": operation,
        "routes": [dict(route) for route in routes],
        "circuit_threshold": circuit_threshold,
    }


def event_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "__hash_domain__": EVENT_DOMAIN,
        "event_id": str(row["event_id"]),
        "supervision_id": str(row["supervision_id"]),
        "route_index": int(row["route_index"]),
        "authorization_id": str(row["authorization_id"]),
        "adapter_id": str(row["adapter_id"]),
        "event_type": str(row["event_type"]),
        "failure_class": row["failure_class"],
        "measured_wall_ms": row["measured_wall_ms"],
        "measured_tokens": row["measured_tokens"],
        "measured_cost_micros": row["measured_cost_micros"],
        "checkpoint_ref": row["checkpoint_ref"],
        "checkpoint_sha256": row["checkpoint_sha256"],
        "run_id": row["run_id"],
        "evidence_id": row["evidence_id"],
    }


class WorkerSupervisorAuthority:
    """Sole owner of supervision plans and attempt events."""

    module_id = "cis.execution.worker_supervisor"
    owned_authority = ("worker_supervision_plans", "worker_attempt_events")

    def __init__(self, store: AuthorityStore) -> None:
        self._store = store
        self._authorizations = AuthorizationAuthority(store)

    def get_plan(self, supervision_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM worker_supervision_plans WHERE supervision_id = ?",
            (supervision_id,))

    def routes(self, plan: Mapping[str, Any]) -> list[dict[str, Any]]:
        try:
            raw = json.loads(str(plan["routes_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise WorkerSupervisionRefused(
                "supervision routes are not valid JSON") from exc
        if canonical_json(raw) != str(plan["routes_json"]):
            raise WorkerSupervisionRefused(
                "supervision routes are not canonical JSON")
        return [_route(item) for item in raw]

    def verify_plan(self, supervision_id: str) -> Row:
        row = self.get_plan(supervision_id)
        if row is None:
            raise WorkerSupervisionRefused(
                "no such supervision plan", supervision_id=supervision_id)
        if str(row["hash_domain"]) != PLAN_DOMAIN:
            raise WorkerSupervisionRefused("unknown supervision plan domain")
        routes = self.routes(row)
        payload = plan_payload(
            supervision_id=str(row["supervision_id"]),
            objective_id=str(row["objective_id"]),
            transaction_id=str(row["transaction_id"]),
            target_module_id=str(row["target_module_id"]),
            operation=str(row["operation"]), routes=routes,
            circuit_threshold=int(row["circuit_threshold"]))
        if sha256_hex(payload) != str(row["plan_hash"]):
            raise WorkerSupervisionRefused(
                "supervision plan digest does not recompute")
        if len(routes) != int(row["route_count"]):
            raise WorkerSupervisionRefused("supervision route count disagrees")
        return row

    def create_plan(self, routes: Sequence[Mapping[str, Any]], *,
                    circuit_threshold: int) -> Row:
        normalized = [_route(route) for route in routes]
        if not normalized or len(normalized) > MAX_ROUTES:
            raise WorkerSupervisionRefused(
                "route count is outside the closed bound", max_routes=MAX_ROUTES)
        if circuit_threshold < 1 or circuit_threshold > len(normalized):
            raise WorkerSupervisionRefused(
                "circuit threshold must fit inside the route count")
        ids = [route["authorization_id"] for route in normalized]
        if len(set(ids)) != len(ids):
            raise WorkerSupervisionRefused(
                "every fallback route requires a distinct authorization")

        rows: list[Row] = []
        for authorization_id in ids:
            source = self._authorizations.get(authorization_id)
            if source is None:
                raise WorkerSupervisionRefused(
                    "route names an unknown authorization",
                    authorization_id=authorization_id)
            if str(source["verdict"]) != ALLOW:
                raise WorkerSupervisionRefused(
                    "route authorization is not ALLOW",
                    authorization_id=authorization_id)
            try:
                verified = self._authorizations.verify(
                    authorization_id,
                    baseline_hash=str(source["baseline_hash"]),
                    active_objective_id=str(source["objective_id"]))
            except Exception as exc:
                raise WorkerSupervisionRefused(
                    "route authorization did not independently verify",
                    authorization_id=authorization_id) from exc
            rows.append(verified)

        first = rows[0]
        identity = (
            str(first["objective_id"]), str(first["transaction_id"]),
            str(first["target_module_id"]), str(first["operation"]))
        for row in rows[1:]:
            if (str(row["objective_id"]), str(row["transaction_id"]),
                    str(row["target_module_id"]), str(row["operation"])) != identity:
                raise WorkerSupervisionRefused(
                    "fallback routes do not govern the same work")

        semantic = {
            "objective_id": identity[0], "transaction_id": identity[1],
            "target_module_id": identity[2], "operation": identity[3],
            "routes": normalized, "circuit_threshold": circuit_threshold,
        }
        supervision_id = "wsp-" + sha256_hex(semantic)[:16]
        payload = plan_payload(
            supervision_id=supervision_id, objective_id=identity[0],
            transaction_id=identity[1], target_module_id=identity[2],
            operation=identity[3], routes=normalized,
            circuit_threshold=circuit_threshold)
        digest = sha256_hex(payload)
        existing = self.get_plan(supervision_id)
        if existing is not None:
            existing = self.verify_plan(supervision_id)
            if str(existing["plan_hash"]) != digest:
                raise WorkerSupervisionRefused(
                    "supervision plan retry disagrees with its recorded plan")
            return existing
        return self._store.insert("worker_supervision_plans", {
            "supervision_id": supervision_id, "objective_id": identity[0],
            "transaction_id": identity[1], "target_module_id": identity[2],
            "operation": identity[3], "routes_json": canonical_json(normalized),
            "route_count": len(normalized),
            "circuit_threshold": circuit_threshold,
            "hash_domain": PLAN_DOMAIN, "plan_hash": digest,
            "created_at": self._store.now(), "seq": self._store.next_seq(),
        })

    def events(self, supervision_id: str) -> list[Row]:
        return self._store.query(
            "SELECT * FROM worker_attempt_events WHERE supervision_id = ? "
            "ORDER BY seq", (supervision_id,))

    def _route_for(self, plan: Mapping[str, Any], route_index: int) -> dict[str, Any]:
        routes = self.routes(plan)
        if route_index < 0 or route_index >= len(routes):
            raise WorkerSupervisionRefused("route index is outside the plan")
        return routes[route_index]

    def resolve_route(self, supervision_id: str, route_index: int) -> dict[str, Any]:
        """Read-only: verify the plan and return its exact canonical route.

        This is the one seam a gateway's supervision-route resolver may be
        bound to. It mints no authorization, invents no route and advances
        no state — it only re-verifies and re-reads what ``create_plan``
        already recorded.
        """
        plan = self.verify_plan(supervision_id)
        return self._route_for(plan, route_index)

    def _event(self, *, plan: Mapping[str, Any], route_index: int,
               event_type: str, failure_class: str | None = None,
               measured_wall_ms: int | None = None,
               measured_tokens: int | None = None,
               measured_cost_micros: int | None = None,
               checkpoint_ref: str | None = None,
               checkpoint_sha256: str | None = None,
               run_id: str | None = None,
               evidence_id: str | None = None) -> Row:
        route = self._route_for(plan, route_index)
        raw = {
            "supervision_id": str(plan["supervision_id"]),
            "route_index": route_index,
            "authorization_id": route["authorization_id"],
            "adapter_id": route["adapter_id"], "event_type": event_type,
            "failure_class": failure_class,
            "measured_wall_ms": measured_wall_ms,
            "measured_tokens": measured_tokens,
            "measured_cost_micros": measured_cost_micros,
            "checkpoint_ref": checkpoint_ref,
            "checkpoint_sha256": checkpoint_sha256,
            "run_id": run_id, "evidence_id": evidence_id,
        }
        event_id = "wse-" + sha256_hex(raw)[:20]
        row = {"event_id": event_id, **raw}
        digest = sha256_hex(event_payload(row))
        existing = self._store.one(
            "SELECT * FROM worker_attempt_events WHERE event_id = ?", (event_id,))
        if existing is not None:
            if str(existing["event_hash"]) != digest:
                raise WorkerSupervisionRefused(
                    "attempt-event retry disagrees with its recorded event")
            return existing
        return self._store.insert("worker_attempt_events", {
            **row, "hash_domain": EVENT_DOMAIN, "event_hash": digest,
            "created_at": self._store.now(), "seq": self._store.next_seq(),
        })

    def _state(self, supervision_id: str, route_index: int) -> tuple[bool, bool]:
        events = self.events(supervision_id)
        started = any(int(e["route_index"]) == route_index
                      and e["event_type"] == "STARTED" for e in events)
        terminal = any(int(e["route_index"]) == route_index
                       and e["event_type"] in ("SUCCEEDED", "FAILED")
                       for e in events)
        return started, terminal

    def start(self, supervision_id: str, route_index: int) -> Row:
        plan = self.verify_plan(supervision_id)
        events = self.events(supervision_id)
        if any(e["event_type"] == "CIRCUIT_OPEN" for e in events):
            raise WorkerSupervisionRefused("the supervision circuit is open")
        existing = next((e for e in events if int(e["route_index"]) == route_index
                         and e["event_type"] == "STARTED"), None)
        if existing is not None:
            return existing
        for prior in range(route_index):
            _, terminal = self._state(supervision_id, prior)
            if not terminal:
                raise WorkerSupervisionRefused(
                    "only the next ordered fallback route may start")
        if route_index > 0:
            prior_terminal = next(
                e for e in events if int(e["route_index"]) == route_index - 1
                and e["event_type"] in ("SUCCEEDED", "FAILED"))
            if prior_terminal["event_type"] != "FAILED":
                raise WorkerSupervisionRefused(
                    "a successful attempt ends fallback routing")
        return self._event(plan=plan, route_index=route_index,
                           event_type="STARTED")

    def checkpoint(self, supervision_id: str, route_index: int, *,
                   checkpoint_ref: str, checkpoint_sha256: str) -> Row:
        plan = self.verify_plan(supervision_id)
        started, terminal = self._state(supervision_id, route_index)
        if not started or terminal:
            raise WorkerSupervisionRefused(
                "a checkpoint requires an active attempt")
        if not checkpoint_ref.strip() or len(checkpoint_sha256) != 64:
            raise WorkerSupervisionRefused("checkpoint identity is invalid")
        return self._event(
            plan=plan, route_index=route_index, event_type="CHECKPOINT",
            checkpoint_ref=checkpoint_ref,
            checkpoint_sha256=checkpoint_sha256)

    def finish(self, supervision_id: str, route_index: int, *, succeeded: bool,
               measured_wall_ms: int, measured_tokens: int,
               measured_cost_micros: int, failure_class: str | None = None,
               run_id: str | None = None, evidence_id: str | None = None) -> Row:
        plan = self.verify_plan(supervision_id)
        route = self._route_for(plan, route_index)
        started, terminal = self._state(supervision_id, route_index)
        if not started:
            raise WorkerSupervisionRefused("an unstarted attempt cannot finish")
        if min(measured_wall_ms, measured_tokens, measured_cost_micros) < 0:
            raise WorkerSupervisionRefused("measured usage cannot be negative")
        expected_failure = None
        if measured_wall_ms > route["wall_time_ms"]:
            expected_failure = "timeout"
        elif (measured_tokens > route["token_limit"]
              or measured_cost_micros > route["cost_limit_micros"]):
            expected_failure = "budget_exhausted"
        if succeeded:
            if failure_class is not None or expected_failure is not None:
                raise WorkerSupervisionRefused(
                    "an over-budget or classified attempt cannot succeed")
            run = self._store.one("SELECT * FROM backend_runs WHERE run_id = ?",
                                  (run_id,)) if run_id else None
            if (run is None or str(run["authorization_id"])
                    != route["authorization_id"]
                    or str(run["adapter_id"]) != route["adapter_id"]
                    or str(run["status"]) != "completed"
                    or str(run["evidence_id"]) != str(evidence_id)):
                raise WorkerSupervisionRefused(
                    "success is not bound to a completed gateway run and evidence")
            event_type = "SUCCEEDED"
        else:
            if failure_class not in FAILURE_CLASSES:
                raise WorkerSupervisionRefused("failure class is not in the closed taxonomy")
            if expected_failure is not None and failure_class != expected_failure:
                raise WorkerSupervisionRefused(
                    "measured budget breach disagrees with failure class",
                    expected=expected_failure, received=failure_class)
            if run_id is not None:
                run = self._store.one(
                    "SELECT * FROM backend_runs WHERE run_id = ?", (run_id,))
                if (run is None or str(run["authorization_id"])
                        != route["authorization_id"]
                        or str(run["adapter_id"]) != route["adapter_id"]
                        or str(run["status"]) != FAILED
                        or str(run["evidence_id"]) != str(evidence_id)):
                    raise WorkerSupervisionRefused(
                        "failure is not bound to this route's exact failed "
                        "gateway run and evidence")
            event_type = "FAILED"
        if terminal:
            existing = next(
                e for e in self.events(supervision_id)
                if int(e["route_index"]) == route_index
                and e["event_type"] in ("SUCCEEDED", "FAILED"))
            candidate_raw = {
                "supervision_id": str(plan["supervision_id"]),
                "route_index": route_index,
                "authorization_id": route["authorization_id"],
                "adapter_id": route["adapter_id"], "event_type": event_type,
                "failure_class": failure_class,
                "measured_wall_ms": measured_wall_ms,
                "measured_tokens": measured_tokens,
                "measured_cost_micros": measured_cost_micros,
                "checkpoint_ref": None, "checkpoint_sha256": None,
                "run_id": run_id, "evidence_id": evidence_id,
            }
            candidate_id = "wse-" + sha256_hex(candidate_raw)[:20]
            if candidate_id != existing["event_id"]:
                raise WorkerSupervisionRefused(
                    "attempt already has a different terminal event")
            return existing
        result = self._event(
            plan=plan, route_index=route_index, event_type=event_type,
            failure_class=failure_class, measured_wall_ms=measured_wall_ms,
            measured_tokens=measured_tokens,
            measured_cost_micros=measured_cost_micros,
            run_id=run_id, evidence_id=evidence_id)
        if event_type == "FAILED":
            terminals = [e for e in self.events(supervision_id)
                         if e["event_type"] in ("SUCCEEDED", "FAILED")]
            consecutive = 0
            for item in reversed(terminals):
                if item["event_type"] != "FAILED":
                    break
                consecutive += 1
            if consecutive >= int(plan["circuit_threshold"]):
                self._event(plan=plan, route_index=route_index,
                            event_type="CIRCUIT_OPEN")
        return result


#: The six typed ``ExecutionRefused`` subclasses the gateway may raise before
#: a run is ever recorded, mapped exactly onto the closed failure taxonomy.
#: Any other ``ExecutionRefused`` — a malformed route, an unbound resolver, a
#: replayed authorization — is a structural refusal, not a worker failure: it
#: is deliberately absent from this map so it propagates and fails closed.
_FAILURE_CLASS_BY_EXCEPTION: dict[type, str] = {
    ExecutionTimedOut: "timeout",
    ExecutionBudgetExhausted: "budget_exhausted",
    ExecutionPermissionWaitRefused: "permission_wait",
    ExecutionProviderFailure: "network_or_provider_failure",
    ExecutionOutputIncomplete: "empty_or_incomplete_output",
    ExecutionArtifactInvalid: "invalid_artifacts",
}

_EMPTY_MEASURED = {
    "measured_wall_ms": 0, "measured_tokens": 0, "measured_cost_micros": 0,
}


def _measured_from_exception(exc: Exception) -> dict[str, int]:
    """The only usage ever measured by the time one of the six typed
    refusals is raised: a timeout knows the wall time it overran by, a
    budget exhaustion knows the tokens or cost it overran by, and every
    other typed refusal fires before any dimension was measured at all."""
    if isinstance(exc, ExecutionTimedOut):
        return {**_EMPTY_MEASURED,
                "measured_wall_ms": int(exc.detail.get("measured_wall_time_ms", 0))}
    if isinstance(exc, ExecutionBudgetExhausted):
        return {**_EMPTY_MEASURED,
                "measured_tokens": int(exc.detail.get("measured_tokens", 0)),
                "measured_cost_micros": int(exc.detail.get("measured_cost_micros", 0))}
    return dict(_EMPTY_MEASURED)


def _usage_from_evidence(evidence_row: Mapping[str, Any] | None, *,
                         run_id: str, authorization_id: str) -> dict[str, int]:
    """Independently read and validate the exact usage mapping the gateway
    bound into a supervised run's evidence content, rather than trusting any
    in-memory copy that may not have survived an interruption."""
    if evidence_row is None:
        raise WorkerSupervisionRefused(
            "a resumed run has no recorded evidence to read usage from",
            run_id=run_id)
    content_text = str(evidence_row["content"])
    if (sha256_text(content_text) != str(evidence_row["content_hash"])
            or str(evidence_row["kind"]) != "execution_evidence"
            or str(evidence_row["source_ref"]) != f"backend_runs:{run_id}"
            or str(evidence_row["admission_basis"])
            != f"verified_execution_authorization:{authorization_id}"):
        raise WorkerSupervisionRefused(
            "a resumed run's evidence integrity or provenance does not verify",
            run_id=run_id)
    try:
        content = json.loads(content_text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise WorkerSupervisionRefused(
            "a resumed run's evidence content is not valid JSON",
            run_id=run_id) from exc
    usage = content.get("usage") if isinstance(content, Mapping) else None
    if (not isinstance(usage, Mapping)
            or set(usage) != {"wall_time_ms", "tokens_used", "cost_micros"}
            or any(not isinstance(value, int) or isinstance(value, bool)
                   or value < 0 for value in usage.values())):
        raise WorkerSupervisionRefused(
            "a resumed run's evidence does not carry valid recorded usage",
            run_id=run_id)
    return {
        "measured_wall_ms": int(usage["wall_time_ms"]),
        "measured_tokens": int(usage["tokens_used"]),
        "measured_cost_micros": int(usage["cost_micros"]),
    }


class SupervisedExecutionCoordinator:
    """Bounded, resumable retry/fallback walk over an existing supervision
    plan.

    This is deliberately thin: every decision it makes is derived from what
    ``WorkerSupervisorAuthority`` and the gateway already recorded. It mints
    no authorization, invents no route, changes no budget, retries no single
    authorization, and never verifies, reviews or promotes anything — it
    only starts the next ordered route, dispatches it exactly once through
    the gateway's existing supervised path, and records the one outcome that
    path or its own durable evidence produces.
    """

    def __init__(self, *, supervisor: WorkerSupervisorAuthority,
                 gateway: ExecutionGateway, runs: RunAuthority,
                 evidence: EvidenceAuthority) -> None:
        self._supervisor = supervisor
        self._gateway = gateway
        self._runs = runs
        self._evidence = evidence

    def run(self, supervision_id: str, *, baseline_hash: str,
            active_objective_id: str | None) -> dict[str, Any]:
        plan = self._supervisor.verify_plan(supervision_id)
        routes = self._supervisor.routes(plan)

        attempted: list[int] = []
        failure_classes: dict[int, str] = {}

        # Replay only the already-terminal prefix the ledger recorded on an
        # earlier run of this coordinator. Terminal events are never
        # re-dispatched; this loop only reads them.
        current = self._supervisor.events(supervision_id)
        for route_index in range(len(routes)):
            terminal = self._terminal_event(current, route_index)
            if terminal is None:
                break
            attempted.append(route_index)
            if terminal["event_type"] == "SUCCEEDED":
                return self._summary(
                    supervision_id, "SUCCEEDED", attempted, failure_classes,
                    route_index=route_index, run_id=terminal["run_id"],
                    evidence_id=terminal["evidence_id"])
            failure_classes[route_index] = str(terminal["failure_class"])

        # An open circuit only changes the outcome while a route still
        # remains that it would otherwise block; if every route is already
        # terminal there is nothing left for it to prevent, so a circuit
        # that happened to open on the very last failure is reported as
        # plain route exhaustion rather than CIRCUIT_OPEN.
        if len(attempted) < len(routes) and self._circuit_open(current):
            return self._summary(
                supervision_id, "CIRCUIT_OPEN", attempted, failure_classes)

        for route_index in range(len(attempted), len(routes)):
            attempted.append(route_index)
            terminal = self._attempt_route(
                supervision_id, route_index, routes[route_index],
                baseline_hash=baseline_hash,
                active_objective_id=active_objective_id)
            if terminal["event_type"] == "SUCCEEDED":
                return self._summary(
                    supervision_id, "SUCCEEDED", attempted, failure_classes,
                    route_index=route_index, run_id=terminal["run_id"],
                    evidence_id=terminal["evidence_id"])
            failure_classes[route_index] = str(terminal["failure_class"])
            has_next_route = route_index < len(routes) - 1
            if has_next_route and self._circuit_open(
                    self._supervisor.events(supervision_id)):
                return self._summary(
                    supervision_id, "CIRCUIT_OPEN", attempted, failure_classes)

        return self._summary(
            supervision_id, "EXHAUSTED", attempted, failure_classes)

    # -- one route ------------------------------------------------------

    def _attempt_route(self, supervision_id: str, route_index: int,
                       route: Mapping[str, Any], *, baseline_hash: str,
                       active_objective_id: str | None) -> Row:
        self._supervisor.start(supervision_id, route_index)
        authorization_id = str(route["authorization_id"])
        claim = self._runs.claim_for_authorization(authorization_id)
        if claim is not None:
            # One verified ALLOW authorizes one attempted boundary crossing;
            # a claim already exists, so redispatching would only earn the
            # gateway's own replay refusal. Resume from whatever the claim
            # left behind instead of trying again.
            existing_runs = self._runs.for_authorization(authorization_id)
            if not existing_runs:
                return self._supervisor.finish(
                    supervision_id, route_index, succeeded=False,
                    failure_class="empty_or_incomplete_output",
                    **_EMPTY_MEASURED)
            return self._resume_from_run(
                supervision_id, route_index, existing_runs[0])

        gateway = self._gateway.using(str(route["adapter_id"])) \
            .with_supervision_resolver(self._supervisor.resolve_route)
        try:
            result = gateway.dispatch_supervised(
                supervision_id, route_index, baseline_hash=baseline_hash,
                active_objective_id=active_objective_id)
        except tuple(_FAILURE_CLASS_BY_EXCEPTION) as exc:
            failure_class = _FAILURE_CLASS_BY_EXCEPTION[type(exc)]
            return self._supervisor.finish(
                supervision_id, route_index, succeeded=False,
                failure_class=failure_class,
                **_measured_from_exception(exc))
        return self._finish_from_result(supervision_id, route_index, result)

    def _finish_from_result(self, supervision_id: str, route_index: int,
                            result: Mapping[str, Any]) -> Row:
        usage = result.get("usage")
        if (not isinstance(usage, Mapping)
                or set(usage) != {"wall_time_ms", "tokens_used", "cost_micros"}
                or any(not isinstance(value, int) or isinstance(value, bool)
                       or value < 0 for value in usage.values())):
            raise WorkerSupervisionRefused(
                "supervised gateway result carries malformed measured usage")
        measured = {
            "measured_wall_ms": usage["wall_time_ms"],
            "measured_tokens": usage["tokens_used"],
            "measured_cost_micros": usage["cost_micros"],
        }
        if str(result["status"]) == COMPLETED:
            return self._supervisor.finish(
                supervision_id, route_index, succeeded=True, **measured,
                run_id=str(result["run_id"]),
                evidence_id=str(result["evidence_id"]))
        return self._supervisor.finish(
            supervision_id, route_index, succeeded=False, **measured,
            failure_class="invalid_artifacts",
            run_id=str(result["run_id"]),
            evidence_id=str(result["evidence_id"]))

    def _resume_from_run(self, supervision_id: str, route_index: int,
                         run: Mapping[str, Any]) -> Row:
        run_id = str(run["run_id"])
        evidence_id = run["evidence_id"]
        evidence_row = (
            self._evidence.get(str(evidence_id)) if evidence_id else None)
        measured = _usage_from_evidence(
            evidence_row, run_id=run_id,
            authorization_id=str(run["authorization_id"]))
        status = str(run["status"])
        if status == COMPLETED:
            return self._supervisor.finish(
                supervision_id, route_index, succeeded=True, **measured,
                run_id=run_id, evidence_id=str(evidence_id))
        if status == FAILED:
            return self._supervisor.finish(
                supervision_id, route_index, succeeded=False, **measured,
                failure_class="invalid_artifacts",
                run_id=run_id, evidence_id=str(evidence_id))
        raise WorkerSupervisionRefused(
            "a resumed run carries an unknown status",
            run_id=run_id, status=status)

    # -- read-only helpers ------------------------------------------------

    @staticmethod
    def _terminal_event(events: Sequence[Mapping[str, Any]],
                        route_index: int) -> Row | None:
        return next(
            (e for e in events if int(e["route_index"]) == route_index
             and e["event_type"] in ("SUCCEEDED", "FAILED")), None)

    @staticmethod
    def _circuit_open(events: Sequence[Mapping[str, Any]]) -> bool:
        return any(e["event_type"] == "CIRCUIT_OPEN" for e in events)

    @staticmethod
    def _summary(supervision_id: str, terminal_status: str,
                attempted: Sequence[int], failure_classes: Mapping[int, str],
                *, route_index: int | None = None,
                run_id: str | None = None,
                evidence_id: str | None = None) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "supervision_id": supervision_id,
            "terminal_status": terminal_status,
            "attempted_route_indexes": list(attempted),
            "failure_classes": dict(failure_classes),
        }
        if route_index is not None:
            summary["successful_route_index"] = route_index
            summary["successful_run_id"] = run_id
            summary["successful_evidence_id"] = evidence_id
        return summary


__all__ = [
    "EVENT_DOMAIN", "FAILURE_CLASSES", "MAX_ROUTES", "PLAN_DOMAIN",
    "SupervisedExecutionCoordinator", "WorkerSupervisorAuthority",
    "event_payload", "plan_payload",
]
