"""Append-only authority for worker-model sessions, requests and their
lifecycle events.

A worker session is opened against an already-verified
``worker_supervision_plans`` route. This module is the sole owner of the
three row shapes migration 0013 defines — session headers, one worker-model
request per route, and the closed lifecycle-event vocabulary — and of every
transition between them: binding an external session, starting,
checkpointing, succeeding or failing a request, and suspending or closing a
session. Every mutation independently re-verifies its governing supervision
route and authorization rather than trusting a prior verdict, and every
event append is idempotent: an identical retry returns the recorded fact, a
disagreeing one refuses rather than silently overwriting it. This authority
never starts or finishes a ``WorkerSupervisorAuthority`` attempt and never
calls the gateway, a provider, an adapter, the verifier, the reviewer or
promotion — it only records what those authorities have already
independently settled.

Migration 0013's ``worker_sessions`` row is a route-bound session leg, not a
durable logical session: its content address includes the supervision route
and adapter, so a fallback to a different route or provider opens a
different row. Migration 0014 adds the durable, provider-neutral logical
session that was missing. This module is also the sole owner of its two row
shapes — ``worker_logical_sessions``, addressed only by
objective/transaction/target/operation/role, and ``worker_session_legs``,
which attaches an existing route-bound session to a logical session at a
strictly positive sequential ordinal. Migration-0013 rows remain immutable
and keep their existing API; they acquire durable continuity only through
explicit attachment, never by inference or backfill.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from ..authority.authorization import ALLOW, AuthorizationAuthority
from ..authority.runs import COMPLETED
from ..authority.store import AuthorityStore, Row
from ..canonical import sha256_hex
from ..errors import CisError, WorkerSessionRefused
from .worker_supervisor import WorkerSupervisorAuthority

SESSION_DOMAIN = "cis.execution.worker_session.header.v1"
REQUEST_DOMAIN = "cis.execution.worker_session.request.v1"
EVENT_DOMAIN = "cis.execution.worker_session.event.v1"
LOGICAL_SESSION_DOMAIN = "cis.execution.worker_session.logical.v1"
LEG_DOMAIN = "cis.execution.worker_session.leg.v1"

LOGICAL_ROLES = frozenset({
    "BRAIN", "MENTOR", "DRAFTER", "IMPLEMENTER", "REVIEWER",
})

EVENT_TYPES = frozenset({
    "SESSION_OPENED", "EXTERNAL_SESSION_BOUND",
    "REQUEST_STARTED", "REQUEST_CHECKPOINTED",
    "REQUEST_SUCCEEDED", "REQUEST_FAILED",
    "SESSION_SUSPENDED", "SESSION_CLOSED",
})

_EVENT_TYPES_REQUIRING_REQUEST = frozenset({
    "EXTERNAL_SESSION_BOUND", "REQUEST_STARTED", "REQUEST_CHECKPOINTED",
    "REQUEST_SUCCEEDED", "REQUEST_FAILED",
})

FAILURE_CLASSES = frozenset({
    "timeout", "budget_exhausted", "permission_wait",
    "network_or_provider_failure", "empty_or_incomplete_output",
    "invalid_artifacts",
})

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _require_sha256(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise WorkerSessionRefused(
            "digest is not a lowercase 64-character sha256", field=field)
    return value


def _require_nonblank(value: str, *, field: str) -> str:
    text = str(value)
    if not text.strip():
        raise WorkerSessionRefused(f"{field} must not be blank", field=field)
    return text


def _check_event_fields(*, event_type: str, request_id: Any,
                        external_session_ref: Any, checkpoint_ref: Any,
                        checkpoint_sha256: Any, run_id: Any,
                        evidence_id: Any, failure_class: Any) -> None:
    """Independently enforce migration 0013's closed vocabulary and its
    conditional-column CHECK constraints in Python, rather than trusting
    that a stored row or a proposed append already satisfies them."""
    if event_type not in EVENT_TYPES:
        raise WorkerSessionRefused(
            "event type is not in the closed vocabulary", event_type=event_type)
    requires_request = event_type in _EVENT_TYPES_REQUIRING_REQUEST
    if requires_request != (request_id is not None):
        raise WorkerSessionRefused(
            "event request binding disagrees with its event type",
            event_type=event_type)
    if (event_type == "EXTERNAL_SESSION_BOUND") != (external_session_ref is not None):
        raise WorkerSessionRefused(
            "external session ref disagrees with its event type",
            event_type=event_type)
    if external_session_ref is not None:
        _require_nonblank(external_session_ref, field="external_session_ref")
    if (event_type == "REQUEST_CHECKPOINTED") != (checkpoint_ref is not None):
        raise WorkerSessionRefused(
            "checkpoint ref disagrees with its event type", event_type=event_type)
    if checkpoint_ref is not None:
        _require_nonblank(checkpoint_ref, field="checkpoint_ref")
    if (event_type == "REQUEST_CHECKPOINTED") != (checkpoint_sha256 is not None):
        raise WorkerSessionRefused(
            "checkpoint digest disagrees with its event type",
            event_type=event_type)
    if checkpoint_sha256 is not None:
        _require_sha256(str(checkpoint_sha256), field="checkpoint_sha256")
    if (event_type == "REQUEST_SUCCEEDED") != (run_id is not None):
        raise WorkerSessionRefused(
            "run binding disagrees with its event type", event_type=event_type)
    if (event_type == "REQUEST_SUCCEEDED") != (evidence_id is not None):
        raise WorkerSessionRefused(
            "evidence binding disagrees with its event type",
            event_type=event_type)
    if (event_type == "REQUEST_FAILED") != (failure_class is not None):
        raise WorkerSessionRefused(
            "failure class disagrees with its event type", event_type=event_type)
    if failure_class is not None and str(failure_class) not in FAILURE_CLASSES:
        raise WorkerSessionRefused(
            "failure class is not in the closed taxonomy",
            failure_class=failure_class)


def session_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "__hash_domain__": SESSION_DOMAIN,
        "session_id": str(row["session_id"]),
        "supervision_id": str(row["supervision_id"]),
        "route_index": int(row["route_index"]),
        "objective_id": str(row["objective_id"]),
        "transaction_id": str(row["transaction_id"]),
        "target_module_id": str(row["target_module_id"]),
        "operation": str(row["operation"]),
        "logical_role": str(row["logical_role"]),
        "adapter_id": str(row["adapter_id"]),
    }


def request_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "__hash_domain__": REQUEST_DOMAIN,
        "request_id": str(row["request_id"]),
        "session_id": str(row["session_id"]),
        "supervision_id": str(row["supervision_id"]),
        "route_index": int(row["route_index"]),
        "authorization_id": str(row["authorization_id"]),
        "adapter_id": str(row["adapter_id"]),
        "wall_time_ms": int(row["wall_time_ms"]),
        "token_limit": int(row["token_limit"]),
        "cost_limit_micros": int(row["cost_limit_micros"]),
        "prompt_sha256": str(row["prompt_sha256"]),
        "context_sha256": str(row["context_sha256"]),
        "response_schema_sha256": str(row["response_schema_sha256"]),
        "ordinal": int(row["ordinal"]),
    }


def event_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "__hash_domain__": EVENT_DOMAIN,
        "event_id": str(row["event_id"]),
        "session_id": str(row["session_id"]),
        "request_id": row["request_id"],
        "event_type": str(row["event_type"]),
        "external_session_ref": row["external_session_ref"],
        "checkpoint_ref": row["checkpoint_ref"],
        "checkpoint_sha256": row["checkpoint_sha256"],
        "run_id": row["run_id"],
        "evidence_id": row["evidence_id"],
        "failure_class": row["failure_class"],
    }


def logical_session_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "__hash_domain__": LOGICAL_SESSION_DOMAIN,
        "logical_session_id": str(row["logical_session_id"]),
        "objective_id": str(row["objective_id"]),
        "transaction_id": str(row["transaction_id"]),
        "target_module_id": str(row["target_module_id"]),
        "operation": str(row["operation"]),
        "logical_role": str(row["logical_role"]),
    }


def leg_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "__hash_domain__": LEG_DOMAIN,
        "leg_id": str(row["leg_id"]),
        "logical_session_id": str(row["logical_session_id"]),
        "session_id": str(row["session_id"]),
        "leg_ordinal": int(row["leg_ordinal"]),
    }


class WorkerSessionAuthority:
    """Sole owner of worker sessions, requests and their events."""

    module_id = "cis.execution.worker_session"
    owned_authority = (
        "worker_sessions", "worker_model_requests", "worker_session_events",
        "worker_logical_sessions", "worker_session_legs",
    )

    def __init__(self, store: AuthorityStore) -> None:
        self._store = store
        self._supervisor = WorkerSupervisorAuthority(store)
        self._authorizations = AuthorizationAuthority(store)

    # -- reads ----------------------------------------------------------

    def get_session(self, session_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM worker_sessions WHERE session_id = ?", (session_id,))

    def get_request(self, request_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM worker_model_requests WHERE request_id = ?",
            (request_id,))

    def events(self, session_id: str) -> list[Row]:
        return self._store.query(
            "SELECT * FROM worker_session_events WHERE session_id = ? "
            "ORDER BY seq", (session_id,))

    def get_logical_session(self, logical_session_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM worker_logical_sessions WHERE logical_session_id = ?",
            (logical_session_id,))

    def get_leg(self, leg_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM worker_session_legs WHERE leg_id = ?", (leg_id,))

    def legs(self, logical_session_id: str) -> list[Row]:
        return self._store.query(
            "SELECT * FROM worker_session_legs WHERE logical_session_id = ? "
            "ORDER BY leg_ordinal", (logical_session_id,))

    # -- verification -----------------------------------------------------

    def verify_session(self, session_id: str) -> Row:
        row = self.get_session(session_id)
        if row is None:
            raise WorkerSessionRefused(
                "no such worker session", session_id=session_id)
        if str(row["hash_domain"]) != SESSION_DOMAIN:
            raise WorkerSessionRefused("unknown worker session domain")
        if str(row["logical_role"]) not in LOGICAL_ROLES:
            raise WorkerSessionRefused(
                "worker session logical role is not in the closed vocabulary",
                logical_role=row["logical_role"])
        if int(row["route_index"]) < 0:
            raise WorkerSessionRefused(
                "worker session route index is negative",
                route_index=row["route_index"])
        digest = sha256_hex(session_payload(row))
        if digest != str(row["session_hash"]):
            raise WorkerSessionRefused(
                "worker session digest does not recompute")
        return row

    def verify_request(self, request_id: str) -> Row:
        row = self.get_request(request_id)
        if row is None:
            raise WorkerSessionRefused(
                "no such worker model request", request_id=request_id)
        if str(row["hash_domain"]) != REQUEST_DOMAIN:
            raise WorkerSessionRefused("unknown worker model request domain")
        for field in ("prompt_sha256", "context_sha256",
                       "response_schema_sha256"):
            _require_sha256(str(row[field]), field=field)
        for field in ("wall_time_ms", "token_limit", "cost_limit_micros"):
            if int(row[field]) <= 0:
                raise WorkerSessionRefused(
                    "worker model request budget must be a positive integer",
                    field=field)
        if int(row["ordinal"]) != 1:
            raise WorkerSessionRefused(
                "worker model request ordinal must be exactly 1",
                ordinal=row["ordinal"])
        digest = sha256_hex(request_payload(row))
        if digest != str(row["request_hash"]):
            raise WorkerSessionRefused(
                "worker model request digest does not recompute")
        return row

    def verify_event(self, event_id: str) -> Row:
        row = self._store.one(
            "SELECT * FROM worker_session_events WHERE event_id = ?",
            (event_id,))
        if row is None:
            raise WorkerSessionRefused(
                "no such worker session event", event_id=event_id)
        if str(row["hash_domain"]) != EVENT_DOMAIN:
            raise WorkerSessionRefused("unknown worker session event domain")
        _check_event_fields(
            event_type=str(row["event_type"]), request_id=row["request_id"],
            external_session_ref=row["external_session_ref"],
            checkpoint_ref=row["checkpoint_ref"],
            checkpoint_sha256=row["checkpoint_sha256"],
            run_id=row["run_id"], evidence_id=row["evidence_id"],
            failure_class=row["failure_class"])
        digest = sha256_hex(event_payload(row))
        if digest != str(row["event_hash"]):
            raise WorkerSessionRefused(
                "worker session event digest does not recompute")
        return row

    def verify_logical_session(self, logical_session_id: str) -> Row:
        row = self.get_logical_session(logical_session_id)
        if row is None:
            raise WorkerSessionRefused(
                "no such worker logical session",
                logical_session_id=logical_session_id)
        if str(row["hash_domain"]) != LOGICAL_SESSION_DOMAIN:
            raise WorkerSessionRefused("unknown worker logical session domain")
        if str(row["logical_role"]) not in LOGICAL_ROLES:
            raise WorkerSessionRefused(
                "worker logical session role is not in the closed vocabulary",
                logical_role=row["logical_role"])
        digest = sha256_hex(logical_session_payload(row))
        if digest != str(row["logical_session_hash"]):
            raise WorkerSessionRefused(
                "worker logical session digest does not recompute")
        return row

    def verify_leg(self, leg_id: str) -> Row:
        row = self.get_leg(leg_id)
        if row is None:
            raise WorkerSessionRefused("no such worker session leg", leg_id=leg_id)
        if str(row["hash_domain"]) != LEG_DOMAIN:
            raise WorkerSessionRefused("unknown worker session leg domain")
        if int(row["leg_ordinal"]) < 1:
            raise WorkerSessionRefused(
                "worker session leg ordinal must be a strictly positive "
                "integer", leg_ordinal=row["leg_ordinal"])
        digest = sha256_hex(leg_payload(row))
        if digest != str(row["leg_hash"]):
            raise WorkerSessionRefused(
                "worker session leg digest does not recompute")
        return row

    # -- shared guards ------------------------------------------------------

    def _refuse_if_closed(self, session_id: str) -> None:
        if any(e["event_type"] == "SESSION_CLOSED"
               for e in self.events(session_id)):
            raise WorkerSessionRefused(
                "session is closed", session_id=session_id)

    def _request_state(self, session_id: str, request_id: str) -> tuple[bool, bool]:
        events = self.events(session_id)
        started = any(e["request_id"] == request_id
                      and e["event_type"] == "REQUEST_STARTED" for e in events)
        terminal = any(e["request_id"] == request_id
                       and e["event_type"] in ("REQUEST_SUCCEEDED", "REQUEST_FAILED")
                       for e in events)
        return started, terminal

    def _existing_terminal_event(self, session_id: str, request_id: str) -> Row:
        """Locate and independently re-verify the recorded terminal event
        (REQUEST_SUCCEEDED or REQUEST_FAILED) for this request. Called only
        once ``_request_state`` has already established that a terminal
        event exists for this request."""
        for event in self.events(session_id):
            if (event["request_id"] == request_id
                    and event["event_type"] in ("REQUEST_SUCCEEDED", "REQUEST_FAILED")):
                return self.verify_event(str(event["event_id"]))
        raise WorkerSessionRefused(
            "request is terminal but no terminal event was found",
            session_id=session_id, request_id=request_id)

    def _verify_session_and_request(self, session_id: str,
                                    request_id: str) -> tuple[Row, Row]:
        """Verify both rows independently, then verify that the request
        belongs to this exact session and its exact supervision route —
        never a route or session the request merely happens to resemble."""
        session = self.verify_session(session_id)
        request = self.verify_request(request_id)
        if (str(request["session_id"]) != session_id
                or str(request["supervision_id"]) != str(session["supervision_id"])
                or int(request["route_index"]) != int(session["route_index"])):
            raise WorkerSessionRefused(
                "worker model request does not belong to this session's "
                "supervision route", session_id=session_id,
                request_id=request_id)
        return session, request

    # -- mutations --------------------------------------------------------

    def _verify_route_authorization(self, route: Mapping[str, Any]) -> Row:
        """Independently re-derive a route's authorization from authority,
        mirroring ``worker_supervisor.create_plan``'s fail-closed pattern.
        This mints no authority; it only refuses to trust a copied verdict."""
        authorization_id = str(route["authorization_id"])
        source = self._authorizations.get(authorization_id)
        if source is None:
            raise WorkerSessionRefused(
                "route names an unknown authorization",
                authorization_id=authorization_id)
        if str(source["verdict"]) != ALLOW:
            raise WorkerSessionRefused(
                "route authorization is not ALLOW",
                authorization_id=authorization_id)
        try:
            return self._authorizations.verify(
                authorization_id,
                baseline_hash=str(source["baseline_hash"]),
                active_objective_id=str(source["objective_id"]))
        except Exception as exc:
            raise WorkerSessionRefused(
                "route authorization did not independently verify",
                authorization_id=authorization_id) from exc

    def _append_event(self, *, session_id: str, event_type: str,
                      request_id: str | None = None,
                      external_session_ref: str | None = None,
                      checkpoint_ref: str | None = None,
                      checkpoint_sha256: str | None = None,
                      run_id: str | None = None,
                      evidence_id: str | None = None,
                      failure_class: str | None = None) -> Row:
        _check_event_fields(
            event_type=event_type, request_id=request_id,
            external_session_ref=external_session_ref,
            checkpoint_ref=checkpoint_ref, checkpoint_sha256=checkpoint_sha256,
            run_id=run_id, evidence_id=evidence_id,
            failure_class=failure_class)

        raw = {
            "session_id": session_id, "request_id": request_id,
            "event_type": event_type,
            "external_session_ref": external_session_ref,
            "checkpoint_ref": checkpoint_ref,
            "checkpoint_sha256": checkpoint_sha256,
            "run_id": run_id, "evidence_id": evidence_id,
            "failure_class": failure_class,
        }
        event_id = "wsev-" + sha256_hex(raw)[:20]
        row = {"event_id": event_id, **raw}
        digest = sha256_hex(event_payload(row))

        existing = self._store.one(
            "SELECT * FROM worker_session_events WHERE event_id = ?",
            (event_id,))
        if existing is not None:
            existing = self.verify_event(event_id)
            if event_payload(existing) != event_payload(row):
                raise WorkerSessionRefused(
                    "worker session event retry disagrees with its "
                    "recorded event", event_id=event_id)
            return existing

        try:
            return self._store.insert("worker_session_events", {
                **row, "hash_domain": EVENT_DOMAIN, "event_hash": digest,
                "created_at": self._store.now(), "seq": self._store.next_seq(),
            })
        except CisError as exc:
            raise WorkerSessionRefused(
                "worker session event was refused by the append-only store",
                event_id=event_id, event_type=event_type) from exc

    def open_session(self, supervision_id: str, route_index: int,
                     logical_role: str) -> Row:
        """Open a worker session against an already-verified supervision
        route. This never starts the supervisor's attempt and never
        dispatches anything — it only binds a session header to a route
        whose authorization independently re-verifies as ALLOW."""
        if logical_role not in LOGICAL_ROLES:
            raise WorkerSessionRefused(
                "logical role is not in the closed vocabulary",
                logical_role=logical_role)
        plan = self._supervisor.verify_plan(supervision_id)
        route = self._supervisor.resolve_route(supervision_id, route_index)
        self._verify_route_authorization(route)

        semantic = {
            "supervision_id": str(plan["supervision_id"]),
            "route_index": int(route_index),
            "objective_id": str(plan["objective_id"]),
            "transaction_id": str(plan["transaction_id"]),
            "target_module_id": str(plan["target_module_id"]),
            "operation": str(plan["operation"]),
            "logical_role": logical_role,
            "adapter_id": str(route["adapter_id"]),
        }
        session_id = "wks-" + sha256_hex(semantic)[:16]
        row = {"session_id": session_id, **semantic}
        digest = sha256_hex(session_payload(row))

        existing = self.get_session(session_id)
        if existing is not None:
            existing = self.verify_session(session_id)
            if str(existing["session_hash"]) != digest:
                raise WorkerSessionRefused(
                    "worker session retry disagrees with its recorded "
                    "session", session_id=session_id)
            # A prior open may have written the session header but been
            # interrupted before its SESSION_OPENED event landed; repair
            # that safely rather than leaving the session eventless.
            self._append_event(
                session_id=session_id, event_type="SESSION_OPENED")
            return existing

        inserted = self._store.insert("worker_sessions", {
            **row, "hash_domain": SESSION_DOMAIN, "session_hash": digest,
            "created_at": self._store.now(), "seq": self._store.next_seq(),
        })
        self._append_event(session_id=session_id, event_type="SESSION_OPENED")
        return inserted

    def open_logical_session(self, objective_id: str, transaction_id: str,
                             target_module_id: str, operation: str,
                             logical_role: str) -> Row:
        """Open a durable, provider-neutral logical session. Its content
        address is derived only from the semantic fields that identify
        conversation/work continuity, deliberately excluding any
        supervision plan, route, authorization, adapter, provider or
        external provider session reference — correcting the defect in
        migration 0013's ``worker_sessions``, which this method never
        rewrites or reads."""
        if logical_role not in LOGICAL_ROLES:
            raise WorkerSessionRefused(
                "logical role is not in the closed vocabulary",
                logical_role=logical_role)
        semantic = {
            "objective_id": _require_nonblank(objective_id, field="objective_id"),
            "transaction_id": _require_nonblank(
                transaction_id, field="transaction_id"),
            "target_module_id": _require_nonblank(
                target_module_id, field="target_module_id"),
            "operation": _require_nonblank(operation, field="operation"),
            "logical_role": logical_role,
        }
        logical_session_id = "wkls-" + sha256_hex(semantic)[:16]
        row = {"logical_session_id": logical_session_id, **semantic}
        digest = sha256_hex(logical_session_payload(row))

        existing = self.get_logical_session(logical_session_id)
        if existing is not None:
            existing = self.verify_logical_session(logical_session_id)
            if str(existing["logical_session_hash"]) != digest:
                raise WorkerSessionRefused(
                    "worker logical session retry disagrees with its "
                    "recorded logical session",
                    logical_session_id=logical_session_id)
            return existing

        try:
            return self._store.insert("worker_logical_sessions", {
                **row, "hash_domain": LOGICAL_SESSION_DOMAIN,
                "logical_session_hash": digest,
                "created_at": self._store.now(), "seq": self._store.next_seq(),
            })
        except CisError as exc:
            raise WorkerSessionRefused(
                "worker logical session was refused by the append-only "
                "store", logical_session_id=logical_session_id) from exc

    def attach_route_session(self, logical_session_id: str, session_id: str,
                             leg_ordinal: int) -> Row:
        """Attach an existing route-bound ``worker_sessions`` leg to a
        durable logical session, in strict positive sequential order.
        Independently re-verifies both records; refuses duplicate,
        disagreeing, reordered or cross-objective attachment rather than
        trusting either side's identity. Legacy migration-0013 rows acquire
        durable continuity only through this explicit attachment — there is
        no inferred or automatic backfill."""
        logical = self.verify_logical_session(logical_session_id)
        session = self.verify_session(session_id)

        if (str(logical["objective_id"]), str(logical["transaction_id"]),
                str(logical["target_module_id"]), str(logical["operation"]),
                str(logical["logical_role"])) != (
                str(session["objective_id"]), str(session["transaction_id"]),
                str(session["target_module_id"]), str(session["operation"]),
                str(session["logical_role"])):
            raise WorkerSessionRefused(
                "route session does not match this logical session's "
                "objective, transaction, target module, operation or "
                "logical role", logical_session_id=logical_session_id,
                session_id=session_id)

        if (not isinstance(leg_ordinal, int) or isinstance(leg_ordinal, bool)
                or leg_ordinal < 1):
            raise WorkerSessionRefused(
                "leg ordinal must be a strictly positive integer",
                leg_ordinal=leg_ordinal)

        existing_for_session = self._store.one(
            "SELECT * FROM worker_session_legs WHERE session_id = ?",
            (session_id,))
        if existing_for_session is not None:
            existing_for_session = self.verify_leg(
                str(existing_for_session["leg_id"]))
            if (str(existing_for_session["logical_session_id"])
                    != logical_session_id
                    or int(existing_for_session["leg_ordinal"]) != leg_ordinal):
                raise WorkerSessionRefused(
                    "route session is already attached to a disagreeing "
                    "leg", session_id=session_id)
            return existing_for_session

        expected_ordinal = len(self.legs(logical_session_id)) + 1
        if leg_ordinal != expected_ordinal:
            raise WorkerSessionRefused(
                "leg ordinal is not the next strictly sequential ordinal "
                "for this logical session",
                logical_session_id=logical_session_id,
                leg_ordinal=leg_ordinal, expected_ordinal=expected_ordinal)

        semantic = {
            "logical_session_id": logical_session_id, "session_id": session_id,
            "leg_ordinal": leg_ordinal,
        }
        leg_id = "wksl-" + sha256_hex(semantic)[:20]
        row = {"leg_id": leg_id, **semantic}
        digest = sha256_hex(leg_payload(row))

        existing = self.get_leg(leg_id)
        if existing is not None:
            existing = self.verify_leg(leg_id)
            if str(existing["leg_hash"]) != digest:
                raise WorkerSessionRefused(
                    "worker session leg retry disagrees with its recorded "
                    "leg", leg_id=leg_id)
            return existing

        try:
            return self._store.insert("worker_session_legs", {
                **row, "hash_domain": LEG_DOMAIN, "leg_hash": digest,
                "created_at": self._store.now(), "seq": self._store.next_seq(),
            })
        except CisError as exc:
            raise WorkerSessionRefused(
                "worker session leg was refused by the append-only store",
                leg_id=leg_id) from exc

    def issue_request(self, session_id: str, prompt_sha256: str,
                      context_sha256: str,
                      response_schema_sha256: str) -> Row:
        """Bind one worker-model request to its session's governed route.
        This schema intentionally permits one request per route."""
        prompt_sha256 = _require_sha256(prompt_sha256, field="prompt_sha256")
        context_sha256 = _require_sha256(context_sha256, field="context_sha256")
        response_schema_sha256 = _require_sha256(
            response_schema_sha256, field="response_schema_sha256")

        session = self.verify_session(session_id)
        self._refuse_if_closed(session_id)

        supervision_id = str(session["supervision_id"])
        route_index = int(session["route_index"])
        plan = self._supervisor.verify_plan(supervision_id)
        route = self._supervisor.resolve_route(supervision_id, route_index)
        if (str(plan["objective_id"]), str(plan["transaction_id"]),
                str(plan["target_module_id"]), str(plan["operation"])) != (
                str(session["objective_id"]), str(session["transaction_id"]),
                str(session["target_module_id"]), str(session["operation"])):
            raise WorkerSessionRefused(
                "supervision plan identity no longer matches this session",
                session_id=session_id)
        if str(route["adapter_id"]) != str(session["adapter_id"]):
            raise WorkerSessionRefused(
                "route adapter no longer matches this session",
                session_id=session_id)
        self._verify_route_authorization(route)

        semantic = {
            "session_id": session_id, "supervision_id": supervision_id,
            "route_index": route_index,
            "authorization_id": str(route["authorization_id"]),
            "adapter_id": str(route["adapter_id"]),
            "wall_time_ms": int(route["wall_time_ms"]),
            "token_limit": int(route["token_limit"]),
            "cost_limit_micros": int(route["cost_limit_micros"]),
            "prompt_sha256": prompt_sha256, "context_sha256": context_sha256,
            "response_schema_sha256": response_schema_sha256, "ordinal": 1,
        }
        request_id = "wkreq-" + sha256_hex(semantic)[:16]
        row = {"request_id": request_id, **semantic}
        digest = sha256_hex(request_payload(row))

        existing_for_route = self._store.one(
            "SELECT * FROM worker_model_requests "
            "WHERE supervision_id = ? AND route_index = ?",
            (supervision_id, route_index))
        if existing_for_route is not None:
            existing_for_route = self.verify_request(
                str(existing_for_route["request_id"]))
            if (str(existing_for_route["request_id"]) != request_id
                    or str(existing_for_route["request_hash"]) != digest):
                raise WorkerSessionRefused(
                    "this route already has a disagreeing worker model "
                    "request", supervision_id=supervision_id,
                    route_index=route_index)
            return existing_for_route

        existing = self.get_request(request_id)
        if existing is not None:
            existing = self.verify_request(request_id)
            if str(existing["request_hash"]) != digest:
                raise WorkerSessionRefused(
                    "worker model request retry disagrees with its "
                    "recorded request", request_id=request_id)
            return existing

        return self._store.insert("worker_model_requests", {
            **row, "hash_domain": REQUEST_DOMAIN, "request_hash": digest,
            "created_at": self._store.now(), "seq": self._store.next_seq(),
        })

    # -- lifecycle events -----------------------------------------------

    def bind_external_session(self, session_id: str, request_id: str,
                              external_session_ref: str) -> Row:
        """Record the external (provider-side) session identifier a
        request was dispatched into. Binds no provider, mints nothing."""
        self._verify_session_and_request(session_id, request_id)
        self._refuse_if_closed(session_id)
        ref = _require_nonblank(external_session_ref, field="external_session_ref")
        return self._append_event(
            session_id=session_id, event_type="EXTERNAL_SESSION_BOUND",
            request_id=request_id, external_session_ref=ref)

    def start_request(self, session_id: str, request_id: str) -> Row:
        """Record that a request's attempt has started. This only records
        the fact — it requires the matching ``WorkerSupervisorAuthority``
        STARTED event to already exist, and never creates or duplicates
        supervisor state itself."""
        session, request = self._verify_session_and_request(
            session_id, request_id)
        self._refuse_if_closed(session_id)
        supervision_id = str(request["supervision_id"])
        route_index = int(request["route_index"])
        started = any(
            int(e["route_index"]) == route_index and e["event_type"] == "STARTED"
            for e in self._supervisor.events(supervision_id))
        if not started:
            raise WorkerSessionRefused(
                "worker supervisor has not started this route",
                session_id=session_id, request_id=request_id)
        return self._append_event(
            session_id=session_id, event_type="REQUEST_STARTED",
            request_id=request_id)

    def checkpoint_request(self, session_id: str, request_id: str,
                           checkpoint_ref: str,
                           checkpoint_sha256: str) -> Row:
        """Record a checkpoint for an active, nonterminal request."""
        self._verify_session_and_request(session_id, request_id)
        self._refuse_if_closed(session_id)
        started, terminal = self._request_state(session_id, request_id)
        if not started or terminal:
            raise WorkerSessionRefused(
                "a checkpoint requires an active, nonterminal request",
                session_id=session_id, request_id=request_id)
        ref = _require_nonblank(checkpoint_ref, field="checkpoint_ref")
        digest = _require_sha256(checkpoint_sha256, field="checkpoint_sha256")
        return self._append_event(
            session_id=session_id, event_type="REQUEST_CHECKPOINTED",
            request_id=request_id, checkpoint_ref=ref,
            checkpoint_sha256=digest)

    def succeed_request(self, session_id: str, request_id: str, run_id: str,
                        evidence_id: str) -> Row:
        """Record a request's success. Requires a matching
        ``WorkerSupervisorAuthority`` SUCCEEDED event for the identical
        route, run and evidence, and independently verifies the backend
        run itself is completed and bound to this request's authorization,
        adapter and evidence — never trusting a copied claim of success."""
        session, request = self._verify_session_and_request(
            session_id, request_id)
        self._refuse_if_closed(session_id)
        started, terminal = self._request_state(session_id, request_id)
        if not started:
            raise WorkerSessionRefused(
                "success requires an active, nonterminal request",
                session_id=session_id, request_id=request_id)

        if terminal:
            existing = self._existing_terminal_event(session_id, request_id)
            if (str(existing["event_type"]) != "REQUEST_SUCCEEDED"
                    or str(existing["run_id"]) != str(run_id)
                    or str(existing["evidence_id"]) != str(evidence_id)):
                raise WorkerSessionRefused(
                    "request already has a disagreeing terminal event",
                    session_id=session_id, request_id=request_id)
            return existing

        supervision_id = str(request["supervision_id"])
        route_index = int(request["route_index"])
        matching = any(
            int(e["route_index"]) == route_index
            and e["event_type"] == "SUCCEEDED"
            and str(e["run_id"]) == str(run_id)
            and str(e["evidence_id"]) == str(evidence_id)
            for e in self._supervisor.events(supervision_id))
        if not matching:
            raise WorkerSessionRefused(
                "no matching worker supervisor success for this route, "
                "run and evidence", session_id=session_id,
                request_id=request_id, run_id=run_id,
                evidence_id=evidence_id)

        run = self._store.one(
            "SELECT * FROM backend_runs WHERE run_id = ?", (run_id,))
        if (run is None
                or str(run["status"]) != COMPLETED
                or str(run["authorization_id"]) != str(request["authorization_id"])
                or str(run["adapter_id"]) != str(request["adapter_id"])
                or str(run["evidence_id"]) != str(evidence_id)):
            raise WorkerSessionRefused(
                "backend run is not a completed run bound to this "
                "request's authorization, adapter and evidence",
                session_id=session_id, request_id=request_id, run_id=run_id)

        return self._append_event(
            session_id=session_id, event_type="REQUEST_SUCCEEDED",
            request_id=request_id, run_id=str(run_id),
            evidence_id=str(evidence_id))

    def fail_request(self, session_id: str, request_id: str,
                     failure_class: str) -> Row:
        """Record a request's failure. Requires a matching
        ``WorkerSupervisorAuthority`` FAILED event with the identical
        closed failure class. Migration 0013 permits no run or evidence
        binding on REQUEST_FAILED, so none is recorded here either."""
        session, request = self._verify_session_and_request(
            session_id, request_id)
        self._refuse_if_closed(session_id)
        started, terminal = self._request_state(session_id, request_id)
        if not started:
            raise WorkerSessionRefused(
                "failure requires an active, nonterminal request",
                session_id=session_id, request_id=request_id)
        if failure_class not in FAILURE_CLASSES:
            raise WorkerSessionRefused(
                "failure class is not in the closed taxonomy",
                failure_class=failure_class)

        if terminal:
            existing = self._existing_terminal_event(session_id, request_id)
            if (str(existing["event_type"]) != "REQUEST_FAILED"
                    or str(existing["failure_class"]) != failure_class):
                raise WorkerSessionRefused(
                    "request already has a disagreeing terminal event",
                    session_id=session_id, request_id=request_id)
            return existing

        supervision_id = str(request["supervision_id"])
        route_index = int(request["route_index"])
        matching = any(
            int(e["route_index"]) == route_index
            and e["event_type"] == "FAILED"
            and str(e["failure_class"]) == failure_class
            for e in self._supervisor.events(supervision_id))
        if not matching:
            raise WorkerSessionRefused(
                "no matching worker supervisor failure with this failure "
                "class", session_id=session_id, request_id=request_id,
                failure_class=failure_class)

        return self._append_event(
            session_id=session_id, event_type="REQUEST_FAILED",
            request_id=request_id, failure_class=failure_class)

    def suspend_session(self, session_id: str) -> Row:
        """Record session continuity suspension. A session-level fact only
        — it binds no request and may occur any number of times while the
        session is open; an identical retry is idempotent by construction
        since the event carries no distinguishing data of its own."""
        self.verify_session(session_id)
        self._refuse_if_closed(session_id)
        return self._append_event(
            session_id=session_id, event_type="SESSION_SUSPENDED")

    def close_session(self, session_id: str) -> Row:
        """Close a session. May be called while open; once closed, nothing
        may append except an identical close retry, which this records
        idempotently rather than refusing."""
        self.verify_session(session_id)
        return self._append_event(
            session_id=session_id, event_type="SESSION_CLOSED")


__all__ = [
    "EVENT_DOMAIN", "EVENT_TYPES", "FAILURE_CLASSES", "LEG_DOMAIN",
    "LOGICAL_ROLES", "LOGICAL_SESSION_DOMAIN", "REQUEST_DOMAIN",
    "SESSION_DOMAIN", "WorkerSessionAuthority", "event_payload",
    "leg_payload", "logical_session_payload", "request_payload",
    "session_payload",
]
