"""The Workbench-facing control surface (Layer 1).

ADR-SEED-018 governing boundary rule: Layer 1 does not read the spine or any
execution backend directly. This module therefore touches exactly two things —
the Layer-2 Conductor for every state-changing route, and the Layer-2
Workbench service and its projection for read-only ones — and holds no SQL, no
authority table name and no adapter.

Every public mutation enters authority through the Conductor, which is the
single ingress boundary: it is constructed here, it is the only path this
surface has to an instruction or an execution, and it wraps each one in an
immutable envelope. Nothing in this module calls a Workbench mutation method.

The slice-2 assurance increment adds READ-ONLY routes and nothing else. This
module holds the assurance PROJECTION and no reference to the task-contract
compiler, the assurance authority facades, the verifier, the reviewer or the
promotion recorder — so there is no route, and no object reachable from a
route, that can freeze a task contract, record a verification, record a review
or record a promotion decision. Those remain privileged in-process seams for
this increment, for the same reason evidence admission is one.

The surface is a pure function of (method, path, body) so the whole slice is
exercisable without a socket. ``http_server`` is a thin wrapper that adds
transport and nothing else.

Honest boundary statement: this surface has NO caller identity, no
authentication and no authorization of its own. It is a loopback operator
console for a single trusted local operator, and the only reason that is
acceptable is that it binds 127.0.0.1 and exposes no privileged seam —
evidence admission and objective bootstrap are deliberately absent from it.
It is NOT an external-agent endpoint: nothing here proves who the caller is,
so every classification and every actor is derived from the exact operator
words rather than from anything a caller may declare.

Request fields are therefore validated structurally: a route accepts exactly
its declared fields, each must be a string, and anything else is refused with
a code rather than raising.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from ..assurance.projection import AssuranceProjection
from ..conductor import Conductor
from ..errors import CisError
from ..workbench import Workbench


@dataclass(frozen=True)
class ApiResponse:
    status: int
    body: Mapping[str, Any]

    def json(self) -> str:
        return json.dumps(self.body, indent=2, sort_keys=True)


_ROUTES = """
GET  /health                        liveness of the slice
GET  /blueprint                     reconstruction manifest, derived dependency order, baseline
GET  /contracts                     module contracts and registry hash
GET  /objective                     the active objective, derived from authority
POST /instruction                   {"verbatim": "..."}
GET  /authorization/<id>            one recorded authorization
POST /execute                       {"authorization_id": "..."}
GET  /trajectory                    macro projection plus the derived you-are-here marker
GET  /trajectory/<transaction_id>   micro steps for one transaction
GET  /assurance                     assurance progress, declared flow, A-O order reconciliation
GET  /assurance/task/<task_contract_id>  one task contract's derived assurance state
""".strip()


class WorkbenchApi:
    """Read-only routes read the Workbench; every mutation goes through the
    Conductor.

    The Conductor is constructed here rather than accepted as an argument, so
    there is no seam through which a caller could hand in a substitute — or
    none at all — and reach ``Workbench.submit_instruction`` or
    ``Workbench.execute`` without an envelope. This module holds no other
    reference to a Workbench mutation method.
    """

    def __init__(self, workbench: Workbench) -> None:
        self.workbench = workbench
        self.conductor = Conductor(workbench)
        # The assurance increment is reachable from here through its READ
        # MODEL only. The compiler, the authority facades, the verifier, the
        # reviewer and the promotion recorder are deliberately absent from
        # this surface: freezing, verifying, reviewing and promoting are
        # privileged in-process seams in this increment, exactly as evidence
        # admission is, and a route that reached one of them would be a route
        # that could manufacture assurance on request.
        self.assurance = AssuranceProjection.for_service(workbench)

    # -- dispatch -----------------------------------------------------------

    def dispatch(self, method: str, path: str,
                 body: Mapping[str, Any] | None = None) -> ApiResponse:
        method = method.upper()
        path = "/" + path.strip("/")
        body = dict(body or {})

        try:
            return self._route(method, path, body)
        except CisError as exc:
            # Fail closed, and say which rule refused.
            return ApiResponse(409, {"ok": False, "error": exc.as_dict()})
        except KeyError as exc:
            return ApiResponse(400, {"ok": False, "error": {
                "code": "MISSING_FIELD", "message": f"missing field: {exc.args[0]}"}})
        except ValueError as exc:
            return ApiResponse(400, {"ok": False, "error": {
                "code": "INVALID_INPUT", "message": str(exc)}})

    def _route(self, method: str, path: str,
               body: Mapping[str, Any]) -> ApiResponse:
        if (method, path) == ("GET", "/health"):
            return ApiResponse(200, {
                "ok": True,
                "slice": self.workbench.blueprint.document["slice"]["slice_id"],
                "current_stage": self.workbench.blueprint.current_stage,
                "routes": _ROUTES.splitlines(),
            })

        if (method, path) == ("GET", "/blueprint"):
            return ApiResponse(200, {"ok": True,
                                     "blueprint": self.workbench.blueprint.as_summary()})

        if (method, path) == ("GET", "/contracts"):
            registry = self.workbench.blueprint.registry
            return ApiResponse(200, {
                "ok": True,
                "registry_hash": registry.registry_hash,
                "dependency_order": registry.dependency_order(),
                "by_layer": registry.by_layer(),
                "authority_owners": registry.authority_owners(),
                "contracts": {
                    module_id: contract.as_dict()
                    for module_id, contract in sorted(registry.contracts.items())
                },
            })

        if (method, path) == ("GET", "/objective"):
            return ApiResponse(200, {"ok": True,
                                     "objective": self.workbench.active_objective()})

        if (method, path) == ("POST", "/instruction"):
            self._exact_fields(body, {"verbatim"})
            verbatim = self._text(body, "verbatim")
            outcome = self.conductor.ingest_instruction(verbatim)
            return ApiResponse(201, {"ok": True, **outcome.as_dict()})

        if (method, path) == ("POST", "/execute"):
            self._exact_fields(body, {"authorization_id"})
            authorization_id = self._text(body, "authorization_id")
            result = self.conductor.execute_authorization(authorization_id)
            return ApiResponse(200, {"ok": True, "run": result})

        if method == "GET" and path.startswith("/authorization/"):
            authorization_id = path.split("/", 2)[2]
            row = self.workbench.authorizations.get(authorization_id)
            if row is None:
                return ApiResponse(404, {"ok": False, "error": {
                    "code": "NOT_FOUND",
                    "message": "no such authorization",
                    "detail": {"authorization_id": authorization_id}}})
            payload = row.as_dict()
            payload["scope"] = self.workbench.authorizations.scope_of(row)
            payload["runs"] = [
                r.as_dict() for r in self.workbench.runs.for_authorization(authorization_id)
            ]
            return ApiResponse(200, {"ok": True, "authorization": payload})

        if (method, path) == ("GET", "/trajectory"):
            return ApiResponse(200, {"ok": True,
                                     "trajectory": self.workbench.projection.full()})

        if method == "GET" and path.startswith("/trajectory/"):
            transaction_id = path.split("/", 2)[2]
            return ApiResponse(200, {
                "ok": True,
                "trajectory": self.workbench.projection.full(transaction_id),
            })

        if (method, path) == ("GET", "/assurance"):
            return ApiResponse(200, {"ok": True,
                                     "assurance": self.assurance.full()})

        if method == "GET" and path.startswith("/assurance/task/"):
            task_contract_id = path.split("/", 3)[3]
            if self.assurance.authority.ledger.task_contract(
                    task_contract_id) is None:
                return ApiResponse(404, {"ok": False, "error": {
                    "code": "NOT_FOUND",
                    "message": "no such task contract",
                    "detail": {"task_contract_id": task_contract_id}}})
            return ApiResponse(200, {
                "ok": True,
                "assurance": self.assurance.full(task_contract_id),
            })

        return ApiResponse(404, {"ok": False, "error": {
            "code": "NO_ROUTE",
            "message": f"no route for {method} {path}",
            "detail": {"routes": _ROUTES.splitlines()}}})

    @staticmethod
    def _exact_fields(body: Mapping[str, Any], allowed: set[str]) -> None:
        unexpected = sorted(set(body) - allowed)
        if unexpected:
            raise ValueError(
                "unexpected request field(s): " + ", ".join(unexpected)
            )

    @staticmethod
    def _text(body: Mapping[str, Any], name: str) -> str:
        """A declared route field must be a string, or the route refuses.

        Without this, a JSON body carrying ``null``, a number or an object
        reaches code that assumes text and raises an untyped error, which a
        fail-closed control surface must never do: a refusal has to come back
        as an error payload with a code.
        """
        value = body[name]
        if not isinstance(value, str):
            raise ValueError(
                f"field '{name}' must be a string, not "
                f"{type(value).__name__}"
            )
        return value
