"""The CIS-owned Layer-2 execution contract.

ADR-ARCH-003 freezes the minimum replacement boundary:
  1. exactly one CIS-owned Layer-2 module family is the sole call path to any
     execution backend;
  2. nothing above Layer 2 may name a backend, its ports, its file paths, its
     configuration or credential files, or its log format;
  3. backend liveness and credentials are obtained only through a declared
     interface, never by reading the backend's private files or parsing its
     logs;
  4. every module in that family declares a replacement_contract;
  5. acceptance test H1 is the boundary's test.

This module is that contract. An adapter implements ``ExecutionPort`` and
nothing else is required of it; the request and result shapes here are the only
vocabulary the rest of CIS knows. Capability declaration, dispatch semantics,
provider negotiation, streaming, error taxonomy and cost accounting are
explicitly NOT modelled — ADR-ARCH-003 defers all of them, and generalising
from a single backend now would produce documentation above a boundary rather
than a boundary.
"""

from __future__ import annotations

import secrets
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from ..canonical import sha256_hex
from ..errors import CisError, ExecutionRefused


_CAPABILITY_LOCK = threading.Lock()
_CAPABILITIES: dict[str, tuple[str, str]] = {}


def _mint_token(*, binding_hash: str, request_hash: str) -> str:
    """Issue one opaque, single-use in-process execution capability.

    The authorization binding and request digest are server-side state, not
    ingredients from which an untrusted caller can derive a token.  A process
    restart invalidates every outstanding capability, which is fail-closed.
    """
    token = secrets.token_urlsafe(32)
    with _CAPABILITY_LOCK:
        _CAPABILITIES[token] = (binding_hash, request_hash)
    return token


def _consume_token(*, token: str, binding_hash: str, request_hash: str) -> bool:
    with _CAPABILITY_LOCK:
        issued_for = _CAPABILITIES.pop(token, None)
    return issued_for == (binding_hash, request_hash)


@dataclass(frozen=True)
class ExecutionRequest:
    """One bounded unit of authorized work, as the port sees it.

    Every field is derived from the recorded execution authorization. A caller
    cannot widen the scope by passing a wider request: the gateway builds the
    request from authority, never from caller input.
    """

    request_id: str
    operation: str
    allowed_scope: tuple[str, ...]
    forbidden_actions: tuple[str, ...]
    required_checks: tuple[str, ...]
    stopping_condition: str
    return_point: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    token: str | None = None
    binding_hash: str | None = None

    def contract_view(self) -> dict:
        """The hashable view of the request: everything except the token."""
        return {
            "request_id": self.request_id,
            "operation": self.operation,
            "allowed_scope": list(self.allowed_scope),
            "forbidden_actions": list(self.forbidden_actions),
            "required_checks": list(self.required_checks),
            "stopping_condition": self.stopping_condition,
            "return_point": self.return_point,
            "payload": dict(self.payload),
        }

    @property
    def request_hash(self) -> str:
        return sha256_hex(self.contract_view())

    def verify_token(self) -> None:
        """Refuse unless the request carries the token for its own binding.

        The authoritative gate is the gateway, which verifies the recorded
        authorization against authority. This check is the adapter-side half of
        the same rule: a backend that is handed a request with no token, or a
        token minted for different content, refuses to run.
        """
        if not self.token or not self.binding_hash:
            raise ExecutionRefused(
                "execution request carries no authorization token",
                request_id=self.request_id,
            )
        if not _consume_token(
            token=self.token,
            binding_hash=self.binding_hash,
            request_hash=self.request_hash,
        ):
            raise ExecutionRefused(
                "execution token is unknown, spent, or does not match the request",
                request_id=self.request_id,
            )


@dataclass(frozen=True)
class ExecutionResult:
    """What any backend returns. No backend-specific field exists."""

    status: str                      # 'completed' | 'failed'
    exit_code: int
    outputs: Mapping[str, Any]
    checks_performed: tuple[str, ...]
    evidence: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "exit_code": self.exit_code,
            "outputs": dict(self.outputs),
            "checks_performed": list(self.checks_performed),
            "evidence": list(self.evidence),
        }

    def deterministic_view(self) -> dict:
        """Stable semantic result; run-specific evidence is deliberately out."""
        return {
            "status": self.status,
            "exit_code": self.exit_code,
            "outputs": dict(self.outputs),
            "checks_performed": list(self.checks_performed),
        }

    @property
    def result_hash(self) -> str:
        return sha256_hex(self.deterministic_view())


class ExecutionPort(ABC):
    """The interface an execution backend satisfies to be usable by CIS.

    Replacement contract: an implementation is replaceable without changing any
    caller as long as it (a) refuses any request whose token does not verify,
    (b) reports only checks it actually performed, and (c) is deterministic in
    the sense that equal requests produce equal ``result_hash``. Authorization-
    level required checks are independently recomputed by the gateway preflight,
    never copied into an adapter's claims. Nothing else is visible to CIS.
    """

    #: Stable, opaque identifier. CIS records it and never branches on it.
    adapter_id: str = "undefined"
    #: A backend may require the gateway to bind an already-verified frozen
    #: task contract into the token-covered request payload.
    requires_frozen_task_contract: bool = False
    #: A backend may require the gateway to verify a compiled MASTER/TASK
    #: policy envelope — bound to this exact authorization, recomputing its
    #: own digest and current against the live catalog — before adapter
    #: entry. ``policy_enforcement_point`` names which compiled set applies;
    #: it is a declared fact of the adapter, never a dispatch argument.
    requires_policy_envelope: bool = False
    policy_enforcement_point: str | None = None
    #: Closed obligations the adapter deterministically enforces. The gateway
    #: refuses an applicable envelope containing anything outside these sets.
    enforced_policy_prohibitions: tuple[str, ...] = ()
    enforced_policy_checks: tuple[str, ...] = ()
    produced_policy_evidence: tuple[str, ...] = ()

    @abstractmethod
    def capabilities(self) -> Sequence[str]:
        """The operations this backend accepts. Declared, never inferred."""

    @abstractmethod
    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """Run one authorized request, or raise ``ExecutionRefused``."""

    def liveness(self) -> bool:
        """Declared liveness.

        ADR-ARCH-003 clause 3: liveness comes through this declared interface
        and never from reading a backend's private files or parsing its logs.
        """
        return True


class AdapterRegistry:
    """The set of available adapters, keyed by opaque id."""

    def __init__(self) -> None:
        self._adapters: dict[str, ExecutionPort] = {}

    def register(self, adapter: ExecutionPort) -> None:
        if not isinstance(adapter, ExecutionPort):
            raise CisError("adapter does not implement the execution port",
                           adapter=type(adapter).__name__)
        if adapter.adapter_id in self._adapters:
            raise CisError("duplicate adapter_id", adapter_id=adapter.adapter_id)
        self._adapters[adapter.adapter_id] = adapter

    def get(self, adapter_id: str) -> ExecutionPort:
        try:
            return self._adapters[adapter_id]
        except KeyError:
            raise CisError("no adapter registered under this id",
                           adapter_id=adapter_id,
                           registered=sorted(self._adapters)) from None

    def ids(self) -> list[str]:
        return sorted(self._adapters)
