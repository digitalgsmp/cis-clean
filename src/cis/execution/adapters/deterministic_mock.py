"""A deterministic, offline execution backend.

This is Layer 3: replaceable execution infrastructure, not part of the durable
definition of CIS (ADR-ARCH-001 clause 8). It exists so the Layer-2 boundary
has something real to call and so replaceability can be proven rather than
documented — a contract above a backend that cannot be swapped is
documentation, not a boundary (handoff A6).

It performs no I/O, opens no socket, reads no configuration file and consults
no model. "Executing" a reconstruction step means deriving a stable artifact
digest from the authorized request, which is enough to prove the governed path
end to end: equal requests produce equal results, and an unauthorized request
produces nothing at all.
"""

from __future__ import annotations

import hashlib
from typing import Sequence

from ...errors import ExecutionRefused
from ..port import ExecutionPort, ExecutionRequest, ExecutionResult


class DeterministicMockAdapter(ExecutionPort):
    adapter_id = "deterministic_mock"

    #: Declared, not inferred (ADR-ARCH-003 clause 3).
    _CAPABILITIES = ("reconstruct_module", "verify_module")

    def capabilities(self) -> Sequence[str]:
        return self._CAPABILITIES

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        # The adapter-side half of the gate: no valid token, no execution.
        request.verify_token()

        if request.operation not in self._CAPABILITIES:
            raise ExecutionRefused(
                "operation is not declared by this backend",
                operation=request.operation,
            )
        if not request.allowed_scope:
            raise ExecutionRefused(
                "request carries no allowed scope", request_id=request.request_id
            )

        artifact = hashlib.sha256(
            f"{self.adapter_id}/{request.request_hash}".encode("utf-8")
        ).hexdigest()

        evidence = [
            f"operation={request.operation}",
            f"allowed_scope={','.join(request.allowed_scope)}",
            f"forbidden_actions={','.join(request.forbidden_actions)}",
            f"artifact_digest={artifact}",
            f"stopped_at={request.stopping_condition}",
            f"returned_to={request.return_point}",
        ]

        return ExecutionResult(
            status="completed",
            exit_code=0,
            outputs={
                "artifact_digest": artifact,
                "scope_honoured": list(request.allowed_scope),
                "operation": request.operation,
            },
            # Every required check is performed, by construction: this backend
            # refuses rather than skipping one.
            checks_performed=tuple(request.required_checks),
            evidence=tuple(evidence),
        )


class SecondDeterministicAdapter(ExecutionPort):
    """A second backend with the same contract and a different implementation.

    Its only purpose is the replacement proof: registering it and switching to
    it must require no change above the Layer-2 port. It deliberately produces
    a different artifact digest, so a test can tell which backend ran while the
    calling code stays identical.
    """

    adapter_id = "deterministic_alternate"

    _CAPABILITIES = ("reconstruct_module", "verify_module", "dry_run")

    def capabilities(self) -> Sequence[str]:
        return self._CAPABILITIES

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        request.verify_token()
        if request.operation not in self._CAPABILITIES:
            raise ExecutionRefused(
                "operation is not declared by this backend",
                operation=request.operation,
            )
        digest = hashlib.blake2b(
            f"{self.adapter_id}/{request.request_hash}".encode("utf-8"),
            digest_size=32,
        ).hexdigest()
        return ExecutionResult(
            status="completed",
            exit_code=0,
            outputs={"artifact_digest": digest, "operation": request.operation},
            checks_performed=tuple(request.required_checks),
            evidence=(
                f"operation={request.operation}",
                f"artifact_digest={digest}",
            ),
        )
