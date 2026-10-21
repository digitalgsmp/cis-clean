"""Provider-neutral seam for external coding-agent controllers.

These protocols describe the structural surface any coding-agent controller
must present to :class:`~cis.execution.adapters.claude_code.CodingAgentAdapter`
(or a future non-Claude adapter). They carry no behavior and grant no
authority; they exist only so controller implementations can be swapped
without widening the adapter's trust boundary.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable


@runtime_checkable
class CodingAgentOutcome(Protocol):
    report: Mapping[str, Any]
    exit_code: int
    wall_time_ms: int
    tokens_used: int
    cost_micros: int
    session_id: str


@runtime_checkable
class CodingAgentController(Protocol):
    @property
    def execution_identity(self) -> str:
        """Stable, human-auditable identity of the bound agent and model."""
        ...

    def liveness(self) -> bool:
        """Side-effect-free check that this controller is ready to execute."""
        ...

    def execute(self, *, prompt: str, workspace: str,
                wall_time_ms: int, cost_limit_micros: int) -> CodingAgentOutcome:
        ...
