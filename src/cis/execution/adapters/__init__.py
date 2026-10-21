"""Layer-3 adapters. Replaceable execution infrastructure, never authority."""

from .contained_worker import ContainedWorkerAdapter
from .claude_code import ClaudeCodeAdapter, CodingAgentAdapter
from .coding_agent import CodingAgentController, CodingAgentOutcome
from .deterministic_mock import DeterministicMockAdapter
from .hermes_process import HermesProcessController, HermesProcessResult

__all__ = [
    "ClaudeCodeAdapter", "CodingAgentAdapter", "CodingAgentController",
    "CodingAgentOutcome", "ContainedWorkerAdapter", "DeterministicMockAdapter",
    "HermesProcessController", "HermesProcessResult",
]
