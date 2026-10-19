"""Layer-3 adapters. Replaceable execution infrastructure, never authority."""

from .contained_worker import ContainedWorkerAdapter
from .deterministic_mock import DeterministicMockAdapter

__all__ = ["ContainedWorkerAdapter", "DeterministicMockAdapter"]
