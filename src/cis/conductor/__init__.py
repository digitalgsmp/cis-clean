"""Layer-2 Conductor: the single ingress-to-evidence boundary for public
mutations from Layer 1.

The Conductor wraps the two existing public write operations — instruction
ingress and authorized execution — in an immutable authority-bound envelope.
It derives the operator identity locally; it does not accept a caller-supplied
actor. Every envelope binds the exact content, the current objective and the
baseline, and links to the intent, authorization and run rows it delegates to.
It copies no verdicts and keeps the existing authority modules as owners of
their own tables.
"""

from __future__ import annotations

from .authority import ConductorAuthority
from .service import Conductor

__all__ = ["Conductor", "ConductorAuthority"]
