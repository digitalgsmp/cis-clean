"""CIS clean-room reconstruction — vertical slice 1.

A deterministic governed substrate that converts human intent into bounded,
inspectable, evidence-producing execution (handoff A2).

Layering is ADR-SEED-018: L1 control surface -> L2 CIS-owned abstraction ->
L3 replaceable execution infrastructure. Planes (control, trust, deployment,
failure) are declared module properties, never a second hierarchy
(ADR-ARCH-001 clause 2).
"""

__all__ = ["errors", "canonical"]
