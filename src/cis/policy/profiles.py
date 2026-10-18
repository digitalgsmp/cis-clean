"""Deterministic profile registry: selector facts from trusted sources only.

A compiled policy envelope is selected by project, module, operation and risk
(``cis.policy.schema.SELECTOR_FIELDS``). None of those four may ever come from
a caller: a caller that could name its own risk tier could narrate its way to
a weaker applicable policy set. This module is the one place that derives
``project`` and ``risk`` — from a CLOSED mapping keyed by task-contract
``template_id``, nothing softer — while ``operation`` and ``module`` are read
straight off the frozen task-contract template and the frozen contract's own
``target_module_id``, never independently chosen here.

An unknown ``template_id`` carries no profile. Guessing one would mean
inventing a project or risk tier from nothing, so it refuses
(``PolicyProfileUnknown``) rather than falling back to some default — the same
"no silent default" discipline ``cis.policy.schema.parse_policy`` applies to
an unrecognised effect kind.
"""

from __future__ import annotations

from typing import Mapping

from ..errors import PolicyProfileUnknown
from .schema import PolicySelector

#: The whole closed vocabulary of task-contract templates this registry
#: knows how to profile. ``reconstruct_module.v1``
#: (``cis.assurance.task_contract.RECONSTRUCT_MODULE_V1``) is the only
#: template this increment's gateway path compiles policy for, and it maps to
#: project ``cis`` at risk ``HIGH`` — reconstruction writes real source under
#: the module's own subtree, which is the highest risk tier this schema
#: defines.
PROFILES: Mapping[str, Mapping[str, str]] = {
    "reconstruct_module.v1": {"project": "cis", "risk": "HIGH"},
}


def derive_selector(*, template_id: str, operation: str,
                    target_module_id: str) -> PolicySelector:
    """Derive one policy selector from frozen task-contract facts, or refuse.

    ``template_id`` and ``operation`` are read from the frozen task-contract
    template, and ``target_module_id`` from the frozen task contract's own
    recorded target — none of the three is caller input at this call site.
    """
    profile = PROFILES.get(template_id)
    if profile is None:
        raise PolicyProfileUnknown(
            "no deterministic policy profile exists for this task-contract "
            "template; compiling a selector for it would require guessing "
            "a project or risk tier rather than reading a trusted fact",
            template_id=template_id, known=sorted(PROFILES),
        )
    return PolicySelector(
        project=profile["project"], module=target_module_id,
        operation=operation, risk=profile["risk"],
    )


__all__ = ["PROFILES", "derive_selector"]
