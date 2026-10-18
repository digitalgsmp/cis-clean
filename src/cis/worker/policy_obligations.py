"""Closed semantics for contained-worker policy checks and evidence.

An obligation label is not proof.  This module maps each label the contained
worker advertises to the independently verified facts that must already exist
before that label may be returned.  Container text can contribute only after
the host has checked the complete attestation key set and every expected
value; host facts such as teardown and binding recomputation never originate
in container output.
"""

from __future__ import annotations

from typing import Mapping, AbstractSet

from ..errors import CisError, ExecutionRefused


VERIFIED_FACTS = frozenset({
    "attestation.capabilities_zero",
    "attestation.cgroup_limits_exact",
    "attestation.contract_write_denied",
    "attestation.identity_nonroot",
    "attestation.network_loopback_only",
    "attestation.no_new_privileges",
    "attestation.rootfs_write_denied",
    "attestation.workspace_write_allowed",
    "host.authorization_binding_recomputed",
    "host.candidate_digest_recomputed",
    "host.frozen_task_contract_recomputed",
    "host.image_digest_resolved",
    "host.policy_envelope_recompiled",
    "host.teardown_absence_verified",
})


CHECK_FACTS: Mapping[str, frozenset[str]] = {
    "capabilities_dropped": frozenset({"attestation.capabilities_zero"}),
    "candidate_digest_recomputes": frozenset({
        "host.candidate_digest_recomputed"}),
    "cgroup_limits_measured": frozenset({
        "attestation.cgroup_limits_exact"}),
    "contract_mount_read_only": frozenset({
        "attestation.contract_write_denied"}),
    "frozen_task_contract_bound": frozenset({
        "host.authorization_binding_recomputed",
        "host.frozen_task_contract_recomputed",
    }),
    "network_isolated": frozenset({
        "attestation.network_loopback_only"}),
    "no_new_privileges_measured": frozenset({
        "attestation.no_new_privileges"}),
    "nonroot_identity_recorded": frozenset({
        "attestation.identity_nonroot"}),
    "policy_envelope_bound": frozenset({
        "host.policy_envelope_recompiled"}),
    "read_only_root_filesystem": frozenset({
        "attestation.rootfs_write_denied"}),
    "teardown_verified": frozenset({
        "host.teardown_absence_verified"}),
    "workspace_write_bounded": frozenset({
        "attestation.contract_write_denied",
        "attestation.rootfs_write_denied",
        "attestation.workspace_write_allowed",
    }),
}


EVIDENCE_FACTS: Mapping[str, frozenset[str]] = {
    "candidate_digest_verified": frozenset({
        "host.candidate_digest_recomputed"}),
    "contained_filesystem_bounds_verified": frozenset({
        "attestation.contract_write_denied",
        "attestation.rootfs_write_denied",
        "attestation.workspace_write_allowed",
    }),
    "contained_network_isolation_verified": frozenset({
        "attestation.network_loopback_only"}),
    "contained_privilege_boundary_verified": frozenset({
        "attestation.capabilities_zero",
        "attestation.identity_nonroot",
        "attestation.no_new_privileges",
    }),
    "contained_resource_bounds_verified": frozenset({
        "attestation.cgroup_limits_exact"}),
    "container_teardown_verified": frozenset({
        "host.teardown_absence_verified"}),
    "task_policy_bindings_verified": frozenset({
        "host.authorization_binding_recomputed",
        "host.frozen_task_contract_recomputed",
        "host.policy_envelope_recompiled",
    }),
}


def validate_obligation_mapping(
    checks: Mapping[str, AbstractSet[str]] = CHECK_FACTS,
    evidence: Mapping[str, AbstractSet[str]] = EVIDENCE_FACTS,
    known_facts: AbstractSet[str] = VERIFIED_FACTS,
) -> None:
    """Refuse an empty, duplicate, or unknowable mapping declaration."""
    overlap = sorted(set(checks) & set(evidence))
    if overlap:
        raise CisError("policy check and evidence labels overlap",
                       labels=overlap)
    for kind, mapping in (("check", checks), ("evidence", evidence)):
        for label, requirements in mapping.items():
            if not isinstance(label, str) or not label.strip():
                raise CisError("policy obligation label is invalid", kind=kind)
            if not requirements:
                raise CisError("policy obligation has no proof requirements",
                               kind=kind, label=label)
            unknown = sorted(set(requirements) - set(known_facts))
            if unknown:
                raise CisError("policy obligation references unknown facts",
                               kind=kind, label=label, unknown=unknown)


def satisfied_labels(mapping: Mapping[str, AbstractSet[str]],
                     verified_facts: AbstractSet[str]) -> tuple[str, ...]:
    return tuple(sorted(
        label for label, required in mapping.items()
        if set(required) <= set(verified_facts)
    ))


def verify_required_obligations(*, required_checks: AbstractSet[str],
                                required_evidence: AbstractSet[str],
                                verified_facts: AbstractSet[str]) -> tuple[str, ...]:
    """Verify required labels from facts, returning evidence labels to emit."""
    unknown_checks = sorted(set(required_checks) - set(CHECK_FACTS))
    unknown_evidence = sorted(set(required_evidence) - set(EVIDENCE_FACTS))
    if unknown_checks or unknown_evidence:
        raise ExecutionRefused(
            "contained worker does not implement policy obligations",
            unknown_checks=unknown_checks,
            unknown_evidence=unknown_evidence,
        )
    satisfied_checks = set(satisfied_labels(CHECK_FACTS, verified_facts))
    satisfied_evidence = set(satisfied_labels(EVIDENCE_FACTS, verified_facts))
    missing_checks = sorted(set(required_checks) - satisfied_checks)
    missing_evidence = sorted(set(required_evidence) - satisfied_evidence)
    if missing_checks or missing_evidence:
        raise ExecutionRefused(
            "contained worker could not prove required policy obligations",
            missing_checks=missing_checks,
            missing_evidence=missing_evidence,
        )
    return tuple(sorted(required_evidence))


validate_obligation_mapping()

CONTAINMENT_CHECKS = tuple(sorted(CHECK_FACTS))
PRODUCED_POLICY_EVIDENCE = tuple(sorted(EVIDENCE_FACTS))

__all__ = [
    "CHECK_FACTS", "CONTAINMENT_CHECKS", "EVIDENCE_FACTS",
    "PRODUCED_POLICY_EVIDENCE", "VERIFIED_FACTS", "satisfied_labels",
    "validate_obligation_mapping", "verify_required_obligations",
]
