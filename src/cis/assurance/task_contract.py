"""The deterministic, template-backed task-contract compiler.

A task contract is the immutable unit of ASSURED work: the thing a verifier
verifies, a reviewer reviews and a promotion decision is recorded against. It
is compiled, never authored by a requester, and it is FROZEN from the moment it
exists.

WHAT THIS MODULE IS AND IS NOT
------------------------------

It is a pure compiler. It holds no store, appends nothing and has no write
path: ``compile`` returns a ``FrozenTaskContract`` value object and
``AssuranceAuthority`` is the module that appends it. That split is deliberate.
A compiler that could also write would be the single place where a widened
contract and the record of it are produced together, and the widening check
would then be guarding its own author.

AN INDEPENDENT HASH DOMAIN
--------------------------

``task_contract_hash`` is sha256 over a canonical payload whose first key is a
literal domain tag, ``cis.assurance.task_contract.v1``. The authorization
binding hash of slice 1 has no domain tag at all, which is exactly why the tag
is needed here: without it, two hash schemes over overlapping facts could
collide in meaning, and a digest minted for one purpose could be presented as
proof of the other. The domain makes the two hash spaces provably disjoint, and
``tests/test_assurance.py`` pins that by hashing the same payload under both
schemes and asserting the digests differ.

The task contract records the authorization's ``binding_hash`` as a FORWARD
LINK rather than recomputing or re-deriving the authorization. Slice-1 tables
are never altered and slice-1 digests are never recomputed under the new
domain; the assurance ledger points at them.

PATH WIDENING
-------------

The template, not the caller, decides the envelope. A template declares a path
envelope as a set of relative roots under the clean environment; the compiler
instantiates it against the target module's own identity and refuses anything
outside it:

  * an absolute path;
  * any path that escapes its root with ``..``;
  * any path outside the module's own compiled subtree;
  * any mention of the read-only reference environment.

A caller may NARROW the compiled envelope by passing ``allowed_paths``; it can
never widen it. That asymmetry is the whole point of ADR-ARCH-004 clause 3: a
model must not expand scope merely by writing a broader contract.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from ..canonical import sha256_hex
from ..errors import ScopeWideningRefused, TaskContractRefused, TaskContractTampered

#: The independent hash domain. Any change to this string is a new contract
#: scheme and invalidates every recorded task-contract digest by design.
TASK_CONTRACT_HASH_DOMAIN = "cis.assurance.task_contract.v1"

#: The only state a task_contracts row may carry. Transitions are DERIVED from
#: the append-only assurance ledger, never written back here (ADR-ARCH-002).
STATE_FROZEN = "FROZEN"

#: The clean environment every compiled path is relative to. Recorded as a
#: relative-root rule rather than an absolute prefix so a task contract is
#: host-independent: this increment performs no host action and must not bake a
#: host path into authority.
CLEAN_ENVIRONMENT_RELATIVE = True

#: Never inside any envelope, at any depth, under any template.
REFERENCE_ENVIRONMENT = "/mnt/projects/cis"


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TaskTemplate:
    """A frozen task-contract template.

    ``path_envelope`` entries are format strings over exactly two names,
    ``{module_path}`` and ``{module_id}``, BOTH of which the compiler derives
    from the authorization's recorded target module. A template can reference
    nothing else, so it cannot widen its own envelope by interpolating caller
    input: there is no name available to it that a caller supplies.
    """

    template_id: str
    operation: str
    path_envelope: tuple[str, ...]
    required_checks: tuple[str, ...]
    required_artifacts: tuple[str, ...]
    forbidden_actions: tuple[str, ...]
    stopping_condition: str
    return_point: str

    def as_dict(self) -> dict:
        return {
            "template_id": self.template_id,
            "operation": self.operation,
            "path_envelope": list(self.path_envelope),
            "required_checks": list(self.required_checks),
            "required_artifacts": list(self.required_artifacts),
            "forbidden_actions": list(self.forbidden_actions),
            "stopping_condition": self.stopping_condition,
            "return_point": self.return_point,
        }

    @property
    def template_hash(self) -> str:
        return sha256_hex(self.as_dict())


#: Baseline forbidden actions every template carries. The reference environment
#: and the network are forbidden in every task contract this increment can
#: compile, and so is any host action — this increment is host-independent.
_ALWAYS_FORBIDDEN = (
    "write:/mnt/projects/cis",
    "network:any",
    "model:any",
    "host:promote",
    "host:restart_service",
    "privilege:escalate",
)

RECONSTRUCT_MODULE_V1 = TaskTemplate(
    template_id="reconstruct_module.v1",
    operation="reconstruct_module",
    path_envelope=(
        "src/{module_path}",
        "contracts/{module_id}.contract.json",
    ),
    required_checks=(
        "task_contract_digest_recomputes",
        "authorization_binding_recomputes",
        "submitted_evidence_present",
        "submitted_evidence_digest_recomputes",
    ),
    required_artifacts=(
        "execution_evidence",
        "run_result_hash",
        "module_contract_hash",
    ),
    forbidden_actions=_ALWAYS_FORBIDDEN,
    stopping_condition=(
        "stop when the declared verification of the target module's own "
        "contract has been recorded, or on the first forbidden action"
    ),
    return_point="assurance:verification_inputs",
)

VERIFY_MODULE_V1 = TaskTemplate(
    template_id="verify_module.v1",
    operation="verify_module",
    path_envelope=("tests/{module_path}",),
    required_checks=(
        "task_contract_digest_recomputes",
        "authorization_binding_recomputes",
        "submitted_evidence_present",
    ),
    required_artifacts=("execution_evidence", "run_result_hash"),
    forbidden_actions=_ALWAYS_FORBIDDEN,
    stopping_condition=(
        "stop when the declared verification command for the target module has "
        "been recorded, or on the first forbidden action"
    ),
    return_point="assurance:verification_inputs",
)

#: Units 2-3 of workstream 4.37. This frozen template names every binding the
#: contained verification and deterministic Verifier now enforce: the
#: execution-input authority itself, candidate, vector contract, entrypoint,
#: worker image, trusted runner, worker and closed result classification. Its
#: required artifacts are the proof values returned by the adapter and then
#: cross-checked against the independently verified execution-input row.
#: Production issuance of the verify_authored_source operation remains a
#: separate integration unit; absence of such an authorization cannot weaken
#: these checks or make another operation eligible for this template.
VERIFY_AUTHORED_SOURCE_V1 = TaskTemplate(
    template_id="verify_authored_source.v1",
    operation="verify_authored_source",
    path_envelope=("tests/{module_path}",),
    required_checks=(
        "task_contract_digest_recomputes",
        "authorization_binding_recomputes",
        "execution_input_binding_recomputes",
        "candidate_source_binding_recomputes",
        "vector_contract_binding_recomputes",
        "authorized_entrypoint_binding_recomputes",
        "worker_image_identity_recomputes",
        "trusted_runner_identity_matches_expected",
        "worker_identity_matches_expected",
        "result_classification_recorded",
    ),
    required_artifacts=(
        "execution_evidence",
        "run_result_hash",
        "execution_input_hash",
        "candidate_source_sha256",
        "vector_contract_sha256",
    ),
    forbidden_actions=_ALWAYS_FORBIDDEN,
    stopping_condition=(
        "stop when verify_authored_source.v1's declared checks have been "
        "recorded against the target module's own task contract, or on the "
        "first forbidden action"
    ),
    return_point="assurance:verification_inputs",
)

TEMPLATES: Mapping[str, TaskTemplate] = {
    template.template_id: template
    for template in (RECONSTRUCT_MODULE_V1, VERIFY_MODULE_V1,
                     VERIFY_AUTHORED_SOURCE_V1)
}


def template(template_id: str) -> TaskTemplate:
    try:
        return TEMPLATES[template_id]
    except KeyError:
        raise TaskContractRefused(
            "no such task-contract template",
            template_id=template_id, known=sorted(TEMPLATES),
        ) from None


# ---------------------------------------------------------------------------
# The compiled value object
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FrozenTaskContract:
    """One immutable compiled task contract.

    ``state`` is ``FROZEN`` and there is no other value: a task contract is not
    a workflow row that advances, it is the fixed subject that the assurance
    ledger records outcomes against.
    """

    task_contract_id: str
    authorization_id: str
    authorization_binding_hash: str
    target_module_id: str
    template_id: str
    template_hash: str
    allowed_paths: tuple[str, ...]
    forbidden_actions: tuple[str, ...]
    required_checks: tuple[str, ...]
    required_artifacts: tuple[str, ...]
    stopping_condition: str
    return_point: str
    state: str = STATE_FROZEN
    hash_domain: str = TASK_CONTRACT_HASH_DOMAIN

    def hash_payload(self) -> dict:
        return task_contract_payload(
            task_contract_id=self.task_contract_id,
            authorization_id=self.authorization_id,
            authorization_binding_hash=self.authorization_binding_hash,
            target_module_id=self.target_module_id,
            template_id=self.template_id,
            template_hash=self.template_hash,
            state=self.state,
            allowed_paths=self.allowed_paths,
            forbidden_actions=self.forbidden_actions,
            required_checks=self.required_checks,
            required_artifacts=self.required_artifacts,
            stopping_condition=self.stopping_condition,
            return_point=self.return_point,
        )

    @property
    def task_contract_hash(self) -> str:
        return sha256_hex(self.hash_payload())

    def as_dict(self) -> dict:
        return {
            "task_contract_id": self.task_contract_id,
            "authorization_id": self.authorization_id,
            "authorization_binding_hash": self.authorization_binding_hash,
            "target_module_id": self.target_module_id,
            "template_id": self.template_id,
            "template_hash": self.template_hash,
            "state": self.state,
            "allowed_paths": list(self.allowed_paths),
            "forbidden_actions": list(self.forbidden_actions),
            "required_checks": list(self.required_checks),
            "required_artifacts": list(self.required_artifacts),
            "stopping_condition": self.stopping_condition,
            "return_point": self.return_point,
            "hash_domain": self.hash_domain,
            "task_contract_hash": self.task_contract_hash,
        }


def task_contract_payload(*, task_contract_id: str, authorization_id: str,
                          authorization_binding_hash: str,
                          target_module_id: str, template_id: str,
                          template_hash: str, state: str,
                          allowed_paths: Sequence[str],
                          forbidden_actions: Sequence[str],
                          required_checks: Sequence[str],
                          required_artifacts: Sequence[str],
                          stopping_condition: str, return_point: str) -> dict:
    """The exact, ordered set of facts a task-contract digest covers.

    ``__hash_domain__`` is part of the payload, not merely of the function
    name, so the digest of a task contract can never equal the digest of any
    other CIS structure over the same facts.
    """
    return {
        "__hash_domain__": TASK_CONTRACT_HASH_DOMAIN,
        "task_contract_id": task_contract_id,
        "authorization_id": authorization_id,
        "authorization_binding_hash": authorization_binding_hash,
        "target_module_id": target_module_id,
        "template_id": template_id,
        "template_hash": template_hash,
        "state": state,
        "allowed_paths": list(allowed_paths),
        "forbidden_actions": list(forbidden_actions),
        "required_checks": list(required_checks),
        "required_artifacts": list(required_artifacts),
        "stopping_condition": stopping_condition,
        "return_point": return_point,
    }


def task_contract_hash(**kwargs: Any) -> str:
    return sha256_hex(task_contract_payload(**kwargs))


def hash_of_row(row: Mapping[str, Any]) -> str:
    """Recompute a stored task contract's digest from the row alone."""
    import json

    return task_contract_hash(
        task_contract_id=str(row["task_contract_id"]),
        authorization_id=str(row["authorization_id"]),
        authorization_binding_hash=str(row["authorization_binding_hash"]),
        target_module_id=str(row["target_module_id"]),
        template_id=str(row["template_id"]),
        template_hash=str(row["template_hash"]),
        state=str(row["state"]),
        allowed_paths=json.loads(str(row["allowed_paths_json"])),
        forbidden_actions=json.loads(str(row["forbidden_actions_json"])),
        required_checks=json.loads(str(row["required_checks_json"])),
        required_artifacts=json.loads(str(row["required_artifacts_json"])),
        stopping_condition=str(row["stopping_condition"]),
        return_point=str(row["return_point"]),
    )


def verify_row(row: Mapping[str, Any]) -> str:
    """Refuse unless a stored task contract recomputes its own digest.

    Three independent refusals, all fail-closed: an unexpected hash domain, a
    state other than FROZEN, and a digest that does not recompute. Any caller
    that is about to rely on a task contract calls this first; the verifier and
    the reviewer each call it separately, from their own code paths, because an
    integrity check performed once and trusted twice is one check.
    """
    domain = str(row["hash_domain"])
    if domain != TASK_CONTRACT_HASH_DOMAIN:
        raise TaskContractTampered(
            "task contract carries an unknown hash domain",
            task_contract_id=str(row["task_contract_id"]),
            recorded=domain, expected=TASK_CONTRACT_HASH_DOMAIN,
        )
    state = str(row["state"])
    if state != STATE_FROZEN:
        raise TaskContractTampered(
            "task contract is not FROZEN",
            task_contract_id=str(row["task_contract_id"]), state=state,
        )
    recomputed = hash_of_row(row)
    if recomputed != str(row["task_contract_hash"]):
        raise TaskContractTampered(
            "task contract digest does not recompute from the stored row",
            task_contract_id=str(row["task_contract_id"]),
            recorded=str(row["task_contract_hash"]), recomputed=recomputed,
        )
    return recomputed


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

def module_path(module_id: str) -> str:
    """The relative subtree a module owns, derived from its id.

    ``cis.workbench.projection`` -> ``cis/workbench/projection``. Derived from
    the structured module id, never from prose, and never from caller input.
    """
    parts = [part for part in module_id.split(".") if part]
    if not parts or any(part in (".", "..") or "/" in part for part in parts):
        raise TaskContractRefused("module id does not form a path",
                                  module_id=module_id)
    return "/".join(parts)


def _normalise(candidate: str) -> str:
    """Refuse anything that is not a clean relative path, else normalise it."""
    text = str(candidate).strip()
    if not text:
        raise ScopeWideningRefused("path is blank", path=candidate)
    if text.startswith("/") or text.startswith("~"):
        raise ScopeWideningRefused(
            "task contract paths are relative to the clean environment; an "
            "absolute path would widen the envelope to the whole host",
            path=candidate,
        )
    if "\\" in text or "\x00" in text:
        raise ScopeWideningRefused("path carries an illegal separator",
                                   path=candidate)
    if REFERENCE_ENVIRONMENT in text:
        raise ScopeWideningRefused(
            "the reference environment is read-only evidence and is never "
            "inside a task-contract envelope",
            path=candidate, reference_environment=REFERENCE_ENVIRONMENT,
        )
    normalised = posixpath.normpath(text)
    if normalised == ".." or normalised.startswith("../") or normalised == ".":
        raise ScopeWideningRefused(
            "path escapes the clean environment", path=candidate,
            normalised=normalised,
        )
    return normalised


def _inside(candidate: str, root: str) -> bool:
    return candidate == root or candidate.startswith(root.rstrip("/") + "/")


class TaskContractCompiler:
    """Compiles a FROZEN task contract from a template and recorded authority.

    The compiler reads the authorization through the authority module that owns
    it and never through SQL of its own, and it calls that module's ``verify``
    so a task contract can only ever be compiled over an authorization that
    still recomputes, is an ALLOW, governs under the active objective, and was
    issued against the current baseline. A task contract over a stale or
    mutated authorization does not come into existence.
    """

    def __init__(self, *, authorizations, blueprint) -> None:
        self._authorizations = authorizations
        self._blueprint = blueprint

    # -- ids ----------------------------------------------------------------

    @staticmethod
    def task_contract_id(authorization_id: str, template_id: str) -> str:
        suffix = sha256_hex({"authorization_id": authorization_id,
                             "template_id": template_id})[:12]
        return f"tc-{suffix}"

    # -- envelope -----------------------------------------------------------

    def envelope_for(self, *, template_id: str, target_module_id: str,
                     ) -> tuple[str, ...]:
        """The compiled path envelope: the widest a contract may ever be."""
        spec = template(template_id)
        relative = module_path(target_module_id)
        return tuple(sorted(
            _normalise(entry.format(module_path=relative,
                                    module_id=target_module_id))
            for entry in spec.path_envelope
        ))

    # -- compilation --------------------------------------------------------

    def compile(self, *, authorization_id: str, template_id: str,
                allowed_paths: Sequence[str] | None = None,
                active_objective_id: str | None) -> FrozenTaskContract:
        """Compile one FROZEN task contract, or refuse.

        ``allowed_paths`` is optional and may only NARROW the compiled
        envelope. Passing a path the envelope does not contain is a widening
        attempt and is refused with ``ScopeWideningRefused``.
        """
        spec = template(template_id)
        row = self._authorizations.verify(
            authorization_id,
            baseline_hash=self._blueprint.baseline_hash,
            active_objective_id=active_objective_id,
        )

        target_module_id = row["target_module_id"]
        if not target_module_id:
            raise TaskContractRefused(
                "authorization names no target module, so there is no subtree "
                "to bound a task contract to",
                authorization_id=authorization_id,
            )
        target_module_id = str(target_module_id)

        scope = self._authorizations.scope_of(row)
        if str(scope["operation"]) != spec.operation:
            raise TaskContractRefused(
                "template operation does not match the authorized operation",
                authorization_id=authorization_id, template_id=template_id,
                template_operation=spec.operation,
                authorized_operation=str(scope["operation"]),
            )

        envelope = self.envelope_for(template_id=template_id,
                                     target_module_id=target_module_id)

        if allowed_paths is None:
            compiled_paths = envelope
        else:
            requested = tuple(_normalise(path) for path in allowed_paths)
            if not requested:
                raise TaskContractRefused(
                    "an explicit allowed_paths list may narrow the envelope "
                    "but may not empty it",
                    authorization_id=authorization_id,
                )
            outside = sorted(
                path for path in requested
                if not any(_inside(path, root) for root in envelope)
            )
            if outside:
                raise ScopeWideningRefused(
                    "requested paths lie outside the compiled template "
                    "envelope; a task contract may narrow its scope and may "
                    "never widen it (ADR-ARCH-004 clause 3)",
                    authorization_id=authorization_id,
                    template_id=template_id,
                    requested=sorted(requested),
                    envelope=list(envelope),
                    outside=outside,
                )
            compiled_paths = tuple(sorted(set(requested)))

        # The forbidden actions are the template's baseline unioned with the
        # authorization's own, so a task contract is never permitted to do
        # something the authorization already forbade.
        forbidden = tuple(sorted(
            set(spec.forbidden_actions) | set(scope["forbidden_actions"])
        ))
        checks = tuple(sorted(
            set(spec.required_checks) | set(scope["required_checks"])
        ))

        return FrozenTaskContract(
            task_contract_id=self.task_contract_id(authorization_id, template_id),
            authorization_id=authorization_id,
            authorization_binding_hash=str(row["binding_hash"]),
            target_module_id=target_module_id,
            template_id=spec.template_id,
            template_hash=spec.template_hash,
            allowed_paths=compiled_paths,
            forbidden_actions=forbidden,
            required_checks=checks,
            required_artifacts=tuple(spec.required_artifacts),
            stopping_condition=spec.stopping_condition,
            return_point=spec.return_point,
        )
