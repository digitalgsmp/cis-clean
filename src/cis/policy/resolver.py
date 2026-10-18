"""The automatic policy resolver for policy-governed gateway tasks.

SCOPE, EXACTLY
--------------

This is not universal governance. It is the required callable
``cis.execution.gateway.ExecutionGateway`` uses as its
``policy_envelope_resolver`` whenever the adapter it is about to call
declares ``requires_policy_envelope = True`` — nothing else in CIS routes
through it, and it makes no claim about anything outside that one boundary.

WHAT IT DOES, IN ORDER
-----------------------

Given only an ``authorization_id``:

  1. resolve the FROZEN task contract already bound to that authorization
     (``cis.assurance.authority``) and verify it still recomputes its own
     digest;
  2. derive the one selector the frozen facts permit — project and risk from
     the closed profile registry keyed by template id
     (``cis.policy.profiles``), operation from the template itself, module
     from the frozen contract's own target — never from caller input;
  3. read the CURRENT, whole-set-validated policy set from the append-only
     source ledger (``cis.policy.sources``) and compile one envelope over it
     (``cis.policy.compiler``);
  4. if no envelope is yet recorded for this task contract, append the
     freshly compiled one;
  5. otherwise, verify the already-recorded envelope against the freshly
     compiled envelope's ``policy_set_hash`` — an envelope is NEVER
     overwritten. If policy has changed since the envelope was appended, the
     existing envelope no longer matches and ``PolicyAuthority.resolve``
     raises ``PolicyStale``: the old task contract is stale, and the only way
     forward is a new one.

Nothing here parses prose or consults a model; every input to every decision
is a structured fact already recorded in authority.
"""

from __future__ import annotations

from pathlib import Path

from ..assurance.authority import AssuranceAuthority
from ..assurance.task_contract import template, verify_row
from ..authority.store import AuthorityStore
from ..errors import PolicyRefused
from .authority import PolicyAuthority
from .compiler import compile_envelope
from .profiles import derive_selector
from .source_catalog import DEFAULT_SOURCE_CATALOG, ingest_source_catalog
from .sources import PolicySourceAuthority


class AutomaticPolicyResolver:
    """Compiles and resolves the mandatory policy envelope for one task.

    ``resolve`` is the whole public surface, and its signature —
    ``str -> dict`` — is exactly the ``policy_envelope_resolver`` callable
    ``ExecutionGateway`` already accepts, so a bound method of this class is
    the required value for that constructor argument; nothing above the
    gateway hand-builds an envelope resolver of its own for an adapter that
    declares ``requires_policy_envelope``.
    """

    def __init__(self, store: AuthorityStore, *,
                 assurance: AssuranceAuthority | None = None,
                 policy_authority: PolicyAuthority | None = None,
                 sources: PolicySourceAuthority | None = None,
                 source_catalog_path: str | Path = DEFAULT_SOURCE_CATALOG) -> None:
        self._assurance = assurance if assurance is not None else AssuranceAuthority(store)
        self._policy_authority = (
            policy_authority if policy_authority is not None
            else PolicyAuthority(store)
        )
        self._sources = sources if sources is not None else PolicySourceAuthority(store)
        self._source_catalog_path = Path(source_catalog_path)

    def resolve(self, authorization_id: str) -> dict:
        # The catalog is cumulative operational input. Admission is idempotent,
        # so every governed dispatch can safely ensure it is present without a
        # separate manual bootstrap step.
        ingest_source_catalog(self._sources, self._source_catalog_path)
        contract_row = self._assurance.ledger.task_contract_for_authorization(
            authorization_id)
        if contract_row is None:
            raise PolicyRefused(
                "no frozen task contract exists for this authorization; "
                "automatic policy compilation has nothing to bind to",
                authorization_id=authorization_id,
            )
        verify_row(contract_row)

        template_id = str(contract_row["template_id"])
        target_module_id = str(contract_row["target_module_id"])
        operation = template(template_id).operation
        selector = derive_selector(
            template_id=template_id, operation=operation,
            target_module_id=target_module_id,
        )

        policy_set = self._sources.current_policy_set()
        task_contract_id = str(contract_row["task_contract_id"])
        task_contract_hash = str(contract_row["task_contract_hash"])
        envelope = compile_envelope(
            policy_set, selector=selector,
            task_contract_id=task_contract_id,
            task_contract_hash=task_contract_hash,
        )

        if self._policy_authority.row_for_task_contract(task_contract_id) is None:
            self._policy_authority.append(envelope)
            return envelope.as_dict()

        return self._policy_authority.resolve(
            task_contract_id,
            expected_task_contract_hash=task_contract_hash,
            expected_policy_set_hash=envelope.policy_set_hash,
        )


__all__ = ["AutomaticPolicyResolver"]
