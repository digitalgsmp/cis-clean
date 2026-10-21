"""Read-only task-contract review cards, composed from already-verified
authority.

A card answers one question for a human (or any provider-neutral worker)
reviewing one bounded unit of work: what was asked, what was authorized, and
what envelope constrains execution. It never widens what a frozen task
contract already says — every field is read verbatim from the contract and
the re-verified ALLOW, and the whole card carries a digest a reader can
recompute to prove nothing was altered in the showing (ADR-ARCH-002: a
projection is derived from authority and never read back into it;
ADR-ARCH-004 clauses 4 and 8: cards are projections, not a second place
scope can be authored).

CF-1 composes exactly one card per ``task_contract_id``, and the caller
supplies nothing else — no scope, no instruction, no provider:

  * ``AssuranceAuthority.verify_task_contract`` must independently stand up
    the frozen contract's own digest, or this refuses with whatever that call
    raises (unknown or tampered task contract);
  * ``AuthorizationAuthority.verify`` must independently re-derive the linked
    ALLOW against the CURRENT reconstruction baseline and the CURRENT active
    objective, or this refuses with whatever that call raises (binding that
    no longer recomputes, a verdict that is not ALLOW, a superseded objective,
    a moved baseline);
  * the task contract's own recorded ``authorization_binding_hash`` must
    still equal the independently re-verified authorization's current
    binding hash — a self-consistent but forged task-contract row naming the
    wrong authorization is the one attack ``verify_task_contract`` cannot see
    on its own, because it only checks the row against itself;
  * the linked intent transaction and governing objective are then read
    verbatim, never paraphrased.

No new refusal vocabulary is introduced here — every failure mode is already
one of the existing CIS errors the calls above raise.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..assurance.authority import AssuranceAuthority
from ..authority.authorization import AuthorizationAuthority
from ..authority.continuity import ContinuityAuthority
from ..authority.intent import IntentAuthority
from ..canonical import sha256_hex
from ..errors import AssuranceRefused, TaskContractTampered

CARD_HASH_DOMAIN = "cis.card_factory.projection.v1"


def card_payload(*, task_contract_id: str, task_contract_hash: str,
                 authorization_id: str, authorization_binding_hash: str,
                 target_module_id: str, template_id: str, template_hash: str,
                 verbatim_instruction: str, verbatim_hash: str,
                 interpretation: str, interpretation_label: str,
                 interpretation_source: str, objective_id: str,
                 objective_statement: str, allowed_paths: list,
                 forbidden_actions: list, required_checks: list,
                 required_artifacts: list, stopping_condition: str,
                 return_point: str, source_references: list) -> dict:
    """The exact, ordered set of facts one card's digest covers.

    ``__hash_domain__`` is part of the payload, not merely of the function
    name, mirroring ``task_contract_payload`` and ``binding_payload`` so a
    card's digest can never equal the digest of any other CIS structure over
    the same facts.
    """
    return {
        "__hash_domain__": CARD_HASH_DOMAIN,
        "task_contract_id": task_contract_id,
        "task_contract_hash": task_contract_hash,
        "authorization_id": authorization_id,
        "authorization_binding_hash": authorization_binding_hash,
        "target_module_id": target_module_id,
        "template_id": template_id,
        "template_hash": template_hash,
        "verbatim_instruction": verbatim_instruction,
        "verbatim_hash": verbatim_hash,
        "interpretation": interpretation,
        "interpretation_label": interpretation_label,
        "interpretation_source": interpretation_source,
        "objective_id": objective_id,
        "objective_statement": objective_statement,
        "allowed_paths": list(allowed_paths),
        "forbidden_actions": list(forbidden_actions),
        "required_checks": list(required_checks),
        "required_artifacts": list(required_artifacts),
        "stopping_condition": stopping_condition,
        "return_point": return_point,
        "source_references": list(source_references),
    }


def card_hash(**kwargs: Any) -> str:
    return sha256_hex(card_payload(**kwargs))


def verify_card(card: dict) -> None:
    """Refuse a card whose closed payload or digest does not recompute."""
    fields = {key: value for key, value in card.items()
              if key not in ("hash_domain", "card_hash")}
    try:
        recomputed = card_hash(**fields)
    except TypeError as exc:
        raise TaskContractTampered(
            "task card fields do not match the closed schema") from exc
    if (set(card) != set(fields) | {"hash_domain", "card_hash"}
            or card.get("hash_domain") != CARD_HASH_DOMAIN
            or card.get("card_hash") != recomputed):
        raise TaskContractTampered("task card digest does not recompute")


def render_card_markdown(card: dict) -> str:
    """Render a verified structured card without consulting new authority."""
    verify_card(card)
    lines = [
        f"# Task Contract Card: {card['task_contract_id']}", "",
        "## Verbatim Instruction", "", f"> {card['verbatim_instruction']}", "",
        f"Interpretation ({card['interpretation_label']}, source: "
        f"`{card['interpretation_source']}`):", "", card["interpretation"], "",
        "## Objective", "",
        f"- `{card['objective_id']}`: {card['objective_statement']}", "",
        "## Task Contract", "",
        f"- task_contract_id: `{card['task_contract_id']}`",
        f"- task_contract_hash: `{card['task_contract_hash']}`",
        f"- target_module_id: `{card['target_module_id']}`",
        f"- template_id: `{card['template_id']}`",
        f"- template_hash: `{card['template_hash']}`", "",
        "## Authorization", "",
        f"- authorization_id: `{card['authorization_id']}`",
        f"- binding_hash: `{card['authorization_binding_hash']}`", "",
        "## Allowed Paths", "", *[f"- `{p}`" for p in card["allowed_paths"]], "",
        "## Forbidden Actions", "",
        *[f"- `{a}`" for a in card["forbidden_actions"]], "",
        "## Required Checks", "", *[f"- `{c}`" for c in card["required_checks"]], "",
        "## Required Artifacts", "",
        *[f"- `{a}`" for a in card["required_artifacts"]], "",
        "## Stopping Condition", "", card["stopping_condition"], "",
        "## Return Point", "", card["return_point"], "",
        "## Source References", "", *[f"- `{r}`" for r in card["source_references"]], "",
        "## Hashes", "", f"- verbatim_hash: `{card['verbatim_hash']}`",
        f"- hash_domain: `{card['hash_domain']}`",
        f"- card_hash: `{card['card_hash']}`", "",
    ]
    return "\n".join(lines)


@dataclass
class CardFactoryProjection:
    """Composes one deterministic review card per frozen task contract.

    Read-only: ``card`` and ``render_markdown`` read through
    ``AssuranceAuthority``, ``AuthorizationAuthority``, ``ContinuityAuthority``
    and ``IntentAuthority`` and append nothing. The caller supplies only a
    ``task_contract_id``; nothing about a card's content is itself a
    parameter, because a card is a projection of what authority already
    recorded, not a value a caller composes by naming fields.
    """

    store: Any
    blueprint: Any

    def card(self, task_contract_id: str) -> dict:
        assurance = AssuranceAuthority(self.store)
        contract = assurance.verify_task_contract(task_contract_id)

        continuity = ContinuityAuthority(self.store)
        authorizations = AuthorizationAuthority(self.store)
        authorization = authorizations.verify(
            str(contract["authorization_id"]),
            baseline_hash=self.blueprint.baseline_hash,
            active_objective_id=continuity.active_objective_id(),
        )

        # The task contract's own forward link must still name the exact
        # ALLOW just re-verified, not merely an authorization sharing its id.
        # verify_task_contract only checks the row against itself; this binds
        # it to the independently re-derived authorization.
        if (str(contract["authorization_binding_hash"])
                != str(authorization["binding_hash"])):
            raise TaskContractTampered(
                "task contract's recorded authorization binding no longer "
                "matches the independently re-verified authorization",
                task_contract_id=task_contract_id,
                authorization_id=str(authorization["authorization_id"]),
                recorded=str(contract["authorization_binding_hash"]),
                recomputed=str(authorization["binding_hash"]),
            )

        intent = IntentAuthority(self.store)
        transaction_id = str(authorization["transaction_id"])
        transaction = intent.transaction(transaction_id)
        if transaction is None:  # pragma: no cover - verify() already proved this
            raise AssuranceRefused(
                "authorization names an intent transaction with no record",
                transaction_id=transaction_id,
            )

        objective_id = str(authorization["objective_id"])
        objective = intent.objective(objective_id)
        if objective is None:
            raise AssuranceRefused(
                "authorization names an objective with no record",
                objective_id=objective_id,
            )

        task_contract_id = str(contract["task_contract_id"])
        authorization_id = str(authorization["authorization_id"])

        source_references = [
            f"intent_transactions:{transaction_id}:verbatim_instruction",
            f"objectives:{objective_id}:statement",
            f"task_contracts:{task_contract_id}:task_contract_hash",
            f"execution_authorizations:{authorization_id}:binding_hash",
        ]

        fields = dict(
            task_contract_id=task_contract_id,
            task_contract_hash=str(contract["task_contract_hash"]),
            authorization_id=authorization_id,
            authorization_binding_hash=str(authorization["binding_hash"]),
            target_module_id=str(contract["target_module_id"]),
            template_id=str(contract["template_id"]),
            template_hash=str(contract["template_hash"]),
            verbatim_instruction=str(transaction["verbatim_instruction"]),
            verbatim_hash=str(transaction["verbatim_hash"]),
            interpretation=str(transaction["interpretation"]),
            interpretation_label=str(transaction["interpretation_label"]),
            interpretation_source=str(transaction["interpretation_source"]),
            objective_id=objective_id,
            objective_statement=str(objective["statement"]),
            allowed_paths=json.loads(str(contract["allowed_paths_json"])),
            forbidden_actions=json.loads(str(contract["forbidden_actions_json"])),
            required_checks=json.loads(str(contract["required_checks_json"])),
            required_artifacts=json.loads(str(contract["required_artifacts_json"])),
            stopping_condition=str(contract["stopping_condition"]),
            return_point=str(contract["return_point"]),
            source_references=source_references,
        )

        card = dict(fields)
        card["hash_domain"] = CARD_HASH_DOMAIN
        card["card_hash"] = card_hash(**fields)
        return card

    def render_markdown(self, task_contract_id: str) -> str:
        """A deterministic markdown rendering of ``card(task_contract_id)``.

        Every line reads a field already present on the card; nothing here
        invents scope the card itself does not carry.
        """
        card = self.card(task_contract_id)
        return render_card_markdown(card)
