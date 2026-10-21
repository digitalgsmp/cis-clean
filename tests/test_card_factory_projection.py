"""Tests for the CF-1 read-only task-contract card projection."""

from __future__ import annotations

import inspect
import json
import unittest

from cis.card_factory import CardFactoryProjection, card_hash
from cis.errors import AssuranceRefused, StaleAuthorization, TaskContractTampered

from . import support


def _projection(wb):
    return CardFactoryProjection(store=wb.store, blueprint=wb.blueprint)


def _table_snapshot(wb):
    return {
        table: [row.as_dict() for row in wb.store.query(f"SELECT * FROM {table}")]
        for table in support.authority_tables()
    }


class CardFactoryProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.wb, self.outcome = support.allow_outcome()
        self.authorization_id = self.outcome.authorization["authorization_id"]
        self.task_contract_id = support.assure(self.wb, self.authorization_id)
        self.projection = _projection(self.wb)

    # -- exact verbatim -------------------------------------------------------

    def test_verbatim_instruction_is_exact(self) -> None:
        card = self.projection.card(self.task_contract_id)
        self.assertEqual(card["verbatim_instruction"], support.ALLOW_INSTRUCTION)
        self.assertEqual(
            card["interpretation_label"], "DERIVATIVE_INTERPRETATION_SOURCE_LINKED"
        )
        self.assertTrue(card["interpretation_source"].startswith(
            "intent_transactions:"))
        # The markdown rendering carries the exact words too, not a summary.
        markdown = self.projection.render_markdown(self.task_contract_id)
        self.assertIn(support.ALLOW_INSTRUCTION, markdown)

    # -- scope is derived from authority, never from the caller ---------------

    def test_card_accepts_only_a_task_contract_id(self) -> None:
        signature = inspect.signature(self.projection.card)
        self.assertEqual(list(signature.parameters), ["task_contract_id"])

    def test_scope_fields_match_the_frozen_task_contract_exactly(self) -> None:
        card = self.projection.card(self.task_contract_id)
        contract = support.assurance_authority(self.wb).ledger.require_task_contract(
            self.task_contract_id)
        self.assertEqual(card["allowed_paths"],
                         json.loads(str(contract["allowed_paths_json"])))
        self.assertEqual(card["forbidden_actions"],
                         json.loads(str(contract["forbidden_actions_json"])))
        self.assertEqual(card["required_checks"],
                         json.loads(str(contract["required_checks_json"])))
        self.assertEqual(card["required_artifacts"],
                         json.loads(str(contract["required_artifacts_json"])))
        self.assertEqual(card["stopping_condition"], contract["stopping_condition"])
        self.assertEqual(card["return_point"], contract["return_point"])
        self.assertEqual(card["target_module_id"], contract["target_module_id"])
        self.assertEqual(card["template_id"], contract["template_id"])

    # -- determinism ------------------------------------------------------------

    def test_card_is_deterministic_and_hash_recomputes(self) -> None:
        first = self.projection.card(self.task_contract_id)
        second = self.projection.card(self.task_contract_id)
        self.assertEqual(first, second)

        recomputed = card_hash(**{
            key: value for key, value in first.items()
            if key not in ("hash_domain", "card_hash")
        })
        self.assertEqual(recomputed, first["card_hash"])

    def test_markdown_is_deterministic_and_omits_nothing_invented(self) -> None:
        card = self.projection.card(self.task_contract_id)
        first = self.projection.render_markdown(self.task_contract_id)
        second = self.projection.render_markdown(self.task_contract_id)
        self.assertEqual(first, second)

        for path in card["allowed_paths"]:
            self.assertIn(path, first)
        for action in card["forbidden_actions"]:
            self.assertIn(action, first)
        self.assertIn(card["task_contract_hash"], first)
        self.assertIn(card["card_hash"], first)
        self.assertIn(card["verbatim_instruction"], first)

    # -- read-only --------------------------------------------------------------

    def test_building_a_card_mutates_no_authority_row(self) -> None:
        before = _table_snapshot(self.wb)
        self.projection.card(self.task_contract_id)
        self.projection.render_markdown(self.task_contract_id)
        after = _table_snapshot(self.wb)
        self.assertEqual(before, after)

    def test_building_a_card_changes_no_table_row_count(self) -> None:
        before = {table: len(rows) for table, rows in _table_snapshot(self.wb).items()}
        self.projection.card(self.task_contract_id)
        after = {table: len(rows) for table, rows in _table_snapshot(self.wb).items()}
        self.assertEqual(before, after)

    # -- refusals -----------------------------------------------------------------

    def test_unknown_task_contract_is_refused(self) -> None:
        with self.assertRaises(AssuranceRefused):
            self.projection.card("tc-does-not-exist")

    def test_tampered_task_contract_is_refused(self) -> None:
        _, second_outcome = support.allow_outcome(self.wb)
        tampered_authorization_id = second_outcome.authorization["authorization_id"]
        self.wb.store.insert("task_contracts", {
            "task_contract_id": "tc-tampered",
            "authorization_id": tampered_authorization_id,
            "authorization_binding_hash": "a" * 64,
            "target_module_id": "cis.workbench.projection",
            "template_id": "reconstruct_module.v1",
            "template_hash": "b" * 64,
            "state": "FROZEN",
            "allowed_paths_json": "[]",
            "forbidden_actions_json": "[]",
            "required_checks_json": "[]",
            "required_artifacts_json": "[]",
            "stopping_condition": "stop",
            "return_point": "return",
            "hash_domain": "cis.assurance.task_contract.v1",
            "task_contract_hash": "0" * 64,
            "created_at": self.wb.store.now(),
            "seq": self.wb.store.next_seq(),
        })
        with self.assertRaises(TaskContractTampered):
            self.projection.card("tc-tampered")

    def test_forged_authorization_binding_is_refused(self) -> None:
        """A task contract whose own digest recomputes, but whose recorded
        ``authorization_binding_hash`` names the wrong authorization state,
        is still refused — ``verify_task_contract`` alone cannot see this,
        because the forged row is self-consistent."""
        from cis.assurance.task_contract import task_contract_hash as compute_hash

        _, second_outcome = support.allow_outcome(self.wb)
        other_authorization_id = second_outcome.authorization["authorization_id"]
        forged_authorization_binding_hash = "f" * 64
        kwargs = dict(
            task_contract_id="tc-forged-binding",
            authorization_id=other_authorization_id,
            authorization_binding_hash=forged_authorization_binding_hash,
            target_module_id="cis.workbench.projection",
            template_id="reconstruct_module.v1",
            template_hash="b" * 64,
            state="FROZEN",
            allowed_paths=[],
            forbidden_actions=[],
            required_checks=[],
            required_artifacts=[],
            stopping_condition="stop",
            return_point="return",
        )
        self.wb.store.insert("task_contracts", {
            "task_contract_id": kwargs["task_contract_id"],
            "authorization_id": kwargs["authorization_id"],
            "authorization_binding_hash": kwargs["authorization_binding_hash"],
            "target_module_id": kwargs["target_module_id"],
            "template_id": kwargs["template_id"],
            "template_hash": kwargs["template_hash"],
            "state": kwargs["state"],
            "allowed_paths_json": "[]",
            "forbidden_actions_json": "[]",
            "required_checks_json": "[]",
            "required_artifacts_json": "[]",
            "stopping_condition": kwargs["stopping_condition"],
            "return_point": kwargs["return_point"],
            "hash_domain": "cis.assurance.task_contract.v1",
            "task_contract_hash": compute_hash(**kwargs),
            "created_at": self.wb.store.now(),
            "seq": self.wb.store.next_seq(),
        })
        with self.assertRaises(TaskContractTampered):
            self.projection.card("tc-forged-binding")

    def test_stale_objective_is_refused(self) -> None:
        original_objective_id = self.wb.continuity.active_objective_id()
        new_objective_id = "obj-superseding"
        self.wb.intent.record_objective(
            objective_id=new_objective_id,
            statement="a later objective that supersedes the first",
            established_by=self.outcome.transaction_id,
        )
        self.wb.continuity.record_decision(
            decision_id="dec-supersede-for-test",
            transaction_id=self.outcome.transaction_id,
            classification="redirection",
            treated_as="objective_supersession",
            prior_objective_id=original_objective_id,
            active_objective_id=new_objective_id,
            antecedents=[],
            disposition="objective_superseded_for_test",
            rationale="force the original authorization stale for this test",
        )
        with self.assertRaises(StaleAuthorization):
            self.projection.card(self.task_contract_id)


if __name__ == "__main__":
    unittest.main()
