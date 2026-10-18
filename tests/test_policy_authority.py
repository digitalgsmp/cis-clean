"""Append-only policy authority and stale-envelope refusal proofs."""

import unittest

from cis.errors import PolicyRefused, PolicyStale, PolicyTampered
from cis.policy.authority import PolicyAuthority, envelope_from_row

from . import support


class PolicyAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.wb, outcome = support.allow_outcome()
        self.contract = support.freeze_task_contract(
            self.wb, outcome.authorization["authorization_id"])
        self.envelope = support.seed_policy_envelope(
            self.wb, self.contract.task_contract_id)
        self.authority = PolicyAuthority(self.wb.store)

    def test_append_and_verified_resolution(self):
        resolved = self.authority.resolve(
            self.contract.task_contract_id,
            expected_task_contract_hash=self.contract.task_contract_hash,
            expected_policy_set_hash=self.envelope.policy_set_hash,
        )
        self.assertEqual(resolved["envelope_hash"], self.envelope.envelope_hash)
        self.assertEqual(envelope_from_row(
            self.authority.row_for_task_contract(self.contract.task_contract_id)
        ).as_dict(), self.envelope.as_dict())

    def test_second_envelope_for_task_contract_refuses(self):
        with self.assertRaises(PolicyRefused):
            self.authority.append(self.envelope)

    def test_stale_policy_set_refuses(self):
        with self.assertRaises(PolicyStale):
            self.authority.resolve(
                self.contract.task_contract_id,
                expected_task_contract_hash=self.contract.task_contract_hash,
                expected_policy_set_hash="changed-policy-set",
            )

    def test_forged_stored_envelope_refuses(self):
        self.wb.store.execute_raw("DROP TRIGGER policy_envelopes_no_update")
        self.wb.store.execute_raw(
            "UPDATE policy_envelopes SET prohibited_actions_json = '[]' "
            "WHERE task_contract_id = ?", (self.contract.task_contract_id,))
        with self.assertRaises(PolicyTampered):
            self.authority.resolve(
                self.contract.task_contract_id,
                expected_task_contract_hash=self.contract.task_contract_hash,
                expected_policy_set_hash=self.envelope.policy_set_hash,
            )


if __name__ == "__main__":
    unittest.main()
