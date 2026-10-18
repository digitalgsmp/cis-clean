from __future__ import annotations

import copy
import unittest

from cis.errors import (
    PolicyAmbiguous, PolicyBaselineMissing, PolicyConflict,
    PolicyCyclicSupersession, PolicyInvalidSupersession, PolicySchemaInvalid,
    PolicyTampered, PolicyWeakensMaster,
)
from cis.policy.compiler import compile_envelope, verify_compiled_envelope
from cis.policy.schema import PolicySelector, PolicySet, parse_policy, verify_envelope_integrity


def raw_policy(policy_id, *, lineage_id=None, kind="MASTER", status="ACTIVE",
               supersedes=None, selector=None, conflicts_with=None,
               prohibited_actions=None, required_checks=None,
               required_evidence=None, narrowed_scope=None, hold=False,
               rationale="test policy"):
    prohibited_actions = prohibited_actions or []
    required_checks = required_checks or []
    required_evidence = required_evidence or []
    effects = []
    if prohibited_actions:
        effects.append("PROHIBIT")
    if required_checks:
        effects.append("REQUIRE_CHECK")
    if required_evidence:
        effects.append("REQUIRE_EVIDENCE")
    if narrowed_scope is not None:
        effects.append("NARROW_SCOPE")
    if hold:
        effects.append("HOLD")
    return {
        "policy_id": policy_id, "lineage_id": lineage_id or policy_id,
        "kind": kind, "version": 1, "status": status,
        "supersedes": supersedes, "conflicts_with": conflicts_with or [],
        "selector": selector, "effect_kinds": effects,
        "prohibited_actions": prohibited_actions,
        "required_checks": required_checks,
        "required_evidence": required_evidence,
        "narrowed_scope": narrowed_scope, "hold": hold,
        "rationale": rationale, "evidence_basis": ["TEST"],
    }


SEL = PolicySelector(project="cis", module="worker", operation="build", risk="HIGH")
OTHER = PolicySelector(project="cis", module="worker", operation="review", risk="HIGH")


class PolicyCompilerTests(unittest.TestCase):
    def compile(self, policies, selector=SEL):
        return compile_envelope(PolicySet(tuple(policies)), selector=selector,
                                task_contract_id="tc-1",
                                task_contract_hash="task-hash-1")

    def master(self, **changes):
        raw = raw_policy("M1", prohibited_actions=["network:any"],
                         narrowed_scope=["read", "write"])
        raw.update(changes)
        return parse_policy(raw)

    def task(self, policy_id="T1", **changes):
        raw = raw_policy(policy_id, kind="TASK", selector=SEL.as_dict(),
                         required_checks=["contract-bound"],
                         narrowed_scope=["read"])
        raw.update(changes)
        return parse_policy(raw)

    def test_missing_master_refuses(self):
        with self.assertRaises(PolicyBaselineMissing):
            self.compile((self.task(),))

    def test_exact_selector_non_match(self):
        result = self.compile((self.master(), self.task()), OTHER)
        self.assertEqual((), result.task_policy_ids)
        self.assertEqual((), result.required_checks)

    def test_task_cannot_widen_master_scope(self):
        task = self.task(narrowed_scope=["read", "write", "execute"])
        with self.assertRaises(PolicyWeakensMaster):
            self.compile((self.master(), task))

    def test_applicable_symmetric_conflict_refuses(self):
        master = self.master(lineage_id="master", conflicts_with=["task"])
        task = self.task(lineage_id="task", conflicts_with=["master"])
        with self.assertRaises(PolicyConflict):
            self.compile((master, task))

    def test_non_applicable_conflict_does_not_refuse(self):
        master = self.master(lineage_id="master", conflicts_with=["task"])
        task = self.task(lineage_id="task", conflicts_with=["master"])
        self.compile((master, task), OTHER)

    def test_invalid_supersession_refuses(self):
        newer = self.task("T2", lineage_id="task", supersedes="missing")
        with self.assertRaises(PolicyInvalidSupersession):
            PolicySet((self.master(), newer)).validate()

    def test_cyclic_supersession_refuses(self):
        a = self.task("A", lineage_id="task", status="SUPERSEDED", supersedes="B")
        b = self.task("B", lineage_id="task", status="SUPERSEDED", supersedes="A")
        with self.assertRaises(PolicyCyclicSupersession):
            PolicySet((self.master(), a, b)).validate()

    def test_ambiguous_active_lineage_refuses(self):
        with self.assertRaises(PolicyAmbiguous):
            PolicySet((self.master(), self.task("A", lineage_id="task"),
                       self.task("B", lineage_id="task"))).validate()

    def test_stable_ordering(self):
        first = self.compile((self.master(), self.task("T2", required_checks=["second"]), self.task()))
        second = self.compile((self.task(), self.master(), self.task("T2", required_checks=["second"])))
        self.assertEqual(first.as_dict(), second.as_dict())

    def test_envelope_mutation_and_extra_field_refuse(self):
        envelope = self.compile((self.master(), self.task())).as_dict()
        verify_envelope_integrity(envelope)
        changed = copy.deepcopy(envelope)
        changed["prohibited_actions"] = []
        with self.assertRaises(PolicyTampered):
            verify_envelope_integrity(changed)
        envelope["ignored"] = True
        with self.assertRaises(PolicyTampered):
            verify_envelope_integrity(envelope)

    def test_unknown_policy_field_refuses(self):
        raw = raw_policy("M1", prohibited_actions=["network:any"])
        raw["allow"] = ["network:any"]
        with self.assertRaises(PolicySchemaInvalid):
            parse_policy(raw)

    def test_hash_binds_full_selected_policy_content(self):
        one = self.compile((self.master(rationale="one"),))
        two = self.compile((self.master(rationale="two"),))
        self.assertNotEqual(one.policy_set_hash, two.policy_set_hash)
        self.assertNotEqual(one.envelope_hash, two.envelope_hash)

    def test_envelope_carries_supersession_ancestry_for_recompilation(self):
        old = self.master(policy_id="M1", lineage_id="master",
                          status="SUPERSEDED", version=1)
        new = self.master(policy_id="M2", lineage_id="master", version=2,
                          supersedes="M1",
                          prohibited_actions=["network:any", "model:any"])
        envelope = self.compile((old, new))
        self.assertEqual(envelope.master_policy_ids, ("M2",))
        self.assertEqual(
            [item["policy_id"] for item in envelope.selected_policies],
            ["M1", "M2"],
        )
        self.assertEqual(verify_compiled_envelope(envelope.as_dict()), envelope)

    def test_master_baseline_hash_independent_of_master_order(self):
        m1 = self.master(policy_id="M1", lineage_id="m1")
        m2 = self.master(policy_id="M2", lineage_id="m2",
                         prohibited_actions=["model:any"])
        first = self.compile((m1, m2, self.task()))
        second = self.compile((m2, self.task(), m1))
        self.assertEqual(first.master_baseline_hash, second.master_baseline_hash)
        self.assertEqual(first.as_dict(), second.as_dict())
        self.assertEqual(verify_compiled_envelope(first.as_dict()), first)
        self.assertEqual(verify_compiled_envelope(second.as_dict()), second)


if __name__ == "__main__":
    unittest.main()
