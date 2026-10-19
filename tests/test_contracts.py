"""Module-contract invariants (ADR-ARCH-001 clauses 3, 4, 5)."""

import unittest

from cis.contracts import REQUIRED_FIELDS, ContractRegistry, load_registry
from cis.contracts.registry import parse_contract
from cis.errors import ContractError

from . import support


class RealRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = load_registry(support.CONTRACTS_DIR)

    def test_sixteen_fields_exactly(self):
        self.assertEqual(len(REQUIRED_FIELDS), 16)
        self.assertEqual(len(set(REQUIRED_FIELDS)), 16)
        for module_id in self.registry.contracts:
            document = support.contract_document(module_id)
            self.assertEqual(set(document), set(REQUIRED_FIELDS), module_id)
            self.assertEqual(len(document), 16, module_id)

    def test_every_contract_validates(self):
        self.assertEqual(len(self.registry.contracts), support.expected_module_count())

    def test_one_owner_per_authority(self):
        owners = self.registry.authority_owners()
        self.assertEqual(len(owners), len(set(owners)))
        # Every authority table the migrations create has exactly one owner,
        # derived from the migration files rather than pinned to migration
        # 0001, so a later migration cannot add an unowned table unnoticed.
        self.assertEqual(set(owners), support.authority_tables())

    def test_dependency_order_is_deterministic_and_topological(self):
        first = self.registry.dependency_order()
        self.assertEqual(first, self.registry.dependency_order())
        position = {module_id: i for i, module_id in enumerate(first)}
        for module_id, contract in self.registry.contracts.items():
            for dependency in contract.depends_on:
                self.assertLess(position[dependency], position[module_id],
                                f"{dependency} must precede {module_id}")

    def test_registry_hash_is_stable_and_order_independent(self):
        documents = [support.contract_document(m) for m in self.registry.contracts]
        shuffled = ContractRegistry.from_documents(reversed(documents))
        self.assertEqual(shuffled.registry_hash, self.registry.registry_hash)

    def test_no_module_writes_authority_owned_by_another(self):
        owners = self.registry.authority_owners()
        for module_id, contract in self.registry.contracts.items():
            for target in contract.writes:
                self.assertEqual(owners.get(target), module_id)

    def test_l3_contains_only_declared_replaceable_backend_adapters(self):
        by_layer = self.registry.by_layer()
        # The property under test is that L3 holds ONLY declared replaceable
        # backend adapters - not that there are exactly two of them forever.
        # ADR-ARCH-001's own acceptance criteria anticipate "a second backend
        # adapter is added with no change above the Layer-2 port", so a
        # properly declared addition preserves this invariant rather than
        # weakening it. cis.execution.adapters.contained_worker is declared in
        # contracts/ and selected in the blueprint (4.37 revision 31).
        self.assertEqual(by_layer["L3"], [
            "cis.execution.adapters.contained_worker",
            "cis.execution.adapters.deterministic_mock",
            "cis.worker.contained_nonroot",
        ])
        self.assertEqual(by_layer["L1"], ["cis.interface.api"])


class FieldValidationTests(unittest.TestCase):
    def test_missing_field_is_refused(self):
        for field in REQUIRED_FIELDS:
            document = support.minimal_contract()
            del document[field]
            with self.assertRaises(ContractError) as caught:
                parse_contract(document)
            self.assertEqual(caught.exception.code, "CONTRACT_INVALID")
            self.assertIn(field, caught.exception.detail["missing"])

    def test_unexpected_field_is_refused(self):
        document = support.minimal_contract(owner="eric")
        with self.assertRaises(ContractError) as caught:
            parse_contract(document)
        self.assertEqual(caught.exception.detail["unexpected"], ["owner"])

    def test_unknown_layer_is_refused(self):
        with self.assertRaises(ContractError):
            parse_contract(support.minimal_contract(layer="L4"))

    def test_failure_boundary_must_state_the_mode(self):
        with self.assertRaises(ContractError):
            parse_contract(support.minimal_contract(
                failure_boundary="it stops and reports"))

    def test_recovery_must_not_collapse_into_failure_boundary(self):
        boundary = "fail_closed on any invalid input"
        with self.assertRaises(ContractError):
            parse_contract(support.minimal_contract(
                failure_boundary=boundary, recovery_behavior=boundary))

    def test_evidence_must_not_collapse_into_verification(self):
        with self.assertRaises(ContractError):
            parse_contract(support.minimal_contract(
                evidence_produced=["the same sentence"],
                verification="the same sentence"))

    def test_responsibility_must_be_one_sentence(self):
        with self.assertRaises(ContractError):
            parse_contract(support.minimal_contract(
                responsibility="Does one thing. Also does a second thing."))

    def test_writes_require_a_mutation_interface(self):
        with self.assertRaises(ContractError):
            parse_contract(support.minimal_contract(
                writes=["some_table"], mutation_interface="none"))

    def test_owned_authority_must_be_written(self):
        with self.assertRaises(ContractError) as caught:
            parse_contract(support.minimal_contract(
                owned_authority=["some_table"],
                mutation_interface="Thing.append"))
        self.assertIn("some_table", caught.exception.detail["authority"])

    def test_list_field_must_be_a_list_of_non_empty_strings(self):
        with self.assertRaises(ContractError):
            parse_contract(support.minimal_contract(reads="everything"))
        with self.assertRaises(ContractError):
            parse_contract(support.minimal_contract(reads=["", "x"]))

    def test_list_field_must_not_repeat(self):
        with self.assertRaises(ContractError):
            parse_contract(support.minimal_contract(reads=["a", "a"]))

    def test_self_dependency_is_refused(self):
        with self.assertRaises(ContractError):
            parse_contract(support.minimal_contract(
                module_id="cis.a", depends_on=["cis.a"]))


class RegistryInvariantTests(unittest.TestCase):
    def test_duplicate_module_id_is_refused(self):
        document = support.minimal_contract("cis.a")
        with self.assertRaises(ContractError) as caught:
            ContractRegistry.from_documents([document, dict(document)])
        self.assertEqual(caught.exception.detail["module_id"], "cis.a")

    def test_duplicate_authority_ownership_is_refused(self):
        a = support.minimal_contract("cis.a", owned_authority=["t"], writes=["t"],
                                     mutation_interface="A.append")
        b = support.minimal_contract("cis.b", owned_authority=["t"], writes=["t"],
                                     mutation_interface="B.append")
        with self.assertRaises(ContractError) as caught:
            ContractRegistry.from_documents([a, b])
        self.assertEqual(caught.exception.detail["authority"], "t")
        self.assertEqual(caught.exception.detail["owners"], ["cis.a", "cis.b"])

    def test_absent_dependency_is_refused(self):
        with self.assertRaises(ContractError) as caught:
            ContractRegistry.from_documents([
                support.minimal_contract("cis.a", depends_on=["cis.missing"]),
            ])
        self.assertEqual(caught.exception.detail["absent"], ["cis.missing"])

    def test_forbidden_dependency_violation_is_refused(self):
        with self.assertRaises(ContractError) as caught:
            ContractRegistry.from_documents([
                support.minimal_contract("cis.a", depends_on=["cis.b"],
                                         forbidden_dependencies=["cis.b"]),
                support.minimal_contract("cis.b"),
            ])
        self.assertEqual(caught.exception.detail["forbidden"], ["cis.b"])

    def test_dependency_cycle_is_refused(self):
        with self.assertRaises(ContractError) as caught:
            ContractRegistry.from_documents([
                support.minimal_contract("cis.a", depends_on=["cis.b"]),
                support.minimal_contract("cis.b", depends_on=["cis.a"]),
            ])
        self.assertIn("cycle", caught.exception.message)

    def test_nothing_may_depend_on_the_control_surface(self):
        with self.assertRaises(ContractError) as caught:
            ContractRegistry.from_documents([
                support.minimal_contract("cis.ui", layer="L1"),
                support.minimal_contract("cis.svc", layer="L2",
                                         depends_on=["cis.ui"]),
            ])
        self.assertIn("L1", caught.exception.message)

    def test_l1_may_not_depend_directly_on_l3(self):
        with self.assertRaises(ContractError) as caught:
            ContractRegistry.from_documents([
                support.minimal_contract("cis.ui", layer="L1",
                                         depends_on=["cis.backend"]),
                support.minimal_contract("cis.backend", layer="L3"),
            ])
        self.assertIn("L2 boundary", caught.exception.message)

    def test_l3_may_not_depend_on_an_authority_owner(self):
        with self.assertRaises(ContractError) as caught:
            ContractRegistry.from_documents([
                support.minimal_contract("cis.backend", layer="L3",
                                         depends_on=["cis.auth"]),
                support.minimal_contract("cis.auth", layer="L2",
                                         owned_authority=["t"], writes=["t"],
                                         mutation_interface="Auth.append"),
            ])
        self.assertIn("owns CIS authority", caught.exception.message)

    def test_l3_may_depend_on_the_layer_two_contract(self):
        # The permitted inversion: an adapter implements the CIS-owned contract.
        registry = ContractRegistry.from_documents([
            support.minimal_contract("cis.backend", layer="L3",
                                     depends_on=["cis.port"]),
            support.minimal_contract("cis.port", layer="L2"),
        ])
        self.assertEqual(registry.dependency_order(), ["cis.port", "cis.backend"])


if __name__ == "__main__":
    unittest.main()
