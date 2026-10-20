"""Unit 1 of workstream 4.37: the execution-input authority.

Covers ``cis.assurance.execution_input`` — an immutable, content-addressed
binding of the exact inputs a future ``verify_authored_source.v1`` task would
run over. This increment adds no task type and no execution path; these tests
exercise only the append/verify/refuse surface of the new table.
"""

from __future__ import annotations

import hashlib
import unittest

from cis.assurance.execution_input import (
    EXECUTION_INPUT_HASH_DOMAIN, ExecutionInputAuthority, execution_input_hash,
    hash_of_row, verify_row,
)
from cis.blueprint import load_blueprint
from cis.canonical import canonical_json
from cis.errors import (
    AppendOnlyViolation, AssuranceRefused, ExecutionInputRefused,
    ExecutionInputTampered,
)

from . import support


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


CANDIDATE = b"def run():\n    return 1\n"
VECTOR_CONTRACT = canonical_json([{"args": [1], "expect_value": 1}]).encode("utf-8")
WORKER_IMAGE = "sha256:" + "c" * 64
RUNNER_DIGEST = "a" * 64
WORKER_DIGEST = "b" * 64


class ExecutionInputFixture(unittest.TestCase):
    def frozen(self):
        """A workbench with one frozen task contract, ready to be bound."""
        wb, authorization_id = support.allow_and_run()
        compiled = support.freeze_task_contract(wb, authorization_id)
        contract = support.assurance_authority(wb).ledger.require_task_contract(
            compiled.task_contract_id)
        return wb, contract

    def valid_kwargs(self, contract):
        return {
            "task_contract_id": str(contract["task_contract_id"]),
            "candidate_source": CANDIDATE,
            "candidate_sha256": _digest(CANDIDATE),
            "vector_contract": VECTOR_CONTRACT,
            "vector_contract_sha256": _digest(VECTOR_CONTRACT),
            "authorized_entrypoint": "run",
            "task_contract_hash": str(contract["task_contract_hash"]),
            "authorization_binding_hash": str(contract["authorization_binding_hash"]),
            "worker_image": WORKER_IMAGE,
            "expected_trusted_runner_sha256": RUNNER_DIGEST,
            "expected_worker_sha256": WORKER_DIGEST,
        }


class AppendTests(ExecutionInputFixture):
    def test_valid_append_and_recomputation(self):
        wb, contract = self.frozen()
        authority = ExecutionInputAuthority(wb.store)
        row = authority.append(**self.valid_kwargs(contract))

        self.assertEqual(row["task_contract_id"], str(contract["task_contract_id"]))
        self.assertEqual(row["hash_domain"], EXECUTION_INPUT_HASH_DOMAIN)
        self.assertEqual(bytes(row["candidate_source"]), CANDIDATE)
        self.assertEqual(bytes(row["vector_contract"]), VECTOR_CONTRACT)

        stored = authority.for_task_contract(str(contract["task_contract_id"]))
        self.assertEqual(verify_row(stored), str(stored["execution_input_hash"]))
        self.assertEqual(hash_of_row(stored), str(stored["execution_input_hash"]))

    def test_deterministic_identical_binding(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        row = ExecutionInputAuthority(wb.store).append(**kwargs)

        # Recomputing the same payload from scratch, independently of the
        # stored row, reaches the identical digest.
        recomputed = execution_input_hash(
            execution_input_id=str(row["execution_input_id"]),
            task_contract_id=kwargs["task_contract_id"],
            candidate_sha256=kwargs["candidate_sha256"],
            vector_contract_sha256=kwargs["vector_contract_sha256"],
            authorized_entrypoint=kwargs["authorized_entrypoint"],
            task_contract_hash=kwargs["task_contract_hash"],
            authorization_binding_hash=kwargs["authorization_binding_hash"],
            worker_image=kwargs["worker_image"],
            expected_trusted_runner_sha256=kwargs["expected_trusted_runner_sha256"],
            expected_worker_sha256=kwargs["expected_worker_sha256"],
        )
        self.assertEqual(recomputed, str(row["execution_input_hash"]))
        self.assertEqual(hash_of_row(row), str(row["execution_input_hash"]))

    def test_wrong_candidate_digest_is_refused(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        kwargs["candidate_sha256"] = "0" * 64
        with self.assertRaises(ExecutionInputRefused):
            ExecutionInputAuthority(wb.store).append(**kwargs)
        self.assertIsNone(ExecutionInputAuthority(wb.store).for_task_contract(
            kwargs["task_contract_id"]))

    def test_wrong_vector_digest_is_refused(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        kwargs["vector_contract_sha256"] = "0" * 64
        with self.assertRaises(ExecutionInputRefused):
            ExecutionInputAuthority(wb.store).append(**kwargs)

    def test_wrong_task_contract_hash_is_refused(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        kwargs["task_contract_hash"] = "0" * 64
        with self.assertRaises(ExecutionInputRefused):
            ExecutionInputAuthority(wb.store).append(**kwargs)

    def test_wrong_authorization_binding_is_refused(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        kwargs["authorization_binding_hash"] = "0" * 64
        with self.assertRaises(ExecutionInputRefused):
            ExecutionInputAuthority(wb.store).append(**kwargs)

    def test_blank_entrypoint_is_refused(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        kwargs["authorized_entrypoint"] = "   "
        with self.assertRaises(ExecutionInputRefused):
            ExecutionInputAuthority(wb.store).append(**kwargs)

    def test_missing_entrypoint_is_refused(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        kwargs["authorized_entrypoint"] = ""
        with self.assertRaises(ExecutionInputRefused):
            ExecutionInputAuthority(wb.store).append(**kwargs)

    def test_blank_worker_image_is_refused(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        kwargs["worker_image"] = ""
        with self.assertRaises(ExecutionInputRefused):
            ExecutionInputAuthority(wb.store).append(**kwargs)

    def test_mutable_worker_image_tag_is_refused(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        kwargs["worker_image"] = "cis-contained-worker:proof-v2"
        with self.assertRaises(ExecutionInputRefused):
            ExecutionInputAuthority(wb.store).append(**kwargs)

    def test_malformed_worker_image_digests_are_refused(self):
        wb, contract = self.frozen()
        for bad in (
            "sha256:" + "C" * 64,       # uppercase hex
            "sha256:" + "g" * 64,       # non-hex characters
            "sha256:" + "c" * 63,       # too short
            "sha256:" + "c" * 65,       # too long
            "sha256" + "c" * 64,        # missing colon
            "md5:" + "c" * 32,          # wrong algorithm/shape entirely
        ):
            kwargs = self.valid_kwargs(contract)
            kwargs["worker_image"] = bad
            with self.assertRaises(ExecutionInputRefused):
                ExecutionInputAuthority(wb.store).append(**kwargs)

    def test_malformed_expected_digests_are_refused(self):
        wb, contract = self.frozen()
        for field in ("expected_trusted_runner_sha256", "expected_worker_sha256"):
            kwargs = self.valid_kwargs(contract)
            kwargs[field] = "not-a-digest"
            with self.assertRaises(ExecutionInputRefused):
                ExecutionInputAuthority(wb.store).append(**kwargs)

    def test_nonhex_length_64_expected_digests_are_refused(self):
        wb, contract = self.frozen()
        for field in ("expected_trusted_runner_sha256", "expected_worker_sha256"):
            kwargs = self.valid_kwargs(contract)
            kwargs[field] = "z" * 64
            with self.assertRaises(ExecutionInputRefused):
                ExecutionInputAuthority(wb.store).append(**kwargs)

    def test_uppercase_hex_expected_digests_are_refused(self):
        wb, contract = self.frozen()
        for field in ("expected_trusted_runner_sha256", "expected_worker_sha256"):
            kwargs = self.valid_kwargs(contract)
            kwargs[field] = kwargs[field].upper()
            with self.assertRaises(ExecutionInputRefused):
                ExecutionInputAuthority(wb.store).append(**kwargs)

    def test_unknown_task_contract_is_refused(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        kwargs["task_contract_id"] = "tc-does-not-exist"
        with self.assertRaises(AssuranceRefused):
            ExecutionInputAuthority(wb.store).append(**kwargs)

    def test_duplicate_binding_is_refused_not_overwritten(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        authority = ExecutionInputAuthority(wb.store)
        first = authority.append(**kwargs)
        with self.assertRaises(ExecutionInputRefused):
            authority.append(**kwargs)
        still = authority.for_task_contract(kwargs["task_contract_id"])
        self.assertEqual(still["execution_input_hash"], first["execution_input_hash"])


class TamperAndAppendOnlyTests(ExecutionInputFixture):
    def test_tampered_stored_row_is_refused_on_verify(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        authority = ExecutionInputAuthority(wb.store)
        authority.append(**kwargs)

        wb.store.execute_raw("DROP TRIGGER task_execution_inputs_no_update")
        wb.store.execute_raw(
            "UPDATE task_execution_inputs SET execution_input_hash = ? "
            "WHERE task_contract_id = ?",
            ("0" * 64, kwargs["task_contract_id"]),
        )
        with self.assertRaises(ExecutionInputTampered):
            authority.verify(kwargs["task_contract_id"])

    def test_tampered_candidate_bytes_are_refused_on_verify(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        authority = ExecutionInputAuthority(wb.store)
        authority.append(**kwargs)

        wb.store.execute_raw("DROP TRIGGER task_execution_inputs_no_update")
        wb.store.execute_raw(
            "UPDATE task_execution_inputs SET candidate_source = ? "
            "WHERE task_contract_id = ?",
            (b"def run():\n    return 2\n", kwargs["task_contract_id"]),
        )
        with self.assertRaises(ExecutionInputTampered):
            authority.verify(kwargs["task_contract_id"])

    def test_update_is_refused(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        ExecutionInputAuthority(wb.store).append(**kwargs)
        with self.assertRaises(AppendOnlyViolation):
            wb.store.execute_raw(
                "UPDATE task_execution_inputs SET seq = seq + 1000")

    def test_delete_is_refused(self):
        wb, contract = self.frozen()
        kwargs = self.valid_kwargs(contract)
        ExecutionInputAuthority(wb.store).append(**kwargs)
        with self.assertRaises(AppendOnlyViolation):
            wb.store.execute_raw("DELETE FROM task_execution_inputs")

    def test_verify_refuses_when_nothing_is_recorded(self):
        wb, contract = self.frozen()
        with self.assertRaises(ExecutionInputRefused):
            ExecutionInputAuthority(wb.store).verify(
                str(contract["task_contract_id"]))


class ContractAndBlueprintTests(unittest.TestCase):
    def test_contract_is_registered_and_owns_exactly_its_table(self):
        blueprint = support.blueprint()
        contract = blueprint.registry.get("cis.assurance.execution_input")
        self.assertEqual(contract.owned_authority, ("task_execution_inputs",))
        self.assertEqual(contract.layer, "L2")

    def test_module_is_selected_by_the_blueprint(self):
        blueprint = support.blueprint()
        self.assertTrue(blueprint.is_selected("cis.assurance.execution_input"))
        entry = blueprint.module("cis.assurance.execution_input")
        self.assertTrue(entry["evidence_basis"])

    def test_no_other_contract_claims_the_table(self):
        blueprint = support.blueprint()
        owners = blueprint.registry.authority_owners()
        self.assertEqual(owners["task_execution_inputs"],
                         "cis.assurance.execution_input")

    def test_blueprint_reloads_cleanly_with_the_new_contract(self):
        # Exercises the real loader end to end, not just the shared fixture.
        loaded = load_blueprint(support.MANIFEST_PATH, support.CONTRACTS_DIR)
        self.assertIn("cis.assurance.execution_input",
                      loaded.registry.contracts)


if __name__ == "__main__":
    unittest.main()
