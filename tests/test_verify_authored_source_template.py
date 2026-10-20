"""Unit 2A of workstream 4.37: the ``verify_authored_source.v1`` template.

Covers only the frozen ``VERIFY_AUTHORED_SOURCE_V1`` template added to
``cis.assurance.task_contract`` — its lookup, its deterministic template hash,
its refusal to compile over the only operation this slice can authorize
(``reconstruct_module``), and that adding it changed neither the task-contract
hash domain nor the shape of a contract compiled from an existing template.
No new task type is issued and no verifier check is taught here.
"""

from __future__ import annotations

import unittest

from cis.assurance.task_contract import (
    TASK_CONTRACT_HASH_DOMAIN, TEMPLATES, VERIFY_AUTHORED_SOURCE_V1,
    template,
)
from cis.errors import TaskContractRefused

from . import support


class LookupTests(unittest.TestCase):
    def test_registered_under_its_own_template_id(self):
        self.assertIs(TEMPLATES["verify_authored_source.v1"],
                      VERIFY_AUTHORED_SOURCE_V1)
        self.assertIs(template("verify_authored_source.v1"),
                      VERIFY_AUTHORED_SOURCE_V1)

    def test_operation_and_shape(self):
        self.assertEqual(VERIFY_AUTHORED_SOURCE_V1.template_id,
                         "verify_authored_source.v1")
        self.assertEqual(VERIFY_AUTHORED_SOURCE_V1.operation,
                         "verify_authored_source")
        self.assertEqual(VERIFY_AUTHORED_SOURCE_V1.path_envelope,
                         ("tests/{module_path}",))

    def test_required_checks_name_every_forward_binding(self):
        checks = set(VERIFY_AUTHORED_SOURCE_V1.required_checks)
        for expected in (
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
        ):
            self.assertIn(expected, checks)
        self.assertEqual(len(checks), 10)

    def test_required_artifacts_name_evidence_and_the_forward_digests(self):
        self.assertEqual(
            set(VERIFY_AUTHORED_SOURCE_V1.required_artifacts),
            {
                "execution_evidence",
                "run_result_hash",
                "execution_input_hash",
                "candidate_source_sha256",
                "vector_contract_sha256",
            },
        )


class DeterminismTests(unittest.TestCase):
    def test_template_hash_is_deterministic(self):
        first = VERIFY_AUTHORED_SOURCE_V1.template_hash
        second = VERIFY_AUTHORED_SOURCE_V1.template_hash
        self.assertEqual(first, second)
        self.assertEqual(first, template("verify_authored_source.v1").template_hash)

    def test_template_hash_distinct_from_other_templates(self):
        other_hashes = {
            TEMPLATES[tid].template_hash
            for tid in TEMPLATES if tid != "verify_authored_source.v1"
        }
        self.assertNotIn(VERIFY_AUTHORED_SOURCE_V1.template_hash, other_hashes)

    def test_envelope_derivation_is_deterministic_and_clean(self):
        wb, authorization_id = support.allow_and_run()
        compiler = support.compiler(wb)
        first = compiler.envelope_for(
            template_id="verify_authored_source.v1",
            target_module_id="cis.workbench.projection",
        )
        second = compiler.envelope_for(
            template_id="verify_authored_source.v1",
            target_module_id="cis.workbench.projection",
        )
        self.assertEqual(first, second)
        self.assertEqual(first, ("tests/cis/workbench/projection",))


class OperationMismatchTests(unittest.TestCase):
    def test_compile_refuses_over_a_reconstruct_module_authorization(self):
        wb, authorization_id = support.allow_and_run()
        compiler = support.compiler(wb)
        with self.assertRaises(TaskContractRefused) as ctx:
            compiler.compile(
                authorization_id=authorization_id,
                template_id="verify_authored_source.v1",
                active_objective_id=wb.continuity.active_objective_id(),
            )
        self.assertEqual(ctx.exception.detail["template_operation"],
                         "verify_authored_source")
        self.assertEqual(ctx.exception.detail["authorized_operation"],
                         "reconstruct_module")


class NoTaskContractShapeChangeTests(unittest.TestCase):
    """Registering a third template must not alter the frozen hash domain or
    the schema a contract compiled from an EXISTING template produces."""

    def test_hash_domain_unchanged(self):
        self.assertEqual(TASK_CONTRACT_HASH_DOMAIN,
                         "cis.assurance.task_contract.v1")

    def test_reconstruct_module_contract_shape_unaffected(self):
        wb, authorization_id = support.allow_and_run()
        compiled = support.freeze_task_contract(wb, authorization_id)
        payload = compiled.hash_payload()
        self.assertEqual(payload["__hash_domain__"], TASK_CONTRACT_HASH_DOMAIN)
        self.assertEqual(
            set(payload),
            {
                "__hash_domain__", "task_contract_id", "authorization_id",
                "authorization_binding_hash", "target_module_id",
                "template_id", "template_hash", "state", "allowed_paths",
                "forbidden_actions", "required_checks", "required_artifacts",
                "stopping_condition", "return_point",
            },
        )
        self.assertEqual(compiled.template_id, "reconstruct_module.v1")


if __name__ == "__main__":
    unittest.main()
