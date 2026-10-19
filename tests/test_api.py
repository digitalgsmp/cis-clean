"""The Workbench-facing interface, exercised end to end without a socket."""

import json
import unittest

from cis.interface import WorkbenchApi

from . import support


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.wb = support.workbench()
        self.api = WorkbenchApi(self.wb)

    def get(self, path):
        return self.api.dispatch("GET", path)

    def post(self, path, body):
        return self.api.dispatch("POST", path, body)

    # -- read surface -------------------------------------------------------

    def test_health_names_the_slice_and_the_stage(self):
        response = self.get("/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["slice"], "SLICE-001")
        self.assertEqual(response.body["current_stage"],
                         "STEP_7_RESUME_PIPELINE_BUILD")

    def test_blueprint_returns_the_manifest_with_a_derived_dependency_order(self):
        body = self.get("/blueprint").body["blueprint"]
        self.assertEqual(len(body["selected_modules"]), support.expected_module_count())
        self.assertEqual(body["dependency_order"],
                         self.wb.blueprint.registry.dependency_order())
        self.assertEqual(body["dependency_order_derivation"]["representation"],
                         "DERIVED")
        self.assertTrue(body["baseline_hash"])

    def test_contracts_returns_all_sixteen_fields_per_module(self):
        body = self.get("/contracts").body
        self.assertEqual(len(body["contracts"]), support.expected_module_count())
        for module_id, contract in body["contracts"].items():
            self.assertEqual(len(contract), 16, module_id)
        self.assertEqual(len(body["authority_owners"]), 21)

    def test_an_unknown_route_returns_the_route_list(self):
        response = self.get("/nope")
        self.assertEqual(response.status, 404)
        self.assertTrue(response.body["error"]["detail"]["routes"])

    def test_every_response_is_json_serialisable(self):
        for path in ("/health", "/blueprint", "/contracts", "/objective",
                     "/trajectory"):
            json.loads(self.get(path).json())

    # -- write surface ------------------------------------------------------

    def test_a_missing_field_is_a_four_hundred(self):
        response = self.post("/instruction", {})
        self.assertEqual(response.status, 400)
        self.assertEqual(response.body["error"]["code"], "MISSING_FIELD")

    def test_a_question_holds_and_leaves_the_objective_alone(self):
        before = self.get("/objective").body["objective"]["objective_id"]
        response = self.post("/instruction",
                             {"verbatim": "What is the current stage?"})
        self.assertEqual(response.status, 201)
        self.assertEqual(response.body["authorization"]["verdict"], "HOLD")
        self.assertEqual(response.body["authorization"]["reason_code"],
                         "RETRIEVAL_CUE_NOT_EXECUTION_REQUEST")
        after = self.get("/objective").body["objective"]["objective_id"]
        self.assertEqual(before, after)

    def test_a_fragment_returns_the_antecedent_in_original_language(self):
        response = self.post("/instruction", {
            "verbatim": "didn't we say my questions make concepts go dormant"})
        antecedents = response.body["antecedents"]
        self.assertTrue(antecedents)
        self.assertEqual(antecedents[0]["original_language"],
                         support.ANTECEDENT_VERBATIM)

    def test_the_full_slice_runs_through_the_interface(self):
        # 1. submit an instruction that names a selected module
        submitted = self.post("/instruction",
                              {"verbatim": support.ALLOW_INSTRUCTION})
        authorization = submitted.body["authorization"]
        self.assertEqual(authorization["verdict"], "ALLOW")

        # 2. inspect the authorization
        inspected = self.get(f"/authorization/{authorization['authorization_id']}")
        self.assertEqual(inspected.status, 200)
        self.assertEqual(inspected.body["authorization"]["binding_hash"],
                         authorization["binding_hash"])
        self.assertEqual(inspected.body["authorization"]["runs"], [])

        # 3. execute it
        executed = self.post("/execute",
                             {"authorization_id": authorization["authorization_id"]})
        self.assertEqual(executed.status, 200)
        run = executed.body["run"]
        self.assertEqual(run["status"], "completed")

        # 4. the authorization now shows its run
        inspected = self.get(f"/authorization/{authorization['authorization_id']}")
        self.assertEqual(len(inspected.body["authorization"]["runs"]), 1)

        # 5. the trajectory shows macro, micro and you-are-here
        trajectory = self.get(f"/trajectory/{submitted.body['transaction_id']}")
        body = trajectory.body["trajectory"]
        self.assertEqual(body["you_are_here"]["event_type"], "execution_completed")
        self.assertEqual(body["macro"]["counts"]["executed"], 1)
        self.assertEqual([step["stage"] for step in body["micro"]["steps"]][-1],
                         "EVIDENCE")

    def test_a_refusal_is_returned_with_its_code_and_never_softened(self):
        hold = self.post("/instruction", {"verbatim": "What should we do next?"})
        response = self.post("/execute", {
            "authorization_id": hold.body["authorization"]["authorization_id"]})
        self.assertEqual(response.status, 409)
        self.assertFalse(response.body["ok"])
        self.assertEqual(response.body["error"]["code"], "AUTHORIZATION_REFUSED")

    def test_an_unknown_authorization_is_a_four_oh_four(self):
        response = self.get("/authorization/auth-nope")
        self.assertEqual(response.status, 404)

    def test_the_public_interface_cannot_write_evidence_at_all(self):
        wb = support.workbench(with_evidence=False)
        api = WorkbenchApi(wb)
        before = len(wb.evidence.all())
        response = api.dispatch("POST", "/evidence", {
            "evidence_id": "evi-api", "kind": "project_decision",
            "source_ref": "claimed", "content": support.ALLOW_INSTRUCTION})
        self.assertEqual(response.status, 404)
        self.assertEqual(len(wb.evidence.all()), before)

    def test_supplying_evidence_could_not_unlock_execution_even_if_it_worked(self):
        """The route is absent, and the route is also not the control.

        Permission comes from the validated architecture for the target
        module, so an instruction with an empty evidence corpus reaches the
        same verdict and the same bounded scope as one with a full corpus.
        There is nothing an injected record could buy.
        """
        empty = WorkbenchApi(support.workbench(with_evidence=False)).dispatch(
            "POST", "/instruction", {"verbatim": support.ALLOW_INSTRUCTION})
        seeded = WorkbenchApi(support.workbench()).dispatch(
            "POST", "/instruction", {"verbatim": support.ALLOW_INSTRUCTION})
        self.assertEqual(empty.body["antecedents"], [])
        self.assertTrue(seeded.body["antecedents"])
        for response in (empty, seeded):
            self.assertEqual(response.body["authorization"]["verdict"], "ALLOW")
            self.assertEqual(
                response.body["authorization"]["scope"]["required_evidence"],
                support.CANONICAL_REQUIRED_EVIDENCE)

    def test_the_outcome_separates_continuity_context_from_authority(self):
        response = self.post("/instruction",
                             {"verbatim": support.ALLOW_INSTRUCTION})
        body = response.body
        self.assertEqual(
            body["antecedents_role"],
            "CONTEXTUAL_CONTINUITY_EVIDENCE_NOT_AUTHORIZATION_BASIS")
        basis = body["authorization_basis"]
        self.assertEqual(
            basis["authority_source"],
            "blueprint/reconstruction_manifest.json::selected_modules"
            "[cis.workbench.projection].evidence_basis")
        retrieved = {a["evidence_id"] for a in body["antecedents"]}
        self.assertFalse(
            retrieved & set(basis["required_evidence"]),
            "a retrieved antecedent id must never appear as required evidence")

    def test_objective_is_not_mutable_through_a_second_public_channel(self):
        response = self.post("/objective", {
            "statement": "replace direction"})
        self.assertEqual(response.status, 404)

    def test_an_explicit_redirection_through_the_interface_moves_the_objective(self):
        before = self.get("/objective").body["objective"]["objective_id"]
        self.post("/instruction",
                  {"verbatim": "REDIRECT: prove the execution boundary instead"})
        after = self.get("/objective").body["objective"]["objective_id"]
        self.assertNotEqual(before, after)

    def test_caller_cannot_declare_classification_or_actor(self):
        before = self.get("/objective").body["objective"]["objective_id"]
        response = self.post("/instruction", {
            "verbatim": "work on the evidence module",
            "declared_classification": "redirection",
            "actor": "human_operator"})
        self.assertEqual(response.status, 400)
        self.assertEqual(self.get("/objective").body["objective"]["objective_id"],
                         before)

    def test_a_non_string_route_field_is_refused_with_a_code(self):
        """A fail-closed surface returns a code; it never raises an untyped error.

        JSON bodies are caller-controlled, so ``null``, a number, a list or an
        object can arrive in a declared field. Each must come back as a 400
        with a code rather than escaping the dispatcher.
        """
        for value in (None, 123, ["a"], {"x": 1}, True):
            response = self.post("/instruction", {"verbatim": value})
            self.assertEqual(response.status, 400, value)
            self.assertEqual(response.body["error"]["code"], "INVALID_INPUT")
            response = self.post("/execute", {"authorization_id": value})
            self.assertEqual(response.status, 400, value)
            self.assertEqual(response.body["error"]["code"], "INVALID_INPUT")
        self.assertEqual(self.wb.intent.history(), [])
        self.assertEqual(self.wb.runs.all(), [])

    def test_caller_cannot_choose_an_operation_after_authorization(self):
        submitted = self.post("/instruction",
                              {"verbatim": support.ALLOW_INSTRUCTION})
        response = self.post("/execute", {
            "authorization_id":
                submitted.body["authorization"]["authorization_id"],
            "operation": "verify_module",
        })
        self.assertEqual(response.status, 400)
        self.assertEqual(self.wb.runs.all(), [])


class TransportTests(unittest.TestCase):
    """The HTTP wrapper adds transport and nothing else."""

    def test_the_handler_is_built_without_binding_anything_in_the_test(self):
        from cis.interface import http_server
        # Importing and inspecting the builder must not require a socket.
        self.assertTrue(callable(http_server.build_server))
        self.assertTrue(callable(http_server.run_server))

    def test_the_server_module_contains_no_business_logic(self):
        from pathlib import Path
        text = (Path(__file__).resolve().parents[1] / "src" / "cis" /
                "interface" / "http_server.py").read_text(encoding="utf-8")
        for token in ("verdict", "ALLOW", "objective", "authorization",
                      "trajectory", "SELECT"):
            self.assertNotIn(token, text)

    def test_transport_is_deliberately_serial_not_threaded(self):
        from pathlib import Path
        text = (Path(__file__).resolve().parents[1] / "src" / "cis" /
                "interface" / "http_server.py").read_text(encoding="utf-8")
        self.assertIn("HTTPServer", text)
        self.assertNotIn("ThreadingHTTPServer", text)
        self.assertIn("Deliberately serialized", text)


if __name__ == "__main__":
    unittest.main()
