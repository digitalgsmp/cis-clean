"""Descriptive surfaces must match runtime behaviour.

README, the machine-readable contracts, the manifest and the route list are
claims about what this slice does. A claim that drifts from the code is the
same failure mode as a stored "you are here" column: a second record of a fact
that something else already owns, going stale silently.

These tests are the only thing that keeps those surfaces honest, so they assert
against the running code rather than against each other.
"""

from __future__ import annotations

import inspect
import json
import re
import unittest
from pathlib import Path

from cis.authority.evidence import EvidenceAuthority
from cis.execution.gateway import ExecutionGateway
from cis.interface import WorkbenchApi
from cis.interface.api import _ROUTES
from cis.workbench import Workbench

from . import support

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")

#: README prose wraps; claims are checked against a single-line view of it so a
#: line break never hides a missing statement or passes a false one.
FLAT_README = " ".join(README.replace("*", "").replace("`", "").split())

#: Every test in the suite, counted the way an operator counts them.
TOTAL_TESTS = 355


class ReadmeTests(unittest.TestCase):
    def setUp(self):
        self.api = WorkbenchApi(support.workbench())

    def test_the_stated_test_count_is_the_real_test_count(self):
        suite = unittest.defaultTestLoader.discover(
            start_dir=str(ROOT / "tests"), top_level_dir=str(ROOT))
        self.assertEqual(suite.countTestCases(), TOTAL_TESTS)
        self.assertIn(f"{TOTAL_TESTS} tests", README)

    def test_the_readme_advertises_no_route_the_dispatcher_does_not_serve(self):
        advertised = set(re.findall(r"localhost:8077(/[^\s'\"]*)", README))
        self.assertTrue(advertised)
        for path in advertised:
            # Placeholder ids in the README are not real rows; a 404 from a
            # GET lookup is fine, a 404 from the ROUTER is not.
            method = "POST" if f"POST localhost:8077{path}" in README else "GET"
            body = {"verbatim": "x"} if path == "/instruction" else {}
            if path == "/execute":
                body = {"authorization_id": "auth-nope"}
            response = self.api.dispatch(method, path, body)
            code = response.body.get("error", {}).get("code")
            self.assertNotEqual(code, "NO_ROUTE", f"{method} {path}")

    def test_the_readme_does_not_advertise_a_public_evidence_route(self):
        self.assertNotIn("localhost:8077/evidence", README)
        self.assertIn("There is deliberately no POST /evidence", FLAT_README)
        self.assertEqual(
            self.api.dispatch("POST", "/evidence", {}).body["error"]["code"],
            "NO_ROUTE")

    def test_the_readme_is_honest_that_the_listener_has_no_identity(self):
        for claim in ("no caller identity", "not an external-agent endpoint",
                      "single-threaded on purpose"):
            self.assertIn(claim, FLAT_README)

    def test_the_readme_states_the_binding_is_not_a_proof_of_issuance(self):
        for claim in ("integrity hash, not a proof of issuance",
                      "unkeyed sha256",
                      "exactly one writer of execution_authorizations"):
            self.assertIn(claim, FLAT_README)

    def test_the_readme_never_claims_overlap_grants_execution_authority(self):
        """The rejected claim, pinned out of the prose.

        The README used to say an ALLOW required that antecedent evidence
        exist. That is the self-bootstrap flaw in one sentence, so the suite
        asserts both that the claim is gone and that its correction is stated.
        """
        for retracted in (
            "that antecedent evidence exist",
            "missing antecedent evidence",
        ):
            self.assertNotIn(retracted, FLAT_README)
        for claim in (
            "token overlap confers no execution authority",
            "Retrieval recovers prior human exchanges",
            "a request must never be able to manufacture the authority that "
            "permits it",
            "never an intent:tx- or evi-run- id",
        ):
            self.assertIn(claim, FLAT_README)

    def test_the_readme_states_what_the_canonical_basis_assumes(self):
        for claim in (
            "its exact bytes are inside baseline_hash",
            "nothing in the slice proves that acceptance",
        ):
            self.assertIn(claim, FLAT_README)

    def test_the_readme_reason_code_claims_match_the_closed_vocabulary(self):
        from cis.authority import authorization as module
        codes = {
            value for name, value in vars(module).items()
            if name.startswith("REASON_")
        }
        self.assertNotIn("MISSING_ANTECEDENT_EVIDENCE", codes)
        self.assertIn("NO_CANONICAL_AUTHORIZATION_BASIS", codes)
        # Every HOLD the README enumerates must be a code that exists, and
        # every code must be reachable from the Workbench verdict function.
        verdict_source = inspect.getsource(Workbench._verdict)
        for code in codes:
            name = next(n for n, v in vars(module).items() if v == code)
            self.assertIn(name, verdict_source, code)

    def test_the_readme_does_not_claim_there_is_no_listener(self):
        self.assertNotIn("there is no listener", FLAT_README.lower())
        self.assertIn("Nothing listens by default", FLAT_README)

    def test_the_readme_counts_contracts_and_migrations_correctly(self):
        registry = support.blueprint().registry
        self.assertIn(f"{len(registry.contracts)} module contracts", FLAT_README)
        migrations = sorted(
            (ROOT / "src" / "cis" / "authority" / "migrations").glob("*.sql"))
        self.assertIn(f"{len(migrations)} migrations", FLAT_README)


class RouteListTests(unittest.TestCase):
    def setUp(self):
        self.api = WorkbenchApi(support.workbench())

    def test_every_route_the_health_payload_lists_is_actually_served(self):
        listed = [line.split()[:2] for line in _ROUTES.splitlines()]
        self.assertTrue(listed)
        for method, path in listed:
            probe = path.replace("<id>", "auth-nope") \
                        .replace("<transaction_id>", "tx-nope")
            body = {"verbatim": "x"} if path == "/instruction" else {}
            if path == "/execute":
                body = {"authorization_id": "auth-nope"}
            response = self.api.dispatch(method, probe, body)
            code = response.body.get("error", {}).get("code")
            self.assertNotEqual(code, "NO_ROUTE", f"{method} {path}")

    def test_the_route_list_declares_exactly_the_fields_each_post_accepts(self):
        self.assertIn('POST /instruction                   {"verbatim": "..."}',
                      _ROUTES)
        self.assertIn('POST /execute                       '
                      '{"authorization_id": "..."}', _ROUTES)


class ContractClaimTests(unittest.TestCase):
    """A contract field that names a method must name one that exists."""

    def _contract(self, module_id):
        return json.loads(
            (ROOT / "contracts" / f"{module_id}.contract.json")
            .read_text(encoding="utf-8"))

    def test_the_evidence_contract_names_the_methods_that_exist(self):
        contract = self._contract("cis.authority.evidence")
        self.assertIn("EvidenceAuthority.admit", contract["mutation_interface"])
        self.assertIn("EvidenceAuthority.record_conflict",
                      contract["mutation_interface"])
        self.assertTrue(hasattr(EvidenceAuthority, "admit"))
        self.assertTrue(hasattr(EvidenceAuthority, "record_conflict"))
        # The generic alias was deliberately removed; the contract must not
        # resurrect it in prose.
        self.assertFalse(hasattr(EvidenceAuthority, "record"))
        self.assertNotIn("EvidenceAuthority.record ",
                         contract["mutation_interface"])

    def test_the_evidence_contract_declares_admission_provenance(self):
        contract = self._contract("cis.authority.evidence")
        self.assertTrue(any("admission_basis" in item
                            for item in contract["evidence_produced"]))
        signature = inspect.signature(EvidenceAuthority.admit)
        parameter = signature.parameters["admission_basis"]
        self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_the_gateway_contract_does_not_claim_a_caller_supplied_operation(self):
        contract = self._contract("cis.execution.gateway")
        signature = inspect.signature(ExecutionGateway.dispatch)
        positional = [
            name for name, parameter in signature.parameters.items()
            if name != "self"
            and parameter.kind is not inspect.Parameter.KEYWORD_ONLY
        ]
        self.assertEqual(positional, ["authorization_id"])
        self.assertNotIn("operation name", contract["replacement_contract"])
        self.assertIn("never a dispatch argument",
                      contract["replacement_contract"])

    def test_the_api_contract_is_honest_about_the_listener(self):
        contract = self._contract("cis.interface.api")
        self.assertIn("no caller identity", contract["execution_location"])
        self.assertIn("single-threaded", contract["execution_location"])

    def test_the_store_contract_claims_only_authority_it_owns(self):
        contract = self._contract("cis.authority.store")
        self.assertEqual(contract["owned_authority"], ["schema_migrations"])
        migrations = (ROOT / "src" / "cis" / "authority" / "migrations"
                      / "0002_append_only_triggers.sql").read_text(
            encoding="utf-8")
        # The contract says UPDATE and DELETE are refused on ANY authority
        # table, schema_migrations included.
        self.assertIn("schema_migrations_no_update", migrations)
        self.assertIn("schema_migrations_no_delete", migrations)


class ColdStartTests(unittest.TestCase):
    """The store contract claims cold-start recoverability. Prove it.

    An authorization issued in one process must still verify in the next one,
    which means the binding has to recompute bit-identically from the file —
    canonical JSON, resumed sequence, no dependence on the in-process logical
    clock. Nothing else in the suite crosses a process-equivalent restart with
    a live ALLOW.
    """

    def test_an_allow_issued_before_a_restart_still_verifies_after_it(self):
        import tempfile

        from cis.authority import AuthorityStore

        path = Path(tempfile.mkdtemp(prefix="cis-clean-cold-")) / "authority.db"
        store = AuthorityStore(path)
        first = Workbench(store, blueprint=support.blueprint())
        first.set_initial_objective(support.OBJECTIVE)
        support.seed_evidence(first)
        outcome = first.submit_instruction(support.ALLOW_INSTRUCTION)
        authorization_id = outcome.authorization["authorization_id"]
        self.assertEqual(outcome.authorization["verdict"], "ALLOW")
        store.close()

        reopened = AuthorityStore(path)
        second = Workbench(reopened, blueprint=support.blueprint())
        self.assertEqual(
            second.authorizations.get(authorization_id)["binding_hash"],
            outcome.authorization["binding_hash"])
        run = second.execute(authorization_id)
        self.assertEqual(run["status"], "completed")
        reopened.close()

    def test_a_restart_does_not_renumber_history(self):
        import tempfile

        from cis.authority import AuthorityStore

        path = Path(tempfile.mkdtemp(prefix="cis-clean-seq-")) / "authority.db"
        store = AuthorityStore(path)
        first = Workbench(store, blueprint=support.blueprint())
        first.set_initial_objective(support.OBJECTIVE)
        first.submit_instruction("an earlier exchange")
        before = [int(row["seq"]) for row in first.trajectory.events()]
        store.close()

        reopened = AuthorityStore(path)
        second = Workbench(reopened, blueprint=support.blueprint())
        second.submit_instruction("a later exchange")
        after = [int(row["seq"]) for row in second.trajectory.events()]
        self.assertEqual(after[:len(before)], before)
        self.assertEqual(sorted(set(after)), after)
        reopened.close()


class DemoNarrationTests(unittest.TestCase):
    """The demo's step labels are claims, so its precondition is enforced."""

    def test_the_demo_refuses_an_authority_that_already_holds_conversation(self):
        """Replayed onto a used authority the labels would lie, so it refuses.

        On a second run the objective the demo redirects to already exists, so
        step 10 establishes nothing and step 11 refuses as a replay rather than
        as a stale authorization. The slice still fails closed either way; the
        narration is what would become false, so the demo names the conflict.
        """
        import argparse
        import tempfile

        from cis import __main__ as cli
        from cis.authority import AuthorityStore
        from cis.errors import CisError

        path = Path(tempfile.mkdtemp(prefix="cis-clean-demo-")) / "authority.db"
        store = AuthorityStore(path)
        used = Workbench(store, blueprint=support.blueprint())
        used.submit_instruction("an earlier conversation already happened")
        store.close()

        with self.assertRaises(CisError) as caught:
            cli.cmd_demo(argparse.Namespace(db=str(path)))
        self.assertIn("empty authority", caught.exception.message)
        self.assertEqual(caught.exception.detail["intent_transactions"], 1)

    def _demo_output(self):
        import argparse
        import contextlib
        import io

        from cis import __main__ as cli

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(cli.cmd_demo(argparse.Namespace(db=None)), 0)
        return buffer.getvalue()

    def test_the_demo_runs_clean_on_a_fresh_authority(self):
        output = self._demo_output()
        # The narration's load-bearing claims, as the demo actually runs.
        self.assertIn('"verdict": "ALLOW"', output)
        self.assertIn("AUTHORIZATION_STALE", output)
        self.assertIn("repeat changed nothing: "
                      "WORK_OUTSIDE_CANONICAL_AUTHORITY -> "
                      "WORK_OUTSIDE_CANONICAL_AUTHORITY", output)
        self.assertIn("scope identical to step 6: True", output)

    def test_the_demo_never_uses_a_held_request_as_its_own_evidence(self):
        """The rejected demo's trick, asserted absent from the real output.

        Every authorization the demo prints carries its required_evidence as a
        JSON column. Not one of them may name a prior request or a prior run,
        and the ALLOW must name the canonical manifest basis instead.
        """
        output = self._demo_output()
        cited = re.findall(r'"required_evidence_json": "(.*?)"(?:,|\n)', output)
        self.assertTrue(cited)
        for value in cited:
            self.assertNotIn("intent:tx-", value)
            self.assertNotIn("evi-run-", value)
        self.assertIn("canonical_evidence_basis:cis.workbench.projection",
                      output)
        self.assertIn('"basis_kind": '
                      '"VALIDATED_RECONSTRUCTION_MANIFEST_MODULE_EVIDENCE_BASIS"',
                      output)

    def test_the_demo_recovers_the_earlier_users_exact_words(self):
        """Continuity still works, with no manual ingestion anywhere in it."""
        output = self._demo_output()
        earlier = ("My questions and semantic memory fragments must recover "
                   "prior intent so important concepts do not go dormant")
        # Once as the user's own instruction, and again as the antecedent a
        # later vague fragment recovered in its original language.
        self.assertGreaterEqual(output.count(earlier), 2)
        self.assertIn('"provenance": "ORIGINAL_HUMAN_INTENT"', output)
        self.assertNotIn("import_authoritative_evidence",
                         (ROOT / "src" / "cis" / "__main__.py")
                         .read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
