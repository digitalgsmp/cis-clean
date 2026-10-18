"""Exact binding, the authorization basis, and the ways an ALLOW fails closed."""

import copy
import unittest

from cis.authority.authorization import (
    ALLOW, HOLD, REASON_EVIDENCE_CONFLICT, REASON_IN_AUTHORITY,
    REASON_NO_CANONICAL_BASIS, REASON_OBJECTIVE_SELF_ESTABLISHED,
    REASON_OUTSIDE_AUTHORITY, REASON_RETRIEVAL_CUE, binding_hash,
)
from cis.blueprint import CANONICAL_BASIS_KIND
from cis.errors import (
    AuthorizationRefused, BindingError, StaleAuthorization,
)

from . import support


class VerdictTests(unittest.TestCase):
    def test_work_inside_authority_with_evidence_is_allowed(self):
        _, outcome = support.allow_outcome()
        authorization = outcome.authorization
        self.assertEqual(authorization["verdict"], ALLOW)
        self.assertEqual(authorization["target_module_id"],
                         "cis.workbench.projection")
        self.assertTrue(authorization["scope"]["allowed_scope"])
        self.assertTrue(authorization["scope"]["stopping_condition"])
        self.assertTrue(authorization["scope"]["return_point"])

    def test_absent_antecedents_do_not_change_the_verdict(self):
        """Retrieval is continuity, not permission.

        With no admitted evidence and no prior exchange there is nothing to
        retrieve, and the verdict is identical to the verdict reached with a
        full corpus: the canonical architecture decides, so overlap is neither
        a requirement nor a grant.
        """
        wb = support.workbench(with_evidence=False)
        outcome = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        self.assertEqual(outcome.antecedents, [])
        self.assertEqual(outcome.authorization["verdict"], ALLOW)
        self.assertEqual(outcome.authorization["reason_code"],
                         REASON_IN_AUTHORITY)
        _, with_corpus = support.allow_outcome()
        self.assertEqual(
            outcome.authorization["scope"],
            with_corpus.authorization["scope"],
        )

    def test_required_evidence_names_canonical_basis_not_retrieved_ids(self):
        wb, outcome = support.allow_outcome()
        required = outcome.authorization["scope"]["required_evidence"]
        self.assertEqual(sorted(required),
                         sorted(support.CANONICAL_REQUIRED_EVIDENCE))
        for entry in required:
            self.assertTrue(entry.startswith("canonical_evidence_basis:"), entry)
            self.assertNotIn("intent:tx-", entry)
            self.assertNotIn("evi-run-", entry)
        basis = outcome.authorization_basis
        self.assertEqual(basis["basis_kind"], CANONICAL_BASIS_KIND)
        self.assertEqual(basis["evidence_basis"],
                         wb.blueprint.evidence_basis("cis.workbench.projection"))
        self.assertEqual(basis["bound_into"]["baseline_hash"],
                         wb.blueprint.baseline_hash)

    def test_a_hold_carries_no_authorization_basis(self):
        wb = support.workbench()
        outcome = wb.submit_instruction("What should we reconstruct next?")
        self.assertEqual(outcome.authorization["verdict"], HOLD)
        self.assertIsNone(outcome.authorization_basis)

    def test_a_question_produces_hold_and_authorizes_nothing(self):
        wb = support.workbench()
        outcome = wb.submit_instruction("What should we reconstruct next?")
        self.assertEqual(outcome.authorization["verdict"], HOLD)
        self.assertEqual(outcome.authorization["reason_code"],
                         REASON_RETRIEVAL_CUE)
        self.assertEqual(outcome.authorization["scope"]["allowed_scope"], [])

    def test_work_outside_the_blueprint_produces_hold(self):
        wb = support.workbench()
        outcome = wb.submit_instruction(
            "Reconstruct the legacy pipeline relay and the gateway profiles")
        self.assertEqual(outcome.authorization["verdict"], HOLD)
        self.assertEqual(outcome.authorization["reason_code"],
                         REASON_OUTSIDE_AUTHORITY)

    def test_an_ambiguous_target_produces_hold(self):
        wb = support.workbench()
        outcome = wb.submit_instruction(
            "Reconstruct cis.workbench.projection and cis.workbench.service")
        self.assertEqual(outcome.authorization["reason_code"],
                         REASON_OUTSIDE_AUTHORITY)

    def test_a_recorded_evidence_conflict_fails_closed(self):
        wb = support.workbench()
        wb.evidence.record_conflict(conflict_id="cf-1", subject="two owners",
                                    detail={"authority": "t"})
        outcome = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        self.assertEqual(outcome.authorization["verdict"], HOLD)
        self.assertEqual(outcome.authorization["reason_code"],
                         REASON_EVIDENCE_CONFLICT)

    def test_scope_is_derived_from_the_target_module_contract(self):
        wb, outcome = support.allow_outcome()
        scope = outcome.authorization["scope"]
        contract = wb.blueprint.registry.get("cis.workbench.projection")
        self.assertIn("module:cis.workbench.projection", scope["allowed_scope"])
        self.assertIn(f"layer:{contract.layer}", scope["allowed_scope"])
        self.assertEqual(scope["stopping_condition"], contract.verification)
        for forbidden in contract.forbidden_dependencies:
            self.assertIn(forbidden, scope["forbidden_actions"])
        self.assertIn("write:/mnt/projects/cis", scope["forbidden_actions"])
        self.assertIn("network:any", scope["forbidden_actions"])
        self.assertIn("model:any", scope["forbidden_actions"])


class SelfBootstrapTests(unittest.TestCase):
    """A request must not be able to manufacture the authority permitting it.

    The rejected behaviour: submit a request, receive HOLD, submit the same
    request again, and have the first (held) request retrieved as the evidence
    that authorizes the second. These tests pin the corrected rule — permission
    comes from canonical accepted authority for the target module and from
    nothing a conversation accumulates.
    """

    def _held_workbench(self):
        """A Workbench whose target module has no canonical basis at all."""
        return support.workbench(
            blueprint=support.blueprint_without_canonical_basis())

    def test_repeating_a_held_request_cannot_turn_hold_into_allow(self):
        wb = self._held_workbench()
        first = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        second = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        for outcome in (first, second):
            self.assertEqual(outcome.authorization["verdict"], HOLD)
            self.assertEqual(outcome.authorization["reason_code"],
                             REASON_NO_CANONICAL_BASIS)
            self.assertEqual(outcome.authorization["scope"]["required_evidence"], [])
        # The second request DID retrieve the first as continuity context —
        # and that context changed nothing about the verdict.
        self.assertIn(f"intent:{first.transaction_id}",
                      [a["evidence_id"] for a in second.antecedents])

    def test_repeating_an_out_of_scope_request_cannot_turn_hold_into_allow(self):
        wb = support.workbench()
        words = "Reconstruct the legacy pipeline relay in the clean environment"
        first = wb.submit_instruction(words)
        second = wb.submit_instruction(words)
        for outcome in (first, second):
            self.assertEqual(outcome.authorization["verdict"], HOLD)
            self.assertEqual(outcome.authorization["reason_code"],
                             REASON_OUTSIDE_AUTHORITY)

    def test_a_repeat_of_an_allowed_request_gains_no_broader_permission(self):
        """The explicit choice: the manifest already supplies the authority.

        The first request ALLOWs, because the target module is already selected
        by the validated architecture and carries a canonical evidence basis.
        The second is a distinct transaction with its own authorization, and it
        is bounded byte-identically — same operation, same scope, same required
        evidence. Repetition buys nothing.
        """
        wb = support.workbench()
        first = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        second = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        self.assertEqual(first.authorization["verdict"], ALLOW)
        self.assertEqual(second.authorization["verdict"], ALLOW)
        self.assertNotEqual(first.transaction_id, second.transaction_id)
        self.assertEqual(first.authorization["scope"],
                         second.authorization["scope"])
        self.assertEqual(first.authorization_basis, second.authorization_basis)
        # Each ALLOW still authorizes exactly one run of exactly one module.
        self.assertEqual(second.authorization["target_module_id"],
                         first.authorization["target_module_id"])

    def test_a_prior_question_naming_the_module_cannot_unlock_execution(self):
        wb = self._held_workbench()
        question = wb.submit_instruction(
            "What does cis.workbench.projection currently show?")
        self.assertEqual(question.authorization["verdict"], HOLD)
        self.assertEqual(question.authorization["reason_code"],
                         REASON_RETRIEVAL_CUE)
        instruction = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        self.assertEqual(instruction.authorization["verdict"], HOLD)
        self.assertEqual(instruction.authorization["reason_code"],
                         REASON_NO_CANONICAL_BASIS)

    def test_prior_execution_evidence_cannot_unlock_a_later_instruction(self):
        wb = support.workbench(
            blueprint=support.blueprint_without_canonical_basis())
        # Real governed execution against a module that DOES have canonical
        # authority, which writes an execution_evidence record.
        allowed = wb.submit_instruction(
            "Reconstruct cis.authority.store in the clean environment")
        self.assertEqual(allowed.authorization["verdict"], ALLOW)
        wb.execute(allowed.authorization["authorization_id"])
        generated = [row["evidence_id"] for row in wb.evidence.all()
                     if row["kind"] == "execution_evidence"]
        self.assertTrue(generated)

        later = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        self.assertEqual(later.authorization["verdict"], HOLD)
        self.assertEqual(later.authorization["reason_code"],
                         REASON_NO_CANONICAL_BASIS)

    def test_no_allow_ever_cites_generated_execution_evidence(self):
        wb, outcome = support.allow_outcome()
        wb.execute(outcome.authorization["authorization_id"])
        second = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        self.assertEqual(second.authorization["verdict"], ALLOW)
        required = second.authorization["scope"]["required_evidence"]
        self.assertEqual(sorted(required),
                         sorted(support.CANONICAL_REQUIRED_EVIDENCE))
        joined = " ".join(required)
        self.assertNotIn("evi-run-", joined)
        self.assertNotIn("intent:", joined)

    def test_an_unrelated_prior_statement_with_one_token_cannot_unlock(self):
        wb = self._held_workbench()
        wb.submit_instruction(
            "The clean environment has no credential worth protecting")
        outcome = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        # Overlap genuinely exists — "clean" and "environment" matched.
        matched = {term for a in outcome.antecedents for term in a["matched_terms"]}
        self.assertIn("environment", matched)
        self.assertEqual(outcome.authorization["verdict"], HOLD)
        self.assertEqual(outcome.authorization["reason_code"],
                         REASON_NO_CANONICAL_BASIS)

    def test_an_emptied_canonical_basis_fails_closed_at_authorization(self):
        """The second half of the boundary the manifest loader also enforces."""
        wb = self._held_workbench()
        self.assertIsNone(
            wb.blueprint.canonical_authorization_basis("cis.workbench.projection"))
        outcome = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        self.assertEqual(outcome.authorization["verdict"], HOLD)
        self.assertEqual(outcome.authorization["reason_code"],
                         REASON_NO_CANONICAL_BASIS)
        self.assertIsNone(outcome.authorization_basis)

    def test_a_request_cannot_supply_the_objective_that_authorizes_it(self):
        wb = support.workbench(with_objective=False)
        outcome = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        self.assertEqual(outcome.authorization["verdict"], HOLD)
        self.assertEqual(outcome.authorization["reason_code"],
                         REASON_OBJECTIVE_SELF_ESTABLISHED)
        # The objective is recorded and kept; it just does not authorize the
        # words that created it.
        self.assertEqual(outcome.objective["established_by"],
                         outcome.transaction_id)

    def test_repeating_the_words_that_set_direction_still_cannot_unlock(self):
        """The same loophole one level up, closed.

        Without this, the rejected retry would survive as: be held for having
        no objective, resend the identical words, and be authorized under the
        objective the first copy established.
        """
        wb = support.workbench(with_objective=False)
        first = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        second = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        third = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        for outcome in (first, second, third):
            self.assertEqual(outcome.authorization["verdict"], HOLD)
            self.assertEqual(outcome.authorization["reason_code"],
                             REASON_OBJECTIVE_SELF_ESTABLISHED)

    def test_direction_from_a_different_earlier_exchange_is_independent(self):
        """Direction has to come from somewhere, and an earlier exchange counts.

        What is refused is a request standing in for its own direction — not
        direction established by a human saying something else first.
        """
        wb = support.workbench(with_objective=False)
        wb.submit_instruction(
            "We are rebuilding the Workbench trajectory projection next")
        outcome = wb.submit_instruction(support.ALLOW_INSTRUCTION)
        self.assertEqual(outcome.authorization["verdict"], ALLOW)
        self.assertEqual(outcome.objective["established_by"],
                         wb.intent.history()[0]["transaction_id"])

    def test_repeating_a_module_naming_redirection_still_cannot_unlock(self):
        wb = support.workbench()
        words = "REDIRECT: reconstruct cis.workbench.projection instead"
        for _ in range(2):
            outcome = wb.submit_instruction(words)
            self.assertEqual(outcome.authorization["verdict"], HOLD)
            self.assertEqual(outcome.authorization["reason_code"],
                             REASON_OBJECTIVE_SELF_ESTABLISHED)

    def test_a_redirection_that_names_a_module_does_not_authorize_itself(self):
        wb = support.workbench()
        outcome = wb.submit_instruction(
            "REDIRECT: reconstruct cis.workbench.projection instead")
        self.assertEqual(outcome.authorization["verdict"], HOLD)
        self.assertEqual(outcome.authorization["reason_code"],
                         REASON_OBJECTIVE_SELF_ESTABLISHED)

    def test_the_verdict_function_cannot_see_retrieved_antecedents(self):
        """Structural proof, not a behavioural one.

        If the antecedents are not a parameter of the decision, no future edit
        can quietly reintroduce overlap as a permission condition without
        changing the signature this test pins.
        """
        import inspect
        from cis.workbench.service import Workbench as WorkbenchService
        parameters = set(
            inspect.signature(WorkbenchService._verdict).parameters)
        self.assertNotIn("antecedents", parameters)
        self.assertIn("basis", parameters)
        source = inspect.getsource(WorkbenchService._verdict)
        for token in ("antecedent", "score", "matched_terms", "retrieve"):
            self.assertNotIn(token, source)


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.wb, self.outcome = support.allow_outcome()
        self.authorization_id = self.outcome.authorization["authorization_id"]
        self.row = self.wb.authorizations.get(self.authorization_id)

    def _args(self, **overrides):
        args = {
            "authorization_id": str(self.row["authorization_id"]),
            "transaction_id": str(self.row["transaction_id"]),
            "decision_id": str(self.row["decision_id"]),
            "objective_id": str(self.row["objective_id"]),
            "verdict": str(self.row["verdict"]),
            "target_module_id": self.row["target_module_id"],
            "verbatim_hash": str(self.row["verbatim_hash"]),
            "decision_hash": str(self.row["decision_hash"]),
            "baseline_hash": str(self.row["baseline_hash"]),
            "scope": self.wb.authorizations.scope_of(self.row),
        }
        args.update(overrides)
        return args

    def test_the_binding_recomputes_exactly(self):
        self.assertEqual(binding_hash(**self._args()), self.row["binding_hash"])

    def test_the_binding_covers_the_instruction(self):
        self.assertNotEqual(
            binding_hash(**self._args(verbatim_hash="0" * 64)),
            self.row["binding_hash"])

    def test_the_binding_covers_the_continuity_decision(self):
        self.assertNotEqual(
            binding_hash(**self._args(decision_hash="0" * 64)),
            self.row["binding_hash"])
        self.assertNotEqual(
            binding_hash(**self._args(decision_id="dec-other")),
            self.row["binding_hash"])

    def test_the_binding_covers_the_authorization_identity_and_verdict(self):
        self.assertNotEqual(
            binding_hash(**self._args(authorization_id="auth-other")),
            self.row["binding_hash"])
        self.assertNotEqual(
            binding_hash(**self._args(verdict="HOLD")),
            self.row["binding_hash"])

    def test_the_binding_covers_every_scope_field(self):
        baseline = self.row["binding_hash"]
        scope = self.wb.authorizations.scope_of(self.row)
        for field in scope:
            widened = copy.deepcopy(scope)
            value = widened[field]
            widened[field] = value + ["anything"] if isinstance(value, list) \
                else f"{value} and more"
            self.assertNotEqual(binding_hash(**self._args(scope=widened)),
                                baseline, field)

    def test_the_binding_covers_the_baseline_and_the_objective(self):
        self.assertNotEqual(
            binding_hash(**self._args(baseline_hash="0" * 64)),
            self.row["binding_hash"])
        self.assertNotEqual(
            binding_hash(**self._args(objective_id="obj-other")),
            self.row["binding_hash"])

    def test_an_incomplete_contract_cannot_be_bound(self):
        scope = self.wb.authorizations.scope_of(self.row)
        del scope["stopping_condition"]
        with self.assertRaises(AuthorizationRefused):
            binding_hash(**self._args(scope=scope))


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.wb, self.outcome = support.allow_outcome()
        self.authorization_id = self.outcome.authorization["authorization_id"]
        self.baseline = self.wb.blueprint.baseline_hash

    _DERIVE = object()

    def _verify(self, authorization_id=None, baseline=None, objective=_DERIVE):
        return self.wb.authorizations.verify(
            authorization_id or self.authorization_id,
            baseline_hash=baseline or self.baseline,
            active_objective_id=(self.wb.continuity.active_objective_id()
                                 if objective is self._DERIVE else objective),
        )

    def test_a_valid_allow_verifies(self):
        row = self._verify()
        self.assertEqual(row["verdict"], ALLOW)

    def test_an_unknown_authorization_is_refused(self):
        with self.assertRaises(AuthorizationRefused):
            self._verify("auth-does-not-exist")

    def test_a_hold_never_verifies(self):
        outcome = self.wb.submit_instruction("What is the current stage?")
        with self.assertRaises(AuthorizationRefused) as caught:
            self._verify(outcome.authorization["authorization_id"])
        self.assertEqual(caught.exception.code, "AUTHORIZATION_REFUSED")

    def test_a_tampered_binding_fails_closed(self):
        """A forged row — right fields, wrong binding — does not verify.

        Authority is append-only, so an attacker cannot edit the real row; the
        realistic attack is appending a row that claims a wider scope while
        carrying a copied binding hash. That is what this proves is refused.
        """
        row = self.wb.authorizations.get(self.authorization_id)
        forged = row.as_dict()
        forged["authorization_id"] = "auth-forged"
        forged["allowed_scope_json"] = '["module:cis.authority.store", "layer:L2"]'
        forged["seq"] = self.wb.store.next_seq()
        forged["created_at"] = self.wb.store.now()
        self.wb.store.insert("execution_authorizations", forged)

        with self.assertRaises(BindingError) as caught:
            self._verify("auth-forged")
        self.assertNotEqual(caught.exception.detail["recorded"],
                            caught.exception.detail["recomputed"])

    def test_an_authorization_whose_instruction_is_unreachable_fails_closed(self):
        row = self.wb.authorizations.get(self.authorization_id)
        orphan = row.as_dict()
        orphan["authorization_id"] = "auth-orphan"
        orphan["seq"] = self.wb.store.next_seq()
        orphan["created_at"] = self.wb.store.now()
        # A row pointing at a decision that exists but an instruction hash that
        # no longer matches is caught by the recompute, not by a foreign key.
        orphan["verbatim_hash"] = "0" * 64
        self.wb.store.insert("execution_authorizations", orphan)
        with self.assertRaises(BindingError):
            self._verify("auth-orphan")

    def test_offline_corruption_of_the_verbatim_hash_fails_closed(self):
        # Controlled test-only bypass simulates an offline database rewrite.
        self.wb.store.execute_raw("DROP TRIGGER intent_transactions_no_update")
        transaction_id = self.outcome.transaction_id
        self.wb.store.execute_raw(
            "UPDATE intent_transactions SET verbatim_hash = ? "
            "WHERE transaction_id = ?",
            ("0" * 64, transaction_id),
        )
        with self.assertRaises(BindingError) as caught:
            self._verify()
        self.assertIn("verbatim hash", caught.exception.message)

    def test_offline_corruption_of_decision_source_fields_fails_closed(self):
        self.wb.store.execute_raw("DROP TRIGGER continuity_decisions_no_update")
        self.wb.store.execute_raw(
            "UPDATE continuity_decisions SET disposition = ? "
            "WHERE decision_id = ?",
            ("FORGED_DISPOSITION", self.outcome.decision["decision_id"]),
        )
        with self.assertRaises(BindingError) as caught:
            self._verify()
        self.assertIn("decision hash", caught.exception.message)

    def test_a_stale_authorization_fails_closed_after_explicit_redirection(self):
        self.wb.submit_instruction(
            "New objective: prove the Layer-2 execution boundary end to end")
        with self.assertRaises(StaleAuthorization) as caught:
            self._verify()
        self.assertNotEqual(caught.exception.detail["issued_under"],
                            caught.exception.detail["active_objective_id"])

    def test_a_moved_baseline_fails_closed(self):
        with self.assertRaises(StaleAuthorization) as caught:
            self._verify(baseline="0" * 64)
        self.assertEqual(caught.exception.detail["current"], "0" * 64)

    def test_no_active_objective_fails_closed(self):
        with self.assertRaises(StaleAuthorization):
            self._verify(objective=None)


class BindingIsIntegrityNotProvenanceTests(unittest.TestCase):
    """The honest limit of ``binding_hash``, pinned so it cannot be mistaken.

    ``binding_hash`` is an unkeyed sha256 over public fields. It proves the row
    is internally consistent with the instruction, the decision, the scope, the
    objective and the baseline. It does NOT prove who issued the row, so a
    holder of the raw append primitive can append a self-consistent ALLOW and
    recompute a matching binding. These tests state that plainly and then pin
    the control that actually stands in the way: exactly one writer of the
    table, reachable from no route.
    """

    def setUp(self):
        self.wb, self.outcome = support.allow_outcome()
        self.row = self.wb.authorizations.get(
            self.outcome.authorization["authorization_id"])

    def _forge(self, authorization_id, **scope_overrides):
        import json
        forged = self.row.as_dict()
        scope = self.wb.authorizations.scope_of(self.row)
        scope.update(scope_overrides)
        forged["authorization_id"] = authorization_id
        forged["operation"] = scope["operation"]
        forged["allowed_scope_json"] = json.dumps(scope["allowed_scope"],
                                                  sort_keys=True)
        forged["binding_hash"] = binding_hash(
            authorization_id=authorization_id,
            transaction_id=str(self.row["transaction_id"]),
            decision_id=str(self.row["decision_id"]),
            objective_id=str(self.row["objective_id"]),
            verdict=str(self.row["verdict"]),
            target_module_id=self.row["target_module_id"],
            verbatim_hash=str(self.row["verbatim_hash"]),
            decision_hash=str(self.row["decision_hash"]),
            baseline_hash=str(self.row["baseline_hash"]),
            scope=scope,
        )
        forged["seq"] = self.wb.store.next_seq()
        forged["created_at"] = self.wb.store.now()
        self.wb.store.insert("execution_authorizations", forged)

    def test_an_inconsistent_forged_row_is_refused(self):
        """The copied-hash attack — the one the binding does stop."""
        import json
        forged = self.row.as_dict()
        forged["authorization_id"] = "auth-copied-hash"
        forged["operation"] = "verify_module"
        forged["seq"] = self.wb.store.next_seq()
        forged["created_at"] = self.wb.store.now()
        self.wb.store.insert("execution_authorizations", forged)
        with self.assertRaises(BindingError):
            self.wb.execute("auth-copied-hash")

    def test_a_self_consistent_forged_row_is_not_caught_by_the_binding(self):
        """Stated limitation, not a passing claim of safety.

        An unkeyed digest cannot distinguish 'issued by the authorization
        authority' from 'appended by anything holding AuthorityStore.insert'.
        Closing this needs a key and a key owner, which this slice does not
        have. The test exists so no reader believes otherwise.
        """
        self._forge("auth-self-consistent", operation="verify_module")
        verified = self.wb.authorizations.verify(
            "auth-self-consistent",
            baseline_hash=self.wb.blueprint.baseline_hash,
            active_objective_id=self.wb.continuity.active_objective_id(),
        )
        self.assertEqual(verified["operation"], "verify_module")

    def test_only_the_authorization_authority_writes_the_table(self):
        """The control that is real: one writer, named, and no route to it."""
        from pathlib import Path
        src = Path(__file__).resolve().parents[1] / "src" / "cis"
        writers = sorted(
            path.relative_to(src).as_posix()
            for path in src.rglob("*.py")
            if 'insert("execution_authorizations"' in
            path.read_text(encoding="utf-8")
        )
        self.assertEqual(writers, ["authority/authorization.py"])

    def test_no_control_surface_route_reaches_the_append_primitive(self):
        from pathlib import Path
        src = Path(__file__).resolve().parents[1] / "src" / "cis"
        text = (src / "interface" / "api.py").read_text(encoding="utf-8")
        for token in ("insert(", "store", "AuthorityStore", "execute_raw"):
            self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
