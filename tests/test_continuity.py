"""Continuity of perspective.

Eric, recorded verbatim at dev_continuity_events revision 178: "so the
continuity of perspective you said I was supplying with semantic memories will
be built into the pipeline and my questions wont keep sending us down rabbit
holes causing important concepts to go dormant."

These tests are that criterion, mechanised.
"""

import unittest

from cis.continuity import ADDITION, CORRECTION, QUESTION, REDIRECTION, classify
from cis.continuity.retrieval import (
    ADMITTED_KNOWLEDGE, GENERATED_DERIVATIVE, ORIGINAL_HUMAN_INTENT,
    provenance_of, retrieve_antecedents, tokenise,
)

from . import support


class ClassifierTests(unittest.TestCase):
    def test_a_question_is_a_retrieval_cue_and_does_not_redirect(self):
        for text in (
            "What does the trajectory projection currently show?",
            "why did we decide the planes are properties?",
            "Is the execution port the only call path to a backend?",
            "how does the you-are-here marker get derived",
        ):
            result = classify(text)
            self.assertEqual(result.classification, QUESTION, text)
            self.assertTrue(result.is_retrieval_cue, text)
            self.assertFalse(result.redirects, text)

    def test_a_vague_memory_fragment_is_a_retrieval_cue(self):
        for text in (
            "I vaguely recall something about concepts going dormant",
            "didn't we talk about semantic memories at some point",
            "there was something about questions sending us down rabbit holes",
        ):
            result = classify(text)
            self.assertTrue(result.is_fragment, text)
            self.assertTrue(result.is_retrieval_cue, text)
            self.assertFalse(result.redirects, text)

    def test_only_an_explicit_marker_redirects(self):
        for text in (
            "REDIRECT: build the evidence ingestion module instead",
            "New objective: prove the execution boundary",
            "stop working on the projection and prove the boundary",
        ):
            result = classify(text)
            self.assertEqual(result.classification, REDIRECTION, text)
            self.assertTrue(result.redirects, text)

    def test_an_ordinary_instruction_is_an_addition_not_a_redirection(self):
        result = classify("Reconstruct cis.workbench.projection in the clean environment")
        self.assertEqual(result.classification, ADDITION)
        self.assertFalse(result.redirects)
        self.assertFalse(result.is_retrieval_cue)

    def test_a_correction_refines_rather_than_replaces(self):
        result = classify("Correction: the port is Layer 2, not Layer 3")
        self.assertEqual(result.classification, CORRECTION)
        self.assertFalse(result.redirects)

    def test_an_empty_instruction_never_redirects(self):
        self.assertFalse(classify("   ").redirects)

    def test_classification_is_deterministic(self):
        text = "I think we discussed the trajectory thing"
        self.assertEqual(classify(text).as_dict(), classify(text).as_dict())


class RetrievalTests(unittest.TestCase):
    def setUp(self):
        self.wb = support.workbench()

    def test_a_fragment_retrieves_the_antecedent_in_original_language(self):
        outcome = self.wb.submit_instruction(
            "I vaguely remember something about my questions causing important "
            "concepts to go dormant"
        )
        self.assertTrue(outcome.antecedents)
        top = outcome.antecedents[0]
        self.assertEqual(top["evidence_id"], "evi-rev178")
        self.assertEqual(top["original_language"], support.ANTECEDENT_VERBATIM)
        self.assertIn("dormant", top["matched_terms"])
        self.assertIn("concepts", top["matched_terms"])

    def test_retrieval_is_deterministic_and_stably_ordered(self):
        records = [r.as_dict() for r in self.wb.evidence.all()]
        cue = "execution backend layer authority projection"
        first = [a.as_dict() for a in retrieve_antecedents(cue, records)]
        second = [a.as_dict() for a in retrieve_antecedents(cue, reversed(records))]
        self.assertEqual(first, second)

    def test_an_unrelated_cue_retrieves_nothing_rather_than_guessing(self):
        records = [r.as_dict() for r in self.wb.evidence.all()]
        self.assertEqual(retrieve_antecedents("xylophone quartz zeppelin", records), [])

    def test_stopwords_carry_no_signal(self):
        self.assertEqual(tokenise("what is the thing about it"), [])

    def test_prior_user_words_are_retrieved_without_manual_evidence_ingestion(self):
        wb = support.workbench(with_evidence=False)
        earlier = (
            "We explored loops within loops integrated between knowledge domains"
        )
        first = wb.submit_instruction(earlier)
        later = wb.submit_instruction(
            "I vaguely recall something about loops integrated between domains"
        )
        self.assertTrue(later.antecedents)
        self.assertEqual(later.antecedents[0]["original_language"], earlier)
        self.assertEqual(
            later.antecedents[0]["evidence_id"],
            f"intent:{first.transaction_id}",
        )


class ProvenancePreferenceTests(unittest.TestCase):
    """Human intent outranks a machine derivative of it, explicitly.

    Retrieval exists so meaning survives. If a record CIS generated about its
    own execution can outrank the words the human actually used, the memory
    the user gets back is a restatement rather than their own intent — so the
    preference is part of the ordering rule, not left to scores.
    """

    def test_kinds_map_to_a_closed_provenance_vocabulary(self):
        self.assertEqual(provenance_of("prior_human_intent"),
                         ORIGINAL_HUMAN_INTENT)
        self.assertEqual(provenance_of("user_instruction"),
                         ORIGINAL_HUMAN_INTENT)
        self.assertEqual(provenance_of("execution_evidence"),
                         GENERATED_DERIVATIVE)
        # An unknown kind is admitted knowledge, never promoted to intent.
        self.assertEqual(provenance_of("something_new"), ADMITTED_KNOWLEDGE)

    def test_human_intent_outranks_execution_evidence_on_the_same_cue(self):
        cue = "reconstruct cis.workbench.projection"
        records = [
            {"evidence_id": "evi-run-auth-tx-aaa", "kind": "execution_evidence",
             "source_ref": "backend_runs:run-auth-tx-aaa",
             "original_language": "operation=reconstruct_module "
                                  "allowed_scope=module:cis.workbench.projection",
             "content": "reconstruct cis.workbench.projection"},
            {"evidence_id": "intent:tx-zzz", "kind": "prior_human_intent",
             "source_ref": "intent_transactions:tx-zzz:verbatim_instruction",
             "original_language": "reconstruct cis.workbench.projection",
             "content": "reconstruct cis.workbench.projection"},
        ]
        ranked = retrieve_antecedents(cue, records)
        self.assertEqual([a.evidence_id for a in ranked],
                         ["intent:tx-zzz", "evi-run-auth-tx-aaa"])
        # And the lower-ranked one scored at least as well, so this is
        # provenance winning rather than a scoring artefact.
        self.assertGreaterEqual(ranked[1].score, ranked[0].score)
        self.assertEqual(ranked[0].provenance, ORIGINAL_HUMAN_INTENT)

    def test_the_preference_holds_through_the_live_workbench(self):
        wb, outcome = support.allow_outcome()
        wb.execute(outcome.authorization["authorization_id"])
        later = wb.submit_instruction(
            "I vaguely remember something about reconstructing "
            "cis.workbench.projection")
        provenances = [a["provenance"] for a in later.antecedents]
        self.assertIn(ORIGINAL_HUMAN_INTENT, provenances)
        self.assertEqual(provenances[0], ORIGINAL_HUMAN_INTENT)
        self.assertEqual(
            provenances, sorted(provenances, key=lambda p: (
                p != ORIGINAL_HUMAN_INTENT, p == GENERATED_DERIVATIVE)))

    def test_every_antecedent_states_it_is_not_an_authorization_basis(self):
        wb, outcome = support.allow_outcome()
        later = wb.submit_instruction(
            "I vaguely recall something about the projection")
        self.assertTrue(later.antecedents)
        for antecedent in later.antecedents:
            self.assertEqual(
                antecedent["role"],
                "CONTEXTUAL_CONTINUITY_EVIDENCE_NOT_AUTHORIZATION_BASIS")


class ObjectiveContinuityTests(unittest.TestCase):
    def setUp(self):
        self.wb = support.workbench()
        self.initial = self.wb.active_objective()["objective_id"]

    def test_a_question_leaves_the_active_objective_exactly_where_it_was(self):
        outcome = self.wb.submit_instruction("What is the current macro stage?")
        self.assertEqual(outcome.decision["classification"], QUESTION)
        self.assertEqual(outcome.decision["treated_as"], "retrieval_cue")
        self.assertEqual(outcome.decision["active_objective_id"], self.initial)
        self.assertEqual(self.wb.active_objective()["objective_id"], self.initial)
        self.assertIn("PRESERVED", outcome.decision["disposition"])

    def test_a_fragment_leaves_the_active_objective_where_it_was(self):
        outcome = self.wb.submit_instruction(
            "didn't we discuss semantic memories going dormant")
        self.assertEqual(self.wb.active_objective()["objective_id"], self.initial)
        self.assertEqual(outcome.decision["treated_as"], "retrieval_cue")

    def test_an_addition_leaves_the_active_objective_where_it_was(self):
        self.wb.submit_instruction("Also record the evidence basis for each module")
        self.assertEqual(self.wb.active_objective()["objective_id"], self.initial)

    def test_explicit_redirection_changes_the_objective(self):
        outcome = self.wb.submit_instruction(
            "New objective: prove the Layer-2 execution boundary end to end")
        self.assertEqual(outcome.decision["classification"], REDIRECTION)
        self.assertEqual(outcome.decision["treated_as"], "objective_supersession")
        self.assertNotEqual(outcome.decision["active_objective_id"], self.initial)
        self.assertEqual(outcome.decision["prior_objective_id"], self.initial)
        self.assertEqual(self.wb.active_objective()["objective_id"],
                         outcome.decision["active_objective_id"])

    def test_a_superseded_objective_is_retained_not_erased(self):
        self.wb.submit_instruction("REDIRECT: prove the execution boundary")
        self.assertIn(self.initial, self.wb.continuity.superseded_objective_ids())
        self.assertIsNotNone(self.wb.intent.objective(self.initial))

    def test_many_questions_never_accumulate_into_a_redirection(self):
        for i in range(5):
            self.wb.submit_instruction(f"What about point {i}?")
        self.assertEqual(self.wb.active_objective()["objective_id"], self.initial)

    def test_first_question_preserves_no_active_objective(self):
        wb = support.workbench(with_objective=False, with_evidence=False)
        outcome = wb.submit_instruction("What had we decided about the pipeline?")
        self.assertIsNone(wb.active_objective())
        self.assertEqual(outcome.objective, {})
        self.assertIsNone(outcome.decision["active_objective_id"])
        self.assertEqual(outcome.authorization["verdict"], "HOLD")

    def test_first_memory_fragment_preserves_no_active_objective(self):
        wb = support.workbench(with_objective=False, with_evidence=False)
        outcome = wb.submit_instruction(
            "I vaguely remember something about loops within loops")
        self.assertIsNone(wb.active_objective())
        self.assertEqual(outcome.objective, {})
        self.assertIsNone(outcome.decision["active_objective_id"])


class VerbatimPreservationTests(unittest.TestCase):
    def test_exact_words_are_preserved_separately_from_interpretation(self):
        wb = support.workbench()
        verbatim = (
            "  so the continuity of perspective\tyou said I was supplying — "
            "my questions wont keep sending us down rabbit holes  "
        )
        outcome = wb.submit_instruction(verbatim)
        row = wb.intent.transaction(outcome.transaction_id)
        self.assertEqual(row["verbatim_instruction"], verbatim)
        self.assertNotEqual(row["interpretation"], verbatim)
        self.assertEqual(row["interpretation_label"],
                         "DERIVATIVE_INTERPRETATION_SOURCE_LINKED")
        self.assertEqual(
            row["interpretation_source"],
            f"intent_transactions:{outcome.transaction_id}:verbatim_instruction")

    def test_the_verbatim_hash_is_over_the_exact_bytes(self):
        import hashlib
        wb = support.workbench()
        verbatim = "Reconstruct cis.workbench.projection — exactly these words"
        outcome = wb.submit_instruction(verbatim)
        row = wb.intent.transaction(outcome.transaction_id)
        self.assertEqual(row["verbatim_hash"],
                         hashlib.sha256(verbatim.encode("utf-8")).hexdigest())


if __name__ == "__main__":
    unittest.main()
