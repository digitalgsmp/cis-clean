"""Antecedent retrieval — deterministic, offline, original-language.

A question or a fragment is a cue to recover what was already said, in the
words it was said in. Retrieval here is a token-overlap score over immutable
evidence records; it is not semantic search and makes no claim to be. It is
deterministic, it has no model and no network, and its score is inspectable,
which is what the slice needs: when the user says "I vaguely remember
something about the trajectory thing", the Workbench must be able to show the
antecedent and the matched words rather than assert a connection.

**What retrieval is for, and what it is not for.** This module serves
CONTINUITY ONLY: it recovers prior human exchanges and admitted knowledge so
meaning is preserved, memory cues are answerable and context is explainable.
It is NOT an execution-authorization basis, and token overlap confers no
permission whatsoever. A returned antecedent is contextual continuity
evidence; the authority that may permit work is the validated canonical
architecture for the target module (``cis.blueprint.manifest``), and nothing
here is consulted when that permission is decided. Retrieval ranks evidence;
ranking highly does not make evidence authority (ADR-ARCH-002).

**Provenance beats score.** When a cue matches both something the human
actually said and something the system later generated about its own
execution, the human's words rank first. That is a deliberate, explicit
preference and not a scoring accident: an execution-evidence record is a
derivative of work CIS did, and surfacing it above the intent it came from is
how an original meaning gets quietly replaced by a machine restatement of it.
Ordering is therefore (provenance tier, then score, then evidence_id), and
every antecedent reports its own tier so the ranking is readable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

#: Words that carry no retrieval signal. Short and fixed; a learned stoplist
#: would make retrieval non-reproducible.
_STOPWORDS = frozenset("""
a an and are as at be been being but by can could did do does for from had has
have how i if in into is it its me my of on or our so than that the their them
then there these they this those to up us was we were what when where which
who why will with would you your about something ever never just really thing
""".split())

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_\-]*")

#: Provenance tiers, lowest first. Closed vocabulary, keyed by the evidence
#: ``kind`` that each authority module writes.
ORIGINAL_HUMAN_INTENT = "ORIGINAL_HUMAN_INTENT"
ADMITTED_KNOWLEDGE = "ADMITTED_KNOWLEDGE"
GENERATED_DERIVATIVE = "GENERATED_DERIVATIVE"

_TIERS = (ORIGINAL_HUMAN_INTENT, ADMITTED_KNOWLEDGE, GENERATED_DERIVATIVE)

#: The human's own words, whether recorded live as an intent transaction or
#: admitted from a preserved conversation record.
HUMAN_KINDS = frozenset({"prior_human_intent", "user_instruction"})

#: Records CIS generated about its own activity. They are retrievable — a
#: question about what ran must be answerable — but they are never preferred
#: over the intent they derive from, and they are never authority.
GENERATED_KINDS = frozenset({"execution_evidence"})


def provenance_of(kind: str) -> str:
    """Classify one evidence ``kind`` into a provenance tier.

    Derived from the single structured ``kind`` field, never from prose, and
    defaulting to ``ADMITTED_KNOWLEDGE`` — an unknown kind is treated as
    admitted knowledge rather than silently promoted to human intent.
    """
    if kind in HUMAN_KINDS:
        return ORIGINAL_HUMAN_INTENT
    if kind in GENERATED_KINDS:
        return GENERATED_DERIVATIVE
    return ADMITTED_KNOWLEDGE


def tokenise(text: str) -> list[str]:
    return [
        token
        for token in _TOKEN.findall(text.lower())
        if token not in _STOPWORDS and len(token) > 2
    ]


@dataclass(frozen=True)
class Antecedent:
    evidence_id: str
    kind: str
    source_ref: str
    original_language: str
    score: float
    matched_terms: tuple[str, ...]
    provenance: str = ADMITTED_KNOWLEDGE

    @property
    def provenance_rank(self) -> int:
        return _TIERS.index(self.provenance)

    def as_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "source_ref": self.source_ref,
            "original_language": self.original_language,
            "score": self.score,
            "matched_terms": list(self.matched_terms),
            "provenance": self.provenance,
            "role": "CONTEXTUAL_CONTINUITY_EVIDENCE_NOT_AUTHORIZATION_BASIS",
        }


def retrieve_antecedents(cue: str, records: Iterable[Mapping[str, Any]], *,
                         limit: int = 5, minimum_overlap: int = 1,
                         ) -> list[Antecedent]:
    """Rank ``records`` against ``cue`` for continuity, never for permission.

    Deterministic ordering: provenance tier ascending, then score descending,
    then evidence_id ascending, so equal scores never reorder between runs and
    the human's own words are never displaced by a machine derivative of them.
    """
    cue_terms = set(tokenise(cue))
    if not cue_terms:
        return []

    scored: list[Antecedent] = []
    for record in records:
        haystack = f"{record['original_language']} {record['content']} {record['source_ref']}"
        record_terms = set(tokenise(haystack))
        matched = sorted(cue_terms & record_terms)
        if len(matched) < minimum_overlap:
            continue
        # Overlap normalised by the cue, so a long evidence record does not
        # outrank a precise one merely by being long.
        score = round(len(matched) / len(cue_terms), 6)
        kind = str(record["kind"])
        scored.append(Antecedent(
            evidence_id=str(record["evidence_id"]),
            kind=kind,
            source_ref=str(record["source_ref"]),
            original_language=str(record["original_language"]),
            score=score,
            matched_terms=tuple(matched),
            provenance=provenance_of(kind),
        ))

    scored.sort(key=lambda a: (a.provenance_rank, -a.score, a.evidence_id))
    return scored[:limit]
