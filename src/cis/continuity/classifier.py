"""Deterministic classification of one exchange.

The recorded acceptance criterion (dev_continuity_events revision 178, Eric
verbatim): "so the continuity of perspective you said I was supplying with
semantic memories will be built into the pipeline and my questions wont keep
sending us down rabbit holes causing important concepts to go dormant."

The operational rule this module implements: classify each new exchange as
question, addition, correction, or explicit redirection, and require EXPLICIT
redirection before the active trajectory is replaced. A question is a retrieval
cue. A vague memory fragment is a retrieval cue. Neither redirects.

No model is consulted. Classification is a closed-vocabulary rule over the
user's exact words, so the same words always classify the same way and the
reason is inspectable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

QUESTION = "question"
ADDITION = "addition"
CORRECTION = "correction"
REDIRECTION = "redirection"

#: Explicit redirection vocabulary. Nothing outside this list replaces the
#: active objective. The bar is deliberately high: an ambiguous instruction is
#: an addition to the current objective, never a silent new one.
_REDIRECTION_MARKERS = (
    "redirect:",
    "new objective:",
    "stop working on",
    "abandon the current objective",
    "drop the current objective",
    "change of direction:",
    "explicit redirection:",
    "supersede the active objective",
)

#: Correction vocabulary — a correction refines the active objective and does
#: not replace it.
_CORRECTION_MARKERS = (
    "correction:",
    "that is wrong",
    "that's wrong",
    "not what i meant",
    "actually, ",
    "fix that",
)

_QUESTION_LEADS = (
    "what", "why", "how", "when", "where", "who", "which", "whose",
    "is", "are", "was", "were", "do", "does", "did", "can", "could",
    "should", "would", "will", "am", "have", "has", "had",
)

#: Fragment markers — vague recollection. A fragment is a retrieval cue even
#: when it is phrased as a statement.
_FRAGMENT_MARKERS = (
    "i remember",
    "i think we",
    "didn't we",
    "did we ever",
    "wasn't there",
    "there was something",
    "something about",
    "at some point we",
    "we talked about",
    "we discussed",
    "vaguely recall",
    "i recall",
)


@dataclass(frozen=True)
class Classification:
    classification: str
    is_retrieval_cue: bool
    is_fragment: bool
    matched_marker: str | None
    rationale: str
    evidence: tuple[str, ...] = field(default=())

    @property
    def redirects(self) -> bool:
        """Only an explicit redirection may replace the active trajectory."""
        return self.classification == REDIRECTION

    def as_dict(self) -> dict:
        return {
            "classification": self.classification,
            "is_retrieval_cue": self.is_retrieval_cue,
            "is_fragment": self.is_fragment,
            "matched_marker": self.matched_marker,
            "rationale": self.rationale,
            "evidence": list(self.evidence),
        }


def _normalise(verbatim: str) -> str:
    return re.sub(r"\s+", " ", verbatim).strip().lower()


def classify(verbatim: str) -> Classification:
    """Classify ``verbatim``.

    Classification is derived only from the exact operator words.  Callers do
    not get a second metadata channel that can silently outrank those words.
    """
    text = _normalise(verbatim)
    if not text:
        return Classification(
            classification=QUESTION,
            is_retrieval_cue=True,
            is_fragment=False,
            matched_marker=None,
            rationale="empty instruction carries no direction and is treated as "
                      "a retrieval cue, never as a redirection",
        )

    for marker in _REDIRECTION_MARKERS:
        if marker in text:
            return Classification(
                classification=REDIRECTION,
                is_retrieval_cue=False,
                is_fragment=False,
                matched_marker=marker,
                rationale="instruction carries an explicit redirection marker, "
                          "so the active objective is superseded",
            )

    is_fragment = any(marker in text for marker in _FRAGMENT_MARKERS)
    is_question = text.endswith("?") or text.split(" ")[0] in _QUESTION_LEADS

    if is_question:
        return Classification(
            classification=QUESTION,
            is_retrieval_cue=True,
            is_fragment=is_fragment,
            matched_marker="?" if text.endswith("?") else text.split(" ")[0],
            rationale="a question is a retrieval cue and does not redirect "
                      "development",
        )

    if is_fragment:
        return Classification(
            classification=ADDITION,
            is_retrieval_cue=True,
            is_fragment=True,
            matched_marker=next(m for m in _FRAGMENT_MARKERS if m in text),
            rationale="a vague memory fragment is a retrieval cue over prior "
                      "intent and does not redirect development",
        )

    for marker in _CORRECTION_MARKERS:
        if marker in text:
            return Classification(
                classification=CORRECTION,
                is_retrieval_cue=False,
                is_fragment=False,
                matched_marker=marker,
                rationale="a correction refines the active objective rather "
                          "than replacing it",
            )

    return Classification(
        classification=ADDITION,
        is_retrieval_cue=False,
        is_fragment=False,
        matched_marker=None,
        rationale="an instruction with no explicit redirection marker is an "
                  "addition to the active objective",
    )
