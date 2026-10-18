"""Canonical serialisation and hashing.

Every binding hash in this slice is a sha256 over the same canonical JSON
encoding, so a hash computed in one module recomputes bit-identically in
another. Determinism is a hard requirement: no clock, no randomness, no
dict-ordering dependence.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

_ENCODE_KWARGS = {
    "sort_keys": True,
    "separators": (",", ":"),
    "ensure_ascii": False,
    "allow_nan": False,
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, **_ENCODE_KWARGS)


def sha256_hex(value: Any) -> str:
    """sha256 of the canonical JSON encoding of ``value``."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_text(text: str) -> str:
    """sha256 of exact bytes of ``text`` — used for verbatim instructions,
    which must hash as the user typed them, not as JSON."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
