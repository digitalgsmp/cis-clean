"""Reviewer-route receipt policy and hash for review verdicts.

A review receipt is an immutable, offline proof of a review's outcome. It
captures all parties to the review (implementer, reviewer), all provider
details, the response schema used, the verdict, and any objections. The receipt
itself is a pure hash: no store, no filesystem, no side effects.

INDEPENDENT HASH DOMAIN
-----------------------

review_receipt_hash is sha256 over a canonical payload whose first key is a
literal domain tag, cis.assurance.review_route_receipt.v1. The domain tag
ensures the receipt hash space is disjoint from every other binding scheme.

REVIEWER POLICY CONSTANTS
-------------------------

The reviewer policy is fixed by the constants in this module:
  - REQUIRED_ADAPTER: openrouter_qwen_reviewer
  - PROVIDER_ID: openrouter
  - MODEL_ID: qwen/qwen3.7-max
  - REVIEWER_LINEAGE: qwen

Any receipt that names a different adapter, provider, model, or reviewer
lineage is refused immediately. The policy is closed and admits no
instantiation or variation.

RESPONSE SCHEMA
---------------

The reviewer's response must conform to RESPONSE_SCHEMA, a closed JSON-schema
shaped mapping with exactly two top-level keys:
  - verdict: enum of PASS or OBJECTIONS
  - objections: an array; every element is a closed object with exactly two
    nonblank string fields, code and detail.

PASS requires an empty objections list; OBJECTIONS requires a nonempty one.
RESPONSE_SCHEMA is itself hashed as RESPONSE_SCHEMA_SHA256 and stored in the
receipt; a tampered schema digest is caught at verification time.

PAYLOAD AND VERIFICATION
------------------------

receipt_payload creates a dict of all receipt fields, including the hash
domain as the first key, and validates it before returning. receipt_hash
rejects a payload with missing or extra fields, validates it, then computes
sha256 of the canonical JSON. verify_receipt accepts a mapping (typically from
untrusted storage), rejects missing or extra receipt fields, validates every
field against the policy, recomputes the receipt_hash, and returns the digest
if valid or raises ReviewRefused if anything is wrong.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from ..canonical import sha256_hex
from ..errors import ReviewRefused

HASH_DOMAIN = "cis.assurance.review_route_receipt.v1"
REQUIRED_ADAPTER = "openrouter_qwen_reviewer"
PROVIDER_ID = "openrouter"
MODEL_ID = "qwen/qwen3.7-max"
REVIEWER_LINEAGE = "qwen"

_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")

RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "objections"],
    "properties": {
        "verdict": {"type": "string", "enum": ["PASS", "OBJECTIONS"]},
        "objections": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["code", "detail"],
                "properties": {
                    "code": {"type": "string", "minLength": 1},
                    "detail": {"type": "string", "minLength": 1},
                },
            },
        },
    },
}

RESPONSE_SCHEMA_SHA256 = sha256_hex(RESPONSE_SCHEMA)

_IDENTIFIER_FIELDS = (
    "receipt_id",
    "task_contract_id",
    "verification_result_id",
    "review_id",
    "implementer_request_id",
    "implementer_adapter_id",
    "reviewer_request_id",
    "reviewer_adapter_id",
    "response_evidence_id",
)

_HEX_DIGEST_FIELDS = (
    "review_packet_hash",
    "response_schema_sha256",
    "response_sha256",
)

PAYLOAD_FIELDS = (
    "hash_domain",
    "receipt_id",
    "task_contract_id",
    "verification_result_id",
    "review_id",
    "review_packet_hash",
    "implementer_request_id",
    "implementer_adapter_id",
    "reviewer_request_id",
    "reviewer_adapter_id",
    "provider_id",
    "model_id",
    "implementer_lineage",
    "reviewer_lineage",
    "response_schema_sha256",
    "response_evidence_id",
    "response_sha256",
    "verdict",
    "objections",
)

RECEIPT_FIELDS = PAYLOAD_FIELDS + ("receipt_hash",)


def _is_valid_hex_digest(value: Any) -> bool:
    """Check if value is a valid lowercase 64-char hex sha256."""
    return isinstance(value, str) and bool(_SHA256_PATTERN.match(value))


def _validate_identifier(name: str, value: Any) -> None:
    """Raise if identifier is not a nonblank string."""
    if not isinstance(value, str) or not value.strip():
        raise ReviewRefused(
            f"Receipt {name} must be a nonblank string",
            name=name,
            value=value,
        )


def _validate_hex_digest(name: str, value: Any) -> None:
    """Raise if value is not a valid 64-char lowercase hex digest."""
    if not _is_valid_hex_digest(value):
        raise ReviewRefused(
            f"Receipt {name} must be 64 lowercase hex characters",
            name=name,
            value=value,
        )


def _validate_objection(objection: Any) -> None:
    """Raise if objection is not a closed mapping of nonblank code/detail strings."""
    if not isinstance(objection, Mapping):
        raise ReviewRefused(
            "Each objection must be a mapping",
            objection=objection,
        )
    if set(objection.keys()) != {"code", "detail"}:
        raise ReviewRefused(
            "Each objection must have exactly the fields code and detail",
            objection=objection,
        )
    for field in ("code", "detail"):
        value = objection[field]
        if not isinstance(value, str) or not value.strip():
            raise ReviewRefused(
                f"Objection {field} must be a nonblank string",
                field=field,
                value=value,
            )


def _validate_objections(objections: Any) -> None:
    """Raise if objections is not a list of valid objection mappings."""
    if not isinstance(objections, Sequence) or isinstance(objections, (str, bytes)):
        raise ReviewRefused(
            "objections must be a list",
            objections=objections,
        )
    for objection in objections:
        _validate_objection(objection)


def _validate_payload_fields(payload: Mapping[str, Any]) -> None:
    """Raise if payload keys do not exactly match PAYLOAD_FIELDS."""
    actual = set(payload.keys())
    expected = set(PAYLOAD_FIELDS)
    if actual != expected:
        raise ReviewRefused(
            "Receipt payload must have exactly the expected fields",
            missing=sorted(expected - actual),
            extra=sorted(actual - expected),
        )


def _validate_payload(payload: Mapping[str, Any]) -> None:
    """Validate a receipt payload against the written contract."""
    _validate_payload_fields(payload)

    if payload.get("hash_domain") != HASH_DOMAIN:
        raise ReviewRefused(
            f"Receipt hash_domain must be {HASH_DOMAIN}",
            expected=HASH_DOMAIN,
            got=payload.get("hash_domain"),
        )

    for id_field in _IDENTIFIER_FIELDS:
        _validate_identifier(id_field, payload.get(id_field))

    for digest_field in _HEX_DIGEST_FIELDS:
        _validate_hex_digest(digest_field, payload.get(digest_field))

    impl_req = payload.get("implementer_request_id")
    rev_req = payload.get("reviewer_request_id")
    if impl_req == rev_req:
        raise ReviewRefused(
            "implementer_request_id and reviewer_request_id must differ",
            implementer_request_id=impl_req,
            reviewer_request_id=rev_req,
        )

    impl_adp = payload.get("implementer_adapter_id")
    rev_adp = payload.get("reviewer_adapter_id")
    if impl_adp == rev_adp:
        raise ReviewRefused(
            "implementer_adapter_id and reviewer_adapter_id must differ",
            implementer_adapter_id=impl_adp,
            reviewer_adapter_id=rev_adp,
        )

    impl_lineage = payload.get("implementer_lineage")
    rev_lineage = payload.get("reviewer_lineage")
    if not isinstance(impl_lineage, str) or not impl_lineage.strip():
        raise ReviewRefused(
            "implementer_lineage must be a nonblank string",
            value=impl_lineage,
        )
    if impl_lineage == rev_lineage:
        raise ReviewRefused(
            "implementer_lineage and reviewer_lineage must differ",
            implementer_lineage=impl_lineage,
            reviewer_lineage=rev_lineage,
        )

    if payload.get("provider_id") != PROVIDER_ID:
        raise ReviewRefused(
            f"Reviewer provider_id must be {PROVIDER_ID}",
            expected=PROVIDER_ID,
            got=payload.get("provider_id"),
        )

    if payload.get("model_id") != MODEL_ID:
        raise ReviewRefused(
            f"Reviewer model_id must be {MODEL_ID}",
            expected=MODEL_ID,
            got=payload.get("model_id"),
        )

    if payload.get("reviewer_adapter_id") != REQUIRED_ADAPTER:
        raise ReviewRefused(
            f"Reviewer adapter_id must be {REQUIRED_ADAPTER}",
            expected=REQUIRED_ADAPTER,
            got=payload.get("reviewer_adapter_id"),
        )

    if payload.get("reviewer_lineage") != REVIEWER_LINEAGE:
        raise ReviewRefused(
            f"Reviewer lineage must be {REVIEWER_LINEAGE}",
            expected=REVIEWER_LINEAGE,
            got=payload.get("reviewer_lineage"),
        )

    if payload.get("response_schema_sha256") != RESPONSE_SCHEMA_SHA256:
        raise ReviewRefused(
            "response_schema_sha256 does not match the closed schema",
            expected=RESPONSE_SCHEMA_SHA256,
            got=payload.get("response_schema_sha256"),
        )

    verdict = payload.get("verdict")
    objections = payload.get("objections")

    _validate_objections(objections)

    if verdict == "PASS":
        if objections:
            raise ReviewRefused(
                "PASS verdict requires empty objections",
                verdict=verdict,
                objections=objections,
            )
    elif verdict == "OBJECTIONS":
        if not objections:
            raise ReviewRefused(
                "OBJECTIONS verdict requires at least one objection",
                verdict=verdict,
                objections=objections,
            )
    else:
        raise ReviewRefused(
            "verdict must be PASS or OBJECTIONS",
            verdict=verdict,
        )


def receipt_payload(
    receipt_id: str,
    task_contract_id: str,
    verification_result_id: str,
    review_id: str,
    review_packet_hash: str,
    implementer_request_id: str,
    implementer_adapter_id: str,
    reviewer_request_id: str,
    reviewer_adapter_id: str,
    provider_id: str,
    model_id: str,
    implementer_lineage: str,
    reviewer_lineage: str,
    response_schema_sha256: str,
    response_evidence_id: str,
    response_sha256: str,
    verdict: str,
    objections: Sequence[Mapping[str, str]],
) -> dict[str, Any]:
    """Create and validate a receipt payload dict."""
    payload = {
        "hash_domain": HASH_DOMAIN,
        "receipt_id": receipt_id,
        "task_contract_id": task_contract_id,
        "verification_result_id": verification_result_id,
        "review_id": review_id,
        "review_packet_hash": review_packet_hash,
        "implementer_request_id": implementer_request_id,
        "implementer_adapter_id": implementer_adapter_id,
        "reviewer_request_id": reviewer_request_id,
        "reviewer_adapter_id": reviewer_adapter_id,
        "provider_id": provider_id,
        "model_id": model_id,
        "implementer_lineage": implementer_lineage,
        "reviewer_lineage": reviewer_lineage,
        "response_schema_sha256": response_schema_sha256,
        "response_evidence_id": response_evidence_id,
        "response_sha256": response_sha256,
        "verdict": verdict,
        "objections": (
            [dict(o) if isinstance(o, Mapping) else o for o in objections]
            if isinstance(objections, Sequence) and not isinstance(objections, (str, bytes))
            else objections
        ),
    }
    _validate_payload(payload)
    return payload


def receipt_hash(payload: Mapping[str, Any]) -> str:
    """Validate a receipt payload and compute sha256 of its canonical JSON."""
    _validate_payload_fields(payload)
    _validate_payload(payload)
    return sha256_hex(payload)


def verify_receipt(stored_receipt: Mapping[str, Any]) -> str:
    """Validate a receipt and return its computed hash digest.

    Validates:
    - The receipt has exactly the expected fields, including receipt_hash.
    - All identifiers are nonblank strings.
    - All digests are 64 lowercase hex characters.
    - Request ids differ (implementer != reviewer).
    - Adapter ids differ (implementer != reviewer).
    - Reviewer policy fields match constants (provider, model, adapter, lineage).
    - implementer_lineage differs from reviewer_lineage.
    - response_schema_sha256 matches RESPONSE_SCHEMA_SHA256.
    - verdict and objections agree: PASS requires empty, OBJECTIONS requires nonempty.
    - Every objection is a closed mapping with nonblank code and detail.
    - hash_domain matches the constant.
    - The stored receipt_hash matches the recomputed digest.

    Args:
        stored_receipt: A mapping with all receipt fields and receipt_hash.

    Returns:
        The computed sha256 hex digest of the payload (excluding receipt_hash).

    Raises:
        ReviewRefused: If any validation fails or the stored hash does not match.
    """
    actual = set(stored_receipt.keys())
    expected = set(RECEIPT_FIELDS)
    if actual != expected:
        raise ReviewRefused(
            "Receipt must have exactly the expected fields",
            missing=sorted(expected - actual),
            extra=sorted(actual - expected),
        )

    payload = {k: stored_receipt[k] for k in PAYLOAD_FIELDS}
    _validate_payload(payload)

    computed_hash = receipt_hash(payload)

    stored_hash = stored_receipt.get("receipt_hash")
    _validate_hex_digest("receipt_hash", stored_hash)
    if stored_hash != computed_hash:
        raise ReviewRefused(
            "receipt_hash does not match recomputed digest",
            expected=computed_hash,
            got=stored_hash,
        )

    return computed_hash
