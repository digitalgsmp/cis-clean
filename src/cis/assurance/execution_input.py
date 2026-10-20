"""Immutable, content-addressed authority for one future verification's inputs.

``task_execution_inputs`` (migration 0009) binds, forward, to an existing
frozen task contract: the exact candidate source bytes a
``verify_authored_source.v1`` task runs, the exact canonical vector
contract that declares what passing would mean, the one authorized
entrypoint, the apparatus identity the run is bound to (an immutable
sha256-digest worker image identity plus the trusted-runner and worker
digests a later verification would be required to observe), and the task
contract's own hash and authorization binding hash as forward links.

NO EXECUTION AUTHORITY LIVES HERE. This module appends exactly one table and
does not dispatch, execute, verify or promote anything. The separately frozen
``verify_authored_source.v1`` template and Verifier consume this authority
without changing its single-writer boundary.

AN INDEPENDENT HASH DOMAIN
--------------------------

``execution_input_hash`` is sha256 over a canonical payload tagged
``cis.assurance.execution_input.v1``, distinct from the task-contract domain and
from the undomained slice-1 authorization binding — two digests over
overlapping facts must never be interchangeable.

EXACT BYTES, NOT A PATH, AND DIGESTS CHECKED BOTH WAYS
-------------------------------------------------------

``candidate_source`` and ``vector_contract`` are stored byte-exact so the
subject of a later verification cannot be swapped after the fact. A caller
supplies the digest it believes those bytes carry; ``append`` recomputes the
digest from the bytes it was actually given and refuses rather than trusting
the caller's arithmetic.

ONE BINDING PER TASK CONTRACT, EVER
------------------------------------

``task_contract_id`` is UNIQUE in SQL and checked again here: a second set of
execution inputs under one frozen task contract would mean two different
things had been authorized under one immutable contract, so a duplicate
refuses rather than overwrites. Combined with the no-update/no-delete
triggers, there is no path to a silent replacement at any layer.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

from ..authority.store import AuthorityStore, Row
from ..canonical import sha256_hex
from ..errors import ExecutionInputRefused, ExecutionInputTampered
from .authority import AssuranceAuthority

#: The independent hash domain. Any change invalidates every recorded
#: execution-input digest by design.
EXECUTION_INPUT_HASH_DOMAIN = "cis.assurance.execution_input.v1"

#: A worker image is an identity, not a label: only the immutable digest form
#: is accepted, never a mutable tag (``name:tag``) that can be repointed at a
#: different image after this row is written.
_WORKER_IMAGE_DIGEST = re.compile(r"\Asha256:[0-9a-f]{64}\Z")

#: Exactly 64 lowercase hex characters — a sha256 hex digest, not merely
#: something of the right length.
_SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def execution_input_id_for(task_contract_id: str) -> str:
    """Deterministic id, derived from the one fact that identifies a binding.

    ``task_contract_id`` is unique per binding by construction, so the id
    needs no other input to be stable and collision-free.
    """
    suffix = sha256_hex({"task_contract_id": task_contract_id})[:12]
    return f"exi-{suffix}"


def execution_input_payload(*, execution_input_id: str, task_contract_id: str,
                            candidate_sha256: str, vector_contract_sha256: str,
                            authorized_entrypoint: str, task_contract_hash: str,
                            authorization_binding_hash: str, worker_image: str,
                            expected_trusted_runner_sha256: str,
                            expected_worker_sha256: str) -> dict:
    """The exact, ordered set of facts an execution-input digest covers.

    The raw candidate and vector-contract bytes are not themselves hashed into
    this payload — their digests are, and ``append``/``verify_row`` separately
    refuse unless those digests match the exact stored bytes. Hashing a
    canonical JSON payload over arbitrary-length binary content would be both
    wasteful and beside the point: the binding this hash protects is over
    *which* digests, entrypoint and worker identity were authorized together,
    not a second encoding of the bytes themselves.
    """
    return {
        "__hash_domain__": EXECUTION_INPUT_HASH_DOMAIN,
        "execution_input_id": execution_input_id,
        "task_contract_id": task_contract_id,
        "candidate_sha256": candidate_sha256,
        "vector_contract_sha256": vector_contract_sha256,
        "authorized_entrypoint": authorized_entrypoint,
        "task_contract_hash": task_contract_hash,
        "authorization_binding_hash": authorization_binding_hash,
        "worker_image": worker_image,
        "expected_trusted_runner_sha256": expected_trusted_runner_sha256,
        "expected_worker_sha256": expected_worker_sha256,
    }


def execution_input_hash(**kwargs: Any) -> str:
    return sha256_hex(execution_input_payload(**kwargs))


def hash_of_row(row: Mapping[str, Any]) -> str:
    """Recompute a stored execution-input binding's digest from the row alone."""
    return execution_input_hash(
        execution_input_id=str(row["execution_input_id"]),
        task_contract_id=str(row["task_contract_id"]),
        candidate_sha256=str(row["candidate_sha256"]),
        vector_contract_sha256=str(row["vector_contract_sha256"]),
        authorized_entrypoint=str(row["authorized_entrypoint"]),
        task_contract_hash=str(row["task_contract_hash"]),
        authorization_binding_hash=str(row["authorization_binding_hash"]),
        worker_image=str(row["worker_image"]),
        expected_trusted_runner_sha256=str(row["expected_trusted_runner_sha256"]),
        expected_worker_sha256=str(row["expected_worker_sha256"]),
    )


def verify_row(row: Mapping[str, Any]) -> str:
    """Refuse unless a stored execution-input row stands up on its own.

    Three independent checks, all fail-closed: an unexpected hash domain, a
    stored digest that no longer matches the bytes recorded beside it (for
    both the candidate and the vector contract), and a binding hash that does
    not recompute from the stored fields.
    """
    task_contract_id = str(row["task_contract_id"])
    domain = str(row["hash_domain"])
    if domain != EXECUTION_INPUT_HASH_DOMAIN:
        raise ExecutionInputTampered(
            "execution-input binding carries an unknown hash domain",
            task_contract_id=task_contract_id,
            recorded=domain, expected=EXECUTION_INPUT_HASH_DOMAIN,
        )
    candidate_digest = _sha256_bytes(bytes(row["candidate_source"]))
    if candidate_digest != str(row["candidate_sha256"]):
        raise ExecutionInputTampered(
            "stored candidate bytes no longer match their recorded digest",
            task_contract_id=task_contract_id,
            recorded=str(row["candidate_sha256"]), recomputed=candidate_digest,
        )
    vector_digest = _sha256_bytes(bytes(row["vector_contract"]))
    if vector_digest != str(row["vector_contract_sha256"]):
        raise ExecutionInputTampered(
            "stored vector-contract bytes no longer match their recorded digest",
            task_contract_id=task_contract_id,
            recorded=str(row["vector_contract_sha256"]), recomputed=vector_digest,
        )
    recomputed = hash_of_row(row)
    if recomputed != str(row["execution_input_hash"]):
        raise ExecutionInputTampered(
            "execution-input binding does not recompute from the stored row",
            task_contract_id=task_contract_id,
            recorded=str(row["execution_input_hash"]), recomputed=recomputed,
        )
    return recomputed


class ExecutionInputAuthority:
    """The single owner of ``task_execution_inputs``.

    ``append`` performs every refusal independently of whatever a future
    ``verify_authored_source.v1`` task would claim: it re-reads and
    re-verifies the referenced task contract itself rather than trusting a
    caller's assertion about it, and it recomputes every digest from the
    bytes it was actually handed.
    """

    owned_authority = ("task_execution_inputs",)

    def __init__(self, store: AuthorityStore,
                 assurance: AssuranceAuthority | None = None) -> None:
        self._store = store
        self._assurance = (assurance if assurance is not None
                           else AssuranceAuthority(store))

    # -- reads ----------------------------------------------------------

    def for_task_contract(self, task_contract_id: str) -> Row | None:
        return self._store.one(
            "SELECT * FROM task_execution_inputs WHERE task_contract_id = ?",
            (task_contract_id,),
        )

    def verify(self, task_contract_id: str) -> Row:
        """Refuse unless a recorded binding exists and stands up on its own."""
        row = self.for_task_contract(task_contract_id)
        if row is None:
            raise ExecutionInputRefused(
                "no execution-input binding is recorded for this task contract",
                task_contract_id=task_contract_id,
            )
        verify_row(row)
        return row

    # -- the one append path ---------------------------------------------

    def append(self, *, task_contract_id: str, candidate_source: bytes,
              candidate_sha256: str, vector_contract: bytes,
              vector_contract_sha256: str, authorized_entrypoint: str,
              task_contract_hash: str, authorization_binding_hash: str,
              worker_image: str, expected_trusted_runner_sha256: str,
              expected_worker_sha256: str) -> Row:
        """Append one immutable execution-input binding, or refuse.

        Every fact is checked before anything is written: the task contract
        must exist and recompute its own digest; the caller's claimed
        ``task_contract_hash`` and ``authorization_binding_hash`` must match
        that contract's own recorded values; the caller's claimed digests
        must match the exact bytes handed in; the entrypoint and worker
        identity must be an immutable sha256 digest, never a mutable tag;
        the expected runner/worker digests must each be exactly 64 lowercase
        hex characters; and the task contract must not already carry a
        binding.
        """
        contract = self._assurance.verify_task_contract(task_contract_id)

        if not isinstance(candidate_source, (bytes, bytearray)) or not candidate_source:
            raise ExecutionInputRefused(
                "candidate source must be non-empty bytes",
                task_contract_id=task_contract_id)
        if not isinstance(vector_contract, (bytes, bytearray)) or not vector_contract:
            raise ExecutionInputRefused(
                "vector contract must be non-empty bytes",
                task_contract_id=task_contract_id)

        candidate_bytes = bytes(candidate_source)
        vector_bytes = bytes(vector_contract)
        recomputed_candidate = _sha256_bytes(candidate_bytes)
        if recomputed_candidate != str(candidate_sha256):
            raise ExecutionInputRefused(
                "candidate digest does not match the exact bytes submitted",
                task_contract_id=task_contract_id,
                claimed=str(candidate_sha256), recomputed=recomputed_candidate,
            )
        recomputed_vector = _sha256_bytes(vector_bytes)
        if recomputed_vector != str(vector_contract_sha256):
            raise ExecutionInputRefused(
                "vector-contract digest does not match the exact bytes submitted",
                task_contract_id=task_contract_id,
                claimed=str(vector_contract_sha256), recomputed=recomputed_vector,
            )

        entrypoint = str(authorized_entrypoint).strip()
        if not entrypoint:
            raise ExecutionInputRefused(
                "authorized entrypoint must be non-empty",
                task_contract_id=task_contract_id)
        image = str(worker_image).strip()
        if not _WORKER_IMAGE_DIGEST.match(image):
            raise ExecutionInputRefused(
                "worker image must be an immutable sha256 digest identity "
                "(sha256: followed by 64 lowercase hex characters), not a "
                "mutable tag",
                task_contract_id=task_contract_id, value=image)
        runner_digest = str(expected_trusted_runner_sha256).strip()
        if not _SHA256_HEX.match(runner_digest):
            raise ExecutionInputRefused(
                "expected trusted-runner digest must be exactly 64 "
                "lowercase hex characters",
                task_contract_id=task_contract_id, value=runner_digest)
        worker_digest = str(expected_worker_sha256).strip()
        if not _SHA256_HEX.match(worker_digest):
            raise ExecutionInputRefused(
                "expected worker digest must be exactly 64 lowercase hex "
                "characters",
                task_contract_id=task_contract_id, value=worker_digest)

        if str(task_contract_hash) != str(contract["task_contract_hash"]):
            raise ExecutionInputRefused(
                "task_contract_hash does not match the referenced task contract",
                task_contract_id=task_contract_id,
                claimed=str(task_contract_hash),
                recorded=str(contract["task_contract_hash"]),
            )
        if str(authorization_binding_hash) != str(contract["authorization_binding_hash"]):
            raise ExecutionInputRefused(
                "authorization_binding_hash does not match the referenced "
                "task contract",
                task_contract_id=task_contract_id,
                claimed=str(authorization_binding_hash),
                recorded=str(contract["authorization_binding_hash"]),
            )

        existing = self.for_task_contract(task_contract_id)
        if existing is not None:
            raise ExecutionInputRefused(
                "this task contract already carries a recorded execution-input "
                "binding; a second one would mean two different things had "
                "been authorized under one immutable contract",
                task_contract_id=task_contract_id,
                execution_input_id=str(existing["execution_input_id"]),
            )

        execution_input_id = execution_input_id_for(task_contract_id)
        binding_hash = execution_input_hash(
            execution_input_id=execution_input_id,
            task_contract_id=task_contract_id,
            candidate_sha256=recomputed_candidate,
            vector_contract_sha256=recomputed_vector,
            authorized_entrypoint=entrypoint,
            task_contract_hash=str(task_contract_hash),
            authorization_binding_hash=str(authorization_binding_hash),
            worker_image=image,
            expected_trusted_runner_sha256=runner_digest,
            expected_worker_sha256=worker_digest,
        )

        return self._store.insert("task_execution_inputs", {
            "execution_input_id": execution_input_id,
            "task_contract_id": task_contract_id,
            "candidate_source": candidate_bytes,
            "candidate_sha256": recomputed_candidate,
            "vector_contract": vector_bytes,
            "vector_contract_sha256": recomputed_vector,
            "authorized_entrypoint": entrypoint,
            "task_contract_hash": str(task_contract_hash),
            "authorization_binding_hash": str(authorization_binding_hash),
            "worker_image": image,
            "expected_trusted_runner_sha256": runner_digest,
            "expected_worker_sha256": worker_digest,
            "hash_domain": EXECUTION_INPUT_HASH_DOMAIN,
            "execution_input_hash": binding_hash,
            "created_at": self._store.now(),
            "seq": self._store.next_seq(),
        })


__all__ = [
    "EXECUTION_INPUT_HASH_DOMAIN",
    "ExecutionInputAuthority",
    "execution_input_hash",
    "execution_input_id_for",
    "execution_input_payload",
    "hash_of_row",
    "verify_row",
]
