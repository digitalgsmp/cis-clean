"""EXTERNAL DEVELOPMENT TOOLING. NOT PART OF THE DURABLE CIS RECONSTRUCTION.

This module lives in tools/ and is deliberately OUTSIDE src/cis. ADR-ARCH-003
records that no alternative backend is adopted, evaluated or recorded, and the
clean room's own tests enforce it: test_no_module_imports_a_network_or_model_library
and test_no_foreign_backend_is_named_anywhere_in_the_slice both scan src/ and
would fail if this file lived there. It previously did, which broke both
invariants at commit cbb11e7. ADR-ARCH-003 IS PRESERVED UNAMENDED and neither
test was weakened; the file was moved instead.

It imports NOTHING from cis and implements no Layer-2 interface. It produces a
candidate artifact plus its provenance record, and hands both to CIS through an
authorized submission path. It never writes to the authoritative evidence store.

PROVENANCE PRESERVED FOR EVERY GENERATION: provider identity, exact model id,
generation reference, prompt and completion token counts, artifact sha256, and
the authorization binding the caller supplies. Those are what let a later
verification be bound to the exact artifact a named model actually produced.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping, Sequence


class GenerationRefused(RuntimeError):
    """External tooling's own refusal. Not a CIS error type: this module is
    outside the reconstruction and must not import from it."""

    def __init__(self, message, **detail):
        super().__init__(message)
        self.detail = detail

#: The provider endpoint. Named here and nowhere above Layer 2.
_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"

#: The declared environment variable the default credential provider reads.
_CREDENTIAL_ENV = "OPENROUTER_API_KEY"

#: Selected against the recorded quality floor and cost ceiling of
#: dev_continuity_events task 4.37 revision 20: the least expensive model with
#: demonstrated reliability for this task class, not the lowest unit price.
_DEFAULT_MODEL = "deepseek/deepseek-v4-pro"

#: The instruction given to the model. Deliberately rigid: the model authors a
#: single file's contents and nothing else, so that what comes back can be
#: verified byte-for-byte against a declared test rather than interpreted.
_SYSTEM_PROMPT = (
    "You author a single Python source file. "
    "Return ONLY the file contents. "
    "No markdown fences, no commentary, no explanation, no leading or trailing "
    "blank lines beyond what the code requires. "
    "The file must be self-contained, use only the Python standard library, "
    "and define exactly what the specification asks for and nothing else."
)


def _default_credential_provider() -> str:
    """The declared credential interface: one named environment variable.

    Absent or empty is a refusal, not a prompt and not a search. The adapter
    does not look anywhere else for a key.
    """
    value = os.environ.get(_CREDENTIAL_ENV, "").strip()
    if not value:
        raise GenerationRefused(
            "no provider credential available through the declared interface",
            declared_interface=_CREDENTIAL_ENV,
        )
    return value


def _default_transport(*, url: str, headers: Mapping[str, str], body: bytes,
                       timeout: float) -> tuple[int, bytes]:
    """The declared transport seam. Injectable so tests never open a socket."""
    request = urllib.request.Request(url, data=body, headers=dict(headers))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:               # pragma: no cover - network
        return int(exc.code), exc.read()


def _strip_fences(text: str) -> str:
    """Remove a markdown fence if the model emitted one despite instruction.

    Normalising a fence is not interpreting the answer: the fence is transport
    packaging, and the file contents inside it are unchanged. Anything beyond
    unwrapping is left alone so that a malformed answer stays visibly malformed
    and fails its test rather than being repaired into looking correct.
    """
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


class OpenRouterGenerator:
    """Authors one file's source through a hosted model, under hard bounds."""

    #: Declared, not inferred (ADR-ARCH-003 clause 3).
    _CAPABILITIES = ("author_module_source",)

    def __init__(
        self,
        *,
        model: str = _DEFAULT_MODEL,
        credential_provider: Callable[[], str] | None = None,
        transport: Callable[..., tuple[int, bytes]] | None = None,
        max_output_tokens: int = 1200,
        timeout_seconds: float = 120.0,
    ) -> None:
        self.model = model
        self._credential = credential_provider or _default_credential_provider
        self._transport = transport or _default_transport
        self.max_output_tokens = int(max_output_tokens)
        self.timeout_seconds = float(timeout_seconds)
        #: Populated after a call so the caller can record real spend.
        self.last_usage: dict[str, Any] = {}

    def capabilities(self) -> Sequence[str]:
        return self._CAPABILITIES

    def liveness(self) -> bool:
        """Declared liveness: can a credential be obtained at all.

        Deliberately does NOT call the provider. Liveness that bills money, or
        that depends on a remote service answering, would make a read-only
        health check a side-effecting one.
        """
        try:
            self._credential()
        except ExecutionRefused:
            return False
        return True

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        # The adapter-side half of the gate: no valid token, no execution.
        request.verify_token()

        if request.operation not in self._CAPABILITIES:
            raise GenerationRefused(
                "operation is not declared by this backend",
                operation=request.operation,
            )
        if not request.allowed_scope:
            raise GenerationRefused(
                "request carries no allowed scope", request_id=request.request_id
            )

        specification = str(request.payload.get("specification", "")).strip()
        if not specification:
            raise GenerationRefused(
                "request carries no specification for the model to author",
                request_id=request.request_id,
            )

        credential = self._credential()
        body = json.dumps({
            "model": self.model,
            "max_tokens": self.max_output_tokens,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": specification},
            ],
        }).encode("utf-8")

        status, raw = self._transport(
            url=_ENDPOINT,
            headers={
                "Authorization": f"Bearer {credential}",
                "Content-Type": "application/json",
            },
            body=body,
            timeout=self.timeout_seconds,
        )

        if status != 200:
            # A provider failure is a recorded, resumable failure. It does not
            # replay a spent authorization and does not fall back to another
            # tier (routing standard clauses 6 and 7).
            raise GenerationRefused(
                "provider call did not succeed",
                request_id=request.request_id,
                http_status=status,
            )

        try:
            parsed = json.loads(raw.decode("utf-8"))
            content = parsed["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, UnicodeDecodeError) as exc:
            raise GenerationRefused(
                "provider response was not in the declared shape",
                request_id=request.request_id,
                detail=type(exc).__name__,
            ) from exc

        source = _strip_fences(content or "")
        if not source:
            raise GenerationRefused(
                "provider returned no source", request_id=request.request_id
            )

        usage = parsed.get("usage") or {}
        self.last_usage = {
            "model": parsed.get("model", self.model),
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": usage.get("completion_tokens"),
            "total_tokens": usage.get("total_tokens"),
            "generation_id": parsed.get("id"),
        }

        artifact = hashlib.sha256(source.encode("utf-8")).hexdigest()

        evidence = [
            f"operation={request.operation}",
            f"allowed_scope={','.join(request.allowed_scope)}",
            f"forbidden_actions={','.join(request.forbidden_actions)}",
            f"artifact_digest={artifact}",
            f"model={self.last_usage['model']}",
            f"generation_id={self.last_usage.get('generation_id')}",
            f"total_tokens={self.last_usage.get('total_tokens')}",
            f"stopped_at={request.stopping_condition}",
            f"returned_to={request.return_point}",
        ]

        # status='completed' means THE BACKEND RAN AND RETURNED A CANDIDATE.
        # It is not a claim that the source is correct: nothing here executes
        # or tests it. Correctness is established downstream by the contained
        # worker and the deterministic verifier, which do not depend on this
        # module and cannot be satisfied by anything it asserts.
        return ExecutionResult(
            status="completed",
            exit_code=0,
            outputs={
                "artifact_digest": artifact,
                "authored_source": source,
                "scope_honoured": list(request.allowed_scope),
                "operation": request.operation,
                "model": self.last_usage["model"],
            },
            checks_performed=(),
            evidence=tuple(evidence),
        )
