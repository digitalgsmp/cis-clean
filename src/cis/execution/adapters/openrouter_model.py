"""A real model-backed execution backend, reached through one hosted API.

This is Layer 3: replaceable execution infrastructure, not part of the durable
definition of CIS (ADR-ARCH-001 clause 8). It is the first backend CIS adopts
under the ADR-ARCH-003 boundary, and it is deliberately the thinnest thing that
can author source code: one request, one response, no agent loop, no tools, no
retries, no fallback to another tier.

ADR-ARCH-003 compliance, clause by clause:

  1. This module is reached only through ``cis.execution.gateway``; nothing
     above Layer 2 imports it or names the provider.
  2. No port, file path, configuration file or log format of the provider
     appears above this module. The provider's identity lives here and in the
     adapter id alone.
  3. Credentials and liveness arrive through a DECLARED INTERFACE: a caller
     supplies ``credential_provider`` (and optionally ``transport``) at
     construction. This module never reads a backend's private files, never
     parses a log, and never searches the filesystem for a key. The default
     credential provider reads one named environment variable, which is the
     declared interface for a hosted API that has no private files on this
     host.
  4. Its ``replacement_contract`` is declared in
     ``contracts/cis.execution.adapters.openrouter_model.contract.json``.
  5. Acceptance test H1 applies to the family, not to this module alone.

The cost ceiling of the recorded routing standard (4.37 revision 20 clause 6)
is enforced here, not by convention: ``max_output_tokens`` bounds the response,
``timeout_seconds`` bounds the call, and there is exactly one attempt. There is
no silent escalation to a more expensive model, and the adapter cannot raise
its own budget.

Model identity confers no authority (clause 4 of the same standard). What this
backend returns is a CANDIDATE. It is verified, independently reviewed and
promoted by modules that do not depend on it, exactly as the mock backend's
output is.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping, Sequence

from ...errors import ExecutionRefused
from ..port import ExecutionPort, ExecutionRequest, ExecutionResult

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
        raise ExecutionRefused(
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


class OpenRouterModelAdapter(ExecutionPort):
    """Authors one file's source through a hosted model, under hard bounds."""

    adapter_id = "openrouter_model"

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
            raise ExecutionRefused(
                "operation is not declared by this backend",
                operation=request.operation,
            )
        if not request.allowed_scope:
            raise ExecutionRefused(
                "request carries no allowed scope", request_id=request.request_id
            )

        specification = str(request.payload.get("specification", "")).strip()
        if not specification:
            raise ExecutionRefused(
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
            raise ExecutionRefused(
                "provider call did not succeed",
                request_id=request.request_id,
                http_status=status,
            )

        try:
            parsed = json.loads(raw.decode("utf-8"))
            content = parsed["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, UnicodeDecodeError) as exc:
            raise ExecutionRefused(
                "provider response was not in the declared shape",
                request_id=request.request_id,
                detail=type(exc).__name__,
            ) from exc

        source = _strip_fences(content or "")
        if not source:
            raise ExecutionRefused(
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
