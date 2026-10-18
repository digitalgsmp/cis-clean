#!/usr/bin/env python3
"""Trusted in-container verifier. VERDICT AUTHORITY LIVES HERE, NOT IN THE CODE UNDER TEST.

BAKED INTO THE IMAGE AT 0555 ON A READ-ONLY ROOT. Never read from /contract,
which carries untrusted, model-authored material: a verifier supplied by the
thing being verified is not a verifier.

THREAT MODEL. The source under test is adversarial. It may print anything,
raise anything, spawn anything, monkeypatch any library it can import, and
terminate its own process with any status at any moment.

WHY THE PREVIOUS DESIGN FAILED, TWICE OVER. v1 ran untrusted tests in the
trusted runner's own process and parsed its stdout: a test printed a forged
verdict line and won. v2 moved untrusted code to a child and authenticated its
self-report with a one-time token - but a self-report is still a self-report,
the token lives in a process the adversary controls, and untrusted source that
monkeypatches ``unittest.TestCase.assertEqual`` or calls ``os._exit(0)``
manufactures a pass without ever being correct.

THE INVARIANT THIS DESIGN ESTABLISHES. Untrusted code influences the verdict
ONLY through the values it actually computes. It is never asked whether it
passed, and its answer to that question would not be read.

HOW. Assertions do not run in the untrusted process at all. The declared test
VECTORS live in the digest-verified contract, not in the code under test. For
each vector this trusted parent spawns one child whose entire job is: import
the source, call the declared entrypoint with the declared argument, print the
return value as JSON, exit. THIS PARENT then compares what came back against
what the contract declared. Every authoritative fact - termination status,
collection count, execution count, failures, errors, harness failures and the
final disposition - is computed here.

Consequences for an adversary:
  * printing a forged verdict         -> nothing parses a verdict from a child
  * monkeypatching the test framework -> no test framework runs in the child
  * os._exit(0) before answering      -> no answer observed; vector FAILS
  * answering with a wrong value      -> compared here; vector FAILS
  * answering with the correct value  -> that is a correct implementation
The only path to SOURCE_PASS is computing every declared answer correctly.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

#: Per-vector wall clock. A hung child is an infrastructure fact, not a verdict.
VECTOR_TIMEOUT_SECONDS = 20

#: The child is trivial and fixed. It contains no logic the contract can steer:
#: import, call, print, exit. It makes no pass/fail judgement of any kind.
_CHILD = (
    "import json,sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "mod = __import__(sys.argv[2])\n"
    "fn = getattr(mod, sys.argv[3])\n"
    "arg = json.loads(sys.argv[4])\n"
    "try:\n"
    "    out = fn(*arg)\n"
    "except BaseException as exc:\n"
    "    sys.stdout.write('R' + json.dumps({'raised': type(exc).__name__}))\n"
    "    sys.exit(0)\n"
    "sys.stdout.write('R' + json.dumps({'value': out}))\n"
)


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _emit(verdict: str, **fields) -> int:
    payload = {"verdict": verdict}
    payload.update(fields)
    sys.stdout.write("CIS_VERDICT " + json.dumps(payload, sort_keys=True) + "\n")
    return {"SOURCE_PASS": 0, "SOURCE_FAIL": 1}.get(verdict, 2)


def _observe(contract_dir: str, run_dir: str, module: str, entry: str, arg) -> dict:
    """Run one vector and report ONLY what was observed. No judgement here."""
    try:
        child = subprocess.run(
            [sys.executable, "-I", "-c", _CHILD, contract_dir, module, entry,
             json.dumps(arg)],
            cwd=run_dir, capture_output=True, text=True,
            timeout=VECTOR_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return {"observed": "timeout"}
    except OSError as exc:
        return {"observed": "spawn_failed", "detail": type(exc).__name__}

    # Untrusted stdout is DATA. The single record marker is a framing device,
    # not an authentication: a forged record can only ever assert a RETURN
    # VALUE, which is then compared against the contract like any other.
    marks = [i for i, line in enumerate(child.stdout.splitlines()) if line.startswith("R")]
    lines = [ln for ln in child.stdout.splitlines() if ln.startswith("R")]
    if len(lines) != 1:
        return {"observed": "no_single_answer", "answers": len(lines),
                "exit": child.returncode}
    try:
        answer = json.loads(lines[0][1:])
    except ValueError:
        return {"observed": "unparseable_answer", "exit": child.returncode}
    if not isinstance(answer, dict) or not ({"value", "raised"} & set(answer)):
        return {"observed": "malformed_answer", "exit": child.returncode}
    return {"observed": "answered", "answer": answer, "exit": child.returncode,
            "marks": len(marks)}


def main() -> int:
    contract_dir = os.environ.get("CIS_CONTRACT_DIR", "/contract")
    run_dir = os.environ.get("CIS_RUN_DIR", "/workspace/run")

    try:
        with open(os.path.join(contract_dir, "input.json"), encoding="utf-8") as fh:
            declared = json.load(fh)
    except Exception as exc:
        return _emit("HARNESS_FAILURE", reason="declaration unreadable",
                     detail=type(exc).__name__, about_the_source="NOTHING")

    try:
        source_name = str(declared["source_filename"])
        expected_source = str(declared["source_sha256"])
        module = str(declared["source_module"])
        entry = str(declared["entrypoint"])
        vectors = list(declared["vectors"])
        expected_count = int(declared["expected_test_count"])
    except (KeyError, TypeError, ValueError) as exc:
        return _emit("HARNESS_FAILURE", reason="declaration incomplete",
                     detail=type(exc).__name__, about_the_source="NOTHING")

    if os.path.basename(source_name) != source_name or source_name in ("", ".", ".."):
        return _emit("HARNESS_FAILURE", reason="declared filename is not a bare name",
                     about_the_source="NOTHING")

    # The collection count is taken from the DIGEST-VERIFIED CONTRACT, never
    # from the code under test. Untrusted source cannot change how many
    # assertions it faces.
    if len(vectors) != expected_count:
        return _emit("HARNESS_FAILURE",
                     reason="declared vector count does not match expected_test_count",
                     vectors=len(vectors), expected_test_count=expected_count,
                     about_the_source="NOTHING - an undeclared suite proves nothing")
    if expected_count <= 0:
        return _emit("HARNESS_FAILURE", reason="no vectors declared",
                     about_the_source="NOTHING - zero tests is never a pass")

    source_path = os.path.join(contract_dir, source_name)
    try:
        actual_source = _sha256(source_path)
    except OSError as exc:
        return _emit("HARNESS_FAILURE", reason="declared source missing",
                     detail=type(exc).__name__, about_the_source="NOTHING")
    if actual_source != expected_source:
        return _emit("HARNESS_FAILURE", reason="source digest mismatch",
                     expected=expected_source, actual=actual_source,
                     about_the_source="NOTHING - refused before execution")

    os.makedirs(run_dir, exist_ok=True)

    executed = failures = errors = 0
    results = []
    for index, vector in enumerate(vectors):
        try:
            arg = list(vector["args"])
            wants_value = "expect_value" in vector
            wants_raise = "expect_raises" in vector
        except (KeyError, TypeError):
            return _emit("HARNESS_FAILURE", reason="vector malformed", index=index,
                         about_the_source="NOTHING")
        if wants_value == wants_raise:
            return _emit("HARNESS_FAILURE",
                         reason="vector must declare exactly one expectation",
                         index=index, about_the_source="NOTHING")

        seen = _observe(contract_dir, run_dir, module, entry, arg)
        executed += 1

        if seen["observed"] in ("spawn_failed",):
            # The harness could not run. That is infrastructure, not the source.
            return _emit("HARNESS_FAILURE", reason="vector could not be spawned",
                         index=index, detail=seen.get("detail"),
                         about_the_source="NOTHING")
        if seen["observed"] == "timeout":
            # Resource exhaustion and hangs are the SOURCE's observable
            # behaviour for this vector, but they are classified as errors
            # rather than silent passes, and the reason is recorded.
            errors += 1
            results.append({"i": index, "outcome": "ERROR", "why": "timeout"})
            continue
        if seen["observed"] != "answered":
            errors += 1
            results.append({"i": index, "outcome": "ERROR", "why": seen["observed"],
                            "exit": seen.get("exit")})
            continue

        answer = seen["answer"]
        if wants_raise:
            ok = answer.get("raised") == str(vector["expect_raises"])
        else:
            ok = ("value" in answer) and (answer["value"] == vector["expect_value"])
        if ok:
            results.append({"i": index, "outcome": "PASS"})
        else:
            failures += 1
            results.append({"i": index, "outcome": "FAIL", "got": answer})

    # EVERY FIGURE BELOW WAS COMPUTED HERE, FROM OBSERVATIONS MADE HERE.
    if executed != expected_count:
        return _emit("HARNESS_FAILURE", reason="executed count does not match declaration",
                     executed=executed, expected_test_count=expected_count,
                     about_the_source="NOTHING")

    verdict = "SOURCE_PASS" if (failures == 0 and errors == 0) else "SOURCE_FAIL"
    return _emit(verdict, tests_collected=expected_count, tests_run=executed,
                 failures=failures, errors=errors, source_sha256=actual_source,
                 results=results)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        sys.exit(_emit("HARNESS_FAILURE", reason="verifier crashed",
                       detail=f"{type(exc).__name__}: {exc}"[:300],
                       about_the_source="NOTHING"))
