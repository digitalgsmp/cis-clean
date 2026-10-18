#!/usr/bin/env python3
"""Trusted in-container verification runner for model-authored source.

BAKED INTO THE IMAGE AT 0555 ON A READ-ONLY ROOT FILESYSTEM. It is deliberately
NOT read from /contract: /contract carries untrusted, model-authored material,
and a verifier supplied by the thing being verified is not a verifier.

It answers exactly one question and refuses to guess:

  SOURCE_PASS     the declared tests were collected in the declared number and
                  all of them passed
  SOURCE_FAIL     the declared tests were collected in the declared number and
                  at least one failed or errored
  HARNESS_FAILURE anything else - a collection error, an unimportable module, a
                  test count that does not match the declaration, a crash in
                  the runner itself

HARNESS_FAILURE IS NEVER A STATEMENT ABOUT THE SOURCE. The distinction exists
because a loader error reporting as a source failure, and a zero-test run
reporting as a pass, are the same defect pointing in opposite directions, and
both have already occurred in this project.

Untrusted code runs with the interpreter's cwd set to the writable run
directory and never with /contract writable. The caller writes evidence after
this process exits, so nothing this process executes can author its own
verdict.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _emit(verdict: str, **fields) -> int:
    payload = {"verdict": verdict}
    payload.update(fields)
    # Single-line JSON on stdout: the caller parses exactly one line, so
    # anything untrusted code prints cannot be mistaken for the verdict.
    sys.stdout.write("CIS_VERDICT " + json.dumps(payload, sort_keys=True) + "\n")
    return {"SOURCE_PASS": 0, "SOURCE_FAIL": 1}.get(verdict, 2)


def main() -> int:
    contract_dir = os.environ.get("CIS_CONTRACT_DIR", "/contract")
    run_dir = os.environ.get("CIS_RUN_DIR", "/workspace/run")

    try:
        with open(os.path.join(contract_dir, "input.json"), encoding="utf-8") as handle:
            declared = json.load(handle)
    except Exception as exc:
        return _emit("HARNESS_FAILURE", reason="declaration unreadable",
                     detail=type(exc).__name__, about_the_source="NOTHING")

    try:
        source_name = str(declared["source_filename"])
        test_name = str(declared["test_filename"])
        expected_source = str(declared["source_sha256"])
        expected_test = str(declared["test_sha256"])
        expected_count = int(declared["expected_test_count"])
        test_module = str(declared["test_module"])
    except (KeyError, TypeError, ValueError) as exc:
        return _emit("HARNESS_FAILURE", reason="declaration incomplete",
                     detail=type(exc).__name__, about_the_source="NOTHING")

    # A declared name that escapes the contract directory is refused outright.
    for name in (source_name, test_name):
        if os.path.basename(name) != name or name in ("", ".", ".."):
            return _emit("HARNESS_FAILURE", reason="declared filename is not a bare name",
                         detail=name, about_the_source="NOTHING")

    source_path = os.path.join(contract_dir, source_name)
    test_path = os.path.join(contract_dir, test_name)

    # DIGEST EQUALITY BEFORE EXECUTION. Nothing is imported until the bytes on
    # disk are the bytes the authorization named.
    try:
        actual_source, actual_test = _sha256(source_path), _sha256(test_path)
    except OSError as exc:
        return _emit("HARNESS_FAILURE", reason="declared file missing",
                     detail=type(exc).__name__, about_the_source="NOTHING")

    if actual_source != expected_source:
        return _emit("HARNESS_FAILURE", reason="source digest mismatch",
                     expected=expected_source, actual=actual_source,
                     about_the_source="NOTHING - refused before execution")
    if actual_test != expected_test:
        return _emit("HARNESS_FAILURE", reason="test digest mismatch",
                     expected=expected_test, actual=actual_test,
                     about_the_source="NOTHING - refused before execution")

    # UNTRUSTED CODE RUNS IN A CHILD PROCESS, NEVER IN THIS ONE.
    #
    # Independent review (GLM-5.2, 2026-10-18, finding HIGH) proved that the
    # previous in-process design was forgeable: untrusted tests shared this
    # process's stdout, the genuine verdict was emitted last, and the caller
    # took the first match - so a test could print a SOURCE_PASS line and win.
    # The exploit was reproduced before this fix: verdict=SOURCE_PASS with
    # runner_exit=1 on a suite whose every test failed.
    #
    # Three things close it. The child's stdout and stderr are captured, so
    # nothing untrusted can write to the channel this process reports on. A
    # one-time token is handed to the child over a pipe that is drained and
    # closed before any untrusted import, so a forged record without the token
    # is rejected. And the child's exit code must agree with the record it
    # returned, so a forged record contradicting the real outcome is refused.
    os.makedirs(run_dir, exist_ok=True)
    token = secrets.token_hex(16)
    read_fd, write_fd = os.pipe()
    os.write(write_fd, (token + "\n").encode("ascii"))
    os.close(write_fd)

    inner = (
        "import json,os,sys,unittest\n"
        "tok=os.read(3,33).decode().strip()\n"
        "os.close(3)\n"
        "sys.path.insert(0,sys.argv[1])\n"
        "ldr=unittest.TestLoader()\n"
        "try:\n"
        "    s=ldr.loadTestsFromName(sys.argv[2])\n"
        "except Exception as e:\n"
        "    print('INNER '+tok+' '+json.dumps({'k':'collect_raise','d':str(e)[:200]}));sys.exit(2)\n"
        "if ldr.errors:\n"
        "    print('INNER '+tok+' '+json.dumps({'k':'collect_error','d':[str(x)[:200] for x in ldr.errors]}));sys.exit(2)\n"
        "n=s.countTestCases()\n"
        "if n!=int(sys.argv[3]):\n"
        "    print('INNER '+tok+' '+json.dumps({'k':'count','n':n}));sys.exit(2)\n"
        "r=unittest.TextTestRunner(verbosity=0,stream=sys.stderr).run(s)\n"
        "ok=r.wasSuccessful()\n"
        "print('INNER '+tok+' '+json.dumps({'k':'ran','n':n,'run':r.testsRun,"
        "'f':len(r.failures),'e':len(r.errors),'ok':ok}))\n"
        "sys.exit(0 if ok else 1)\n"
    )

    try:
        child = subprocess.run(
            [sys.executable, "-I", "-c", inner, contract_dir, test_module, str(expected_count)],
            cwd=run_dir, capture_output=True, text=True, timeout=120,
            pass_fds=(read_fd,),
        )
    except subprocess.TimeoutExpired:
        return _emit("HARNESS_FAILURE", reason="verification workload timed out",
                     about_the_source="NOTHING")
    finally:
        try: os.close(read_fd)
        except OSError: pass

    # Only a record bearing the one-time token counts, and exactly one may.
    records = [ln for ln in child.stdout.splitlines() if ln.startswith("INNER " + token + " ")]
    if len(records) != 1:
        return _emit("HARNESS_FAILURE",
                     reason="expected exactly one authenticated result record",
                     records_found=len(records), child_exit=child.returncode,
                     about_the_source="NOTHING - a forged or absent record proves nothing")
    try:
        rec = json.loads(records[0].split(" ", 2)[2])
    except ValueError:
        return _emit("HARNESS_FAILURE", reason="result record unparseable",
                     about_the_source="NOTHING")

    kind = rec.get("k")
    if kind == "collect_raise":
        return _emit("HARNESS_FAILURE", reason="collection raised", detail=rec.get("d"),
                     about_the_source="NOTHING")
    if kind == "collect_error":
        return _emit("HARNESS_FAILURE", reason="collection error", detail=rec.get("d"),
                     about_the_source="NOTHING - the source was never imported")
    if kind == "count":
        return _emit("HARNESS_FAILURE",
                     reason="collected test count does not match the declaration",
                     expected_test_count=expected_count, tests_collected=rec.get("n"),
                     about_the_source="NOTHING - an undeclared suite proves nothing")
    if kind != "ran":
        return _emit("HARNESS_FAILURE", reason="unknown result record",
                     about_the_source="NOTHING")

    # The record and the exit code must agree, or neither is trustworthy.
    expected_exit = 0 if rec.get("ok") else 1
    if child.returncode != expected_exit:
        return _emit("HARNESS_FAILURE",
                     reason="result record contradicts the workload exit code",
                     record_ok=rec.get("ok"), child_exit=child.returncode,
                     about_the_source="NOTHING - an inconsistent run proves nothing")

    verdict = "SOURCE_PASS" if rec.get("ok") else "SOURCE_FAIL"
    return _emit(verdict, tests_collected=rec.get("n"), tests_run=rec.get("run"),
                 failures=rec.get("f"), errors=rec.get("e"),
                 source_sha256=actual_source, test_sha256=actual_test)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        sys.exit(_emit("HARNESS_FAILURE", reason="runner crashed",
                       detail=f"{type(exc).__name__}: {exc}"[:300],
                       about_the_source="NOTHING"))
