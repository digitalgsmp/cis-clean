#!/usr/bin/env python3
"""Deterministic verification for the pilot task.

Refuses to report a result it did not actually obtain. A collection error, a
zero-test run, or an unimportable module is a HARNESS FAILURE and is reported
as such - never as a verdict about the authored source. This mirrors the
recorded trap in both directions: zero tests discovered is not a pass, and a
loader error is not a model failure.
"""
import json, os, sys, unittest

# Isolated mode (-I) ignores both the cwd and PYTHONPATH by design, so the
# directory holding the task must be declared explicitly rather than assumed.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

EXPECTED_TESTS = 4

def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName("test_duration")
    collected = suite.countTestCases()

    if loader.errors:
        print(json.dumps({"verdict": "HARNESS_FAILURE", "reason": "collection error",
                          "detail": [str(e)[:200] for e in loader.errors],
                          "about_the_source": "NOTHING - the source was never imported"},
                         indent=2))
        return 2
    if collected != EXPECTED_TESTS:
        print(json.dumps({"verdict": "HARNESS_FAILURE",
                          "reason": f"expected {EXPECTED_TESTS} tests, collected {collected}",
                          "about_the_source": "NOTHING - an incomplete suite proves nothing"},
                         indent=2))
        return 2

    result = unittest.TextTestRunner(verbosity=0, stream=sys.stderr).run(suite)
    passed = result.wasSuccessful()
    print(json.dumps({
        "verdict": "SOURCE_PASS" if passed else "SOURCE_FAIL",
        "tests_collected": collected,
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
    }, indent=2))
    return 0 if passed else 1

if __name__ == "__main__":
    sys.exit(main())
