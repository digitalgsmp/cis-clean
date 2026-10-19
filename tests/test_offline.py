"""The slice requires no network and no model.

Not asserted by reading the code: the whole end-to-end path runs with
``socket.socket`` replaced by a trap that raises on construction, and with
``urllib`` and ``http.client`` request paths poisoned. If anything in the slice
tried to reach a network or a provider, these tests would fail rather than
pass quietly.
"""

import http.client
import socket
import unittest
import urllib.request
from pathlib import Path

from cis.interface import WorkbenchApi

from . import support

SRC = Path(__file__).resolve().parents[1] / "src"


class NetworkTrap:
    """Replaces socket.socket for the duration of a test."""

    def __init__(self):
        self.attempts = []

    def __call__(self, *args, **kwargs):
        self.attempts.append((args, kwargs))
        raise AssertionError("the slice attempted to open a socket")


class OfflineExecutionTests(unittest.TestCase):
    def setUp(self):
        self.trap = NetworkTrap()
        self._real_socket = socket.socket
        self._real_create = socket.create_connection
        self._real_getaddrinfo = socket.getaddrinfo
        self._real_urlopen = urllib.request.urlopen
        self._real_http = http.client.HTTPConnection.request
        socket.socket = self.trap
        socket.create_connection = self.trap
        socket.getaddrinfo = self.trap
        urllib.request.urlopen = self.trap
        http.client.HTTPConnection.request = self.trap

    def tearDown(self):
        socket.socket = self._real_socket
        socket.create_connection = self._real_create
        socket.getaddrinfo = self._real_getaddrinfo
        urllib.request.urlopen = self._real_urlopen
        http.client.HTTPConnection.request = self._real_http

    def test_the_whole_slice_runs_with_networking_disabled(self):
        wb = support.workbench()
        api = WorkbenchApi(wb)

        question = api.dispatch("POST", "/instruction",
                                {"verbatim": "What is the current stage?"})
        self.assertEqual(question.body["authorization"]["verdict"], "HOLD")

        fragment = api.dispatch(
            "POST", "/instruction",
            {"verbatim": "I vaguely remember something about dormant concepts"})
        self.assertTrue(fragment.body["antecedents"])

        allowed = api.dispatch("POST", "/instruction",
                               {"verbatim": support.ALLOW_INSTRUCTION})
        authorization_id = allowed.body["authorization"]["authorization_id"]
        run = api.dispatch("POST", "/execute",
                           {"authorization_id": authorization_id})
        self.assertEqual(run.body["run"]["status"], "completed")

        trajectory = api.dispatch(
            "GET", f"/trajectory/{allowed.body['transaction_id']}")
        self.assertEqual(
            trajectory.body["trajectory"]["you_are_here"]["event_type"],
            "execution_completed")

        self.assertEqual(self.trap.attempts, [])

    def test_the_blueprint_and_contracts_load_with_networking_disabled(self):
        blueprint = support.blueprint()
        self.assertEqual(len(blueprint.registry.contracts), support.expected_module_count())
        self.assertEqual(self.trap.attempts, [])


class NoModelDependencyTests(unittest.TestCase):
    _FORBIDDEN_IMPORTS = (
        "import requests", "import httpx", "import urllib",
        "import socket", "import http.client", "from urllib",
        "openai", "anthropic", "langchain", "transformers",
        "import torch", "sentence_transformers", "chromadb",
    )

    def _source_files(self):
        for path in sorted(SRC.rglob("*.py")):
            yield path, path.read_text(encoding="utf-8")

    def test_no_module_imports_a_network_or_model_library(self):
        offenders = []
        for path, text in self._source_files():
            # The HTTP transport wrapper is the one permitted exception, and it
            # may only use the standard library server, never a client.
            if path.name == "http_server.py":
                continue
            for token in self._FORBIDDEN_IMPORTS:
                if token in text:
                    offenders.append((path.name, token))
        self.assertEqual(offenders, [])

    def test_the_transport_wrapper_is_a_server_only(self):
        text = (SRC / "cis" / "interface" / "http_server.py").read_text(encoding="utf-8")
        self.assertIn("from http.server import", text)
        for token in ("HTTPConnection", "urlopen", "requests.", "connect("):
            self.assertNotIn(token, text)

    def test_the_slice_depends_on_the_standard_library_only(self):
        """No third-party import appears anywhere in src."""
        import sys
        stdlib = set(sys.stdlib_module_names)
        offenders = []
        for path, text in self._source_files():
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped.startswith("import "):
                    continue
                module = stripped.split()[1].split(".")[0]
                if module not in stdlib and not module.startswith("cis"):
                    offenders.append((path.name, module))
        self.assertEqual(offenders, [])

    def test_the_test_suite_itself_needs_no_third_party_package(self):
        import sys
        stdlib = set(sys.stdlib_module_names)
        tests_dir = Path(__file__).resolve().parent
        offenders = []
        for path in sorted(tests_dir.glob("*.py")):
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped.startswith("import "):
                    continue
                module = stripped.split()[1].split(".")[0]
                if module not in stdlib and not module.startswith("cis"):
                    offenders.append((path.name, module))
        self.assertEqual(offenders, [])


class ReferenceEnvironmentUntouchedTests(unittest.TestCase):
    def test_the_reference_environment_is_never_opened_for_writing(self):
        from cis.authority import AuthorityStore
        from cis.errors import CisError
        with self.assertRaises(CisError):
            AuthorityStore("/mnt/projects/cis/data/anything.db")

    def test_no_source_file_writes_a_path_under_the_reference_environment(self):
        for path in sorted(SRC.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for line in text.splitlines():
                if "/mnt/projects/cis/" not in line and \
                        '"/mnt/projects/cis"' not in line:
                    continue
                # Every mention must be a guard, a constant for the guard, or
                # a comment, never a write target.
                lowered = line.strip().lower()
                self.assertTrue(
                    lowered.startswith("#") or "refus" in lowered
                    or "_reference_environment" in lowered
                    or "reference" in lowered or "forbidden" in lowered
                    or "write:" in lowered,
                    f"{path.name}: {line.strip()}")


if __name__ == "__main__":
    unittest.main()
