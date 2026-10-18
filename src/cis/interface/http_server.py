"""Transport only: a stdlib HTTP wrapper over the pure API dispatcher.

No framework, no dependency, no behaviour. Everything this module can answer,
``WorkbenchApi.dispatch`` can answer without a socket, which is how the test
suite exercises the slice with networking disabled.

Binds loopback by default. Nothing here makes an outbound call.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from .api import WorkbenchApi


def build_server(api: WorkbenchApi, *, host: str = "127.0.0.1",
                 port: int = 8077) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "cis-clean-workbench/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
            pass

        def _respond(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                payload = json.dumps({"ok": False, "error": {
                    "code": "BAD_JSON", "message": "request body is not JSON"}})
                self._write(400, payload)
                return
            response = api.dispatch(method, self.path, body)
            self._write(response.status, response.json())

        def _write(self, status: int, payload: str) -> None:
            encoded = payload.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            self._respond("GET")

        def do_POST(self) -> None:
            self._respond("POST")

    # Deliberately serialized. AuthorityStore owns one SQLite connection and
    # logical sequence; a transactional multi-writer design is a later slice.
    return HTTPServer((host, port), Handler)


def run_server(api: WorkbenchApi, *, host: str = "127.0.0.1",
               port: int = 8077) -> None:  # pragma: no cover - operator entry
    server = build_server(api, host=host, port=port)
    print(f"cis-clean workbench listening on http://{host}:{port}")
    print("GET /health for the route list. Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
