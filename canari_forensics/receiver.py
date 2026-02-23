from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from canari_forensics.parsers.otel import OTELParser
from canari_forensics.storage import SQLiteTurnStore


class _TraceHandler(BaseHTTPRequestHandler):
    receiver: "OTLPReceiver"

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in ("/v1/traces", "/traces"):
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)

        try:
            inserted = self.receiver.ingest_payload(body)
        except Exception as exc:  # pragma: no cover - network handling
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(exc)}).encode("utf-8"))
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"inserted": inserted}).encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


class OTLPReceiver:
    def __init__(self, host: str, port: int, db_path: str) -> None:
        self.host = host
        self.port = port
        self.parser = OTELParser()
        self.store = SQLiteTurnStore(db_path)
        self._server: HTTPServer | None = None

    def ingest_payload(self, payload: bytes | str | dict[str, Any] | list[Any]) -> int:
        if isinstance(payload, (dict, list)):
            data = payload
        elif isinstance(payload, bytes):
            data = json.loads(payload.decode("utf-8"))
        elif isinstance(payload, str):
            data = json.loads(payload)
        else:
            raise TypeError("Unsupported payload type")

        turns = list(self.parser._parse_payload(data))
        return self.store.insert_turns(turns)

    def _build_server(self) -> HTTPServer:
        handler_cls = type(
            "CanariTraceHandler",
            (_TraceHandler,),
            {"receiver": self},
        )
        return HTTPServer((self.host, self.port), handler_cls)

    def serve_forever(self) -> None:
        self._server = self._build_server()
        self._server.serve_forever()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()

    def serve_in_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, daemon=True)
        t.start()
        return t
