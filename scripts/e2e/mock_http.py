#!/usr/bin/env python3
"""Mock HTTP upstream for the ATI E2E harness.

Modes (--mode):
  echo              200; body = JSON dump of received {method, path, headers, body_len}.
                    Records every received request to $MOCK_LOG (if set) so tests can
                    assert about hop-by-hop stripping, host_override, auth injection.
  slow              Same as echo, but sleeps SLOW_SECONDS (default 1.5) before responding.
  big_response      200; body = NN bytes (default 1MB) regardless of request — used to
                    exercise max_response_bytes stream cap.
"""

import argparse
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MOCK_LOG = os.environ.get("MOCK_LOG", "")


def log_record(record: dict) -> None:
    if not MOCK_LOG:
        return
    try:
        with open(MOCK_LOG, "a") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        pass


class Handler(BaseHTTPRequestHandler):
    mode: str = "echo"
    slow_seconds: float = 1.5
    big_size: int = 1 << 20  # 1 MiB

    # Quiet — stdout is a global resource and 50 concurrent requests in a single
    # test would otherwise flood the console.
    def log_message(self, fmt, *args):  # noqa: D401, N802
        return

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _record(self, body: bytes) -> dict:
        return {
            "method": self.command,
            "path": self.path,
            "host": self.headers.get("Host", ""),
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body_len": len(body),
            "body_sha_prefix": body[:64].decode("utf-8", "replace"),
        }

    def _respond(self) -> None:
        body = self._read_body()
        record = self._record(body)
        log_record(record)

        if self.mode == "slow":
            time.sleep(self.slow_seconds)
            payload = json.dumps(record).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if self.mode == "big_response":
            payload = b"x" * self.big_size
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            # Don't send Content-Length so axum streams the body and our cap
            # has to fire mid-stream.
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            chunk = b"x" * 4096
            written = 0
            while written < self.big_size:
                n = min(len(chunk), self.big_size - written)
                # chunk framing: <hex-size>\r\n<data>\r\n
                self.wfile.write(f"{n:x}\r\n".encode() + chunk[:n] + b"\r\n")
                written += n
            self.wfile.write(b"0\r\n\r\n")
            return

        # default: echo
        payload = json.dumps(record).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        # An echo header so assertions can prove "the upstream actually ran".
        self.send_header("X-Mock-Upstream", "echo")
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond
    do_DELETE = _respond
    do_PATCH = _respond


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--mode", choices=["echo", "slow", "big_response"], default="echo")
    ap.add_argument("--slow-seconds", type=float, default=1.5)
    ap.add_argument("--big-size", type=int, default=1 << 20)
    args = ap.parse_args()

    Handler.mode = args.mode
    Handler.slow_seconds = args.slow_seconds
    Handler.big_size = args.big_size

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    srv.daemon_threads = True
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
