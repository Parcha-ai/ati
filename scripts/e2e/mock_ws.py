#!/usr/bin/env python3
"""Mock WebSocket upstream for the ATI E2E harness.

Modes (--mode):
  echo       Accept upgrade, echo all frames (text + binary) back. Logs received
             upgrade path + query + headers to $WS_LOG so tests can assert about
             auth header / auth_query / subprotocol injection.
  blackhole  Accept TCP but NEVER respond to the HTTP upgrade — used to validate
             that connect_timeout_seconds fails fast.
"""

import argparse
import asyncio
import json
import os
import sys

WS_LOG = os.environ.get("WS_LOG", "")


def log_upgrade(path: str, headers: dict, subproto: str | None) -> None:
    if not WS_LOG:
        return
    try:
        with open(WS_LOG, "a") as f:
            f.write(
                json.dumps(
                    {
                        "path": path,
                        "headers": {k.lower(): v for k, v in headers.items()},
                        "subprotocol_negotiated": subproto,
                    }
                )
                + "\n"
            )
    except OSError:
        pass


async def run_echo(host: str, port: int) -> None:
    import websockets

    async def handler(ws):
        # path/query lives on ws.request.path (websockets >= 13). Headers on
        # ws.request.headers (Headers obj that walks like dict).
        req = getattr(ws, "request", None)
        path = req.path if req is not None else "/"
        hdrs = dict(req.headers) if req is not None else {}
        subproto = getattr(ws, "subprotocol", None)
        log_upgrade(path, hdrs, subproto)
        try:
            async for msg in ws:
                # Echo verbatim. websockets gives bytes for binary, str for text.
                await ws.send(msg)
        except websockets.exceptions.ConnectionClosed:
            pass

    # Negotiate any subprotocol the client offers — picks the first one,
    # so the upstream sees Sec-WebSocket-Protocol echoed back.
    def select_subprotocol(connection, subprotocols):
        return subprotocols[0] if subprotocols else None

    async with websockets.serve(
        handler,
        host,
        port,
        select_subprotocol=select_subprotocol,
        max_size=2 * (1 << 20),  # 2 MiB — covers the 1 MiB test frame
    ):
        await asyncio.Future()


async def run_blackhole(host: str, port: int) -> None:
    # Accept TCP, dump bytes, never write back. Mimics a kernel-accept'd
    # socket whose userspace never replies.
    server = await asyncio.start_server(
        lambda r, w: asyncio.sleep(3600), host, port
    )
    async with server:
        await server.serve_forever()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--mode", choices=["echo", "blackhole"], default="echo")
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    try:
        if args.mode == "echo":
            asyncio.run(run_echo(args.host, args.port))
        else:
            asyncio.run(run_blackhole(args.host, args.port))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
