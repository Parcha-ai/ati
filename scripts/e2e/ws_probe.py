#!/usr/bin/env python3
"""WebSocket probe client for the ATI E2E harness.

Connects to a URL through the proxy, sends optional payloads, expects an echo
back (or a close code), and reports JSON-line results. Exits 0 on success.

Flags:
  --url ws://...                   Required.
  --header K:V                     Add request header (repeatable).
  --subprotocol NAME[,NAME...]     Offer subprotocol(s).
  --send-text TEXT                 Send a text frame and assert it echoes back.
  --send-binary HEX                Hex-encoded bytes to send & assert echo.
  --send-binary-size N             Send N bytes of random binary; assert echo.
  --expect-no-connect              Expect the upgrade to FAIL (timeout/refused).
  --expect-close-code N            Expect upstream close code N.
  --connect-timeout SECONDS        Bail out if upgrade doesn't complete in N s.
"""

import argparse
import asyncio
import json
import secrets
import sys


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--subprotocol", default=None)
    ap.add_argument("--send-text", default=None)
    ap.add_argument("--send-binary", default=None)
    ap.add_argument("--send-binary-size", type=int, default=0)
    ap.add_argument("--expect-no-connect", action="store_true")
    ap.add_argument("--expect-close-code", type=int, default=None)
    ap.add_argument("--connect-timeout", type=float, default=4.0)
    return ap.parse_args()


async def run() -> int:
    import websockets

    args = parse_args()
    headers = []
    for h in args.header:
        if ":" not in h:
            print(f"ws_probe: bad --header (no colon): {h}", file=sys.stderr)
            return 2
        k, v = h.split(":", 1)
        headers.append((k.strip(), v.strip()))

    subprotos = (
        [s.strip() for s in args.subprotocol.split(",")] if args.subprotocol else None
    )

    try:
        connect = websockets.connect(
            args.url,
            additional_headers=headers,
            subprotocols=subprotos,
            open_timeout=args.connect_timeout,
            close_timeout=2,
            max_size=2 * (1 << 20),
        )
        ws = await asyncio.wait_for(connect, timeout=args.connect_timeout)
    except (
        asyncio.TimeoutError,
        ConnectionRefusedError,
        OSError,
        websockets.exceptions.WebSocketException,
    ) as e:
        if args.expect_no_connect:
            print(json.dumps({"ok": True, "no_connect": str(e)}))
            return 0
        print(json.dumps({"ok": False, "error": f"connect failed: {e}"}), file=sys.stderr)
        return 1

    if args.expect_no_connect:
        await ws.close()
        print(json.dumps({"ok": False, "error": "expected no-connect but upgrade succeeded"}),
              file=sys.stderr)
        return 1

    try:
        if args.send_text is not None:
            await ws.send(args.send_text)
            got = await asyncio.wait_for(ws.recv(), timeout=4)
            if got != args.send_text:
                print(json.dumps({"ok": False, "error": f"text echo mismatch: got={got!r}"}),
                      file=sys.stderr)
                return 1

        if args.send_binary is not None:
            payload = bytes.fromhex(args.send_binary)
            await ws.send(payload)
            got = await asyncio.wait_for(ws.recv(), timeout=4)
            if got != payload:
                print(json.dumps({"ok": False, "error": "binary echo mismatch"}), file=sys.stderr)
                return 1

        if args.send_binary_size > 0:
            payload = secrets.token_bytes(args.send_binary_size)
            await ws.send(payload)
            got = await asyncio.wait_for(ws.recv(), timeout=8)
            if got != payload:
                print(json.dumps({"ok": False, "error": "large binary mismatch"}), file=sys.stderr)
                return 1

        if args.expect_close_code is not None:
            await ws.close(code=args.expect_close_code, reason="probe close")
            await asyncio.sleep(0.05)
            print(json.dumps({"ok": True, "close_code": ws.close_code}))
            return 0
    finally:
        try:
            await ws.close()
        except Exception:
            pass

    subproto = ws.subprotocol if hasattr(ws, "subprotocol") else None
    print(json.dumps({"ok": True, "subprotocol_negotiated": subproto}))
    return 0


def main() -> int:
    try:
        return asyncio.run(run())
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
