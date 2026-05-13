#!/usr/bin/env python3
"""HMAC signer that mirrors src/core/sig_verify.rs byte-for-byte.

Header format: X-Sandbox-Signature: t=<ts>,s=<hex>
Canonical message: f"{ts}.{method}.{path}"
Secret: hex-decoded if string is all-hex even length, else UTF-8 bytes
(matches Rust classify_secret() in sig_verify.rs).

Usage: sign.py <ts> <method> <path> <secret>
"""

import hashlib
import hmac
import string
import sys


def classify_secret(s: str) -> bytes:
    """Match Rust: try hex-decode first, fall back to UTF-8 bytes."""
    if len(s) % 2 == 0 and s and all(c in string.hexdigits for c in s):
        try:
            return bytes.fromhex(s)
        except ValueError:
            return s.encode()
    return s.encode()


def main() -> int:
    if len(sys.argv) != 5:
        print("usage: sign.py <ts> <method> <path> <secret>", file=sys.stderr)
        return 2
    ts, method, path, secret = sys.argv[1:5]
    key = classify_secret(secret)
    msg = f"{ts}.{method}.{path}".encode()
    digest = hmac.new(key, msg, hashlib.sha256).hexdigest()
    print(f"t={ts},s={digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
