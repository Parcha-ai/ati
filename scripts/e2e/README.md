# Full-stack E2E harness

A bash + Python harness that drives the real `ati proxy` binary on
`127.0.0.1`, real mock upstreams, real SIGHUPs, real WebSocket upgrades,
and real `ati edge` invocations against a fake `op` binary. Designed to
catch regressions that the in-process `cargo test` suite can't — middleware
ordering, signal handling, atomic-rename behaviour, real socket lifecycle.

## Quick start

```bash
cargo build --release --bin ati
pip install --user websockets==15.0.1
bash scripts/test_full_stack_e2e.sh --pr all     # ~17s, 67 cases
```

Filter by PR scope:

```bash
bash scripts/test_full_stack_e2e.sh --pr 96   # sig-verify + middleware order + SIGHUP
bash scripts/test_full_stack_e2e.sh --pr 97   # ati edge CLI
bash scripts/test_full_stack_e2e.sh --pr 98   # WebSocket passthrough
```

Keep the temp directory for post-mortem (proxy logs, mock recordings):

```bash
bash scripts/test_full_stack_e2e.sh --pr all --keep-tmpdir
# Kept tmpdir: /tmp/ati-e2e-XXXXXX
```

## Scenario matrix

| Group | What it covers | # cases |
|---|---|---|
| A | sig-verify in log/warn/enforce; missing/valid/expired/tampered/malformed/exempt/no-secret/hex/utf8 | 22 |
| B | SIGHUP rotation, old-secret revocation, corrupt-keyring preserves previous, **50-concurrent in-flight torn-read guard** | 6 |
| C | host_match, path_prefix strip, strip_prefix=false, path_replace, deny_paths, auth injection, hop-by-hop stripping (incl. RFC 7230 §6.1 Connection-named), x-sandbox-* stripping, caller-Authorization replaced, max_request_bytes 413, max_response_bytes stream-cut, named-route precedence | 17 |
| D | text/binary/large echo, close propagation both directions, auth header & auth_query on upgrade, subprotocol forwarded both directions, forward_websockets=false rejection, connect_timeout fail-fast | 11 |
| E | bootstrap-keyring, rotate-keyring atomic-rename, **--op-token-file passes VALUE not PATH**, op-fail leaves keyring intact, missing-dir clean error | 5 |
| F | sig-verify-runs-BEFORE-JWT (the protect-passthrough property), named-route precedence over passthrough fallback | 6 |

## Layout

```
scripts/
├── test_full_stack_e2e.sh         # orchestrator + --pr filter
└── e2e/
    ├── lib.sh                     # assert_*, start/stop_proxy, port helpers, trap cleanup
    ├── sign.py                    # HMAC signer (mirrors src/core/sig_verify.rs)
    ├── mock_http.py               # threaded HTTP echo / slow / big_response upstream
    ├── mock_ws.py                 # websockets-based echo / blackhole WS upstream
    ├── ws_probe.py                # WS client used by Group D
    ├── fake_op.sh                 # PATH-injectable fake `op` binary (--op-path)
    ├── fixtures/
    │   ├── op_*.json              # 1Password JSON fixtures (bootstrap, rotated, corrupt, no_secret)
    │   └── manifest_*.toml.tmpl   # passthrough manifest templates (port-substituted at runtime)
    └── groups/
        ├── group_a.sh             # sig-verify modes (PR #96)
        ├── group_b.sh             # SIGHUP rotation (PRs #96 + #97)
        ├── group_c.sh             # HTTP passthrough routing (PR #95)
        ├── group_d.sh             # WebSocket passthrough (PR #98)
        ├── group_e.sh             # `ati edge` CLI (PR #97)
        └── group_f.sh             # middleware ordering
```

## Ports used (all 127.0.0.1)

| Port | Purpose |
|---|---|
| 18910 | proxy under test |
| 18920 | HTTP echo upstream |
| 18921 | HTTP slow upstream (Group B in-flight test) |
| 18922 | HTTP big-response upstream (Group C max_response_bytes test) |
| 18930 | WS echo upstream |
| 18931 | WS black-hole upstream (Group D connect_timeout) |

The orchestrator force-kills anything holding these ports at start-of-run
and on exit (trap), so re-running after a crash is always clean.

## Why this exists (and what `cargo test` can't replicate)

`cargo test` mocks each axum layer in isolation via `wiremock` +
`tower::ServiceExt::oneshot`. That misses:

- **Middleware ordering** — sig-verify must run BEFORE JWT auth so an
  unsigned passthrough request gets 403 (sig-verify), not 401 (JWT). Only
  a real `Router` driven from outside the process can verify this.
- **SIGHUP signal delivery** to a real PID with a real ArcSwap secret swap.
- **Torn-read protection** — 50 concurrent in-flight requests crossing a
  SIGHUP rotation, exposing whether the secret is resolved at request-start
  vs. at upstream-response.
- **Atomic-rename behaviour** of `ati edge rotate-keyring` against a real
  filesystem.
- **`op` subprocess plumbing** — the harness uses `ati edge ... --op-path
  scripts/e2e/fake_op.sh` to inject a known-shape fake (no PATH shimming).
- **Real WS upgrade**: subprotocol negotiation, close-frame propagation
  both directions, large frames, connect_timeout against a black-hole
  upstream — all use real sockets, not in-process `tokio::io::duplex`.

## Findings the harness has already surfaced

Each of these started as a real proxy bug the harness found on its first
run, and was fixed in the same PR that adds the harness:

1. **Greptile #96 P1 not cherry-picked onto WS branch.** The "preserve
   secret on SIGHUP reload error" fix lived only on `feat/sig-verify-middleware`.
   Group B3 caught it immediately; cherry-picked.
2. **`Trailer` hop-by-hop spelled `trailers` (plural) in HOP_BY_HOP list.**
   RFC 7230 §6.1 names the singular header. Fixed: added "trailer".
3. **Headers named in `Connection:` not stripped.** RFC 7230 §6.1 says
   any header named in `Connection` is hop-by-hop. Added
   `connection_hop_names()` and a second-pass filter.
4. **WebSocket subprotocol not echoed back to client.** Proxy used bare
   `WebSocketUpgrade::from_request` which never sets `Sec-WebSocket-Protocol`
   on the inbound 101 — even when the upstream chose one. Now captures the
   client's offered list up front and passes it to `upgrade.protocols(...)`.

## CI

Wired into `.github/workflows/ci.yml` as a step in the `Test and E2E` job,
runs after `Proxy server E2E`. Same script, debug binary, ~17s. CI step
times out at 5 minutes.
