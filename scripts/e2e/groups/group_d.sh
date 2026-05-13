# Group D — WebSocket passthrough (PR #98), 10 cases.

group_header "Group D — WebSocket passthrough (10 cases)"

S1="11111111111111111111111111111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# Mocks: echo WS upstream + black-hole WS upstream (TCP accept, no reply)
start_mock_ws "$PORT_UPSTREAM_WS" echo
start_mock_ws "$PORT_UPSTREAM_WS_BH" blackhole

# Install WS-relevant manifests
install_manifests ws ws_blackhole ws_disabled ws_query
bootstrap_keyring "$E2E_DIR/fixtures/op_bootstrap.json"

# WS upgrades do NOT carry HTTP body, so sig-verify's HMAC over
# {ts}.{method}.{path} still works for GET-style upgrade. We use enforce mode
# to validate that the sig-verify gate runs before the WS upgrade.
start_proxy --mode enforce

: > "$WS_LOG"

# Helper: sign + connect via ws_probe.py against /ws path on the proxy
ws_signed_probe() {
    local path="$1"; shift
    local ts sig
    ts=$(now); sig=$(sign "$ts" GET "$path" "$S1")
    python3 "$E2E_DIR/ws_probe.py" \
        --url "ws://127.0.0.1:$PROXY_PORT$path" \
        --header "X-Sandbox-Signature: $sig" \
        "$@"
}

# --- D1: text echo ---
if ws_signed_probe /ws/echo --send-text "hello-text-frame" > "$TMPDIR_E2E/d1.out" 2>&1; then
    case_pass "D1_text_echo"
else
    case_fail "D1_text_echo" "$(cat "$TMPDIR_E2E/d1.out" | head -c 300)"
fi

# --- D2: binary echo (small) ---
if ws_signed_probe /ws/bin --send-binary "deadbeef0123456789" > "$TMPDIR_E2E/d2.out" 2>&1; then
    case_pass "D2_binary_echo"
else
    case_fail "D2_binary_echo" "$(cat "$TMPDIR_E2E/d2.out" | head -c 300)"
fi

# --- D3: large frame (1 MiB) ---
if ws_signed_probe /ws/large --send-binary-size 1048576 > "$TMPDIR_E2E/d3.out" 2>&1; then
    case_pass "D3_large_frame_1mb"
else
    case_fail "D3_large_frame_1mb" "$(cat "$TMPDIR_E2E/d3.out" | head -c 300)"
fi

# --- D4: client-initiated close (expect close code 1000) ---
if ws_signed_probe /ws/close --expect-close-code 1000 > "$TMPDIR_E2E/d4.out" 2>&1; then
    case_pass "D4_client_close_propagated"
else
    case_fail "D4_client_close_propagated" "$(cat "$TMPDIR_E2E/d4.out" | head -c 300)"
fi

# --- D5: server-initiated close (the echo upstream closes after our close;
# the proxy must propagate). Combined with D4 in practice — same probe.
# We separate by sending a NORMAL close on a different path.
if ws_signed_probe /ws/close2 --expect-close-code 1001 > "$TMPDIR_E2E/d5.out" 2>&1; then
    case_pass "D5_close_code_alt"
else
    case_fail "D5_close_code_alt" "$(cat "$TMPDIR_E2E/d5.out" | head -c 300)"
fi

# --- D6: auth header injection on upgrade ---
# The /ws route has auth_type=header, auth_header_name=X-BB-API-Key,
# auth_key_name=bb_api_key → upstream upgrade should carry x-bb-api-key.
: > "$WS_LOG"
ws_signed_probe /ws/authcheck --send-text "ping" > "$TMPDIR_E2E/d6.out" 2>&1 || true
sleep 0.1
if grep -q '"x-bb-api-key":\s*"bb_test_KEY_AAAAAAAAAA"' "$WS_LOG"; then
    case_pass "D6_auth_header_injected_on_upgrade"
else
    case_fail "D6_auth_header_injected_on_upgrade" \
        "no x-bb-api-key in upgrade. WS_LOG tail: $(tail -1 "$WS_LOG" | head -c 400)"
fi

# --- D7: auth_query token injected on upgrade URL (Greptile #98 P1) ---
# The /wsq route uses auth_type=query, auth_query_name=token. The upstream
# should see ?token=<key> in the path of its upgrade request.
: > "$WS_LOG"
TS=$(now); SIG=$(sign "$TS" GET /wsq/echo "$S1")
python3 "$E2E_DIR/ws_probe.py" \
    --url "ws://127.0.0.1:$PROXY_PORT/wsq/echo" \
    --header "X-Sandbox-Signature: $SIG" \
    --send-text "q" > "$TMPDIR_E2E/d7.out" 2>&1 || true
sleep 0.1
if grep -qE '"path":\s*"/echo\?token=bb_test_KEY_AAAAAAAAAA' "$WS_LOG"; then
    case_pass "D7_auth_query_injected_on_upgrade_url"
else
    case_fail "D7_auth_query_injected_on_upgrade_url" \
        "auth_query NOT injected. WS_LOG tail: $(tail -1 "$WS_LOG" | head -c 400)"
fi

# --- D8a: subprotocol header forwarded TO upstream on upgrade ---
: > "$WS_LOG"
TS=$(now); SIG=$(sign "$TS" GET /ws/subproto "$S1")
python3 "$E2E_DIR/ws_probe.py" \
    --url "ws://127.0.0.1:$PROXY_PORT/ws/subproto" \
    --header "X-Sandbox-Signature: $SIG" \
    --subprotocol "chat,json" \
    --send-text "sub" > "$TMPDIR_E2E/d8.out" 2>&1
d8_rc=$?
sleep 0.1
if (( d8_rc == 0 )) && grep -q '"sec-websocket-protocol":\s*"chat' "$WS_LOG"; then
    case_pass "D8a_subprotocol_forwarded_to_upstream"
else
    case_fail "D8a_subprotocol_forwarded_to_upstream" \
        "rc=$d8_rc, WS_LOG tail: $(tail -1 "$WS_LOG" | head -c 300)"
fi

# --- D8b: subprotocol echoed back TO client (proxy must call
# WebSocketUpgrade::protocols on the inbound side; current impl uses bare
# WebSocketUpgrade::from_request so this FAILS until the proxy fix lands).
# Documenting this as a Known Issue surfaced by the harness.
if grep -q '"subprotocol_negotiated":\s*"chat"' "$TMPDIR_E2E/d8.out"; then
    case_pass "D8b_subprotocol_echoed_to_client"
else
    case_fail "D8b_subprotocol_echoed_to_client" \
        "client got no subprotocol back. probe: $(head -c 200 "$TMPDIR_E2E/d8.out")  (KNOWN: proxy doesn't yet call WebSocketUpgrade::protocols on the inbound side)"
fi

# --- D9: forward_websockets=false → upgrade rejected ---
# Try a WS upgrade against /wsoff and expect the connection to fail.
TS=$(now); SIG=$(sign "$TS" GET /wsoff/x "$S1")
if python3 "$E2E_DIR/ws_probe.py" \
    --url "ws://127.0.0.1:$PROXY_PORT/wsoff/x" \
    --header "X-Sandbox-Signature: $SIG" \
    --expect-no-connect > "$TMPDIR_E2E/d9.out" 2>&1; then
    case_pass "D9_forward_websockets_false_rejected"
else
    case_fail "D9_forward_websockets_false_rejected" "$(cat "$TMPDIR_E2E/d9.out" | head -c 300)"
fi

# --- D10: connect_timeout fails fast against blackhole upstream ---
# The /wsbh route has connect_timeout_seconds=2. The proxy completes the
# client-side 101 BEFORE trying upstream (see comment in handle_passthrough_ws),
# so the probe sees a successful upgrade. The proxy then attempts upstream,
# hits the 2s timeout, and CLOSES the WS connection. The property we want:
# the close arrives WITHIN ~3s of upgrade (timeout + small slack), proving
# the proxy isn't leaking a stuck task. We measure by sending a frame and
# observing the close.
TS=$(now); SIG=$(sign "$TS" GET /wsbh/x "$S1")
D10_START=$(date +%s%N)
python3 -c "
import asyncio, sys, time
import websockets

async def main():
    try:
        ws = await asyncio.wait_for(
            websockets.connect(
                'ws://127.0.0.1:$PROXY_PORT/wsbh/x',
                additional_headers=[('X-Sandbox-Signature', '$SIG')],
                open_timeout=5,
                close_timeout=5,
            ),
            timeout=5,
        )
    except Exception as e:
        # Connection refused or closed during handshake also counts as
        # fail-fast behaviour.
        print(f'OK_no_connect: {e}')
        return 0
    # Wait for the proxy to close us (blackhole upstream will trigger
    # the connect_timeout after 2s).
    try:
        msg = await asyncio.wait_for(ws.recv(), timeout=4)
        print(f'unexpected message: {msg!r}')
        return 1
    except websockets.exceptions.ConnectionClosed:
        print('OK_closed_by_proxy')
        return 0
    except asyncio.TimeoutError:
        print('FAIL_no_close_within_4s')
        return 1

sys.exit(asyncio.run(main()))
" > "$TMPDIR_E2E/d10.out" 2>&1
d10_rc=$?
D10_END=$(date +%s%N)
D10_ELAPSED_MS=$(( (D10_END - D10_START) / 1000000 ))
if (( d10_rc == 0 )) && (( D10_ELAPSED_MS <= 4500 )); then
    case_pass "D10_connect_timeout_fail_fast (${D10_ELAPSED_MS}ms ≤ 4500ms)"
else
    case_fail "D10_connect_timeout_fail_fast" \
        "rc=$d10_rc, elapsed=${D10_ELAPSED_MS}ms. out: $(head -c 300 "$TMPDIR_E2E/d10.out")"
fi

stop_proxy
