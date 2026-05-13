# Group C — HTTP passthrough routing (PR #95 surface, exercised together
# with PR #96 sig-verify), 12+ cases.

group_header "Group C — HTTP passthrough routing (12 cases)"

S1="11111111111111111111111111111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# Spin a fresh mock if the orchestrator didn't already
if [[ -z "${MOCK_PIDS[*]:-}" ]]; then
    start_mock_http "$PORT_UPSTREAM_HTTP" echo
fi
# Also start the big-response upstream for C11. Use the orchestrator-
# exported port so preflight cleanup + EXIT-trap kill_port_owners cover it
# on re-run-after-abort (Greptile #99 P2).
BIG_PORT="${PORT_UPSTREAM_HTTP_BIG:-18922}"
start_mock_http "$BIG_PORT" big_response --big-size 1048576

# Install ALL the C-relevant manifests on a single proxy boot
install_manifests passthrough auth deny replace no_strip host_match

# Add an extra route pointing at the big-response upstream on a known prefix.
cat > "$ATI_DIR/manifests/passthrough_big.toml" <<EOF
[provider]
name = "passthrough_big"
description = "E2E: big response capped"
handler = "passthrough"
base_url = "http://127.0.0.1:$BIG_PORT"
path_prefix = "/big"
strip_prefix = true
auth_type = "none"
max_response_bytes = 524288
EOF

bootstrap_keyring "$E2E_DIR/fixtures/op_bootstrap.json"
start_proxy --mode enforce

mksig() { sign "$(now)" "$1" "$2" "$S1"; }

# Reset the mock log so we can scan a clean slate
: > "$MOCK_LOG"

# --- C1: host_match dispatch ---
TS=$(now); SIG=$(sign "$TS" GET /anything "$S1")
assert_status_and_header C1_host_match 200 X-Mock-Upstream echo \
    -H "X-Sandbox-Signature: $SIG" \
    -H "Host: bb.localhost" \
    "http://127.0.0.1:$PROXY_PORT/anything"

# Inspect the mock log: upstream Host header should be "upstream.test"
# because host_override is set on that manifest.
sleep 0.05
if grep -q '"host":\s*"upstream.test"' "$MOCK_LOG"; then
    case_pass "C1_host_override_seen_by_upstream"
else
    case_fail "C1_host_override_seen_by_upstream" "no upstream record with host=upstream.test. tail: $(tail -1 "$MOCK_LOG" 2>/dev/null | head -c 200)"
fi

# --- C2: path_prefix strip ---
TS=$(now); SIG=$(sign "$TS" GET /api/v1/foo "$S1")
status=$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "X-Sandbox-Signature: $SIG" \
    "http://127.0.0.1:$PROXY_PORT/api/v1/foo")
# Verify in mock log the upstream saw stripped path /v1/foo (not /api/v1/foo)
sleep 0.05
if [[ "$status" == "200" ]] && grep -q '"path":\s*"/v1/foo"' "$MOCK_LOG"; then
    case_pass "C2_path_prefix_strip"
else
    case_fail "C2_path_prefix_strip" "status=$status; mock log tail: $(tail -1 "$MOCK_LOG" | head -c 200)"
fi

# --- C3: strip_prefix=false (devpi pattern) ---
: > "$MOCK_LOG"
TS=$(now); SIG=$(sign "$TS" GET /root/pypi/+simple/foo "$S1")
status=$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "X-Sandbox-Signature: $SIG" \
    "http://127.0.0.1:$PROXY_PORT/root/pypi/+simple/foo")
sleep 0.05
if [[ "$status" == "200" ]] && grep -q '"path":\s*"/root/pypi/+simple/foo"' "$MOCK_LOG"; then
    case_pass "C3_strip_prefix_false"
else
    case_fail "C3_strip_prefix_false" "status=$status; tail: $(tail -1 "$MOCK_LOG" | head -c 200)"
fi

# --- C4: path_replace /otel → /otlp ---
: > "$MOCK_LOG"
TS=$(now); SIG=$(sign "$TS" POST /otel/v1/traces "$S1")
status=$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/otel/v1/traces" -d '{}')
sleep 0.05
if [[ "$status" == "200" ]] && grep -q '"path":\s*"/otlp/v1/traces"' "$MOCK_LOG"; then
    case_pass "C4_path_replace_otel_otlp"
else
    case_fail "C4_path_replace_otel_otlp" "status=$status; tail: $(tail -1 "$MOCK_LOG" | head -c 200)"
fi

# --- C5: deny_paths 403 without upstream hit ---
: > "$MOCK_LOG"
TS=$(now); SIG=$(sign "$TS" GET /litellm/config/get "$S1")
assert_status C5_deny_paths_blocks 403 \
    -H "X-Sandbox-Signature: $SIG" \
    "http://127.0.0.1:$PROXY_PORT/litellm/config/get"
# Critically: upstream must NOT have been hit.
sleep 0.05
if [[ ! -s "$MOCK_LOG" ]] || ! grep -q '"path":\s*"/config/get"' "$MOCK_LOG"; then
    case_pass "C5_deny_paths_no_upstream_hit"
else
    case_fail "C5_deny_paths_no_upstream_hit" "upstream WAS called: $(cat "$MOCK_LOG" | head -c 200)"
fi

# --- C6: bearer auth injection ---
: > "$MOCK_LOG"
TS=$(now); SIG=$(sign "$TS" POST /secure/x "$S1")
assert_status_and_header C6_auth_injection 200 X-Mock-Upstream echo \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/secure/x" -d '{}'
sleep 0.05
# Upstream should have seen Authorization: Bearer sk-test-bootstrap-token
if grep -q '"authorization":\s*"Bearer sk-test-bootstrap-token"' "$MOCK_LOG"; then
    case_pass "C6_auth_header_seen_by_upstream"
else
    case_fail "C6_auth_header_seen_by_upstream" "no upstream auth header. tail: $(tail -1 "$MOCK_LOG" | head -c 300)"
fi

# --- C7: hop-by-hop headers from the proxy's HOP_BY_HOP list are stripped.
# The proxy's list (src/core/passthrough.rs:430) is:
#   connection, keep-alive, proxy-authenticate, proxy-authorization,
#   te, trailers, transfer-encoding, upgrade
# Note: the list has "trailers" (plural) — RFC 7230 §6.1 spells it
# "Trailer" (singular). That mismatch is itself a finding worth surfacing
# as C7b below.
: > "$MOCK_LOG"
TS=$(now); SIG=$(sign "$TS" GET /api/h "$S1")
assert_status C7_hop_by_hop_request 200 \
    -H "X-Sandbox-Signature: $SIG" \
    -H "Keep-Alive: timeout=5" \
    -H "TE: trailers" \
    -H "Proxy-Authorization: Bearer probe" \
    "http://127.0.0.1:$PROXY_PORT/api/h"
sleep 0.05
hop_leaked=""
for h in keep-alive te proxy-authorization; do
    if grep -q "\"$h\":" "$MOCK_LOG"; then hop_leaked="$h $hop_leaked"; fi
done
if [[ -z "$hop_leaked" ]]; then
    case_pass "C7a_hop_by_hop_in_list_stripped"
else
    case_fail "C7a_hop_by_hop_in_list_stripped" "leaked: $hop_leaked. tail: $(tail -1 "$MOCK_LOG" | head -c 400)"
fi

# --- C7b: regression-tracker for the "Trailer" vs "trailers" typo and the
# unsupported Connection-named-hop mechanism. These two are KNOWN bugs the
# harness surfaces — when the proxy fix lands, C7b will start passing.
: > "$MOCK_LOG"
TS=$(now); SIG=$(sign "$TS" GET /api/h2 "$S1")
curl -sS -o /dev/null \
    -H "X-Sandbox-Signature: $SIG" \
    -H "Connection: keep-alive, X-Custom-Hop" \
    -H "X-Custom-Hop: should-be-stripped" \
    -H "Trailer: x-foo" \
    "http://127.0.0.1:$PROXY_PORT/api/h2" || true
sleep 0.05
spec_leaked=""
# RFC 7230 §6.1: "Trailer" (singular) is hop-by-hop, AND any header named
# in Connection: should also be stripped before forwarding.
if grep -q '"trailer":' "$MOCK_LOG"; then spec_leaked="trailer "; fi
if grep -q '"x-custom-hop":' "$MOCK_LOG"; then spec_leaked="${spec_leaked}x-custom-hop"; fi
if [[ -z "$spec_leaked" ]]; then
    case_pass "C7b_rfc7230_hop_by_hop_stripping_complete"
else
    case_fail "C7b_rfc7230_hop_by_hop_stripping_complete" \
        "(KNOWN finding) leaked: $spec_leaked — proxy HOP_BY_HOP list spells \"trailers\" not \"trailer\", and doesn't honour Connection-named hops"
fi

# --- C8: x-sandbox-* stripped ---
: > "$MOCK_LOG"
TS=$(now); SIG=$(sign "$TS" GET /api/s "$S1")
curl -sS -o /dev/null \
    -H "X-Sandbox-Signature: $SIG" \
    -H "X-Sandbox-Job-Id: e2e-job-1" \
    -H "X-Sandbox-Trace-Id: tr-abc" \
    "http://127.0.0.1:$PROXY_PORT/api/s" || true
sleep 0.05
if ! grep -qE '"x-sandbox-(signature|job-id|trace-id)":' "$MOCK_LOG"; then
    case_pass "C8_x_sandbox_stripped_from_upstream"
else
    case_fail "C8_x_sandbox_stripped_from_upstream" "x-sandbox-* leaked. tail: $(tail -1 "$MOCK_LOG" | head -c 300)"
fi

# --- C9: caller Authorization stripped before injection ---
# Route /secure has auth_key_name=upstream_bearer → token "sk-test-bootstrap-token".
# Caller passes a different bearer; upstream must see the INJECTED one only.
: > "$MOCK_LOG"
TS=$(now); SIG=$(sign "$TS" POST /secure/x "$S1")
curl -sS -o /dev/null \
    -H "X-Sandbox-Signature: $SIG" \
    -H "Authorization: Bearer caller-supplied-FAKE" \
    -X POST "http://127.0.0.1:$PROXY_PORT/secure/x" -d '{}' || true
sleep 0.05
if grep -q '"authorization":\s*"Bearer sk-test-bootstrap-token"' "$MOCK_LOG" \
   && ! grep -q "caller-supplied-FAKE" "$MOCK_LOG"; then
    case_pass "C9_caller_auth_replaced_by_injected"
else
    case_fail "C9_caller_auth_replaced_by_injected" "tail: $(tail -1 "$MOCK_LOG" | head -c 300)"
fi

# --- C10: max_request_bytes (1 MiB cap) → 413 ---
# Build a 2 MiB body
BIG_BODY="$TMPDIR_E2E/big-2mb.bin"
head -c $((2 * 1024 * 1024)) /dev/zero > "$BIG_BODY"
TS=$(now); SIG=$(sign "$TS" POST /api/big "$S1")
assert_status C10_max_request_bytes_413 413 \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/big" \
    --data-binary @"$BIG_BODY"

# --- C11: max_response_bytes (512 KiB cap) cuts upstream's 1 MiB response ---
TS=$(now); SIG=$(sign "$TS" GET /big/blob "$S1")
recv_bytes=$(curl -sS -o /tmp/c11-resp.bin -w '%{size_download}' \
    -H "X-Sandbox-Signature: $SIG" \
    "http://127.0.0.1:$PROXY_PORT/big/blob")
# Must NOT receive the full 1 MiB (1048576). Allow some slack — cap is 512 KiB
# but the chunk boundary may overshoot by one chunk (4096). Anything under
# the full 1 MiB proves the cap fired.
if (( recv_bytes < 1048576 )); then
    case_pass "C11_max_response_bytes_streamcut (received $recv_bytes / cap 524288)"
else
    case_fail "C11_max_response_bytes_streamcut" "received $recv_bytes (no cap fired)"
fi
rm -f /tmp/c11-resp.bin

# --- C12: named-route precedence over passthrough fallback ---
# /health is a named route AND is exempt from sig-verify. Even with all the
# passthrough manifests installed, GET /health must return 200 from the
# proxy's own handler (which returns JSON), NOT 404 from the fallback.
status=$(curl -sS -o /tmp/c12-body -w '%{http_code}' "http://127.0.0.1:$PROXY_PORT/health")
if [[ "$status" == "200" ]] && grep -q -E 'ok|healthy|status' /tmp/c12-body; then
    case_pass "C12_named_route_precedence_health"
else
    case_fail "C12_named_route_precedence_health" "status=$status body=$(head -c 200 /tmp/c12-body)"
fi
rm -f /tmp/c12-body

stop_proxy
