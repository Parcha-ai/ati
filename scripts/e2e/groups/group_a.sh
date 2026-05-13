# Group A — sig-verify middleware (PR #96), 18 cases.
#
# Each mode (log / warn / enforce) is exercised with the same input matrix,
# differing only by expected outcome:
#   - log   → always passes (200), logs reason
#   - warn  → always passes (200), inserts X-Signature-Status: <reason>
#   - enforce → invalid → 403 with reason in body; valid → 200
#
# A separate run validates the "no secret configured" + "hex/utf8 secret"
# branches by bootstrapping a different keyring fixture.
#
# Expects (set by orchestrator): ATI_BIN, ATI_DIR, PROXY_PORT, PORT_UPSTREAM_HTTP,
# TMPDIR_E2E, E2E_DIR. Sources lib.sh through the orchestrator.

group_header "Group A — sig-verify (18 cases)"

# Mocks: one HTTP echo upstream
start_mock_http "$PORT_UPSTREAM_HTTP" echo

# Manifest: simple /api/* passthrough
install_manifests passthrough

# --- A common: bootstrap keyring with S1 ---
S1="11111111111111111111111111111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bootstrap_keyring "$E2E_DIR/fixtures/op_bootstrap.json"

#############################################################################
# Sub-group A1-A6 — LOG mode
#############################################################################

start_proxy --mode log

# A1: log, no signature → 200, log has missing_signature
assert_status A1_log_no_signature 200 \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'
sleep 0.1
assert_file_contains A1_log_no_signature_log "$ATI_LOG" "missing_signature"

# A2: log, valid sig → 200, log line has "reason":"valid" (JSON tracing format)
TS=$(now); SIG=$(sign "$TS" POST /api/x "$S1")
assert_status A2_log_valid 200 \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'
sleep 0.1
assert_file_contains A2_log_valid_log "$ATI_LOG" '"reason":"valid"'

# A3: log, wrong-secret sig → 200 (log mode permits) + log has hmac_mismatch
TS=$(now); SIG=$(sign "$TS" POST /api/x "wrongwrongwrongwrongwrongwrongwr")
assert_status A3_log_wrong_secret 200 \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'
sleep 0.1
assert_file_contains A3_log_wrong_secret_log "$ATI_LOG" "hmac_mismatch"

stop_proxy

#############################################################################
# Sub-group A4-A6 — WARN mode (validates Greptile #96 P2 fix:
# warn passes traffic through AND inserts X-Signature-Status header)
#############################################################################

start_proxy --mode warn

# A4: warn, no signature → 200, X-Signature-Status: missing_signature
assert_status_and_header A4_warn_no_sig 200 X-Signature-Status missing_signature \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# A5: warn, valid sig → 200, X-Signature-Status: valid
TS=$(now); SIG=$(sign "$TS" POST /api/x "$S1")
assert_status_and_header A5_warn_valid 200 X-Signature-Status valid \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# A6: warn, expired (TS - drift - 1) → 200, status header has expired_timestamp_drift
TS=$(( $(now) - 120 )); SIG=$(sign "$TS" POST /api/x "$S1")
assert_status_and_header A6_warn_expired 200 X-Signature-Status expired_timestamp_drift \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

stop_proxy

#############################################################################
# Sub-group A7-A15 — ENFORCE mode
#############################################################################

start_proxy --mode enforce

# A7: enforce, no signature → 403 body=missing_signature
assert_status_and_body A7_enforce_no_sig 403 missing_signature \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# A8: enforce, valid sig → 200 from upstream echo
TS=$(now); SIG=$(sign "$TS" POST /api/x "$S1")
assert_status_and_header A8_enforce_valid 200 X-Mock-Upstream echo \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# A9: enforce, expired ts → 403, body has expired_timestamp_drift
TS=$(( $(now) - 200 )); SIG=$(sign "$TS" POST /api/x "$S1")
assert_status_and_body A9_enforce_expired 403 expired_timestamp_drift \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# A10: enforce, future ts → 403 (still expired, just other direction)
TS=$(( $(now) + 200 )); SIG=$(sign "$TS" POST /api/x "$S1")
assert_status_and_body A10_enforce_future 403 expired_timestamp_drift \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# A11: sign for GET, send POST → 403 hmac_mismatch
TS=$(now); SIG=$(sign "$TS" GET /api/x "$S1")
assert_status_and_body A11_enforce_method_tamper 403 hmac_mismatch \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# A12: sign for /api/a, send /api/b → 403 hmac_mismatch
TS=$(now); SIG=$(sign "$TS" POST /api/a "$S1")
assert_status_and_body A12_enforce_path_tamper 403 hmac_mismatch \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/b" -d '{}'

# A13: malformed signature → 403, body has malformed_signature
assert_status_and_body A13_enforce_malformed 403 malformed_signature \
    -H "X-Sandbox-Signature: not-a-valid-shape" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# A14: exempt path /health with no signature → 200
assert_status A14_enforce_exempt_health 200 "http://127.0.0.1:$PROXY_PORT/health"

# A15: exempt glob /otel/v1/traces with no signature → falls through to
# passthrough/named-route logic. Since we have no /otel route installed,
# this should NOT be a 403 (sig-verify bypassed it). We accept 404 (fallback
# match failure) as proof the sig-verify exemption fired.
status=$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PROXY_PORT/otel/v1/traces")
if [[ "$status" != "403" ]]; then
    case_pass "A15_enforce_exempt_otel (status=$status, sig-verify exempted as expected)"
else
    case_fail "A15_enforce_exempt_otel" "expected non-403 (sig-verify exempt); got 403"
fi

stop_proxy

#############################################################################
# Sub-group A16 — ENFORCE with NO secret in keyring: proxy MUST fail to start
# (fail-closed at boot, per src/main.rs preflight). This is an explicit
# operational safety property: an operator can't accidentally run enforce
# mode without a configured secret.
#############################################################################

bootstrap_keyring "$E2E_DIR/fixtures/op_no_secret.json"
# Don't use start_proxy (which expects readiness). Spawn directly and assert
# the process exits non-zero within 2 seconds.
A16_LOG="$TMPDIR_E2E/ati-a16.log"
"$ATI_BIN" proxy \
    --port "$PROXY_PORT" --bind 127.0.0.1 \
    --ati-dir "$ATI_DIR" \
    --enable-passthrough --sig-verify-mode enforce \
    >"$A16_LOG" 2>&1 &
A16_PID=$!
# Give the process up to 2s to fail-closed and exit.
for _ in $(seq 1 20); do
    if ! kill -0 "$A16_PID" 2>/dev/null; then break; fi
    sleep 0.1
done
if kill -0 "$A16_PID" 2>/dev/null; then
    case_fail A16_enforce_no_secret "proxy did NOT fail-closed; still running"
    kill "$A16_PID" 2>/dev/null || true
    wait "$A16_PID" 2>/dev/null || true
else
    wait "$A16_PID" 2>/dev/null
    a16_rc=$?
    if (( a16_rc != 0 )); then
        case_pass "A16_enforce_no_secret (proxy exited $a16_rc, fail-closed)"
    else
        case_fail A16_enforce_no_secret "proxy exited 0 instead of failing closed"
    fi
fi
assert_file_contains A16_enforce_no_secret_log "$A16_LOG" "sandbox_signing_shared_secret"

#############################################################################
# Sub-group A17-A18 — hex vs utf8 secret fallback
#############################################################################

# The bootstrap fixture uses a 64-char hex secret. A18 covers UTF-8 fallback
# by writing a fixture where the secret is plain ASCII (not hex-shaped).

cat > "$TMPDIR_E2E/op_utf8.json" <<'EOF'
{
  "fields": [
    { "label": "sandbox_signing_shared_secret", "value": "plain-utf8-secret-NOT-hex!" }
  ]
}
EOF
bootstrap_keyring "$TMPDIR_E2E/op_utf8.json"
start_proxy --mode enforce

# A17 / A18 — Rust uses hex-then-utf8 fallback. Python sign.py does the same.
# Both halves prove that the proxy and the signer agree on secret-classification.
S_UTF8="plain-utf8-secret-NOT-hex!"
TS=$(now); SIG=$(sign "$TS" POST /api/x "$S_UTF8")
assert_status A17_enforce_utf8_secret_valid 200 \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# A18: same secret but use a deliberately-wrong key — confirms classification
# wasn't an accident (i.e. both sides DID treat it as utf-8 bytes, not as hex).
TS=$(now); SIG=$(sign "$TS" POST /api/x "different-secret-here")
assert_status_and_body A18_enforce_utf8_wrong_secret 403 hmac_mismatch \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

stop_proxy

# Restore bootstrap keyring for any group that runs after us in the chain.
bootstrap_keyring "$E2E_DIR/fixtures/op_bootstrap.json"
