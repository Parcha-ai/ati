# Group B — SIGHUP rotation safety (PR #96 + #97 boundary), 4 cases.
#
# B1: rotate keyring to S2 + SIGHUP, signed-S2 → 200
# B2: signed-S1 after rotation → 403 (old secret revoked)
# B3: corrupt keyring + SIGHUP → previous in-memory secret preserved (#96 P1)
# B4: 50 concurrent in-flight requests during SIGHUP — all must complete 200
#     (torn-read regression guard — the property is that secret resolution
#     happens at request-start, not at upstream response)

group_header "Group B — SIGHUP rotation (4 cases)"

S1="11111111111111111111111111111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
S2="22222222222222222222222222222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

# Need both the regular HTTP echo mock AND the slow mock (B4)
if [[ -z "${MOCK_PIDS[*]:-}" ]]; then
    start_mock_http "$PORT_UPSTREAM_HTTP" echo
fi
start_mock_http "$PORT_UPSTREAM_HTTP_SLOW" slow

install_manifests passthrough slow
bootstrap_keyring "$E2E_DIR/fixtures/op_bootstrap.json"

start_proxy --mode enforce

# B-pre: confirm S1 is valid at start
TS=$(now); SIG=$(sign "$TS" POST /api/x "$S1")
assert_status B0_pre_rotation_s1_valid 200 \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# Rotate keyring on-disk to S2 via the REAL ati edge rotate-keyring command,
# then deliver SIGHUP from bash (--no-signal in rotate-keyring so we control
# timing explicitly).
rotate_keyring "$E2E_DIR/fixtures/op_rotated.json"
kill -HUP "$ATI_PID"
sleep 0.3

# B1: signed-S2 → 200
TS=$(now); SIG=$(sign "$TS" POST /api/x "$S2")
assert_status B1_post_rotation_s2_valid 200 \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# B2: signed-S1 → 403 (old secret no longer accepted)
TS=$(now); SIG=$(sign "$TS" POST /api/x "$S1")
assert_status_and_body B2_post_rotation_s1_revoked 403 hmac_mismatch \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# B3: corrupt keyring + SIGHUP → previous in-memory secret (S2) preserved.
# Writes garbage to keyring.enc, sends SIGHUP, validates that a signed-S2
# request STILL succeeds. This is the Greptile #96 P1 fix: a transient I/O
# error in reload mustn't wipe the secret.
KEYRING_BACKUP="$TMPDIR_E2E/keyring.enc.backup-b3"
cp "$ATI_DIR/keyring.enc" "$KEYRING_BACKUP"
printf '\x00\xff\xee\xdd' > "$ATI_DIR/keyring.enc"
kill -HUP "$ATI_PID"
sleep 0.3

TS=$(now); SIG=$(sign "$TS" POST /api/x "$S2")
assert_status B3_corrupt_sighup_preserves_secret 200 \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# Restore the keyring (so subsequent groups see a sane state)
cp "$KEYRING_BACKUP" "$ATI_DIR/keyring.enc"
kill -HUP "$ATI_PID"
sleep 0.3

# B4: 50 concurrent in-flight requests using S2 against the SLOW upstream
# (handler sleeps 1.5s). Rotate to S1 + SIGHUP MID-FLIGHT. All 50 must
# return 200 — i.e. their secret resolved at REQUEST-START, not at upstream
# response time. If any request 403s, sig-verify is re-reading the secret
# after the upstream reply and the in-flight requests get torn.
INFLIGHT_DIR="$TMPDIR_E2E/inflight"
mkdir -p "$INFLIGHT_DIR"
rm -f "$INFLIGHT_DIR"/*

TS=$(now); SIG=$(sign "$TS" POST /slow/x "$S2")

# Fire 50 concurrent requests in the background. Each writes its status code
# to a per-request file. Wall-clock budget is ~3s (1.5s upstream sleep + RTT).
INFLIGHT_PIDS=()
for i in $(seq 1 50); do
    (curl -sS -o /dev/null -w '%{http_code}\n' -m 6 \
        -H "X-Sandbox-Signature: $SIG" \
        -X POST "http://127.0.0.1:$PROXY_PORT/slow/x" -d '{}' \
        > "$INFLIGHT_DIR/$i.code") &
    INFLIGHT_PIDS+=("$!")
done
INFLIGHT_KICKED_AT=$(date +%s)

# Mid-flight: at +0.5s rotate to S1 + SIGHUP.
sleep 0.5
rotate_keyring "$E2E_DIR/fixtures/op_bootstrap.json"
kill -HUP "$ATI_PID"

# Wait for ONLY the curl backgrounds — `wait` with no args would also wait
# on long-lived child processes (mock servers, proxy) and hang forever.
for p in "${INFLIGHT_PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
INFLIGHT_DONE_AT=$(date +%s)

ok_count=$(grep -l '^200$' "$INFLIGHT_DIR"/*.code 2>/dev/null | wc -l)
total=$(ls "$INFLIGHT_DIR"/*.code 2>/dev/null | wc -l)
elapsed=$((INFLIGHT_DONE_AT - INFLIGHT_KICKED_AT))

if (( ok_count == 50 && total == 50 )); then
    case_pass "B4_inflight_sighup_50_concurrent (${ok_count}/${total} succeeded, wall ${elapsed}s)"
else
    dist=$(cat "$INFLIGHT_DIR"/*.code 2>/dev/null | sort | uniq -c | tr '\n' ' ')
    case_fail B4_inflight_sighup_50_concurrent "only ${ok_count}/${total} returned 200 — torn read? dist: $dist"
fi

# Post-B4 sanity: a fresh signed-S1 request must succeed (S1 is now active).
TS=$(now); SIG=$(sign "$TS" POST /api/x "$S1")
assert_status B5_post_inflight_s1_active 200 \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

stop_proxy
