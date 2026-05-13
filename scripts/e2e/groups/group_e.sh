# Group E — `ati edge` CLI (PR #97), 5 cases.
#
# Validates bootstrap-keyring + rotate-keyring against a fake `op` binary
# (wired via --op-path; the CLI already supports that flag for testing).

group_header "Group E — ati edge CLI (5 cases)"

# E uses an isolated ATI dir per case so we can probe failure modes
# without contaminating the orchestrator's main keyring.
E_ATI_DIR="$TMPDIR_E2E/edge-test"
mkdir -p "$E_ATI_DIR/manifests"

# --- E1: bootstrap with fake op writes a valid keyring.enc ---
FAKE_OP_FIXTURE="$E2E_DIR/fixtures/op_bootstrap.json" \
"$ATI_BIN" edge bootstrap-keyring \
    --vault e2e --item canned \
    --ati-dir "$E_ATI_DIR" \
    --op-path "$E2E_DIR/fake_op.sh" >"$TMPDIR_E2E/e1.out" 2>&1
e1_rc=$?
if (( e1_rc == 0 )) && [[ -s "$E_ATI_DIR/keyring.enc" ]] && [[ -s "$E_ATI_DIR/.keyring-key" ]]; then
    case_pass "E1_bootstrap_writes_keyring (size=$(stat -c%s "$E_ATI_DIR/keyring.enc"))"
else
    case_fail "E1_bootstrap_writes_keyring" "rc=$e1_rc out=$(head -c 200 "$TMPDIR_E2E/e1.out")"
fi

# --- E2: rotate-keyring atomic-rename + --no-signal ---
# Capture the pre-rotation keyring fingerprint, rotate, capture post.
PRE_HASH=$(sha256sum "$E_ATI_DIR/keyring.enc" | awk '{print $1}')
FAKE_OP_FIXTURE="$E2E_DIR/fixtures/op_rotated.json" \
"$ATI_BIN" edge rotate-keyring \
    --vault e2e --item canned \
    --ati-dir "$E_ATI_DIR" \
    --op-path "$E2E_DIR/fake_op.sh" \
    --no-signal >"$TMPDIR_E2E/e2.out" 2>&1
e2_rc=$?
POST_HASH=$(sha256sum "$E_ATI_DIR/keyring.enc" | awk '{print $1}')
if (( e2_rc == 0 )) && [[ "$PRE_HASH" != "$POST_HASH" ]]; then
    case_pass "E2_rotate_atomic_rename (hash changed)"
else
    case_fail "E2_rotate_atomic_rename" "rc=$e2_rc, pre=$PRE_HASH, post=$POST_HASH, out=$(head -c 200 "$TMPDIR_E2E/e2.out")"
fi

# --- E3: --op-token-file passes VALUE not PATH (Greptile #97 P1 guard) ---
# Write a token file whose content is a recognizable sentinel. The fake_op
# binary echoes its received OP_SERVICE_ACCOUNT_TOKEN env var into a sink
# file; we then assert the sink contains the VALUE, not the path.
TOKEN_FILE="$TMPDIR_E2E/op-token-file"
echo -n 'sentinel-token-value-XYZ' > "$TOKEN_FILE"
TOKEN_SINK="$TMPDIR_E2E/op-token-sink"
rm -f "$TOKEN_SINK"
FAKE_OP_FIXTURE="$E2E_DIR/fixtures/op_bootstrap.json" \
FAKE_OP_TOKEN_SINK="$TOKEN_SINK" \
"$ATI_BIN" edge bootstrap-keyring \
    --vault e2e --item canned \
    --ati-dir "$E_ATI_DIR" \
    --op-path "$E2E_DIR/fake_op.sh" \
    --op-token-file "$TOKEN_FILE" >"$TMPDIR_E2E/e3.out" 2>&1
e3_rc=$?
sink_content="$(cat "$TOKEN_SINK" 2>/dev/null || echo MISSING)"
if (( e3_rc == 0 )) && [[ "$sink_content" == "sentinel-token-value-XYZ" ]]; then
    case_pass "E3_op_token_file_passes_VALUE_not_path"
else
    # Mis-implementation would put TOKEN_FILE's PATH in OP_SERVICE_ACCOUNT_TOKEN
    # (the Greptile P1 bug).
    case_fail "E3_op_token_file_passes_VALUE_not_path" \
        "rc=$e3_rc, sink=[$sink_content] (expected sentinel-token-value-XYZ; if you see a /tmp/... path that's the P1 regression)"
fi

# --- E4: op returns nonzero → old keyring untouched ---
PRE_HASH=$(sha256sum "$E_ATI_DIR/keyring.enc" | awk '{print $1}')
FAKE_OP_FIXTURE="__fail__" \
"$ATI_BIN" edge rotate-keyring \
    --vault e2e --item canned \
    --ati-dir "$E_ATI_DIR" \
    --op-path "$E2E_DIR/fake_op.sh" \
    --no-signal >"$TMPDIR_E2E/e4.out" 2>&1
e4_rc=$?
POST_HASH=$(sha256sum "$E_ATI_DIR/keyring.enc" | awk '{print $1}')
if (( e4_rc != 0 )) && [[ "$PRE_HASH" == "$POST_HASH" ]]; then
    case_pass "E4_rotate_op_fail_old_keyring_intact"
else
    case_fail "E4_rotate_op_fail_old_keyring_intact" \
        "rc=$e4_rc (expected nonzero), pre=$PRE_HASH, post=$POST_HASH"
fi

# --- E5: missing target dir → clean error (no half-state) ---
GHOST_DIR="$TMPDIR_E2E/does-not-exist-$$"
FAKE_OP_FIXTURE="$E2E_DIR/fixtures/op_bootstrap.json" \
"$ATI_BIN" edge rotate-keyring \
    --vault e2e --item canned \
    --ati-dir "$GHOST_DIR" \
    --op-path "$E2E_DIR/fake_op.sh" \
    --no-signal >"$TMPDIR_E2E/e5.out" 2>&1
e5_rc=$?
if (( e5_rc != 0 )) && [[ ! -d "$GHOST_DIR" ]]; then
    case_pass "E5_rotate_missing_dir_clean_error"
else
    case_fail "E5_rotate_missing_dir_clean_error" \
        "rc=$e5_rc, dir_exists=$([[ -d "$GHOST_DIR" ]] && echo yes || echo no), stderr=$(head -c 200 "$TMPDIR_E2E/e5.out")"
fi
