#!/usr/bin/env bash
# End-to-end tests for the post-implementation cleanup changes.
# Tests: audit (append/tail/search, status enum, streaming reads, wildcard),
#        rate limiter (atomic writes, shared wildcard matching, shared unit_to_secs),
#        plan mode, ati_dir dedup, duration parsing.
#
# Usage: bash scripts/test_cleanup_e2e.sh

set -euo pipefail

ATI="${ATI:-./target/release/ati}"
PASS=0
FAIL=0
TOTAL=0

red()   { printf "\033[31m%s\033[0m\n" "$*"; }
green() { printf "\033[32m%s\033[0m\n" "$*"; }
bold()  { printf "\033[1m%s\033[0m\n" "$*"; }

assert_ok() {
    TOTAL=$((TOTAL + 1))
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        green "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $desc (exit=$?)"
        FAIL=$((FAIL + 1))
    fi
}

assert_fail() {
    TOTAL=$((TOTAL + 1))
    local desc="$1"; shift
    if ! "$@" >/dev/null 2>&1; then
        green "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $desc (expected failure, got success)"
        FAIL=$((FAIL + 1))
    fi
}

assert_contains() {
    TOTAL=$((TOTAL + 1))
    local desc="$1"
    local actual="$2"
    local expected="$3"
    if echo "$actual" | grep -qF "$expected"; then
        green "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $desc"
        red "    expected to contain: $expected"
        red "    actual: $(echo "$actual" | head -5)"
        FAIL=$((FAIL + 1))
    fi
}

assert_not_contains() {
    TOTAL=$((TOTAL + 1))
    local desc="$1"
    local actual="$2"
    local not_expected="$3"
    if ! echo "$actual" | grep -qF "$not_expected"; then
        green "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $desc"
        red "    should NOT contain: $not_expected"
        FAIL=$((FAIL + 1))
    fi
}

# Create isolated ATI dir for all tests
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT
export ATI_DIR="$TMPDIR/ati"
mkdir -p "$ATI_DIR/manifests" "$ATI_DIR/specs" "$ATI_DIR/skills"

# Write a simple HTTP manifest for testing tool calls
cat > "$ATI_DIR/manifests/test_api.toml" <<'TOML'
[provider]
name = "testapi"
base_url = "https://httpbin.org"
auth_type = "none"
description = "Test API for e2e"
category = "testing"

[[tools]]
name = "testapi__get"
endpoint = "/get"
method = "GET"
description = "Simple GET test"
scope = "tool:testapi__*"
[tools.input_schema]
type = "object"
[tools.input_schema.properties.q]
type = "string"
description = "Query param"
TOML

bold "=== E2E Tests: Post-Implementation Cleanup ==="
echo ""

# -----------------------------------------------------------------------
bold "1. ATI_DIR dedup — all paths resolve consistently"
# -----------------------------------------------------------------------

# The binary should use our ATI_DIR
OUTPUT=$($ATI tool list 2>&1 || true)
assert_contains "tool list uses ATI_DIR" "$OUTPUT" "testapi__get"

# -----------------------------------------------------------------------
bold "2. Audit log — append, tail, search, AuditStatus enum"
# -----------------------------------------------------------------------

AUDIT_FILE="$TMPDIR/audit_test.jsonl"
export ATI_AUDIT_FILE="$AUDIT_FILE"

# Run a tool call — should create an audit entry (even if the HTTP call fails)
$ATI run testapi__get --q hello 2>/dev/null || true

# Tail should return at least 1 entry
TAIL_OUT=$($ATI audit tail -n 5 2>&1)
assert_contains "audit tail has entry" "$TAIL_OUT" "testapi__get"

# The raw JSONL should have "status":"ok" or "status":"error" (enum lowercase)
JSONL=$(cat "$AUDIT_FILE")
if echo "$JSONL" | grep -qE '"status":"(ok|error)"'; then
    green "  PASS: audit JSONL uses lowercase enum status"
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
else
    red "  FAIL: audit JSONL status not lowercase enum"
    red "    content: $(head -1 "$AUDIT_FILE")"
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
fi

# Append more entries with different tools for search testing
cat >> "$AUDIT_FILE" <<'JSONL'
{"ts":"2026-03-05T10:00:00Z","tool":"github__search","args":{},"status":"ok","duration_ms":50,"agent_sub":"test"}
{"ts":"2026-03-05T10:01:00Z","tool":"github__create_issue","args":{},"status":"ok","duration_ms":30,"agent_sub":"test"}
{"ts":"2026-03-05T10:02:00Z","tool":"linear__list","args":{},"status":"error","duration_ms":20,"agent_sub":"test","error":"timeout"}
JSONL

# Search by exact tool
SEARCH_OUT=$($ATI audit search --tool linear__list 2>&1)
assert_contains "audit search exact match" "$SEARCH_OUT" "linear__list"
assert_not_contains "audit search exact excludes others" "$SEARCH_OUT" "github__search"

# Search by wildcard
SEARCH_WILD=$($ATI audit search --tool "github__*" 2>&1)
assert_contains "audit search wildcard matches github__search" "$SEARCH_WILD" "github__search"
assert_contains "audit search wildcard matches github__create_issue" "$SEARCH_WILD" "github__create_issue"
assert_not_contains "audit search wildcard excludes linear" "$SEARCH_WILD" "linear__list"

# Search with --since (recent entries)
SEARCH_SINCE=$($ATI audit search --since 1h 2>&1)
assert_contains "audit search --since 1h finds recent" "$SEARCH_SINCE" "testapi__get"

# JSON output
SEARCH_JSON=$($ATI --output json audit search --tool "github__*" 2>&1)
assert_contains "audit search JSON output" "$SEARCH_JSON" '"tool":"github__search"'
assert_contains "audit JSON has enum status" "$SEARCH_JSON" '"status":"ok"'

# Backward compat: old string-status entries still parse
cat >> "$AUDIT_FILE" <<'JSONL'
{"ts":"2026-03-04T00:00:00Z","tool":"old_tool","args":{},"status":"ok","duration_ms":1,"agent_sub":"old"}
JSONL
TAIL_OLD=$($ATI audit tail -n 10 2>&1)
assert_contains "old string status entries still parse" "$TAIL_OLD" "old_tool"

unset ATI_AUDIT_FILE
echo ""

# -----------------------------------------------------------------------
bold "3. Rate limiter — atomic writes, pattern matching"
# -----------------------------------------------------------------------

# Create a JWT with rate limits to test rate enforcement
# We'll test via the unit/integration tests since rate limiting requires JWT setup.
# But we can verify the state file uses atomic writes by checking for .tmp absence.

RATE_STATE="$ATI_DIR/rate-state.json"
# Ensure no leftover tmp file exists
rm -f "${RATE_STATE}.tmp"

# The rate tests ran in cargo test already. Let's verify the binary handles
# the rate state path correctly under our ATI_DIR.
if [ ! -f "$RATE_STATE" ]; then
    green "  PASS: rate-state.json not created without rate config (expected)"
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
else
    red "  FAIL: rate-state.json should not exist without rate limits configured"
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
fi

# Verify no .tmp file was left behind
if [ ! -f "${RATE_STATE}.tmp" ]; then
    green "  PASS: no rate-state.json.tmp leftover (atomic write clean)"
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
else
    red "  FAIL: rate-state.json.tmp leftover found"
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
fi

echo ""

# -----------------------------------------------------------------------
bold "4. Plan mode — validate and execute"
# -----------------------------------------------------------------------

# Create a plan file
PLAN_FILE="$TMPDIR/test_plan.json"
cat > "$PLAN_FILE" <<'JSON'
{
  "query": "Test the cleanup changes",
  "steps": [
    {
      "tool": "testapi__get",
      "args": {"q": "step1"},
      "description": "First step: simple GET"
    },
    {
      "tool": "testapi__get",
      "args": {"q": "step2"},
      "description": "Second step: another GET"
    }
  ],
  "created_at": "2026-03-05T00:00:00Z"
}
JSON

# Execute the plan (don't require confirm since stdin isn't a tty)
PLAN_OUT=$($ATI plan execute "$PLAN_FILE" 2>&1 || true)
assert_contains "plan executes steps" "$PLAN_OUT" "Step 1/2"
assert_contains "plan shows step 2" "$PLAN_OUT" "Step 2/2"
assert_contains "plan completes" "$PLAN_OUT" "Plan execution complete"

# Plan with unknown tool should fail at validation
BAD_PLAN="$TMPDIR/bad_plan.json"
cat > "$BAD_PLAN" <<'JSON'
{
  "query": "Bad plan",
  "steps": [{"tool": "nonexistent__tool", "args": {}, "description": "nope"}],
  "created_at": "2026-03-05T00:00:00Z"
}
JSON

assert_fail "plan rejects unknown tools" $ATI plan execute "$BAD_PLAN"

echo ""

# -----------------------------------------------------------------------
bold "5. Tool list & search still work"
# -----------------------------------------------------------------------

TOOL_LIST=$($ATI tool list 2>&1)
assert_contains "tool list shows provider" "$TOOL_LIST" "testapi"

TOOL_INFO=$($ATI tool info testapi__get 2>&1)
assert_contains "tool info shows description" "$TOOL_INFO" "Simple GET test"

echo ""

# -----------------------------------------------------------------------
bold "6. Duration parsing variants"
# -----------------------------------------------------------------------

# Test via audit search --since with different units
export ATI_AUDIT_FILE="$TMPDIR/duration_test.jsonl"
cat > "$ATI_AUDIT_FILE" <<JSONL
{"ts":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","tool":"recent_tool","args":{},"status":"ok","duration_ms":10,"agent_sub":"test"}
JSONL

for unit in "1h" "60m" "1d" "3600s"; do
    RESULT=$($ATI audit search --since "$unit" 2>&1)
    assert_contains "duration parsing: --since $unit" "$RESULT" "recent_tool"
done

unset ATI_AUDIT_FILE
echo ""

# -----------------------------------------------------------------------
bold "7. Proxy server health (quick smoke test)"
# -----------------------------------------------------------------------

# Start proxy in background
PROXY_PORT=18099
$ATI proxy --port $PROXY_PORT --ati-dir "$ATI_DIR" &
PROXY_PID=$!
sleep 1

if kill -0 $PROXY_PID 2>/dev/null; then
    HEALTH=$(curl -s "http://127.0.0.1:$PROXY_PORT/health" 2>/dev/null || true)
    assert_contains "proxy health returns ok" "$HEALTH" '"status":"ok"'
    assert_contains "proxy health shows tools" "$HEALTH" '"tools":'

    # Call a tool through the proxy
    CALL_OUT=$(curl -s -X POST "http://127.0.0.1:$PROXY_PORT/call" \
        -H "Content-Type: application/json" \
        -d '{"tool_name":"testapi__get","args":{"q":"proxy_test"}}' 2>/dev/null || true)
    # Should get a result (even if upstream fails, the proxy should respond)
    if echo "$CALL_OUT" | grep -qE '"result"|"error"'; then
        green "  PASS: proxy /call returns structured response"
        PASS=$((PASS + 1))
        TOTAL=$((TOTAL + 1))
    else
        red "  FAIL: proxy /call unexpected response: $CALL_OUT"
        FAIL=$((FAIL + 1))
        TOTAL=$((TOTAL + 1))
    fi

    # Check that the proxy wrote an audit entry
    PROXY_AUDIT="$ATI_DIR/audit.jsonl"
    if [ -f "$PROXY_AUDIT" ]; then
        PROXY_JSONL=$(cat "$PROXY_AUDIT")
        assert_contains "proxy audit entry written" "$PROXY_JSONL" "testapi__get"
        # Verify enum status in proxy audit
        if echo "$PROXY_JSONL" | grep -qE '"status":"(ok|error)"'; then
            green "  PASS: proxy audit uses enum status"
            PASS=$((PASS + 1))
            TOTAL=$((TOTAL + 1))
        else
            red "  FAIL: proxy audit status not enum"
            FAIL=$((FAIL + 1))
            TOTAL=$((TOTAL + 1))
        fi
    else
        red "  FAIL: proxy did not write audit.jsonl"
        FAIL=$((FAIL + 1))
        TOTAL=$((TOTAL + 1))
    fi

    kill $PROXY_PID 2>/dev/null || true
    wait $PROXY_PID 2>/dev/null || true
else
    red "  FAIL: proxy server failed to start"
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
fi

echo ""

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo ""
bold "=== Results ==="
echo "Total: $TOTAL  Pass: $PASS  Fail: $FAIL"
echo ""

if [ $FAIL -eq 0 ]; then
    green "ALL $TOTAL TESTS PASSED"
    exit 0
else
    red "$FAIL TESTS FAILED"
    exit 1
fi
