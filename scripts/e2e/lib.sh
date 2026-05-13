# shellcheck shell=bash
# Shared helpers for the full-stack E2E harness.
#
# Sourced by scripts/test_full_stack_e2e.sh AND by every scripts/e2e/groups/*.sh.
# All assertions push results to GLOBAL counters and arrays so the orchestrator
# can print a final summary and exit non-zero on any failure.

set -u

# ---------- output / counters ----------------------------------------------

E2E_PASS=0
E2E_FAIL=0
E2E_FAILED_CASES=()

color_red()   { printf '\033[31m%s\033[0m' "$*"; }
color_green() { printf '\033[32m%s\033[0m' "$*"; }
color_yellow(){ printf '\033[33m%s\033[0m' "$*"; }
color_dim()   { printf '\033[2m%s\033[0m' "$*"; }

case_pass() {
    E2E_PASS=$((E2E_PASS + 1))
    printf '  %s  %s\n' "$(color_green PASS)" "$1"
}
case_fail() {
    E2E_FAIL=$((E2E_FAIL + 1))
    E2E_FAILED_CASES+=("$1")
    printf '  %s  %s\n    %s\n' "$(color_red FAIL)" "$1" "${2:-}"
}
group_header() {
    printf '\n%s %s\n' "$(color_yellow '==')" "$*"
}

# ---------- assertions -----------------------------------------------------

# assert_status CASE_ID EXPECTED_CODE CURL_ARGS...
# Runs curl, captures status code, asserts. On failure dumps response body.
assert_status() {
    local case_id="$1"; shift
    local expected="$1"; shift
    local body_file status
    body_file=$(mktemp)
    status=$(curl -sS -o "$body_file" -w '%{http_code}' "$@" || echo "000")
    if [[ "$status" == "$expected" ]]; then
        case_pass "$case_id (HTTP $status)"
    else
        case_fail "$case_id" "expected $expected, got $status. body: $(head -c 200 "$body_file")"
    fi
    rm -f "$body_file"
}

# assert_status_and_body CASE_ID EXPECTED_CODE BODY_SUBSTRING CURL_ARGS...
assert_status_and_body() {
    local case_id="$1"; shift
    local expected="$1"; shift
    local needle="$1"; shift
    local body_file status
    body_file=$(mktemp)
    status=$(curl -sS -o "$body_file" -w '%{http_code}' "$@" || echo "000")
    if [[ "$status" != "$expected" ]]; then
        case_fail "$case_id" "expected $expected, got $status. body: $(head -c 200 "$body_file")"
    elif ! grep -q -- "$needle" "$body_file"; then
        case_fail "$case_id" "status OK ($status) but body did not contain '$needle'. body: $(head -c 200 "$body_file")"
    else
        case_pass "$case_id (HTTP $status, body~/$needle/)"
    fi
    rm -f "$body_file"
}

# assert_status_and_header CASE_ID EXPECTED_CODE HEADER_NAME HEADER_VALUE_SUBSTR CURL_ARGS...
assert_status_and_header() {
    local case_id="$1"; shift
    local expected="$1"; shift
    local header_name="$1"; shift
    local header_substr="$1"; shift
    local body_file headers_file status
    body_file=$(mktemp)
    headers_file=$(mktemp)
    status=$(curl -sS -o "$body_file" -D "$headers_file" -w '%{http_code}' "$@" || echo "000")
    if [[ "$status" != "$expected" ]]; then
        case_fail "$case_id" "expected $expected, got $status. body: $(head -c 200 "$body_file")"
    elif ! grep -i -- "^$header_name:" "$headers_file" | grep -q -- "$header_substr"; then
        case_fail "$case_id" "status OK ($status) but header '$header_name' missing or wrong. headers: $(grep -i "^$header_name:" "$headers_file" || echo NONE)"
    else
        case_pass "$case_id (HTTP $status, $header_name~/$header_substr/)"
    fi
    rm -f "$body_file" "$headers_file"
}

# assert_file_contains CASE_ID FILE NEEDLE
assert_file_contains() {
    local case_id="$1" file="$2" needle="$3"
    if grep -q -- "$needle" "$file" 2>/dev/null; then
        case_pass "$case_id (file $file ~ /$needle/)"
    else
        case_fail "$case_id" "$file does not contain '$needle'. content: $(head -c 200 "$file" 2>/dev/null || echo MISSING)"
    fi
}

# assert_file_not_contains CASE_ID FILE NEEDLE
assert_file_not_contains() {
    local case_id="$1" file="$2" needle="$3"
    if grep -q -- "$needle" "$file" 2>/dev/null; then
        case_fail "$case_id" "$file unexpectedly contains '$needle'. content: $(head -c 200 "$file")"
    else
        case_pass "$case_id (file $file does NOT contain /$needle/)"
    fi
}

# assert_cmd_ok CASE_ID CMD...
assert_cmd_ok() {
    local case_id="$1"; shift
    local out
    if out=$("$@" 2>&1); then
        case_pass "$case_id"
    else
        case_fail "$case_id" "command failed: $* — $(echo "$out" | head -c 200)"
    fi
}

# assert_cmd_fail CASE_ID CMD...
assert_cmd_fail() {
    local case_id="$1"; shift
    local out
    if out=$("$@" 2>&1); then
        case_fail "$case_id" "expected nonzero exit; got 0. out: $(echo "$out" | head -c 200)"
    else
        case_pass "$case_id (expected failure)"
    fi
}

# ---------- proxy lifecycle ------------------------------------------------

# Globals set by start_proxy:
#   ATI_PID    — pid of the running proxy (used by SIGHUP tests)
#   ATI_LOG    — stderr/stdout capture path
ATI_PID=""
ATI_LOG=""

wait_for_port() {
    local port="$1" max=40 i=0
    while (( i < max )); do
        if (echo > /dev/tcp/127.0.0.1/"$port") 2>/dev/null; then return 0; fi
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

# Wait for a port to become FREE (no listener).
wait_for_port_free() {
    local port="$1" max=50 i=0
    while (( i < max )); do
        if ! (echo > /dev/tcp/127.0.0.1/"$port") 2>/dev/null; then return 0; fi
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

# Forcefully kill whatever owns these TCP ports. Used during cleanup and
# at orchestrator startup to guarantee a clean slate.
kill_port_owners() {
    local p pid
    for p in "$@"; do
        pid=$(ss -tlnH "sport = :$p" 2>/dev/null | awk 'match($0,/pid=([0-9]+)/,a){print a[1]; exit}')
        if [[ -n "${pid:-}" ]]; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
}

wait_for_http() {
    local url="$1" max=50 i=0
    while (( i < max )); do
        if curl -sSf -m 1 "$url" >/dev/null 2>&1; then return 0; fi
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

# start_proxy [--mode log|warn|enforce] [extra args...]
# Reads $ATI_BIN, $ATI_DIR, $PROXY_PORT, $RUST_LOG from caller.
start_proxy() {
    local mode="log"
    if [[ "${1:-}" == "--mode" ]]; then mode="$2"; shift 2; fi
    ATI_LOG=$(mktemp "${TMPDIR_E2E:-/tmp}/ati-proxy-XXXXXX.log")
    # Disable colored output to make log greps deterministic.
    RUST_LOG="${RUST_LOG:-info}" NO_COLOR=1 \
    "$ATI_BIN" proxy \
        --port "$PROXY_PORT" \
        --bind 127.0.0.1 \
        --ati-dir "$ATI_DIR" \
        --enable-passthrough \
        --sig-verify-mode "$mode" \
        "$@" \
        >"$ATI_LOG" 2>&1 &
    ATI_PID=$!
    if ! wait_for_http "http://127.0.0.1:$PROXY_PORT/health"; then
        echo "FATAL: ati proxy did not come up on :$PROXY_PORT in 5s" >&2
        echo "--- proxy log ---" >&2
        cat "$ATI_LOG" >&2
        return 1
    fi
}

stop_proxy() {
    if [[ -n "$ATI_PID" ]] && kill -0 "$ATI_PID" 2>/dev/null; then
        kill "$ATI_PID" 2>/dev/null || true
        wait "$ATI_PID" 2>/dev/null || true
    fi
    # Don't return until the port is actually free — otherwise the next
    # `start_proxy` races EADDRINUSE.
    if ! wait_for_port_free "$PROXY_PORT"; then
        # Take whoever's holding it down hard; the port MUST be ours.
        kill_port_owners "$PROXY_PORT"
        wait_for_port_free "$PROXY_PORT" || true
    fi
    ATI_PID=""
}

restart_proxy_with() {
    stop_proxy
    start_proxy "$@"
}

# ---------- mock lifecycle -------------------------------------------------

MOCK_PIDS=()

start_mock_http() {
    local port="$1" mode="$2"; shift 2
    python3 "$E2E_DIR/mock_http.py" --port "$port" --mode "$mode" "$@" >/dev/null 2>&1 &
    MOCK_PIDS+=("$!")
    wait_for_port "$port" || { echo "FATAL: mock_http port $port did not bind" >&2; return 1; }
}

start_mock_ws() {
    local port="$1" mode="$2"; shift 2
    python3 "$E2E_DIR/mock_ws.py" --port "$port" --mode "$mode" "$@" >/dev/null 2>&1 &
    MOCK_PIDS+=("$!")
    wait_for_port "$port" || { echo "FATAL: mock_ws port $port did not bind" >&2; return 1; }
}

# ---------- cleanup --------------------------------------------------------

_e2e_cleanup() {
    local code=$?
    stop_proxy
    for pid in "${MOCK_PIDS[@]:-}"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    # Belt-and-suspenders: even if we lost track of a child PID, no process
    # gets to keep one of our ports past harness exit.
    kill_port_owners "${PROXY_PORT:-}" \
        "${PORT_UPSTREAM_HTTP:-}" "${PORT_UPSTREAM_HTTP_SLOW:-}" \
        "${PORT_UPSTREAM_WS:-}" "${PORT_UPSTREAM_WS_BH:-}"
    if [[ "${KEEP_TMPDIR:-0}" != "1" ]] \
       && [[ -n "${TMPDIR_E2E:-}" && -d "$TMPDIR_E2E" ]]; then
        rm -rf "$TMPDIR_E2E"
    fi
    return $code
}

# ---------- signing helper -------------------------------------------------

# sign TS METHOD PATH SECRET — prints the X-Sandbox-Signature header value.
sign() {
    python3 "$E2E_DIR/sign.py" "$1" "$2" "$3" "$4"
}

now() { date +%s; }
