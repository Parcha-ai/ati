#!/usr/bin/env bash
# Full-stack local E2E harness for ati#96 (sig-verify) + #97 (ati edge) + #98 (WS).
#
# Boots a real `ati proxy` on 127.0.0.1, real mock upstreams, real keyring
# bootstrapped via the real `ati edge` CLI (against a fake `op` binary).
# Drives ~49 scenarios across 6 groups. Exits 0 clean / 1 on any failing case.
#
#   bash scripts/test_full_stack_e2e.sh --pr {96|97|98|all}
#
# Local-only by design — the machine running this has no external ingress for
# the test ports. Same script is wired into .github/workflows/ci.yml.

set -u -o pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
E2E_DIR="$REPO_ROOT/scripts/e2e"
ATI_BIN="${ATI_BIN:-$REPO_ROOT/target/release/ati}"

# --- args ------------------------------------------------------------------

PR_FILTER="all"
KEEP_TMPDIR=0
while (( $# > 0 )); do
    case "$1" in
        --pr) PR_FILTER="$2"; shift 2 ;;
        --keep-tmpdir) KEEP_TMPDIR=1; shift ;;
        -h|--help)
            sed -n '2,16p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

case "$PR_FILTER" in
    96|97|98|all) ;;
    *) echo "--pr must be one of: 96 97 98 all (got $PR_FILTER)" >&2; exit 2 ;;
esac

# --- preflight -------------------------------------------------------------

if [[ ! -x "$ATI_BIN" ]]; then
    echo "Building $ATI_BIN (release)…" >&2
    (cd "$REPO_ROOT" && cargo build --release --bin ati) >&2
fi

if ! python3 -c "import websockets" 2>/dev/null; then
    echo "ERROR: python3 -c 'import websockets' failed. Install with: pip install --user websockets==15.0.1" >&2
    exit 3
fi

# --- ports + tmpdir --------------------------------------------------------

# Port plan (validated unused via `ss -tln`):
export PROXY_PORT=18910
export PORT_UPSTREAM_HTTP=18920
export PORT_UPSTREAM_HTTP_SLOW=18921
export PORT_UPSTREAM_WS=18930
export PORT_UPSTREAM_WS_BH=18931

TMPDIR_E2E=$(mktemp -d /tmp/ati-e2e-XXXXXXXX)
export TMPDIR_E2E
export ATI_DIR="$TMPDIR_E2E/ati"
export MOCK_LOG="$TMPDIR_E2E/mock_http.log"
export WS_LOG="$TMPDIR_E2E/mock_ws.log"
mkdir -p "$ATI_DIR/manifests"

# --- libs ------------------------------------------------------------------

# shellcheck disable=SC1091
source "$E2E_DIR/lib.sh"

# --- pre-flight port sanity ------------------------------------------------
# Anything left over from a previous abort is killed up front so the first
# start_proxy doesn't EADDRINUSE silently.
kill_port_owners "$PROXY_PORT" "$PORT_UPSTREAM_HTTP" "$PORT_UPSTREAM_HTTP_SLOW" \
    "$PORT_UPSTREAM_WS" "$PORT_UPSTREAM_WS_BH"
sleep 0.1

# --- manifest rendering ----------------------------------------------------

render_manifest() {
    local tmpl="$1" out="$2"
    sed \
        -e "s|__PORT_UPSTREAM_HTTP__|$PORT_UPSTREAM_HTTP|g" \
        -e "s|__PORT_UPSTREAM_HTTP_SLOW__|$PORT_UPSTREAM_HTTP_SLOW|g" \
        -e "s|__PORT_UPSTREAM_WS__|$PORT_UPSTREAM_WS|g" \
        -e "s|__PORT_UPSTREAM_WS_BH__|$PORT_UPSTREAM_WS_BH|g" \
        "$tmpl" > "$out"
}

install_manifests() {
    # Wipe and re-install. Caller picks which manifests to drop in.
    rm -f "$ATI_DIR/manifests/"*.toml
    for name in "$@"; do
        render_manifest \
            "$E2E_DIR/fixtures/manifest_${name}.toml.tmpl" \
            "$ATI_DIR/manifests/${name}.toml"
    done
}

# --- keyring ---------------------------------------------------------------

bootstrap_keyring() {
    local fixture="${1:-$E2E_DIR/fixtures/op_bootstrap.json}"
    FAKE_OP_FIXTURE="$fixture" \
    "$ATI_BIN" edge bootstrap-keyring \
        --vault test --item canned \
        --ati-dir "$ATI_DIR" \
        --op-path "$E2E_DIR/fake_op.sh" >/dev/null
}

rotate_keyring() {
    local fixture="$1"
    FAKE_OP_FIXTURE="$fixture" \
    "$ATI_BIN" edge rotate-keyring \
        --vault test --item canned \
        --ati-dir "$ATI_DIR" \
        --op-path "$E2E_DIR/fake_op.sh" \
        --no-signal >/dev/null
}

# --- cleanup ---------------------------------------------------------------

trap 'rc=$?
_e2e_cleanup
if (( KEEP_TMPDIR )); then echo "Kept tmpdir: $TMPDIR_E2E" >&2; fi
exit $rc' EXIT INT TERM

# --- group dispatch --------------------------------------------------------

run_group() {
    local group="$1"
    local path="$E2E_DIR/groups/group_${group}.sh"
    if [[ ! -f "$path" ]]; then
        echo "missing group script: $path" >&2
        return 1
    fi
    # shellcheck disable=SC1090
    source "$path"
}

case "$PR_FILTER" in
    all) E2E_GROUPS=(a f b c d e) ;;
    96)  E2E_GROUPS=(a f b) ;;     # sig-verify, middleware order, SIGHUP
    97)  E2E_GROUPS=(e) ;;         # ati edge CLI
    98)  E2E_GROUPS=(d) ;;         # WebSocket
esac

echo "Running E2E groups: ${E2E_GROUPS[*]} (--pr $PR_FILTER)"
echo "tmpdir: $TMPDIR_E2E"
echo

START_TS=$(date +%s)
for g in "${E2E_GROUPS[@]}"; do
    run_group "$g"
done
END_TS=$(date +%s)

# --- summary ---------------------------------------------------------------

printf '\n'
printf '%s\n' "================================================================"
printf '%s: %d  %s: %d  (wall %ds)\n' \
    "$(color_green PASS)" "$E2E_PASS" "$(color_red FAIL)" "$E2E_FAIL" "$((END_TS - START_TS))"
if (( E2E_FAIL > 0 )); then
    printf '\nFailed cases:\n'
    for c in "${E2E_FAILED_CASES[@]}"; do
        printf '  - %s\n' "$c"
    done
    exit 1
fi
exit 0
