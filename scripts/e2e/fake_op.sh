#!/usr/bin/env bash
# Fake `op` binary for E2E tests. Wired via `ati edge ... --op-path <this>`.
#
# Behaviour:
# - Validates argv looks like `op item get --format json <vault> <item>`.
# - If $FAKE_OP_FIXTURE == "__fail__", exits 1 to simulate op failure.
# - Otherwise cats $FAKE_OP_FIXTURE (path to a JSON fixture).
# - As a side-effect, writes $OP_SERVICE_ACCOUNT_TOKEN to $FAKE_OP_TOKEN_SINK if
#   the sink is set. This lets us prove that --op-token-file passes the VALUE
#   not the PATH (Greptile #97 P1 regression guard).
set -u

if [[ -n "${FAKE_OP_TOKEN_SINK:-}" ]]; then
    printf '%s' "${OP_SERVICE_ACCOUNT_TOKEN:-<UNSET>}" > "$FAKE_OP_TOKEN_SINK"
fi

if [[ "$1" != "item" || "$2" != "get" ]]; then
    echo "fake_op: unexpected args: $*" >&2
    exit 2
fi

if [[ "${FAKE_OP_FIXTURE:-}" == "__fail__" ]]; then
    echo "fake_op: simulated failure" >&2
    exit 1
fi

if [[ -z "${FAKE_OP_FIXTURE:-}" || ! -f "$FAKE_OP_FIXTURE" ]]; then
    echo "fake_op: FAKE_OP_FIXTURE not set or missing: ${FAKE_OP_FIXTURE:-<unset>}" >&2
    exit 3
fi

cat "$FAKE_OP_FIXTURE"
