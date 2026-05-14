#!/usr/bin/env bash
#
# End-to-end smoke test for the `otel` feature.
#
# Boots:
#   1. A 60-line Python OTLP/HTTP collector that captures POSTs to
#      /v1/traces and /v1/metrics and writes raw bodies to disk.
#   2. `ati proxy --features otel` configured to export to the stub
#      collector via OTEL_EXPORTER_OTLP_ENDPOINT.
#
# Then:
#   - Makes a request to /health on the proxy.
#   - Waits a few seconds for the batch exporter to flush.
#   - Asserts the collector received at least one /v1/traces POST.
#
# Why this exists: tests/otel_test.rs covers the layer wiring in-process
# but cannot verify the OTLP exporter actually serializes and ships spans
# over HTTP. This script is the integration safety net for that.
#
# Run from the repo root:
#   bash scripts/test_otel_e2e.sh
#
# Skip with: SKIP_OTEL_E2E=1 (CI knob; the script always exits 0 then).

set -euo pipefail

if [[ "${SKIP_OTEL_E2E:-0}" == "1" ]]; then
  echo "SKIP_OTEL_E2E=1 set — skipping."
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 required" >&2; exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="$(mktemp -d -t ati-otel-e2e.XXXXXX)"
trap 'cleanup' EXIT

COLLECTOR_PORT=14318
PROXY_PORT=18099
ATI_BIN="${ATI_BIN:-${REPO_ROOT}/target/debug/ati}"

cleanup() {
  set +e
  [[ -n "${PROXY_PID:-}" ]] && kill "${PROXY_PID}" 2>/dev/null
  [[ -n "${COLLECTOR_PID:-}" ]] && kill "${COLLECTOR_PID}" 2>/dev/null
  wait 2>/dev/null
  if [[ "${NOCLEAN:-0}" != "1" ]]; then
    rm -rf "${WORK_DIR}"
  else
    echo "NOCLEAN=1 — work dir preserved at ${WORK_DIR}"
  fi
}

# ---------------------------------------------------------------------------
# 1. Build ati with --features otel
# ---------------------------------------------------------------------------
echo ">>> Building ati --features otel (debug profile)..."
(cd "${REPO_ROOT}" && cargo build --features otel --bin ati --quiet)

# ---------------------------------------------------------------------------
# 2. Stub OTLP collector
# ---------------------------------------------------------------------------
cat >"${WORK_DIR}/collector.py" <<'PYEOF'
"""Minimal OTLP/HTTP collector.

Accepts POSTs to /v1/traces and /v1/metrics. Each request body (protobuf,
opaque to us) is written to a per-signal file with a request counter
appended, so the e2e script can assert non-empty traffic.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import os, sys, threading

OUT = os.environ.get("OUT_DIR", ".")
COUNTERS = {"traces": 0, "metrics": 0}
LOCK = threading.Lock()

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length) if length > 0 else b""
        signal = "traces" if self.path.endswith("/v1/traces") else \
                 "metrics" if self.path.endswith("/v1/metrics") else "other"
        with LOCK:
            COUNTERS[signal] = COUNTERS.get(signal, 0) + 1
            n = COUNTERS[signal]
        path = os.path.join(OUT, f"{signal}-{n}.bin")
        with open(path, "wb") as f:
            f.write(body)
        sys.stderr.write(f"[collector] {signal} #{n} bytes={len(body)}\n")
        sys.stderr.flush()
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_): pass

port = int(os.environ.get("PORT", "4318"))
print(f"[collector] listening on 127.0.0.1:{port}", flush=True)
HTTPServer(("127.0.0.1", port), H).serve_forever()
PYEOF

echo ">>> Starting stub OTLP collector on :${COLLECTOR_PORT} ..."
OUT_DIR="${WORK_DIR}" PORT="${COLLECTOR_PORT}" \
  python3 "${WORK_DIR}/collector.py" > "${WORK_DIR}/collector.log" 2>&1 &
COLLECTOR_PID=$!

# Wait until collector is accepting connections.
for _ in {1..30}; do
  if curl -sf -o /dev/null -X POST "http://127.0.0.1:${COLLECTOR_PORT}/v1/traces"; then
    break
  fi
  sleep 0.2
done

# ---------------------------------------------------------------------------
# 3. Boot ati proxy pointed at the collector
# ---------------------------------------------------------------------------
ATI_DIR="${WORK_DIR}/ati"
mkdir -p "${ATI_DIR}/manifests"

echo ">>> Starting ati proxy on :${PROXY_PORT} (otel→127.0.0.1:${COLLECTOR_PORT}) ..."
OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:${COLLECTOR_PORT}" \
OTEL_SERVICE_NAME="ati-e2e" \
OTEL_TRACES_SAMPLER="always_on" \
RUST_LOG="info,opentelemetry=debug" \
"${ATI_BIN}" proxy \
  --bind 127.0.0.1 \
  --port "${PROXY_PORT}" \
  --ati-dir "${ATI_DIR}" \
  > "${WORK_DIR}/ati.log" 2>&1 &
PROXY_PID=$!

# Wait for proxy /health to return 200.
for _ in {1..50}; do
  code=$(curl -sf -o /dev/null -w "%{http_code}" "http://127.0.0.1:${PROXY_PORT}/health" || echo "")
  if [[ "${code}" == "200" ]]; then break; fi
  sleep 0.2
done

# ---------------------------------------------------------------------------
# 4. Generate traffic
# ---------------------------------------------------------------------------
echo ">>> Hitting /health a few times to generate spans/metrics ..."
for _ in {1..5}; do
  curl -sf -o /dev/null "http://127.0.0.1:${PROXY_PORT}/health"
done

# Batch span processor flushes on a 5s schedule by default. PeriodicReader
# for metrics is on a 60s default — we don't wait for metrics in this E2E
# (it would slow CI too much); the in-process tests cover metric recording.
echo ">>> Waiting 10s for span exporter to flush ..."
sleep 10

# ---------------------------------------------------------------------------
# 5. Assert at least one trace POST landed
# ---------------------------------------------------------------------------
trace_files=("${WORK_DIR}"/traces-*.bin)
if [[ ! -e "${trace_files[0]}" ]]; then
  echo "FAIL: collector received no /v1/traces POSTs." >&2
  echo "--- ati.log (tail) ---" >&2
  tail -50 "${WORK_DIR}/ati.log" >&2
  echo "--- collector.log ---" >&2
  cat "${WORK_DIR}/collector.log" >&2
  exit 1
fi

# Smoke check: at least one trace body should be non-empty.
biggest=$(stat --printf="%s\n" "${trace_files[@]}" | sort -n | tail -1)
if [[ "${biggest}" -lt 50 ]]; then
  echo "FAIL: collector got trace POSTs but all bodies are suspiciously small (${biggest} bytes)." >&2
  exit 1
fi

echo "PASS: collector received $(ls "${WORK_DIR}"/traces-*.bin | wc -l) trace POST(s), largest=${biggest} bytes."
