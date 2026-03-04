#!/usr/bin/env bash
# E2E test for ATI proxy mode.
# Starts a tiny mock proxy server, runs ati run through it, verifies the round-trip.
#
# Prerequisites: cargo build (ati binary must exist)
# Usage: bash scripts/test_proxy_e2e.sh

set -euo pipefail

ATI_BIN="${ATI_BIN:-./target/debug/ati}"
PROXY_PORT="${PROXY_PORT:-18923}"
PROXY_PID=""

cleanup() {
    if [[ -n "$PROXY_PID" ]]; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# --- Build if needed ---
if [[ ! -f "$ATI_BIN" ]]; then
    echo "Building ATI..."
    cargo build
fi

# --- Start mock proxy server ---
# Using Python's http.server as a quick mock that responds to /call and /help
echo "Starting mock proxy on port $PROXY_PORT..."

python3 -c "
import http.server
import json
import sys

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        request = json.loads(body) if body else {}

        if self.path == '/call':
            tool_name = request.get('tool_name', 'unknown')
            args = request.get('args', {})
            response = {
                'result': {
                    'proxy_mode': True,
                    'tool': tool_name,
                    'echo_args': args,
                    'message': f'Proxy executed {tool_name} successfully'
                },
                'error': None
            }
        elif self.path == '/help':
            query = request.get('query', '')
            response = {
                'content': f'Proxy help response for: {query}\n\nTry: ati run web_search --query \"your query\"',
                'error': None
            }
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not found')
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        pass  # Suppress logs

server = http.server.HTTPServer(('127.0.0.1', $PROXY_PORT), ProxyHandler)
print(f'Mock proxy listening on 127.0.0.1:{$PROXY_PORT}', file=sys.stderr)
server.serve_forever()
" &
PROXY_PID=$!

# Wait for server to start
sleep 0.5

# --- Test 1: ati run via proxy ---
echo ""
echo "=== Test 1: ati run via proxy ==="
OUTPUT=$(ATI_PROXY_URL="http://127.0.0.1:$PROXY_PORT" ATI_DIR=/tmp/ati-e2e-nonexistent "$ATI_BIN" --output json run web_search --query "test query" 2>&1)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "proxy_mode"; then
    echo "PASS: Proxy mode confirmed"
else
    echo "FAIL: Expected proxy_mode in response"
    exit 1
fi

if echo "$OUTPUT" | grep -q "web_search"; then
    echo "PASS: Tool name echoed back"
else
    echo "FAIL: Expected tool name in response"
    exit 1
fi

# --- Test 2: ati assist via proxy ---
echo ""
echo "=== Test 2: ati assist via proxy ==="
OUTPUT=$(ATI_PROXY_URL="http://127.0.0.1:$PROXY_PORT" ATI_DIR=/tmp/ati-e2e-nonexistent "$ATI_BIN" assist "how do I search?" 2>&1)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "Proxy help response"; then
    echo "PASS: Help routed through proxy"
else
    echo "FAIL: Expected proxy help response"
    exit 1
fi

# --- Test 3: without ATI_PROXY_URL, falls back to local mode ---
echo ""
echo "=== Test 3: local mode fallback ==="
OUTPUT=$(ATI_DIR=/tmp/ati-e2e-nonexistent "$ATI_BIN" run web_search --query "test" 2>&1 || true)

if echo "$OUTPUT" | grep -qi "manifest\|directory\|no manifests"; then
    echo "PASS: Local mode attempted (manifest error expected)"
else
    echo "FAIL: Expected local mode manifest error. Got: $OUTPUT"
    exit 1
fi

# --- Test 4: verbose output shows mode ---
echo ""
echo "=== Test 4: verbose mode detection ==="
OUTPUT=$(ATI_PROXY_URL="http://127.0.0.1:$PROXY_PORT" ATI_DIR=/tmp/ati-e2e-nonexistent "$ATI_BIN" --verbose --output json call test_tool 2>&1)

if echo "$OUTPUT" | grep -q "Mode: proxy"; then
    echo "PASS: Verbose shows proxy mode"
else
    echo "FAIL: Expected 'Mode: proxy' in verbose output. Got: $OUTPUT"
    exit 1
fi

echo ""
echo "=== All E2E tests passed ==="
