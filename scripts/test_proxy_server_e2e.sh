#!/usr/bin/env bash
# E2E test for the ATI proxy server (ati proxy) + client (ati run with ATI_PROXY_URL).
#
# This test:
# 1. Sets up a temporary ATI directory with a manifest for a mock upstream API
# 2. Starts a mock upstream API (Python)
# 3. Starts `ati proxy` pointing at that ATI directory
# 4. Runs `ati run` with ATI_PROXY_URL pointing at the proxy
# 5. Verifies the full round-trip: client → proxy → upstream → proxy → client
#
# Prerequisites: cargo build
# Usage: bash scripts/test_proxy_server_e2e.sh

set -euo pipefail

ATI_BIN="${ATI_BIN:-./target/debug/ati}"
UPSTREAM_PORT="${UPSTREAM_PORT:-18930}"
PROXY_PORT="${PROXY_PORT:-18931}"
UPSTREAM_PID=""
PROXY_PID=""
ATI_DIR=""

cleanup() {
    [[ -n "$UPSTREAM_PID" ]] && kill "$UPSTREAM_PID" 2>/dev/null || true
    [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
    [[ -n "$ATI_DIR" ]] && rm -rf "$ATI_DIR" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# --- Build if needed ---
if [[ ! -f "$ATI_BIN" ]]; then
    echo "Building ATI..."
    cargo build
fi

# --- Create temporary ATI directory ---
ATI_DIR=$(mktemp -d /tmp/ati-e2e-server-XXXXXX)
mkdir -p "$ATI_DIR/manifests"

# Create a test manifest pointing at our mock upstream
cat > "$ATI_DIR/manifests/mock.toml" << EOF
[provider]
name = "mock"
description = "Mock provider for E2E testing"
base_url = "http://127.0.0.1:$UPSTREAM_PORT"
auth_type = "bearer"
auth_key_name = "mock_api_key"

[[tools]]
name = "mock_search"
description = "Mock search tool"
endpoint = "/search"
method = "GET"

[tools.input_schema]
type = "object"
required = ["query"]

[tools.input_schema.properties.query]
type = "string"
description = "Search query"

[[tools]]
name = "mock_create"
description = "Mock create tool (POST)"
endpoint = "/create"
method = "POST"

[tools.input_schema]
type = "object"
required = ["title"]

[tools.input_schema.properties.title]
type = "string"
description = "Title to create"
EOF

# Create an encrypted keyring with a mock API key
# We'll use a known session key and encrypt the keyring
python3 -c "
import json, os, base64, struct
from hashlib import sha256

# The keyring we want to encrypt
keyring = json.dumps({'mock_api_key': 'test-secret-key-12345'}).encode()

# Generate a random session key
session_key = os.urandom(32)

# AES-256-GCM encryption (using Python's cryptography library if available, else skip)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, keyring, None)
    encrypted = nonce + ciphertext

    # Write encrypted keyring
    with open('$ATI_DIR/keyring.enc', 'wb') as f:
        f.write(encrypted)

    # Write session key file (base64 encoded)
    key_dir = '/tmp/ati-e2e-key'
    os.makedirs(key_dir, exist_ok=True)
    with open(key_dir + '/.key', 'w') as f:
        f.write(base64.b64encode(session_key).decode())

    print(f'KEY_DIR={key_dir}')
    print('KEYRING_OK=true')
except ImportError:
    print('KEYRING_OK=false')
    print('Skipping keyring encryption (cryptography package not installed)')
" > /tmp/ati-e2e-keyinfo.txt

source /tmp/ati-e2e-keyinfo.txt 2>/dev/null || KEYRING_OK=false

# --- Start mock upstream API ---
echo "Starting mock upstream API on port $UPSTREAM_PORT..."

python3 -c "
import http.server
import json
import sys

class UpstreamHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Check auth header
        auth = self.headers.get('Authorization', '')
        if auth != 'Bearer test-secret-key-12345':
            self.send_response(401)
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'unauthorized', 'got_auth': auth}).encode())
            return

        # Parse query string
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        response = {
            'results': [
                {'title': f'Result for: {params.get(\"query\", [\"?\"])[0]}', 'score': 0.95},
                {'title': 'Second result', 'score': 0.87},
            ],
            'total': 2,
            'auth_verified': True
        }

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def do_POST(self):
        auth = self.headers.get('Authorization', '')
        if auth != 'Bearer test-secret-key-12345':
            self.send_response(401)
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'unauthorized'}).encode())
            return

        content_length = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}

        response = {
            'id': 'created-123',
            'title': body.get('title', 'untitled'),
            'created': True
        }

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        pass

server = http.server.HTTPServer(('127.0.0.1', $UPSTREAM_PORT), UpstreamHandler)
print(f'Mock upstream on 127.0.0.1:{$UPSTREAM_PORT}', file=sys.stderr)
server.serve_forever()
" &
UPSTREAM_PID=$!
sleep 0.3

# --- Start ATI proxy server ---
echo "Starting ATI proxy server on port $PROXY_PORT..."

if [[ "$KEYRING_OK" == "true" ]]; then
    # Set the key file location for the proxy to find
    ATI_KEY_FILE="$KEY_DIR/.key" "$ATI_BIN" proxy --port "$PROXY_PORT" --ati-dir "$ATI_DIR" &
    PROXY_PID=$!
else
    # No keyring — proxy will run without auth (tools requiring auth will fail)
    "$ATI_BIN" proxy --port "$PROXY_PORT" --ati-dir "$ATI_DIR" &
    PROXY_PID=$!
fi

# Wait for proxy to be ready
for i in $(seq 1 20); do
    if curl -sf "http://127.0.0.1:$PROXY_PORT/health" > /dev/null 2>&1; then
        break
    fi
    sleep 0.25
done

# --- Test 1: Health check ---
echo ""
echo "=== Test 1: Proxy health check ==="
HEALTH=$(curl -sf "http://127.0.0.1:$PROXY_PORT/health")
echo "$HEALTH"

if echo "$HEALTH" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['status']=='ok'; print('PASS: Health OK')"; then
    true
else
    echo "FAIL: Health check failed"
    exit 1
fi

# --- Test 2: Client → Proxy → Upstream round-trip (GET) ---
echo ""
echo "=== Test 2: Full round-trip via proxy (GET tool) ==="
OUTPUT=$(ATI_PROXY_URL="http://127.0.0.1:$PROXY_PORT" ATI_DIR=/tmp/nonexistent "$ATI_BIN" --output json run mock_search --query "hello world" 2>&1)
echo "$OUTPUT"

if echo "$OUTPUT" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('auth_verified') == True; print('PASS: Auth verified through proxy')"; then
    true
else
    # If keyring wasn't available, we expect a different error
    if [[ "$KEYRING_OK" != "true" ]]; then
        echo "SKIP: Keyring not available (cryptography package missing) — auth test skipped"
    else
        echo "FAIL: Expected auth_verified=true in response"
        exit 1
    fi
fi

# --- Test 3: Client → Proxy → Upstream round-trip (POST tool) ---
echo ""
echo "=== Test 3: Full round-trip via proxy (POST tool) ==="
OUTPUT=$(ATI_PROXY_URL="http://127.0.0.1:$PROXY_PORT" ATI_DIR=/tmp/nonexistent "$ATI_BIN" --output json run mock_create --title "test document" 2>&1)
echo "$OUTPUT"

if echo "$OUTPUT" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('created') == True; print('PASS: POST tool works through proxy')"; then
    true
else
    if [[ "$KEYRING_OK" != "true" ]]; then
        echo "SKIP: Keyring not available — POST auth test skipped"
    else
        echo "FAIL: Expected created=true in response"
        exit 1
    fi
fi

# --- Test 4: Unknown tool returns 404 ---
echo ""
echo "=== Test 4: Unknown tool returns error ==="
OUTPUT=$(ATI_PROXY_URL="http://127.0.0.1:$PROXY_PORT" ATI_DIR=/tmp/nonexistent "$ATI_BIN" run nonexistent_tool --foo bar 2>&1 || true)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -qi "unknown tool\|error"; then
    echo "PASS: Unknown tool returned error"
else
    echo "FAIL: Expected error for unknown tool"
    exit 1
fi

# --- Test 5: Proxy subcommand help ---
echo ""
echo "=== Test 5: ati proxy --help ==="
OUTPUT=$("$ATI_BIN" proxy --help 2>&1)
if echo "$OUTPUT" | grep -q "proxy server"; then
    echo "PASS: Proxy help shows server description"
else
    echo "FAIL: Expected proxy server description in help"
    exit 1
fi

echo ""
echo "=== All proxy server E2E tests passed ==="
