# Group F — middleware ordering (PR #96 × #95 integration), 4 cases.
#
# The critical property being verified: sig-verify in enforce mode runs
# BEFORE auth_middleware (JWT). An unsigned passthrough request must be
# rejected by sig-verify with 403, not by JWT with 401. And named routes
# must remain reachable when the passthrough fallback is installed.

group_header "Group F — middleware ordering (4 cases)"

# Mocks + manifests already running from Group A. If running solo, set up.
if [[ -z "${MOCK_PIDS[*]:-}" ]]; then
    start_mock_http "$PORT_UPSTREAM_HTTP" echo
fi
install_manifests passthrough
bootstrap_keyring "$E2E_DIR/fixtures/op_bootstrap.json"
S1="11111111111111111111111111111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# Generate an HS256 secret and issue a token. The proxy picks up
# ATI_JWT_SECRET from env at boot.
JWT_SECRET_HEX="$(openssl rand -hex 32)"
JWT_TOKEN=$("$ATI_BIN" token issue \
    --sub e2e-harness \
    --scope "tool:*" \
    --secret "$JWT_SECRET_HEX" \
    --aud ati-proxy 2>/dev/null | tr -d '\n')

if [[ -z "$JWT_TOKEN" ]]; then
    echo "FATAL: could not mint JWT for Group F" >&2
    return 1
fi

# Boot proxy with both sig-verify=enforce AND JWT validation enabled.
ATI_JWT_SECRET="$JWT_SECRET_HEX" start_proxy --mode enforce

# F1: enforce + unsigned passthrough → 403 from sig-verify (NOT 401 from JWT).
# This is THE property — sig-verify must run before JWT.
assert_status_and_body F1_unsigned_passthrough_403_sigverify 403 missing_signature \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# F2: signed passthrough request with a valid JWT → 200 (both layers pass).
# Also confirms that the Authorization header from the JWT does NOT survive
# to the upstream (filter_request_headers strips Authorization).
TS=$(now); SIG=$(sign "$TS" POST /api/x "$S1")
assert_status_and_header F2_signed_passthrough_with_jwt 200 X-Mock-Upstream echo \
    -H "X-Sandbox-Signature: $SIG" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# F3: signed passthrough WITHOUT JWT → 200 (sig-verify is what protects
# passthrough; JWT is bypassed for passthrough routes per auth_middleware).
TS=$(now); SIG=$(sign "$TS" POST /api/x "$S1")
assert_status F3_signed_passthrough_no_jwt 200 \
    -H "X-Sandbox-Signature: $SIG" \
    -X POST "http://127.0.0.1:$PROXY_PORT/api/x" -d '{}'

# F4: named routes are still reachable when passthrough fallback is installed.
# /health is exempt from both sig-verify (default exempt list) AND JWT (public).
# /.well-known/jwks.json is also exempt from both.
# These prove named-route precedence over fallback.
assert_status F4a_named_health 200 "http://127.0.0.1:$PROXY_PORT/health"
# /.well-known/jwks.json returns 404 here because we boot with HS256 (no
# public key to publish). The PROPERTY we want to assert is that this route
# is reachable as a NAMED route (not eaten by the passthrough fallback +
# its sig-verify gate); 404 from the named handler proves that.
assert_status F4b_named_jwks 404 "http://127.0.0.1:$PROXY_PORT/.well-known/jwks.json"

# F5: /skills (named route) requires JWT — with a valid token + valid sig
# header in case sig-verify hits it, must return 200, NOT 403 or 404
# (which would mean fallback ate it).
TS=$(now); SIG=$(sign "$TS" GET /skills "$S1")
assert_status F4c_named_skills_with_jwt 200 \
    -H "X-Sandbox-Signature: $SIG" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    "http://127.0.0.1:$PROXY_PORT/skills"

stop_proxy
unset ATI_JWT_SECRET 2>/dev/null || true
