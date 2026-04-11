#!/usr/bin/env bash
# End-to-end verification harness for the 0.7.5 skill fetch shape change.
#
# Boots a local ATI proxy against the real parcha-ati-skills GCS bucket
# with an isolated ATI_DIR (no local skills on disk), mints a wildcard
# JWT, then fetches a set of known-good skills and checks that every
# activation response:
#
#   - Has a non-empty `description` field                (new in 0.7.5)
#   - Does NOT have a `resources` field                  (removed in 0.7.5)
#   - Has `${ATI_SKILL_DIR}` / `${CLAUDE_SKILL_DIR}`
#     substituted to `skillati://<name>`                 (new in 0.7.5)
#   - Has `.claude/skills/<other>/` references
#     rewritten to `skillati://<other>/`                 (new in 0.7.5)
#
# Exits 0 if every response matches the new shape, non-zero otherwise.
#
# Dependencies: jq, curl, python3 (for the ephemeral port helper), an
# ati binary at ./target/debug/ati (or the first arg), and a
# ~/.ati/credentials file containing a `gcp_credentials` entry. Safe
# to run locally — does not mutate the GCS bucket or the running LOCAL
# GREP proxy; by default it binds to 127.0.0.1 on an ephemeral port
# (picked by asking the kernel for a free socket), so concurrent runs
# and pre-occupied ports don't collide. Set `ATI_E2E_PORT` to force a
# specific port if you need to curl the proxy from outside the script.

set -euo pipefail

ATI_BIN="${1:-./target/debug/ati}"
# Default to an ephemeral port chosen by the kernel — `bind((\"\",0))` gives
# us a free high port, so two concurrent runs of this harness don't
# collide on the same socket. Override with ATI_E2E_PORT for manual
# debugging.
PROXY_PORT="${ATI_E2E_PORT:-$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')}"
BUCKET="${ATI_E2E_BUCKET:-gcs://parcha-ati-skills}"
SKILLS=(
  slidedeck-production
  html-app-architecture
  data-visualization
  ati-tools-reference
  fal-generate
  elevenlabs-tts-api
  gcs-upload-serving
  fal-audio
)

if [[ ! -x "$ATI_BIN" ]]; then
  echo "error: ati binary not found at $ATI_BIN"
  echo "       build first: cargo build --features sentry"
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq not installed (required for JSON assertions)"
  exit 1
fi

# Stage an isolated ATI_DIR — empty skills/ so any filesystem fallback
# proves nothing, and a scoped credentials file carrying only the GCS key.
REPRO_DIR="$(mktemp -d /tmp/ati-e2e-XXXXXX)"
trap 'rm -rf "$REPRO_DIR"; [[ -n "${PROXY_PID:-}" ]] && kill "$PROXY_PID" 2>/dev/null || true' EXIT

mkdir -p "$REPRO_DIR/skills"
if [[ ! -f "$HOME/.ati/credentials" ]]; then
  echo "error: no credentials file at ~/.ati/credentials — gcp_credentials required"
  exit 1
fi
# Extract just gcp_credentials so the isolated proxy has zero other keys.
python3 -c '
import json, sys
with open("'"$HOME"'/.ati/credentials") as f:
    creds = json.load(f)
if "gcp_credentials" not in creds:
    sys.exit("credentials file has no gcp_credentials key")
with open("'"$REPRO_DIR"'/credentials", "w") as f:
    json.dump({"gcp_credentials": creds["gcp_credentials"]}, f)
'

SECRET="$(openssl rand -hex 32)"
echo "==> Booting isolated proxy on 127.0.0.1:${PROXY_PORT} against ${BUCKET}"
ATI_DIR="$REPRO_DIR" \
  ATI_SKILL_REGISTRY="$BUCKET" \
  ATI_JWT_SECRET="$SECRET" \
  ATI_JWT_AUDIENCE=ati-proxy \
  RUST_LOG=warn \
  "$ATI_BIN" proxy --port "$PROXY_PORT" --bind 127.0.0.1 \
  >"$REPRO_DIR/proxy.log" 2>&1 &
PROXY_PID=$!

# Wait for /health to come up (max 5s).
for _ in $(seq 1 25); do
  if curl -fsS "http://127.0.0.1:${PROXY_PORT}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
if ! curl -fsS "http://127.0.0.1:${PROXY_PORT}/health" >/dev/null 2>&1; then
  echo "error: proxy did not start — log tail:"
  tail -30 "$REPRO_DIR/proxy.log"
  exit 1
fi

TOKEN="$(ATI_JWT_SECRET="$SECRET" ATI_JWT_AUDIENCE=ati-proxy \
  "$ATI_BIN" token issue --sub ati-e2e --scope '*' \
  --secret "$SECRET" --ttl 3600 --output text 2>&1 | tail -1)"

pass=0
fail=0
report=""

for skill in "${SKILLS[@]}"; do
  resp_file="$REPRO_DIR/${skill}.json"
  http_status="$(curl -sS -o "$resp_file" \
    -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    "http://127.0.0.1:${PROXY_PORT}/skillati/${skill}")"

  if [[ "$http_status" != "200" ]]; then
    fail=$((fail + 1))
    report+="  ✗ ${skill}: HTTP ${http_status}\n"
    continue
  fi

  # New-shape assertions — each one is a printable reason if it fails.
  reasons=()

  has_description="$(jq -r 'if (.description // "") == "" then "no" else "yes" end' "$resp_file")"
  if [[ "$has_description" != "yes" ]]; then
    reasons+=("description missing or empty")
  fi

  has_resources="$(jq -r 'if has("resources") then "yes" else "no" end' "$resp_file")"
  if [[ "$has_resources" != "no" ]]; then
    reasons+=("resources field still present (expected to be removed)")
  fi

  has_ati_var="$(jq -r '.content | contains("${ATI_SKILL_DIR}")' "$resp_file")"
  if [[ "$has_ati_var" == "true" ]]; then
    reasons+=("unsubstituted \${ATI_SKILL_DIR} still present in body")
  fi

  has_claude_var="$(jq -r '.content | contains("${CLAUDE_SKILL_DIR}")' "$resp_file")"
  if [[ "$has_claude_var" == "true" ]]; then
    reasons+=("unsubstituted \${CLAUDE_SKILL_DIR} still present in body")
  fi

  # `.claude/skills/<name>/…` rewrite check: match only directory-form
  # references (followed by `/` and another path segment), not prose
  # mentions like `.claude/skills/ directory`.
  cross_ref="$(jq -r '.content | capture("\\.claude/skills/(?<n>[a-z0-9][a-z0-9-]*)/")?.n // ""' "$resp_file" 2>/dev/null || true)"
  if [[ -n "$cross_ref" ]]; then
    reasons+=("cross-skill filesystem ref `.claude/skills/${cross_ref}/` not rewritten")
  fi

  if [[ ${#reasons[@]} -eq 0 ]]; then
    pass=$((pass + 1))
    size="$(wc -c <"$resp_file")"
    desc="$(jq -r '.description | .[0:60]' "$resp_file")"
    report+="  ✓ ${skill} (${size}B) — ${desc}\n"
  else
    fail=$((fail + 1))
    report+="  ✗ ${skill}:\n"
    for r in "${reasons[@]}"; do
      report+="      - ${r}\n"
    done
  fi
done

printf "%b\n" "$report"
echo "==> ${pass} pass / ${fail} fail"

if [[ $fail -ne 0 ]]; then
  echo "proxy log tail:"
  tail -20 "$REPRO_DIR/proxy.log"
  exit 1
fi
