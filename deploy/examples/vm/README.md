# Edge VM deployment example

Generic, hostname-free templates showing how to deploy ATI on a static-IP
egress VM that absorbs the role of a separate reverse-proxy box (Caddy +
HMAC sidecar + package-registry caches).

This is the pattern the Parcha team uses on their `sandbox-proxy` VM
(deployment specifics live in a private repo). Use this as the starting
point for your own deployment — the placeholders below are everything
you need to fill in.

> **Threat model.** This setup assumes:
> - Sandboxes egressing through the VM hold a JWT for tool dispatch AND sign
>   every request with HMAC-SHA256 using a shared secret pulled from 1Password.
> - The VM itself is owned/operated by you — no untrusted code runs on it.
> - Upstream services (LLM gateway, browser-automation API, OTel collector,
>   etc.) each have their own credentials that you do NOT want sandboxes to
>   see directly. ATI injects them at the edge from a keyring file owned by
>   `root:ati`, mode `0600`.

## Architecture

```
sandbox ──HMAC-signed request──▶ Caddy :443 ──TLS-terminate──▶ ati :8080
                                                                  │
                                  + tool dispatch routes (/call, /mcp, /skills*)
                                  + raw HTTP passthrough by manifest:
                                      /litellm/*    → LLM gateway
                                      /git/*        → code storage
                                      bb.example/*  → browser API
                                      otel.example/* → OTel collector
                                      /root/*       → devpi (PyPI mirror)
                                      /npm/*        → verdaccio (npm mirror)

                                  haproxy :6381–6384 → Redis fan-out (L4, TLS upstream)
                                  devpi :3141  (local PyPI cache)
                                  verdaccio :4873  (local npm cache)
```

ATI handles HTTP. haproxy handles L4 Redis. devpi/verdaccio are package
registry caches with no auth.

## Prerequisites

- A VM with a static public IP (e.g. GCP, Hetzner, OVH). Linux x86_64.
- Outbound 443 to every upstream you'll route to (LLM gateway, browser-automation API, code storage, OTel collector, Redis, PyPI, npm).
- DNS records for your TLS-terminated subdomains pointing at the static IP.
- `op` (1Password CLI) installed AND a service-account token at `/etc/op-service-account-token` (root-readable, mode `0400`) so `ati edge bootstrap-keyring` can fetch credentials non-interactively.

## Setup

```bash
# 1. Install ati (musl static build from GH releases)
curl -L https://github.com/Parcha-ai/ati/releases/latest/download/ati-x86_64-unknown-linux-musl \
  -o /usr/local/bin/ati
chmod +x /usr/local/bin/ati

# 2. Install Caddy, haproxy, devpi, verdaccio (apt + nodejs in Verdaccio's case)
apt-get install -y caddy haproxy nodejs npm python3-pip
pip install devpi-server devpi-web
npm install -g verdaccio

# 3. Drop ATI's user
useradd --system --no-create-home --shell /usr/sbin/nologin ati
mkdir -p /etc/ati/manifests /var/lib/ati
chown -R ati:ati /etc/ati /var/lib/ati

# 4. Copy this template's configs into place
cp deploy/examples/vm/caddy/Caddyfile         /etc/caddy/Caddyfile
cp deploy/examples/vm/systemd/ati.service     /etc/systemd/system/
cp deploy/examples/vm/systemd/ati-rotate-keyring.service /etc/systemd/system/
cp deploy/examples/vm/systemd/ati-rotate-keyring.timer   /etc/systemd/system/
cp deploy/examples/vm/haproxy/haproxy.cfg.example        /etc/haproxy/haproxy.cfg
cp deploy/examples/vm/verdaccio/config.yaml.example      /etc/verdaccio/config.yaml
cp deploy/examples/vm/manifests/*.toml                   /etc/ati/manifests/

# 5. Author your manifests
#    Each file in /etc/ati/manifests/ describes one upstream. See
#    example-passthrough.toml for the shape. Real production deployments
#    will have one manifest per upstream service (LiteLLM, Browserbase,
#    code.storage, Grafana OTel, devpi, verdaccio).

# 6. Bootstrap the keyring from 1Password
sudo -u ati env OP_SERVICE_ACCOUNT_TOKEN=$(cat /etc/op-service-account-token) \
  ati edge bootstrap-keyring \
    --vault "Production Secrets" \
    --item "ATI Edge VM Keyring" \
    --ati-dir /var/lib/ati

# 7. Start services
systemctl daemon-reload
systemctl enable --now caddy ati haproxy devpi verdaccio ati-rotate-keyring.timer
```

## Operating

### Healthcheck
```bash
curl -fsS http://localhost:8080/health
```

### Keyring rotation
Triggered automatically by the systemd timer (default: weekly at 03:00 UTC).
Manual rotation:
```bash
sudo -u ati env OP_SERVICE_ACCOUNT_TOKEN=$(cat /etc/op-service-account-token) \
  ati edge rotate-keyring \
    --vault "Production Secrets" \
    --item "ATI Edge VM Keyring" \
    --ati-dir /var/lib/ati \
    --service ati
```
The command writes the new keyring atomically (tempfile + `rename(2)`),
then sends `SIGHUP` to the running `ati.service`. The proxy hot-reloads
the HMAC signing secret without restarting.

### Sig-verify rollout

Brand-new deployments should run in `--sig-verify-mode log` for at
least 24 hours, then flip to `enforce`:

```bash
# Validate that all sandbox traffic is signing correctly
journalctl -u ati --since "24 hours ago" | grep sig_verify | \
  awk '/valid=true/{t++} /valid=false/{f++} END{print "valid:",t,"invalid:",f}'

# Gate: invalid must be 0 (or only on exempt paths) before enforcing.
# Once green, edit /etc/systemd/system/ati.service to set
#   --sig-verify-mode enforce
# then `systemctl daemon-reload && systemctl restart ati`.
```

## Files

| Path | Purpose |
|---|---|
| `caddy/Caddyfile` | Thin TLS terminator. No header rewriting; just LE certs + reverse_proxy to ATI on `127.0.0.1:8080`. |
| `manifests/example-passthrough.toml` | Generic passthrough manifest template — clone for each upstream. |
| `systemd/ati.service` | Runs `ati proxy --enable-passthrough --sig-verify-mode log` (flip to `enforce` after soak). |
| `systemd/ati-rotate-keyring.service` + `.timer` | Weekly cron-style rotation. |
| `haproxy/haproxy.cfg.example` | L4 Redis fan-out. Replace `<UPSTREAM_HOST>` per backend. |
| `verdaccio/config.yaml.example` | Local npm registry cache. |

## See also

- `src/core/passthrough.rs` — the handler that consumes these manifests.
- `src/core/sig_verify.rs` — HMAC verification middleware.
- `src/cli/edge.rs` — `bootstrap-keyring` / `rotate-keyring` source.
- Tracking issue: [#94](https://github.com/Parcha-ai/ati/issues/94).
