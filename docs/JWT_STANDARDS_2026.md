# JWT-Based Auth Standards & Best Practices (2025-2026)

**Research Date:** 2026-03-03
**Target Use Case:** Machine-to-Machine (M2M) authentication for AI agent sandboxes

---

## Table of Contents

1. [Core RFC Standards](#core-rfc-standards)
2. [RFC 9068: JWT Profile for OAuth 2.0 Access Tokens](#rfc-9068-jwt-profile-for-oauth-20-access-tokens)
3. [RFC 7519: Core JWT Specification](#rfc-7519-core-jwt-specification)
4. [RFC 8725: JWT Best Current Practices (Security)](#rfc-8725-jwt-best-current-practices-security)
5. [Algorithm Selection (HS256 vs RS256 vs ES256 vs EdDSA)](#algorithm-selection)
6. [JWKS: JSON Web Key Set](#jwks-json-web-key-set)
7. [Token Binding to Clients](#token-binding-to-clients)
8. [Scope Claim Conventions](#scope-claim-conventions)
9. [Audience (aud) Claim for Service-to-Service Auth](#audience-aud-claim-for-service-to-service-auth)
10. [Confirmation (cnf) Claim: Proof-of-Possession](#confirmation-cnf-claim-proof-of-possession)
11. [Token Introspection vs Local Validation](#token-introspection-vs-local-validation)
12. [OWASP Security Guidance](#owasp-security-guidance)
13. [M2M Authentication Best Practices](#m2m-authentication-best-practices)
14. [Implementation Recommendations for ATI](#implementation-recommendations-for-ati)

---

## Core RFC Standards

| RFC | Title | Status | Purpose |
|-----|-------|--------|---------|
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) | JSON Web Token (JWT) | Standard | Core JWT format, claims, validation |
| [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) | JSON Web Key (JWK) | Standard | Key representation format |
| [RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800) | Proof-of-Possession Key Semantics for JWTs | Standard | `cnf` claim for PoP tokens |
| [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) | OAuth 2.0 Mutual-TLS Client Auth | Standard | Certificate-bound tokens |
| [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) | JWT Best Current Practices | BCP 225 | Security considerations |
| [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) | JWT Profile for OAuth 2.0 Access Tokens | Standard | Standard JWT access token format |
| [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) | OAuth 2.0 Demonstrating Proof of Possession (DPoP) | Standard | Application-level token binding |
| [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) | OAuth 2.0 Token Introspection | Standard | Server-side token validation |

**Note:** [draft-ietf-oauth-rfc8725bis-02](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc8725bis/) (November 2025, expires May 2026) is set to obsolete RFC 8725 with additional security guidance.

---

## RFC 9068: JWT Profile for OAuth 2.0 Access Tokens

### Overview

[RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) defines a **standard profile** for issuing OAuth 2.0 access tokens in JWT format. This eliminates the need for token introspection by embedding structured token information directly into a cryptographically signed JWT.

### Key Benefits

- **Interoperability:** Authorization servers and resource servers from different vendors can issue and consume tokens in a standard format
- **Performance:** Eliminates overhead of token introspection via local validation
- **Security:** Strictly mandates that JWT access tokens **MUST NEVER use the `none` algorithm**

### Required Claims (Section 2.2)

RFC 9068 specifies the following claims as **REQUIRED**:

| Claim | RFC 7519 Ref | Description | Format |
|-------|--------------|-------------|--------|
| `iss` | Section 4.1.1 | Issuer - identifies the authorization server | StringOrURI |
| `exp` | Section 4.1.4 | Expiration Time - Unix timestamp | NumericDate |
| `aud` | Section 4.1.3 | Audience - resource server(s) | StringOrURI or array |
| `sub` | Section 4.1.2 | Subject - user or client identifier | StringOrURI |
| `client_id` | RFC 9068 Section 2.2 | OAuth 2.0 client identifier | String |
| `iat` | Section 4.1.6 | Issued At - Unix timestamp | NumericDate |
| `jti` | Section 4.1.7 | JWT ID - unique token identifier | String |

### Optional but Recommended Claims

| Claim | Description |
|-------|-------------|
| `scope` | Space-delimited list of OAuth 2.0 scopes (REQUIRED if scopes were requested) |
| `auth_time` | Time when authentication occurred |
| `acr` | Authentication Context Class Reference |
| `amr` | Authentication Methods References |

### Authorization Attributes (Section 2.2.3.1)

RFC 9068 recommends using claims from [RFC 7643 (SCIM)](https://datatracker.ietf.org/doc/html/rfc7643) for authorization:

- `roles` - User roles (e.g., `["admin", "editor"]`)
- `groups` - User groups (e.g., `["engineering", "security"]`)
- `entitlements` - Fine-grained permissions

### Example RFC 9068-Compliant Token

```json
{
  "iss": "https://authorization-server.example.com/",
  "sub": "5ba552d67",
  "aud": "https://rs.example.com/",
  "exp": 1639528912,
  "iat": 1618354090,
  "jti": "dbe39bf3a3ba4238a513f51d6e1691c4",
  "client_id": "s6BhdRkqt3",
  "scope": "openid profile read:email"
}
```

---

## RFC 7519: Core JWT Specification

### Overview

[RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) defines the base JWT format. **ALL claims are OPTIONAL** - their necessity depends on the application context.

### Registered Claims (All Optional)

| Claim | Section | Description | Validation When Present |
|-------|---------|-------------|-------------------------|
| `iss` | 4.1.1 | Issuer | StringOrURI |
| `sub` | 4.1.2 | Subject | StringOrURI |
| `aud` | 4.1.3 | Audience | MUST reject if recipient not in audience |
| `exp` | 4.1.4 | Expiration Time | MUST reject if current time >= exp |
| `nbf` | 4.1.5 | Not Before | MUST reject if current time < nbf |
| `iat` | 4.1.6 | Issued At | NumericDate |
| `jti` | 4.1.7 | JWT ID (unique identifier) | String |

### Key Validation Rules (Section 7.2)

1. **Duplicate Claims:** Parsers MUST either reject JWTs with duplicate claim names OR return only the lexically last duplicate
2. **Unknown Claims:** Claims not understood by implementations MUST be ignored (unless application requires them)
3. **Case Sensitivity:** Claim names are case-sensitive

---

## RFC 8725: JWT Best Current Practices (Security)

### Overview

[RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) (BCP 225) provides **actionable security guidance** for JWT implementations. A new draft ([rfc8725bis](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc8725bis/), November 2025) adds guidance on threats discovered since RFC 8725 was published.

### Critical Security Requirements

#### 1. Algorithm Protection (Section 3.1)

- **MUST explicitly validate `alg` header** - do NOT trust the JWT header to select the verification algorithm
- **MUST reject `"alg": "none"`** in production
- **Prevent algorithm confusion attacks:** Ensure RS256 tokens cannot be validated as HS256

#### 2. Token Validation (Section 3.2)

Always validate these claims:
- `iss` (issuer) - verify against trusted issuer list
- `aud` (audience) - verify token is intended for your service
- `exp` (expiration) - reject expired tokens
- `nbf` (not before) - reject tokens used too early

#### 3. Token Lifetime (Section 3.3)

- **Keep lifetimes SHORT:** Minutes to hours, NOT days/months
- **Refresh tokens** for long-running sessions
- Expired tokens are the #1 defense against token theft

#### 4. Key Management (Section 3.4)

- **Use strong keys:** ≥256 bits for HMAC, ≥2048 bits for RSA
- **Rotate keys regularly**
- **Use `kid` (key ID)** in JWK for key identification

#### 5. Content Security (Section 3.5)

- **JWTs are NOT encrypted by default** - they are base64-encoded and readable
- **Use JWE (JSON Web Encryption)** if tokens contain sensitive data
- **Do NOT put secrets in claims** unless using JWE

#### 6. New Guidance in RFC 8725bis (2025)

- **Limit decompressed JWE size** to ~250 KB to prevent decompression bombs
- **Strict JSON validation:** Reject content with unexpected braces/quotes

---

## Algorithm Selection

### 2026 Recommendation Hierarchy (for M2M Auth)

Based on current best practices, here's the recommended algorithm selection:

| Algorithm | Security | Performance | Key Management | Use Case | 2026 Status |
|-----------|----------|-------------|----------------|----------|-------------|
| **EdDSA** | Best | Best (62x faster than RSA-2048 signing) | Simple | Modern systems, high-performance APIs | **RECOMMENDED** |
| **ES256** | Excellent | Very Good (14x faster than RSA-2048 signing) | Moderate | Mobile, IoT, constrained devices | **GOOD CHOICE** |
| **RS256** | Good | Moderate | Complex | Legacy compatibility, broad support | **WIDELY SUPPORTED** |
| **HS256** | Good (if secret protected) | Fast | Simple (symmetric) | Internal systems only | **NOT RECOMMENDED for M2M** |

### Detailed Algorithm Analysis

#### EdDSA (Edwards Curve Digital Signature Algorithm)

**Algorithms:** `EdDSA` with Ed25519 curve

**Pros:**
- Fastest signing/verification performance (62x faster than RSA-2048)
- Smaller keys (256-bit equivalent to 3072-bit RSA security)
- Easier to implement securely (resistant to timing attacks)
- Modern cryptographic standard

**Cons:**
- Newer standard - may have less library support in older systems

**2026 Recommendation:** **BEST CHOICE** for new M2M systems

#### ES256 (ECDSA with P-256 Curve)

**Algorithms:** `ES256` (P-256), `ES384` (P-384), `ES512` (P-521)

**Pros:**
- Excellent performance (14x faster than RSA-2048)
- Strong security with smaller keys (256-bit ≈ 3072-bit RSA)
- Good mobile/IoT support
- Widely supported in modern libraries

**Cons:**
- Slightly more complex than EdDSA
- Requires careful implementation to avoid side-channel attacks

**2026 Recommendation:** **GOOD CHOICE** for distributed systems, especially with constrained devices

#### RS256 (RSA with SHA-256)

**Algorithms:** `RS256`, `RS384`, `RS512`

**Pros:**
- Most widely supported (every decent JWT library supports it)
- Based on RSA PKCS #1 standard
- Non-repudiation guarantee (only private key holder can sign)
- Best for public APIs where broad compatibility is critical

**Cons:**
- Slower performance than ECDSA/EdDSA
- Larger keys (≥2048 bits recommended, ≥3072 bits for high security)

**2026 Recommendation:** **SAFE CHOICE** for maximum compatibility

#### HS256 (HMAC with SHA-256)

**Algorithms:** `HS256`, `HS384`, `HS512`

**Pros:**
- Fast signing/verification
- Simple implementation (symmetric key)

**Cons:**
- **Symmetric key** - any service that validates tokens can also create tokens
- Compromise of ANY service compromises ALL services sharing the key
- Cannot provide non-repudiation
- Not suitable for distributed M2M where services don't mutually trust

**2026 Recommendation:** **AVOID for M2M** - only use for internal systems where all services are equally trusted

### OWASP Guidance on Algorithm Selection

From [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html):

> For machine-to-machine scenarios, signatures should be preferred over MACs for integrity protection. MACs mean every service that validates JWTs can also create new JWTs using the same key, requiring mutual trust between all services. A compromise of any service compromises all others sharing the same key.

### Key Size Recommendations (RFC 8725 Section 3.2)

| Algorithm | Minimum Key Size | Recommended Key Size |
|-----------|------------------|---------------------|
| HMAC | 256 bits | 256+ bits |
| RSA | 2048 bits | 3072+ bits |
| ECDSA P-256 | 256 bits | 256 bits |
| EdDSA Ed25519 | 256 bits | 256 bits |

---

## JWKS: JSON Web Key Set

### Overview

**JWKS** ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) is the **standard way** to distribute public keys for JWT validation in 2026. It enables key rotation without service reconfiguration.

### JWKS Format

A JWKS is a JSON object with a `keys` array containing one or more JWKs:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "2024-11-key-001",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuu...",
      "e": "AQAB"
    },
    {
      "kty": "EC",
      "kid": "2024-11-key-002",
      "use": "sig",
      "alg": "ES256",
      "crv": "P-256",
      "x": "WKn-ZIGevcwG...",
      "y": "Tq5Qn9yWPEsH..."
    }
  ]
}
```

### Required JWK Members

| Member | Description | Example |
|--------|-------------|---------|
| `kty` | Key Type | `"RSA"`, `"EC"`, `"OKP"` (EdDSA) |
| `kid` | Key ID (for matching JWT header) | `"2024-11-key-001"` |
| `use` | Public Key Use | `"sig"` (signature), `"enc"` (encryption) |
| `alg` | Algorithm | `"RS256"`, `"ES256"`, `"EdDSA"` |

### How JWKS Works

1. **Publish:** Authorization server hosts JWKS at a well-known URL (e.g., `https://auth.example.com/.well-known/jwks.json`)
2. **Fetch:** Resource server fetches JWKS periodically (e.g., hourly) and caches it
3. **Validate:** When a JWT arrives with `kid: "2024-11-key-001"`, resource server looks up that key in cached JWKS and validates signature
4. **Rotate:** To rotate keys, authorization server adds new key to JWKS, starts issuing tokens with new `kid`, keeps old key in JWKS until old tokens expire, then removes old key

### Best Practices (2026)

- **Always serve JWKS over HTTPS** (required for security)
- **Use stable `kid` values** for easier rotation tracking
- **Implement refresh strategy:**
  - Periodic refresh (e.g., every hour)
  - Refresh on verification failure (unknown `kid`)
- **Cache JWKS** for hours/days to minimize latency
- **Support multiple keys** in JWKS for graceful rotation

### JWKS Validation Workflow

```
1. JWT arrives with header: {"alg": "RS256", "kid": "2024-11-key-001"}
2. Resource server checks cached JWKS for key with kid="2024-11-key-001"
3. If found: validate signature using that public key
4. If not found: refresh JWKS from authorization server, retry validation
5. If still not found: reject token (unknown key)
```

---

## Token Binding to Clients

Token binding ensures a token can only be used by the client it was issued to. Three main approaches:

### 1. RFC 8705: Mutual TLS Certificate Binding

[RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) binds tokens to X.509 client certificates using the `cnf` (confirmation) claim.

#### How It Works

1. Client connects to authorization server using **mutual TLS** with client certificate
2. Authorization server issues JWT with `cnf` claim containing certificate thumbprint:
   ```json
   {
     "iss": "https://auth.example.com",
     "sub": "client123",
     "aud": "https://api.example.com",
     "exp": 1639528912,
     "cnf": {
       "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"
     }
   }
   ```
3. Resource server validates JWT, extracts `x5t#S256` from `cnf` claim
4. Resource server verifies client's TLS certificate matches the thumbprint

#### x5t#S256 Format

- **SHA-256 hash** of the DER-encoded X.509 certificate
- Base64url-encoded
- Defined in RFC 8705 Section 3.1

#### Pros/Cons

**Pros:**
- Strong cryptographic binding
- Works at TLS layer (transparent to application)
- Prevents token theft (stolen token useless without certificate)

**Cons:**
- Requires mTLS infrastructure
- Certificate management complexity
- Not suitable for browser-based clients

**Use Case:** Internal service-to-service communication with PKI infrastructure

### 2. RFC 9449: DPoP (Demonstrating Proof-of-Possession)

[RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) provides **application-level** proof-of-possession without requiring TLS client certificates.

#### How It Works

1. Client generates a public/private key pair
2. Client requests token from authorization server, includes `DPoP` header with signed proof:
   ```
   DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik...
   ```
3. Authorization server issues JWT with `cnf` claim containing public key thumbprint:
   ```json
   {
     "iss": "https://auth.example.com",
     "sub": "client123",
     "aud": "https://api.example.com",
     "exp": 1639528912,
     "cnf": {
       "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
     }
   }
   ```
4. Client includes **both** access token and fresh `DPoP` proof in every API request
5. Resource server validates both JWT and DPoP proof

#### DPoP Proof JWT

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
  }
}
.
{
  "jti": "e1j3V_bKic8-SDHJfyiYmg",
  "htm": "POST",
  "htu": "https://api.example.com/resource",
  "iat": 1562262616,
  "ath": "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
}
```

**Key fields:**
- `jwk` - public key
- `htm` - HTTP method
- `htu` - HTTP URI (without query/fragment)
- `ath` - hash of access token (binds proof to token)

#### Pros/Cons

**Pros:**
- Works without mTLS (browser-compatible)
- Prevents token replay attacks
- Application-level (no TLS infrastructure changes)

**Cons:**
- Requires client to generate and manage key pair
- More complex than simple Bearer tokens
- Adds `DPoP` header to every request

**Use Case:** Public APIs, browser-based apps, mobile apps

### 3. Simple Client ID Binding (Not Cryptographic)

For less critical scenarios, bind tokens to `client_id` claim without cryptographic proof:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user123",
  "aud": "https://api.example.com",
  "exp": 1639528912,
  "client_id": "mobile-app-v2"
}
```

Resource server validates `client_id` matches the expected client for the request context.

**Pros:** Simple, no crypto overhead
**Cons:** Not cryptographically secure, vulnerable to token theft

---

## Scope Claim Conventions

### RFC 9068 Standard (Section 2.2.3)

RFC 9068 standardizes the `scope` claim for OAuth 2.0 scopes:

- **Claim name:** `scope` (singular, not `scopes`)
- **Format:** Space-delimited string (NOT array)
- **Example:** `"scope": "read:messages write:messages admin:users"`

```json
{
  "iss": "https://auth.example.com",
  "sub": "client123",
  "aud": "https://api.example.com",
  "exp": 1639528912,
  "scope": "openid profile email read:calendar write:calendar"
}
```

### Authorization Attributes (RFC 7643)

For more structured permissions, RFC 9068 recommends using **RFC 7643 (SCIM)** attributes:

#### `roles` Claim

Array of role names:

```json
{
  "roles": [
    {"value": "admin", "display": "Administrator"},
    {"value": "editor", "display": "Content Editor"}
  ]
}
```

#### `groups` Claim

Array of group identifiers:

```json
{
  "groups": [
    {"value": "engineering", "display": "Engineering Team"},
    {"value": "security", "display": "Security Team"}
  ]
}
```

#### `entitlements` Claim

Array of fine-grained permissions:

```json
{
  "entitlements": [
    {"value": "user:read", "display": "Read user data"},
    {"value": "user:write", "display": "Write user data"},
    {"value": "admin:billing", "display": "Manage billing"}
  ]
}
```

### Custom Permission Claim Patterns

While RFC 9068 standardizes `scope`, many implementations use custom claim names:

| Provider | Claim Name | Format |
|----------|------------|--------|
| Auth0 | `scope` + `permissions` | `scope`: string, `permissions`: array |
| Azure AD | `scp` (user) or `roles` (app) | Space-delimited string |
| Okta | `scp` | Array of strings |
| AWS Cognito | `cognito:groups` | Array of strings |

**Recommendation:** Use RFC 9068's `scope` claim for OAuth 2.0 scopes, and `roles`/`groups`/`entitlements` for application-specific permissions.

---

## Audience (aud) Claim for Service-to-Service Auth

### Purpose

The `aud` (audience) claim identifies the **resource server(s)** that the token is intended for. This prevents **token substitution attacks** where a token issued for Service A is used to access Service B.

### RFC 7519 Definition (Section 4.1.3)

> The "aud" (audience) claim identifies the recipients that the JWT is intended for. Each principal intended to process the JWT MUST identify itself with a value in the audience claim. If the principal processing the claim does not identify itself with a value in the "aud" claim when this claim is present, then the JWT MUST be rejected.

### Format

- **Single audience:** String
- **Multiple audiences:** Array of strings

```json
{
  "aud": "https://api.example.com"
}
```

```json
{
  "aud": ["https://api.example.com", "https://api2.example.com"]
}
```

### RFC 9068 Requirements (Section 2.2.2)

> The resource server MUST validate that the "aud" claim contains a resource indicator value corresponding to an identifier the resource server expects for itself.

### Best Practices for Service-to-Service Auth

#### 1. Use Specific Resource Identifiers

**Good:**
```json
{
  "aud": "https://api.payments.example.com"
}
```

**Bad (too broad):**
```json
{
  "aud": "example.com"
}
```

#### 2. Validate Audience on Every Request

```rust
fn validate_token(token: &Jwt, expected_audience: &str) -> Result<(), Error> {
    let audiences = token.claims.aud.as_array()?;
    if !audiences.contains(&expected_audience) {
        return Err(Error::InvalidAudience);
    }
    Ok(())
}
```

#### 3. Use Service-Specific Audience Values

For M2M auth, `aud` should identify the **API/service**, not the client:

```json
{
  "iss": "https://auth.example.com",
  "sub": "service-account-123",
  "aud": "https://api.example.com",
  "client_id": "backend-worker-v2",
  "scope": "read:data write:data"
}
```

#### 4. Zero Trust: Validate Even Internal Traffic

> Assume zero trust, even for internal traffic and service-to-service communication.

Always validate `aud` even for internal services to prevent lateral movement in case of compromise.

### Attack Scenario Without Audience Validation

1. Attacker compromises Service A
2. Service A has a valid token for accessing Service B
3. Without `aud` validation, attacker uses Service A's token to access Service C (unintended)
4. With `aud` validation, Service C rejects the token (wrong audience)

---

## Confirmation (cnf) Claim: Proof-of-Possession

### Overview

The `cnf` (confirmation) claim ([RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800)) binds a JWT to a **cryptographic key** held by the presenter. This enables **proof-of-possession (PoP) tokens**.

### Format

```json
{
  "cnf": {
    "jwk": { ... },        // Embedded JWK (not recommended - leaks public key)
    "jwe": "...",          // Encrypted JWK
    "jku": "https://...",  // JWK Set URL
    "x5t#S256": "...",     // X.509 certificate thumbprint (RFC 8705)
    "jkt": "..."           // JWK thumbprint (DPoP, RFC 9449)
  }
}
```

**Rule:** At most ONE confirmation method should be present.

### Use Case 1: Certificate-Bound Tokens (RFC 8705)

For mTLS-based M2M auth:

```json
{
  "iss": "https://auth.example.com",
  "sub": "service-account-123",
  "aud": "https://api.example.com",
  "exp": 1639528912,
  "cnf": {
    "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"
  }
}
```

**Validation:**
1. Extract `x5t#S256` from `cnf` claim
2. Compute SHA-256 hash of client's TLS certificate (DER-encoded)
3. Verify hash matches `x5t#S256` value

### Use Case 2: DPoP Tokens (RFC 9449)

For application-level proof-of-possession:

```json
{
  "iss": "https://auth.example.com",
  "sub": "service-account-123",
  "aud": "https://api.example.com",
  "exp": 1639528912,
  "cnf": {
    "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
  }
}
```

**Validation:**
1. Extract `jkt` from access token's `cnf` claim
2. Extract `jwk` from `DPoP` proof JWT header
3. Compute SHA-256 hash of `jwk` (thumbprint)
4. Verify thumbprint matches `jkt` value
5. Verify `DPoP` proof signature using `jwk`
6. Verify `ath` claim in `DPoP` proof matches access token hash

### Relevant for Agent Sandboxes?

**Yes, if you want to prevent token exfiltration:**

- Agent sandbox generates ephemeral key pair on startup
- Tokens issued to that sandbox include `cnf` with key thumbprint
- Even if token is stolen, attacker cannot use it (lacks private key)

**Trade-offs:**
- Adds complexity (key generation, proof generation)
- Requires changes to both authorization server and resource server
- May be overkill for low-risk environments

**Recommendation:** Start without `cnf`, add later if token theft becomes a threat.

---

## Token Introspection vs Local Validation

### Local JWT Validation (JWKS)

#### How It Works

1. Resource server fetches JWKS from authorization server (cached for hours/days)
2. When JWT arrives, resource server validates signature locally using cached JWKS
3. No network call needed for each request (after JWKS is cached)

#### Pros

- **Fast:** No network latency
- **Scalable:** No bottleneck on authorization server
- **Decentralized:** Resource server doesn't depend on authorization server being online

#### Cons

- **No real-time revocation:** Cannot immediately revoke tokens (must wait for expiration)
- **Larger token size:** JWTs are larger than opaque tokens (~1-2 KB)
- **Key rotation complexity:** Must ensure JWKS stays in sync

#### When to Use

- High-throughput APIs
- Distributed systems
- When token lifetime is short (minutes to hours)
- When revocation is not time-critical

### Token Introspection (RFC 7662)

#### How It Works

1. Resource server receives opaque token
2. Resource server sends token to authorization server's introspection endpoint
3. Authorization server responds with token metadata (active, exp, scope, etc.)

**Introspection Request:**
```http
POST /introspect HTTP/1.1
Host: auth.example.com
Authorization: Bearer <resource-server-token>
Content-Type: application/x-www-form-urlencoded

token=<opaque-token>
```

**Introspection Response:**
```json
{
  "active": true,
  "scope": "read:data write:data",
  "client_id": "backend-worker",
  "exp": 1639528912,
  "iat": 1639525312,
  "sub": "service-account-123",
  "aud": "https://api.example.com"
}
```

#### Pros

- **Real-time revocation:** Authorization server can immediately mark tokens as inactive
- **Opaque tokens:** Smaller token size, no information leakage
- **Centralized control:** All validation logic in authorization server

#### Cons

- **Latency:** Network round-trip for every request (or cache with TTL)
- **Scalability bottleneck:** Authorization server must handle introspection load
- **Availability coupling:** Resource server depends on authorization server being online

#### When to Use

- Opaque tokens (cannot validate locally)
- When real-time revocation is critical
- Low-to-medium throughput APIs
- Zero-trust architectures

### Hybrid Approach

**Best of both worlds:**

1. Use JWTs with local validation for most requests
2. Periodically introspect to check for revocation (e.g., every 100 requests or every 5 minutes)
3. For sensitive operations, always introspect

```rust
fn validate_token(token: &str, cache: &mut TokenCache) -> Result<Claims, Error> {
    // 1. Validate JWT signature locally
    let claims = jwt::decode(token)?;

    // 2. Check if we've recently introspected this token
    if let Some(cached) = cache.get(token) {
        if cached.timestamp.elapsed() < Duration::from_secs(300) { // 5 min TTL
            return Ok(claims);
        }
    }

    // 3. Introspect to check for revocation
    let introspection = introspect_token(token)?;
    if !introspection.active {
        return Err(Error::TokenRevoked);
    }

    cache.insert(token, Cached { timestamp: Instant::now() });
    Ok(claims)
}
```

---

## OWASP Security Guidance

### Key Recommendations from OWASP JWT Cheat Sheet

From [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html):

#### 1. Algorithm Validation

> The relying party MUST verify JWT integrity based on its own configuration or hard-coded logic and MUST NOT rely on the JWT header information to select the verification algorithm.

**Implementation:**
```rust
// GOOD: Explicitly specify allowed algorithms
let validation = Validation::new(Algorithm::RS256);
jwt::decode(token, &decoding_key, &validation)?;

// BAD: Trust algorithm from token header
// let validation = Validation::from_header(token); // DON'T DO THIS
```

#### 2. Reject "none" Algorithm

> JWTs must be integrity protected by either a signature or MAC, and unsecured JWTs with `"alg":"none"` should not be allowed.

#### 3. Use Asymmetric Algorithms for M2M

> For machine-to-machine scenarios, signatures should be preferred over MACs for integrity protection. MACs mean every service that validates JWTs can also create new JWTs using the same key, requiring mutual trust between all services. A compromise of any service compromises all others sharing the same key.

#### 4. Short Token Lifetime

> JWT expiration should be set to minutes or hours at maximum, avoiding access tokens valid for days or months.

**Recommendations:**
- M2M tokens: 5-60 minutes
- User sessions: 15-60 minutes (with refresh tokens)
- Long-running jobs: Auto re-authentication

#### 5. Validate Standard Claims

Always validate:
- `iss` (issuer) - against trusted issuer list
- `aud` (audience) - verify token is for your service
- `exp` (expiration) - reject expired tokens
- `nbf` (not before) - reject tokens used too early

#### 6. Encryption for Sensitive Data

> JWTs are base64 encoded but not encrypted by default, so attackers can extract information like security roles. Encryption using symmetric algorithms can protect against this.

**Options:**
- Use JWE (JSON Web Encryption) for sensitive claims
- Store sensitive data server-side (reference by `jti` or `sub`)
- Minimize claims in JWT

---

## M2M Authentication Best Practices

### 2026 Industry Standards

From [Stytch M2M Guide](https://stytch.com/blog/the-complete-guide-to-m2m-auth/), [Authgear M2M Guide](https://www.authgear.com/post/the-complete-guide-to-machine-to-machine-m2m-authentication), and other current sources:

#### 1. OAuth 2.0 Client Credentials Flow

**The most common, standards-based pattern:**

1. Service A authenticates to authorization server with `client_id` + `client_secret`
2. Authorization server issues short-lived JWT access token
3. Service A includes token in requests to Service B
4. Service B validates token (locally or via introspection)

```http
POST /oauth/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=backend-worker
&client_secret=<secret>
&scope=read:data write:data
&audience=https://api.example.com
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read:data write:data"
}
```

#### 2. Token Lifetime Strategy

- **Short lifetime tokens:** 5-60 minutes
- **Auto re-authentication:** Request fresh token when current one expires
- **Pre-emptive refresh:** Refresh token before expiration (e.g., at 80% of lifetime)

```rust
struct TokenManager {
    token: Option<String>,
    expires_at: Option<Instant>,
}

impl TokenManager {
    async fn get_token(&mut self) -> Result<String, Error> {
        // Refresh if token is missing or expires in <5 minutes
        if self.token.is_none() || self.expires_at.unwrap() - Instant::now() < Duration::from_secs(300) {
            let response = self.fetch_token().await?;
            self.token = Some(response.access_token);
            self.expires_at = Some(Instant::now() + Duration::from_secs(response.expires_in));
        }
        Ok(self.token.clone().unwrap())
    }
}
```

#### 3. Algorithm Selection

**Recommendation:** **EdDSA or ES256** for new M2M systems

- Enables **local validation** via JWKS (no introspection needed)
- **Non-repudiation:** Only authorization server can issue tokens
- **Key rotation:** Add new key to JWKS, start using it, remove old key after TTL

#### 4. Scope Management

Use **least-privilege scopes:**

```json
{
  "client_id": "analytics-worker",
  "scope": "read:events read:users"
}
```

Not:
```json
{
  "client_id": "analytics-worker",
  "scope": "admin:*"
}
```

#### 5. Key Rotation Strategy

From [Stytch Key Rotation Guide](https://stytch.com/blog/the-complete-guide-to-m2m-auth/):

1. **Introduce new key:** Add to JWKS with new `kid`, don't issue tokens yet
2. **Wait for propagation:** Allow time for resource servers to fetch updated JWKS (e.g., 1 hour)
3. **Start using new key:** Begin issuing tokens with new `kid`
4. **Keep old key:** Continue serving old key in JWKS until all old tokens expire
5. **Remove old key:** After `max_token_lifetime` has passed, remove old key from JWKS

#### 6. Secret Management

**Store `client_secret` securely:**
- Environment variables (not hardcoded)
- Secret management services (Vault, AWS Secrets Manager, etc.)
- Hardware security modules (HSMs) for high security

**The `client_secret` is only stored and managed in one place**, centralizing secret management while maintaining distributed authorization using short-lived, verifiable tokens.

#### 7. Service Account Design

Create **dedicated service accounts** per service:

```json
{
  "service_accounts": [
    {
      "client_id": "analytics-worker",
      "name": "Analytics Data Processor",
      "scopes": ["read:events", "read:users"]
    },
    {
      "client_id": "backup-service",
      "name": "Database Backup Service",
      "scopes": ["read:database"]
    }
  ]
}
```

Not:
```json
{
  "service_accounts": [
    {
      "client_id": "admin-service",
      "scopes": ["*"]
    }
  ]
}
```

---

## Implementation Recommendations for ATI

Based on the research above, here are specific recommendations for implementing JWT-based auth in ATI's proxy server for agent sandboxes:

### 1. Token Structure (RFC 9068-Compliant)

```json
{
  "iss": "https://proxy.ati.example.com",
  "sub": "sandbox-abc123",
  "aud": "https://proxy.ati.example.com",
  "exp": 1639528912,
  "iat": 1639525312,
  "jti": "token-uuid-1234",
  "client_id": "sandbox-abc123",
  "scope": "tool:github__search_repositories tool:linear__create_issue"
}
```

**Required claims:**
- `iss`: ATI proxy URL
- `sub`: Sandbox identifier
- `aud`: ATI proxy URL (validates token is for this proxy)
- `exp`: Short lifetime (15-60 minutes)
- `iat`: Issued timestamp
- `jti`: Unique token ID (for revocation tracking)
- `client_id`: Sandbox identifier (same as `sub` for service accounts)
- `scope`: Space-delimited list of allowed tools (using `tool:` prefix)

**Optional but recommended:**
- `cnf`: If implementing proof-of-possession (future enhancement)
- `nbf`: Not-before timestamp (if tokens are issued for future use)

### 2. Algorithm Selection

**Recommendation: ES256 (ECDSA P-256)**

**Why:**
- Better performance than RS256 (14x faster signing)
- Smaller keys than RSA (256-bit ≈ 3072-bit RSA security)
- Well-supported in Rust ecosystem (`jsonwebtoken` crate)
- Good balance of security, performance, and compatibility

**Alternative: EdDSA (if library support is good)**

**Why:**
- Best performance (62x faster than RSA)
- Modern standard
- May have less library support in older systems (not a concern for ATI)

**Implementation:**
```rust
use jsonwebtoken::{Algorithm, EncodingKey, DecodingKey};

// Generate ES256 key pair
let encoding_key = EncodingKey::from_ec_pem(private_key_pem)?;
let decoding_key = DecodingKey::from_ec_pem(public_key_pem)?;

let header = Header::new(Algorithm::ES256);
let token = encode(&header, &claims, &encoding_key)?;
```

### 3. JWKS Endpoint

**Implement JWKS endpoint for key distribution:**

```rust
#[get("/.well-known/jwks.json")]
async fn jwks(state: web::Data<ProxyState>) -> Result<Json<JwkSet>, Error> {
    Ok(Json(state.jwks.clone()))
}
```

**JWKS format:**
```json
{
  "keys": [
    {
      "kty": "EC",
      "kid": "2026-03-ati-001",
      "use": "sig",
      "alg": "ES256",
      "crv": "P-256",
      "x": "WKn-ZIGevcwGIyyrzFiyT...",
      "y": "Tq5Qn9yWPEsHavck9FU2..."
    }
  ]
}
```

### 4. Token Validation

```rust
use jsonwebtoken::{decode, Validation, Algorithm};

fn validate_token(token: &str, state: &ProxyState) -> Result<Claims, Error> {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["https://proxy.ati.example.com"]);
    validation.set_issuer(&["https://proxy.ati.example.com"]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);

    let token_data = decode::<Claims>(token, &state.decoding_key, &validation)?;

    // Additional checks
    if !token_data.claims.jti.is_empty() {
        // Check if token is revoked (query revocation list)
        if state.revocation_list.contains(&token_data.claims.jti) {
            return Err(Error::TokenRevoked);
        }
    }

    Ok(token_data.claims)
}
```

### 5. Scope Encoding

Use **space-delimited string** format (RFC 9068):

```json
{
  "scope": "tool:github__search_repositories tool:linear__create_issue provider:github category:project-management"
}
```

**Validation:**
```rust
fn check_scope(token: &Claims, required_tool: &str) -> Result<(), Error> {
    let scopes: HashSet<_> = token.scope.split_whitespace().collect();

    // Check exact tool scope
    if scopes.contains(&format!("tool:{}", required_tool)) {
        return Ok(());
    }

    // Check provider scope (e.g., tool:github__* matches provider:github)
    let provider = required_tool.split("__").next().unwrap();
    if scopes.contains(&format!("provider:{}", provider)) {
        return Ok(());
    }

    // Check category scope
    // ... (lookup tool -> category mapping)

    Err(Error::InsufficientScope)
}
```

### 6. Token Lifetime

**Recommendation: 30 minutes**

**Why:**
- Short enough to limit damage from token theft
- Long enough to avoid frequent re-authentication
- Aligns with typical agent session duration

**Implementation:**
```rust
let claims = Claims {
    iss: "https://proxy.ati.example.com".to_string(),
    sub: sandbox_id.clone(),
    aud: "https://proxy.ati.example.com".to_string(),
    exp: (Utc::now() + Duration::minutes(30)).timestamp() as usize,
    iat: Utc::now().timestamp() as usize,
    jti: Uuid::new_v4().to_string(),
    client_id: sandbox_id,
    scope: scopes.join(" "),
};
```

### 7. Token Issuance

**Option A: Session Key File (current approach)**

Keep current `/run/ati/.key` one-shot session key approach, but **encode scopes in JWT** instead of separate `scopes.json`:

1. User runs `ati auth --scope tool:github__search_repositories --ttl 30m`
2. ATI generates JWT with scopes, writes to `/run/ati/.key`
3. Agent reads JWT from `/run/ati/.key` (or ATI reads and validates it)
4. JWT is validated on every `ati run`

**Option B: Proxy-Issued Tokens**

1. User starts proxy: `ati proxy --port 8090`
2. Agent authenticates to proxy (initial auth mechanism TBD)
3. Proxy issues JWT to agent
4. Agent includes JWT in every request: `Authorization: Bearer <jwt>`
5. Proxy validates JWT and extracts scopes

### 8. Key Management

**Generate key pair on proxy startup:**

```rust
use openssl::ec::{EcKey, EcGroup};
use openssl::nid::Nid;

// Generate ES256 key pair
let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
let ec_key = EcKey::generate(&group)?;
let private_key_pem = ec_key.private_key_to_pem()?;
let public_key_pem = ec_key.public_key_to_pem()?;

// Derive JWKS
let jwks = generate_jwks(&public_key_pem, "2026-03-ati-001")?;
```

**Key rotation strategy (future):**
1. Generate new key, add to JWKS with new `kid`
2. Issue new tokens with new `kid`
3. Keep old key in JWKS for 30 minutes (token TTL)
4. Remove old key after 30 minutes

### 9. Revocation

**Option A: Short TTL + No Revocation**
- Token lifetime = 30 minutes
- No revocation needed (tokens expire quickly)
- Simple, scalable

**Option B: Revocation List (jti-based)**
- Track revoked `jti` values in Redis/memory
- Check revocation list on every request
- Expire revoked `jti` from list after token `exp`

```rust
use std::collections::HashSet;
use std::sync::RwLock;

struct RevocationList {
    revoked: RwLock<HashSet<String>>, // jti values
}

impl RevocationList {
    fn revoke(&self, jti: String, exp: u64) {
        self.revoked.write().unwrap().insert(jti);
        // Schedule removal after exp timestamp
    }

    fn is_revoked(&self, jti: &str) -> bool {
        self.revoked.read().unwrap().contains(jti)
    }
}
```

### 10. Migration Path

**Phase 1: Add JWT Support (Backward Compatible)**
- Generate ES256 key pair on proxy startup
- Implement `/call` endpoint JWT validation (optional for now)
- Support both session key file and JWT authentication

**Phase 2: Encode Scopes in JWT**
- Migrate `scopes.json` to JWT `scope` claim
- Session key file becomes JWT file
- Keep existing scope resolution logic, read scopes from JWT

**Phase 3: Proxy-Issued Tokens**
- Implement token issuance endpoint
- Agents authenticate and receive JWT
- Deprecate session key file approach

---

## Sources

### RFC Documents

- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 7643 - SCIM Core Schema (roles, groups, entitlements)](https://datatracker.ietf.org/doc/html/rfc7643)
- [RFC 7662 - OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 7800 - Proof-of-Possession Key Semantics for JWTs](https://datatracker.ietf.org/doc/html/rfc7800)
- [RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication](https://datatracker.ietf.org/doc/html/rfc8705)
- [RFC 8725 - JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [RFC 9068 - JWT Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)
- [RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [draft-ietf-oauth-rfc8725bis - JWT Best Current Practices (2025 Update)](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc8725bis/)

### Standards Organizations

- [OAuth.net - JWT Access Tokens](https://oauth.net/2/jwt-access-tokens/)
- [OpenID Foundation - JSON Web Key Specs](https://openid.net/specs/draft-jones-json-web-key-03.html)

### Industry Best Practices

- [Curity - JWT Security Best Practices](https://curity.io/resources/learn/jwt-best-practices/)
- [Curity - DPoP Overview](https://curity.io/resources/learn/dpop-overview/)
- [Curity - OAuth Certificate-Bound Access Tokens](https://curity.io/resources/learn/oauth-certificate-bound-access-token/)
- [Scott Brady - JWTs: Which Signing Algorithm Should I Use?](https://www.scottbrady.io/jose/jwts-which-signing-algorithm-should-i-use)
- [WorkOS - HMAC vs RSA vs ECDSA for JWT Signing](https://workos.com/blog/hmac-vs-rsa-vs-ecdsa-which-algorithm-should-you-use-to-sign-jwts)
- [Auth0 - RS256 vs HS256](https://auth0.com/blog/rs256-vs-hs256-whats-the-difference/)
- [Auth0 - How RFC 9068 Became a Standard](https://auth0.com/blog/how-the-jwt-profile-for-oauth-20-access-tokens-became-rfc9068)
- [Auth0 - Access Token Profiles](https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles)
- [Auth0 - JSON Web Key Sets](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets)
- [Auth0 - Demonstrating Proof-of-Possession (DPoP)](https://auth0.com/docs/secure/sender-constraining/demonstrating-proof-of-possession-dpop)

### M2M Authentication Guides

- [Stytch - Complete Guide to M2M Auth](https://stytch.com/blog/the-complete-guide-to-m2m-auth/)
- [Authgear - Complete Guide to M2M Authentication](https://www.authgear.com/post/the-complete-guide-to-machine-to-machine-m2m-authentication)
- [Authgear - JWKS Explained](https://www.authgear.com/post/what-is-jwks)
- [Authgear - DPoP Complete Guide](https://www.authgear.com/post/demonstrating-proof-of-possession-dpop)
- [Descope - How to Use JWT aud Claim Securely](https://www.descope.com/blog/post/jwt-aud-claim)
- [Scalekit - RFC 9068 JWT Structure](https://www.scalekit.com/blog/json-web-token-rfc9068)
- [Scalekit - OAuth 2.0 Token Introspection (RFC 7662)](https://www.scalekit.com/blog/oauth-2-0-token-introspection-rfc-7662)
- [Scalekit - API Key vs JWT for B2B SaaS](https://www.scalekit.com/blog/apikey-jwt-comparison)

### Security Resources

- [OWASP - JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP - REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [Red Sentry - JWT Vulnerabilities List 2026](https://redsentry.com/resources/blog/jwt-vulnerabilities-list-2026-security-risks-mitigation-guide)
- [PortSwigger - Algorithm Confusion Attacks](https://portswigger.net/web-security/jwt/algorithm-confusion)

### Technical Implementations

- [Medium - RFC 9068: A JWT-Based OAuth2 Access Token Format Standard](https://medium.com/@robert.broeckelmann/rfc-9068-a-jwt-based-oauth2-access-token-format-671d8e13acb4)
- [Authlib - RFC 9068 Documentation](https://docs.authlib.org/en/latest/specs/rfc9068.html)
- [Dapr - JSON Web Key Sets](https://docs.dapr.io/reference/components-reference/supported-cryptography/json-web-key-sets/)
- [DEV Community - JWKS vs Token Introspection](https://dev.to/mechcloud_academy/choosing-between-jwks-and-token-introspection-for-oauth-20-token-validation-1h9d)

---

**Document Version:** 1.0
**Last Updated:** 2026-03-03
**Maintained By:** ATI Team
