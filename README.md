# API Encryption Decryption Policy

## 1. Overview

A MuleSoft Omni(Flex) Gateway custom policy that transparently **encrypts and decrypts HTTP request and response bodies** using **AES‑256‑CBC**. It sits as an inbound policy on the Omni(Flex) Gateway, in the data path of every API call to the protected API instance, and transforms the body on either leg (request → upstream, upstream → client) independently.

The AES key is **fetched at request time** from **AWS Secrets Manager**, cached locally in Flex memory for a configurable TTL, and keyed per client via the `Source` request header — so the same policy instance can serve many clients with isolated keys.

**Why:** Enterprises that terminate TLS at the gateway often still need the body to be at‑rest‑encrypted on the client side, on the upstream side, or both — for compliance (RBI, PCI‑DSS, HIPAA, DPDPA), for cross‑region transport, or when integrating with legacy systems that already speak AES. Doing this at the gateway keeps the client and backend simple: neither has to know the other is encrypting.

**Policy name in Anypoint Exchange:** `API Encryption Decryption Policy`
**Current version:** `1.0.3`

> ⚠️ **Before you can build OR publish:** this repo ships with a nil
> placeholder Anypoint business-group UUID
> (`00000000-0000-0000-0000-000000000000`) in [Cargo.toml](Cargo.toml).
> `make build` itself will fail against this placeholder because
> `anypoint-cli-v4 pdk policy-project build-asset-files` validates the
> UUID against the live control plane. **Replace it with your own org's
> real UUID before running any `make` target** — see
> [Section 4 — Installation, step 3](#option-b-build-and-publish-from-source).

## 2. Architecture

```
┌──────────┐         ┌─────────────────────────────────────────────┐         ┌──────────────┐
│          │         │          Omni(Flex) Gateway                 │         │              │
│  Client  │──POST──▶│                                              │──POST──▶│   Upstream   │
│          │         │  ┌──────────┐  ┌────────────────────────┐   │         │   Backend    │
│          │◀────────│  │  Auth    │→ │  API Encryption        │   │◀────────│              │
│          │         │  └──────────┘  │   Decryption Policy    │   │         │              │
└──────────┘         │                └────────────┬───────────┘   │         └──────────────┘
                     │                             │                │
                     │  REQUEST  leg: Encrypt / Decrypt / Plain     │
                     │  RESPONSE leg: Encrypt / Decrypt / Plain     │
                     │                                              │
                     │  Secret cache (shared, in-process, TTL)      │
                     │        │ miss                                 │
                     │        ▼                                      │
                     │  ┌──────────────────────────────────────┐    │
                     │  │ AWS Secrets Manager (SigV4)          │    │
                     │  │ Secret name: aeskeys/<Source>        │    │
                     │  └──────────────────────────────────────┘    │
                     └──────────────────────────────────────────────┘
```

**Two independent knobs:**
- **`requestMode`** controls what happens on the way to the upstream.
- **`responseMode`** controls what happens on the way back to the client.

Each can be `Encrypt`, `Decrypt`, or `Plain`. Any combination of the nine is valid; the common ones are documented in [Section 7](#7-mode-combinations).

**Wire format for an encrypted body (v2, since 1.0.2):**

```
base64(
  magic      (2)  = 0x4B 0x41          // "KA"
  version    (1)  = 0x02
  iv         (16) = CSPRNG per request
  ciphertext (n)  = AES-256-CBC, PKCS#7 padded
  mac        (32) = HMAC-SHA256(mac_key, magic ‖ version ‖ iv ‖ ciphertext)
)
```

The MAC covers every byte before it including the version byte, so an attacker cannot downgrade a v2 envelope or flip ciphertext bits unnoticed. The MAC key is derived from the stored AES key via HKDF-SHA256 (label `"api-encryption-decryption-policy/v2/mac-key"`), so operators still manage a single 32-byte secret. v1 envelopes are **rejected** — see [Section 13 — Compatibility](#13-compatibility) for the migration note.

The original `Content-Type` is preserved in the `X-Content-Type` header so the other side can parse the plaintext after decrypting.

**Safety rails (request leg, since 1.0.2; response leg fail-closed added 1.0.3):**

The request and response legs have different fail-closed primitives because PDK's state machine commits response headers at a different point than request headers. Both legs now have a true fail-closed contract — on a transforming response leg (1.0.3+), the policy uses the `enable_stop_iteration` combined headers+body state so it can rewrite `:status` and `Content-Type` alongside the body.

| Guard | Request leg | Response leg (transforming only) |
|---|---|---|
| **Max body** | `> 786,367` bytes of plaintext → HTTP `413` | `> 786,367` bytes of plaintext (encrypt) or `> 1,048,576` bytes of base64 (decrypt) → the policy rewrites status to `502 Bad Gateway` + JSON error body; upstream plaintext never reaches the client |
| **Content-Encoding** | Non-`identity` → HTTP `415` | Non-`identity` → `502` fail-closed, upstream body replaced with JSON error |
| **Content-Type streaming** | `text/event-stream`, `application/grpc*` → HTTP `415` | Same → `502` fail-closed |
| **Range requests** | Transforming legs reject `Range:` with HTTP `416` | n/a (status gating skips 206) |
| **MAC mismatch / bad envelope** | Decrypt leg: HTTP `400 Malformed ciphertext` | Decrypt leg: `502 Upstream ciphertext malformed or tampered` — upstream ciphertext never surfaces as plaintext |
| **Source header** | ASCII alphanumeric + `.` `_` `-`, max 128 chars, non-empty → `400` | — |
| **Mode / TTL** | Unknown `requestMode`/`responseMode` or non-positive `cacheConfig.ttl` fails the policy at config load, not at request time. | — |

### Error-to-HTTP-status table

Request leg:

| Condition                                    | Status | Body                                              |
|----------------------------------------------|--------|---------------------------------------------------|
| Missing / invalid `Source` header            | 400    | `{"errorMessage":"Missing or invalid  Source"}`  |
| MAC mismatch / bad magic / wrong version     | 400    | `{"errorMessage":"Malformed ciphertext"}`        |
| Secret not found in AWS Secrets Manager      | 400    | `{"errorMessage":"Missing or invalid  Source"}`  |
| Plaintext over `786,367` bytes               | 413    | `{"errorMessage":"Request body exceeds policy maximum"}` |
| `Content-Encoding != identity`               | 415    | `{"errorMessage":"Unsupported Content-Encoding"}` |
| Streaming Content-Type                       | 415    | `{"errorMessage":"Unsupported streaming Content-Type"}` |
| `Range:` present on a transforming leg       | 416    | `{"errorMessage":"Range requests not supported on transforming legs"}` |
| AWS IAM / signing misconfiguration           | 500    | `{"errorMessage":"AWS Secrets Manager configuration error"}` |
| AWS throttled or transient outage            | 503    | `{"errorMessage":"Secret backend temporarily unavailable"}` |

Response leg (1.0.3+) — the policy rewrites the upstream response:

| Condition                                              | Status | Body                                                             |
|--------------------------------------------------------|--------|------------------------------------------------------------------|
| Upstream response has `Content-Encoding != identity`   | 502    | `{"errorMessage":"Upstream response Content-Encoding not supported by policy"}` |
| Upstream response is streaming                         | 502    | `{"errorMessage":"Upstream response Content-Type is streaming..."}`             |
| Upstream response exceeds configured size              | 502    | `{"errorMessage":"Upstream response exceeds policy size limit"}`                |
| Decrypt: upstream ciphertext tampered / malformed      | 502    | `{"errorMessage":"Upstream ciphertext malformed or tampered"}`                  |
| Codec internal error on response                       | 502    | `{"errorMessage":"Policy codec error on response leg"}`                         |
| `set_body` rejected after transform                    | 500    | `{"errorMessage":"Failed to write transformed response body"}`                  |

All response-leg errors carry `Content-Type: application/json` and strip stale `ETag`/`Content-Length`/`Last-Modified`/`Content-Digest`/`Repr-Digest`/`Content-Range`/`X-Content-Type` so a client cannot match a conditional against a rewritten body.

## 3. Prerequisites

- Omni(Flex) Gateway running the PDK 1.10.0 runtime (or compatible — tested on Omni Gateway 1.14.x)
- Rust toolchain **1.83.0+** with the `wasm32-wasip1` target
- Anypoint CLI v4 with the PDK plugin (`anypoint-pdk-plugin`)
- Anypoint Platform account with Exchange publish permissions
- An AWS IAM user/role allowed `secretsmanager:GetSecretValue` on secrets named `aeskeys/*`

## 4. Installation

### Option A: Install from Exchange

If the policy is already published to your org, apply it directly to any API instance in API Manager — no build required.

### Option B: Build and Publish from Source

**1. Install required tools:**

```bash
# Install Anypoint CLI v4
npm install -g anypoint-cli-v4-public

# Install the PDK plugin
anypoint-cli-v4 plugins:install anypoint-pdk-plugin

# Install cargo-anypoint matching the policy's PDK version
cargo install cargo-anypoint@1.10.0

# Add the WASM target
rustup target add wasm32-wasip1
```

**2. Authenticate:**

```bash
anypoint-cli-v4 account:login

# Or if the CLI version uses the conf flow:
anypoint-cli-v4 conf username <you>
anypoint-cli-v4 conf password <your-pwd>
anypoint-cli-v4 conf organization <org-id>
```

**3. Update your Anypoint organization / business-group ID:**

> ⚠️ **Required before any `make` target.** The repo ships with the nil
> placeholder UUID `00000000-0000-0000-0000-000000000000`. `anypoint-cli-v4
> pdk policy-project build-asset-files` validates the UUID against the live
> Anypoint control plane and rejects non-org values — the nil UUID
> included. `cargo test --lib` (Rust-only) works, but `make build`,
> `make publish`, and `make release` all fail until you replace it with
> your own Anypoint business-group UUID.

Edit [Cargo.toml](Cargo.toml):

```toml
[package.metadata.anypoint]
group_id = "<YOUR-BUSINESS-GROUP-UUID>"                       # ← REPLACE THIS
definition_asset_id = "api-encryption-decryption-policy"
implementation_asset_id = "api-encryption-decryption-policy-wasm"
```

**How to find your business group UUID:**

- **Option A (CLI):**
  ```bash
  anypoint-cli-v4 account:business-group:list
  ```
  Copy the `Id` column of the business group you want to publish into.

- **Option B (UI):** Anypoint Platform → top‑right org dropdown → **Access
  Management → Business Groups** → click your group → copy the UUID from the
  URL bar (the portion after `/accounts/businessGroups/`).

Permissions check: the user you authenticated as in step 2 must have **Exchange
Contributor** (or higher) in the target business group, otherwise `make release`
fails with `403 Forbidden`.

**4. Setup, build, publish:**

```bash
make setup
make build
make publish     # dev build (adds -dev suffix + timestamp)
make release     # release build (publishes the real asset at 1.0.1)
```

**5. Apply the policy:**

After `make release`, the policy appears in API Manager under **Custom** policies as **API Encryption Decryption Policy**. Apply it to an API instance via the UI and fill in the AWS fields.

### Available Make Targets

| Target | Description |
|--------|-------------|
| `make setup` | Install cargo-anypoint and fetch dependencies |
| `make build` | Compile WASM + generate the definition + implementation YAMLs |
| `make test` | Run Rust unit tests (45 tests covering codec, helpers, AWS classifier) + Python redactor regression suite |
| `make publish` | Publish a development version (`-dev` suffix + timestamp) to Exchange |
| `make release` | Publish a release version to Exchange |
| `make show-policy-ref-name` | Print the `policyRef.name` to use in `api.yaml` |

## 5. Configuration Reference

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `requestMode` | enum | yes | `Encrypt` / `Decrypt` / `Plain` — what to do with the body on the way to the upstream |
| `responseMode` | enum | yes | `Encrypt` / `Decrypt` / `Plain` — what to do with the body on the way back to the client |
| `SuccessStatusCode` | string | no | Extra response status codes to encrypt on, comma‑separated. Appended to the always‑allowed `200,201,202,204` |
| `SuccessStatusCodeDecrypt` | string | no | Same, for decrypt |
| `awsAccessKey` | string | yes | AWS IAM access key ID with `secretsmanager:GetSecretValue` |
| `awsAccessSecret` | string | yes | AWS IAM secret access key (marked `security:sensitive`; API Manager renders as password) |
| `awsRegion` | string | yes | AWS region of the Secrets Manager endpoint, e.g. `ap-south-1` |
| `awsService` | service URL | yes | Full URL of Secrets Manager, e.g. `https://secretsmanager.ap-south-1.amazonaws.com` |
| `sourceBinding` | enum | no (default `principalMatch`) | **Since 1.0.3.** How the policy decides whether the caller is authorized to select a given `Source` value. See [Section 9.1 — Caller identity binding](#91-caller-identity-binding). |
| `cacheConfig.ttl` | integer | yes | TTL in seconds for the per‑`Source` AES‑key cache. Default `86400` (24h) |

Cache capacity is a hard‑coded 100 entries per Flex pod. The cache is in‑memory and shared across Envoy worker threads in the same pod; **not** shared across pods. **Since 1.0.3**, the cache namespace hashes `region + access_key + sha256(access_secret) + service_uri` so a rotation of the signing secret or a change to the Secrets Manager endpoint invalidates any warmed entries that the old credentials would otherwise still have reached.

### 9.1 Caller identity binding

> ⚠️ **What the policy does and does not authenticate.** The v2 envelope MAC proves that the body was produced by a holder of the AES key — nothing else. It does NOT authenticate HTTP headers, does NOT prevent replay, and does NOT substitute for transport-layer authentication. Treat the `Source` header as an untrusted claim until an earlier policy binds it to an authenticated identity.

Two bindings are supported:

- **`principalMatch`** (default, since 1.0.3). The policy reads the authenticated identity set by a prior auth policy (`Authentication::authentication()` → `client_id` or, as a fallback, `principal`) and rejects the request with HTTP 403 if the `Source` header does not exactly equal that identity. If no auth data is present at all the policy rejects with 403 — this mode requires an earlier auth policy in the chain. Comparison is byte-exact, no case folding.
- **`headerTrust`**. The policy accepts the caller-supplied `Source` verbatim (the pre-1.0.3 behaviour). This is only safe when an earlier policy in the chain has already rewritten or verified `Source` against the authenticated principal. Choosing this value makes the operator responsible for that pairing.

Migration: a 1.0.2 deployment that silently trusted the `Source` header must now either (a) chain a policy that rewrites `Source` from the authenticated principal before this one, OR (b) set `sourceBinding: headerTrust` to opt back into the old behaviour.

## 6. Request Headers

| Header | When used | Required? | Purpose |
|--------|-----------|-----------|---------|
| `Source` | Always, for secret lookup | **Yes** (unless `requestMode` AND `responseMode` are both `Plain`) | Keys the AES‑key lookup — `aeskeys/<Source>` in AWS Secrets Manager. Different `Source` values get different keys. **Since 1.0.3**: with `sourceBinding: principalMatch` (the default) the policy additionally requires that `Source` match the authenticated `client_id`/`principal`. See [Section 9.1](#91-caller-identity-binding) |
| `X-Content-Type` | Non‑GET, request leg = `Decrypt` only | Yes in that case | The real plaintext media type. Required ONLY on a Decrypt request leg (since 1.0.3) — on an Encrypt request leg the policy now preserves the actual `Content-Type` automatically |
| `Content-Type` | Always | Yes (standard HTTP) | Preserved into `X-Content-Type` when the policy encrypts a request/response, restored from `X-Content-Type` when it decrypts |
| `Range` | Requests with a transforming leg | **Not supported** — HTTP 416 if present | Partial-body transforms would silently drop the range contract |

**Plain request pass-through (since 1.0.3):** when `requestMode = Plain`, the request leg does NOT strip `Content-Type`, `Content-Length`, `ETag`, `Content-Digest`, `Repr-Digest`, `Content-Range`, or `Last-Modified`. The bytes the backend receives are byte-exact what the caller sent. The secret lookup still runs when `responseMode` transforms, so the response leg can decrypt or encrypt.

GET requests skip body transformation entirely and don't require `X-Content-Type`.

## 7. Mode Combinations

| `requestMode` | `responseMode` | Direction | When to use |
|---|---|---|---|
| `Decrypt` | `Encrypt` | **End‑to‑end encryption client ↔ gateway**; backend sees plaintext | Most common. Protect the wire to/from the client; keep the backend simple |
| `Encrypt` | `Decrypt` | **End‑to‑end encryption gateway ↔ backend**; client sees plaintext | Legacy backend expects AES‑CBC payloads; clients don't |
| `Encrypt` | `Encrypt` | Both sides encrypted; gateway is a straight codec | Rare; cross‑region relay |
| `Decrypt` | `Decrypt` | Both sides encrypted; gateway terminates for both | Shared‑broker patterns |
| `Decrypt` | `Plain` | Decrypt in, pass response through | Staged rollout — only request leg is encrypted yet |
| `Plain` | `Encrypt` | Encrypt out only | Hardening response but request is already plaintext |
| `Plain` | `Plain` | No‑op | Debugging / policy pre‑stage |

**Status‑code gating on the response leg:** encryption/decryption only runs if the upstream status is in the allow‑list for that mode (defaults 200/201/202/204 plus any extras from `SuccessStatusCode` / `SuccessStatusCodeDecrypt`). An upstream error (e.g. 500) is passed through untouched.

## 8. How It Works

### Request Phase

1. Snapshot the watched headers (`Content-Type`, `Source`, `X-Content-Type`) into a lowercase map — missing headers stay missing (no empty-string fabrication).
2. **Non‑GET AND `requestMode ≠ Plain`:** only when the request leg actually transforms, enforce request-side preconditions:
   - If `requestMode = Decrypt`: require `X-Content-Type` (plaintext media type for the decrypted body). Reject with HTTP 400 if missing.
   - Reject `Content-Encoding` other than `identity` with HTTP 415.
   - Reject streaming content types (`text/event-stream`, `application/grpc*`) with HTTP 415.
   - Reject requests carrying a `Range` header with HTTP 416.
3. **Resolve the AES key** (unless `requestMode = responseMode = Plain`, which short-circuits):
   - Look up `aeskeys/<Source>` in the in‑memory TTL cache.
   - On hit (and still within TTL), use it.
   - On miss or expiry, call AWS Secrets Manager with SigV4, store the result with a fresh timestamp.
4. Build an AES‑256 codec from the base64‑encoded key (fails fast if the decoded key isn't exactly 32 bytes).
5. **Non‑GET AND `requestMode ≠ Plain`:** rewrite headers and transform the body:
   - `Encrypt`: set `Content-Type: application/octet-stream`, preserve the original type in `X-Content-Type`, base64-v2-envelope the body.
   - `Decrypt`: restore `Content-Type` from `X-Content-Type`, strip the v2 envelope back to plaintext.
   - Representation-stale headers (`Content-Length`, `ETag`, `Content-Digest`, `Repr-Digest`, `Content-Range`, `Last-Modified`) are dropped on transforming legs only; a Plain request leg leaves them intact.
6. Serialize the carry‑over state (secret, headers, response mode, parsed status‑code allow‑lists) and hand it to the response filter.

### Response Phase

1. Deserialize the carry‑over state.
2. Rebuild the AES codec from the shuttled key.
3. If `responseMode == Encrypt` **and** the upstream status is in the encrypt allow‑list:
   - Save upstream `Content-Type` into `X-Content-Type`, set wire `Content-Type: application/octet-stream`, encrypt the body.
4. If `responseMode == Decrypt` **and** status is in the decrypt allow‑list:
   - Restore `Content-Type` from the request‑leg `X-Content-Type`, decrypt the body.
5. Otherwise pass through untouched.
6. On any transform failure in the response phase: the response status is left as‑is but the body is replaced with a JSON error object.

## 9. AWS Secrets Manager Setup

### Generate the AES key

```bash
openssl rand 32 | base64
# Example output:
# YOUR_BASE64_AES_256_KEY_HERE_44_CHARS_WITH_EQ=
```

Must decode to exactly 32 bytes:

```bash
echo "<the base64 string>" | base64 -d | wc -c   # must print 32
```

### Store the key

Secret naming: `aeskeys/<Source-header-value>`. If a client calls with `Source: partnerA`, the policy fetches `aeskeys/partnerA`.

```bash
aws secretsmanager create-secret \
  --region ap-south-1 \
  --name "aeskeys/partnerA" \
  --secret-string "<the base64 key>"
```

**Important:** store the key as a plaintext **string** (not binary). The policy only reads the `SecretString` field of the response, not `SecretBinary`.

### IAM policy for the gateway's IAM user

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "secretsmanager:GetSecretValue",
    "Resource": "arn:aws:secretsmanager:ap-south-1:<account-id>:secret:aeskeys/*"
  }]
}
```

### Secret caching

The AES key for a given `Source` is cached in Flex's in‑process shared cache for up to `cacheConfig.ttl` seconds (default **86400 s = 24h**). Refresh is **lazy** — the first request after the TTL expires evicts the entry and refetches from AWS. Rotation lag is therefore bounded by TTL. Pod restarts flush the cache cluster‑wide; `kubectl rollout restart deploy/flex` is the "rotate immediately" lever.

## 10. Input/Output Specification

### Request on the wire — client → gateway (with `requestMode: Decrypt`)

```
POST /payments HTTP/1.1
Host: api.example.com
Content-Type: application/octet-stream
X-Content-Type: application/json
Source: partnerA
Content-Length: 128

<base64 of IV || AES-256-CBC(ciphertext) of the real JSON>
```

### Request after policy — gateway → upstream

```
POST /payments HTTP/1.1
Content-Type: application/json
Source: partnerA
...

{"amount": 10000, "currency": "INR", ...}
```

### Response on the wire — upstream → gateway

```
HTTP/1.1 200 OK
Content-Type: application/json

{"transactionId": "txn-9981", "status": "accepted"}
```

### Response after policy — gateway → client (with `responseMode: Encrypt`)

```
HTTP/1.1 200 OK
Content-Type: application/octet-stream
X-Content-Type: application/json

<base64 of IV || AES-256-CBC(ciphertext) of the JSON above>
```

### Error response — missing or invalid Source

```json
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "errorMessage": "Missing or invalid  Source",
  "source": "partnerA"
}
```

## 11. Observability

Every meaningful step emits a structured JSON log line through the PDK logger:

```json
{
  "source":  "partnerA",
  "message": "Fetch Secret - Got cache secret aeskeys/partnerA"
}
```

Key events to grep for in Flex logs:

| Message prefix | What it tells you |
|---|---|
| `Fetch Secret - Got cache secret` | Cache hit — no AWS call for this request |
| `Fetch Secret - No cached Data` | Cache miss — AWS call about to happen |
| `Fetch Secret (AWS) - Failed` | AWS rejected the lookup — bad `Source`, bad credentials, or secret doesn't exist |
| `Encrypt request and replace Body - Encryption success` | Request body encrypted successfully |
| `Decrypt request and replace Body - Decryption success` | Request body decrypted successfully |
| `Required Header - Missing or empty required header` | A required header was missing — HTTP 400 returned |

## 12. Testing with curl

```bash
# 1. Generate a key, store it in AWS
KEY=$(openssl rand 32 | base64)
aws secretsmanager create-secret \
  --region ap-south-1 \
  --name "aeskeys/partnerA" \
  --secret-string "$KEY"

# 2. Encrypt a JSON payload client-side
PLAIN='{"amount": 1000, "currency": "INR"}'
IV_HEX=$(openssl rand -hex 16)
KEY_HEX=$(printf '%s' "$KEY" | base64 -d | xxd -p -c 256)
CT_HEX=$(printf '%s' "$PLAIN" | openssl enc -aes-256-cbc -K "$KEY_HEX" -iv "$IV_HEX" | xxd -p -c 1000000 | tr -d '\n')
WIRE=$(printf '%s%s' "$IV_HEX" "$CT_HEX" | xxd -r -p | base64 | tr -d '\n')

# 3. Call the policy
curl -i -X POST "http://<flex-host>/your-endpoint" \
  -H "Content-Type: application/octet-stream" \
  -H "X-Content-Type: application/json" \
  -H "Source: partnerA" \
  --data-binary "$WIRE"
```

## 13. Compatibility

| Scenario | Supported | Notes |
|----------|-----------|-------|
| JSON request/response bodies | Yes | Full support |
| Binary request/response bodies | Yes | v2 codec round-trips arbitrary bytes exactly; no UTF-8 coercion |
| Multipart/form‑data | Partial | The whole body is encrypted/decrypted as a blob; multipart structure is not preserved across the hop |
| Streaming responses (SSE, chunked) | No | Request leg → HTTP 415; response leg → fail-closed 502 (upstream body never reaches the client as plaintext) |
| Compressed bodies (gzip/br/deflate) | No | Request leg → HTTP 415; response leg → fail-closed 502. Set `Content-Encoding: identity` upstream |
| Plaintext larger than 786,367 bytes | No | Request leg → HTTP 413; response leg → fail-closed 502. Limit anchors on the gateway's 1 MiB write buffer; the envelope size for the max plaintext is 1,048,560 bytes |
| Partial / conditional responses (206, Range) | No | Request `Range:` on a transforming leg → HTTP 416; upstream 206 is outside the default status allow-list and passes through untransformed |
| GET requests | Yes | Body transformation is skipped on GET; the response leg still runs |
| WebSocket upgrades | No | PDK WebSocket support is separate; this policy only touches HTTP |

### Migration from v1 (< 1.0.2) envelopes

Version 1.0.2 is a **hard cut** from the v1 wire format (`base64(IV ‖ ciphertext)`, no MAC). v1 envelopes sent to a 1.0.2 gateway are rejected with HTTP 400 "Decryption failed" because they don't start with the v2 magic bytes `0x4B 0x41`. There is no dual-read path.

To migrate:

1. **Deploy 1.0.2 to all gateways simultaneously** or front them with a brief maintenance window. Running mixed 1.0.1 / 1.0.2 gateways against the same clients will cause client-side decrypt failures for the half still producing v1.
2. **Re-generate test fixtures** on the client side using the new `aes-tester.html` (also shipped in this release). The HTML tester produces v2 envelopes matching the server.
3. **Update any client SDK** that builds the envelope by hand. The v2 recipe is in [Section 2 — Wire format](#2-architecture) above; a reference JavaScript implementation is in `aes-tester.html`.

If you need temporary v1 interop (e.g. a slow client rollout), the clean path is to deploy a second policy instance pinned at 1.0.1 and route legacy clients through it — not to downgrade 1.0.2 to accept v1.

## 14. Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| HTTP 400 "Missing or empty required header" | `X-Content-Type` not sent by the client on a non‑GET request | Add `X-Content-Type: <real-type>` on the client, or use GET |
| HTTP 400 "Missing or invalid Source" | Secret doesn't exist, or the IAM user can't read it, or `Source` header is missing | Check `Source` header value; verify the secret exists under `aeskeys/<source>`; check IAM policy |
| HTTP 500 "Internal Server Error" on request | AES key not exactly 32 bytes after base64 decode | Regenerate: `openssl rand 32 \| base64` |
| Decrypt returns `Response decryption failed` body | Client encrypted with a different key than AWS holds, or wrong IV length, or non‑base64 input | Confirm the client and AWS share the same base64 key; confirm wire format is `base64(IV16 ‖ ciphertext)` |
| Secret rotation not picked up | Still within `cacheConfig.ttl` window on at least one pod | Lower TTL, or `kubectl rollout restart deploy/flex` for an immediate rotation |
| AWS log shows `SecretString not found in AWS response` | Secret stored as `SecretBinary` instead of `SecretString`, or doesn't exist | Recreate the secret with `--secret-string` (not `--secret-binary`) |

## 15. Project Layout

```
.
├── Cargo.toml                     Crate metadata + Anypoint asset IDs
├── Makefile                       Standard PDK targets (setup / build / publish / release)
├── definition/
│   └── gcl.yaml                   Policy schema the API Manager UI renders
├── src/
│   ├── lib.rs                     Entrypoint, request/response filters
│   ├── aws/mod.rs                 AWS Secrets Manager client (SigV4)
│   ├── codec/mod.rs               AES-256-CBC encode / decode
│   ├── support/
│   │   ├── cache.rs               TTL wrapper around the PDK shared cache
│   │   ├── headers.rs             Header snapshot / require / mutate helpers
│   │   ├── log.rs                 Structured JSON logger
│   │   ├── reply.rs               Error-response builder
│   │   └── mod.rs                 TraceCtx shared by every module
│   └── generated/
│       └── config.rs              Rust types mirroring gcl.yaml (regenerated by `make build`)
└── tests/
    ├── requests.rs                Integration tests driven by pdk-test
    ├── common/mod.rs              Test harness constants
    └── config/                    Per-test logging / registration configs
```

## 16. Asset Identifiers

| Place | Value |
|-------|-------|
| Exchange display name | **API Encryption Decryption Policy** |
| Exchange category | Custom |
| Release assetId | `api-encryption-decryption-policy` |
| Implementation assetId | `api-encryption-decryption-policy-wasm` |
| Flex `policyRef.name` | `api-encryption-decryption-policy-v1-0-impl` |
| WASM binary | `api_encryption_decryption_policy.wasm` |
| Current version | `1.0.3` |

> ⚠️ Before publishing to your own tenant, update `group_id` in
> [Cargo.toml](Cargo.toml) (`[package.metadata.anypoint]`) from the shipped
> nil placeholder (`00000000-0000-0000-0000-000000000000`) to your business
> group's real UUID. See
> [Section 4 step 3](#option-b-build-and-publish-from-source) for how to
> find it.
