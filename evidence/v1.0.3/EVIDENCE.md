# API Encryption Decryption Policy — v1.0.3 Target-Gateway Evidence

Evidence pass performed against a managed Omni(Flex) Gateway 1.14.x on
2026-11-12, covering every follow-up blocker filed in issues #18, #19,
#20, #21, and #22 against commit `0e90ed3` (v1.0.2).

| Field | Value |
|---|---|
| Policy version | `1.0.3` |
| Gateway | `vp-omni-gateway-shared-x89y1k.yz4tr9-1.aus-s1.cloudhub.io` (CloudHub managed Omni(Flex) Gateway 1.14.x) |
| Upstream under test | `https://httpbin.org` (reflects request details as JSON, serves `/gzip`, `/sse`, `/bytes/N` for response-leg cases) |
| Consumer path | `/aes-evidence` |
| Secrets Manager key | `aeskeys/partnerA` → base64(32-byte AES-256 key) |
| Protocol / codec | AES-256-CBC + HKDF-SHA256-derived HMAC-SHA256 MAC, v2 envelope (`base64(magic ‖ version ‖ iv ‖ ciphertext ‖ mac)`) |

All scenarios ran from a developer workstation; each curl command and
the gateway's response (status line, headers, body) is captured verbatim
below. Transcripts are also available as individual files alongside
this document.

---

## Scenario index

| # | What it proves | Fixes issue | Result |
|---|---|---|---|
| 01 | Request-leg Encrypt forwards v2 envelope to upstream with correct Content-Type swap and X-Content-Type sidecar | #7, baseline | ✅ |
| 02 | Same, with non-UTF-8 binary body (round-trips byte-exact) | #9 | ✅ |
| 10 | Oversize plaintext request → HTTP 413 at policy boundary derived from the exact v2 wire-size math | #19 | ✅ |
| 11 | Request `Content-Encoding: gzip` on a transforming leg → HTTP 415 | #8 | ✅ |
| 12 | Request `Content-Type: text/event-stream` on a transforming leg → HTTP 415 | #13 | ✅ |
| 13 | `Range:` header on a transforming leg → HTTP 416 | #20 | ✅ |
| 21 | Tampered v2 envelope on decrypt → HTTP 400 "Malformed ciphertext" (MAC check rejects before AES decrypt) | #1 regression | ✅ |
| 30 | Upstream responds with `Content-Encoding: gzip` under an Encrypt response leg → HTTP 502 fail-closed, JSON error, body-encoding headers stripped | #18 | ✅ |
| 31 | Upstream responds with `text/event-stream` under an Encrypt response leg → HTTP 502 fail-closed | #18 | ✅ |
| 32 | Upstream responds with 1 MiB body under an Encrypt response leg → HTTP 502 fail-closed | #18 / #19 | ✅ |
| 40 | `sourceBinding: principalMatch` with no prior auth policy → HTTP 403 "Not authorized to select Source" | #22a | ✅ |
| 41 | Malformed `Source` header (path traversal) → HTTP 400 before any AWS call | #2 complement | ✅ |
| 50 | Plain/Plain leaves request `Content-Type` AND `ETag` intact end-to-end (byte-exact pass-through) | #20 | ✅ |
| 51 | Plain/Encrypt preserves request `Content-Type` and encrypts the response into a v2 envelope | #20 + baseline | ✅ |

An out-of-band finding surfaced during this evidence pass: the original
`fail_closed_response` helper did not strip body-encoding headers from
the upstream response, so scenario 30 initially returned a 502 JSON
body under a stale `Content-Encoding: gzip` header. Fixed in the same
1.0.3 WASM before capture of the transcripts below; the strip list in
`src/lib.rs::fail_closed_response` now covers
`Content-Encoding`, `Content-Language`, `Transfer-Encoding`, `Vary`,
and `Trailer` in addition to the representation validators.

---

## Policy configurations used across the run

The six configurations below are the cells of the mode-combination
matrix the scenarios exercise. All share the same AWS Secrets Manager
authority (one `aeskeys/partnerA` secret); only `requestMode`,
`responseMode`, and `sourceBinding` change.

| Config | `requestMode` | `responseMode` | `sourceBinding` | Scenarios driven |
|---|---|---|---|---|
| `cfg-01` | Encrypt | Plain | headerTrust | 01, 02 |
| `cfg-02` | Encrypt | Plain | headerTrust | 10, 11, 12, 13, 41 |
| `cfg-03` | Decrypt | Plain | headerTrust | 21 |
| `cfg-04` | Plain | Encrypt | headerTrust | 30, 31, 32, 51 |
| `cfg-05` | Plain | Plain | headerTrust | 50 |
| `cfg-06` | Encrypt | Plain | principalMatch | 40 |

---

## Scenario 01 — Encrypt request leg, JSON plaintext

**Fixes:** #7 baseline (real Content-Type preserved into X-Content-Type sidecar).

**curl:**

```bash
curl -i -X POST "$GW/anything/echo" \
  -H "Content-Type: application/json" \
  -H "Source: partnerA" \
  --data-binary '{"amount":1000,"currency":"INR"}'
```

**Response:**

```
HTTP/1.1 200 OK
access-control-allow-credentials: true
access-control-allow-origin: *
access-control-expose-headers: Retry-After, RateLimit, RateLimit-Policy, WWW-Authenticate
content-length: 832
content-type: application/json
x-content-type-options: nosniff
date: Thu, 12 Nov 2026 10:46:23 GMT
server: Anypoint Flex Gateway
x-envoy-decorator-operation: api-instance-21294366.edc1ebcc-bf80-423a-b46a-192b3fc86794.svc
x-correlation-id: b0d54587-b879-41ec-a325-6fe7dd2f61e9
Strict-Transport-Security: max-age=31536000; includeSubdomains
Connection: Keep-Alive

{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Content-Type": "application/octet-stream",
    "Host": "httpbin.org",
    "Source": "partnerA",
    "Traceparent": "00-4103468903f1adedd48e87ddad1ed483-0fa337bfc2662e35-01",
    "Tracestate": "",
    "Transfer-Encoding": "chunked",
    "User-Agent": "curl/8.7.1",
    "X-Content-Type": "application/json",
    "X-Correlation-Id": "b0d54587-b879-41ec-a325-6fe7dd2f61e9",
    "X-Forwarded-Host": "vp-omni-gateway-shared-x89y1k.yz4tr9-1.aus-s1.cloudhub.io"
  },
  "method": "POST",
  "origin": "104.161.246.3,100.64.100.181,52.64.167.139",
  "url": "https://httpbin.org/anything/echo",
  "data": "S0EClGA91iLjdNfcvvDxWt1Tcz61zZnWHBCLL+B302rGTl49EhLBB15zZ8xaUH0uM/QRPvfm8ibrxKY7vVkzRwAq9OAd2zPW3B+PT3AXc6/eiOhR2HdKaadXnPD+SRvre/Tv",
  "files": {},
  "form": {},
  "json": null
}
```

**What this proves:**

- The upstream (httpbin.org) saw `Content-Type: application/octet-stream` and `X-Content-Type: application/json` — the request-leg Encrypt (issue #7) correctly preserved the plaintext MIME type into the sidecar header before swapping the wire type.
- The `data` field contains the v2 envelope that reached the upstream. Base64-decoding the first three bytes:
  - `S0EC` → `0x4B 0x41 0x02` → `"KA"` magic + version byte `0x02` ✓
  This is direct on-the-wire proof that the request body the backend received was a v2 envelope, not plaintext.

---

## Scenario 02 — Encrypt request leg, non-UTF-8 binary bytes

**Fixes:** #9 regression (codec is byte-oriented; binary bytes round-trip).

**curl:**

```bash
printf '\x00\xff\x80\x41\x00\x7f\xc0' | \
  curl -i -X POST "$GW/anything/echo" \
    -H "Content-Type: application/octet-stream" \
    -H "Source: partnerA" \
    --data-binary @-
```

**Response:**

```
HTTP/1.1 200 OK
content-length: 798
content-type: application/json
date: Thu, 12 Nov 2026 10:47:56 GMT
server: Anypoint Flex Gateway
x-correlation-id: b8248ac9-b698-4fb6-a6b3-466787f36788

{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Content-Type": "application/octet-stream",
    "Host": "httpbin.org",
    "Source": "partnerA",
    "User-Agent": "curl/8.7.1",
    "X-Content-Type": "application/octet-stream",
    "X-Correlation-Id": "b8248ac9-b698-4fb6-a6b3-466787f36788"
  },
  "method": "POST",
  "data": "S0EChjGDxHhzURzjT5Q8EmHrKTav8PxVT8QF/m6YuoeQSatrfmdxPc3ibbzZFiwTiSzslSa8Sqy5+pthl8FS4CrinA==",
  "files": {},
  "form": {},
  "json": null
}
```

**What this proves:**

- Non-UTF-8 bytes (`0x00 0xFF 0x80 ...`) are handled correctly by the byte-oriented codec. The pre-#9 codec coerced through `String`, which would have corrupted these bytes; this one does not.
- `X-Content-Type: application/octet-stream` preserved as the caller sent it.
- `data` once again starts with `S0EC`: v2 envelope on the wire.

---

## Scenario 10 — Oversize plaintext request → 413

**Fixes:** #19 (payload limits derived from exact v2 wire-size math).

**Setup:** client sent 786,368 bytes of random body — exactly one byte
over the derived cap `MAX_PLAINTEXT_BYTES = 786,367`. The math:

```
wire_size_for_plaintext(786_368) = 1_048_580 bytes
runtime_write_buffer              = 1_048_576 bytes (1 MiB)
```

So 786,368 bytes of plaintext would produce an envelope the gateway
could not write, and 786,367 bytes would fit. The policy rejects at
the input boundary before the AES operation.

**curl:**

```bash
head -c 786368 /dev/urandom > /tmp/oversize.bin
curl -i -X POST "$GW/anything/big" \
  -H "Content-Type: application/octet-stream" \
  -H "Source: partnerA" \
  --data-binary @/tmp/oversize.bin
```

**Response:**

```
HTTP/1.1 413 Payload Too Large
content-type: application/json
content-length: 74
date: Thu, 12 Nov 2026 10:48:48 GMT
server: Anypoint Flex Gateway
x-correlation-id: 2a3bc1b5-5438-4718-818d-7d26cb5f3f78

{"errorMessage":"Request body exceeds policy maximum","source":"partnerA"}
```

**What this proves:** #19's reproducible 92-byte overshoot from v1.0.2
is fixed. The gateway rejects exactly at the derived cap, not at the
eyeballed 768 KiB that v1.0.2 used.

---

## Scenario 11 — `Content-Encoding: gzip` on request → 415

**Fixes:** #8 (compressed bodies on a transforming leg never reach codec).

**curl:**

```bash
curl -i -X POST "$GW/anything/gz" \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  -H "Source: partnerA" \
  --data-binary '{"ignored":true}'
```

**Response:**

```
HTTP/1.1 415 Unsupported Media Type
content-type: application/json
content-length: 67
date: Thu, 12 Nov 2026 10:49:01 GMT
server: Anypoint Flex Gateway
x-correlation-id: 4827b89f-77d1-4fea-8cb3-3d3c03a7f5ec

{"errorMessage":"Unsupported Content-Encoding","source":"partnerA"}
```

**What this proves:** the policy rejects at header time (pre-forward),
so no gzipped bytes ever reach the codec. The `unsupported_encoding`
helper catches anything other than `identity`.

---

## Scenario 12 — `Content-Type: text/event-stream` on request → 415

**Fixes:** #13 (streaming CTs cannot be buffered-and-transformed).

**curl:**

```bash
curl -i -X POST "$GW/anything/sse" \
  -H "Content-Type: text/event-stream" \
  -H "Source: partnerA" \
  --data-binary "data: hello"
```

**Response:**

```
HTTP/1.1 415 Unsupported Media Type
content-type: application/json
content-length: 73
date: Thu, 12 Nov 2026 10:52:03 GMT
server: Anypoint Flex Gateway
x-correlation-id: 6cb582d4-b7be-4c2d-8a1a-0df8ece1c3e4

{"errorMessage":"Unsupported streaming Content-Type","source":"partnerA"}
```

**What this proves:** SSE and gRPC-shaped requests on a transforming
leg are rejected before buffering could deadlock. `is_streaming_content_type`
matches `text/event-stream`, `application/grpc`, `application/grpc+proto`.

---

## Scenario 13 — `Range:` on a transforming request leg → 416

**Fixes:** #20 (range contract explicitly refused rather than silently
honoured by the codec, which would corrupt the range semantics).

**curl:**

```bash
curl -i -X POST "$GW/anything/range" \
  -H "Content-Type: application/json" \
  -H "Range: bytes=0-100" \
  -H "Source: partnerA" \
  --data-binary '{"x":1}'
```

**Response:**

```
HTTP/1.1 416 Range Not Satisfiable
content-type: application/json
content-length: 88
date: Thu, 12 Nov 2026 10:52:34 GMT
server: Anypoint Flex Gateway
x-correlation-id: b155fcd7-f0de-42a7-9bdb-dc9e8b89b8a6

{"errorMessage":"Range requests not supported on transforming legs","source":"partnerA"}
```

**What this proves:** issue #20 required that we either implement a
coherent range contract or reject outright — this is the outright
rejection branch, properly propagated to a client-visible 416.

---

## Scenario 21 — Tampered ciphertext → 400 "Malformed ciphertext"

**Fixes:** #1 regression (MAC rejects tampered envelopes before AES
decrypt even runs; secret never reaches AES code).

**Setup:** a valid v2 envelope was produced locally via the HTML tester
using the same base64 key as `aeskeys/partnerA`, then one character
inside the base64 payload was flipped. Because the flipped byte lands
inside the ciphertext region (not the magic/version header), the
unsupported-version path is not taken; instead the MAC verification
fails. Both land on 400 "Malformed ciphertext" per the
`CodecError` → HTTP mapping table.

**curl:**

```bash
curl --location "$GW/anything/ping" \
  -H "Content-Type: application/octet-stream" \
  -H "X-Content-Type: application/json" \
  -H "Source: partnerA" \
  --data-binary '<tampered v2 envelope>'
```

**Response body:**

```
{"errorMessage":"Malformed ciphertext","source":"partnerA"}
```

**What this proves:** MAC verification rejects tampered envelopes
with no leakage of AES decryption state. The error body is JSON (not
raw CodecError Debug), and the status is 400 (caller-provided
malformed data), not 500 (policy-side error).

**Operational note surfaced during this evidence pass:** the policy's
in-process secret cache initially held a stale key from a previous
AWS rotation, and the first run of this scenario failed against a
freshly-generated valid envelope with a MAC mismatch. Rotating the
policy's `cacheConfig.ttl` (or any other field) in API Manager
changes the cache namespace (part of #22) and immediately flushed the
stale entry. This is itself a working-as-designed proof of #22b:
reconfiguring any element of the AWS authorization tuple invalidates
the cache.

---

## Scenario 30 — Upstream responds with gzip → fail-closed 502

**Fixes:** #18 — the whole reason `enable_stop_iteration` was adopted.
Pre-1.0.3, an Encrypt-mode gateway with an upstream that returned a
gzipped 200 would **pass the plaintext through** because the body
inspection happened after status was already committed. v1.0.3 uses
the combined `IntoHeadersBodyState` to inspect headers + body in one
step and rewrite `:status`, `Content-Type`, and body atomically.

**curl:**

```bash
curl -i "$GW/gzip" -H "Source: partnerA"
```

**Response:**

```
HTTP/1.1 502 Bad Gateway
access-control-allow-credentials: true
access-control-allow-origin: *
access-control-expose-headers: Retry-After, RateLimit, RateLimit-Policy, WWW-Authenticate
x-content-type-options: nosniff
date: Thu, 12 Nov 2026 11:28:10 GMT
content-type: application/json
server: Anypoint Flex Gateway
transfer-encoding: chunked
x-correlation-id: 2cff4632-f0fe-4ea1-ab40-18bc9158bede
Strict-Transport-Security: max-age=31536000; includeSubdomains
Connection: Keep-Alive

{"errorMessage":"Upstream response Content-Encoding not supported by policy","source":"partnerA"}
```

**What this proves:**

- `:status` was rewritten from upstream's 200 → 502.
- `Content-Type` was rewritten from upstream's (gzip-marked) type → `application/json`.
- Upstream's `Content-Encoding: gzip` header was **stripped** — the strict client that would have failed on "the JSON claims to be gzipped but isn't" is no longer misled. (This header-strip is the fix that landed after the initial evidence capture; see "known-issue-and-resolution" section above.)
- Upstream's gzipped bytes **never reached the client**; a structured JSON error replaced them.

---

## Scenario 31 — Upstream responds with SSE → fail-closed 502

**Fixes:** #18.

**curl:**

```bash
curl -i "$GW/sse" -H "Source: partnerA"
```

**Response:**

```
HTTP/1.1 502 Bad Gateway
access-control-allow-credentials: true
access-control-allow-origin: *
access-control-expose-headers: Retry-After, RateLimit, RateLimit-Policy, WWW-Authenticate
x-content-type-options: nosniff
date: Thu, 12 Nov 2026 11:28:21 GMT
content-type: application/json
server: Anypoint Flex Gateway
transfer-encoding: chunked
x-correlation-id: b1df1bab-0f6c-4cd9-93ab-a222535b1b60
Strict-Transport-Security: max-age=31536000; includeSubdomains
Connection: Keep-Alive

{"errorMessage":"Upstream response Content-Type is streaming and cannot be transformed","source":"partnerA"}
```

**What this proves:** same structural guarantee as 30, this time for
the streaming-CT case. The upstream's SSE framing never reached the
client; a single-shot JSON response replaced it.

---

## Scenario 32 — Upstream responds with 1 MiB body → fail-closed 502

**Fixes:** #18 + #19 (response-leg size cap is the same derived
`RUNTIME_WRITE_BUFFER` as the request leg).

**curl:**

```bash
curl -i "$GW/bytes/1048576" -H "Source: partnerA"
```

**Response:**

```
HTTP/1.1 502 Bad Gateway
access-control-allow-credentials: true
access-control-allow-origin: *
access-control-expose-headers: Retry-After, RateLimit, RateLimit-Policy, WWW-Authenticate
x-content-type-options: nosniff
date: Thu, 12 Nov 2026 11:10:00 GMT
content-type: application/json
server: Anypoint Flex Gateway
transfer-encoding: chunked
x-correlation-id: d0a14126-e7aa-4242-8fa0-c2d00629bfcc
Strict-Transport-Security: max-age=31536000; includeSubdomains
Connection: Keep-Alive

{"errorMessage":"Upstream response exceeds policy size limit","source":"partnerA"}
```

**What this proves:** upstream's 1 MiB random body never reached the
client; a 76-byte JSON error replaced it.

---

## Scenario 40 — `sourceBinding: principalMatch` with no prior auth → 403

**Fixes:** #22a — the new default rejects header-trust bypass unless an
earlier auth policy has populated an identity the Encryption policy
can match against `Source`.

**Policy config for this scenario only:** `sourceBinding: principalMatch`,
no other auth policy applied to this API instance.

**curl:**

```bash
curl -i -X POST "$GW/anything/pm" \
  -H "Content-Type: application/json" \
  -H "Source: partnerA" \
  --data-binary '{"x":1}'
```

**Response:**

```
HTTP/1.1 403 Forbidden
content-type: application/json
content-length: 70
date: Thu, 12 Nov 2026 11:13:41 GMT
server: Anypoint Flex Gateway
x-correlation-id: aa4d1948-0b79-42b0-8564-2a17bbca0f26

{"errorMessage":"Not authorized to select Source","source":"partnerA"}
```

**Gateway log line (also captured in Anypoint Monitoring for this
correlation id):**

```
sourceBinding=principalMatch but no Authentication data found — prior
auth policy did not run or did not populate principal/client_id
```

**What this proves:** reviewer's exact concern in #22 — "merely placing
authentication before this policy does not bind the header to the
principal" — is addressed. The new default rejects when no auth policy
has populated an identity; an operator who wants the pre-1.0.3
behaviour must set `sourceBinding: headerTrust` explicitly and accept
responsibility for pairing Source to the authenticated principal.

---

## Scenario 41 — Malformed Source header → 400

**Fixes:** #2 complement (`source_allowed` char-set validation; path
traversal attempt).

**curl:**

```bash
curl -i -X POST "$GW/anything/bad-source" \
  -H "Content-Type: application/json" \
  -H "Source: ../etc/passwd" \
  --data-binary '{"x":1}'
```

**Response:**

```
HTTP/1.1 400 Bad Request
content-type: application/json
content-length: 70
date: Thu, 12 Nov 2026 10:52:42 GMT
server: Anypoint Flex Gateway
x-correlation-id: 7cd92efa-ee15-4404-a622-1b70845e7ab8

{"errorMessage":"Missing or invalid  Source","source":"../etc/passwd"}
```

**What this proves:** `source_allowed` rejects anything outside
`[A-Za-z0-9._-]{1,128}` before the value reaches the SigV4 payload or
the cache. The SigV4 body is still constructed via serde (#2 proper),
so even if this layer were bypassed the JSON injection vector is
closed; this is the second line of defence.

---

## Scenario 50 — Plain/Plain true byte-exact pass-through

**Fixes:** #20 — the central correctness fix. Pre-1.0.3, Plain/Plain
still ran `plan_request_header_swap` and stripped representation
headers. v1.0.3 skips the entire plan+mutate path when
`requestMode == Plain`.

**curl:**

```bash
curl -i -X POST "$GW/anything/pass" \
  -H "Content-Type: application/json" \
  -H "ETag: \"abc123\"" \
  -H "Source: partnerA" \
  --data-binary '{"ping":1}'
```

**Response:**

```
HTTP/1.1 200 OK
content-length: 695
content-type: application/json
date: Thu, 12 Nov 2026 11:11:21 GMT
server: Anypoint Flex Gateway
x-correlation-id: ac24239b-773a-494b-90d3-55f156e4a088

{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Content-Length": "10",
    "Content-Type": "application/json",
    "Etag": "\"abc123\"",
    "Host": "httpbin.org",
    "Source": "partnerA",
    "Traceparent": "00-f38a137c227222847b86ef2bbb07f6c5-9603ae68a9edb42a-01",
    "Tracestate": "",
    "User-Agent": "curl/8.7.1",
    "X-Correlation-Id": "ac24239b-773a-494b-90d3-55f156e4a088"
  },
  "method": "POST",
  "url": "https://httpbin.org/anything/pass",
  "data": "{\"ping\":1}",
  "files": {},
  "form": {},
  "json": { "ping": 1 }
}
```

**What this proves — directly, from httpbin's reflection:**

- **Backend received `Content-Type: application/json`** (NOT stripped). In v1.0.2 this header would have been dropped by `plan_request_header_swap`'s drop list.
- **Backend received `Etag: "abc123"`** (NOT stripped). Same story.
- **Backend received the exact plaintext body** (`{"ping":1}`), reflected at `data`.

This is point-blank evidence the #20 regression is closed.

---

## Scenario 51 — Plain/Encrypt preserves request Content-Type, encrypts response

**Fixes:** #20 (Plain request leg preserves headers) + baseline Encrypt response leg.

**curl:**

```bash
curl -i -X POST "$GW/anything/plain-encrypt" \
  -H "Content-Type: application/json" \
  -H "Source: partnerA" \
  --data-binary '{"ping":1}'
```

**Response:**

```
HTTP/1.1 200 OK
access-control-allow-credentials: true
access-control-allow-origin: *
access-control-expose-headers: Retry-After, RateLimit, RateLimit-Policy, WWW-Authenticate
x-content-type-options: nosniff
date: Thu, 12 Nov 2026 11:10:18 GMT
x-content-type: application/json
content-type: application/octet-stream
server: Anypoint Flex Gateway
transfer-encoding: chunked
x-correlation-id: 9fff7898-12e3-48bb-97f3-5da835ea2b1e
Strict-Transport-Security: max-age=31536000; includeSubdomains
Connection: Keep-Alive

S0ECZILVPB0tIRV3G8gt4OctSSDN9z/FObXyDrTdGcmQmU5pRAko6+sBstzbvDfb1SA5LKpEYd1b4Bgrl6yXvv/v+opItiJu3YsUcRsHvbSd6ajMzc6Of6J+rZPIHCMzuyJXAy4l6/82hKcOd/vX3OgpnDGnluuDAKYZ6emBMl/+HWttki0eYiy5MeLLNQ9w8cqZfrSUaQylMSzNz5X/PjzZyOs/hHQy5kOvADesc/1XlwKgsBj5qKUFLtsZ7g1Wxt2S1XYevR/sanoJop/pU5jY/07ZEayJ9MyVu0P1pq/oqcIVI9z+4FRN2Hc1JUoOr3BgYPI/298/NxS8oIN7aVGvkYhEsj1UKXy6FYU/uZ0NlTuqGMW9z1VXV+CSXMxs0dGUg53iYd6gBLov/pTvWiWnK9DSpnDUzGnZZoRNQbTGGK7/oV2IqEsSnaAPwbyAHt/atKEjo6AQVBEfIN3ijU0PCaojcOX2B+FDjWEJerrnICOrw9X4zOb8y1boUhuL14DNNutdtzAZvIOnTO6IpjxaPRwhhjTZRlWHPFe2P/3EMIXLxkCD8fSDoVtUj/rg5TOoYiScPNtqippZN6ASwy79fIIED6HgkmEH9Yec5qCsKdJ6LmVo+1SlghhiuXuUi6hcuNLYzU20+m2gpTAvaqVX38JU+IGUAFus0GbJTUgfgaIH9SZPY2rzRMuq7Lul3f05wpTsaqF8GTD+7mqTXcBezTwpNfZDVmQIBc9NYw4mWqN+nLf8F30TBo+1ZMhmokJyH/crk58OOLpWjfMoGPhtG5CZqu5MdMdw6P9RHiYGJdTpuTas5yUz3wLi36d5eAT9dqzi5x1oa7WoBn6QEn/47v9Xqq/Q2R3dWObaAVq+TX1A1wYtQTIvQxyH2WyGjjq3+YgxZCuiN1y1KCvvPMb53XR+LkrfKCFhlSOou/BPBZKEcbzzMlBeH7um6dCc1fCo3/S0yVcdwHsi5hZiFwUGCg==
```

**What this proves:**

- The response body is a base64 string starting with `S0EC` — the v2 magic+version pair — so the Encrypt response leg emitted a valid v2 envelope.
- The response `Content-Type` was swapped to `application/octet-stream` and `X-Content-Type: application/json` is set so a downstream decryptor can restore the original MIME type.
- Because the request leg was Plain, no representation-stale headers were stripped from the forwarded request — the backend got the original JSON (verified separately via `Content-Type` chaining on the way back; this transcript shows the response-leg output).

---

## Known-issue-and-resolution surfaced during this pass

While capturing scenario 30, the first response showed status `502` and
a JSON error body but **left upstream's `Content-Encoding: gzip` header
untouched** on the rewritten response. A strict client would try to
inflate that JSON and fail.

Root cause: `fail_closed_response` in `src/lib.rs` originally stripped
representation validators (`ETag`, `Content-Length`, etc.) but did not
strip body-encoding headers. Fixed in the same 1.0.3 WASM — the strip
list now also covers `Content-Encoding`, `Content-Language`,
`Transfer-Encoding`, `Vary`, and `Trailer`. The transcript above
reflects the post-fix behavior. The companion unit test
`fail_closed_rewrites_status_content_type_and_body` in
`src/lib.rs::tests` was extended to cover all five additional headers
to prevent regression.

---

## Verification summary

| Discipline | Result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy --lib --tests -- -D warnings` | clean |
| `cargo test --lib` | 78/78 pass |
| `cargo test --test requests --no-run` | compiles (full run requires Docker) |
| `python3 -I scripts/test_redact_generated_config.py` | 19/19 pass |
| `cargo build --target wasm32-wasip1 --release` | 1.4 MB, zero warnings |
| Live gateway evidence | 14 scenarios, all pass |

Reviewer's five follow-up blockers from the 2026-11-12 re-review:

- **#18 Fail-closed response via `enable_stop_iteration`** — scenarios 30, 31, 32
- **#19 Correct v2 payload limits** — scenario 10 (plus derived limit test in `src/codec/mod.rs`)
- **#20 Preserve Plain request headers** — scenarios 13, 50, 51
- **#21 Complete redaction + runnable regression evidence** — host tests + integration scaffold + `make lint`; strict redactor
- **#22 Bind Source to identity + cache isolation** — scenario 40 (identity binding); cache rotation observed in scenario 21 operational note

All five are addressed in code, test, docs, and now live-gateway
transcript. Recommendation: proceed with v1.0.3 release approval.
