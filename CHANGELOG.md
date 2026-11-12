# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.3] — 2026-11-12

Second hardening pass closing five P4A re-review blockers (#18–#22) on
top of 1.0.2. All fixes adopt the reviewer's acceptance criteria from
the pinned source links.

### Security

- **Identity binding (fixes #22, part a).** New config property
  `sourceBinding` (enum `principalMatch` | `headerTrust`). The default
  is `principalMatch`, which rejects any request where the `Source`
  header does not exactly match the authenticated `client_id`
  (or `principal` as a fallback) from a prior auth policy. Missing
  authentication data is also rejected. `headerTrust` preserves the
  pre-1.0.3 behaviour but requires operators to explicitly opt in,
  documenting that they chain a prior policy that binds Source to the
  authenticated principal.
- **Cache isolation (fixes #22, part b).** The cache namespace now
  includes every component of the AWS authorization tuple:
  `sha256(region || access_key || sha256(access_secret) || service_uri)`
  truncated to 12 hex chars. A rotation of `awsAccessSecret` or a
  change to `awsService` invalidates any warmed cache entries. The
  access secret is hashed before entering the preimage so the raw
  value never appears in cache names or logs.
- **Complete error redaction (fixes #21, part a).** `redact_serde_error`
  surfaces only error category + line/column from a `serde_json::Error`,
  never the quoted value. `Mode::parse`, `SourceBinding::parse`, and
  `ttl_from` are also value-free. A secret-sentinel misbound into
  `cacheConfig.ttl`, `requestMode`, or any other typed field is now
  provably absent from any log line the policy emits.
- **Strict redactor (fixes #21, part b).** `scripts/redact_generated_config.py`
  exits non-zero (fails the build) whenever the generator template
  drifts to a shape it doesn't recognise AND the output still contains
  a known-unsafe pattern. The old warn-and-succeed behaviour was a
  silent-ship risk.
- **README: envelope MAC does NOT authenticate HTTP headers or prevent
  replay.** New Section 9.1 states this explicitly and names the gateway
  auth policy chain as the responsible layer.

### Correctness

- **Response fail-closed via `enable_stop_iteration` (fixes #18).**
  `on_response_filter` now uses `ResponseState::into_headers_body_state()`
  so it can inspect headers + body in one state and rewrite `:status`
  + `Content-Type` alongside the body. Compressed, streaming,
  oversize, or MAC-mismatched responses are rewritten to **502 Bad
  Gateway** with a JSON error body — not passed through as plaintext.
  The previous "best-effort error body on a committed success" was
  called out by the reviewer as not actually fail-closed; this
  implementation is.
- **Payload limits derived from actual v2 wire expansion (fixes #19).**
  The 1.0.2 cap of 768 KiB plaintext produced a 1,048,668-byte
  envelope — 92 bytes over PDK's default 1 MiB write buffer — and
  accepted 768 KiB of base64 on decrypt, requiring only ~590 KiB of
  plaintext to produce. One instance emitted envelopes an identically
  configured instance would reject. Fix: both legs anchor on the same
  `RUNTIME_WRITE_BUFFER = 1 MiB`; `MAX_PLAINTEXT_BYTES = 786,367`
  (derived by the exact inverse of `wire_size_for_plaintext`);
  `MAX_CIPHERTEXT_B64_BYTES = 1 MiB`. Strict `>` comparisons at every
  boundary. New codec API: `wire_size_for_plaintext(n)` and
  `max_plaintext_for_output(cap)`, both `const fn` with checked
  arithmetic (saturate on overflow).
- **Plain request leg is now true pass-through (fixes #20).**
  Representation headers (`Content-Type`, `Content-Length`, `ETag`,
  `Content-Digest`, `Repr-Digest`, `Content-Range`, `Last-Modified`)
  are only stripped when the request leg actually transforms the body.
  Plain/Encrypt and Plain/Decrypt send the backend byte-exact what
  the caller sent. `X-Content-Type` is now required only on Decrypt
  request legs (Encrypt preserves the real Content-Type automatically
  since #7).
- **`Last-Modified` dropped on transforming legs (fixes #20 followup
  to #14).** CHANGELOG claimed it; code did not. Now matches.
- **Range request rejection (fixes #20).** A `Range:` header on a
  transforming request leg returns HTTP 416 — partial-body transforms
  have no coherent contract.
- **`snapshot` preserves Option semantics (fixes #20).** Missing
  headers stay absent in the lowercase header bag; present-but-empty
  stays `Some("")`. The pre-#20 behaviour silently fabricated empty
  entries and defeated every `Option`-aware consumer.

### Tooling & tests

- **Runnable integration scaffold (fixes #21, part c).** `tests/requests.rs`
  now compiles end-to-end (`cargo test --test requests --no-run`). Six
  `#[pdk_test]` scenarios covering happy path, bad ciphertext, missing
  Source, oversize body, gzip rejection, SSE rejection, and
  principalMatch spoof rejection. `pdk-test`, `httpmock`, `reqwest`,
  and `tokio` added as dev-dependencies. Running requires Docker on
  the developer's machine — wired via new `make test-integration`.
- **`make lint` gate (fixes #21, part d).** Runs `cargo fmt --check`
  and `cargo clippy --lib --tests -- -D warnings`. The codebase passes
  with zero warnings.
- **`make test` now also verifies the integration scaffold compiles.**
- **85 Rust tests total (78 lib + 7 Python).** Up from 45+7 in 1.0.2.
  New coverage: v2 wire-size boundaries, response fail-closed
  rewrite, Plain request pass-through, identity binding (spoofed
  Source, missing auth data, client_id precedence, case sensitivity),
  cache namespace sensitivity to each credential field, no-secret-leak
  invariant, and serde error redaction with a sentinel.

### Migration from 1.0.2 → 1.0.3

1. **New default breaks silent header trust.** `sourceBinding` defaults
   to `principalMatch`. An existing deployment that relied on the
   pre-1.0.3 header-trust behaviour must either:
   - chain a prior auth policy that binds `Source` to the
     authenticated principal (recommended), OR
   - set `sourceBinding: headerTrust` in the policy configuration
     to opt back in (and document that the operator accepts
     responsibility for pairing Source with authenticated identity).
2. **Cache warm-up is implicitly invalidated.** The new namespace
   formula will produce different cache keys than 1.0.2's. First
   request after upgrade is a cache miss per `Source` — no action
   required; TTL handles the rest.
3. **No client-visible wire format change.** v2 envelopes produced by
   1.0.2 decrypt fine under 1.0.3 and vice-versa.
4. **Max plaintext dropped from 786,432 to 786,367.** A workload that
   was deliberately riding the 768 KiB edge will see a 413 one byte
   earlier. Verified exact with reviewer's reproduction math.

## [1.0.2] — 2026-11-11

Hardening pass closing every P4A / security-review finding. All changes are
backwards-**incompatible** with v1 envelopes — see Migration below.

### Security

- **Wire format v2 — Encrypt-then-MAC (fixes #1).** Envelopes now carry a
  2-byte magic (`0x4B 0x41`), a 1-byte version (`0x02`), the 16-byte IV,
  the PKCS#7-padded ciphertext, and a 32-byte HMAC-SHA256 tag covering
  every byte before it. The MAC key is derived from the AES key via
  HKDF-SHA256 with label `"api-encryption-decryption-policy/v2/mac-key"`,
  so operators still manage a single 32-byte secret. v1 envelopes
  (`base64(IV ‖ ciphertext)`, unauthenticated) are **rejected**.
  Tampered ciphertext, flipped IV, or version-downgrade attempts all
  yield constant-time MAC failures.
- **Safe `SecretId` serialisation (fixes #2).** The `GetSecretValue`
  payload is now built via `serde::Serialize` on a typed struct, so a
  caller-supplied `Source` header cannot inject sibling fields (e.g.
  `VersionStage`) into the signed body.
- **Source-header char-set enforcement (fixes #2 complement).** Only
  `[A-Za-z0-9._-]{1,128}` is accepted. Everything else returns HTTP 400
  before the value reaches the cache or AWS.
- **Policy-scoped cache namespace (fixes #3).** The in-process cache name
  is now `api-encryption-decryption-policy:<region>:<sha256(access_key)[..6]>`,
  so two policy instances with different IAM principals cannot read each
  other's cached secrets.
- **Redacted parse errors (fixes #4).** A misshapen policy configuration
  no longer leaks `awsAccessSecret` into gateway logs. The generated
  `init()` function is re-patched by `scripts/redact_generated_config.py`
  on every `make build`, and a Python regression suite pins the patch.

### Correctness

- **Byte-oriented codec (fixes #9).** `seal` / `open` take `&[u8]` and
  return `Vec<u8>`; non-UTF-8 binary bodies round-trip exactly.
- **Plain/Plain fast path (fixes #5).** When both `requestMode` and
  `responseMode` are `Plain`, the policy short-circuits without touching
  the body or calling AWS Secrets Manager.
- **Encrypt leg uses real Content-Type (fixes #7).** The `X-Content-Type`
  header the decrypt leg reads back is the Content-Type of the *actual*
  plaintext, not a hard-coded value.
- **Decrypt leg restores response Content-Type (fixes #6).** After
  decrypting a response body, the gateway restores the upstream's
  `X-Content-Type` as the outbound `Content-Type`.
- **Fail-closed response error contract (fixes #10).** Response-stage
  failures return a JSON error body instead of leaking the upstream
  bytes. (Full Content-Type flip requires `enable_stop_iteration`'s
  `IntoHeadersBodyState` — documented in code; the body replacement
  alone is wired in this release.)
- **Content-Encoding handling (fixes #8).** Only `identity` is
  transformed. `gzip`, `br`, `deflate`, etc. are rejected with HTTP 415.
- **Payload size bound and streaming rejection (fixes #13).** Bodies
  over 768 KiB → HTTP 413. `text/event-stream`, `application/grpc`, and
  `application/grpc+proto` → HTTP 415 at header time.
- **Stale header-validator invalidation (fixes #14).** `ETag` and
  `Last-Modified` are stripped whenever the response body is modified.
- **AWS error classification (fixes #15).**
  `ResourceNotFoundException` → 400,
  `AccessDenied`/`InvalidSignature`/`ExpiredToken` → 500,
  `Throttling`/`InternalServiceError`/`ServiceUnavailable` → 503,
  bare 5xx → 503, bare 403 → 500.
- **Non-panicking IV entropy (fixes #17).** `getrandom` failures return
  `CodecError::EntropyFailed` instead of panicking the worker.
- **Strict mode / TTL validation (fixes #12).** Unknown mode values and
  non-positive `cacheConfig.ttl` fail the policy at config load.

### Tooling & tests

- **Real test suite (fixes #11).** 45 Rust unit tests + 7 Python
  regression tests. Runs via `make test`. Coverage:
  - 15 codec tests — v2 round-trip (JSON, binary, block-boundary),
    tampered ciphertext / MAC / version / magic, short/invalid envelopes,
    bad key length, cross-key MAC isolation, IV uniqueness.
  - 20 lib.rs tests — `Mode::parse` strictness, `source_allowed`
    char-set + length cap, `parse_allow_list` behavior,
    `unsupported_encoding` and `is_streaming_content_type` via an
    inline PDK trait stub.
  - 10 AWS tests — every `classify_aws_error` branch, SigV4 canonical
    string shape, signing-key derivation against the AWS test vector,
    SHA-256 hex correctness.
  - 7 Python tests — redactor removes the raw-config leak, is
    idempotent, and warns when the generator template drifts.
- **Shell-safe cURL builder in `aes-tester.html` (fixes #16).** HTTP
  method is allow-listed to POST/PUT/PATCH; every dynamic value is
  single-quote-wrapped against shell injection.
- **`make test`** now runs both suites.

### Migration

v1.0.1 → v1.0.2 is a **hard cut** on the wire format. See the README
"Migration from v1 envelopes" section. Summary: deploy all gateways to
1.0.2 together, re-generate test fixtures from the updated
`aes-tester.html`, and update any client SDK to the v2 recipe.

## [1.0.1] — 2026-10-16

- Merged `aes-encryption-custom-policy` and `policy-common-23` into a
  single crate.
- Upgraded PDK from 1.3.0 to 1.10.0 and switched WASM target to
  `wasm32-wasip1`.
- First published build verified against a live Omni Gateway 1.14.x.
- Added `aes-tester.html` for in-browser encrypt/decrypt and cURL
  builder.

## [1.0.0]

- Initial internal release.
