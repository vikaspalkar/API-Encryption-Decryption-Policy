# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

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
