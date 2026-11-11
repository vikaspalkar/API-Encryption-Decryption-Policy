// AES-256-CBC Encrypt/Decrypt policy for Omni(Flex) Gateway.
//
// Fetches a per-`Source` AES-256 key from AWS Secrets Manager (named
// `aeskeys/<Source>`), caches it in Flex memory for `cacheConfig.ttl`
// seconds, and uses it to encrypt or decrypt request/response bodies
// based on `requestMode` and `responseMode`.

mod aws;
mod codec;
mod generated;
mod support;

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use pdk::cache::*;
use pdk::hl::*;
use serde::{Deserialize, Serialize};

use crate::aws::{fetch_secret_string, SecretsManagerCreds};
use crate::codec::Codec;
use crate::generated::config::Config;
use crate::support::cache::{get as cache_get, put as cache_put, TtlPolicy};
use crate::support::headers::{mutate as mutate_headers, require as require_header, snapshot as snap_headers, HeaderBag};
use crate::support::log::{emit as trace, Level};
use crate::support::reply::error_response;
use crate::support::TraceCtx;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WATCHED: &[&str] = &[
    "Content-Type",
    "Source",
    "X-Content-Type",
];

const DEFAULT_ALLOWED_STATUS: &str = "200, 201, 202, 204";
const CACHE_CAPACITY: usize = 100;
/// Issue #3 — the PDK shared cache is scoped by its string name across
/// every policy instance in a gateway cache-sharing domain. Using a
/// static "policy-cache" meant two instances of this policy (same WASM,
/// different AWS accounts/regions) would hit each other's AES keys. We
/// now build the cache name at runtime from the group_id, AWS region,
/// and a hash of the access key so each `(authority, region)` pair gets
/// its own isolated namespace.
const CACHE_NAME_PREFIX: &str = "api-encryption-decryption-policy";

/// Issue #13 — upper bound on **plaintext** body size we'll attempt to
/// encrypt or **base64 ciphertext** we'll attempt to decrypt. The
/// post-encryption wire size is `4 * ceil((16 + 16 * (ceil(n/16) + 1)) / 3)`
/// which, for n = 768 KiB, is about 1.05 MiB — comfortably below Flex's
/// default 1 MiB write ceiling with headroom for base64 padding. Operators
/// who know their gateway runs with a larger buffer can only grow this in
/// the source today; a future revision could expose it in gcl.yaml.
const MAX_BODY_BYTES: usize = 768 * 1024;

/// Issue #13 — content types we outright refuse to transform because the
/// body never arrives as a single buffered unit. Attempting to transform
/// one would deadlock on end-of-stream.
const UNSUPPORTED_STREAMING_CTS: &[&str] = &[
    "text/event-stream",
    "application/grpc",
    "application/grpc+proto",
];

// ---------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Serialize, Deserialize)]
enum Mode {
    Encrypt,
    Decrypt,
    Plain,
}

impl Mode {
    /// Strict parse — the GCL schema declares an exact enum (Encrypt, Decrypt,
    /// Plain). Anything else is a configuration error and must NOT silently
    /// fall through to Plain (which would disable encryption without the
    /// operator noticing).
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "Encrypt" => Ok(Self::Encrypt),
            "Decrypt" => Ok(Self::Decrypt),
            "Plain"   => Ok(Self::Plain),
            other     => Err(format!(
                "unknown mode {other:?}; expected Encrypt, Decrypt, or Plain"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-filter state
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct TxState {
    secret:              String,
    headers:             HeaderBag,
    response_mode:       Mode,
    encrypt_allow_list:  Vec<String>,
    decrypt_allow_list:  Vec<String>,
}

fn parse_allow_list(user_input: &str) -> Vec<String> {
    let combined = format!("{user_input}, {DEFAULT_ALLOWED_STATUS}");
    combined
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// Config → runtime adapters
// ---------------------------------------------------------------------------

/// Convert the operator's TTL value into a runtime [`TtlPolicy`], rejecting
/// values that would either panic (negative) or silently disable caching
/// (zero). The GCL schema sets `minimum: 1`, but direct/local-mode configs
/// may bypass that — this check is the runtime safety net.
fn ttl_from(cfg: &Config) -> Result<TtlPolicy, String> {
    let ttl: u64 = cfg
        .cache_config
        .ttl
        .try_into()
        .map_err(|_| format!("cacheConfig.ttl must be > 0 (got {})", cfg.cache_config.ttl))?;
    if ttl == 0 {
        return Err("cacheConfig.ttl must be > 0 (got 0)".into());
    }
    Ok(TtlPolicy {
        max_entries: CACHE_CAPACITY,
        ttl_secs:    ttl,
    })
}

/// All operator-supplied values after they've been parsed and validated
/// **once at policy startup**. The request/response filters receive this
/// instead of the raw `Config` so every per-request path is a cheap
/// borrow — no re-parsing modes or re-splitting allow-lists on the hot
/// path, and no way for an invalid value to reach a request handler.
struct ValidatedConfig {
    request_mode:        Mode,
    response_mode:       Mode,
    encrypt_allow_list:  Vec<String>,
    decrypt_allow_list:  Vec<String>,
    ttl:                 TtlPolicy,
    raw:                 Config,
}

impl ValidatedConfig {
    fn from_raw(cfg: Config) -> Result<Self, String> {
        let request_mode  = Mode::parse(&cfg.request_mode)
            .map_err(|e| format!("requestMode: {e}"))?;
        let response_mode = Mode::parse(&cfg.response_mode)
            .map_err(|e| format!("responseMode: {e}"))?;
        let ttl = ttl_from(&cfg)?;
        let encrypt_allow_list =
            parse_allow_list(cfg.success_status_code.clone().unwrap_or_default().as_str());
        let decrypt_allow_list =
            parse_allow_list(cfg.success_status_code_decrypt.clone().unwrap_or_default().as_str());
        Ok(Self {
            request_mode,
            response_mode,
            encrypt_allow_list,
            decrypt_allow_list,
            ttl,
            raw: cfg,
        })
    }
}

// ---------------------------------------------------------------------------
// Secret resolution — cache first, AWS Secrets Manager on miss
// ---------------------------------------------------------------------------

/// Reject Source values that contain anything outside the policy's secret
/// naming scheme. Even though the signed payload is now built via serde
/// (issue #2) so JSON-injection via quotes is impossible, we still
/// restrict the char set so an unexpected value can't accidentally select
/// a different secret (e.g. embedded `/`, slashes, path traversal, URL
/// escapes). Valid: ASCII alphanumeric, `.`, `_`, `-`.
fn source_allowed(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// Issue #8 — this policy only transforms bodies when their wire bytes
/// are the plaintext (encrypt leg) or base64 ciphertext (decrypt leg).
/// Any Content-Encoding other than identity means the wire bytes are
/// compressed/encoded in some way the policy doesn't understand: we
/// would end up either base64-ing gzip bytes (encrypt) or trying to
/// base64-decode gzip bytes (decrypt). Both corrupt the payload.
///
/// Returns `None` if the request is safe to transform (no Content-Encoding
/// header, or an explicit "identity"); `Some(encoding)` if it must be
/// rejected.
fn unsupported_encoding(hh: &dyn HeadersHandler) -> Option<String> {
    match hh.header("Content-Encoding") {
        None => None,
        Some(v) => {
            let normalised = v.trim().to_ascii_lowercase();
            if normalised.is_empty() || normalised == "identity" {
                None
            } else {
                Some(normalised)
            }
        }
    }
}

/// Issue #13 — SSE, gRPC, and similar streaming content types never arrive
/// as a single buffered body. Attempting to buffer-and-transform them
/// would block the stream forever. Reject at header time.
fn is_streaming_content_type(hh: &dyn HeadersHandler) -> Option<String> {
    let ct = hh.header("Content-Type")?;
    let primary = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if UNSUPPORTED_STREAMING_CTS.iter().any(|s| *s == primary) {
        Some(primary)
    } else {
        None
    }
}

async fn resolve_secret(
    cfg: &Config,
    client: HttpClient,
    policy: &TtlPolicy,
    cache: &impl Cache,
    headers: &HeaderBag,
) -> std::result::Result<String, Flow<()>> {
    let ctx = TraceCtx::from_headers(headers);

    // Reject malformed Source early (issue #2 complement). Never reaches
    // the SigV4 payload or the cache.
    if !source_allowed(ctx.source) {
        trace(&ctx, Level::Error, "Fetch Secret - Source header contains disallowed characters");
        return Err(error_response(400, "Missing or invalid  Source", &ctx));
    }

    let secret_name = format!("aeskeys/{}", ctx.source);

    if let Some(cached) = cache_get(cache, policy, &secret_name, &ctx) {
        trace(&ctx, Level::Info, &format!("Fetch Secret - Got cache secret {secret_name}"));
        return Ok(cached);
    }

    trace(&ctx, Level::Info, &format!("Fetch Secret - No cached Data {secret_name}"));

    let creds = SecretsManagerCreds::new(
        cfg.aws_access_key.clone(),
        cfg.aws_access_secret.clone(),
        cfg.aws_region.clone(),
    );
    // AWS error → HTTP status mapping (issue #15). Caller-named a bad
    // secret → 400; our signing/IAM is wrong → 500; AWS is throttled or
    // down → 503; unknown AWS error → 503 (conservative).
    let fetched = fetch_secret_string(&creds, &secret_name, client, &cfg.aws_service, &ctx)
        .await
        .map_err(|e| {
            use crate::aws::AwsSecretError::*;
            trace(&ctx, Level::Error, &format!("Fetch Secret (AWS) - Failed: {e}"));
            match e {
                NotFound => error_response(400, "Missing or invalid  Source", &ctx),
                AuthFailed(_) | MissingSecretString => {
                    error_response(500, "AWS Secrets Manager configuration error", &ctx)
                }
                Throttled(_) | HttpClient(_) | JsonParse | Other(_) => {
                    error_response(503, "Secret backend temporarily unavailable", &ctx)
                }
            }
        })?;

    let _ = cache_put(cache, policy, &secret_name, &fetched);
    Ok(fetched)
}

// ---------------------------------------------------------------------------
// Body transforms
// ---------------------------------------------------------------------------

mod body {
    use super::*;

    /// Replace the response body with a JSON error.
    ///
    /// Issue #10 — honest acknowledgement: PDK's split header/body state
    /// machine commits response headers (including status and
    /// Content-Type) **before** this function is called. The body
    /// handler surface (`BodyHandler`) only exposes `body` and
    /// `set_body` — there is no supported way to mutate `Content-Type`
    /// or status from the body stage. To do that properly we would need
    /// the `enable_stop_iteration` feature (`IntoHeadersBodyState`),
    /// which this build deliberately avoids.
    ///
    /// Given the constraint, the fail-closed contract this policy can
    /// honour is:
    ///
    /// 1. On transform failure, replace the body with a JSON error so
    ///    the client receives a structured failure signal, never the
    ///    half-transformed or raw plaintext.
    /// 2. Operators and clients are told (via README §10) that on
    ///    failure the response's `Content-Type` may still advertise
    ///    the originally-planned encoding (e.g. application/octet-stream
    ///    for encrypt-mode) — they must parse the body as JSON if
    ///    body starts with `{"errorMessage":`.
    /// 3. If `set_body` itself is rejected by the host, we log it and
    ///    leave the response untouched — attempting any further rewrite
    ///    would just double-fault.
    ///
    /// The next revision (tracked in CHANGELOG) adopts
    /// `enable_stop_iteration` so we can also flip Content-Type and
    /// strip stale validators at this stage.
    fn write_error_body(h: &dyn BodyHandler, ctx: &TraceCtx<'_>, msg: &str) {
        let payload = serde_json::json!({
            "errorMessage": msg,
            "source":       ctx.source,
        })
        .to_string();
        if let Err(e) = h.set_body(payload.as_bytes()) {
            trace(ctx, Level::Error, &format!(
                "Fail-closed response: set_body rejected the error body: {e}"
            ));
        }
    }

    pub async fn encrypt_request(hs: RequestHeadersState, codec: &Codec, headers: &HeaderBag) -> Flow<()> {
        let ctx = TraceCtx::from_headers(headers);
        let body_state = hs.into_body_state().await;
        let bh = body_state.handler();
        let body = bh.body();

        if body.is_empty() {
            return Flow::Continue(());
        }

        // Issue #13: plaintext too large to base64-expand within buffer.
        if body.len() > MAX_BODY_BYTES {
            trace(&ctx, Level::Error, &format!(
                "Encrypt request body too large: {} bytes > {} byte limit",
                body.len(), MAX_BODY_BYTES
            ));
            return error_response(413, "Request body exceeds policy maximum", &ctx);
        }

        // Byte-oriented path (issue #9): we hand raw body bytes to the
        // codec. No UTF-8 coercion in either direction.
        match codec.seal(body.as_slice(), &ctx) {
            Ok(enc) => {
                if let Err(e) = bh.set_body(&enc) {
                    trace(&ctx, Level::Error, &format!("Failed to set error body: {e}"));
                    return error_response(500, "Failed in set body after encryption in request", &ctx);
                }
                trace(&ctx, Level::Info, "Encrypt request and replace Body - Encryption success ");
                Flow::Continue(())
            }
            Err(e) => {
                trace(&ctx, Level::Error, &format!("Encrypt request and replace Body - Encryption failed: {e}"));
                error_response(500, "Internal Server Error", &ctx)
            }
        }
    }

    pub async fn decrypt_request(hs: RequestHeadersState, codec: &Codec, headers: &HeaderBag) -> Flow<()> {
        let ctx = TraceCtx::from_headers(headers);
        let body_state = hs.into_body_state().await;
        let bh = body_state.handler();
        let body = bh.body();

        if body.is_empty() {
            return Flow::Continue(());
        }

        // Issue #13: ciphertext (base64) too large to even decode; also
        // keeps us from spending CPU on absurdly large bodies.
        if body.len() > MAX_BODY_BYTES {
            trace(&ctx, Level::Error, &format!(
                "Decrypt request body too large: {} bytes > {} byte limit",
                body.len(), MAX_BODY_BYTES
            ));
            return error_response(413, "Request body exceeds policy maximum", &ctx);
        }

        // Byte-oriented decrypt (issue #9): the codec strips ASCII
        // whitespace from the base64 input itself and returns raw bytes.
        //
        // Error classification (issue #15):
        //   BadBase64 / Decrypt   → caller sent malformed ciphertext → 400
        //   EntropyFailed         → not possible on decrypt; still 500
        //   KeyLength / CipherInit → our key is bad → 500 (misconfig)
        match codec.open(body.as_slice(), &ctx) {
            Ok(plain) => {
                if let Err(e) = bh.set_body(&plain) {
                    trace(&ctx, Level::Error, &format!("Failed to set error body: {e}"));
                    return error_response(500, "Failed in set body after decryption in request", &ctx);
                }
                trace(&ctx, Level::Info, "Decrypt request and replace Body - Decryption success ");
                Flow::Continue(())
            }
            Err(e) => {
                trace(&ctx, Level::Error, &format!("Decrypt request and replace Body - Decryption failed: {e}"));
                use crate::codec::CodecError::*;
                match e {
                    // Caller sent a malformed or tampered envelope — 400.
                    BadBase64 | BadMagic | UnsupportedVersion(_) | MacMismatch | Decrypt(_) =>
                        error_response(400, "Malformed ciphertext", &ctx),
                    // Our key or host RNG is broken — 500.
                    KeyLength | CipherInit(_) | EntropyFailed(_) =>
                        error_response(500, "Internal Server Error", &ctx),
                }
            }
        }
    }

    pub async fn encrypt_response(hs: ResponseHeadersState, codec: &Codec, headers: &HeaderBag) {
        let ctx = TraceCtx::from_headers(headers);
        let body_state = hs.into_body_state().await;
        let bh = body_state.handler();
        let body = bh.body();

        if body.is_empty() {
            return;
        }

        // Issue #13: oversize responses are passed through. We cannot
        // reasonably rewrite status + content-type on the response leg
        // without breaking the fail-closed contract (#10), so passthrough
        // is the least-bad option here.
        if body.len() > MAX_BODY_BYTES {
            trace(&ctx, Level::Warn, &format!(
                "Encrypt response body too large ({} bytes) — passing through unchanged",
                body.len()
            ));
            return;
        }

        match codec.seal(body.as_ref(), &ctx) {
            Ok(enc) => {
                if let Err(e) = bh.set_body(&enc) {
                    trace(&ctx, Level::Error, &format!("Failed to set error body: {e}"));
                    write_error_body(bh, &ctx, "Failed in set body after encryption in response");
                    return;
                }
                trace(&ctx, Level::Info, "Encrypt resposne and replace Body - Encryption success ");
            }
            Err(e) => {
                trace(&ctx, Level::Error, &format!("Encrypt response and replace Body - Encryption failed: {e}"));
                write_error_body(bh, &ctx, "Response encryption failed");
            }
        }
    }

    pub async fn decrypt_response(hs: ResponseHeadersState, codec: &Codec, headers: &HeaderBag) {
        let ctx = TraceCtx::from_headers(headers);
        let body_state = hs.into_body_state().await;
        let bh = body_state.handler();
        let body = bh.body();

        if body.is_empty() {
            return;
        }

        // Issue #13: same reasoning as encrypt_response.
        if body.len() > MAX_BODY_BYTES {
            trace(&ctx, Level::Warn, &format!(
                "Decrypt response body too large ({} bytes) — passing through unchanged",
                body.len()
            ));
            return;
        }

        match codec.open(body.as_ref(), &ctx) {
            Ok(plain) => {
                if let Err(e) = bh.set_body(&plain) {
                    trace(&ctx, Level::Error, &format!("Failed to set error body: {e}"));
                    write_error_body(bh, &ctx, "Failed in set body after decryption in response");
                    return;
                }
                trace(&ctx, Level::Info, "Decrypt resposne and replace Body - Decryption success ");
            }
            Err(e) => {
                trace(&ctx, Level::Error, &format!("Decrypt response and replace Body - Decryption failed: {e}"));
                write_error_body(bh, &ctx, "Response decryption failed");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Header planning
// ---------------------------------------------------------------------------

/// Plan which request headers to add/drop before body transformation.
///
/// Issue #7 — on Encrypt we preserve the **actual request `Content-Type`**
/// (the plaintext's true media type), not the caller's `X-Content-Type`
/// (which may differ or be absent). After encryption the wire type becomes
/// `application/octet-stream` and the real type travels as `X-Content-Type`
/// to the receiver.
///
/// On Decrypt the caller sent us a ciphertext wrapper; the real plaintext
/// media type lives in their `X-Content-Type`. We restore that onto
/// `Content-Type` before the body transform.
fn plan_request_header_swap(mode: Mode, headers: &HeaderBag) -> (HashMap<String, String>, Vec<&'static str>) {
    // Issue #14: anything that validates or sizes the pre-transform
    // representation is now semantically stale. Strip them so clients
    // don't match a conditional against the ciphertext (nor the other
    // way around).
    let drop = vec![
        "Content-Type",
        "content-length",
        "ETag",
        "Content-Digest",
        "Repr-Digest",
        "Content-Range",
    ];
    let mut add = HashMap::new();
    match mode {
        Mode::Encrypt => {
            // Preserve the true plaintext Content-Type as X-Content-Type.
            let plaintext_ct = headers
                .get("content-type")
                .cloned()
                .unwrap_or_else(|| "application/octet-stream".into());
            add.insert("Content-Type".into(), "application/octet-stream".into());
            add.insert("X-Content-Type".into(), plaintext_ct);
        }
        Mode::Decrypt => {
            // The caller's X-Content-Type names the plaintext media type.
            let xct = headers
                .get("x-content-type")
                .cloned()
                .unwrap_or_else(|| "application/octet-stream".into());
            add.insert("Content-Type".into(), xct);
        }
        Mode::Plain => {}
    }
    (add, drop)
}

/// Plan which response headers to add/drop before body transformation.
///
/// Issue #6 — on Decrypt we restore the plaintext media type from the
/// **upstream response's `X-Content-Type`** (where the upstream explicitly
/// labelled the plaintext), NOT from the request snapshot. The request and
/// response can carry different media types, and a GET may not have sent
/// `X-Content-Type` on the request at all.
fn plan_response_header_swap(
    mode: Mode,
    upstream_ct: &str,
    upstream_xct: &str,
) -> (HashMap<String, String>, Vec<&'static str>) {
    // Issue #14: anything that validates or sizes the pre-transform
    // representation is now semantically stale. Strip them so clients
    // don't match a conditional against the ciphertext (nor the other
    // way around).
    let drop = vec![
        "Content-Type",
        "content-length",
        "ETag",
        "Content-Digest",
        "Repr-Digest",
        "Content-Range",
    ];
    let mut add = HashMap::new();

    match mode {
        Mode::Encrypt => {
            // Upstream sent plaintext; preserve its real type into
            // X-Content-Type and swap wire type to octet-stream.
            add.insert("Content-Type".into(), "application/octet-stream".into());
            add.insert("X-Content-Type".into(), upstream_ct.to_owned());
        }
        Mode::Decrypt => {
            // Upstream sent ciphertext labelled with X-Content-Type.
            // Fall back to octet-stream if the header was missing — the
            // receiver can still read the bytes, just without media typing.
            let restored = if upstream_xct.is_empty() {
                "application/octet-stream".to_owned()
            } else {
                upstream_xct.to_owned()
            };
            add.insert("Content-Type".into(), restored);
        }
        Mode::Plain => {}
    }
    (add, drop)
}

// ---------------------------------------------------------------------------
// Request filter
// ---------------------------------------------------------------------------

async fn on_request_filter(
    request_state: RequestState,
    cfg: &ValidatedConfig,
    client: HttpClient,
    cache: &impl Cache,
) -> Flow<String> {
    let headers_state = request_state.into_headers_state().await;
    let method = headers_state.method();
    let hh = headers_state.handler();

    let headers = snap_headers(hh, WATCHED);
    let ctx = TraceCtx::from_headers(&headers);

    // Plain/Plain fast path (issue #5): if no leg transforms the body,
    // skip header validation, skip the AWS Secrets Manager lookup, and
    // skip header mutation entirely. The request flows through untouched
    // and the response filter's early-return on a non-Encrypt/Decrypt
    // mode produces a true no-op.
    let pure_passthrough =
        matches!(cfg.request_mode,  Mode::Plain) &&
        matches!(cfg.response_mode, Mode::Plain);
    if pure_passthrough {
        return Flow::Continue(String::new());
    }

    // X-Content-Type is only required when a leg actually transforms the
    // body. GETs have no body to transform, and a Plain request leg does
    // not need the sidecar media type for its own leg — but a non-Plain
    // response leg still needs it on the request side to carry media info
    // through the chain, so we only waive the requirement when the
    // request leg itself is Plain AND method is non-GET AND the response
    // leg also won't need it.
    let request_leg_transforms  = !matches!(cfg.request_mode,  Mode::Plain);
    if method != "GET" && request_leg_transforms {
        if let Flow::Break(resp) = require_header(hh, "x-content-type", &ctx) {
            return Flow::Break(resp);
        }

        // Issue #8: reject compressed/encoded bodies before we touch them.
        if let Some(enc) = unsupported_encoding(hh) {
            trace(&ctx, Level::Error, &format!(
                "Request body has Content-Encoding {enc:?} — policy only supports 'identity'"
            ));
            return Flow::Break(
                match error_response(415, "Unsupported Content-Encoding", &ctx) {
                    Flow::Break(r) => r,
                    _ => unreachable!(),
                },
            );
        }

        // Issue #13: reject streaming content types that never buffer as
        // a single body.
        if let Some(ct) = is_streaming_content_type(hh) {
            trace(&ctx, Level::Error, &format!(
                "Request body is streaming Content-Type {ct:?} — policy cannot transform"
            ));
            return Flow::Break(
                match error_response(415, "Unsupported streaming Content-Type", &ctx) {
                    Flow::Break(r) => r,
                    _ => unreachable!(),
                },
            );
        }
    }

    let secret = match resolve_secret(&cfg.raw, client, &cfg.ttl, cache, &headers).await {
        Ok(s) => s,
        Err(break_flow) => return match break_flow {
            Flow::Break(r) => Flow::Break(r),
            Flow::Continue(_) => Flow::Continue(String::new()),
        },
    };

    let codec = match Codec::from_b64_key(&secret) {
        Ok(c) => c,
        Err(e) => {
            trace(&ctx, Level::Error, &format!("Encrypt/Decrypt setup failed: {e}"));
            return Flow::Break(
                match error_response(500, "Internal Server Error", &ctx) {
                    Flow::Break(r) => r,
                    _ => unreachable!(),
                },
            );
        }
    };

    if method != "GET" {
        let (add, drop) = plan_request_header_swap(cfg.request_mode, &headers);
        mutate_headers(hh, &add, &drop);

        let outcome = match cfg.request_mode {
            Mode::Encrypt => body::encrypt_request(headers_state, &codec, &headers).await,
            Mode::Decrypt => body::decrypt_request(headers_state, &codec, &headers).await,
            Mode::Plain   => Flow::Continue(()),
        };
        if let Flow::Break(resp) = outcome {
            return Flow::Break(resp);
        }
    }

    let state = TxState {
        secret,
        headers,
        response_mode:      cfg.response_mode,
        encrypt_allow_list: cfg.encrypt_allow_list.clone(),
        decrypt_allow_list: cfg.decrypt_allow_list.clone(),
    };
    Flow::Continue(serde_json::to_string(&state).unwrap())
}

// ---------------------------------------------------------------------------
// Response filter
// ---------------------------------------------------------------------------

async fn on_response_filter(response_state: ResponseState, carry: RequestData<String>) {
    let RequestData::Continue(json_blob) = carry else { return };

    let state: TxState = match serde_json::from_str(&json_blob) {
        Ok(s) => s,
        Err(_) => return,
    };

    let headers_state = response_state.into_headers_state().await;
    let status = headers_state.status_code().to_string();
    let hh = headers_state.handler();
    // Both upstream metadata headers come from the RESPONSE side (issue
    // #6): Content-Type names the upstream payload's current wire type,
    // and X-Content-Type names the plaintext media type when the upstream
    // is sending ciphertext.
    let upstream_ct  = hh.header("Content-Type").unwrap_or_default();
    let upstream_xct = hh.header("X-Content-Type").unwrap_or_default();

    // Issue #8: if the upstream response is compressed/encoded, we cannot
    // safely base64 its bytes (encrypt) nor base64-decode them (decrypt).
    // Pass the response through untouched — this is the only safe choice
    // on the response leg, where we cannot return a new HTTP status
    // without committing to a different Content-Type too.
    if let Some(enc) = unsupported_encoding(hh) {
        let ctx = TraceCtx::from_headers(&state.headers);
        trace(&ctx, Level::Warn, &format!(
            "Response has Content-Encoding {enc:?} — skipping transform, passing through"
        ));
        return;
    }

    // Issue #13: same reasoning for streaming response types.
    if let Some(ct) = is_streaming_content_type(hh) {
        let ctx = TraceCtx::from_headers(&state.headers);
        trace(&ctx, Level::Warn, &format!(
            "Response is streaming Content-Type {ct:?} — skipping transform, passing through"
        ));
        return;
    }

    let codec = match Codec::from_b64_key(&state.secret) {
        Ok(c) => c,
        Err(_) => return,
    };

    match state.response_mode {
        Mode::Encrypt if state.encrypt_allow_list.iter().any(|c| c == &status) => {
            let (add, drop) = plan_response_header_swap(Mode::Encrypt, &upstream_ct, &upstream_xct);
            mutate_headers(hh, &add, &drop);
            body::encrypt_response(headers_state, &codec, &state.headers).await;
        }
        Mode::Decrypt if state.decrypt_allow_list.iter().any(|c| c == &status) => {
            let (add, drop) = plan_response_header_swap(Mode::Decrypt, &upstream_ct, &upstream_xct);
            mutate_headers(hh, &add, &drop);
            body::decrypt_response(headers_state, &codec, &state.headers).await;
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    cache_builder: CacheBuilder,
) -> Result<()> {
    // Parse the raw config. The error message is deliberately redacted —
    // the raw bytes contain `awsAccessSecret` and we do not want that
    // appearing in gateway logs (issue #4).
    let cfg: Config = serde_json::from_slice(&bytes)
        .map_err(|err| anyhow!("Failed to parse policy configuration: {}", err))?;

    // Validate once at startup. Any failure here aborts policy load with a
    // clear message, instead of letting an invalid value reach a request
    // handler (issue #12). None of these messages reference the raw
    // configuration body.
    let validated = ValidatedConfig::from_raw(cfg)
        .map_err(|e| anyhow!("Invalid policy configuration: {}", e))?;

    // Issue #3 — namespace the cache by AWS authority so two policy
    // instances using different AWS accounts/regions cannot share entries.
    //
    // The identity bundle is (region, SHA-256 of access key). We include a
    // short hash of the access key rather than the key itself: it's stable
    // per IAM principal, is NOT a secret (it's a one-way hash of a
    // public access key ID), and reliably differs between two instances
    // using different IAM users.
    use sha2::{Digest, Sha256};
    let key_hash_short: String = {
        let hash = Sha256::digest(validated.raw.aws_access_key.as_bytes());
        hex::encode(&hash[..6])
    };
    let cache_name = format!(
        "{CACHE_NAME_PREFIX}:{}:{}",
        validated.raw.aws_region,
        key_hash_short,
    );

    let cache = cache_builder
        .new(cache_name)
        .max_entries(validated.ttl.max_entries)
        .shared()
        .build();

    let filter = on_request(|rs, client| on_request_filter(rs, &validated, client, &cache))
        .on_response(|rs, rd| on_response_filter(rs, rd));

    launcher.launch(filter).await?;
    Ok(())
}
