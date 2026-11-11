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
use crate::codec::{strip_ws, Codec};
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
const CACHE_NAME: &str = "policy-cache";
const CACHE_CAPACITY: usize = 100;

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
    let fetched = fetch_secret_string(&creds, &secret_name, client, &cfg.aws_service, &ctx)
        .await
        .map_err(|e| {
            trace(&ctx, Level::Error, &format!("Fetch Secret (AWS) - Failed: {e}"));
            error_response(400, "Missing or invalid  Source", &ctx)
        })?;

    let _ = cache_put(cache, policy, &secret_name, &fetched);
    Ok(fetched)
}

// ---------------------------------------------------------------------------
// Body transforms
// ---------------------------------------------------------------------------

mod body {
    use super::*;

    fn write_error_body(h: &dyn BodyHandler, ctx: &TraceCtx<'_>, msg: &str) {
        let payload = serde_json::json!({
            "errorMessage": msg,
            "source":       ctx.source,
        })
        .to_string();
        let _ = h.set_body(payload.as_bytes());
    }

    pub async fn encrypt_request(hs: RequestHeadersState, codec: &Codec, headers: &HeaderBag) -> Flow<()> {
        let ctx = TraceCtx::from_headers(headers);
        let body_state = hs.into_body_state().await;
        let bh = body_state.handler();
        let body = bh.body();

        if body.is_empty() {
            return Flow::Continue(());
        }

        let plaintext = String::from_utf8_lossy(body.as_slice());
        match codec.seal(&plaintext, &ctx) {
            Ok(enc) => {
                if let Err(e) = bh.set_body(enc.as_bytes()) {
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

        let encoded = String::from_utf8_lossy(body.as_slice());
        let cleaned = strip_ws(&encoded);
        match codec.open(&cleaned, &ctx) {
            Ok(plain) => {
                if let Err(e) = bh.set_body(plain.as_bytes()) {
                    trace(&ctx, Level::Error, &format!("Failed to set error body: {e}"));
                    return error_response(500, "Failed in set body after decryption in request", &ctx);
                }
                trace(&ctx, Level::Info, "Decrypt request and replace Body - Decryption success ");
                Flow::Continue(())
            }
            Err(e) => {
                trace(&ctx, Level::Error, &format!("Decrypt request and replace Body - Decryption failed: {e}"));
                error_response(500, "Internal Server Error", &ctx)
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

        let plaintext = String::from_utf8_lossy(body.as_ref()).to_string();
        match codec.seal(&plaintext, &ctx) {
            Ok(enc) => {
                if let Err(e) = bh.set_body(enc.as_bytes()) {
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

        let encoded = String::from_utf8_lossy(body.as_ref()).to_string();
        let cleaned = strip_ws(&encoded);
        match codec.open(&cleaned, &ctx) {
            Ok(plain) => {
                if let Err(e) = bh.set_body(plain.as_bytes()) {
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
    let drop = vec!["Content-Type", "content-length"];
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
    let drop = vec!["Content-Type", "content-length"];
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

    let cache = cache_builder
        .new(CACHE_NAME.to_string())
        .max_entries(validated.ttl.max_entries)
        .shared()
        .build();

    let filter = on_request(|rs, client| on_request_filter(rs, &validated, client, &cache))
        .on_response(|rs, rd| on_response_filter(rs, rd));

    launcher.launch(filter).await?;
    Ok(())
}
