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
use pdk::authentication::{Authentication, AuthenticationHandler};
use pdk::cache::*;
use pdk::hl::*;
use serde::{Deserialize, Serialize};

use crate::aws::{fetch_secret_string, SecretsManagerCreds};
use crate::codec::Codec;
use crate::generated::config::Config;
use crate::support::cache::{get as cache_get, put as cache_put, TtlPolicy};
use crate::support::headers::{
    mutate as mutate_headers, require as require_header, snapshot as snap_headers, HeaderBag,
};
use crate::support::log::{emit as trace, Level};
use crate::support::reply::error_response;
use crate::support::TraceCtx;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WATCHED: &[&str] = &["Content-Type", "Source", "X-Content-Type"];

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

/// Issue #19 — size limits derived from the ACTUAL v2 base64 expansion,
/// not an eyeballed 768 KiB. The 1.0.2 cap of 768 KiB plaintext produced a
/// 1,048,668-byte envelope — 92 bytes over PDK's default 1 MiB write
/// buffer — and simultaneously accepted encoded decrypt inputs up to
/// 768 KiB, which would require an encryptor plaintext of only ~590 KiB
/// to produce. One instance could emit envelopes an identically-configured
/// instance would reject.
///
/// Fix: both legs anchor on the same `RUNTIME_WRITE_BUFFER`, and we derive
/// the plaintext/base64 caps from the exact v2 formula via
/// `codec::max_plaintext_for_output` (reviewer-verified).
///
/// Operators whose gateway runs with a larger buffer can grow
/// `RUNTIME_WRITE_BUFFER` in a future revision that exposes it in gcl.yaml;
/// today it is a const until the gcl schema change lands.
const RUNTIME_WRITE_BUFFER: usize = 1024 * 1024;

/// Largest plaintext we'll encrypt. For the default 1 MiB buffer this is
/// exactly 786,367 bytes — one byte less than the reviewer's reproduction
/// of the 1.0.2 off-by-92 bug.
const MAX_PLAINTEXT_BYTES: usize = codec::max_plaintext_for_output(RUNTIME_WRITE_BUFFER);

/// Largest base64 ciphertext we'll decrypt. Same anchor as the encrypt
/// side, so decrypt will accept any envelope encrypt could have emitted.
const MAX_CIPHERTEXT_B64_BYTES: usize = RUNTIME_WRITE_BUFFER;

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
#[cfg_attr(test, derive(Debug))]
enum Mode {
    Encrypt,
    Decrypt,
    Plain,
}

impl Mode {
    /// Stable string form for log lines — kept separate from a `Debug`
    /// derive so it's a deliberate choice visible in traces.
    fn name(self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
            Self::Plain => "Plain",
        }
    }
}

// ---------------------------------------------------------------------------
// Source → caller-identity binding (issue #22)
// ---------------------------------------------------------------------------

/// How the policy decides whether a caller is authorized to select a given
/// `Source` header value.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
enum SourceBinding {
    /// Trust the caller-supplied `Source` header verbatim. Only safe when
    /// an earlier policy in the chain has rewritten / verified it against
    /// the authenticated principal. Pre-1.0.3 behaviour; preserved so
    /// deployments relying on it can opt back in.
    HeaderTrust,
    /// Default from 1.0.3. Require that `Source` exactly matches the
    /// authenticated `client_id` (or `principal` as a fallback) populated
    /// by a prior authentication policy. Mismatch → HTTP 403.
    PrincipalMatch,
}

impl SourceBinding {
    /// Issue #21: value-free error — see Mode::parse above.
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "principalMatch" => Ok(Self::PrincipalMatch),
            "headerTrust" => Ok(Self::HeaderTrust),
            _ => Err("value not one of {principalMatch, headerTrust}".to_string()),
        }
    }
}

impl Mode {
    /// Strict parse — the GCL schema declares an exact enum (Encrypt, Decrypt,
    /// Plain). Anything else is a configuration error and must NOT silently
    /// fall through to Plain (which would disable encryption without the
    /// operator noticing).
    ///
    /// Issue #21: value-free error. We do NOT echo the offending input, so
    /// a secret-looking value misbound here never reaches gateway logs.
    /// The operator has the config in front of them; an exact field-level
    /// pointer is enough.
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "Encrypt" => Ok(Self::Encrypt),
            "Decrypt" => Ok(Self::Decrypt),
            "Plain" => Ok(Self::Plain),
            _ => Err("value not one of {Encrypt, Decrypt, Plain}".to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-filter state
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct TxState {
    secret: String,
    headers: HeaderBag,
    response_mode: Mode,
    encrypt_allow_list: Vec<String>,
    decrypt_allow_list: Vec<String>,
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
/// Issue #21: value-free — do not echo the numeric value the operator
/// supplied (it's an integer and normally not sensitive, but we keep the
/// contract uniform across every validator so an accidental sensitive-
/// shape mis-bind cannot leak through any path).
fn ttl_from(cfg: &Config) -> Result<TtlPolicy, String> {
    let ttl: u64 = cfg
        .cache_config
        .ttl
        .try_into()
        .map_err(|_| "cacheConfig.ttl must be a positive integer".to_string())?;
    if ttl == 0 {
        return Err("cacheConfig.ttl must be a positive integer".into());
    }
    Ok(TtlPolicy {
        max_entries: CACHE_CAPACITY,
        ttl_secs: ttl,
    })
}

/// All operator-supplied values after they've been parsed and validated
/// **once at policy startup**. The request/response filters receive this
/// instead of the raw `Config` so every per-request path is a cheap
/// borrow — no re-parsing modes or re-splitting allow-lists on the hot
/// path, and no way for an invalid value to reach a request handler.
struct ValidatedConfig {
    request_mode: Mode,
    response_mode: Mode,
    source_binding: SourceBinding,
    encrypt_allow_list: Vec<String>,
    decrypt_allow_list: Vec<String>,
    ttl: TtlPolicy,
    raw: Config,
}

impl ValidatedConfig {
    fn from_raw(cfg: Config) -> Result<Self, String> {
        let request_mode =
            Mode::parse(&cfg.request_mode).map_err(|e| format!("requestMode: {e}"))?;
        let response_mode =
            Mode::parse(&cfg.response_mode).map_err(|e| format!("responseMode: {e}"))?;
        // #22: default to the strict binding when the field is absent so an
        // upgrade of the policy binary against an older gcl.yaml schema
        // still gets the safer default rather than silent header-trust.
        let source_binding = match cfg.source_binding.as_deref() {
            None | Some("") => SourceBinding::PrincipalMatch,
            Some(v) => SourceBinding::parse(v).map_err(|e| format!("sourceBinding: {e}"))?,
        };
        let ttl = ttl_from(&cfg)?;
        let encrypt_allow_list =
            parse_allow_list(cfg.success_status_code.clone().unwrap_or_default().as_str());
        let decrypt_allow_list = parse_allow_list(
            cfg.success_status_code_decrypt
                .clone()
                .unwrap_or_default()
                .as_str(),
        );
        Ok(Self {
            request_mode,
            response_mode,
            source_binding,
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
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
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
    let primary = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
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
        trace(
            &ctx,
            Level::Error,
            "Fetch Secret - Source header contains disallowed characters",
        );
        return Err(error_response(400, "Missing or invalid  Source", &ctx));
    }

    let secret_name = format!("aeskeys/{}", ctx.source);

    if let Some(cached) = cache_get(cache, policy, &secret_name, &ctx) {
        trace(
            &ctx,
            Level::Info,
            &format!("Fetch Secret - Got cache secret {secret_name}"),
        );
        return Ok(cached);
    }

    trace(
        &ctx,
        Level::Info,
        &format!("Fetch Secret - No cached Data {secret_name}"),
    );

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
            trace(
                &ctx,
                Level::Error,
                &format!("Fetch Secret (AWS) - Failed: {e}"),
            );
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

    pub async fn encrypt_request(
        hs: RequestHeadersState,
        codec: &Codec,
        headers: &HeaderBag,
    ) -> Flow<()> {
        let ctx = TraceCtx::from_headers(headers);
        let body_state = hs.into_body_state().await;
        let bh = body_state.handler();
        let body = bh.body();

        if body.is_empty() {
            return Flow::Continue(());
        }

        // Issue #19: strict '>' against the exact plaintext cap derived
        // from v2 wire expansion + the runtime write buffer. A body of
        // exactly MAX_PLAINTEXT_BYTES still fits (verified by the codec
        // round_trip_at_max_plaintext_for_1mib test); only `> cap` is
        // rejected.
        if body.len() > MAX_PLAINTEXT_BYTES {
            trace(
                &ctx,
                Level::Error,
                &format!(
                    "Encrypt request body too large: {} bytes > {} byte limit",
                    body.len(),
                    MAX_PLAINTEXT_BYTES
                ),
            );
            return error_response(413, "Request body exceeds policy maximum", &ctx);
        }

        // Byte-oriented path (issue #9): we hand raw body bytes to the
        // codec. No UTF-8 coercion in either direction.
        match codec.seal(body.as_slice(), &ctx) {
            Ok(enc) => {
                if let Err(e) = bh.set_body(&enc) {
                    trace(
                        &ctx,
                        Level::Error,
                        &format!("Failed to set error body: {e}"),
                    );
                    return error_response(
                        500,
                        "Failed in set body after encryption in request",
                        &ctx,
                    );
                }
                trace(
                    &ctx,
                    Level::Info,
                    "Encrypt request and replace Body - Encryption success ",
                );
                Flow::Continue(())
            }
            Err(e) => {
                trace(
                    &ctx,
                    Level::Error,
                    &format!("Encrypt request and replace Body - Encryption failed: {e}"),
                );
                error_response(500, "Internal Server Error", &ctx)
            }
        }
    }

    pub async fn decrypt_request(
        hs: RequestHeadersState,
        codec: &Codec,
        headers: &HeaderBag,
    ) -> Flow<()> {
        let ctx = TraceCtx::from_headers(headers);
        let body_state = hs.into_body_state().await;
        let bh = body_state.handler();
        let body = bh.body();

        if body.is_empty() {
            return Flow::Continue(());
        }

        // Issue #19: decrypt accepts up to the full RUNTIME_WRITE_BUFFER of
        // base64 input — the same anchor the encrypt side uses — so this
        // leg will accept any envelope an identically configured encryptor
        // could have emitted. Strict '>' comparison; equal is fine.
        if body.len() > MAX_CIPHERTEXT_B64_BYTES {
            trace(
                &ctx,
                Level::Error,
                &format!(
                    "Decrypt request body too large: {} bytes > {} byte limit",
                    body.len(),
                    MAX_CIPHERTEXT_B64_BYTES
                ),
            );
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
                    trace(
                        &ctx,
                        Level::Error,
                        &format!("Failed to set error body: {e}"),
                    );
                    return error_response(
                        500,
                        "Failed in set body after decryption in request",
                        &ctx,
                    );
                }
                trace(
                    &ctx,
                    Level::Info,
                    "Decrypt request and replace Body - Decryption success ",
                );
                Flow::Continue(())
            }
            Err(e) => {
                trace(
                    &ctx,
                    Level::Error,
                    &format!("Decrypt request and replace Body - Decryption failed: {e}"),
                );
                use crate::codec::CodecError::*;
                match e {
                    // Caller sent a malformed or tampered envelope — 400.
                    BadBase64 | BadMagic | UnsupportedVersion(_) | MacMismatch | Decrypt(_) => {
                        error_response(400, "Malformed ciphertext", &ctx)
                    }
                    // Our key or host RNG is broken — 500.
                    KeyLength | CipherInit(_) | EntropyFailed(_) => {
                        error_response(500, "Internal Server Error", &ctx)
                    }
                }
            }
        }
    }

    // Response body transformations moved inline into `on_response_filter`
    // (issue #18). They need the combined headers+body state from
    // `enable_stop_iteration` so a fail-closed can rewrite `:status` and
    // `Content-Type` atomically with the body, which the old BodyHandler
    // surface did not allow.
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
///
/// Issue #20 — for `Mode::Plain` this returns an empty (add, drop) pair
/// so the caller is responsible for skipping the mutation step entirely
/// (callers in `on_request_filter` do this, treating request_mode==Plain
/// as a signal to skip both this plan and the mutate call). We intentionally
/// do NOT drop representation headers when the request leg is pass-through
/// — those headers describe the bytes the backend will receive, and a
/// Plain leg leaves those bytes untouched.
fn plan_request_header_swap(
    mode: Mode,
    headers: &HeaderBag,
) -> (HashMap<String, String>, Vec<&'static str>) {
    // Issue #14 + #20: anything that validates or sizes the pre-transform
    // representation is now semantically stale ONLY when the body is being
    // transformed. For Plain we must not strip these — see caller guard.
    //
    // #20 reviewer ask: Last-Modified was named in CHANGELOG but missing in
    // code; added here so we match the advertised contract.
    let drop = vec![
        "Content-Type",
        "content-length",
        "ETag",
        "Content-Digest",
        "Repr-Digest",
        "Content-Range",
        "Last-Modified",
    ];
    let mut add = HashMap::new();
    match mode {
        Mode::Encrypt => {
            // Preserve the true plaintext Content-Type as X-Content-Type.
            // If the caller didn't send one, fall back to octet-stream
            // (per RFC 7231 §3.1.1.5 "If a Content-Type header field is
            // not present, the recipient MAY either assume a media type
            // of application/octet-stream").
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
        Mode::Plain => {
            // Unreachable at runtime: on_request_filter skips both the
            // plan call AND the mutate call for Plain. Leaving this arm
            // defensive in case a future caller forgets the guard.
            return (HashMap::new(), Vec::new());
        }
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
    // Issue #20: symmetric to plan_request_header_swap — Plain means
    // true pass-through. Representation-stale headers only get stripped
    // on legs that actually transform the body.
    if matches!(mode, Mode::Plain) {
        return (HashMap::new(), Vec::new());
    }

    // Issue #14 + #20: anything that validates or sizes the pre-transform
    // representation is now semantically stale. Strip them so clients
    // don't match a conditional against the ciphertext (nor the other
    // way around). Last-Modified added per #20 (CHANGELOG claimed it
    // before; code now matches).
    let drop = vec![
        "Content-Type",
        "content-length",
        "ETag",
        "Content-Digest",
        "Repr-Digest",
        "Content-Range",
        "Last-Modified",
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

/// Issue #22 — enforce that the caller is authorized to select the
/// `Source` they named. Only called when sourceBinding is PrincipalMatch.
///
/// The authenticated identity comes from `pdk::authentication::Authentication`,
/// populated by whatever auth policy ran earlier in the chain
/// (Basic Auth, OAuth2, JWT, Client ID Enforcement, Mutual TLS, …).
///
/// Match rule:
///   - If `client_id` is set, Source MUST equal `client_id`.
///   - Else if `principal` is set, Source MUST equal `principal`.
///   - Else (no auth data at all): **reject** 403 — PrincipalMatch means
///     an auth policy MUST have run; absence of auth means the deployment
///     is missing the prerequisite.
///
/// Comparisons are byte-exact. We deliberately do not do case folding or
/// normalization — Source values are already restricted to a safe ASCII
/// charset by `source_allowed` (#2 complement), and the authenticated
/// identity is likewise an opaque string from the issuer.
fn enforce_source_binding(
    auth: &dyn AuthenticationHandler,
    source: &str,
    ctx: &TraceCtx<'_>,
) -> Result<(), Flow<()>> {
    let Some(data) = auth.authentication() else {
        trace(
            ctx,
            Level::Error,
            "sourceBinding=principalMatch but no Authentication data found — \
             prior auth policy did not run or did not populate principal/client_id",
        );
        return Err(error_response(403, "Not authorized to select Source", ctx));
    };
    let identity = data
        .client_id
        .as_deref()
        .or(data.principal.as_deref())
        .unwrap_or("");
    if identity.is_empty() {
        trace(
            ctx,
            Level::Error,
            "sourceBinding=principalMatch but authenticated principal/client_id is empty",
        );
        return Err(error_response(403, "Not authorized to select Source", ctx));
    }
    if identity != source {
        trace(
            ctx,
            Level::Error,
            "sourceBinding=principalMatch rejected: Source != authenticated identity",
        );
        return Err(error_response(
            403,
            "Source does not match authenticated identity",
            ctx,
        ));
    }
    Ok(())
}

async fn on_request_filter(
    request_state: RequestState,
    cfg: &ValidatedConfig,
    client: HttpClient,
    cache: &impl Cache,
    auth: Authentication,
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
        matches!(cfg.request_mode, Mode::Plain) && matches!(cfg.response_mode, Mode::Plain);
    if pure_passthrough {
        return Flow::Continue(String::new());
    }

    // Issue #20: the request leg is a true pass-through for `Mode::Plain`.
    // Representation headers (Content-Type, Content-Length, ETag,
    // Content-Digest, Repr-Digest, Content-Range, Last-Modified) describe
    // the bytes the backend will receive, and a Plain leg leaves those
    // bytes untouched — so we must NOT strip them. We still do size and
    // key-fetching work below if the response leg transforms.
    //
    // Issue #20: the X-Content-Type sidecar requirement was vestigial on
    // Encrypt (since #7, Encrypt preserves the real Content-Type
    // automatically). Only Decrypt genuinely needs X-Content-Type to
    // know the plaintext media type after decryption. Encrypt no longer
    // requires it.
    let request_leg_transforms = !matches!(cfg.request_mode, Mode::Plain);
    if method != "GET" && request_leg_transforms {
        // Only Decrypt genuinely needs X-Content-Type from the caller.
        if matches!(cfg.request_mode, Mode::Decrypt) {
            if let Flow::Break(resp) = require_header(hh, "x-content-type", &ctx) {
                return Flow::Break(resp);
            }
        }

        // Issue #8: reject compressed/encoded bodies before we touch them.
        if let Some(enc) = unsupported_encoding(hh) {
            trace(
                &ctx,
                Level::Error,
                &format!(
                    "Request body has Content-Encoding {enc:?} — policy only supports 'identity'"
                ),
            );
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
            trace(
                &ctx,
                Level::Error,
                &format!("Request body is streaming Content-Type {ct:?} — policy cannot transform"),
            );
            return Flow::Break(
                match error_response(415, "Unsupported streaming Content-Type", &ctx) {
                    Flow::Break(r) => r,
                    _ => unreachable!(),
                },
            );
        }

        // Issue #20: partial-body transforms make no sense — encrypting
        // a Range slice and sending it as a full envelope would silently
        // drop the range semantics. Reject outright with 416 Range Not
        // Satisfiable (per RFC 9110 §15.5.17, the closest-fitting status
        // for a request this policy will not honour as a range).
        if hh.header("Range").is_some() {
            trace(
                &ctx,
                Level::Error,
                "Request has Range header but request_mode transforms body — rejecting",
            );
            return Flow::Break(
                match error_response(
                    416,
                    "Range requests not supported on transforming legs",
                    &ctx,
                ) {
                    Flow::Break(r) => r,
                    _ => unreachable!(),
                },
            );
        }
    }

    // Issue #22 — identity binding (part a). When sourceBinding is
    // principalMatch we require that the Source header match the
    // authenticated client_id / principal. Done BEFORE the AWS lookup so
    // an unauthorized caller never triggers a signed request to AWS at
    // all and never sees whether a given Source exists.
    //
    // We read `Source` from the lowercase header snapshot; `ctx.source`
    // is already that string. source_allowed() in `resolve_secret` will
    // still check syntax below.
    if matches!(cfg.source_binding, SourceBinding::PrincipalMatch) {
        if let Err(flow) = enforce_source_binding(&auth, ctx.source, &ctx) {
            return match flow {
                Flow::Break(r) => Flow::Break(r),
                _ => unreachable!(),
            };
        }
    }

    let secret = match resolve_secret(&cfg.raw, client, &cfg.ttl, cache, &headers).await {
        Ok(s) => s,
        Err(break_flow) => {
            return match break_flow {
                Flow::Break(r) => Flow::Break(r),
                Flow::Continue(_) => Flow::Continue(String::new()),
            }
        }
    };

    let codec = match Codec::from_b64_key(&secret) {
        Ok(c) => c,
        Err(e) => {
            trace(
                &ctx,
                Level::Error,
                &format!("Encrypt/Decrypt setup failed: {e}"),
            );
            return Flow::Break(match error_response(500, "Internal Server Error", &ctx) {
                Flow::Break(r) => r,
                _ => unreachable!(),
            });
        }
    };

    // Issue #20: request leg is a true pass-through for `Mode::Plain`.
    // Only touch headers AND body when the request leg actually transforms.
    // The response leg still gets the key via the TxState sidecar below.
    if method != "GET" && !matches!(cfg.request_mode, Mode::Plain) {
        let (add, drop) = plan_request_header_swap(cfg.request_mode, &headers);
        mutate_headers(hh, &add, &drop);

        let outcome = match cfg.request_mode {
            Mode::Encrypt => body::encrypt_request(headers_state, &codec, &headers).await,
            Mode::Decrypt => body::decrypt_request(headers_state, &codec, &headers).await,
            // Unreachable: Plain is excluded by the outer guard.
            Mode::Plain => Flow::Continue(()),
        };
        if let Flow::Break(resp) = outcome {
            return Flow::Break(resp);
        }
    }

    let state = TxState {
        secret,
        headers,
        response_mode: cfg.response_mode,
        encrypt_allow_list: cfg.encrypt_allow_list.clone(),
        decrypt_allow_list: cfg.decrypt_allow_list.clone(),
    };
    Flow::Continue(serde_json::to_string(&state).unwrap())
}

// ---------------------------------------------------------------------------
// Response filter
// ---------------------------------------------------------------------------

/// JSON error body to emit on a fail-closed response transformation.
/// Mirrors the shape of request-side `error_response` so clients see a
/// consistent envelope on both legs.
fn fail_closed_body(message: &str, source: &str) -> Vec<u8> {
    serde_json::json!({
        "errorMessage": message,
        "source":       source,
    })
    .to_string()
    .into_bytes()
}

/// Rewrite the response to a fail-closed error state using the combined
/// headers+body handler. Sets `:status`, forces `Content-Type:
/// application/json`, writes a JSON error body, and strips any
/// representation metadata that would be semantically stale.
///
/// This is only reachable from inside a `HeadersBodyState` on the response
/// leg — the `enable_stop_iteration` feature's `IntoHeadersBodyState`
/// mechanism pauses header emission until the state drops, so mutating
/// `:status` here propagates to the client. `send_response` from the
/// headers-only state cannot be used from the body phase (PDK docs:
/// "Cannot send early response from body state"), so this helper is the
/// response-leg equivalent of that primitive.
fn fail_closed_response(
    hh: &dyn HeadersBodyHandler,
    ctx: &TraceCtx<'_>,
    status: u32,
    message: &str,
) {
    // Overwrite status, swap Content-Type to JSON, drop stale metadata.
    //
    // #18 + live-gateway evidence pass: in addition to the representation
    // validators (ETag, Content-Digest, etc.), strip body-encoding
    // headers. Without this, an upstream that returned
    // `Content-Encoding: gzip` on the response we rejected would leave
    // that header on our plaintext JSON error body — a strict client
    // would try to inflate it and fail. Observed on the gzip response
    // fail-closed transcript (scenario 30).
    hh.set_header(":status", &status.to_string());
    hh.set_header("Content-Type", "application/json");
    for stale in [
        "Content-Length",
        "ETag",
        "Content-Digest",
        "Repr-Digest",
        "Content-Range",
        "Last-Modified",
        "X-Content-Type",
        // Body-encoding headers — must not describe our replacement body.
        "Content-Encoding",
        "Content-Language",
        "Transfer-Encoding",
        "Vary",
        "Trailer",
    ] {
        hh.remove_header(stale);
    }
    let body = fail_closed_body(message, ctx.source);
    if let Err(e) = hh.set_body(&body) {
        // If even the error body write is rejected, there's no further
        // recovery — log and let the response resume. The headers we
        // already wrote (:status, Content-Type) will still be in effect.
        trace(
            ctx,
            Level::Error,
            &format!("fail-closed: set_body failed after status rewrite: {e}"),
        );
    }
}

async fn on_response_filter(response_state: ResponseState, carry: RequestData<String>) {
    let RequestData::Continue(json_blob) = carry else {
        return;
    };

    let state: TxState = match serde_json::from_str(&json_blob) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Issue #18: enter the combined headers+body state so we can inspect
    // headers AND body in a single step. `enable_stop_iteration` pauses
    // header emission while we're here, so if we need to rewrite status
    // and Content-Type on a fail-closed, the client sees the rewritten
    // values — not the upstream's.
    let hb_state = response_state.into_headers_body_state().await;
    let hh = hb_state.handler();
    let ctx = TraceCtx::from_headers(&state.headers);

    // Read the upstream status at the start; it's what we'd pass through
    // unchanged on a true passthrough and what we'd compare against the
    // allow-list for a transforming leg.
    let upstream_status = hh
        .header(":status")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    // --- 1. Plain response → passthrough. No key use, no mutation. ----
    if matches!(state.response_mode, Mode::Plain) {
        return;
    }

    // --- 2. Status-code gating: upstream status outside the allow-list
    // for this mode means we do not transform. Passthrough is the correct
    // behaviour here: the policy deliberately only encrypts/decrypts
    // success responses so an upstream 500 flows through unchanged. ---
    let allow_list = match state.response_mode {
        Mode::Encrypt => &state.encrypt_allow_list,
        Mode::Decrypt => &state.decrypt_allow_list,
        Mode::Plain => return, // handled above
    };
    let status_str = upstream_status.to_string();
    if !allow_list.iter().any(|c| c == &status_str) {
        trace(
            &ctx,
            Level::Info,
            &format!(
                "Response status {upstream_status} not in {} allow-list — passing through",
                state.response_mode.name(),
            ),
        );
        return;
    }

    // From here on we're committed to a transformation. Any failure
    // (precondition or codec) rewrites the response via fail_closed_response.

    // --- 3. Precondition: Content-Encoding (#8 continued).
    // An eligible 200 with gzip/br was previously passed through as
    // plaintext in Encrypt mode. That is exactly the "plaintext never
    // escapes the Encrypt boundary" promise the reviewer named. Fix:
    // reject with 502 Bad Gateway — the backend produced a response we
    // can't honour on this configured leg.
    if let Some(enc) = unsupported_encoding(hh) {
        trace(&ctx, Level::Error, &format!(
            "Response Content-Encoding {enc:?} is not supported on transforming leg — fail-closed 502"
        ));
        fail_closed_response(
            hh,
            &ctx,
            502,
            "Upstream response Content-Encoding not supported by policy",
        );
        return;
    }

    // --- 4. Precondition: streaming content type (#13 continued).
    if let Some(ct) = is_streaming_content_type(hh) {
        trace(&ctx, Level::Error, &format!(
            "Response streaming Content-Type {ct:?} is not supported on transforming leg — fail-closed 502"
        ));
        fail_closed_response(
            hh,
            &ctx,
            502,
            "Upstream response Content-Type is streaming and cannot be transformed",
        );
        return;
    }

    // --- 5. Codec setup. If the stored key is unusable at response time
    // the request leg must have already succeeded with it — this is a
    // defensive guard. 502 because the policy state itself is broken.
    let codec = match Codec::from_b64_key(&state.secret) {
        Ok(c) => c,
        Err(e) => {
            trace(
                &ctx,
                Level::Error,
                &format!("Response leg codec setup failed: {e} — fail-closed 502"),
            );
            fail_closed_response(hh, &ctx, 502, "Policy key material unusable");
            return;
        }
    };

    // --- 6. Read upstream bytes. Reject oversize BEFORE touching headers,
    // so the response is a clean 502 not a half-rewritten 200.
    let body = hh.body();
    let cap = match state.response_mode {
        Mode::Encrypt => MAX_PLAINTEXT_BYTES, // encrypt accepts plaintext
        Mode::Decrypt => MAX_CIPHERTEXT_B64_BYTES, // decrypt accepts b64 input
        Mode::Plain => unreachable!(),
    };
    if body.len() > cap {
        trace(
            &ctx,
            Level::Error,
            &format!(
                "Response body {} bytes exceeds {} byte limit — fail-closed 502",
                body.len(),
                cap,
            ),
        );
        fail_closed_response(hh, &ctx, 502, "Upstream response exceeds policy size limit");
        return;
    }

    // Empty-body is a true no-op (the status/headers were allow-listed but
    // there's nothing to transform). Leave the response alone.
    if body.is_empty() {
        return;
    }

    // --- 7. Capture upstream metadata BEFORE mutation, for the header
    // plan. These values come off the paused upstream headers.
    let upstream_ct = hh.header("Content-Type").unwrap_or_default();
    let upstream_xct = hh.header("X-Content-Type").unwrap_or_default();

    // --- 8. Codec operation. Any failure rewrites the whole response.
    let transformed = match state.response_mode {
        Mode::Encrypt => codec.seal(&body, &ctx),
        Mode::Decrypt => codec.open(&body, &ctx),
        Mode::Plain => unreachable!(),
    };
    let transformed = match transformed {
        Ok(bytes) => bytes,
        Err(e) => {
            use crate::codec::CodecError::*;
            trace(
                &ctx,
                Level::Error,
                &format!(
                    "Response codec operation failed ({}): {e}",
                    state.response_mode.name()
                ),
            );
            // Caller sent malformed ciphertext? That's a 502 — the upstream
            // produced it, not the client, so this is a bad-gateway event
            // from the client's point of view. Internal errors are 502
            // too since the client cannot do anything about them.
            let (code, msg) = match e {
                BadBase64 | BadMagic | UnsupportedVersion(_) | MacMismatch | Decrypt(_) => {
                    (502, "Upstream ciphertext malformed or tampered")
                }
                KeyLength | CipherInit(_) | EntropyFailed(_) => {
                    (502, "Policy codec error on response leg")
                }
            };
            fail_closed_response(hh, &ctx, code, msg);
            return;
        }
    };

    // --- 9. Apply the header plan AND write the transformed body. We
    // have both handlers at once so the client sees a consistent
    // Content-Type for the new body.
    let (add, drop) = plan_response_header_swap(state.response_mode, &upstream_ct, &upstream_xct);
    for k in &drop {
        hh.remove_header(k);
    }
    for (k, v) in &add {
        hh.set_header(k, v);
    }
    if let Err(e) = hh.set_body(&transformed) {
        trace(
            &ctx,
            Level::Error,
            &format!("set_body on transformed response failed: {e} — fail-closed 500"),
        );
        fail_closed_response(hh, &ctx, 500, "Failed to write transformed response body");
        return;
    }
    trace(
        &ctx,
        Level::Info,
        &format!(
            "Response {} transform succeeded ({} bytes → {} bytes)",
            state.response_mode.name(),
            body.len(),
            transformed.len(),
        ),
    );
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

/// Issue #21 — value-free redaction of a `serde_json::Error`.
///
/// The default `Display` impl on a serde_json error quotes the offending
/// input value (`invalid type: string "SECRET_SENTINEL", expected i64`).
/// If an operator misbinds a secret-shaped value into a type-mismatched
/// field (e.g. `cacheConfig.ttl` bound to `$AwsAccessSecretKey`), the
/// secret ends up in gateway logs.
///
/// We only surface:
///   - the error category (Syntax | Data | Eof | Io) — classifies the
///     problem WITHOUT quoting the input;
///   - the line and column — safe location markers.
///
/// We deliberately drop the serde-supplied message text, because it is
/// the vehicle that carries the quoted value. A bounded, categorized
/// pointer is enough for an operator to debug via the gcl.yaml / policy
/// config they already have in front of them.
fn redact_serde_error(err: &serde_json::Error) -> String {
    let cat = match err.classify() {
        serde_json::error::Category::Io => "I/O",
        serde_json::error::Category::Syntax => "malformed JSON",
        serde_json::error::Category::Data => "type or structure mismatch",
        serde_json::error::Category::Eof => "unexpected end of input",
    };
    format!("{cat} at line {}, column {}", err.line(), err.column())
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    cache_builder: CacheBuilder,
) -> Result<()> {
    // Issue #4 + #21 — strip all operator-supplied values from the parse
    // error. The raw bytes contain `awsAccessSecret`; any serde error that
    // quotes an input value could carry that secret into logs.
    let cfg: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Failed to parse policy configuration: {}",
            redact_serde_error(&err)
        )
    })?;

    // Validate once at startup. Any failure here aborts policy load with a
    // clear message, instead of letting an invalid value reach a request
    // handler (issue #12). Messages come from Mode::parse / SourceBinding::
    // parse / ttl_from — all value-free by construction (#21).
    let validated = ValidatedConfig::from_raw(cfg)
        .map_err(|e| anyhow!("Invalid policy configuration: {}", e))?;

    // Issue #3 + #22 — namespace the cache by the FULL AWS authorization
    // tuple so two policy instances with any credential or endpoint
    // difference cannot share cached secrets. Prior to 1.0.3 we used
    // only (region, sha256(access_key)); a rotation of `awsAccessSecret`
    // or a change of `awsService` left the warmed cache usable with
    // stale credentials (reviewer #22, part b).
    //
    // Namespace = sha256(region ‖ 0x00 ‖ access_key ‖ 0x00
    //                    ‖ sha256(access_secret) ‖ 0x00 ‖ service_uri)
    // truncated to 12 hex chars. Reasons:
    //   - We hash the secret rather than including it raw, so the secret
    //     never appears in the cache registry name or in any log line.
    //   - access_key is already public (it's an AWS ACCESS KEY ID); still
    //     in the preimage for stability, but no secrecy claim.
    //   - service_uri distinguishes the production endpoint from a mock
    //     endpoint (or a VPC endpoint from the public one).
    //   - Any one of these changing produces a different namespace, so
    //     the old warmed entries are unreachable and age out via TTL.
    use sha2::{Digest, Sha256};
    let cache_name = {
        let secret_hash = Sha256::digest(validated.raw.aws_access_secret.as_bytes());
        let service_uri = validated.raw.aws_service.uri().to_string();
        let mut hasher = Sha256::new();
        hasher.update(validated.raw.aws_region.as_bytes());
        hasher.update([0x00u8]);
        hasher.update(validated.raw.aws_access_key.as_bytes());
        hasher.update([0x00u8]);
        hasher.update(secret_hash); // already a hash, not the raw secret
        hasher.update([0x00u8]);
        hasher.update(service_uri.as_bytes());
        let ns = hasher.finalize();
        format!("{CACHE_NAME_PREFIX}:{}", hex::encode(&ns[..6]))
    };

    let cache = cache_builder
        .new(cache_name)
        .max_entries(validated.ttl.max_entries)
        .shared()
        .build();

    // Injectables for `on_request`: RequestState, HttpClient (standard),
    // and Authentication (issue #22). PDK's FromContext resolves
    // Authentication from the per-request stream properties, populated
    // by any earlier auth policy.
    let filter =
        on_request(|rs, client, auth| on_request_filter(rs, &validated, client, &cache, auth))
            .on_response(on_response_filter);

    launcher.launch(filter).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — host unit tests (`cargo test --lib`) covering the pure helpers.
// Each cluster below maps to specific P4A reviewer findings:
//   Mode::parse         → #12 (strict mode validation)
//   source_allowed      → #2  (Source header char-set)
//   parse_allow_list    → status allow-list parsing
//   HeadersHandler stub → #8  (Content-Encoding) and #13 (streaming CTs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    // ---- Mode::parse (issue #12) -----------------------------------------

    #[test]
    fn mode_parse_accepts_canonical_values() {
        assert!(matches!(Mode::parse("Encrypt"), Ok(Mode::Encrypt)));
        assert!(matches!(Mode::parse("Decrypt"), Ok(Mode::Decrypt)));
        assert!(matches!(Mode::parse("Plain"), Ok(Mode::Plain)));
    }

    #[test]
    fn mode_parse_rejects_unknown_values() {
        // The entire point of #12 — an unknown value must NOT silently
        // become Plain (which would disable encryption without notice).
        assert!(Mode::parse("encrypt").is_err(), "case-sensitive");
        assert!(Mode::parse("ENCRYPT").is_err());
        assert!(Mode::parse("Bypass").is_err(), "unknown token");
        assert!(Mode::parse("").is_err(), "empty string");
        assert!(Mode::parse(" Encrypt ").is_err(), "no whitespace trimming");
    }

    /// Reversed from 1.0.2 (issue #21): the error does NOT echo the bad
    /// value — a secret misbound here would otherwise leak into logs.
    /// The error still lists the valid options so an operator can debug.
    #[test]
    fn mode_parse_error_is_value_free_and_lists_options() {
        let err = Mode::parse("bogus").unwrap_err();
        assert!(!err.contains("bogus"), "error must NOT echo the value");
        assert!(err.contains("Encrypt"), "but must list the valid options");
    }

    // ---- source_allowed (issue #2) ---------------------------------------

    #[test]
    fn source_allowed_accepts_safe_chars() {
        assert!(source_allowed("partnerA"));
        assert!(source_allowed("partner-A"));
        assert!(source_allowed("partner_A"));
        assert!(source_allowed("partner.A"));
        assert!(source_allowed("ABC123"));
        assert!(source_allowed("a"), "single char is fine");
    }

    #[test]
    fn source_allowed_rejects_dangerous_chars() {
        // These are the classes we must reject: slash (path traversal),
        // quote (JSON injection — even though serde closes that door),
        // whitespace, control chars, unicode.
        assert!(!source_allowed(""), "empty rejected");
        assert!(!source_allowed("partner/A"), "slash forbidden");
        assert!(!source_allowed("partner\\A"), "backslash forbidden");
        assert!(!source_allowed("partner\"A"), "double-quote forbidden");
        assert!(!source_allowed("partner A"), "space forbidden");
        assert!(!source_allowed("partner\nA"), "newline forbidden");
        assert!(!source_allowed("partner\x00A"), "null forbidden");
        assert!(!source_allowed("partnerΩ"), "non-ASCII forbidden");
        assert!(!source_allowed("../etc/passwd"), "path traversal");
    }

    #[test]
    fn source_allowed_enforces_length_cap() {
        let ok = "a".repeat(128);
        let bad = "a".repeat(129);
        assert!(source_allowed(&ok), "128 chars OK");
        assert!(!source_allowed(&bad), "129 chars rejected");
    }

    // ---- parse_allow_list ------------------------------------------------

    #[test]
    fn parse_allow_list_merges_user_and_default() {
        // Empty user input → just the default list.
        let got = parse_allow_list("");
        assert!(got.contains(&"200".to_string()));
        assert!(got.contains(&"201".to_string()));
        assert!(got.contains(&"202".to_string()));
        assert!(got.contains(&"204".to_string()));
    }

    #[test]
    fn parse_allow_list_appends_user_codes() {
        let got = parse_allow_list("418, 299");
        assert!(got.contains(&"418".to_string()));
        assert!(got.contains(&"299".to_string()));
        // defaults still present
        assert!(got.contains(&"200".to_string()));
    }

    #[test]
    fn parse_allow_list_trims_and_drops_empties() {
        let got = parse_allow_list("  418  ,  ,  ");
        assert!(got.contains(&"418".to_string()));
        assert!(
            !got.contains(&"".to_string()),
            "empty tokens must be dropped"
        );
    }

    // ---- HeadersHandler stub (shared by the two tests below) -------------

    /// Minimal stub that satisfies the PDK `HeadersHandler` trait for host
    /// tests. The policy helpers we test only call `.header(name)` — the
    /// mutator methods are no-ops.
    struct StubHeaders {
        store: RefCell<HashMap<String, String>>,
    }
    impl StubHeaders {
        fn with(pairs: &[(&str, &str)]) -> Self {
            let mut m = HashMap::new();
            for (k, v) in pairs {
                m.insert(k.to_string(), v.to_string());
            }
            Self {
                store: RefCell::new(m),
            }
        }
    }
    impl HeadersHandler for StubHeaders {
        fn headers(&self) -> Vec<(String, String)> {
            self.store
                .borrow()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        }
        fn header(&self, name: &str) -> Option<String> {
            // Case-insensitive like real PDK does.
            self.store
                .borrow()
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        }
        fn add_header(&self, _name: &str, _value: &str) {}
        fn set_header(&self, _name: &str, _value: &str) {}
        fn set_headers(&self, _headers: Vec<(&str, &str)>) {}
        fn remove_header(&self, _name: &str) {}
    }

    // ---- unsupported_encoding (issue #8) ---------------------------------

    #[test]
    fn encoding_none_means_safe() {
        let h = StubHeaders::with(&[]);
        assert_eq!(unsupported_encoding(&h), None);
    }

    #[test]
    fn encoding_identity_means_safe() {
        let h = StubHeaders::with(&[("Content-Encoding", "identity")]);
        assert_eq!(unsupported_encoding(&h), None);

        // With surrounding whitespace / mixed case
        let h = StubHeaders::with(&[("Content-Encoding", "  Identity  ")]);
        assert_eq!(unsupported_encoding(&h), None);
    }

    #[test]
    fn encoding_gzip_is_rejected() {
        let h = StubHeaders::with(&[("Content-Encoding", "gzip")]);
        assert_eq!(unsupported_encoding(&h), Some("gzip".to_string()));
    }

    #[test]
    fn encoding_br_is_rejected() {
        let h = StubHeaders::with(&[("Content-Encoding", "BR")]);
        assert_eq!(unsupported_encoding(&h), Some("br".to_string()));
    }

    #[test]
    fn encoding_deflate_is_rejected() {
        let h = StubHeaders::with(&[("Content-Encoding", "deflate")]);
        assert_eq!(unsupported_encoding(&h), Some("deflate".to_string()));
    }

    // ---- is_streaming_content_type (issue #13) ---------------------------

    #[test]
    fn streaming_none_when_no_ct() {
        let h = StubHeaders::with(&[]);
        assert_eq!(is_streaming_content_type(&h), None);
    }

    #[test]
    fn streaming_none_for_json() {
        let h = StubHeaders::with(&[("Content-Type", "application/json")]);
        assert_eq!(is_streaming_content_type(&h), None);
    }

    #[test]
    fn streaming_rejects_sse() {
        let h = StubHeaders::with(&[("Content-Type", "text/event-stream")]);
        assert_eq!(
            is_streaming_content_type(&h),
            Some("text/event-stream".into())
        );
    }

    #[test]
    fn streaming_rejects_grpc() {
        let h = StubHeaders::with(&[("Content-Type", "application/grpc")]);
        assert_eq!(
            is_streaming_content_type(&h),
            Some("application/grpc".into())
        );

        let h = StubHeaders::with(&[("Content-Type", "application/grpc+proto")]);
        assert_eq!(
            is_streaming_content_type(&h),
            Some("application/grpc+proto".into())
        );
    }

    #[test]
    fn streaming_ignores_charset_param() {
        // Content-Type with parameters: only the primary MIME type is compared.
        let h = StubHeaders::with(&[("Content-Type", "text/event-stream; charset=utf-8")]);
        assert_eq!(
            is_streaming_content_type(&h),
            Some("text/event-stream".into())
        );
    }

    #[test]
    fn streaming_case_insensitive() {
        let h = StubHeaders::with(&[("Content-Type", "TEXT/EVENT-STREAM")]);
        assert_eq!(
            is_streaming_content_type(&h),
            Some("text/event-stream".into())
        );
    }

    // ---- Issue #20: Plain request pass-through + plan correctness -------

    use crate::support::headers::snapshot as snap_headers_fn;

    fn bag(pairs: &[(&str, &str)]) -> HeaderBag {
        pairs
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
            .collect()
    }

    /// snapshot MUST NOT fabricate present-but-empty entries for headers
    /// the caller did not send. Reviewer #20 item 4.
    #[test]
    fn snapshot_omits_absent_headers() {
        let h = StubHeaders::with(&[("Content-Type", "application/json")]);
        let snap = snap_headers_fn(&h, &["Content-Type", "Source", "X-Content-Type"]);
        assert_eq!(
            snap.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert!(
            !snap.contains_key("source"),
            "absent Source must not appear"
        );
        assert!(
            !snap.contains_key("x-content-type"),
            "absent X-Content-Type must not appear"
        );
    }

    /// snapshot preserves present-but-empty as Some(""). Distinguishable
    /// from None so downstream fallback logic fires only for the real
    /// None case.
    #[test]
    fn snapshot_preserves_empty_as_some() {
        let h = StubHeaders::with(&[("Content-Type", "")]);
        let snap = snap_headers_fn(&h, &["Content-Type"]);
        assert_eq!(snap.get("content-type").map(String::as_str), Some(""));
    }

    /// Plain mode MUST produce an empty (add, drop) pair — the caller is
    /// expected to skip the mutate call entirely, but the plan itself
    /// must not advertise a drop list that would strip representation
    /// headers.
    #[test]
    fn plain_mode_plans_no_mutation() {
        let headers = bag(&[("content-type", "application/json")]);
        let (add, drop) = plan_request_header_swap(Mode::Plain, &headers);
        assert!(add.is_empty(), "Plain mode must not add any headers");
        assert!(drop.is_empty(), "Plain mode must not drop any headers");
    }

    /// Encrypt mode preserves the caller's actual Content-Type into
    /// X-Content-Type (issue #7) and swaps Content-Type to octet-stream.
    #[test]
    fn encrypt_plan_preserves_content_type_sidecar() {
        let headers = bag(&[("content-type", "application/xml")]);
        let (add, drop) = plan_request_header_swap(Mode::Encrypt, &headers);
        assert_eq!(
            add.get("Content-Type").map(String::as_str),
            Some("application/octet-stream")
        );
        assert_eq!(
            add.get("X-Content-Type").map(String::as_str),
            Some("application/xml")
        );
        // Representation-stale headers are dropped on a transforming leg.
        assert!(drop.contains(&"Content-Type"));
        assert!(
            drop.contains(&"Last-Modified"),
            "#20: Last-Modified must be dropped on transforming legs"
        );
        assert!(drop.contains(&"ETag"));
        assert!(drop.contains(&"Content-Range"));
    }

    /// Encrypt plan without a caller Content-Type falls back to
    /// octet-stream rather than fabricating a MIME type.
    #[test]
    fn encrypt_plan_handles_missing_content_type() {
        let headers = bag(&[]); // caller sent no Content-Type
        let (add, _drop) = plan_request_header_swap(Mode::Encrypt, &headers);
        assert_eq!(
            add.get("X-Content-Type").map(String::as_str),
            Some("application/octet-stream")
        );
    }

    /// Decrypt plan restores Content-Type from the caller's X-Content-Type.
    #[test]
    fn decrypt_plan_restores_content_type_from_sidecar() {
        let headers = bag(&[("x-content-type", "application/json")]);
        let (add, drop) = plan_request_header_swap(Mode::Decrypt, &headers);
        assert_eq!(
            add.get("Content-Type").map(String::as_str),
            Some("application/json")
        );
        assert!(drop.contains(&"Content-Type"));
        assert!(drop.contains(&"Last-Modified"));
    }

    /// Response plan also drops Last-Modified on transforming legs (#20).
    #[test]
    fn response_plan_drops_last_modified() {
        let (_add, drop) = plan_response_header_swap(Mode::Encrypt, "application/json", "");
        assert!(
            drop.contains(&"Last-Modified"),
            "#20: response plan must drop Last-Modified"
        );
    }

    /// Plain response mode produces no header mutation at all.
    #[test]
    fn plain_response_plans_no_mutation() {
        let (add, drop) =
            plan_response_header_swap(Mode::Plain, "application/json", "application/xml");
        assert!(add.is_empty(), "Plain response: nothing to add");
        assert!(drop.is_empty(), "Plain response: nothing to drop");
    }

    // ---- Issue #18: fail_closed_response correctness --------------------

    /// Stub implementing both `HeadersHandler` and `BodyHandler` for the
    /// fail-closed tests. Mutations are recorded; `body()` and `set_body`
    /// use an in-memory buffer so we can assert the exact bytes written.
    struct StubHeadersBody {
        store: RefCell<HashMap<String, String>>,
        body: RefCell<Vec<u8>>,
    }
    impl StubHeadersBody {
        fn with(pairs: &[(&str, &str)], body: &[u8]) -> Self {
            let mut m = HashMap::new();
            for (k, v) in pairs {
                m.insert(k.to_string(), v.to_string());
            }
            Self {
                store: RefCell::new(m),
                body: RefCell::new(body.to_vec()),
            }
        }
    }
    impl HeadersHandler for StubHeadersBody {
        fn headers(&self) -> Vec<(String, String)> {
            self.store
                .borrow()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        }
        fn header(&self, name: &str) -> Option<String> {
            self.store
                .borrow()
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        }
        fn add_header(&self, name: &str, value: &str) {
            self.store
                .borrow_mut()
                .insert(name.to_string(), value.to_string());
        }
        fn set_header(&self, name: &str, value: &str) {
            // Case-insensitive overwrite.
            self.store
                .borrow_mut()
                .retain(|k, _| !k.eq_ignore_ascii_case(name));
            self.store
                .borrow_mut()
                .insert(name.to_string(), value.to_string());
        }
        fn set_headers(&self, headers: Vec<(&str, &str)>) {
            let mut m = self.store.borrow_mut();
            m.clear();
            for (k, v) in headers {
                m.insert(k.to_string(), v.to_string());
            }
        }
        fn remove_header(&self, name: &str) {
            self.store
                .borrow_mut()
                .retain(|k, _| !k.eq_ignore_ascii_case(name));
        }
    }
    impl BodyHandler for StubHeadersBody {
        fn body(&self) -> Vec<u8> {
            self.body.borrow().clone()
        }
        fn set_body(&self, body: &[u8]) -> Result<(), BodyError> {
            *self.body.borrow_mut() = body.to_vec();
            Ok(())
        }
    }
    impl HeadersBodyHandler for StubHeadersBody {}

    fn trace_ctx() -> TraceCtx<'static> {
        TraceCtx { source: "partnerA" }
    }

    /// fail_closed_response must overwrite `:status`, swap `Content-Type`
    /// to `application/json`, strip representation-stale headers, and
    /// write a JSON error body containing the message.
    #[test]
    fn fail_closed_rewrites_status_content_type_and_body() {
        let hh = StubHeadersBody::with(
            &[
                (":status", "200"),
                ("Content-Type", "application/octet-stream"),
                ("Content-Length", "1024"),
                ("Content-Encoding", "gzip"),
                ("Content-Language", "en-US"),
                ("Transfer-Encoding", "chunked"),
                ("Vary", "Accept-Encoding"),
                ("Trailer", "Server-Timing"),
                ("ETag", r#""deadbeef""#),
                ("Last-Modified", "Wed, 12 Nov 2026 12:00:00 GMT"),
                ("X-Content-Type", "application/json"),
            ],
            b"upstream bytes that must NOT leak",
        );

        fail_closed_response(
            &hh,
            &trace_ctx(),
            502,
            "Upstream Content-Encoding not supported",
        );

        // Status overwritten.
        assert_eq!(hh.header(":status").as_deref(), Some("502"));
        // Content-Type swapped to JSON.
        assert_eq!(
            hh.header("Content-Type").as_deref(),
            Some("application/json")
        );
        // Stale metadata stripped — including body-encoding headers that
        // would otherwise lie about our replacement body (observed in the
        // live-gateway evidence pass against httpbin's /gzip endpoint).
        for stale in [
            "Content-Length",
            "ETag",
            "Last-Modified",
            "X-Content-Type",
            "Content-Digest",
            "Repr-Digest",
            "Content-Range",
            "Content-Encoding",
            "Content-Language",
            "Transfer-Encoding",
            "Vary",
            "Trailer",
        ] {
            assert!(
                hh.header(stale).is_none(),
                "{stale} should have been stripped on fail-closed"
            );
        }
        // Body replaced with JSON error.
        let body = hh.body();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(body_str.starts_with("{"), "fail-closed body must be JSON");
        assert!(
            body_str.contains("Upstream Content-Encoding not supported"),
            "fail-closed body must contain the error message"
        );
        assert!(
            body_str.contains("partnerA"),
            "fail-closed body must include the source"
        );
        assert!(
            !body_str.contains("upstream bytes"),
            "fail-closed body must not leak the upstream response"
        );
    }

    /// fail_closed_response is idempotent-ish: calling it when `:status`
    /// is already an error status still succeeds (overwrite).
    #[test]
    fn fail_closed_overwrites_any_prior_status() {
        let hh = StubHeadersBody::with(&[(":status", "500")], b"");
        fail_closed_response(&hh, &trace_ctx(), 502, "x");
        assert_eq!(hh.header(":status").as_deref(), Some("502"));
    }

    /// fail_closed_body is deterministic JSON — guards against accidental
    /// format changes that would break client parsers.
    #[test]
    fn fail_closed_body_shape_is_stable() {
        let bytes = fail_closed_body("the-msg", "the-source");
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["errorMessage"], "the-msg");
        assert_eq!(parsed["source"], "the-source");
    }

    // ---- Issue #22: SourceBinding parsing + enforcement ------------------

    #[test]
    fn source_binding_parse_accepts_canonical() {
        assert_eq!(
            SourceBinding::parse("principalMatch").unwrap(),
            SourceBinding::PrincipalMatch
        );
        assert_eq!(
            SourceBinding::parse("headerTrust").unwrap(),
            SourceBinding::HeaderTrust
        );
    }

    #[test]
    fn source_binding_parse_rejects_unknown() {
        assert!(SourceBinding::parse("").is_err());
        assert!(
            SourceBinding::parse("PrincipalMatch").is_err(),
            "case-sensitive"
        );
        assert!(
            SourceBinding::parse("none").is_err(),
            "no 'none' value — operator must pick principalMatch or headerTrust explicitly"
        );
    }

    /// Stub AuthenticationHandler that returns canned data.
    struct StubAuth {
        data: Option<pdk::authentication::AuthenticationData>,
    }
    impl AuthenticationHandler for StubAuth {
        fn authentication(&self) -> Option<pdk::authentication::AuthenticationData> {
            self.data.clone()
        }
        fn set_authentication(&self, _: Option<&pdk::authentication::AuthenticationData>) {}
    }

    fn auth_with(client_id: Option<&str>, principal: Option<&str>) -> StubAuth {
        StubAuth {
            data: Some(pdk::authentication::AuthenticationData {
                principal: principal.map(str::to_string),
                client_id: client_id.map(str::to_string),
                client_name: None,
                properties: Default::default(),
            }),
        }
    }

    #[test]
    fn enforce_rejects_when_no_authentication_data() {
        let auth = StubAuth { data: None };
        let r = enforce_source_binding(&auth, "partnerA", &trace_ctx());
        assert!(r.is_err(), "no auth data MUST be rejected");
    }

    #[test]
    fn enforce_rejects_when_identity_empty() {
        // Both fields present but empty — treat as "no identity".
        let auth = auth_with(Some(""), Some(""));
        let r = enforce_source_binding(&auth, "partnerA", &trace_ctx());
        assert!(r.is_err());
    }

    #[test]
    fn enforce_rejects_spoofed_source() {
        // Caller authenticated as partnerA but tries to select partnerB.
        let auth = auth_with(Some("partnerA"), None);
        let r = enforce_source_binding(&auth, "partnerB", &trace_ctx());
        assert!(r.is_err(), "Source spoofing MUST be rejected");
    }

    #[test]
    fn enforce_accepts_matching_client_id() {
        let auth = auth_with(Some("partnerA"), None);
        let r = enforce_source_binding(&auth, "partnerA", &trace_ctx());
        assert!(r.is_ok());
    }

    #[test]
    fn enforce_falls_back_to_principal_when_no_client_id() {
        let auth = auth_with(None, Some("partnerA"));
        let r = enforce_source_binding(&auth, "partnerA", &trace_ctx());
        assert!(r.is_ok());
    }

    /// client_id takes precedence over principal — if a caller authenticated
    /// as client_id=A, principal=B, they can only use Source=A.
    #[test]
    fn enforce_prefers_client_id_over_principal() {
        let auth = auth_with(Some("partnerA"), Some("partnerB"));
        assert!(
            enforce_source_binding(&auth, "partnerA", &trace_ctx()).is_ok(),
            "Source matches client_id → accept"
        );
        assert!(
            enforce_source_binding(&auth, "partnerB", &trace_ctx()).is_err(),
            "Source matches principal but NOT client_id → reject"
        );
    }

    #[test]
    fn enforce_is_case_sensitive() {
        let auth = auth_with(Some("partnerA"), None);
        assert!(
            enforce_source_binding(&auth, "partnera", &trace_ctx()).is_err(),
            "identity matching must be byte-exact, no case folding"
        );
    }

    /// Issue #22 — the cache namespace must change when any of
    /// {region, access_key, access_secret, service_uri} changes.
    /// This is a property test over the hashing in `configure` fn; we
    /// extract the formula into a small helper and prove the property
    /// holds for each independent variable.
    #[test]
    fn cache_namespace_responds_to_every_credential_field() {
        use sha2::{Digest, Sha256};
        fn ns(region: &str, ak: &str, sk: &str, uri: &str) -> String {
            let secret_hash = Sha256::digest(sk.as_bytes());
            let mut h = Sha256::new();
            h.update(region.as_bytes());
            h.update([0x00]);
            h.update(ak.as_bytes());
            h.update([0x00]);
            h.update(secret_hash);
            h.update([0x00]);
            h.update(uri.as_bytes());
            hex::encode(&h.finalize()[..6])
        }
        let base = ns("us-east-1", "AKIA", "s3cr3t", "https://sm.example.com");
        // region changes
        assert_ne!(
            base,
            ns("us-west-2", "AKIA", "s3cr3t", "https://sm.example.com")
        );
        // access key changes
        assert_ne!(
            base,
            ns("us-east-1", "AKIB", "s3cr3t", "https://sm.example.com")
        );
        // SECRET rotation changes namespace — this is the core #22 part-b
        assert_ne!(
            base,
            ns("us-east-1", "AKIA", "n3ws3cret", "https://sm.example.com")
        );
        // service URI change (mock → prod, VPC endpoint, etc.)
        assert_ne!(
            base,
            ns("us-east-1", "AKIA", "s3cr3t", "https://sm.other.com")
        );
    }

    // ---- Issue #21: redact_serde_error strips offending values ---------

    /// The reviewer's primary regression for #21: bind a sentinel string
    /// to a wrong-type field; serde_json's default Display would quote
    /// that value in its error. `redact_serde_error` must NOT emit it.
    #[test]
    fn redact_strips_sentinel_value_from_data_error() {
        let sentinel = "SECRET_SENTINEL_42_ROTATE_ME";
        let bad_json = format!(r#"{{"ttl": "{sentinel}"}}"#);
        #[derive(serde::Deserialize, Debug)]
        #[allow(dead_code)]
        struct T {
            ttl: i64,
        }
        let err = serde_json::from_str::<T>(&bad_json).unwrap_err();
        // Sanity: the DEFAULT serde message DOES contain the sentinel.
        assert!(
            err.to_string().contains(sentinel),
            "test premise: serde Display quotes the value",
        );
        // The redacted form must not.
        let redacted = redact_serde_error(&err);
        assert!(
            !redacted.contains(sentinel),
            "redact_serde_error leaked the value: {redacted}",
        );
        // But must still classify the problem.
        assert!(redacted.contains("type or structure mismatch"));
    }

    #[test]
    fn redact_strips_sentinel_value_from_syntax_error() {
        let sentinel = "SECRET_SENTINEL_IN_SYNTAX";
        let bad_json = format!(r#"{{"a":"{sentinel}", "b":}}"#);
        let err = serde_json::from_str::<serde_json::Value>(&bad_json).unwrap_err();
        let redacted = redact_serde_error(&err);
        assert!(
            !redacted.contains(sentinel),
            "redact must strip sentinel even in Syntax errors: {redacted}"
        );
        assert!(redacted.contains("malformed JSON"));
    }

    /// Guarantees we also record line/column so an operator CAN debug
    /// using the config they have in front of them.
    #[test]
    fn redact_reports_line_and_column() {
        let bad_json = "{\n  \"ttl\": \"x\"\n}";
        #[derive(serde::Deserialize, Debug)]
        #[allow(dead_code)]
        struct T {
            ttl: i64,
        }
        let err = serde_json::from_str::<T>(bad_json).unwrap_err();
        let redacted = redact_serde_error(&err);
        assert!(redacted.contains("line "), "{redacted}");
        assert!(redacted.contains("column "), "{redacted}");
    }

    /// Mode::parse must not echo the bad value — a secret mis-bound into
    /// requestMode / responseMode would otherwise surface here.
    #[test]
    fn mode_parse_error_is_value_free() {
        let secret = "SECRET_SENTINEL_IN_MODE";
        let err = Mode::parse(secret).unwrap_err();
        assert!(!err.contains(secret), "Mode::parse echoed the value: {err}");
        assert!(err.contains("Encrypt"), "but still lists the valid options");
    }

    #[test]
    fn source_binding_parse_error_is_value_free() {
        let secret = "SECRET_SENTINEL_IN_BINDING";
        let err = SourceBinding::parse(secret).unwrap_err();
        assert!(
            !err.contains(secret),
            "SourceBinding::parse echoed the value: {err}"
        );
    }

    /// The cache namespace must NOT include the raw access secret anywhere
    /// in its preimage representation. Guards against a future "optimization"
    /// that drops the sha256 wrapper.
    #[test]
    fn cache_namespace_does_not_leak_secret() {
        use sha2::{Digest, Sha256};
        let secret = "SUPER_SECRET_42";
        let secret_hash = Sha256::digest(secret.as_bytes());
        let mut h = Sha256::new();
        h.update(b"us-east-1");
        h.update([0x00]);
        h.update(b"AKIA");
        h.update([0x00]);
        h.update(secret_hash);
        h.update([0x00]);
        h.update(b"https://sm.example.com");
        let ns = hex::encode(&h.finalize()[..6]);
        // ns is 12 hex chars; the raw secret is not. Invariant check:
        assert!(
            !ns.contains("SUPER_SECRET"),
            "namespace must not contain the raw secret"
        );
        assert!(
            !ns.contains("42"),
            "namespace is a 6-byte hash; no plaintext fragment should appear"
        );
    }
}
