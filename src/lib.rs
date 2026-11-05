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
    fn parse(s: &str) -> Self {
        match s {
            "Encrypt" => Self::Encrypt,
            "Decrypt" => Self::Decrypt,
            _         => Self::Plain,
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

fn ttl_from(cfg: &Config) -> TtlPolicy {
    TtlPolicy {
        max_entries: CACHE_CAPACITY,
        ttl_secs:    cfg.cache_config.ttl.try_into().unwrap(),
    }
}

// ---------------------------------------------------------------------------
// Secret resolution — cache first, AWS Secrets Manager on miss
// ---------------------------------------------------------------------------

async fn resolve_secret(
    cfg: &Config,
    client: HttpClient,
    policy: &TtlPolicy,
    cache: &impl Cache,
    headers: &HeaderBag,
) -> std::result::Result<String, Flow<()>> {
    let ctx = TraceCtx::from_headers(headers);
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

fn plan_request_header_swap(mode: Mode, headers: &HeaderBag) -> (HashMap<String, String>, Vec<&'static str>) {
    let drop = vec!["Content-Type", "content-length"];
    let xct = headers.get("x-content-type").cloned().unwrap_or_default();

    let mut add = HashMap::new();
    match mode {
        Mode::Encrypt => {
            add.insert("Content-Type".into(), "application/octet-stream".into());
            add.insert("X-Content-Type".into(), xct);
        }
        Mode::Decrypt => {
            add.insert("Content-Type".into(), xct);
        }
        Mode::Plain => {}
    }
    (add, drop)
}

fn plan_response_header_swap(
    mode: Mode,
    headers: &HeaderBag,
    upstream_ct: &str,
) -> (HashMap<String, String>, Vec<&'static str>) {
    let drop = vec!["Content-Type", "content-length"];
    let mut add = HashMap::new();

    match mode {
        Mode::Encrypt => {
            add.insert("Content-Type".into(), "application/octet-stream".into());
            add.insert("X-Content-Type".into(), upstream_ct.to_owned());
        }
        Mode::Decrypt => {
            let xct = headers.get("x-content-type").cloned().unwrap_or_default();
            add.insert("Content-Type".into(), xct);
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
    cfg: &Config,
    client: HttpClient,
    cache: &impl Cache,
) -> Flow<String> {
    let ttl = ttl_from(cfg);
    let request_mode = Mode::parse(&cfg.request_mode);
    let response_mode = Mode::parse(&cfg.response_mode);

    let encrypt_allow_list =
        parse_allow_list(cfg.success_status_code.clone().unwrap_or_default().as_str());
    let decrypt_allow_list =
        parse_allow_list(cfg.success_status_code_decrypt.clone().unwrap_or_default().as_str());

    let headers_state = request_state.into_headers_state().await;
    let method = headers_state.method();
    let hh = headers_state.handler();

    let headers = snap_headers(hh, WATCHED);
    let ctx = TraceCtx::from_headers(&headers);

    if method != "GET" {
        if let Flow::Break(resp) = require_header(hh, "x-content-type", &ctx) {
            return Flow::Break(resp);
        }
    }

    let secret = match resolve_secret(cfg, client, &ttl, cache, &headers).await {
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
        let (add, drop) = plan_request_header_swap(request_mode, &headers);
        mutate_headers(hh, &add, &drop);

        let outcome = match request_mode {
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
        response_mode,
        encrypt_allow_list,
        decrypt_allow_list,
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
    let upstream_ct = hh.header("Content-Type").unwrap_or_default();

    let codec = match Codec::from_b64_key(&state.secret) {
        Ok(c) => c,
        Err(_) => return,
    };

    match state.response_mode {
        Mode::Encrypt if state.encrypt_allow_list.iter().any(|c| c == &status) => {
            let (add, drop) = plan_response_header_swap(Mode::Encrypt, &state.headers, &upstream_ct);
            mutate_headers(hh, &add, &drop);
            body::encrypt_response(headers_state, &codec, &state.headers).await;
        }
        Mode::Decrypt if state.decrypt_allow_list.iter().any(|c| c == &status) => {
            let (add, drop) = plan_response_header_swap(Mode::Decrypt, &state.headers, &upstream_ct);
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
    let cfg: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Failed to parse configuration '{}'. Cause: {}",
            String::from_utf8_lossy(&bytes),
            err
        )
    })?;

    let ttl = ttl_from(&cfg);
    let cache = cache_builder
        .new(CACHE_NAME.to_string())
        .max_entries(ttl.max_entries)
        .shared()
        .build();

    let filter = on_request(|rs, client| on_request_filter(rs, &cfg, client, &cache))
        .on_response(|rs, rd| on_response_filter(rs, rd));

    launcher.launch(filter).await?;
    Ok(())
}
