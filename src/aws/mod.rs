//! Minimal AWS Secrets Manager client with hand-rolled SigV4.
//!
//! Only the one API we need — `GetSecretValue` — is implemented. The code
//! is intentionally organised as "pure helpers → one orchestrator" so the
//! signing math can be read top-down without jumping through a request
//! object.

use std::fmt;

use chrono::Utc;
use hmac::{Hmac, Mac};
use pdk::hl::*;
use sha2::{Digest, Sha256};

use crate::support::TraceCtx;
use crate::support::log::{emit as trace, Level};

const SIGN_ALGO: &str = "AWS4-HMAC-SHA256";
const SERVICE: &str = "secretsmanager";
const TARGET_OP: &str = "secretsmanager.GetSecretValue";
const CONTENT_TYPE: &str = "application/x-amz-json-1.1";

/// IAM credentials + region needed to sign a request.
pub struct SecretsManagerCreds {
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
}

impl SecretsManagerCreds {
    pub fn new(access_key: String, secret_key: String, region: String) -> Self {
        Self { access_key, secret_key, region }
    }
}

/// Errors that `fetch_secret_string` can return.
#[derive(Debug)]
pub enum AwsSecretError {
    HttpClient(String),
    JsonParse,
    InvalidUri,
    MissingSecretString,
}

impl fmt::Display for AwsSecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpClient(m) => write!(f, "HTTP client error while fetching secret: {m:?}"),
            Self::JsonParse     => f.write_str("Failed to parse secret JSON"),
            Self::InvalidUri    => f.write_str("Invalid URI used in secret fetch"),
            Self::MissingSecretString => f.write_str("SecretString not found in AWS response"),
        }
    }
}
impl std::error::Error for AwsSecretError {}

impl From<pdk::hl::HttpClientError> for AwsSecretError {
    fn from(e: pdk::hl::HttpClientError) -> Self { Self::HttpClient(format!("{e:?}")) }
}
impl From<serde_json::Error> for AwsSecretError {
    fn from(_: serde_json::Error) -> Self { Self::JsonParse }
}
impl From<pdk::hl::InvalidUri> for AwsSecretError {
    fn from(_: pdk::hl::InvalidUri) -> Self { Self::InvalidUri }
}

// ---------------------------------------------------------------------------
// Signing primitives
// ---------------------------------------------------------------------------

/// `HMAC-SHA256(key, data)` returned as raw bytes.
fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).unwrap();
    m.update(data.as_bytes());
    m.finalize().into_bytes().to_vec()
}

/// Fold the signing-key derivation chain from the AWS docs.
fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let seed = format!("AWS4{secret}");
    [date, region, service, "aws4_request"]
        .iter()
        .fold(seed.into_bytes(), |acc, step| hmac(&acc, step))
}

/// Hex-encode `SHA256(bytes)`.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Build the `(canonical_request, string_to_sign, credential_scope)` tuple.
///
/// Kept as a pure function so it is easy to unit-test offline.
fn build_sigv4_strings(
    host: &str,
    amz_date: &str,
    date_stamp: &str,
    region: &str,
    payload: &[u8],
) -> (String, String, String) {
    let signed_headers = "content-type;host;x-amz-date;x-amz-target";

    let canonical_headers = [
        format!("content-type:{CONTENT_TYPE}"),
        format!("host:{host}"),
        format!("x-amz-date:{amz_date}"),
        format!("x-amz-target:{TARGET_OP}"),
    ]
    .join("\n");

    let payload_hash = sha256_hex(payload);

    let canonical_request = format!(
        "POST\n/\n\n{canonical_headers}\n\n{signed_headers}\n{payload_hash}"
    );

    let credential_scope = format!("{date_stamp}/{region}/{SERVICE}/aws4_request");

    let string_to_sign = format!(
        "{SIGN_ALGO}\n{amz_date}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    (canonical_request, string_to_sign, credential_scope)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Call `secretsmanager.GetSecretValue` and return the `SecretString`.
pub async fn fetch_secret_string(
    creds: &SecretsManagerCreds,
    secret_id: &str,
    client: HttpClient,
    service: &Service,
    ctx: &TraceCtx<'_>,
) -> Result<String, AwsSecretError> {
    let host = format!("secretsmanager.{}.amazonaws.com", creds.region);
    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    // Request body: SecretsManager accepts a single JSON object.
    let payload = format!(r#"{{"SecretId":"{secret_id}"}}"#);

    let (_canonical, string_to_sign, credential_scope) =
        build_sigv4_strings(&host, &amz_date, &date_stamp, &creds.region, payload.as_bytes());

    // Derive key, HMAC the string_to_sign, hex-encode → signature.
    let signing_key = derive_signing_key(&creds.secret_key, &date_stamp, &creds.region, SERVICE);
    let signature = hex::encode(hmac(&signing_key, &string_to_sign));

    let auth_header = format!(
        "{SIGN_ALGO} Credential={}/{credential_scope}, \
         SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature={signature}",
        creds.access_key,
    );

    let response = client
        .request(service)
        .path("/")
        .headers(vec![
            ("Content-Type",  CONTENT_TYPE),
            ("X-Amz-Date",    &amz_date),
            ("X-Amz-Target",  TARGET_OP),
            ("Authorization", &auth_header),
        ])
        .body(payload.as_bytes())
        .post()
        .await
        .map_err(|e| {
            trace(ctx, Level::Error, &format!("Get secret from AWS - AWS call failed: {e:?}"));
            AwsSecretError::HttpClient(format!("{e:?}"))
        })?;

    trace(ctx, Level::Info, "Get secret from AWS - Received response from AWS: \"\"");

    let json: serde_json::Value = serde_json::from_slice(response.body()).map_err(|e| {
        trace(ctx, Level::Error, &format!("Get secret from AWS - Failed to parse secret JSON: {e:?}"));
        AwsSecretError::JsonParse
    })?;

    json.get("SecretString")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(AwsSecretError::MissingSecretString)
}
