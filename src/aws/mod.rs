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

/// Errors that `fetch_secret_string` can return. Each variant carries
/// semantic meaning so the caller can map it to the right HTTP status
/// (issue #15) — caller-supplied bad input is 4xx, our own problems are
/// 5xx, and dependency outages are 5xx too (503).
#[derive(Debug)]
pub enum AwsSecretError {
    /// Transport-level failure calling AWS (connection reset, DNS, TLS).
    /// Caller should return 503.
    HttpClient(String),
    /// AWS returned a response but it wasn't JSON. Treat as a dependency
    /// outage — 503.
    JsonParse,
    /// A ResourceNotFoundException from AWS — the named secret does not
    /// exist. This is almost always a caller mistake (bad Source header).
    /// Caller should return 400.
    NotFound,
    /// AWS refused the signed request (SigV4 rejected, IAM policy denied,
    /// invalid access key, expired STS token). This is a policy
    /// MISCONFIGURATION, not a caller problem. Caller should return 500.
    AuthFailed(String),
    /// AWS throttled or returned an internal failure. Transient dependency
    /// state — caller should return 503.
    Throttled(String),
    /// AWS returned a well-formed JSON response but it's missing the
    /// `SecretString` field. Usually means the secret is stored as
    /// `SecretBinary`, which this policy does not support. 500.
    MissingSecretString,
    /// Other AWS-side error identified by an `__type` we don't handle
    /// specifically. 503 by default — treat as dependency.
    Other(String),
}

impl fmt::Display for AwsSecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpClient(m)       => write!(f, "HTTP client error while fetching secret: {m:?}"),
            Self::JsonParse           => f.write_str("Failed to parse secret JSON"),
            Self::NotFound            => f.write_str("Secret not found in AWS Secrets Manager"),
            Self::AuthFailed(m)       => write!(f, "AWS rejected the signed request: {m}"),
            Self::Throttled(m)        => write!(f, "AWS throttled or unavailable: {m}"),
            Self::MissingSecretString => f.write_str("Secret value has no SecretString (likely stored as SecretBinary)"),
            Self::Other(m)            => write!(f, "AWS error: {m}"),
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
    fn from(_: pdk::hl::InvalidUri) -> Self { Self::HttpClient("invalid URI".into()) }
}

/// Map an AWS Secrets Manager error response into a typed `AwsSecretError`.
/// AWS returns a 400 with JSON like `{"__type":"ResourceNotFoundException",...}`
/// for domain errors and a 400/5xx with the same shape for infra errors.
fn classify_aws_error(status: u32, body_json: &serde_json::Value) -> AwsSecretError {
    let ty = body_json
        .get("__type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let msg = body_json
        .get("Message")
        .or_else(|| body_json.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Error type (if present) is the authoritative signal — AWS always
    // returns 400 even for 5xx-worthy conditions.
    match ty {
        "ResourceNotFoundException" => AwsSecretError::NotFound,
        "AccessDeniedException"
        | "UnrecognizedClientException"
        | "InvalidSignatureException"
        | "ExpiredTokenException"
        | "InvalidClientTokenId" => AwsSecretError::AuthFailed(ty.to_string()),
        "ThrottlingException"
        | "InternalServiceError"
        | "InternalFailure"
        | "ServiceUnavailable"
        | "SlowDown" => AwsSecretError::Throttled(ty.to_string()),
        "" if status >= 500 => AwsSecretError::Throttled(format!("HTTP {status}")),
        "" if status == 403 => AwsSecretError::AuthFailed(format!("HTTP {status}")),
        "" if status == 400 => AwsSecretError::Other(format!("HTTP 400 no __type: {msg}")),
        _ => AwsSecretError::Other(format!("{ty}: {msg} (HTTP {status})")),
    }
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
    // Build it via serde (issue #2) so a caller-supplied SecretId cannot
    // inject sibling fields such as `VersionStage` into the signed body.
    #[derive(serde::Serialize)]
    struct GetSecretValueRequest<'a> { #[serde(rename = "SecretId")] secret_id: &'a str }
    let payload = serde_json::to_vec(&GetSecretValueRequest { secret_id })
        .expect("GetSecretValueRequest is always serialisable");

    let (_canonical, string_to_sign, credential_scope) =
        build_sigv4_strings(&host, &amz_date, &date_stamp, &creds.region, &payload);

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
        .body(&payload)
        .post()
        .await
        .map_err(|e| {
            trace(ctx, Level::Error, &format!("Get secret from AWS - AWS call failed: {e:?}"));
            AwsSecretError::HttpClient(format!("{e:?}"))
        })?;

    let status = response.status_code();
    trace(ctx, Level::Info, &format!("Get secret from AWS - HTTP {status}"));

    let json: serde_json::Value = serde_json::from_slice(response.body()).map_err(|e| {
        trace(ctx, Level::Error, &format!("Get secret from AWS - Failed to parse secret JSON: {e:?}"));
        AwsSecretError::JsonParse
    })?;

    // Non-200 responses: classify the __type from AWS so the caller can
    // map ResourceNotFoundException → 400, AccessDenied → 500, throttling
    // → 503, etc. (issue #15).
    if status != 200 {
        let err = classify_aws_error(status, &json);
        trace(ctx, Level::Error, &format!("Get secret from AWS - error: {err}"));
        return Err(err);
    }

    json.get("SecretString")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(AwsSecretError::MissingSecretString)
}

// ---------------------------------------------------------------------------
// Tests — host unit tests for the pure helpers. The AWS call itself can't be
// unit-tested here (it needs a real `HttpClient`/`Service` pair), but the
// signing math and the error-classification logic are pure and worth
// covering. Classifier tests map directly to reviewer finding #15.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- classify_aws_error (issue #15) ---------------------------------

    #[test]
    fn classifies_resource_not_found_as_caller_error() {
        let body = json!({ "__type": "ResourceNotFoundException", "Message": "nope" });
        assert!(matches!(
            classify_aws_error(400, &body),
            AwsSecretError::NotFound
        ));
    }

    #[test]
    fn classifies_access_denied_as_misconfig() {
        for ty in [
            "AccessDeniedException",
            "UnrecognizedClientException",
            "InvalidSignatureException",
            "ExpiredTokenException",
            "InvalidClientTokenId",
        ] {
            let body = json!({ "__type": ty, "Message": "denied" });
            let err = classify_aws_error(400, &body);
            assert!(
                matches!(err, AwsSecretError::AuthFailed(_)),
                "{ty} should map to AuthFailed, got {err:?}"
            );
        }
    }

    #[test]
    fn classifies_throttling_as_transient() {
        for ty in [
            "ThrottlingException",
            "InternalServiceError",
            "InternalFailure",
            "ServiceUnavailable",
            "SlowDown",
        ] {
            let body = json!({ "__type": ty });
            let err = classify_aws_error(400, &body);
            assert!(
                matches!(err, AwsSecretError::Throttled(_)),
                "{ty} should map to Throttled, got {err:?}"
            );
        }
    }

    /// If AWS returned a 5xx with no __type, we must still treat it as
    /// transient — never as a caller error.
    #[test]
    fn classifies_bare_5xx_as_throttled() {
        let body = json!({});
        let err = classify_aws_error(500, &body);
        assert!(
            matches!(err, AwsSecretError::Throttled(_)),
            "bare HTTP 500 must map to Throttled, got {err:?}"
        );
        let err = classify_aws_error(503, &body);
        assert!(
            matches!(err, AwsSecretError::Throttled(_)),
            "bare HTTP 503 must map to Throttled, got {err:?}"
        );
    }

    #[test]
    fn classifies_bare_403_as_auth_failed() {
        let body = json!({});
        let err = classify_aws_error(403, &body);
        assert!(
            matches!(err, AwsSecretError::AuthFailed(_)),
            "bare HTTP 403 must map to AuthFailed, got {err:?}"
        );
    }

    #[test]
    fn classifies_unknown_type_as_other() {
        let body = json!({ "__type": "SomeNewFutureException", "Message": "?" });
        assert!(matches!(
            classify_aws_error(400, &body),
            AwsSecretError::Other(_)
        ));
    }

    #[test]
    fn classifies_bare_400_as_other() {
        // 400 with no __type — likely a caller / validation issue.
        let body = json!({ "Message": "malformed" });
        assert!(matches!(
            classify_aws_error(400, &body),
            AwsSecretError::Other(_)
        ));
    }

    // ---- signing primitives ---------------------------------------------

    /// Sanity: the SigV4 canonical-request / string-to-sign shapes are
    /// stable (exactly the layout AWS specifies). A regression here would
    /// break every call, so pin the shape.
    #[test]
    fn sigv4_strings_have_expected_layout() {
        let (canonical, sts, scope) = build_sigv4_strings(
            "secretsmanager.us-east-1.amazonaws.com",
            "20260101T000000Z",
            "20260101",
            "us-east-1",
            b"{}",
        );
        // Canonical request begins with POST\n/\n\n
        assert!(canonical.starts_with("POST\n/\n\n"), "canonical starts wrong");
        // Must contain each header line and the signed-headers list.
        assert!(canonical.contains("content-type:application/x-amz-json-1.1"));
        assert!(canonical.contains("host:secretsmanager.us-east-1.amazonaws.com"));
        assert!(canonical.contains("x-amz-date:20260101T000000Z"));
        assert!(canonical.contains("x-amz-target:secretsmanager.GetSecretValue"));
        assert!(canonical.contains("content-type;host;x-amz-date;x-amz-target"));
        // Scope shape: yyyymmdd/region/service/aws4_request
        assert_eq!(scope, "20260101/us-east-1/secretsmanager/aws4_request");
        // StringToSign has 4 lines: algo, amz_date, scope, hash
        assert_eq!(sts.lines().count(), 4);
        assert_eq!(sts.lines().next().unwrap(), "AWS4-HMAC-SHA256");
    }

    /// The signing-key derivation is a fixed HMAC chain. Compare against a
    /// known-answer test from the AWS docs (the test vector in the SigV4
    /// examples), verifying our chain matches AWS's exactly.
    #[test]
    fn signing_key_matches_aws_test_vector() {
        // From the AWS SigV4 test suite:
        //   secret   = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
        //   date     = "20120215"
        //   region   = "us-east-1"
        //   service  = "iam"
        // Expected signing key (hex):
        //   f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex::encode(&key),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d",
            "SigV4 key derivation drifted from the AWS reference",
        );
    }

    #[test]
    fn sha256_hex_is_lowercase_hex() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }
}
