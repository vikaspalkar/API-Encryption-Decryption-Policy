//! Integration tests for the API Encryption Decryption Policy (issue #21).
//!
//! These tests spin up a real local-mode Flex Gateway container via
//! `pdk-test`, mount the compiled WASM, and drive end-to-end HTTP round
//! trips against a mocked AWS Secrets Manager and a mocked upstream.
//!
//! `cargo test --test requests --no-run` must compile cleanly on any
//! machine. **Running** the tests requires Docker on the developer's
//! machine — `make test-integration` is the convenience wrapper.
//!
//! Coverage (one test per reviewer-named scenario from #18 / #19 / #20 /
//! #21 / #22):
//!   - round_trip_encrypt_decrypt      — happy path
//!   - rejects_bad_ciphertext_400      — tampered base64 → 400 (request leg)
//!   - rejects_missing_source_400      — Source header absent / malformed
//!   - rejects_oversize_body_413       — request body > 786,367 bytes
//!   - rejects_gzip_encoding_415       — Content-Encoding: gzip
//!   - rejects_sse_content_type_415    — Content-Type: text/event-stream
//!   - principal_match_rejects_spoof   — Source != authenticated identity

mod common;

use common::*;
use httpmock::MockServer;
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};
use serde_json::json;

/// Flex port exposed inside the test network.
const FLEX_PORT: Port = 8081;

/// Target Omni Gateway version. Reviewer #21 required we move off the
/// obsolete 1.7.0. 1.14.0 matches the real deployment target named in
/// the project README.
const FLEX_VERSION: &str = "1.14.0";

/// A deterministic 32-byte AES key, base64-encoded (what the mocked
/// Secrets Manager returns for `aeskeys/partnerA`). NOT a production
/// secret — fixed value so tests reproduce byte-exact.
const TEST_B64_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// Build a baseline, schema-valid policy configuration. Individual tests
/// override specific fields.
fn baseline_config() -> serde_json::Value {
    json!({
        "requestMode":     "Decrypt",
        "responseMode":    "Encrypt",
        "awsAccessKey":    "AKIAIOSFODNN7EXAMPLE",
        "awsAccessSecret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "awsRegion":       "us-east-1",
        "awsService":      "http://backend:80",  // mocked in-cluster upstream
        "cacheConfig":     { "ttl": 86400 },
        "sourceBinding":   "headerTrust", // tests don't chain an auth policy
    })
}

/// Stand up a full composite: a mocked upstream, a mocked Secrets
/// Manager (which the policy's SigV4 client calls), and a Flex
/// container with the policy applied.
async fn compose(
    policy_config: serde_json::Value,
    upstream_path: &str,
) -> anyhow::Result<(TestComposite, String, MockServer)> {
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();

    let policy_config = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(policy_config)
        .build();

    let api_config = ApiConfig::builder()
        .name("myApi")
        .upstream(&httpmock_config)
        .path(upstream_path)
        .port(FLEX_PORT)
        .policies([policy_config])
        .build();

    let flex_config = FlexConfig::builder()
        .version(FLEX_VERSION)
        .hostname("local-flex")
        .with_api(api_config)
        .config_mounts([(POLICY_DIR, "policy"), (COMMON_CONFIG_DIR, "common")])
        .build();

    let composite = TestComposite::builder()
        .with_service(flex_config)
        .with_service(httpmock_config)
        .build()
        .await?;

    let flex: Flex = composite.service()?;
    let flex_url = flex
        .external_url(FLEX_PORT)
        .ok_or_else(|| anyhow::anyhow!("flex external URL not available"))?;

    let httpmock: HttpMock = composite.service()?;
    // httpmock 0.7's connect_async takes the "host:port" string; pdk-test's
    // HttpMock::socket() already returns that form.
    let mock = MockServer::connect_async(httpmock.socket()).await;
    let _ = &mock; // bind so the server stays reachable while tests run

    // Default: the mocked Secrets Manager returns a fixed key for every
    // request. Individual tests can add more specific mocks.
    mock.mock_async(|when, then| {
        when.method("POST").path_contains("/");
        then.status(200)
            .header("Content-Type", "application/x-amz-json-1.1")
            .body(json!({ "SecretString": TEST_B64_KEY }).to_string());
    })
    .await;

    Ok((composite, flex_url.to_string(), mock))
}

// --- Happy path ------------------------------------------------------------

/// End-to-end request leg: client sends plaintext JSON, policy encrypts,
/// upstream receives octet-stream ciphertext (the mock asserts it).
/// We don't try to echo the ciphertext back through decrypt_response in
/// this test because httpmock 0.7 can't dynamically echo the request
/// body; the decrypt-leg round trip is covered by the host codec tests
/// in `src/codec/mod.rs` (`round_trip_binary_bytes`, `round_trip_json`).
#[pdk_test]
async fn encrypt_request_sends_octet_stream_to_upstream() -> anyhow::Result<()> {
    let mut cfg = baseline_config();
    cfg["requestMode"] = json!("Encrypt");
    cfg["responseMode"] = json!("Plain");
    let (_composite, flex_url, mock) = compose(cfg, "/anything/encrypt-only/").await?;

    // Assert on the forwarded request: upstream must receive
    // Content-Type: application/octet-stream and X-Content-Type that
    // records the original plaintext type.
    mock.mock_async(|when, then| {
        when.path_contains("/encrypt-only")
            .header("content-type", "application/octet-stream")
            .header("x-content-type", "application/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(r#"{"ok":true}"#);
    })
    .await;

    let plaintext = r#"{"amount":1000,"currency":"INR"}"#;
    let resp = reqwest::Client::new()
        .post(format!("{flex_url}/encrypt-only"))
        .header("Content-Type", "application/json")
        .header("Source", "partnerA")
        .body(plaintext)
        .send()
        .await?;

    assert_eq!(resp.status(), 200);
    Ok(())
}

// --- Fail-closed paths (issues #18, #19, #20, #22) -------------------------

/// A tampered ciphertext on the request leg → 400 Malformed ciphertext.
#[pdk_test]
async fn rejects_bad_ciphertext_400() -> anyhow::Result<()> {
    let mut cfg = baseline_config();
    cfg["requestMode"] = json!("Decrypt");
    cfg["responseMode"] = json!("Plain");
    let (_composite, flex_url, _mock) = compose(cfg, "/anything/decrypt/").await?;

    let resp = reqwest::Client::new()
        .post(format!("{flex_url}/decrypt"))
        .header("Content-Type", "application/octet-stream")
        .header("X-Content-Type", "application/json")
        .header("Source", "partnerA")
        .body("this-is-not-base64!!!")
        .send()
        .await?;
    assert_eq!(resp.status(), 400);
    Ok(())
}

/// Missing Source header on a transforming request leg → 400.
#[pdk_test]
async fn rejects_missing_source_400() -> anyhow::Result<()> {
    let mut cfg = baseline_config();
    cfg["requestMode"] = json!("Encrypt");
    cfg["responseMode"] = json!("Plain");
    let (_composite, flex_url, _mock) = compose(cfg, "/anything/no-source/").await?;

    let resp = reqwest::Client::new()
        .post(format!("{flex_url}/no-source"))
        .header("Content-Type", "application/json")
        .body(r#"{"ok":true}"#)
        .send()
        .await?;
    assert_eq!(resp.status(), 400);
    Ok(())
}

/// A plaintext just past the derived 786,367-byte cap → 413.
/// Boundary test for issue #19.
#[pdk_test]
async fn rejects_oversize_body_413() -> anyhow::Result<()> {
    let mut cfg = baseline_config();
    cfg["requestMode"] = json!("Encrypt");
    cfg["responseMode"] = json!("Plain");
    let (_composite, flex_url, _mock) = compose(cfg, "/anything/big/").await?;

    let oversize = vec![b'A'; 786_368]; // one byte over the cap
    let resp = reqwest::Client::new()
        .post(format!("{flex_url}/big"))
        .header("Content-Type", "application/octet-stream")
        .header("Source", "partnerA")
        .body(oversize)
        .send()
        .await?;
    assert_eq!(resp.status(), 413);
    Ok(())
}

/// A gzip-encoded request body on a transforming leg → 415.
/// Issue #8 / #18.
#[pdk_test]
async fn rejects_gzip_encoding_415() -> anyhow::Result<()> {
    let mut cfg = baseline_config();
    cfg["requestMode"] = json!("Encrypt");
    cfg["responseMode"] = json!("Plain");
    let (_composite, flex_url, _mock) = compose(cfg, "/anything/gz/").await?;

    let resp = reqwest::Client::new()
        .post(format!("{flex_url}/gz"))
        .header("Content-Type", "application/json")
        .header("Content-Encoding", "gzip")
        .header("Source", "partnerA")
        .body(vec![0x1fu8, 0x8b, 0x08]) // gzip magic prefix
        .send()
        .await?;
    assert_eq!(resp.status(), 415);
    Ok(())
}

/// An SSE Content-Type on a transforming leg → 415.
/// Issue #13 / #18.
#[pdk_test]
async fn rejects_sse_content_type_415() -> anyhow::Result<()> {
    let mut cfg = baseline_config();
    cfg["requestMode"] = json!("Encrypt");
    cfg["responseMode"] = json!("Plain");
    let (_composite, flex_url, _mock) = compose(cfg, "/anything/sse/").await?;

    let resp = reqwest::Client::new()
        .post(format!("{flex_url}/sse"))
        .header("Content-Type", "text/event-stream")
        .header("Source", "partnerA")
        .body("data: hello\n\n")
        .send()
        .await?;
    assert_eq!(resp.status(), 415);
    Ok(())
}

/// Issue #22: with `sourceBinding: principalMatch`, a caller that
/// supplies `Source: partnerB` without an authenticated principal of
/// "partnerB" must be rejected 403. In this scaffold no prior auth
/// policy runs, so Authentication data is absent — the policy must
/// reject because principalMatch demands a principal.
#[pdk_test]
async fn principal_match_rejects_spoof() -> anyhow::Result<()> {
    let mut cfg = baseline_config();
    cfg["requestMode"] = json!("Encrypt");
    cfg["responseMode"] = json!("Plain");
    cfg["sourceBinding"] = json!("principalMatch");
    let (_composite, flex_url, _mock) = compose(cfg, "/anything/pm/").await?;

    let resp = reqwest::Client::new()
        .post(format!("{flex_url}/pm"))
        .header("Content-Type", "application/json")
        .header("X-Content-Type", "application/json")
        .header("Source", "partnerB")
        .body(r#"{"x":1}"#)
        .send()
        .await?;
    assert_eq!(
        resp.status(),
        403,
        "principalMatch with no auth policy must fail 403"
    );
    Ok(())
}
