//! Builder for the JSON error response the policy returns on failures.

use pdk::hl::*;
use serde_json::json;

use super::TraceCtx;

/// Produce a `Flow::Break` carrying a JSON error body.
///
/// Shape: `{"errorMessage":"…","source":"…"}`
pub fn error_response(status: u32, message: &str, ctx: &TraceCtx<'_>) -> Flow<()> {
    let body = json!({
        "errorMessage": message,
        "source":       ctx.source,
    })
    .to_string();

    let response = Response::new(status)
        .with_headers(vec![("content-type".to_string(), "application/json".to_string())])
        .with_body(body);

    Flow::Break(response)
}
