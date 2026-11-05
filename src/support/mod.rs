//! Cross-cutting helpers: structured logging, header manipulation, a tiny
//! TTL cache and a reusable error-response builder.
//!
//! Everything in this module is intentionally policy-agnostic — nothing
//! here depends on the AES codec or the generated `Config`.

pub mod cache;
pub mod headers;
pub mod log;
pub mod reply;

use std::collections::HashMap;

pub use headers::HeaderBag;

/// Context carried through every log line and error response.
///
/// Only the `source` header is tracked — it names the AWS secret the
/// request is bound to, so it's useful on every log line and in every
/// error response.
pub struct TraceCtx<'a> {
    pub source: &'a str,
}

impl<'a> TraceCtx<'a> {
    /// Build a context by looking the source up in a lowercase header map.
    /// Missing value becomes an empty string.
    pub fn from_headers(h: &'a HashMap<String, String>) -> Self {
        Self {
            source: h.get("source").map(String::as_str).unwrap_or(""),
        }
    }
}
