//! Header read/write helpers used by both request and response filters.
//!
//! The policy only ever cares about a short, fixed list of headers, so we
//! snapshot them into a lowercase [`HashMap`] once per request (`HeaderBag`)
//! and work off that for logging and for threading values into the
//! response filter.

use std::collections::HashMap;

use pdk::hl::*;
use regex::Regex;

use super::TraceCtx;
use super::log::{emit, Level};
use super::reply::error_response;

/// Lowercase header snapshot built from an incoming request.
pub type HeaderBag = HashMap<String, String>;

/// Pull a fixed set of headers into a lowercase map.
///
/// Every requested name is present in the output — missing headers map to
/// the empty string, which matches the original behaviour.
pub fn snapshot(h: &dyn HeadersHandler, wanted: &[&str]) -> HeaderBag {
    wanted
        .iter()
        .map(|name| {
            let value = h.header(name).unwrap_or_default();
            (name.to_ascii_lowercase(), value)
        })
        .collect()
}

/// Fail the request with a 400 if `name` is absent or whitespace-only.
pub fn require(h: &dyn HeadersHandler, name: &str, ctx: &TraceCtx<'_>) -> Flow<()> {
    let present = h
        .header(name)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);

    if present {
        return Flow::Continue(());
    }

    emit(ctx, Level::Error, &format!("Required Header - Missing or empty required header {name}"));
    error_response(400, "Missing or empty required header", ctx)
}

/// Validate a header against a regex. Missing header → 400.
#[allow(dead_code)]
pub fn match_regex(
    h: &dyn HeadersHandler,
    name: &str,
    re: &Regex,
    ctx: &TraceCtx<'_>,
) -> Flow<()> {
    match h.header(name) {
        Some(v) if re.is_match(&v) => Flow::Continue(()),
        Some(_) => {
            emit(ctx, Level::Error, &format!("Invalid header format {name}"));
            error_response(400, &format!("Invalid header format: {name}"), ctx)
        }
        None => {
            emit(ctx, Level::Error, &format!("Required Header - Missing or empty required header {name}"));
            error_response(400, "Missing or empty required header", ctx)
        }
    }
}

/// Add / overwrite one set of headers, then drop another set.
///
/// Order (remove-then-add) matches the legacy behaviour.
pub fn mutate(
    h: &dyn HeadersHandler,
    add: &HashMap<String, String>,
    drop: &[&str],
) {
    for k in drop {
        h.remove_header(k);
    }
    for (k, v) in add {
        h.set_header(k, v);
    }
}
