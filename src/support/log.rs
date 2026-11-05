//! Structured JSON logging keyed off a [`TraceCtx`].

use pdk::logger;
use serde_json::json;

use super::TraceCtx;

/// Enum form of the log level — avoids the stringly-typed `&str` from the
/// original codebase and makes `todo!()` fallbacks unnecessary.
#[derive(Clone, Copy)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

/// Emit a single JSON log line.
///
/// Shape: `{"source":"…","message":"…"}`
pub fn emit(ctx: &TraceCtx<'_>, level: Level, message: &str) {
    let payload = json!({
        "source":  ctx.source,
        "message": message,
    })
    .to_string();

    match level {
        Level::Debug => logger::debug!("{payload}"),
        Level::Info  => logger::info!("{payload}"),
        Level::Warn  => logger::warn!("{payload}"),
        Level::Error => logger::error!("{payload}"),
    }
}
