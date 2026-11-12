//! Thin TTL wrapper over the PDK shared cache.
//!
//! Entries are stored as JSON (`{value, timestamp}`) so the TTL check can
//! be done lazily on read without needing a separate index.

use std::time::{SystemTime, UNIX_EPOCH};

use pdk::cache::Cache;
use serde::{Deserialize, Serialize};

use super::log::{emit, Level};
use super::TraceCtx;

/// Policy-wide cache knobs.
#[derive(Clone)]
pub struct TtlPolicy {
    pub max_entries: usize,
    pub ttl_secs: u64,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    value: String,
    timestamp: u64,
}

/// Current Unix time, or 0 on the (impossible) failure case.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Return the cached value for `key` iff it's still within TTL.
///
/// Expired entries are deleted lazily so the cache doesn't grow unbounded.
pub fn get(
    cache: &impl Cache,
    policy: &TtlPolicy,
    key: &str,
    ctx: &TraceCtx<'_>,
) -> Option<String> {
    let bytes = cache.get(key)?;

    let entry: Entry = match serde_json::from_slice(&bytes) {
        Ok(e) => e,
        Err(_) => {
            emit(
                ctx,
                Level::Error,
                &format!("Get Cache function - Failed to deserialize cache entry for key {key:?}"),
            );
            return None;
        }
    };

    if now_secs().saturating_sub(entry.timestamp) <= policy.ttl_secs {
        Some(entry.value)
    } else {
        let _ = cache.delete(key);
        None
    }
}

/// Store `value` under `key`, stamping it with the current time.
pub fn put(cache: &impl Cache, _policy: &TtlPolicy, key: &str, value: &str) -> anyhow::Result<()> {
    let entry = Entry {
        value: value.to_owned(),
        timestamp: now_secs(),
    };
    let bytes = serde_json::to_vec(&entry)?;
    Ok(cache.save(key, bytes)?)
}
