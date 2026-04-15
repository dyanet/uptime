use std::path::Path;

use chrono::Utc;
use serde::Serialize;

pub use uptime_store::types::UptimeEntry;

use crate::types::CheckResult;

/// A single JSONL record for uptime graphing.
/// This is the local type used to construct entries from CheckResult.
#[derive(Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub domain: String,
    pub up: bool,
    pub dns_ok: bool,
    pub http_status: Option<u16>,
    pub ssl_error: Option<String>,
    pub response_size: Option<u64>,
    pub error: Option<String>,
    pub redirected: bool,
}

impl LogEntry {
    pub fn from_check(result: &CheckResult) -> Self {
        let up = result.dns_ok
            && result.ssl_error.is_none()
            && result.error.is_none()
            && matches!(result.http_status, Some(s) if (200..400).contains(&s));

        Self {
            timestamp: Utc::now().to_rfc3339(),
            domain: result.domain.clone(),
            up,
            dns_ok: result.dns_ok,
            http_status: result.http_status,
            ssl_error: result.ssl_error.clone(),
            response_size: result.body_size,
            error: result.error.clone(),
            redirected: result.redirected,
        }
    }

    /// Convert to the shared UptimeEntry type for storage.
    pub fn to_entry(&self) -> UptimeEntry {
        UptimeEntry {
            timestamp: self.timestamp.clone(),
            domain: self.domain.clone(),
            up: self.up,
            dns_ok: self.dns_ok,
            http_status: self.http_status,
            ssl_error: self.ssl_error.clone(),
            response_size: self.response_size,
            error: self.error.clone(),
            redirected: self.redirected,
        }
    }
}

/// Append a log entry as a single JSON line to the given file.
pub fn append_entry(path: &Path, entry: &LogEntry) -> std::io::Result<()> {
    use uptime_store::file_store::FileStore;
    use uptime_store::traits::UptimeWriter;

    let store = FileStore::new("", path, "", "");
    let ue = entry.to_entry();
    store.append_uptime(&ue).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
    })
}
