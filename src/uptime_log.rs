use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use chrono::Utc;
use serde::Serialize;

use crate::types::CheckResult;

/// A single JSONL record for uptime graphing.
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
        }
    }
}

/// Append a log entry as a single JSON line to the given file.
pub fn append_entry(path: &Path, entry: &LogEntry) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let line = serde_json::to_string(entry)?;
    writeln!(file, "{line}")?;
    Ok(())
}
