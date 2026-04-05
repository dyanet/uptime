use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use chrono::Utc;
use serde::Serialize;

#[derive(Serialize)]
struct ErrorEntry<'a> {
    timestamp: String,
    source: &'a str,
    category: &'a str,
    detail: &'a str,
}

/// Append a structured error entry to the JSONL error log.
/// Failures are silently ignored (best-effort logging).
pub fn log_error(path: &Path, source: &str, category: &str, detail: &str) {
    let entry = ErrorEntry {
        timestamp: Utc::now().to_rfc3339(),
        source,
        category,
        detail,
    };
    let Ok(json) = serde_json::to_string(&entry) else { return };
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else { return };
    let _ = writeln!(file, "{json}");
}
