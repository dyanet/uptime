use std::path::Path;

use uptime_store::file_store::FileStore;
use uptime_store::traits::ErrorWriter;

/// Append a structured error entry to the JSONL error log.
/// Failures are silently ignored (best-effort logging).
pub fn log_error(path: &Path, source: &str, category: &str, detail: &str) {
    // Construct a minimal FileStore just for error logging.
    // The other paths are unused for this operation.
    let store = FileStore::new("", "", path, "");
    store.log_error(source, category, detail);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_error_appends_entry_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("errors.jsonl");

        log_error(&path, "checker", "dns", "resolution failed");

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("resolution failed"));
        assert!(content.contains("checker"));
        assert!(content.contains("dns"));
    }

    #[test]
    fn log_error_appends_multiple_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("errors.jsonl");

        log_error(&path, "checker", "dns", "first");
        log_error(&path, "ssl", "expiry", "second");

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 2);
        assert!(content.contains("first"));
        assert!(content.contains("second"));
    }
}
