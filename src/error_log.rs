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
