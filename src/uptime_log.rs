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
    /// Special handling flag: 0 = normal, 1 = content change (portal classifies).
    pub special_handling: i8,
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
            special_handling: result.special_handling,
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
            special_handling: self.special_handling,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CheckResult;

    fn healthy() -> CheckResult {
        CheckResult {
            domain: "example.com".to_string(),
            dns_ok: true,
            ssl_error: None,
            http_status: Some(200),
            body_hash: Some("abc".to_string()),
            body_size: Some(1234),
            error: None,
            redirected: false,
            special_handling: 0,
        }
    }

    #[test]
    fn from_check_healthy_is_up() {
        let e = LogEntry::from_check(&healthy());
        assert!(e.up);
        assert_eq!(e.domain, "example.com");
        assert_eq!(e.http_status, Some(200));
        assert_eq!(e.response_size, Some(1234));
        assert!(!e.redirected);
        assert!(!e.timestamp.is_empty());
    }

    #[test]
    fn from_check_dns_failure_is_down() {
        let mut r = healthy();
        r.dns_ok = false;
        assert!(!LogEntry::from_check(&r).up);
    }

    #[test]
    fn from_check_ssl_error_is_down() {
        let mut r = healthy();
        r.ssl_error = Some("bad cert".to_string());
        let e = LogEntry::from_check(&r);
        assert!(!e.up);
        assert_eq!(e.ssl_error.as_deref(), Some("bad cert"));
    }

    #[test]
    fn from_check_generic_error_is_down() {
        let mut r = healthy();
        r.error = Some("timeout".to_string());
        assert!(!LogEntry::from_check(&r).up);
    }

    #[test]
    fn from_check_5xx_is_down() {
        let mut r = healthy();
        r.http_status = Some(500);
        assert!(!LogEntry::from_check(&r).up);
    }

    #[test]
    fn from_check_no_status_is_down() {
        let mut r = healthy();
        r.http_status = None;
        assert!(!LogEntry::from_check(&r).up);
    }

    #[test]
    fn from_check_redirect_3xx_is_up() {
        let mut r = healthy();
        r.http_status = Some(301);
        r.redirected = true;
        let e = LogEntry::from_check(&r);
        assert!(e.up);
        assert!(e.redirected);
    }

    #[test]
    fn to_entry_preserves_fields() {
        let e = LogEntry::from_check(&healthy());
        let ue = e.to_entry();
        assert_eq!(ue.domain, e.domain);
        assert_eq!(ue.up, e.up);
        assert_eq!(ue.dns_ok, e.dns_ok);
        assert_eq!(ue.http_status, e.http_status);
        assert_eq!(ue.response_size, e.response_size);
        assert_eq!(ue.redirected, e.redirected);
        assert_eq!(ue.special_handling, e.special_handling);
        assert_eq!(ue.timestamp, e.timestamp);
    }

    #[test]
    fn append_entry_writes_one_json_line_per_call() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("uptime.jsonl");
        let entry = LogEntry::from_check(&healthy());

        append_entry(&path, &entry).unwrap();
        append_entry(&path, &entry).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 2, "expected one JSONL record per append");

        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["domain"], "example.com");
            assert_eq!(v["up"], true);
        }
    }
}
