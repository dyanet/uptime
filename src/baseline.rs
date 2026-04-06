use std::path::Path;

use log::warn;

pub use uptime_store::types::{Baseline, BaselineMap};

use crate::types::{AppError, CheckResult};

/// Result of comparing a check result against the baseline map.
#[derive(Debug, PartialEq)]
pub enum BaselineAction {
    NewBaseline,
    Unchanged,
    ContentChanged { old_size: u64, new_size: u64 },
    Skipped,
}

/// Load baselines from a JSON file via the shared store.
pub fn load_baselines(path: &Path) -> Result<BaselineMap, AppError> {
    use uptime_store::file_store::FileStore;
    use uptime_store::traits::BaselineStore;

    let store = FileStore::new("", "", "", path);
    store.load_baselines().map_err(|e| AppError::Baseline(e.to_string()))
}

/// Save baselines to a JSON file via the shared store.
pub fn save_baselines(path: &Path, baselines: &BaselineMap) -> Result<(), AppError> {
    use uptime_store::file_store::FileStore;
    use uptime_store::traits::BaselineStore;

    let store = FileStore::new("", "", "", path);
    store.save_baselines(baselines).map_err(|e| AppError::Baseline(e.to_string()))
}

/// Compare a `CheckResult` against the baseline map and return the action taken.
pub fn compare_and_update(result: &CheckResult, baselines: &mut BaselineMap) -> BaselineAction {
    let (hash, size) = match (&result.body_hash, result.body_size) {
        (Some(h), Some(s)) => (h.clone(), s),
        _ => return BaselineAction::Skipped,
    };

    match result.http_status {
        Some(status) if (200..300).contains(&status) => {}
        _ => return BaselineAction::Skipped,
    }

    let new_baseline = Baseline {
        hash: hash.clone(),
        size,
    };

    match baselines.get(&result.domain) {
        None => {
            baselines.insert(result.domain.clone(), new_baseline);
            BaselineAction::NewBaseline
        }
        Some(existing) if existing.hash == hash => BaselineAction::Unchanged,
        Some(existing) => {
            let old_size = existing.size;
            baselines.insert(result.domain.clone(), new_baseline);
            BaselineAction::ContentChanged {
                old_size,
                new_size: size,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    fn make_check_result(domain: &str, status: u16, hash: &str, size: u64) -> CheckResult {
        CheckResult {
            domain: domain.to_string(),
            dns_ok: true,
            ssl_error: None,
            http_status: Some(status),
            body_hash: Some(hash.to_string()),
            body_size: Some(size),
            error: None,
        }
    }

    #[test]
    fn load_nonexistent_file_returns_empty_map() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.json");
        let map = load_baselines(&path).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn load_valid_json_returns_correct_baselines() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("baselines.json");
        let json = r#"{"example.com": {"hash": "abc123", "size": 1024}}"#;
        fs::write(&path, json).unwrap();

        let map = load_baselines(&path).unwrap();
        assert_eq!(map.len(), 1);
        let b = map.get("example.com").unwrap();
        assert_eq!(b.hash, "abc123");
        assert_eq!(b.size, 1024);
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("baselines.json");

        let mut map = BaselineMap::new();
        map.insert("example.com".to_string(), Baseline { hash: "deadbeef".to_string(), size: 2048 });
        map.insert("test.org".to_string(), Baseline { hash: "cafebabe".to_string(), size: 512 });

        save_baselines(&path, &map).unwrap();
        let loaded = load_baselines(&path).unwrap();
        assert_eq!(map, loaded);
    }

    #[test]
    fn compare_new_domain_stores_baseline() {
        let mut baselines = BaselineMap::new();
        let result = make_check_result("new.com", 200, "hash1", 100);
        let action = compare_and_update(&result, &mut baselines);
        assert_eq!(action, BaselineAction::NewBaseline);
        assert_eq!(baselines.get("new.com").unwrap().hash, "hash1");
    }

    #[test]
    fn compare_unchanged_hash_no_action() {
        let mut baselines = BaselineMap::new();
        baselines.insert("same.com".to_string(), Baseline { hash: "hash1".to_string(), size: 100 });
        let result = make_check_result("same.com", 200, "hash1", 100);
        let action = compare_and_update(&result, &mut baselines);
        assert_eq!(action, BaselineAction::Unchanged);
    }

    #[test]
    fn compare_changed_hash_flags_content_change() {
        let mut baselines = BaselineMap::new();
        baselines.insert("changed.com".to_string(), Baseline { hash: "old_hash".to_string(), size: 100 });
        let result = make_check_result("changed.com", 200, "new_hash", 200);
        let action = compare_and_update(&result, &mut baselines);
        assert_eq!(action, BaselineAction::ContentChanged { old_size: 100, new_size: 200 });
    }

    #[test]
    fn compare_non_2xx_skipped() {
        let mut baselines = BaselineMap::new();
        let result = make_check_result("error.com", 500, "hash1", 100);
        let action = compare_and_update(&result, &mut baselines);
        assert_eq!(action, BaselineAction::Skipped);
    }
}
