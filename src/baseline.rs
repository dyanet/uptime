use std::collections::HashMap;
use std::fs;
use std::path::Path;

use log::warn;
use serde::{Deserialize, Serialize};

use crate::types::{AppError, CheckResult};

/// Stored baseline for a domain's home page content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Baseline {
    pub hash: String,
    pub size: u64,
}

/// Map of domain name to its baseline.
pub type BaselineMap = HashMap<String, Baseline>;

/// Result of comparing a check result against the baseline map.
#[derive(Debug, PartialEq)]
pub enum BaselineAction {
    /// Domain not in map, new baseline stored.
    NewBaseline,
    /// Hash unchanged, no action needed.
    Unchanged,
    /// Content changed — includes old and new sizes.
    ContentChanged { old_size: u64, new_size: u64 },
    /// Check didn't produce a body hash (non-2xx or error), skip baseline logic.
    Skipped,
}

/// Load baselines from a JSON file. Returns an empty map if the file doesn't exist.
/// Logs a warning and returns an empty map if the file is corrupt.
pub fn load_baselines(path: &Path) -> Result<BaselineMap, AppError> {
    if !path.exists() {
        return Ok(BaselineMap::new());
    }

    let data = fs::read_to_string(path).map_err(|e| {
        AppError::Baseline(format!("failed to read baseline file {}: {e}", path.display()))
    })?;

    match serde_json::from_str::<BaselineMap>(&data) {
        Ok(map) => Ok(map),
        Err(e) => {
            warn!(
                "Corrupt baseline file {}, starting with empty baselines: {e}",
                path.display()
            );
            Ok(BaselineMap::new())
        }
    }
}

/// Save baselines to a JSON file atomically (write to temp file, then rename).
pub fn save_baselines(path: &Path, baselines: &BaselineMap) -> Result<(), AppError> {
    let data = serde_json::to_string_pretty(baselines)
        .map_err(|e| AppError::Baseline(format!("failed to serialize baselines: {e}")))?;

    // Write to a sibling temp file, then rename for atomicity.
    let parent = path.parent().unwrap_or(Path::new("."));
    let temp_path = parent.join(format!(
        ".baselines.tmp.{}",
        std::process::id()
    ));

    fs::write(&temp_path, &data).map_err(|e| {
        AppError::Baseline(format!("failed to write temp baseline file: {e}"))
    })?;

    fs::rename(&temp_path, path).map_err(|e| {
        // Clean up temp file on rename failure.
        let _ = fs::remove_file(&temp_path);
        AppError::Baseline(format!("failed to rename temp baseline file: {e}"))
    })?;

    Ok(())
}

/// Compare a `CheckResult` against the baseline map and return the action taken.
///
/// - If the check has no body hash (non-2xx or error): returns `Skipped`.
/// - If the domain is new: stores the baseline and returns `NewBaseline`.
/// - If the hash is unchanged: returns `Unchanged`.
/// - If the hash changed: updates the baseline and returns `ContentChanged`.
pub fn compare_and_update(result: &CheckResult, baselines: &mut BaselineMap) -> BaselineAction {
    let (hash, size) = match (&result.body_hash, result.body_size) {
        (Some(h), Some(s)) => (h.clone(), s),
        _ => return BaselineAction::Skipped,
    };

    // Only process 2xx responses for baseline logic.
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
    fn load_corrupt_file_returns_empty_map() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("baselines.json");
        fs::write(&path, "not valid json {{{").unwrap();

        let map = load_baselines(&path).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("baselines.json");

        let mut map = BaselineMap::new();
        map.insert(
            "example.com".to_string(),
            Baseline {
                hash: "deadbeef".to_string(),
                size: 2048,
            },
        );
        map.insert(
            "test.org".to_string(),
            Baseline {
                hash: "cafebabe".to_string(),
                size: 512,
            },
        );

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
        assert_eq!(baselines.get("new.com").unwrap().size, 100);
    }

    #[test]
    fn compare_unchanged_hash_no_action() {
        let mut baselines = BaselineMap::new();
        baselines.insert(
            "same.com".to_string(),
            Baseline {
                hash: "hash1".to_string(),
                size: 100,
            },
        );
        let result = make_check_result("same.com", 200, "hash1", 100);

        let action = compare_and_update(&result, &mut baselines);
        assert_eq!(action, BaselineAction::Unchanged);
    }

    #[test]
    fn compare_changed_hash_flags_content_change() {
        let mut baselines = BaselineMap::new();
        baselines.insert(
            "changed.com".to_string(),
            Baseline {
                hash: "old_hash".to_string(),
                size: 100,
            },
        );
        let result = make_check_result("changed.com", 200, "new_hash", 200);

        let action = compare_and_update(&result, &mut baselines);
        assert_eq!(
            action,
            BaselineAction::ContentChanged {
                old_size: 100,
                new_size: 200,
            }
        );
        // Baseline should be updated
        assert_eq!(baselines.get("changed.com").unwrap().hash, "new_hash");
        assert_eq!(baselines.get("changed.com").unwrap().size, 200);
    }

    #[test]
    fn compare_non_2xx_skipped() {
        let mut baselines = BaselineMap::new();
        let result = make_check_result("error.com", 500, "hash1", 100);

        let action = compare_and_update(&result, &mut baselines);
        assert_eq!(action, BaselineAction::Skipped);
        assert!(baselines.is_empty());
    }

    #[test]
    fn compare_no_body_hash_skipped() {
        let mut baselines = BaselineMap::new();
        let result = CheckResult {
            domain: "nodata.com".to_string(),
            dns_ok: false,
            ssl_error: None,
            http_status: None,
            body_hash: None,
            body_size: None,
            error: Some("DNS failed".to_string()),
        };

        let action = compare_and_update(&result, &mut baselines);
        assert_eq!(action, BaselineAction::Skipped);
    }
}
