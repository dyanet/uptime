use std::fs::{self, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::Serialize;

use crate::traits::*;
use crate::types::*;

/// File-system backed store. Paths are configured at construction time.
pub struct FileStore {
    pub domain_file: PathBuf,
    pub uptime_file: PathBuf,
    pub error_file: PathBuf,
    pub baseline_file: PathBuf,
}

impl FileStore {
    pub fn new(
        domain_file: impl Into<PathBuf>,
        uptime_file: impl Into<PathBuf>,
        error_file: impl Into<PathBuf>,
        baseline_file: impl Into<PathBuf>,
    ) -> Self {
        Self {
            domain_file: domain_file.into(),
            uptime_file: uptime_file.into(),
            error_file: error_file.into(),
            baseline_file: baseline_file.into(),
        }
    }
}

// ── CSV helpers ──────────────────────────────────────────────────────────────

fn parse_csv_line(line: &str) -> Result<DomainRecord, StoreError> {
    let parts: Vec<&str> = line.splitn(8, ',').map(|s| s.trim()).collect();
    if parts.len() < 7 {
        return Err(StoreError(format!("expected at least 7 columns, got {}", parts.len())));
    }
    let date = parts[4].to_string();
    let created_at = if parts.len() >= 8 && !parts[7].is_empty() {
        parts[7].to_string()
    } else {
        date.clone()
    };
    Ok(DomainRecord {
        domain: parts[0].to_string(),
        recipient: parts[1].to_string(),
        interval: parts[2].to_string(),
        status: parts[3].parse()?,
        date,
        stripe: parts[5].to_string(),
        key: parts[6].to_string(),
        created_at,
    })
}

fn format_csv_line(record: &DomainRecord) -> String {
    format!(
        "{},{},{},{},{},{},{},{}",
        record.domain, record.recipient, record.interval, record.status,
        record.date, record.stripe, record.key, record.created_at
    )
}

fn parse_records_from_str(content: &str) -> Vec<DomainRecord> {
    let mut records = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match parse_csv_line(trimmed) {
            Ok(record) => records.push(record),
            Err(e) => log::warn!("Skipping invalid CSV line: {e} — {trimmed}"),
        }
    }
    records
}

fn save_records_to_file(path: &Path, records: &[DomainRecord]) -> Result<(), StoreError> {
    let mut content = String::from("# domain,recipient,interval,status,date,stripe,key,created_at\n");
    for record in records {
        content.push_str(&format_csv_line(record));
        content.push('\n');
    }
    fs::write(path, content)?;
    Ok(())
}

// ── Trait implementations ────────────────────────────────────────────────────

impl DomainReader for FileStore {
    fn load_records(&self) -> Result<Vec<DomainRecord>, StoreError> {
        let content = fs::read_to_string(&self.domain_file)?;
        Ok(parse_records_from_str(&content))
    }

    fn with_locked_records(
        &self,
        f: Box<dyn FnOnce(&mut Vec<DomainRecord>) -> Result<(), StoreError> + '_>,
    ) -> Result<(), StoreError> {
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&self.domain_file)?;

        lock_file
            .try_lock_exclusive()
            .map_err(|e| StoreError(format!("failed to acquire file lock: {e}")))?;

        let mut content = String::new();
        let mut reader = BufReader::new(&lock_file);
        reader.read_to_string(&mut content)?;

        let mut records = parse_records_from_str(&content);
        f(&mut records)?;

        let _ = lock_file.unlock();
        drop(lock_file);

        // Atomic write via temp + rename.
        let parent = self.domain_file.parent().unwrap_or(Path::new("."));
        let temp_path = parent.join(format!(".domains.tmp.{}", std::process::id()));
        save_records_to_file(&temp_path, &records)?;

        fs::rename(&temp_path, &self.domain_file).map_err(|e| {
            let _ = fs::remove_file(&temp_path);
            StoreError(format!("failed to rename temp file: {e}"))
        })?;

        Ok(())
    }
}

impl UptimeWriter for FileStore {
    fn append_uptime(&self, entry: &UptimeEntry) -> Result<(), StoreError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.uptime_file)?;
        let line = serde_json::to_string(entry)?;
        writeln!(file, "{line}")?;
        Ok(())
    }
}

impl UptimeReader for FileStore {
    fn read_uptime(&self, domain: &str, days: i64) -> Result<Vec<UptimeEntry>, StoreError> {
        let content = match fs::read_to_string(&self.uptime_file) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                log::warn!("Could not read uptime log: {e}");
                return Ok(Vec::new());
            }
        };

        let cutoff = Utc::now() - chrono::Duration::days(days);
        let mut entries = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<UptimeEntry>(trimmed) {
                Ok(entry) => {
                    if entry.domain != domain {
                        continue;
                    }
                    if let Ok(ts) = entry.timestamp.parse::<DateTime<Utc>>() {
                        if ts >= cutoff {
                            entries.push(entry);
                        }
                    }
                }
                Err(e) => log::warn!("Skipping malformed JSONL line: {e}"),
            }
        }

        Ok(entries)
    }
}

impl ErrorWriter for FileStore {
    fn log_error(&self, source: &str, category: &str, detail: &str) {
        #[derive(Serialize)]
        struct ErrorEntry<'a> {
            timestamp: String,
            source: &'a str,
            category: &'a str,
            detail: &'a str,
        }

        let entry = ErrorEntry {
            timestamp: Utc::now().to_rfc3339(),
            source,
            category,
            detail,
        };
        let Ok(json) = serde_json::to_string(&entry) else { return };
        let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&self.error_file) else { return };
        let _ = writeln!(file, "{json}");
    }
}

impl BaselineStore for FileStore {
    fn load_baselines(&self) -> Result<BaselineMap, StoreError> {
        if !self.baseline_file.exists() {
            return Ok(BaselineMap::new());
        }

        let data = fs::read_to_string(&self.baseline_file).map_err(|e| {
            StoreError(format!("failed to read baseline file: {e}"))
        })?;

        match serde_json::from_str::<BaselineMap>(&data) {
            Ok(map) => Ok(map),
            Err(e) => {
                log::warn!("Corrupt baseline file, starting empty: {e}");
                Ok(BaselineMap::new())
            }
        }
    }

    fn save_baselines(&self, baselines: &BaselineMap) -> Result<(), StoreError> {
        let data = serde_json::to_string_pretty(baselines)?;

        let parent = self.baseline_file.parent().unwrap_or(Path::new("."));
        let temp_path = parent.join(format!(".baselines.tmp.{}", std::process::id()));

        fs::write(&temp_path, &data).map_err(|e| {
            StoreError(format!("failed to write temp baseline file: {e}"))
        })?;

        fs::rename(&temp_path, &self.baseline_file).map_err(|e| {
            let _ = fs::remove_file(&temp_path);
            StoreError(format!("failed to rename temp baseline file: {e}"))
        })?;

        Ok(())
    }
}
