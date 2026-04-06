use std::sync::Mutex;

use rusqlite::Connection;

use crate::traits::*;
use crate::types::*;

/// SQLite-backed store implementation.
pub struct SqlStore {
    conn: Mutex<Connection>,
}

impl SqlStore {
    /// Open (or create) a SQLite database and ensure tables exist.
    pub fn open(db_path: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(db_path)
            .map_err(|e| StoreError(format!("sqlite open: {e}")))?;
        let store = Self { conn: Mutex::new(conn) };
        store.create_tables()?;
        Ok(store)
    }

    /// Open an in-memory database (useful for testing).
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| StoreError(format!("sqlite open: {e}")))?;
        let store = Self { conn: Mutex::new(conn) };
        store.create_tables()?;
        Ok(store)
    }

    fn create_tables(&self) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(SCHEMA).map_err(|e| StoreError(format!("schema: {e}")))?;
        Ok(())
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS domains (
    domain     TEXT NOT NULL,
    recipient  TEXT NOT NULL,
    interval   TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'Verifying',
    date       TEXT NOT NULL,
    stripe     TEXT NOT NULL DEFAULT '',
    key        TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (domain, recipient)
);

CREATE TABLE IF NOT EXISTS uptime (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,
    domain        TEXT NOT NULL,
    up            INTEGER NOT NULL,
    dns_ok        INTEGER NOT NULL,
    http_status   INTEGER,
    ssl_error     TEXT,
    response_size INTEGER,
    error         TEXT
);
CREATE INDEX IF NOT EXISTS idx_uptime_domain_ts ON uptime(domain, timestamp);

CREATE TABLE IF NOT EXISTS errors (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source    TEXT NOT NULL,
    category  TEXT NOT NULL,
    detail    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baselines (
    domain TEXT PRIMARY KEY,
    hash   TEXT NOT NULL,
    size   INTEGER NOT NULL
);
"#;

impl DomainReader for SqlStore {
    fn load_records(&self) -> Result<Vec<DomainRecord>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT domain, recipient, interval, status, date, stripe, key, created_at FROM domains ORDER BY rowid")
            .map_err(|e| StoreError(format!("query: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(DomainRecord {
                    domain: row.get(0)?,
                    recipient: row.get(1)?,
                    interval: row.get(2)?,
                    status: {
                        let s: String = row.get(3)?;
                        s.parse().unwrap_or(Status::Disabled)
                    },
                    date: row.get(4)?,
                    stripe: row.get(5)?,
                    key: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })
            .map_err(|e| StoreError(format!("query: {e}")))?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|e| StoreError(format!("row: {e}")))?);
        }
        Ok(records)
    }

    fn with_locked_records(
        &self,
        f: Box<dyn FnOnce(&mut Vec<DomainRecord>) -> Result<(), StoreError> + '_>,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();

        conn.execute("BEGIN EXCLUSIVE", [])
            .map_err(|e| StoreError(format!("begin: {e}")))?;

        // Load all records.
        let mut records = {
            let mut stmt = conn
                .prepare("SELECT domain, recipient, interval, status, date, stripe, key, created_at FROM domains ORDER BY rowid")
                .map_err(|e| StoreError(format!("query: {e}")))?;

            let rows = stmt
                .query_map([], |row| {
                    Ok(DomainRecord {
                        domain: row.get(0)?,
                        recipient: row.get(1)?,
                        interval: row.get(2)?,
                        status: {
                            let s: String = row.get(3)?;
                            s.parse().unwrap_or(Status::Disabled)
                        },
                        date: row.get(4)?,
                        stripe: row.get(5)?,
                        key: row.get(6)?,
                        created_at: row.get(7)?,
                    })
                })
                .map_err(|e| StoreError(format!("query: {e}")))?;

            let mut v = Vec::new();
            for row in rows {
                v.push(row.map_err(|e| StoreError(format!("row: {e}")))?);
            }
            v
        };

        f(&mut records).map_err(|e| {
            let _ = conn.execute("ROLLBACK", []);
            e
        })?;

        // Replace all records.
        conn.execute("DELETE FROM domains", [])
            .map_err(|e| StoreError(format!("delete: {e}")))?;

        let mut insert = conn
            .prepare("INSERT INTO domains (domain, recipient, interval, status, date, stripe, key, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)")
            .map_err(|e| StoreError(format!("prepare: {e}")))?;

        for r in &records {
            insert
                .execute(rusqlite::params![
                    r.domain, r.recipient, r.interval, r.status.to_string(),
                    r.date, r.stripe, r.key, r.created_at
                ])
                .map_err(|e| StoreError(format!("insert: {e}")))?;
        }

        conn.execute("COMMIT", [])
            .map_err(|e| StoreError(format!("commit: {e}")))?;

        Ok(())
    }
}

impl UptimeWriter for SqlStore {
    fn append_uptime(&self, entry: &UptimeEntry) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO uptime (timestamp, domain, up, dns_ok, http_status, ssl_error, response_size, error) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![
                entry.timestamp,
                entry.domain,
                entry.up as i32,
                entry.dns_ok as i32,
                entry.http_status.map(|s| s as i32),
                entry.ssl_error,
                entry.response_size.map(|s| s as i64),
                entry.error,
            ],
        ).map_err(|e| StoreError(format!("insert uptime: {e}")))?;
        Ok(())
    }
}

impl UptimeReader for SqlStore {
    fn read_uptime(&self, domain: &str, days: i64) -> Result<Vec<UptimeEntry>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(days)).to_rfc3339();

        let mut stmt = conn
            .prepare("SELECT timestamp, domain, up, dns_ok, http_status, ssl_error, response_size, error FROM uptime WHERE domain = ?1 AND timestamp >= ?2 ORDER BY timestamp")
            .map_err(|e| StoreError(format!("query: {e}")))?;

        let rows = stmt
            .query_map(rusqlite::params![domain, cutoff], |row| {
                Ok(UptimeEntry {
                    timestamp: row.get(0)?,
                    domain: row.get(1)?,
                    up: row.get::<_, i32>(2)? != 0,
                    dns_ok: row.get::<_, i32>(3)? != 0,
                    http_status: row.get::<_, Option<i32>>(4)?.map(|s| s as u16),
                    ssl_error: row.get(5)?,
                    response_size: row.get::<_, Option<i64>>(6)?.map(|s| s as u64),
                    error: row.get(7)?,
                })
            })
            .map_err(|e| StoreError(format!("query: {e}")))?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|e| StoreError(format!("row: {e}")))?);
        }
        Ok(entries)
    }
}

impl ErrorWriter for SqlStore {
    fn log_error(&self, source: &str, category: &str, detail: &str) {
        let Ok(conn) = self.conn.lock() else { return };
        let timestamp = chrono::Utc::now().to_rfc3339();
        let _ = conn.execute(
            "INSERT INTO errors (timestamp, source, category, detail) VALUES (?1,?2,?3,?4)",
            rusqlite::params![timestamp, source, category, detail],
        );
    }
}

impl BaselineStore for SqlStore {
    fn load_baselines(&self) -> Result<BaselineMap, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT domain, hash, size FROM baselines")
            .map_err(|e| StoreError(format!("query: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    Baseline {
                        hash: row.get(1)?,
                        size: row.get::<_, i64>(2)? as u64,
                    },
                ))
            })
            .map_err(|e| StoreError(format!("query: {e}")))?;

        let mut map = BaselineMap::new();
        for row in rows {
            let (domain, baseline) = row.map_err(|e| StoreError(format!("row: {e}")))?;
            map.insert(domain, baseline);
        }
        Ok(map)
    }

    fn save_baselines(&self, baselines: &BaselineMap) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM baselines", [])
            .map_err(|e| StoreError(format!("delete: {e}")))?;

        let mut stmt = conn
            .prepare("INSERT INTO baselines (domain, hash, size) VALUES (?1,?2,?3)")
            .map_err(|e| StoreError(format!("prepare: {e}")))?;

        for (domain, b) in baselines {
            stmt.execute(rusqlite::params![domain, b.hash, b.size as i64])
                .map_err(|e| StoreError(format!("insert: {e}")))?;
        }
        Ok(())
    }
}
