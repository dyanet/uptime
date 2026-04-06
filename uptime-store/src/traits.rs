use crate::types::*;

/// Read domain records from storage.
///
/// The portal uses full `DomainRecord` rows; the monitor only needs
/// (domain, recipient, interval) and filters by status.
pub trait DomainReader: Send + Sync {
    /// Load all domain records.
    fn load_records(&self) -> Result<Vec<DomainRecord>, StoreError>;

    /// Acquire an exclusive lock, read records, apply a mutation, and persist.
    /// Implementations must guarantee atomicity.
    ///
    /// The closure receives a mutable reference to the records vec.
    /// It should return `Ok(())` on success; the mutated vec is then persisted.
    fn with_locked_records(
        &self,
        f: Box<dyn FnOnce(&mut Vec<DomainRecord>) -> Result<(), StoreError> + '_>,
    ) -> Result<(), StoreError>;
}

/// Append uptime check entries.
pub trait UptimeWriter: Send + Sync {
    fn append_uptime(&self, entry: &UptimeEntry) -> Result<(), StoreError>;
}

/// Read uptime entries (used by the portal dashboard).
pub trait UptimeReader: Send + Sync {
    fn read_uptime(&self, domain: &str, days: i64) -> Result<Vec<UptimeEntry>, StoreError>;
}

/// Append error log entries.
pub trait ErrorWriter: Send + Sync {
    /// Best-effort error logging. Implementations should not panic.
    fn log_error(&self, source: &str, category: &str, detail: &str);
}

/// Load and save content baselines.
pub trait BaselineStore: Send + Sync {
    fn load_baselines(&self) -> Result<BaselineMap, StoreError>;
    fn save_baselines(&self, baselines: &BaselineMap) -> Result<(), StoreError>;
}
