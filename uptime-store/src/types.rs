use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

// ── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "store error: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError(format!("IO: {e}"))
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        StoreError(format!("JSON: {e}"))
    }
}

// ── Domain status ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Internal,
    Free,
    Paid,
    Verifying,
    Disabled,
    Lapsed,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Internal => write!(f, "Internal"),
            Status::Free => write!(f, "Free"),
            Status::Paid => write!(f, "Paid"),
            Status::Verifying => write!(f, "Verifying"),
            Status::Disabled => write!(f, "Disabled"),
            Status::Lapsed => write!(f, "Lapsed"),
        }
    }
}

impl FromStr for Status {
    type Err = StoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Internal" => Ok(Status::Internal),
            "Free" => Ok(Status::Free),
            "Paid" => Ok(Status::Paid),
            "Verifying" => Ok(Status::Verifying),
            "Disabled" => Ok(Status::Disabled),
            "Lapsed" => Ok(Status::Lapsed),
            other => Err(StoreError(format!("invalid status: {other}"))),
        }
    }
}

// ── Domain record (full, for portal) ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainRecord {
    pub domain: String,
    pub recipient: String,
    pub interval: String,
    pub status: Status,
    pub date: String,
    pub stripe: String,
    pub key: String,
    pub created_at: String,
}

// ── Uptime entry ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UptimeEntry {
    pub timestamp: String,
    pub domain: String,
    pub up: bool,
    pub dns_ok: bool,
    pub http_status: Option<u16>,
    pub ssl_error: Option<String>,
    pub response_size: Option<u64>,
    pub error: Option<String>,
}

// ── Baseline ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Baseline {
    pub hash: String,
    pub size: u64,
}

pub type BaselineMap = HashMap<String, Baseline>;
