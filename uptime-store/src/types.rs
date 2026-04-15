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
    #[serde(default)]
    pub redirected: bool,
}

// ── Baseline ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Baseline {
    pub hash: String,
    pub size: u64,
}

pub type BaselineMap = HashMap<String, Baseline>;


#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Arbitrary `UptimeEntry` generator for property-based tests.
    fn arb_uptime_entry() -> impl Strategy<Value = UptimeEntry> {
        (
            "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",  // timestamp
            "[a-z]{1,10}\\.[a-z]{2,4}",                                  // domain
            any::<bool>(),                                                // up
            any::<bool>(),                                                // dns_ok
            prop::option::of(200u16..600u16),                             // http_status
            prop::option::of("[a-z ]{0,30}"),                             // ssl_error
            prop::option::of(0u64..1_000_000u64),                        // response_size
            prop::option::of("[a-z ]{0,30}"),                             // error
            any::<bool>(),                                                // redirected
        )
            .prop_map(
                |(timestamp, domain, up, dns_ok, http_status, ssl_error, response_size, error, redirected)| {
                    UptimeEntry {
                        timestamp,
                        domain,
                        up,
                        dns_ok,
                        http_status,
                        ssl_error,
                        response_size,
                        error,
                        redirected,
                    }
                },
            )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// **Property 1: UptimeEntry serialization round-trip preserves the redirected field**
        ///
        /// For any valid `UptimeEntry` with any boolean value for `redirected`,
        /// serializing to JSON and deserializing back produces an entry with the
        /// same `redirected` value.
        ///
        /// **Validates: Requirements 2.1, 2.2**
        #[test]
        fn serialization_round_trip_preserves_redirected(entry in arb_uptime_entry()) {
            let json = serde_json::to_string(&entry).expect("serialize");
            let deserialized: UptimeEntry = serde_json::from_str(&json).expect("deserialize");
            prop_assert_eq!(deserialized.redirected, entry.redirected);
        }

        /// **Property 2: Legacy entries without redirected field default to false**
        ///
        /// For any valid `UptimeEntry`, serializing to JSON, removing the
        /// `redirected` key (simulating a legacy entry), and deserializing back
        /// produces an entry with `redirected == false`.
        ///
        /// **Validates: Requirements 2.4**
        #[test]
        fn legacy_entries_without_redirected_default_to_false(entry in arb_uptime_entry()) {
            let mut value = serde_json::to_value(&entry).expect("serialize to Value");
            value.as_object_mut().expect("JSON object").remove("redirected");
            let deserialized: UptimeEntry = serde_json::from_value(value).expect("deserialize legacy entry");
            prop_assert_eq!(deserialized.redirected, false);
        }
    }
}
