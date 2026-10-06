// Library root: re-exports the monitor's modules for integration tests and for
// downstream crates (e.g. the private portal). `src/main.rs` declares the same
// modules itself and is the binary entrypoint.
pub mod alerter;
pub mod baseline;
pub mod checker;
pub mod config;
pub mod domain;
pub mod error_log;
pub mod ssl_expiry;
pub mod types;
pub mod uptime_log;
