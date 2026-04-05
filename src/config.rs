use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use crate::types::AppError;

/// Domain health monitor — checks DNS, SSL, HTTP, and content changes.
#[derive(Parser, Debug)]
#[command(name = "domain-monitor")]
struct CliArgs {
    /// Path to the domain list file (CSV or TXT)
    #[arg(long = "domains", env = "UPTIME_DOMAINS")]
    domain_file: String,

    /// Check interval: 30m, 1h, 3h, or 24h
    #[arg(long = "interval", env = "UPTIME_INTERVAL", default_value = "1h")]
    interval: String,

    /// Path to the baseline JSON file
    #[arg(long = "baseline", env = "UPTIME_BASELINE", default_value = "/data/baselines.json")]
    baseline_file: String,

    /// Sender email address
    #[arg(long = "sender", env = "UPTIME_SENDER")]
    sender_email: String,

    /// Recipient email address
    #[arg(long = "recipient", env = "UPTIME_RECIPIENT")]
    recipient_email: String,

    /// SMTP server hostname
    #[arg(long = "smtp-host", env = "UPTIME_SMTP_HOST")]
    smtp_host: String,

    /// SMTP server port
    #[arg(long = "smtp-port", env = "UPTIME_SMTP_PORT", default_value = "587")]
    smtp_port: u16,

    /// SMTP username
    #[arg(long = "smtp-user", env = "UPTIME_SMTP_USER")]
    smtp_user: String,

    /// SMTP password
    #[arg(long = "smtp-pass", env = "UPTIME_SMTP_PASS")]
    smtp_pass: String,

    /// Use STARTTLS (true) or implicit TLS (false)
    #[arg(long = "smtp-tls", env = "UPTIME_SMTP_TLS", default_value = "true")]
    smtp_tls: bool,

    /// Path to the JSONL uptime log file
    #[arg(long = "log-file", env = "UPTIME_LOG_FILE", default_value = "/data/uptime.jsonl")]
    log_file: String,

    /// Path to the JSONL error log file
    #[arg(long = "error-log", env = "UPTIME_ERROR_LOG", default_value = "/data/errors.jsonl")]
    error_log: String,
}

/// Parsed and validated application configuration.
pub struct AppConfig {
    pub domain_file: PathBuf,
    pub check_interval: Duration,
    pub baseline_file: PathBuf,
    pub sender_email: String,
    pub recipient_email: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub smtp_tls: bool,
    pub log_file: PathBuf,
    pub error_log: PathBuf,
    pub interval_str: String,
}

/// Parse an interval string into a `Duration`.
/// Valid values: "30m", "1h", "3h", "24h".
pub fn parse_interval(value: &str) -> Result<Duration, AppError> {
    match value {
        "30m" => Ok(Duration::from_secs(30 * 60)),
        "1h" => Ok(Duration::from_secs(60 * 60)),
        "3h" => Ok(Duration::from_secs(3 * 60 * 60)),
        "24h" => Ok(Duration::from_secs(24 * 60 * 60)),
        other => Err(AppError::Config(format!(
            "invalid check interval '{other}': must be one of 30m, 1h, 3h, 24h"
        ))),
    }
}

/// Parse CLI arguments and validate configuration.
/// Exits with a descriptive error and non-zero exit code on invalid input.
pub fn parse_config() -> Result<AppConfig, AppError> {
    let args = CliArgs::parse();

    let check_interval = match parse_interval(&args.interval) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    Ok(AppConfig {
        domain_file: PathBuf::from(args.domain_file),
        check_interval,
        baseline_file: PathBuf::from(args.baseline_file),
        sender_email: args.sender_email,
        recipient_email: args.recipient_email,
        smtp_host: args.smtp_host,
        smtp_port: args.smtp_port,
        smtp_user: args.smtp_user,
        smtp_pass: args.smtp_pass,
        smtp_tls: args.smtp_tls,
        log_file: PathBuf::from(args.log_file),
        error_log: PathBuf::from(args.error_log),
        interval_str: args.interval,
    })
}
