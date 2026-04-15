use std::fmt;

/// Shared error type for the domain monitor application.
#[derive(Debug)]
#[allow(dead_code)]
pub enum AppError {
    Io(std::io::Error),
    Config(String),
    Dns(String),
    Ssl(String),
    Http(String),
    Ses(String),
    Baseline(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(e) => write!(f, "IO error: {e}"),
            AppError::Config(msg) => write!(f, "Config error: {msg}"),
            AppError::Dns(msg) => write!(f, "DNS error: {msg}"),
            AppError::Ssl(msg) => write!(f, "SSL error: {msg}"),
            AppError::Http(msg) => write!(f, "HTTP error: {msg}"),
            AppError::Ses(msg) => write!(f, "SES error: {msg}"),
            AppError::Baseline(msg) => write!(f, "Baseline error: {msg}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e)
    }
}

/// Result of a single domain health check.
pub struct CheckResult {
    pub domain: String,
    pub dns_ok: bool,
    pub ssl_error: Option<String>,
    pub http_status: Option<u16>,
    pub body_hash: Option<String>,
    pub body_size: Option<u64>,
    pub error: Option<String>,
    pub redirected: bool,
}
