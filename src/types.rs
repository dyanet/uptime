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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_formats_each_variant() {
        assert!(
            AppError::Io(std::io::Error::new(std::io::ErrorKind::Other, "boom"))
                .to_string()
                .contains("IO error")
        );
        assert_eq!(AppError::Config("x".into()).to_string(), "Config error: x");
        assert_eq!(AppError::Dns("x".into()).to_string(), "DNS error: x");
        assert_eq!(AppError::Ssl("x".into()).to_string(), "SSL error: x");
        assert_eq!(AppError::Http("x".into()).to_string(), "HTTP error: x");
        assert_eq!(AppError::Ses("x".into()).to_string(), "SES error: x");
        assert_eq!(AppError::Baseline("x".into()).to_string(), "Baseline error: x");
    }

    #[test]
    fn from_io_error_maps_to_io_variant() {
        let e: AppError = std::io::Error::new(std::io::ErrorKind::NotFound, "missing").into();
        assert!(matches!(e, AppError::Io(_)));
        assert!(e.to_string().contains("IO error"));
    }

    #[test]
    fn error_is_std_error() {
        // Exercise the std::error::Error impl via trait object.
        let e = AppError::Config("nope".into());
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.to_string().contains("nope"));
    }
}
