use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use log::{error, info};
use reqwest::Client;
use sha2::{Digest, Sha256};

use crate::types::CheckResult;

/// Perform a full health check on a single domain: DNS → HTTPS GET → SSL → content hash.
///
/// On DNS failure, remaining checks are skipped and `dns_ok` is set to `false`.
pub async fn check_domain(domain: &str, timeout: Duration) -> CheckResult {
    let mut result = CheckResult {
        domain: domain.to_string(),
        dns_ok: false,
        ssl_error: None,
        http_status: None,
        body_hash: None,
        body_size: None,
        error: None,
    };

    // --- DNS resolution ---
    let resolver = Resolver::builder_with_config(
        ResolverConfig::default(),
        TokioConnectionProvider::default(),
    )
    .build();

    match resolver.lookup_ip(format!("{domain}.")).await {
        Ok(lookup) if lookup.iter().next().is_some() => {
            result.dns_ok = true;
            info!("{domain}: DNS resolved successfully");
        }
        Ok(_) => {
            let msg = "DNS resolved but returned no addresses".to_string();
            error!("{domain}: {msg}");
            result.error = Some(msg);
            return result;
        }
        Err(e) => {
            let msg = format!("DNS resolution failed: {e}");
            error!("{domain}: {msg}");
            result.error = Some(msg);
            return result;
        }
    }

    // --- HTTPS GET request ---
    let client = match Client::builder()
        .timeout(timeout)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("failed to build HTTP client: {e}");
            error!("{domain}: {msg}");
            result.error = Some(msg);
            return result;
        }
    };

    let url = format!("https://{domain}/");
    let response = match client.get(&url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            if e.is_timeout() {
                let msg = "request timed out".to_string();
                error!("{domain}: {msg}");
                result.error = Some(msg);
            } else if e.is_connect() {
                // Check for SSL errors in the connect error chain.
                let full = format!("{e}");
                if full.contains("certificate")
                    || full.contains("SSL")
                    || full.contains("tls")
                    || full.contains("TLS")
                {
                    let msg = format!("SSL error: {e}");
                    error!("{domain}: {msg}");
                    result.ssl_error = Some(msg);
                } else {
                    let msg = format!("connection refused or failed: {e}");
                    error!("{domain}: {msg}");
                    result.error = Some(msg);
                }
            } else {
                // Catch-all for other request errors; still check for SSL indicators.
                let full = format!("{e}");
                if full.contains("certificate")
                    || full.contains("SSL")
                    || full.contains("tls")
                    || full.contains("TLS")
                {
                    let msg = format!("SSL error: {e}");
                    error!("{domain}: {msg}");
                    result.ssl_error = Some(msg);
                } else {
                    let msg = format!("request failed: {e}");
                    error!("{domain}: {msg}");
                    result.error = Some(msg);
                }
            }
            return result;
        }
    };

    // --- Record HTTP status ---
    let status = response.status().as_u16();
    result.http_status = Some(status);
    info!("{domain}: HTTP status {status}");

    // --- Body processing for 2xx responses ---
    if (200..300).contains(&status) {
        match response.bytes().await {
            Ok(body) => {
                let size = body.len() as u64;
                let hash = compute_sha256(&body);
                result.body_hash = Some(hash);
                result.body_size = Some(size);
                info!("{domain}: body size={size}, hash computed");
            }
            Err(e) => {
                let msg = format!("failed to read response body: {e}");
                error!("{domain}: {msg}");
                result.error = Some(msg);
            }
        }
    }

    result
}

/// Compute the hex-encoded SHA-256 hash of a byte slice.
pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Classify an HTTP status code as an error (4xx/5xx) or not.
pub fn is_http_error(status: u16) -> bool {
    (400..600).contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_deterministic() {
        let data = b"hello world";
        let h1 = compute_sha256(data);
        let h2 = compute_sha256(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_known_value() {
        // SHA-256 of empty string
        let hash = compute_sha256(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn http_error_classification() {
        assert!(!is_http_error(200));
        assert!(!is_http_error(301));
        assert!(!is_http_error(399));
        assert!(is_http_error(400));
        assert!(is_http_error(404));
        assert!(is_http_error(500));
        assert!(is_http_error(599));
        assert!(!is_http_error(600));
    }
}
