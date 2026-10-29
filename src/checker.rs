use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::config::{GOOGLE, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use log::{error, info};
use reqwest::Client;
use sha2::{Digest, Sha256};

use crate::types::CheckResult;

/// Perform a full health check on a single domain: DNS → HTTPS GET → SSL → content hash.
///
/// On DNS failure, remaining checks are skipped and `dns_ok` is set to `false`.
pub async fn check_domain(domain: &str, timeout: Duration) -> CheckResult {
    let client = match Client::builder().timeout(timeout).build() {
        Ok(client) => client,
        Err(error) => {
            return failed_result(domain, format!("failed to build HTTP client: {error}"));
        }
    };
    check_domain_with_client(domain, client).await
}

/// Check using the caller's transport policy. Hosted deployments can enforce
/// public-address resolution and bounded redirects without changing standalone behavior.
pub async fn check_domain_with_client(domain: &str, client: Client) -> CheckResult {
    let mut result = CheckResult {
        domain: domain.to_string(),
        dns_ok: false,
        ssl_error: None,
        http_status: None,
        body_hash: None,
        body_size: None,
        error: None,
        redirected: false,
        special_handling: 0,
    };

    // --- DNS resolution ---
    let resolver = match Resolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&GOOGLE),
        TokioRuntimeProvider::default(),
    )
    .build()
    {
        Ok(resolver) => resolver,
        Err(error) => {
            result.error = Some(format!("DNS resolver initialization failed: {error}"));
            return result;
        }
    };

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
    let url = format!("https://{domain}/");
    let mut response = match send_with_http_fallback(&client, domain, &url).await {
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

    // --- Detect redirect by comparing final URL to original request URL ---
    if response.url().as_str() != url {
        result.redirected = true;
    }

    // --- Record HTTP status ---
    let status = response.status().as_u16();
    result.http_status = Some(status);
    info!("{domain}: HTTP status {status}");

    // --- Body processing for 2xx responses ---
    if (200..300).contains(&status) {
        match read_bounded_body(&mut response).await {
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

/// A monitor should not download an unlimited streaming response into memory.
/// This ceiling still permits ordinary pages while bounding concurrent checks.
async fn read_bounded_body(response: &mut reqwest::Response) -> Result<Vec<u8>, String> {
    const MAX_BODY: usize = 8 * 1024 * 1024;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if chunk.len() > MAX_BODY.saturating_sub(body.len()) {
            return Err("response body exceeds 8 MiB monitoring limit".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn failed_result(domain: &str, error: String) -> CheckResult {
    CheckResult {
        domain: domain.into(),
        dns_ok: false,
        ssl_error: None,
        http_status: None,
        body_hash: None,
        body_size: None,
        error: Some(error),
        redirected: false,
        special_handling: 0,
    }
}

/// Send a GET to the HTTPS URL, falling back to HTTP on a plain connectivity failure.
///
/// Some apex domains only listen on port 80 to issue a redirect to an HTTPS host
/// on a different name; connecting to `:443` on the apex then times out or is
/// refused. In that case we retry over `http://<domain>/` and let reqwest follow
/// the redirect chain (including the upgrade back to HTTPS), so the site is
/// correctly reported as up.
///
/// The fallback is deliberately NOT attempted for TLS/certificate errors — those
/// are genuine problems that must be surfaced. If the fallback also fails, the
/// original HTTPS error is returned so downstream error classification is
/// unchanged. Sites whose `:443` responds normally never hit the fallback.
async fn send_with_http_fallback(
    client: &Client,
    domain: &str,
    https_url: &str,
) -> Result<reqwest::Response, reqwest::Error> {
    match client.get(https_url).send().await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            let full = format!("{e}");
            let looks_ssl = full.contains("certificate")
                || full.contains("SSL")
                || full.contains("tls")
                || full.contains("TLS");
            if !looks_ssl && (e.is_timeout() || e.is_connect()) {
                let http_url = format!("http://{domain}/");
                if let Ok(resp) = client.get(&http_url).send().await {
                    info!("{domain}: HTTPS unreachable, recovered via HTTP→redirect fallback");
                    return Ok(resp);
                }
            }
            // Fallback not applicable or also failed — preserve the original error.
            Err(e)
        }
    }
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

    async fn body_response(length: usize) -> reqwest::Response {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await;
            let header =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n");
            socket.write_all(header.as_bytes()).await.unwrap();
            let _ = socket.write_all(&vec![b'x'; length]).await;
        });
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn bounded_body_preserves_small_response() {
        let mut response = body_response(128).await;
        assert_eq!(
            read_bounded_body(&mut response).await.unwrap(),
            vec![b'x'; 128]
        );
    }

    #[tokio::test]
    async fn bounded_body_rejects_oversized_response() {
        let mut response = body_response(8 * 1024 * 1024 + 1).await;
        assert!(
            read_bounded_body(&mut response)
                .await
                .unwrap_err()
                .contains("8 MiB")
        );
    }

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
