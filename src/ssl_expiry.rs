use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use chrono::{NaiveDate, NaiveDateTime, Utc};
use rustls::pki_types::ServerName;

/// Days-until-expiry thresholds that trigger an email (descending).
const ALERT_THRESHOLDS: &[i64] = &[15, 7, 1, 0];

/// Result of checking a single domain's SSL certificate expiry.
#[derive(Debug)]
pub struct SslExpiryResult {
    #[allow(dead_code)]
    pub domain: String,
    pub days_remaining: Option<i64>,
    pub expiry_date: Option<String>,
    pub error: Option<String>,
    /// The host whose certificate was actually inspected. This differs from
    /// `domain` when the apex only listens on port 80 and redirects to an
    /// HTTPS host (e.g. `dhanvalley.com` → `www.dhanvalley.com`). `None` when
    /// the cert came directly from `domain` itself.
    pub checked_host: Option<String>,
}

/// Maximum number of HTTP redirect hops to follow on port 80 when looking for
/// the real HTTPS host. Keeps the fallback bounded and loop-free.
const MAX_REDIRECT_HOPS: u8 = 5;

/// Per-connection timeout for the port-80 redirect probe.
const REDIRECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Track which threshold was last alerted per domain so we don't repeat.
/// Key: domain, Value: last threshold that was emailed (e.g. 15, 7, 1, 0).
pub type SslAlertState = HashMap<String, i64>;

/// Determine which threshold (if any) should trigger an email.
///
/// Returns `Some(threshold)` if the domain has crossed a new threshold
/// since the last alert, or `None` if no email is needed.
pub fn should_alert(days_remaining: i64, last_alerted: Option<i64>) -> Option<i64> {
    // Find the lowest threshold that the domain has reached or passed.
    // Thresholds are descending: [15, 7, 1, 0].
    // We want the tightest match, e.g. 3 days remaining → threshold 7 (not 15).
    let current_threshold = ALERT_THRESHOLDS
        .iter()
        .copied()
        .filter(|&t| days_remaining <= t)
        .last();

    let threshold = current_threshold?;

    match last_alerted {
        None => Some(threshold),
        Some(prev) if prev <= threshold => None,
        Some(_) => Some(threshold),
    }
}

/// Check the SSL certificate expiry for a domain.
///
/// Strategy:
/// 1. Try a direct TLS handshake against `<domain>:443`. If it succeeds, return
///    immediately — this is the common path and behaves exactly as before, so
///    regular SSL sites are never affected.
/// 2. If the direct check fails (e.g. the apex only listens on port 80 to issue
///    a redirect, like `dhanvalley.com`), fall back to following HTTP redirects
///    on port 80 until the first `https://` target is found, then verify the
///    certificate of that resolved host.
/// 3. If the fallback finds no HTTPS target, return the original direct error so
///    genuine SSL failures still surface unchanged.
pub fn check_ssl_expiry(domain: &str) -> SslExpiryResult {
    let direct = check_ssl_expiry_host(domain, None);
    if direct.error.is_none() {
        return direct;
    }

    // Direct :443 check failed — attempt the port-80 redirect fallback.
    if let Some(resolved) = resolve_https_host_via_redirects(domain, MAX_REDIRECT_HOPS)
        && resolved != domain
    {
        let fallback = check_ssl_expiry_host(&resolved, Some(domain.to_string()));
        if fallback.error.is_none() {
            return fallback;
        }
    }

    // No usable redirect target — preserve the original direct-check error.
    direct
}

/// Check the SSL certificate expiry for a specific host by connecting to its
/// port 443. `display_domain`, when set, becomes the `domain` reported in the
/// result (used when `host` was resolved via a redirect from another domain).
fn check_ssl_expiry_host(host: &str, display_domain: Option<String>) -> SslExpiryResult {
    let domain = host;
    let mut result = SslExpiryResult {
        domain: display_domain.clone().unwrap_or_else(|| domain.to_string()),
        days_remaining: None,
        expiry_date: None,
        error: None,
        checked_host: display_domain.map(|_| host.to_string()),
    };

    // Ensure a crypto provider is installed (idempotent after first call).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = match ServerName::try_from(domain.to_string()) {
        Ok(sn) => sn,
        Err(e) => {
            result.error = Some(format!("invalid server name: {e}"));
            return result;
        }
    };

    let mut conn = match rustls::ClientConnection::new(Arc::new(config), server_name) {
        Ok(c) => c,
        Err(e) => {
            result.error = Some(format!("TLS connection setup: {e}"));
            return result;
        }
    };

    // Resolve and connect with timeout.
    let addr = format!("{domain}:443");
    let sock_addr = match addr.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => a,
            None => {
                result.error = Some("no addresses resolved".into());
                return result;
            }
        },
        Err(e) => {
            result.error = Some(format!("DNS resolve: {e}"));
            return result;
        }
    };

    let mut sock = match TcpStream::connect_timeout(&sock_addr, Duration::from_secs(10)) {
        Ok(s) => s,
        Err(e) => {
            result.error = Some(format!("TCP connect: {e}"));
            return result;
        }
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = sock.set_write_timeout(Some(Duration::from_secs(10)));

    // Drive the TLS handshake to completion.
    loop {
        if conn.is_handshaking() {
            match conn.complete_io(&mut sock) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    result.error = Some(format!("TLS handshake: {e}"));
                    return result;
                }
            }
        } else {
            break;
        }
    }

    // Extract peer certificates.
    let certs = match conn.peer_certificates() {
        Some(c) if !c.is_empty() => c,
        _ => {
            result.error = Some("no peer certificates".into());
            return result;
        }
    };

    // Parse the leaf certificate to get notAfter.
    let leaf = &certs[0];
    match x509_parser::parse_x509_certificate(leaf.as_ref()) {
        Ok((_, cert)) => {
            let not_after = cert.validity().not_after.to_datetime();
            let expiry = NaiveDateTime::new(
                NaiveDate::from_ymd_opt(
                    not_after.year() as i32,
                    not_after.month() as u32,
                    not_after.day() as u32,
                )
                .unwrap(),
                chrono::NaiveTime::from_hms_opt(
                    not_after.hour() as u32,
                    not_after.minute() as u32,
                    not_after.second() as u32,
                )
                .unwrap(),
            );
            let now = Utc::now().naive_utc();
            let days = (expiry - now).num_days();

            result.days_remaining = Some(days);
            result.expiry_date = Some(expiry.format("%Y-%m-%d").to_string());
        }
        Err(e) => {
            result.error = Some(format!("x509 parse: {e}"));
        }
    }

    result
}

/// Outcome of classifying a redirect `Location` header value.
#[derive(Debug, PartialEq, Eq)]
enum Hop {
    /// First HTTPS target reached — this host's cert should be verified.
    Https(String),
    /// Another HTTP hop to follow on port 80.
    Http { host: String, port: u16, path: String },
    /// Location we can't or won't follow (unknown scheme, malformed, etc.).
    Unsupported,
}

/// Follow HTTP redirects starting at `http://<domain>/` (port 80) and return the
/// host of the first `https://` URL encountered, or `None` if no HTTPS target is
/// found within `max_hops`.
fn resolve_https_host_via_redirects(domain: &str, max_hops: u8) -> Option<String> {
    let mut host = domain.to_string();
    let mut port: u16 = 80;
    let mut path = "/".to_string();

    for _ in 0..max_hops {
        let location = http_fetch_location(&host, port, &path, &host)?;
        match classify_location(&location, &host) {
            Hop::Https(h) => return Some(h),
            Hop::Http { host: h, port: p, path: new_path } => {
                host = h;
                port = p;
                path = new_path;
            }
            Hop::Unsupported => return None,
        }
    }
    None
}

/// Decide how to follow a `Location` header value given the current host.
fn classify_location(location: &str, current_host: &str) -> Hop {
    let loc = location.trim();
    if let Some(rest) = strip_prefix_ci(loc, "https://") {
        let (host, _port, _path) = split_authority(rest, 443);
        if host.is_empty() {
            Hop::Unsupported
        } else {
            Hop::Https(host)
        }
    } else if let Some(rest) = strip_prefix_ci(loc, "http://") {
        let (host, port, path) = split_authority(rest, 80);
        if host.is_empty() {
            Hop::Unsupported
        } else {
            Hop::Http { host, port, path }
        }
    } else if loc.starts_with('/') {
        // Same-host relative redirect — stay on HTTP/port 80.
        Hop::Http {
            host: current_host.to_string(),
            port: 80,
            path: loc.to_string(),
        }
    } else {
        Hop::Unsupported
    }
}

/// Case-insensitive prefix strip for URL schemes.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Split an authority+path string (everything after `scheme://`) into
/// `(host, port, path)`, applying `default_port` when none is specified.
fn split_authority(s: &str, default_port: u16) -> (String, u16, String) {
    // Strip any userinfo (`user:pass@host`) — not expected, but be safe.
    let s = match s.split_once('@') {
        Some((_, rest)) => rest,
        None => s,
    };
    let (authority, path) = match s.find('/') {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    };
    let path = if path.is_empty() { "/".to_string() } else { path.to_string() };
    (host, port, path)
}

/// Issue a bounded HTTP/1.1 GET against `host:port` and return the value of the
/// `Location` header if the response is a 3xx redirect. Reads only the response
/// headers, with connection/read timeouts and a hard byte cap.
fn http_fetch_location(host: &str, port: u16, path: &str, host_header: &str) -> Option<String> {
    let addr = format!("{host}:{port}");
    let sock_addr = addr.to_socket_addrs().ok()?.next()?;

    let mut stream = TcpStream::connect_timeout(&sock_addr, REDIRECT_TIMEOUT).ok()?;
    let _ = stream.set_read_timeout(Some(REDIRECT_TIMEOUT));
    let _ = stream.set_write_timeout(Some(REDIRECT_TIMEOUT));

    let request_path = if path.is_empty() { "/" } else { path };
    let request = format!(
        "GET {request_path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         User-Agent: uptime-monitor/ssl-redirect-check\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;

    // Read until the end of headers (blank line), capped to avoid unbounded reads.
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if find_header_end(&buf).is_some() || buf.len() >= MAX_HEADER_BYTES {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let header_end = find_header_end(&buf).unwrap_or(buf.len());
    let headers = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = headers.split("\r\n").flat_map(|l| l.split('\n'));

    let status_line = lines.next()?;
    let code = parse_status_code(status_line)?;
    if !(300..400).contains(&code) {
        return None;
    }

    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("location")
        {
            let v = value.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Find the byte offset just past the end of the HTTP header block
/// (the first `\r\n\r\n`, or `\n\n` as a fallback).
fn find_header_end(buf: &[u8]) -> Option<usize> {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(pos + 4);
    }
    buf.windows(2).position(|w| w == b"\n\n").map(|pos| pos + 2)
}

/// Parse the numeric status code out of an HTTP status line
/// (e.g. `HTTP/1.1 302 Found` → `302`).
fn parse_status_code(status_line: &str) -> Option<u16> {
    let mut parts = status_line.split_whitespace();
    let _http = parts.next()?;
    parts.next()?.parse().ok()
}

/// Format the subject line for an SSL expiry email.
pub fn format_subject(domain: &str, days: i64) -> String {
    match days {
        d if d <= 0 => format!("[Uptime Monitor] SSL certificate EXPIRED — {domain}"),
        1 => format!("[Uptime Monitor] SSL certificate expires TOMORROW — {domain}"),
        _ => format!("[Uptime Monitor] SSL certificate expires in {days} days — {domain}"),
    }
}

/// Format the body of an SSL expiry warning email.
pub fn format_body(domain: &str, days: i64, expiry_date: &str) -> String {
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

    let urgency = match days {
        d if d <= 0 => format!(
            "The SSL certificate for {domain} has EXPIRED.\n\
             Your site is no longer serving secure connections. Visitors will see\n\
             browser warnings and may be unable to access your site."
        ),
        1 => format!(
            "The SSL certificate for {domain} expires TOMORROW.\n\
             Renew it now to avoid any downtime or browser warnings."
        ),
        d if d <= 7 => format!(
            "The SSL certificate for {domain} expires in {d} days.\n\
             This is your final reminder before the deadline. Please renew soon."
        ),
        d => format!(
            "The SSL certificate for {domain} expires in {d} days.\n\
             You have time, but we recommend renewing early to avoid last-minute issues."
        ),
    };

    let action = match days {
        d if d <= 0 => "\
             - Renew your SSL certificate immediately\n\
             - If using Let's Encrypt, run your renewal command or check your automation\n\
             - Verify the new certificate is installed: openssl s_client -connect {domain}:443\n\
             - Clear any CDN or proxy caches that may serve the old certificate",
        d if d <= 1 => "\
             - Renew your SSL certificate today\n\
             - If using Let's Encrypt, check that auto-renewal is working\n\
             - Verify after renewal: openssl s_client -connect {domain}:443",
        _ => "\
             - Schedule your SSL certificate renewal\n\
             - If using Let's Encrypt, confirm auto-renewal is configured\n\
             - No immediate action required, but don't wait until the last day",
    };

    let action = action.replace("{domain}", domain);

    format!(
        "Uptime Monitor — SSL Certificate Expiry\n\
         =========================================\n\
         \n\
         {urgency}\n\
         \n\
         Domain:      {domain}\n\
         Expires:     {expiry_date}\n\
         Days Left:   {days}\n\
         Checked:     {timestamp}\n\
         \n\
         Next steps:\n\
         {action}\n\
         \n\
         — Uptime Monitor\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_alert_first_time_at_15_days() {
        assert_eq!(should_alert(15, None), Some(15));
        assert_eq!(should_alert(14, None), Some(15));
        assert_eq!(should_alert(8, None), Some(15));
    }

    #[test]
    fn should_alert_first_time_at_7_days() {
        assert_eq!(should_alert(7, None), Some(7));
        assert_eq!(should_alert(5, None), Some(7));
    }

    #[test]
    fn should_alert_first_time_at_1_day() {
        assert_eq!(should_alert(1, None), Some(1));
    }

    #[test]
    fn should_alert_first_time_at_0_days() {
        assert_eq!(should_alert(0, None), Some(0));
        assert_eq!(should_alert(-5, None), Some(0));
    }

    #[test]
    fn should_not_alert_above_15_days() {
        assert_eq!(should_alert(16, None), None);
        assert_eq!(should_alert(90, None), None);
    }

    #[test]
    fn should_not_repeat_same_threshold() {
        assert_eq!(should_alert(14, Some(15)), None);
        assert_eq!(should_alert(7, Some(7)), None);
        assert_eq!(should_alert(0, Some(0)), None);
    }

    #[test]
    fn should_alert_on_new_lower_threshold() {
        assert_eq!(should_alert(7, Some(15)), Some(7));
        assert_eq!(should_alert(1, Some(7)), Some(1));
        assert_eq!(should_alert(0, Some(1)), Some(0));
    }

    #[test]
    fn should_not_alert_between_thresholds_if_already_alerted() {
        assert_eq!(should_alert(10, Some(15)), None);
    }

    #[test]
    fn format_subject_expired() {
        let s = format_subject("example.com", 0);
        assert!(s.contains("EXPIRED"));
    }

    #[test]
    fn format_subject_tomorrow() {
        let s = format_subject("example.com", 1);
        assert!(s.contains("TOMORROW"));
    }

    #[test]
    fn format_subject_days() {
        let s = format_subject("example.com", 7);
        assert!(s.contains("7 days"));
    }

    #[test]
    fn format_body_contains_domain_and_date() {
        let body = format_body("example.com", 7, "2026-04-13");
        assert!(body.contains("example.com"));
        assert!(body.contains("2026-04-13"));
        assert!(body.contains("7"));
    }

    #[test]
    fn format_body_expired_urgency() {
        let body = format_body("example.com", 0, "2026-04-06");
        assert!(body.contains("EXPIRED"));
        assert!(body.contains("immediately"));
    }

    #[test]
    fn format_body_tomorrow_urgency() {
        let body = format_body("example.com", 1, "2026-04-07");
        assert!(body.contains("TOMORROW"));
        assert!(body.contains("today"));
    }

    // ── Redirect-following helpers ───────────────────────────────────────────

    #[test]
    fn split_authority_host_only() {
        assert_eq!(
            split_authority("www.example.com", 443),
            ("www.example.com".to_string(), 443, "/".to_string())
        );
    }

    #[test]
    fn split_authority_with_path() {
        assert_eq!(
            split_authority("www.example.com/foo/bar", 443),
            ("www.example.com".to_string(), 443, "/foo/bar".to_string())
        );
    }

    #[test]
    fn split_authority_with_port() {
        assert_eq!(
            split_authority("example.com:8443/x", 443),
            ("example.com".to_string(), 8443, "/x".to_string())
        );
    }

    #[test]
    fn split_authority_strips_userinfo() {
        assert_eq!(
            split_authority("user:pass@example.com/x", 80),
            ("example.com".to_string(), 80, "/x".to_string())
        );
    }

    #[test]
    fn classify_https_target_returns_host() {
        assert_eq!(
            classify_location("https://www.dhanvalley.com", "dhanvalley.com"),
            Hop::Https("www.dhanvalley.com".to_string())
        );
        assert_eq!(
            classify_location("https://www.dhanvalley.com/", "dhanvalley.com"),
            Hop::Https("www.dhanvalley.com".to_string())
        );
    }

    #[test]
    fn classify_https_is_case_insensitive() {
        assert_eq!(
            classify_location("HTTPS://Www.Example.com/", "example.com"),
            Hop::Https("Www.Example.com".to_string())
        );
    }

    #[test]
    fn classify_http_target_returns_next_hop() {
        assert_eq!(
            classify_location("http://other.example.com/path", "example.com"),
            Hop::Http {
                host: "other.example.com".to_string(),
                port: 80,
                path: "/path".to_string()
            }
        );
    }

    #[test]
    fn classify_relative_redirect_stays_on_same_host() {
        assert_eq!(
            classify_location("/login", "example.com"),
            Hop::Http {
                host: "example.com".to_string(),
                port: 80,
                path: "/login".to_string()
            }
        );
    }

    #[test]
    fn classify_unsupported_scheme() {
        assert_eq!(classify_location("ftp://example.com", "example.com"), Hop::Unsupported);
        assert_eq!(classify_location("mailto:a@b.com", "example.com"), Hop::Unsupported);
    }

    #[test]
    fn parse_status_code_extracts_3xx() {
        assert_eq!(parse_status_code("HTTP/1.1 302 Found"), Some(302));
        assert_eq!(parse_status_code("HTTP/1.0 301 Moved Permanently"), Some(301));
        assert_eq!(parse_status_code("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(parse_status_code("garbage"), None);
    }

    #[test]
    fn find_header_end_crlf() {
        let buf = b"HTTP/1.1 302 Found\r\nLocation: https://x\r\n\r\nbody";
        let end = find_header_end(buf).unwrap();
        assert_eq!(&buf[..end], b"HTTP/1.1 302 Found\r\nLocation: https://x\r\n\r\n");
    }
}
