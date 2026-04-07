use std::collections::HashMap;
use std::io;
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
}

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

/// Check the SSL certificate expiry for a domain by connecting to port 443.
pub fn check_ssl_expiry(domain: &str) -> SslExpiryResult {
    let mut result = SslExpiryResult {
        domain: domain.to_string(),
        days_remaining: None,
        expiry_date: None,
        error: None,
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
}
