use std::path::PathBuf;

use chrono::Utc;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use log::error;

use crate::checker::is_http_error;
use crate::error_log;
use crate::types::{AppError, CheckResult};

/// Configuration for sending alert emails via SMTP.
pub struct AlertConfig {
    pub sender: String,
    pub recipient: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub smtp_tls: bool,
    pub error_log: PathBuf,
}

/// What kind of alert (if any) should be sent for a check result.
#[derive(Debug, PartialEq)]
pub enum AlertDecision {
    /// Send an error email with the given error type and detail.
    ErrorEmail { error_type: String, detail: String },
    /// No alert needed from the check result alone.
    /// Content-change warnings are handled separately via baseline comparison.
    None,
}

// ---------------------------------------------------------------------------
// Pure formatting functions (public for property-based testing)
// ---------------------------------------------------------------------------

/// Format the body of an error email.
pub fn format_error_email_body(domain: &str, error_type: &str, detail: &str) -> String {
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    format!(
        "Uptime Monitor — Alert\n\
         =======================\n\
         \n\
         Domain:     {domain}\n\
         Error Type: {error_type}\n\
         Detail:     {detail}\n\
         Timestamp:  {timestamp}\n\
         \n\
         Next steps:\n\
         - Check your domain's DNS records for {domain}\n\
         - Verify your SSL certificate is valid and not expired\n\
         - Confirm your web server is running and accessible\n\
         - Review your dashboard for uptime history\n\
         \n\
         This check will automatically retry on the next cycle.\n\
         \n\
         — Uptime Monitor\n"
    )
}

/// Format the body of a warning (content-change) email.
pub fn format_warning_email_body(
    domain: &str,
    description: &str,
    old_size: u64,
    new_size: u64,
) -> String {
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    format!(
        "Uptime Monitor — Content Change\n\
         ================================\n\
         \n\
         Domain:      {domain}\n\
         Change:      {description}\n\
         Old Size:    {old_size} bytes\n\
         New Size:    {new_size} bytes\n\
         Timestamp:   {timestamp}\n\
         \n\
         Next steps:\n\
         - If you deployed a change, this is expected — no action needed\n\
         - If unexpected, check for unauthorized changes to {domain}\n\
         - Review your dashboard for full uptime history\n\
         \n\
         The new content is now your baseline for future comparisons.\n\
         \n\
         — Uptime Monitor\n"
    )
}

// ---------------------------------------------------------------------------
// SMTP sending functions
// ---------------------------------------------------------------------------

/// Build an async SMTP transport from the alert config.
fn build_smtp_transport(config: &AlertConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>, AppError> {
    let creds = Credentials::new(config.smtp_user.clone(), config.smtp_pass.clone());

    let builder = if !config.smtp_tls {
        // No TLS at all (rare, testing only)
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_host)
            .port(config.smtp_port)
    } else if config.smtp_port == 465 {
        // Implicit TLS (port 465) — connection is TLS from the start
        AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
            .map_err(|e| AppError::Ses(format!("SMTP relay error: {e}")))?
            .port(config.smtp_port)
    } else {
        // STARTTLS (port 587) — plaintext then upgrade
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
            .map_err(|e| AppError::Ses(format!("SMTP relay error: {e}")))?
            .port(config.smtp_port)
    };

    Ok(builder.credentials(creds).build())
}

/// Send an error alert email via SMTP.
///
/// Per Requirement 6.5, send failures are logged but **not** propagated.
pub async fn send_error_email(
    config: &AlertConfig,
    recipient_override: Option<&str>,
    domain: &str,
    error_type: &str,
    detail: &str,
) -> Result<(), AppError> {
    let body_text = format_error_email_body(domain, error_type, detail);
    let subject = format!("[Uptime Monitor] ALERT: {error_type} — {domain}");
    let to = recipient_override.unwrap_or(&config.recipient);

    if let Err(e) = send_smtp_email(config, to, &subject, &body_text).await {
        error!("Failed to send error email for {domain}: {e}");
        error_log::log_error(&config.error_log, "monitor", "email", &format!("error email for {domain}: {e}"));
    }
    Ok(())
}

/// Send a warning (content-change) email via SMTP.
///
/// Per Requirement 6.5, send failures are logged but **not** propagated.
pub async fn send_warning_email(
    config: &AlertConfig,
    recipient_override: Option<&str>,
    domain: &str,
    description: &str,
    old_size: u64,
    new_size: u64,
) -> Result<(), AppError> {
    let body_text = format_warning_email_body(domain, description, old_size, new_size);
    let subject = format!("[Uptime Monitor] Content changed — {domain}");
    let to = recipient_override.unwrap_or(&config.recipient);

    if let Err(e) = send_smtp_email(config, to, &subject, &body_text).await {
        error!("Failed to send warning email for {domain}: {e}");
        error_log::log_error(&config.error_log, "monitor", "email", &format!("warning email for {domain}: {e}"));
    }
    Ok(())
}

/// Send an SSL certificate expiry warning email.
///
/// Failures are logged but not propagated.
pub async fn send_ssl_expiry_email(
    config: &AlertConfig,
    recipient_override: Option<&str>,
    subject: &str,
    body_text: &str,
) -> Result<(), AppError> {
    let to = recipient_override.unwrap_or(&config.recipient);

    if let Err(e) = send_smtp_email(config, to, subject, body_text).await {
        error!("Failed to send SSL expiry email: {e}");
        error_log::log_error(&config.error_log, "monitor", "email", &format!("ssl expiry: {e}"));
    }
    Ok(())
}

/// Send an informational email (startup/shutdown notifications).
///
/// Failures are logged but not propagated.
pub async fn send_info_email(
    config: &AlertConfig,
    subject: &str,
    body_text: &str,
) -> Result<(), AppError> {
    if let Err(e) = send_smtp_email(config, &config.recipient, subject, body_text).await {
        error!("Failed to send info email: {e}");
        error_log::log_error(&config.error_log, "monitor", "email", &format!("info email '{subject}': {e}"));
    }
    Ok(())
}

/// Low-level helper: send a single email through SMTP.
async fn send_smtp_email(
    config: &AlertConfig,
    recipient: &str,
    subject: &str,
    body_text: &str,
) -> Result<(), AppError> {
    let from_addr = format!("🌐 Uptime Monitor 🕐 <{}>", config.sender);
    let email = Message::builder()
        .from(from_addr.parse().map_err(|e| AppError::Ses(format!("invalid sender: {e}")))?)
        .to(recipient.parse().map_err(|e| AppError::Ses(format!("invalid recipient: {e}")))?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body_text.to_string())
        .map_err(|e| AppError::Ses(format!("failed to build email: {e}")))?;

    let transport = build_smtp_transport(config)?;
    transport.send(email).await
        .map_err(|e| AppError::Ses(format!("SMTP send failed: {e}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Alert-decision logic (pure function — no network access)
// ---------------------------------------------------------------------------

/// Determine what alert to send based on a `CheckResult`.
///
/// - DNS error → error email
/// - SSL error → error email
/// - HTTP 4xx/5xx → error email
/// - Timeout / connection refused (recorded in `error` field) → error email
/// - Otherwise → no alert (content-change warnings are handled via baseline comparison)
pub fn decide_alert(result: &CheckResult) -> AlertDecision {
    // DNS failure
    if !result.dns_ok {
        return AlertDecision::ErrorEmail {
            error_type: "DNS Error".to_string(),
            detail: result
                .error
                .clone()
                .unwrap_or_else(|| "DNS resolution failed".to_string()),
        };
    }

    // SSL error
    if let Some(ref ssl_err) = result.ssl_error {
        return AlertDecision::ErrorEmail {
            error_type: "SSL Error".to_string(),
            detail: ssl_err.clone(),
        };
    }

    // HTTP 4xx/5xx
    if let Some(status) = result.http_status {
        if is_http_error(status) {
            return AlertDecision::ErrorEmail {
                error_type: "HTTP Error".to_string(),
                detail: format!("HTTP status {status}"),
            };
        }
    }

    // Timeout / connection refused / other request-level error
    if let Some(ref err) = result.error {
        return AlertDecision::ErrorEmail {
            error_type: "Connection Error".to_string(),
            detail: err.clone(),
        };
    }

    AlertDecision::None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_result(domain: &str) -> CheckResult {
        CheckResult {
            domain: domain.to_string(),
            dns_ok: true,
            ssl_error: None,
            http_status: Some(200),
            body_hash: Some("abc".to_string()),
            body_size: Some(100),
            error: None,
        }
    }

    #[test]
    fn decide_alert_dns_failure() {
        let r = CheckResult {
            dns_ok: false,
            error: Some("DNS resolution failed".to_string()),
            ..ok_result("fail.com")
        };
        match decide_alert(&r) {
            AlertDecision::ErrorEmail { error_type, .. } => {
                assert_eq!(error_type, "DNS Error");
            }
            other => panic!("expected ErrorEmail, got {other:?}"),
        }
    }

    #[test]
    fn decide_alert_ssl_error() {
        let r = CheckResult {
            ssl_error: Some("certificate expired".to_string()),
            http_status: None,
            body_hash: None,
            body_size: None,
            ..ok_result("ssl.com")
        };
        match decide_alert(&r) {
            AlertDecision::ErrorEmail { error_type, .. } => {
                assert_eq!(error_type, "SSL Error");
            }
            other => panic!("expected ErrorEmail, got {other:?}"),
        }
    }

    #[test]
    fn decide_alert_http_error() {
        let r = CheckResult {
            http_status: Some(503),
            body_hash: None,
            body_size: None,
            ..ok_result("down.com")
        };
        match decide_alert(&r) {
            AlertDecision::ErrorEmail { error_type, detail, .. } => {
                assert_eq!(error_type, "HTTP Error");
                assert!(detail.contains("503"));
            }
            other => panic!("expected ErrorEmail, got {other:?}"),
        }
    }

    #[test]
    fn decide_alert_timeout() {
        let r = CheckResult {
            http_status: None,
            body_hash: None,
            body_size: None,
            error: Some("request timed out".to_string()),
            ..ok_result("slow.com")
        };
        match decide_alert(&r) {
            AlertDecision::ErrorEmail { error_type, .. } => {
                assert_eq!(error_type, "Connection Error");
            }
            other => panic!("expected ErrorEmail, got {other:?}"),
        }
    }

    #[test]
    fn decide_alert_healthy_domain() {
        let r = ok_result("healthy.com");
        assert_eq!(decide_alert(&r), AlertDecision::None);
    }

    #[test]
    fn error_email_body_contains_required_fields() {
        let body = format_error_email_body("example.com", "DNS Error", "no records");
        assert!(body.contains("example.com"));
        assert!(body.contains("DNS Error"));
        assert!(body.contains("no records"));
        assert!(body.contains("UTC"));
    }

    #[test]
    fn warning_email_body_contains_required_fields() {
        let body = format_warning_email_body("example.com", "content changed", 100, 200);
        assert!(body.contains("example.com"));
        assert!(body.contains("content changed"));
        assert!(body.contains("100"));
        assert!(body.contains("200"));
        assert!(body.contains("UTC"));
    }
}
