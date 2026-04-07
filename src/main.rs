mod alerter;
mod baseline;
mod checker;
mod config;
mod domain;
mod error_log;
mod ghost;
mod ssl_expiry;
mod types;
mod uptime_log;

use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use log::{error, info, warn};
use tokio::signal;

use alerter::{AlertConfig, AlertDecision};
use baseline::BaselineAction;
use domain::DomainEntry;

#[tokio::main]
async fn main() {
    env_logger::Builder::new()
        .target(env_logger::Target::Stderr)
        .filter_level(log::LevelFilter::Info)
        .init();

    let cfg = match config::parse_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let mut entries = match domain::load_domains(&cfg.domain_file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    if entries.is_empty() {
        warn!("No valid domains found in {}", cfg.domain_file.display());
    }

    let mut baselines = match baseline::load_baselines(&cfg.baseline_file) {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to load baselines: {e}");
            std::process::exit(1);
        }
    };

    // Sync new recipient emails to Ghost CMS (if configured).
    if let Some(ghost_config) = ghost::GhostConfig::from_env() {
        let unique_emails: Vec<&str> = entries
            .iter()
            .filter_map(|e| e.recipient.as_deref())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let synced_file = cfg.log_file.with_file_name("ghost_synced.txt");
        ghost::sync_new_emails(&ghost_config, &unique_emails, &synced_file).await;
    }

    let alert_config = AlertConfig {
        sender: cfg.sender_email.clone(),
        recipient: cfg.recipient_email.clone(),
        smtp_host: cfg.smtp_host.clone(),
        smtp_port: cfg.smtp_port,
        smtp_user: cfg.smtp_user.clone(),
        smtp_pass: cfg.smtp_pass.clone(),
        smtp_tls: cfg.smtp_tls,
        error_log: cfg.error_log.clone(),
    };

    let timeout = Duration::from_secs(30);
    let domain_names: Vec<&str> = entries.iter().map(|e| e.domain.as_str()).collect();

    // Send startup notification.
    let startup_body = format!(
        "Uptime Monitor — Started\n\
         =========================\n\n\
         Monitoring {} domains: {}\n\
         Default interval: {}\n\
         Timestamp: {}\n\n\
         Checks: DNS resolution, SSL certificate, HTTP status, content changes\n\
         Alerts: You'll receive an email the moment any issue is detected.\n\n\
         — Uptime Monitor\n",
        entries.len(),
        domain_names.join(", "),
        &cfg.interval_str,
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
    );
    let _ = alerter::send_info_email(&alert_config, "[Uptime Monitor] Monitoring started", &startup_body).await;

    // Re-read the domain file every 30 minutes so additions/removals
    // take effect without restarting the container.
    const DOMAIN_RELOAD_SECS: u64 = 1800;
    let mut last_domain_reload = std::time::Instant::now();

    // SSL expiry check: once per day.
    const SSL_CHECK_SECS: u64 = 86400;
    let mut last_ssl_check = std::time::Instant::now() - Duration::from_secs(SSL_CHECK_SECS);
    let mut ssl_alert_state = ssl_expiry::SslAlertState::new();

    // Group domains by their effective interval for scheduling.
    let mut interval_groups: HashMap<Duration, Vec<DomainEntry>> = HashMap::new();
    for entry in &entries {
        let interval = entry.interval.unwrap_or(cfg.check_interval);
        interval_groups.entry(interval).or_default().push(entry.clone());
    }

    // Track last-check time per interval group.
    let mut last_check: HashMap<Duration, std::time::Instant> = HashMap::new();
    // Run all groups immediately on first iteration.
    let now = std::time::Instant::now();
    for interval in interval_groups.keys() {
        last_check.insert(*interval, now - *interval);
    }

    // Monitoring loop with graceful shutdown.
    loop {
        let tick_start = std::time::Instant::now();

        // Periodically re-read the domain file to pick up changes.
        if tick_start.duration_since(last_domain_reload).as_secs() >= DOMAIN_RELOAD_SECS {
            match domain::load_domains(&cfg.domain_file) {
                Ok(new_entries) => {
                    if new_entries != entries {
                        info!("Domain file changed — reloading ({} domains)", new_entries.len());
                        entries = new_entries;

                        // Rebuild interval groups from the fresh list.
                        interval_groups.clear();
                        for entry in &entries {
                            let iv = entry.interval.unwrap_or(cfg.check_interval);
                            interval_groups.entry(iv).or_default().push(entry.clone());
                        }

                        // Ensure new interval groups get checked promptly.
                        for iv in interval_groups.keys() {
                            last_check.entry(*iv).or_insert(tick_start - *iv);
                        }
                        // Remove stale interval groups that no longer exist.
                        last_check.retain(|iv, _| interval_groups.contains_key(iv));
                    }
                }
                Err(e) => {
                    error!("Failed to reload domain file: {e} — keeping previous list");
                }
            }
            last_domain_reload = tick_start;
        }

        // Daily SSL certificate expiry check.
        if tick_start.duration_since(last_ssl_check).as_secs() >= SSL_CHECK_SECS {
            info!("Starting daily SSL expiry check for {} domains", entries.len());
            for entry in &entries {
                let d = &entry.domain;
                let result = ssl_expiry::check_ssl_expiry(d);

                if let Some(ref err) = result.error {
                    warn!("{d}: SSL expiry check failed — {err}");
                    continue;
                }

                if let (Some(days), Some(expiry_date)) = (result.days_remaining, &result.expiry_date) {
                    info!("{d}: SSL certificate expires in {days} days ({expiry_date})");

                    let last = ssl_alert_state.get(d).copied();
                    if let Some(threshold) = ssl_expiry::should_alert(days, last) {
                        let subject = ssl_expiry::format_subject(d, days);
                        let body = ssl_expiry::format_body(d, days, expiry_date);
                        let recipient_override = entry.recipient.as_deref();

                        info!("{d}: sending SSL expiry alert ({days} days, threshold {threshold})");
                        let _ = alerter::send_ssl_expiry_email(
                            &alert_config, recipient_override, &subject, &body,
                        ).await;

                        ssl_alert_state.insert(d.clone(), threshold);
                    }
                }
            }
            last_ssl_check = tick_start;
        }

        for (&interval, group) in &interval_groups {
            let elapsed = tick_start.duration_since(*last_check.get(&interval).unwrap_or(&tick_start));
            if elapsed < interval {
                continue;
            }
            last_check.insert(interval, tick_start);

            info!("Starting check cycle for {} domains (interval {:?})", group.len(), interval);

            for entry in group.iter() {
                let d = &entry.domain;
                let recipient_override = entry.recipient.as_deref();

                let result = checker::check_domain(d, timeout).await;

                // Write JSONL log entry.
                let log_entry = uptime_log::LogEntry::from_check(&result);
                if let Err(e) = uptime_log::append_entry(&cfg.log_file, &log_entry) {
                    error!("Failed to write uptime log: {e}");
                }

                // Log health check outcome.
                if !result.dns_ok {
                    info!("{d}: DNS check FAILED");
                } else {
                    info!("{d}: DNS check OK");
                }
                if let Some(ref ssl) = result.ssl_error {
                    info!("{d}: SSL check FAILED — {ssl}");
                }
                match result.http_status {
                    Some(s) => info!("{d}: HTTP status {s}"),
                    None if result.dns_ok => info!("{d}: HTTP check — no response"),
                    _ => {}
                }
                if let Some(ref err) = result.error {
                    info!("{d}: error — {err}");
                }

                // Alert decision.
                match alerter::decide_alert(&result) {
                    AlertDecision::ErrorEmail { error_type, detail } => {
                        info!("{d}: sending error email ({error_type})");
                        let _ = alerter::send_error_email(
                            &alert_config, recipient_override, d, &error_type, &detail,
                        ).await;
                    }
                    AlertDecision::None => {}
                }

                // Baseline comparison.
                match baseline::compare_and_update(&result, &mut baselines) {
                    BaselineAction::NewBaseline => info!("{d}: new baseline stored"),
                    BaselineAction::Unchanged => info!("{d}: content unchanged"),
                    BaselineAction::ContentChanged { old_size, new_size } => {
                        warn!("{d}: content changed (old={old_size}, new={new_size})");
                        let _ = alerter::send_warning_email(
                            &alert_config, recipient_override, d,
                            "Home page content changed", old_size, new_size,
                        ).await;
                    }
                    BaselineAction::Skipped => {}
                }
            }
        }

        // Persist baselines.
        if let Err(e) = baseline::save_baselines(&cfg.baseline_file, &baselines) {
            error!("Failed to save baselines: {e}");
        }

        // Sleep in 1-second ticks, checking for shutdown signal.
        let sleep_until = tick_start + Duration::from_secs(30);
        loop {
            let remaining = sleep_until.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(remaining.min(Duration::from_secs(1))) => {}
                _ = signal::ctrl_c() => {
                    info!("Shutdown signal received");
                    let shutdown_body = format!(
                        "Uptime Monitor — Stopped\n\
                         =========================\n\n\
                         Timestamp: {}\n\n\
                         Monitoring has stopped. Domains are no longer being checked.\n\
                         Restart the monitor to resume health checks and alerts.\n\n\
                         — Uptime Monitor\n",
                        Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
                    );
                    let _ = alerter::send_info_email(
                        &alert_config, "[Uptime Monitor] Monitoring stopped", &shutdown_body,
                    ).await;
                    std::process::exit(0);
                }
            }
        }
    }
}
