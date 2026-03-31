mod alerter;
mod baseline;
mod checker;
mod config;
mod domain;
mod types;
mod uptime_log;

use std::time::Duration;

use chrono::Utc;
use log::{error, info, warn};

use alerter::{AlertConfig, AlertDecision};
use baseline::BaselineAction;

#[tokio::main]
async fn main() {
    // Initialize logging to stderr.
    env_logger::Builder::new()
        .target(env_logger::Target::Stderr)
        .filter_level(log::LevelFilter::Info)
        .init();

    // Parse CLI configuration.
    let cfg = match config::parse_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    // Load domains from file.
    let domains = match domain::load_domains(&cfg.domain_file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    if domains.is_empty() {
        warn!("No valid domains found in {}", cfg.domain_file.display());
    }

    // Load existing baselines.
    let mut baselines = match baseline::load_baselines(&cfg.baseline_file) {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to load baselines: {e}");
            std::process::exit(1);
        }
    };

    // Build alert configuration.
    let alert_config = AlertConfig {
        sender: cfg.sender_email.clone(),
        recipient: cfg.recipient_email.clone(),
        smtp_host: cfg.smtp_host.clone(),
        smtp_port: cfg.smtp_port,
        smtp_user: cfg.smtp_user.clone(),
        smtp_pass: cfg.smtp_pass.clone(),
        smtp_tls: cfg.smtp_tls,
    };

    let timeout = Duration::from_secs(30);

    // Monitoring loop — runs indefinitely.
    loop {
        let cycle_start = Utc::now();
        info!("Starting monitoring cycle at {cycle_start}");

        for d in &domains {
            let result = checker::check_domain(d, timeout).await;

            // Write structured JSONL log entry for uptime graphing.
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

            // Decide whether to send an error email.
            match alerter::decide_alert(&result) {
                AlertDecision::ErrorEmail { error_type, detail } => {
                    info!("{d}: sending error email ({error_type})");
                    let _ = alerter::send_error_email(
                        &alert_config, d, &error_type, &detail,
                    )
                    .await;
                }
                AlertDecision::None => {}
            }

            // Baseline comparison and content-change warning.
            match baseline::compare_and_update(&result, &mut baselines) {
                BaselineAction::NewBaseline => {
                    info!("{d}: new baseline stored");
                }
                BaselineAction::Unchanged => {
                    info!("{d}: content unchanged");
                }
                BaselineAction::ContentChanged { old_size, new_size } => {
                    warn!("{d}: content changed (old={old_size}, new={new_size})");
                    let _ = alerter::send_warning_email(
                        &alert_config,
                        d,
                        "Home page content changed",
                        old_size,
                        new_size,
                    )
                    .await;
                }
                BaselineAction::Skipped => {}
            }
        }

        // Persist baselines after each cycle.
        if let Err(e) = baseline::save_baselines(&cfg.baseline_file, &baselines) {
            error!("Failed to save baselines: {e}");
        }

        let cycle_end = Utc::now();
        info!("Monitoring cycle completed at {cycle_end}");

        // Sleep until next cycle.
        tokio::time::sleep(cfg.check_interval).await;
    }
}
