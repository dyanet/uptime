//! Integration tests: exercise the full stack locally against real domains.
//!
//! These tests hit the network (DNS, HTTPS, TLS) so they require internet access.
//! They do NOT require SMTP credentials — email sending is not tested here.

use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;

// ── 1. Domain loading ────────────────────────────────────────────────────────

#[test]
fn load_domains_from_real_file() {
    let path = Path::new("data/domains.txt");
    if !path.exists() {
        eprintln!("Skipping: data/domains.txt not found");
        return;
    }
    // We can't call domain::load_domains directly (it's a private module),
    // but we can verify the file parses correctly via the same logic.
    let content = std::fs::read_to_string(path).unwrap();
    let domains: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert!(!domains.is_empty(), "domains.txt should have entries");
    for d in &domains {
        assert!(d.contains('.'), "domain should have a dot: {d}");
    }
    println!("Loaded {} domains: {:?}", domains.len(), domains);
}

// ── 2. SSL expiry check against real domains ─────────────────────────────────

#[test]
fn ssl_expiry_check_real_domains() {
    // Test against well-known domains that should always have valid certs.
    for domain in &["google.com", "github.com"] {
        let result = uptime::ssl_expiry::check_ssl_expiry(domain);
        assert!(
            result.error.is_none(),
            "{domain}: SSL check failed: {:?}",
            result.error
        );
        assert!(
            result.days_remaining.is_some(),
            "{domain}: no days_remaining"
        );
        let days = result.days_remaining.unwrap();
        assert!(days > 0, "{domain}: cert should not be expired, got {days} days");
        assert!(
            result.expiry_date.is_some(),
            "{domain}: no expiry_date"
        );
        println!(
            "{domain}: expires in {days} days ({})",
            result.expiry_date.as_deref().unwrap_or("?")
        );
    }
}

#[test]
fn ssl_expiry_check_bad_domain() {
    let result = uptime::ssl_expiry::check_ssl_expiry("this-domain-does-not-exist-xyz.com");
    // Should fail gracefully with an error, not panic.
    assert!(result.error.is_some(), "expected error for nonexistent domain");
    println!("Bad domain error: {}", result.error.unwrap());
}

// ── 3. SSL alert threshold logic end-to-end ──────────────────────────────────

#[test]
fn ssl_alert_threshold_full_lifecycle() {
    use uptime::ssl_expiry::{should_alert, SslAlertState};

    let mut state = SslAlertState::new();
    let domain = "example.com";

    // Day 30: no alert (above all thresholds).
    assert_eq!(should_alert(30, state.get(domain).copied()), None);

    // Day 15: first alert at threshold 15.
    let t = should_alert(15, state.get(domain).copied());
    assert_eq!(t, Some(15));
    state.insert(domain.to_string(), 15);

    // Day 14: no alert (still in 15-day band).
    assert_eq!(should_alert(14, state.get(domain).copied()), None);

    // Day 8: no alert (still in 15-day band, haven't crossed 7).
    assert_eq!(should_alert(8, state.get(domain).copied()), None);

    // Day 7: alert at threshold 7.
    let t = should_alert(7, state.get(domain).copied());
    assert_eq!(t, Some(7));
    state.insert(domain.to_string(), 7);

    // Day 3: no alert (between 7 and 1).
    assert_eq!(should_alert(3, state.get(domain).copied()), None);

    // Day 1: alert at threshold 1.
    let t = should_alert(1, state.get(domain).copied());
    assert_eq!(t, Some(1));
    state.insert(domain.to_string(), 1);

    // Day 0: alert at threshold 0.
    let t = should_alert(0, state.get(domain).copied());
    assert_eq!(t, Some(0));
    state.insert(domain.to_string(), 0);

    // Day -1: no alert (already at 0).
    assert_eq!(should_alert(-1, state.get(domain).copied()), None);

    println!("SSL alert lifecycle: all thresholds fired correctly");
}

// ── 4. Email formatting ──────────────────────────────────────────────────────

#[test]
fn ssl_email_formatting_all_urgency_levels() {
    use uptime::ssl_expiry::{format_subject, format_body};

    // 15 days
    let subj = format_subject("example.com", 15);
    assert!(subj.contains("15 days"));
    let body = format_body("example.com", 15, "2026-04-21");
    assert!(body.contains("recommend renewing early"));

    // 7 days
    let subj = format_subject("example.com", 7);
    assert!(subj.contains("7 days"));
    let body = format_body("example.com", 7, "2026-04-13");
    assert!(body.contains("final reminder"));

    // 1 day
    let subj = format_subject("example.com", 1);
    assert!(subj.contains("TOMORROW"));
    let body = format_body("example.com", 1, "2026-04-07");
    assert!(body.contains("TOMORROW"));
    assert!(body.contains("today"));

    // 0 days (expired)
    let subj = format_subject("example.com", 0);
    assert!(subj.contains("EXPIRED"));
    let body = format_body("example.com", 0, "2026-04-06");
    assert!(body.contains("EXPIRED"));
    assert!(body.contains("immediately"));

    // Negative (already expired)
    let subj = format_subject("example.com", -5);
    assert!(subj.contains("EXPIRED"));

    println!("All email urgency levels formatted correctly");
}

// ── 5. Store adapter: file backend round-trip ────────────────────────────────

#[test]
fn file_store_full_round_trip() {
    use uptime_store::file_store::FileStore;
    use uptime_store::traits::*;
    use uptime_store::types::*;

    let dir = TempDir::new().unwrap();
    let domain_path = dir.path().join("domains.csv");
    let uptime_path = dir.path().join("uptime.jsonl");
    let error_path = dir.path().join("errors.jsonl");
    let baseline_path = dir.path().join("baselines.json");

    // Seed a CSV file.
    std::fs::write(
        &domain_path,
        "# header\nexample.com,ops@example.com,1h,Free,2025-07-10,,key123456789012345678901234567890,2025-07-10\n",
    ).unwrap();

    let store = FileStore::new(&domain_path, &uptime_path, &error_path, &baseline_path);

    // Domain loading.
    let records = store.load_records().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].domain, "example.com");
    assert_eq!(records[0].status, Status::Free);

    // Locked mutation.
    store.with_locked_records(Box::new(|records| {
        records[0].status = Status::Paid;
        records[0].stripe = "sub_123".to_string();
        Ok(())
    })).unwrap();
    let records = store.load_records().unwrap();
    assert_eq!(records[0].status, Status::Paid);
    assert_eq!(records[0].stripe, "sub_123");

    // Uptime write + read.
    let entry = UptimeEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        domain: "example.com".to_string(),
        up: true,
        dns_ok: true,
        http_status: Some(200),
        ssl_error: None,
        response_size: Some(1024),
        error: None,
    };
    store.append_uptime(&entry).unwrap();
    let entries = store.read_uptime("example.com", 30).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].up);

    // Baseline save + load.
    let mut baselines = BaselineMap::new();
    baselines.insert("example.com".to_string(), Baseline { hash: "abc".to_string(), size: 100 });
    store.save_baselines(&baselines).unwrap();
    let loaded = store.load_baselines().unwrap();
    assert_eq!(loaded, baselines);

    // Error logging (best-effort, just verify no panic).
    store.log_error("test", "integration", "test error");
    let error_content = std::fs::read_to_string(&error_path).unwrap();
    assert!(error_content.contains("test error"));

    println!("File store round-trip: all operations passed");
}

// ── 6. Store adapter: SQL backend round-trip ─────────────────────────────────

#[cfg(feature = "sql_store")]
#[test]
fn sql_store_full_round_trip() {
    use uptime_store::sql_store::SqlStore;
    use uptime_store::traits::*;
    use uptime_store::types::*;

    let store = SqlStore::open_in_memory().unwrap();

    // Insert a domain via locked mutation.
    store.with_locked_records(Box::new(|records| {
        records.push(DomainRecord {
            domain: "sql-test.com".to_string(),
            recipient: "ops@sql-test.com".to_string(),
            interval: "1h".to_string(),
            status: Status::Free,
            date: "2025-07-10".to_string(),
            stripe: String::new(),
            key: "sqlkey12345678901234567890123456".to_string(),
            created_at: "2025-07-10".to_string(),
        });
        Ok(())
    })).unwrap();

    let records = store.load_records().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].domain, "sql-test.com");

    // Uptime.
    let entry = UptimeEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        domain: "sql-test.com".to_string(),
        up: false,
        dns_ok: false,
        http_status: None,
        ssl_error: None,
        response_size: None,
        error: Some("DNS failed".to_string()),
    };
    store.append_uptime(&entry).unwrap();
    let entries = store.read_uptime("sql-test.com", 30).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(!entries[0].up);

    // Baselines.
    let mut baselines = BaselineMap::new();
    baselines.insert("sql-test.com".to_string(), Baseline { hash: "def".to_string(), size: 200 });
    store.save_baselines(&baselines).unwrap();
    let loaded = store.load_baselines().unwrap();
    assert_eq!(loaded, baselines);

    // Error logging.
    store.log_error("test", "sql", "sql test error");

    println!("SQL store round-trip: all operations passed");
}

// ── 7. Uptime checker against real domain ────────────────────────────────────

#[tokio::test]
async fn check_real_domain_health() {
    let result = uptime::checker::check_domain("google.com", Duration::from_secs(15)).await;
    assert!(result.dns_ok, "google.com DNS should resolve");
    assert!(result.ssl_error.is_none(), "google.com should have valid SSL");
    assert!(result.http_status.is_some(), "google.com should return HTTP status");
    let status = result.http_status.unwrap();
    assert!(
        (200..400).contains(&status),
        "google.com should return 2xx/3xx, got {status}"
    );
    assert!(result.error.is_none(), "google.com should have no error");
    println!("google.com: DNS ok, SSL ok, HTTP {status}");
}

#[tokio::test]
async fn check_nonexistent_domain() {
    let result = uptime::checker::check_domain(
        "this-domain-absolutely-does-not-exist-12345.com",
        Duration::from_secs(10),
    ).await;
    assert!(!result.dns_ok, "nonexistent domain should fail DNS");
    assert!(result.error.is_some(), "should have an error message");
    println!("Nonexistent domain: error = {}", result.error.unwrap());
}

// ── 8. Baseline compare-and-update logic ─────────────────────────────────────

#[test]
fn baseline_full_lifecycle() {
    use uptime::baseline::*;
    use uptime::types::CheckResult;

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("baselines.json");

    // Load from nonexistent file → empty.
    let mut baselines = load_baselines(&path).unwrap();
    assert!(baselines.is_empty());

    // First check → NewBaseline.
    let r1 = CheckResult {
        domain: "test.com".to_string(),
        dns_ok: true,
        ssl_error: None,
        http_status: Some(200),
        body_hash: Some("hash1".to_string()),
        body_size: Some(1000),
        error: None,
    };
    assert_eq!(compare_and_update(&r1, &mut baselines), BaselineAction::NewBaseline);

    // Same hash → Unchanged.
    assert_eq!(compare_and_update(&r1, &mut baselines), BaselineAction::Unchanged);

    // Different hash → ContentChanged.
    let r2 = CheckResult {
        body_hash: Some("hash2".to_string()),
        body_size: Some(2000),
        ..CheckResult {
            domain: "test.com".to_string(),
            dns_ok: true,
            ssl_error: None,
            http_status: Some(200),
            body_hash: None,
            body_size: None,
            error: None,
        }
    };
    match compare_and_update(&r2, &mut baselines) {
        BaselineAction::ContentChanged { old_size, new_size } => {
            assert_eq!(old_size, 1000);
            assert_eq!(new_size, 2000);
        }
        other => panic!("expected ContentChanged, got {other:?}"),
    }

    // Non-2xx → Skipped.
    let r3 = CheckResult {
        domain: "test.com".to_string(),
        dns_ok: true,
        ssl_error: None,
        http_status: Some(500),
        body_hash: Some("hash3".to_string()),
        body_size: Some(500),
        error: None,
    };
    assert_eq!(compare_and_update(&r3, &mut baselines), BaselineAction::Skipped);

    // Save and reload.
    save_baselines(&path, &baselines).unwrap();
    let reloaded = load_baselines(&path).unwrap();
    assert_eq!(reloaded.get("test.com").unwrap().hash, "hash2");

    println!("Baseline lifecycle: all states verified");
}

// ── 9. Portal CSV store operations ───────────────────────────────────────────

#[test]
fn portal_csv_store_operations() {
    use uptime_store::file_store::FileStore;
    use uptime_store::traits::*;
    use uptime_store::types::*;

    let dir = TempDir::new().unwrap();
    let csv = dir.path().join("domains.csv");
    let store = FileStore::new(&csv, "", "", "");

    // Start empty — create via locked mutation.
    std::fs::write(&csv, "# header\n").unwrap();

    // Add three domains.
    store.with_locked_records(Box::new(|records| {
        records.push(DomainRecord {
            domain: "a.com".to_string(),
            recipient: "a@a.com".to_string(),
            interval: "1h".to_string(),
            status: Status::Verifying,
            date: "2025-07-10".to_string(),
            stripe: String::new(),
            key: "key_a_12345678901234567890123456".to_string(),
            created_at: "2025-07-10".to_string(),
        });
        records.push(DomainRecord {
            domain: "b.com".to_string(),
            recipient: "b@b.com".to_string(),
            interval: String::new(),
            status: Status::Free,
            date: "2025-06-01".to_string(),
            stripe: String::new(),
            key: "key_b_12345678901234567890123456".to_string(),
            created_at: "2025-06-01".to_string(),
        });
        records.push(DomainRecord {
            domain: "c.com".to_string(),
            recipient: "c@c.com".to_string(),
            interval: "3h".to_string(),
            status: Status::Paid,
            date: "2025-05-01".to_string(),
            stripe: "sub_123".to_string(),
            key: "key_c_12345678901234567890123456".to_string(),
            created_at: "2025-05-01".to_string(),
        });
        Ok(())
    })).unwrap();

    let records = store.load_records().unwrap();
    assert_eq!(records.len(), 3);

    // Verify → Free transition.
    store.with_locked_records(Box::new(|records| {
        if let Some(r) = records.iter_mut().find(|r| r.domain == "a.com") {
            r.status = Status::Free;
            r.date = "2025-07-11".to_string();
        }
        Ok(())
    })).unwrap();

    let records = store.load_records().unwrap();
    assert_eq!(records.iter().find(|r| r.domain == "a.com").unwrap().status, Status::Free);

    // Delete a domain.
    store.with_locked_records(Box::new(|records| {
        records.retain(|r| r.domain != "b.com");
        Ok(())
    })).unwrap();

    let records = store.load_records().unwrap();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|r| r.domain != "b.com"));

    println!("Portal CSV store: add/mutate/delete all verified");
}
