//! Standalone smoke tests for the open-source monitor.
//!
//! These run the REAL `uptime` binary the way the README's "Without Docker"
//! section describes (configuration through `UPTIME_*` environment variables,
//! no flags) against a tiny SMTP server that lives inside the test, and verify
//! that the monitor actually monitors, logs and alerts. No Docker, no
//! privileged ports.
//!
//! Network: the checker resolves names with hickory's `ResolverConfig::default()`,
//! i.e. Google Public DNS (8.8.8.8 / 8.8.4.4) regardless of the host resolver,
//! so the DNS test needs outbound DNS to Google. CI runners have it. On a
//! network that blocks 8.8.8.8 the lookup retries for longer than the test's
//! budget and the test fails; set `UPTIME_TEST_OFFLINE=1` to skip it there.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};

/// Path to the compiled `uptime` binary, provided by Cargo for integration tests.
const UPTIME_BIN: &str = env!("CARGO_BIN_EXE_uptime");

// ── In-test SMTP sink ────────────────────────────────────────────────────────

/// One message as received over SMTP: envelope recipients plus the raw payload.
#[derive(Debug, Clone)]
struct Mail {
    rcpt_to: Vec<String>,
    /// `(username, password)` from AUTH PLAIN/LOGIN on the delivering connection.
    auth: Option<(String, String)>,
    /// Raw RFC 5322 message exactly as transmitted after DATA, dot-unstuffed.
    raw: String,
}

impl Mail {
    fn split(&self) -> (&str, &str) {
        if let Some(i) = self.raw.find("\r\n\r\n") {
            (&self.raw[..i], &self.raw[i + 4..])
        } else if let Some(i) = self.raw.find("\n\n") {
            (&self.raw[..i], &self.raw[i + 2..])
        } else {
            (self.raw.as_str(), "")
        }
    }

    /// Header value, unfolded and RFC 2047-decoded. lettre encodes any header
    /// with non-ASCII content, and the monitor's alert subjects contain an em
    /// dash (`ALERT: DNS Error — nxdomain.invalid`), so the raw Subject line on
    /// the wire looks like `=?utf-8?b?W1VwdGlt...?=`.
    fn header(&self, name: &str) -> Option<String> {
        let (head, _) = self.split();
        let mut unfolded: Vec<String> = Vec::new();
        for line in head.lines() {
            if line.starts_with([' ', '\t'])
                && let Some(prev) = unfolded.last_mut()
            {
                prev.push(' ');
                prev.push_str(line.trim_start());
                continue;
            }
            unfolded.push(line.to_string());
        }
        unfolded.iter().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name)
                .then(|| decode_rfc2047(v.trim()))
        })
    }

    fn subject(&self) -> String {
        self.header("Subject").unwrap_or_default()
    }

    /// Body decoded according to Content-Transfer-Encoding (lettre picks
    /// quoted-printable or base64 for bodies containing non-ASCII characters).
    fn body_text(&self) -> String {
        let (_, body) = self.split();
        let cte = self
            .header("Content-Transfer-Encoding")
            .unwrap_or_default()
            .to_ascii_lowercase();
        match cte.as_str() {
            "base64" => {
                let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
                String::from_utf8_lossy(&BASE64.decode(compact).unwrap_or_default()).into_owned()
            }
            "quoted-printable" => decode_quoted_printable(body),
            _ => body.to_string(),
        }
    }
}

/// Decode RFC 2047 encoded-words (`=?charset?B|Q?text?=`). Whitespace between
/// two adjacent encoded-words is dropped, as the RFC requires. Charset is
/// assumed to be UTF-8 (lettre always uses utf-8).
fn decode_rfc2047(input: &str) -> String {
    let mut out = String::new();
    let mut rest = input;
    let mut last_was_encoded = false;
    while let Some(start) = rest.find("=?") {
        let before = &rest[..start];
        let after = &rest[start + 2..];
        match parse_encoded_word(after) {
            Some((decoded, consumed)) => {
                if !(last_was_encoded && before.trim().is_empty()) {
                    out.push_str(before);
                }
                out.push_str(&decoded);
                last_was_encoded = true;
                rest = &after[consumed..];
            }
            None => {
                out.push_str(&rest[..start + 2]);
                last_was_encoded = false;
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Parse `charset?enc?text?=` (the part after `=?`). Returns the decoded text
/// and the number of bytes consumed.
fn parse_encoded_word(s: &str) -> Option<(String, usize)> {
    let q1 = s.find('?')?;
    let s2 = &s[q1 + 1..];
    let q2 = s2.find('?')?;
    let enc = &s2[..q2];
    let s3 = &s2[q2 + 1..];
    let end = s3.find("?=")?;
    let text = &s3[..end];
    let bytes = match enc.to_ascii_uppercase().as_str() {
        "B" => BASE64.decode(text).ok()?,
        "Q" => decode_q_encoding(text),
        _ => return None,
    };
    let consumed = q1 + 1 + q2 + 1 + end + 2;
    Some((String::from_utf8_lossy(&bytes).into_owned(), consumed))
}

fn decode_q_encoding(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'_' => out.push(b' '),
            b'=' if i + 2 < bytes.len() => {
                if let Some(b) = text
                    .get(i + 1..i + 3)
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    out.push(b);
                    i += 3;
                    continue;
                }
                out.push(b'=');
            }
            b => out.push(b),
        }
        i += 1;
    }
    out
}

fn decode_quoted_printable(input: &str) -> String {
    let mut out: Vec<u8> = Vec::new();
    for line in input.lines() {
        let (content, soft_break) = match line.strip_suffix('=') {
            Some(c) => (c, true),
            None => (line, false),
        };
        let bytes = content.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'='
                && i + 2 < bytes.len()
                && let Some(b) = content
                    .get(i + 1..i + 3)
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(b);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        }
        if !soft_break {
            out.push(b'\n');
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A minimal ESMTP server on 127.0.0.1:<ephemeral> that advertises and accepts
/// AUTH (the monitor always sends credentials) and stores every message.
#[derive(Clone)]
struct SmtpSink {
    port: u16,
    mails: Arc<Mutex<Vec<Mail>>>,
}

impl SmtpSink {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind SMTP sink on 127.0.0.1:0");
        let port = listener.local_addr().unwrap().port();
        let mails: Arc<Mutex<Vec<Mail>>> = Arc::default();
        let store = mails.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                let store = store.clone();
                tokio::spawn(async move {
                    let _ = serve_smtp_session(sock, store).await;
                });
            }
        });
        Self { port, mails }
    }

    fn mails(&self) -> Vec<Mail> {
        self.mails.lock().unwrap().clone()
    }

    fn subjects(&self) -> Vec<String> {
        self.mails().iter().map(Mail::subject).collect()
    }

    async fn wait_for(&self, timeout: Duration, pred: impl Fn(&Mail) -> bool) -> Option<Mail> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(m) = self.mails().into_iter().find(|m| pred(m)) {
                return Some(m);
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// `<addr>` or `addr`, ignoring any ESMTP parameters after it.
fn angle_addr(s: &str) -> String {
    s.split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(['<', '>'])
        .to_string()
}

fn b64_lossy(s: &str) -> String {
    String::from_utf8_lossy(&BASE64.decode(s.trim()).unwrap_or_default()).into_owned()
}

/// AUTH PLAIN payload is `authzid \0 authcid \0 password`.
fn decode_auth_plain(b64: &str) -> Option<(String, String)> {
    let bytes = BASE64.decode(b64.trim()).ok()?;
    let parts: Vec<&[u8]> = bytes.split(|b| *b == 0).collect();
    if parts.len() != 3 {
        return None;
    }
    Some((
        String::from_utf8_lossy(parts[1]).into_owned(),
        String::from_utf8_lossy(parts[2]).into_owned(),
    ))
}

async fn read_line(rd: &mut AsyncBufReader<OwnedReadHalf>) -> std::io::Result<String> {
    let mut s = String::new();
    rd.read_line(&mut s).await?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

async fn serve_smtp_session(sock: TcpStream, store: Arc<Mutex<Vec<Mail>>>) -> std::io::Result<()> {
    let (rd, mut wr) = sock.into_split();
    let mut rd = AsyncBufReader::new(rd);
    wr.write_all(b"220 localhost ESMTP test-sink\r\n").await?;

    let mut auth: Option<(String, String)> = None;
    let mut rcpts: Vec<String> = Vec::new();
    let mut line = String::new();

    loop {
        line.clear();
        if rd.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        let cmd = line.trim_end_matches(['\r', '\n']).to_string();
        let upper = cmd.to_ascii_uppercase();

        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            wr.write_all(b"250-localhost\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n")
                .await?;
        } else if let Some(rest) = strip_prefix_ci(&cmd, "AUTH PLAIN") {
            // Initial response may be on the same line or sent after a 334.
            let payload = if rest.trim().is_empty() {
                wr.write_all(b"334 \r\n").await?;
                read_line(&mut rd).await?
            } else {
                rest.trim().to_string()
            };
            auth = decode_auth_plain(&payload);
            wr.write_all(b"235 2.7.0 Authentication successful\r\n")
                .await?;
        } else if upper.starts_with("AUTH LOGIN") {
            wr.write_all(b"334 VXNlcm5hbWU6\r\n").await?; // "Username:"
            let user = read_line(&mut rd).await?;
            wr.write_all(b"334 UGFzc3dvcmQ6\r\n").await?; // "Password:"
            let pass = read_line(&mut rd).await?;
            auth = Some((b64_lossy(&user), b64_lossy(&pass)));
            wr.write_all(b"235 2.7.0 Authentication successful\r\n")
                .await?;
        } else if strip_prefix_ci(&cmd, "MAIL FROM:").is_some() {
            wr.write_all(b"250 OK\r\n").await?;
        } else if let Some(rest) = strip_prefix_ci(&cmd, "RCPT TO:") {
            rcpts.push(angle_addr(rest));
            wr.write_all(b"250 OK\r\n").await?;
        } else if upper == "DATA" {
            wr.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                .await?;
            let mut raw = String::new();
            loop {
                line.clear();
                if rd.read_line(&mut line).await? == 0 {
                    return Ok(());
                }
                if line == ".\r\n" || line == ".\n" {
                    break;
                }
                // Dot-unstuffing: a leading '.' was doubled by the client.
                raw.push_str(line.strip_prefix('.').unwrap_or(&line));
            }
            store.lock().unwrap().push(Mail {
                rcpt_to: std::mem::take(&mut rcpts),
                auth: auth.clone(),
                raw,
            });
            wr.write_all(b"250 OK queued\r\n").await?;
        } else if upper == "QUIT" {
            wr.write_all(b"221 Bye\r\n").await?;
            return Ok(());
        } else if upper == "RSET" || upper == "NOOP" {
            rcpts.clear();
            wr.write_all(b"250 OK\r\n").await?;
        } else {
            wr.write_all(b"502 Command not implemented\r\n").await?;
        }
    }
}

// ── Running the real binary ──────────────────────────────────────────────────

/// The monitor process plus a thread that drains its stderr (the monitor logs
/// every check; without a reader the pipe would fill and block it).
struct Monitor {
    child: Child,
    stderr: Arc<Mutex<String>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Monitor {
    /// Spawn `uptime` with ONLY the given `UPTIME_*` configuration (anything
    /// inherited from the parent that could change behaviour is removed).
    fn spawn(env: &[(&str, String)]) -> Self {
        let mut cmd = Command::new(UPTIME_BIN);
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().into_owned();
            if k.starts_with("UPTIME_") || k.starts_with("GHOST_") || k == "RUST_LOG" {
                cmd.env_remove(&k);
            }
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {UPTIME_BIN}: {e}"));
        let pipe = child.stderr.take().expect("stderr is piped");
        let stderr: Arc<Mutex<String>> = Arc::default();
        let sink = stderr.clone();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                let mut buf = sink.lock().unwrap();
                buf.push_str(&line);
                buf.push('\n');
            }
        });
        Self {
            child,
            stderr,
            reader: Some(reader),
        }
    }

    fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    fn finish(&mut self) -> String {
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
        self.stderr()
    }

    /// Kill the monitor (SIGINT is not portable from Rust tests on Windows, so
    /// `kill()` it is) and return the captured stderr.
    fn stop(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.finish()
    }

    /// Wait for the process to exit by itself, killing it if it is still alive
    /// after `timeout`. Returns the exit status and captured stderr.
    fn wait_exit(mut self, timeout: Duration) -> (ExitStatus, String) {
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(s) = self.child.try_wait().expect("try_wait") {
                break s;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                break self.child.wait().expect("wait after kill");
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        (status, self.finish())
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        // Never leave a monitor running if a test panics half-way.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn p(dir: &Path, name: &str) -> String {
    dir.join(name).to_string_lossy().into_owned()
}

/// The environment-variable configuration the README documents, pointed at a
/// temp directory and the in-test SMTP sink. No TLS: the sink is plaintext,
/// which exercises lettre's `builder_dangerous` path in the monitor.
fn base_env(dir: &Path, smtp_port: u16) -> Vec<(&'static str, String)> {
    vec![
        ("UPTIME_DOMAINS", p(dir, "domains.csv")),
        ("UPTIME_BASELINE", p(dir, "baselines.json")),
        ("UPTIME_LOG_FILE", p(dir, "uptime.jsonl")),
        ("UPTIME_ERROR_LOG", p(dir, "errors.jsonl")),
        ("UPTIME_SENDER", "monitor@example.com".to_string()),
        ("UPTIME_RECIPIENT", "ops@example.com".to_string()),
        ("UPTIME_SMTP_HOST", "127.0.0.1".to_string()),
        ("UPTIME_SMTP_PORT", smtp_port.to_string()),
        ("UPTIME_SMTP_USER", "u".to_string()),
        ("UPTIME_SMTP_PASS", "p".to_string()),
        ("UPTIME_SMTP_TLS", "false".to_string()),
        ("UPTIME_INTERVAL", "30m".to_string()),
    ]
}

fn log_lines_for(path: &Path, domain: &str) -> Vec<serde_json::Value> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["domain"] == domain)
        .collect()
}

async fn wait_for_log_line(
    path: &Path,
    domain: &str,
    timeout: Duration,
) -> Option<serde_json::Value> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = log_lines_for(path, domain).into_iter().next() {
            return Some(v);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn tmp_leftovers(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .is_some_and(|n| n.to_string_lossy().contains(".tmp"))
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// The headline scenario: a stranger runs the binary with env-var config and a
/// CSV containing one unresolvable domain. The monitor must log the DNS
/// failure as JSONL, e-mail the global recipient on startup and the per-domain
/// recipient about the failure, persist its baseline file and leave no temp
/// files behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn monitors_logs_and_alerts_on_dns_failure() {
    if std::env::var_os("UPTIME_TEST_OFFLINE").is_some() {
        eprintln!("skipping: UPTIME_TEST_OFFLINE is set (needs outbound DNS to 8.8.8.8)");
        return;
    }
    let sink = SmtpSink::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("domains.csv"),
        "# domain,recipient,interval,status,date,stripe,key,created_at\n\
         nxdomain.invalid,alerts@example.com,30m\n\
         \n",
    )
    .unwrap();
    let log_path = dir.path().join("uptime.jsonl");
    let baseline_path = dir.path().join("baselines.json");

    let monitor = Monitor::spawn(&base_env(dir.path(), sink.port));

    // 1. Structured uptime log entry for the failing domain.
    let line = wait_for_log_line(&log_path, "nxdomain.invalid", Duration::from_secs(90))
        .await
        .unwrap_or_else(|| {
            panic!(
                "no uptime.jsonl line for nxdomain.invalid within 90s\n--- monitor stderr ---\n{}",
                monitor.stderr()
            )
        });
    assert_eq!(line["domain"], "nxdomain.invalid");
    assert_eq!(line["up"], false, "line: {line}");
    assert_eq!(line["dns_ok"], false, "line: {line}");
    let err = line["error"]
        .as_str()
        .unwrap_or_else(|| panic!("error should be a string: {line}"));
    assert!(err.contains("DNS"), "error should mention DNS: {err}");
    assert_eq!(line["special_handling"], 0, "line: {line}");
    let ts = line["timestamp"]
        .as_str()
        .unwrap_or_else(|| panic!("timestamp should be a string: {line}"));
    chrono::DateTime::parse_from_rfc3339(ts)
        .unwrap_or_else(|e| panic!("timestamp {ts:?} is not RFC 3339: {e}"));

    // 2. Startup e-mail to the global recipient, naming the monitored domain.
    let startup = sink
        .wait_for(Duration::from_secs(30), |m| {
            m.subject().contains("Monitoring started")
        })
        .await
        .unwrap_or_else(|| {
            panic!(
                "no 'Monitoring started' e-mail; got subjects {:?}\n--- monitor stderr ---\n{}",
                sink.subjects(),
                monitor.stderr()
            )
        });
    assert_eq!(startup.rcpt_to, vec!["ops@example.com".to_string()]);
    let body = startup.body_text();
    assert!(body.contains("nxdomain.invalid"), "startup body:\n{body}");
    assert_eq!(
        startup.auth,
        Some(("u".to_string(), "p".to_string())),
        "monitor should authenticate with the configured SMTP credentials"
    );

    // 3. DNS error e-mail to the per-domain recipient.
    let alert = sink
        .wait_for(Duration::from_secs(30), |m| {
            m.subject().contains("DNS Error")
        })
        .await
        .unwrap_or_else(|| {
            panic!(
                "no 'DNS Error' e-mail; got subjects {:?}\n--- monitor stderr ---\n{}",
                sink.subjects(),
                monitor.stderr()
            )
        });
    let subject = alert.subject();
    assert!(subject.contains("nxdomain.invalid"), "subject: {subject}");
    assert_eq!(alert.rcpt_to, vec!["alerts@example.com".to_string()]);
    assert!(alert.body_text().contains("nxdomain.invalid"));

    // 4. Baselines are persisted after every cycle (atomically via a temp file).
    assert!(
        wait_until(Duration::from_secs(30), || baseline_path.exists()).await,
        "baselines.json was not written after the first cycle\n--- stderr ---\n{}",
        monitor.stderr()
    );

    let stderr = monitor.stop();
    assert!(stderr.contains("DNS check FAILED"), "stderr:\n{stderr}");

    let leftovers = tmp_leftovers(dir.path());
    assert!(
        leftovers.is_empty(),
        "temp files left behind: {leftovers:?}"
    );
    let baselines: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&baseline_path).unwrap())
            .expect("baselines.json is valid JSON");
    assert!(
        baselines.is_object(),
        "baselines.json should be a JSON object: {baselines}"
    );
}

/// A missing domains file is a hard startup error: non-zero exit, and the
/// message names the file so the user knows what to fix.
#[test]
fn exits_non_zero_when_domains_file_is_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut env = base_env(dir.path(), 1); // nothing should ever connect
    env[0] = ("UPTIME_DOMAINS", p(dir.path(), "does-not-exist.csv"));

    let (status, stderr) = Monitor::spawn(&env).wait_exit(Duration::from_secs(30));

    assert!(!status.success(), "expected a failure exit, got {status:?}");
    assert_eq!(status.code(), Some(1), "stderr:\n{stderr}");
    assert!(
        stderr.contains("does-not-exist.csv"),
        "stderr should name the missing file:\n{stderr}"
    );
}

/// A domains file with nothing usable in it is NOT fatal: the monitor warns,
/// still sends its startup e-mail (for zero domains) and keeps running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn warns_but_runs_when_no_domain_is_valid() {
    let sink = SmtpSink::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("domains.csv"),
        "# only junk below\n\
         not a domain\n\
         localhost\n\
         -bad-.example\n",
    )
    .unwrap();

    let monitor = Monitor::spawn(&base_env(dir.path(), sink.port));

    let startup = sink
        .wait_for(Duration::from_secs(30), |m| {
            m.subject().contains("Monitoring started")
        })
        .await
        .unwrap_or_else(|| {
            panic!(
                "no 'Monitoring started' e-mail; got subjects {:?}\n--- monitor stderr ---\n{}",
                sink.subjects(),
                monitor.stderr()
            )
        });
    assert_eq!(startup.rcpt_to, vec!["ops@example.com".to_string()]);
    assert!(
        startup.body_text().contains("Monitoring 0 domains"),
        "startup body:\n{}",
        startup.body_text()
    );

    assert!(
        wait_until(Duration::from_secs(10), || monitor
            .stderr()
            .contains("No valid domains"))
        .await,
        "expected a 'No valid domains' warning\n--- stderr ---\n{}",
        monitor.stderr()
    );

    let stderr = monitor.stop();
    assert!(
        stderr.contains("Invalid domain at line"),
        "stderr:\n{stderr}"
    );
    assert!(
        !std::fs::read_to_string(dir.path().join("uptime.jsonl"))
            .map(|s| s.lines().any(|l| !l.trim().is_empty()))
            .unwrap_or(false),
        "no checks should have been logged for zero domains"
    );
}
