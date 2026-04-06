# Uptime Monitor

[![CI](https://github.com/dyanet/uptime/actions/workflows/ci.yml/badge.svg)](https://github.com/dyanet/uptime/actions/workflows/ci.yml)

A single-binary domain monitor that checks DNS, SSL, HTTP, and content changes on a schedule, sends alert emails via SMTP, and writes a structured uptime log.

## Quick Start

1. Set up your `data/` directory:

```bash
mkdir data
cp example.env data/env
vi data/env                    # fill in your SMTP credentials
```

2. Add your domains (CSV format, 8 columns — extra columns from the portal are ignored):

```bash
cat > data/domains.csv <<EOF
# domain,recipient,interval,status,date,stripe,key,created_at
example.com,ops@example.com,1h
shop.example.com,ops@example.com,30m
EOF
```

3. Run:

```bash
docker run --rm -v ./data:/data ghcr.io/dyanet/uptime:latest
```

Config, domains, baselines, and uptime logs all live in `./data/`. The container reads `data/env` on startup automatically.

### Without Docker

```bash
cargo build --release
./target/release/uptime \
  --domains domains.csv \
  --baseline baselines.json \
  --log-file uptime.jsonl \
  --sender monitor@example.com \
  --recipient ops@example.com \
  --smtp-host email-smtp.us-east-1.amazonaws.com \
  --smtp-user your-smtp-user \
  --smtp-pass your-smtp-password
```

Or set the `UPTIME_*` env vars and run `./target/release/uptime` with no flags.

## Configuration

Every option works as a CLI flag or an environment variable.

| CLI Flag | Env Var | Default | Description |
|----------|---------|---------|-------------|
| `--domains` | `UPTIME_DOMAINS` | *(required)* | Path to domain list file (CSV or plain text) |
| `--interval` | `UPTIME_INTERVAL` | `1h` | Default check interval: `30m`, `1h`, `3h`, `24h` |
| `--baseline` | `UPTIME_BASELINE` | `/data/baselines.json` | Baseline persistence file |
| `--sender` | `UPTIME_SENDER` | *(required)* | From email address |
| `--recipient` | `UPTIME_RECIPIENT` | *(required)* | Default To email address |
| `--smtp-host` | `UPTIME_SMTP_HOST` | *(required)* | SMTP server hostname |
| `--smtp-port` | `UPTIME_SMTP_PORT` | `587` | SMTP server port |
| `--smtp-user` | `UPTIME_SMTP_USER` | *(required)* | SMTP username |
| `--smtp-pass` | `UPTIME_SMTP_PASS` | *(required)* | SMTP password |
| `--smtp-tls` | `UPTIME_SMTP_TLS` | `true` | Enable TLS (port 465 = implicit, port 587 = STARTTLS) |
| `--log-file` | `UPTIME_LOG_FILE` | `/data/uptime.jsonl` | JSONL uptime log path |
| `--error-log` | `UPTIME_ERROR_LOG` | `/data/errors.jsonl` | JSONL error log path |

## Domain File Format

CSV, one domain per line. Comments (`#`) and blank lines are ignored. The monitor reads the first 4 columns and ignores the rest (columns 5–8 are managed by the portal).

```
# domain,recipient,interval,status,date,stripe,key,created_at

# Production — alerts go to ops team, check every 30 minutes
example.com,ops@example.com,30m,Paid,2025-07-10,sub_123,abc123,2025-01-01

# Staging — use global defaults
staging.example.com

# Marketing site — different recipient, check every 3 hours
blog.example.com,marketing@example.com,3h
```

The monitor skips rows with status `Disabled` or `Lapsed`. All other statuses (`Free`, `Paid`, `Verifying`, `Internal`) are monitored. Multiple rows for the same domain (different watchers) are handled correctly — each gets independent checks.

## Hot Reload

The monitor re-reads the domain file every 30 minutes. If the file has changed, it rebuilds its interval groups and starts/stops monitoring domains accordingly. No container restart needed.

## Uptime Log

Each check appends a JSON line to the log file:

```json
{"timestamp":"2026-03-31T14:22:01Z","domain":"example.com","up":true,"dns_ok":true,"http_status":200,"ssl_error":null,"response_size":45230,"error":null}
```

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | RFC 3339 UTC |
| `domain` | string | Domain checked |
| `up` | bool | `true` if DNS ok, no SSL/connection error, HTTP 2xx/3xx |
| `dns_ok` | bool | DNS resolution succeeded |
| `http_status` | int \| null | HTTP status code |
| `ssl_error` | string \| null | SSL error detail |
| `response_size` | int \| null | Body size in bytes (2xx only) |
| `error` | string \| null | Connection/timeout error |

Quick uptime percentage with `jq`:

```bash
jq -s 'group_by(.domain) | map({domain: .[0].domain, pct: (map(select(.up)) | length) / length * 100})' uptime.jsonl
```

## Alerts

- Startup/shutdown emails — sent to the global recipient when the monitor starts and stops
- Error emails — DNS failure, SSL error, HTTP 4xx/5xx, timeout/refused (sent to per-domain recipient if configured)
- Warning emails — home page content changed (sent to per-domain recipient if configured)

Send failures are logged but never stop monitoring.

## Docker

```bash
docker build -t uptime .
docker run --rm -v ./data:/data uptime
```

The container sources `/data/env` on startup if it exists. Multi-stage build: compiles a release binary in the Rust image, copies it into a slim Debian runtime.
