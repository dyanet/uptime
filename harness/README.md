# Docker harness

An end-to-end check that somebody who downloads this repository (or pulls
`ghcr.io/dyanet/uptime:latest`) can run the monitor by following the README
alone, and that it really monitors, logs and alerts.

The harness runs the documented Quick Start without modification: a `data/`
directory containing `env` and `domains.csv` is mounted at `/data` and the
image's entrypoint sources `/data/env`. Only the outside world is replaced by
local stand-ins:

| Container | Image | Role |
|-----------|-------|------|
| `monitor` | the repo `Dockerfile` (or `$UPTIME_IMAGE`) | the thing under test |
| `mailpit` | `axllent/mailpit` | SMTP server; every alert lands here (API + web UI on http://127.0.0.1:8025) |
| `target`  | `nginx:alpine` | the "monitored sites": 200, 503 and a page the script rewrites |

## What it proves

`run.sh` prints a PASS/FAIL table for each of these:

1. **Startup**: the container reads `/data/env` and `/data/domains.csv`, runs its
   first check cycle immediately and appends one JSON line per domain to
   `data/uptime.jsonl`.
2. **Log contents**: `up.*` has `up=true`, `http_status=200`; `down.*` has
   `up=false`, `http_status=503`; `nxdomain.invalid` has `dns_ok=false`.
3. **Alert e-mails**: "Monitoring started" to the global recipient
   (`ops@harness.test`), "HTTP Error — down.127.0.0.1.nip.io" to the per-domain
   recipient (`watcher@harness.test`), "DNS Error — nxdomain.invalid" to
   `alerts@harness.test`.
4. **Graceful shutdown**: `SIGINT` produces a "Monitoring stopped" e-mail and
   the container exits; `data/baselines.json` is persisted.
5. **Content change across a restart**: the `changed.*` page is rewritten, the
   monitor is restarted, and its first cycle logs a new `changed.*` line with
   `special_handling=1` (compared against the persisted baseline).
6. **No content-change e-mail**: the monitor only flags content changes in the
   log; it no longer e-mails about them (the portal classifies and e-mails).
   Every message in Mailpit is one of started / stopped / HTTP Error / DNS Error.

## Running it

```bash
./harness/run.sh                                            # build from this checkout
UPTIME_IMAGE=ghcr.io/dyanet/uptime:latest ./harness/run.sh  # test the published image
HARNESS_KEEP=1 ./harness/run.sh                             # keep containers up afterwards
MAILPIT_PORT=9025 ./harness/run.sh                          # if 8025 is already taken
```

On Windows run it from Git Bash (`bash harness/run.sh`). Requirements: Docker
with Compose v2 and `curl`; `jq` is optional (there is a `grep` fallback).

A run takes about two minutes once the image exists; the first build of the
monitor image from source adds a few minutes. The script prints progress while
waiting, tears everything down (`docker compose down -v`) on exit, and on
failure prints the monitor logs and the Mailpit message list and saves the full
compose logs to `harness/data/compose.log`. In CI (`.github/workflows/ci.yml`,
job `harness`) those files are uploaded as an artifact.

Generated files (`harness/data/uptime.jsonl`, `baselines.json`, `errors.jsonl`,
`compose.log`) are git-ignored; `env` and `domains.csv` are committed and
contain no secrets.

## The DNS dependency

The monitor's checker resolves domains through Google Public DNS
(`8.8.8.8`/`8.8.4.4`), not through the host or Docker resolver. The harness
therefore cannot use `/etc/hosts` or Docker service names for the monitored
sites. Instead it uses public wildcard names that resolve to `127.0.0.1`:

- `up.127.0.0.1.nip.io`, `down.127.0.0.1.nip.io`, `changed.127.0.0.1.nip.io`
  (healthy / 503 / rewritable), and
- `nxdomain.invalid`, which never resolves.

and runs the monitor with `network_mode: "service:target"`, so that
`127.0.0.1` inside the monitor container *is* the nginx container. nginx
listens on port 80 only; the HTTPS attempt is refused, which triggers the
monitor's documented HTTP fallback, and nginx then answers by `server_name`.

If `*.127.0.0.1.nip.io` cannot be resolved via `8.8.8.8` from inside Docker
(nip.io outage, or a network that blocks Google DNS), step 1 times out and the
script says so. Check with:

```bash
docker run --rm alpine nslookup up.127.0.0.1.nip.io 8.8.8.8
```

The SMTP host (`mailpit`) is resolved by the system resolver, so Docker's
service discovery works for it.

## Looking at the mail

While the harness runs (or with `HARNESS_KEEP=1`), open http://127.0.0.1:8025
for the Mailpit UI, or query the API:

```bash
curl -s http://127.0.0.1:8025/api/v1/messages | jq '.messages[] | {Subject, To}'
curl -s -G --data-urlencode 'query=subject:"DNS Error"' http://127.0.0.1:8025/api/v1/search | jq .messages_count
```

## Adapting it

- **Different scenarios**: add a `server` block to `nginx/default.conf` with a
  new `<name>.127.0.0.1.nip.io` server name and a row to `data/domains.csv`,
  then add `assert_field` / `assert_mail` lines to `run.sh`.
- **Real SMTP**: point `data/env` at your relay (and set `UPTIME_SMTP_TLS=true`);
  the Mailpit assertions in `run.sh` then no longer apply.
- **Real sites**: any public domain can go into `data/domains.csv`; the
  `network_mode` trick only matters for the local nginx names.
- **Intervals**: the monitor accepts `30m`, `1h`, `3h`, `24h` only. The harness
  relies on the first cycle running immediately at start-up, which is why it
  restarts the monitor to trigger the second cycle instead of waiting 30 min.
