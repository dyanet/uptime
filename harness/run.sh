#!/usr/bin/env bash
# Docker harness for the open-source uptime monitor.
#
# Runs the README Quick Start exactly as documented (a data/ directory with
# `env` and `domains.csv`, mounted at /data) against local stand-ins for the
# outside world: Mailpit as the SMTP server, nginx as the monitored sites.
# Then checks that the monitor logs, alerts, shuts down gracefully and detects
# a content change across a restart. See harness/README.md.
#
# Usage:
#   ./harness/run.sh                                            # build the repo Dockerfile
#   UPTIME_IMAGE=ghcr.io/dyanet/uptime:latest ./harness/run.sh  # test a published image
#   HARNESS_KEEP=1 ./harness/run.sh                             # leave containers running
#   MAILPIT_PORT=9025 ./harness/run.sh                          # if 8025 is taken
#
# Requires: docker with compose v2, curl. jq is optional (grep fallback).
# Network: the monitor resolves names ONLY via Google public DNS (8.8.8.8), so
# *.127.0.0.1.nip.io must be resolvable through it from inside Docker.
# Runs under bash on Linux, macOS and Git Bash on Windows.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

MAILPIT_PORT="${MAILPIT_PORT:-8025}"
export MAILPIT_PORT
MAILPIT_API="http://127.0.0.1:${MAILPIT_PORT}/api/v1"
DATA_DIR="$HERE/data"
LOG_FILE="$DATA_DIR/uptime.jsonl"
CHANGED_PAGE="$HERE/nginx/html/changed/index.html"
CHANGED_V1='<!doctype html><title>changed</title><h1>Harness page: version 1</h1>'
CHANGED_V2='<!doctype html><title>changed</title><h1>Harness page: version 2 - the content changed</h1>'

UP_DOMAIN=up.127.0.0.1.nip.io
DOWN_DOMAIN=down.127.0.0.1.nip.io
CHANGED_DOMAIN=changed.127.0.0.1.nip.io
NX_DOMAIN=nxdomain.invalid

START_TS=$(date +%s)
RESULTS=()
FAILED=0
HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── output helpers ───────────────────────────────────────────────────────────

compose() { docker compose -f "$HERE/docker-compose.yml" "$@"; }
elapsed() { echo $(( $(date +%s) - START_TS )); }
log()  { printf '[harness %4ss] %s\n' "$(elapsed)" "$*"; }
pass() { RESULTS+=("PASS  $*"); log "PASS: $*"; }
fail() { RESULTS+=("FAIL  $*"); FAILED=1; log "FAIL: $*"; }
die()  { fail "$*"; exit 1; }

print_table() {
  echo
  echo "==================== harness results ===================="
  for r in ${RESULTS[@]+"${RESULTS[@]}"}; do echo "  $r"; done
  echo "========================================================="
  if [ "$FAILED" = 0 ]; then
    echo "RESULT: PASS in $(elapsed)s"
  else
    echo "RESULT: FAIL in $(elapsed)s"
  fi
}

cleanup() {
  local rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ] || [ "$FAILED" -ne 0 ]; then
    FAILED=1
    echo
    echo "===== monitor logs (last 100 lines) ====="
    compose logs --no-color --tail 100 monitor 2>&1 || true
    echo
    echo "===== mailpit messages ====="
    mail_list || true
    echo
    compose logs --no-color > "$DATA_DIR/compose.log" 2>&1 || true
    log "compose logs saved to $DATA_DIR/compose.log"
  fi
  # Restore the committed version of the rewritable page.
  printf '%s\n' "$CHANGED_V1" > "$CHANGED_PAGE" 2>/dev/null || true
  if [ "${HARNESS_KEEP:-0}" = 1 ]; then
    log "HARNESS_KEEP=1: leaving containers running (Mailpit UI: http://127.0.0.1:${MAILPIT_PORT})"
  else
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  print_table
  [ "$FAILED" = 0 ] && exit 0 || exit 1
}
trap cleanup EXIT

# ── generic helpers ──────────────────────────────────────────────────────────

# wait_until <timeout-seconds> <description> <command...>
wait_until() {
  local timeout=$1 desc=$2 waited=0
  shift 2
  until "$@"; do
    if [ "$waited" -ge "$timeout" ]; then
      log "timed out after ${timeout}s waiting for $desc"
      return 1
    fi
    sleep 5
    waited=$((waited + 5))
    log "waiting for $desc (${waited}s/${timeout}s)"
  done
}

# Number of uptime.jsonl lines for a domain.
line_count() {
  [ -f "$LOG_FILE" ] || { echo 0; return; }
  grep -c "\"domain\":\"$1\"" "$LOG_FILE" || true
}

# Most recent uptime.jsonl line for a domain.
last_line() { grep "\"domain\":\"$1\"" "$LOG_FILE" | tail -n 1 || true; }

# field <json-line> <name> -> the scalar as JSON text (true / 200 / "str" / null)
field() {
  if [ "$HAVE_JQ" = 1 ]; then
    printf '%s' "$1" | jq -c ".$2"
  else
    printf '%s' "$1" | grep -o "\"$2\":[^,}]*" | head -n 1 | cut -d: -f2- || true
  fi
}

# assert_field <domain> <field> <expected>
assert_field() {
  local line actual
  line=$(last_line "$1")
  actual=$(field "$line" "$2")
  if [ "$actual" = "$3" ]; then
    pass "$1: $2=$3"
  else
    fail "$1: expected $2=$3, got ${actual:-<missing>}   line: ${line:-<none>}"
  fi
}

all_domains_logged() {
  local d
  for d in "$UP_DOMAIN" "$DOWN_DOMAIN" "$CHANGED_DOMAIN" "$NX_DOMAIN"; do
    [ "$(line_count "$d")" -ge 1 ] || return 1
  done
}

# ── Mailpit helpers (HTTP API) ───────────────────────────────────────────────

# mail_count <mailpit search query> -> number of matching messages
mail_count() {
  local out
  out=$(curl -fsS -G --data-urlencode "query=$1" --data-urlencode "limit=200" \
        "$MAILPIT_API/search" 2>/dev/null) || { echo 0; return; }
  if [ "$HAVE_JQ" = 1 ]; then
    printf '%s' "$out" | jq '.messages | length'
  else
    printf '%s' "$out" | grep -o '"ID":"' | wc -l | tr -d ' ' || true
  fi
}

# Total messages in the mailbox.
mail_total() {
  local out
  out=$(curl -fsS "$MAILPIT_API/messages?limit=1" 2>/dev/null) || { echo 0; return; }
  if [ "$HAVE_JQ" = 1 ]; then
    printf '%s' "$out" | jq '.total'
  else
    printf '%s' "$out" | grep -o '"total":[0-9]*' | head -n 1 | cut -d: -f2 || true
  fi
}

# Human-readable message list for diagnostics.
mail_list() {
  local out
  out=$(curl -fsS "$MAILPIT_API/messages?limit=200" 2>/dev/null) || { echo "(mailpit not reachable)"; return; }
  if [ "$HAVE_JQ" = 1 ]; then
    printf '%s' "$out" | jq -r '.messages[] | "\(.Created)  to=\(.To[0].Address)  \(.Subject)"'
  else
    printf '%s' "$out" | grep -o '"Subject":"[^"]*"' || true
  fi
}

have_mail()    { [ "$(mail_count "$1")" -ge 1 ]; }
two_startups() { [ "$(mail_count "$Q_STARTED")" -ge 2 ]; }

# assert_mail <description> <query> <expected-minimum>
assert_mail() {
  local n
  n=$(mail_count "$2")
  if [ "$n" -ge "$3" ]; then
    pass "$1 ($n message(s))"
  else
    fail "$1: expected at least $3, got $n"
  fi
}

monitor_exited() {
  local cid status
  cid=$(compose ps -aq monitor 2>/dev/null | head -n 1)
  [ -n "$cid" ] || return 1
  status=$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)
  [ "$status" = "exited" ]
}

changed_detected() {
  [ "$(line_count "$CHANGED_DOMAIN")" -gt "$CHANGED_LINES_BEFORE" ] \
    && [ "$(field "$(last_line "$CHANGED_DOMAIN")" special_handling)" = 1 ]
}

# ── 0. preflight ─────────────────────────────────────────────────────────────

command -v docker >/dev/null 2>&1 || die "docker is required"
command -v curl   >/dev/null 2>&1 || die "curl is required"
docker compose version >/dev/null 2>&1 || die "docker compose (v2) is required"
[ "$HAVE_JQ" = 1 ] || log "jq not found: using grep fallbacks for JSON (install jq for nicer diagnostics)"

# ── 1. image ─────────────────────────────────────────────────────────────────

if [ -n "${UPTIME_IMAGE:-}" ]; then
  log "using published image $UPTIME_IMAGE"
  compose pull monitor
else
  log "building the monitor image from the repo Dockerfile (a cold build takes a few minutes)"
  compose build monitor
fi

# ── 2. reset generated state ─────────────────────────────────────────────────

compose down -v --remove-orphans >/dev/null 2>&1 || true
rm -f "$DATA_DIR/uptime.jsonl" "$DATA_DIR/baselines.json" "$DATA_DIR/errors.jsonl" \
      "$DATA_DIR/compose.log" "$DATA_DIR"/.baselines.tmp.* 2>/dev/null || true
printf '%s\n' "$CHANGED_V1" > "$CHANGED_PAGE"

# ── 3. start ─────────────────────────────────────────────────────────────────

log "starting mailpit, target (nginx) and monitor"
compose up -d --no-build

# ── 4. first check cycle (runs immediately on start) ─────────────────────────

wait_until 120 "first check cycle (all 4 domains in data/uptime.jsonl)" all_domains_logged \
  || die "monitor did not log all four domains within 120s. The monitor resolves names ONLY via Google DNS (8.8.8.8): is *.127.0.0.1.nip.io resolvable through it from inside Docker?"
pass "first cycle logged all four domains"

# ── 5. uptime.jsonl assertions ───────────────────────────────────────────────

assert_field "$UP_DOMAIN"      up               true
assert_field "$UP_DOMAIN"      http_status      200
assert_field "$UP_DOMAIN"      special_handling 0
assert_field "$DOWN_DOMAIN"    up               false
assert_field "$DOWN_DOMAIN"    http_status      503
assert_field "$CHANGED_DOMAIN" up               true
assert_field "$CHANGED_DOMAIN" http_status      200
assert_field "$CHANGED_DOMAIN" special_handling 0
assert_field "$NX_DOMAIN"      dns_ok           false
assert_field "$NX_DOMAIN"      up               false

# ── 6. alert e-mails (Mailpit API) ───────────────────────────────────────────

Q_STARTED='subject:"Monitoring started" to:ops@harness.test'
Q_STOPPED='subject:"Monitoring stopped" to:ops@harness.test'
# Two ASCII phrase terms instead of the em-dash subject: non-ASCII query text is
# mangled between Git Bash and curl on Windows, and Mailpit ANDs the terms.
Q_HTTP="subject:\"HTTP Error\" subject:\"${DOWN_DOMAIN}\" to:watcher@harness.test"
Q_DNS="subject:\"DNS Error\" subject:\"${NX_DOMAIN}\" to:alerts@harness.test"
Q_CONTENT='subject:"Content changed"'

# nxdomain.invalid is last in domains.csv, so its alert is the last e-mail of a cycle.
wait_until 60 "alert e-mails to arrive in Mailpit" have_mail "$Q_DNS" || true
assert_mail "'Monitoring started' to ops@harness.test"            "$Q_STARTED" 1
assert_mail "'HTTP Error — $DOWN_DOMAIN' to watcher@harness.test" "$Q_HTTP"    1
assert_mail "'DNS Error — $NX_DOMAIN' to alerts@harness.test"     "$Q_DNS"     1

# ── 7. content change detected across a graceful restart ────────────────────

MAIL_BEFORE_RESTART=$(mail_total)
CHANGED_LINES_BEFORE=$(line_count "$CHANGED_DOMAIN")
log "rewriting the $CHANGED_DOMAIN page, then stopping the monitor with SIGINT"
printf '%s\n' "$CHANGED_V2" > "$CHANGED_PAGE"
compose kill -s SIGINT monitor

if wait_until 30 "'Monitoring stopped' e-mail" have_mail "$Q_STOPPED"; then
  pass "SIGINT: graceful shutdown sent 'Monitoring stopped'"
else
  fail "no 'Monitoring stopped' e-mail after SIGINT"
fi
wait_until 30 "monitor container to exit" monitor_exited || fail "monitor did not exit after SIGINT"
if [ -f "$DATA_DIR/baselines.json" ]; then
  pass "baselines.json persisted in data/ across the restart"
else
  fail "baselines.json missing after shutdown"
fi

log "restarting the monitor (its first cycle compares against the persisted baseline)"
compose up -d --no-build monitor
if wait_until 120 "new $CHANGED_DOMAIN line with special_handling=1" changed_detected; then
  pass "$CHANGED_DOMAIN: content change flagged special_handling=1 after restart"
else
  fail "$CHANGED_DOMAIN: content change not detected after restart (last line: $(last_line "$CHANGED_DOMAIN"))"
fi

# ── 8. e-mail inventory: no content-change mail, only the expected kinds ─────

if wait_until 30 "second 'Monitoring started' e-mail" two_startups; then
  pass "second 'Monitoring started' after restart"
else
  fail "no second 'Monitoring started' e-mail after restart"
fi
sleep 5  # let the restarted monitor finish e-mailing its first cycle

N_CONTENT=$(mail_count "$Q_CONTENT")
if [ "$N_CONTENT" = 0 ]; then
  pass "no 'Content changed' e-mail (the monitor flags it; the portal classifies and e-mails)"
else
  fail "unexpected content-change e-mail(s): $N_CONTENT"
fi

N_TOTAL=$(mail_total)
N_STARTED=$(mail_count "$Q_STARTED")
N_STOPPED=$(mail_count "$Q_STOPPED")
N_HTTP=$(mail_count 'subject:"HTTP Error"')
N_DNS=$(mail_count 'subject:"DNS Error"')
N_EXPECTED=$((N_STARTED + N_STOPPED + N_HTTP + N_DNS))
log "mailbox grew from $MAIL_BEFORE_RESTART to $N_TOTAL messages across the restart"
if [ "$N_TOTAL" = "$N_EXPECTED" ]; then
  pass "every e-mail is started/stopped/HTTP Error/DNS Error ($N_STARTED+$N_STOPPED+$N_HTTP+$N_DNS = $N_TOTAL)"
else
  fail "mail total $N_TOTAL != started $N_STARTED + stopped $N_STOPPED + http $N_HTTP + dns $N_DNS"
fi

log "done"
