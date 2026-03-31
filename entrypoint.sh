#!/bin/sh
# Source env file from data mount if it exists.
# Strip carriage returns to handle Windows-style line endings.
if [ -f /data/env ]; then
  set -a
  eval "$(sed 's/\r$//' /data/env)"
  set +a
fi

exec uptime "$@"
