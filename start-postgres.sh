#!/bin/sh
# Starts the local Postgres cluster used for checkpointing.
# Not a launchd service on purpose: run it when you want it.
PGBIN=/opt/homebrew/opt/postgresql@16/bin
PGDIR="$HOME/.local/share/aegis/pgdata"
mkdir -p /tmp/aegispg
LC_ALL=C "$PGBIN/pg_ctl" -D "$PGDIR" \
  -o "-p 5436 -k /tmp/aegispg -h 127.0.0.1" -l "$PGDIR/server.log" "${1:-start}"
