#!/usr/bin/env bash
# One local Web3Signer with its own slashing protection on, over a local PostgreSQL, for the
# web3signer-pg integration test (scripts/web3signer-pg-it.sh). Everything lives in <dir>.
#   setup  initdb in <dir>/pg, two free ports, one test key in <dir>/keys
#   start  PostgreSQL, a fresh database with Web3Signer's slashing schema (migrations/postgresql,
#          in version order), then Web3Signer; writes its URL to <dir>/w3s.url
#   stop   Web3Signer, then PostgreSQL
# Usage: scripts/web3signer-pg.sh setup|start|stop <dir>
# Environment: W3S the web3signer launcher (bin/web3signer), JAVA_HOME a Java 21+ runtime,
# PG_BIN the directory with initdb, pg_ctl and psql (default /usr/lib/postgresql/16/bin).
set -euo pipefail
cmd=${1:?setup, start or stop}
dir=${2:?directory}
mkdir -p "$dir"
dir=$(realpath "$dir")
PG_BIN=${PG_BIN:-/usr/lib/postgresql/16/bin}

free_port() {
  python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

pg_ctl_() { timeout 60 "$PG_BIN/pg_ctl" -D "$dir/pg" "$@"; }

case "$cmd" in
setup)
  if [ ! -f "$dir/pg/PG_VERSION" ]; then
    timeout 120 "$PG_BIN/initdb" -D "$dir/pg" -U postgres --auth=trust -E UTF8 --no-locale > "$dir/initdb.log"
  fi
  # The ports are taken now and checked again at start.
  [ -f "$dir/ports.env" ] || printf 'pg_port=%s\nw3s_port=%s\n' "$(free_port)" "$(free_port)" > "$dir/ports.env"
  # Interop key 0 (a public test key, never for real funds).
  mkdir -p "$dir/keys"
  printf 'type: "file-raw"\nkeyType: "BLS"\nprivateKey: "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866"\n' \
    > "$dir/keys/key0.yaml"
  echo "set up in $dir"
  ;;
start)
  launcher=$(realpath "${W3S:?W3S: path to bin/web3signer}")
  [ -f "$dir/ports.env" ] || { echo "run setup first" >&2; exit 1; }
  . "$dir/ports.env"
  for p in "$pg_port" "$w3s_port"; do
    if ss -ltnH "sport = :$p" | grep -q .; then echo "port $p is taken; delete $dir/ports.env and run setup" >&2; exit 1; fi
  done
  mkdir -p "$dir/sock"
  pg_ctl_ start -w -t 30 -l "$dir/pg.log" \
    -o "-p $pg_port -k $dir/sock -c listen_addresses=127.0.0.1 -c jit=off -c fsync=off"
  psql_() { timeout 60 "$PG_BIN/psql" -X -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$pg_port" -U postgres "$@"; }
  # A fresh database each start: the test expects no marks but its own.
  psql_ -d postgres -c "DROP DATABASE IF EXISTS web3signer" -c "CREATE DATABASE web3signer"
  migrations="$(dirname "$(dirname "$launcher")")/migrations/postgresql"
  find "$migrations" -name 'V*.sql' | sort -V | while read -r f; do psql_ -d web3signer -f "$f"; done
  mkdir -p "$dir/data"
  "$launcher" --http-listen-host=127.0.0.1 --http-listen-port="$w3s_port" --data-path="$dir/data" \
    --key-store-path="$dir/keys" --logging=INFO \
    eth2 --network=minimal --slashing-protection-enabled=true \
    --slashing-protection-db-url="jdbc:postgresql://127.0.0.1:$pg_port/web3signer" \
    --slashing-protection-db-username=postgres --slashing-protection-db-password=unused \
    > "$dir/w3s.log" 2>&1 &
  echo $! > "$dir/w3s.pid"
  url="http://127.0.0.1:$w3s_port"
  for _ in $(seq 1 600); do
    curl -sf -m 2 "$url/upcheck" > /dev/null && break
    kill -0 "$(cat "$dir/w3s.pid")" 2>/dev/null || { echo "Web3Signer exited; see $dir/w3s.log" >&2; exit 1; }
    sleep 0.1
  done
  curl -sf -m 2 "$url/upcheck" > /dev/null || { echo "Web3Signer did not answer in 60 s; see $dir/w3s.log" >&2; exit 1; }
  echo "$url" > "$dir/w3s.url"
  echo "Web3Signer at $url, PostgreSQL at 127.0.0.1:$pg_port"
  ;;
stop)
  if [ -f "$dir/w3s.pid" ]; then
    pid=$(cat "$dir/w3s.pid")
    if kill "$pid" 2>/dev/null; then
      for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$dir/w3s.pid" "$dir/w3s.url"
  fi
  if [ -f "$dir/pg/postmaster.pid" ]; then pg_ctl_ stop -m fast -w -t 30 || pg_ctl_ stop -m immediate -w -t 10 || true; fi
  ;;
*)
  echo "usage: $0 setup|start|stop <dir>" >&2
  exit 2
  ;;
esac
