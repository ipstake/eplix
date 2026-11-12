#!/usr/bin/env bash
# A local Dirk cluster for tests: three Dirk instances (ids 1 to 3, ports 19591 to 19593) with a
# distributed wallet "Dist" (2 of 3 accounts made by Dirk's distributed key generation) and a
# plain wallet "Solo" on dirk1 only. Test keys only: every passphrase is in this script.
#
# Needs the dirk and ethdo binaries (DIRK, ETHDO, default on PATH) and the host names dirk1,
# dirk2 and dirk3 resolving to 127.0.0.1 (/etc/hosts).
#
# Usage:
#   scripts/dirk-local.sh setup <dir> [accounts]   certificates, configs, wallets, accounts (default 4 distributed, 2 solo)
#   scripts/dirk-local.sh start <dir> [ids]        start the instances (default: 1 2 3)
#   scripts/dirk-local.sh stop <dir> [ids]         stop them
#   scripts/dirk-local.sh wipe-protection <dir>    stop all, delete Dirk's slashing protection, keep the keys
#   scripts/dirk-local.sh bench-accounts <dir> <n> distributed accounts Bench/B1..Bn for the benchmark
#   scripts/dirk-local.sh configure <dir>          stop all and write the configs again
set -euo pipefail

DIRK=${DIRK:-dirk}
ETHDO=${ETHDO:-ethdo}
PASS=eplix-test-only

cmd=${1:?command}
dir=${2:?directory}
mkdir -p "$dir"
dir=$(cd "$dir" && pwd)

cert() { # name
  local n=$1
  openssl req -new -newkey rsa:2048 -nodes -keyout "$dir/certs/$n.key" -out "$dir/certs/$n.csr" -subj "/CN=$n" 2>/dev/null
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=digitalSignature,keyEncipherment\n' "$n" > "$dir/certs/$n.ext"
  openssl x509 -req -in "$dir/certs/$n.csr" -CA "$dir/certs/ca.crt" -CAkey "$dir/certs/ca.key" -CAcreateserial \
    -out "$dir/certs/$n.crt" -days 365 -sha256 -extfile "$dir/certs/$n.ext" 2>/dev/null
  rm -f "$dir/certs/$n.csr" "$dir/certs/$n.ext"
}

config() { # id
  local i=$1 d="$dir/dirk$1"
  mkdir -p "$d/wallets" "$d/storage"
  cat > "$d/dirk.yml" <<EOF
log-level: info
log-file: $d/dirk.log
server:
  id: $i
  name: dirk$i
  rules:
    admin-ips:
      - 127.0.0.1
  listen-address: 127.0.0.1:1959$i
certificates:
  ca-cert: file://$dir/certs/ca.crt
  server-cert: file://$dir/certs/dirk$i.crt
  server-key: file://$dir/certs/dirk$i.key
storage-path: $d/storage
stores:
  - name: local
    type: filesystem
    location: $d/wallets
unlocker:
  account-passphrases:
    - $PASS
process:
  generation-passphrase: $PASS
permissions:
  eplix:
    Dist: All
    Solo: All
    Bench: All
  admin:
    Dist: All
    Solo: All
    Bench: All
  other:
    Solo: All
peers:
  1: dirk1:19591
  2: dirk2:19592
  3: dirk3:19593
EOF
}

# The names are in the certificates and in each distributed account's participant list, and Dirk
# and ethdo are static Go binaries that read only /etc/hosts and DNS, so no setting here can
# stand in for /etc/hosts. WSL writes /etc/hosts again at each distro start unless
# /etc/wsl.conf has generateHosts = false under [network].
need_names() {
  local n
  for n in dirk1 dirk2 dirk3; do
    getent hosts "$n" > /dev/null || { echo "$n does not resolve: dirk1, dirk2 and dirk3 must (add '127.0.0.1 dirk1 dirk2 dirk3' to /etc/hosts)" >&2; exit 1; }
  done
}

start() {
  need_names
  for i in "$@"; do
    local d="$dir/dirk$i"
    if [ -f "$d/pid" ] && kill -0 "$(cat "$d/pid")" 2>/dev/null; then continue; fi
    nohup "$DIRK" --base-dir "$d" > "$d/stdout.log" 2>&1 &
    echo $! > "$d/pid"
  done
  for i in "$@"; do
    for _ in $(seq 1 100); do
      if (exec 3<>"/dev/tcp/127.0.0.1/1959$i") 2>/dev/null; then break; fi
      sleep 0.1
    done
  done
}

stop() {
  for i in "$@"; do
    local d="$dir/dirk$i"
    if [ -f "$d/pid" ]; then
      kill "$(cat "$d/pid")" 2>/dev/null || true
      for _ in $(seq 1 50); do kill -0 "$(cat "$d/pid")" 2>/dev/null || break; sleep 0.1; done
      rm -f "$d/pid"
    fi
  done
}

remote() { # id, then ethdo arguments
  local i=$1; shift
  "$ETHDO" --remote "dirk$i:1959$i" --server-ca-cert "$dir/certs/ca.crt" \
    --client-cert "$dir/certs/admin.crt" --client-key "$dir/certs/admin.key" "$@"
}

case "$cmd" in
  setup)
    n=${3:-4}
    need_names
    mkdir -p "$dir/certs"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$dir/certs/ca.key" -out "$dir/certs/ca.crt" -days 365 -subj "/CN=eplix test CA" 2>/dev/null
    for name in dirk1 dirk2 dirk3 eplix admin other; do cert "$name"; done
    for i in 1 2 3; do
      config "$i"
      "$ETHDO" wallet create --base-dir "$dir/dirk$i/wallets" --type distributed --wallet Dist --quiet
    done
    "$ETHDO" wallet create --base-dir "$dir/dirk1/wallets" --type non-deterministic --wallet Solo --quiet
    for a in 1 2; do
      "$ETHDO" account create --base-dir "$dir/dirk1/wallets" --account "Solo/Solo$a" --passphrase "$PASS" --allow-weak-passphrases --quiet
    done
    start 1 2 3
    for a in $(seq 1 "$n"); do
      remote 1 account create --account "Dist/Val$a" --participants 3 --signing-threshold 2 --passphrase "$PASS" --allow-weak-passphrases
    done
    # A restart unlocks every account through unlocker.account-passphrases.
    stop 1 2 3
    start 1 2 3
    remote 1 wallet accounts --wallet Dist --verbose || true
    ;;
  start|stop)
    shift 2
    ids=("$@")
    [ ${#ids[@]} -gt 0 ] || ids=(1 2 3)
    "$cmd" "${ids[@]}"
    ;;
  bench-accounts)
    # Distributed accounts Bench/B1..Bn for the burst benchmark, in their own wallet.
    n=${3:?number of accounts}
    stop 1 2 3
    for i in 1 2 3; do
      config "$i"
      "$ETHDO" wallet info --base-dir "$dir/dirk$i/wallets" --wallet Bench > /dev/null 2>&1 \
        || "$ETHDO" wallet create --base-dir "$dir/dirk$i/wallets" --type distributed --wallet Bench --quiet
    done
    start 1 2 3
    have=$(remote 1 wallet accounts --wallet Bench 2>/dev/null | grep -c '^B' || true)
    for a in $(seq $((have + 1)) "$n"); do
      remote 1 account create --account "Bench/B$a" --participants 3 --signing-threshold 2 --passphrase "$PASS" --allow-weak-passphrases
    done
    stop 1 2 3
    start 1 2 3
    ;;
  configure)
    stop 1 2 3
    for i in 1 2 3; do config "$i"; done
    ;;
  wipe-protection)
    stop 1 2 3
    for i in 1 2 3; do rm -rf "$dir/dirk$i/storage"; mkdir -p "$dir/dirk$i/storage"; done
    ;;
  *) echo "unknown command $cmd" >&2; exit 2 ;;
esac
