#!/usr/bin/env bash
# A local Charon cluster for tests: 4 nodes, threshold 3, on Charon's beacon mock (simnet), with
# insecure test keys made by `charon create cluster`. No deposits, no real network: the nodes
# find each other through a local relay. Node i serves its validator API on 127.0.0.1:(3600+i)
# with the shares in <dir>/node<i>/validator_keys (EIP-2335, Teku layout: keystore-*.json and
# keystore-*.txt).
#
# Needs the charon binary (CHARON, default on PATH). Every process runs under `timeout`
# (CHARON_TIMEOUT seconds, default 900), so a forgotten cluster stops by itself.
#
# Usage:
#   scripts/charon-local.sh setup <dir> [validators]   create the cluster (default 16 validators)
#   scripts/charon-local.sh run <dir> [mock nodes]     start the relay and the 4 nodes; Charon's own
#                                                      validator mock runs on the listed nodes (default none)
#   scripts/charon-local.sh stop <dir>                 stop them
#
# Environment for setup: CHARON_SLOT_SECONDS (beacon mock slot duration, default 4; run reads it
# from <dir>/slot). With 2 s slots Charon's aggregation duty (fetch, consensus) does not finish
# before the slot ends, so a VC that asks for the aggregate attestation at 2/3 of the slot times
# out; 4 s slots leave it time.
#
# The cluster is on a custom test network (eplix-simnet). The beacon mock reports Hoodi's fork
# versions, fork epochs and genesis validators root whatever the network: Electra at epoch 2048,
# and Fulu at epoch 50688 in its fork schedule while its spec says Fulu is not scheduled. With
# Hoodi's own genesis (`--network hoodi`) the chain is past epoch 50688, so Charon checks
# signatures with the Fulu fork version while a VC that reads the spec signs with Electra's.
# Eplix needs Electra (SingleAttestation). So setup puts the genesis 2080 epochs back
# (16-slot epochs): the chain is in Electra and before epoch 50688, where spec and fork schedule
# agree. With 4 s slots that holds for 34 days; run refuses an older cluster.
set -euo pipefail

CHARON=${CHARON:-charon}
CHARON_TIMEOUT=${CHARON_TIMEOUT:-900}
RELAY_HTTP=127.0.0.1:3640

cmd=${1:?command}
dir=${2:?directory}
mkdir -p "$dir"
dir=$(cd "$dir" && pwd)

testnet() { # genesis time
  echo --testnet-name eplix-simnet --testnet-fork-version 0x10000999 --testnet-chain-id 99999 --testnet-genesis-timestamp "$1"
}

wait_tcp() { # host port seconds
  for _ in $(seq 1 $(($3 * 10))); do
    if (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  return 1
}

start_bg() { # pid file, log file, command...
  local pid=$1 log=$2; shift 2
  # setsid: a new process group, so stop can kill timeout and charon together.
  setsid timeout --kill-after=10 "$CHARON_TIMEOUT" "$@" > "$log" 2>&1 < /dev/null &
  echo $! > "$pid"
}

stop() {
  for p in "$dir"/node*/pid "$dir"/relay/pid; do
    [ -f "$p" ] || continue
    local id
    id=$(cat "$p")
    kill -TERM -- "-$id" 2>/dev/null || kill -TERM "$id" 2>/dev/null || true
    for _ in $(seq 1 50); do kill -0 "$id" 2>/dev/null || break; sleep 0.1; done
    kill -KILL -- "-$id" 2>/dev/null || true
    rm -f "$p"
  done
}

case "$cmd" in
  setup)
    n=${3:-16}
    if [ -f "$dir/node0/cluster-lock.json" ]; then echo "$dir already has a cluster" >&2; exit 0; fi
    slot=${CHARON_SLOT_SECONDS:-4}
    echo "$slot" > "$dir/slot"
    echo $(( $(date +%s) - 2080 * 16 * slot )) > "$dir/genesis"
    timeout 120 "$CHARON" create cluster --nodes 4 --threshold 3 --num-validators "$n" --insecure-keys \
      $(testnet "$(cat "$dir/genesis")") --name eplix-test \
      --withdrawal-addresses 0x000000000000000000000000000000000000dEaD \
      --fee-recipient-addresses 0x000000000000000000000000000000000000dEaD \
      --cluster-dir "$dir" > "$dir/create.log" 2>&1 || { cat "$dir/create.log" >&2; exit 1; }
    ;;
  run)
    shift 2
    mocks=" $* "
    stop
    genesis=$(cat "$dir/genesis")
    SLOT=$(cat "$dir/slot")
    if [ $(( $(date +%s) - genesis )) -gt $(( 50000 * 16 * SLOT )) ]; then
      echo "the cluster in $dir is too old for the beacon mock; set up a new one" >&2; exit 1
    fi
    mkdir -p "$dir/relay"
    start_bg "$dir/relay/pid" "$dir/relay/relay.log" "$CHARON" relay --data-dir "$dir/relay" \
      --http-address "$RELAY_HTTP" --p2p-tcp-address 127.0.0.1:3630 --p2p-external-ip 127.0.0.1 \
      --p2p-relays="" --log-color disable --monitoring-address 127.0.0.1:3639
    wait_tcp 127.0.0.1 3640 20 || { cat "$dir/relay/relay.log" >&2; stop; exit 1; }
    for i in 0 1 2 3; do
      d="$dir/node$i"
      vmock=false
      case "$mocks" in *" $i "*) vmock=true ;; esac
      start_bg "$d/pid" "$d/charon.log" "$CHARON" run \
        --lock-file "$d/cluster-lock.json" --private-key-file "$d/charon-enr-private-key" \
        --simnet-beacon-mock --simnet-slot-duration "${SLOT}s" $(testnet "$genesis") \
        --simnet-validator-mock="$vmock" --simnet-validator-keys-dir "$d/validator_keys" \
        --validator-api-address "127.0.0.1:360$i" --monitoring-address "127.0.0.1:362$i" \
        --p2p-tcp-address "127.0.0.1:361$i" --p2p-external-ip 127.0.0.1 \
        --p2p-relays "http://$RELAY_HTTP/enr" --log-color disable --log-level info \
        --nickname "node$i"
    done
    for i in 0 1 2 3; do
      wait_tcp 127.0.0.1 "360$i" 60 || { echo "node$i: no validator API" >&2; tail -30 "$dir/node$i/charon.log" >&2; stop; exit 1; }
    done
    ;;
  stop) stop ;;
  *) echo "unknown command $cmd" >&2; exit 2 ;;
esac
