#!/usr/bin/env bash
# Smoke test of the published binary with the Web3Signer module: one local Web3Signer with four
# test keys behind mutual TLS (certificates made here with openssl), eplix attesting for them
# against scripts/fake-beacon-node.py. Web3Signer's slashing protection is off (it needs
# PostgreSQL). Halfway through, the client certificate files are replaced with a second
# certificate, which eplix must load and use without a restart. The
# endpoint is attested by the pinned source with the hash of Web3Signer's TLS key.
# Run after scripts/publish-aot.sh.
# Usage: scripts/smoke-web3signer.sh <web3signer launcher> [seconds]   (JAVA_HOME set)
set -euo pipefail
cd "$(dirname "$0")/.."
launcher=$(realpath "${1:?path to bin/web3signer}")
seconds=${2:-24}
bin="$PWD/artifacts/publish/linux-x64/eplix"
work=$(mktemp -d)
bnport=15053
w3sport=19320
cleanup() {
  [ -n "${vc:-}" ] && kill "$vc" 2>/dev/null || true
  [ -n "${bn:-}" ] && kill "$bn" 2>/dev/null || true
  [ -n "${w3s:-}" ] && kill "$w3s" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# Test certificates: a CA, the server (localhost) and the eplix client.
cd "$work"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj "/CN=eplix smoke CA" 2>/dev/null
for n in localhost eplix eplix2; do
  openssl req -new -newkey rsa:2048 -nodes -keyout "$n.key" -out "$n.csr" -subj "/CN=$n" 2>/dev/null
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth,clientAuth\n' "$n" > "$n.ext"
  openssl x509 -req -in "$n.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$n.crt" -days 2 -sha256 -extfile "$n.ext" 2>/dev/null
done
echo eplix-smoke > password.txt
openssl pkcs12 -export -in localhost.crt -inkey localhost.key -out server.p12 -passout file:password.txt
{
  echo "eplix $(openssl x509 -in eplix.crt -noout -fingerprint -sha256 | cut -d= -f2)"
  echo "eplix2 $(openssl x509 -in eplix2.crt -noout -fingerprint -sha256 | cut -d= -f2)"
} > known-clients.txt
cd - > /dev/null

# Four whole keys as Web3Signer raw key files (test keys only).
mkdir -p "$work/keys" "$work/data"
for i in 1 2 3 4; do
  printf 'type: "file-raw"\nkeyType: "BLS"\nprivateKey: "0x%064x"\n' $((0x11000000 + i)) > "$work/keys/k$i.yaml"
done
# The fake node's chain (minimal preset, every fork at epoch 0) as a Web3Signer network file.
python3 -I - "$(dirname "$launcher")/../lib" "$work/network.yaml" <<'P'
import glob, re, sys, zipfile
jar = glob.glob(sys.argv[1] + "/spec-*.jar")[0]
text = zipfile.ZipFile(jar).read("tech/pegasys/teku/spec/config/configs/minimal.yaml").decode()
for fork in ["ALTAIR", "BELLATRIX", "CAPELLA", "DENEB", "ELECTRA", "FULU"]:
    text = re.sub(rf"^{fork}_FORK_EPOCH: .*$", f"{fork}_FORK_EPOCH: 0", text, flags=re.M)
open(sys.argv[2], "w").write(text)
P
"$launcher" --http-listen-host=127.0.0.1 --http-listen-port=$w3sport --data-path="$work/data" --key-store-path="$work/keys" \
  --tls-keystore-file="$work/server.p12" --tls-keystore-password-file="$work/password.txt" \
  --tls-known-clients-file="$work/known-clients.txt" --tls-allow-any-client=false \
  eth2 --network="$work/network.yaml" --slashing-protection-enabled=false > "$work/w3s.log" 2>&1 &
w3s=$!
curlw3s() { curl -sf --cacert "$work/ca.crt" --cert "$work/eplix.crt" --key "$work/eplix.key" "https://localhost:$w3sport$1"; }
for _ in $(seq 1 300); do curlw3s /upcheck > /dev/null && break; sleep 0.1; done
curlw3s /api/v1/eth2/publicKeys | python3 -I -c 'import json,sys; print("\n".join(json.load(sys.stdin)))' > "$work/pubkeys.txt"
echo "$(wc -l < "$work/pubkeys.txt") keys in Web3Signer"

cat > "$work/chain.yaml" <<'Y'
CONFIG_NAME: 'fake'
PRESET_BASE: 'minimal'
SECONDS_PER_SLOT: 2
GENESIS_FORK_VERSION: 0x00000001
ALTAIR_FORK_VERSION: 0x01000001
ALTAIR_FORK_EPOCH: 0
BELLATRIX_FORK_VERSION: 0x02000001
BELLATRIX_FORK_EPOCH: 0
CAPELLA_FORK_VERSION: 0x03000001
CAPELLA_FORK_EPOCH: 0
DENEB_FORK_VERSION: 0x04000001
DENEB_FORK_EPOCH: 0
ELECTRA_FORK_VERSION: 0x05000001
ELECTRA_FORK_EPOCH: 0
FULU_FORK_VERSION: 0x06000001
FULU_FORK_EPOCH: 0
GLOAS_FORK_VERSION: 0x07000001
GLOAS_FORK_EPOCH: 18446744073709551615
Y
# The pinned attestation: the SHA-256 of the server's SubjectPublicKeyInfo.
pin=$(openssl x509 -in "$work/localhost.crt" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)
cat > "$work/eplix.json" <<J
{ "beacon_node": "http://127.0.0.1:$bnport", "chain_config": "chain.yaml", "data_dir": "data",
  "allow_start_without_history": ["all"],
  "modules": { "doppelganger": { "enabled": false }, "web3signer": {
    "signers": [ { "url": "https://localhost:$w3sport", "ca_cert": "ca.crt", "client_cert": "eplix.crt", "client_key": "eplix.key",
                   "attestation": { "source": "pinned", "tls_key_pin": "$pin" } } ] } } }
J
python3 -I scripts/fake-beacon-node.py "$bnport" "$work/pubkeys.txt" 2 8 > "$work/bn.log" 2>&1 &
bn=$!
sleep 0.5
(cd "$work" && exec "$bin" run --config eplix.json) > "$work/vc.log" 2>&1 &
vc=$!
sleep $((seconds / 2))
# Rotate the client certificate in place, as a renewal job would.
cp "$work/eplix2.crt" "$work/eplix.crt.new" && mv "$work/eplix.crt.new" "$work/eplix.crt"
cp "$work/eplix2.key" "$work/eplix.key.new" && mv "$work/eplix.key.new" "$work/eplix.key"
sleep $((seconds - seconds / 2))
kill "$vc"; wait "$vc" 2>/dev/null || true
vc=
grep -E "web3signer:|ready:" "$work/vc.log"
grep -E "reloaded|new client certificate" "$work/vc.log" || true
rotated=$(grep -cE "new connections use the new client certificate" "$work/vc.log" || true)
attested=$(grep -cE "attested by pinned tls_key_pin, TLS keys $pin" "$work/vc.log" || true)
echo "attested: $attested"
grep -E "slot [0-9]+: " "$work/vc.log" | tail -n 4
signed=$(grep -cE "slot [0-9]+: [0-9]+ duties, [1-9][0-9]* signed, 0 refused, 0 failed, submitted True" "$work/vc.log" || true)
# Slot 0 is left out: the VC starts inside it, and its duty sometimes misses on older
# builds too (1 in 6 runs), which the old final check never caught.
failed=$(grep -E "slot [0-9]+: [0-9]+ duties" "$work/vc.log" | grep -v "slot 0: " | grep -vcE " 0 refused, 0 failed" || true)
echo "slots signed: $signed; slots with a refusal or failure: $failed"
grep -E "slot [0-9]+: [0-9]+ duties" "$work/vc.log" | grep -vE " 0 refused, 0 failed" || true
grep -E "ERROR|WARN" "$work/vc.log" | grep -v -E "starting without slashing history|HTTP 404" | head -n 5 || true
# Not a bare test: under set -e a failing test before && does not stop the script.
if ! { [ "$signed" -gt 0 ] && [ "$failed" -eq 0 ] && [ "$rotated" -eq 1 ] && [ "$attested" -eq 1 ]; }; then
  echo "smoke failed" >&2
  exit 1
fi
echo "smoke ok: the published binary attests through an attested Web3Signer over mutual TLS, and moves to a new client certificate without a restart"
