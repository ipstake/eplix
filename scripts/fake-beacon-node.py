#!/usr/bin/env python3
"""A minimal fake beacon node for measuring the eplix binary's start-up (no live node needed).

Serves genesis, spec, validators, attester duties and attestation data, accepts attestation
submissions and voluntary exits, and holds the event stream open. With a Gloas epoch it also serves PTC duties (each
validator one seat per epoch) and payload attestation data, and accepts PTC votes. Standard
library only.

Usage: scripts/fake-beacon-node.py <port> <pubkeys-file> [seconds-per-slot] [slots-per-epoch] [gloas-epoch]
The genesis time is the start time of this script, or FAKE_BN_GENESIS (Unix seconds).
FAKE_BN_ATTESTATIONS=<file> appends one JSON line per submitted attestation (slot, attester index,
source and target epochs, block root, signature) and flushes it before the node answers.
FAKE_BN_BUILDER=1 models a node with MEV-Boost before Gloas: validator 0 proposes in slot 3 of
each epoch, produceBlockV3 with builder_boost_factor above 0 answers a blinded block (JSON), and
the node accepts register_validator, prepare_beacon_proposer and blinded blocks.
"""
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
PUBKEYS = [l.strip() for l in open(sys.argv[2]) if l.strip()]
SPS = int(sys.argv[3]) if len(sys.argv) > 3 else 6
SPE = int(sys.argv[4]) if len(sys.argv) > 4 else 8
GLOAS = sys.argv[5] if len(sys.argv) > 5 else "18446744073709551615"
GENESIS = int(os.environ.get("FAKE_BN_GENESIS") or time.time())
ATT_LOG = os.environ.get("FAKE_BN_ATTESTATIONS")
ATT_LOCK = threading.Lock()
GVR = "0x" + "a0" * 32
SPEC = {
    "CONFIG_NAME": "fake", "PRESET_BASE": "minimal",
    "SECONDS_PER_SLOT": str(SPS), "SLOTS_PER_EPOCH": str(SPE),
    "GENESIS_FORK_VERSION": "0x00000001",
    "ALTAIR_FORK_VERSION": "0x01000001", "ALTAIR_FORK_EPOCH": "0",
    "BELLATRIX_FORK_VERSION": "0x02000001", "BELLATRIX_FORK_EPOCH": "0",
    "CAPELLA_FORK_VERSION": "0x03000001", "CAPELLA_FORK_EPOCH": "0",
    "DENEB_FORK_VERSION": "0x04000001", "DENEB_FORK_EPOCH": "0",
    "ELECTRA_FORK_VERSION": "0x05000001", "ELECTRA_FORK_EPOCH": "0",
    "FULU_FORK_VERSION": "0x06000001", "FULU_FORK_EPOCH": "0",
    "GLOAS_FORK_VERSION": "0x07000001", "GLOAS_FORK_EPOCH": GLOAS,
}
SUBMITTED = []
BUILDER = os.environ.get("FAKE_BN_BUILDER") == "1"
Z32 = "0x" + "00" * 32


def blinded_block(slot, randao, graffiti):
    """A minimal-preset Fulu BlindedBeaconBlock whose payload header pays a builder address."""
    header = {"parent_hash": Z32, "fee_recipient": "0x" + "ee" * 20, "state_root": Z32,
              "receipts_root": Z32, "logs_bloom": "0x" + "00" * 256, "prev_randao": Z32,
              "block_number": "1", "gas_limit": "60000000", "gas_used": "0", "timestamp": "0",
              "extra_data": "0x", "base_fee_per_gas": "7", "block_hash": "0x" + "42" * 32,
              "transactions_root": Z32, "withdrawals_root": Z32, "blob_gas_used": "0",
              "excess_blob_gas": "0"}
    body = {"randao_reveal": randao, "eth1_data": {"deposit_root": Z32, "deposit_count": "0", "block_hash": Z32},
            "graffiti": graffiti, "proposer_slashings": [], "attester_slashings": [], "attestations": [],
            "deposits": [], "voluntary_exits": [],
            "sync_aggregate": {"sync_committee_bits": "0x00000000", "sync_committee_signature": "0xc0" + "00" * 95},
            "execution_payload_header": header, "bls_to_execution_changes": [], "blob_kzg_commitments": [],
            "execution_requests": {"deposits": [], "withdrawals": [], "consolidations": []}}
    return {"slot": str(slot), "proposer_index": "0", "parent_root": root(slot - 1, "bb"),
            "state_root": "0x" + "77" * 32, "body": body}


def root(n, tag):
    return "0x" + (n + 1).to_bytes(8, "little").hex() + "00" * 23 + tag


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(n) or b"null")

    def do_GET(self):
        p = self.path
        if p == "/eth/v1/beacon/genesis":
            self.reply({"data": {"genesis_time": str(GENESIS), "genesis_validators_root": GVR,
                                 "genesis_fork_version": "0x00000001"}})
        elif p == "/eth/v1/config/spec":
            self.reply({"data": SPEC})
        elif p.startswith("/eth/v1/validator/attestation_data"):
            slot = int(p.split("slot=")[1].split("&")[0])
            epoch = slot // SPE
            src = max(epoch - 1, 0)
            self.reply({"data": {"slot": str(slot), "index": "0", "beacon_block_root": root(slot, "bb"),
                                 "source": {"epoch": str(src), "root": root(src * SPE, "bb")},
                                 "target": {"epoch": str(epoch), "root": root(epoch * SPE, "bb")}}})
        elif p.startswith("/eth/v1/validator/payload_attestation_data"):
            slot = int(p.split("slot=")[1].split("&")[0])
            self.reply({"version": "gloas", "data": {"beacon_block_root": root(slot, "bb"), "slot": str(slot),
                                                     "payload_present": True, "blob_data_available": True}})
        elif BUILDER and p.startswith("/eth/v1/validator/duties/proposer/"):
            epoch = int(p.rsplit("/", 1)[1])
            self.reply({"dependent_root": root(epoch, "dd"), "execution_optimistic": False,
                        "data": [{"pubkey": PUBKEYS[0], "validator_index": "0", "slot": str(epoch * SPE + 3)}]})
        elif BUILDER and p.startswith("/eth/v3/validator/blocks/"):
            slot = int(p.split("/")[5].split("?")[0])
            q = dict(kv.split("=", 1) for kv in p.split("?", 1)[1].split("&"))
            boost = int(q.get("builder_boost_factor", "100"))
            print(f"produce block for slot {slot} with builder_boost_factor {boost}", flush=True)
            if boost == 0:
                self.reply({"code": 500, "message": "this fake node has builder blocks only"}, 500)
            else:
                self.reply({"version": "fulu", "execution_payload_blinded": True,
                            "execution_payload_value": "9000", "consensus_block_value": "1000",
                            "data": blinded_block(slot, q["randao_reveal"], q["graffiti"])})
        elif p.startswith("/eth/v1/events"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            try:
                while True:
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    time.sleep(5)
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self.reply({"code": 404, "message": "not found"}, 404)

    def do_POST(self):
        p = self.path
        if BUILDER and p.startswith("/eth/v2/beacon/blinded_blocks"):
            n = int(self.headers.get("Content-Length", "0"))
            data = self.rfile.read(n)
            # SignedBlindedBeaconBlock SSZ: offset of the message (4), signature (96), then the
            # message, whose first 8 bytes are the slot.
            slot = int.from_bytes(data[100:108], "little")
            print(f"published blinded block for slot {slot} ({self.headers.get('Content-Type')}, "
                  f"{self.headers.get('Eth-Consensus-Version')}, {len(data)} bytes)", flush=True)
            self.reply({})
            return
        b = self.body()
        if BUILDER and p == "/eth/v1/validator/register_validator":
            for r in b:
                m = r["message"]
                print(f"registration of {m['pubkey']} fee recipient {m['fee_recipient']} "
                      f"gas limit {m['gas_limit']}", flush=True)
            self.reply({})
            return
        if BUILDER and p == "/eth/v1/validator/prepare_beacon_proposer":
            self.reply({})
            return
        if p.endswith("/validators"):
            # A set: with a list, 50,000 ids against 50,000 keys took minutes.
            ids = set(b["ids"])
            data = [{"index": str(i), "balance": "32000000000", "status": "active_ongoing",
                     "validator": {"pubkey": pk, "activation_epoch": "0",
                                   "exit_epoch": "18446744073709551615"}}
                    for i, pk in enumerate(PUBKEYS) if pk in ids or str(i) in ids]
            self.reply({"data": data})
        elif p.startswith("/eth/v1/validator/duties/attester/"):
            epoch = int(p.rsplit("/", 1)[1])
            data = [{"pubkey": PUBKEYS[int(i)], "validator_index": i, "committee_index": "0",
                     "committee_length": "128", "committees_at_slot": "1",
                     "validator_committee_index": i, "slot": str(epoch * SPE + int(i) % SPE)}
                    for i in b if int(i) < len(PUBKEYS)]
            self.reply({"dependent_root": root(epoch, "dd"), "execution_optimistic": False, "data": data})
        elif p.startswith("/eth/v1/validator/duties/ptc/"):
            epoch = int(p.rsplit("/", 1)[1])
            data = [{"pubkey": PUBKEYS[int(i)], "validator_index": i, "slot": str(epoch * SPE + (int(i) + 1) % SPE)}
                    for i in b if int(i) < len(PUBKEYS)]
            self.reply({"dependent_root": root(epoch, "dd"), "execution_optimistic": False, "data": data})
        elif p.startswith("/eth/v1/validator/liveness/"):
            # Nobody else signs with these keys: never live (doppelganger checks pass).
            self.reply({"data": [{"index": i, "is_live": False} for i in b]})
        elif p == "/eth/v2/beacon/pool/attestations":
            SUBMITTED.extend(b)
            version = self.headers.get("Eth-Consensus-Version", "")
            if ATT_LOG:
                with ATT_LOCK, open(ATT_LOG, "a") as f:
                    for a in b:
                        d = a["data"]
                        f.write(json.dumps({"slot": int(d["slot"]), "attester_index": int(a["attester_index"]),
                                            "source": int(d["source"]["epoch"]), "target": int(d["target"]["epoch"]),
                                            "root": d["beacon_block_root"], "signature": a["signature"]}) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            print(f"submitted {len(b)} attestations for slot {b[0]['data']['slot']} ({version})", flush=True)
            self.reply({})
        elif p == "/eth/v1/beacon/pool/voluntary_exits":
            print(f"submitted voluntary exit of validator {b['message']['validator_index']} "
                  f"at epoch {b['message']['epoch']}", flush=True)
            self.reply({})
        elif p == "/eth/v1/beacon/pool/payload_attestations":
            print(f"submitted {len(b)} payload attestations for slot {b[0]['data']['slot']}", flush=True)
            self.reply({})
        else:
            self.reply({"code": 404, "message": "not found"}, 404)


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
