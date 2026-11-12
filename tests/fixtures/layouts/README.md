# Client key layouts

Key directories and EIP-3076 exports written by the clients' own tools, 2026-10-23, on Linux
x86-64. Every key comes from the BIP-39 test mnemonic
`abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`
(keys 0 to 5), so they are throwaway test keys; every password here is a test password. The
slashing history is made up (block at slot 1000, attestation 30 to 31), imported into each client
with its own import command and exported again. Network: Hoodi. The client versions are in the
table below; each binary came from the client's GitHub release and matched its published checksum.

| Directory | Client and version | Key | Made with |
| --- | --- | --- | --- |
| `deposit-cli/` | ethstaker-deposit-cli v1.3.0 | 5 | `deposit --language english --non_interactive --ignore_connectivity existing-mnemonic --mnemonic "<test mnemonic>" --validator_start_index 0 --num_validators 6 --chain hoodi --keystore_password layout-test-pw --withdrawal_address 0x...dEaD --regular-withdrawal --pbkdf2` (keys 0 to 4 went to the clients below) |
| `lighthouse/` | Lighthouse v8.3.2 | 0 | `lighthouse --network hoodi --datadir D account validator import --directory <key 0> --password-file pw --reuse-password --stdin-inputs`; `... slashing-protection import` and `export`. `slashing_protection.sqlite` left out. |
| `teku/` | Teku 26.10.2 | 1 | Teku has no key import command; operators place `<name>.json` and `<name>.txt`. Teku loaded this pair (`validator-client --validator-keys=keys:passwords`, log: "Loaded 1 Validators"). History: `teku slashing-protection import --data-path D --from in.json`, `export --to out.json`. |
| `nimbus/` | Nimbus v26.10.2 | 2 | `nimbus_beacon_node deposits import --network=hoodi --data-dir=D <dir>` with the password on stdin; `nimbus_beacon_node slashingdb import` and `export`. |
| `lodestar/` | Lodestar v1.50.1 | 3 | `lodestar validator import --network hoodi --dataDir D --keystore <dir> --passphraseFile pw`; `lodestar validator slashing-protection import` and `export`. |
| `prysm/` | Prysm v7.3.1 (validator binary) | 4 | see below |

Prysm keeps imported keys in one wallet file (`wallet/direct/accounts/all-accounts.keystore.json`),
not as EIP-2335 files. The export path, as run here:

```sh
validator wallet create --wallet-dir=W --keymanager-kind=imported --wallet-password-file=wallet-pw --accept-terms-of-use --hoodi
validator accounts import --keys-dir=<key 4> --wallet-dir=W --wallet-password-file=wallet-pw --account-password-file=pw --accept-terms-of-use --hoodi
# validator.db exists only after the validator ran once (it stops without a beacon node):
validator --datadir=D --wallet-dir=W --wallet-password-file=wallet-pw --beacon-rpc-provider=127.0.0.1:1 --suggested-fee-recipient=0x...dEaD --accept-terms-of-use --hoodi
validator slashing-protection-history import --datadir=D --slashing-protection-json-file=in.json --accept-terms-of-use --hoodi
validator slashing-protection-history export --datadir=D --slashing-protection-export-dir=OUT --accept-terms-of-use --hoodi
validator accounts backup --wallet-dir=W --wallet-password-file=wallet-pw --backup-dir=B --backup-password-file=backup-pw --backup-public-keys=0x<pubkey> --accept-terms-of-use --hoodi
```

`B/backup.zip` holds `keystore-0.json`, an EIP-2335 keystore under the backup password; `prysm/backup/`
is that file unzipped, `prysm/interchange.json` is `OUT/slashing_protection.json`.

What the files showed: Lighthouse keeps the original keystore
file name inside `validators/<0xpubkey>/` and writes absolute paths (rewritten here to `/srv/layouts/`) and, with `--reuse-password`, the
password inline into `validator_definitions.yml`; Nimbus re-encrypts each keystore under a random
password in `secrets/<0xpubkey>` and exports unknown attestation roots as all zero; Lighthouse and
Teku drop the signing roots on export.
