# Migrating keys

`eplix import --from <dir>` detects the layout or takes `--layout`:

| Client | Point `--from` at | Passwords |
| --- | --- | --- |
| staking-deposit-cli, ethstaker-deposit-cli | `validator_keys/` | `--password-file` |
| Teku | the `--validator-keys` key directory | `<name>.txt` next to each key, or `--password-file <password dir>` |
| Lighthouse | the network data dir (holds `validators/` and `secrets/`) | `secrets/<0xpubkey>` or `validator_definitions.yml` |
| Nimbus | the data dir (holds `validators/` and `secrets/`) | `secrets/<0xpubkey>` |
| Lodestar | the dir that holds `keystores/` and `secrets/` | `secrets/<0xpubkey>` |
| Prysm | `validator accounts backup --wallet-dir=W --wallet-password-file=F --backup-dir=B --backup-password-file=P --backup-public-keys=0x...`, unzip `B/backup.zip`, then `--layout plain --password-file P` | the backup password |

Export the old client's slashing history as EIP-3076 (`lighthouse account validator slashing-protection export`, `teku slashing-protection export`, `nimbus_beacon_node slashingdb export`, `lodestar validator slashing-protection export`, `validator slashing-protection-history export` for Prysm). `tests/fixtures/layouts/README.md` has the exact commands each client was run with and pass it with `--slashing-protection`. Stop the old client first, and keep it stopped. On its first start in Eplix each key waits for the doppelganger check, which misses 3 to 4 epochs of duties with the defaults. With no history at all (a new key, or keys made again after a disk loss), pass `--no-signing-history` instead: each key gets a floor record at the epoch now + 1, and a key a beacon node shows as possibly having signed needs a `y` on the terminal. A beacon node head more than one epoch past the system clock stops the import with an error and writes no floor: check the clock and the nodes first (`docs/runbook.md`).
