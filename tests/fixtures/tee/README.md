# TEE runner fixtures

| File | What it holds | Made by |
| --- | --- | --- |
| `oracle-vectors.json` | Attestation settings, runner identities and AWS Nitro documents, each with the verdict of tee-signer's Go verifiers. `TeeVerifierTests.fs` replays every case through Eplix's verifiers. | `tests/tools/tee-oracle` |
| `identity-v1-teesigner.json` | An IDENTITY request and answer in tee-signer's current layout (version 1), with its user data and MAA runtime data. | tee-signer's `signer-protocol` Go code |
| `wire-go.json` | Frames of the runner protocol, frame version 1: SIGN requests per duty, error answers, key lists. | the Go code of an earlier runner with tee-signer's layouts for these frames |

All inputs in these files are synthetic. No real attestation document, cloud account, instance or
key is in them.

## oracle-vectors.json

The generator in `tests/tools/tee-oracle` makes every input at run time: throwaway RSA keys sign
the Azure MAA and GCP Confidential Space tokens, and a local ECDSA P-384 CA (root, intermediate,
leaf, shaped like the AWS Nitro chain) signs the Nitro documents. It writes the CBOR of the Nitro
documents by hand, so it can make the encodings a CBOR library will not: indefinite lengths,
duplicate keys, stray tags. Cloud values are reserved or made up: `maa.attest.example`,
`example-project`, `signer@example-project.iam.gserviceaccount.com`. The settings cases use
`sharedweu.weu.attest.azure.net`, Microsoft's public shared MAA provider, as a host name only.

It then runs tee-signer's verifiers, from the Go module `attestation-verify`, on each case:

- `settings_cases`: `verify.Attestation` decoded with `encoding/json` and checked with `Validate`.
- `identity_cases`: the identity decoded with `wire.DecodeIdentity`, its user data checked against
  `backend.IdentityUserData`, then the verifier `verify.Attestation.NewVerifier` builds. An HTTP
  transport inside the generator serves each case's key set to the verifier, so nothing goes out
  to the network.
- `nitro_cases`: `attest.VerifyNitro` with the case's roots, PCRs, nonce, user data and time.

Each case records `ok` or `fail` and Go's error text. Eplix must give the same verdict; the error
text is for reading only.

To regenerate (Go and the modules tee-signer needs must be available):

```sh
TEE_SIGNER_DIR=/path/to/tee-signer tests/tools/tee-oracle/gen.sh
dotnet run --project tests/Eplix.Tests -- --filter-test-list tee-oracle
```

Keys and documents change on every run; the verdicts do not. The identity tokens are checked by Go
against the clock at generation time, and Eplix replays them at the recorded `now`, so the cases keep
30 seconds or more away from any time limit.

`TeeVerifierTests.fs` lists the cases where Eplix differs on purpose (`stricter`: Eplix refuses
unknown and wrongly cased setting names); every other case must agree.
