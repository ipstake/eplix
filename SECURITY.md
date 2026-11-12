# Security policy

Eplix signs for validators, so a bug can cost stake. Please report security problems privately.

## Reporting

Email mail@ipstake.eu. Do not open a public issue or pull request for a security problem.

Include what you can of:

- the version or commit, the platform and the signing backend (local keys, Dirk, Web3Signer, TEE signers);
- what goes wrong and what an attacker gains;
- steps or a test that shows it.

You get a reply that the report arrived. We then agree on a fix and a date to publish it, and you are credited in the release notes unless you ask not to be.

## What counts

Anything that can make Eplix:

- sign a slashable message, or a message the slashing protection should have refused;
- leak or weaken a key or a key share;
- accept a remote signer that fails its attestation, setup or key release checks;
- sign for the wrong chain, fork or validator;
- crash or stall on input from a beacon node, a signer or the keymanager API.

## Supported versions

0.1.x gets security fixes. Fixes go to the main branch and the next 0.1.x release.
