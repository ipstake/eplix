# Keymanager API

The keymanager API listens on 127.0.0.1:5062 over plain HTTP unless told otherwise. `tls_cert` (PEM: the certificate, then its intermediates) and `tls_key` (PEM) switch it to HTTPS, and the intermediates go out in the handshake. `client_ca` (PEM or DER, one or more CA certificates) also requires a client certificate that chains to one of them, through the intermediates the client sends or the ones listed in the file. An address that is not a loopback address needs TLS, or `"allow_plain_http": true`, since the bearer token would cross the network in clear text. `eplix check` loads the files and prints the certificate's subject and end date:

```json
"keymanager": { "address": "0.0.0.0", "port": 5062, "tls_cert": "km-cert.pem", "tls_key": "km-key.pem", "client_ca": "ops-ca.pem" }
```

The bearer token lives in `token_file` (default `<data_dir>/api-token.txt`); when the file is missing Eplix writes a random token there with mode 0600. A token file that the group or others can read or write, or an empty one, stops the start. One import request takes at most 1,000 keystores. `max_import_bytes` caps the body of a keystore import (default 268435456, 256 MiB; 1 MiB to 16 GiB). Eplix reads the import as a stream and keeps only the highest block and attestation per key from its `slashing_protection` history, so the cap bounds how long one request reads, not memory. A larger body gets 413: split the import, or minimise the interchange first. `max_import_keys` caps the distinct keys in that history (default 100,000; 1,000 to 1,000,000); more also get 413 and import nothing. `eplix slashing import` takes at most 100,000 keys per file.
