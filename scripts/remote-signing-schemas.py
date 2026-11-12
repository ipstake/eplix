#!/usr/bin/env python3
"""Converts remote-signing-api's schemas.yaml and the request schema of signing/paths/sign.yaml
into one JSON document for the contract tests (RemoteSigningContractTests.fs).

Reads the YAML as data (PyYAML safe_load). The output has the schemas under
components.schemas, as in schemas.yaml, and the sign request body under components.request,
with sign.yaml's "../schemas.yaml#/..." references made local. The output is
tests/fixtures/remote-signing-api/schemas.json (CC0-1.0, as the API).
Usage: python3 -I scripts/remote-signing-schemas.py <schemas.yaml> <sign.yaml> <out.json>
"""
import json
import sys

import yaml


def local(x):
    """sign.yaml points into schemas.yaml; the bundle holds both, so the references become local."""
    if isinstance(x, dict):
        return {k: local(v) for k, v in x.items()}
    if isinstance(x, list):
        return [local(v) for v in x]
    if isinstance(x, str) and x.startswith("../schemas.yaml#/"):
        return x.replace("../schemas.yaml#/", "#/")
    return x


with open(sys.argv[1]) as f:
    schemas = yaml.safe_load(f)
with open(sys.argv[2]) as f:
    sign = yaml.safe_load(f)
request = sign["post"]["requestBody"]["content"]["application/json"]["schema"]
doc = {"components": {"schemas": schemas["components"]["schemas"], "request": local(request)}}
text = json.dumps(doc, indent=1, sort_keys=True)
assert "../" not in text, "an external reference is left"
with open(sys.argv[3], "w") as f:
    f.write(text + "\n")
print(f"{len(doc['components']['schemas'])} schemas")
