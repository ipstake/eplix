#!/usr/bin/env python3
"""Extracts the request examples of remote-signing-api's signing/paths/sign.yaml into JSON.

Reads the YAML as data (PyYAML safe_load) and writes [{"name": ..., "value": ...}, ...] in file
order. The output is tests/fixtures/remote-signing-api/sign-examples.json (CC0-1.0, as the API).
Usage: python3 -I scripts/remote-signing-examples.py <sign.yaml> <out.json>
"""
import json
import sys

import yaml

with open(sys.argv[1]) as f:
    doc = yaml.safe_load(f)
examples = doc["post"]["requestBody"]["content"]["application/json"]["examples"]
out = [{"name": name, "value": ex["value"]} for name, ex in examples.items()]
with open(sys.argv[2], "w") as f:
    json.dump(out, f, indent=1, sort_keys=False)
    f.write("\n")
print(f"{len(out)} examples")
