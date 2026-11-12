#!/usr/bin/env python3
"""Checks the operator files: contrib/prometheus/eplix-alerts.yml, contrib/grafana/eplix-dashboard.json
and docs/runbook.md, against each other and against the metrics a running VC serves.

A structure check; with PROMTOOL naming the binary it also runs
`promtool check rules` and `promtool test rules` on contrib/prometheus/eplix-alerts.test.yml:
- every rule parses and has an alert name, an expression, a severity (critical or warning), a
  summary and a runbook_url of docs/runbook.md#<alert in lower case>;
- docs/runbook.md has a section for every alert, and for every alert the rules file names in its
  comments as waiting for a metric;
- every eplix_ metric in the rules and the dashboard is one the VC serves (from a /metrics scrape,
  as contrib/systemd/sandbox-check.sh saves it), and every label a selector or a "by" names is one
  the scrape shows on that metric, where the scrape has samples of it;
- brackets balance in every expression, and dashboard panel ids are unique;
- every alert has a unit test in contrib/prometheus/eplix-alerts.test.yml.
Several scrapes may be given (the metrics smoke, the builder smoke); their union counts.
Usage: [PROMTOOL=<promtool>] python3 -I scripts/check-ops.py <metrics.txt>...
"""
import json
import os
import re
import subprocess
import sys

import yaml

root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
rules_file = os.path.join(root, "contrib", "prometheus", "eplix-alerts.yml")
dash_file = os.path.join(root, "contrib", "grafana", "eplix-dashboard.json")
runbook_file = os.path.join(root, "docs", "runbook.md")
problems = []

# The metric families and their label names, from the scrape.
families, labels = set(), {}
for line in (l for f in sys.argv[1:] for l in open(f)):
    m = re.match(r"# TYPE (\S+) (\S+)", line)
    if m:
        families.add(m.group(1))
        continue
    m = re.match(r"([a-z_]+)(\{([^}]*)\})? ", line)
    if m and not line.startswith("#"):
        names = set(re.findall(r"([a-z_]+)=", m.group(3) or ""))
        labels.setdefault(m.group(1), set()).update(names)


def family(name):
    for suffix in ("_bucket", "_sum", "_count"):
        if name.endswith(suffix) and name[: -len(suffix)] in families:
            return name[: -len(suffix)]
    return name


# Labels by family (bucket, sum and count samples count for their histogram).
by_family = {}
for name, names in labels.items():
    by_family.setdefault(family(name), set()).update(names)
TARGET = {"job", "instance"}


def check_expr(where, expr):
    depth = {"(": 0, "[": 0, "{": 0}
    pairs = {")": "(", "]": "[", "}": "{"}
    for c in re.sub(r'"[^"]*"', '""', expr):
        if c in depth:
            depth[c] += 1
        elif c in pairs:
            depth[pairs[c]] -= 1
            if depth[pairs[c]] < 0:
                problems.append(f"{where}: unbalanced {c}")
    if any(depth.values()):
        problems.append(f"{where}: unbalanced brackets")
    used = set()
    for m in re.finditer(r"\b(eplix_[a-z_]+)(\{([^}]*)\})?", expr):
        f = family(m.group(1))
        used.add(f)
        if f not in families:
            problems.append(f"{where}: {m.group(1)} is not a metric the VC serves")
            continue
        known = by_family.get(f)
        if known:
            for label in re.findall(r"([a-z_]+)\s*(?:=~|!=|!~|=)", m.group(3) or ""):
                if label not in known | TARGET:
                    problems.append(f"{where}: {m.group(1)} has no label {label}")
    known = set().union(*[by_family.get(f, set()) for f in used]) if used else set()
    if all(by_family.get(f) for f in used):
        for group in re.findall(r"\bby\s*\(([^)]*)\)", expr):
            for label in [x.strip() for x in group.split(",") if x.strip()]:
                if label not in known | TARGET | {"le"}:
                    problems.append(f"{where}: no metric in the expression has label {label}")


runbook = open(runbook_file).read()
sections = set(re.findall(r"^### (\S+)$", runbook, re.M))
rules = yaml.safe_load(open(rules_file))
alerts = []
for group in rules["groups"]:
    for rule in group["rules"]:
        name = rule.get("alert")
        if not name:
            problems.append(f"{group['name']}: a rule without an alert name")
            continue
        alerts.append(name)
        if rule.get("labels", {}).get("severity") not in ("critical", "warning"):
            problems.append(f"{name}: severity is not critical or warning")
        ann = rule.get("annotations", {})
        if not ann.get("summary"):
            problems.append(f"{name}: no summary")
        if ann.get("runbook_url") != f"docs/runbook.md#{name.lower()}":
            problems.append(f"{name}: runbook_url is not docs/runbook.md#{name.lower()}")
        if name not in sections:
            problems.append(f"{name}: no section in docs/runbook.md")
        check_expr(name, rule["expr"])
if len(alerts) != len(set(alerts)):
    problems.append("an alert name repeats")
comments = [l for l in open(rules_file) if l.lstrip().startswith("#")]
waiting = sorted(set(re.findall(r"\b(Eplix[A-Z][A-Za-z]+)\b", "".join(comments))))
for name in waiting:
    if name not in sections:
        problems.append(f"{name} (waiting for its metric): no section in docs/runbook.md")

dash = json.load(open(dash_file))
ids = [p["id"] for p in dash["panels"]]
if len(ids) != len(set(ids)):
    problems.append("dashboard: panel ids repeat")
exprs = 0
for p in dash["panels"]:
    for t in p.get("targets", []):
        exprs += 1
        check_expr(f"dashboard panel '{p['title']}'", t["expr"].replace("$job", "eplix").replace("$instance", ".*"))

# Rule unit tests: every alert fires in contrib/prometheus/eplix-alerts.test.yml, and with
# PROMTOOL set, promtool checks the rules and runs the tests.
tests_file = os.path.join(root, "contrib", "prometheus", "eplix-alerts.test.yml")
tested = set(re.findall(r"alertname: (Eplix[A-Za-z]+)", open(tests_file).read()))
for name in alerts:
    if name not in tested:
        problems.append(f"{name}: no unit test in eplix-alerts.test.yml")
promtool = os.environ.get("PROMTOOL")
if promtool:
    for args in (["check", "rules", rules_file], ["test", "rules", tests_file]):
        r = subprocess.run([promtool] + args, capture_output=True, text=True, cwd=os.path.dirname(rules_file))
        if r.returncode != 0:
            problems.append(f"promtool {args[0]} rules failed:\n{r.stdout}{r.stderr}")

for p in problems:
    print(p)
print(f"{len(alerts)} alerts, {len(waiting)} waiting for their metric, {len(dash['panels'])} panels, {exprs} panel queries, {len(problems)} problems")
sys.exit(1 if problems else 0)
