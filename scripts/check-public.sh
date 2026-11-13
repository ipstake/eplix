#!/usr/bin/env bash
# Fails if a tracked file, or a tracked path, names something private: home
# paths, Windows user paths, private or CGNAT address ranges, or citations of
# the internal design notes, decisions, milestones, the list of missing
# features, and work item labels. The regexes match across line breaks: each
# line's leading comment marker is dropped before the lines are joined.
#
# Maintainers also keep a list of private names outside the repository, one
# word or phrase per line, # for comments. The default path is
# ~/.config/eplix/private-names.txt; EPLIX_PRIVATE_NAMES overrides it. Names
# are compared as runs of [a-z0-9] words, lowercase, so "a-b", "a_b", "A B"
# and a name split over two comment lines all match. CI has no list and runs
# the regexes only.
#
# Allowed: the tee-signer Go import paths in tests/tools/tee-oracle, and
# the tee-signer repository named as a source in docs/design.md.
# Skipped: files that are not UTF-8 text, and the SSZ test vectors.
#
#   scripts/check-public.sh   check the tracked files
set -euo pipefail
cd "$(dirname "$0")/.."
script=$(cat <<'PY'
import bisect, os, re, subprocess, sys

WORD = re.compile(r"[a-z0-9]+")
BS = chr(92)  # a backslash


def load_names():
    path = os.environ.get("EPLIX_PRIVATE_NAMES") or os.path.expanduser("~/.config/eplix/private-names.txt")
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        print(f"check-public: no local name list ({path}), regexes only", file=sys.stderr)
        return set(), 0, 0
    names = set()
    for line in lines:
        words = WORD.findall(line.split("#", 1)[0].lower())
        if words:
            names.add("-".join(words))
    if not names:
        print(f"check-public: the local name list {path} is empty", file=sys.stderr)
        return set(), 0, 0
    print(f"check-public: {len(names)} names from {path}", file=sys.stderr)
    return names, max(n.count("-") + 1 for n in names), max(len(w) for n in names for w in n.split("-"))


NAMES, MAX_RUN, MAX_WORD = load_names()

# (what, regex, flags, file filter)
PATTERNS = [
    ("home path", r"/home/[A-Za-z0-9_.-]", 0, None),
    ("Windows user path", r"[A-Za-z]:[/" + BS + BS + r"]+Users\b", re.I, None),
    ("private address", r"\b192\.168\.\d", 0, None),
    ("CGNAT address", r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d", 0, None),
    ("design note citation", r"\bnotes?\s+#?\d", re.I, None),
    # A decision ID is a number, or a letter and a number.
    ("decision citation", r"\bdecisions?\s+#?[a-z]?\d", re.I, None),
    # The internal list of missing features, cited by item or as a whole.
    ("missing features citation", r"\bfeature[\s-]+gap\b", re.I, None),
    # A work item label in parentheses: one capital letter and one or two digits.
    ("item label", r"\([A-Z]\d{1,2}\)", 0, None),
    # SVG path data is full of move-to commands that look like milestones.
    ("milestone citation", r"\bM(?:\d|1\d)\b", 0, lambda p: not p.endswith(".svg")),
]
PATTERNS = [(w, re.compile(r, f), ok) for w, r, f, ok in PATTERNS]

# A line break plus the next line's indent and comment marker, if any.
JOIN = re.compile(r"[ \t]*\r?\n[ \t]*(?:///?|#+|\(\*|\*+|--|;+|>)?[ \t]*")
# The tee-signer repository, whose organisation name may be on the list: its
# Go import paths, and the design's source line.
ALLOW = {
    "tests/tools/tee-oracle/": re.compile(r"github\.com/[a-z0-9-]+/tee-signer\b"),
    "docs/design.md": re.compile(r"\b[a-z0-9-]+/tee-signer\b"),
}


def allowed(path, text):
    for prefix, rx in ALLOW.items():
        if path.startswith(prefix):
            text = rx.sub(lambda m: " " * len(m.group()), text)
    return text


def check(path, text, report):
    starts = [0] + [m.end() for m in re.finditer("\n", text)]
    line_of = lambda pos: bisect.bisect_right(starts, pos)
    lower = text.lower()
    # Words longer than any listed word are never part of a name; skipping
    # them keeps hex and base64 cheap.
    words = [m for m in WORD.finditer(lower) if len(m.group()) <= MAX_WORD] if NAMES else []
    for i, m in enumerate(words):
        for n in range(1, MAX_RUN + 1):
            if i + n > len(words):
                break
            if n > 1 and words[i + n - 1].start() - words[i + n - 2].end() > 8:
                break  # words far apart are not one name
            run = "-".join(w.group() for w in words[i:i + n])
            if run in NAMES:
                report(path, line_of(m.start()), "private name", text[m.start():words[i + n - 1].end()])
    # The regexes run on the joined text. offsets holds (start in joined,
    # start in text) of each kept piece, to map a match back to its line.
    pieces, offsets, last, size = [], [], 0, 0
    for m in JOIN.finditer(text):
        pieces += [text[last:m.start()], " "]
        offsets.append((size, last))
        size += m.start() - last + 1
        last = m.end()
    pieces.append(text[last:])
    offsets.append((size, last))
    joined = "".join(pieces)
    joined_starts = [o for o, _ in offsets]
    for what, rx, ok in PATTERNS:
        if ok and not ok(path):
            continue
        for m in rx.finditer(joined):
            k = bisect.bisect_right(joined_starts, m.start()) - 1
            src = offsets[k][1] + m.start() - offsets[k][0]
            report(path, line_of(src), what, m.group())


def main():
    out = subprocess.run(["git", "ls-files", "-z"], check=True, capture_output=True).stdout
    found = []
    report = lambda path, line, what, match: found.append(f"{path}:{line}: {what}: {match!r}")
    checked = 0
    for path in filter(None, out.decode().split("\0")):
        check(path, allowed(path, path), lambda p, l, w, m: report(p, 0, w + " in the path", m))
        if path.endswith((".ssz", ".ssz_snappy")):
            continue
        try:
            with open(path, "rb") as f:
                text = f.read().decode("utf-8")
        except (FileNotFoundError, IsADirectoryError):
            continue  # deleted in the work tree, or a submodule
        except UnicodeDecodeError:
            continue  # binary
        if "\0" in text:
            continue
        check(path, allowed(path, text), report)
        checked += 1
    for line in found:
        print(line)
    print(f"check-public: {checked} files, {len(found)} finding(s)", file=sys.stderr)
    sys.exit(1 if found else 0)


main()
PY
)
exec python3 -I -c "$script" "$@"
