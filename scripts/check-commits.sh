#!/usr/bin/env bash
# Checks commit messages against the rules in CONTRIBUTING.md:
# - the subject is a Conventional Commit, `type(scope)!: subject`, with one
#   of the types below, at most 72 characters;
# - the second line, if any, is blank;
# - no Co-Authored-By trailer and no "Generated with" line.
# Merge commits in a range are skipped; a single commit is checked as given.
#
#   scripts/check-commits.sh origin/main..HEAD   every commit in a range
#   scripts/check-commits.sh <sha>               one commit
#   scripts/check-commits.sh --subject "text"    one subject line (a PR title)
set -euo pipefail

types='feat|fix|perf|refactor|docs|test|build|ci|chore|revert|style'
subject_re="^($types)(\([a-z0-9][a-z0-9._/-]*(,[a-z0-9][a-z0-9._/-]*)*\))?!?: [^ ](.*[^ ])?\$"
max_len=72

# check_subject WHAT SUBJECT: prints the problems, returns 1 if there are any.
check_subject() {
  local what=$1 subject=$2 bad=0
  if ! [[ $subject =~ $subject_re ]]; then
    echo "$what: not a Conventional Commit subject (type(scope)!: subject, types $types): $subject" >&2
    bad=1
  fi
  if (( ${#subject} > max_len )); then
    echo "$what: subject is ${#subject} characters, the limit is $max_len: $subject" >&2
    bad=1
  fi
  return $bad
}

if [[ ${1:-} == --subject ]]; then
  (( $# == 2 )) || { echo "usage: $0 --subject TEXT" >&2; exit 2; }
  check_subject "title" "$2"
  exit
fi

(( $# == 1 )) || { echo "usage: $0 <base>..<head> | <commit> | --subject TEXT" >&2; exit 2; }
if [[ $1 == *..* ]]; then
  commits=$(git rev-list --no-merges --reverse "$1")
else
  git rev-parse -q --verify "$1^{commit}" > /dev/null || { echo "not a commit: $1" >&2; exit 2; }
  commits=$(git rev-parse "$1^{commit}")  # checked even if it is a merge
fi

fail=0 count=0
for c in $commits; do
  count=$((count + 1))
  short=$(git rev-parse --short "$c")
  msg=$(git log -1 --format=%B "$c")
  check_subject "$short" "$(head -n 1 <<< "$msg")" || fail=1
  if [[ $(sed -n 2p <<< "$msg") =~ [^[:space:]] ]]; then
    echo "$short: the second line must be blank" >&2
    fail=1
  fi
  if grep -qiE '^[[:space:]]*co-authored-by:' <<< "$msg"; then
    echo "$short: has a Co-Authored-By trailer" >&2
    fail=1
  fi
  if grep -qi 'generated with' <<< "$msg"; then
    echo "$short: has a \"Generated with\" line" >&2
    fail=1
  fi
done
echo "checked $count commit(s)" >&2
exit $fail
