#!/usr/bin/env bash
# Hand-written mutants of the slashing rules, the threshold combinator, signing domains and the
# duty checks: each must make at least one test fail. Works on a copy of HEAD (git archive) in a
# temporary directory, so the worktree is never touched. Each mutant builds and runs the whole
# test binary under a time limit. About 1 min per mutant; not part of scripts/ci.sh.
# Usage: scripts/mutants.sh [mutant number ...]   (default: all)
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git archive HEAD | tar -x -C "$work"
mkdir -p "$work/tests/vectors/.download"
cp -r tests/vectors/.download/. "$work/tests/vectors/.download/"
cd "$work"
timeout 900 dotnet build -c Debug -m:2 -nologo > build.log 2>&1 || { tail -20 build.log; echo "the unmutated copy does not build" >&2; exit 1; }
timeout 900 dotnet tests/Eplix.Tests/bin/Debug/net10.0/Eplix.Tests.dll --colours 0 --no-spinner > base.log 2>&1 || { echo "the unmutated suite fails" >&2; exit 1; }

# file@@@old@@@new, one mutant per line; \n stands for a line break. A mutant must still
# compile (the compiler already kills one that leaves a value unused or a match incomplete). The old text must occur
# exactly once in the file.
mutants=$(cat <<'EOF'
src/Eplix.Core/Slashing/Marks.fs@@@        | ValueSome b when slot > b.Slot -> Check.Allow@@@        | ValueSome b when slot >= b.Slot -> Check.Allow
src/Eplix.Core/Slashing/Marks.fs@@@        | ValueSome b when slot = b.Slot && b.Root = ValueSome root -> Check.Repeat@@@        | ValueSome b when slot = b.Slot && (b.Root = ValueSome root || true) -> Check.Repeat
src/Eplix.Core/Slashing/Marks.fs@@@        if source > target then@@@        if source > target + 1UL then
src/Eplix.Core/Slashing/Marks.fs@@@            | ValueSome a when source >= a.Source && target > a.Target -> Check.Allow@@@            | ValueSome a when target > a.Target -> Check.Allow
src/Eplix.Core/Slashing/Marks.fs@@@            | ValueSome a when source >= a.Source && target > a.Target -> Check.Allow@@@            | ValueSome a when source >= a.Source && target >= a.Target -> Check.Allow
src/Eplix.Core/Slashing/Marks.fs@@@            | ValueSome a when target = a.Target && source = a.RootSource && a.Root = ValueSome root -> Check.Repeat@@@            | ValueSome a when target = a.Target && source = a.RootSource && (a.Root = ValueSome root || true) -> Check.Repeat
src/Eplix.Core/Slashing/Marks.fs@@@        | ValueSome b when x.Slot > b.Slot -> { m with Block = ValueSome x }@@@        | ValueSome b when x.Slot < b.Slot -> { m with Block = ValueSome x }
src/Eplix.Core/Slashing/Marks.fs@@@            let source = max a.Source x.Source@@@            let source = min a.Source x.Source
src/Eplix.Core/Slashing/Marks.fs@@@                if x.Target > a.Target then@@@                if x.Target < a.Target then
src/Eplix.Core/Slashing/Marks.fs@@@                        Root = (if sameVote then a.Root else ValueNone) }@@@                        Root = (if sameVote || true then a.Root else ValueNone) }
src/Eplix.Core/Slashing/SlotMarks.fs@@@        | ValueSome b when slot > b.Slot -> Check.Allow@@@        | ValueSome b when slot >= b.Slot -> Check.Allow
src/Eplix.Core/Signing.fs@@@    Buffer.BlockCopy(forkDataRoot.Bytes, 0, d, 4, 28)@@@    Buffer.BlockCopy(forkDataRoot.Bytes, 4, d, 4, 28)
src/Eplix.Core/Signing.fs@@@    computeDomain domainType (spec.ForkAt epoch).Version genesisValidatorsRoot@@@    computeDomain domainType (spec.ForkAt(epoch + 1UL)).Version genesisValidatorsRoot
src/Eplix.Core/Backend.fs@@@        | Duty.Attestation d -> d.Target.Epoch@@@        | Duty.Attestation d -> spec.EpochOf d.Slot
src/Eplix.Core/Backend.fs@@@        | Duty.SyncSelectionProof d -> spec.EpochOf d.Slot@@@        | Duty.SyncSelectionProof d -> spec.EpochOf(if d.Slot > 0UL then d.Slot - 1UL else 0UL)
src/Eplix.Core/Backend.fs@@@        | Duty.VoluntaryExit _ -> Signing.computeDomain spec.DomainVoluntaryExit spec.ExitForkVersion gvr@@@        | Duty.VoluntaryExit x -> Signing.domainAt spec gvr spec.DomainVoluntaryExit x.Epoch
src/Eplix.Core/Backend.fs@@@        | Duty.ProposerPreferences p -> spec.EpochOf p.ProposalSlot@@@        | Duty.ProposerPreferences p -> spec.EpochOf(if p.ProposalSlot > 0UL then p.ProposalSlot - 1UL else 0UL)
src/Eplix.Core/Backend.fs@@@        | Duty.Block h -> spec.EpochOf h.Slot@@@        | Duty.Block h -> spec.EpochOf(h.Slot + 1UL)
src/Eplix.Core/Backend.fs@@@        | Attestation _\n        | Block _ -> true\n        | _ -> false\n\n    /// Kinds whose@@@        | Attestation _ -> true\n        | _ -> false\n\n    /// Kinds whose
src/Eplix.Core/Backend.fs@@@        | Duty.AggregateAndProof(s, _)\n@@@        | Duty.AggregateAndProof(s, _) -> spec.EpochOf s + 1UL\n
src/Eplix.Core/Threshold.fs@@@                return [ for KeyValue(k, c) in counts do if c >= m then { Key = k; Share = ValueNone } ]@@@                return [ for KeyValue(k, c) in counts do if c >= 1 then { Key = k; Share = ValueNone } ]
src/Eplix.Core/Threshold.fs@@@subsets sorted.Length m |>@@@subsets sorted.Length (max 1 (m - 1)) |>
src/Eplix.Core/Threshold.fs@@@                        elif result.IsNone && partials.Count + (n - received) < m then@@@                        elif result.IsNone && partials.Count + (n - received) < m - 1 then
src/Eplix.Core/Scheduler.fs@@@                | Ok data when data.Target.Epoch <> epoch || (data.Source.Epoch >= data.Target.Epoch && data.Target.Epoch > 0UL) ->@@@                | Ok data when data.Target.Epoch > epoch ->
src/Eplix.Core/Scheduler.fs@@@                        elif expectedFee.IsSome && expectedFee.Value <> payloadFee then@@@                        elif false then
src/Eplix.Core/Beacon/BeaconNodes.fs@@@        d.Slot = slot && d.Source.Epoch <= currentEpoch && d.Target.Epoch <= currentEpoch@@@        (d.Slot = slot || true) && d.Source.Epoch <= currentEpoch && d.Target.Epoch <= currentEpoch
src/Eplix.Core/Beacon/BeaconNodes.fs@@@        lock gate (fun () -> nodes |> Array.sortBy (fun n -> struct (n.Health.Rank, -n.Score, n.Order)))@@@        lock gate (fun () -> nodes |> Array.sortBy (fun n -> struct (-n.Score, n.Order)))
src/Eplix.Doppelganger/DoppelgangerModule.fs@@@                                | (true, s), (true, clean) when clean >= s + settings.Epochs ->@@@                                | (true, s), (true, clean) when clean + 1UL >= s + settings.Epochs ->
src/Eplix.Core/Pipeline.fs@@@            | KeyState.Halted _, d -> not d.IsSlashable@@@            | KeyState.Halted _, _ -> true
src/Eplix.Core/Runner.fs@@@                                            do! checkSpecs ct\n@@@                                            if false then do! checkSpecs ct\n
EOF
)

only=" $* "
total=0; killed=0; survived=(); broken=()
i=0
while IFS= read -r line; do
  i=$((i + 1))
  [ -z "$*" ] || [[ "$only" == *" $i "* ]] || continue
  total=$((total + 1))
  file=${line%%@@@*}; rest=${line#*@@@}
  old=${rest%%@@@*}; new=${rest#*@@@}
  cp "$file" "$file.orig"
  if ! python3 -I - "$file" "$old" "$new" <<'PY'
import sys
path = sys.argv[1]
old = sys.argv[2].replace("\\n", "\n")
new = sys.argv[3].replace("\\n", "\n")
s = open(path).read()
if s.count(old) != 1:
    sys.exit(f"mutant text found {s.count(old)} times in {path}")
open(path, "w").write(s.replace(old, new))
PY
  then
    broken+=("$i (text not found in $file)"); mv "$file.orig" "$file"; continue
  fi
  start=$(date +%s)
  if ! timeout 900 dotnet build -c Debug -m:2 -nologo > "build-$i.log" 2>&1; then
    broken+=("$i (does not build: $file)")
  elif timeout 900 dotnet tests/Eplix.Tests/bin/Debug/net10.0/Eplix.Tests.dll --colours 0 --no-spinner > "test-$i.log" 2>&1; then
    survived+=("$i: $file: $(echo "$new" | head -c 100)")
    echo "mutant $i SURVIVED ($(( $(date +%s) - start )) s): $file"
  else
    killed=$((killed + 1))
    failed=$(grep -a -c " ERR\]" "test-$i.log" || true)
    echo "mutant $i killed by $failed failing tests ($(( $(date +%s) - start )) s): $file"
  fi
  mv "$file.orig" "$file"
done <<< "$mutants"
echo "$killed of $total mutants killed"
for s in "${survived[@]}"; do echo "survived: $s"; done
for b in "${broken[@]}"; do echo "not run: $b"; done
[ ${#survived[@]} -eq 0 ] && [ ${#broken[@]} -eq 0 ]
