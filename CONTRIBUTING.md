# Contributing

Issues and pull requests are welcome. For a security problem, see `SECURITY.md` instead.

## Before a pull request

```sh
dotnet build -m:2                  # warnings are errors
scripts/fetch-test-vectors.sh      # once: the vectors the repository does not carry
dotnet test -m:2
scripts/lint.sh                    # commit messages, public text, F# formatting
```

`scripts/check-public.sh` fails on home paths, Windows user paths, private and CGNAT addresses, citations of internal notes, decisions, milestones or the list of missing features, and work item labels in parentheses. CI runs it with these patterns only. Maintainers also keep a list of private names outside the repository (`~/.config/eplix/private-names.txt`, or the path in `EPLIX_PRIVATE_NAMES`), which the same script checks when the file is there.

A change to the slashing protection, signing, the threshold combinator or an attestation verifier needs a test that fails without it. `scripts/ci.sh` runs the full set, including the smoke tests of the published binary.

## Style

- F# with 4-space indents and LF line endings (`.editorconfig`). Keep the core small: anything the core does not need to attest and propose safely goes in a module that the build can leave out.
- A new package needs a reason in `docs/dependencies.md`.
- Comments say what the code does or why, in plain words.
- Docs: plain technical English, short sentences, active voice, sentence-case headings. Numbers come from a measurement or a source, or are marked as estimates.
- F# formatting is Fantomas at the version `.config/dotnet-tools.json` pins. `scripts/check-format.sh --fix` formats the tree. CI fails on unformatted code.

## Commits

- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/): `type(scope)!: subject`, for example `fix(slashing): ...`, `feat(tee): ...`, `docs: ...`. Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`, `revert`, `style`. The subject is at most 72 characters and the second line is blank. A pull request title follows the same rules.
- No `Co-Authored-By` trailers and no "Generated with" lines.
- `scripts/check-commits.sh origin/main..HEAD` checks a branch; CI runs it on every pull request and push.
- `main` accepts signed commits only, enforced by a GitHub ruleset. Sign with an SSH or GPG key listed on your GitHub account.
- One logical change per commit.

## Licence

Eplix is licensed under Apache-2.0 (`LICENSE`). Contributions are accepted under the same licence.
