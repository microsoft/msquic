---
name: cherry-pick-to-release
description: 'Cherry-pick a merged main-branch PR onto a MsQuic release branch (e.g. release/2.4, release/2.5) following the project''s established conventions.'
---

# Cherry-Pick to MsQuic Release Branch

You are helping a maintainer back-port a fix from `main` to one or more
MsQuic release branches (`release/2.4`, `release/2.5`, etc.).

This skill encodes the patterns the project actually uses — derived from
recent cherry-pick PRs and commits on `release/2.4` and `release/2.5`.

## When This Skill Activates

The user asks to cherry-pick / back-port / "CP" a PR or commit from `main`
onto a release branch. Typical requests:

- "Cherry-pick #5942 to release/2.4 and release/2.5"
- "Back-port the ACK underflow fix to 2.5"
- "CP this commit to the 2.4 release branch"

## Inputs You Need

Before doing anything, make sure you know:

1. **Source**: a PR number on `main` (preferred) or a commit SHA on `origin/main`.
2. **Target release branch(es)**: e.g. `release/2.4`, `release/2.5`. If the
   user is ambiguous (e.g. "to the release branches"), ask whether they want
   one branch or both, and which.
3. **Whether to push / open a PR**. Per the user's standing rule, you must
   never push a branch or open a PR without explicit permission. Stop and
   ask before any `git push` or `gh pr create`.

If anything is missing, ask before proceeding.

## Project Conventions (must follow)

These were inferred from ~30 recent cherry-pick PRs to `release/2.4` and
`release/2.5`. Match them exactly unless the user tells you otherwise.

### PR Title

Dominant pattern:

```
[CP] <Original PR title> (#<original_pr_number>)
```

Examples actually used on the release branches:

- `[CP] Fix underflow in ACK frame parsing #5942`            (→ PR #5943 on 2.5, #5944 on 2.4)
- `[CP] Fix SAL annotation placement on function templates (#5895)`
- `[CP] Free AES 256 GCM algorithm handle on cleanup (#5526)`
- `[CP] Fix double deref in connection pool error path (#5597)`

When the same fix targets multiple release branches, the title is identical
across PRs; only the target branch differs. After squash-merge, GitHub
appends the new PR number, producing commits like
`[CP] Fix underflow in ACK frame parsing #5942 (#5943)` on the release
branch — this is expected and required (it makes traceability trivial).

Acceptable variants (use only if the user prefers them or the situation
calls for it):

- `[CP v2.5] <title> (#<orig_pr>)` — when the target branch needs to be
  explicit in the title.
- `[CP] <title A> (#<prA>) + <title B> (#<prB>)` — multi-PR cherry-pick in
  one branch.
- `CP: <title> (#<orig_pr>)` / `Cherry-pick: <title> (#<orig_pr>)` —
  older style, still accepted.

Do **not** invent new prefixes; stick to `[CP]` unless asked.

### PR Body

**Use the exact body of the original PR, verbatim**, including the
`## Description`, `## Testing`, and `## Documentation` sections as the
original author wrote them. Do **not** rewrite, summarize, or augment them
with cherry-pick commentary.

Allowed additions, kept *outside* the verbatim original body:

- A single short prefix line (above the original `## Description`)
  identifying this as a cherry-pick, e.g. `Cherry-pick of #<orig_pr>` or
  `Cherry-pick of #<orig_pr> to release 2.5`.
- A companion-PR cross-reference when cherry-picking the same fix to
  multiple branches (e.g. `Companion PR for release/2.4: #<sibling>`).
  Add this as a separate trailing line, not inside the original sections.

If the original PR description references an upstream issue, keep the
`Fixes #<issue>` line so the issue closes when the cherry-pick merges.

If tests from the original PR could not be back-ported, do **not** alter
the original `## Testing` section. Instead, mention it in the cherry-pick
prefix line above the body (e.g.
`Cherry-pick of #<orig_pr>. Tests not back-ported — they rely on changes
present only in main.`).

### Branch Naming

Project convention (observed on most recent cherry-pick PRs):

```
<user>/cp_<short_description>_<target_version>
```

For the current user (`@guhetier_microsoft`), the additional standing
rule is that branches created by Copilot must end in `_copilot`. Combine
both → use:

```
guhetier/cp_<short_description>_2_5_copilot
guhetier/cp_<short_description>_2_4_copilot
```

The `<short_description>` is a snake_case summary of the fix, mirroring
prior branches like `cp_conn_pool_deref`, `cp_free_aes_256_gcm_handle`,
`underflow_fix_cp`.

Use one branch per target release branch (do not try to land both
release branches from a single branch / PR).

### Commits Inside the PR

- Almost always **one commit** — the cherry-picked commit, with its
  original message preserved.
- Occasionally a **second commit** is acceptable if needed to make the
  release branch build/pass tests (e.g. `Add missing variable definition`,
  `Upgrade perl action`). Keep these tightly scoped to enabling the
  cherry-pick; do **not** sneak in unrelated changes.
- Squash-merge erases the multi-commit structure on the release branch.
- Do **not** add `(cherry picked from commit X)` trailers — the project
  doesn't use `git cherry-pick -x`; traceability comes from the PR title
  containing the original PR number.

## Workflow

Follow these steps in order. Do not skip a phase.

### Phase 1 — Identify the source commit on main

1. If given a PR number, find its squash-merge commit on `origin/main`:
   ```powershell
   gh pr view <orig_pr> --repo microsoft/msquic --json mergeCommit,state,title,body,baseRefName
   ```
   Verify `state == MERGED` and `baseRefName == main`. If not merged, stop and tell the user — never cherry-pick an unmerged change.
2. If given a SHA, confirm it is reachable from `origin/main`:
   ```powershell
   git --no-pager log -1 --format="%H %s" <sha>
   git --no-pager branch -r --contains <sha> | Select-String "origin/main"
   ```
3. Capture the original PR title and body — you'll reuse them.

### Phase 2 — Prepare the local branch

Repeat for each target release branch.

1. Make sure the working tree is clean (`git status`). If not, stop and ask.
2. Fetch latest refs: `git fetch origin --prune`.
3. Create the branch from the tip of the release branch:
   ```powershell
   git checkout -b guhetier/cp_<short_desc>_2_5_copilot origin/release/2.5
   ```

### Phase 3 — Apply the cherry-pick

1. Run `git cherry-pick <commit_sha>` (no `-x`).
2. **On conflicts**:
   - Resolve them, keeping the spirit of the original fix.
   - If the conflict is non-trivial, briefly summarize the resolution in the PR body under `## Description` so reviewers know what differs from `main`.
   - If the fix depends on code that doesn't exist on the release branch, **stop and ask the user** how to proceed (skip, adapt, or pull in additional commits) — do not silently rewrite the fix.
3. If the original change touched tests that depend on main-only APIs and they don't apply cleanly, you may drop those test changes and note `Test not backported as they rely on changes present only in main` in the PR body. Try to keep at least one regression test when feasible.

### Phase 4 — Regenerate derived files (only if applicable)

Check whether the cherry-pick touches things that require regeneration. CI
will fail otherwise (`check-clog.yml`, `check-dotnet.yml`).

- **Trace / log macro changes** (`QuicTraceLogInfo`, `QuicTraceEvent`,
  etc., or anything under `src/manifest/`):
  ```powershell
  ./scripts/update-sidecar.ps1
  ```
  Commit any changes under `src/generated/` and `src/manifest/clog.sidecar` as part of the same commit (or amend).

- **Public C API surface changes** (anything under `src/inc/`, especially `msquic.h`):
  ```powershell
  ./scripts/generate-dotnet.ps1
  ```
  Commit any changes under `src/cs/`.

If neither applies, skip this phase.

### Phase 5 — Build and run tests locally (REQUIRED)

Build and run tests locally before pushing. This is **required for every
cherry-pick**, regardless of whether the `git cherry-pick` was clean or
required conflict resolution. Do not skip this phase.

1. **Build** with the default TLS provider for the platform you're on:
   ```powershell
   ./scripts/build.ps1 -Tls schannel    # Windows
   pwsh ./scripts/build.ps1 -Tls openssl # Linux
   ```
   If the cherry-pick touches OpenSSL- or QuicTLS-specific code on
   Windows, also build with `-Tls openssl` / `-Tls quictls` (requires
   Perl + NASM).

2. **Run the tests that exercise the cherry-picked code.** Use a
   GoogleTest `--Filter` to keep the runtime short:
   ```powershell
   ./scripts/test.ps1 -Tls schannel -Filter '<TestSuite>.<TestPattern>*'
   ```
   At minimum, run:
   - the tests that were added or modified by the cherry-pick, and
   - the tests directly covering the changed code paths (e.g.
     `TlsTest.*` for `src/platform/tls_*`, `ApiTest.*` for `src/inc/`
     surface changes, `HandshakeTest.*` for `src/core/` handshake logic).
   For pure CI / build-system cherry-picks where no functional tests
   apply, run a representative smoke test (e.g. one BVT) and note that
   in the PR body.

3. If the build or the relevant tests fail on the release branch but
   pass on `main`, **stop and ask the user** — do not push a broken
   cherry-pick. Likely causes: missing prerequisite commits, API drift
   between branches, or test infra changes that didn't get back-ported.

Capture the build and test outcome (pass/fail, number of tests run) to
mention briefly when you ask for permission to push.

### Phase 6 — Push and open the PR (gated on explicit user permission)

Stop here and confirm with the user before pushing. Then:

1. Push the branch:
   ```powershell
   git push -u origin guhetier/cp_<short_desc>_2_5_copilot
   ```
2. Open the PR as a **draft** (per the user's standing rule, unless they say otherwise):
   ```powershell
   gh pr create --repo microsoft/msquic `
     --base release/2.5 `
     --head guhetier/cp_<short_desc>_2_5_copilot `
     --draft `
     --title "[CP] <Original title> (#<orig_pr>)" `
     --body-file <path_to_body.md>
   ```
   - `--base` must be the release branch (`release/2.4`, `release/2.5`, …), **not** `main`.
3. If cherry-picking to multiple release branches, repeat phases 2–6 for each branch. Open one PR per branch; mention the sibling PR number in each body so reviewers can correlate them (e.g. `Companion PR for release/2.4: #5944`).

## Self-Verification Checklist

Before telling the user the cherry-pick is ready:

- [ ] PR `--base` is the correct `release/X.Y` branch (never `main`).
- [ ] PR title is `[CP] <orig title> (#<orig_pr>)` (or an explicitly approved variant).
- [ ] PR body uses the **exact body of the original PR verbatim**, optionally with a single `Cherry-pick of #<orig_pr>` prefix line and a companion-PR cross-reference. No rewritten / summarized descriptions.
- [ ] Branch name follows `guhetier/cp_<short_desc>_<X_Y>_copilot`.
- [ ] PR is opened as a draft.
- [ ] Only the cherry-picked commit (+ optional minimal build-fix commits) is on the branch — no unrelated changes.
- [ ] **Local build succeeded** on the release branch with the cherry-pick applied (Phase 5).
- [ ] **Relevant tests were run locally and pass** (Phase 5). The exact test filter and result are mentioned when asking the user for permission to push.
- [ ] If trace/log macros were touched → `scripts/update-sidecar.ps1` was run and generated files committed.
- [ ] If `src/inc/` public headers were touched → `scripts/generate-dotnet.ps1` was run and generated files committed.
- [ ] For multi-branch cherry-picks, one PR per release branch (not a single PR targeting multiple branches).
- [ ] You obtained explicit user permission before pushing and opening the PR.

## Anti-Patterns to Avoid

- **Don't** cherry-pick a PR that isn't merged on `main` yet.
- **Don't** target both `release/2.4` and `release/2.5` from a single PR.
- **Don't** use `git cherry-pick -x` — the project doesn't include
  `(cherry picked from commit X)` trailers in the final commit message.
- **Don't** bundle unrelated fixes into the same cherry-pick PR. If you
  see a related-but-distinct issue, open a separate cherry-pick.
- **Don't** invent a new title prefix (e.g. `[BACKPORT 2.5]`) — stick to
  `[CP]` to stay consistent with the last ~2 years of cherry-pick PRs.
- **Don't** silently drop test changes. If you skip back-porting tests,
  call it out explicitly in `## Testing`.
- **Don't** rewrite, summarize, or paraphrase the original PR's
  description. The body must contain the original PR's body verbatim
  (you may prepend a short `Cherry-pick of #<orig_pr>` line and append a
  companion-PR cross-reference, but the original sections themselves
  stay intact).
- **Don't** skip the local build / test step (Phase 5), even when the
  cherry-pick applied with no conflicts. Auto-merged hunks can still
  produce subtly wrong code.
- **Don't** push or open a PR without explicit user permission.
- **Don't** bump the version number as part of a cherry-pick PR —
  version bumps (`Bump version to v2.5.X`) are separate PRs done at
  release time.

## Non-Goals

- Triaging whether a fix *should* be cherry-picked. The user decides
  that; this skill just executes the cherry-pick cleanly.
- Releasing / tagging / publishing artifacts. Those are separate
  processes handled outside this skill.
