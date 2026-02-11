---
description: Analyze PR files and generate tests using DeepTest agent
on:
  pull_request:
    types: [opened, synchronize]
permissions:
  contents: read
  pull-requests: read
  issues: read
roles: all
sandbox: false
strict: false
tools:
  bash: [":*"]
  edit:
  github:
env:
  PR_NUMBER: ${{ inputs.pr_number || github.event.pull_request.number }}
  PR_REPO: ${{ inputs.repo || github.repository }}
  FILTER: ${{ inputs.filter || '^src/.*' }}
  GH_AW_DIR: /tmp/gh-aw
  PR_FILES_PATH: /tmp/gh-aw/pr-files.json
  COVERAGE_RESULT_PATH: /tmp/gh-aw/coverage-result.md
engine:
  id: copilot
  agent: DeepTest
safe-outputs:
  create-pull-request:
    title-prefix: "[Deep Test]"
    labels: [deeptest]
    draft: true
    expires: 7d
  noop:

jobs:
  # workflow call cannot use env.* as input
  # and thus create a step to pass these
  # values directly to list-pr-files
  resolve-params-for-list-pr-files:
    runs-on: ubuntu-slim
    permissions:
      contents: read
    outputs:
      pr_number: ${{ env.PR_NUMBER }}
      pr_repo: ${{ env.PR_REPO }}
      filter: ${{ env.FILTER }}
    steps:
      - name: Export params
        run: echo "Resolved pr_number, pr_repo, filter"
  list-files:
    needs: resolve-params-for-list-pr-files
    uses: ./.github/workflows/list-pr-files.yml
    permissions:
      contents: read
      pull-requests: read
    with:
      # needs.resolve-params-for-list-pr-files.outputs.pr_number is always string type
      # need to convert to number type
      pr_number: ${{ fromJSON(needs.resolve-params-for-list-pr-files.outputs.pr_number) }}
      repo: ${{ needs.resolve-params-for-list-pr-files.outputs.pr_repo }}
      filter: ${{ needs.resolve-params-for-list-pr-files.outputs.filter }}
steps:
  - name: Checkout repository
    uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6
    with:
      fetch-depth: 1
  - name: Download PR Files List
    uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16 # v4.1.8
    with:
      name: pr-files-list
      path: ${{ env.GH_AW_DIR }}
post-steps:
  - name: Upload Coverage Result
    if: always()
    uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882 # v4.4.3
    with:
      name: coverage-result
      path: ${{ env.COVERAGE_RESULT_PATH }}
      if-no-files-found: ignore
---

# DeepTest + pwsh

Analyze files changed in PR #${{ env.PR_NUMBER }} from repository `${{ env.PR_REPO }}` and generate comprehensive tests.

## PR Files to Analyze

The list of changed files is available at `${{ env.PR_FILES_PATH }}`.

Each file entry contains:
- `path`: The file path relative to the repository root
- `status`: One of `added`, `modified`, or `removed`

## Instructions

You must never attempt to run `git push` as it is not supported in this environment.

1. Read the PR files list from `${{ env.PR_FILES_PATH }}`
   - **`added`**: Analyze the new code and create comprehensive tests
   - **`modified`**: Analyze the changes and update/add tests to cover modifications
   - **`removed`**: Check if associated tests should be removed or updated

2. For each file path, map to relevant test harnesses:
   - `src/core/*.c` → Test harnesses: `Basic*`, `Core*`, `Connection*`, `Stream*`
   - `src/core/cubic.c` → Test harnesses: `Cubic*`, `CongestionControl*`
   - `src/core/loss_detection.c` → Test harnesses: `Loss*`, `Recovery*`
   - `src/core/stream.c` → Test harnesses: `Stream*`
   - `src/core/connection.c` → Test harnesses: `Connection*`
   - `src/platform/*.c` → Test harnesses: `Platform*`, `Datapath*`

3. Store the coverage report at `${{ env.COVERAGE_RESULT_PATH }}`.

4. Prepare commit with `scripts/create-commit-for-safe-outputs.sh` and use `create_pull_request` with:
    - Title: "Tests for PR #${{ env.PR_NUMBER }}"
    - Body: workflow run ${{ github.run_id }}

5. If no staged changes, use `noop` with message "No test changes generated for PR #${{ env.PR_NUMBER }}."
