---
description: Analyze PR files and generate tests using DeepTest agent
on:
  pull_request:
    types: [opened, synchronize, reopened]
  workflow_dispatch:
    inputs:
      pr_number:
        description: 'Pull Request number to analyze'
        required: true
        type: number
      repo:
        description: 'Repository in owner/repo format (e.g., microsoft/msquic). Defaults to current repo.'
        required: false
        type: string
      filter:
        description: 'Regex pattern to filter file paths (e.g., "^src/.*" to include only src/)'
        required: false
        type: string
        default: '^src/.*'
  workflow_call:
    inputs:
      pr_number:
        description: 'Pull Request number to analyze'
        required: false
        type: number
      repo:
        description: 'Repository in owner/repo format (e.g., microsoft/msquic). Defaults to current repo.'
        required: false
        type: string
      filter:
        description: 'Regex pattern to filter file paths'
        required: false
        type: string
        default: '^src/.*'
permissions:
  contents: read
  pull-requests: read
  issues: read
roles: all
env:
  PR_NUMBER: ${{ inputs.pr_number || github.event.pull_request.number }}
  PR_REPO: ${{ inputs.repo || github.repository }}
  FILTER: ${{ inputs.filter || '^src/.*' }}
  RUN_ID: ${{ github.run_id }}
  PR_FILES_PATH: /tmp/pr-files.json
engine:
  id: copilot
  agent: DeepTest
safe-outputs:
  create-pull-request:
    title-prefix: ""
    labels: [automation, tests, deeptest]
    draft: true
    expires: 7d
  noop:
jobs:
  list-files:
    uses: ./.github/workflows/list-pr-files.yml
    permissions:
      contents: read
      pull-requests: read
    with:
      pr_number: ${{ fromJSON(inputs.pr_number || github.event.pull_request.number || '0') }}
      repo: ${{ inputs.repo || '' }}
      filter: ${{ inputs.filter || '^src/.*' }}
steps:
  - name: Download PR Files List
    uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16 # v4.1.8
    with:
      name: pr-files-list
      path: /tmp
  - name: Display PR Files
    run: |
      echo "PR Files to analyze:"
      cat /tmp/pr-files.json
---

# Generate Tests for PR Files with DeepTest

Analyze files changed in PR #${{ env.PR_NUMBER }} from repository `${{ env.PR_REPO }}` and generate comprehensive tests.

## PR Files to Analyze

The list of changed files is available at `${{ env.PR_FILES_PATH }}`.

Each file entry contains:
- `path`: The file path relative to the repository root
- `status`: One of `added`, `modified`, or `removed`

## Instructions

### Step 1: Determine Related Test Harnesses

Based on the files in the PR, identify related test harnesses:

1. Read the PR files list from `${{ env.PR_FILES_PATH }}`
2. For each file path, map to relevant test harnesses:
   - `src/core/*.c` → Test harnesses: `Basic*`, `Core*`, `Connection*`, `Stream*`
   - `src/core/cubic.c` → Test harnesses: `Cubic*`, `CongestionControl*`
   - `src/core/loss_detection.c` → Test harnesses: `Loss*`, `Recovery*`
   - `src/core/stream.c` → Test harnesses: `Stream*`
   - `src/core/connection.c` → Test harnesses: `Connection*`
   - `src/platform/*.c` → Test harnesses: `Platform*`, `Datapath*`

### Step 2: Create Tests for Each Changed File

1. For each file in the `files` array, check the `status` field:
   - **`added`**: Analyze the new code and create comprehensive tests
   - **`modified`**: Analyze the changes and update/add tests to cover modifications
   - **`removed`**: Check if associated tests should be removed or updated
2. Create test cases following MsQuic test patterns in `src/test/`
3. Stage all new and modified test files with `git add`

### Step 3: Create Report

Generate a markdown report based on the test generation output from Step 2:
- List of files analyzed
- Tests created or modified for each file
- Any files skipped and why

### Step 4: Create Pull Request

Check if there are staged changes using `git diff --cached --stat`.

If there are staged changes, use `create_pull_request` with:
- Title: "[DeepTest PR #${{ env.PR_NUMBER }}] Tests for changed files"
- Body: Include the following sections:
  - Summary: "Auto-generated tests for files changed in PR #${{ env.PR_NUMBER }} by DeepTest workflow run #${{ env.RUN_ID }}."
  - Report: The report from Step 3
  - List of test files added/modified
- Branch: "deeptest/pr-${{ env.PR_NUMBER }}_run-${{ env.RUN_ID }}"

If no staged changes, use `noop` with message "No test changes generated for PR #${{ env.PR_NUMBER }}."
