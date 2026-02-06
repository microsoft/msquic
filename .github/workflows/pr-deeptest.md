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
  noop:
jobs:
  list-files:
    uses: ./.github/workflows/list-pr-files.yml
    with:
      pr_number: ${{ inputs.pr_number || github.event.pull_request.number }}
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

Analyze files changed in PR #${{ env.PR_NUMBER }} and generate comprehensive tests.

## PR Files to Analyze

The list of changed files is available at `${{ env.PR_FILES_PATH }}`.

Each file entry contains:
- `path`: The file path relative to the repository root
- `status`: One of `added`, `modified`, or `removed`

## Instructions

1. Read the PR files list from `${{ env.PR_FILES_PATH }}`
2. For each file in the `files` array, check the `status` field:
   - **`added`**: Analyze the new code and create comprehensive tests
   - **`modified`**: Analyze the changes and update/add tests to cover modifications
   - **`removed`**: Check if associated tests should be removed or updated
3. Create test cases following MsQuic test patterns in `src/test/`
4. Stage all new and modified test files with `git add`

## After Generating Tests

Check if there are staged changes using `git diff --cached --stat`.

If there are staged changes, use `create_pull_request` with:
- Title: "[DeepTest PR #${{ env.PR_NUMBER }}] Tests for changed files"
- Body: "Auto-generated tests for files changed in PR #${{ env.PR_NUMBER }} by DeepTest workflow run #${{ env.RUN_ID }}."
- Branch: "deeptest/pr-${{ env.PR_NUMBER }}_run-${{ env.RUN_ID }}"

If no staged changes, use `noop` with message "No test changes generated for PR #${{ env.PR_NUMBER }}."
