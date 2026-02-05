---
description: Generate tests for a user-specified source file using DeepTest agent
on:
  workflow_dispatch:
    inputs:
      source_file:
        description: "Relative path to the source file (e.g., src/core/connection.c)"
        required: true
        type: string
  workflow_call:
    inputs:
      source_file:
        description: "Relative path to the source file (e.g., src/core/connection.c)"
        required: false
        type: string
permissions:
  contents: read
  pull-requests: read
  issues: read
roles: all
env:
  SOURCE_FILE: ${{ inputs.source_file || github.event.inputs.source_file }}
  RUN_ID: ${{ github.run_id }}
engine:
  id: copilot
  agent: DeepTest
safe-outputs:
  create-pull-request:
    title-prefix: ""
    labels: [automation, tests]
    draft: true
  noop:
---

# Generate Tests with DeepTest

Generate comprehensive tests for the source file at `${{ env.SOURCE_FILE }}`.

## Instructions

1. Analyze the source file to identify testable functions
2. Create test cases following MsQuic test patterns in `src/test/`
3. Stage all new and modified test files with `git add`

## After Generating Tests

Check if there are staged changes using `git diff --cached --stat`.

If there are staged changes, use `create_pull_request` with:
- Title: "[DeepTest Run #${{ env.RUN_ID }}] Tests for ${{ env.SOURCE_FILE }}"
- Body: "Auto-generated tests for `${{ env.SOURCE_FILE }}` by DeepTest workflow run #${{ env.RUN_ID }}."
- Branch: "meiyang/${{ env.RUN_ID }}"

If no staged changes, use `noop` with message "No test changes generated."
