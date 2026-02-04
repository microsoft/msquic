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
steps:
  - name: Run DeepTest Agent
    run: |
      gh copilot --agent DeepTest -p "Generate comprehensive tests for the source file at $SOURCE_FILE. Analyze the file, identify testable functions, and create test cases following MsQuic test patterns in src/test/. After generating tests, stage all new and modified files with 'git add'. Do NOT commit or push." --allow-all-tools
    env:
      COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_GITHUB_TOKEN }}
safe-outputs:
  create-pull-request:
    title-prefix: ""
    labels: [automation, tests]
    draft: true
  noop:
---

# Create PR for DeepTest Results

The DeepTest agent has already run and staged any generated test files.

Check if there are staged changes using `git diff --cached --stat`.

If there are staged changes, use `create_pull_request` with:
- Title: "[DeepTest Run #${{ env.RUN_ID }}] Tests for ${{ env.SOURCE_FILE }}"
- Body: "Auto-generated tests for `${{ env.SOURCE_FILE }}` by DeepTest workflow run #${{ env.RUN_ID }}."
- Branch: "meiyang/${{ env.RUN_ID }}"

If no staged changes, use `noop` with message "No test changes generated."
