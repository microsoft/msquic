---
description: Generate tests for a user-specified source file using Copilot CLI with DeepTest custom agent
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
strict: false
env:
  GH_TOKEN: ${{ github.token }}
  COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_GITHUB_TOKEN }}
  SOURCE_FILE: ${{ inputs.source_file || github.event.inputs.source_file || 'src/core/loss_detection.c' }}
  RUN_ID: ${{ github.run_id }}
engine:
  id: custom
  steps:
    - name: Install Copilot CLI
      run: |
        gh extension install github/gh-copilot || echo "Copilot CLI already installed"
    - name: Run DeepTest via Copilot CLI
      run: |
        echo "Invoking DeepTest custom agent for: $SOURCE_FILE (Run ID: $RUN_ID)"
        gh copilot --agent DeepTest -p "Generate comprehensive tests for the source file at $SOURCE_FILE. Analyze the file, identify testable functions, and create test cases following MsQuic test patterns in src/test/. After generating tests, create a PR with all changed files. Include the workflow run ID $RUN_ID in the PR title." --allow-all-tools
safe-outputs:
  create-pull-request:
    title-prefix: "[DeepTest Run #${{ github.run_id }}] "
    labels: [automation, tests]
  noop:
---

{{#runtime-import agentics/deeptest-ubuntu.md}}
