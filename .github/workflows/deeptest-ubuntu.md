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
roles: all
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
        gh copilot --agent DeepTest -p "Generate comprehensive tests for the source file at $SOURCE_FILE. Analyze the file, identify testable functions, and create test cases following MsQuic test patterns in src/test/. After generating tests:
        1. Create a new branch named 'deeptest-run-$RUN_ID'
        2. Commit all changes to that branch
        3. Push the branch to origin (you have write access via the GH_TOKEN)
        4. Then write a JSON line to $GH_AW_SAFE_OUTPUTS file with this exact format:
           {\"tool\":\"create_pull_request\",\"args\":{\"title\":\"[DeepTest Run #$RUN_ID] Tests for $SOURCE_FILE\",\"body\":\"Auto-generated tests for $SOURCE_FILE by DeepTest workflow run $RUN_ID\",\"branch\":\"deeptest-run-$RUN_ID\",\"labels\":[\"automation\",\"tests\"]}}
        This will trigger the safe_outputs job to create the PR." --allow-all-tools
safe-outputs:
  create-pull-request:
    title-prefix: "[DeepTest Run #${{ github.run_id }}] "
    labels: [automation, tests]
  noop:
---

{{#runtime-import agentics/deeptest-ubuntu.md}}
