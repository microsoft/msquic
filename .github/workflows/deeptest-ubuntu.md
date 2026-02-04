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
        gh copilot --agent DeepTest -p "Generate comprehensive tests for the source file at $SOURCE_FILE. Analyze the file, identify testable functions, and create test cases following MsQuic test patterns in src/test/. After generating tests, commit all changes locally. Do NOT create a PR - just generate and commit the test code." --allow-all-tools
    - name: Create branch and push changes
      run: |
        BRANCH_NAME="deeptest-run-$RUN_ID"
        echo "Creating branch: $BRANCH_NAME"
        
        # Check if there are any changes to commit
        if git diff --quiet && git diff --cached --quiet; then
          echo "No changes detected, skipping branch creation"
          echo "NO_CHANGES=true" >> $GITHUB_ENV
        else
          git checkout -b "$BRANCH_NAME"
          git add -A
          git commit -m "[DeepTest Run #$RUN_ID] Add tests for $SOURCE_FILE" || echo "Nothing to commit"
          git push origin "$BRANCH_NAME"
          echo "BRANCH_NAME=$BRANCH_NAME" >> $GITHUB_ENV
          echo "NO_CHANGES=false" >> $GITHUB_ENV
        fi
    - name: Write safe-output for PR creation
      run: |
        if [ "$NO_CHANGES" = "true" ]; then
          echo "No changes to create PR for, writing noop"
          echo '{"tool":"noop","args":{"message":"No test changes generated"}}' >> "$GH_AW_SAFE_OUTPUTS"
        else
          echo "Writing PR creation request to safe-outputs"
          cat >> "$GH_AW_SAFE_OUTPUTS" << EOF
        {"tool":"create_pull_request","args":{"title":"Tests for $SOURCE_FILE","body":"Auto-generated tests for $SOURCE_FILE by DeepTest workflow run #$RUN_ID","branch":"$BRANCH_NAME","labels":["automation","tests"]}}
        EOF
          echo "Safe-output written successfully"
          cat "$GH_AW_SAFE_OUTPUTS"
        fi
safe-outputs:
  create-pull-request:
    title-prefix: "[DeepTest Run #${{ github.run_id }}] "
    labels: [automation, tests]
  noop:
---

{{#runtime-import agentics/deeptest-ubuntu.md}}
