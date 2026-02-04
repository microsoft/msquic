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
    - name: Save original HEAD
      run: |
        echo "ORIGINAL_HEAD=$(git rev-parse HEAD)" >> $GITHUB_ENV
    - name: Run DeepTest via Copilot CLI
      run: |
        echo "Invoking DeepTest custom agent for: $SOURCE_FILE (Run ID: $RUN_ID)"
        gh copilot --agent DeepTest -p "Generate comprehensive tests for the source file at $SOURCE_FILE. Analyze the file, identify testable functions, and create test cases following MsQuic test patterns in src/test/. After generating tests, stage all new and modified files with 'git add'. Do NOT commit or push - just generate the test code and stage the files." --allow-all-tools
    - name: Write safe-output for PR creation
      run: |
        CURRENT_HEAD=$(git rev-parse HEAD)
        echo "Original HEAD: $ORIGINAL_HEAD"
        echo "Current HEAD: $CURRENT_HEAD"
        
        # Check for any changes: new commits OR staged/unstaged changes
        HAS_COMMITS=false
        HAS_STAGED=false
        HAS_UNSTAGED=false
        
        if [ "$ORIGINAL_HEAD" != "$CURRENT_HEAD" ]; then
          HAS_COMMITS=true
          echo "New commits detected"
        fi
        
        if ! git diff --cached --quiet 2>/dev/null; then
          HAS_STAGED=true
          echo "Staged changes detected"
        fi
        
        if ! git diff --quiet 2>/dev/null; then
          HAS_UNSTAGED=true
          echo "Unstaged changes detected"
        fi
        
        if [ "$HAS_COMMITS" = "false" ] && [ "$HAS_STAGED" = "false" ] && [ "$HAS_UNSTAGED" = "false" ]; then
          echo "No changes detected, writing noop"
          echo '{"tool":"noop","args":{"message":"No test changes generated"}}' >> "$GH_AW_SAFE_OUTPUTS"
        else
          echo "Changes detected, writing PR creation request"
          # Stage any unstaged changes
          git add -A
          # Generate the git patch
          git diff --cached > /tmp/changes.patch
          echo "Patch size: $(wc -c < /tmp/changes.patch) bytes"
          # Write safe-output with embedded patch using base64
          PATCH_B64=$(base64 -w0 /tmp/changes.patch)
          PR_TITLE="[DeepTest Run #$RUN_ID] Tests for $SOURCE_FILE"
          PR_BODY="Auto-generated tests for $SOURCE_FILE by DeepTest workflow run #$RUN_ID. This PR was created automatically by the DeepTest agent."
          echo "{\"tool\":\"create_pull_request\",\"args\":{\"title\":\"$PR_TITLE\",\"body\":\"$PR_BODY\",\"patch\":\"$PATCH_B64\"}}" >> "$GH_AW_SAFE_OUTPUTS"
          echo "Safe-output written successfully"
        fi
safe-outputs:
  create-pull-request:
    title-prefix: ""
    labels: [automation, tests]
    draft: true
  noop:
---

{{#runtime-import agentics/deeptest-ubuntu.md}}
