---
description: Generate tests for the files changed in a PR using Copilot CLI with the DeepTest custom agent
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
  workflow_dispatch:
    inputs:
      pr_number:
        description: "Pull request number (required when manually dispatching)"
        required: true
        type: string
      max_files:
        description: "Max number of changed files to include"
        required: false
        default: "10"
        type: string
      include_regex:
        description: "grep -E include filter (applied to path list)"
        required: false
        default: "^src/"
        type: string
      exclude_regex:
        description: "grep -E exclude filter (applied to path list)"
        required: false
        default: "(\\.md$|\\.ya?ml$|\\.json$|\\.txt$|^docs/|^submodules/|^src/test/)"
        type: string
permissions:
  contents: read
  pull-requests: read
  issues: read
strict: false
env:
  GH_TOKEN: ${{ github.token }}
  COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_GITHUB_TOKEN }}
  RUN_ID: ${{ github.run_id }}
  PR_NUMBER: ${{ github.event.pull_request.number || github.event.inputs.pr_number }}
  MAX_FILES: ${{ github.event.inputs.max_files || '10' }}
  INCLUDE_REGEX: ${{ github.event.inputs.include_regex || '^src/' }}
  EXCLUDE_REGEX: ${{ github.event.inputs.exclude_regex || '(\\.md$|\\.ya?ml$|\\.json$|\\.txt$|^docs/|^submodules/|^src/test/)' }}
engine:
  id: custom
  steps:
    - name: Install Copilot CLI
      run: |
        gh extension install github/gh-copilot || echo "Copilot CLI already installed"

    - name: Collect changed files from PR
      run: |
        set -euo pipefail
        if [ -z "${PR_NUMBER:-}" ]; then
          echo "PR_NUMBER is required" >&2
          exit 1
        fi

        echo "Fetching changed files for PR #$PR_NUMBER in $GITHUB_REPOSITORY"
        ALL_FILES="$(gh api \"repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER/files\" --paginate --jq '.[].filename')"

        echo "$ALL_FILES" > /tmp/changed_files_all.txt

        FILTERED_FILES="$(printf '%s\n' "$ALL_FILES" \
          | grep -E "$INCLUDE_REGEX" \
          | grep -Ev "$EXCLUDE_REGEX" \
          | grep -E '\\.(c|h|cc|cpp|cxx|hpp|rs)$' \
          | head -n "$MAX_FILES" || true)"

        if [ -z "$FILTERED_FILES" ]; then
          echo "No matching source files after filters; falling back to first $MAX_FILES changed files."
          FILTERED_FILES="$(printf '%s\n' "$ALL_FILES" | head -n "$MAX_FILES" || true)"
        fi

        printf '%s\n' "$FILTERED_FILES" > /tmp/changed_files.txt

        echo "CHANGED_FILES<<EOF" >> "$GITHUB_ENV"
        cat /tmp/changed_files.txt >> "$GITHUB_ENV"
        echo "EOF" >> "$GITHUB_ENV"

        echo "Selected files:" 
        cat /tmp/changed_files.txt

    - name: Run DeepTest via Copilot CLI
      run: |
        set -euo pipefail
        echo "Invoking DeepTest for PR #$PR_NUMBER (Run ID: $RUN_ID)"

        CHANGED_FILES_BULLETS="$(sed 's/^/- /' /tmp/changed_files.txt | tr '\n' '\r')"
        # Convert back to newlines inside the prompt reliably
        CHANGED_FILES_BULLETS="$(printf '%b' "${CHANGED_FILES_BULLETS//\r/\n}")"

        gh copilot --agent DeepTest --allow-all-tools -p "You are generating tests for PR #$PR_NUMBER in $GITHUB_REPOSITORY.\n\nFocus on these changed files (filtered, up to $MAX_FILES):\n$CHANGED_FILES_BULLETS\n\nRequirements:\n- Follow MsQuic test patterns in src/test/. Prefer adding or updating focused tests for behavior changes.\n- Cover error paths and boundary conditions; avoid flaky timing-dependent tests.\n- Make minimal changes outside tests unless necessary for testability.\n- Create a PR with all test changes; include workflow run ID $RUN_ID in the PR title."
safe-outputs:
  create-pull-request:
    title-prefix: "[DeepTest PR Changes Run #${{ github.run_id }}] "
    labels: [automation, tests]
  noop:
---

{{#runtime-import agentics/deeptest-pr-changes.md}}
