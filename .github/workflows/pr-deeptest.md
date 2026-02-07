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
    permissions:
      contents: read
      pull-requests: read
    with:
      pr_number: ${{ fromJSON(inputs.pr_number || github.event.pull_request.number || '0') }}
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
  - name: Install PowerShell
    run: |
      # Check if pwsh is available
      if command -v pwsh &> /dev/null; then
          echo "PowerShell already installed:"
          pwsh --version
      else
          echo "PowerShell not found, checking common paths..."
          if [ -f /usr/bin/pwsh ]; then
              echo "Found pwsh at /usr/bin/pwsh, adding to PATH"
              export PATH="/usr/bin:$PATH"
          else
              echo "Installing PowerShell..."
              sudo apt-get update
              sudo apt-get install -y wget
              source /etc/os-release
              wget -q "https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/packages-microsoft-prod.deb"
              sudo dpkg -i packages-microsoft-prod.deb
              rm packages-microsoft-prod.deb
              sudo apt-get update
              sudo apt-get install -y powershell
          fi
          pwsh --version
      fi
---

# Generate Tests for PR Files with DeepTest

Analyze files changed in PR #${{ env.PR_NUMBER }} and generate comprehensive tests.

## PR Files to Analyze

The list of changed files is available at `${{ env.PR_FILES_PATH }}`.

Each file entry contains:
- `path`: The file path relative to the repository root
- `status`: One of `added`, `modified`, or `removed`

## Step 1: Determine Related Test Suites

Based on the files in the PR, identify related test suites to run:

1. Read the PR files list from `${{ env.PR_FILES_PATH }}`
2. For each file path, map to relevant test suites:
   - `src/core/*.c` → Test suites: `Basic*`, `Core*`, `Connection*`, `Stream*`
   - `src/core/cubic.c` → Test suites: `Cubic*`, `CongestionControl*`
   - `src/core/loss_detection.c` → Test suites: `Loss*`, `Recovery*`
   - `src/core/stream.c` → Test suites: `Stream*`
   - `src/core/connection.c` → Test suites: `Connection*`
   - `src/platform/*.c` → Test suites: `Platform*`, `Datapath*`
   - `src/test/lib/*.cpp` → Run the specific test file's suite
3. Construct a gtest filter expression combining the relevant suites (e.g., `"Cubic*:Stream*:Connection*"`)
4. Save this filter for use in coverage commands

## Step 2: Measure Baseline Code Coverage

Before generating new tests, measure the current test coverage as a baseline:

1. **Prepare Machine**:
   ```bash
   pwsh scripts/prepare-machine.ps1 -ForBuild -ForTest -InstallCodeCoverage
   ```

2. **Build with Coverage**:
   ```bash
   pwsh scripts/build.ps1 -CodeCoverage
   ```

3. **Run Tests with Coverage (Baseline)**:
   ```bash
   pwsh scripts/test.ps1 -CodeCoverage -Filter "<selected_test_suites>"
   ```
   Use the gtest filter determined in Step 1.

4. Save the baseline coverage output to a file or variable for later comparison.

## Step 3: Generate Tests

1. For each file in the `files` array, check the `status` field:
   - **`added`**: Analyze the new code and create comprehensive tests
   - **`modified`**: Analyze the changes and update/add tests to cover modifications
   - **`removed`**: Check if associated tests should be removed or updated
2. Create test cases following MsQuic test patterns in `src/test/`
3. Stage all new and modified test files with `git add`

## Step 4: Measure Updated Code Coverage

After generating tests, measure the new coverage:

1. **Rebuild with Coverage** (if test files changed):
   ```bash
   pwsh scripts/build.ps1 -CodeCoverage
   ```

2. **Run Tests with Coverage (After)**:
   ```bash
   pwsh scripts/test.ps1 -CodeCoverage -Filter "<selected_test_suites>:*NewTestName*"
   ```
   Update the filter to include your newly generated test names.

3. Save the updated coverage output.

## Step 5: Generate Coverage Comparison Report

Compare baseline and updated coverage:

1. Extract key metrics from both runs:
   - Total lines covered
   - Total lines
   - Coverage percentage
   - Per-file coverage for files in the PR

2. Create a markdown report:
   ```markdown
   ## Code Coverage Report
   
   ### Summary
   | Metric | Baseline | After | Change |
   |--------|----------|-------|--------|
   | Lines Covered | X | Y | +Z |
   | Total Lines | A | B | +C |
   | Coverage % | P% | Q% | +R% |
   
   ### Per-File Coverage (PR Files)
   | File | Baseline | After | Change |
   |------|----------|-------|--------|
   | src/core/example.c | X% | Y% | +Z% |
   ```

## Step 6: Create Pull Request

Check if there are staged changes using `git diff --cached --stat`.

If there are staged changes, use `create_pull_request` with:
- Title: "[DeepTest PR #${{ env.PR_NUMBER }}] Tests for changed files"
- Body: Include the following sections:
  - Summary: "Auto-generated tests for files changed in PR #${{ env.PR_NUMBER }} by DeepTest workflow run #${{ env.RUN_ID }}."
  - Code Coverage Report: The comparison report from Step 5
  - Test Suites Run: The gtest filter used
  - List of test files added/modified
- Branch: "deeptest/pr-${{ env.PR_NUMBER }}_run-${{ env.RUN_ID }}"

If no staged changes, use `noop` with message "No test changes generated for PR #${{ env.PR_NUMBER }}."
